package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/exporter-toolkit/web"
	"golang.org/x/crypto/bcrypt"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/buildinfo"
	"github.com/raphaelthomas/ssh_transport_exporter/internal/config"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// knownHostsFile writes a syntactically valid known_hosts file, which a config
// needs in order to build, and returns its path.
func knownHostsFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	writeFile(t, path, "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1PBHkQPBnPqJ8pI8Fzq1RJgSJRfCLYVOJyGvVJZ8Nq\n")
	return path
}

func configWithModules(t *testing.T, names ...string) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "known_hosts_file: %q\nallowed_targets: [\"example.com\"]\nmodules:\n", knownHostsFile(t))
	for _, n := range names {
		b.WriteString("  " + n + ": {}\n")
	}
	return b.String()
}

func TestReloadSwapsLiveModules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, configWithModules(t, "a"))

	logger := slog.New(slog.DiscardHandler)
	reloadMetrics := newConfigReloadMetrics()

	initial, err := config.Load(path, false, logger)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	var live atomic.Pointer[map[string]config.Module]
	live.Store(&initial)

	writeFile(t, path, configWithModules(t, "a", "b"))
	if err := testReloader(logger, path, &live, reloadMetrics).reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	got := *live.Load()
	if len(got) != 2 {
		t.Fatalf("module count = %d, want 2; modules = %v", len(got), keys(got))
	}
	if _, ok := got["b"]; !ok {
		t.Errorf("module %q missing after reload; modules = %v", "b", keys(got))
	}
	if v := testutil.ToFloat64(reloadMetrics.successful); v != 1 {
		t.Errorf("config_last_reload_successful = %v, want 1", v)
	}
	if v := testutil.ToFloat64(reloadMetrics.timestamp); v == 0 {
		t.Error("config_last_reload_success_timestamp_seconds = 0, want the reload time")
	}
}

func TestReloadKeepsPreviousConfigOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, configWithModules(t, "a"))

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	reloadMetrics := newConfigReloadMetrics()

	initial, err := config.Load(path, false, logger)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	var live atomic.Pointer[map[string]config.Module]
	live.Store(&initial)
	before := live.Load()

	writeFile(t, path, "modules: [this is not a map\n")
	if err := testReloader(logger, path, &live, reloadMetrics).reload(); err == nil {
		t.Error("reload succeeded on a broken config, want an error")
	}

	if live.Load() != before {
		t.Error("live module set was swapped despite a failed reload")
	}
	if got := *live.Load(); len(got) != 1 {
		t.Errorf("module count = %d, want the previous 1; modules = %v", len(got), keys(got))
	}
	if !bytes.Contains(buf.Bytes(), []byte("config reload failed")) {
		t.Errorf("expected a reload-failure log, got: %s", buf.String())
	}
	if v := testutil.ToFloat64(reloadMetrics.successful); v != 0 {
		t.Errorf("config_last_reload_successful = %v, want 0 after a failed reload", v)
	}
}

func TestReloadMissingFileKeepsPreviousConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, configWithModules(t, "a"))

	logger := slog.New(slog.DiscardHandler)
	reloadMetrics := newConfigReloadMetrics()

	initial, err := config.Load(path, false, logger)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	var live atomic.Pointer[map[string]config.Module]
	live.Store(&initial)
	before := live.Load()

	if err := os.Remove(path); err != nil {
		t.Fatalf("removing config: %v", err)
	}
	if err := testReloader(logger, path, &live, reloadMetrics).reload(); err == nil {
		t.Error("reload succeeded without a config file, want an error")
	}

	if live.Load() != before {
		t.Error("live module set was swapped after the config file disappeared")
	}
}

func TestReloadHonorsAllowAllTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	// No allowed_targets: only valid when allow-all is enabled.
	writeFile(t, path, fmt.Sprintf("known_hosts_file: %q\nmodules:\n  a: {}\n", knownHostsFile(t)))

	logger := slog.New(slog.DiscardHandler)
	reloadMetrics := newConfigReloadMetrics()

	var live atomic.Pointer[map[string]config.Module]
	empty := map[string]config.Module{}
	live.Store(&empty)
	if err := testReloader(logger, path, &live, reloadMetrics).reload(); err == nil || len(*live.Load()) != 0 {
		t.Error("reload succeeded without --allow-all-targets, want failure")
	}

	if err := (&reloader{logger: logger, configFile: path, allowAllTargets: true, live: &live, metrics: reloadMetrics}).reload(); err != nil {
		t.Fatalf("reload with --allow-all-targets: %v", err)
	}
	modules := *live.Load()
	mod, ok := modules["a"]
	if !ok {
		t.Fatalf("module %q missing; modules = %v", "a", keys(modules))
	}
	if len(mod.AllowedTargets) != 1 || !mod.AllowedTargets[0].Match("anything.example") {
		t.Error("expected an allow-all matcher after reload with --allow-all-targets")
	}
}

func TestReloadHandler(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, configWithModules(t, "a"))

	logger := slog.New(slog.DiscardHandler)
	initial, err := config.Load(path, false, logger)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	var live atomic.Pointer[map[string]config.Module]
	live.Store(&initial)

	mux := http.NewServeMux()
	addLifecycleHandlers(mux, testReloader(logger, path, &live, newConfigReloadMetrics()))
	do := func(method string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, "/-/reload", http.NoBody))
		return rec
	}

	writeFile(t, path, configWithModules(t, "a", "b"))
	if rec := do(http.MethodPost); rec.Code != http.StatusOK || rec.Body.String() != "OK\n" {
		t.Errorf("POST = %d %q, want 200 %q", rec.Code, rec.Body.String(), "OK\n")
	}
	if _, ok := (*live.Load())["b"]; !ok {
		t.Errorf("module %q missing after reload; modules = %v", "b", keys(*live.Load()))
	}

	before := live.Load()
	writeFile(t, path, "modules: [this is not a map\n")
	if rec := do(http.MethodPost); rec.Code != http.StatusInternalServerError || rec.Body.String() != "config reload failed, keeping previous config\n" {
		t.Errorf("POST with a broken config = %d %q, want 500 without details", rec.Code, rec.Body.String())
	}
	if live.Load() != before {
		t.Error("live module set was swapped despite a failed reload")
	}

	if rec := do(http.MethodGet); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

// A reload waiting for another one reads the config only once it runs, so the
// newest file wins.
func TestReloadsAreSerialized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, configWithModules(t, "a"))

	logger := slog.New(slog.DiscardHandler)
	var live atomic.Pointer[map[string]config.Module]

	rl := testReloader(logger, path, &live, newConfigReloadMetrics())
	rl.mu.Lock()
	done := make(chan error)
	go func() { done <- rl.reload() }()
	writeFile(t, path, configWithModules(t, "a", "b"))
	rl.mu.Unlock()

	if err := <-done; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := (*live.Load())["b"]; !ok {
		t.Errorf("module %q missing, want the newest config; modules = %v", "b", keys(*live.Load()))
	}
}

func testReloader(logger *slog.Logger, path string, live *atomic.Pointer[map[string]config.Module], metrics configReloadMetrics) *reloader {
	return &reloader{logger: logger, configFile: path, live: live, metrics: metrics}
}

func keys(m map[string]config.Module) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestLandingPage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", landingPageHandler)

	tests := []struct {
		path     string
		wantCode int
	}{
		{"/", http.StatusOK},
		{"/nope", http.StatusNotFound},
		{"/metrics", http.StatusNotFound}, // routed elsewhere in the real mux
	}
	for _, tt := range tests {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, http.NoBody))
		if rec.Code != tt.wantCode {
			t.Errorf("GET %s = %d, want %d", tt.path, rec.Code, tt.wantCode)
		}
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`href="/metrics"`,
		"github.com/raphaelthomas/ssh_transport_exporter",
		buildinfo.Version,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page missing %q:\n%s", want, body)
		}
	}
}

func TestHealthEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	addLifecycleHandlers(mux, &reloader{})

	for _, path := range []string{"/-/healthy", "/-/ready"} {
		for _, tt := range []struct {
			method   string
			wantCode int
		}{
			{http.MethodGet, http.StatusOK},
			{http.MethodHead, http.StatusOK},
			{http.MethodPost, http.StatusMethodNotAllowed},
		} {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tt.method, path, http.NoBody))
			if rec.Code != tt.wantCode {
				t.Errorf("%s %s = %d, want %d", tt.method, path, rec.Code, tt.wantCode)
			}
			if tt.method == http.MethodGet && rec.Body.String() != "OK\n" {
				t.Errorf("GET %s body = %q, want %q", path, rec.Body.String(), "OK\n")
			}
		}
	}
}

func TestLandingPageEscapesVersion(t *testing.T) {
	if got := html.EscapeString(`1.0<script>`); strings.Contains(got, "<script>") {
		t.Errorf("EscapeString(%q) = %q, want the tag escaped", `1.0<script>`, got)
	}
	if strings.Contains(landingPage, "<script>") {
		t.Error("landing page contains an unescaped script tag")
	}
}

func serveTestSetup(t *testing.T, handler http.Handler, rl *reloader) (baseURL string, signals chan os.Signal, serveErr <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	sigCh := make(chan os.Signal, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(slog.New(slog.DiscardHandler), srv, func() error { return srv.Serve(ln) }, sigCh, rl)
	}()
	return "http://" + ln.Addr().String(), sigCh, errCh
}

// A termination signal drains in-flight requests: serve returns only after
// they finish, and the client still gets a complete response.
func TestServeDrainsInFlightRequests(t *testing.T) {
	var handlerFinished atomic.Bool
	started := make(chan struct{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(300 * time.Millisecond)
		handlerFinished.Store(true)
		_, _ = w.Write([]byte("drained"))
	})

	addr, sigCh, errCh := serveTestSetup(t, handler, &reloader{})

	type result struct {
		body string
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		resp, err := http.Get(addr + "/slow")
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		resCh <- result{body: string(body), err: err}
	}()

	<-started // request is in flight
	sigCh <- syscall.SIGTERM

	if err := <-errCh; err != nil {
		t.Fatalf("serve returned %v, want nil", err)
	}
	if !handlerFinished.Load() {
		t.Error("serve returned before the in-flight request finished")
	}

	res := <-resCh
	if res.err != nil {
		t.Fatalf("in-flight request failed: %v", res.err)
	}
	if res.body != "drained" {
		t.Errorf("body = %q, want %q", res.body, "drained")
	}
}

// serve owns the signal handler, so it has to reap it on every exit path, not
// only the one a termination signal drives.
func TestServeStopsSignalHandlerOnListenerError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.NewServeMux(), ReadHeaderTimeout: time.Second}
	sigCh := make(chan os.Signal, 1)
	errCh := make(chan error, 1)

	go func() {
		errCh <- serve(slog.New(slog.DiscardHandler), srv, func() error { return srv.Serve(ln) }, sigCh, &reloader{})
	}()

	// Break Accept so Serve fails with something other than ErrServerClosed.
	if err := ln.Close(); err != nil {
		t.Fatalf("closing listener: %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("serve returned nil, want the listener error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after the listener closed")
	}

	// A stranded handler would still be reading sigCh and consume this.
	sigCh <- syscall.SIGHUP
	time.Sleep(100 * time.Millisecond)
	if len(sigCh) != 1 {
		t.Error("signal handler still running after serve returned")
	}
}

func TestServeReloadsOnSIGHUPAndKeepsServing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, configWithModules(t, "a"))

	initial, err := config.Load(path, false, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	var live atomic.Pointer[map[string]config.Module]
	live.Store(&initial)

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	addr, sigCh, errCh := serveTestSetup(t, handler, testReloader(slog.New(slog.DiscardHandler), path, &live, newConfigReloadMetrics()))

	writeFile(t, path, configWithModules(t, "a", "b"))
	sigCh <- syscall.SIGHUP

	// Poll until the reload lands; the signal is handled asynchronously.
	deadline := time.Now().Add(5 * time.Second)
	for len(*live.Load()) != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("config not reloaded after SIGHUP; modules = %v", keys(*live.Load()))
		}
		time.Sleep(10 * time.Millisecond)
	}

	resp, err := http.Get(addr + "/probe")
	if err != nil {
		t.Fatalf("server stopped serving after SIGHUP: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("closing body: %v", err)
	}

	sigCh <- syscall.SIGTERM
	if err := <-errCh; err != nil {
		t.Errorf("serve returned %v, want nil", err)
	}
}

// writeWebConfig writes a web config with a self-signed certificate and one user.
func writeWebConfig(t *testing.T, user, password string) (string, *x509.Certificate) {
	t.Helper()
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeFile(t, certPath, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeFile(t, keyPath, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})))

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}
	path := filepath.Join(dir, "web.yml")
	writeFile(t, path, fmt.Sprintf("tls_server_config:\n  cert_file: %q\n  key_file: %q\nbasic_auth_users:\n  %s: %q\n", certPath, keyPath, user, hash))
	return path, cert
}

// --web.config.file reaches the toolkit, which then serves TLS and basic auth.
func TestServeWithWebConfig(t *testing.T) {
	webConfig, cert := writeWebConfig(t, "prometheus", "secret")
	cfg := parseFlags([]string{"--web.config.file=" + webConfig})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	sigCh := make(chan os.Signal, 1)
	errCh := make(chan error, 1)
	logger := slog.New(slog.DiscardHandler)
	go func() {
		errCh <- serve(logger, srv, func() error { return web.Serve(ln, srv, cfg.Web, logger) }, sigCh, &reloader{})
	}()

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	get := func(user, password string) int {
		req, err := http.NewRequest(http.MethodGet, "https://"+ln.Addr().String()+"/probe", http.NoBody)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		if user != "" {
			req.SetBasicAuth(user, password)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET over TLS: %v", err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if code := get("", ""); code != http.StatusUnauthorized {
		t.Errorf("without credentials = %d, want %d", code, http.StatusUnauthorized)
	}
	if code := get("prometheus", "wrong"); code != http.StatusUnauthorized {
		t.Errorf("with a wrong password = %d, want %d", code, http.StatusUnauthorized)
	}
	if code := get("prometheus", "secret"); code != http.StatusOK {
		t.Errorf("with credentials = %d, want %d", code, http.StatusOK)
	}

	sigCh <- syscall.SIGTERM
	if err := <-errCh; err != nil {
		t.Errorf("serve returned %v, want nil", err)
	}
}

func TestCheckConfigValidatesWebConfig(t *testing.T) {
	valid, _ := writeWebConfig(t, "prometheus", "secret")
	broken := filepath.Join(t.TempDir(), "web.yml")
	writeFile(t, broken, "tls_server_config:\n  cert_file: /does/not/exist.pem\n  key_file: /does/not/exist.key\n")

	for _, tt := range []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"no web config", nil, false},
		{"valid web config", []string{"--web.config.file=" + valid}, false},
		{"broken web config", []string{"--web.config.file=" + broken}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := checkConfig(slog.New(slog.NewTextHandler(&buf, nil)), parseFlags(tt.args), 1)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkConfig() = %v, want error %t", err, tt.wantErr)
			}
			if gotOK := strings.Contains(buf.String(), "config OK"); gotOK == tt.wantErr {
				t.Errorf("logged %q, want \"config OK\" only on success", buf.String())
			}
		})
	}
}

func TestParseFlags(t *testing.T) {
	check := func(t *testing.T, got *flags, want flags, wantListen []string, wantWebConfig string) {
		t.Helper()
		if addrs := *got.Web.WebListenAddresses; !slices.Equal(addrs, wantListen) {
			t.Errorf("listen addresses = %q, want %q", addrs, wantListen)
		}
		if path := *got.Web.WebConfigFile; path != wantWebConfig {
			t.Errorf("web config file = %q, want %q", path, wantWebConfig)
		}
		got.Web = nil
		if *got != want {
			t.Errorf("flags = %+v, want %+v", *got, want)
		}
	}

	want := flags{
		LogLevel:           slog.LevelInfo,
		ConfigFile:         "ssh_transport_exporter.yaml",
		ProbeTimeout:       5 * time.Second,
		MaxConcurrentProbe: 500,
	}
	check(t, parseFlags(nil), want, []string{":10022"}, "")

	want = flags{
		LogLevel:           slog.LevelDebug,
		ConfigFile:         "other.yaml",
		CheckConfig:        true,
		ProbeTimeout:       time.Second,
		MaxConcurrentProbe: 10,
		AllowAllTargets:    true,
	}
	listen := []string{"127.0.0.1:9999", "[::1]:9999"}
	args := []string{
		"--web.listen-address=" + listen[0],
		"--web.listen-address=" + listen[1],
		"--web.config.file=web.yml",
		"--log.level=debug",
		"--config.file=other.yaml",
		"--config.check",
		"--probe.timeout=1s",
		"--probe.max-concurrent=10",
		"--allow-all-targets",
	}
	check(t, parseFlags(args), want, listen, "web.yml")

	for name, value := range map[string]string{
		"LISTEN_ADDRESS":       strings.Join(listen, "\n"),
		"WEB_CONFIG_FILE":      "web.yml",
		"LOG_LEVEL":            "debug",
		"CONFIG_FILE":          "other.yaml",
		"PROBE_TIMEOUT":        "1s",
		"PROBE_MAX_CONCURRENT": "10",
		"ALLOW_ALL_TARGETS":    "true",
	} {
		t.Setenv("SSH_TRANSPORT_EXPORTER_"+name, value)
	}
	want.CheckConfig = false // a one-off action, so it has no env var
	check(t, parseFlags(nil), want, listen, "web.yml")
}

func TestFlagsValidate(t *testing.T) {
	tests := []struct {
		name          string
		timeout       time.Duration
		maxConcurrent int
		wantErr       string
	}{
		{"defaults", 5 * time.Second, 500, ""},
		{"no concurrency limit", 5 * time.Second, 0, ""},
		{"zero timeout", 0, 500, "--probe.timeout"},
		{"negative timeout", -time.Second, 500, "--probe.timeout"},
		{"negative concurrency", 5 * time.Second, -1, "--probe.max-concurrent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (&flags{ProbeTimeout: tt.timeout, MaxConcurrentProbe: tt.maxConcurrent}).validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("validate() = %v, want error mentioning %s", err, tt.wantErr)
			}
		})
	}
}
