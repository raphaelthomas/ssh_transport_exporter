package probehttp

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/crypto/ssh"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/config"
	"github.com/raphaelthomas/ssh_transport_exporter/internal/probe"
	"github.com/raphaelthomas/ssh_transport_exporter/internal/sshtest"
)

// newRequests builds the probe request counter the handler expects.
func newRequests() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ssh_transport_exporter",
			Name:      "probe_requests_total",
			Help:      "Total probe requests served by module and HTTP status code.",
		},
		[]string{"module", "code"},
	)
}

// modulePointer wraps modules in the atomic pointer the handler reads.
func modulePointer(modules map[string]config.Module) *atomic.Pointer[map[string]config.Module] {
	var live atomic.Pointer[map[string]config.Module]
	live.Store(&modules)
	return &live
}

// testModule builds a module allowing host on the given ports.
func testModule(host string, targetPort int, allowedPorts []int, hostKey ssh.PublicKey) config.Module {
	ports := make(map[int]struct{}, len(allowedPorts))
	for _, p := range allowedPorts {
		ports[p] = struct{}{}
	}
	callback := ssh.InsecureIgnoreHostKey()
	if hostKey != nil {
		callback = ssh.FixedHostKey(hostKey)
	}
	return config.Module{
		Options:        probe.Options{HostKeyCallback: callback},
		AllowedTargets: []config.TargetMatcher{exactMatcher{host: host}},
		AllowedPorts:   ports,
		TargetPort:     targetPort,
	}
}

// doProbe issues a GET against the handler and returns the recorder.
func doProbe(t *testing.T, h http.HandlerFunc, query string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/probe"+query, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// itoa is strconv.Itoa, aliased for readable metric-label assertions.
func itoa(i int) string { return strconv.Itoa(i) }

// atoiOrFatal parses a port string, failing the test on error.
func atoiOrFatal(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("parsing port %q: %v", s, err)
	}
	return n
}

// portOf returns the port part of a "host:port" address.
func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	return port
}

func TestHandlerRejects(t *testing.T) {
	t.Parallel()

	modules := map[string]config.Module{
		config.DefaultModuleName: testModule("127.0.0.1", 22, []int{22}, nil),
	}

	tests := []struct {
		name     string
		query    string
		wantCode int
		wantBody string
		wantMod  string
	}{
		{"missing target", "", http.StatusBadRequest, "target parameter is required", config.DefaultModuleName},
		{"unknown module", "?target=127.0.0.1&module=nope", http.StatusBadRequest, `unknown module "nope"`, "nope"},
		{"malformed target", "?target=user@127.0.0.1", http.StatusBadRequest, "invalid target", config.DefaultModuleName},
		{"port not allowed", "?target=127.0.0.1:2222", http.StatusForbidden, "not allowed for module", config.DefaultModuleName},
		{"target not allowed", "?target=192.0.2.9", http.StatusForbidden, "not allowed for module", config.DefaultModuleName},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			requests := newRequests()
			h := Handler(slog.New(slog.DiscardHandler), time.Second, requests, modulePointer(modules))

			rec := doProbe(t, h, tt.query, nil)

			if rec.Code != tt.wantCode {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tt.wantCode, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, want containing %q", rec.Body.String(), tt.wantBody)
			}
			// The status word is echoed in the body for browser hits.
			if !strings.Contains(rec.Body.String(), http.StatusText(tt.wantCode)) {
				t.Errorf("body = %q, want containing status text %q", rec.Body.String(), http.StatusText(tt.wantCode))
			}
			if got := testutil.ToFloat64(requests.WithLabelValues(tt.wantMod, itoa(tt.wantCode))); got != 1 {
				t.Errorf("probe_requests_total{module=%q,code=%d} = %v, want 1", tt.wantMod, tt.wantCode, got)
			}
		})
	}
}

func TestHandlerSuccess(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{ServerVersion: "SSH-2.0-TestServer_1.0"})
	port := srv.Port(t)

	modules := map[string]config.Module{
		config.DefaultModuleName: testModule("127.0.0.1", atoiOrFatal(t, port), []int{atoiOrFatal(t, port)}, srv.HostKey),
	}
	requests := newRequests()
	h := Handler(slog.New(slog.DiscardHandler), 10*time.Second, requests, modulePointer(modules))

	rec := doProbe(t, h, "?target=127.0.0.1:"+port, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	for _, want := range []string{
		"ssh_transport_tcp_connect_success 1",
		"ssh_transport_kex_success 1",
		"ssh_transport_host_key_verify_success 1",
		"ssh_transport_tcp_connect_duration_seconds",
		"ssh_transport_kex_duration_seconds",
		`ssh_transport_identification_server_version_info{version="SSH-2.0-TestServer_1.0"} 1`,
		`ssh_transport_cipher_info{cipher=`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("response body missing %q\nbody:\n%s", want, body)
		}
	}
	if strings.Contains(body, "ssh_transport_error_info") {
		t.Errorf("error_info present on a successful probe:\n%s", body)
	}
	if got := testutil.ToFloat64(requests.WithLabelValues(config.DefaultModuleName, "200")); got != 1 {
		t.Errorf("probe_requests_total{code=200} = %v, want 1", got)
	}
}

func TestHandlerDefaultPortApplied(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})
	port := atoiOrFatal(t, srv.Port(t))

	// target has no port; the module's TargetPort must be used.
	modules := map[string]config.Module{
		config.DefaultModuleName: testModule("127.0.0.1", port, []int{port}, srv.HostKey),
	}
	requests := newRequests()
	h := Handler(slog.New(slog.DiscardHandler), 10*time.Second, requests, modulePointer(modules))

	rec := doProbe(t, h, "?target=127.0.0.1", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ssh_transport_tcp_connect_success 1") {
		t.Errorf("probe did not reach the server on the default port:\n%s", rec.Body.String())
	}
}

func TestHandlerProbeFailureStillReturns200(t *testing.T) {
	t.Parallel()
	addr := sshtest.ClosedPort(t)
	port := atoiOrFatal(t, portOf(t, addr))

	modules := map[string]config.Module{
		config.DefaultModuleName: testModule("127.0.0.1", port, []int{port}, nil),
	}
	requests := newRequests()
	h := Handler(slog.New(slog.DiscardHandler), 5*time.Second, requests, modulePointer(modules))

	rec := doProbe(t, h, "?target=127.0.0.1:"+portOf(t, addr), nil)

	// A failed probe is still a successfully served scrape.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ssh_transport_tcp_connect_success 0") {
		t.Errorf("body missing tcp_connect_success 0:\n%s", body)
	}
	if !strings.Contains(body, `stage="tcp_connect"`) || !strings.Contains(body, `reason="connection_refused"`) {
		t.Errorf("body missing error_info labels:\n%s", body)
	}
}

func TestHandlerNamedModuleSelected(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})
	port := atoiOrFatal(t, srv.Port(t))

	modules := map[string]config.Module{
		config.DefaultModuleName: testModule("192.0.2.1", 22, []int{22}, nil), // would deny 127.0.0.1
		"custom":                 testModule("127.0.0.1", port, []int{port}, srv.HostKey),
	}
	requests := newRequests()
	h := Handler(slog.New(slog.DiscardHandler), 10*time.Second, requests, modulePointer(modules))

	rec := doProbe(t, h, "?target=127.0.0.1&module=custom", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if got := testutil.ToFloat64(requests.WithLabelValues("custom", "200")); got != 1 {
		t.Errorf("probe_requests_total{module=custom,code=200} = %v, want 1", got)
	}
}

func TestHandlerScrapeTimeoutHeaderShortensProbe(t *testing.T) {
	t.Parallel()
	addr := sshtest.SilentServer(t) // accepts TCP, never speaks SSH
	port := atoiOrFatal(t, portOf(t, addr))

	modules := map[string]config.Module{
		config.DefaultModuleName: testModule("127.0.0.1", port, []int{port}, nil),
	}
	requests := newRequests()
	// Handler timeout is long; the header must shorten it.
	h := Handler(slog.New(slog.DiscardHandler), 30*time.Second, requests, modulePointer(modules))

	start := time.Now()
	rec := doProbe(t, h, "?target=127.0.0.1:"+portOf(t, addr), map[string]string{
		"X-Prometheus-Scrape-Timeout-Seconds": "0.5",
	})
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if elapsed > 10*time.Second {
		t.Errorf("probe took %s; scrape timeout header did not shorten the deadline", elapsed)
	}
	if !strings.Contains(rec.Body.String(), "ssh_transport_kex_success 0") {
		t.Errorf("expected kex failure after timeout:\n%s", rec.Body.String())
	}
}

func TestHandlerInvalidScrapeTimeoutHeaderIgnored(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})
	port := atoiOrFatal(t, srv.Port(t))

	modules := map[string]config.Module{
		config.DefaultModuleName: testModule("127.0.0.1", port, []int{port}, srv.HostKey),
	}
	requests := newRequests()
	h := Handler(slog.New(slog.DiscardHandler), 10*time.Second, requests, modulePointer(modules))

	for _, hdr := range []string{"not-a-number", "0", "-1"} {
		rec := doProbe(t, h, "?target=127.0.0.1:"+srv.Port(t), map[string]string{
			"X-Prometheus-Scrape-Timeout-Seconds": hdr,
		})
		if rec.Code != http.StatusOK {
			t.Errorf("header %q: status = %d, want 200", hdr, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "ssh_transport_kex_success 1") {
			t.Errorf("header %q: probe did not succeed, header should have been ignored", hdr)
		}
	}
}

func TestHandlerReadsLiveModulesOnReload(t *testing.T) {
	t.Parallel()
	requests := newRequests()
	live := modulePointer(map[string]config.Module{
		config.DefaultModuleName: testModule("127.0.0.1", 22, []int{22}, nil),
	})
	h := Handler(slog.New(slog.DiscardHandler), time.Second, requests, live)

	// Initially 192.0.2.9 is not allowed.
	if rec := doProbe(t, h, "?target=192.0.2.9", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 before reload", rec.Code)
	}

	// Swap in a module set that only knows a different module name.
	swapped := map[string]config.Module{
		"other": testModule("127.0.0.1", 22, []int{22}, nil),
	}
	live.Store(&swapped)

	if rec := doProbe(t, h, "?target=127.0.0.1", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 after reload removed the default module", rec.Code)
	}
	if rec := doProbe(t, h, "?target=192.0.2.9&module=other", nil); rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 from the reloaded module", rec.Code)
	}
}

// A scrape timeout header applies to its own request only, never to others
// served by the same handler. Concurrency makes a shared, mutated bound fail
// under -race.
func TestHandlerScrapeTimeoutIsPerRequest(t *testing.T) {
	t.Parallel()
	addr := sshtest.SilentServer(t) // accepts TCP, never speaks SSH
	port := atoiOrFatal(t, portOf(t, addr))

	modules := map[string]config.Module{
		config.DefaultModuleName: testModule("127.0.0.1", port, []int{port}, nil),
	}
	// One handler serves every request, as in production.
	h := Handler(slog.New(slog.DiscardHandler), 2*time.Second, newRequests(), modulePointer(modules))
	query := "?target=127.0.0.1:" + portOf(t, addr)

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			doProbe(t, h, query, map[string]string{
				"X-Prometheus-Scrape-Timeout-Seconds": fmt.Sprintf("0.%02d", 10+i),
			})
		}(i)
	}
	wg.Wait()

	// Without the header the full 2s bound applies.
	start := time.Now()
	rec := doProbe(t, h, query, nil)
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if elapsed < time.Second {
		t.Errorf("probe without a scrape timeout header took %s; a shortened timeout leaked from an earlier request", elapsed)
	}
}
