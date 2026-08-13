package main

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/config"
)

// writeFile writes content to path, failing the test on error.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// configWithModules renders a minimal valid config defining the named modules.
func configWithModules(names ...string) string {
	// A syntactically valid known_hosts line is required for the config to build.
	const knownHosts = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1PBHkQPBnPqJ8pI8Fzq1RJgSJRfCLYVOJyGvVJZ8Nq"
	s := fmt.Sprintf("known_hosts: %q\nallowed_targets: [\"example.com\"]\nmodules:\n", knownHosts)
	for _, n := range names {
		s += "  " + n + ": {}\n"
	}
	return s
}

func TestReloadSwapsLiveModules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, configWithModules("a"))

	logger := slog.New(slog.DiscardHandler)
	cfg := &flags{ConfigFile: path}

	initial, err := config.Load(path, false, logger)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	var live atomic.Pointer[map[string]config.Module]
	live.Store(&initial)

	// Rewrite the config with a different module set and reload.
	writeFile(t, path, configWithModules("a", "b"))
	reload(logger, cfg, &live)

	got := *live.Load()
	if len(got) != 2 {
		t.Fatalf("module count = %d, want 2; modules = %v", len(got), keys(got))
	}
	if _, ok := got["b"]; !ok {
		t.Errorf("module %q missing after reload; modules = %v", "b", keys(got))
	}
}

func TestReloadKeepsPreviousConfigOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, configWithModules("a"))

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cfg := &flags{ConfigFile: path}

	initial, err := config.Load(path, false, logger)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	var live atomic.Pointer[map[string]config.Module]
	live.Store(&initial)
	before := live.Load()

	// Break the config, then reload.
	writeFile(t, path, "modules: [this is not a map\n")
	reload(logger, cfg, &live)

	if live.Load() != before {
		t.Error("live module set was swapped despite a failed reload")
	}
	if got := *live.Load(); len(got) != 1 {
		t.Errorf("module count = %d, want the previous 1; modules = %v", len(got), keys(got))
	}
	if !bytes.Contains(buf.Bytes(), []byte("config reload failed")) {
		t.Errorf("expected a reload-failure log, got: %s", buf.String())
	}
}

func TestReloadMissingFileKeepsPreviousConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, configWithModules("a"))

	logger := slog.New(slog.DiscardHandler)
	cfg := &flags{ConfigFile: path}

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
	reload(logger, cfg, &live)

	if live.Load() != before {
		t.Error("live module set was swapped after the config file disappeared")
	}
}

func TestReloadHonorsAllowAllTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	// No allowed_targets: only valid when allow-all is enabled.
	const knownHosts = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1PBHkQPBnPqJ8pI8Fzq1RJgSJRfCLYVOJyGvVJZ8Nq"
	writeFile(t, path, fmt.Sprintf("known_hosts: %q\nmodules:\n  a: {}\n", knownHosts))

	logger := slog.New(slog.DiscardHandler)

	// Without the flag the config is invalid, so nothing is stored.
	var live atomic.Pointer[map[string]config.Module]
	empty := map[string]config.Module{}
	live.Store(&empty)
	reload(logger, &flags{ConfigFile: path, AllowAllTargets: false}, &live)
	if len(*live.Load()) != 0 {
		t.Error("reload succeeded without --allow-all-targets, want failure")
	}

	// With the flag it loads and permits any target.
	reload(logger, &flags{ConfigFile: path, AllowAllTargets: true}, &live)
	modules := *live.Load()
	mod, ok := modules["a"]
	if !ok {
		t.Fatalf("module %q missing; modules = %v", "a", keys(modules))
	}
	if len(mod.AllowedTargets) != 1 || !mod.AllowedTargets[0].Match("anything.example") {
		t.Error("expected an allow-all matcher after reload with --allow-all-targets")
	}
}

// keys returns the module names of m, for readable failure messages.
func keys(m map[string]config.Module) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// serveTestSetup starts serve on a random port and returns its address, the
// signal channel, and a channel carrying serve's return value.
func serveTestSetup(t *testing.T, handler http.Handler, cfg *flags, live *atomic.Pointer[map[string]config.Module]) (string, chan os.Signal, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	sigCh := make(chan os.Signal, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(slog.New(slog.DiscardHandler), cfg, srv, live, ln, sigCh)
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

	var live atomic.Pointer[map[string]config.Module]
	addr, sigCh, errCh := serveTestSetup(t, handler, &flags{}, &live)

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

	var live atomic.Pointer[map[string]config.Module]
	go func() {
		errCh <- serve(slog.New(slog.DiscardHandler), &flags{}, srv, &live, ln, sigCh)
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

// SIGHUP reloads config and leaves the server serving.
func TestServeReloadsOnSIGHUPAndKeepsServing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, configWithModules("a"))

	initial, err := config.Load(path, false, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	var live atomic.Pointer[map[string]config.Module]
	live.Store(&initial)

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	addr, sigCh, errCh := serveTestSetup(t, handler, &flags{ConfigFile: path}, &live)

	writeFile(t, path, configWithModules("a", "b"))
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
