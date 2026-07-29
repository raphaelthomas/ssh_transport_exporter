package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

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
