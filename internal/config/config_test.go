package config

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeConfig writes content to a temp file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return path
}

// discardLogger returns a logger that drops all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// loadRaw is a convenience wrapper for the common (no allow-all) case.
func loadRaw(t *testing.T, content string) (*rawConfig, error) {
	t.Helper()
	return loadRawConfig(writeConfig(t, content), false, discardLogger())
}

func TestLoadRawConfigDefaultModuleInjected(t *testing.T) {
	raw, err := loadRaw(t, "known_hosts: \"example.com ssh-ed25519 AAAA\"\n")
	if err != nil {
		t.Fatalf("loadRawConfig: %v", err)
	}
	if len(raw.Modules) != 1 {
		t.Fatalf("got %d modules, want 1", len(raw.Modules))
	}
	if _, ok := raw.Modules[DefaultModuleName]; !ok {
		t.Errorf("default module %q not injected; modules = %v", DefaultModuleName, raw.Modules)
	}
}

func TestLoadRawConfigFileErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		_, err := loadRawConfig(filepath.Join(t.TempDir(), "nope.yaml"), false, discardLogger())
		if err == nil || !strings.Contains(err.Error(), "reading config file") {
			t.Errorf("err = %v, want reading config file error", err)
		}
	})
	t.Run("invalid yaml", func(t *testing.T) {
		_, err := loadRaw(t, "known_hosts: [unterminated\n")
		if err == nil || !strings.Contains(err.Error(), "parsing config file") {
			t.Errorf("err = %v, want parsing config file error", err)
		}
	})
}

func TestLoadRawConfigKnownHostsPrecedence(t *testing.T) {
	t.Run("module inline over module file", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		path := writeConfig(t, `
modules:
  m:
    known_hosts: "inline-key"
    known_hosts_file: "/some/file"
`)
		raw, err := loadRawConfig(path, false, logger)
		if err != nil {
			t.Fatalf("loadRawConfig: %v", err)
		}
		mod := raw.Modules["m"]
		if mod.KnownHosts != "inline-key" || mod.KnownHostsFile != "" {
			t.Errorf("module known_hosts=%q file=%q, want inline wins and file cleared", mod.KnownHosts, mod.KnownHostsFile)
		}
		if !strings.Contains(buf.String(), "known_hosts (inline) takes precedence") {
			t.Errorf("expected precedence warning, log = %q", buf.String())
		}
	})

	t.Run("module file preserved", func(t *testing.T) {
		raw, err := loadRaw(t, `
modules:
  m:
    known_hosts_file: "/module/file"
`)
		if err != nil {
			t.Fatalf("loadRawConfig: %v", err)
		}
		mod := raw.Modules["m"]
		if mod.KnownHostsFile != "/module/file" || mod.KnownHosts != "" {
			t.Errorf("module file=%q inline=%q, want file preserved", mod.KnownHostsFile, mod.KnownHosts)
		}
	})

	t.Run("inherit default inline", func(t *testing.T) {
		raw, err := loadRaw(t, `
known_hosts: "default-inline"
modules:
  m: {}
`)
		if err != nil {
			t.Fatalf("loadRawConfig: %v", err)
		}
		if mod := raw.Modules["m"]; mod.KnownHosts != "default-inline" {
			t.Errorf("module known_hosts = %q, want inherited default-inline", mod.KnownHosts)
		}
	})

	t.Run("inherit default file", func(t *testing.T) {
		raw, err := loadRaw(t, `
known_hosts_file: "/default/file"
modules:
  m: {}
`)
		if err != nil {
			t.Fatalf("loadRawConfig: %v", err)
		}
		if mod := raw.Modules["m"]; mod.KnownHostsFile != "/default/file" {
			t.Errorf("module known_hosts_file = %q, want inherited /default/file", mod.KnownHostsFile)
		}
	})

	t.Run("module inline over default file", func(t *testing.T) {
		raw, err := loadRaw(t, `
known_hosts_file: "/default/file"
modules:
  m:
    known_hosts: "module-inline"
`)
		if err != nil {
			t.Fatalf("loadRawConfig: %v", err)
		}
		mod := raw.Modules["m"]
		if mod.KnownHosts != "module-inline" || mod.KnownHostsFile != "" {
			t.Errorf("module known_hosts=%q file=%q, want module inline and no file", mod.KnownHosts, mod.KnownHostsFile)
		}
	})

	t.Run("missing everywhere errors", func(t *testing.T) {
		_, err := loadRaw(t, `
modules:
  m: {}
`)
		if err == nil || !strings.Contains(err.Error(), "known_hosts or known_hosts_file is required") {
			t.Errorf("err = %v, want required known_hosts error", err)
		}
	})
}

func TestLoadRawConfigAllowedTargetsInheritance(t *testing.T) {
	raw, err := loadRaw(t, `
known_hosts: "k"
allowed_targets: ["a.example.com", "b.example.com"]
modules:
  inherits: {}
  overrides:
    allowed_targets: ["c.example.com"]
`)
	if err != nil {
		t.Fatalf("loadRawConfig: %v", err)
	}
	if got := raw.Modules["inherits"].AllowedTargets; !slices.Equal(got, []string{"a.example.com", "b.example.com"}) {
		t.Errorf("inherits allowed_targets = %v, want default", got)
	}
	if got := raw.Modules["overrides"].AllowedTargets; !slices.Equal(got, []string{"c.example.com"}) {
		t.Errorf("overrides allowed_targets = %v, want its own", got)
	}
}

func TestLoadRawConfigTargetPortDefaulting(t *testing.T) {
	t.Run("defaults to 22", func(t *testing.T) {
		raw, err := loadRaw(t, `
known_hosts: "k"
modules:
  m: {}
`)
		if err != nil {
			t.Fatalf("loadRawConfig: %v", err)
		}
		if got := raw.Modules["m"].TargetPort; got != 22 {
			t.Errorf("target_port = %d, want 22", got)
		}
	})

	t.Run("inherits default target_port", func(t *testing.T) {
		raw, err := loadRaw(t, `
known_hosts: "k"
target_port: 2022
modules:
  m: {}
`)
		if err != nil {
			t.Fatalf("loadRawConfig: %v", err)
		}
		if got := raw.Modules["m"].TargetPort; got != 2022 {
			t.Errorf("target_port = %d, want 2022", got)
		}
	})

	t.Run("module overrides default target_port", func(t *testing.T) {
		raw, err := loadRaw(t, `
known_hosts: "k"
target_port: 2022
allowed_ports: [22, 2022, 2222]
modules:
  m:
    target_port: 2222
`)
		if err != nil {
			t.Fatalf("loadRawConfig: %v", err)
		}
		if got := raw.Modules["m"].TargetPort; got != 2222 {
			t.Errorf("target_port = %d, want 2222", got)
		}
	})
}

func TestLoadRawConfigAllowedPortsResolution(t *testing.T) {
	t.Run("defaults to target_port", func(t *testing.T) {
		raw, err := loadRaw(t, `
known_hosts: "k"
target_port: 2022
modules:
  m: {}
`)
		if err != nil {
			t.Fatalf("loadRawConfig: %v", err)
		}
		if got := raw.Modules["m"].AllowedPorts; !slices.Equal(got, []int{2022}) {
			t.Errorf("allowed_ports = %v, want [2022]", got)
		}
	})

	t.Run("inherits default allowed_ports", func(t *testing.T) {
		raw, err := loadRaw(t, `
known_hosts: "k"
target_port: 22
allowed_ports: [22, 2222]
modules:
  m: {}
`)
		if err != nil {
			t.Fatalf("loadRawConfig: %v", err)
		}
		if got := raw.Modules["m"].AllowedPorts; !slices.Equal(got, []int{22, 2222}) {
			t.Errorf("allowed_ports = %v, want [22 2222]", got)
		}
	})

	t.Run("module overrides allowed_ports", func(t *testing.T) {
		raw, err := loadRaw(t, `
known_hosts: "k"
allowed_ports: [22]
modules:
  m:
    target_port: 2222
    allowed_ports: [2222, 22]
`)
		if err != nil {
			t.Fatalf("loadRawConfig: %v", err)
		}
		if got := raw.Modules["m"].AllowedPorts; !slices.Equal(got, []int{2222, 22}) {
			t.Errorf("allowed_ports = %v, want [2222 22]", got)
		}
	})
}

func TestLoadRawConfigPortValidation(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		contains string
	}{
		{
			"port too low",
			"known_hosts: \"k\"\nallowed_ports: [0]\nmodules:\n  m: {}\n",
			"invalid port 0",
		},
		{
			"port too high",
			"known_hosts: \"k\"\nallowed_ports: [70000]\nmodules:\n  m: {}\n",
			"invalid port 70000",
		},
		{
			"target_port not in allowed_ports",
			"known_hosts: \"k\"\ntarget_port: 22\nallowed_ports: [2222]\nmodules:\n  m: {}\n",
			"is not in allowed_ports",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadRaw(t, tt.content)
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("err = %v, want containing %q", err, tt.contains)
			}
		})
	}
}

func TestLoadRawConfigAlgorithmValidation(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		contains string
	}{
		{
			"mistyped cipher",
			"known_hosts: \"k\"\nmodules:\n  m:\n    ciphers: [arcfour28]\n",
			`unknown ciphers ["arcfour28"]`,
		},
		{
			"mac name in the ciphers list",
			"known_hosts: \"k\"\nmodules:\n  m:\n    ciphers: [hmac-sha2-256]\n",
			`unknown ciphers ["hmac-sha2-256"]`,
		},
		{
			"mistyped host key algorithm",
			"known_hosts: \"k\"\nmodules:\n  m:\n    host_key_algorithms: [ssh-ed25519-cert-v02@openssh.com]\n",
			`unknown host key algorithms ["ssh-ed25519-cert-v02@openssh.com"]`,
		},
		{
			"security key algorithms are not host key algorithms",
			"known_hosts: \"k\"\nmodules:\n  m:\n    host_key_algorithms: [sk-ssh-ed25519@openssh.com]\n",
			`unknown host key algorithms ["sk-ssh-ed25519@openssh.com"]`,
		},
		{
			"a valid entry does not excuse an invalid one",
			"known_hosts: \"k\"\nmodules:\n  m:\n    ciphers: [aes128-ctr, arcfour28]\n",
			`unknown ciphers ["arcfour28"]`,
		},
		{
			"every offending name is reported, in config order",
			"known_hosts: \"k\"\nmodules:\n  m:\n    ciphers: [arcfour28, aes128-ctr, aes128-ctrl, hmac-sha2-256]\n",
			`unknown ciphers ["arcfour28" "aes128-ctrl" "hmac-sha2-256"]`,
		},
		{
			"every offending host key algorithm is reported",
			"known_hosts: \"k\"\nmodules:\n  m:\n    host_key_algorithms: [sk-ssh-ed25519@openssh.com, ssh-ed25519, sk-ecdsa-sha2-nistp256@openssh.com]\n",
			`unknown host key algorithms ["sk-ssh-ed25519@openssh.com" "sk-ecdsa-sha2-nistp256@openssh.com"]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadRaw(t, tt.content)
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("err = %v, want containing %q", err, tt.contains)
			}
		})
	}
}

// Deliberately weak algorithms must stay configurable; rejecting them would
// defeat the point of advertising them.
func TestLoadRawConfigAcceptsInsecureAlgorithms(t *testing.T) {
	content := "known_hosts: \"k\"\nmodules:\n  m:\n" +
		"    ciphers: [arcfour, arcfour128, arcfour256, 3des-cbc, aes128-cbc]\n" +
		"    host_key_algorithms: [ssh-dss, ssh-rsa, ssh-dss-cert-v01@openssh.com, ssh-rsa-cert-v01@openssh.com]\n"
	if _, err := loadRaw(t, content); err != nil {
		t.Errorf("loadRawConfig: %v", err)
	}
}

// The shipped example is documentation operators copy from, so it has to pass
// the same validation as any other config. Only parsing and validation are
// exercised; the known_hosts paths it names are not read.
func TestExampleConfigIsValid(t *testing.T) {
	if _, err := loadRawConfig("../../ssh_transport_exporter.example.yaml", false, discardLogger()); err != nil {
		t.Errorf("example config: %v", err)
	}
}

func TestLoadRawConfigAllowAllGating(t *testing.T) {
	t.Run("flag set, no default -> allow all enabled", func(t *testing.T) {
		raw, err := loadRawConfig(writeConfig(t, "known_hosts: \"k\"\nmodules:\n  m: {}\n"), true, discardLogger())
		if err != nil {
			t.Fatalf("loadRawConfig: %v", err)
		}
		if !raw.allowAllTargets {
			t.Error("allowAllTargets = false, want true when flag set and no default allowed_targets")
		}
	})

	t.Run("flag set, default present -> allow all inert", func(t *testing.T) {
		raw, err := loadRawConfig(writeConfig(t, "known_hosts: \"k\"\nallowed_targets: [\"a.example.com\"]\nmodules:\n  m: {}\n"), true, discardLogger())
		if err != nil {
			t.Fatalf("loadRawConfig: %v", err)
		}
		if raw.allowAllTargets {
			t.Error("allowAllTargets = true, want false when a top-level default is configured")
		}
	})

	t.Run("flag unset -> allow all disabled", func(t *testing.T) {
		raw, err := loadRaw(t, "known_hosts: \"k\"\nmodules:\n  m: {}\n")
		if err != nil {
			t.Fatalf("loadRawConfig: %v", err)
		}
		if raw.allowAllTargets {
			t.Error("allowAllTargets = true, want false when flag unset")
		}
	})
}
