package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// newHostKey returns a fresh ed25519 SSH public key for use as a server host key.
func newHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return signer.PublicKey()
}

// exercise invokes a built HostKeyCallback for host "example.com:22".
func exercise(cb ssh.HostKeyCallback, key ssh.PublicKey) error {
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	return cb("example.com:22", remote, key)
}

func TestLoadStripServerVersionComment(t *testing.T) {
	content := fmt.Sprintf(`
known_hosts: %q
allowed_targets: ["example.com"]
modules:
  keeps: {}
  strips:
    strip_server_version_comment: true
`, knownhosts.Line([]string{"example.com:22"}, newHostKey(t)))

	modules, err := Load(writeConfig(t, content), false, discardLogger())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := modules["keeps"].Options.StripServerVersionComment; got {
		t.Error("keeps: StripServerVersionComment = true, want false by default")
	}
	if got := modules["strips"].Options.StripServerVersionComment; !got {
		t.Error("strips: StripServerVersionComment = false, want true")
	}
}

// The top-level default enables stripping everywhere, and a module cannot turn
// it back off.
func TestLoadStripServerVersionCommentDefault(t *testing.T) {
	content := fmt.Sprintf(`
known_hosts: %q
allowed_targets: ["example.com"]
strip_server_version_comment: true
modules:
  inherits: {}
  cannot_opt_out:
    strip_server_version_comment: false
`, knownhosts.Line([]string{"example.com:22"}, newHostKey(t)))

	modules, err := Load(writeConfig(t, content), false, discardLogger())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, name := range []string{"inherits", "cannot_opt_out"} {
		if got := modules[name].Options.StripServerVersionComment; !got {
			t.Errorf("%s: StripServerVersionComment = false, want true", name)
		}
	}
}

func TestLoadInlineKnownHosts(t *testing.T) {
	pub := newHostKey(t)
	line := knownhosts.Line([]string{"example.com:22"}, pub)

	content := fmt.Sprintf(`
known_hosts: %q
allowed_targets: ["example.com"]
target_port: 22
allowed_ports: [22, 2222]
modules:
  default: {}
`, line)

	modules, err := Load(writeConfig(t, content), false, discardLogger())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	mod, ok := modules[DefaultModuleName]
	if !ok {
		t.Fatalf("default module missing; got %v", modules)
	}
	if mod.Options.HostKeyCallback == nil {
		t.Fatal("HostKeyCallback is nil")
	}
	if mod.TargetPort != 22 {
		t.Errorf("TargetPort = %d, want 22", mod.TargetPort)
	}
	if _, ok := mod.AllowedPorts[22]; !ok {
		t.Errorf("AllowedPorts missing 22: %v", mod.AllowedPorts)
	}
	if _, ok := mod.AllowedPorts[2222]; !ok {
		t.Errorf("AllowedPorts missing 2222: %v", mod.AllowedPorts)
	}
	if len(mod.AllowedTargets) == 0 {
		t.Fatal("AllowedTargets is empty")
	}
	if !mod.AllowedTargets[0].Match("example.com") {
		t.Error("AllowedTargets[0] does not match example.com")
	}

	// Callback accepts the correct key and rejects a different one.
	if err := exercise(mod.Options.HostKeyCallback, pub); err != nil {
		t.Errorf("callback rejected the correct host key: %v", err)
	}
	if err := exercise(mod.Options.HostKeyCallback, newHostKey(t)); err == nil {
		t.Error("callback accepted a wrong host key, want error")
	}
}

func TestLoadKnownHostsFile(t *testing.T) {
	pub := newHostKey(t)
	line := knownhosts.Line([]string{"example.com:22"}, pub)

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(khPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("writing known_hosts: %v", err)
	}

	content := fmt.Sprintf(`
known_hosts_file: %q
allowed_targets: ["example.com"]
modules:
  default: {}
`, khPath)

	modules, err := Load(writeConfig(t, content), false, discardLogger())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	mod := modules[DefaultModuleName]
	if mod.Options.HostKeyCallback == nil {
		t.Fatal("HostKeyCallback is nil")
	}
	if err := exercise(mod.Options.HostKeyCallback, pub); err != nil {
		t.Errorf("callback rejected the correct host key: %v", err)
	}
}

func TestLoadCiphersAndAlgorithmsPassThrough(t *testing.T) {
	pub := newHostKey(t)
	line := knownhosts.Line([]string{"example.com:22"}, pub)

	content := fmt.Sprintf(`
known_hosts: %q
allowed_targets: ["example.com"]
modules:
  default:
    ciphers: ["aes128-gcm@openssh.com"]
    host_key_algorithms: ["ssh-ed25519"]
`, line)

	modules, err := Load(writeConfig(t, content), false, discardLogger())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	mod := modules[DefaultModuleName]
	if got := mod.Options.Ciphers; len(got) != 1 || got[0] != "aes128-gcm@openssh.com" {
		t.Errorf("Ciphers = %v, want [aes128-gcm@openssh.com]", got)
	}
	if got := mod.Options.HostKeyAlgorithms; len(got) != 1 || got[0] != "ssh-ed25519" {
		t.Errorf("HostKeyAlgorithms = %v, want [ssh-ed25519]", got)
	}
}

func TestLoadAllowAllTargets(t *testing.T) {
	pub := newHostKey(t)
	line := knownhosts.Line([]string{"example.com:22"}, pub)

	content := fmt.Sprintf(`
known_hosts: %q
modules:
  default: {}
`, line)

	modules, err := Load(writeConfig(t, content), true, discardLogger())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	mod := modules[DefaultModuleName]
	if len(mod.AllowedTargets) != 1 || !mod.AllowedTargets[0].Match("anything.example") {
		t.Errorf("expected allow-all matcher, got %v", mod.AllowedTargets)
	}
}

func TestLoadErrors(t *testing.T) {
	t.Run("bad known_hosts", func(t *testing.T) {
		content := `
known_hosts: "this is not a valid known_hosts entry"
allowed_targets: ["example.com"]
modules:
  default: {}
`
		_, err := Load(writeConfig(t, content), false, discardLogger())
		if err == nil {
			t.Fatal("Load = nil error, want error for invalid known_hosts")
		}
	})

	t.Run("no allowed_targets without allow-all", func(t *testing.T) {
		pub := newHostKey(t)
		line := knownhosts.Line([]string{"example.com:22"}, pub)
		content := fmt.Sprintf(`
known_hosts: %q
modules:
  default: {}
`, line)
		_, err := Load(writeConfig(t, content), false, discardLogger())
		if err == nil {
			t.Fatal("Load = nil error, want error for missing allowed_targets")
		}
	})

	t.Run("propagates loadRawConfig error", func(t *testing.T) {
		_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), false, discardLogger())
		if err == nil {
			t.Fatal("Load = nil error, want error for missing config file")
		}
	})
}
