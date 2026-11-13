package knownhosts

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var remote = &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}

// implementations are ours and x/crypto's, which the tests compare.
var implementations = []struct {
	name string
	load func(files ...string) (ssh.HostKeyCallback, error)
}{
	{"ours", New},
	{"x/crypto", knownhosts.New},
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// knownHostsLine returns a known_hosts line for key; prefix holds the marker,
// if any, and the host patterns.
func knownHostsLine(prefix string, key ssh.PublicKey) string {
	return prefix + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func writeKnownHosts(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// outcome names how a host key check ended.
func outcome(err error) string {
	if err == nil {
		return "verified"
	}
	if _, ok := errors.AsType[*knownhosts.RevokedError](err); ok {
		return "revoked"
	}
	return "rejected"
}

// TestPatterns checks that a host pattern applies to a target like OpenSSH,
// checked against ssh-keygen -F when it is on PATH, and that x/crypto still
// matches as the table says.
func TestPatterns(t *testing.T) {
	key := newSigner(t).PublicKey()
	sshKeygen, _ := exec.LookPath("ssh-keygen")
	tests := []struct {
		pattern, target  string
		openssh, xcrypto bool
	}{
		{"*", "h:2222", true, false},
		{"[*]:*", "h:2222", true, false},
		{"[h]:*", "h:2222", true, false},
		{"*h*", "h:2222", true, false},
		{"h*", "h:22", true, false},
		{"h:2222", "h:2222", false, true},
		{"[h]:22", "h:22", false, true},
		{"h", "h:22", true, true},
		{"H", "h:22", true, false},
		{"::1", "[::1]:22", true, true},
		{"[::1]:2222", "[::1]:2222", true, true},
		{"*", "[::1]:2222", true, false},
		{"!h,*", "h:22", false, false},
		{"!h,*", "h:2222", true, false},
		{"h,!h", "h:22", false, false},
		{knownhosts.HashHostname("h"), "h:22", true, true},
		{knownhosts.HashHostname("[h]:2222"), "h:2222", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+" "+tt.target, func(t *testing.T) {
			path := writeKnownHosts(t, []string{knownHostsLine(tt.pattern, key)})
			for _, impl := range implementations {
				want := tt.openssh
				if impl.name == "x/crypto" {
					want = tt.xcrypto
				}
				cb, err := impl.load(path)
				if err != nil {
					t.Fatal(err)
				}
				if got := cb(tt.target, remote, key) == nil; got != want {
					t.Errorf("%s: matches = %v, want %v", impl.name, got, want)
				}
			}
			if sshKeygen == "" {
				return
			}
			out, err := exec.Command(sshKeygen, "-F", knownhosts.Normalize(tt.target), "-f", path).Output()
			if _, ok := errors.AsType[*exec.ExitError](err); err != nil && !ok {
				t.Fatal(err)
			}
			if got := strings.Contains(string(out), "found: line 1"); got != tt.openssh {
				t.Errorf("ssh-keygen -F: matches = %v, want %v", got, tt.openssh)
			}
		})
	}
}

// TestRevoked checks that @revoked lines apply only to matching hosts, like
// OpenSSH, and to all hosts with x/crypto.
func TestRevoked(t *testing.T) {
	hostKey, ca := newSigner(t), newSigner(t)
	hostPub, caPub := hostKey.PublicKey(), ca.PublicKey()
	cert := &ssh.Certificate{
		Key:             hostPub,
		CertType:        ssh.HostCert,
		ValidPrincipals: []string{"h"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		knownHosts    []string
		key           ssh.PublicKey
		ours, xcrypto string
	}{
		{
			name:       "key revoked for another host",
			knownHosts: []string{knownHostsLine("h", hostPub), knownHostsLine("@revoked other", hostPub)},
			key:        hostPub,
			ours:       "verified", xcrypto: "revoked",
		},
		{
			name:       "key revoked for the host",
			knownHosts: []string{knownHostsLine("h", hostPub), knownHostsLine("@revoked h", hostPub)},
			key:        hostPub,
			ours:       "revoked", xcrypto: "revoked",
		},
		{
			name:       "key revoked for the hashed host",
			knownHosts: []string{knownHostsLine("h", hostPub), knownHostsLine("@revoked "+knownhosts.HashHostname("h"), hostPub)},
			key:        hostPub,
			ours:       "revoked", xcrypto: "revoked",
		},
		{
			name:       "certificate, CA revoked for another host",
			knownHosts: []string{knownHostsLine("@cert-authority h", caPub), knownHostsLine("@revoked other", caPub)},
			key:        cert,
			ours:       "verified", xcrypto: "rejected",
		},
		{
			name:       "certificate, CA revoked for the host",
			knownHosts: []string{knownHostsLine("@cert-authority h", caPub), knownHostsLine("@revoked h", caPub)},
			key:        cert,
			ours:       "rejected", xcrypto: "rejected",
		},
		{
			name:       "CA as host key, revoked for another host",
			knownHosts: []string{knownHostsLine("@cert-authority h", caPub), knownHostsLine("@revoked other", caPub)},
			key:        caPub,
			ours:       "verified", xcrypto: "revoked",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeKnownHosts(t, tt.knownHosts)
			for _, impl := range implementations {
				want := tt.ours
				if impl.name == "x/crypto" {
					want = tt.xcrypto
				}
				cb, err := impl.load(path)
				if err != nil {
					t.Fatal(err)
				}
				if got := outcome(cb("h:22", remote, tt.key)); got != want {
					t.Errorf("%s: %s, want %s", impl.name, got, want)
				}
			}
		})
	}
}

// TestInvalidLines checks that invalid lines are skipped, and that a file with
// invalid lines and no valid one fails to load, in both implementations.
func TestInvalidLines(t *testing.T) {
	key := newSigner(t).PublicKey()
	valid := knownHostsLine("h", key)
	wrongType := strings.Replace(valid, "ssh-ed25519 ", "ssh-rsa ", 1)
	tests := []struct {
		name       string
		knownHosts []string
		wantErr    string
	}{
		{"empty", nil, ""},
		{"comments only", []string{"# comment", ""}, ""},
		{"invalid lines skipped", []string{"garbage", "@bogus " + valid, wrongType, valid}, ""},
		{"only invalid lines", []string{"# comment", "garbage", wrongType}, "line 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeKnownHosts(t, tt.knownHosts)
			for _, impl := range implementations {
				cb, err := impl.load(path)
				if tt.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
						t.Errorf("%s: err = %v, want it to name %q", impl.name, err, tt.wantErr)
					}
					continue
				}
				if err != nil {
					t.Fatalf("%s: %v", impl.name, err)
				}
				wantOutcome := "rejected"
				if slices.Contains(tt.knownHosts, valid) {
					wantOutcome = "verified"
				}
				if got := outcome(cb("h:22", remote, key)); got != wantOutcome {
					t.Errorf("%s: %s, want %s", impl.name, got, wantOutcome)
				}
			}
		})
	}
	if _, err := New(os.DevNull); err != nil {
		t.Errorf("New(%s): %v", os.DevNull, err)
	}
}
