package probe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	xknownhosts "golang.org/x/crypto/ssh/knownhosts"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/knownhosts"
)

// loadKnownHosts writes lines to a known_hosts file and loads it.
func loadKnownHosts(t *testing.T, lines []string) (cb ssh.HostKeyCallback, isCA func(xknownhosts.KnownKey) bool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		t.Fatal(err)
	}
	isCA, err = knownhosts.CertAuthorities(path)
	if err != nil {
		t.Fatal(err)
	}
	return cb, isCA
}
