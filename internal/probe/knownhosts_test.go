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
func loadKnownHosts(t *testing.T, lines []string) *knownhosts.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := knownhosts.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// acceptKey lists key for addr, host:port, as the only known_hosts line.
func acceptKey(t *testing.T, addr string, key ssh.PublicKey) *knownhosts.DB {
	t.Helper()
	return loadKnownHosts(t, []string{knownHostsLine(xknownhosts.Normalize(addr), key)})
}
