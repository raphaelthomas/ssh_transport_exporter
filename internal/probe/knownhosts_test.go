package probe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/knownhosts"
)

// knownHostsCallback writes lines to a known_hosts file and loads it.
func knownHostsCallback(t *testing.T, lines []string) ssh.HostKeyCallback {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		t.Fatal(err)
	}
	return cb
}
