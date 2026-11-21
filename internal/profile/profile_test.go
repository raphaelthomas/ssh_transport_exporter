package profile

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The lists of design/07's tables.
var (
	goldenKexA = []string{"curve25519-sha256", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256"}
	goldenKexB = append([]string{"mlkem768x25519-sha256"}, goldenKexA...)

	goldenCiphersA = []string{"chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"}
	goldenCiphersB = []string{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr"}

	goldenMACs = []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"}

	goldenHostKeys = []string{
		"ssh-ed25519-cert-v01@openssh.com", "ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp521-cert-v01@openssh.com",
		"rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com",
		"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256",
	}

	goldenCA = []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "rsa-sha2-512", "rsa-sha2-256"}

	goldenXCryptoKex      = []string{"mlkem768x25519-sha256", "curve25519-sha256", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"}
	goldenXCryptoCiphers  = []string{"aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr"}
	goldenXCryptoMACs     = []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", "hmac-sha1-96"}
	goldenXCryptoHostKeys = []string{
		"rsa-sha2-256-cert-v01@openssh.com", "rsa-sha2-512-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com",
		"ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp521-cert-v01@openssh.com", "ssh-ed25519-cert-v01@openssh.com",
		"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa", "ssh-ed25519",
		"ssh-mldsa-44-cert-v01@golang.org", "ssh-mldsa-65-cert-v01@golang.org", "ssh-mldsa-87-cert-v01@golang.org",
		"ssh-mldsa-44", "ssh-mldsa-65", "ssh-mldsa-87",
	}
)

func TestProfiles(t *testing.T) {
	tests := []struct {
		name                                         string
		kex, ciphers, macs, hostKeys, ca             []string
		order, fallback, wildcards, require, caLines bool
	}{
		{"openssh-10.3", goldenKexB, goldenCiphersB, goldenMACs, goldenHostKeys, goldenCA, true, true, true, true, false},
		{"openssh-10.0", goldenKexB, goldenCiphersB, goldenMACs, goldenHostKeys, goldenCA, true, true, false, false, false},
		{"openssh-9.9", goldenKexB, goldenCiphersA, goldenMACs, goldenHostKeys, goldenCA, true, true, false, false, false},
		{"openssh-8.8", goldenKexA, goldenCiphersA, goldenMACs, goldenHostKeys, goldenCA, true, true, false, false, false},
		{"x-crypto", goldenXCryptoKex, goldenXCryptoCiphers, goldenXCryptoMACs, goldenXCryptoHostKeys, slices.Concat(ssh.SupportedAlgorithms().PublicKeyAuths, ssh.InsecureAlgorithms().PublicKeyAuths), false, false, false, true, true},
	}
	if len(tests) != len(profiles) {
		t.Errorf("%d profiles tested, %d defined", len(tests), len(profiles))
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Lookup(tt.name)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			for _, l := range []struct {
				name      string
				got, want []string
			}{
				{"kex_algorithms", p.KeyExchanges, tt.kex},
				{"ciphers", p.Ciphers, tt.ciphers},
				{"macs", p.MACs, tt.macs},
				{"host_key_algorithms", p.HostKeyAlgorithms, tt.hostKeys},
				{"ca_signature_algorithms", p.CASignatureAlgorithms, tt.ca},
			} {
				if !slices.Equal(l.got, l.want) {
					t.Errorf("%s = %v, want %v", l.name, l.got, l.want)
				}
			}
			got := []bool{p.OrderByKnownHosts, p.PlainKeyFallback, p.WildcardPrincipals, p.RequirePrincipals, p.CALinesMatchPlainKeys}
			want := []bool{tt.order, tt.fallback, tt.wildcards, tt.require, tt.caLines}
			if !slices.Equal(got, want) {
				t.Errorf("order, fallback, wildcards, require, CA lines = %v, want %v", got, want)
			}
		})
	}
}

func TestProfileAliases(t *testing.T) {
	for alias, want := range map[string]string{
		"openssh":      "openssh-10.3",
		"openssh-8.9":  "openssh-8.8",
		"openssh-9.8":  "openssh-8.8",
		"openssh-10.2": "openssh-10.0",
		"openssh-10.6": "openssh-10.3",
	} {
		p, err := Lookup(alias)
		if err != nil {
			t.Errorf("%s: %v", alias, err)
			continue
		}
		if p.Name != want {
			t.Errorf("%s resolves to %s, want %s", alias, p.Name, want)
		}
	}
	for alias, target := range aliases {
		if _, ok := profiles[target]; !ok {
			t.Errorf("alias %s points to unknown profile %s", alias, target)
		}
	}
}

func TestDefault(t *testing.T) {
	want, err := Lookup(DefaultName)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got := Default(); !reflect.DeepEqual(got, want) {
		t.Errorf("Default() = %+v, want %+v", got, want)
	}
}

// Callers get their own lists, so changing one doesn't change the profile.
func TestLookupCopiesLists(t *testing.T) {
	for _, get := range []func() Profile{
		Default,
		func() Profile { p, _ := Lookup("x-crypto"); return p },
	} {
		p := get()
		want := slices.Clone(p.Ciphers)
		p.Ciphers[0] = "changed"
		if got := get().Ciphers; !slices.Equal(got, want) {
			t.Errorf("ciphers = %v after changing a returned list, want %v", got, want)
		}
	}
}

func TestNames(t *testing.T) {
	names := Names()
	if !slices.IsSorted(names) || len(names) != len(profiles)+len(aliases) {
		t.Errorf("Names() = %v, want all %d profiles and aliases, sorted", names, len(profiles)+len(aliases))
	}
	for _, name := range names {
		if _, err := Lookup(name); err != nil {
			t.Errorf("Lookup(%q): %v", name, err)
		}
	}
}

// x/crypto doesn't export its default lists, so this reads them from the
// KEXINIT it sends with an empty ClientConfig; a fork rebase that changes them
// fails here.
func TestXCryptoProfileMatchesXCryptoDefaults(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	go func() {
		conn, _, _, err := ssh.NewClientConn(client, "example.com:22", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey()})
		if err == nil {
			_ = conn.Close()
		}
		_ = client.Close()
	}()

	r := bufio.NewReader(server)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("reading client version: %v", err)
	}
	if _, err := io.WriteString(server, "SSH-2.0-test\r\n"); err != nil {
		t.Fatalf("writing server version: %v", err)
	}
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		t.Fatalf("reading packet length: %v", err)
	}
	packet := make([]byte, length)
	if _, err := io.ReadFull(r, packet); err != nil {
		t.Fatalf("reading packet: %v", err)
	}
	// RFC 4253, sections 6 and 7.1: padding length, payload, padding; the
	// payload is the message number, a 16-byte cookie and the name-lists.
	payload := packet[1 : len(packet)-int(packet[0])]
	if payload[0] != 20 {
		t.Fatalf("message number %d, want SSH_MSG_KEXINIT (20)", payload[0])
	}
	b := payload[17:]
	var lists [][]string
	for range 6 {
		n := binary.BigEndian.Uint32(b)
		lists = append(lists, strings.Split(string(b[4:4+n]), ","))
		b = b[4+n:]
	}
	// x/crypto adds these to any list, the libssh name after curve25519-sha256.
	kex := slices.DeleteFunc(lists[0], func(a string) bool {
		return a == "ext-info-c" || a == "kex-strict-c-v00@openssh.com" || a == "curve25519-sha256@libssh.org"
	})

	p := profiles["x-crypto"]
	for _, l := range []struct {
		name      string
		sent, got []string
	}{
		{"kex_algorithms", kex, p.KeyExchanges},
		{"host_key_algorithms", lists[1], p.HostKeyAlgorithms},
		{"ciphers", lists[2], p.Ciphers},
		{"macs", lists[4], p.MACs},
	} {
		if !slices.Equal(l.got, l.sent) {
			t.Errorf("x-crypto %s = %v, x/crypto sends %v", l.name, l.got, l.sent)
		}
	}
}
