package config

import (
	"bufio"
	"encoding/binary"
	"io"
	"maps"
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
		{"x-crypto", goldenXCryptoKex, goldenXCryptoCiphers, goldenXCryptoMACs, goldenXCryptoHostKeys, slices.Sorted(maps.Keys(knownCASignatureAlgorithms)), false, false, false, true, true},
	}
	if len(tests) != len(profiles) {
		t.Errorf("%d profiles tested, %d defined", len(tests), len(profiles))
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := lookupProfile(tt.name)
			if err != nil {
				t.Fatalf("lookupProfile: %v", err)
			}
			if err := p.validate(); err != nil {
				t.Errorf("validate: %v", err)
			}
			for _, l := range []struct {
				name      string
				got, want []string
			}{
				{"kex_algorithms", p.keyExchanges, tt.kex},
				{"ciphers", p.ciphers, tt.ciphers},
				{"macs", p.macs, tt.macs},
				{"host_key_algorithms", p.hostKeyAlgorithms, tt.hostKeys},
				{"ca_signature_algorithms", p.caSignatureAlgorithms, tt.ca},
			} {
				if !slices.Equal(l.got, l.want) {
					t.Errorf("%s = %v, want %v", l.name, l.got, l.want)
				}
			}
			got := []bool{p.orderByKnownHosts, p.plainKeyFallback, p.wildcardPrincipals, p.requirePrincipals, p.caLinesMatchPlainKeys}
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
		p, err := lookupProfile(alias)
		if err != nil {
			t.Errorf("%s: %v", alias, err)
			continue
		}
		if p.name != want {
			t.Errorf("%s resolves to %s, want %s", alias, p.name, want)
		}
	}
	for alias, target := range profileAliases {
		if _, ok := profiles[target]; !ok {
			t.Errorf("alias %s points to unknown profile %s", alias, target)
		}
	}
}

func mustProfile(t *testing.T, name string) profile {
	t.Helper()
	p, err := lookupProfile(name)
	if err != nil {
		t.Fatalf("lookupProfile: %v", err)
	}
	return p
}

func with(p profile, change func(*profile)) profile {
	change(&p)
	return p
}

// allKeys sets every key a profile presets to a value x-crypto's differs from.
const allKeys = `ciphers: [aes128-ctr]
kex_algorithms: [curve25519-sha256]
macs: [hmac-sha2-256]
host_key_algorithms: [ssh-ed25519]
ca_signature_algorithms: [ssh-ed25519]
host_key_algorithms_order_by_known_hosts: true
host_certificate_allow_plain_key_fallback: true
host_certificate_allow_wildcard_principals: true
host_certificate_require_principals: false
cert_authority_lines_match_plain_keys: false
`

func setAllKeys(p *profile) {
	p.ciphers = []string{"aes128-ctr"}
	p.keyExchanges = []string{"curve25519-sha256"}
	p.macs = []string{"hmac-sha2-256"}
	p.hostKeyAlgorithms = []string{"ssh-ed25519"}
	p.caSignatureAlgorithms = []string{"ssh-ed25519"}
	p.orderByKnownHosts = true
	p.plainKeyFallback = true
	p.wildcardPrincipals = true
	p.requirePrincipals = false
	p.caLinesMatchPlainKeys = false
}

func TestProfilePrecedence(t *testing.T) {
	xCrypto := mustProfile(t, "x-crypto")
	inModule := "    " + strings.ReplaceAll(strings.TrimSuffix(allKeys, "\n"), "\n", "\n    ") + "\n"
	tests := []struct {
		name    string
		content string
		want    profile
	}{
		{"left out everywhere gives openssh", "modules:\n  m: {}\n", mustProfile(t, "openssh")},
		{"top-level profile applies to modules", "profile: openssh-9.5\nmodules:\n  m: {}\n", mustProfile(t, "openssh-8.8")},
		{"top-level keys override the top-level profile", "profile: x-crypto\n" + allKeys + "modules:\n  m: {}\n", with(xCrypto, setAllKeys)},
		{"module profile overrides top-level keys", allKeys + "modules:\n  m:\n    profile: x-crypto\n", xCrypto},
		{"module keys override the module profile", "modules:\n  m:\n    profile: x-crypto\n" + inModule, with(xCrypto, setAllKeys)},
		{"module keys override the top level", "profile: x-crypto\nmodules:\n  m:\n" + inModule, with(xCrypto, setAllKeys)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := loadRaw(t, "known_hosts_file: \"k\"\n"+tt.content)
			if err != nil {
				t.Fatalf("loadRawConfig: %v", err)
			}
			if got := raw.Modules["m"].profile; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("profile = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// Each key changes its own field only, so no two keys are wired to the same one.
func TestResolveSetsEachKey(t *testing.T) {
	base := mustProfile(t, "x-crypto")
	list := []string{"ssh-ed25519"}
	yes, no := true, false
	tests := []struct {
		name   string
		b      behaviour
		change func(*profile)
	}{
		{"ciphers", behaviour{Ciphers: list}, func(p *profile) { p.ciphers = list }},
		{"kex_algorithms", behaviour{KeyExchanges: list}, func(p *profile) { p.keyExchanges = list }},
		{"macs", behaviour{MACs: list}, func(p *profile) { p.macs = list }},
		{"host_key_algorithms", behaviour{HostKeyAlgorithms: list}, func(p *profile) { p.hostKeyAlgorithms = list }},
		{"ca_signature_algorithms", behaviour{CASignatureAlgorithms: list}, func(p *profile) { p.caSignatureAlgorithms = list }},
		{"host_key_algorithms_order_by_known_hosts", behaviour{HostKeyAlgorithmsOrderByKnownHosts: &yes}, func(p *profile) { p.orderByKnownHosts = true }},
		{"host_certificate_allow_plain_key_fallback", behaviour{HostCertificateAllowPlainKeyFallback: &yes}, func(p *profile) { p.plainKeyFallback = true }},
		{"host_certificate_allow_wildcard_principals", behaviour{HostCertificateAllowWildcardPrincipals: &yes}, func(p *profile) { p.wildcardPrincipals = true }},
		{"host_certificate_require_principals", behaviour{HostCertificateRequirePrincipals: &no}, func(p *profile) { p.requirePrincipals = false }},
		{"cert_authority_lines_match_plain_keys", behaviour{CertAuthorityLinesMatchPlainKeys: &no}, func(p *profile) { p.caLinesMatchPlainKeys = false }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.b.resolve(base)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if want := with(base, tt.change); !reflect.DeepEqual(got, want) {
				t.Errorf("profile = %+v, want %+v", got, want)
			}
		})
	}
}

func TestProfileErrors(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		contains string
	}{
		{"unknown top-level profile", "profile: openssh-7.4\n", `unknown profile "openssh-7.4" (valid: [`},
		{"unknown module profile", "modules:\n  m:\n    profile: xcrypto\n", `module "m": unknown profile "xcrypto"`},
		{"invalid top-level list", "ciphers: [arcfour28]\n", `unknown ciphers ["arcfour28"]`},
		{"empty top-level list", "macs: []\n", "macs is empty; leave it out to inherit"},
		{"empty module list", "ciphers: [aes128-ctr]\nmodules:\n  m:\n    ciphers: []\n", `module "m": ciphers is empty; leave it out to inherit`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadRaw(t, "known_hosts_file: \"k\"\n"+tt.content)
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("err = %v, want containing %q", err, tt.contains)
			}
		})
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
		{"kex_algorithms", kex, p.keyExchanges},
		{"host_key_algorithms", lists[1], p.hostKeyAlgorithms},
		{"ciphers", lists[2], p.ciphers},
		{"macs", lists[4], p.macs},
	} {
		if !slices.Equal(l.got, l.sent) {
			t.Errorf("x-crypto %s = %v, x/crypto sends %v", l.name, l.got, l.sent)
		}
	}
}
