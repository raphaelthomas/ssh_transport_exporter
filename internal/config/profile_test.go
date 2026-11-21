package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/profile"
)

func mustProfile(t *testing.T, name string) profile.Profile {
	t.Helper()
	p, err := profile.Lookup(name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	return p
}

func with(p profile.Profile, change func(*profile.Profile)) profile.Profile {
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

func setAllKeys(p *profile.Profile) {
	p.Ciphers = []string{"aes128-ctr"}
	p.KeyExchanges = []string{"curve25519-sha256"}
	p.MACs = []string{"hmac-sha2-256"}
	p.HostKeyAlgorithms = []string{"ssh-ed25519"}
	p.CASignatureAlgorithms = []string{"ssh-ed25519"}
	p.OrderByKnownHosts = true
	p.PlainKeyFallback = true
	p.WildcardPrincipals = true
	p.RequirePrincipals = false
	p.CALinesMatchPlainKeys = false
}

func TestProfilePrecedence(t *testing.T) {
	xCrypto := mustProfile(t, "x-crypto")
	inModule := "    " + strings.ReplaceAll(strings.TrimSuffix(allKeys, "\n"), "\n", "\n    ") + "\n"
	tests := []struct {
		name    string
		content string
		want    profile.Profile
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
			if got := raw.Modules["m"].resolved; !reflect.DeepEqual(got, tt.want) {
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
		change func(*profile.Profile)
	}{
		{"ciphers", behaviour{Ciphers: list}, func(p *profile.Profile) { p.Ciphers = list }},
		{"kex_algorithms", behaviour{KeyExchanges: list}, func(p *profile.Profile) { p.KeyExchanges = list }},
		{"macs", behaviour{MACs: list}, func(p *profile.Profile) { p.MACs = list }},
		{"host_key_algorithms", behaviour{HostKeyAlgorithms: list}, func(p *profile.Profile) { p.HostKeyAlgorithms = list }},
		{"ca_signature_algorithms", behaviour{CASignatureAlgorithms: list}, func(p *profile.Profile) { p.CASignatureAlgorithms = list }},
		{"host_key_algorithms_order_by_known_hosts", behaviour{HostKeyAlgorithmsOrderByKnownHosts: &yes}, func(p *profile.Profile) { p.OrderByKnownHosts = true }},
		{"host_certificate_allow_plain_key_fallback", behaviour{HostCertificateAllowPlainKeyFallback: &yes}, func(p *profile.Profile) { p.PlainKeyFallback = true }},
		{"host_certificate_allow_wildcard_principals", behaviour{HostCertificateAllowWildcardPrincipals: &yes}, func(p *profile.Profile) { p.WildcardPrincipals = true }},
		{"host_certificate_require_principals", behaviour{HostCertificateRequirePrincipals: &no}, func(p *profile.Profile) { p.RequirePrincipals = false }},
		{"cert_authority_lines_match_plain_keys", behaviour{CertAuthorityLinesMatchPlainKeys: &no}, func(p *profile.Profile) { p.CALinesMatchPlainKeys = false }},
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

// A built-in profile must pass the same validation as a configured list.
func TestProfilesPassValidation(t *testing.T) {
	for _, name := range profile.Names() {
		if err := validateProfile(mustProfile(t, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
