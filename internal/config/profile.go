package config

import (
	"errors"
	"fmt"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/profile"
)

// behaviour holds the keys a profile presets, as set at one config level.
// Nil values are left out.
type behaviour struct {
	Profile                                string   `yaml:"profile,omitempty"`
	Ciphers                                []string `yaml:"ciphers,omitempty"`
	KeyExchanges                           []string `yaml:"kex_algorithms,omitempty"`
	MACs                                   []string `yaml:"macs,omitempty"`
	HostKeyAlgorithms                      []string `yaml:"host_key_algorithms,omitempty"`
	HostKeyAlgorithmsOrderByKnownHosts     *bool    `yaml:"host_key_algorithms_order_by_known_hosts,omitempty"`
	CASignatureAlgorithms                  []string `yaml:"ca_signature_algorithms,omitempty"`
	HostCertificateAllowPlainKeyFallback   *bool    `yaml:"host_certificate_allow_plain_key_fallback,omitempty"`
	HostCertificateAllowWildcardPrincipals *bool    `yaml:"host_certificate_allow_wildcard_principals,omitempty"`
	HostCertificateRequirePrincipals       *bool    `yaml:"host_certificate_require_principals,omitempty"`
	CertAuthorityLinesMatchPlainKeys       *bool    `yaml:"cert_authority_lines_match_plain_keys,omitempty"`
}

// resolve returns the level's profile with its keys on top; a level without a
// profile builds on base.
func (b behaviour) resolve(base profile.Profile) (profile.Profile, error) {
	p := base
	if b.Profile != "" {
		var err error
		if p, err = profile.Lookup(b.Profile); err != nil {
			return profile.Profile{}, err
		}
	}
	for _, l := range []struct {
		key string
		dst *[]string
		v   []string
	}{
		{"ciphers", &p.Ciphers, b.Ciphers},
		{"kex_algorithms", &p.KeyExchanges, b.KeyExchanges},
		{"macs", &p.MACs, b.MACs},
		{"host_key_algorithms", &p.HostKeyAlgorithms, b.HostKeyAlgorithms},
		{"ca_signature_algorithms", &p.CASignatureAlgorithms, b.CASignatureAlgorithms},
	} {
		if l.v == nil {
			continue
		}
		if len(l.v) == 0 {
			return profile.Profile{}, fmt.Errorf("%s is empty; leave it out to inherit", l.key)
		}
		*l.dst = l.v
	}
	setBool(&p.OrderByKnownHosts, b.HostKeyAlgorithmsOrderByKnownHosts)
	setBool(&p.PlainKeyFallback, b.HostCertificateAllowPlainKeyFallback)
	setBool(&p.WildcardPrincipals, b.HostCertificateAllowWildcardPrincipals)
	setBool(&p.RequirePrincipals, b.HostCertificateRequirePrincipals)
	setBool(&p.CALinesMatchPlainKeys, b.CertAuthorityLinesMatchPlainKeys)
	return p, nil
}

func setBool(dst, v *bool) {
	if v != nil {
		*dst = *v
	}
}

// validateProfile rejects names x/crypto/ssh does not implement.
func validateProfile(p profile.Profile) error {
	return errors.Join(
		validateAlgorithms("ciphers", p.Ciphers, knownCiphers),
		validateAlgorithms("kex algorithms", p.KeyExchanges, knownKeyExchanges),
		validateAlgorithms("macs", p.MACs, knownMACs),
		validateAlgorithms("host key algorithms", p.HostKeyAlgorithms, knownHostKeyAlgorithms),
		validateAlgorithms("ca signature algorithms", p.CASignatureAlgorithms, knownCASignatureAlgorithms),
	)
}
