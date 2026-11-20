package config

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"golang.org/x/crypto/ssh"
)

// DefaultProfileName is the profile used where none is set.
const DefaultProfileName = "openssh"

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

// profile is a resolved set of behaviour keys.
type profile struct {
	name                  string
	ciphers               []string
	keyExchanges          []string
	macs                  []string
	hostKeyAlgorithms     []string
	orderByKnownHosts     bool
	caSignatureAlgorithms []string
	plainKeyFallback      bool
	wildcardPrincipals    bool
	requirePrincipals     bool
	caLinesMatchPlainKeys bool
}

// OpenSSH's client defaults (myproposal.h), limited to what x/crypto implements.
var (
	opensshKexA = []string{
		ssh.KeyExchangeCurve25519,
		ssh.KeyExchangeECDHP256,
		ssh.KeyExchangeECDHP384,
		ssh.KeyExchangeECDHP521,
		ssh.KeyExchangeDHGEXSHA256,
		ssh.KeyExchangeDH16SHA512,
		ssh.KeyExchangeDH14SHA256,
	}
	opensshKexB = slices.Concat([]string{ssh.KeyExchangeMLKEM768X25519}, opensshKexA)

	opensshCiphersA = []string{
		ssh.CipherChaCha20Poly1305,
		ssh.CipherAES128CTR,
		ssh.CipherAES192CTR,
		ssh.CipherAES256CTR,
		ssh.CipherAES128GCM,
		ssh.CipherAES256GCM,
	}
	opensshCiphersB = []string{
		ssh.CipherChaCha20Poly1305,
		ssh.CipherAES128GCM,
		ssh.CipherAES256GCM,
		ssh.CipherAES128CTR,
		ssh.CipherAES192CTR,
		ssh.CipherAES256CTR,
	}

	opensshMACs = []string{
		ssh.HMACSHA256ETM,
		ssh.HMACSHA512ETM,
		ssh.HMACSHA256,
		ssh.HMACSHA512,
		ssh.HMACSHA1,
	}

	opensshHostKeyAlgorithms = []string{
		ssh.CertAlgoED25519v01,
		ssh.CertAlgoECDSA256v01,
		ssh.CertAlgoECDSA384v01,
		ssh.CertAlgoECDSA521v01,
		ssh.CertAlgoRSASHA512v01,
		ssh.CertAlgoRSASHA256v01,
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoRSASHA512,
		ssh.KeyAlgoRSASHA256,
	}

	opensshCASignatureAlgorithms = []string{
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoSKED25519,
		ssh.KeyAlgoSKECDSA256,
		ssh.KeyAlgoRSASHA512,
		ssh.KeyAlgoRSASHA256,
	}
)

// x/crypto's default client lists, which it doesn't export.
var (
	xCryptoKeyExchanges = []string{
		ssh.KeyExchangeMLKEM768X25519,
		ssh.KeyExchangeCurve25519,
		ssh.KeyExchangeECDHP256,
		ssh.KeyExchangeECDHP384,
		ssh.KeyExchangeECDHP521,
		ssh.KeyExchangeDH14SHA256,
		ssh.InsecureKeyExchangeDH14SHA1,
	}

	xCryptoCiphers = []string{
		ssh.CipherAES128GCM,
		ssh.CipherAES256GCM,
		ssh.CipherChaCha20Poly1305,
		ssh.CipherAES128CTR,
		ssh.CipherAES192CTR,
		ssh.CipherAES256CTR,
	}

	xCryptoMACs = []string{
		ssh.HMACSHA256ETM,
		ssh.HMACSHA512ETM,
		ssh.HMACSHA256,
		ssh.HMACSHA512,
		ssh.HMACSHA1,
		ssh.InsecureHMACSHA196,
	}

	xCryptoHostKeyAlgorithms = []string{
		ssh.CertAlgoRSASHA256v01,
		ssh.CertAlgoRSASHA512v01,
		ssh.CertAlgoRSAv01,
		ssh.CertAlgoECDSA256v01,
		ssh.CertAlgoECDSA384v01,
		ssh.CertAlgoECDSA521v01,
		ssh.CertAlgoED25519v01,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoRSASHA256,
		ssh.KeyAlgoRSASHA512,
		ssh.KeyAlgoRSA,
		ssh.KeyAlgoED25519,
		ssh.CertAlgoMLDSA44v01Go,
		ssh.CertAlgoMLDSA65v01Go,
		ssh.CertAlgoMLDSA87v01Go,
		ssh.KeyAlgoMLDSA44,
		ssh.KeyAlgoMLDSA65,
		ssh.KeyAlgoMLDSA87,
	}

	// x/crypto checks no CA signature algorithm, so any it verifies passes.
	xCryptoCASignatureAlgorithms = slices.Sorted(maps.Keys(knownCASignatureAlgorithms))
)

var profiles = map[string]profile{
	"openssh-10.3": {
		ciphers:               opensshCiphersB,
		keyExchanges:          opensshKexB,
		macs:                  opensshMACs,
		hostKeyAlgorithms:     opensshHostKeyAlgorithms,
		orderByKnownHosts:     true,
		caSignatureAlgorithms: opensshCASignatureAlgorithms,
		plainKeyFallback:      true,
		wildcardPrincipals:    true,
		requirePrincipals:     true,
	},
	"openssh-10.0": {
		ciphers:               opensshCiphersB,
		keyExchanges:          opensshKexB,
		macs:                  opensshMACs,
		hostKeyAlgorithms:     opensshHostKeyAlgorithms,
		orderByKnownHosts:     true,
		caSignatureAlgorithms: opensshCASignatureAlgorithms,
		plainKeyFallback:      true,
	},
	"openssh-9.9": {
		ciphers:               opensshCiphersA,
		keyExchanges:          opensshKexB,
		macs:                  opensshMACs,
		hostKeyAlgorithms:     opensshHostKeyAlgorithms,
		orderByKnownHosts:     true,
		caSignatureAlgorithms: opensshCASignatureAlgorithms,
		plainKeyFallback:      true,
	},
	"openssh-8.8": {
		ciphers:               opensshCiphersA,
		keyExchanges:          opensshKexA,
		macs:                  opensshMACs,
		hostKeyAlgorithms:     opensshHostKeyAlgorithms,
		orderByKnownHosts:     true,
		caSignatureAlgorithms: opensshCASignatureAlgorithms,
		plainKeyFallback:      true,
	},
	"x-crypto": {
		ciphers:               xCryptoCiphers,
		keyExchanges:          xCryptoKeyExchanges,
		macs:                  xCryptoMACs,
		hostKeyAlgorithms:     xCryptoHostKeyAlgorithms,
		caSignatureAlgorithms: xCryptoCASignatureAlgorithms,
		requirePrincipals:     true,
		caLinesMatchPlainKeys: true,
	},
}

// profileAliases maps every OpenSSH version a profile covers to it.
var profileAliases = map[string]string{
	DefaultProfileName: "openssh-10.3",
	"openssh-8.9":      "openssh-8.8",
	"openssh-9.0":      "openssh-8.8",
	"openssh-9.1":      "openssh-8.8",
	"openssh-9.2":      "openssh-8.8",
	"openssh-9.3":      "openssh-8.8",
	"openssh-9.4":      "openssh-8.8",
	"openssh-9.5":      "openssh-8.8",
	"openssh-9.6":      "openssh-8.8",
	"openssh-9.7":      "openssh-8.8",
	"openssh-9.8":      "openssh-8.8",
	"openssh-10.1":     "openssh-10.0",
	"openssh-10.2":     "openssh-10.0",
	"openssh-10.4":     "openssh-10.3",
	"openssh-10.5":     "openssh-10.3",
	"openssh-10.6":     "openssh-10.3",
}

func lookupProfile(name string) (profile, error) {
	resolved := name
	if alias, ok := profileAliases[name]; ok {
		resolved = alias
	}
	p, ok := profiles[resolved]
	if !ok {
		names := slices.Sorted(maps.Keys(profiles))
		names = append(names, slices.Sorted(maps.Keys(profileAliases))...)
		return profile{}, fmt.Errorf("unknown profile %q (valid: %v)", name, names)
	}
	p.name = resolved
	return p, nil
}

// resolve returns the level's profile with its keys on top; a level without a
// profile builds on base.
func (b behaviour) resolve(base profile) (profile, error) {
	p := base
	if b.Profile != "" {
		var err error
		if p, err = lookupProfile(b.Profile); err != nil {
			return profile{}, err
		}
	}
	for _, l := range []struct {
		key string
		dst *[]string
		v   []string
	}{
		{"ciphers", &p.ciphers, b.Ciphers},
		{"kex_algorithms", &p.keyExchanges, b.KeyExchanges},
		{"macs", &p.macs, b.MACs},
		{"host_key_algorithms", &p.hostKeyAlgorithms, b.HostKeyAlgorithms},
		{"ca_signature_algorithms", &p.caSignatureAlgorithms, b.CASignatureAlgorithms},
	} {
		if l.v == nil {
			continue
		}
		if len(l.v) == 0 {
			return profile{}, fmt.Errorf("%s is empty; leave it out to inherit", l.key)
		}
		*l.dst = l.v
	}
	setBool(&p.orderByKnownHosts, b.HostKeyAlgorithmsOrderByKnownHosts)
	setBool(&p.plainKeyFallback, b.HostCertificateAllowPlainKeyFallback)
	setBool(&p.wildcardPrincipals, b.HostCertificateAllowWildcardPrincipals)
	setBool(&p.requirePrincipals, b.HostCertificateRequirePrincipals)
	setBool(&p.caLinesMatchPlainKeys, b.CertAuthorityLinesMatchPlainKeys)
	return p, nil
}

func setBool(dst, v *bool) {
	if v != nil {
		*dst = *v
	}
}

// validate rejects names x/crypto/ssh does not implement.
func (p profile) validate() error {
	return errors.Join(
		validateAlgorithms("ciphers", p.ciphers, knownCiphers),
		validateAlgorithms("kex algorithms", p.keyExchanges, knownKeyExchanges),
		validateAlgorithms("macs", p.macs, knownMACs),
		validateAlgorithms("host key algorithms", p.hostKeyAlgorithms, knownHostKeyAlgorithms),
		validateAlgorithms("ca signature algorithms", p.caSignatureAlgorithms, knownCASignatureAlgorithms),
	)
}
