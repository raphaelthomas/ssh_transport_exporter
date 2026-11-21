// Package profile holds how SSH client implementations behave: their algorithm
// lists and host key verification switches.
package profile

import (
	"fmt"
	"maps"
	"slices"

	"golang.org/x/crypto/ssh"
)

// DefaultName names the profile used where none is set.
const DefaultName = "openssh"

// Profile is how an SSH client implementation behaves.
type Profile struct {
	Name                  string
	Ciphers               []string
	KeyExchanges          []string
	MACs                  []string
	HostKeyAlgorithms     []string
	CASignatureAlgorithms []string

	// OrderByKnownHosts asks first for the host key types known_hosts lists.
	OrderByKnownHosts bool
	// PlainKeyFallback checks the host key inside a host certificate that
	// doesn't verify.
	PlainKeyFallback bool
	// WildcardPrincipals matches host certificate principals as patterns.
	WildcardPrincipals bool
	// RequirePrincipals fails a host certificate without principals.
	RequirePrincipals bool
	// CALinesMatchPlainKeys checks a plain host key against @cert-authority
	// lines, too.
	CALinesMatchPlainKeys bool
}

// OpenSSH's client defaults (myproposal.h), limited to what x/crypto
// implements. OpenSSH 8.8 to 10.6 also offer sntrup761x25519-sha512,
// diffie-hellman-group18-sha512, umac-*, hmac-sha1-etm@openssh.com, sk-* and
// webauthn-sk-* host keys, ssh-mldsa44-ed25519, and the CA signature algorithm
// webauthn-sk-ecdsa-sha2-nistp256@openssh.com.
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
	xCryptoCASignatureAlgorithms = slices.Concat(ssh.SupportedAlgorithms().PublicKeyAuths, ssh.InsecureAlgorithms().PublicKeyAuths)
)

var profiles = map[string]Profile{
	"openssh-10.3": {
		Ciphers:               opensshCiphersB,
		KeyExchanges:          opensshKexB,
		MACs:                  opensshMACs,
		HostKeyAlgorithms:     opensshHostKeyAlgorithms,
		OrderByKnownHosts:     true,
		CASignatureAlgorithms: opensshCASignatureAlgorithms,
		PlainKeyFallback:      true,
		WildcardPrincipals:    true,
		RequirePrincipals:     true,
	},
	"openssh-10.0": {
		Ciphers:               opensshCiphersB,
		KeyExchanges:          opensshKexB,
		MACs:                  opensshMACs,
		HostKeyAlgorithms:     opensshHostKeyAlgorithms,
		OrderByKnownHosts:     true,
		CASignatureAlgorithms: opensshCASignatureAlgorithms,
		PlainKeyFallback:      true,
	},
	"openssh-9.9": {
		Ciphers:               opensshCiphersA,
		KeyExchanges:          opensshKexB,
		MACs:                  opensshMACs,
		HostKeyAlgorithms:     opensshHostKeyAlgorithms,
		OrderByKnownHosts:     true,
		CASignatureAlgorithms: opensshCASignatureAlgorithms,
		PlainKeyFallback:      true,
	},
	"openssh-8.8": {
		Ciphers:               opensshCiphersA,
		KeyExchanges:          opensshKexA,
		MACs:                  opensshMACs,
		HostKeyAlgorithms:     opensshHostKeyAlgorithms,
		OrderByKnownHosts:     true,
		CASignatureAlgorithms: opensshCASignatureAlgorithms,
		PlainKeyFallback:      true,
	},
	"x-crypto": {
		Ciphers:               xCryptoCiphers,
		KeyExchanges:          xCryptoKeyExchanges,
		MACs:                  xCryptoMACs,
		HostKeyAlgorithms:     xCryptoHostKeyAlgorithms,
		CASignatureAlgorithms: xCryptoCASignatureAlgorithms,
		RequirePrincipals:     true,
		CALinesMatchPlainKeys: true,
	},
}

// aliases maps every OpenSSH version a profile covers to it.
var aliases = map[string]string{
	DefaultName:    "openssh-10.3",
	"openssh-8.9":  "openssh-8.8",
	"openssh-9.0":  "openssh-8.8",
	"openssh-9.1":  "openssh-8.8",
	"openssh-9.2":  "openssh-8.8",
	"openssh-9.3":  "openssh-8.8",
	"openssh-9.4":  "openssh-8.8",
	"openssh-9.5":  "openssh-8.8",
	"openssh-9.6":  "openssh-8.8",
	"openssh-9.7":  "openssh-8.8",
	"openssh-9.8":  "openssh-8.8",
	"openssh-10.1": "openssh-10.0",
	"openssh-10.2": "openssh-10.0",
	"openssh-10.4": "openssh-10.3",
	"openssh-10.5": "openssh-10.3",
	"openssh-10.6": "openssh-10.3",
}

// Lookup returns the profile called name, after aliases, with its own copies of
// the lists. The error lists the valid names.
func Lookup(name string) (Profile, error) {
	resolved := name
	if alias, ok := aliases[name]; ok {
		resolved = alias
	}
	p, ok := profiles[resolved]
	if !ok {
		return Profile{}, fmt.Errorf("unknown profile %q (valid: %v)", name, Names())
	}
	p.Name = resolved
	p.Ciphers = slices.Clone(p.Ciphers)
	p.KeyExchanges = slices.Clone(p.KeyExchanges)
	p.MACs = slices.Clone(p.MACs)
	p.HostKeyAlgorithms = slices.Clone(p.HostKeyAlgorithms)
	p.CASignatureAlgorithms = slices.Clone(p.CASignatureAlgorithms)
	return p, nil
}

// Default returns the profile called DefaultName, like Lookup with its own
// copies of the lists.
func Default() Profile {
	p, err := Lookup(DefaultName)
	if err != nil {
		panic(err)
	}
	return p
}

// Names returns every profile name and alias, sorted.
func Names() []string {
	names := slices.AppendSeq(slices.Collect(maps.Keys(profiles)), maps.Keys(aliases))
	slices.Sort(names)
	return names
}
