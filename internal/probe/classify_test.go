package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestParseServerIdentification(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    ServerIdentification
		wantErr bool
	}{
		{"normal", "SSH-2.0-OpenSSH_9.6", ServerIdentification{"SSH-2.0-OpenSSH_9.6", "2.0", "OpenSSH_9.6", "", true}, false},
		{"with comments", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", ServerIdentification{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "2.0", "OpenSSH_9.6p1", "Ubuntu-3ubuntu13.5", true}, false},
		{"comments containing spaces", "SSH-2.0-Foo_1.0 a b c", ServerIdentification{"SSH-2.0-Foo_1.0 a b c", "2.0", "Foo_1.0", "a b c", true}, false},
		{"1.99 protoversion", "SSH-1.99-OpenSSH_9.6", ServerIdentification{"SSH-1.99-OpenSSH_9.6", "1.99", "OpenSSH_9.6", "", true}, false},
		{"minus in softwareversion", "SSH-2.0-Cisco-1.25", ServerIdentification{"SSH-2.0-Cisco-1.25", "2.0", "Cisco-1.25", "", false}, false},
		{"empty", "", ServerIdentification{}, true},
		{"missing prefix", "OpenSSH_9.6", ServerIdentification{}, true},
		{"unsupported protoversion", "SSH-1.5-OpenSSH_9.6", ServerIdentification{}, true},
		{"empty softwareversion", "SSH-2.0-", ServerIdentification{}, true},
		{"comments without softwareversion", "SSH-2.0- Ubuntu", ServerIdentification{}, true},
		{"control chars", "SSH-2.0-\x00\x01\x1fTest", ServerIdentification{}, true},
		{"del char", "SSH-2.0-Test\x7f", ServerIdentification{}, true},
		{"tab and newline", "SSH-2.0-Te\tst\n", ServerIdentification{}, true},
		{"invalid utf8", "SSH-2.0-Test\xff", ServerIdentification{}, true},
		{"non-ascii", "SSH-2.0-café", ServerIdentification{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseServerIdentification([]byte(tt.in))
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Errorf("parseServerIdentification(%q) = %+v, %v, want %+v, error %t", tt.in, got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestServerIdentificationWithoutComments(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"comments dropped", "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10", "SSH-2.0-OpenSSH_9.2p1"},
		{"no comments is unchanged", "SSH-2.0-OpenSSH_9.6", "SSH-2.0-OpenSSH_9.6"},
		{"comments containing spaces", "SSH-2.0-Foo_1.0 a b c", "SSH-2.0-Foo_1.0"},
		{"empty comments after trailing space", "SSH-2.0-Foo_1.0 ", "SSH-2.0-Foo_1.0"},
		{"1.99 protoversion kept", "SSH-1.99-Foo_1.0 bar", "SSH-1.99-Foo_1.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ident, err := parseServerIdentification([]byte(tt.in))
			if err != nil {
				t.Fatalf("parseServerIdentification(%q): %v", tt.in, err)
			}
			got := ident.withoutComments()
			if got.String != tt.want || got.Comments != "" {
				t.Errorf("withoutComments() = %q, comments %q, want %q, no comments", got.String, got.Comments, tt.want)
			}
		})
	}
}

func TestParseServerIdentificationLengthLimit(t *testing.T) {
	for _, tt := range []struct {
		length            int
		wantRFCConformant bool
		wantErr           bool
	}{
		{253, true, false},
		{254, false, false},
		{255, false, false},
		{256, false, true},
	} {
		raw := "SSH-2.0-" + strings.Repeat("a", tt.length-len("SSH-2.0-"))
		ident, err := parseServerIdentification([]byte(raw))
		if ident.RFCConformant != tt.wantRFCConformant || (err != nil) != tt.wantErr {
			t.Errorf("length %d: got %t, %v, want %t, error %t", tt.length, ident.RFCConformant, err, tt.wantRFCConformant, tt.wantErr)
		}
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func expiredContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	t.Cleanup(cancel)
	return ctx
}

func canceledContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestClassifyDialError(t *testing.T) {
	tests := []struct {
		name string
		ctx  func(*testing.T) context.Context
		err  error
		want string
	}{
		{"timeout", nil, timeoutError{}, ErrReasonTimeout},
		{"connection refused", nil, syscall.ECONNREFUSED, ErrReasonConnectionRefused},
		{"no route to host", nil, syscall.EHOSTUNREACH, ErrReasonNoRouteToHost},
		{"network unreachable", nil, syscall.ENETUNREACH, ErrReasonNetworkUnreachable},
		{"reset before connect completed", nil, syscall.ECONNRESET, ErrReasonConnectionReset},
		{"dns failure", nil, &net.DNSError{Err: "no such host", Name: "nope"}, ErrReasonDNSFailure},
		{"wrapped connection refused", nil, fmt.Errorf("dial: %w", syscall.ECONNREFUSED), ErrReasonConnectionRefused},
		{"other", nil, errors.New("boom"), ErrReasonOther},
		{"expired context reports timeout", expiredContext, errors.New("boom"), ErrReasonTimeout},
		{"expired context outranks ErrClosed", expiredContext, net.ErrClosed, ErrReasonTimeout},
		{"canceled context reports canceled", canceledContext, errors.New("boom"), ErrReasonCanceled},
		{"canceled context outranks ErrClosed", canceledContext, net.ErrClosed, ErrReasonCanceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.ctx != nil {
				ctx = tt.ctx(t)
			}
			if got := classifyDialError(ctx, tt.err); got != tt.want {
				t.Errorf("classifyDialError(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestClassifyKexError(t *testing.T) {
	tests := []struct {
		name string
		ctx  func(*testing.T) context.Context
		err  error
		want string
	}{
		{"timeout", nil, timeoutError{}, ErrReasonTimeout},
		{"peer closed", nil, io.EOF, ErrReasonConnectionReset},
		{"peer closed mid-packet", nil, io.ErrUnexpectedEOF, ErrReasonConnectionReset},
		{"wrapped as by NewClientConn", nil, fmt.Errorf("ssh: handshake failed: %w", io.EOF), ErrReasonConnectionReset},
		{"peer reset", nil, syscall.ECONNRESET, ErrReasonConnectionReset},
		{"peer reset seen on write", nil, syscall.EPIPE, ErrReasonConnectionReset},
		{"peer reset in a net.OpError", nil, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, ErrReasonConnectionReset},
		{"own close without an expired context", nil, net.ErrClosed, ErrReasonOther},
		{"other", nil, errors.New("kex exploded"), ErrReasonOther},
		{"no common kex", nil, &ssh.AlgorithmNegotiationError{What: "key exchange"}, ErrReasonNoCommonKex},
		{"no common host key", nil, &ssh.AlgorithmNegotiationError{What: "host key"}, ErrReasonNoCommonHostKey},
		{"no common cipher client to server", nil, &ssh.AlgorithmNegotiationError{What: "client to server cipher"}, ErrReasonNoCommonCipher},
		{"no common cipher server to client", nil, &ssh.AlgorithmNegotiationError{What: "server to client cipher"}, ErrReasonNoCommonCipher},
		{"no common MAC client to server", nil, &ssh.AlgorithmNegotiationError{What: "client to server MAC"}, ErrReasonNoCommonMAC},
		{"no common MAC server to client", nil, &ssh.AlgorithmNegotiationError{What: "server to client MAC"}, ErrReasonNoCommonMAC},
		{"no common compression", nil, &ssh.AlgorithmNegotiationError{What: "client to server compression"}, ErrReasonNoCommonAlgorithm},
		{"wrapped no common host key", nil, fmt.Errorf("ssh: handshake failed: %w", &ssh.AlgorithmNegotiationError{What: "host key"}), ErrReasonNoCommonHostKey},
		{"expired context reports timeout", expiredContext, net.ErrClosed, ErrReasonTimeout},
		{"expired context outranks a generic error", expiredContext, errors.New("kex exploded"), ErrReasonTimeout},
		{"canceled context reports canceled", canceledContext, net.ErrClosed, ErrReasonCanceled},
		{"canceled context outranks a generic error", canceledContext, errors.New("kex exploded"), ErrReasonCanceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.ctx != nil {
				ctx = tt.ctx(t)
			}
			if got := classifyKexError(ctx, tt.err); got != tt.want {
				t.Errorf("classifyKexError(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestClassifyHostKeyVerifyError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"unknown host (empty Want)", &knownhosts.KeyError{}, ErrReasonServerHostKeyUnknown},
		{"mismatch (non-empty Want)", &knownhosts.KeyError{Want: []knownhosts.KnownKey{{}}}, ErrReasonServerHostKeyMismatch},
		{"revoked", &knownhosts.RevokedError{}, ErrReasonServerHostKeyRevoked},
		{"wrapped mismatch", fmt.Errorf("verify: %w", &knownhosts.KeyError{Want: []knownhosts.KnownKey{{}}}), ErrReasonServerHostKeyMismatch},
		{"certificate CA unknown", fmt.Errorf("%w: %w", errHostCertificateCAUnknown, &knownhosts.KeyError{}), ErrReasonServerHostCertificateCAUnknown},
		{"certificate not yet valid", fmt.Errorf("%w: %w", errHostCertificateNotYetValid, errors.New("ssh: cert is not yet valid")), ErrReasonServerHostCertificateNotYetValid},
		{"certificate expired", fmt.Errorf("%w: %w", errHostCertificateExpired, errors.New("ssh: cert has expired")), ErrReasonServerHostCertificateExpired},
		{"certificate principal not listed", fmt.Errorf("%w: %w", errHostCertificatePrincipalNotListed, errors.New("ssh: principal not in the set")), ErrReasonServerHostCertificatePrincipalNotListed},
		{"certificate signature algorithm disallowed", fmt.Errorf("%w: %w", errHostCertificateSignatureAlgorithmDisallowed, errors.New(`CA signature algorithm "ssh-rsa" not allowed`)), ErrReasonServerHostCertificateSignatureAlgorithmDisallowed},
		{"certificate invalid", fmt.Errorf("%w: %w", errHostCertificateInvalid, errors.New("ssh: certificate presented as a host key has type 1")), ErrReasonServerHostCertificateOther},
		{"certificate signature invalid", fmt.Errorf("%w: %w", errHostCertificateSignatureInvalid, errors.New("ssh: certificate signature does not verify")), ErrReasonServerHostCertificateSignatureInvalid},
		{"rejected", errors.New("nope"), ErrReasonServerHostKeyRejected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyHostKeyVerifyError(tt.err); got != tt.want {
				t.Errorf("classifyHostKeyVerifyError(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func newEd25519Signer(t *testing.T) ssh.Signer {
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

// newRSASigner returns an RSA signer restricted to algorithm.
func newRSASigner(t *testing.T, algorithm string) ssh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	restricted, err := ssh.NewSignerWithAlgorithms(signer.(ssh.AlgorithmSigner), []string{algorithm})
	if err != nil {
		t.Fatal(err)
	}
	return restricted
}

// knownHostsLine returns a known_hosts line for key; prefix holds the marker, if
// any, and the host patterns.
func knownHostsLine(prefix string, key ssh.PublicKey) string {
	return prefix + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// TestVerifyHostKey checks that verifyHostKey decides like OpenSSH. It also
// fails if x/crypto changes behavior verifyHostKey relies on:
//   - a CA key passes as a host key if its @cert-authority line matches;
//   - a KeyError's Want lists every matching line but @revoked ones, with file
//     and line number;
//   - IsRevoked checks a certificate's key and CA;
//   - a @revoked certificate line revokes the key inside the certificate;
//   - knownhosts doesn't fall back to the plain key itself;
//   - CheckCert checks nothing beyond what verifyCertSignature sets up to pass.
func TestVerifyHostKey(t *testing.T) {
	const host = "host.example.com"
	hostKey, otherKey, ca := newEd25519Signer(t), newEd25519Signer(t), newEd25519Signer(t)
	hostPub, caPub := hostKey.PublicKey(), ca.PublicKey()

	newCert := func(authority ssh.Signer, edit func(*ssh.Certificate)) *ssh.Certificate {
		t.Helper()
		cert := &ssh.Certificate{
			Key:             hostPub,
			CertType:        ssh.HostCert,
			ValidPrincipals: []string{host},
			ValidBefore:     ssh.CertTimeInfinity,
		}
		if edit != nil {
			edit(cert)
		}
		if err := cert.SignCert(rand.Reader, authority); err != nil {
			t.Fatal(err)
		}
		return cert
	}
	valid := newCert(ca, nil)
	expired := newCert(ca, func(c *ssh.Certificate) { c.ValidBefore = uint64(time.Now().Add(-time.Hour).Unix()) })
	wrongPrincipal := newCert(ca, func(c *ssh.Certificate) { c.ValidPrincipals = []string{"other.example.com"} })
	userCert := newCert(ca, func(c *ssh.Certificate) { c.CertType = ssh.UserCert })
	notYetValid := newCert(ca, func(c *ssh.Certificate) { c.ValidAfter = uint64(time.Now().Add(time.Hour).Unix()) })
	criticalOption := newCert(ca, func(c *ssh.Certificate) { c.CriticalOptions = map[string]string{"unknown@example.com": ""} })
	// x/crypto checks critical options and principals before validity, OpenSSH after.
	expiredCriticalOption := newCert(ca, func(c *ssh.Certificate) {
		c.ValidBefore = expired.ValidBefore
		c.CriticalOptions = criticalOption.CriticalOptions
	})
	expiredWrongPrincipal := newCert(ca, func(c *ssh.Certificate) {
		c.ValidBefore = expired.ValidBefore
		c.ValidPrincipals = wrongPrincipal.ValidPrincipals
	})
	rsaSHA1CA, rsaSHA2CA := newRSASigner(t, ssh.KeyAlgoRSA), newRSASigner(t, ssh.KeyAlgoRSASHA512)
	sha1Signed, sha2Signed := newCert(rsaSHA1CA, nil), newCert(rsaSHA2CA, nil)
	sha1WrongPrincipal := newCert(rsaSHA1CA, func(c *ssh.Certificate) { c.ValidPrincipals = wrongPrincipal.ValidPrincipals })
	badSignature := func(cert *ssh.Certificate) *ssh.Certificate {
		bad, sig := *cert, *cert.Signature
		sig.Blob = slices.Clone(sig.Blob)
		sig.Blob[0] ^= 1
		bad.Signature = &sig
		return &bad
	}
	principals := func(ps ...string) func(*ssh.Certificate) {
		return func(c *ssh.Certificate) { c.ValidPrincipals = ps }
	}
	wildcard := newCert(ca, principals("*.example.com"))
	questionMark := newCert(ca, principals("h?st.example.com"))
	otherWildcard := newCert(ca, principals("*.other.com"))
	sha1Wildcard := newCert(rsaSHA1CA, principals("*.example.com"))
	wildcardExpired := newCert(ca, func(c *ssh.Certificate) {
		c.ValidPrincipals = wildcard.ValidPrincipals
		c.ValidBefore = expired.ValidBefore
	})
	wildcardCriticalOption := newCert(ca, func(c *ssh.Certificate) {
		c.ValidPrincipals = wildcard.ValidPrincipals
		c.CriticalOptions = criticalOption.CriticalOptions
	})
	wildcardUserCert := newCert(ca, func(c *ssh.Certificate) {
		c.ValidPrincipals = wildcard.ValidPrincipals
		c.CertType = ssh.UserCert
	})
	// SignCert refuses a certificate without principals; removing them after
	// signing breaks the signature, too.
	noPrincipals := *valid
	noPrincipals.ValidPrincipals = nil

	authority := func(key ssh.PublicKey) string { return knownHostsLine("@cert-authority *.example.com", key) }
	listed := knownHostsLine(host, hostPub)
	listedOther := knownHostsLine(host, otherKey.PublicKey())
	listedCA := knownHostsLine(host, caPub)
	trusted := authority(caPub)
	revokedKey := knownHostsLine("@revoked *", hostPub)
	revokedCA := knownHostsLine("@revoked *", caPub)
	revokedCert := knownHostsLine("@revoked *", valid)

	tests := []struct {
		name       string
		key        ssh.PublicKey
		knownHosts []string
		want       string // which key verified it, or the error reason
		certReason string // the certificate's error reason, if its plain key verified
	}{
		{"plain key, listed", hostPub, []string{listed}, VerifiedByPlainKey, ""},
		{"plain key, not listed", hostPub, nil, ErrReasonServerHostKeyUnknown, ""},
		{"plain key, other key listed", hostPub, []string{listedOther}, ErrReasonServerHostKeyMismatch, ""},
		{"plain key, not listed, @cert-authority line only", hostPub, []string{trusted}, ErrReasonServerHostKeyUnknown, ""},
		{"CA key as plain key, @cert-authority line only", caPub, []string{trusted}, ErrReasonServerHostKeyUnknown, ""},
		{"CA on a plain line, plain key not listed", valid, []string{listedCA}, ErrReasonServerHostKeyMismatch, ""},
		{"CA on a plain line, plain key listed", valid, []string{listedCA, listed}, VerifiedByPlainKey, ErrReasonServerHostCertificateCAUnknown},
		{"trusted CA, valid", valid, []string{trusted}, VerifiedByCAKey, ""},
		{"trusted CA, rsa-sha2-512 CA signature", sha2Signed, []string{authority(rsaSHA2CA.PublicKey())}, VerifiedByCAKey, ""},
		{"trusted CA, expired, plain key listed", expired, []string{trusted, listed}, VerifiedByPlainKey, ErrReasonServerHostCertificateExpired},
		{"trusted CA, expired, plain key not listed", expired, []string{trusted}, ErrReasonServerHostCertificateExpired, ""},
		{"trusted CA, expired, other plain key listed", expired, []string{trusted, listedOther}, ErrReasonServerHostCertificateExpired, ""},
		{"trusted CA, wrong principal, plain key not listed", wrongPrincipal, []string{trusted}, ErrReasonServerHostCertificatePrincipalNotListed, ""},
		{"trusted CA, user certificate, plain key not listed", userCert, []string{trusted}, ErrReasonServerHostCertificateOther, ""},
		{"trusted CA, ssh-rsa CA signature, plain key not listed", sha1Signed, []string{authority(rsaSHA1CA.PublicKey())}, ErrReasonServerHostCertificateSignatureAlgorithmDisallowed, ""},
		{"trusted CA, not yet valid, plain key not listed", notYetValid, []string{trusted}, ErrReasonServerHostCertificateNotYetValid, ""},
		{"trusted CA, unsupported critical option, plain key not listed", criticalOption, []string{trusted}, ErrReasonServerHostCertificateOther, ""},
		{"trusted CA, expired, unsupported critical option, plain key not listed", expiredCriticalOption, []string{trusted}, ErrReasonServerHostCertificateExpired, ""},
		{"trusted CA, expired, wrong principal, plain key not listed", expiredWrongPrincipal, []string{trusted}, ErrReasonServerHostCertificateExpired, ""},
		{"trusted CA, wrong principal, ssh-rsa CA signature, plain key not listed", sha1WrongPrincipal, []string{authority(rsaSHA1CA.PublicKey())}, ErrReasonServerHostCertificatePrincipalNotListed, ""},
		{"trusted CA, ssh-rsa CA signature, plain key listed", sha1Signed, []string{authority(rsaSHA1CA.PublicKey()), listed}, VerifiedByPlainKey, ErrReasonServerHostCertificateSignatureAlgorithmDisallowed},
		{"untrusted CA, plain key listed", valid, []string{listed}, VerifiedByPlainKey, ErrReasonServerHostCertificateCAUnknown},
		{"trusted CA, not yet valid, plain key listed", notYetValid, []string{trusted, listed}, VerifiedByPlainKey, ErrReasonServerHostCertificateNotYetValid},
		{"trusted CA, wrong principal, plain key listed", wrongPrincipal, []string{trusted, listed}, VerifiedByPlainKey, ErrReasonServerHostCertificatePrincipalNotListed},
		{"trusted CA, user certificate, plain key listed", userCert, []string{trusted, listed}, VerifiedByPlainKey, ErrReasonServerHostCertificateOther},
		{"trusted CA, unsupported critical option, plain key listed", criticalOption, []string{trusted, listed}, VerifiedByPlainKey, ErrReasonServerHostCertificateOther},
		{"trusted CA, expired, unsupported critical option, plain key listed", expiredCriticalOption, []string{trusted, listed}, VerifiedByPlainKey, ErrReasonServerHostCertificateExpired},
		{"trusted CA, expired, wrong principal, plain key listed", expiredWrongPrincipal, []string{trusted, listed}, VerifiedByPlainKey, ErrReasonServerHostCertificateExpired},
		{"trusted CA, wrong principal, ssh-rsa CA signature, plain key listed", sha1WrongPrincipal, []string{authority(rsaSHA1CA.PublicKey()), listed}, VerifiedByPlainKey, ErrReasonServerHostCertificatePrincipalNotListed},
		{"untrusted CA, expired, plain key listed", expired, []string{listed}, VerifiedByPlainKey, ErrReasonServerHostCertificateCAUnknown},
		{"untrusted CA, plain key not listed", valid, nil, ErrReasonServerHostKeyUnknown, ""},
		{"untrusted CA, other plain key listed", valid, []string{listedOther}, ErrReasonServerHostKeyMismatch, ""},
		{"trusted CA, key revoked", valid, []string{trusted, listed, revokedKey}, ErrReasonServerHostKeyRevoked, ""},
		{"trusted CA, CA revoked", valid, []string{trusted, listed, revokedCA}, ErrReasonServerHostKeyRevoked, ""},
		{"trusted CA, certificate revoked", valid, []string{trusted, listed, revokedCert}, ErrReasonServerHostKeyRevoked, ""},
		{"trusted CA, expired, key revoked", expired, []string{trusted, listed, revokedKey}, ErrReasonServerHostKeyRevoked, ""},
		{"untrusted CA, key revoked", valid, []string{listed, revokedKey}, ErrReasonServerHostKeyRevoked, ""},
		{"untrusted CA, CA revoked", valid, []string{listed, revokedCA}, ErrReasonServerHostKeyRevoked, ""},
		{"trusted CA, bad signature, plain key listed", badSignature(valid), []string{trusted, listed}, ErrReasonServerHostCertificateSignatureInvalid, ""},
		{"trusted CA, expired, bad signature, plain key listed", badSignature(expired), []string{trusted, listed}, ErrReasonServerHostCertificateSignatureInvalid, ""},
		{"untrusted CA, bad signature, plain key listed", badSignature(valid), []string{listed}, ErrReasonServerHostCertificateSignatureInvalid, ""},
		{"trusted CA, bad signature, key revoked", badSignature(valid), []string{trusted, listed, revokedKey}, ErrReasonServerHostCertificateSignatureInvalid, ""},
		// verifyCertSignature can't reach the signature check without principals.
		{"trusted CA, no principals, bad signature, plain key listed", &noPrincipals, []string{trusted, listed}, VerifiedByPlainKey, ErrReasonServerHostCertificatePrincipalNotListed},
		{"trusted CA, no principals, bad signature, plain key not listed", &noPrincipals, []string{trusted}, ErrReasonServerHostCertificatePrincipalNotListed, ""},
		{"trusted CA, wildcard principal", wildcard, []string{trusted}, VerifiedByCAKey, ""},
		{"trusted CA, ? principal", questionMark, []string{trusted}, VerifiedByCAKey, ""},
		{"trusted CA, other wildcard principal, plain key not listed", otherWildcard, []string{trusted}, ErrReasonServerHostCertificatePrincipalNotListed, ""},
		{"trusted CA, wildcard principal, ssh-rsa CA signature, plain key not listed", sha1Wildcard, []string{authority(rsaSHA1CA.PublicKey())}, ErrReasonServerHostCertificateSignatureAlgorithmDisallowed, ""},
		{"trusted CA, wildcard principal, key revoked", wildcard, []string{trusted, revokedKey}, ErrReasonServerHostKeyRevoked, ""},
		{"trusted CA, wildcard principal, certificate revoked", wildcard, []string{trusted, knownHostsLine("@revoked *", wildcard)}, ErrReasonServerHostKeyRevoked, ""},
		{"trusted CA, wildcard principal, expired, plain key not listed", wildcardExpired, []string{trusted}, ErrReasonServerHostCertificateExpired, ""},
		{"trusted CA, wildcard principal, unsupported critical option, plain key not listed", wildcardCriticalOption, []string{trusted}, ErrReasonServerHostCertificateOther, ""},
		{"CA on a plain line, wildcard principal, plain key not listed", wildcard, []string{listedCA}, ErrReasonServerHostKeyMismatch, ""},
		{"trusted CA, wildcard principal, user certificate, plain key not listed", wildcardUserCert, []string{trusted}, ErrReasonServerHostCertificateOther, ""},
	}
	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb, isCA := loadKnownHosts(t, tt.knownHosts)
			lines := knownHostsLines(cb, isCA, host+":22", remote)
			got, certErr, err := verifyHostKey(cb, isCA, lines, defaultCASignatureAlgorithms, host+":22", remote, tt.key)
			if err != nil {
				got = classifyHostKeyVerifyError(err)
			}
			certReason := ""
			if certErr != nil {
				certReason = classifyHostKeyVerifyError(certErr)
			}
			if got != tt.want || certReason != tt.certReason {
				t.Errorf("verifyHostKey() = %q, %v, %v, want %q, %q", got, certErr, err, tt.want, tt.certReason)
			}
		})
	}
}

func TestVerifyHostKeyCASignatureAlgorithms(t *testing.T) {
	const host = "host.example.com"
	hostPub := newEd25519Signer(t).PublicKey()
	newCert := func(authority ssh.Signer) *ssh.Certificate {
		t.Helper()
		cert := &ssh.Certificate{Key: hostPub, CertType: ssh.HostCert, ValidPrincipals: []string{host}, ValidBefore: ssh.CertTimeInfinity}
		if err := cert.SignCert(rand.Reader, authority); err != nil {
			t.Fatal(err)
		}
		return cert
	}
	edCA, rsaSHA1CA := newEd25519Signer(t), newRSASigner(t, ssh.KeyAlgoRSA)
	edSigned, sha1Signed := newCert(edCA), newCert(rsaSHA1CA)
	authority := func(key ssh.PublicKey) string { return knownHostsLine("@cert-authority "+host, key) }
	listed := knownHostsLine(host, hostPub)

	tests := []struct {
		name       string
		algorithms []string
		key        ssh.PublicKey
		knownHosts []string
		want       string // which key verified it, or the error reason
		certReason string // the certificate's error reason, if its plain key verified
	}{
		{"ssh-rsa, default, plain key not listed", defaultCASignatureAlgorithms, sha1Signed, []string{authority(rsaSHA1CA.PublicKey())},
			ErrReasonServerHostCertificateSignatureAlgorithmDisallowed, ""},
		{"ssh-rsa, listed", []string{ssh.KeyAlgoED25519, ssh.KeyAlgoRSA}, sha1Signed, []string{authority(rsaSHA1CA.PublicKey())},
			VerifiedByCAKey, ""},
		{"ssh-ed25519, not listed, plain key listed", []string{ssh.KeyAlgoRSASHA512}, edSigned, []string{authority(edCA.PublicKey()), listed},
			VerifiedByPlainKey, ErrReasonServerHostCertificateSignatureAlgorithmDisallowed},
	}
	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb, isCA := loadKnownHosts(t, tt.knownHosts)
			lines := knownHostsLines(cb, isCA, host+":22", remote)
			got, certErr, err := verifyHostKey(cb, isCA, lines, tt.algorithms, host+":22", remote, tt.key)
			if err != nil {
				got = classifyHostKeyVerifyError(err)
			}
			certReason := ""
			if certErr != nil {
				certReason = classifyHostKeyVerifyError(certErr)
			}
			if got != tt.want || certReason != tt.certReason {
				t.Errorf("verifyHostKey() = %q, %v, %v, want %q, %q", got, certErr, err, tt.want, tt.certReason)
			}
		})
	}
}

func TestDecidingLine(t *testing.T) {
	const host = "host.example.com"
	hostKey, ca := newEd25519Signer(t), newEd25519Signer(t)
	hostPub, caPub := hostKey.PublicKey(), ca.PublicKey()
	newCert := func(validBefore uint64) *ssh.Certificate {
		t.Helper()
		cert := &ssh.Certificate{Key: hostPub, CertType: ssh.HostCert, ValidPrincipals: []string{host}, ValidBefore: validBefore}
		if err := cert.SignCert(rand.Reader, ca); err != nil {
			t.Fatal(err)
		}
		return cert
	}
	valid, expired := newCert(ssh.CertTimeInfinity), newCert(uint64(time.Now().Add(-time.Hour).Unix()))
	badSignature, sig := *valid, *valid.Signature
	sig.Blob = slices.Clone(sig.Blob)
	sig.Blob[0] ^= 1
	badSignature.Signature = &sig

	listed := knownHostsLine(host, hostPub)
	listedOther := knownHostsLine(host, newEd25519Signer(t).PublicKey())
	trusted := knownHostsLine("@cert-authority "+host, caPub)

	tests := []struct {
		name       string
		key        ssh.PublicKey
		knownHosts []string
		want       int // line number, 0 for none
	}{
		{"verified through a CA, two @cert-authority lines", valid, []string{listed, trusted, trusted}, 2},
		{"verified by the plain key, earlier @cert-authority line with it", hostPub, []string{knownHostsLine("@cert-authority "+host, hostPub), listed}, 2},
		{"expired certificate, fallback to the plain key", expired, []string{trusted, listed}, 2},
		{"mismatch, later @cert-authority line", hostPub, []string{listedOther, knownHostsLine(host, caPub), trusted}, 2},
		{"key revoked", valid, []string{trusted, listed, knownHostsLine("@revoked *", hostPub)}, 3},
		{"CA revoked", valid, []string{trusted, listed, knownHostsLine("@revoked *", caPub)}, 3},
		{"expired certificate, trusted CA, plain key not listed", expired, []string{listedOther, trusted}, 2},
		{"unknown host", hostPub, nil, 0},
		{"unknown CA, plain key not listed", valid, nil, 0},
		{"bad CA signature", &badSignature, []string{trusted, listed}, 0},
	}
	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb, isCA := loadKnownHosts(t, tt.knownHosts)
			lines := knownHostsLines(cb, isCA, host+":22", remote)
			verifiedBy, _, err := verifyHostKey(cb, isCA, lines, defaultCASignatureAlgorithms, host+":22", remote, tt.key)
			line, ok := decidingLine(lines, isCA, tt.key, verifiedBy, err)
			if line.Line != tt.want || ok != (tt.want != 0) {
				t.Errorf("decidingLine() = %d, %t, want %d (verifyHostKey: %q, %v)", line.Line, ok, tt.want, verifiedBy, err)
			}
		})
	}

	t.Run("without IsCertAuthority", func(t *testing.T) {
		cb, isCA := loadKnownHosts(t, []string{listed})
		lines := knownHostsLines(cb, isCA, host+":22", remote)
		if line, ok := decidingLine(lines, nil, hostPub, VerifiedByPlainKey, nil); ok {
			t.Errorf("decidingLine() = %d, want none", line.Line)
		}
	})
}

func TestOrderHostKeyAlgorithms(t *testing.T) {
	const host = "host.example.com"
	ed, edOther, ca := newEd25519Signer(t).PublicKey(), newEd25519Signer(t).PublicKey(), newEd25519Signer(t).PublicKey()
	rsaKey := newRSASigner(t, ssh.KeyAlgoRSASHA512).PublicKey()
	ecdsa384, err := ssh.NewSignerFromKey(mustECDSA(t, elliptic.P384()))
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{Key: ed, CertType: ssh.HostCert, ValidPrincipals: []string{host}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, newEd25519Signer(t)); err != nil {
		t.Fatal(err)
	}

	certs := defaultHostKeyAlgorithms[:6]
	rsaFirst := []string{
		ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
		ssh.CertAlgoED25519v01, ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01,
		ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	}
	tests := []struct {
		name       string
		algorithms []string // nil for defaultHostKeyAlgorithms
		knownHosts []string
		want       []string
	}{
		{"no lines", nil, nil, defaultHostKeyAlgorithms},
		{"plain ed25519", nil, []string{knownHostsLine(host, ed)}, defaultHostKeyAlgorithms},
		{"plain ed25519 and plain rsa", nil, []string{knownHostsLine(host, ed), knownHostsLine(host, rsaKey)}, defaultHostKeyAlgorithms},
		{"plain rsa", nil, []string{knownHostsLine(host, rsaKey)}, rsaFirst},
		{"plain ecdsa nistp384", nil, []string{knownHostsLine(host, ecdsa384.PublicKey())}, []string{
			ssh.CertAlgoECDSA384v01, ssh.KeyAlgoECDSA384,
			ssh.CertAlgoED25519v01, ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA521v01, ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01,
			ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
		}},
		{"@cert-authority line only", nil, []string{knownHostsLine("@cert-authority "+host, ca)}, defaultHostKeyAlgorithms},
		{"@cert-authority line and plain rsa", nil, []string{knownHostsLine("@cert-authority "+host, ca), knownHostsLine(host, rsaKey)}, append(slices.Clone(certs),
			ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521)},
		{"plain ed25519 revoked, plain rsa", nil, []string{knownHostsLine(host, ed), knownHostsLine("@revoked *", ed), knownHostsLine(host, rsaKey)}, rsaFirst},
		{"first plain ed25519 revoked, a later one not, plain rsa", nil, []string{
			knownHostsLine(host, ed), knownHostsLine(host, edOther), knownHostsLine("@revoked *", ed), knownHostsLine(host, rsaKey),
		}, rsaFirst},
		{"plain line holding a certificate", nil, []string{knownHostsLine(host, cert)}, defaultHostKeyAlgorithms},
		{"set list, plain ed25519", []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoED25519}, []string{knownHostsLine(host, ed)},
			[]string{ssh.KeyAlgoED25519, ssh.KeyAlgoRSASHA512}},
		{"set list with ssh-rsa, plain rsa", []string{ssh.KeyAlgoED25519, ssh.KeyAlgoRSA, ssh.CertAlgoRSAv01}, []string{knownHostsLine(host, rsaKey)},
			[]string{ssh.KeyAlgoRSA, ssh.CertAlgoRSAv01, ssh.KeyAlgoED25519}},
		{"set list with an ML-DSA certificate, @cert-authority line", []string{ssh.KeyAlgoED25519, ssh.CertAlgoMLDSA65v01Go}, []string{knownHostsLine("@cert-authority "+host, ca)},
			[]string{ssh.CertAlgoMLDSA65v01Go, ssh.KeyAlgoED25519}},
	}
	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb, isCA := loadKnownHosts(t, tt.knownHosts)
			revoked := func(k ssh.PublicKey) bool {
				_, ok := errors.AsType[*knownhosts.RevokedError](cb(host+":22", remote, k))
				return ok
			}
			algorithms := tt.algorithms
			if algorithms == nil {
				algorithms = defaultHostKeyAlgorithms
			}
			got := orderHostKeyAlgorithms(algorithms, knownHostsLines(cb, isCA, host+":22", remote), isCA, revoked)
			if !slices.Equal(got, tt.want) {
				t.Errorf("orderHostKeyAlgorithms() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestHostKeyTypes fails when a fork rebase adds a host key algorithm the config
// accepts but orderHostKeyAlgorithms can't place.
func TestHostKeyTypes(t *testing.T) {
	for _, alg := range slices.Concat(ssh.SupportedAlgorithms().HostKeys, ssh.InsecureAlgorithms().HostKeys) {
		if _, ok := hostKeyTypes[alg]; !ok {
			t.Errorf("no key type for %s", alg)
		}
	}
}

func mustECDSA(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
