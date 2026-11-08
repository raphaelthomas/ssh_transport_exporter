package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
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
		{"certificate invalid", fmt.Errorf("%w: %w", errHostCertificateInvalid, errors.New("ssh: cert has expired")), ErrReasonServerHostCertificateInvalid},
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

// TestVerifyHostKey checks that verifyHostKey decides like OpenSSH. It also
// fails if x/crypto changes behavior verifyHostKey relies on:
//   - a CA key passes as a host key if its @cert-authority line matches;
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
	rsaSHA1CA, rsaSHA2CA := newRSASigner(t, ssh.KeyAlgoRSA), newRSASigner(t, ssh.KeyAlgoRSASHA512)
	sha1Signed, sha2Signed := newCert(rsaSHA1CA, nil), newCert(rsaSHA2CA, nil)
	badSignature := func(cert *ssh.Certificate) *ssh.Certificate {
		bad, sig := *cert, *cert.Signature
		sig.Blob = slices.Clone(sig.Blob)
		sig.Blob[0] ^= 1
		bad.Signature = &sig
		return &bad
	}
	// Removing the principals after signing breaks the signature, too.
	noPrincipals := *valid
	noPrincipals.ValidPrincipals = nil

	line := func(prefix string, key ssh.PublicKey) string {
		return prefix + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	}
	authority := func(key ssh.PublicKey) string { return line("@cert-authority *.example.com", key) }
	listed := line(host, hostPub)
	listedOther := line(host, otherKey.PublicKey())
	trusted := authority(caPub)
	revokedKey := line("@revoked *", hostPub)
	revokedCA := line("@revoked *", caPub)
	revokedCert := line("@revoked *", valid)

	tests := []struct {
		name       string
		key        ssh.PublicKey
		knownHosts []string
		want       string // empty when verified
	}{
		{"plain key, listed", hostPub, []string{listed}, ""},
		{"plain key, not listed", hostPub, nil, ErrReasonServerHostKeyUnknown},
		{"plain key, other key listed", hostPub, []string{listedOther}, ErrReasonServerHostKeyMismatch},
		{"trusted CA, valid", valid, []string{trusted}, ""},
		{"trusted CA, rsa-sha2-512 CA signature", sha2Signed, []string{authority(rsaSHA2CA.PublicKey())}, ""},
		{"trusted CA, expired, plain key listed", expired, []string{trusted, listed}, ""},
		{"trusted CA, expired, plain key not listed", expired, []string{trusted}, ErrReasonServerHostCertificateInvalid},
		{"trusted CA, expired, other plain key listed", expired, []string{trusted, listedOther}, ErrReasonServerHostCertificateInvalid},
		{"trusted CA, wrong principal, plain key not listed", wrongPrincipal, []string{trusted}, ErrReasonServerHostCertificateInvalid},
		{"trusted CA, user certificate, plain key not listed", userCert, []string{trusted}, ErrReasonServerHostCertificateInvalid},
		{"trusted CA, ssh-rsa CA signature, plain key not listed", sha1Signed, []string{authority(rsaSHA1CA.PublicKey())}, ErrReasonServerHostCertificateInvalid},
		{"trusted CA, ssh-rsa CA signature, plain key listed", sha1Signed, []string{authority(rsaSHA1CA.PublicKey()), listed}, ""},
		{"untrusted CA, plain key listed", valid, []string{listed}, ""},
		{"untrusted CA, plain key not listed", valid, nil, ErrReasonServerHostKeyUnknown},
		{"untrusted CA, other plain key listed", valid, []string{listedOther}, ErrReasonServerHostKeyMismatch},
		{"trusted CA, key revoked", valid, []string{trusted, listed, revokedKey}, ErrReasonServerHostKeyRevoked},
		{"trusted CA, CA revoked", valid, []string{trusted, listed, revokedCA}, ErrReasonServerHostKeyRevoked},
		{"trusted CA, certificate revoked", valid, []string{trusted, listed, revokedCert}, ErrReasonServerHostKeyRevoked},
		{"trusted CA, expired, key revoked", expired, []string{trusted, listed, revokedKey}, ErrReasonServerHostKeyRevoked},
		{"untrusted CA, key revoked", valid, []string{listed, revokedKey}, ErrReasonServerHostKeyRevoked},
		{"untrusted CA, CA revoked", valid, []string{listed, revokedCA}, ErrReasonServerHostKeyRevoked},
		{"trusted CA, bad signature, plain key listed", badSignature(valid), []string{trusted, listed}, ErrReasonServerHostCertificateSignatureInvalid},
		{"trusted CA, expired, bad signature, plain key listed", badSignature(expired), []string{trusted, listed}, ErrReasonServerHostCertificateSignatureInvalid},
		{"untrusted CA, bad signature, plain key listed", badSignature(valid), []string{listed}, ErrReasonServerHostCertificateSignatureInvalid},
		{"trusted CA, bad signature, key revoked", badSignature(valid), []string{trusted, listed, revokedKey}, ErrReasonServerHostCertificateSignatureInvalid},
		// verifyCertSignature can't reach the signature check without principals.
		{"trusted CA, no principals, bad signature, plain key listed", &noPrincipals, []string{trusted, listed}, ""},
	}
	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "known_hosts")
			if err := os.WriteFile(path, []byte(strings.Join(tt.knownHosts, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cb, err := knownhosts.New(path)
			if err != nil {
				t.Fatal(err)
			}
			err = verifyHostKey(cb, host+":22", remote, tt.key)
			got := ""
			if err != nil {
				got = classifyHostKeyVerifyError(err)
			}
			if got != tt.want {
				t.Errorf("verifyHostKey() = %v (%q), want %q", err, got, tt.want)
			}
		})
	}
}
