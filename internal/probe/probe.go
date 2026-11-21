// Package probe implements the SSH transport-layer (RFC 4253) probe
package probe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	xknownhosts "golang.org/x/crypto/ssh/knownhosts"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/knownhosts"
	"github.com/raphaelthomas/ssh_transport_exporter/internal/match"
	"github.com/raphaelthomas/ssh_transport_exporter/internal/profile"
)

// Phases a probe can fail at, reported as Result.ErrorPhase.
const (
	ErrPhaseDNSLookup       = "dns_lookup"
	ErrPhaseTCPConnect      = "tcp_connect"
	ErrPhaseVersionExchange = "version_exchange"
	ErrPhaseKeyExchange     = "key_exchange"
)

// Why a probe failed, reported as Result.ErrorReason.
const (
	ErrReasonConnectionRefused                                 = "connection_refused"
	ErrReasonNoRouteToHost                                     = "no_route_to_host"
	ErrReasonNetworkUnreachable                                = "network_unreachable"
	ErrReasonDNSFailure                                        = "dns_failure"
	ErrReasonConnectionReset                                   = "connection_reset"
	ErrReasonServerHostKeyUnknown                              = "server_host_key_unknown"
	ErrReasonServerHostKeyMismatch                             = "server_host_key_mismatch"
	ErrReasonServerHostKeyRevoked                              = "server_host_key_revoked"
	ErrReasonServerHostKeyRejected                             = "server_host_key_rejected"
	ErrReasonServerHostCertificateCAUnknown                    = "server_host_certificate_ca_unknown"
	ErrReasonServerHostCertificateNotYetValid                  = "server_host_certificate_not_yet_valid"
	ErrReasonServerHostCertificateExpired                      = "server_host_certificate_expired"
	ErrReasonServerHostCertificatePrincipalNotListed           = "server_host_certificate_principal_not_listed"
	ErrReasonServerHostCertificateSignatureAlgorithmDisallowed = "server_host_certificate_signature_algorithm_disallowed"
	ErrReasonServerHostCertificateOther                        = "server_host_certificate_other"
	ErrReasonServerHostCertificateSignatureInvalid             = "server_host_certificate_signature_invalid"
	ErrReasonTimeout                                           = "timeout"
	ErrReasonCanceled                                          = "canceled"
	ErrReasonUserAuthReached                                   = "user_auth_reached"
	ErrReasonNoCommonKex                                       = "no_common_kex_algorithm"
	ErrReasonNoCommonHostKey                                   = "no_common_host_key_algorithm"
	ErrReasonNoCommonCipher                                    = "no_common_cipher"
	ErrReasonNoCommonMAC                                       = "no_common_mac"
	ErrReasonNoCommonAlgorithm                                 = "no_common_algorithm"
	ErrReasonOther                                             = "other"
)

// Which key listed in known_hosts verified the server host key, reported as
// Result.ServerHostKeyVerifiedBy.
const (
	VerifiedByCAKey    = "ca_key"
	VerifiedByPlainKey = "plain_key"
)

// Result is the outcome of one probe against one target.
type Result struct {
	// DNSLookup reports whether the target is a hostname; IP literal targets
	// have no DNS lookup phase.
	DNSLookup         bool
	DNSLookupSuccess  bool
	DNSLookupDuration time.Duration

	TCPConnectSuccess  bool
	TCPConnectDuration time.Duration
	TCPMSS             int

	// ServerIdentification is zero unless the version exchange succeeded and the
	// string could be parsed.
	ServerIdentification ServerIdentification

	VersionExchangeSuccess  bool
	VersionExchangeDuration time.Duration

	KeyExchangeSuccess  bool
	KeyExchangeDuration time.Duration
	KEXAlgorithm        string

	ServerHostKeyVerifySuccess bool
	ServerHostKeyAlgorithm     string
	// ServerHostKeyVerifiedBy is VerifiedByCAKey or VerifiedByPlainKey, empty
	// unless verification succeeded.
	ServerHostKeyVerifiedBy string
	// ServerHostKeyKnownHostsFile and ServerHostKeyKnownHostsLine name the
	// known_hosts line that decided the verification, like OpenSSH's "Found key
	// in" and "Offending key in"; the line is 0 for none.
	ServerHostKeyKnownHostsFile string
	ServerHostKeyKnownHostsLine int
	// ServerHostCertificateErrorReason is the error reason of a host certificate
	// whose plain key verified, e.g. ErrReasonServerHostCertificateExpired.
	ServerHostCertificateErrorReason string

	// ServerHostCertificate reports whether the server presented a host
	// certificate, verified or not. Its validity period is in Unix seconds;
	// ValidBefore is ssh.CertTimeInfinity for no expiry.
	ServerHostCertificate            bool
	ServerHostCertificateValidAfter  uint64
	ServerHostCertificateValidBefore uint64

	EncryptionClientToServer string
	EncryptionServerToClient string
	// Negotiated MACs, empty for AEAD ciphers, which need none
	MACClientToServer string
	MACServerToClient string

	ErrorPhase  string
	ErrorReason string

	Duration time.Duration
	Success  bool
}

// errAbort is returned from TransportReadyCallback to abort the connection
// after the transport layer is ready, but before user authentication.
var errAbort = errors.New("probe: aborting before auth by design")

// KnownHosts looks up known_hosts lines and checks host keys against them, like
// *knownhosts.DB.
type KnownHosts interface {
	// Lines returns the lines that match addr, host:port, @revoked ones aside,
	// with CertAuthority and Revoked set.
	Lines(addr string) []knownhosts.Line
	// Check verifies key for addr like x/crypto's knownhosts callback: a host
	// certificate passes only through a matching @cert-authority line.
	Check(addr string, key ssh.PublicKey) error
}

// noKnownHosts lists no line and rejects every host key.
type noKnownHosts struct{}

func (noKnownHosts) Lines(string) []knownhosts.Line { return nil }

func (noKnownHosts) Check(string, ssh.PublicKey) error {
	return errors.New("no known_hosts configured")
}

// Options controls how a probe's SSH client connection is configured.
type Options struct {
	// KnownHosts holds the known_hosts lines the server's host key is checked
	// against. Used concurrently by probes. Nil fails verification.
	KnownHosts KnownHosts

	// Profile is how the probe behaves: its algorithm lists and host key
	// verification switches. Nil uses profile.Default(). Run doesn't change it.
	Profile *profile.Profile

	StripServerIdentificationComments bool

	Logger *slog.Logger
}

// defaultProfile is the profile Run uses for nil Options.Profile.
var defaultProfile = profile.Default()

// hostKeyResult moves the verification result off the goroutine that runs
// HostKeyCallback; only the first key exchange is recorded.
type hostKeyResult struct {
	verified               bool
	verifiedBy             string
	certificateErrorReason string
	errorReason            string
	line                   xknownhosts.KnownKey
	cert                   *ssh.Certificate // nil for a plain host key
}

// identificationWatcher records the server's identification string and when it
// was read, which ends the version exchange (RFC 4253, section 4.2). It sees the
// string even when the key exchange fails afterwards.
type identificationWatcher struct {
	net.Conn
	line           []byte
	identification []byte // without the CR LF
	received       atomic.Pointer[time.Time]
}

func (w *identificationWatcher) Read(p []byte) (int, error) {
	n, err := w.Conn.Read(p)
	if w.received.Load() == nil {
		w.scan(p[:n])
	}
	return n, err
}

// scan looks for the end of the line starting with "SSH-"; the server may send
// other lines before it.
func (w *identificationWatcher) scan(b []byte) {
	for _, c := range b {
		if c == '\n' {
			if bytes.HasPrefix(w.line, []byte("SSH-")) {
				w.identification = bytes.TrimSuffix(w.line, []byte{'\r'})
				now := time.Now()
				w.received.Store(&now)
				return
			}
			w.line = w.line[:0]
			continue
		}
		// Capped past the limit, so an overlong line still fails parsing once
		// the CR is trimmed.
		if len(w.line) < maxIdentificationLen+len("\r\n") {
			w.line = append(w.line, c)
		}
	}
}

// Run probes target and reports any failure in the returned Result.
func Run(ctx context.Context, target string, opts Options) (result Result) {
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	knownHosts := opts.KnownHosts
	if knownHosts == nil {
		knownHosts = noKnownHosts{}
	}

	// ControlContext runs after name resolution, before each connect attempt. Using it
	// instead of a separate lookup keeps the dialer's address fallback and dual-stack racing.
	var connectStart atomic.Pointer[time.Time]
	dialer := net.Dialer{
		ControlContext: func(context.Context, string, string, syscall.RawConn) error {
			now := time.Now()
			connectStart.CompareAndSwap(nil, &now)
			return nil
		},
	}
	dialStart := time.Now()
	rawConn, err := dialer.DialContext(ctx, "tcp", target)
	dialEnd := time.Now()

	result.DNSLookup = isHostname(target)
	attemptStart := connectStart.Load()
	connectFrom := dialStart
	if attemptStart != nil {
		connectFrom = *attemptStart
		if result.DNSLookup {
			result.DNSLookupSuccess = true
			result.DNSLookupDuration = attemptStart.Sub(dialStart)
		}
	}

	if err != nil {
		result.ErrorPhase = ErrPhaseTCPConnect
		if result.DNSLookup && !result.DNSLookupSuccess {
			result.ErrorPhase = ErrPhaseDNSLookup
		}
		result.ErrorReason = classifyDialError(ctx, err)
		return result
	}
	defer func() {
		_ = rawConn.Close()
	}()

	result.TCPConnectSuccess = true
	result.TCPConnectDuration = dialEnd.Sub(connectFrom)

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		if mss, err := tcpNegotiatedMSS(tcpConn); err == nil {
			result.TCPMSS = mss
		} else if logger.Enabled(ctx, slog.LevelDebug) {
			logger.Debug("failed to read negotiated TCP MSS", "target", target, "error", err)
		}
	}

	// Like OpenSSH, after the connect: known_hosts decides which host key to ask for.
	lines := knownHosts.Lines(target)
	p := &defaultProfile
	if opts.Profile != nil {
		p = opts.Profile
	}
	hostKeyAlgorithms := p.HostKeyAlgorithms
	if p.OrderByKnownHosts {
		hostKeyAlgorithms = orderHostKeyAlgorithms(hostKeyAlgorithms, lines)
	}
	forceCloseOnCtxDone := context.AfterFunc(ctx, func() {
		_ = rawConn.Close()
	})
	defer forceCloseOnCtxDone()

	versionExchangeStart := time.Now()
	conn := &identificationWatcher{Conn: rawConn}
	hostKeyResultCh := make(chan hostKeyResult, 1)

	clientConfig := &ssh.ClientConfig{
		User:              "ssh_transport_exporter",
		Auth:              nil,
		Ciphers:           p.Ciphers,
		KeyExchanges:      p.KeyExchanges,
		MACs:              p.MACs,
		HostKeyAlgorithms: hostKeyAlgorithms,
		HostKeyCallback: func(hostname string, _ net.Addr, key ssh.PublicKey) error {
			verifiedBy, certErr, err := verifyHostKey(knownHosts, lines, p, hostname, key)
			hk := hostKeyResult{verified: err == nil, verifiedBy: verifiedBy}
			hk.line, _ = decidingLine(lines, p.CALinesMatchPlainKeys, key, verifiedBy, err)
			hk.cert, _ = key.(*ssh.Certificate)
			if certErr != nil {
				hk.certificateErrorReason = classifyHostKeyVerifyError(certErr)
			}
			if err != nil {
				hk.errorReason = classifyHostKeyVerifyError(err)
				logger.Debug("host key verification failed", "target", target, "reason", hk.errorReason, "error", err)
			}
			select {
			case hostKeyResultCh <- hk:
			default:
			}
			// Continue even if verification failed, so TransportReadyCallback can record the
			// negotiated algorithms; it aborts before authentication either way.
			return nil
		},
		TransportReadyCallback: func(tc *ssh.ClientTransportReadyContext) error {
			if received := conn.received.Load(); received != nil {
				result.KeyExchangeDuration = time.Since(*received)
			}
			result.KEXAlgorithm = tc.Algorithms.KeyExchange
			result.ServerHostKeyAlgorithm = tc.Algorithms.HostKey
			result.EncryptionClientToServer = tc.Algorithms.Write.Cipher
			result.EncryptionServerToClient = tc.Algorithms.Read.Cipher
			result.MACClientToServer = tc.Algorithms.Write.MAC
			result.MACServerToClient = tc.Algorithms.Read.MAC

			return errAbort
		},
	}

	_, _, _, handshakeErr := ssh.NewClientConn(conn, target, clientConfig)

	if received := conn.received.Load(); received != nil {
		result.VersionExchangeSuccess = true
		result.VersionExchangeDuration = received.Sub(versionExchangeStart)

		ident, err := parseServerIdentification(conn.identification)
		switch {
		case err != nil:
			logger.Debug("dropping unparsable server identification string", "target", target, "identification", string(conn.identification), "error", err)
		case opts.StripServerIdentificationComments:
			result.ServerIdentification = ident.withoutComments()
		default:
			result.ServerIdentification = ident
		}
	}

	switch {
	case errors.Is(handshakeErr, errAbort):
		result.KeyExchangeSuccess = true
	case handshakeErr == nil:
		// Unreachable while TransportReadyCallback returns errAbort.
		logger.Error("probe reached user authentication instead of aborting; x/crypto/ssh behavior may have changed", "target", target)
		result.ErrorPhase = ErrPhaseKeyExchange
		result.ErrorReason = ErrReasonUserAuthReached
	default:
		result.ErrorPhase = ErrPhaseKeyExchange
		if !result.VersionExchangeSuccess {
			result.ErrorPhase = ErrPhaseVersionExchange
		}
		result.ErrorReason = classifyKexError(ctx, handshakeErr)
		if negErr, ok := errors.AsType[*ssh.AlgorithmNegotiationError](handshakeErr); ok {
			logger.Debug("no common algorithm with server", "target", target, "what", negErr.What, "offered", negErr.SupportedAlgorithms, "server_offered", negErr.RequestedAlgorithms)
		}
	}

	// A failed host key check outranks a key exchange that failed after it.
	select {
	case hk := <-hostKeyResultCh:
		result.ServerHostKeyVerifySuccess = hk.verified
		result.ServerHostKeyVerifiedBy = hk.verifiedBy
		result.ServerHostCertificateErrorReason = hk.certificateErrorReason
		result.ServerHostKeyKnownHostsFile = hk.line.Filename
		result.ServerHostKeyKnownHostsLine = hk.line.Line
		if hk.cert != nil {
			result.ServerHostCertificate = true
			result.ServerHostCertificateValidAfter = hk.cert.ValidAfter
			result.ServerHostCertificateValidBefore = hk.cert.ValidBefore
		}
		if !hk.verified {
			result.ErrorPhase = ErrPhaseKeyExchange
			result.ErrorReason = hk.errorReason
		}
	default:
	}

	result.Success = result.ErrorPhase == "" && result.KeyExchangeSuccess && result.ServerHostKeyVerifySuccess
	return result
}

func isHostname(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	_, err = netip.ParseAddr(host)
	return err != nil
}

// Why an SSH host certificate didn't verify through its CA.
var (
	errHostCertificateCAUnknown                    = errors.New("host certificate CA is not trusted for the host")
	errHostCertificateNotYetValid                  = errors.New("host certificate is not yet valid")
	errHostCertificateExpired                      = errors.New("host certificate has expired")
	errHostCertificatePrincipalNotListed           = errors.New("host is not a listed principal of the host certificate")
	errHostCertificateSignatureAlgorithmDisallowed = errors.New("host certificate CA signature algorithm is not allowed")
	errHostCertificateInvalid                      = errors.New("host certificate from a trusted CA is invalid")
)

// errHostCertificateSignatureInvalid marks an SSH host certificate whose CA signature doesn't verify.
var errHostCertificateSignatureInvalid = errors.New("host certificate CA signature does not verify")

// hostKeyTypes maps each host key algorithm x/crypto accepts to the type of the
// key it verifies with; a certificate algorithm to that of the key inside it.
var hostKeyTypes = map[string]string{
	ssh.CertAlgoED25519v01:   ssh.KeyAlgoED25519,
	ssh.CertAlgoECDSA256v01:  ssh.KeyAlgoECDSA256,
	ssh.CertAlgoECDSA384v01:  ssh.KeyAlgoECDSA384,
	ssh.CertAlgoECDSA521v01:  ssh.KeyAlgoECDSA521,
	ssh.CertAlgoRSASHA512v01: ssh.KeyAlgoRSA,
	ssh.CertAlgoRSASHA256v01: ssh.KeyAlgoRSA,
	ssh.CertAlgoRSAv01:       ssh.KeyAlgoRSA,
	ssh.CertAlgoMLDSA44v01Go: ssh.KeyAlgoMLDSA44,
	ssh.CertAlgoMLDSA65v01Go: ssh.KeyAlgoMLDSA65,
	ssh.CertAlgoMLDSA87v01Go: ssh.KeyAlgoMLDSA87,
	ssh.KeyAlgoED25519:       ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256:      ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384:      ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521:      ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512:     ssh.KeyAlgoRSA,
	ssh.KeyAlgoRSASHA256:     ssh.KeyAlgoRSA,
	ssh.KeyAlgoRSA:           ssh.KeyAlgoRSA,
	ssh.KeyAlgoMLDSA44:       ssh.KeyAlgoMLDSA44,
	ssh.KeyAlgoMLDSA65:       ssh.KeyAlgoMLDSA65,
	ssh.KeyAlgoMLDSA87:       ssh.KeyAlgoMLDSA87,
}

// orderHostKeyAlgorithms orders algorithms like OpenSSH's order_hostkeyalgs:
// those whose key type lines lists for the host come first.
func orderHostKeyAlgorithms(algorithms []string, lines []knownhosts.Line) []string {
	// Like OpenSSH, only the first plain line of a type counts, and only if its
	// key isn't revoked. A line holding a certificate has no plain key type.
	listed := make(map[string]bool)
	ca := false
	for _, l := range lines {
		if l.CertAuthority {
			ca = true
			continue
		}
		if _, seen := listed[l.Key.Type()]; !seen {
			listed[l.Key.Type()] = !l.Revoked
		}
	}
	if len(algorithms) == 0 || listed[hostKeyTypes[algorithms[0]]] {
		return algorithms
	}
	var first, last []string
	for _, alg := range algorithms {
		if (ca && strings.Contains(alg, "-cert-v01@")) || listed[hostKeyTypes[alg]] {
			first = append(first, alg)
		} else {
			last = append(last, alg)
		}
	}
	return append(first, last...)
}

// verifyHostKey checks key against known_hosts like OpenSSH's check_host_key and
// returns which listed key verified it and, for the plain key inside a host
// certificate, why the certificate didn't. An invalid SSH host certificate falls
// back to the host key inside it, if p.PlainKeyFallback. A bad CA signature, or
// a @revoked key or CA, fails without fallback. lines are kh's for hostname.
func verifyHostKey(kh KnownHosts, lines []knownhosts.Line, p *profile.Profile, hostname string, key ssh.PublicKey) (verifiedBy string, certificateErr, err error) {
	check := func(k ssh.PublicKey) error { return kh.Check(hostname, k) }

	listed := func(k ssh.PublicKey, ca bool) bool {
		_, ok := firstLine(lines, k, func(l knownhosts.Line) bool { return l.CertAuthority == ca })
		return ok
	}
	// OpenSSH looks a plain host key up on plain lines only, x/crypto on all.
	checkPlain := func(k ssh.PublicKey) error {
		err := check(k)
		if _, ok := errors.AsType[*xknownhosts.KeyError](err); p.CALinesMatchPlainKeys || (err != nil && !ok) {
			return err
		}
		if err == nil && listed(k, false) {
			return nil
		}
		keyErr := &xknownhosts.KeyError{}
		for _, l := range lines {
			if !l.CertAuthority {
				keyErr.Want = append(keyErr.Want, l.KnownKey)
			}
		}
		return keyErr
	}

	// Check a plain host key directly.
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		if err := checkPlain(key); err != nil {
			return "", nil, err
		}
		return VerifiedByPlainKey, nil, nil
	}
	// OpenSSH rejects a bad CA signature when parsing the key, before known_hosts.
	if err := verifyCertSignature(cert); err != nil {
		return "", nil, err
	}
	// Run dials hostname, so it has a port.
	host, _, _ := net.SplitHostPort(hostname)
	certErr := check(cert)
	// Checking the CA as a host key tells whether it is @revoked or listed, but
	// also passes on a plain line; OpenSSH trusts only a @cert-authority line.
	caErr := check(cert.SignatureKey)
	if _, ok := errors.AsType[*xknownhosts.RevokedError](caErr); ok {
		return "", nil, caErr
	}
	caTrusted := caErr == nil && listed(cert.SignatureKey, true)
	// x/crypto matches principals exactly, OpenSSH 10.3 to 10.6 as patterns:
	// check again with the principal that matches. x/crypto can't check a
	// certificate without principals at all.
	if certErr != nil && cert.CertType == ssh.HostCert && caTrusted {
		isRevoked := func(c *ssh.Certificate) bool {
			_, ok := errors.AsType[*xknownhosts.RevokedError](check(c.Key))
			return ok
		}
		if principal := hostCertPrincipal(cert, host, p.WildcardPrincipals); principal != "" {
			checker := ssh.CertChecker{IsRevoked: isRevoked}
			certErr = checker.CheckCert(principal, cert)
		} else if len(cert.ValidPrincipals) == 0 && !p.RequirePrincipals {
			certErr = checkCertWithoutPrincipals(cert, isRevoked)
		}
	}
	// Validate the certificate like OpenSSH, including its CA signature algorithm.
	if certErr == nil {
		if slices.Contains(p.CASignatureAlgorithms, cert.Signature.Format) {
			return VerifiedByCAKey, nil, nil
		}
		certErr = fmt.Errorf("CA signature algorithm %q not allowed", cert.Signature.Format)
	}
	hostCertErr := hostCertificateError(cert, host, certErr, caTrusted, p)
	// Without fallback, a @revoked key inside the certificate still fails as revoked.
	if !p.PlainKeyFallback {
		err := check(cert.Key)
		if _, ok := errors.AsType[*xknownhosts.RevokedError](err); ok {
			return "", nil, err
		}
		return "", nil, hostCertErr
	}
	// Fall back to the host key inside the certificate.
	plainErr := checkPlain(cert.Key)
	if plainErr == nil {
		return VerifiedByPlainKey, hostCertErr, nil
	}
	if _, ok := errors.AsType[*xknownhosts.KeyError](plainErr); ok && caTrusted {
		return "", nil, hostCertErr
	}
	return "", nil, plainErr
}

// decidingLine returns the known_hosts line that decided the verification of
// key, like OpenSSH's "Found key in" and "Offending key in", or false for none.
// verifiedBy and err are verifyHostKey's, which looked a plain host key up on
// @cert-authority lines, too, if caLinesMatchPlainKeys.
func decidingLine(lines []knownhosts.Line, caLinesMatchPlainKeys bool, key ssh.PublicKey, verifiedBy string, err error) (xknownhosts.KnownKey, bool) {
	caLine := func(l knownhosts.Line) bool { return l.CertAuthority }
	plainLine := func(l knownhosts.Line) bool { return !l.CertAuthority || caLinesMatchPlainKeys }
	cert, _ := key.(*ssh.Certificate)
	switch verifiedBy {
	case VerifiedByCAKey:
		return firstLine(lines, cert.SignatureKey, caLine)
	case VerifiedByPlainKey:
		if cert != nil {
			key = cert.Key
		}
		return firstLine(lines, key, plainLine)
	}
	if revoked, ok := errors.AsType[*xknownhosts.RevokedError](err); ok {
		return revoked.Revoked, true
	}
	switch classifyHostKeyVerifyError(err) {
	case ErrReasonServerHostKeyMismatch:
		// Like OpenSSH, which reports the last plain line that didn't match.
		for _, l := range slices.Backward(lines) {
			if plainLine(l) {
				return l.KnownKey, true
			}
		}
	case ErrReasonServerHostCertificateNotYetValid, ErrReasonServerHostCertificateExpired,
		ErrReasonServerHostCertificatePrincipalNotListed, ErrReasonServerHostCertificateSignatureAlgorithmDisallowed,
		ErrReasonServerHostCertificateOther:
		return firstLine(lines, cert.SignatureKey, caLine)
	}
	return xknownhosts.KnownKey{}, false
}

// firstLine returns the first of lines that lists k, among those kind accepts.
func firstLine(lines []knownhosts.Line, k ssh.PublicKey, kind func(knownhosts.Line) bool) (xknownhosts.KnownKey, bool) {
	i := slices.IndexFunc(lines, func(l knownhosts.Line) bool {
		return kind(l) && bytes.Equal(l.Key.Marshal(), k.Marshal())
	})
	if i < 0 {
		return xknownhosts.KnownKey{}, false
	}
	return lines[i].KnownKey, true
}

// hostCertificateError tells why cert didn't verify through its CA, in the order
// of OpenSSH's check_host_key and sshkey_cert_check_host. certErr is the result
// of checking cert, caTrusted whether a @cert-authority line lists its CA; the
// certificate's fields only name the reason.
func hostCertificateError(cert *ssh.Certificate, host string, certErr error, caTrusted bool, p *profile.Profile) error {
	now := time.Now().Unix()
	var reason error
	switch {
	case !caTrusted:
		reason = errHostCertificateCAUnknown
	case cert.CertType != ssh.HostCert:
		reason = errHostCertificateInvalid
	case now < certUnix(cert.ValidAfter):
		reason = errHostCertificateNotYetValid
	case now >= certUnix(cert.ValidBefore):
		reason = errHostCertificateExpired
	case hostCertPrincipal(cert, host, p.WildcardPrincipals) == "" && (len(cert.ValidPrincipals) > 0 || p.RequirePrincipals):
		reason = errHostCertificatePrincipalNotListed
	case len(cert.CriticalOptions) > 0:
		reason = errHostCertificateInvalid
	case !slices.Contains(p.CASignatureAlgorithms, cert.Signature.Format):
		reason = errHostCertificateSignatureAlgorithmDisallowed
	default:
		reason = errHostCertificateInvalid
	}
	return fmt.Errorf("%w: %w", reason, certErr)
}

// hostCertPrincipal returns the first of cert's principals that equals host, or
// with wildcards matches it like OpenSSH's match_pattern, or "" if none does.
func hostCertPrincipal(cert *ssh.Certificate, host string, wildcards bool) string {
	for _, p := range cert.ValidPrincipals {
		if p == host || wildcards && match.Pattern(host, p) {
			return p
		}
	}
	return ""
}

// checkCertWithoutPrincipals checks a host certificate without principals like
// CheckCert would, if it could; verifyCertSignature checked its CA signature.
func checkCertWithoutPrincipals(cert *ssh.Certificate, isRevoked func(*ssh.Certificate) bool) error {
	now := time.Now().Unix()
	switch {
	case isRevoked(cert):
		return errors.New("certificate revoked")
	case now < certUnix(cert.ValidAfter):
		return errors.New("certificate not yet valid")
	case now >= certUnix(cert.ValidBefore):
		return errors.New("certificate expired")
	case len(cert.CriticalOptions) > 0:
		return errors.New("certificate has critical options")
	}
	return nil
}

// certUnix converts a certificate timestamp to Unix seconds. Timestamps past the
// largest int64, such as ssh.CertTimeInfinity, become the largest int64.
func certUnix(t uint64) int64 {
	if t > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(t)
}

// verifyCertSignature checks only cert's CA signature, by calling CheckCert with
// cert's own principal, critical options and valid-after time, so that nothing
// else can fail. A certificate without principals or validity window can't be
// set up that way; it verifies the signature itself.
func verifyCertSignature(cert *ssh.Certificate) error {
	i := slices.IndexFunc(cert.ValidPrincipals, func(p string) bool { return p != "" })
	inWindow := cert.ValidBefore == ssh.CertTimeInfinity ||
		(cert.ValidBefore > cert.ValidAfter && cert.ValidBefore <= math.MaxInt64)
	if i < 0 || !inWindow || cert.ValidAfter > math.MaxInt64 {
		// The CA signs the certificate up to its last field, the signature.
		// Unlike CheckCert, Verify requires user presence on an sk-* CA's signature.
		signed := cert.Marshal()
		signed = signed[:len(signed)-4-len(ssh.Marshal(cert.Signature))]
		if err := cert.SignatureKey.Verify(signed, cert.Signature); err != nil {
			return fmt.Errorf("%w: %w", errHostCertificateSignatureInvalid, err)
		}
		return nil
	}
	now := time.Unix(int64(cert.ValidAfter), 0)
	checker := ssh.CertChecker{
		Clock:                    func() time.Time { return now },
		SupportedCriticalOptions: slices.Collect(maps.Keys(cert.CriticalOptions)),
	}
	if err := checker.CheckCert(cert.ValidPrincipals[i], cert); err != nil {
		return fmt.Errorf("%w: %w", errHostCertificateSignatureInvalid, err)
	}
	return nil
}

func classifyHostKeyVerifyError(err error) string {
	if errors.Is(err, errHostCertificateSignatureInvalid) {
		return ErrReasonServerHostCertificateSignatureInvalid
	}
	switch {
	case errors.Is(err, errHostCertificateCAUnknown):
		return ErrReasonServerHostCertificateCAUnknown
	case errors.Is(err, errHostCertificateNotYetValid):
		return ErrReasonServerHostCertificateNotYetValid
	case errors.Is(err, errHostCertificateExpired):
		return ErrReasonServerHostCertificateExpired
	case errors.Is(err, errHostCertificatePrincipalNotListed):
		return ErrReasonServerHostCertificatePrincipalNotListed
	case errors.Is(err, errHostCertificateSignatureAlgorithmDisallowed):
		return ErrReasonServerHostCertificateSignatureAlgorithmDisallowed
	case errors.Is(err, errHostCertificateInvalid):
		return ErrReasonServerHostCertificateOther
	}

	if keyErr, ok := errors.AsType[*xknownhosts.KeyError](err); ok {
		if len(keyErr.Want) == 0 {
			return ErrReasonServerHostKeyUnknown
		}
		return ErrReasonServerHostKeyMismatch
	}

	if _, ok := errors.AsType[*xknownhosts.RevokedError](err); ok {
		return ErrReasonServerHostKeyRevoked
	}

	return ErrReasonServerHostKeyRejected
}

// classifyContextError reports the probe's own timeout or cancellation, so it is not
// misreported as the connection error it caused.
func classifyContextError(ctx context.Context) string {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return ErrReasonTimeout
	case errors.Is(ctx.Err(), context.Canceled):
		return ErrReasonCanceled
	default:
		return ""
	}
}

func classifyDialError(ctx context.Context, err error) string {
	if reason := classifyContextError(ctx); reason != "" {
		return reason
	}

	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		return ErrReasonTimeout
	}

	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return ErrReasonConnectionRefused
	case errors.Is(err, syscall.EHOSTUNREACH):
		return ErrReasonNoRouteToHost
	case errors.Is(err, syscall.ENETUNREACH):
		return ErrReasonNetworkUnreachable
	case errors.Is(err, syscall.ECONNRESET):
		return ErrReasonConnectionReset
	}

	if _, ok := errors.AsType[*net.DNSError](err); ok {
		return ErrReasonDNSFailure
	}

	return ErrReasonOther
}

func classifyKexError(ctx context.Context, err error) string {
	if reason := classifyContextError(ctx); reason != "" {
		return reason
	}

	if negErr, ok := errors.AsType[*ssh.AlgorithmNegotiationError](err); ok {
		return classifyNegotiationError(negErr)
	}

	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		return ErrReasonTimeout
	}
	// EOF and RST are not told apart: which one arrives depends on timing.
	switch {
	case errors.Is(err, io.EOF),
		errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.EPIPE):
		return ErrReasonConnectionReset
	}
	return ErrReasonOther
}

// classifyNegotiationError maps What, as set by x/crypto's findAgreedAlgorithms,
// to a reason; an unknown What still proves a failed negotiation.
func classifyNegotiationError(err *ssh.AlgorithmNegotiationError) string {
	switch err.What {
	case "key exchange":
		return ErrReasonNoCommonKex
	case "host key":
		return ErrReasonNoCommonHostKey
	case "client to server cipher", "server to client cipher":
		return ErrReasonNoCommonCipher
	case "client to server MAC", "server to client MAC":
		return ErrReasonNoCommonMAC
	default:
		return ErrReasonNoCommonAlgorithm
	}
}

// maxIdentificationLen is the RFC 4253, section 4.2 limit, including the CR LF.
const maxIdentificationLen = 255

// ServerIdentification is the server's identification string, split into its
// RFC 4253, section 4.2 fields.
type ServerIdentification struct {
	String          string
	ProtoVersion    string
	SoftwareVersion string
	Comments        string
	RFCConformant   bool
}

// parseServerIdentification splits raw into its fields. An error means raw
// cannot be parsed and must not be exported, since it is untrusted input that
// ends up in label values.
func parseServerIdentification(raw []byte) (ServerIdentification, error) {
	if len(raw) > maxIdentificationLen {
		return ServerIdentification{}, fmt.Errorf("longer than %d characters", maxIdentificationLen)
	}

	// RFC 4253, section 5.1 defines 2.0 and 1.99 as the only protoversions.
	var proto string
	var rest []byte
	for _, v := range []string{"2.0", "1.99"} {
		if r, ok := bytes.CutPrefix(raw, []byte("SSH-"+v+"-")); ok {
			proto, rest = v, r
			break
		}
	}
	if proto == "" {
		return ServerIdentification{}, errors.New(`does not start with "SSH-2.0-" or "SSH-1.99-"`)
	}

	for _, c := range rest {
		if c < 0x20 || c > 0x7e {
			return ServerIdentification{}, errors.New("contains characters other than printable US-ASCII")
		}
	}

	// softwareversion runs up to the optional comments, and must be present.
	software, comments, _ := bytes.Cut(rest, []byte{' '})
	if len(software) == 0 {
		return ServerIdentification{}, errors.New("softwareversion is empty")
	}

	return ServerIdentification{
		String:          string(raw),
		ProtoVersion:    proto,
		SoftwareVersion: string(software),
		Comments:        string(comments),
		// raw comes without the CR LF the length limit includes. Servers in the
		// wild put a minus in softwareversion (e.g. "Cisco-1.25"), so it is
		// parsed and exported, just not RFC conformant.
		RFCConformant: len(raw) <= maxIdentificationLen-len("\r\n") && !bytes.ContainsRune(software, '-'),
	}, nil
}

func (s ServerIdentification) withoutComments() ServerIdentification {
	s.String = "SSH-" + s.ProtoVersion + "-" + s.SoftwareVersion
	s.Comments = ""
	return s
}
