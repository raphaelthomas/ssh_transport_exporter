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
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
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
	ErrReasonConnectionRefused                     = "connection_refused"
	ErrReasonNoRouteToHost                         = "no_route_to_host"
	ErrReasonNetworkUnreachable                    = "network_unreachable"
	ErrReasonDNSFailure                            = "dns_failure"
	ErrReasonConnectionReset                       = "connection_reset"
	ErrReasonServerHostKeyUnknown                  = "server_host_key_unknown"
	ErrReasonServerHostKeyMismatch                 = "server_host_key_mismatch"
	ErrReasonServerHostKeyRevoked                  = "server_host_key_revoked"
	ErrReasonServerHostKeyRejected                 = "server_host_key_rejected"
	ErrReasonServerHostCertificateOther            = "server_host_certificate_other"
	ErrReasonServerHostCertificateSignatureInvalid = "server_host_certificate_signature_invalid"
	ErrReasonTimeout                               = "timeout"
	ErrReasonCanceled                              = "canceled"
	ErrReasonUserAuthReached                       = "user_auth_reached"
	ErrReasonNoCommonKex                           = "no_common_kex_algorithm"
	ErrReasonNoCommonHostKey                       = "no_common_host_key_algorithm"
	ErrReasonNoCommonCipher                        = "no_common_cipher"
	ErrReasonNoCommonMAC                           = "no_common_mac"
	ErrReasonNoCommonAlgorithm                     = "no_common_algorithm"
	ErrReasonOther                                 = "other"
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

// Options controls how a probe's SSH client connection is configured.
type Options struct {
	// HostKeyCallback does the identity check. Called synchronously per probe,
	// so must be safe for concurrent use. Nil fails verification.
	HostKeyCallback ssh.HostKeyCallback

	// Ciphers to advertise, in preference order. Empty uses defaultCiphers.
	Ciphers []string

	// KeyExchanges to advertise, in preference order. Empty uses
	// defaultKeyExchanges.
	KeyExchanges []string

	// MACs to advertise, in preference order. Empty uses defaultMACs.
	MACs []string

	// HostKeyAlgorithms to accept, in preference order. Empty uses
	// defaultHostKeyAlgorithms.
	HostKeyAlgorithms []string

	StripServerIdentificationComments bool

	Logger *slog.Logger
}

// The defaults are the client defaults of OpenSSH 10.0 - 10.6 (myproposal.h),
// without the algorithms x/crypto does not implement: sntrup761x25519-sha512,
// diffie-hellman-group18-sha512, sk-* and webauthn-sk-* host keys,
// ssh-mldsa44-ed25519, umac-* and hmac-sha1-etm.
var (
	defaultKeyExchanges = []string{
		ssh.KeyExchangeMLKEM768X25519,
		ssh.KeyExchangeCurve25519,
		ssh.KeyExchangeECDHP256,
		ssh.KeyExchangeECDHP384,
		ssh.KeyExchangeECDHP521,
		ssh.KeyExchangeDHGEXSHA256,
		ssh.KeyExchangeDH16SHA512,
		ssh.KeyExchangeDH14SHA256,
	}

	defaultHostKeyAlgorithms = []string{
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

	defaultCiphers = []string{
		ssh.CipherChaCha20Poly1305,
		ssh.CipherAES128GCM,
		ssh.CipherAES256GCM,
		ssh.CipherAES128CTR,
		ssh.CipherAES192CTR,
		ssh.CipherAES256CTR,
	}

	defaultMACs = []string{
		ssh.HMACSHA256ETM,
		ssh.HMACSHA512ETM,
		ssh.HMACSHA256,
		ssh.HMACSHA512,
		ssh.HMACSHA1,
	}

	// caSignatureAlgorithms is OpenSSH's default CASignatureAlgorithms, without
	// webauthn-sk-ecdsa-sha2-nistp256@openssh.com, which x/crypto does not implement.
	caSignatureAlgorithms = []string{
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

func orDefault(algorithms, defaults []string) []string {
	if len(algorithms) == 0 {
		return defaults
	}
	return algorithms
}

// hostKeyResult moves the verification result off the goroutine that runs
// HostKeyCallback; only the first key exchange is recorded.
type hostKeyResult struct {
	verified    bool
	verifiedBy  string
	errorReason string
	cert        *ssh.Certificate // nil for a plain host key
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

	hostKeyCallback := opts.HostKeyCallback
	if hostKeyCallback == nil {
		hostKeyCallback = func(string, net.Addr, ssh.PublicKey) error {
			return errors.New("no HostKeyCallback configured")
		}
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
		Ciphers:           orDefault(opts.Ciphers, defaultCiphers),
		KeyExchanges:      orDefault(opts.KeyExchanges, defaultKeyExchanges),
		MACs:              orDefault(opts.MACs, defaultMACs),
		HostKeyAlgorithms: orDefault(opts.HostKeyAlgorithms, defaultHostKeyAlgorithms),
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			verifiedBy, err := verifyHostKey(hostKeyCallback, hostname, remote, key)
			hk := hostKeyResult{verified: err == nil, verifiedBy: verifiedBy}
			hk.cert, _ = key.(*ssh.Certificate)
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

// errHostCertificateInvalid marks an invalid SSH host certificate signed by a CA trusted for the host.
var errHostCertificateInvalid = errors.New("host certificate from a trusted CA is invalid")

// errHostCertificateSignatureInvalid marks an SSH host certificate whose CA signature doesn't verify.
var errHostCertificateSignatureInvalid = errors.New("host certificate CA signature does not verify")

// verifyHostKey checks key against known_hosts like OpenSSH's check_host_key and
// returns which listed key verified it. An invalid SSH host certificate falls
// back to the host key inside it. A bad CA signature, or a @revoked key or CA,
// fails without fallback.
func verifyHostKey(cb ssh.HostKeyCallback, hostname string, remote net.Addr, key ssh.PublicKey) (string, error) {
	check := func(k ssh.PublicKey) error { return cb(hostname, remote, k) }

	// Check a plain host key directly.
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		if err := check(key); err != nil {
			return "", err
		}
		return VerifiedByPlainKey, nil
	}
	// OpenSSH rejects a bad CA signature when parsing the key, before known_hosts.
	if err := verifyCertSignature(cert); err != nil {
		return "", err
	}
	// Validate the certificate like OpenSSH, including its CA signature algorithm.
	certErr := check(cert)
	if certErr == nil {
		if slices.Contains(caSignatureAlgorithms, cert.Signature.Format) {
			return VerifiedByCAKey, nil
		}
		certErr = fmt.Errorf("CA signature algorithm %q not allowed", cert.Signature.Format)
	}
	// Checking the CA as a host key tells whether it is @revoked or trusted.
	caErr := check(cert.SignatureKey)
	if _, ok := errors.AsType[*knownhosts.RevokedError](caErr); ok {
		return "", caErr
	}
	// Fall back to the host key inside the certificate.
	plainErr := check(cert.Key)
	if plainErr == nil {
		return VerifiedByPlainKey, nil
	}
	if _, ok := errors.AsType[*knownhosts.KeyError](plainErr); ok && caErr == nil {
		return "", fmt.Errorf("%w: %w", errHostCertificateInvalid, certErr)
	}
	return "", plainErr
}

// verifyCertSignature checks only cert's CA signature, by calling CheckCert with
// cert's own principal, critical options and valid-after time, so that nothing
// else can fail. A certificate without principals or validity window passes unchecked.
func verifyCertSignature(cert *ssh.Certificate) error {
	i := slices.IndexFunc(cert.ValidPrincipals, func(p string) bool { return p != "" })
	inWindow := cert.ValidBefore == ssh.CertTimeInfinity ||
		(cert.ValidBefore > cert.ValidAfter && cert.ValidBefore <= math.MaxInt64)
	if i < 0 || !inWindow {
		return nil
	}
	if cert.ValidAfter > math.MaxInt64 {
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
	if errors.Is(err, errHostCertificateInvalid) {
		return ErrReasonServerHostCertificateOther
	}

	if keyErr, ok := errors.AsType[*knownhosts.KeyError](err); ok {
		if len(keyErr.Want) == 0 {
			return ErrReasonServerHostKeyUnknown
		}
		return ErrReasonServerHostKeyMismatch
	}

	if _, ok := errors.AsType[*knownhosts.RevokedError](err); ok {
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
