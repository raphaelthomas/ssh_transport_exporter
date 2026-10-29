// Package probe implements the SSH transport-layer (RFC 4253) probe
package probe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
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
	ErrReasonConnectionRefused     = "connection_refused"
	ErrReasonNoRouteToHost         = "no_route_to_host"
	ErrReasonNetworkUnreachable    = "network_unreachable"
	ErrReasonDNSFailure            = "dns_failure"
	ErrReasonConnectionReset       = "connection_reset"
	ErrReasonServerHostKeyUnknown  = "server_host_key_unknown"
	ErrReasonServerHostKeyMismatch = "server_host_key_mismatch"
	ErrReasonServerHostKeyRevoked  = "server_host_key_revoked"
	ErrReasonServerHostKeyRejected = "server_host_key_rejected"
	ErrReasonTimeout               = "timeout"
	ErrReasonCanceled              = "canceled"
	ErrReasonUserAuthReached       = "user_auth_reached"
	ErrReasonOther                 = "other"
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

	// Ciphers to advertise. Empty uses golang.org/x/crypto/ssh's default.
	Ciphers []string

	// KeyExchanges to advertise. Empty uses golang.org/x/crypto/ssh's default.
	KeyExchanges []string

	// MACs to advertise. Empty uses golang.org/x/crypto/ssh's default.
	MACs []string

	// HostKeyAlgorithms to accept, in preference order. Empty uses
	// defaultHostKeyAlgorithms below, not the library's own default.
	HostKeyAlgorithms []string

	StripServerIdentificationComments bool

	Logger *slog.Logger
}

// defaultHostKeyAlgorithms mirrors OpenSSH's client default order.
var defaultHostKeyAlgorithms = []string{
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
	ssh.KeyAlgoRSASHA256,
	ssh.KeyAlgoRSASHA512,
}

// hostKeyResult moves the verification result off the goroutine that runs
// HostKeyCallback; only the first key exchange is recorded.
type hostKeyResult struct {
	verified    bool
	errorReason string
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

	hostKeyAlgorithms := opts.HostKeyAlgorithms
	if len(hostKeyAlgorithms) == 0 {
		hostKeyAlgorithms = defaultHostKeyAlgorithms
	}

	clientConfig := &ssh.ClientConfig{
		User:              "ssh_transport_exporter",
		Auth:              nil,
		Ciphers:           opts.Ciphers,
		KeyExchanges:      opts.KeyExchanges,
		MACs:              opts.MACs,
		HostKeyAlgorithms: hostKeyAlgorithms,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			hk := hostKeyResult{verified: true}
			if err := hostKeyCallback(hostname, remote, key); err != nil {
				hk.verified = false
				hk.errorReason = classifyHostKeyVerifyError(err)
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
	}

	// A failed host key check outranks a key exchange that failed after it.
	select {
	case hk := <-hostKeyResultCh:
		result.ServerHostKeyVerifySuccess = hk.verified
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

func classifyHostKeyVerifyError(err error) string {
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
