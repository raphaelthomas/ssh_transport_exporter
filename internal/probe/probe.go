// Package probe implements the SSH transport-layer (RFC 4253) probe
package probe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Phases a probe can fail at, reported as Result.ErrorPhase.
const (
	ErrPhaseDNSLookup     = "dns_lookup"
	ErrPhaseTCPConnect    = "tcp_connect"
	ErrPhaseKeyExchange   = "key_exchange"
	ErrPhaseHostKeyVerify = "host_key_verify"
)

// Why a probe failed, reported as Result.ErrorReason.
const (
	ErrReasonConnectionRefused  = "connection_refused"
	ErrReasonNoRouteToHost      = "no_route_to_host"
	ErrReasonNetworkUnreachable = "network_unreachable"
	ErrReasonDNSFailure         = "dns_failure"
	ErrReasonConnectionReset    = "connection_reset"
	ErrReasonUnknownHost        = "unknown_host"
	ErrReasonMismatch           = "mismatch"
	ErrReasonRevoked            = "revoked"
	ErrReasonTimeout            = "timeout"
	ErrReasonCanceled           = "canceled"
	ErrReasonUserAuthReached    = "user_auth_reached"
	ErrReasonOther              = "other"
)

// Result is the outcome of one probe against one target.
type Result struct {
	// Name resolution results, zero for IP literal targets and failed lookups
	DNSLookupDuration time.Duration

	TCPConnectSuccess       bool
	TCPConnectDuration      time.Duration
	TCPConnectNegotiatedMSS int

	ServerVersion string
	// ServerVersionMalformed records that a banner was presented but did not
	// conform, which ServerVersion alone cannot express once it is dropped.
	ServerVersionMalformed bool

	KEXSuccess   bool
	KEXDuration  time.Duration
	KEXAlgorithm string

	HostKeyVerifySuccess bool
	HostKeyAlgorithm     string

	CipherRead  string
	CipherWrite string
	// Negotiated MACs, empty for AEAD ciphers, which need none
	MACRead  string
	MACWrite string

	ErrorPhase  string
	ErrorReason string
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

	StripServerVersionComment bool

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

// Run probes target and reports any failure in the returned Result.
func Run(ctx context.Context, target string, opts Options) Result {
	var result Result

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

	lookup := isHostname(target)
	attemptStart := connectStart.Load()
	connectFrom := dialStart
	if attemptStart != nil {
		connectFrom = *attemptStart
		if lookup {
			result.DNSLookupDuration = attemptStart.Sub(dialStart)
		}
	}

	if err != nil {
		result.ErrorPhase = ErrPhaseTCPConnect
		if lookup && attemptStart == nil {
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
			result.TCPConnectNegotiatedMSS = mss
		} else if logger.Enabled(ctx, slog.LevelDebug) {
			logger.Debug("failed to read negotiated TCP MSS", "target", target, "error", err)
		}
	}

	forceCloseOnCtxDone := context.AfterFunc(ctx, func() {
		_ = rawConn.Close()
	})
	defer forceCloseOnCtxDone()

	kexStart := time.Now()
	hostKeyResultCh := make(chan hostKeyResult, 1)

	hostKeyAlgorithms := opts.HostKeyAlgorithms
	if len(hostKeyAlgorithms) == 0 {
		hostKeyAlgorithms = defaultHostKeyAlgorithms
	}

	clientConfig := &ssh.ClientConfig{
		User: "ssh_transport_exporter",
		Auth: nil,
		Config: ssh.Config{
			Ciphers:      opts.Ciphers,
			KeyExchanges: opts.KeyExchanges,
			MACs:         opts.MACs,
		},
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
			rawVersion := tc.Metadata.ServerVersion()
			version := sanitizeServerVersion(rawVersion)
			if version == "" {
				result.ServerVersionMalformed = true
				logger.Debug("dropping malformed server version banner", "target", target, "banner", string(rawVersion))
			} else if opts.StripServerVersionComment {
				version = stripServerVersionComment(version)
			}
			result.ServerVersion = version
			result.KEXDuration = time.Since(kexStart)
			result.KEXAlgorithm = tc.Algorithms.KeyExchange
			result.HostKeyAlgorithm = tc.Algorithms.HostKey
			result.CipherRead = tc.Algorithms.Read.Cipher
			result.CipherWrite = tc.Algorithms.Write.Cipher
			result.MACRead = tc.Algorithms.Read.MAC
			result.MACWrite = tc.Algorithms.Write.MAC

			return errAbort
		},
	}

	_, _, _, handshakeErr := ssh.NewClientConn(rawConn, target, clientConfig)

	switch {
	case errors.Is(handshakeErr, errAbort):
		result.KEXSuccess = true
	case handshakeErr == nil:
		// Unreachable while TransportReadyCallback returns errAbort.
		logger.Error("probe reached user authentication instead of aborting; x/crypto/ssh behavior may have changed", "target", target)
		result.ErrorPhase = ErrPhaseKeyExchange
		result.ErrorReason = ErrReasonUserAuthReached
	default:
		result.ErrorPhase = ErrPhaseKeyExchange
		result.ErrorReason = classifyKexError(ctx, handshakeErr)
	}

	// A failed host key check outranks a key exchange that failed after it.
	select {
	case hk := <-hostKeyResultCh:
		result.HostKeyVerifySuccess = hk.verified
		if !hk.verified {
			result.ErrorPhase = ErrPhaseHostKeyVerify
			result.ErrorReason = hk.errorReason
		}
	default:
	}

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
			return ErrReasonUnknownHost
		}
		return ErrReasonMismatch
	}

	if _, ok := errors.AsType[*knownhosts.RevokedError](err); ok {
		return ErrReasonRevoked
	}

	return ErrReasonOther
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

// sanitizeServerVersion drops a malformed banner rather than repairing it, since
// the banner is untrusted input that ends up in a label value.
func sanitizeServerVersion(raw []byte) string {
	const maxLen = 255 // see RFC 4253, section 4.2

	if len(raw) > maxLen {
		return ""
	}

	// RFC 4253, section 5.1 defines 2.0 and 1.99 as the only protoversions.
	rest, ok := bytes.CutPrefix(raw, []byte("SSH-2.0-"))
	if !ok {
		rest, ok = bytes.CutPrefix(raw, []byte("SSH-1.99-"))
	}
	if !ok {
		return ""
	}

	// softwareversion runs up to the optional comments, and must be present.
	if software, _, _ := bytes.Cut(rest, []byte{' '}); len(software) == 0 {
		return ""
	}
	for _, c := range rest {
		if c < 0x20 || c > 0x7e {
			return ""
		}
	}
	return string(raw)
}

func stripServerVersionComment(version string) string {
	software, _, _ := strings.Cut(version, " ")
	return software
}
