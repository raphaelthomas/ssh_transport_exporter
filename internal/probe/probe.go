// Package probe implements the SSH transport-layer (RFC 4253) probe
package probe

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Stages a probe can fail at, reported as Result.ErrorStage.
const (
	ErrStageTCPConnect    = "tcp_connect"
	ErrStageKeyExchange   = "kex"
	ErrStageHostKeyVerify = "host_key_verify"
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
	ErrReasonOther              = "other"
)

// Result is the outcome of one probe against one target.
type Result struct {
	// TCP connection results
	TCPConnectSuccess       bool
	TCPConnectDuration      time.Duration
	TCPConnectNegotiatedMSS int
	// SSH identification string exchange results
	ServerVersion string
	// Key exchange results
	KEXSuccess   bool
	KEXDuration  time.Duration
	KEXAlgorithm string
	// Host key verification results
	HostKeyVerifySuccess bool
	HostKeyAlgorithm     string
	// Negotiated ciphers
	CipherRead  string
	CipherWrite string
	// Error classification results
	ErrorStage  string
	ErrorReason string
}

// errAbort is returned from TransportReadyCallback to abort the connection
// after the transport layer is ready, but before user authentication.
var errAbort = errors.New("probe: aborting before auth by design")

// Options controls how a probe's SSH client connection is configured.
type Options struct {
	// HostKeyCallback does the identity check. Called synchronously per probe,
	// so must be safe for concurrent use.
	HostKeyCallback ssh.HostKeyCallback

	// Ciphers to advertise. Empty uses golang.org/x/crypto/ssh's default.
	Ciphers []string

	// HostKeyAlgorithms to accept, in preference order. Empty uses
	// defaultHostKeyAlgorithms below, not the library's own default.
	HostKeyAlgorithms []string

	// Optional Logger for diagnostics (not for target health).
	Logger *slog.Logger
}

// defaultHostKeyAlgorithms mirrors OpenSSH's client default order:
// certificate types first, then plain key types, Ed25519 preferred.
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

// Run probes the provided target and returns the result including a potential
// error.
func Run(ctx context.Context, target string, opts Options) Result {
	var result Result

	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	dialer := net.Dialer{}
	dialStart := time.Now()
	rawConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		result.ErrorStage = ErrStageTCPConnect
		result.ErrorReason = classifyDialError(ctx, err)
		return result
	}
	defer func() {
		_ = rawConn.Close()
	}()

	result.TCPConnectSuccess = true
	result.TCPConnectDuration = time.Since(dialStart)

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

	hostKeyAlgorithms := opts.HostKeyAlgorithms
	if len(hostKeyAlgorithms) == 0 {
		hostKeyAlgorithms = defaultHostKeyAlgorithms
	}

	clientConfig := &ssh.ClientConfig{
		User:              "ssh_transport_exporter",
		Auth:              nil,
		Config:            ssh.Config{Ciphers: opts.Ciphers},
		HostKeyAlgorithms: hostKeyAlgorithms,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			result.KEXSuccess = true
			result.KEXDuration = time.Since(kexStart)

			if err := opts.HostKeyCallback(hostname, remote, key); err != nil {
				result.HostKeyVerifySuccess = false
				result.ErrorStage = ErrStageHostKeyVerify
				result.ErrorReason = classifyHostKeyVerifyError(err)
			} else {
				result.HostKeyVerifySuccess = true
			}
			// we deliberately continue here regardless of the host key verification
			// result, so that we can record connection metadata and negotiated
			// algorithms in TransportReadyCallback and abort therein.
			return nil
		},
		TransportReadyCallback: func(connMetadata ssh.ConnMetadata, negotiatedAlgorithms ssh.NegotiatedAlgorithms) error {
			result.ServerVersion = sanitizeServerVersion(connMetadata.ServerVersion())
			result.KEXAlgorithm = negotiatedAlgorithms.KeyExchange
			result.HostKeyAlgorithm = negotiatedAlgorithms.HostKey
			result.CipherRead = negotiatedAlgorithms.Read.Cipher
			result.CipherWrite = negotiatedAlgorithms.Write.Cipher

			return errAbort
		},
	}

	_, _, _, handshakeErr := ssh.NewClientConn(rawConn, target, clientConfig)

	switch {
	case errors.Is(handshakeErr, errAbort):
		// "Successful" probe, since we got the sentinel error
	case handshakeErr == nil:
		// Should be unreachable, since TransportReadyCallback always returns
		// errAbort, so we log this explicitly. Probe itself was successful, so
		// neither ErrorStage nor ErrorReason are set here.
		logger.Warn("SSH handshake completed without hitting abort sentinel; x/crypto/ssh behavior may have changed", "target", target)
	default:
		result.ErrorStage = ErrStageKeyExchange
		result.ErrorReason = classifyKexError(ctx, handshakeErr)
	}

	return result
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

// classifyContextError reports the reason implied by ctx's own state, or the
// empty string when ctx is still live. It takes precedence over the error
// value: aborting a probe closes the connection, which is indistinguishable
// from a peer reset by error alone.
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
	if errors.Is(err, net.ErrClosed) {
		return ErrReasonConnectionReset
	}
	return ErrReasonOther
}

// sanitizeServerVersion returns a bounded, control-character-free copy of the
// raw SSH version banner. The banner is attacker-controlled: nothing about it
// is signed or verified, so this must not pass the raw bytes straight through
// to a Prometheus label.
func sanitizeServerVersion(raw []byte) string {
	const maxLen = 255 // see RFC 4253, section 4.2
	if len(raw) > maxLen {
		raw = raw[:maxLen]
	}
	b := make([]byte, 0, len(raw))
	for _, r := range string(raw) {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			continue // drop control characters and invalid encoding
		}
		b = utf8.AppendRune(b, r)
	}
	return string(b)
}
