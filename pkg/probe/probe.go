// Package probe implements the SSH transport-layer (RFC 4253) probe
package probe

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	ErrStageTCPConnect    = "tcp_connect"
	ErrStageKeyExchange   = "kex"
	ErrStageHostKeyVerify = "host_key_verify"
)

const (
	ErrReasonConnectionRefused = "connection_refused"
	ErrReasonNoRouteToHost     = "no_route_to_host"
	ErrReasonDNSFailure        = "dns_failure"
	ErrReasonConnectionReset   = "connection_reset"
	ErrReasonUnknownHost       = "unknown_host"
	ErrReasonMismatch          = "mismatch"
	ErrReasonRevoked           = "revoked"
	ErrReasonTimeout           = "timeout"
	ErrReasonOther             = "other"
)

// Result is the outcome of one probe against one target.
type Result struct {
	TCPConnectSuccess       bool
	TCPConnectDuration      time.Duration
	TCPConnectNegotiatedMSS int
	KEXSuccess              bool
	KEXDuration             time.Duration
	HostKeyVerifySuccess    bool
	ErrorStage              string
	ErrorReason             string
}

// Returned from TransportReadyCallback to abort the connection after the
// transport layer is ready, but before user authentication.
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

	dialer := net.Dialer{}
	dialStart := time.Now()
	rawConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		result.ErrorStage = ErrStageTCPConnect
		result.ErrorReason = classifyDialError(err)
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
		}
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(deadline)
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
			return errAbort
		},
	}

	_, _, _, handshakeErr := ssh.NewClientConn(rawConn, target, clientConfig)

	switch {
	case errors.Is(handshakeErr, errAbort):
		// "Successful" probe, since we got the sentinel error
	case handshakeErr == nil:
		// Unreachable in practice: our callback always aborts.
		result.ErrorStage = ErrStageHostKeyVerify
		result.ErrorReason = ErrReasonOther
	default:
		result.ErrorStage = ErrStageKeyExchange
		result.ErrorReason = classifyKexError(handshakeErr)
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

func classifyDialError(err error) string {
	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		return ErrReasonTimeout
	}

	if opErr, ok := errors.AsType[*net.OpError](err); ok {
		switch {
		case opErr.Op == "dial" && strings.Contains(opErr.Err.Error(), "refused"):
			return ErrReasonConnectionRefused
		case strings.Contains(opErr.Err.Error(), "no route to host"):
			return ErrReasonNoRouteToHost
		}
	}

	if _, ok := errors.AsType[*net.DNSError](err); ok {
		return ErrReasonDNSFailure
	}

	return ErrReasonOther
}

func classifyKexError(err error) string {
	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		return ErrReasonTimeout
	}
	if errors.Is(err, net.ErrClosed) {
		return ErrReasonConnectionReset
	}
	return ErrReasonOther
}
