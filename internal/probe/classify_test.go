package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"
)

func TestParseServerIdentification(t *testing.T) {
	tests := []struct {
		name              string
		in                string
		wantRFCConformant bool
		wantErr           bool
	}{
		{"normal", "SSH-2.0-OpenSSH_9.6", true, false},
		{"with comments", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", true, false},
		{"1.99 protoversion", "SSH-1.99-OpenSSH_9.6", true, false},
		{"minus in softwareversion", "SSH-2.0-Cisco-1.25", false, false},
		{"empty", "", false, true},
		{"missing prefix", "OpenSSH_9.6", false, true},
		{"unsupported protoversion", "SSH-1.5-OpenSSH_9.6", false, true},
		{"empty softwareversion", "SSH-2.0-", false, true},
		{"comments without softwareversion", "SSH-2.0- Ubuntu", false, true},
		{"control chars", "SSH-2.0-\x00\x01\x1fTest", false, true},
		{"del char", "SSH-2.0-Test\x7f", false, true},
		{"tab and newline", "SSH-2.0-Te\tst\n", false, true},
		{"invalid utf8", "SSH-2.0-Test\xff", false, true},
		{"non-ascii", "SSH-2.0-café", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rfcConformant, err := parseServerIdentification([]byte(tt.in))
			if rfcConformant != tt.wantRFCConformant || (err != nil) != tt.wantErr {
				t.Errorf("parseServerIdentification(%q) = %t, %v, want %t, error %t", tt.in, rfcConformant, err, tt.wantRFCConformant, tt.wantErr)
			}
		})
	}
}

func TestStripServerIdentificationComments(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"comment dropped", "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10", "SSH-2.0-OpenSSH_9.2p1"},
		{"no comment is unchanged", "SSH-2.0-OpenSSH_9.6", "SSH-2.0-OpenSSH_9.6"},
		{"comment containing spaces", "SSH-2.0-Foo_1.0 a b c", "SSH-2.0-Foo_1.0"},
		{"empty comment after trailing space", "SSH-2.0-Foo_1.0 ", "SSH-2.0-Foo_1.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripServerIdentificationComments(tt.in); got != tt.want {
				t.Errorf("stripServerIdentificationComments(%q) = %q, want %q", tt.in, got, tt.want)
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
		rfcConformant, err := parseServerIdentification([]byte(raw))
		if rfcConformant != tt.wantRFCConformant || (err != nil) != tt.wantErr {
			t.Errorf("length %d: got %t, %v, want %t, error %t", tt.length, rfcConformant, err, tt.wantRFCConformant, tt.wantErr)
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
