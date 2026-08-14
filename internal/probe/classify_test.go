package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"
)

func TestSanitizeServerVersion(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"normal banner", "SSH-2.0-OpenSSH_9.6", "SSH-2.0-OpenSSH_9.6"},
		{"banner with comments", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"},
		{"minus in softwareversion", "SSH-2.0-Cisco-1.25", "SSH-2.0-Cisco-1.25"},
		{"1.99 protoversion", "SSH-1.99-OpenSSH_9.6", "SSH-1.99-OpenSSH_9.6"},
		{"empty", "", ""},
		{"missing prefix", "OpenSSH_9.6", ""},
		{"unsupported protoversion", "SSH-1.5-OpenSSH_9.6", ""},
		{"empty softwareversion", "SSH-2.0-", ""},
		{"comments without softwareversion", "SSH-2.0- Ubuntu", ""},
		{"control chars rejected", "SSH-2.0-\x00\x01\x1fTest", ""},
		{"del char rejected", "SSH-2.0-Test\x7f", ""},
		{"tab and newline rejected", "SSH-2.0-Te\tst\n", ""},
		{"invalid utf8 rejected", "SSH-2.0-Test\xff", ""},
		{"non-ascii rejected", "SSH-2.0-café", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeServerVersion([]byte(tt.in)); got != tt.want {
				t.Errorf("sanitizeServerVersion(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizeServerVersionLengthLimit(t *testing.T) {
	const maxLen = 255

	atLimit := "SSH-2.0-" + strings.Repeat("a", maxLen-len("SSH-2.0-"))
	if got := sanitizeServerVersion([]byte(atLimit)); got != atLimit {
		t.Errorf("a %d byte banner was rejected", len(atLimit))
	}

	if got := sanitizeServerVersion([]byte(atLimit + "a")); got != "" {
		t.Errorf("sanitizeServerVersion = %q, want %q for an overlong banner", got, "")
	}
}

// timeoutError is a net.Error whose Timeout() reports true.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// expiredContext returns a context whose deadline has already passed.
func expiredContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	t.Cleanup(cancel)
	return ctx
}

// canceledContext returns a context that has already been cancelled.
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
		{"connection reset via ErrClosed", nil, net.ErrClosed, ErrReasonConnectionReset},
		{"wrapped ErrClosed", nil, fmt.Errorf("read: %w", net.ErrClosed), ErrReasonConnectionReset},
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
		{"unknown host (empty Want)", &knownhosts.KeyError{}, ErrReasonUnknownHost},
		{"mismatch (non-empty Want)", &knownhosts.KeyError{Want: []knownhosts.KnownKey{{}}}, ErrReasonMismatch},
		{"revoked", &knownhosts.RevokedError{}, ErrReasonRevoked},
		{"wrapped mismatch", fmt.Errorf("verify: %w", &knownhosts.KeyError{Want: []knownhosts.KnownKey{{}}}), ErrReasonMismatch},
		{"other", errors.New("nope"), ErrReasonOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyHostKeyVerifyError(tt.err); got != tt.want {
				t.Errorf("classifyHostKeyVerifyError(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}
