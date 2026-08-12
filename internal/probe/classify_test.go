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
		{"empty", "", ""},
		{"control chars stripped", "SSH-2.0-\x00\x01\x1fTest", "SSH-2.0-Test"},
		{"del char stripped", "SSH-2.0-Test\x7f", "SSH-2.0-Test"},
		{"tab and newline stripped", "SSH-2.0-Te\tst\n", "SSH-2.0-Test"},
		{"invalid utf8 dropped", "SSH-2.0-Test\xff", "SSH-2.0-Test"},
		{"printable unicode kept", "SSH-2.0-café", "SSH-2.0-café"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeServerVersion([]byte(tt.in)); got != tt.want {
				t.Errorf("sanitizeServerVersion(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizeServerVersionTruncates(t *testing.T) {
	const maxLen = 255
	raw := strings.Repeat("a", 300)
	got := sanitizeServerVersion([]byte(raw))
	if len(got) != maxLen {
		t.Errorf("sanitizeServerVersion length = %d, want %d", len(got), maxLen)
	}
	if got != strings.Repeat("a", maxLen) {
		t.Errorf("sanitizeServerVersion did not truncate to first %d bytes", maxLen)
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
