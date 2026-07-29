package probe

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"

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

func TestClassifyDialError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"timeout", timeoutError{}, ErrReasonTimeout},
		{"connection refused", syscall.ECONNREFUSED, ErrReasonConnectionRefused},
		{"no route to host", syscall.EHOSTUNREACH, ErrReasonNoRouteToHost},
		{"network unreachable", syscall.ENETUNREACH, ErrReasonNetworkUnreachable},
		{"dns failure", &net.DNSError{Err: "no such host", Name: "nope"}, ErrReasonDNSFailure},
		{"wrapped connection refused", fmt.Errorf("dial: %w", syscall.ECONNREFUSED), ErrReasonConnectionRefused},
		{"other", errors.New("boom"), ErrReasonOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyDialError(tt.err); got != tt.want {
				t.Errorf("classifyDialError(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestClassifyKexError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"timeout", timeoutError{}, ErrReasonTimeout},
		{"connection reset via ErrClosed", net.ErrClosed, ErrReasonConnectionReset},
		{"wrapped ErrClosed", fmt.Errorf("read: %w", net.ErrClosed), ErrReasonConnectionReset},
		{"other", errors.New("kex exploded"), ErrReasonOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyKexError(tt.err); got != tt.want {
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
