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

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestParseServerIdentification(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    ServerIdentification
		wantErr bool
	}{
		{"normal", "SSH-2.0-OpenSSH_9.6", ServerIdentification{"SSH-2.0-OpenSSH_9.6", "2.0", "OpenSSH_9.6", "", true}, false},
		{"with comments", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", ServerIdentification{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "2.0", "OpenSSH_9.6p1", "Ubuntu-3ubuntu13.5", true}, false},
		{"comments containing spaces", "SSH-2.0-Foo_1.0 a b c", ServerIdentification{"SSH-2.0-Foo_1.0 a b c", "2.0", "Foo_1.0", "a b c", true}, false},
		{"1.99 protoversion", "SSH-1.99-OpenSSH_9.6", ServerIdentification{"SSH-1.99-OpenSSH_9.6", "1.99", "OpenSSH_9.6", "", true}, false},
		{"minus in softwareversion", "SSH-2.0-Cisco-1.25", ServerIdentification{"SSH-2.0-Cisco-1.25", "2.0", "Cisco-1.25", "", false}, false},
		{"empty", "", ServerIdentification{}, true},
		{"missing prefix", "OpenSSH_9.6", ServerIdentification{}, true},
		{"unsupported protoversion", "SSH-1.5-OpenSSH_9.6", ServerIdentification{}, true},
		{"empty softwareversion", "SSH-2.0-", ServerIdentification{}, true},
		{"comments without softwareversion", "SSH-2.0- Ubuntu", ServerIdentification{}, true},
		{"control chars", "SSH-2.0-\x00\x01\x1fTest", ServerIdentification{}, true},
		{"del char", "SSH-2.0-Test\x7f", ServerIdentification{}, true},
		{"tab and newline", "SSH-2.0-Te\tst\n", ServerIdentification{}, true},
		{"invalid utf8", "SSH-2.0-Test\xff", ServerIdentification{}, true},
		{"non-ascii", "SSH-2.0-café", ServerIdentification{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseServerIdentification([]byte(tt.in))
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Errorf("parseServerIdentification(%q) = %+v, %v, want %+v, error %t", tt.in, got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestServerIdentificationWithoutComments(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"comments dropped", "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10", "SSH-2.0-OpenSSH_9.2p1"},
		{"no comments is unchanged", "SSH-2.0-OpenSSH_9.6", "SSH-2.0-OpenSSH_9.6"},
		{"comments containing spaces", "SSH-2.0-Foo_1.0 a b c", "SSH-2.0-Foo_1.0"},
		{"empty comments after trailing space", "SSH-2.0-Foo_1.0 ", "SSH-2.0-Foo_1.0"},
		{"1.99 protoversion kept", "SSH-1.99-Foo_1.0 bar", "SSH-1.99-Foo_1.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ident, err := parseServerIdentification([]byte(tt.in))
			if err != nil {
				t.Fatalf("parseServerIdentification(%q): %v", tt.in, err)
			}
			got := ident.withoutComments()
			if got.String != tt.want || got.Comments != "" {
				t.Errorf("withoutComments() = %q, comments %q, want %q, no comments", got.String, got.Comments, tt.want)
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
		ident, err := parseServerIdentification([]byte(raw))
		if ident.RFCConformant != tt.wantRFCConformant || (err != nil) != tt.wantErr {
			t.Errorf("length %d: got %t, %v, want %t, error %t", tt.length, ident.RFCConformant, err, tt.wantRFCConformant, tt.wantErr)
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
		{"no common kex", nil, &ssh.AlgorithmNegotiationError{What: "key exchange"}, ErrReasonNoCommonKex},
		{"no common host key", nil, &ssh.AlgorithmNegotiationError{What: "host key"}, ErrReasonNoCommonHostKey},
		{"no common cipher client to server", nil, &ssh.AlgorithmNegotiationError{What: "client to server cipher"}, ErrReasonNoCommonCipher},
		{"no common cipher server to client", nil, &ssh.AlgorithmNegotiationError{What: "server to client cipher"}, ErrReasonNoCommonCipher},
		{"no common MAC client to server", nil, &ssh.AlgorithmNegotiationError{What: "client to server MAC"}, ErrReasonNoCommonMAC},
		{"no common MAC server to client", nil, &ssh.AlgorithmNegotiationError{What: "server to client MAC"}, ErrReasonNoCommonMAC},
		{"no common compression", nil, &ssh.AlgorithmNegotiationError{What: "client to server compression"}, ErrReasonNoCommonAlgorithm},
		{"wrapped no common host key", nil, fmt.Errorf("ssh: handshake failed: %w", &ssh.AlgorithmNegotiationError{What: "host key"}), ErrReasonNoCommonHostKey},
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
