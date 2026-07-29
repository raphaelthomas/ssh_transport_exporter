// Package sshtest provides in-process SSH servers for tests.
package sshtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Server is an in-process SSH server that completes the transport-layer
// handshake and then drops the connection at user authentication, which is
// exactly how far the exporter's probe goes.
type Server struct {
	// Addr is the "127.0.0.1:port" address the server listens on.
	Addr string
	// HostKey is the server's public host key.
	HostKey ssh.PublicKey
}

// Options configures a test server. The zero value uses library defaults.
type Options struct {
	// ServerVersion overrides the announced SSH banner. Empty uses the default.
	ServerVersion string
	// Ciphers restricts the server's cipher list. Nil uses the default set.
	Ciphers []string
}

// NewServer starts an SSH server on 127.0.0.1 with an ephemeral port and
// registers cleanup with t.
func NewServer(t *testing.T, opts Options) *Server {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("sshtest: generating host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("sshtest: NewSignerFromKey: %v", err)
	}

	cfg := &ssh.ServerConfig{
		// The probe never authenticates, but a server must advertise a method.
		NoClientAuth:  true,
		ServerVersion: opts.ServerVersion,
		Config:        ssh.Config{Ciphers: opts.Ciphers},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sshtest: listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed at test cleanup
			}
			go func() {
				defer func() { _ = conn.Close() }()
				// Errors are expected: the probe aborts at authentication.
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					_ = nc.Reject(ssh.Prohibited, "sshtest")
				}
				_ = sc.Close()
			}()
		}
	}()

	return &Server{Addr: ln.Addr().String(), HostKey: signer.PublicKey()}
}

// Port returns the server's port as a string.
func (s *Server) Port(t *testing.T) string {
	t.Helper()
	_, port, err := net.SplitHostPort(s.Addr)
	if err != nil {
		t.Fatalf("sshtest: SplitHostPort(%q): %v", s.Addr, err)
	}
	return port
}

// ClosedPort returns an address on 127.0.0.1 with nothing listening, suitable
// for provoking a connection-refused error.
func ClosedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sshtest: listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("sshtest: close: %v", err)
	}
	return addr
}

// SilentServer starts a TCP listener that accepts connections but never speaks
// SSH, so a probe hangs in key exchange until its context deadline fires.
func SilentServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sshtest: listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	return ln.Addr().String()
}
