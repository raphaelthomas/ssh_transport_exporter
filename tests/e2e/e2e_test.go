//go:build e2e

// Package e2e probes the real SSH servers that compose.yaml starts.
package e2e

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/probe"
)

const (
	readyTimeout = 60 * time.Second
	probeTimeout = 10 * time.Second
)

type server struct {
	name     string
	addr     string
	software string // softwareversion prefix
}

// servers must match the host ports in compose.yaml.
var servers = []server{
	{"openssh-rocky8", "127.0.0.1:2201", "OpenSSH_"},
	{"openssh-rocky9", "127.0.0.1:2202", "OpenSSH_"},
	{"openssh-ubuntu2204", "127.0.0.1:2203", "OpenSSH_"},
	{"openssh-debian12", "127.0.0.1:2204", "OpenSSH_"},
	{"openssh-ubuntu2404", "127.0.0.1:2205", "OpenSSH_"},
	{"openssh-rocky10", "127.0.0.1:2206", "OpenSSH_"},
	{"openssh-debian13", "127.0.0.1:2207", "OpenSSH_"},
	{"openssh-ubuntu2604", "127.0.0.1:2208", "OpenSSH_"},
	{"openssh-alpine", "127.0.0.1:2209", "OpenSSH_"},
	{"dropbear", "127.0.0.1:2221", "dropbear"},
	{"tinyssh", "127.0.0.1:2222", "tinyssh"},
	{"asyncssh", "127.0.0.1:2223", "AsyncSSH_"},
	{"erlang", "127.0.0.1:2224", "Erlang/"},
}

var aeadCiphers = []string{ssh.CipherAES128GCM, ssh.CipherAES256GCM, ssh.CipherChaCha20Poly1305}

func lookup(t *testing.T, name string) server {
	t.Helper()
	i := slices.IndexFunc(servers, func(s server) bool { return s.name == name })
	if i < 0 {
		t.Fatalf("no server %q", name)
	}
	return servers[i]
}

// trustOnFirstUse retries until a probe with opts succeeds, which also waits
// for the container to come up, and returns the host key it presented.
func trustOnFirstUse(t *testing.T, addr string, opts probe.Options) ssh.PublicKey {
	t.Helper()
	var hostKey ssh.PublicKey
	opts.HostKeyCallback = func(_ string, _ net.Addr, key ssh.PublicKey) error {
		hostKey = key
		return nil
	}
	deadline := time.Now().Add(readyTimeout)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		result := probe.Run(ctx, addr, opts)
		cancel()
		if result.Success {
			t.Logf("first use: %q", result.ServerIdentification.String)
			return hostKey
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not ready after %s: %s/%s", addr, readyTimeout, result.ErrorPhase, result.ErrorReason)
		}
		time.Sleep(time.Second)
	}
}

func probeVerified(t *testing.T, addr string, opts probe.Options) probe.Result {
	t.Helper()
	opts.HostKeyCallback = ssh.FixedHostKey(trustOnFirstUse(t, addr, opts))
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	result := probe.Run(ctx, addr, opts)
	if !result.Success {
		t.Fatalf("probe failed: %s/%s", result.ErrorPhase, result.ErrorReason)
	}
	return result
}

func TestServers(t *testing.T) {
	for _, s := range servers {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			result := probeVerified(t, s.addr, probe.Options{})
			id := result.ServerIdentification
			t.Logf("%q, kex %s", id.String, result.KEXAlgorithm)

			if !strings.HasPrefix(id.SoftwareVersion, s.software) {
				t.Errorf("softwareversion = %q, want prefix %q", id.SoftwareVersion, s.software)
			}
			for name, alg := range map[string]string{
				"kex":                     result.KEXAlgorithm,
				"host key":                result.ServerHostKeyAlgorithm,
				"cipher client to server": result.EncryptionClientToServer,
				"cipher server to client": result.EncryptionServerToClient,
			} {
				if alg == "" {
					t.Errorf("%s algorithm not reported", name)
				}
			}
			if !slices.Contains(aeadCiphers, result.EncryptionClientToServer) && result.MACClientToServer == "" {
				t.Errorf("MAC client to server not reported for cipher %s", result.EncryptionClientToServer)
			}
			if !slices.Contains(aeadCiphers, result.EncryptionServerToClient) && result.MACServerToClient == "" {
				t.Errorf("MAC server to client not reported for cipher %s", result.EncryptionServerToClient)
			}
		})
	}
}

func TestRSAHostKey(t *testing.T) {
	rsaOnly := []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512}
	for _, name := range []string{"openssh-rocky8", "openssh-alpine"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := probeVerified(t, lookup(t, name).addr, probe.Options{HostKeyAlgorithms: rsaOnly})
			if !slices.Contains(rsaOnly, result.ServerHostKeyAlgorithm) {
				t.Errorf("host key algorithm = %q, want one of %q", result.ServerHostKeyAlgorithm, rsaOnly)
			}
		})
	}
}

func TestNoCommonHostKeyAlgorithm(t *testing.T) {
	addr := lookup(t, "openssh-alpine").addr
	trustOnFirstUse(t, addr, probe.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	// A stock sshd has no HostCertificate, so it offers no certificate algorithms.
	result := probe.Run(ctx, addr, probe.Options{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		HostKeyAlgorithms: []string{
			ssh.CertAlgoED25519v01,
			ssh.CertAlgoECDSA256v01,
			ssh.CertAlgoECDSA384v01,
			ssh.CertAlgoECDSA521v01,
			ssh.CertAlgoRSASHA512v01,
			ssh.CertAlgoRSASHA256v01,
		},
	})
	if result.ErrorPhase != probe.ErrPhaseKeyExchange || result.ErrorReason != probe.ErrReasonNoCommonHostKey {
		t.Errorf("error = %s/%s, want %s/%s", result.ErrorPhase, result.ErrorReason, probe.ErrPhaseKeyExchange, probe.ErrReasonNoCommonHostKey)
	}
}
