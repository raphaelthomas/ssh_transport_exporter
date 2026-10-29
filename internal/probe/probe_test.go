package probe

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/sshtest"
)

func acceptKey(want ssh.PublicKey) ssh.HostKeyCallback {
	return ssh.FixedHostKey(want)
}

func TestRunSuccess(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{ServerVersion: "SSH-2.0-TestServer_1.0"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{HostKeyCallback: acceptKey(srv.HostKey)})

	if !result.TCPConnectSuccess {
		t.Fatalf("TCPConnectSuccess = false, want true (error %s/%s)", result.ErrorPhase, result.ErrorReason)
	}
	if result.TCPConnectDuration <= 0 {
		t.Error("TCPConnectDuration = 0, want > 0")
	}
	if result.DNSLookup || result.DNSLookupSuccess || result.DNSLookupDuration != 0 {
		t.Errorf("DNSLookup = %t, DNSLookupSuccess = %t, DNSLookupDuration = %s, want none for an IP literal target", result.DNSLookup, result.DNSLookupSuccess, result.DNSLookupDuration)
	}
	if !result.KeyExchangeSuccess {
		t.Errorf("KeyExchangeSuccess = false, want true (error %s/%s)", result.ErrorPhase, result.ErrorReason)
	}
	if result.KeyExchangeDuration <= 0 {
		t.Error("KeyExchangeDuration = 0, want > 0")
	}
	if result.KEXAlgorithm == "" {
		t.Error("KEXAlgorithm is empty")
	}
	if !result.ServerHostKeyVerifySuccess {
		t.Error("ServerHostKeyVerifySuccess = false, want true")
	}
	if result.ServerHostKeyAlgorithm != ssh.KeyAlgoED25519 {
		t.Errorf("ServerHostKeyAlgorithm = %q, want %q", result.ServerHostKeyAlgorithm, ssh.KeyAlgoED25519)
	}
	if want := (ServerIdentification{"SSH-2.0-TestServer_1.0", "2.0", "TestServer_1.0", "", true}); result.ServerIdentification != want {
		t.Errorf("ServerIdentification = %+v, want %+v", result.ServerIdentification, want)
	}
	if result.EncryptionClientToServer == "" || result.EncryptionServerToClient == "" {
		t.Errorf("encryption client_to_server=%q server_to_client=%q, want both set", result.EncryptionClientToServer, result.EncryptionServerToClient)
	}
	if result.ErrorPhase != "" || result.ErrorReason != "" {
		t.Errorf("error = %s/%s, want none", result.ErrorPhase, result.ErrorReason)
	}
	if !result.Success {
		t.Error("Success = false, want true")
	}
	if !result.VersionExchangeSuccess || result.VersionExchangeDuration <= 0 {
		t.Errorf("VersionExchangeSuccess = %t, VersionExchangeDuration = %s, want true, > 0", result.VersionExchangeSuccess, result.VersionExchangeDuration)
	}
	if phases := result.TCPConnectDuration + result.VersionExchangeDuration + result.KeyExchangeDuration; result.Duration < phases {
		t.Errorf("Duration = %s, want at least the sum of the phases (%s)", result.Duration, phases)
	}
}

// Everything the probe reports beyond the TCP and key exchange timings is
// recorded in TransportReadyCallback, whose errAbort return ends the handshake
// before user authentication. Were the callback to stop firing, the fields
// below would stay empty and the probe would authenticate.
func TestRunAbortsAtTransportReady(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{HostKeyCallback: acceptKey(srv.HostKey)})

	if !result.KeyExchangeSuccess {
		t.Fatalf("KeyExchangeSuccess = false, want true (phase %q, reason %q)", result.ErrorPhase, result.ErrorReason)
	}
	for _, f := range []struct{ name, got string }{
		{"ServerIdentification", result.ServerIdentification.String},
		{"KEXAlgorithm", result.KEXAlgorithm},
		{"ServerHostKeyAlgorithm", result.ServerHostKeyAlgorithm},
		{"EncryptionClientToServer", result.EncryptionClientToServer},
		{"EncryptionServerToClient", result.EncryptionServerToClient},
	} {
		if f.got == "" {
			t.Errorf("%s is empty, want it recorded by TransportReadyCallback", f.name)
		}
	}
	if srv.AuthReached() {
		t.Error("server reached user authentication, want the probe to abort before it")
	}
}

func TestRunNegotiatesRequestedCipher(t *testing.T) {
	t.Parallel()
	const cipher = "aes128-ctr"
	srv := sshtest.NewServer(t, sshtest.Options{Ciphers: []string{cipher}})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{
		HostKeyCallback: acceptKey(srv.HostKey),
		Ciphers:         []string{cipher},
	})

	if !result.KeyExchangeSuccess {
		t.Fatalf("KeyExchangeSuccess = false (error %s/%s)", result.ErrorPhase, result.ErrorReason)
	}
	if result.EncryptionClientToServer != cipher || result.EncryptionServerToClient != cipher {
		t.Errorf("encryption client_to_server=%q server_to_client=%q, want %q", result.EncryptionClientToServer, result.EncryptionServerToClient, cipher)
	}
}

func TestRunHostKeyAlgorithmsRespected(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The server only has an ed25519 host key; demanding RSA must fail KEX.
	result := Run(ctx, srv.Addr, Options{
		HostKeyCallback:   acceptKey(srv.HostKey),
		HostKeyAlgorithms: []string{ssh.KeyAlgoRSASHA256},
	})

	if !result.TCPConnectSuccess {
		t.Fatal("TCPConnectSuccess = false, want true")
	}
	if result.KeyExchangeSuccess {
		t.Error("KeyExchangeSuccess = true, want false when no common host key algorithm")
	}
	if result.ErrorPhase != ErrPhaseKeyExchange {
		t.Errorf("ErrorPhase = %q, want %q", result.ErrorPhase, ErrPhaseKeyExchange)
	}
}

func TestRunKeyExchangesRespected(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{ServerVersion: "SSH-2.0-TestServer_1.0"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The server offers only its defaults, which exclude this insecure kex.
	result := Run(ctx, srv.Addr, Options{
		HostKeyCallback: acceptKey(srv.HostKey),
		KeyExchanges:    []string{ssh.InsecureKeyExchangeDH1SHA1},
	})

	if !result.TCPConnectSuccess {
		t.Fatal("TCPConnectSuccess = false, want true")
	}
	if !result.VersionExchangeSuccess {
		t.Error("VersionExchangeSuccess = false, want true before the key exchange fails")
	}
	if got := result.ServerIdentification.String; got != "SSH-2.0-TestServer_1.0" {
		t.Errorf("ServerIdentification = %q, want SSH-2.0-TestServer_1.0 although the key exchange failed", got)
	}
	if result.KeyExchangeSuccess {
		t.Error("KeyExchangeSuccess = true, want false when no common key exchange")
	}
	if result.ErrorPhase != ErrPhaseKeyExchange {
		t.Errorf("ErrorPhase = %q, want %q", result.ErrorPhase, ErrPhaseKeyExchange)
	}
}

func TestRunMACsRespected(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{
		HostKeyCallback: acceptKey(srv.HostKey),
		Ciphers:         []string{ssh.CipherAES128CTR},
		MACs:            []string{ssh.HMACSHA512},
	})

	if !result.KeyExchangeSuccess {
		t.Fatalf("KeyExchangeSuccess = false, want true (phase %q, reason %q)", result.ErrorPhase, result.ErrorReason)
	}
	if result.MACClientToServer != ssh.HMACSHA512 || result.MACServerToClient != ssh.HMACSHA512 {
		t.Errorf("MACs client_to_server=%q server_to_client=%q, want %q", result.MACClientToServer, result.MACServerToClient, ssh.HMACSHA512)
	}
}

func TestRunNonAEADCipherReportsMAC(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{
		HostKeyCallback: acceptKey(srv.HostKey),
		Ciphers:         []string{ssh.CipherAES128CTR},
	})

	if !result.KeyExchangeSuccess {
		t.Fatalf("KeyExchangeSuccess = false, want true (phase %q, reason %q)", result.ErrorPhase, result.ErrorReason)
	}
	if result.MACClientToServer == "" || result.MACServerToClient == "" {
		t.Errorf("MACs client_to_server=%q server_to_client=%q, want both set for a non-AEAD cipher", result.MACClientToServer, result.MACServerToClient)
	}
}

// AEAD ciphers provide integrity themselves, so no MAC is negotiated.
func TestRunAEADCipherReportsNoMAC(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{
		HostKeyCallback: acceptKey(srv.HostKey),
		Ciphers:         []string{ssh.CipherAES128GCM},
	})

	if !result.KeyExchangeSuccess {
		t.Fatalf("KeyExchangeSuccess = false, want true (phase %q, reason %q)", result.ErrorPhase, result.ErrorReason)
	}
	if result.MACClientToServer != "" || result.MACServerToClient != "" {
		t.Errorf("MACs client_to_server=%q server_to_client=%q, want both empty for an AEAD cipher", result.MACClientToServer, result.MACServerToClient)
	}
}

func TestRunStripsServerIdentificationComments(t *testing.T) {
	t.Parallel()
	const banner = "SSH-2.0-TestServer_1.0 Debian-2+deb12u10"

	for _, tt := range []struct {
		name         string
		strip        bool
		want         string
		wantComments string
	}{
		{"off keeps the comments", false, banner, "Debian-2+deb12u10"},
		{"on drops the comments", true, "SSH-2.0-TestServer_1.0", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := sshtest.NewServer(t, sshtest.Options{ServerVersion: banner})

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result := Run(ctx, srv.Addr, Options{
				HostKeyCallback:                   acceptKey(srv.HostKey),
				StripServerIdentificationComments: tt.strip,
			})

			if got := result.ServerIdentification; got.String != tt.want || got.Comments != tt.wantComments {
				t.Errorf("ServerIdentification = %q, comments %q, want %q, comments %q", got.String, got.Comments, tt.want, tt.wantComments)
			}
		})
	}
}

func TestRunHostKeyVerificationFailure(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	// A callback for a different key: KEX still completes, verification fails.
	otherSrv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{HostKeyCallback: acceptKey(otherSrv.HostKey)})

	if !result.TCPConnectSuccess {
		t.Fatal("TCPConnectSuccess = false, want true")
	}
	if !result.KeyExchangeSuccess {
		t.Error("KeyExchangeSuccess = false, want true (KEX completes before verification)")
	}
	if result.Success {
		t.Error("Success = true, want false when the host key was rejected")
	}
	if result.ServerHostKeyVerifySuccess {
		t.Error("ServerHostKeyVerifySuccess = true, want false")
	}
	if result.ErrorPhase != ErrPhaseKeyExchange {
		t.Errorf("ErrorPhase = %q, want %q", result.ErrorPhase, ErrPhaseKeyExchange)
	}
	// ssh.FixedHostKey returns a plain error rather than a knownhosts one.
	if result.ErrorReason != ErrReasonServerHostKeyRejected {
		t.Errorf("ErrorReason = %q, want %q", result.ErrorReason, ErrReasonServerHostKeyRejected)
	}
	if result.ServerHostKeyAlgorithm == "" || result.KEXAlgorithm == "" {
		t.Error("expected algorithm metadata to be recorded despite verify failure")
	}
}

func TestRunNilHostKeyCallback(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{})

	if result.ServerHostKeyVerifySuccess {
		t.Error("ServerHostKeyVerifySuccess = true, want false without a callback")
	}
	if result.ErrorPhase != ErrPhaseKeyExchange {
		t.Errorf("ErrorPhase = %q, want %q", result.ErrorPhase, ErrPhaseKeyExchange)
	}
	if result.ErrorReason != ErrReasonServerHostKeyRejected {
		t.Errorf("ErrorReason = %q, want %q", result.ErrorReason, ErrReasonServerHostKeyRejected)
	}
}

func TestRunConnectionRefused(t *testing.T) {
	t.Parallel()
	addr := sshtest.ClosedPort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, addr, Options{HostKeyCallback: ssh.InsecureIgnoreHostKey()})

	if result.TCPConnectSuccess {
		t.Error("TCPConnectSuccess = true, want false")
	}
	if result.ErrorPhase != ErrPhaseTCPConnect {
		t.Errorf("ErrorPhase = %q, want %q", result.ErrorPhase, ErrPhaseTCPConnect)
	}
	if result.ErrorReason != ErrReasonConnectionRefused {
		t.Errorf("ErrorReason = %q, want %q", result.ErrorReason, ErrReasonConnectionRefused)
	}
	if result.KeyExchangeSuccess || result.ServerHostKeyVerifySuccess {
		t.Error("KEX/host key reported success on a refused connection")
	}
	if result.Duration <= 0 {
		t.Error("Duration = 0, want > 0 on an early failure")
	}
	if result.Success {
		t.Error("Success = true, want false on a refused connection")
	}
}

func TestRunHostnameTargetTimesLookup(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, net.JoinHostPort("localhost", srv.Port(t)), Options{HostKeyCallback: acceptKey(srv.HostKey)})

	if !result.TCPConnectSuccess {
		t.Fatalf("TCPConnectSuccess = false, want true (error %s/%s)", result.ErrorPhase, result.ErrorReason)
	}
	if !result.DNSLookup || !result.DNSLookupSuccess {
		t.Errorf("DNSLookup = %t, DNSLookupSuccess = %t, want both true for a hostname target", result.DNSLookup, result.DNSLookupSuccess)
	}
	if result.DNSLookupDuration <= 0 {
		t.Error("DNSLookupDuration = 0, want > 0 for a hostname target")
	}
	if result.TCPConnectDuration <= 0 {
		t.Error("TCPConnectDuration = 0, want > 0")
	}
}

func TestRunHostnameTargetConnectionRefusedKeepsLookup(t *testing.T) {
	t.Parallel()
	_, port, err := net.SplitHostPort(sshtest.ClosedPort(t))
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, net.JoinHostPort("localhost", port), Options{HostKeyCallback: ssh.InsecureIgnoreHostKey()})

	if result.TCPConnectSuccess {
		t.Error("TCPConnectSuccess = true, want false")
	}
	if result.ErrorReason != ErrReasonConnectionRefused {
		t.Errorf("ErrorReason = %q, want %q", result.ErrorReason, ErrReasonConnectionRefused)
	}
	if !result.DNSLookupSuccess {
		t.Error("DNSLookupSuccess = false, want true when the lookup succeeded")
	}
	if result.DNSLookupDuration <= 0 {
		t.Error("DNSLookupDuration = 0, want > 0 when the lookup succeeded")
	}
}

func TestRunDNSFailure(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, "no-such-host.invalid:22", Options{HostKeyCallback: ssh.InsecureIgnoreHostKey()})

	if result.TCPConnectSuccess {
		t.Error("TCPConnectSuccess = true, want false")
	}
	if result.ErrorPhase != ErrPhaseDNSLookup {
		t.Errorf("ErrorPhase = %q, want %q", result.ErrorPhase, ErrPhaseDNSLookup)
	}
	if result.ErrorReason != ErrReasonDNSFailure {
		t.Errorf("ErrorReason = %q, want %q", result.ErrorReason, ErrReasonDNSFailure)
	}
	if !result.DNSLookup || result.DNSLookupSuccess {
		t.Errorf("DNSLookup = %t, DNSLookupSuccess = %t, want true, false when the lookup failed", result.DNSLookup, result.DNSLookupSuccess)
	}
	if result.DNSLookupDuration != 0 {
		t.Errorf("DNSLookupDuration = %s, want 0 when the lookup failed", result.DNSLookupDuration)
	}
}

func TestRunContextAlreadyCanceled(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before the dial

	result := Run(ctx, srv.Addr, Options{HostKeyCallback: acceptKey(srv.HostKey)})

	if result.TCPConnectSuccess {
		t.Error("TCPConnectSuccess = true, want false for a canceled context")
	}
	if result.ErrorPhase != ErrPhaseTCPConnect {
		t.Errorf("ErrorPhase = %q, want %q", result.ErrorPhase, ErrPhaseTCPConnect)
	}
}

func TestRunContextAlreadyCanceledHostname(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before the lookup

	result := Run(ctx, "localhost:22", Options{HostKeyCallback: ssh.InsecureIgnoreHostKey()})

	if result.ErrorPhase != ErrPhaseDNSLookup {
		t.Errorf("ErrorPhase = %q, want %q", result.ErrorPhase, ErrPhaseDNSLookup)
	}
	if result.ErrorReason != ErrReasonCanceled {
		t.Errorf("ErrorReason = %q, want %q", result.ErrorReason, ErrReasonCanceled)
	}
}

func TestRunPeerHangup(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		reset bool
	}{
		{"clean close", false},
		{"reset", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			addr := sshtest.HangupServer(t, tt.reset)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result := Run(ctx, addr, Options{HostKeyCallback: ssh.InsecureIgnoreHostKey()})

			if !result.TCPConnectSuccess {
				t.Fatalf("TCPConnectSuccess = false, want true (error %s/%s)", result.ErrorPhase, result.ErrorReason)
			}
			if result.KeyExchangeSuccess {
				t.Error("KeyExchangeSuccess = true, want false")
			}
			if result.ErrorPhase != ErrPhaseVersionExchange {
				t.Errorf("ErrorPhase = %q, want %q", result.ErrorPhase, ErrPhaseVersionExchange)
			}
			if result.ErrorReason != ErrReasonConnectionReset {
				t.Errorf("ErrorReason = %q, want %q", result.ErrorReason, ErrReasonConnectionReset)
			}
		})
	}
}

func slowHostKeyCallback(delay time.Duration, cb ssh.HostKeyCallback) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		time.Sleep(delay)
		return cb(hostname, remote, key)
	}
}

func TestRunKexFailsAfterHostKeyAccepted(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{HostKeyCallback: slowHostKeyCallback(500*time.Millisecond, acceptKey(srv.HostKey))})

	if result.KeyExchangeSuccess {
		t.Error("KeyExchangeSuccess = true, want false when NEWKEYS never completed")
	}
	if result.KeyExchangeDuration != 0 {
		t.Errorf("KeyExchangeDuration = %s, want 0", result.KeyExchangeDuration)
	}
	if !result.ServerHostKeyVerifySuccess {
		t.Error("ServerHostKeyVerifySuccess = false, want true")
	}
	if result.ErrorPhase != ErrPhaseKeyExchange || result.ErrorReason != ErrReasonTimeout {
		t.Errorf("error = %s/%s, want %s/%s", result.ErrorPhase, result.ErrorReason, ErrPhaseKeyExchange, ErrReasonTimeout)
	}
}

func TestRunHostKeyFailureOutranksLaterKexFailure(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})
	otherSrv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{HostKeyCallback: slowHostKeyCallback(500*time.Millisecond, acceptKey(otherSrv.HostKey))})

	if result.KeyExchangeSuccess {
		t.Error("KeyExchangeSuccess = true, want false when NEWKEYS never completed")
	}
	if result.ServerHostKeyVerifySuccess {
		t.Error("ServerHostKeyVerifySuccess = true, want false")
	}
	if result.ErrorPhase != ErrPhaseKeyExchange || result.ErrorReason != ErrReasonServerHostKeyRejected {
		t.Errorf("error = %s/%s, want %s/%s", result.ErrorPhase, result.ErrorReason, ErrPhaseKeyExchange, ErrReasonServerHostKeyRejected)
	}
}

func TestRunVersionExchangeTimeout(t *testing.T) {
	t.Parallel()
	addr := sshtest.SilentServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	result := Run(ctx, addr, Options{HostKeyCallback: ssh.InsecureIgnoreHostKey()})

	if !result.TCPConnectSuccess {
		t.Fatal("TCPConnectSuccess = false, want true (TCP connect should succeed)")
	}
	if result.VersionExchangeSuccess || result.KeyExchangeSuccess {
		t.Errorf("VersionExchangeSuccess = %t, KeyExchangeSuccess = %t, want both false", result.VersionExchangeSuccess, result.KeyExchangeSuccess)
	}
	if result.ErrorPhase != ErrPhaseVersionExchange {
		t.Errorf("ErrorPhase = %q, want %q", result.ErrorPhase, ErrPhaseVersionExchange)
	}
	if result.ErrorReason != ErrReasonTimeout {
		t.Errorf("ErrorReason = %q, want %q", result.ErrorReason, ErrReasonTimeout)
	}
}

func TestRunVersionExchangeCanceled(t *testing.T) {
	t.Parallel()
	addr := sshtest.SilentServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	defer cancel()

	result := Run(ctx, addr, Options{HostKeyCallback: ssh.InsecureIgnoreHostKey()})

	if !result.TCPConnectSuccess {
		t.Fatal("TCPConnectSuccess = false, want true (TCP connect should succeed)")
	}
	if result.ErrorPhase != ErrPhaseVersionExchange {
		t.Errorf("ErrorPhase = %q, want %q", result.ErrorPhase, ErrPhaseVersionExchange)
	}
	if result.ErrorReason != ErrReasonCanceled {
		t.Errorf("ErrorReason = %q, want %q", result.ErrorReason, ErrReasonCanceled)
	}
}

func TestRunNegotiatedMSS(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{HostKeyCallback: acceptKey(srv.HostKey)})

	if runtime.GOOS == "linux" {
		if result.TCPMSS <= 0 {
			t.Errorf("TCPMSS = %d, want > 0 on linux", result.TCPMSS)
		}
	} else if result.TCPMSS != 0 {
		t.Errorf("TCPMSS = %d, want 0 on %s", result.TCPMSS, runtime.GOOS)
	}
}

func TestRunNilLoggerDoesNotPanic(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{HostKeyCallback: acceptKey(srv.HostKey), Logger: nil})
	if !result.KeyExchangeSuccess {
		t.Errorf("KeyExchangeSuccess = false with nil logger (error %s/%s)", result.ErrorPhase, result.ErrorReason)
	}
}

func TestRunDebugLoggingEnabled(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{HostKeyCallback: acceptKey(srv.HostKey), Logger: logger})
	if !result.KeyExchangeSuccess {
		t.Fatalf("KeyExchangeSuccess = false (error %s/%s)", result.ErrorPhase, result.ErrorReason)
	}
	// On non-Linux the MSS read fails and logs at debug level; on Linux it
	// succeeds and logs nothing. Either way the probe must not log an error,
	// which would signal that it was not aborted before user authentication.
	if strings.Contains(buf.String(), "level=ERROR") {
		t.Errorf("probe logged an error: %s", buf.String())
	}
}

func TestRunDropsUnparsableServerIdentification(t *testing.T) {
	t.Parallel()
	// Banner containing a DEL byte, which must not reach the label.
	srv := sshtest.NewServer(t, sshtest.Options{ServerVersion: "SSH-2.0-Test\x7fServer"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{HostKeyCallback: acceptKey(srv.HostKey)})
	if result.ServerIdentification != (ServerIdentification{}) {
		t.Errorf("ServerIdentification = %+v, want it dropped as unparsable", result.ServerIdentification)
	}
	if !result.VersionExchangeSuccess {
		t.Error("VersionExchangeSuccess = false, want true")
	}
	if !result.KeyExchangeSuccess {
		t.Error("KeyExchangeSuccess = false, want true")
	}
}

func TestIdentificationWatcher(t *testing.T) {
	t.Parallel()
	const stream = "Hello\r\nSSH\r\nSSH-2.0-Foo_1.0\r\n\x00\x00\x00\x0c"
	for _, size := range []int{1, 3, len(stream)} {
		t.Run(fmt.Sprintf("reads of %d bytes", size), func(t *testing.T) {
			t.Parallel()
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			go func() {
				_, _ = server.Write([]byte(stream))
				_ = server.Close()
			}()

			w := &identificationWatcher{Conn: client}
			buf := make([]byte, size)
			var read []byte
			for {
				n, err := w.Read(buf)
				read = append(read, buf[:n]...)
				if w.received.Load() != nil {
					break
				}
				if err != nil {
					t.Fatalf("identification string not detected; read %q: %v", read, err)
				}
			}
			// Detection must happen in the read that delivers the newline.
			want := "Hello\r\nSSH\r\nSSH-2.0-Foo_1.0\r\n"
			if !strings.HasPrefix(string(read), want) || len(read) >= len(want)+size {
				t.Errorf("detected after %q, want after %q", read, want)
			}
			if got := string(w.identification); got != "SSH-2.0-Foo_1.0" {
				t.Errorf("identification = %q, want SSH-2.0-Foo_1.0 without CR LF", got)
			}
		})
	}
}

func TestIdentificationWatcherIgnoresOtherLines(t *testing.T) {
	t.Parallel()
	w := &identificationWatcher{}
	w.scan([]byte("Hello\r\nSSH\r\nNot SSH-2.0-Foo\r\n"))
	if w.received.Load() != nil {
		t.Error("identification string detected in lines not starting with SSH-")
	}
}

func TestIdentificationWatcherCapsLongLines(t *testing.T) {
	t.Parallel()
	w := &identificationWatcher{}
	w.scan([]byte("SSH-2.0-" + strings.Repeat("a", 1000) + "\r\n"))
	if w.received.Load() == nil {
		t.Fatal("identification string not detected")
	}
	if _, err := parseServerIdentification(w.identification); err == nil {
		t.Errorf("capped %d byte identification string was parsed, want an error", len(w.identification))
	}
}
