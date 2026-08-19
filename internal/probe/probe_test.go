package probe

import (
	"bytes"
	"context"
	"log/slog"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/sshtest"
)

// acceptKey returns a HostKeyCallback that accepts exactly want.
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
		t.Fatalf("TCPConnectSuccess = false, want true (error %s/%s)", result.ErrorStage, result.ErrorReason)
	}
	if result.TCPConnectDuration <= 0 {
		t.Error("TCPConnectDuration = 0, want > 0")
	}
	if !result.KEXSuccess {
		t.Errorf("KEXSuccess = false, want true (error %s/%s)", result.ErrorStage, result.ErrorReason)
	}
	if result.KEXDuration <= 0 {
		t.Error("KEXDuration = 0, want > 0")
	}
	if result.KEXAlgorithm == "" {
		t.Error("KEXAlgorithm is empty")
	}
	if !result.HostKeyVerifySuccess {
		t.Error("HostKeyVerifySuccess = false, want true")
	}
	if result.HostKeyAlgorithm != ssh.KeyAlgoED25519 {
		t.Errorf("HostKeyAlgorithm = %q, want %q", result.HostKeyAlgorithm, ssh.KeyAlgoED25519)
	}
	if result.ServerVersion != "SSH-2.0-TestServer_1.0" {
		t.Errorf("ServerVersion = %q, want SSH-2.0-TestServer_1.0", result.ServerVersion)
	}
	if result.ServerVersionMalformed {
		t.Error("ServerVersionMalformed = true, want false for a conforming banner")
	}
	if result.CipherRead == "" || result.CipherWrite == "" {
		t.Errorf("ciphers read=%q write=%q, want both set", result.CipherRead, result.CipherWrite)
	}
	if result.ErrorStage != "" || result.ErrorReason != "" {
		t.Errorf("error = %s/%s, want none", result.ErrorStage, result.ErrorReason)
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

	if !result.KEXSuccess {
		t.Fatalf("KEXSuccess = false, want true (stage %q, reason %q)", result.ErrorStage, result.ErrorReason)
	}
	for _, f := range []struct{ name, got string }{
		{"ServerVersion", result.ServerVersion},
		{"KEXAlgorithm", result.KEXAlgorithm},
		{"HostKeyAlgorithm", result.HostKeyAlgorithm},
		{"CipherRead", result.CipherRead},
		{"CipherWrite", result.CipherWrite},
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

	if !result.KEXSuccess {
		t.Fatalf("KEXSuccess = false (error %s/%s)", result.ErrorStage, result.ErrorReason)
	}
	if result.CipherRead != cipher || result.CipherWrite != cipher {
		t.Errorf("ciphers read=%q write=%q, want %q", result.CipherRead, result.CipherWrite, cipher)
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
	if result.KEXSuccess {
		t.Error("KEXSuccess = true, want false when no common host key algorithm")
	}
	if result.ErrorStage != ErrStageKeyExchange {
		t.Errorf("ErrorStage = %q, want %q", result.ErrorStage, ErrStageKeyExchange)
	}
}

func TestRunKeyExchangesRespected(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

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
	if result.KEXSuccess {
		t.Error("KEXSuccess = true, want false when no common key exchange")
	}
	if result.ErrorStage != ErrStageKeyExchange {
		t.Errorf("ErrorStage = %q, want %q", result.ErrorStage, ErrStageKeyExchange)
	}
}

// The configured MAC list decides which MAC a non-AEAD cipher agrees.
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

	if !result.KEXSuccess {
		t.Fatalf("KEXSuccess = false, want true (stage %q, reason %q)", result.ErrorStage, result.ErrorReason)
	}
	if result.MACRead != ssh.HMACSHA512 || result.MACWrite != ssh.HMACSHA512 {
		t.Errorf("MACs read=%q write=%q, want %q", result.MACRead, result.MACWrite, ssh.HMACSHA512)
	}
}

// A non-AEAD cipher agrees a MAC, which is reported per direction.
func TestRunNonAEADCipherReportsMAC(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{
		HostKeyCallback: acceptKey(srv.HostKey),
		Ciphers:         []string{ssh.CipherAES128CTR},
	})

	if !result.KEXSuccess {
		t.Fatalf("KEXSuccess = false, want true (stage %q, reason %q)", result.ErrorStage, result.ErrorReason)
	}
	if result.MACRead == "" || result.MACWrite == "" {
		t.Errorf("MACs read=%q write=%q, want both set for a non-AEAD cipher", result.MACRead, result.MACWrite)
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

	if !result.KEXSuccess {
		t.Fatalf("KEXSuccess = false, want true (stage %q, reason %q)", result.ErrorStage, result.ErrorReason)
	}
	if result.MACRead != "" || result.MACWrite != "" {
		t.Errorf("MACs read=%q write=%q, want both empty for an AEAD cipher", result.MACRead, result.MACWrite)
	}
}

func TestRunStripsServerVersionComment(t *testing.T) {
	t.Parallel()
	const banner = "SSH-2.0-TestServer_1.0 Debian-2+deb12u10"

	for _, tt := range []struct {
		name  string
		strip bool
		want  string
	}{
		{"off keeps the comment", false, banner},
		{"on drops the comment", true, "SSH-2.0-TestServer_1.0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := sshtest.NewServer(t, sshtest.Options{ServerVersion: banner})

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result := Run(ctx, srv.Addr, Options{
				HostKeyCallback:           acceptKey(srv.HostKey),
				StripServerVersionComment: tt.strip,
			})

			if result.ServerVersionMalformed {
				t.Fatal("ServerVersionMalformed = true, want false")
			}
			if result.ServerVersion != tt.want {
				t.Errorf("ServerVersion = %q, want %q", result.ServerVersion, tt.want)
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
	if !result.KEXSuccess {
		t.Error("KEXSuccess = false, want true (KEX completes before verification)")
	}
	if result.HostKeyVerifySuccess {
		t.Error("HostKeyVerifySuccess = true, want false")
	}
	if result.ErrorStage != ErrStageHostKeyVerify {
		t.Errorf("ErrorStage = %q, want %q", result.ErrorStage, ErrStageHostKeyVerify)
	}
	// ssh.FixedHostKey returns a plain error, so it classifies as "other".
	if result.ErrorReason != ErrReasonOther {
		t.Errorf("ErrorReason = %q, want %q", result.ErrorReason, ErrReasonOther)
	}
	// Metadata is still recorded despite the verification failure.
	if result.HostKeyAlgorithm == "" || result.KEXAlgorithm == "" {
		t.Error("expected algorithm metadata to be recorded despite verify failure")
	}
}

func TestRunNilHostKeyCallback(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{})

	if result.HostKeyVerifySuccess {
		t.Error("HostKeyVerifySuccess = true, want false without a callback")
	}
	if result.ErrorStage != ErrStageHostKeyVerify {
		t.Errorf("ErrorStage = %q, want %q", result.ErrorStage, ErrStageHostKeyVerify)
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
	if result.ErrorStage != ErrStageTCPConnect {
		t.Errorf("ErrorStage = %q, want %q", result.ErrorStage, ErrStageTCPConnect)
	}
	if result.ErrorReason != ErrReasonConnectionRefused {
		t.Errorf("ErrorReason = %q, want %q", result.ErrorReason, ErrReasonConnectionRefused)
	}
	if result.KEXSuccess || result.HostKeyVerifySuccess {
		t.Error("KEX/host key reported success on a refused connection")
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
	if result.ErrorStage != ErrStageTCPConnect {
		t.Errorf("ErrorStage = %q, want %q", result.ErrorStage, ErrStageTCPConnect)
	}
	if result.ErrorReason != ErrReasonDNSFailure {
		t.Errorf("ErrorReason = %q, want %q", result.ErrorReason, ErrReasonDNSFailure)
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
	if result.ErrorStage != ErrStageTCPConnect {
		t.Errorf("ErrorStage = %q, want %q", result.ErrorStage, ErrStageTCPConnect)
	}
}

func TestRunKexTimeout(t *testing.T) {
	t.Parallel()
	addr := sshtest.SilentServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	result := Run(ctx, addr, Options{HostKeyCallback: ssh.InsecureIgnoreHostKey()})

	if !result.TCPConnectSuccess {
		t.Fatal("TCPConnectSuccess = false, want true (TCP connect should succeed)")
	}
	if result.KEXSuccess {
		t.Error("KEXSuccess = true, want false")
	}
	if result.ErrorStage != ErrStageKeyExchange {
		t.Errorf("ErrorStage = %q, want %q", result.ErrorStage, ErrStageKeyExchange)
	}
	if result.ErrorReason != ErrReasonTimeout {
		t.Errorf("ErrorReason = %q, want %q", result.ErrorReason, ErrReasonTimeout)
	}
}

func TestRunKexCanceled(t *testing.T) {
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
	if result.ErrorStage != ErrStageKeyExchange {
		t.Errorf("ErrorStage = %q, want %q", result.ErrorStage, ErrStageKeyExchange)
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
		if result.TCPConnectNegotiatedMSS <= 0 {
			t.Errorf("TCPConnectNegotiatedMSS = %d, want > 0 on linux", result.TCPConnectNegotiatedMSS)
		}
	} else if result.TCPConnectNegotiatedMSS != 0 {
		t.Errorf("TCPConnectNegotiatedMSS = %d, want 0 on %s", result.TCPConnectNegotiatedMSS, runtime.GOOS)
	}
}

func TestRunNilLoggerDoesNotPanic(t *testing.T) {
	t.Parallel()
	srv := sshtest.NewServer(t, sshtest.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{HostKeyCallback: acceptKey(srv.HostKey), Logger: nil})
	if !result.KEXSuccess {
		t.Errorf("KEXSuccess = false with nil logger (error %s/%s)", result.ErrorStage, result.ErrorReason)
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
	if !result.KEXSuccess {
		t.Fatalf("KEXSuccess = false (error %s/%s)", result.ErrorStage, result.ErrorReason)
	}
	// On non-Linux the MSS read fails and logs at debug level; on Linux it
	// succeeds and logs nothing. Either way the probe must not warn about the
	// abort sentinel, which would signal an x/crypto behavior change.
	if strings.Contains(buf.String(), "abort sentinel") {
		t.Errorf("probe logged the abort-sentinel warning: %s", buf.String())
	}
}

func TestRunSanitizesServerVersion(t *testing.T) {
	t.Parallel()
	// Banner containing a DEL byte, which must not reach the label.
	srv := sshtest.NewServer(t, sshtest.Options{ServerVersion: "SSH-2.0-Test\x7fServer"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Run(ctx, srv.Addr, Options{HostKeyCallback: acceptKey(srv.HostKey)})
	if result.ServerVersion != "" {
		t.Errorf("ServerVersion = %q, want it dropped as malformed", result.ServerVersion)
	}
	if !result.ServerVersionMalformed {
		t.Error("ServerVersionMalformed = false, want true")
	}
	// The probe itself still succeeds; only the banner is withheld.
	if !result.KEXSuccess {
		t.Error("KEXSuccess = false, want true")
	}
}
