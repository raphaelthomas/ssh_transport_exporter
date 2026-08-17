package collector

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/probe"
)

// collectMetrics runs the collector with its probe function stubbed to return
// result and returns the gathered metric families keyed by fully-qualified name.
func collectMetrics(t *testing.T, result probe.Result) map[string]*dto.MetricFamily {
	t.Helper()

	c := New(context.Background(), "example.com:22", "default", probe.Options{}, nil)
	c.run = func(context.Context, string, probe.Options) probe.Result { return result }

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	byName := make(map[string]*dto.MetricFamily, len(mfs))
	for _, mf := range mfs {
		byName[mf.GetName()] = mf
	}
	return byName
}

// singleValue returns the value of a metric family that has exactly one series.
func singleValue(t *testing.T, mfs map[string]*dto.MetricFamily, name string) float64 {
	t.Helper()
	mf, ok := mfs[name]
	if !ok {
		t.Fatalf("metric %q not present", name)
	}
	if len(mf.GetMetric()) != 1 {
		t.Fatalf("metric %q has %d series, want 1", name, len(mf.GetMetric()))
	}
	return mf.GetMetric()[0].GetGauge().GetValue()
}

// labelValue returns the value of label key on the (first) series of name.
func labelValue(t *testing.T, mfs map[string]*dto.MetricFamily, name, key string) string {
	t.Helper()
	mf, ok := mfs[name]
	if !ok {
		t.Fatalf("metric %q not present", name)
	}
	for _, lp := range mf.GetMetric()[0].GetLabel() {
		if lp.GetName() == key {
			return lp.GetValue()
		}
	}
	t.Fatalf("metric %q series has no label %q", name, key)
	return ""
}

// directionSeries returns the series of metric name carrying the given
// direction label, or nil.
func directionSeries(mfs map[string]*dto.MetricFamily, name, direction string) *dto.Metric {
	mf, ok := mfs[name]
	if !ok {
		return nil
	}
	for _, m := range mf.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetName() == "direction" && lp.GetValue() == direction {
				return m
			}
		}
	}
	return nil
}

func TestCollectFullSuccess(t *testing.T) {
	t.Parallel()
	result := probe.Result{
		TCPConnectSuccess:       true,
		TCPConnectDuration:      500 * time.Millisecond,
		TCPConnectNegotiatedMSS: 1448,
		ServerVersion:           "SSH-2.0-OpenSSH_9.6",
		KEXSuccess:              true,
		KEXDuration:             time.Second,
		KEXAlgorithm:            "curve25519-sha256",
		HostKeyVerifySuccess:    true,
		HostKeyAlgorithm:        "ssh-ed25519",
		CipherRead:              "aes128-gcm@openssh.com",
		CipherWrite:             "chacha20-poly1305@openssh.com",
	}
	mfs := collectMetrics(t, result)

	if got := singleValue(t, mfs, "ssh_transport_tcp_connect_success"); got != 1 {
		t.Errorf("tcp_connect_success = %v, want 1", got)
	}
	if got := singleValue(t, mfs, "ssh_transport_tcp_connect_duration_seconds"); got != 0.5 {
		t.Errorf("tcp_connect_duration_seconds = %v, want 0.5", got)
	}
	if got := singleValue(t, mfs, "ssh_transport_tcp_connect_negotiated_mss_bytes"); got != 1448 {
		t.Errorf("negotiated_mss_bytes = %v, want 1448", got)
	}
	if got := labelValue(t, mfs, "ssh_transport_identification_server_version_info", "version"); got != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("server_version_info version = %q", got)
	}
	if got := singleValue(t, mfs, "ssh_transport_kex_success"); got != 1 {
		t.Errorf("kex_success = %v, want 1", got)
	}
	if got := singleValue(t, mfs, "ssh_transport_kex_duration_seconds"); got != 1 {
		t.Errorf("kex_duration_seconds = %v, want 1", got)
	}
	if got := labelValue(t, mfs, "ssh_transport_kex_algorithm_info", "algorithm"); got != "curve25519-sha256" {
		t.Errorf("kex_algorithm_info algorithm = %q", got)
	}
	if got := singleValue(t, mfs, "ssh_transport_host_key_verify_success"); got != 1 {
		t.Errorf("host_key_verify_success = %v, want 1", got)
	}
	if got := labelValue(t, mfs, "ssh_transport_host_key_verify_algorithm_info", "algorithm"); got != "ssh-ed25519" {
		t.Errorf("host_key_verify_algorithm_info algorithm = %q", got)
	}

	if m := directionSeries(mfs, "ssh_transport_cipher_info", "read"); m == nil {
		t.Error("cipher_info read series missing")
	} else if got := labelOf(m, "cipher"); got != "aes128-gcm@openssh.com" {
		t.Errorf("cipher_info read cipher = %q", got)
	}
	if m := directionSeries(mfs, "ssh_transport_cipher_info", "write"); m == nil {
		t.Error("cipher_info write series missing")
	} else if got := labelOf(m, "cipher"); got != "chacha20-poly1305@openssh.com" {
		t.Errorf("cipher_info write cipher = %q", got)
	}

	// The sample negotiates AEAD ciphers, so no separate MAC is agreed.
	if _, ok := mfs["ssh_transport_mac_info"]; ok {
		t.Error("mac_info present for AEAD ciphers, want absent")
	}

	if got := singleValue(t, mfs, "ssh_transport_identification_server_version_valid"); got != 1 {
		t.Errorf("server_version_valid = %v, want 1", got)
	}

	if _, ok := mfs["ssh_transport_error_info"]; ok {
		t.Error("error_info present on a fully successful probe, want absent")
	}
}

// A rejected banner is reported as invalid rather than vanishing silently.
func TestCollectMalformedServerVersion(t *testing.T) {
	t.Parallel()
	mfs := collectMetrics(t, probe.Result{
		TCPConnectSuccess:      true,
		KEXSuccess:             true,
		ServerVersionMalformed: true,
	})

	if got := singleValue(t, mfs, "ssh_transport_identification_server_version_valid"); got != 0 {
		t.Errorf("server_version_valid = %v, want 0", got)
	}
	if _, ok := mfs["ssh_transport_identification_server_version_info"]; ok {
		t.Error("server_version_info present for a rejected banner, want absent")
	}
}

// No banner observed at all is distinct from one that was rejected.
func TestCollectNoServerVersionObserved(t *testing.T) {
	t.Parallel()
	mfs := collectMetrics(t, probe.Result{TCPConnectSuccess: true})

	if _, ok := mfs["ssh_transport_identification_server_version_valid"]; ok {
		t.Error("server_version_valid present when no banner was observed, want absent")
	}
	if _, ok := mfs["ssh_transport_identification_server_version_info"]; ok {
		t.Error("server_version_info present when no banner was observed, want absent")
	}
}

func TestCollectTCPFailure(t *testing.T) {
	t.Parallel()
	result := probe.Result{
		TCPConnectSuccess: false,
		ErrorStage:        probe.ErrStageTCPConnect,
		ErrorReason:       probe.ErrReasonConnectionRefused,
	}
	mfs := collectMetrics(t, result)

	if got := singleValue(t, mfs, "ssh_transport_tcp_connect_success"); got != 0 {
		t.Errorf("tcp_connect_success = %v, want 0", got)
	}
	if got := singleValue(t, mfs, "ssh_transport_kex_success"); got != 0 {
		t.Errorf("kex_success = %v, want 0", got)
	}
	if got := singleValue(t, mfs, "ssh_transport_host_key_verify_success"); got != 0 {
		t.Errorf("host_key_verify_success = %v, want 0", got)
	}

	// Omitted-on-failure metrics must be absent.
	for _, name := range []string{
		"ssh_transport_tcp_connect_duration_seconds",
		"ssh_transport_tcp_connect_negotiated_mss_bytes",
		"ssh_transport_identification_server_version_info",
		"ssh_transport_kex_duration_seconds",
		"ssh_transport_kex_algorithm_info",
		"ssh_transport_host_key_verify_algorithm_info",
		"ssh_transport_cipher_info",
	} {
		if _, ok := mfs[name]; ok {
			t.Errorf("metric %q present on TCP failure, want absent", name)
		}
	}

	if got := labelValue(t, mfs, "ssh_transport_error_info", "stage"); got != probe.ErrStageTCPConnect {
		t.Errorf("error_info stage = %q, want %q", got, probe.ErrStageTCPConnect)
	}
	if got := labelValue(t, mfs, "ssh_transport_error_info", "reason"); got != probe.ErrReasonConnectionRefused {
		t.Errorf("error_info reason = %q, want %q", got, probe.ErrReasonConnectionRefused)
	}
}

func TestCollectOmissionBranches(t *testing.T) {
	t.Parallel()
	// TCP connected but MSS unknown; KEX succeeded but algorithm empty; only the
	// read cipher was negotiated. Each should suppress the corresponding metric.
	result := probe.Result{
		TCPConnectSuccess:       true,
		TCPConnectDuration:      time.Second,
		TCPConnectNegotiatedMSS: 0,
		KEXSuccess:              true,
		KEXDuration:             time.Second,
		KEXAlgorithm:            "",
		HostKeyAlgorithm:        "",
		CipherRead:              "aes256-ctr",
		CipherWrite:             "",
	}
	mfs := collectMetrics(t, result)

	if _, ok := mfs["ssh_transport_tcp_connect_negotiated_mss_bytes"]; ok {
		t.Error("negotiated_mss_bytes present when MSS is 0, want absent")
	}
	if _, ok := mfs["ssh_transport_kex_algorithm_info"]; ok {
		t.Error("kex_algorithm_info present when algorithm empty, want absent")
	}
	if _, ok := mfs["ssh_transport_host_key_verify_algorithm_info"]; ok {
		t.Error("host_key_verify_algorithm_info present when algorithm empty, want absent")
	}
	if _, ok := mfs["ssh_transport_identification_server_version_info"]; ok {
		t.Error("server_version_info present when version empty, want absent")
	}
	// kex_duration is still emitted because KEX succeeded.
	if got := singleValue(t, mfs, "ssh_transport_kex_duration_seconds"); got != 1 {
		t.Errorf("kex_duration_seconds = %v, want 1", got)
	}
	// Only the read cipher series exists.
	if m := directionSeries(mfs, "ssh_transport_cipher_info", "read"); m == nil {
		t.Error("cipher_info read series missing")
	}
	if m := directionSeries(mfs, "ssh_transport_cipher_info", "write"); m != nil {
		t.Error("cipher_info write series present, want absent")
	}
}

// A non-AEAD cipher agrees a MAC per direction, which is reported.
func TestCollectMACInfo(t *testing.T) {
	t.Parallel()
	mfs := collectMetrics(t, probe.Result{
		TCPConnectSuccess: true,
		KEXSuccess:        true,
		CipherRead:        "aes128-cbc",
		CipherWrite:       "aes128-cbc",
		MACRead:           "hmac-sha1",
		MACWrite:          "hmac-sha2-256",
	})

	if m := directionSeries(mfs, "ssh_transport_mac_info", "read"); m == nil {
		t.Error("mac_info read series missing")
	} else if got := labelOf(m, "mac"); got != "hmac-sha1" {
		t.Errorf("mac_info read mac = %q, want hmac-sha1", got)
	}
	if m := directionSeries(mfs, "ssh_transport_mac_info", "write"); m == nil {
		t.Error("mac_info write series missing")
	} else if got := labelOf(m, "mac"); got != "hmac-sha2-256" {
		t.Errorf("mac_info write mac = %q, want hmac-sha2-256", got)
	}
}

func TestDescribeEmitsAllDescriptors(t *testing.T) {
	t.Parallel()
	c := New(context.Background(), "example.com:22", "default", probe.Options{}, nil)
	ch := make(chan *prometheus.Desc, 32)
	c.Describe(ch)
	close(ch)
	if got := len(ch); got != 13 {
		t.Errorf("Describe emitted %d descriptors, want 13", got)
	}
}

func TestNewWiresDefaultProbe(t *testing.T) {
	t.Parallel()
	c := New(context.Background(), "example.com:22", "default", probe.Options{}, nil)
	if c.run == nil {
		t.Error("New did not set the probe function")
	}
	if c.logger == nil {
		t.Error("New did not default the logger")
	}
}

func TestBoolToFloat64(t *testing.T) {
	t.Parallel()
	if got := boolToFloat64(true); got != 1 {
		t.Errorf("boolToFloat64(true) = %v, want 1", got)
	}
	if got := boolToFloat64(false); got != 0 {
		t.Errorf("boolToFloat64(false) = %v, want 0", got)
	}
}

// labelOf returns the value of label key on m.
func labelOf(m *dto.Metric, key string) string {
	for _, lp := range m.GetLabel() {
		if lp.GetName() == key {
			return lp.GetValue()
		}
	}
	return ""
}
