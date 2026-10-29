package collector

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/probe"
)

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
		DNSLookup:                  true,
		DNSLookupSuccess:           true,
		DNSLookupDuration:          250 * time.Millisecond,
		TCPConnectSuccess:          true,
		TCPConnectDuration:         500 * time.Millisecond,
		TCPMSS:                     1448,
		ServerIdentification:       "SSH-2.0-OpenSSH_9.6",
		KEXSuccess:                 true,
		KEXDuration:                time.Second,
		KEXAlgorithm:               "curve25519-sha256",
		ServerHostKeyVerifySuccess: true,
		ServerHostKeyAlgorithm:     "ssh-ed25519",
		EncryptionServerToClient:   "aes128-gcm@openssh.com",
		EncryptionClientToServer:   "chacha20-poly1305@openssh.com",
	}
	mfs := collectMetrics(t, result)

	if got := singleValue(t, mfs, "ssh_transport_dns_lookup_success"); got != 1 {
		t.Errorf("dns_lookup_success = %v, want 1", got)
	}
	if got := singleValue(t, mfs, "ssh_transport_dns_lookup_duration_seconds"); got != 0.25 {
		t.Errorf("dns_lookup_duration_seconds = %v, want 0.25", got)
	}
	if got := singleValue(t, mfs, "ssh_transport_tcp_connect_success"); got != 1 {
		t.Errorf("tcp_connect_success = %v, want 1", got)
	}
	if got := singleValue(t, mfs, "ssh_transport_tcp_connect_duration_seconds"); got != 0.5 {
		t.Errorf("tcp_connect_duration_seconds = %v, want 0.5", got)
	}
	if got := singleValue(t, mfs, "ssh_transport_tcp_mss_bytes"); got != 1448 {
		t.Errorf("tcp_mss_bytes = %v, want 1448", got)
	}
	if got := labelValue(t, mfs, "ssh_transport_server_identification_info", "version"); got != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("server_identification_info version = %q", got)
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
	if got := singleValue(t, mfs, "ssh_transport_server_host_key_verify_success"); got != 1 {
		t.Errorf("server_host_key_verify_success = %v, want 1", got)
	}
	if got := labelValue(t, mfs, "ssh_transport_server_host_key_algorithm_info", "algorithm"); got != "ssh-ed25519" {
		t.Errorf("server_host_key_algorithm_info algorithm = %q", got)
	}

	if m := directionSeries(mfs, "ssh_transport_encryption_algorithm_info", "server_to_client"); m == nil {
		t.Error("encryption_algorithm_info server_to_client series missing")
	} else if got := algorithmOf(m); got != "aes128-gcm@openssh.com" {
		t.Errorf("encryption_algorithm_info server_to_client algorithm = %q", got)
	}
	if m := directionSeries(mfs, "ssh_transport_encryption_algorithm_info", "client_to_server"); m == nil {
		t.Error("encryption_algorithm_info client_to_server series missing")
	} else if got := algorithmOf(m); got != "chacha20-poly1305@openssh.com" {
		t.Errorf("encryption_algorithm_info client_to_server algorithm = %q", got)
	}

	// The sample negotiates AEAD ciphers, so no separate MAC is agreed.
	if _, ok := mfs["ssh_transport_mac_algorithm_info"]; ok {
		t.Error("mac_algorithm_info present for AEAD ciphers, want absent")
	}

	if got := singleValue(t, mfs, "ssh_transport_server_identification_valid"); got != 1 {
		t.Errorf("server_identification_valid = %v, want 1", got)
	}

	if _, ok := mfs["ssh_transport_error_info"]; ok {
		t.Error("error_info present on a fully successful probe, want absent")
	}
}

// A rejected banner is reported as invalid rather than vanishing silently.
func TestCollectMalformedServerIdentification(t *testing.T) {
	t.Parallel()
	mfs := collectMetrics(t, probe.Result{
		TCPConnectSuccess:             true,
		KEXSuccess:                    true,
		ServerIdentificationMalformed: true,
	})

	if got := singleValue(t, mfs, "ssh_transport_server_identification_valid"); got != 0 {
		t.Errorf("server_identification_valid = %v, want 0", got)
	}
	if _, ok := mfs["ssh_transport_server_identification_info"]; ok {
		t.Error("server_identification_info present for a rejected banner, want absent")
	}
}

// No banner observed at all is distinct from one that was rejected.
func TestCollectNoServerIdentificationObserved(t *testing.T) {
	t.Parallel()
	mfs := collectMetrics(t, probe.Result{TCPConnectSuccess: true})

	if _, ok := mfs["ssh_transport_server_identification_valid"]; ok {
		t.Error("server_identification_valid present when no banner was observed, want absent")
	}
	if _, ok := mfs["ssh_transport_server_identification_info"]; ok {
		t.Error("server_identification_info present when no banner was observed, want absent")
	}
}

func TestCollectDNSFailure(t *testing.T) {
	t.Parallel()
	result := probe.Result{
		DNSLookup:   true,
		ErrorPhase:  probe.ErrPhaseDNSLookup,
		ErrorReason: probe.ErrReasonDNSFailure,
	}
	mfs := collectMetrics(t, result)

	if got := singleValue(t, mfs, "ssh_transport_dns_lookup_success"); got != 0 {
		t.Errorf("dns_lookup_success = %v, want 0", got)
	}
	if _, ok := mfs["ssh_transport_dns_lookup_duration_seconds"]; ok {
		t.Error("dns_lookup_duration_seconds present on DNS failure, want absent")
	}
}

func TestCollectTCPFailure(t *testing.T) {
	t.Parallel()
	result := probe.Result{
		TCPConnectSuccess: false,
		ErrorPhase:        probe.ErrPhaseTCPConnect,
		ErrorReason:       probe.ErrReasonConnectionRefused,
	}
	mfs := collectMetrics(t, result)

	if got := singleValue(t, mfs, "ssh_transport_tcp_connect_success"); got != 0 {
		t.Errorf("tcp_connect_success = %v, want 0", got)
	}
	if got := singleValue(t, mfs, "ssh_transport_kex_success"); got != 0 {
		t.Errorf("kex_success = %v, want 0", got)
	}
	if got := singleValue(t, mfs, "ssh_transport_server_host_key_verify_success"); got != 0 {
		t.Errorf("server_host_key_verify_success = %v, want 0", got)
	}

	for _, name := range []string{
		"ssh_transport_dns_lookup_success",
		"ssh_transport_dns_lookup_duration_seconds",
		"ssh_transport_tcp_connect_duration_seconds",
		"ssh_transport_tcp_mss_bytes",
		"ssh_transport_server_identification_info",
		"ssh_transport_kex_duration_seconds",
		"ssh_transport_kex_algorithm_info",
		"ssh_transport_server_host_key_algorithm_info",
		"ssh_transport_encryption_algorithm_info",
		"ssh_transport_mac_algorithm_info",
	} {
		if _, ok := mfs[name]; ok {
			t.Errorf("metric %q present on TCP failure, want absent", name)
		}
	}

	if got := labelValue(t, mfs, "ssh_transport_error_info", "phase"); got != probe.ErrPhaseTCPConnect {
		t.Errorf("error_info phase = %q, want %q", got, probe.ErrPhaseTCPConnect)
	}
	if got := labelValue(t, mfs, "ssh_transport_error_info", "reason"); got != probe.ErrReasonConnectionRefused {
		t.Errorf("error_info reason = %q, want %q", got, probe.ErrReasonConnectionRefused)
	}
}

func TestCollectOmissionBranches(t *testing.T) {
	t.Parallel()
	result := probe.Result{
		TCPConnectSuccess:        true,
		TCPConnectDuration:       time.Second,
		TCPMSS:                   0,
		KEXSuccess:               true,
		KEXDuration:              time.Second,
		KEXAlgorithm:             "",
		ServerHostKeyAlgorithm:   "",
		EncryptionServerToClient: "aes256-ctr",
		EncryptionClientToServer: "",
	}
	mfs := collectMetrics(t, result)

	if _, ok := mfs["ssh_transport_dns_lookup_success"]; ok {
		t.Error("dns_lookup_success present without a lookup, want absent")
	}
	if _, ok := mfs["ssh_transport_dns_lookup_duration_seconds"]; ok {
		t.Error("dns_lookup_duration_seconds present without a lookup, want absent")
	}
	if _, ok := mfs["ssh_transport_tcp_mss_bytes"]; ok {
		t.Error("tcp_mss_bytes present when MSS is 0, want absent")
	}
	if _, ok := mfs["ssh_transport_kex_algorithm_info"]; ok {
		t.Error("kex_algorithm_info present when algorithm empty, want absent")
	}
	if _, ok := mfs["ssh_transport_server_host_key_algorithm_info"]; ok {
		t.Error("server_host_key_algorithm_info present when algorithm empty, want absent")
	}
	if _, ok := mfs["ssh_transport_server_identification_info"]; ok {
		t.Error("server_identification_info present when version empty, want absent")
	}
	// kex_duration is still emitted because KEX succeeded.
	if got := singleValue(t, mfs, "ssh_transport_kex_duration_seconds"); got != 1 {
		t.Errorf("kex_duration_seconds = %v, want 1", got)
	}
	if m := directionSeries(mfs, "ssh_transport_encryption_algorithm_info", "server_to_client"); m == nil {
		t.Error("encryption_algorithm_info server_to_client series missing")
	}
	if m := directionSeries(mfs, "ssh_transport_encryption_algorithm_info", "client_to_server"); m != nil {
		t.Error("encryption_algorithm_info client_to_server series present, want absent")
	}
}

// A non-AEAD cipher agrees a MAC per direction, which is reported.
func TestCollectMACInfo(t *testing.T) {
	t.Parallel()
	mfs := collectMetrics(t, probe.Result{
		TCPConnectSuccess:        true,
		KEXSuccess:               true,
		EncryptionServerToClient: "aes128-cbc",
		EncryptionClientToServer: "aes128-cbc",
		MACServerToClient:        "hmac-sha1",
		MACClientToServer:        "hmac-sha2-256",
	})

	if m := directionSeries(mfs, "ssh_transport_mac_algorithm_info", "server_to_client"); m == nil {
		t.Error("mac_algorithm_info server_to_client series missing")
	} else if got := algorithmOf(m); got != "hmac-sha1" {
		t.Errorf("mac_algorithm_info server_to_client algorithm = %q, want hmac-sha1", got)
	}
	if m := directionSeries(mfs, "ssh_transport_mac_algorithm_info", "client_to_server"); m == nil {
		t.Error("mac_algorithm_info client_to_server series missing")
	} else if got := algorithmOf(m); got != "hmac-sha2-256" {
		t.Errorf("mac_algorithm_info client_to_server algorithm = %q, want hmac-sha2-256", got)
	}
}

func TestDescribeEmitsAllDescriptors(t *testing.T) {
	t.Parallel()
	c := New(context.Background(), "example.com:22", "default", probe.Options{}, nil)
	ch := make(chan *prometheus.Desc, 32)
	c.Describe(ch)
	close(ch)
	if got := len(ch); got != 15 {
		t.Errorf("Describe emitted %d descriptors, want 15", got)
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

func algorithmOf(m *dto.Metric) string {
	for _, lp := range m.GetLabel() {
		if lp.GetName() == "algorithm" {
			return lp.GetValue()
		}
	}
	return ""
}
