// Package collector implements the Prometheus collector for
// ssh_transport_exporter.
package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/probe"
)

const (
	namespace              = "ssh_transport"
	subSystemDNS           = "dns_lookup"
	subSystemTCP           = "tcp"
	subSystemTCPConnect    = "tcp_connect"
	subSystemServerIdent   = "server_identification"
	subSystemKEX           = "kex"
	subSystemHostKeyVerify = "host_key_verify"
	subSystemServerHostKey = "server_host_key"
	subSystemCipher        = "cipher"
	subSystemMAC           = "mac"
	subSystemError         = "error"
)

type typedDesc struct {
	desc      *prometheus.Desc
	valueType prometheus.ValueType
}

func (td typedDesc) mustNewConstMetric(value float64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(td.desc, td.valueType, value, labelValues...)
}

var (
	dnsLookupDurationDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemDNS, "duration_seconds"),
			"Time taken to resolve the target hostname. Absent for IP literal targets and when the lookup fails.",
			nil,
			nil,
		),
		prometheus.GaugeValue,
	}
	tcpConnectSuccessDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemTCPConnect, "success"),
			"Whether a TCP connection to the target could be established.",
			nil,
			nil,
		),
		prometheus.GaugeValue,
	}
	tcpConnectDurationDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemTCPConnect, "duration_seconds"),
			"Time taken to establish the TCP connection, excluding name resolution. Absent on failure.",
			nil,
			nil,
		),
		prometheus.GaugeValue,
	}
	tcpMSSDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemTCP, "mss_bytes"),
			"TCP maximum segment size negotiated at connect time. Absent if unavailable.",
			nil,
			nil,
		),
		prometheus.GaugeValue,
	}
	serverIdentificationInfoDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemServerIdent, "info"),
			"Identification string sent by the server (RFC 4253 section 4.2). Absent if not observed.",
			[]string{"version"},
			nil,
		),
		prometheus.GaugeValue,
	}
	serverIdentificationValidDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemServerIdent, "valid"),
			"Whether the server's identification string conformed to RFC 4253 section 4.2. Absent if none was presented.",
			nil,
			nil,
		),
		prometheus.GaugeValue,
	}
	kexAlgorithmInfoDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemKEX, "algorithm_info"),
			"Negotiated key exchange algorithm. Absent unless key exchange completed.",
			[]string{"algorithm"},
			nil,
		),
		prometheus.GaugeValue,
	}
	hostKeyAlgorithmInfoDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemHostKeyVerify, "algorithm_info"),
			"Negotiated host key algorithm. Absent unless key exchange completed.",
			[]string{"algorithm"},
			nil,
		),
		prometheus.GaugeValue,
	}
	cipherInfoDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemCipher, "info"),
			"Negotiated cipher per direction. Absent unless key exchange completed.",
			[]string{"direction", "cipher"},
			nil,
		),
		prometheus.GaugeValue,
	}
	macInfoDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemMAC, "info"),
			"Negotiated MAC algorithm per direction. Absent for AEAD ciphers, which need no separate MAC.",
			[]string{"direction", "mac"},
			nil,
		),
		prometheus.GaugeValue,
	}
	serverHostKeyVerifySuccessDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemServerHostKey, "verify_success"),
			"Whether the server host key was verified (RFC 4253 section 8).",
			nil,
			nil,
		),
		prometheus.GaugeValue,
	}
	kexSuccessDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemKEX, "success"),
			"Whether the SSH transport layer key exchange (RFC 4253) completed successfully.",
			nil,
			nil,
		),
		prometheus.GaugeValue,
	}
	kexDurationDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemKEX, "duration_seconds"),
			"Time taken for the SSH transport layer handshake. Absent on failure.",
			nil,
			nil,
		),
		prometheus.GaugeValue,
	}
	errorInfoDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemError, "info"),
			"Phase and reason this probe failed. Absent if the probe succeeded.",
			[]string{"phase", "reason"},
			nil,
		),
		prometheus.GaugeValue,
	}
)

// SSHCollector implements prometheus.Collector for one target/module.
type SSHCollector struct {
	ctx    context.Context
	target string
	module string
	opts   probe.Options
	logger *slog.Logger
	// run is probe.Run, swapped out in tests.
	run func(context.Context, string, probe.Options) probe.Result
}

// New builds a collector for one probe, to be registered on a per-request
// registry; module is only used for logging.
func New(ctx context.Context, target, module string, opts probe.Options, logger *slog.Logger) *SSHCollector {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &SSHCollector{ctx: ctx, target: target, module: module, opts: opts, logger: logger, run: probe.Run}
}

// Describe sends every possible descriptor regardless of whether a
// given probe emits it.
func (c *SSHCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- dnsLookupDurationDesc.desc
	ch <- tcpConnectSuccessDesc.desc
	ch <- tcpConnectDurationDesc.desc
	ch <- tcpMSSDesc.desc
	ch <- serverIdentificationInfoDesc.desc
	ch <- serverIdentificationValidDesc.desc
	ch <- kexAlgorithmInfoDesc.desc
	ch <- hostKeyAlgorithmInfoDesc.desc
	ch <- cipherInfoDesc.desc
	ch <- macInfoDesc.desc
	ch <- serverHostKeyVerifySuccessDesc.desc
	ch <- kexSuccessDesc.desc
	ch <- kexDurationDesc.desc
	ch <- errorInfoDesc.desc
}

// Collect runs the probe and translates the result into metrics.
func (c *SSHCollector) Collect(ch chan<- prometheus.Metric) {
	result := c.run(c.ctx, c.target, c.opts)

	if c.logger.Enabled(c.ctx, slog.LevelDebug) {
		c.logger.Debug("probe result",
			"target", c.target,
			"module", c.module,
			"dns_lookup_duration", result.DNSLookupDuration,
			"tcp_connect_success", result.TCPConnectSuccess,
			"tcp_connect_duration", result.TCPConnectDuration,
			"tcp_mss", result.TCPMSS,
			"server_identification", result.ServerIdentification,
			"server_identification_malformed", result.ServerIdentificationMalformed,
			"kex_algorithm", result.KEXAlgorithm,
			"host_key_algorithm", result.HostKeyAlgorithm,
			"cipher_read", result.CipherRead,
			"cipher_write", result.CipherWrite,
			"mac_read", result.MACRead,
			"mac_write", result.MACWrite,
			"server_host_key_verify_success", result.ServerHostKeyVerifySuccess,
			"kex_success", result.KEXSuccess,
			"kex_duration", result.KEXDuration,
			"error_phase", result.ErrorPhase,
			"error_reason", result.ErrorReason,
		)
	}

	if result.DNSLookupDuration > 0 {
		ch <- dnsLookupDurationDesc.mustNewConstMetric(result.DNSLookupDuration.Seconds())
	}

	ch <- tcpConnectSuccessDesc.mustNewConstMetric(boolToFloat64(result.TCPConnectSuccess))
	if result.TCPConnectSuccess {
		ch <- tcpConnectDurationDesc.mustNewConstMetric(result.TCPConnectDuration.Seconds())
		if result.TCPMSS > 0 {
			ch <- tcpMSSDesc.mustNewConstMetric(float64(result.TCPMSS))
		}
	}

	switch {
	case result.ServerIdentification != "":
		ch <- serverIdentificationInfoDesc.mustNewConstMetric(1, result.ServerIdentification)
		ch <- serverIdentificationValidDesc.mustNewConstMetric(1)
	case result.ServerIdentificationMalformed:
		ch <- serverIdentificationValidDesc.mustNewConstMetric(0)
	}

	if result.KEXSuccess && result.KEXAlgorithm != "" {
		ch <- kexAlgorithmInfoDesc.mustNewConstMetric(1, result.KEXAlgorithm)
	}

	if result.HostKeyAlgorithm != "" {
		ch <- hostKeyAlgorithmInfoDesc.mustNewConstMetric(1, result.HostKeyAlgorithm)
	}

	if result.CipherRead != "" {
		ch <- cipherInfoDesc.mustNewConstMetric(1, "read", result.CipherRead)
	}
	if result.CipherWrite != "" {
		ch <- cipherInfoDesc.mustNewConstMetric(1, "write", result.CipherWrite)
	}

	if result.MACRead != "" {
		ch <- macInfoDesc.mustNewConstMetric(1, "read", result.MACRead)
	}
	if result.MACWrite != "" {
		ch <- macInfoDesc.mustNewConstMetric(1, "write", result.MACWrite)
	}

	ch <- serverHostKeyVerifySuccessDesc.mustNewConstMetric(boolToFloat64(result.ServerHostKeyVerifySuccess))

	ch <- kexSuccessDesc.mustNewConstMetric(boolToFloat64(result.KEXSuccess))
	if result.KEXSuccess {
		ch <- kexDurationDesc.mustNewConstMetric(result.KEXDuration.Seconds())
	}

	if result.ErrorPhase != "" {
		ch <- errorInfoDesc.mustNewConstMetric(1, result.ErrorPhase, result.ErrorReason)
	}
}

func boolToFloat64(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
