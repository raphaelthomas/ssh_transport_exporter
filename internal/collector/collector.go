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
	subSystemTCP           = "tcp_connect"
	subSystemIdent         = "identification"
	subSystemKEX           = "kex"
	subSystemHostKeyVerify = "host_key_verify"
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
	tcpConnectSuccessDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemTCP, "success"),
			"Whether a TCP connection to the target could be established.",
			nil,
			nil,
		),
		prometheus.GaugeValue,
	}
	tcpConnectDurationDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemTCP, "duration_seconds"),
			"Time taken to establish the TCP connection. Absent on failure.",
			nil,
			nil,
		),
		prometheus.GaugeValue,
	}
	tcpConnectNegotiatedMSSDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemTCP, "negotiated_mss_bytes"),
			"Negotiated TCP maximum segment size at connect time. Absent if unavailable.",
			nil,
			nil,
		),
		prometheus.GaugeValue,
	}
	serverVersionInfoDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemIdent, "server_version_info"),
			"SSH version banner presented by the server (RFC 4253 4.2). Absent if not observed.",
			[]string{"version"},
			nil,
		),
		prometheus.GaugeValue,
	}
	serverVersionValidDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemIdent, "server_version_valid"),
			"Whether the server's identification string conformed to RFC 4253 4.2. Absent if none was presented.",
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
	kexAlgorithmInfoDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemKEX, "algorithm_info"),
			"Negotiated key exchange algorithm. Absent unless key exchange completed.",
			[]string{"algorithm"},
			nil,
		),
		prometheus.GaugeValue,
	}
	hostKeyVerifySuccessDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemHostKeyVerify, "success"),
			"Whether the server host key was successfully verified.",
			nil,
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
	errorInfoDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemError, "info"),
			"Stage and reason this probe failed. Absent if the probe succeeded.",
			[]string{"stage", "reason"},
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
	// run performs the probe. Set by New to probe.Run; overridden in tests.
	run func(context.Context, string, probe.Options) probe.Result
}

// New builds a collector for one probe. Register it on a fresh,
// request-scoped *prometheus.Registry per HTTP request. module is used
// only for logging context, not for metric labels.
func New(ctx context.Context, target, module string, opts probe.Options, logger *slog.Logger) *SSHCollector {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &SSHCollector{ctx: ctx, target: target, module: module, opts: opts, logger: logger, run: probe.Run}
}

// Describe sends every possible descriptor regardless of whether a
// given probe emits it.
func (c *SSHCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- tcpConnectSuccessDesc.desc
	ch <- tcpConnectDurationDesc.desc
	ch <- tcpConnectNegotiatedMSSDesc.desc
	ch <- serverVersionInfoDesc.desc
	ch <- serverVersionValidDesc.desc
	ch <- kexSuccessDesc.desc
	ch <- kexDurationDesc.desc
	ch <- kexAlgorithmInfoDesc.desc
	ch <- hostKeyVerifySuccessDesc.desc
	ch <- hostKeyAlgorithmInfoDesc.desc
	ch <- cipherInfoDesc.desc
	ch <- macInfoDesc.desc
	ch <- errorInfoDesc.desc
}

// Collect runs the probe and translates the result into metrics.
func (c *SSHCollector) Collect(ch chan<- prometheus.Metric) {
	result := c.run(c.ctx, c.target, c.opts)

	if c.logger.Enabled(c.ctx, slog.LevelDebug) {
		c.logger.Debug("probe result",
			"target", c.target,
			"module", c.module,
			"tcp_connect_success", result.TCPConnectSuccess,
			"tcp_connect_duration", result.TCPConnectDuration,
			"tcp_connect_negotiated_mss", result.TCPConnectNegotiatedMSS,
			"server_version", result.ServerVersion,
			"server_version_malformed", result.ServerVersionMalformed,
			"kex_success", result.KEXSuccess,
			"kex_duration", result.KEXDuration,
			"kex_algorithm", result.KEXAlgorithm,
			"host_key_verify_success", result.HostKeyVerifySuccess,
			"host_key_algorithm", result.HostKeyAlgorithm,
			"cipher_read", result.CipherRead,
			"cipher_write", result.CipherWrite,
			"mac_read", result.MACRead,
			"mac_write", result.MACWrite,
			"error_stage", result.ErrorStage,
			"error_reason", result.ErrorReason,
		)
	}

	ch <- tcpConnectSuccessDesc.mustNewConstMetric(boolToFloat64(result.TCPConnectSuccess))
	if result.TCPConnectSuccess {
		ch <- tcpConnectDurationDesc.mustNewConstMetric(result.TCPConnectDuration.Seconds())
		if result.TCPConnectNegotiatedMSS > 0 {
			ch <- tcpConnectNegotiatedMSSDesc.mustNewConstMetric(float64(result.TCPConnectNegotiatedMSS))
		}
	}

	switch {
	case result.ServerVersion != "":
		ch <- serverVersionInfoDesc.mustNewConstMetric(1, result.ServerVersion)
		ch <- serverVersionValidDesc.mustNewConstMetric(1)
	case result.ServerVersionMalformed:
		ch <- serverVersionValidDesc.mustNewConstMetric(0)
	}

	ch <- kexSuccessDesc.mustNewConstMetric(boolToFloat64(result.KEXSuccess))
	if result.KEXSuccess {
		ch <- kexDurationDesc.mustNewConstMetric(result.KEXDuration.Seconds())
		if result.KEXAlgorithm != "" {
			ch <- kexAlgorithmInfoDesc.mustNewConstMetric(1, result.KEXAlgorithm)
		}
	}

	ch <- hostKeyVerifySuccessDesc.mustNewConstMetric(boolToFloat64(result.HostKeyVerifySuccess))
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

	if result.ErrorStage != "" {
		ch <- errorInfoDesc.mustNewConstMetric(1, result.ErrorStage, result.ErrorReason)
	}
}

func boolToFloat64(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
