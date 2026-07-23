// Package collector implements the Prometheus collector for
// ssh_transport_exporter.
package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/raphaelthomas/ssh_transport_exporter/pkg/probe"
)

const (
	namespace              = "ssh_transport"
	subSystemTCP           = "tcp_connect"
	subSystemKEX           = "kex"
	subSystemHostKeyVerify = "host_key_verify"
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
			"Time taken to establish the TCP connection. Omitted on failure.",
			nil,
			nil,
		),
		prometheus.GaugeValue,
	}
	tcpConnectNegotiatedMSSDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemTCP, "negotiated_mss_bytes"),
			"Negotiated TCP maximum segment size (MSS) observed at TCP connect time. Omitted if unavailable.",
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
			"Time taken for the SSH transport layer handshake. Omitted on failure.",
			nil,
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
	errorInfoDesc = typedDesc{
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subSystemError, "info"),
			"Stage and reason this probe failed. Constant 1. Absent if the probe fully succeeded.",
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
}

// New builds a collector for one probe. Register it on a fresh,
// request-scoped *prometheus.Registry per HTTP request. module is used
// only for logging context, not for metric labels.
func New(ctx context.Context, target, module string, opts probe.Options, logger *slog.Logger) *SSHCollector {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &SSHCollector{ctx: ctx, target: target, module: module, opts: opts, logger: logger}
}

// Describe sends every possible descriptor regardless of whether a
// given probe emits it.
func (c *SSHCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- tcpConnectSuccessDesc.desc
	ch <- tcpConnectDurationDesc.desc
	ch <- tcpConnectNegotiatedMSSDesc.desc
	ch <- kexSuccessDesc.desc
	ch <- kexDurationDesc.desc
	ch <- hostKeyVerifySuccessDesc.desc
	ch <- errorInfoDesc.desc
}

// Collect runs the probe and translates the result into metrics.
func (c *SSHCollector) Collect(ch chan<- prometheus.Metric) {
	result := probe.Run(c.ctx, c.target, c.opts)

	if c.logger.Enabled(c.ctx, slog.LevelDebug) {
		c.logger.Debug("probe result",
			"target", c.target,
			"module", c.module,
			"tcp_connect_success", result.TCPConnectSuccess,
			"tcp_connect_duration", result.TCPConnectDuration,
			"tcp_connect_negotiated_mss", result.TCPConnectNegotiatedMSS,
			"kex_success", result.KEXSuccess,
			"kex_duration", result.KEXDuration,
			"host_key_verify_success", result.HostKeyVerifySuccess,
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

	ch <- kexSuccessDesc.mustNewConstMetric(boolToFloat64(result.KEXSuccess))
	if result.KEXSuccess {
		ch <- kexDurationDesc.mustNewConstMetric(result.KEXDuration.Seconds())
	}

	ch <- hostKeyVerifySuccessDesc.mustNewConstMetric(boolToFloat64(result.HostKeyVerifySuccess))

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
