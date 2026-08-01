// Copyright 2026 Raphael Seebacher
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/buildinfo"
	"github.com/raphaelthomas/ssh_transport_exporter/internal/config"
	"github.com/raphaelthomas/ssh_transport_exporter/internal/fdlimit"
	"github.com/raphaelthomas/ssh_transport_exporter/internal/probehttp"
)

// flags holds the exporter's runtime configuration parsed from CLI flags.
type flags struct {
	ListenAddress      string
	LogLevel           slog.Level
	ConfigFile         string
	ProbeTimeout       time.Duration
	MaxConcurrentProbe int
	AllowAllTargets    bool
}

func parseFlags() *flags {
	app := kingpin.New("ssh_transport_exporter", "")
	app.Version(buildinfo.Version)
	app.HelpFlag.Short('h')

	f := &flags{}
	const envPrefix = "SSH_TRANSPORT_EXPORTER_"

	app.Flag("web.listen-address", "Address to listen on for web interface and telemetry").
		Default(":10022").
		Envar(envPrefix + "LISTEN_ADDRESS").
		StringVar(&f.ListenAddress)

	logLevelFlag := app.Flag("log-level", "Log level (debug, info, warn, error)").
		Default("info").
		Enum("debug", "info", "warn", "error")

	app.Flag("config.file", "Path to the exporter's YAML config file with module definitions)").
		Default("ssh_transport_exporter.yaml").
		Envar(envPrefix + "CONFIG_FILE").
		StringVar(&f.ConfigFile)

	app.Flag("probe.timeout", "Hard upper bound for a single probe; Prometheus scrape timeout may shorten it.").
		Default("5s").
		Envar(envPrefix + "PROBE_TIMEOUT").
		DurationVar(&f.ProbeTimeout)

	app.Flag("probe.max-concurrent", "Maximum probes running at once; further requests get 503 rather than queueing. 0 disables the limit.").
		Default("500").
		Envar(envPrefix + "PROBE_MAX_CONCURRENT").
		IntVar(&f.MaxConcurrentProbe)

	app.Flag("allow-all-targets", "Probe any target when no allowed_targets is set; for fleets too diverse to enumerate. An explicit list always wins.").
		Default("false").
		Envar(envPrefix + "ALLOW_ALL_TARGETS").
		BoolVar(&f.AllowAllTargets)

	kingpin.MustParse(app.Parse(os.Args[1:]))

	if err := f.LogLevel.UnmarshalText([]byte(*logLevelFlag)); err != nil {
		f.LogLevel = slog.LevelInfo
	}
	return f
}

// reload re-reads the config file and atomically swaps the live module
// set. On any error, it logs and leaves the previous (still valid)
// module set in place.
func reload(logger *slog.Logger, cfg *flags, live *atomic.Pointer[map[string]config.Module]) {
	modules, err := config.Load(cfg.ConfigFile, cfg.AllowAllTargets, logger)
	if err != nil {
		logger.Error("config reload failed, keeping previous config", "path", cfg.ConfigFile, "error", err)
		return
	}
	live.Store(&modules)
	logger.Info("config reloaded", "module_count", len(modules))
}

// shutdownTimeout bounds how long in-flight probes may drain on shutdown.
const shutdownTimeout = 10 * time.Second

// serve runs srv on ln until a termination signal arrives on sigCh, reloading
// config on SIGHUP. It returns once in-flight requests have drained, so the
// caller must not exit before it does.
func serve(logger *slog.Logger, cfg *flags, srv *http.Server, live *atomic.Pointer[map[string]config.Module], ln net.Listener, sigCh <-chan os.Signal) error {
	shutdownDone := make(chan struct{})

	go func() {
		defer close(shutdownDone)
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				logger.Info("received SIGHUP, reloading config")
				reload(logger, cfg, live)
				continue
			}
			logger.Info("received signal, shutting down HTTP server", "signal", sig)
			shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				logger.Error("HTTP server shutdown error", "error", err)
			}
			return
		}
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	// Serve returns as soon as the listener closes; wait for the drain.
	<-shutdownDone
	logger.Info("shutdown complete")
	return nil
}

func main() {
	cfg := parseFlags()

	logLevel := &slog.LevelVar{}
	logLevel.Set(cfg.LogLevel)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	modules, err := config.Load(cfg.ConfigFile, cfg.AllowAllTargets, logger)
	if err != nil {
		logger.Error("failed to load config", "path", cfg.ConfigFile, "error", err)
		os.Exit(1)
	}

	var live atomic.Pointer[map[string]config.Module]
	live.Store(&modules)

	logger.Info("Starting SSH Transport Exporter",
		"version", buildinfo.Version,
		"listen_address", cfg.ListenAddress,
		"config_file", cfg.ConfigFile,
		"module_count", len(modules),
	)

	if ok, soft, needed := fdlimit.Sufficient(cfg.MaxConcurrentProbe); !ok {
		logger.Warn("file descriptor limit is too low for the configured probe concurrency; probes may fail with 'too many open files'",
			"soft_limit", soft, "needed", needed, "probe_max_concurrent", cfg.MaxConcurrentProbe)
	}

	probeRequests := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ssh_transport_exporter",
			Name:      "probe_requests_total",
			Help:      "Total probe requests served by module and HTTP status code. Module is empty when the request named no configured module.",
		},
		[]string{"module", "code"},
	)
	prometheus.MustRegister(probeRequests)

	probesInFlight := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ssh_transport_exporter",
			Name:      "probes_in_flight",
			Help:      "Probes currently running.",
		},
	)
	prometheus.MustRegister(probesInFlight)

	prometheus.MustRegister(version.NewCollector("ssh_transport_exporter"))

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/probe", probehttp.Handler(probehttp.Options{
		Logger:        logger,
		Timeout:       cfg.ProbeTimeout,
		MaxConcurrent: cfg.MaxConcurrentProbe,
		Requests:      probeRequests,
		InFlight:      probesInFlight,
		Live:          &live,
	}))

	srv := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	ln, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		logger.Error("failed to listen", "address", cfg.ListenAddress, "error", err)
		os.Exit(1)
	}
	logger.Info("HTTP server listening", "address", ln.Addr().String())

	if err := serve(logger, cfg, srv, &live, ln, sigCh); err != nil {
		logger.Error("HTTP server error", "error", err)
		os.Exit(1)
	}
}
