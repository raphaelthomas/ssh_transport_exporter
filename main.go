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
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/raphaelthomas/ssh_transport_exporter/pkg/buildinfo"
	"github.com/raphaelthomas/ssh_transport_exporter/pkg/config"
	"github.com/raphaelthomas/ssh_transport_exporter/pkg/probehttp"
)

// Cfg holds the exporter's runtime flags, distinct from config.Config
// (module definitions loaded from --config.file).
type Cfg struct {
	ListenAddress string
	LogLevel      slog.Level
	ConfigFile    string
	ProbeTimeout  time.Duration
}

func parseFlags() *Cfg {
	app := kingpin.New("ssh_transport_exporter", "")
	app.Version(buildinfo.Version)
	app.HelpFlag.Short('h')

	cfg := &Cfg{}
	const envPrefix = "SSH_TRANSPORT_EXPORTER_"

	app.Flag("web.listen-address", "Address to listen on for web interface and telemetry").
		Default(":10022").
		Envar(envPrefix + "LISTEN_ADDRESS").
		StringVar(&cfg.ListenAddress)

	logLevelFlag := app.Flag("log-level", "Log level (debug, info, warn, error)").
		Default("info").
		Enum("debug", "info", "warn", "error")

	app.Flag("config.file", "Path to the exporter's YAML config file with module definitions)").
		Default("ssh_transport_exporter.yaml").
		Envar(envPrefix + "CONFIG_FILE").
		StringVar(&cfg.ConfigFile)

	app.Flag("probe.timeout", "Hard upper bound for a single probe; Prometheus scrape timeout may shorten it.").
		Default("5s").
		Envar(envPrefix + "PROBE_TIMEOUT").
		DurationVar(&cfg.ProbeTimeout)

	kingpin.MustParse(app.Parse(os.Args[1:]))

	if err := cfg.LogLevel.UnmarshalText([]byte(*logLevelFlag)); err != nil {
		cfg.LogLevel = slog.LevelInfo
	}
	return cfg
}

// reload re-reads the config file and atomically swaps the live module
// set. On any error, it logs and leaves the previous (still valid)
// module set in place.
func reload(logger *slog.Logger, configFile string, live *atomic.Pointer[map[string]config.Module]) {
	modules, err := config.Load(configFile, logger)
	if err != nil {
		logger.Error("config reload failed, keeping previous config", "path", configFile, "error", err)
		return
	}
	live.Store(&modules)
	logger.Info("config reloaded", "module_count", len(modules))
}

func main() {
	cfg := parseFlags()

	logLevel := &slog.LevelVar{}
	logLevel.Set(cfg.LogLevel)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	modules, err := config.Load(cfg.ConfigFile, logger)
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

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/probe", probehttp.Handler(logger, cfg.ProbeTimeout, &live))

	srv := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				logger.Info("received SIGHUP, reloading config")
				reload(logger, cfg.ConfigFile, &live)
				continue
			}
			logger.Info("received signal, shutting down HTTP server", "signal", sig)
			if err := srv.Shutdown(context.Background()); err != nil {
				logger.Error("HTTP server shutdown error", "error", err)
			}
			return
		}
	}()

	logger.Info("HTTP server listening", "address", cfg.ListenAddress)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("HTTP server error", "error", err)
		os.Exit(1)
	}
}
