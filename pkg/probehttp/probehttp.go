// Package probehttp implements the HTTP entry point for probe requests.
package probehttp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/raphaelthomas/ssh_transport_exporter/pkg/collector"
	"github.com/raphaelthomas/ssh_transport_exporter/pkg/config"
)

// Handler returns the /probe HTTP handler. timeout is a hard upper bound
// on a single probe; a shorter Prometheus scrape timeout (sent via the
// X-Prometheus-Scrape-Timeout-Seconds header) takes precedence. live is
// the current module set, swapped atomically on config reload.
func Handler(logger *slog.Logger, timeout time.Duration, live *atomic.Pointer[map[string]config.Module]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, "target parameter is required", http.StatusBadRequest)
			return
		}

		moduleName := r.URL.Query().Get("module")
		if moduleName == "" {
			moduleName = config.DefaultModuleName
		}
		modules := *live.Load()
		mod, ok := modules[moduleName]
		if !ok {
			http.Error(w, fmt.Sprintf("unknown module %q", moduleName), http.StatusBadRequest)
			return
		}

		target = ensurePort(target, mod.TargetPort)

		if timeoutSecs := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); timeoutSecs != "" {
			if s, err := strconv.ParseFloat(timeoutSecs, 64); err == nil && s > 0 {
				if scrapeTimeout := time.Duration(s * float64(time.Second)); scrapeTimeout < timeout {
					timeout = scrapeTimeout
				}
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		registry := prometheus.NewRegistry()
		registry.MustRegister(collector.New(ctx, target, moduleName, mod.Options, logger))

		promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
	}
}

// ensurePort appends defaultPort to target if target has none. Uses
// net.SplitHostPort rather than a naive colon check, since that breaks
// on bare IPv6 addresses (which contain colons but no port).
func ensurePort(target string, defaultPort int) string {
	if _, _, err := net.SplitHostPort(target); err == nil {
		return target
	}
	return net.JoinHostPort(target, strconv.Itoa(defaultPort))
}
