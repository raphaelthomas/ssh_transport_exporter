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
// the current module set, swapped atomically on config reload. requests
// counts every probe request by module and HTTP status code; it must be
// registered by the caller.
func Handler(logger *slog.Logger, timeout time.Duration, requests *prometheus.CounterVec, live *atomic.Pointer[map[string]config.Module]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		moduleName := r.URL.Query().Get("module")
		if moduleName == "" {
			moduleName = config.DefaultModuleName
		}

		target := r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, "target parameter is required", http.StatusBadRequest)
			requests.WithLabelValues(moduleName, strconv.Itoa(http.StatusBadRequest)).Inc()
			return
		}

		modules := *live.Load()
		mod, ok := modules[moduleName]
		if !ok {
			http.Error(w, fmt.Sprintf("unknown module %q", moduleName), http.StatusBadRequest)
			requests.WithLabelValues(moduleName, strconv.Itoa(http.StatusBadRequest)).Inc()
			return
		}

		target, port, err := ensurePort(target, mod.TargetPort)
		if err != nil {
			logger.Warn("probe rejected: malformed target port", "module", moduleName, "target", r.URL.Query().Get("target"), "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			requests.WithLabelValues(moduleName, strconv.Itoa(http.StatusBadRequest)).Inc()
			return
		}
		if _, allowed := mod.AllowedPorts[port]; !allowed {
			logger.Warn("probe rejected: port not allowed", "module", moduleName, "target", target, "port", port)
			http.Error(w, fmt.Sprintf("port %d not allowed for module %q", port, moduleName), http.StatusForbidden)
			requests.WithLabelValues(moduleName, strconv.Itoa(http.StatusForbidden)).Inc()
			return
		}

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
		requests.WithLabelValues(moduleName, strconv.Itoa(http.StatusOK)).Inc()
	}
}

// ensurePort returns target guaranteed to carry a port (appending
// defaultPort if it had none) along with that port as an int. It errors
// only if target carries a malformed port (client error).
func ensurePort(target string, defaultPort int) (string, int, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return net.JoinHostPort(target, strconv.Itoa(defaultPort)), defaultPort, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q in target", portStr)
	}
	return net.JoinHostPort(host, portStr), port, nil
}
