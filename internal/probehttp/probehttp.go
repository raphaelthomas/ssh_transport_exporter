// Package probehttp implements the HTTP entry point for probe requests.
package probehttp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/collector"
	"github.com/raphaelthomas/ssh_transport_exporter/internal/config"
	"github.com/raphaelthomas/ssh_transport_exporter/internal/normalize"
)

// moduleUnresolved is the module label value for requests that named no
// configured module. Empty is collision-free: a request omitting module is
// rewritten to config.DefaultModuleName, so no served probe ever labels itself
// with the empty string.
const moduleUnresolved = ""

// Handler returns the /probe HTTP handler. timeout is a hard upper bound
// on a single probe; a shorter Prometheus scrape timeout (sent via the
// X-Prometheus-Scrape-Timeout-Seconds header) takes precedence. live is
// the current module set, swapped atomically on config reload. requests
// counts every probe request by module and HTTP status code, with an empty
// module for requests naming no configured one; it must be registered by the
// caller.
func Handler(logger *slog.Logger, timeout time.Duration, requests *prometheus.CounterVec, live *atomic.Pointer[map[string]config.Module]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		moduleName := r.URL.Query().Get("module")
		if moduleName == "" {
			moduleName = config.DefaultModuleName
		}

		modules := *live.Load()
		mod, ok := modules[moduleName]
		if !ok {
			logger.Warn("probe rejected: unknown module", "module", moduleName)
			writeError(w, requests, moduleUnresolved, http.StatusBadRequest, fmt.Sprintf("unknown module %q", moduleName))
			return
		}

		target := r.URL.Query().Get("target")
		if target == "" {
			writeError(w, requests, moduleName, http.StatusBadRequest, "target parameter is required")
			return
		}

		target, host, port, err := ensurePort(target, mod.TargetPort)
		if err != nil {
			logger.Warn("probe rejected: malformed target", "module", moduleName, "target", r.URL.Query().Get("target"), "error", err)
			writeError(w, requests, moduleName, http.StatusBadRequest, err.Error())
			return
		}
		if _, allowed := mod.AllowedPorts[port]; !allowed {
			logger.Warn("probe rejected: port not allowed", "module", moduleName, "target", target, "port", port)
			writeError(w, requests, moduleName, http.StatusForbidden, fmt.Sprintf("port %d not allowed for module %q", port, moduleName))
			return
		}
		if !targetAllowed(host, mod.AllowedTargets) {
			logger.Warn("probe rejected: target not allowed", "module", moduleName, "target", target, "host", host)
			writeError(w, requests, moduleName, http.StatusForbidden, fmt.Sprintf("target %q not allowed for module %q", host, moduleName))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), effectiveTimeout(r, timeout))
		defer cancel()

		registry := prometheus.NewRegistry()
		registry.MustRegister(collector.New(ctx, target, moduleName, mod.Options, logger))

		promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
		requests.WithLabelValues(moduleName, strconv.Itoa(http.StatusOK)).Inc()
	}
}

// effectiveTimeout returns max, shortened to the Prometheus scrape timeout
// when the request carries a valid, shorter one via the
// X-Prometheus-Scrape-Timeout-Seconds header. Malformed, zero, and negative
// header values are ignored.
func effectiveTimeout(r *http.Request, max time.Duration) time.Duration {
	timeoutSecs := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds")
	if timeoutSecs == "" {
		return max
	}
	s, err := strconv.ParseFloat(timeoutSecs, 64)
	if err != nil || s <= 0 {
		return max
	}
	if scrapeTimeout := time.Duration(s * float64(time.Second)); scrapeTimeout < max {
		return scrapeTimeout
	}
	return max
}

// writeError responds with "CODE WORD: msg" (e.g. "403 Forbidden: ...") so a
// direct browser hit shows the status inline, and counts the request by module
// and code. It centralizes the response + metric increment for all /probe
// error paths.
func writeError(w http.ResponseWriter, requests *prometheus.CounterVec, moduleName string, code int, msg string) {
	http.Error(w, fmt.Sprintf("%d %s: %s", code, http.StatusText(code), msg), code)
	requests.WithLabelValues(moduleName, strconv.Itoa(code)).Inc()
}

// ensurePort parses target (a bare "host" or "host:port", where host may be a
// bracketed IPv6 literal) and returns the canonical "host:port" target, the
// bracket-free host, and the port. When target carries no port, defaultPort is
// used. It errors on a malformed target or port.
func ensurePort(target string, defaultPort int) (normalizedTarget, host string, port int, err error) {
	u, err := url.Parse("//" + target)
	if err != nil {
		return "", "", 0, fmt.Errorf("invalid target %q: %w", target, err)
	}
	// A target must be a bare host[:port]; reject any URL structure that
	// url.Parse would otherwise silently drop (userinfo, path, query, fragment).
	if u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", "", 0, fmt.Errorf("invalid target %q: must be host or host:port", target)
	}
	host = normalize.Hostname(u.Hostname())
	if host == "" {
		return "", "", 0, fmt.Errorf("invalid target %q: no host", target)
	}
	port = defaultPort
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil {
			return "", "", 0, fmt.Errorf("invalid port %q in target %q", p, target)
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), host, port, nil
}

// targetAllowed reports whether host matches any matcher. No matchers means
// deny-all.
func targetAllowed(host string, matchers []config.TargetMatcher) bool {
	for _, m := range matchers {
		if m.Match(host) {
			return true
		}
	}
	return false
}
