// Package probehttp implements the HTTP entry point for probe requests.
package probehttp

import (
	"context"
	"fmt"
	"log/slog"
	"math"
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
// configured module.
const moduleUnresolved = ""

// Options configures the /probe handler.
type Options struct {
	Logger *slog.Logger
	// Timeout is a hard upper bound on a single probe; a shorter Prometheus
	// scrape timeout (X-Prometheus-Scrape-Timeout-Seconds) takes precedence.
	Timeout time.Duration
	// TimeoutOffset is subtracted from the scrape timeout so the probe gives up,
	// and its timeout metrics reach Prometheus, before the scrape itself does.
	TimeoutOffset time.Duration
	// MaxConcurrent bounds probes running at once. Requests beyond it are
	// rejected with 503 rather than queued. Zero disables the limit.
	MaxConcurrent int
	Requests      *prometheus.CounterVec
	InFlight      prometheus.Gauge
	Live          *atomic.Pointer[map[string]config.Module]
}

// Handler returns the /probe handler; nil metrics in opts are replaced with unregistered stand-ins.
func Handler(opts Options) http.HandlerFunc {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	requests := opts.Requests
	if requests == nil {
		requests = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "probe_requests_total"}, []string{"module", "code"})
	}
	inFlight := opts.InFlight
	if inFlight == nil {
		inFlight = prometheus.NewGauge(prometheus.GaugeOpts{Name: "probes_in_flight"})
	}

	var sem chan struct{}
	if opts.MaxConcurrent > 0 {
		sem = make(chan struct{}, opts.MaxConcurrent)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		moduleName := r.URL.Query().Get("module")
		if moduleName == "" {
			moduleName = config.DefaultModuleName
		}

		modules := *opts.Live.Load()
		mod, ok := modules[moduleName]
		if !ok {
			logger.Debug("probe rejected: unknown module", "module", moduleName)
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
			logger.Debug("probe rejected: malformed target", "module", moduleName, "target", r.URL.Query().Get("target"), "error", err)
			writeError(w, requests, moduleName, http.StatusBadRequest, err.Error())
			return
		}
		if _, allowed := mod.AllowedPorts[port]; !allowed {
			logger.Debug("probe rejected: port not allowed", "module", moduleName, "target", target, "port", port)
			writeError(w, requests, moduleName, http.StatusForbidden, fmt.Sprintf("port %d not allowed for module %q", port, moduleName))
			return
		}
		if !targetAllowed(host, mod.AllowedTargets) {
			logger.Debug("probe rejected: target not allowed", "module", moduleName, "target", target, "host", host)
			writeError(w, requests, moduleName, http.StatusForbidden, fmt.Sprintf("target %q not allowed for module %q", host, moduleName))
			return
		}

		if sem != nil {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			default:
				logger.Warn("probe rejected: concurrency limit reached", "module", moduleName, "target", target, "limit", opts.MaxConcurrent)
				writeError(w, requests, moduleName, http.StatusServiceUnavailable, fmt.Sprintf("probe concurrency limit of %d reached", opts.MaxConcurrent))
				return
			}
		}

		inFlight.Inc()
		defer inFlight.Dec()

		ctx, cancel := context.WithTimeout(r.Context(), effectiveTimeout(r, opts.Timeout, opts.TimeoutOffset))
		defer cancel()

		registry := prometheus.NewRegistry()
		registry.MustRegister(collector.New(ctx, target, moduleName, mod.Options, logger))

		rec := newStatusRecorder(w)
		promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(rec, r)
		requests.WithLabelValues(moduleName, strconv.Itoa(rec.status)).Inc()
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

// newStatusRecorder defaults to 200, which net/http sends when WriteHeader is never called.
func newStatusRecorder(w http.ResponseWriter) *statusRecorder {
	return &statusRecorder{ResponseWriter: w, status: http.StatusOK}
}

func (rec *statusRecorder) WriteHeader(code int) {
	if !rec.wroteHeader {
		rec.status = code
		rec.wroteHeader = true
	}
	rec.ResponseWriter.WriteHeader(code)
}

func (rec *statusRecorder) Write(b []byte) (int, error) {
	rec.wroteHeader = true
	return rec.ResponseWriter.Write(b)
}

// Unwrap keeps http.ResponseController able to reach the wrapped writer.
func (rec *statusRecorder) Unwrap() http.ResponseWriter { return rec.ResponseWriter }

// effectiveTimeout shortens maxTimeout to the scrape timeout minus offset; unusable header values are ignored.
func effectiveTimeout(r *http.Request, maxTimeout, offset time.Duration) time.Duration {
	timeoutSecs := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds")
	if timeoutSecs == "" {
		return maxTimeout
	}
	s, err := strconv.ParseFloat(timeoutSecs, 64)
	if err != nil || math.IsNaN(s) || s <= 0 || s >= (maxTimeout+offset).Seconds() {
		return maxTimeout
	}
	if scrapeTimeout := time.Duration(s*float64(time.Second)) - offset; scrapeTimeout > 0 {
		return scrapeTimeout
	}
	return maxTimeout
}

// writeError prefixes msg with the status, so a browser shows it inline, and counts the request.
func writeError(w http.ResponseWriter, requests *prometheus.CounterVec, moduleName string, code int, msg string) {
	http.Error(w, fmt.Sprintf("%d %s: %s", code, http.StatusText(code), msg), code)
	requests.WithLabelValues(moduleName, strconv.Itoa(code)).Inc()
}

// ensurePort parses target as a URL authority, which handles bracketed IPv6 literals and optional ports.
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

func targetAllowed(host string, matchers []config.TargetMatcher) bool {
	for _, m := range matchers {
		if m.Match(host) {
			return true
		}
	}
	return false
}
