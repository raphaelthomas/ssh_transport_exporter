package probehttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/config"
)

func TestEnsurePort(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		defaultPort int
		wantTarget  string
		wantHost    string
		wantPort    int
		wantErr     bool
	}{
		{"bare host uses default port", "example.com", 22, "example.com:22", "example.com", 22, false},
		{"host with explicit port", "example.com:2222", 22, "example.com:2222", "example.com", 2222, false},
		{"host uppercased is normalized", "Example.COM", 22, "example.com:22", "example.com", 22, false},
		{"ipv4 with port", "192.0.2.1:22", 22, "192.0.2.1:22", "192.0.2.1", 22, false},
		{"bracketed ipv6 with port", "[2001:db8::1]:2222", 22, "[2001:db8::1]:2222", "2001:db8::1", 2222, false},
		{"bracketed ipv6 no port", "[2001:db8::1]", 22, "[2001:db8::1]:22", "2001:db8::1", 22, false},
		{"invalid port", "example.com:notaport", 22, "", "", 0, true},
		{"empty host", "", 22, "", "", 0, true},
		{"userinfo rejected", "user@example.com", 22, "", "", 0, true},
		{"path rejected", "example.com/foo", 22, "", "", 0, true},
		{"query rejected", "example.com?x=1", 22, "", "", 0, true},
		{"fragment rejected", "example.com#frag", 22, "", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTarget, gotHost, gotPort, err := ensurePort(tt.target, tt.defaultPort)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ensurePort(%q) = nil error, want error", tt.target)
				}
				return
			}
			if err != nil {
				t.Fatalf("ensurePort(%q) unexpected error: %v", tt.target, err)
			}
			if gotTarget != tt.wantTarget || gotHost != tt.wantHost || gotPort != tt.wantPort {
				t.Errorf("ensurePort(%q) = (%q, %q, %d), want (%q, %q, %d)",
					tt.target, gotTarget, gotHost, gotPort, tt.wantTarget, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestEnsurePortErrorMentionsTarget(t *testing.T) {
	_, _, _, err := ensurePort("user@example.com", 22)
	if err == nil || !strings.Contains(err.Error(), "example.com") {
		t.Errorf("error = %v, want it to mention the target", err)
	}
}

// exactMatcher is a minimal config.TargetMatcher stub that matches one host,
// letting us exercise targetAllowed without reaching into config internals.
type exactMatcher struct{ host string }

func (m exactMatcher) Match(host string) bool { return host == m.host }

func TestTargetAllowed(t *testing.T) {
	matchers := []config.TargetMatcher{
		exactMatcher{host: "host.example.com"},
		exactMatcher{host: "192.0.2.7"},
	}

	tests := []struct {
		host string
		want bool
	}{
		{"host.example.com", true},
		{"192.0.2.7", true},
		{"other.example.com", false},
		{"192.0.3.1", false},
	}
	for _, tt := range tests {
		if got := targetAllowed(tt.host, matchers); got != tt.want {
			t.Errorf("targetAllowed(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}

	// No matchers means deny-all.
	if targetAllowed("anything", nil) {
		t.Error("targetAllowed with no matchers = true, want false (deny-all)")
	}
}

func TestEffectiveTimeout(t *testing.T) {
	const maxTimeout = 10 * time.Second

	tests := []struct {
		name   string
		header string // empty means the header is not set at all
		want   time.Duration
	}{
		{name: "no header keeps the hard bound", header: "", want: maxTimeout},
		{name: "shorter header wins", header: "2.5", want: 2500 * time.Millisecond},
		{name: "longer header is capped by the hard bound", header: "30", want: maxTimeout},
		{name: "equal header keeps the hard bound", header: "10", want: maxTimeout},
		{name: "sub-second header wins", header: "0.25", want: 250 * time.Millisecond},
		{name: "malformed header ignored", header: "not-a-number", want: maxTimeout},
		{name: "zero header ignored", header: "0", want: maxTimeout},
		{name: "negative header ignored", header: "-1", want: maxTimeout},
		{name: "empty header value ignored", header: `""`, want: maxTimeout},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/probe?target=host:22", nil)
			if tt.header != "" {
				req.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", strings.Trim(tt.header, `"`))
			}
			if got := effectiveTimeout(req, maxTimeout); got != tt.want {
				t.Errorf("effectiveTimeout(header=%q) = %s, want %s", tt.header, got, tt.want)
			}
		})
	}
}

func TestStatusRecorder(t *testing.T) {
	tests := []struct {
		name  string
		serve func(w http.ResponseWriter)
		want  int
	}{
		{
			name:  "body without WriteHeader records the implied 200",
			serve: func(w http.ResponseWriter) { _, _ = w.Write([]byte("ok")) },
			want:  http.StatusOK,
		},
		{
			name:  "explicit error status is recorded",
			serve: func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) },
			want:  http.StatusInternalServerError,
		},
		{
			name: "only the first WriteHeader counts",
			serve: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.WriteHeader(http.StatusOK)
			},
			want: http.StatusServiceUnavailable,
		},
		{
			name: "WriteHeader after a body write cannot rewrite the status",
			serve: func(w http.ResponseWriter) {
				_, _ = w.Write([]byte("ok"))
				w.WriteHeader(http.StatusInternalServerError)
			},
			want: http.StatusOK,
		},
		{
			name:  "nothing written at all records 200",
			serve: func(http.ResponseWriter) {},
			want:  http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := newStatusRecorder(httptest.NewRecorder())
			tt.serve(rec)
			if rec.status != tt.want {
				t.Errorf("recorded status = %d, want %d", rec.status, tt.want)
			}
		})
	}
}

// The recorder must stay transparent: what it records has to match what the
// underlying ResponseWriter actually sent.
func TestStatusRecorderPassesThroughToTheClient(t *testing.T) {
	under := httptest.NewRecorder()
	rec := newStatusRecorder(under)

	rec.WriteHeader(http.StatusInternalServerError)
	if _, err := rec.Write([]byte("boom")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if under.Code != http.StatusInternalServerError {
		t.Errorf("underlying status = %d, want %d", under.Code, http.StatusInternalServerError)
	}
	if got := under.Body.String(); got != "boom" {
		t.Errorf("underlying body = %q, want %q", got, "boom")
	}
	if rec.status != under.Code {
		t.Errorf("recorded status %d does not match what was sent (%d)", rec.status, under.Code)
	}
}

// http.ResponseController must be able to reach past the wrapper, otherwise
// flushing and write deadlines would silently stop working.
func TestStatusRecorderUnwrap(t *testing.T) {
	under := httptest.NewRecorder()
	rec := newStatusRecorder(under)

	if got := rec.Unwrap(); got != http.ResponseWriter(under) {
		t.Errorf("Unwrap() = %v, want the underlying recorder", got)
	}
	// httptest.ResponseRecorder implements Flush, so this must reach it.
	if err := http.NewResponseController(rec).Flush(); err != nil {
		t.Errorf("ResponseController.Flush through the wrapper: %v", err)
	}
	if !under.Flushed {
		t.Error("underlying recorder was not flushed through the wrapper")
	}
}

// A header on one request must not shorten the next one.
func TestEffectiveTimeoutDoesNotLeakAcrossRequests(t *testing.T) {
	const maxTimeout = 10 * time.Second

	withHeader := httptest.NewRequest(http.MethodGet, "/probe?target=host:22", nil)
	withHeader.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", "0.1")
	if got := effectiveTimeout(withHeader, maxTimeout); got != 100*time.Millisecond {
		t.Fatalf("first request: got %s, want 100ms", got)
	}

	bare := httptest.NewRequest(http.MethodGet, "/probe?target=host:22", nil)
	if got := effectiveTimeout(bare, maxTimeout); got != maxTimeout {
		t.Errorf("second request without header: got %s, want the full %s bound", got, maxTimeout)
	}
}
