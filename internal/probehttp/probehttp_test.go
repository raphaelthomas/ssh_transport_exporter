package probehttp

import (
	"strings"
	"testing"

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
