package config

import (
	"strings"
	"testing"
)

func TestHostMatcher(t *testing.T) {
	m, err := newHostMatcher("Example.COM")
	if err != nil {
		t.Fatalf("newHostMatcher: %v", err)
	}
	tests := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"other.com", false},
		{"sub.example.com", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := m.Match(tt.host); got != tt.want {
			t.Errorf("hostMatcher.Match(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
	if _, err := newHostMatcher("."); err == nil {
		t.Error("newHostMatcher(\".\") = nil error, want error for empty hostname")
	}
}

func TestWildcardMatcher(t *testing.T) {
	m, err := newWildcardMatcher("*.example.com")
	if err != nil {
		t.Fatalf("newWildcardMatcher: %v", err)
	}
	tests := []struct {
		host string
		want bool
	}{
		{"a.example.com", true},
		{"host.example.com", true},
		{"example.com", false},            // apex does not match
		{"a.b.example.com", false},        // multi-label does not match
		{".example.com", false},           // empty label
		{"aexample.com", false},           // not a subdomain
		{"a.example.com.evil.com", false}, // suffix mid-string
	}
	for _, tt := range tests {
		if got := m.Match(tt.host); got != tt.want {
			t.Errorf("wildcardMatcher.Match(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}

	for _, bad := range []string{"*.", "*.*"} {
		if _, err := newWildcardMatcher(bad); err == nil {
			t.Errorf("newWildcardMatcher(%q) = nil error, want error", bad)
		}
	}
}

func TestIPMatcher(t *testing.T) {
	m, err := buildTarget("192.0.2.1")
	if err != nil {
		t.Fatalf("buildTarget: %v", err)
	}
	tests := []struct {
		host string
		want bool
	}{
		{"192.0.2.1", true},
		{"192.0.2.2", false},
		{"2001:db8::1", false},
		{"not-an-ip", false},
		{"192.0.2.1%eth0", false},
	}
	for _, tt := range tests {
		if got := m.Match(tt.host); got != tt.want {
			t.Errorf("ipMatcher.Match(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}

	// IPv6 literal
	m6, err := buildTarget("2001:db8::1")
	if err != nil {
		t.Fatalf("buildTarget(v6): %v", err)
	}
	if !m6.Match("2001:db8::1") {
		t.Error("ipMatcher.Match(2001:db8::1) = false, want true")
	}
	if m6.Match("2001:db8::2") {
		t.Error("ipMatcher.Match(2001:db8::2) = true, want false")
	}
}

func TestCIDRMatcher(t *testing.T) {
	m, err := buildTarget("192.0.2.0/24")
	if err != nil {
		t.Fatalf("buildTarget: %v", err)
	}
	tests := []struct {
		host string
		want bool
	}{
		{"192.0.2.1", true},
		{"192.0.2.255", true},
		{"192.0.3.1", false},
		{"not-an-ip", false},
		{"192.0.2.1%eth0", false},
	}
	for _, tt := range tests {
		if got := m.Match(tt.host); got != tt.want {
			t.Errorf("cidrMatcher.Match(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}

	// IPv6 CIDR
	m6, err := buildTarget("2001:db8::/32")
	if err != nil {
		t.Fatalf("buildTarget(v6 cidr): %v", err)
	}
	if !m6.Match("2001:db8::1") {
		t.Error("cidrMatcher.Match(2001:db8::1) = false, want true")
	}
	if m6.Match("2001:db9::1") {
		t.Error("cidrMatcher.Match(2001:db9::1) = true, want false")
	}
}

func TestBuildTargetClassificationAndRejections(t *testing.T) {
	// Valid patterns classify without error and produce the right type.
	valid := []struct {
		pattern string
		typ     string
	}{
		{"host.example.com", "config.hostMatcher"},
		{"*.example.com", "config.wildcardMatcher"},
		{"192.0.2.1", "config.ipMatcher"},
		{"192.0.2.0/24", "config.cidrMatcher"},
	}
	for _, tt := range valid {
		m, err := buildTarget(tt.pattern)
		if err != nil {
			t.Errorf("buildTarget(%q) unexpected error: %v", tt.pattern, err)
			continue
		}
		if got := typeName(m); got != tt.typ {
			t.Errorf("buildTarget(%q) type = %s, want %s", tt.pattern, got, tt.typ)
		}
	}

	// Rejected patterns.
	rejected := []struct {
		pattern  string
		contains string
	}{
		{"", "empty target pattern"},
		{"*", "allow-all"},
		{"**.example.com", "multi-label wildcards"},
		{"192.0.2.1%eth0", "zone"},
	}
	for _, tt := range rejected {
		_, err := buildTarget(tt.pattern)
		if err == nil {
			t.Errorf("buildTarget(%q) = nil error, want error", tt.pattern)
			continue
		}
		if !strings.Contains(err.Error(), tt.contains) {
			t.Errorf("buildTarget(%q) error = %q, want containing %q", tt.pattern, err, tt.contains)
		}
	}
}

func TestResolveAllowedTargets(t *testing.T) {
	// Empty with allowAll -> single allowAllMatcher that permits anything.
	matchers, err := resolveAllowedTargets(nil, true)
	if err != nil {
		t.Fatalf("resolveAllowedTargets(nil, true): %v", err)
	}
	if len(matchers) != 1 || !matchers[0].Match("anything.example") {
		t.Errorf("resolveAllowedTargets(nil, true) did not produce allow-all matcher")
	}

	// Empty without allowAll -> error (deny all).
	if _, err := resolveAllowedTargets(nil, false); err == nil {
		t.Error("resolveAllowedTargets(nil, false) = nil error, want error")
	}

	// Patterns compile in order.
	matchers, err = resolveAllowedTargets([]string{"host.example.com", "192.0.2.0/24"}, false)
	if err != nil {
		t.Fatalf("resolveAllowedTargets(patterns): %v", err)
	}
	if len(matchers) != 2 {
		t.Fatalf("got %d matchers, want 2", len(matchers))
	}
	if !matchers[0].Match("host.example.com") || !matchers[1].Match("192.0.2.5") {
		t.Error("compiled matchers do not match their patterns")
	}

	// A bad pattern surfaces the error.
	if _, err := resolveAllowedTargets([]string{"*"}, false); err == nil {
		t.Error("resolveAllowedTargets([\"*\"]) = nil error, want error")
	}
}

// typeName returns the concrete type name (with package) of a TargetMatcher.
func typeName(m TargetMatcher) string {
	switch m.(type) {
	case hostMatcher:
		return "config.hostMatcher"
	case wildcardMatcher:
		return "config.wildcardMatcher"
	case ipMatcher:
		return "config.ipMatcher"
	case cidrMatcher:
		return "config.cidrMatcher"
	case allowAllMatcher:
		return "config.allowAllMatcher"
	default:
		return "unknown"
	}
}
