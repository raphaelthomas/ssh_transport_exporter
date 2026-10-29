package config

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/normalize"
)

// TargetMatcher reports whether a target host, normalized via normalize.Hostname, is permitted.
type TargetMatcher interface {
	Match(host string) bool
}

func resolveAllowedTargets(patterns []string, allowAll bool) ([]TargetMatcher, error) {
	if len(patterns) == 0 {
		if allowAll {
			return []TargetMatcher{allowAllMatcher{}}, nil
		}
		return nil, fmt.Errorf("no allowed_targets configured (set allowed_targets, or pass --allow-all-targets to probe any target)")
	}

	matchers := make([]TargetMatcher, 0, len(patterns))
	for _, pat := range patterns {
		m, err := buildTarget(pat)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, m)
	}
	return matchers, nil
}

func buildTarget(pattern string) (TargetMatcher, error) {
	switch {
	case pattern == "":
		return nil, fmt.Errorf("empty target pattern")
	case pattern == "*":
		return nil, fmt.Errorf("%q (allow-all) is not configurable via allowed_targets", pattern)
	case strings.HasPrefix(pattern, "**"):
		return nil, fmt.Errorf("%q: multi-label wildcards (**) are not supported", pattern)
	case strings.ContainsRune(pattern, '%'):
		return nil, fmt.Errorf("%q: IP address with zone is not allowed", pattern)
	case strings.HasPrefix(pattern, "*."):
		return newWildcardMatcher(pattern)
	case strings.ContainsRune(pattern, '/'):
		return newCIDRMatcher(pattern)
	default:
		if addr, err := netip.ParseAddr(pattern); err == nil {
			return newIPMatcher(addr)
		}
		return newHostMatcher(pattern)
	}
}

// allowAllMatcher is never built from a pattern, only from --allow-all-targets.
type allowAllMatcher struct{}

func (allowAllMatcher) Match(string) bool { return true }

type hostMatcher struct{ host string }

func newHostMatcher(pattern string) (TargetMatcher, error) {
	h := normalize.Hostname(pattern)
	if h == "" {
		return nil, fmt.Errorf("%q: empty hostname", pattern)
	}
	return hostMatcher{host: h}, nil
}

func (m hostMatcher) Match(host string) bool { return host == m.host }

// wildcardMatcher matches exactly one label below parent, as TLS wildcards do; parent itself does not match.
type wildcardMatcher struct{ parent string }

func newWildcardMatcher(pattern string) (TargetMatcher, error) {
	parent := normalize.Hostname(strings.TrimPrefix(pattern, "*."))
	if parent == "" || strings.Contains(parent, "*") {
		return nil, fmt.Errorf("%q: invalid wildcard pattern", pattern)
	}
	return wildcardMatcher{parent: parent}, nil
}

func (m wildcardMatcher) Match(host string) bool {
	suffix := "." + m.parent
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := host[:len(host)-len(suffix)]
	return label != "" && !strings.Contains(label, ".")
}

type ipMatcher struct{ addr netip.Addr }

func newIPMatcher(addr netip.Addr) (TargetMatcher, error) {
	if addr.Zone() != "" {
		return nil, fmt.Errorf("%q: IP address with zone is not allowed", addr)
	}
	return ipMatcher{addr: addr}, nil
}

func (m ipMatcher) Match(host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return false
	}
	return addr == m.addr
}

type cidrMatcher struct{ prefix netip.Prefix }

func newCIDRMatcher(pattern string) (TargetMatcher, error) {
	prefix, err := netip.ParsePrefix(pattern)
	if err != nil {
		return nil, fmt.Errorf("%q: invalid CIDR: %w", pattern, err)
	}
	return cidrMatcher{prefix: prefix.Masked()}, nil
}

func (m cidrMatcher) Match(host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return false
	}
	return m.prefix.Contains(addr)
}
