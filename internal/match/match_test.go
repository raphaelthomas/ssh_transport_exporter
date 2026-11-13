package match

import (
	"strings"
	"testing"
)

func TestPattern(t *testing.T) {
	tests := []struct {
		s, pattern string
		want       bool
	}{
		{"", "", true},
		{"h", "", false},
		{"", "*", true},
		{"h", "*", true},
		{"", "?", false},
		{"h", "?", true},
		{"h", "h*", true},
		{"host", "h*", true},
		{"host", "*t", true},
		{"host", "h*t", true},
		{"ht", "h*t", true},
		{"host", "h*s", false},
		{"host", "hos?", true},
		{"hos", "hos?", false},
		{"[h]:2222", "*h*", true},
		{"[h]:2222", "[*]:*", true},
		{"[h]:2222", "h:2222", false},
		{"host", "Host", false},
		{"a.example.com", "*.example.com", true},
		{"example.com", "*.example.com", false},
		{"h", "**", true},
		{"h", "*?*", true},
		{"", "*?*", false},
		{strings.Repeat("a", 64), strings.Repeat("*a", 32) + "b", false},
	}
	for _, tt := range tests {
		if got := Pattern(tt.s, tt.pattern); got != tt.want {
			t.Errorf("Pattern(%q, %q) = %v, want %v", tt.s, tt.pattern, got, tt.want)
		}
	}
}
