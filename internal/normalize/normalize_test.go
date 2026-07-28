package normalize

import "testing"

func TestHostname(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"already canonical", "example.com", "example.com"},
		{"uppercase lowered", "Example.COM", "example.com"},
		{"single trailing dot stripped", "example.com.", "example.com"},
		{"only one trailing dot stripped", "example.com..", "example.com."},
		{"uppercase and trailing dot", "HOST.Example.Com.", "host.example.com"},
		{"ipv4 literal unaffected", "192.0.2.1", "192.0.2.1"},
		{"ipv6 literal lowercased", "2001:DB8::1", "2001:db8::1"},
		{"empty string", "", ""},
		{"single dot", ".", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Hostname(tt.in); got != tt.want {
				t.Errorf("Hostname(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
