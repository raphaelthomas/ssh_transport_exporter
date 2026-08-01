package fdlimit

import "testing"

// Sufficient only reports a shortfall when the descriptor budget cannot cover
// the concurrency, so operators are not trained to ignore the warning.
func TestSufficient(t *testing.T) {
	soft, err := softLimit()
	if err != nil {
		t.Skipf("no file descriptor limit on this platform: %v", err)
	}
	if soft < headroom+perProbe {
		t.Skipf("file descriptor limit of %d is too low to test against", soft)
	}

	tests := []struct {
		name          string
		maxConcurrent int
		want          bool
	}{
		{name: "concurrency unlimited", maxConcurrent: 0, want: true},
		{name: "negative concurrency", maxConcurrent: -1, want: true},
		{name: "within budget", maxConcurrent: 1, want: true},
		{name: "exactly at budget", maxConcurrent: int((soft - headroom) / perProbe), want: true},
		{name: "beyond budget", maxConcurrent: int(soft), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, gotSoft, needed := Sufficient(tc.maxConcurrent)
			if ok != tc.want {
				t.Errorf("Sufficient(%d) = %v with a soft limit of %d, want %v", tc.maxConcurrent, ok, soft, tc.want)
			}
			if !ok && needed <= gotSoft {
				t.Errorf("Sufficient(%d) reported a shortfall with needed %d <= soft %d", tc.maxConcurrent, needed, gotSoft)
			}
		})
	}
}

// An unreadable limit must not produce a warning, so unsupported platforms stay
// quiet.
func TestSufficientUnlimitedNeedsNoLimit(t *testing.T) {
	ok, soft, needed := Sufficient(0)
	if !ok || soft != 0 || needed != 0 {
		t.Errorf("Sufficient(0) = (%v, %d, %d), want (true, 0, 0)", ok, soft, needed)
	}
}
