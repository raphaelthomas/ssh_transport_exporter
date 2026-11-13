// Package match ports OpenSSH's pattern matching.
package match

import "slices"

// Pattern reports whether s matches pattern like OpenSSH's match_pattern: '*'
// matches any sequence of bytes, '?' any one byte, and all else itself.
func Pattern(s, pattern string) bool {
	// An NFA with a state per pattern byte plus an accepting one, as in
	// OpenSSH 10.4+, so that matching never backtracks.
	m := len(pattern)
	if m == 0 {
		return s == ""
	}
	states, next := make([]bool, m+1), make([]bool, m+1)
	states[0] = true
	closeOverStars(states, pattern)
	for i := range len(s) {
		clear(next)
		for j := range m {
			if !states[j] {
				continue
			}
			switch pattern[j] {
			case '*':
				next[j] = true
			case '?', s[i]:
				next[j+1] = true
			}
		}
		closeOverStars(next, pattern)
		states, next = next, states
		if !slices.Contains(states, true) {
			return false
		}
	}
	return states[m]
}

// closeOverStars activates the state after each active '*', which matches the
// empty sequence.
func closeOverStars(states []bool, pattern string) {
	for i := range len(pattern) {
		if states[i] && pattern[i] == '*' {
			states[i+1] = true
		}
	}
}
