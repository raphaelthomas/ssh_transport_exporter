// Package normalize provides shared, canonical normalization.
package normalize

import "strings"

// Hostname lowercases (ASCII) and strips a single trailing dot, yielding the
// canonical form used for allowed_targets matching. IP literals are unaffected
// beyond case (a no-op for them); IP canonicalization is handled via netip in
// the matchers.
func Hostname(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}
