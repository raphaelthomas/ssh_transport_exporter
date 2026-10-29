// Package normalize provides shared, canonical normalization.
package normalize

import "strings"

// Hostname returns the canonical form of h for allowed_targets matching; IP
// literals are canonicalized by the matchers, not here.
func Hostname(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}
