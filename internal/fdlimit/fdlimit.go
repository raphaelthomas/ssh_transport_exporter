// Package fdlimit reports whether the process file descriptor budget covers a
// given probe concurrency.
package fdlimit

// Each in-flight probe holds an inbound HTTP connection and an outbound TCP
// connection; the headroom covers the listener, config reloads and the runtime.
const (
	perProbe = 2
	headroom = 64
)

// Sufficient reports whether the soft RLIMIT_NOFILE covers maxConcurrent
// probes, along with that limit and the budget needed. It reports true when the
// concurrency is unlimited or the limit cannot be read.
func Sufficient(maxConcurrent int) (ok bool, soft, needed uint64) {
	if maxConcurrent <= 0 {
		return true, 0, 0
	}
	soft, err := softLimit()
	if err != nil {
		return true, 0, 0
	}
	needed = uint64(maxConcurrent)*perProbe + headroom
	return soft >= needed, soft, needed
}
