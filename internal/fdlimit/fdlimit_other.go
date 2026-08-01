//go:build !unix

package fdlimit

import "errors"

var errNotSupported = errors.New("reading the file descriptor limit is not supported on this platform")

// softLimit is unimplemented outside unix.
func softLimit() (uint64, error) {
	return 0, errNotSupported
}
