//go:build unix

package fdlimit

import "golang.org/x/sys/unix"

func softLimit() (uint64, error) {
	var rlim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rlim); err != nil {
		return 0, err
	}
	return rlim.Cur, nil
}
