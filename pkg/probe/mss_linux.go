//go:build linux

package probe

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// tcpNegotiatedMSS returns the kernel's effective negotiated MSS
// (tp->mss_cache) for an established TCP connection, read via
// getsockopt(TCP_MAXSEG).
func tcpNegotiatedMSS(conn *net.TCPConn) (int, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("SyscallConn: %w", err)
	}

	var mss int
	var controlErr error
	var sockErr error

	controlErr = rawConn.Control(func(fd uintptr) {
		mss, sockErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG)
	})
	if controlErr != nil {
		return 0, fmt.Errorf("syscall.RawConn.Control: %w", err)
	}
	if sockErr != nil {
		return 0, fmt.Errorf("getsockopt(TCP_MAXSEG): %w", sockErr)
	}

	return mss, nil
}
