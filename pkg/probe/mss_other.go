//go:build !linux

package probe

import (
	"fmt"
	"net"
)

// tcpNegotiatedMSS is unimplemented outside Linux.
func tcpNegotiatedMSS(_ *net.TCPConn) (int, error) {
	return 0, fmt.Errorf("negotiated MSS reading is only supported on linux")
}
