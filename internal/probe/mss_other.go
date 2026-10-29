//go:build !linux

package probe

import (
	"errors"
	"net"
)

var errMSSNotSupported = errors.New("negotiated MSS reading is only supported on linux")

func tcpNegotiatedMSS(_ *net.TCPConn) (int, error) {
	return 0, errMSSNotSupported
}
