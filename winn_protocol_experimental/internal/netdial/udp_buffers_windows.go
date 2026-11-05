//go:build windows

package netdial

import (
	"net"
	"syscall"

	"winsvpn.local/winnprotocol/internal/sysconv"
)

func happyUDPSockoptInt(conn *net.UDPConn, opt int) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var ctrlErr error
	if err := raw.Control(func(fd uintptr) {
		descriptor, convErr := sysconv.Descriptor(fd)
		if convErr != nil {
			ctrlErr = convErr
			return
		}
		// Windows syscall.GetsockoptInt takes syscall.Handle, not int.
		n, ctrlErr = syscall.GetsockoptInt(syscall.Handle(descriptor), syscall.SOL_SOCKET, opt)
	}); err != nil {
		return 0, err
	}
	return n, ctrlErr
}
