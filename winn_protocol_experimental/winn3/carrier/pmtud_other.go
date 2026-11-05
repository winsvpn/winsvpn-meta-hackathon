//go:build !linux && !android

package carrier

import (
	"errors"
	"net"
)

// Platforms without a portable per-socket path-MTU readback.
//
// Darwin, Windows and the BSDs do not expose a connected UDP socket's
// discovered path MTU through a getsockopt this package can depend on. The
// honest answer there is "no measurement", which is exactly what a zero from
// DiscoveredPathMTU already means everywhere else. Returning a guess would be
// worse than returning nothing: the driver would shrink a tunnel on a number
// the kernel never measured.

func enableUDPPathMTUDiscovery(conn *net.UDPConn) error {
	return wrap(ErrConfig, "path MTU discovery is not available on this platform")
}

// EnableDontFragment is Linux and Android only. Elsewhere it returns
// errors.ErrUnsupported and the socket keeps its platform behaviour, the same
// contract as EnableSendErrorReporting.
func EnableDontFragment(conn *net.UDPConn) error {
	return errors.ErrUnsupported
}

func udpKernelPathMTU(conn *net.UDPConn) (int, error) {
	return 0, wrap(ErrConfig, "path MTU discovery is not available on this platform")
}

func isPathMTUExceeded(err error) bool {
	return false
}
