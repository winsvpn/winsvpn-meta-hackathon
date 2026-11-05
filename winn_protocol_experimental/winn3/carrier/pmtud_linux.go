//go:build linux || android

package carrier

import (
	"errors"
	"net"
	"syscall"

	"winsvpn.local/winnprotocol/internal/sysconv"
)

// Linux and Android: IP_MTU_DISCOVER / IPV6_MTU_DISCOVER with IP_PMTUDISC_DO.
//
// IP_PMTUDISC_DO sets the Don't Fragment bit on every outgoing datagram and
// makes the kernel refuse, with EMSGSIZE, any datagram larger than the path MTU
// it currently believes in. That refusal is the signal. Without DF the datagram
// is fragmented instead, the fragments are dropped by the middleboxes this
// protocol exists to get past, and nothing anywhere learns why.
//
// IP_PMTUDISC_PROBE is deliberately NOT used. PROBE sets DF and suppresses the
// EMSGSIZE, which is right for a program implementing its own RFC 8899 probe
// ladder and exactly wrong here: the error IS the mechanism this file reports.
const (
	ipPMTUDiscDo = 2 // IP_PMTUDISC_DO / IPV6_PMTUDISC_DO

	ipMTUDiscover   = 10 // IP_MTU_DISCOVER
	ipMTU           = 14 // IP_MTU
	ipv6MTUDiscover = 23 // IPV6_MTU_DISCOVER
	ipv6MTU         = 24 // IPV6_MTU
)

// udpSocketIsIPv6 reports whether this socket's local address is an IPv6
// address that is not a v4-mapped one. A v4-mapped socket takes the IPv4
// options: the kernel accounts its path MTU under IP_MTU, not IPV6_MTU.
func udpSocketIsIPv6(conn *net.UDPConn) bool {
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		return false
	}
	return local.IP.To4() == nil
}

func udpSetsockoptInt(conn *net.UDPConn, level, opt, value int) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var ctrlErr error
	if err := raw.Control(func(fd uintptr) {
		descriptor, convErr := sysconv.Descriptor(fd)
		if convErr != nil {
			ctrlErr = convErr
			return
		}
		ctrlErr = syscall.SetsockoptInt(descriptor, level, opt, value)
	}); err != nil {
		return err
	}
	return ctrlErr
}

func udpGetsockoptInt(conn *net.UDPConn, level, opt int) (int, error) {
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
		n, ctrlErr = syscall.GetsockoptInt(descriptor, level, opt)
	}); err != nil {
		return 0, err
	}
	return n, ctrlErr
}

func enableUDPPathMTUDiscovery(conn *net.UDPConn) error {
	if conn == nil {
		return wrap(ErrConfig, "path MTU discovery: no socket")
	}
	if udpSocketIsIPv6(conn) {
		return udpSetsockoptInt(conn, syscall.IPPROTO_IPV6, ipv6MTUDiscover, ipPMTUDiscDo)
	}
	return udpSetsockoptInt(conn, syscall.IPPROTO_IP, ipMTUDiscover, ipPMTUDiscDo)
}

// EnableDontFragment sets IP_PMTUDISC_DO (IPV6_PMTUDISC_DO on an IPv6 socket)
// on a UDP socket that is not wrapped in a *UDP: the gateway's shared,
// unconnected listener. It is the same setsockopt EnablePathMTUDiscovery
// issues, exported so that socket stops being the one place in the protocol
// where the kernel may fragment a full-size datagram without saying so
// (Round CM: us-chicago1, a 1400-byte NIC under a 1430-byte datagram plan).
//
// An unconnected socket has no IP_MTU to read back, so nothing is recorded:
// the effect is DF on every datagram, and EMSGSIZE from the send path for any
// datagram wider than the route to its peer.
func EnableDontFragment(conn *net.UDPConn) error {
	return enableUDPPathMTUDiscovery(conn)
}

func udpKernelPathMTU(conn *net.UDPConn) (int, error) {
	if conn == nil {
		return 0, wrap(ErrConfig, "path MTU discovery: no socket")
	}
	if udpSocketIsIPv6(conn) {
		return udpGetsockoptInt(conn, syscall.IPPROTO_IPV6, ipv6MTU)
	}
	return udpGetsockoptInt(conn, syscall.IPPROTO_IP, ipMTU)
}

func isPathMTUExceeded(err error) bool {
	return errors.Is(err, syscall.EMSGSIZE)
}
