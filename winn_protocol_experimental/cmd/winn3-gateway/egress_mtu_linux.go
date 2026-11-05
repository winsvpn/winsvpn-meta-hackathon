//go:build linux || android

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// measureEgressRoute asks the kernel, once per representative destination,
// which device a UDP datagram from the listener's own address and port would
// leave through (RTM_GETROUTE, the `ip route get` question). The answer
// follows every policy rule the listener's replies follow (from, ipproto,
// sport, uidrange), which the main table's default route does not (Round CM2
// retro, Sol OI-CM2-1a). A destination the kernel will not route is reported
// per destination, not as a failure of the whole measurement.
func measureEgressRoute(lookup egressLookup) ([]egressRoute, error) {
	dsts := make([]netip.AddrPort, 0, len(egressProbeDestinations))
	for _, d := range egressProbeDestinations {
		// Port 0: a probe stands for any client, so it has no destination
		// port and sends no RTA_DPORT. The per-client guard sends the real one.
		dsts = append(dsts, netip.AddrPortFrom(d, 0))
	}
	return measureEgressRouteTo(lookup, dsts)
}

// rtnlSocket is the rtnetlink request socket every egress question uses
// (nlTransport, egress_netlink_answer.go).
type rtnlSocket struct {
	fd     int
	portID uint32
	buf    []byte
}

// openRouteSocket opens the rtnetlink socket every lookup uses, with STRICT
// checking of GET requests (NETLINK_GET_STRICT_CHK, Linux 4.20+). Without it a
// kernel ignores an attribute it does not know, so a lookup that asked about
// the destination port could silently be answered as if it had not (Round
// CM3 Turn 2). With it the kernel refuses the request (EINVAL) instead. A
// kernel that cannot enable strict checking cannot describe the reply flow:
// errFlowNotDescribable. Any other failure to set the socket up is an
// incomplete answer (Round CM3 Turn 6): asked again, then failed closed.
//
// groups are rtnetlink multicast groups the socket also joins. A dump socket
// joins the IPv4 rule and route groups (openDumpTransport): the kernel then
// queues a notification on it for every rule or route change, in order with
// the dump's own messages, so a change that lands while a dump is being
// assembled arrives before that dump's NLMSG_DONE and the attempt is
// incomplete (recv rejects any datagram that is not the kernel's unicast
// answer). This covers what NLM_F_DUMP_INTR does not: a multi-part dump the
// kernel resumes by position can skip an object when another is removed in
// between, with no flag (measured: TestEgressNetnsDumpUnderRuleChurn).
func openRouteSocket(groups ...int) (*rtnlSocket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			// A sandbox without AF_NETLINK (RestrictAddressFamilies) would
			// otherwise leave every egress check silently unmeasured.
			return nil, fmt.Errorf("%w: rtnetlink socket refused (%v); the unit must allow AF_NETLINK",
				errFlowNotDescribable, err)
		}
		return nil, incompleteAnswer("rtnetlink socket: %v", err)
	}
	if err := setRouteSocketStrict(fd); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: NETLINK_GET_STRICT_CHK: %v", errFlowNotDescribable, err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, incompleteAnswer("rtnetlink bind: %v", err)
	}
	for _, g := range groups {
		if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, g); err != nil {
			_ = unix.Close(fd)
			return nil, incompleteAnswer("rtnetlink join group %d: %v", g, err)
		}
	}
	// The kernel addresses every answer to this socket's port id; an answer
	// carrying another is not ours (splitAnswer).
	sa, err := unix.Getsockname(fd)
	nl, ok := sa.(*unix.SockaddrNetlink)
	if err != nil || !ok || nl.Pid == 0 {
		_ = unix.Close(fd)
		return nil, incompleteAnswer("rtnetlink port id: %v %T", err, sa)
	}
	// 64 KiB: larger than any datagram the kernel builds for a dump (it
	// sizes them from the reader's buffer, capped at 32 KiB) or for one route
	// or link. A larger one still arrives as MSG_TRUNC and fails closed.
	return &rtnlSocket{fd: fd, portID: nl.Pid, buf: make([]byte, 64<<10)}, nil
}

// openRouteTransport is openRouteSocket as an nlTransport, for single
// questions (a route, a device).
func openRouteTransport() (nlTransport, error) {
	s, err := openRouteSocket()
	if err != nil {
		return nil, err
	}
	return s, nil
}

// dumpChangeGroups are the groups a dump socket joins: a change to either
// table during the rule-then-route dump invalidates the attempt.
var dumpChangeGroups = []int{unix.RTNLGRP_IPV4_RULE, unix.RTNLGRP_IPV4_ROUTE}

// openDumpTransport is openRouteSocket for the rule and route dumps.
func openDumpTransport() (nlTransport, error) {
	s, err := openRouteSocket(dumpChangeGroups...)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *rtnlSocket) port() uint32 { return s.portID }

func (s *rtnlSocket) close() { _ = unix.Close(s.fd) }

func (s *rtnlSocket) send(req []byte) error {
	return unix.Sendto(s.fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

// recv returns one datagram the kernel sent to this socket before deadline.
// MSG_TRUNC (the datagram did not fit), a sender other than the kernel (port
// id 0, no multicast group), an empty datagram and no datagram by the
// deadline are incomplete answers.
func (s *rtnlSocket) recv(deadline time.Time) ([]byte, error) {
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return nil, incompleteAnswer("no answer within %v", netlinkAnswerBound)
		}
		tv := unix.NsecToTimeval(left.Nanoseconds())
		if tv.Sec == 0 && tv.Usec == 0 {
			tv.Usec = 1
		}
		if err := unix.SetsockoptTimeval(s.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			return nil, incompleteAnswer("rtnetlink receive timeout: %v", err)
		}
		n, _, flags, from, err := unix.Recvmsg(s.fd, s.buf, nil, 0)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			return nil, incompleteAnswer("no answer within %v", netlinkAnswerBound)
		case err != nil:
			return nil, incompleteAnswer("rtnetlink receive: %v", err)
		}
		if flags&unix.MSG_TRUNC != 0 {
			return nil, incompleteAnswer("a datagram longer than %d bytes was truncated (MSG_TRUNC)", len(s.buf))
		}
		nl, ok := from.(*unix.SockaddrNetlink)
		switch {
		case !ok || nl.Pid != 0:
			return nil, incompleteAnswer("a datagram from %+v, not the kernel", from)
		case nl.Groups != 0:
			return nil, incompleteAnswer("the routing state changed while it was being read (a notification for group mask %#x arrived)", nl.Groups)
		}
		if n <= 0 {
			return nil, incompleteAnswer("an empty datagram")
		}
		return s.buf[:n], nil
	}
}

// setRouteSocketStrict is a variable so a test can show that the strictness
// is what turns an unknown attribute into a refusal.
var setRouteSocketStrict = func(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_GET_STRICT_CHK, 1)
}

// measureEgressRouteTo is measureEgressRoute for the given destinations. The
// per-client guard (clientEgressGuard) calls it with one client address and
// port. Each destination is asked on its own socket (measureRouteVia): the
// route, then the device's name and MTU by index. A kernel that cannot be
// asked about the exact flow ends the measurement (errFlowNotDescribable);
// any other failure is that destination's Err.
func measureEgressRouteTo(lookup egressLookup, dsts []netip.AddrPort) ([]egressRoute, error) {
	routes := make([]egressRoute, 0, len(dsts))
	for _, dst := range dsts {
		r, err := measureRouteVia(openRouteTransport, lookup, dst)
		if errors.Is(err, errFlowNotDescribable) {
			return nil, err
		}
		if err != nil {
			r = egressRoute{Dest: dst.Addr(), DestPort: dst.Port(), Err: err}
		}
		routes = append(routes, r)
	}
	return routes, nil
}

// listenerMark reads the listener's SO_MARK, the fwmark its replies carry
// into the route lookup. The gateway sets none today; reading it keeps the
// per-client lookup exact if a future change or an operator's tooling does.
func listenerMark(conn *net.UDPConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var mark int
	var getErr error
	if err := raw.Control(func(fd uintptr) {
		mark, getErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
	}); err != nil {
		return 0, err
	}
	if getErr != nil {
		return 0, getErr
	}
	return uint32(mark), nil
}

// listRoutingSelectors dumps the IPv4 policy rules and routes and returns
// every rule and route the per-client lookup cannot account for
// (egress_route_netlink.go). Both dumps are unprivileged and read-only; the
// socket is the strict one, and an incomplete dump fails closed
// (egress_netlink_answer.go).
func listRoutingSelectors() ([]routingSelector, error) {
	return listSelectorsVia(openDumpTransport)
}
