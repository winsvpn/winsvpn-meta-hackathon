//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"winsvpn.local/winnprotocol/winn3/tun"
)

// The Linux tun plumbing for the lab rig.
//
// IFF_NO_PI is not optional and is the single most common way to make a v3
// tunnel look alive while carrying nothing: without it every read from the
// device carries a 4-byte packet-information header, so what reaches the tun
// layer does not start at an IP version nibble, every packet fails the inner-IP
// validator, RxPackets stays 0 and the promotion gate never opens. The symptom
// is a session that handshakes, rekeys, moves bytes on the wire, and delivers
// nothing — which reads as a protocol bug and is a flag.

// openConfiguredTun creates the interface, addresses it as a /32 and brings it
// up at exactly the inner MTU.
//
// A /32 and never a prefix, because winn3/tun assigns ADDRESSES: a prefix would
// tell the kernel this endpoint is on a shared link and let it originate
// packets from addresses the gateway never assigned, which is the
// deanonymisation the address rule exists to prevent.
//
// addr6 is the inner IPv6 address the profile assigns, or "" when it assigns
// none. See configureInterface for why that distinction has to reach this far
// down.
func openConfiguredTun(
	name, addr, addr6 string, mtu int, routes []string,
) (tun.Device, func() error, error) {
	if strings.TrimSpace(addr) == "" {
		return nil, nil, errors.New("tun address is empty")
	}
	file, err := openTunDevice(name)
	if err != nil {
		return nil, nil, err
	}
	if err := configureInterface(name, addr, addr6, mtu, routes); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	device := &labTun{file: file, mtu: mtu}
	return device, device.Close, nil
}

// openTunDevice opens /dev/net/tun and binds it to name.
func openTunDevice(name string) (*os.File, error) {
	if name == "" {
		return nil, errors.New("tun interface name is empty")
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun (needs CAP_NET_ADMIN): %w", err)
	}
	request, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("interface name %q: %w", name, err)
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF %q: %w", name, err)
	}
	return os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}

// configureInterface applies the bootstrap posture to name.
//
// It shells out to ip(8) rather than opening a netlink socket. A lab rig is
// allowed that; the shipping hosts are not, which is why linux_tunnel_backend.cc
// does its own and this file is not a template for it.
//
// routes are added AFTER the link is up, each as a host route out of this
// device. They are the narrow bootstrap posture written out explicitly: a /32
// per inner peer, never a default route, so nothing but the addresses named
// here can leave through the tunnel.
//
// # THE IPv6 STEP, AND WHY IT SITS EXACTLY WHERE IT SITS
//
// When the profile assigns NO inner IPv6 address, IPv6 is disabled on the
// interface BETWEEN addressing it and bringing it up. Measured on the
// 2026-08-12 two-host run (registered as
// .winn_platform_progress/evidence/winn3_linux_20260812T203038Z_two_host_
// standalone_v3_rehearsal_not_carriage.txt): the kernel starts IPv6 housekeeping
// the moment the link comes up and emits router solicitations from a link-local
// address on a tun that has no v6 assignment. winn3/tun's validator.outbound
// refuses each one — familyAllowed runs FIRST, so the reason is ErrFamilyOff,
// not ErrSourceNotOurs — and Tunnel.Outbound counts it tx_dropped_invalid. Seven
// such frames per host cost that run the "all rejection counters zero" clause
// while every payload byte moved intact.
//
//   - It is CONDITIONAL. An unconditional disable would silently destroy inner
//     IPv6 on the day the profile starts assigning it, and the symptom would be
//     a tunnel that looks healthy and carries no v6 at all.
//   - It lives HERE and not in a shell script. One of the seven frames per host
//     landed in the sub-second window between `link set up` and the gate opening
//     — it was counted tx_dropped_closed, before a single payload byte moved. No
//     script can win that race; only the code that owns the `up` can.
//   - It is scoped to THIS interface. net.ipv6.conf.default.disable_ipv6 would
//     catch every interface created afterwards, including container interfaces
//     that have nothing to do with this rig.
func configureInterface(name, addr, addr6 string, mtu int, routes []string) error {
	if addr == "" {
		return errors.New("tun address is empty")
	}
	steps := [][]string{
		{"ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu)},
		{"ip", "addr", "add", addr + "/32", "dev", name},
	}
	if inner6 := strings.TrimSpace(addr6); inner6 == "" {
		steps = append(steps,
			[]string{"sysctl", "-w", "net.ipv6.conf." + name + ".disable_ipv6=1"})
	} else {
		// A /128 for the same reason the v4 address is a /32: winn3/tun assigns
		// ADDRESSES, not prefixes.
		steps = append(steps,
			[]string{"ip", "-6", "addr", "add", inner6 + "/128", "dev", name})
	}
	steps = append(steps, []string{"ip", "link", "set", "dev", name, "up"})
	for _, route := range routes {
		if route = strings.TrimSpace(route); route != "" {
			steps = append(steps,
				[]string{"ip", "route", "add", route, "dev", name})
		}
	}
	for _, step := range steps {
		cmd := exec.Command(step[0], step[1:]...) //nolint:gosec // fixed argv
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %w: %s", step, err, output)
		}
	}
	return nil
}

// labTun is a tun.Device over the kernel device.
type labTun struct {
	file *os.File
	mtu  int
}

func (t *labTun) ReadPacket(buf []byte) (int, error) { return t.file.Read(buf) }

func (t *labTun) WritePacket(pkt []byte) (int, error) {
	n, err := t.file.Write(pkt)
	if err != nil {
		return n, fmt.Errorf("%w: %s", tun.ErrDeviceWrite, err)
	}
	return n, nil
}

func (t *labTun) MTU() int     { return t.mtu }
func (t *labTun) Close() error { return t.file.Close() }

var _ tun.Device = (*labTun)(nil)

// peekPeer reads the source of the next datagram without consuming it.
func peekPeer(conn *net.UDPConn) (*net.UDPAddr, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var peer *net.UDPAddr
	var opErr error
	// Read blocks until the descriptor is readable and calls the closure; false
	// asks it to wait again, which is how a spurious wakeup is handled without a
	// busy loop.
	err = raw.Read(func(fd uintptr) bool {
		buf := make([]byte, 1)
		_, from, recvErr := unix.Recvfrom(int(fd), buf, unix.MSG_PEEK)
		if recvErr == unix.EAGAIN || recvErr == unix.EWOULDBLOCK {
			return false
		}
		if recvErr != nil {
			opErr = recvErr
			return true
		}
		switch sa := from.(type) {
		case *unix.SockaddrInet4:
			peer = &net.UDPAddr{IP: net.IP(sa.Addr[:]), Port: sa.Port}
		case *unix.SockaddrInet6:
			peer = &net.UDPAddr{IP: net.IP(sa.Addr[:]), Port: sa.Port}
		default:
			opErr = fmt.Errorf("first datagram came from a %T, not an IP address", from)
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	if opErr != nil {
		return nil, opErr
	}
	if peer == nil {
		return nil, errors.New("no peer address was learned")
	}
	return peer, nil
}

// runTunFDExec creates and configures a tun device, then execs a child with the
// descriptor inherited.
//
// This is how the SHIPPING client is driven: cmd/winn-datapath's -winn3-tun-fd
// takes a descriptor number and expects the host to have opened, configured and
// inherited it. On the product that host is linux_tunnel_backend.cc; here it is
// this mode, so that the binary under test is the shipping one rather than a
// re-implementation of it.
func runTunFDExec(
	name, addr, addr6 string, mtu, childFD int, routes []string, argv []string,
) error {
	if err := tunfdExecFlagError(name, addr, mtu, childFD, argv); err != nil {
		return err
	}
	file, err := openTunDevice(name)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if err := configureInterface(name, addr, addr6, mtu, routes); err != nil {
		return err
	}

	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // operator-named
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	// ExtraFiles[0] is descriptor 3 in the child. Anything else would have to be
	// arranged with dup2 in a fork the Go runtime does not offer.
	cmd.ExtraFiles = []*os.File{file}
	fmt.Fprintf(os.Stderr,
		"winn3-labrig: %s is up at mtu %d, running %v with the descriptor at fd 3\n",
		name, mtu, argv)
	return cmd.Run()
}
