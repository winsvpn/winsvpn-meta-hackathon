//go:build linux

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"winsvpn.local/winnprotocol/winn3/tun"
)

// The Linux tun descriptor backend.
//
// The host opens /dev/net/tun, configures the interface in the BOOTSTRAP
// posture, and passes the descriptor here over the control socket's ancillary
// data — the same SCM_RIGHTS hand-off this binary already implements for
// Android's protected UDP socket, reused rather than reinvented.
//
// This is strictly better than the loopback seam and is why Linux is the
// cheaper of the two desktop hosts: no inner packet crosses a socket in
// cleartext at all, there is no seam port for a local process to write to, and
// the interface MTU is READ BACK from the kernel rather than asserted by the
// host that was supposed to set it.
//
// # Two obligations on the host
//
//  1. The descriptor must have been opened with IFF_NO_PI. Without it every
//     read carries a 4-byte packet-information header and what arrives at the
//     tun layer does not start at an IP version nibble, so every packet fails
//     validation and the tunnel looks alive and carries nothing.
//  2. The interface must already be up, addressed with a /32, and set to
//     exactly the inner MTU this engine publishes. The MTU is verified below;
//     the rest is the host's and cannot be checked from here without becoming
//     a second configuration authority.

// winn3TunFDDevice is a tun.Device backed by an inherited /dev/net/tun
// descriptor.
type winn3TunFDDevice struct {
	file *os.File
	name string
	mtu  int
}

// newWinn3TunFDDevice adopts descriptor and reads back the interface MTU.
//
// Ownership of the descriptor passes to this call on every outcome. A caller
// has one rule to remember rather than two, which is the same rule
// StartLinuxWinnEngine already states for the seam descriptor.
func newWinn3TunFDDevice(descriptor int, name string) (*winn3TunFDDevice, error) {
	if descriptor < 0 {
		return nil, fmt.Errorf(
			"device.kind %s needs -winn3-tun-fd N: tun descriptor %d is not usable",
			winn3DeviceTunFD, descriptor)
	}
	file := os.NewFile(uintptr(descriptor), "/dev/net/tun")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("descriptor %d is not a usable file", descriptor)
	}
	mtu, err := winn3InterfaceMTU(name)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &winn3TunFDDevice{file: file, name: name, mtu: mtu}, nil
}

// winn3InterfaceMTU reads SIOCGIFMTU for name.
//
// The socket it opens is a datagram socket that is never connected and never
// written to; it exists because an ioctl needs a descriptor and this one asks
// the kernel a question about an interface rather than about the socket. It
// cannot escape the tunnel because it never sends anything.
func winn3InterfaceMTU(name string) (int, error) {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("open ioctl socket: %w", err)
	}
	defer func() { _ = unix.Close(sock) }()
	request, err := unix.NewIfreq(name)
	if err != nil {
		return 0, fmt.Errorf("interface name %q: %w", name, err)
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCGIFMTU, request); err != nil {
		return 0, fmt.Errorf("read MTU of %q: %w", name, err)
	}
	return int(request.Uint32()), nil
}

// ReadPacket blocks until the kernel hands over one inner IP packet.
func (d *winn3TunFDDevice) ReadPacket(buf []byte) (int, error) {
	return d.file.Read(buf)
}

// WritePacket delivers one inner IP packet to the host stack.
func (d *winn3TunFDDevice) WritePacket(pkt []byte) (int, error) {
	n, err := d.file.Write(pkt)
	if err != nil {
		return n, fmt.Errorf("%w: %s", tun.ErrDeviceWrite, err)
	}
	return n, nil
}

// MTU reports what the kernel says, not what anybody claimed.
func (d *winn3TunFDDevice) MTU() int { return d.mtu }

// Close releases the descriptor.
func (d *winn3TunFDDevice) Close() error { return d.file.Close() }

var _ tun.Device = (*winn3TunFDDevice)(nil)
