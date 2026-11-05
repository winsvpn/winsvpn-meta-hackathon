//go:build linux

package directawg

import (
	"golang.org/x/sys/unix"

	"winsvpn.local/winnprotocol/internal/sysconv"
)

type linuxRealSocketSetter struct{}

func (linuxRealSocketSetter) Set(
	fd uintptr,
	interfaceName string,
	firewallMark uint32,
) error {
	// Checked rather than asserted: a truncated descriptor number would not
	// fail, it would address a different descriptor.
	descriptor, err := sysconv.Descriptor(fd)
	if err != nil {
		return err
	}
	if err := unix.SetsockoptString(
		descriptor, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, interfaceName,
	); err != nil {
		return err
	}
	// Not a no-op widening. This file carries a plain //go:build linux
	// constraint, so it also compiles for linux/386 and linux/arm where int is
	// 32 bits and a mark above MaxInt32 would become a negative number.
	mark, err := sysconv.SocketOptionInt(firewallMark)
	if err != nil {
		return err
	}
	return unix.SetsockoptInt(
		descriptor, unix.SOL_SOCKET, unix.SO_MARK, mark,
	)
}

func linuxPlatformSocketSetter() linuxSocketSetter {
	return linuxRealSocketSetter{}
}
