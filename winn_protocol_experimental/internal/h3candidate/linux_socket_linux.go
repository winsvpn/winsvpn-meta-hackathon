//go:build linux

package h3candidate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"

	"winsvpn.local/winnprotocol/internal/sysconv"
)

type linuxRealProtectedPacketOpener struct{}

func (linuxRealProtectedPacketOpener) Open(
	ctx context.Context,
	network string,
	interfaceName string,
	firewallMark uint32,
) (net.PacketConn, error) {
	if ctx == nil {
		return nil, errors.New("linux packet listen context is required")
	}
	local := "0.0.0.0:0"
	if network == "udp6" {
		local = "[::]:0"
	} else if network != "udp4" {
		return nil, errors.New("linux H3 packet network is invalid")
	}
	var controlError error
	listener := net.ListenConfig{
		Control: func(_, _ string, raw syscall.RawConn) error {
			if err := raw.Control(func(fd uintptr) {
				controlError = setAndVerifyLinuxSocket(
					fd, interfaceName, firewallMark,
				)
			}); err != nil {
				return err
			}
			return controlError
		},
	}
	socket, err := listener.ListenPacket(ctx, network, local)
	if err != nil {
		return nil, fmt.Errorf("listen on protected Linux H3 socket: %w", err)
	}
	return socket, nil
}

func (linuxRealProtectedPacketOpener) Protect(
	socket net.PacketConn,
	interfaceName string,
	firewallMark uint32,
) error {
	syscallConnection, ok := socket.(syscall.Conn)
	if !ok {
		return errors.New(
			"linux H3 migration socket does not expose syscall control",
		)
	}
	raw, err := syscallConnection.SyscallConn()
	if err != nil {
		return err
	}
	var protectionError error
	if err := raw.Control(func(fd uintptr) {
		protectionError = setAndVerifyLinuxSocket(
			fd, interfaceName, firewallMark,
		)
	}); err != nil {
		return err
	}
	return protectionError
}

func setAndVerifyLinuxSocket(
	fd uintptr,
	interfaceName string,
	firewallMark uint32,
) error {
	if err := validateLinuxInterfaceAndMark(
		interfaceName, firewallMark,
	); err != nil {
		return err
	}
	descriptor, err := sysconv.Descriptor(fd)
	if err != nil {
		return err
	}
	if err := unix.SetsockoptString(
		descriptor,
		unix.SOL_SOCKET,
		unix.SO_BINDTODEVICE,
		interfaceName,
	); err != nil {
		return fmt.Errorf("bind Linux H3 socket to underlay: %w", err)
	}
	// Not a no-op widening: on linux/386 and linux/arm int is 32 bits, so a
	// mark above MaxInt32 would be applied as a negative number.
	mark, err := sysconv.SocketOptionInt(firewallMark)
	if err != nil {
		return err
	}
	if err := unix.SetsockoptInt(
		descriptor,
		unix.SOL_SOCKET,
		unix.SO_MARK,
		mark,
	); err != nil {
		return fmt.Errorf("mark Linux H3 socket: %w", err)
	}
	actualInterface, err := unix.GetsockoptString(
		descriptor, unix.SOL_SOCKET, unix.SO_BINDTODEVICE,
	)
	if err != nil {
		return fmt.Errorf("verify Linux H3 socket underlay: %w", err)
	}
	actualMark, err := unix.GetsockoptInt(
		descriptor, unix.SOL_SOCKET, unix.SO_MARK,
	)
	if err != nil {
		return fmt.Errorf("verify Linux H3 socket mark: %w", err)
	}
	// The mark read back from the socket is an int; narrowing it with a bare
	// conversion would make a negative or oversized value compare equal to
	// some legitimate mark, so the comparison would silently succeed on a
	// socket that is not protected the way it was asked to be.
	observedMark, err := sysconv.FirewallMark(actualMark)
	if err != nil {
		return fmt.Errorf("verify Linux H3 socket mark: %w", err)
	}
	if actualInterface != interfaceName || observedMark != firewallMark {
		return errors.New(
			"linux H3 socket protection differs from requested underlay and mark",
		)
	}
	return nil
}
