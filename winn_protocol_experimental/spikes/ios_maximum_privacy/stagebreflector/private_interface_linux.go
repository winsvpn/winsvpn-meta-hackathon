//go:build linux

package stagebreflector

import (
	"encoding/binary"
	"math"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

type linuxPrivateInterfaceController struct{}

type privateSyscallConnection interface {
	SyscallConn() (syscall.RawConn, error)
}

func systemPrivateInterfaceController() privateInterfaceController {
	return linuxPrivateInterfaceController{}
}

func (linuxPrivateInterfaceController) Configure(
	connection privateUDPConnection,
	network string,
	_ netip.Addr,
	_ int,
) error {
	syscallConnection, ok := connection.(privateSyscallConnection)
	if !ok {
		return ErrPrivateInterface
	}
	raw, err := syscallConnection.SyscallConn()
	if err != nil {
		return ErrPrivateInterface
	}
	var controlErr error
	err = raw.Control(func(fileDescriptor uintptr) {
		descriptor, ok := linuxFileDescriptor(fileDescriptor)
		if !ok {
			controlErr = ErrPrivateInterface
			return
		}
		switch network {
		case "udp4":
			controlErr = unix.SetsockoptInt(
				descriptor,
				unix.IPPROTO_IP,
				unix.IP_PKTINFO,
				1,
			)
		case "udp6":
			controlErr = unix.SetsockoptInt(
				descriptor,
				unix.IPPROTO_IPV6,
				unix.IPV6_RECVPKTINFO,
				1,
			)
		default:
			controlErr = ErrPrivateInterface
		}
	})
	if err != nil || controlErr != nil {
		return ErrPrivateInterface
	}
	return nil
}

func linuxFileDescriptor(fileDescriptor uintptr) (int, bool) {
	if fileDescriptor > uintptr(^uint(0)>>1) {
		return 0, false
	}
	return int(fileDescriptor), true
}

func (linuxPrivateInterfaceController) ControlMessageSize(network string) int {
	switch network {
	case "udp4":
		return unix.CmsgSpace(unix.SizeofInet4Pktinfo)
	case "udp6":
		return unix.CmsgSpace(unix.SizeofInet6Pktinfo)
	default:
		return 0
	}
}

func (linuxPrivateInterfaceController) InboundInterfaceIndex(
	network string,
	control []byte,
) (int, error) {
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return 0, ErrPrivateInterface
	}
	found := 0
	interfaceIndex := 0
	for _, message := range messages {
		switch {
		case network == "udp4" &&
			message.Header.Level == unix.IPPROTO_IP &&
			message.Header.Type == unix.IP_PKTINFO &&
			len(message.Data) >= unix.SizeofInet4Pktinfo:
			found++
			encodedIndex := binary.NativeEndian.Uint32(message.Data[:4])
			if encodedIndex > math.MaxInt32 {
				return 0, ErrPrivateInterface
			}
			interfaceIndex = int(encodedIndex)
		case network == "udp6" &&
			message.Header.Level == unix.IPPROTO_IPV6 &&
			message.Header.Type == unix.IPV6_PKTINFO &&
			len(message.Data) >= unix.SizeofInet6Pktinfo:
			found++
			interfaceIndex = int(binary.NativeEndian.Uint32(message.Data[16:20]))
		}
	}
	if found != 1 || interfaceIndex <= 0 {
		return 0, ErrPrivateInterface
	}
	return interfaceIndex, nil
}

func (linuxPrivateInterfaceController) WriteResponse(
	connection privateUDPConnection,
	network string,
	payload []byte,
	destination netip.AddrPort,
	bindAddress netip.Addr,
	interfaceIndex int,
) (int, error) {
	var control []byte
	switch network {
	case "udp4":
		if !bindAddress.Is4() ||
			interfaceIndex <= 0 ||
			uint64(interfaceIndex) > math.MaxInt32 {
			return 0, ErrPrivateInterface
		}
		control = unix.PktInfo4(&unix.Inet4Pktinfo{
			Ifindex:  int32(interfaceIndex),
			Spec_dst: bindAddress.As4(),
		})
	case "udp6":
		if bindAddress.Is4() ||
			interfaceIndex <= 0 ||
			uint64(interfaceIndex) > math.MaxUint32 {
			return 0, ErrPrivateInterface
		}
		control = unix.PktInfo6(&unix.Inet6Pktinfo{
			Addr:    bindAddress.As16(),
			Ifindex: uint32(interfaceIndex),
		})
	default:
		return 0, ErrPrivateInterface
	}
	written, controlWritten, err :=
		connection.WriteMsgUDPAddrPort(payload, control, destination)
	if err != nil || controlWritten != len(control) {
		return written, ErrWrite
	}
	return written, nil
}
