package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const (
	// udpSocketBufferBytes is the SO_RCVBUF/SO_SNDBUF this process asks for.
	// 16 MiB scales absorption capacity for multi-gigabit wire speed: large
	// enough that a one-millisecond readLoop stall at line rate does not
	// overflow the socket, small enough that an unprivileged setsockopt is
	// honoured on a host whose rmem_max is the data-plane/gateway-installer
	// value (128 MiB) and on Darwin where kern.ipc.maxsockbuf is 8 MiB.
	udpSocketBufferBytes = 16 << 20

	// udpSocketBufferMinBytes is the floor on the kernel-granted size. Linux
	// silently clamps SO_RCVBUF to net.core.rmem_max and returns success, so
	// a gateway-only node that never ran the data-plane installer would sit
	// at rmem_default (~256 KiB, ~187 full-size datagrams) and drop under a
	// stall with no error. Refusing here is the loud half of that defect;
	// wins_winn3_gateway_install.sh raising rmem_max is the other half.
	udpSocketBufferMinBytes = 8 << 20
)

// configureUDPSocketBuffers raises the UDP listener's kernel send/receive
// buffers and reads the granted sizes back. SetReadBuffer returning nil is
// not evidence the kernel granted the request: Linux clamps to rmem_max
// and still returns 0.
func configureUDPSocketBuffers(conn *net.UDPConn) (gotRead, gotWrite int, err error) {
	if conn == nil {
		return 0, 0, fmt.Errorf("UDP socket buffers: no socket")
	}
	setReadErr := conn.SetReadBuffer(udpSocketBufferBytes)
	setWriteErr := conn.SetWriteBuffer(udpSocketBufferBytes)
	gotRead, readErr := udpSockoptInt(conn, syscall.SO_RCVBUF)
	if readErr != nil {
		return gotRead, gotWrite, fmt.Errorf("read back SO_RCVBUF: %w", readErr)
	}
	gotWrite, writeErr := udpSockoptInt(conn, syscall.SO_SNDBUF)
	if writeErr != nil {
		return gotRead, gotWrite, fmt.Errorf("read back SO_SNDBUF: %w", writeErr)
	}
	if setReadErr != nil {
		return gotRead, gotWrite, fmt.Errorf(
			"SetReadBuffer(%d): %w (granted read=%d write=%d)",
			udpSocketBufferBytes, setReadErr, gotRead, gotWrite)
	}
	if setWriteErr != nil {
		return gotRead, gotWrite, fmt.Errorf(
			"SetWriteBuffer(%d): %w (granted read=%d write=%d)",
			udpSocketBufferBytes, setWriteErr, gotRead, gotWrite)
	}
	if err := udpBuffersTooSmall(gotRead, gotWrite); err != nil {
		return gotRead, gotWrite, err
	}
	return gotRead, gotWrite, nil
}

func udpBuffersTooSmall(gotRead, gotWrite int) error {
	if gotRead >= udpSocketBufferMinBytes && gotWrite >= udpSocketBufferMinBytes {
		return nil
	}
	return fmt.Errorf(
		"UDP socket buffers are read=%d write=%d bytes; want at least %d (requested %d). "+
			"The kernel silently clamps SO_RCVBUF/SO_SNDBUF to net.core.rmem_max/wmem_max, "+
			"so a grant this small is rmem_default, not a working 8MiB socket. "+
			"wins_winn3_gateway_install.sh must raise those sysctls; a gateway-only node "+
			"that never ran the data-plane installer will overflow in a 1ms readLoop stall "+
			"and increment UdpRcvbufErrors with no other error",
		gotRead, gotWrite, udpSocketBufferMinBytes, udpSocketBufferBytes)
}

// parseUdpRcvbufErrors reads the Udp: RcvbufErrors column from /proc/net/snmp
// text. It ignores UdpLite. ok is false when the column is absent or unparsable.
func parseUdpRcvbufErrors(snmp string) (uint64, bool) {
	var header []string
	for _, line := range strings.Split(snmp, "\n") {
		if !strings.HasPrefix(line, "Udp: ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Udp: "))
		if len(fields) == 0 {
			continue
		}
		if _, err := strconv.ParseUint(fields[0], 10, 64); err != nil {
			header = fields
			continue
		}
		if header == nil {
			return 0, false
		}
		for i, col := range header {
			if col != "RcvbufErrors" {
				continue
			}
			if i >= len(fields) {
				return 0, false
			}
			n, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				return 0, false
			}
			return n, true
		}
		return 0, false
	}
	return 0, false
}

func hostUdpRcvbufErrors() *uint64 {
	body, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return nil
	}
	n, ok := parseUdpRcvbufErrors(string(body))
	if !ok {
		return nil
	}
	return &n
}
