// Package wirefmt holds the pure wire-format helpers of the devicecheck engine
// instrument (the DNS query assembler, the IPv4/UDP encoder, the internet
// checksum, and the host:port splitter).
//
// WHY THIS IS A SEPARATE PACKAGE. The instrument's main.go is gated
// //go:build linux because its job is to inspect an SCM_RIGHTS descriptor that
// only exists on the Android/linux kernel: abstract AF_UNIX sockets, SO_MARK,
// SO_COOKIE, /proc, SYS_GETSOCKOPT. Those cannot compile or run on macOS or
// Windows, so the module previously reported "no packages" to `go test` there
// (exit 1). These four helpers, however, are pure bytes-in/bytes-out and are
// exactly the load-bearing protocol logic the instrument's DNS probes and its
// tun relay depend on. They are extracted here verbatim so that `go test ./...`
// can compile and exercise them on any host, while the syscall-touching halves
// of the engine stay behind their build gate. Moving them changes no code bytes:
// the functions below are the same bodies that used to live in main.go.
package wirefmt

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)

// SplitHostPort is a thin host:port splitter used by the instrument's egress
// probe, its bare-socket probe and its relay to locate the upstream DNS server.
func SplitHostPort(value string) (string, int, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// DNSQuery assembles a one-question A/IN DNS query. The instrument builds its
// egress and bare-socket probes and its relayed questions with this, and its
// probes check the returned transaction id byte-for-byte, so a mis-encoded
// label would read as "no reply".
func DNSQuery(id uint16, name string) []byte {
	var out []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(header[4:6], 1)      // one question
	out = append(out, header...)
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	question := make([]byte, 4)
	binary.BigEndian.PutUint16(question[0:2], 1) // A
	binary.BigEndian.PutUint16(question[2:4], 1) // IN
	return append(out, question...)
}

// Checksum is the internet one's-complement checksum (RFC 1071) over an exact
// or odd-length block. The engine's relay depends on it twice per re-written
// packet: once for the IPv4 header and once, over the pseudo-header plus UDP
// header, for the UDP checksum.
func Checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// BuildUDPv4 rewrites a relayed DNS answer back into an IPv4/UDP packet whose
// source address is the tun's view of the client. Both checksums are computed
// here; a wrong value here is a corrupt packet on the far side of the tun.
func BuildUDPv4(srcIP, dstIP []byte, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	total := 20 + udpLen
	packet := make([]byte, total)

	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(total))
	binary.BigEndian.PutUint16(packet[4:6], 0x1234)
	packet[8] = 64 // TTL
	packet[9] = 17 // UDP
	copy(packet[12:16], srcIP)
	copy(packet[16:20], dstIP)
	binary.BigEndian.PutUint16(packet[10:12], Checksum(packet[0:20]))

	udp := packet[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)

	pseudo := make([]byte, 12+udpLen)
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(udpLen))
	copy(pseudo[12:], udp[:udpLen])
	binary.BigEndian.PutUint16(udp[6:8], Checksum(pseudo))
	return packet
}
