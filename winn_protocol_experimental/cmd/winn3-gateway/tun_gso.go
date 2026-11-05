package main

import "encoding/binary"

// TUN segment coalescing (-tun-gso), the portable half.
//
// TUNSPEED-2 measured the uplink ceiling as the per-session consumer's TUN
// write: a loopback consumer with a free write ran at 528,045 to 544,836
// messages/s, Canada's ran at 34,413 (G-C) to 70,387 (G-G with async write and
// RPS), so 85 to 95% of each message is one write(2) and the kernel forward
// path it runs. A TUN opened with IFF_VNET_HDR accepts a TCP "super packet"
// with a virtio_net_hdr that asks the kernel to segment it (gso_type TCPV4):
// one write, one netfilter and routing pass, and the segmentation happens at
// the egress device (software GSO, or the NIC's TSO). The write count falls by
// the run length.
//
// What may be merged is exactly what Linux GRO would merge, so segmentation
// gives back the original packets byte for byte:
//   - IPv4 with IHL 5, not a fragment, TCP, the same addresses, ports, TOS, TTL,
//     DF bit and IP IDs that increase by one per packet (TCPV4 segmentation
//     increments the ID from the first segment);
//   - the same TCP data offset and identical option bytes (timestamps
//     included), the same ACK number and window, sequence numbers contiguous;
//   - flags exactly ACK on every member except the last, which may be
//     ACK|PSH (segmentation clears PSH on all but the last segment);
//   - a nonzero payload, equal (the MSS) on every member except a shorter or
//     equal last one, and an IP total length of at most 65,535.
// Anything else is written alone, so the loss and order profile of a session
// that does not coalesce is unchanged.
//
// The checksum: the virtio header asks the kernel to complete it
// (VIRTIO_NET_HDR_F_NEEDS_CSUM, csum_start at the TCP header, csum_offset 16)
// and the TCP checksum field carries the folded, uncomplemented pseudo-header
// sum of the merged segment, as CHECKSUM_PARTIAL requires. The IPv4 header
// checksum is recomputed for the merged total length.

const (
	vnetHdrLen         = 10 // sizeof(struct virtio_net_hdr), no mergeable buffers
	vnetHdrFNeedsCsum  = 1  // VIRTIO_NET_HDR_F_NEEDS_CSUM
	vnetHdrFDataValid  = 2  // VIRTIO_NET_HDR_F_DATA_VALID
	vnetHdrGSONone     = 0  // VIRTIO_NET_HDR_GSO_NONE
	vnetHdrGSOTCPv4    = 1  // VIRTIO_NET_HDR_GSO_TCPV4
	gsoMaxMembers      = 64
	gsoMaxIPTotal      = 65535
	tcpFlagACK         = 0x10
	tcpFlagPSH         = 0x08
	ipv4FlagDF         = 0x4000
	ipv4FragOffsetMask = 0x1fff
	ipv4FlagMF         = 0x2000
)

// zeroVnetHdr prefixes every packet written without segmentation once the
// descriptor carries IFF_VNET_HDR.
var zeroVnetHdr [vnetHdrLen]byte

// tcpv4Shape is the parsed shape of one candidate member.
type tcpv4Shape struct {
	ok      bool
	thl     int // TCP header length
	payload int
	seq     uint32
	id      uint16
	flags   byte
}

func parseTCPv4(p []byte) tcpv4Shape {
	if len(p) < 40 || p[0] != 0x45 || p[9] != 6 {
		return tcpv4Shape{}
	}
	tot := int(binary.BigEndian.Uint16(p[2:4]))
	if tot != len(p) {
		return tcpv4Shape{}
	}
	frag := binary.BigEndian.Uint16(p[6:8])
	if frag&(ipv4FlagMF|ipv4FragOffsetMask) != 0 {
		return tcpv4Shape{}
	}
	thl := int(p[32]>>4) * 4
	if thl < 20 || 20+thl > len(p) {
		return tcpv4Shape{}
	}
	return tcpv4Shape{
		ok:      true,
		thl:     thl,
		payload: len(p) - 20 - thl,
		seq:     binary.BigEndian.Uint32(p[24:28]),
		id:      binary.BigEndian.Uint16(p[4:6]),
		flags:   p[33],
	}
}

// sameFlowHeaders compares everything GRO requires to be identical between
// two members: TOS, flags-and-offset word, TTL, addresses, ports, ACK number,
// data offset, window, urgent pointer and the option bytes.
func sameFlowHeaders(a, b []byte, thl int) bool {
	if a[1] != b[1] || a[8] != b[8] || a[6] != b[6] || a[7] != b[7] {
		return false
	}
	if string(a[12:20]) != string(b[12:20]) || string(a[20:24]) != string(b[20:24]) {
		return false
	}
	if string(a[28:32]) != string(b[28:32]) || a[32] != b[32] || string(a[34:36]) != string(b[34:36]) {
		return false
	}
	if string(a[38:40]) != string(b[38:40]) {
		return false
	}
	return string(a[40:20+thl]) == string(b[40:20+thl])
}

// gsoRun reports how many leading packets of pkts form one coalescible run
// (at least 1). A run of 1 means "write pkts[0] alone".
func gsoRun(pkts [][]byte) int {
	if len(pkts) < 2 {
		return 1
	}
	first := parseTCPv4(pkts[0])
	if !first.ok || first.payload == 0 || first.flags != tcpFlagACK {
		return 1
	}
	mss := first.payload
	total := len(pkts[0])
	nextSeq := first.seq + uint32(first.payload)
	nextID := first.id + 1
	n := 1
	for n < len(pkts) && n < gsoMaxMembers {
		p := pkts[n]
		s := parseTCPv4(p)
		if !s.ok || s.thl != first.thl || s.payload == 0 || s.payload > mss {
			break
		}
		if s.flags != tcpFlagACK && s.flags != tcpFlagACK|tcpFlagPSH {
			break
		}
		if s.seq != nextSeq || s.id != nextID || !sameFlowHeaders(pkts[0], p, first.thl) {
			break
		}
		if total+s.payload > gsoMaxIPTotal {
			break
		}
		total += s.payload
		n++
		nextSeq += uint32(s.payload)
		nextID++
		if s.payload < mss || s.flags != tcpFlagACK {
			// A short or PSH member ends the run: only the last segment may
			// be short or carry PSH.
			break
		}
	}
	return n
}

// buildGSO writes the virtio header and the merged TCPv4 super packet for
// pkts[:n] (a run from gsoRun with n >= 2) into out, which must hold
// vnetHdrLen plus the merged length, and returns the frame.
func buildGSO(pkts [][]byte, out []byte) []byte {
	first := pkts[0]
	s := parseTCPv4(first)
	hdrLen := 20 + s.thl
	total := hdrLen
	for _, p := range pkts {
		total += len(p) - hdrLen
	}
	frame := out[:vnetHdrLen+total]
	// virtio_net_hdr fields in the HOST's byte order: without TUNSETVNETLE
	// or TUNSETVNETBE the kernel reads the __virtio16 fields natively
	// (tun_get_user), and the aarch64 harness saw csum_start 20 come back
	// as the bytes 14 00. NativeEndian is that order on every target, not
	// only the little-endian two this gateway ships for today.
	frame[0] = vnetHdrFNeedsCsum
	frame[1] = vnetHdrGSOTCPv4
	binary.NativeEndian.PutUint16(frame[2:4], uint16(hdrLen))    // hdr_len
	binary.NativeEndian.PutUint16(frame[4:6], uint16(s.payload)) // gso_size (the MSS)
	binary.NativeEndian.PutUint16(frame[6:8], 20)                // csum_start
	binary.NativeEndian.PutUint16(frame[8:10], 16)               // csum_offset
	pkt := frame[vnetHdrLen:]
	copy(pkt, first[:hdrLen])
	at := hdrLen
	for _, p := range pkts {
		at += copy(pkt[at:], p[hdrLen:])
	}
	last := pkts[len(pkts)-1]
	pkt[33] = last[33] // the last member's flags (ACK or ACK|PSH)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[10], pkt[11] = 0, 0
	binary.BigEndian.PutUint16(pkt[10:12], ^foldChecksum(onesSum(pkt[:20], 0)))
	tcpLen := total - 20
	pseudo := onesSum(pkt[12:20], 0) + 6 + uint32(tcpLen)
	binary.BigEndian.PutUint16(pkt[36:38], foldChecksum(pseudo))
	return frame
}

// onesSum adds b as big-endian 16-bit words to sum without folding.
func onesSum(b []byte, sum uint32) uint32 {
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

// foldChecksum folds a 32-bit ones-complement sum to 16 bits.
func foldChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}
