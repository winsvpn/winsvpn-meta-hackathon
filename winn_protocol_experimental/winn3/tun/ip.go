package tun

import (
	"encoding/binary"
	"net/netip"
)

// packet is one structurally validated inner IP packet.
//
// body is the packet truncated to the length its own header declares, never
// the length the device happened to hand us. That distinction is the whole
// reason this field exists: the pump reuses one buffer, so bytes past the
// declared length are the tail of the PREVIOUS packet. Forwarding them would
// push one flow's bytes into another flow's packet, inside the tunnel, where
// nothing downstream would ever notice.
type packet struct {
	v6       bool
	src      netip.Addr
	dst      netip.Addr
	body     []byte
	hdrLen   int
	proto    uint8
	ttl      uint8
	df       bool
	fragment bool
	// tail is how many bytes the device handed us beyond the declared length.
	tail int
}

// parsePacket does the structural half: everything that can be decided from
// the bytes alone, before any question of whose addresses these are.
//
// It is strict in the same way core.ParseFrames is strict, and for the same
// reason: a lenient parser is a parsing differential, and a parsing
// differential between the client and the gateway is a way to make one of them
// see a packet the other does not.
func parsePacket(b []byte) (packet, error) {
	if len(b) < 1 {
		return packet{}, ErrShortPacket
	}
	switch b[0] >> 4 {
	case 4:
		return parseIPv4(b)
	case 6:
		return parseIPv6(b)
	default:
		return packet{}, errWrap(ErrBadVersion, "version nibble is %d", b[0]>>4)
	}
}

func parseIPv4(b []byte) (packet, error) {
	if len(b) < IPv4HeaderMin {
		return packet{}, errWrap(ErrShortPacket, "%d bytes is below the %d-byte IPv4 header", len(b), IPv4HeaderMin)
	}
	hdrLen := int(b[0]&0x0f) * 4
	if hdrLen < IPv4HeaderMin {
		return packet{}, errWrap(ErrBadHeader, "IHL declares a %d-byte header", hdrLen)
	}
	if hdrLen > len(b) {
		return packet{}, errWrap(ErrBadHeader, "IHL declares %d bytes but only %d are present", hdrLen, len(b))
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < hdrLen {
		return packet{}, errWrap(ErrBadHeader, "total length %d is below the %d-byte header", total, hdrLen)
	}
	if total > len(b) {
		return packet{}, errWrap(ErrBadHeader, "total length %d exceeds the %d bytes present", total, len(b))
	}
	if checksum(b[:hdrLen]) != 0 {
		return packet{}, ErrBadChecksum
	}
	// Bit 15 of the flags/fragment word is reserved and must be zero. It is
	// free to check and it is one of the few places a deliberately malformed
	// packet announces itself.
	if b[6]&0x80 != 0 {
		return packet{}, errWrap(ErrBadHeader, "reserved flag bit is set")
	}
	if b[8] == 0 {
		return packet{}, errWrap(ErrBadHeader, "TTL is zero")
	}
	fragOff := binary.BigEndian.Uint16(b[6:8]) & 0x1fff
	moreFrags := b[6]&0x20 != 0
	return packet{
		v6:       false,
		src:      netip.AddrFrom4([4]byte(b[12:16])),
		dst:      netip.AddrFrom4([4]byte(b[16:20])),
		body:     b[:total],
		hdrLen:   hdrLen,
		proto:    b[9],
		ttl:      b[8],
		df:       b[6]&0x40 != 0,
		fragment: fragOff != 0 || moreFrags,
		tail:     len(b) - total,
	}, nil
}

func parseIPv6(b []byte) (packet, error) {
	if len(b) < IPv6HeaderLen {
		return packet{}, errWrap(ErrShortPacket, "%d bytes is below the %d-byte IPv6 header", len(b), IPv6HeaderLen)
	}
	payload := int(binary.BigEndian.Uint16(b[4:6]))
	if payload == 0 {
		// Either a jumbogram, whose real length lives in a hop-by-hop option
		// this tunnel does not carry, or a header with nothing behind it.
		// Neither is something to forward.
		return packet{}, errWrap(ErrBadHeader, "IPv6 payload length is zero")
	}
	total := IPv6HeaderLen + payload
	if total > len(b) {
		return packet{}, errWrap(ErrBadHeader, "payload length %d exceeds the %d bytes present", payload, len(b)-IPv6HeaderLen)
	}
	if b[7] == 0 {
		return packet{}, errWrap(ErrBadHeader, "hop limit is zero")
	}
	return packet{
		v6:  true,
		src: netip.AddrFrom16([16]byte(b[8:24])),
		dst: netip.AddrFrom16([16]byte(b[24:40])),
		// IPv6 has no in-network fragmentation, so every IPv6 packet is
		// implicitly don't-fragment and an oversize one always earns a Packet
		// Too Big rather than a silent drop.
		body:   b[:total],
		hdrLen: IPv6HeaderLen,
		proto:  b[6],
		ttl:    b[7],
		df:     true,
		tail:   len(b) - total,
	}, nil
}

// martianReason names why an address must never cross this tunnel, or returns
// "" if it may.
//
// Multicast is in the list and that is a deliberate policy choice, not an
// oversight. The traffic it excludes is mDNS, LLMNR and NetBIOS name
// advertisement, and those packets carry the device's hostname. A tunnel that
// forwards them has published "MyaNyein's MacBook Pro" to the gateway and to
// anything on the far side of it — a privacy leak that the encryption around
// it does absolutely nothing about.
func martianReason(a netip.Addr) string {
	switch {
	case !a.IsValid():
		return "not a valid address"
	case a.Is4In6():
		return "IPv4-mapped IPv6, which bypasses the IPv4 rules"
	case a.IsUnspecified():
		return "unspecified"
	case a.IsLoopback():
		return "loopback"
	case a.IsMulticast():
		return "multicast"
	case a.IsLinkLocalUnicast():
		return "link-local unicast"
	}
	if a.Is4() {
		b := a.As4()
		switch {
		case b[0] == 0:
			return "reserved leading zero block"
		case b[0] >= 240:
			return "reserved high block or limited broadcast"
		}
		return ""
	}
	b := a.As16()
	var zero bool = true
	for _, x := range b[:12] {
		if x != 0 {
			zero = false
			break
		}
	}
	if zero {
		return "IPv4-compatible IPv6, which bypasses the IPv4 rules"
	}
	return ""
}

// validator applies the address rules. It is a value with no state so that the
// rules can be exercised on their own, without a device, a sink or a gate.
type validator struct {
	assign Assignment
	// acceptTransit relaxes ONLY the destination-is-ours test. See tun.Config.
	acceptTransit bool
}

// familyAllowed reports whether this tunnel carries the packet's family at all.
// An unassigned family is refused rather than passed through: a host that
// somehow routes IPv6 at a tunnel that negotiated none is a host about to leak
// IPv6, and the tunnel is the last place that can say no.
//
// Both outbound and inbound call this immediately after parse, BEFORE the
// martian checks and BEFORE source/destination equality. An IPv6 packet on a
// v4-only assignment is therefore ErrFamilyOff ("no inner IPv6 address is
// assigned"), never ErrSourceNotOurs or ErrNotForUs. That includes a kernel
// IPv6 router solicitation (link-local source, all-routers multicast dest):
// this function looks only at p.v6 and hasV6(), not at the addresses.
func (v validator) familyAllowed(p packet) error {
	if p.v6 {
		if !v.assign.hasV6() {
			return errWrap(ErrFamilyOff, "no inner IPv6 address is assigned")
		}
		return nil
	}
	if !v.assign.hasV4() {
		return errWrap(ErrFamilyOff, "no inner IPv4 address is assigned")
	}
	return nil
}

func (v validator) ours(p packet) netip.Addr {
	if p.v6 {
		return v.assign.V6
	}
	return v.assign.V4
}

// outbound validates a packet the host handed us, on its way into the tunnel.
//
// After parse, the address rules run in this order and the first match wins:
//  1. familyAllowed         → ErrFamilyOff
//  2. martian source / dest → ErrMartian
//  3. src == assigned addr  → ErrSourceNotOurs
//  4. dst == assigned addr  → ErrMartian (self-addressed)
//
// A v4-only tun that sees an IPv6 router solicitation therefore returns
// ErrFamilyOff, never ErrSourceNotOurs: the source check is not reached.
// Even on a dual-stack tun the same frame is ErrMartian (link-local unicast
// source, multicast dest) before source equality runs.
//
// The source check itself is an equality against a single address rather than
// a containment test against a prefix. A prefix test forwards every other host
// inside the prefix; on a shared inner subnet that is every other subscriber
// on the gateway.
func (v validator) outbound(b []byte) (packet, error) {
	p, err := parsePacket(b)
	if err != nil {
		return packet{}, err
	}
	if err := v.familyAllowed(p); err != nil {
		return packet{}, err
	}
	if reason := martianReason(p.src); reason != "" {
		return packet{}, errWrap(ErrMartian, "source is %s", reason)
	}
	if reason := martianReason(p.dst); reason != "" {
		return packet{}, errWrap(ErrMartian, "destination is %s", reason)
	}
	if p.src != v.ours(p) {
		// Deliberately does not name the address it saw. This error can be
		// logged by a host, and a log line naming the host's real
		// carrier-assigned source address is the exact fact the tunnel exists
		// to keep off the record.
		return packet{}, ErrSourceNotOurs
	}
	if p.dst == v.ours(p) {
		// A packet addressed to our own inner address does not belong on the
		// wire; the host's loopback path owns it. Sending it makes the gateway
		// route it straight back, which is a reflector built out of our own
		// tunnel.
		return packet{}, errWrap(ErrMartian, "destination is this endpoint's own inner address")
	}
	return p, nil
}

// inbound validates a packet arriving from the tunnel, on its way to the host.
//
// familyAllowed still runs first (same order as outbound). An inbound IPv6
// packet on a v4-only assignment is ErrFamilyOff, not ErrNotForUs.
//
// Once the family is assigned, the destination check is what makes this
// endpoint structurally incapable of routing. A gateway — or anything that
// has compromised one — that sends a packet destined elsewhere is asking this
// host to forward it, and a host with IP forwarding enabled would oblige, out
// its real interface, sourced from a third party. That is the leak in its
// purest form and it is one equality test away.
func (v validator) inbound(b []byte) (packet, error) {
	p, err := parsePacket(b)
	if err != nil {
		return packet{}, err
	}
	if err := v.familyAllowed(p); err != nil {
		return packet{}, err
	}
	if reason := martianReason(p.src); reason != "" {
		return packet{}, errWrap(ErrMartian, "source is %s", reason)
	}
	if reason := martianReason(p.dst); reason != "" {
		return packet{}, errWrap(ErrMartian, "destination is %s", reason)
	}
	if p.dst != v.ours(p) && !v.acceptTransit {
		return packet{}, ErrNotForUs
	}
	if p.src == v.ours(p) {
		// Our own address as a source, arriving from the tunnel. Either a loop
		// or something trying to make the host trust a packet as locally
		// originated.
		return packet{}, ErrReflected
	}
	return p, nil
}

// checksum is the 16-bit one's complement of the one's complement sum, as used
// by the IPv4 header and by ICMP.
//
// Applied to a buffer that already carries its correct checksum it returns 0,
// which is how verification is done here and what TestChecksumSelfVerifies
// asserts on every packet this package synthesises.
func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
