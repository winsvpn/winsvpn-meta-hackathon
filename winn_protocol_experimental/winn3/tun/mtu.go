package tun

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// Path-MTU signalling geometry.
const (
	// icmpv4ErrorMaxTotal caps a synthesised ICMPv4 error at RFC 1812's
	// recommended 576 bytes, so it can never itself be the packet that needs
	// fragmenting.
	icmpv4ErrorMaxTotal = 576

	// icmpv6ErrorMaxTotal caps a synthesised ICMPv6 error at the IPv6 minimum
	// link MTU, as RFC 4443 §2.4(c) requires.
	icmpv6ErrorMaxTotal = IPv6MinLinkMTU

	// icmpHeaderLen is type(1) || code(1) || checksum(2) || four bytes that are
	// the next-hop MTU for both of the messages this package emits.
	icmpHeaderLen = 8

	icmpv4TypeDestUnreachable = 3
	icmpv4CodeFragNeeded      = 4
	icmpv6TypePacketTooBig    = 2
	icmpv6NextHeader          = 58

	synthesisedTTL = 64
)

// tokenBucket rate-limits synthesised path-MTU signals.
//
// It exists because the trigger is not adversarial in the usual sense — it is
// a local misconfiguration, a host MTU set too high, a batching offload
// handing up a 64 KB segment — and every one of those produces oversize
// packets at line rate. Answering each one with an ICMP write turns a
// misconfiguration into a livelock inside the packet loop.
//
// It reads the injected Clock and nothing else, so its behaviour under test is
// exactly its behaviour in production.
type tokenBucket struct {
	mu      sync.Mutex
	perSec  float64
	burst   float64
	tokens  float64
	last    time.Time
	started bool
}

func newTokenBucket(perSec, burst int) *tokenBucket {
	return &tokenBucket{
		perSec: float64(perSec),
		burst:  float64(burst),
		tokens: float64(burst),
	}
}

func (tb *tokenBucket) allow(now time.Time) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if !tb.started {
		tb.started = true
		tb.last = now
	}
	if elapsed := now.Sub(tb.last); elapsed > 0 {
		tb.last = now
		tb.tokens += elapsed.Seconds() * tb.perSec
		if tb.tokens > tb.burst {
			tb.tokens = tb.burst
		}
	}
	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}

// synthesiseTooBig builds the path-MTU signal for an oversize inner packet.
//
// It is built for delivery INWARD — to the host's own stack, addressed to the
// host's own inner address, sourced from the inner next hop. It is never a
// DATA frame and it never reaches a carrier. That direction is what makes it
// compatible with the design's silence rule (§4.3, "no ICMP"): the rule is
// about what a non-key-holder can elicit from an endpoint on the wire, and
// this packet is not on the wire.
//
// Returns nil when no signal can be built: no router address configured, or a
// packet whose sender would not act on one anyway.
func synthesiseTooBig(p packet, mtu int, assign Assignment) []byte {
	if p.v6 {
		if !assign.RouterV6.IsValid() {
			return nil
		}
		return icmpv6PacketTooBig(assign.RouterV6, p, mtu)
	}
	if !assign.RouterV4.IsValid() {
		return nil
	}
	if !p.df {
		// Without DF the sender expects a router to fragment. We refuse to
		// fragment, so the packet is dropped — but a Fragmentation Needed
		// message for a packet that did not set DF is non-standard and hosts
		// ignore it, so emitting one would be noise pretending to be a fix.
		// The real answer is the host contract: set the device MTU to the
		// value this package publishes and the host stops generating these.
		return nil
	}
	return icmpv4FragNeeded(assign.RouterV4, p, mtu)
}

func icmpv4FragNeeded(from netip.Addr, p packet, nextHopMTU int) []byte {
	quote := len(p.body)
	if max := icmpv4ErrorMaxTotal - IPv4HeaderMin - icmpHeaderLen; quote > max {
		quote = max
	}
	total := IPv4HeaderMin + icmpHeaderLen + quote
	out := make([]byte, total)

	out[0] = 0x45
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	// DF set. With DF set and the packet atomic, RFC 6864 leaves the
	// identification field unconstrained — which is the point: this package
	// has no entropy source, because it makes no host calls, and a fixed
	// identification on a fragmentable packet would have been a real defect.
	out[6] = 0x40
	out[8] = synthesisedTTL
	out[9] = 1 // ICMP
	src := from.As4()
	dst := p.src.As4()
	copy(out[12:16], src[:])
	copy(out[16:20], dst[:])
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:IPv4HeaderMin]))

	icmp := out[IPv4HeaderMin:]
	icmp[0] = icmpv4TypeDestUnreachable
	icmp[1] = icmpv4CodeFragNeeded
	// icmp[4:6] stays zero (unused); icmp[6:8] is the next-hop MTU.
	binary.BigEndian.PutUint16(icmp[6:8], uint16(nextHopMTU))
	copy(icmp[icmpHeaderLen:], p.body[:quote])
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))

	return out
}

func icmpv6PacketTooBig(from netip.Addr, p packet, mtu int) []byte {
	quote := len(p.body)
	if max := icmpv6ErrorMaxTotal - IPv6HeaderLen - icmpHeaderLen; quote > max {
		quote = max
	}
	payload := icmpHeaderLen + quote
	out := make([]byte, IPv6HeaderLen+payload)

	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:6], uint16(payload))
	out[6] = icmpv6NextHeader
	out[7] = synthesisedTTL
	src := from.As16()
	dst := p.src.As16()
	copy(out[8:24], src[:])
	copy(out[24:40], dst[:])

	icmp := out[IPv6HeaderLen:]
	icmp[0] = icmpv6TypePacketTooBig
	binary.BigEndian.PutUint32(icmp[4:8], uint32(mtu))
	copy(icmp[icmpHeaderLen:], p.body[:quote])
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(src, dst, icmp))

	return out
}

// icmpv6Checksum covers the RFC 8200 §8.1 pseudo-header as well as the
// message. Omitting the pseudo-header produces a packet every stack silently
// discards, which would turn a path-MTU signal into an invisible black hole —
// so TestChecksumSelfVerifies checks it the way a receiver does, by summing
// the pseudo-header and the message together and requiring zero.
func icmpv6Checksum(src, dst [16]byte, msg []byte) uint16 {
	var pseudo [40]byte
	copy(pseudo[0:16], src[:])
	copy(pseudo[16:32], dst[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(msg)))
	pseudo[39] = icmpv6NextHeader

	var sum uint32
	add := func(b []byte) {
		for len(b) >= 2 {
			sum += uint32(b[0])<<8 | uint32(b[1])
			b = b[2:]
		}
		if len(b) == 1 {
			sum += uint32(b[0]) << 8
		}
	}
	add(pseudo[:])
	add(msg)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
