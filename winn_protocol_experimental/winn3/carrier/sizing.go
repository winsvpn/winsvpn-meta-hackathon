package carrier

import (
	"winsvpn.local/winnprotocol/winn3/session"
)

// Header costs, in bytes, that sit between a Winn3 message and the path MTU.
//
// These are the numbers session.MaxMessageSizeForPath is called with. This
// package never subtracts them itself and never uses
// session.DefaultMaxMessageSize: that constant is 1280 − 48, correct for UDP
// over IPv6 and for nothing else, and a stream carrier is 64 bytes off it. Using
// it on a TLS carrier at the IPv6 minimum MTU produces a fragmented packet on
// every full-size message, and fragments are both widely dropped and a
// distinctive fingerprint. TestPackageNeverUsesTheDefaultMessageSize greps this
// package's own source to hold that.
const (
	// ipv4HeaderBytes is the IPv4 header with no options, which is what every
	// path in practice presents.
	ipv4HeaderBytes = 20

	// ipv6HeaderBytes is the fixed IPv6 header. Extension headers would add
	// more; a path that presents them is already outside the planning envelope
	// and will fragment for reasons this arithmetic cannot see.
	ipv6HeaderBytes = 40

	// udpHeaderBytes is the UDP header.
	udpHeaderBytes = 8

	// tcpHeaderBytes is 20 bytes of fixed TCP header plus 12 for the timestamps
	// option.
	//
	// The 12 is not padding-for-safety, it is the common case: Linux, macOS,
	// Windows and Android all negotiate RFC 7323 timestamps by default, so the
	// steady-state segment on a real handset carries them. Sizing to a bare
	// 20-byte header would make every full-size message 12 bytes too big for the
	// path — which fragments at the IP layer or, worse on TCP, silently costs a
	// second segment carrying 12 bytes. A recurring 12-byte trailing segment is
	// a fleet-wide length signature, so being wrong here is a fingerprint bug as
	// well as a performance one.
	tcpHeaderBytes = 20 + 12

	// tlsRecordBytes is a TLS 1.3 record's overhead: a 5-byte header, a 1-byte
	// inner content type inside the AEAD, and a 16-byte tag.
	//
	// One Winn3 message is one Write, and crypto/tls emits one record per Write
	// below 16 KiB, so this is charged once per message and not once per
	// segment.
	tlsRecordBytes = 5 + 1 + 16

	// LengthRecordOverhead is §4.2's sealed length: AEAD(k_len, n_i, uint16) —
	// two bytes of plaintext, eighteen on the wire.
	LengthRecordOverhead = 2 + 16

	// SaltSize is the per-connection random salt a stream sender prepends to its
	// first record. It is charged to the first message only, so it does not
	// appear in Overhead; §2 of the handoff explains why it exists and why it
	// travels with the first Send rather than on its own.
	SaltSize = 16
)

// Overhead is the bytes a carrier of this class and family wraps around one
// Winn3 message, all the way down to the IP header.
//
// FamilyUnknown is charged the IPv6 cost. Over-reserving 20 bytes wastes 20
// bytes of payload; under-reserving them fragments, and the fragment is both
// dropped by the middleboxes this protocol exists to get past and a signature in
// its own right. The asymmetry decides the default.
func Overhead(class Class, family Family) int {
	ip := ipv6HeaderBytes
	if family == FamilyIPv4 {
		ip = ipv4HeaderBytes
	}
	switch class {
	case ClassUDP:
		return ip + udpHeaderBytes
	case ClassTCP:
		return ip + tcpHeaderBytes + LengthRecordOverhead
	case ClassTLS:
		return ip + tcpHeaderBytes + tlsRecordBytes + LengthRecordOverhead
	default:
		// An unknown class is charged the most expensive carrier this package
		// knows how to build, for the same reason FamilyUnknown is charged IPv6.
		return ip + tcpHeaderBytes + tlsRecordBytes + LengthRecordOverhead
	}
}

// MaxMessageSizeFor is the MaxMessageSize a carrier of this class and family
// should use on a path of pathMTU bytes.
//
// It is a one-line delegation to session.MaxMessageSizeForPath on purpose. That
// function owns the floor and the ceiling clamps and the session lane owns the
// arithmetic; a second implementation here would be a number that agrees today
// and drifts later, and the symptom of the drift is "large downloads stall",
// reported from somewhere nobody can attach a debugger.
func MaxMessageSizeFor(class Class, family Family, pathMTU int) int {
	return session.MaxMessageSizeForPath(pathMTU, Overhead(class, family))
}

// DefaultPathMTU is the planning path MTU when none has been measured, and it
// is THE FLEET DEFAULT: every host entry point that resolves a missing
// `path_mtu` resolves it through this constant and no other.
//
// ===========================================================================
// WHY IT IS NO LONGER 1280 — CHANGED 2026-08-10
// ===========================================================================
//
// It was 1280, described here as "the RFC 8200 floor every link carrying IPv6
// must offer". That description was right about the number and wrong about what
// the number does when it is an OUTER path MTU rather than an inner one.
//
// 1280 outer does not yield 1280 inner. Over the shipping migration plan it
// yields 1139 — 29 bytes of v3 overhead plus 112 for the widest class the plan
// may reach, TLS over IPv6 — and an inner interface at 1139 cannot carry IPv6
// at all. The kernel says so and it is not a policy anything here can waive:
// ipv6_add_dev() returns -EINVAL below 1280, on Android and on desktop Linux
// alike.
//
// So 1280..1420 is a 141-VALUE DEAD ZONE. A session planned there resolves,
// bootstraps and carries, and can NEVER PROMOTE. The fleet defaulted into the
// middle of it and the four hosts each mispriced it differently: Android
// refused outright, Apple installed an IPv6 sink at an MTU the kernel rejects
// with no guard anywhere in its tree, and Windows and Linux gated inner IPv6
// out entirely — shipping the leak Android's sink exists to close.
//
// 1421 is where the zone ends (1280 + 29 + 112) and driver.NewSizing refuses
// below the plan-aware form of it. 1450 rather than 1421 leaves 29 bytes of
// headroom so the first narrow hop does not land back on the edge, and rather
// than 1500 because conceding 50 bytes is cheaper than black-holing a path that
// really is narrower — 1500 is an assumption about someone else's network, and
// this one is made in Myanmar.
//
// A carrier that has MEASURED its path should still say so. Leaving bytes on
// the floor of every packet is a real cost on a metered mobile connection where
// data is expensive, and this constant is only ever the answer to "nobody told
// us".
const DefaultPathMTU = 1450

// Floor is the narrowest MaxMessageSize across every class the session may
// migrate to, across both address families.
//
// This is the number the session driver and the tun device should both be built
// with, and it is the primary sizing API of this package. §2.4 of the tun lane's
// handoff states the trap it closes:
//
//	Config.CarrierFloorMessageSize is the SMALLEST MaxMessageSize across every
//	carrier class this session may migrate to — not the one it dialled.
//
// Size to the carrier in use and the first failover silently black holes every
// full-size flow: the tunnel stays "up", small packets keep working, large
// transfers stall. That is the worst failure to diagnose remotely, and since the
// answer to a censor who blocks UDP is precisely to fail over, it is a likely
// failure rather than an exotic one.
//
// Both families are included whether or not the current carrier resolved to one,
// because a migration can change family as easily as it changes class — a
// gateway reachable over both, or a handset moving from a v4-only cellular
// network to a v6-only one. A floor computed for the family in use is the same
// bug one layer along.
//
// With no classes it returns the floor for the most expensive carrier this
// package can build, which is the conservative reading of "we do not yet know".
func Floor(pathMTU int, classes ...Class) int {
	if len(classes) == 0 {
		classes = []Class{ClassUnknown}
	}
	best := 0
	for _, class := range classes {
		for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
			n := MaxMessageSizeFor(class, family, pathMTU)
			if best == 0 || n < best {
				best = n
			}
		}
	}
	return best
}

// InnerMTU is the tun device MTU implied by a MaxMessageSize.
//
// Re-exported from winn3/session rather than re-derived. The two lanes already
// found they had independently derived the same expression; keeping two copies
// is how that agreement turns into a divergence nobody notices until a download
// stalls.
func InnerMTU(maxMessageSize int) int { return session.InnerMTU(maxMessageSize) }

// MinPathMTUForInnerIPv6 is the outer path MTU a carrier of this class and
// family needs before the tunnel can carry inner IPv6 at all.
//
// A caller that intends to assign inner IPv6 must check this rather than
// discover it as a black hole. At a 1280-byte outer path inner IPv6 is
// impossible for any tunnel; over a TLS carrier the bar is higher still, because
// the record and the sealed length are charged on top of the IP and TCP headers.
func MinPathMTUForInnerIPv6(class Class, family Family) int {
	return session.MinPathMTUForInnerIPv6(Overhead(class, family))
}
