package tun

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// Header and packet geometry, fixed by IP itself.
const (
	// IPv4HeaderMin is the smallest legal IPv4 header (IHL == 5).
	IPv4HeaderMin = 20

	// IPv6HeaderLen is the fixed IPv6 header size.
	IPv6HeaderLen = 40

	// MaxIPPacket is the largest packet an IPv4 total-length field can
	// describe, and therefore the size of the read buffer a pump uses. Reading
	// into anything smaller makes "oversize" and "truncated" indistinguishable,
	// and misclassifying an oversize packet as malformed loses the PMTU signal
	// the sender needs.
	MaxIPPacket = 65535
)

// Framing overhead. This is the whole of the MTU arithmetic.
const (
	// FrameOverhead is core's frame header: type(1) || length(2 BE). It is
	// asserted against core.AppendFrame in TestOverheadMatchesCore rather than
	// trusted, so that a change to core's framing breaks this package's tests
	// instead of silently shifting its MTU.
	FrameOverhead = 3
)

// Outer-encapsulation costs, published for the host lane's path arithmetic.
// This package never opens a socket and so never observes them; they are here
// so that InnerMTUForPath can be used from a host integration and from tests.
const (
	// UDPOverIPv4Overhead is 20 bytes of IPv4 header with no options plus 8
	// bytes of UDP header.
	UDPOverIPv4Overhead = 28

	// UDPOverIPv6Overhead is 40 bytes of IPv6 header plus 8 bytes of UDP
	// header.
	UDPOverIPv6Overhead = 48
)

// MTU floors.
const (
	// IPv6MinLinkMTU is RFC 8200's hard floor: every link must convey a
	// 1280-octet packet in one piece. The tun interface IS a link. A tunnel
	// that offers an inner IPv6 route on a link narrower than this has built a
	// black hole, because IPv6 routers do not fragment and the alternative —
	// link-layer fragmentation below IPv6 — means reassembly state and an
	// extra packet per oversize datagram. This package declines both and
	// refuses to enable inner IPv6 instead.
	IPv6MinLinkMTU = 1280

	// MinInnerMTUv4 is RFC 1122's minimum reassembly buffer. Below this the
	// tunnel is not usable for IPv4 either and New refuses.
	MinInnerMTUv4 = 576
)

// ICMP rate-limit defaults for synthesised path-MTU signals.
const (
	DefaultICMPPerSecond = 10
	DefaultICMPBurst     = 20
)

// Overhead is what one inner IP packet costs on the wire: the transport
// message overhead (demux token + inner length + AEAD tag) plus the DATA
// frame header.
//
//	Overhead() = core.TransportOverhead() + FrameOverhead
//	           = (8 + 2 + 16)             + 3
//	           = 29
//
// Padding does not appear here on purpose. core.Seal writes padding as zero
// bytes *inside* the AEAD, after the payload, and the inner length field
// recovers the payload boundary — so padding costs no frame header and no
// per-packet overhead. It can only round a message up to a length that must
// already fit the carrier; see Config.CarrierFloorMessageSize.
func Overhead() int { return core.TransportOverhead() + FrameOverhead }

// InnerMTU is the largest inner IP packet that fits one carrier message.
func InnerMTU(carrierMaxMessage int) int { return carrierMaxMessage - Overhead() }

// CarrierMessageFor is the inverse: the on-wire message size an inner packet
// of mtu bytes produces. A driver's top padding bucket must not exceed the
// carrier's maximum message size, and this is how to check it.
func CarrierMessageFor(mtu int) int { return mtu + Overhead() }

// InnerMTUForPath is the whole chain, for a host lane that knows its path MTU
// and its outer encapsulation: subtract the outer headers to get the carrier's
// maximum message, then subtract this package's overhead.
//
//	InnerMTUForPath(1500, UDPOverIPv4Overhead) == 1443
//	InnerMTUForPath(1500, UDPOverIPv6Overhead) == 1423
//	InnerMTUForPath(1280, UDPOverIPv6Overhead) == 1203
func InnerMTUForPath(pathMTU, outerOverhead int) int {
	return InnerMTU(pathMTU - outerOverhead)
}

// MinCarrierMessageForIPv6 is the smallest carrier message size that can carry
// inner IPv6 at all: IPv6MinLinkMTU + Overhead() == 1309. Anything less and
// New refuses to enable the v6 half of the assignment.
func MinCarrierMessageForIPv6() int { return CarrierMessageFor(IPv6MinLinkMTU) }

// Errors. Every one is LOCAL, in the same sense the core means it: nothing here
// is ever signalled to a peer, and the only thing that is ever synthesised in
// response to one is a path-MTU packet written inward to the host's own device.
var (
	ErrConfig = errors.New("winn3/tun: invalid configuration")

	// ErrNotCarrying is the fail-closed refusal. It is returned for every
	// packet, in either direction, whenever the gate is not open — before the
	// packet is parsed, before its addresses are looked at, and before
	// anything at all is written to the host.
	ErrNotCarrying = errors.New("winn3/tun: session is not carrying; dropped fail-closed")

	ErrShortPacket   = errors.New("winn3/tun: packet is shorter than its header")
	ErrBadVersion    = errors.New("winn3/tun: not an IPv4 or IPv6 packet")
	ErrBadHeader     = errors.New("winn3/tun: malformed IP header")
	ErrBadChecksum   = errors.New("winn3/tun: bad IPv4 header checksum")
	ErrFamilyOff     = errors.New("winn3/tun: address family is not assigned to this tunnel")
	ErrMartian       = errors.New("winn3/tun: address must never cross a tunnel")
	ErrSourceNotOurs = errors.New("winn3/tun: source is not the address assigned to this tunnel")
	ErrNotForUs      = errors.New("winn3/tun: destination is not the address assigned to this tunnel")
	ErrReflected     = errors.New("winn3/tun: inbound packet claims our own source address")
	ErrOversize      = errors.New("winn3/tun: inner packet exceeds the inner MTU and is never fragmented")
)

// Assignment is what the gateway assigned to THIS endpoint's inner interface,
// and it is the whole of this package's address authority.
//
// Addresses, never prefixes. A validator that accepts a prefix forwards every
// other host inside it; a tunnel that forwards a packet whose source it never
// assigned has deanonymised its user. The narrow rule costs nothing and the
// broad one cannot be made safe.
//
// Either family may be absent (the zero netip.Addr), in which case that family
// is refused outright in both directions rather than passed through.
type Assignment struct {
	// V4 and V6 are the inner addresses this endpoint owns.
	V4 netip.Addr
	V6 netip.Addr

	// RouterV4 and RouterV6 are the inner next hop, used ONLY as the source
	// address of a synthesised path-MTU packet written inward to the host. They
	// are optional: with no router address there is no credible source for the
	// signal, so oversize packets are dropped silently and counted instead.
	RouterV4 netip.Addr
	RouterV6 netip.Addr
}

// hasV4 and hasV6 report which families this tunnel carries.
func (a Assignment) hasV4() bool { return a.V4.IsValid() }
func (a Assignment) hasV6() bool { return a.V6.IsValid() }

// validate rejects an assignment that could not be a usable inner address.
//
// The checks are the same ones applied to packets, applied once to the
// configuration: an assignment the packet validator would reject is a tunnel
// that drops all of its own traffic, and finding that out at New is much
// better than finding it out as silence.
func (a Assignment) validate() error {
	if !a.hasV4() && !a.hasV6() {
		return errWrap(ErrConfig, "assignment carries neither an IPv4 nor an IPv6 address")
	}
	if a.hasV4() {
		if !a.V4.Is4() {
			return errWrap(ErrConfig, "assigned IPv4 address is not a 4-byte address")
		}
		if reason := martianReason(a.V4); reason != "" {
			return errWrap(ErrConfig, "assigned IPv4 address is unusable: %s", reason)
		}
	}
	if a.hasV6() {
		if !a.V6.Is6() || a.V6.Is4In6() {
			return errWrap(ErrConfig, "assigned IPv6 address is not a native 16-byte address")
		}
		if reason := martianReason(a.V6); reason != "" {
			return errWrap(ErrConfig, "assigned IPv6 address is unusable: %s", reason)
		}
	}
	if a.RouterV4.IsValid() {
		if !a.RouterV4.Is4() {
			return errWrap(ErrConfig, "IPv4 router address is not a 4-byte address")
		}
		if !a.hasV4() {
			return errWrap(ErrConfig, "IPv4 router address without an assigned IPv4 address")
		}
	}
	if a.RouterV6.IsValid() {
		if !a.RouterV6.Is6() || a.RouterV6.Is4In6() {
			return errWrap(ErrConfig, "IPv6 router address is not a native 16-byte address")
		}
		if !a.hasV6() {
			return errWrap(ErrConfig, "IPv6 router address without an assigned IPv6 address")
		}
	}
	return nil
}

// Clock is the only time source this package has. It exists so that the ICMP
// rate limiter is deterministic under test; there is no timer, no ticker and
// no sleep anywhere in the package, and TestPackageOpensNothing proves it.
type Clock interface {
	Now() time.Time
}

// Device is the host's tun interface, seen from here.
//
// This package never opens one. The host lane supplies the implementation, and
// that is what keeps the same code correct on utun, /dev/net/tun, WinTun, an
// Android VpnService descriptor and NEPacketTunnelFlow.
//
// Neither method may be called after the host has closed the device; lifecycle
// belongs to the host, which is why there is deliberately no Close here. A tun
// layer that can close the host's interface is a tun layer making a host call.
type Device interface {
	// ReadPacket blocks until one inner IP packet is available, copies it into
	// buf and returns its length. Any framing the platform adds — Darwin's
	// 4-byte address family prefix, Linux's optional packet-information header
	// — must already have been stripped: what arrives here is an IP packet
	// starting at its version nibble.
	ReadPacket(buf []byte) (int, error)

	// WritePacket delivers one inner IP packet to the host stack.
	WritePacket(pkt []byte) (int, error)

	// MTU reports the MTU the host configured on the interface.
	//
	// New refuses if this exceeds the tunnel's inner MTU. A device MTU
	// larger than the tunnel can carry turns every full-size flow into a black
	// hole that path-MTU discovery may or may not rescue, and on a censored
	// network "may or may not" resolves to "does not".
	MTU() int
}

// MTUSetter is the optional seam that lets a live tunnel re-apply its host
// interface MTU after the handshake.
//
// Device does not include SetMTU: most production implementations (VpnService,
// NEPacketTunnel, utun, WinTun) configure the MTU once at start, and a Device
// that cannot change it must not pretend. winn3/driver type-asserts this
// interface; if it is missing, a path-MTU mismatch stays a loud refusal
// rather than a silent shrink that leaves the device generating packets the
// tunnel can only drop — the black hole Device.MTU's comment already names.
//
// SetMTU must not raise the MTU above the value New observed. Lowering is
// the only direction ClampInnerMTU asks for.
type MTUSetter interface {
	SetMTU(mtu int) error
}

// FrameSink is the frame-level session driver (winn3/session), seen from here.
//
// It is declared in THIS package on purpose. Taking winn3/session's concrete
// type as a dependency would put an import edge in the direction that makes
// the tun layer untestable. The session driver satisfies this, or a ten-line
// adapter does.
type FrameSink interface {
	// SendData enqueues one inner IP packet for transmission as a single DATA
	// frame.
	//
	// Two obligations, both load-bearing:
	//
	//   - It MUST NOT retain pkt after returning. The pump reuses one buffer
	//     across reads; TestPumpBufferIsReused makes that aliasing observable
	//     rather than a footnote.
	//   - It MUST fail closed rather than buffer. A packet parked in a queue
	//     across a rekey is a packet that can be emitted under the wrong epoch,
	//     and a packet parked across a teardown is the leak this whole layer
	//     exists to prevent.
	SendData(pkt []byte) error
}

// BatchDevice is an optional extension to Device allowing vectorised packet reads.
type BatchDevice interface {
	Device
	ReadBatch(bufs [][]byte) ([]int, error)
}

// BatchFrameSink is an optional extension to FrameSink allowing vectorised packet transmission.
type BatchFrameSink interface {
	FrameSink
	SendDataBatch(pkts [][]byte) (int, error)
}

func errWrap(base error, format string, args ...any) error {
	return &wrapped{base: base, msg: fmt.Sprintf(format, args...)}
}

type wrapped struct {
	base error
	msg  string
}

func (w *wrapped) Error() string { return w.base.Error() + ": " + w.msg }
func (w *wrapped) Unwrap() error { return w.base }
