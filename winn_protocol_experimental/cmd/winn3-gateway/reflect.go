package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	"winsvpn.local/winnprotocol/winn3/tun"
)

// reflector is the gateway's inner side: an in-process tun.Device that returns
// what it is given, with the addresses swapped.
//
// # Why a reflector and not a router
//
// The claim this binary exists to support is "a v3 packet crossed a real
// network and came back", and a reflector supports exactly that claim and no
// larger one. It forwards nothing, resolves nothing and egresses nothing, so
// there is no way to read a successful run here as evidence about NAT, routing
// or internet reachability — none of which this process does. A stub that
// quietly forwarded would let this file's evidence be cited for something it
// never tested, which is the failure mode the capability table was made honest
// to prevent.
//
// It also needs no privilege and no kernel interface, which is why the gateway
// runs unprivileged on macOS as well as Linux, where cmd/winn3-labrig cannot.
//
// # The address rule, which is not cosmetic
//
// winn3/tun/ip.go validates both directions against the endpoint's own
// assignment (ip.go:229 and ip.go:268):
//
//	outbound (device -> tunnel):  src MUST be ours, dst MUST NOT be ours
//	inbound  (tunnel -> device):  dst MUST be ours, src MUST NOT be ours
//
// So a reply cannot simply mirror the arriving header: it must be sourced from
// the gateway's OWN assigned address or the tunnel refuses to carry it and
// counts it as TxDroppedInvalid. The swap below therefore sets src to the
// assignment and dst to the arriving packet's source, which satisfies the
// outbound rule for any destination a client addresses — including one this
// gateway does not own, which is the case a naive mirror gets wrong.
type reflector struct {
	mtu   int
	ours  netip.Addr
	inbox chan []byte

	reflected atomic.Uint64
	ignored   atomic.Uint64

	closeOnce sync.Once
	done      chan struct{}
}

// reflectorDepth bounds the queue. A full queue drops rather than blocks:
// WritePacket is called from the tunnel's delivery path, and a device that
// blocks there stalls the session that is trying to deliver.
const reflectorDepth = 256

func newReflector(mtu int, ours netip.Addr) *reflector {
	return &reflector{
		mtu:   mtu,
		ours:  ours,
		inbox: make(chan []byte, reflectorDepth),
		done:  make(chan struct{}),
	}
}

var errReflectorClosed = errors.New("reflector closed")

// ReadPacket blocks until there is a reply to send, which is what tun.Device
// requires and what makes the loop's device pump behave as it does against a
// real interface.
func (r *reflector) ReadPacket(buf []byte) (int, error) {
	select {
	case pkt := <-r.inbox:
		if len(pkt) > len(buf) {
			return 0, errors.New("reflector: reply exceeds the read buffer")
		}
		return copy(buf, pkt), nil
	case <-r.done:
		return 0, errReflectorClosed
	}
}

// WritePacket takes one delivered inner packet and queues its reflection.
//
// It reports the full length as written whatever it decides, because the return
// value is the DEVICE's contract — "the host took these bytes" — and not a
// statement about whether a reply was produced. Returning short here would make
// tun.deliver count a device write failure for a packet the device accepted.
func (r *reflector) WritePacket(pkt []byte) (int, error) {
	select {
	case <-r.done:
		return 0, errReflectorClosed
	default:
	}
	reply := r.reflect(pkt)
	if reply == nil {
		r.ignored.Add(1)
		return len(pkt), nil
	}
	select {
	case r.inbox <- reply:
		r.reflected.Add(1)
	default:
		r.ignored.Add(1)
	}
	return len(pkt), nil
}

// reflect builds the reply, or nil for anything it will not answer.
//
// IPv4 only, and deliberately: this gateway's assignment is IPv4 and at the
// path MTUs v3 plans for, inner IPv6 is frequently impossible anyway
// (driver.Sizing.InnerIPv6). An inner IPv6 packet arriving here is not an error,
// it is simply not something this reflector answers, and it is counted.
func (r *reflector) reflect(pkt []byte) []byte {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || ihl > len(pkt) {
		return nil
	}
	if !r.ours.Is4() {
		return nil
	}
	var src [4]byte
	copy(src[:], pkt[12:16])
	from := netip.AddrFrom4(src)
	if from == r.ours {
		// Would violate the outbound rule dst != ours. Cannot arise from a
		// validated inbound packet; refused here rather than trusted.
		return nil
	}

	reply := make([]byte, len(pkt))
	copy(reply, pkt)
	ours := r.ours.As4()
	copy(reply[12:16], ours[:]) // src := our assignment
	copy(reply[16:20], src[:])  // dst := where it came from
	// The header checksum covers the addresses that just changed. Zero it
	// first: the routine below sums the whole header, so a stale value would be
	// folded into its own replacement.
	reply[10], reply[11] = 0, 0
	binary.BigEndian.PutUint16(reply[10:12], ipv4Checksum(reply[:ihl]))
	return reply
}

// ipv4Checksum is the ones-complement header checksum over an IPv4 header whose
// own checksum field has already been zeroed.
func ipv4Checksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	if len(h)%2 == 1 {
		sum += uint32(h[len(h)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// MTU reports the inner MTU the tunnel planned. The reflector has no interface
// to measure, so this is the plan floor by construction rather than a
// measurement — the same honest weakness cmd/winn-datapath's loopback device
// documents about itself.
func (r *reflector) MTU() int { return r.mtu }

// Reflected is how many packets were answered.
func (r *reflector) Reflected() uint64 { return r.reflected.Load() }

// Ignored is how many were taken and not answered: non-IPv4, malformed, or
// arriving with the queue full.
func (r *reflector) Ignored() uint64 { return r.ignored.Load() }

// Close unblocks a parked ReadPacket, which is the lifecycle tun.Device
// documents: the HOST closes the device and that is what releases the pump.
func (r *reflector) Close() error {
	r.closeOnce.Do(func() { close(r.done) })
	return nil
}

var _ tun.Device = (*reflector)(nil)
