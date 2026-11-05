package carrier

import (
	"errors"
	"sync/atomic"
)

// Kernel path-MTU discovery for the datagram carrier.
//
// WHY THIS EXISTS. Before this file the only path-MTU mechanism in the protocol
// was the handshake CLAIM exchange (session.EncodePathMTUNotice and
// Driver.refusePathMTUMismatch). That reconciles two CONFIGURED numbers. It
// cannot see the network. Both ends default to carrier.DefaultPathMTU (1450),
// both agree, no refusal fires, and a cellular path whose real MTU is 1380 or
// 1360 silently drops every full-size datagram while the handshake and every
// small message keep working. That is the exact failure mode Floor's own doc
// comment names as "the worst failure to diagnose remotely", reached through a
// door the claim exchange does not watch.
//
// WHAT THIS ADDS. On Linux and Android the kernel already performs RFC 1191 /
// RFC 8201 path-MTU discovery for a connected UDP socket when the socket asks
// for it. Asking costs one setsockopt; the answer arrives as EMSGSIZE on the
// oversized send, and the discovered number is then readable with one
// getsockopt. This file is those two calls plus the plumbing that turns the
// answer into a value the driver can act on.
//
// WHAT THIS DELIBERATELY DOES NOT DO. It does not resize the session, clamp the
// tun device, or renegotiate anything. Those decisions belong to winn3/driver,
// which owns the tun MTU setter and the shrink-safety rule
// (session.ShrinkToPeerPathMTU). This package reports; the driver decides. A
// carrier that silently resized itself would reintroduce the "ends disagree
// without either noticing" defect the claim exchange exists to prevent.
//
// PLATFORM SCOPE. Linux and Android only, which is where the carriers this
// closes actually bite (Android handsets, Linux clients, the gateway). Darwin,
// Windows and the BSDs compile the no-op in pmtud_other.go: on those platforms
// a connected UDP socket does not surface a per-socket discovered MTU through a
// portable getsockopt, and guessing one would be worse than reporting none.
// EnablePathMTUDiscovery returns false there and DiscoveredPathMTU stays zero,
// which every caller already treats as "no measurement".

// ErrPathMTUReduced is returned by Send and SendBatch when the kernel refused a
// datagram because the path is narrower than the carrier's configured ceiling.
//
// It is NOT fatal to the carrier. The socket is fine, the peer is fine, and the
// very next smaller message will go out. It is a signal with a number attached:
// the caller should read DiscoveredPathMTU, shrink, and resume. Treating it as
// a dead carrier would tear down a working tunnel for a recoverable reason.
var ErrPathMTUReduced = errors.New(
	"winn3/carrier: the path is narrower than this carrier's message ceiling")

// pathMTUState is the carrier's measurement, kept in an atomic rather than
// under u.mu because Send reads it on the hot path and a failed send already
// holds no lock at the point it needs the number.
type pathMTUState struct {
	// discovered is the most recent kernel path-MTU reading, in bytes. Zero
	// means "never measured", which is distinct from "measured and wide".
	discovered atomic.Int64
	// enabled records whether the setsockopt succeeded, so DiscoveredPathMTU
	// can never report a number from a socket that was not asked to measure.
	enabled atomic.Bool
}

func (p *pathMTUState) record(mtu int) {
	if mtu > 0 {
		p.discovered.Store(int64(mtu))
	}
}

func (p *pathMTUState) read() int {
	if !p.enabled.Load() {
		return 0
	}
	return int(p.discovered.Load())
}

// EnablePathMTUDiscovery asks the kernel to perform path-MTU discovery on this
// carrier's socket and reports whether the kernel accepted.
//
// Calling it more than once is safe and idempotent. A false return is not an
// error the caller must handle: it means this platform or this socket does not
// offer the measurement, and the carrier continues exactly as it did before.
func (u *UDP) EnablePathMTUDiscovery() bool {
	if u == nil || u.conn == nil {
		return false
	}
	if err := enableUDPPathMTUDiscovery(u.conn); err != nil {
		return false
	}
	u.pathMTU.enabled.Store(true)
	// Seed with whatever the kernel already believes, so a caller that asks
	// before the first oversized send still gets the interface MTU rather than
	// a zero that reads as "never measured".
	if mtu, err := udpKernelPathMTU(u.conn); err == nil {
		u.pathMTU.record(mtu)
	}
	return true
}

// DiscoveredPathMTU is the kernel's current path-MTU reading for this carrier's
// socket, in bytes, or zero when there is no measurement.
//
// Zero is the honest answer on every platform without the measurement and on
// every socket that was never asked for it. A caller must treat zero as "no
// information" and keep its configured plan, never as "the path is 0 bytes".
func (u *UDP) DiscoveredPathMTU() int {
	if u == nil {
		return 0
	}
	return u.pathMTU.read()
}

func pathMTUExplainsDatagram(mtu, msgLen int) bool {
	return mtu > 0 && msgLen > 0 && mtu < msgLen
}

// notePathMTUSendFailure converts a send error into ErrPathMTUReduced when the
// kernel refused the datagram for being larger than the discovered path, and
// returns the original error otherwise.
//
// The kernel reports this as EMSGSIZE. That code is also what a send larger
// than the socket's send buffer produces on some platforms, which is why the
// discovered MTU is read back before the error is reclassified: a reading that
// is both present and smaller than the message is what distinguishes a genuine
// path narrowing from every other EMSGSIZE.
func (u *UDP) notePathMTUSendFailure(msgLen int, err error) error {
	if err == nil || !u.pathMTU.enabled.Load() {
		return err
	}
	if !isPathMTUExceeded(err) {
		return err
	}
	mtu, readErr := udpKernelPathMTU(u.conn)
	if readErr == nil {
		u.pathMTU.record(mtu)
	}
	current := u.pathMTU.read()
	if !pathMTUExplainsDatagram(current, msgLen) {
		return err
	}
	return wrap(ErrPathMTUReduced,
		"%d-byte datagram refused, kernel path MTU is %d", msgLen, current)
}
