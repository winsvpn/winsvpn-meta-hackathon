package tun

import (
	"context"
	"errors"
	"sync/atomic"
)

// ErrDeviceWrite wraps a failure reported by the host device itself, so that a
// host problem is counted apart from a packet problem.
var ErrDeviceWrite = errors.New("winn3/tun: host device rejected the write")

// Config is everything a Tunnel needs. Every field that touches the outside
// world is an interface, which is why this package has no build tags, no
// platform files and no test that has to open anything.
type Config struct {
	// AcceptTransit makes this tunnel accept inner packets whose destination is
	// NOT its own assigned address, counting them as delivered instead of
	// rejecting them with ErrNotForUs.
	//
	// It exists for one job: a lab responder that terminates a client's
	// FULL-TUNNEL traffic. A client configured with AllowedIPs 0.0.0.0/0 sends
	// every packet to an internet destination, never to the responder's own
	// inner address, so a strict endpoint rejects 100% of them. Measured
	// 2026-08-11: the first standalone iOS carriage produced rx_offered 50,
	// rx_packets 0, rx_dropped_invalid 50 for exactly this reason, and the
	// promotion predicate (RxPackets > 0) could never converge.
	//
	// DEFAULT FALSE, and it must stay false for any real tunnel endpoint: the
	// dst check is what stops a peer injecting packets addressed to someone
	// else into this host. Martian, family and reflection checks still apply
	// when this is set; only the "is it addressed to me" test is relaxed.
	AcceptTransit bool

	// Assign is the inner address authority. Required.
	Assign Assignment

	// Device is the host's tun interface. Required.
	Device Device

	// Sink is the frame-level session driver. Required.
	Sink FrameSink

	// Clock drives the path-MTU rate limiter and nothing else. Required —
	// there is deliberately no fallback to time.Now(), because a package that
	// can reach the wall clock when its Clock is nil is a package whose tests
	// are not deterministic on the one path that matters least and the one
	// that matters most alike.
	Clock Clock

	// Gate is the fail-closed authority. Nil means New allocates a fresh one,
	// which starts closed.
	Gate *Gate

	// CarrierFloorMessageSize is the SMALLEST Carrier.MaxMessageSize() across
	// every carrier class this session is permitted to migrate to — not the
	// one it happened to dial.
	//
	// The design (§5.4) makes carrier migration free: a session survives a move
	// from a UDP carrier to a TLS-over-TCP carrier without re-handshaking,
	// which is the structural answer to a censor who blocks UDP wholesale. But
	// the two carriers do not have the same maximum message size, and the inner
	// MTU is baked into the host's interface configuration at start. Size the
	// inner MTU to the carrier in use and the first failover silently black
	// holes every full-size flow — the tunnel stays "up", small packets keep
	// working, and large transfers stall. Size it to the floor and failover
	// costs a dial, exactly as designed.
	CarrierFloorMessageSize int

	// ICMPPerSecond and ICMPBurst bound synthesised path-MTU signals. Zero
	// means the defaults.
	ICMPPerSecond int
	ICMPBurst     int

	// DisablePMTUSignal drops oversize packets silently instead of telling the
	// local stack why. Off by default: without the signal, a TCP flow with DF
	// set stalls at the first full-size segment and never recovers.
	DisablePMTUSignal bool
}

// Stats is a snapshot of the tunnel's counters.
//
// The names say WHERE the count is taken, because that is the part that goes
// wrong. DeviceReads counts what the host handed us; TxPackets counts what the
// session accepted. On a slow host those two differ, and a health check that
// confuses them tears down a working tunnel.
type Stats struct {
	// DeviceReads counts successful reads from the host device, before any
	// validation at all.
	DeviceReads uint64

	// TxPackets and TxBytes count packets the session ACCEPTED. Incremented
	// after SendData returns nil, never on the read.
	TxPackets uint64
	TxBytes   uint64

	// TxDroppedClosed counts packets refused because the gate was not open.
	// This is the fail-closed counter and it is the one to watch.
	TxDroppedClosed  uint64
	TxDroppedInvalid uint64

	// Why TxDroppedInvalid moved. These sum to it, and their DIFFERENCE is the
	// diagnosis: TxDropSourceNotOurs dominating means the host is emitting a
	// source this session was never assigned (the deanonymisation refusal);
	// TxDropFamilyOff means one address family is unassigned; TxDropMartian
	// means a forbidden address tried to leave; TxDropMalformed means the
	// bytes were not a packet.
	//
	// Four reasons, not five: the inbound split has ErrNotForUs and
	// ErrReflected, which outbound cannot return. ErrSourceNotOurs is the
	// outbound analogue of NotForUs. Added 2026-08-12 so an operator is not
	// left staring at tx_dropped_invalid the way the 2026-08-11 iOS carry
	// left them staring at rx_dropped_invalid 50.
	TxDropFamilyOff     uint64
	TxDropMartian       uint64
	TxDropSourceNotOurs uint64
	TxDropMalformed     uint64

	TxDroppedOversize uint64
	TxDroppedSink     uint64
	TxTruncatedTail   uint64

	// RxOffered counts payloads handed to Inbound — arrivals, not deliveries.
	RxOffered uint64

	// RxPackets and RxBytes count packets DELIVERED to the host, and delivery
	// takes TWO facts, not one: the device write returned success, and the
	// device has been proven to have a host on the other end of it.
	//
	// The second fact is here because the first does not imply it on every
	// backend, and the difference is not academic. cmd/winn-datapath's
	// loopback-udp seam writes with an unconnected sendto to 127.0.0.1:
	// host_port. A sendto to a port nobody is bound to returns the full byte
	// count with no error — measured on darwin/arm64 on 2026-08-09, five writes
	// to a closed loopback port, five times n=60 err=nil. The ICMP port
	// unreachable the stack does generate is only ever matched to a socket with
	// a four-tuple, so an unconnected socket never sees it, and nothing in this
	// tree sets IP_RECVERR or reads MSG_ERRQUEUE. A wrong host_port therefore
	// produced a successful write, a credited RxPackets and a true
	// promotion_ready on a tunnel that had moved nothing — the host installing
	// a default route into a void while the app said "connected". Connecting the
	// socket does not fix it either: measured on the same host, a connected
	// socket's FIRST write to a dead port also succeeded and only the SECOND
	// reported ECONNREFUSED, and the reference promotion is RxPackets:1.
	//
	// So a write is not evidence. DeviceProven is, and RxPackets is the
	// conjunction. See DeviceProven for what proves it.
	RxPackets uint64
	RxBytes   uint64

	// RxDeviceWrites and RxDeviceWriteBytes count what was written to the
	// device whether or not anything was there to receive it. They are the
	// ungated truth behind RxPackets, and they are published rather than kept
	// private because their DIFFERENCE is the diagnosis:
	//
	//	RxDeviceWrites > 0 && RxPackets == 0 && !DeviceProven
	//
	// reads as "inner packets are being written to a host device that has never
	// spoken", which is a misconfigured seam and not a censored path. Without
	// them the fix would be silent, and a counter that stops moving with no
	// counter that says why is how the last three of these were missed.
	RxDeviceWrites     uint64
	RxDeviceWriteBytes uint64

	// DeviceProven reports whether anything has ever come OUT of the host
	// device — DeviceReads > 0.
	//
	// That is the evidence a write into a void cannot manufacture, and it is the
	// only such evidence this package has. It is sound for the backend that
	// needs it: the loopback seam delivers a read only from the pinned peer
	// 127.0.0.1:host_port, so the same wrong port that makes the write vacuous
	// makes the read impossible, and a read requires somebody to have actually
	// sent. It is honest for the others: a read from a tun descriptor means the
	// kernel put a packet on that interface.
	//
	// It latches. DeviceReads never decreases, so a tunnel cannot become
	// unproven, and RxPackets cannot go backwards.
	DeviceProven bool

	RxDroppedClosed  uint64
	RxDroppedInvalid uint64

	// Why RxDroppedInvalid moved. These sum to it, and their DIFFERENCE is the
	// diagnosis: RxDropNotForUs dominating means the far end is being asked to
	// be the destination of full-tunnel traffic rather than a next hop;
	// RxDropFamilyOff means one address family is unassigned.
	RxDropFamilyOff   uint64
	RxDropMartian     uint64
	RxDropNotForUs    uint64
	RxDropReflected   uint64
	RxDropMalformed   uint64
	RxDroppedOversize uint64
	RxDroppedDevice   uint64
	RxTruncatedTail   uint64

	// PMTUSignals counts synthesised path-MTU packets delivered inward.
	// PMTUSuppressed counts the ones the rate limiter, the missing router
	// address or a device error prevented.
	PMTUSignals    uint64
	PMTUSuppressed uint64
}

type counters struct {
	deviceReads atomic.Uint64

	txPackets        atomic.Uint64
	txBytes          atomic.Uint64
	txDroppedClosed  atomic.Uint64
	txDroppedInvalid atomic.Uint64
	// Per-reason breakdown of txDroppedInvalid. Mirror of the rxDrop* split:
	// the total still moves exactly as it did; these say WHICH outbound
	// validator check fired. They must sum to txDroppedInvalid.
	txDropFamilyOff     atomic.Uint64
	txDropMartian       atomic.Uint64
	txDropSourceNotOurs atomic.Uint64
	txDropMalformed     atomic.Uint64
	txDroppedOversize   atomic.Uint64
	txDroppedSink       atomic.Uint64
	txTruncatedTail     atomic.Uint64

	rxOffered atomic.Uint64

	// rxDeviceWrites and rxDeviceWriteBytes are what Inbound credits. Stats
	// decides whether they may be reported as DELIVERIES; the write path itself
	// is unchanged and still writes every packet, because dropping a packet the
	// device accepted would trade one silent failure for another.
	rxDeviceWrites     atomic.Uint64
	rxDeviceWriteBytes atomic.Uint64

	rxDroppedClosed  atomic.Uint64
	rxDroppedInvalid atomic.Uint64
	// Per-reason breakdown of rxDroppedInvalid. Added 2026-08-11 after an iOS
	// investigation spent hours on "rx_offered 50 / rx_packets 0 /
	// rx_dropped_invalid 50" with no way to tell WHICH of five distinct
	// rejections was firing. A counter that stops moving with no counter that
	// says why is how the last three of these were missed.
	rxDropFamilyOff   atomic.Uint64
	rxDropMartian     atomic.Uint64
	rxDropNotForUs    atomic.Uint64
	rxDropReflected   atomic.Uint64
	rxDropMalformed   atomic.Uint64
	rxDroppedOversize atomic.Uint64
	rxDroppedDevice   atomic.Uint64
	rxTruncatedTail   atomic.Uint64

	pmtuSignals    atomic.Uint64
	pmtuSuppressed atomic.Uint64
}

// Tunnel is the inner-IP layer for one session.
type Tunnel struct {
	v        validator
	dev      Device
	sink     FrameSink
	clock    Clock
	gate     *Gate
	innerMTU int
	devMTU   int
	pmtu     *tokenBucket
	noPMTU   bool
	c        counters
}

// New validates a configuration and returns a tunnel whose gate is closed.
//
// Everything that could make the tunnel silently wrong later is refused here
// instead: an inner MTU too small for the family being carried, a device MTU
// larger than the carrier can move, a router address that the tunnel's own
// inbound rules would reject. A tunnel that starts and then drops everything
// is much harder to diagnose from Yangon than a start that says why.
func New(cfg Config) (*Tunnel, error) {
	if cfg.Device == nil {
		return nil, errWrap(ErrConfig, "no device")
	}
	if cfg.Sink == nil {
		return nil, errWrap(ErrConfig, "no frame sink")
	}
	if cfg.Clock == nil {
		return nil, errWrap(ErrConfig, "no clock")
	}
	if err := cfg.Assign.validate(); err != nil {
		return nil, err
	}
	if cfg.Assign.RouterV4.IsValid() {
		if reason := martianReason(cfg.Assign.RouterV4); reason != "" {
			return nil, errWrap(ErrConfig, "IPv4 router address is unusable: %s", reason)
		}
		if cfg.Assign.RouterV4 == cfg.Assign.V4 {
			return nil, errWrap(ErrConfig, "IPv4 router address equals the assigned address")
		}
	}
	if cfg.Assign.RouterV6.IsValid() {
		if reason := martianReason(cfg.Assign.RouterV6); reason != "" {
			return nil, errWrap(ErrConfig, "IPv6 router address is unusable: %s", reason)
		}
		if cfg.Assign.RouterV6 == cfg.Assign.V6 {
			return nil, errWrap(ErrConfig, "IPv6 router address equals the assigned address")
		}
	}

	if cfg.CarrierFloorMessageSize <= Overhead() {
		return nil, errWrap(ErrConfig,
			"carrier floor message size %d leaves nothing after the %d-byte per-packet overhead",
			cfg.CarrierFloorMessageSize, Overhead())
	}
	innerMTU := InnerMTU(cfg.CarrierFloorMessageSize)
	if innerMTU < MinInnerMTUv4 {
		return nil, errWrap(ErrConfig,
			"carrier floor message size %d yields an inner MTU of %d, below the %d-byte IPv4 floor",
			cfg.CarrierFloorMessageSize, innerMTU, MinInnerMTUv4)
	}
	if cfg.Assign.hasV6() && innerMTU < IPv6MinLinkMTU {
		// Refusing is the honest option. IPv6 forbids in-network fragmentation
		// and requires every link to convey 1280 octets; a tunnel that installs
		// an inner IPv6 route on a narrower link has built a black hole that
		// looks exactly like working IPv6 until something sends a full-size
		// packet.
		return nil, errWrap(ErrConfig,
			"inner IPv6 is assigned but the inner MTU is %d, below the %d-byte IPv6 minimum; a carrier floor of at least %d is required",
			innerMTU, IPv6MinLinkMTU, MinCarrierMessageForIPv6())
	}

	devMTU := cfg.Device.MTU()
	if devMTU <= 0 {
		return nil, errWrap(ErrConfig, "device reports an MTU of %d", devMTU)
	}
	if devMTU > innerMTU {
		return nil, errWrap(ErrConfig,
			"device MTU %d exceeds the %d-byte inner MTU; the host would generate packets this tunnel can only drop",
			devMTU, innerMTU)
	}
	if devMTU < MinInnerMTUv4 {
		return nil, errWrap(ErrConfig, "device MTU %d is below the %d-byte IPv4 floor", devMTU, MinInnerMTUv4)
	}
	if cfg.Assign.hasV6() && devMTU < IPv6MinLinkMTU {
		return nil, errWrap(ErrConfig,
			"device MTU %d is below the %d-byte IPv6 minimum while inner IPv6 is assigned",
			devMTU, IPv6MinLinkMTU)
	}

	perSec, burst := cfg.ICMPPerSecond, cfg.ICMPBurst
	if perSec <= 0 {
		perSec = DefaultICMPPerSecond
	}
	if burst <= 0 {
		burst = DefaultICMPBurst
	}

	gate := cfg.Gate
	if gate == nil {
		gate = NewGate()
	}

	return &Tunnel{
		v:        validator{assign: cfg.Assign, acceptTransit: cfg.AcceptTransit},
		dev:      cfg.Device,
		sink:     cfg.Sink,
		clock:    cfg.Clock,
		gate:     gate,
		innerMTU: innerMTU,
		devMTU:   devMTU,
		pmtu:     newTokenBucket(perSec, burst),
		noPMTU:   cfg.DisablePMTUSignal,
	}, nil
}

// Gate returns the fail-closed authority. The session driver owns it and is
// the only thing that should call Set.
func (t *Tunnel) Gate() *Gate { return t.gate }

// SetState is sugar for t.Gate().Set. Like Gate.Set it does not return until
// every in-flight packet has drained.
func (t *Tunnel) SetState(s State) { t.gate.Set(s) }

// InnerMTU is the largest inner packet this tunnel carries, and the value the
// host must configure on the interface.
func (t *Tunnel) InnerMTU() int { return t.innerMTU }

// DeviceMTU is what the host actually configured. It is never larger than
// InnerMTU; New refuses that configuration.
func (t *Tunnel) DeviceMTU() int { return t.devMTU }

// ClampInnerMTU lowers the tunnel's inner MTU, and the host device MTU, to n.
//
// It exists for silent-refusal instance #3's apply half: after the handshake
// names a narrower peer path MTU, the session shrinks MaxMessageSize and the
// loop must re-clamp the tun before the gate opens. Raising is refused.
// Calling this while the gate is carrying is refused, because that is the
// window in which the host is already generating packets at the old MTU.
//
// The carrying check takes the gate write lock (see Gate.exclude), so it
// drains in-flight packets and cannot race Set: a concurrent Set(StateCarrying)
// waits until the clamp has either finished or refused. Reading State() and
// then mutating innerMTU without that lock is the window that would recreate
// the construction-time black hole New already refuses (device MTU > inner MTU
// under live traffic).
//
// The device must implement MTUSetter. A device that cannot change its MTU
// leaves the mismatch as a loud refusal one layer up; clamping innerMTU
// alone would recreate the construction-time black hole New already refuses
// (device MTU > inner MTU).
func (t *Tunnel) ClampInnerMTU(n int) error {
	state, unlock := t.gate.exclude()
	defer unlock()
	if state.MayCarry() {
		return errWrap(ErrConfig, "cannot clamp inner MTU while the gate is carrying")
	}
	if n > t.innerMTU {
		return errWrap(ErrConfig, "cannot raise inner MTU from %d to %d", t.innerMTU, n)
	}
	if n == t.innerMTU {
		return nil
	}
	if n < MinInnerMTUv4 {
		return errWrap(ErrConfig, "inner MTU %d is below the %d-byte IPv4 floor", n, MinInnerMTUv4)
	}
	if t.v.assign.hasV6() && n < IPv6MinLinkMTU {
		return errWrap(ErrConfig,
			"inner IPv6 is assigned but inner MTU %d is below the %d-byte IPv6 minimum",
			n, IPv6MinLinkMTU)
	}
	setter, ok := t.dev.(MTUSetter)
	if !ok {
		return errWrap(ErrConfig, "the host device cannot re-apply its MTU after the handshake")
	}
	if err := setter.SetMTU(n); err != nil {
		return errWrap(ErrConfig, "device SetMTU(%d): %v", n, err)
	}
	t.innerMTU = n
	t.devMTU = n
	return nil
}

// DeviceProven reports whether the host device has ever produced a packet.
//
// It is the corroborating half of a delivery, and it is derived rather than
// tracked so that it cannot drift from the counter it is derived from. There is
// deliberately no setter: a host that could assert this could re-create the
// false promotion by asserting it.
func (t *Tunnel) DeviceProven() bool { return t.c.deviceReads.Load() > 0 }

// Stats snapshots the counters.
//
// RxPackets and RxBytes are the ONLY reported fields that are not a straight
// read of a counter, and the conditional is the whole of the fix for the false
// promotion: an uncorroborated device write is reported as what it is — a
// write — and never as a delivery. Nothing is lost by waiting. RxDeviceWrites
// keeps counting throughout, so the instant the device is proven RxPackets
// reports every delivery including the ones made before the proof arrived. A
// gateway-side reflector, which by construction can only be read from AFTER it
// has been written to, therefore still reports every packet it took.
func (t *Tunnel) Stats() Stats {
	writes := t.c.rxDeviceWrites.Load()
	writeBytes := t.c.rxDeviceWriteBytes.Load()
	proven := t.DeviceProven()
	var delivered, deliveredBytes uint64
	if proven {
		delivered, deliveredBytes = writes, writeBytes
	}
	return Stats{
		DeviceReads:        t.c.deviceReads.Load(),
		TxPackets:          t.c.txPackets.Load(),
		TxBytes:            t.c.txBytes.Load(),
		TxDroppedClosed:     t.c.txDroppedClosed.Load(),
		TxDroppedInvalid:    t.c.txDroppedInvalid.Load(),
		TxDropFamilyOff:     t.c.txDropFamilyOff.Load(),
		TxDropMartian:       t.c.txDropMartian.Load(),
		TxDropSourceNotOurs: t.c.txDropSourceNotOurs.Load(),
		TxDropMalformed:     t.c.txDropMalformed.Load(),
		TxDroppedOversize:   t.c.txDroppedOversize.Load(),
		TxDroppedSink:      t.c.txDroppedSink.Load(),
		TxTruncatedTail:    t.c.txTruncatedTail.Load(),
		RxOffered:          t.c.rxOffered.Load(),
		RxPackets:          delivered,
		RxBytes:            deliveredBytes,
		RxDeviceWrites:     writes,
		RxDeviceWriteBytes: writeBytes,
		DeviceProven:       proven,

		RxDroppedClosed:   t.c.rxDroppedClosed.Load(),
		RxDroppedInvalid:  t.c.rxDroppedInvalid.Load(),
		RxDropFamilyOff:   t.c.rxDropFamilyOff.Load(),
		RxDropMartian:     t.c.rxDropMartian.Load(),
		RxDropNotForUs:    t.c.rxDropNotForUs.Load(),
		RxDropReflected:   t.c.rxDropReflected.Load(),
		RxDropMalformed:   t.c.rxDropMalformed.Load(),
		RxDroppedOversize: t.c.rxDroppedOversize.Load(),
		RxDroppedDevice:   t.c.rxDroppedDevice.Load(),
		RxTruncatedTail:   t.c.rxTruncatedTail.Load(),
		PMTUSignals:       t.c.pmtuSignals.Load(),
		PMTUSuppressed:    t.c.pmtuSuppressed.Load(),
	}
}

// Outbound moves one inner packet from the host into the tunnel.
//
// The order of the first two steps is the fail-closed property and it is not
// an accident. The gate is taken BEFORE the packet is parsed, before its
// addresses are examined and before anything at all is synthesised — so a
// closed gate produces exactly one observable effect, a counter increment, and
// zero bytes anywhere. Validate-then-gate would have the same return value and
// a path-MTU packet written to the host of a session that no longer exists.
func (t *Tunnel) Outbound(b []byte) error {
	if !t.gate.enter() {
		t.c.txDroppedClosed.Add(1)
		return ErrNotCarrying
	}
	defer t.gate.leave()

	p, err := t.v.outbound(b)
	if err != nil {
		t.countTxDroppedInvalid(err)
		return err
	}
	if p.tail > 0 {
		t.c.txTruncatedTail.Add(1)
	}
	if len(p.body) > t.innerMTU {
		t.c.txDroppedOversize.Add(1)
		t.signalTooBig(p)
		return errWrap(ErrOversize, "inner packet is %d bytes, inner MTU is %d", len(p.body), t.innerMTU)
	}
	if err := t.sink.SendData(p.body); err != nil {
		t.c.txDroppedSink.Add(1)
		return err
	}
	t.c.txPackets.Add(1)
	t.c.txBytes.Add(uint64(len(p.body)))
	return nil
}

// countTxDroppedInvalid records one outbound validator refusal. The total
// TxDroppedInvalid always moves, exactly as it did before the split; the
// per-reason counter says WHICH check fired. These must sum: a total that
// moves with no reason is the iOS rx_dropped_invalid-50 diagnosis again,
// on the way out.
func (t *Tunnel) countTxDroppedInvalid(err error) {
	t.c.txDroppedInvalid.Add(1)
	switch {
	case errors.Is(err, ErrFamilyOff):
		t.c.txDropFamilyOff.Add(1)
	case errors.Is(err, ErrMartian):
		t.c.txDropMartian.Add(1)
	case errors.Is(err, ErrSourceNotOurs):
		t.c.txDropSourceNotOurs.Add(1)
	default:
		t.c.txDropMalformed.Add(1)
	}
}

// Inbound moves one DATA frame's payload from the tunnel to the host.
//
// It still writes every packet it validates, exactly as before. What changed
// with the false-promotion fix is only what the write is COUNTED as: Inbound
// credits RxDeviceWrites, and Stats decides whether that may be reported as a
// delivery. Refusing the write instead would have swapped a tunnel that lies
// about carrying for a tunnel that drops the traffic it is carrying, and on a
// backend where the write really is a delivery — a tun descriptor — the second
// is the worse of the two.
func (t *Tunnel) Inbound(b []byte) error {
	t.c.rxOffered.Add(1)
	if !t.gate.enter() {
		t.c.rxDroppedClosed.Add(1)
		return ErrNotCarrying
	}
	defer t.gate.leave()

	p, err := t.deliver(b)
	if err != nil {
		switch {
		case errors.Is(err, ErrOversize):
			t.c.rxDroppedOversize.Add(1)
		case errors.Is(err, ErrDeviceWrite):
			t.c.rxDroppedDevice.Add(1)
		default:
			t.c.rxDroppedInvalid.Add(1)
			switch {
			case errors.Is(err, ErrFamilyOff):
				t.c.rxDropFamilyOff.Add(1)
			case errors.Is(err, ErrMartian):
				t.c.rxDropMartian.Add(1)
			case errors.Is(err, ErrNotForUs):
				t.c.rxDropNotForUs.Add(1)
			case errors.Is(err, ErrReflected):
				t.c.rxDropReflected.Add(1)
			default:
				t.c.rxDropMalformed.Add(1)
			}
		}
		return err
	}
	if p.tail > 0 {
		t.c.rxTruncatedTail.Add(1)
	}
	// The packet HAS been written. Whether that write was a delivery is a
	// question Stats answers, because the answer can change after this point
	// and this call cannot see it.
	t.c.rxDeviceWrites.Add(1)
	t.c.rxDeviceWriteBytes.Add(uint64(len(p.body)))
	return nil
}

// deliver is the ONLY place in this package that writes to the host device,
// and it validates first, always.
//
// TestDeviceHasExactlyOneWriteSite parses the package's own source and
// requires that to stay true, because the invariant "everything written to the
// host passed the inbound rules" is worth exactly as much as the number of
// call sites that can violate it.
func (t *Tunnel) deliver(b []byte) (packet, error) {
	p, err := t.v.inbound(b)
	if err != nil {
		return packet{}, err
	}
	if len(p.body) > t.devMTU {
		return packet{}, errWrap(ErrOversize, "packet is %d bytes, device MTU is %d", len(p.body), t.devMTU)
	}
	n, err := t.dev.WritePacket(p.body)
	if err != nil {
		return packet{}, errWrap(ErrDeviceWrite, "%v", err)
	}
	if n != len(p.body) {
		return packet{}, errWrap(ErrDeviceWrite, "wrote %d of %d bytes", n, len(p.body))
	}
	return p, nil
}

// signalTooBig tells the local stack why an oversize packet did not travel.
//
// Inward only. The packet it builds is addressed to the host's own inner
// address and passes the same inbound rules every other delivered packet
// passes — which is what keeps it from being an exception to the no-forwarding
// property rather than an instance of it.
func (t *Tunnel) signalTooBig(p packet) {
	if t.noPMTU {
		t.c.pmtuSuppressed.Add(1)
		return
	}
	msg := synthesiseTooBig(p, t.innerMTU, t.v.assign)
	if msg == nil {
		t.c.pmtuSuppressed.Add(1)
		return
	}
	if !t.pmtu.allow(t.clock.Now()) {
		t.c.pmtuSuppressed.Add(1)
		return
	}
	if _, err := t.deliver(msg); err != nil {
		t.c.pmtuSuppressed.Add(1)
		return
	}
	t.c.pmtuSignals.Add(1)
}

// PumpOutbound reads from the device and moves packets into the tunnel until
// ctx is cancelled or the device returns an error.
//
// A packet-level failure — malformed, wrong source, oversize, refused by the
// session — is counted and the loop continues. Only a device failure stops it.
// A tunnel that dies because one application emitted one bad packet is a
// tunnel that a hostile network can kill by injecting one.
//
// The context is checked between reads. ReadPacket blocks, so cancellation
// takes effect on the next packet or when the host closes the device; the host
// owns that lifecycle, which is why there is no Close here to call.
func (t *Tunnel) PumpOutbound(ctx context.Context) error {
	batchDev, hasBatchDev := t.dev.(BatchDevice)
	batchSink, hasBatchSink := t.sink.(BatchFrameSink)
	if hasBatchDev && hasBatchSink {
		return t.pumpOutboundBatch(ctx, batchDev, batchSink)
	}
	buf := make([]byte, MaxIPPacket)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := t.dev.ReadPacket(buf)
		if err != nil {
			return err
		}
		// This is the one place a host device proves it exists, and therefore
		// the one place DeviceProven can become true. It is credited on the
		// READ succeeding and before any validation, deliberately: the weakest
		// possible requirement is the one least likely to hold a working
		// tunnel shut. A malformed packet from the host still proves a host.
		t.c.deviceReads.Add(1)
		if n <= 0 {
			continue
		}
		if n > len(buf) {
			// A device that reports more than it copied is a device bug;
			// trusting n would read past the buffer. Counted as malformed
			// so the per-reason split still sums to TxDroppedInvalid.
			t.countTxDroppedInvalid(ErrBadHeader)
			continue
		}
		_ = t.Outbound(buf[:n])
	}
}

func (t *Tunnel) pumpOutboundBatch(ctx context.Context, bDev BatchDevice, bSink BatchFrameSink) error {
	const batchSize = 256
	bufs := make([][]byte, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, MaxIPPacket)
	}
	outPackets := make([][]byte, 0, batchSize)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		lengths, err := bDev.ReadBatch(bufs)
		if err != nil {
			return err
		}
		if len(lengths) == 0 {
			continue
		}
		t.c.deviceReads.Add(uint64(len(lengths)))

		if !t.gate.enter() {
			t.c.txDroppedClosed.Add(uint64(len(lengths)))
			continue
		}

		outPackets = outPackets[:0]
		for i, n := range lengths {
			if n <= 0 {
				continue
			}
			if i >= len(bufs) || n > len(bufs[i]) {
				// A device that reports more slots or bytes than it was
				// given is a device bug, as in the scalar pump: count it,
				// never index past the buffers.
				t.countTxDroppedInvalid(ErrBadHeader)
				continue
			}
			p, vErr := t.v.outbound(bufs[i][:n])
			if vErr != nil {
				t.countTxDroppedInvalid(vErr)
				continue
			}
			if p.tail > 0 {
				t.c.txTruncatedTail.Add(1)
			}
			if len(p.body) > t.innerMTU {
				t.c.txDroppedOversize.Add(1)
				t.signalTooBig(p)
				continue
			}
			outPackets = append(outPackets, p.body)
		}

		if len(outPackets) > 0 {
			sent, sErr := bSink.SendDataBatch(outPackets)
			if sErr != nil {
				t.c.txDroppedSink.Add(uint64(len(outPackets) - sent))
			}
			if sent > 0 {
				var totalBytes uint64
				for i := 0; i < sent; i++ {
					totalBytes += uint64(len(outPackets[i]))
				}
				t.c.txPackets.Add(uint64(sent))
				t.c.txBytes.Add(totalBytes)
			}
		}
		t.gate.leave()
	}
}
