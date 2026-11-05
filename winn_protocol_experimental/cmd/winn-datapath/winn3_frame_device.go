package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/winn3/tun"
)

var packetPool = sync.Pool{
	New: func() any {
		var b [2048]byte
		return &b
	},
}

// The frame-channel inner-packet device.
//
// This is the seam WINN3_ANDROID_INTEGRATION_20260808.md §7 item 3 asks for: a
// tun.Device whose two ends are the duplex Inbound and Outbound frames rather
// than a file descriptor.
//
//	host writes  OpInbound  -> offer()  -> ReadPacket() -> the session encrypts
//	host reads   OpOutbound <- take()   <- WritePacket() <- the session decrypted
//
// # Why the host owns the device and not the engine
//
// Android has no API to change the routes, MTU or resolvers of a live
// VpnService: the only mechanism is Builder.establish() again, which yields a
// NEW descriptor. The staged posture therefore replaces the tun descriptor at
// exactly the moment the tunnel starts carrying — and tun.Config.Device is read
// once, in tun.New, with no way to swap it afterwards. A descriptor handed to
// this process at create time goes stale precisely when it starts mattering.
//
// A channel-backed device has no such identity. The host closes one file stream
// and opens another under it; the engine's Device never changes and PumpOutbound
// is never unblocked by a promotion it should not have noticed. Measured on the
// emulator as bootstrap fd=84 -> promoted fd=102.
//
// # Why the desktop hosts get the same seam and not a different one
//
// Linux and Windows CAN pass a descriptor, and the sibling loopback-udp and
// tun-fd backends in this package exist for them. They are optimisations, not a
// different contract: every host that speaks the frame channel — which is every
// host that already runs this binary — can drive v3 with no descriptor
// arrangement at all, and Windows in particular gets an inner-packet path with
// no second socket in it. Where a platform can pass a tun descriptor it should;
// where it cannot, this is not a fallback but the same seam.
//
// # What crosses it, and the direction that would be a leak
//
// RAW INNER IP PACKETS, starting at the version nibble, one per frame. That is
// the inversion: the winn/1 path pumps AmneziaWG OUTER datagrams over these same
// two opcodes because datapath/ has no WireGuard in it and would forward tun
// packets to the gateway in cleartext, so datapath.Config refuses
// payload:"ip-packet" at create time. winn3/core IS the crypto and winn3/tun IS
// the inner-IP validator, so here ip-packet is the only correct payload and
// awg-datagram is the refusal. A host that wires the two backwards either sends
// cleartext (v1 engine, inner packets) or double-encrypts (v3 engine, AWG
// datagrams) — so the payload class is checked before anything else about the
// transport, in winn3CreateDocument.decode.

// winn3FrameQueueDepth is a quarter second of a saturated gigabit link at the
// inner MTU, rounded to a power of two. Deep enough that a scheduling hiccup on
// either side does not drop; shallow enough that a stalled side cannot grow the
// process by more than a few megabytes.
//
// The same number as cdatapath's abiDevice, deliberately: two host seams with
// two different queue depths would produce two different loss profiles for the
// same protocol, and the first bug report would be unreproducible on the other.
const winn3FrameQueueDepth = 65536

// errWinn3DeviceClosed is what both ends return once the device is closed, so
// that tun.PumpOutbound unwinds instead of spinning and a host parked in the
// outbound pump wakes rather than hanging.
var errWinn3DeviceClosed = errors.New("winn3: the frame device is closed")

// winn3FrameDevice is a tun.Device backed by the duplex frame channel.
//
// Both queues are bounded, and the two directions drop DIFFERENTLY under
// pressure, because they carry different things.
//
// toHost drops the OLDEST. A datapath that drops the newest delivers a stale
// burst when the slow side wakes up; dropping the oldest keeps the queue
// current, which is what inner TCP recovers from best.
//
// toEngine drops the NEWEST, which is plain tail drop. This queue carries the
// uplink, an in-order inner TCP stream on its way out. Removing its HEAD
// deletes the lowest unacknowledged sequence number, and the receiver can no
// longer describe the hole with a SACK block, so the sender has to wait out an
// RTO instead: cwnd collapses to one, slow-starts back up, hits the same full
// queue and collapses again. Measured on a Samsung Galaxy S26 Ultra against the
// Canada gateway, the uplink sat between 21.5 and 255 Mbps with exactly that
// variance, while the same handset with no VPN did 1652.9 Mbps up. Tail drop
// leaves the head intact, so the loss is reported by a SACK and the sender
// recovers by fast retransmit with cwnd merely halved.
//
// Drops are counted in both directions so the silence is never unexplained.
type winn3FrameDevice struct {
	mtu int

	// toEngine is what the host offered and the tun layer has not yet read.
	// toHost is what the tun layer delivered and the host has not yet taken.
	toEngine *toEngineRing
	toHost   chan []byte

	// offerScratch and readPackets are reused across calls following the
	// single-producer (serve) and single-consumer (pumpOutboundBatch) contract.
	offerScratch [][]byte
	readPackets  [][]byte

	closed chan struct{}
	once   atomic.Bool

	// readMu is held for the whole of every tun-side read, including the wait
	// for a packet. retireReader takes it after Close to join a reader that was
	// parked inside, so a supervisor can prove the round's reader has left the
	// device before it publishes a successor. Uncontended except at that join:
	// the tun layer has exactly one reader.
	readMu sync.Mutex

	droppedToEngine atomic.Uint64
	droppedToHost   atomic.Uint64
	oversize        atomic.Uint64

	// The downlink queue census. hostHighWater is the deepest toHost has been,
	// raised after every WritePacket. The four host write
	// counters are the frame pump's: batches and packets handed to the host
	// channel, the time spent in those writes including the flush, and the
	// longest single write. A host that reads slowly shows up as write time,
	// and as a high-water mark climbing toward winn3FrameQueueDepth, long
	// before it shows up as droppedToHost. Telemetry only: nothing reads them
	// to decide anything.
	hostHighWater     atomic.Uint64
	hostWriteBatches  atomic.Uint64
	hostWritePackets  atomic.Uint64
	hostWriteNanos    atomic.Uint64
	hostWriteMaxNanos atomic.Uint64

	readLengths []int
}

// winn3FrameTelemetry is one snapshot of the frame device's queue census.
type winn3FrameTelemetry struct {
	HostQueueDepth       uint64
	HostQueueHighWater   uint64
	DroppedToHost        uint64
	HostWriteBatches     uint64
	HostWritePackets     uint64
	HostWriteNanos       uint64
	HostWriteMaxNanos    uint64
	EngineQueueDepth     uint64
	EngineQueueHighWater uint64
	DroppedToEngine      uint64
	Ring                 RingTelemetry
}

// telemetry snapshots the census. Each counter is read once, without a common
// lock, so two fields may straddle one packet; every field is monotone except
// the two depths, which are instants.
func (d *winn3FrameDevice) telemetry() winn3FrameTelemetry {
	ring := d.toEngine.Telemetry()
	return winn3FrameTelemetry{
		HostQueueDepth:       uint64(len(d.toHost)),
		HostQueueHighWater:   d.hostHighWater.Load(),
		DroppedToHost:        d.droppedToHost.Load(),
		HostWriteBatches:     d.hostWriteBatches.Load(),
		HostWritePackets:     d.hostWritePackets.Load(),
		HostWriteNanos:       d.hostWriteNanos.Load(),
		HostWriteMaxNanos:    d.hostWriteMaxNanos.Load(),
		EngineQueueDepth:     uint64(d.toEngine.depth()),
		EngineQueueHighWater: ring.HighWater,
		DroppedToEngine:      d.droppedToEngine.Load(),
		Ring:                 ring,
	}
}

// noteHostWrite records one frame-pump write of packets to the host.
func (d *winn3FrameDevice) noteHostWrite(packets int, elapsed time.Duration) {
	ns := uint64(0)
	if elapsed > 0 {
		ns = uint64(elapsed)
	}
	d.hostWriteBatches.Add(1)
	d.hostWritePackets.Add(uint64(packets))
	d.hostWriteNanos.Add(ns)
	winn3RaiseTo(&d.hostWriteMaxNanos, ns)
}

// winn3RaiseTo raises *mark to value if value is larger. The compare and swap
// loop keeps a mark monotone however many goroutines raise it, so no census
// field depends on a single-writer argument about its callers.
func winn3RaiseTo(mark *atomic.Uint64, value uint64) {
	for {
		current := mark.Load()
		if value <= current || mark.CompareAndSwap(current, value) {
			return
		}
	}
}

// newWinn3FrameDevice builds the device at the inner MTU the host declared.
//
// The MTU is an obligation on the host, not a measurement of it: this device
// has no interface to read back. tun.New checks it against the tunnel's own
// inner MTU, and winn3CreateDocument refuses a disagreement in either
// direction before we ever get here, which is where that check belongs.
func newWinn3FrameDevice(mtu int) (*winn3FrameDevice, error) {
	if mtu <= 0 {
		return nil, fmt.Errorf("frame device: mtu %d is not usable", mtu)
	}
	return &winn3FrameDevice{
		mtu:          mtu,
		toEngine:     newToEngineRing(winn3FrameQueueDepth),
		toHost:       make(chan []byte, winn3FrameQueueDepth),
		offerScratch: make([][]byte, 0, winn3RingPushBatch),
		readPackets:  make([][]byte, 0, winn3RingPopBatch),
		closed:       make(chan struct{}),
	}, nil
}

// MTU reports the inner MTU the host is required to have configured.
func (d *winn3FrameDevice) MTU() int { return d.mtu }

// offer is the OpInbound side: the host hands one inner IP packet in.
//
// It never blocks. A host that outruns the session must not be able to stall
// the frame reader, because the frame reader is also how Close arrives.
func (d *winn3FrameDevice) offer(packet []byte) error {
	if d.isClosed() {
		return errWinn3DeviceClosed
	}
	// Bounded here as well as by the tun layer's own validator. The frame
	// channel's MaxPayload is 65535 and the inner MTU is around 1.2 kB, so an
	// oversize frame is a host bug or a hostile local peer; counting it and
	// dropping it keeps the tun layer's invalid counter meaning "a packet that
	// failed IP validation" rather than "the host sent something absurd".
	if len(packet) > d.mtu {
		d.oversize.Add(1)
		return nil
	}
	var cp []byte
	if len(packet) <= 2048 {
		bp := packetPool.Get().(*[2048]byte)
		cp = bp[:len(packet)]
	} else {
		cp = make([]byte, len(packet))
	}
	copy(cp, packet)
	// Tail drop on the uplink: never remove the head of an in-order stream.
	accepted, open := d.toEngine.pushOne(cp)
	if !open {
		d.recycle(cp)
		return errWinn3DeviceClosed
	}
	if !accepted {
		d.droppedToEngine.Add(1)
		d.recycle(cp)
	}
	return nil
}

// offerBatch is the batched OpInbound side: the host hands multiple inner IP packets in.
// Packets in the slice are already allocated from packetPool and copied.
func (d *winn3FrameDevice) offerBatch(packets [][]byte) error {
	if d.isClosed() {
		for _, pkt := range packets {
			d.recycle(pkt)
		}
		return errWinn3DeviceClosed
	}
	valid := d.offerScratch[:0]
	for _, pkt := range packets {
		if len(pkt) > d.mtu {
			d.oversize.Add(1)
			d.recycle(pkt)
			continue
		}
		valid = append(valid, pkt)
	}

	accepted, open := d.toEngine.pushBatch(valid)
	if !open {
		for _, pkt := range valid {
			d.recycle(pkt)
		}
		d.releaseOfferScratch(valid)
		return errWinn3DeviceClosed
	}
	// Tail drop on the uplink: never remove the head of an in-order stream.
	if rejected := valid[accepted:]; len(rejected) > 0 {
		d.droppedToEngine.Add(uint64(len(rejected)))
		for _, pkt := range rejected {
			d.recycle(pkt)
		}
	}
	d.releaseOfferScratch(valid)
	return nil
}

// releaseOfferScratch clears the retained packet pointers so a recycled buffer
// is not kept reachable by the scratch slice until the next offerBatch.
func (d *winn3FrameDevice) releaseOfferScratch(valid [][]byte) {
	for i := range valid {
		valid[i] = nil
	}
	d.offerScratch = valid[:0]
}

// take is the OpOutbound side: the frame pump collects one delivered packet.
//
// It blocks until a packet is available or the device closes, so the pump has
// no poll interval and a quiet tunnel costs nothing.
func (d *winn3FrameDevice) take() ([]byte, error) {
	select {
	case pkt := <-d.toHost:
		return pkt, nil
	case <-d.closed:
		// Drain what is already queued before reporting closure, so a teardown
		// does not discard packets the tunnel had already validated and
		// delivered. Anything still in flight after this is genuinely lost.
		select {
		case pkt := <-d.toHost:
			return pkt, nil
		default:
			return nil, errWinn3DeviceClosed
		}
	}
}

// tryTake attempts to take one delivered packet without blocking.
// Returns (packet, true) if a packet was available, or (nil, false) if empty or closed.
func (d *winn3FrameDevice) tryTake() ([]byte, bool) {
	select {
	case pkt := <-d.toHost:
		return pkt, true
	default:
		return nil, false
	}
}

func (d *winn3FrameDevice) recycle(pkt []byte) {
	if cap(pkt) == 2048 {
		bp := (*[2048]byte)(pkt[:2048])
		packetPool.Put(bp)
	}
}

// ReadPacket is tun.PumpOutbound's side: one inner IP packet on its way out.
func (d *winn3FrameDevice) ReadPacket(buf []byte) (int, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	pkt, ok := d.toEngine.popOne()
	if !ok {
		return 0, errWinn3DeviceClosed
	}
	defer d.recycle(pkt)
	n := copy(buf, pkt)
	if n < len(pkt) {
		// A short buffer is the caller's bug, not a reason to lose a packet
		// silently: a truncated IP packet is undetectable corruption at the
		// next layer.
		return n, fmt.Errorf(
			"winn3: read buffer of %d bytes is shorter than the %d-byte packet",
			len(buf), len(pkt))
	}
	return n, nil
}

// WritePacket is tun.Tunnel.Inbound's side, called only AFTER the inner-IP
// validator has accepted the packet.
//
// Reaching here is what moves tun.Stats().RxPackets, which is the counter the
// promotion gate is built from (so a packet that gets here is a packet
// DELIVERED, not merely one that arrived). That distinction is the whole reason
// the status document publishes rx_offered next to it rather than instead of
// it.
func (d *winn3FrameDevice) WritePacket(packet []byte) (int, error) {
	if d.isClosed() {
		return 0, fmt.Errorf("%w: %s", tun.ErrDeviceWrite, errWinn3DeviceClosed)
	}
	var cp []byte
	if len(packet) <= 2048 {
		bp := packetPool.Get().(*[2048]byte)
		cp = bp[:len(packet)]
	} else {
		cp = make([]byte, len(packet))
	}
	copy(cp, packet)
	// Drop the oldest inbound: a stale burst is worse than a current one.
	d.push(d.toHost, cp, &d.droppedToHost, true)
	winn3RaiseTo(&d.hostHighWater, uint64(len(d.toHost)))
	return len(packet), nil
}

// push enqueues one packet on a full-queue policy chosen by the caller.
//
// dropOldest true removes the head to make room, which keeps the queue current
// and is right for toHost. dropOldest false is tail drop: the NEW packet is
// recycled and counted and the head is left alone, which is right for toEngine
// because deleting the head of an in-order uplink costs an RTO rather than a
// SACK. See the type comment for the measured numbers behind that split.
//
// Both policies are safe because each queue has exactly one producer: toEngine
// is written only by the frame reader goroutine and toHost only by the tun
// layer's inbound path. That is what makes the read-then-write pair below
// atomic enough: no second producer can refill the slot between them.
func (d *winn3FrameDevice) push(q chan []byte, pkt []byte, dropped *atomic.Uint64, dropOldest bool) {
	select {
	case q <- pkt:
		return
	default:
	}
	if !dropOldest {
		d.recycle(pkt)
		dropped.Add(1)
		return
	}
	select {
	case old := <-q:
		d.recycle(old)
		dropped.Add(1)
	default:
	}
	select {
	case q <- pkt:
	default:
		// The single-producer rule makes this unreachable; counting rather
		// than blocking keeps it that way if the rule is ever broken.
		d.recycle(pkt)
		dropped.Add(1)
	}
}

func (d *winn3FrameDevice) isClosed() bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}

// Close unblocks both ends. It is idempotent.
func (d *winn3FrameDevice) Close() error {
	if d.once.CompareAndSwap(false, true) {
		close(d.closed)
		d.toEngine.close()
	}
	return nil
}

// retireReader waits until no tun reader is inside the device. Close must have
// run first, so a reader parked in the ring has already been woken; any read
// after this returns the closed error without touching a host packet.
func (d *winn3FrameDevice) retireReader(ctx context.Context) bool {
	joined := make(chan struct{})
	go func() {
		d.readMu.Lock()
		d.readMu.Unlock() //nolint:staticcheck // the lock is a join, not a guard
		close(joined)
	}()
	return winn3FrameAwait(ctx, joined)
}

// drainToEngine returns every packet the ring still holds to the packet pool.
func (d *winn3FrameDevice) drainToEngine() {
	for _, pkt := range d.toEngine.drain() {
		d.recycle(pkt)
	}
}

// ReadBatch drains up to len(bufs) ready packets.
// It blocks for the first batch, then moves slice headers out under one ring lock acquisition.
// Payload copying and packetPool recycling run after the ring lock is released.
func (d *winn3FrameDevice) ReadBatch(bufs [][]byte) ([]int, error) {
	if len(bufs) == 0 {
		return nil, nil
	}
	d.readMu.Lock()
	defer d.readMu.Unlock()
	if cap(d.readPackets) < len(bufs) {
		d.readPackets = make([][]byte, len(bufs))
	}
	packets := d.readPackets[:len(bufs)]

	n, ok := d.toEngine.popBatch(packets)
	if !ok {
		return nil, errWinn3DeviceClosed
	}

	lengths := d.readLengths[:0]
	if cap(lengths) < len(bufs) {
		lengths = make([]int, 0, len(bufs))
	}
	for i := 0; i < n; i++ {
		pkt := packets[i]
		packets[i] = nil
		idx := len(lengths)
		if len(pkt) > len(bufs[idx]) {
			d.oversize.Add(1)
			d.recycle(pkt)
			continue
		}
		lengths = append(lengths, copy(bufs[idx], pkt))
		d.recycle(pkt)
	}

	d.readLengths = lengths
	return lengths, nil
}

var _ tun.Device = (*winn3FrameDevice)(nil)
var _ tun.BatchDevice = (*winn3FrameDevice)(nil)
