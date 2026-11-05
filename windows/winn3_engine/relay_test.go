package main

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// A loopback harness for the two pumps.
//
// The sockets are REAL: the seam is a real UDP socket on 127.0.0.1 and the
// stand-in engine is another one, so the peer pin, the datagram boundary and
// the one-packet-per-datagram rule are exercised rather than mocked. Only the
// adapter is faked, because Wintun is a Windows driver. That is the honest
// division: everything this relay decides is under test here, and the thing
// that is not under test is the thing that cannot be, on any machine without
// Windows.

type fakeTun struct {
	out      chan []byte // the host stack wants to send these  (tun -> seam)
	in       chan []byte // these were delivered to the host stack (seam -> tun)
	ready    chan struct{}
	closed   chan struct{}
	ringFull atomic.Bool
	released atomic.Uint64
}

func newFakeTun() *fakeTun {
	return &fakeTun{
		out:    make(chan []byte, 16),
		in:     make(chan []byte, 16),
		ready:  make(chan struct{}, 1),
		closed: make(chan struct{}),
	}
}

// push queues a packet as if the host stack had written it to the adapter.
func (f *fakeTun) push(packet []byte) {
	f.out <- packet
	select {
	case f.ready <- struct{}{}:
	default:
	}
}

func (f *fakeTun) receivePacket() ([]byte, func(), error) {
	select {
	case packet := <-f.out:
		return packet, func() { f.released.Add(1) }, nil
	case <-f.closed:
		return nil, nil, errTunClosed
	default:
		return nil, nil, errTunAgain
	}
}

func (f *fakeTun) waitReadable() error {
	select {
	case <-f.ready:
		return nil
	case <-f.closed:
		return errTunClosed
	}
}

func (f *fakeTun) sendPacket(packet []byte) error {
	if f.ringFull.Load() {
		return errTunRingFull
	}
	clone := append([]byte(nil), packet...)
	select {
	case f.in <- clone:
		return nil
	case <-f.closed:
		return errTunClosed
	}
}

var _ tunSide = (*fakeTun)(nil)

type harness struct {
	tun    *fakeTun
	engine *net.UDPConn // stands in for winn-datapath's loopback device
	stats  *counters
}

const harnessMTU = winn3ShippingFloorInnerMTU

// newHarness wires a relay to a stand-in engine over real loopback sockets.
func newHarness(t *testing.T) *harness {
	t.Helper()

	// The engine's socket first, because the relay needs its port to pin.
	engine, err := net.ListenUDP("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("bind stand-in engine: %v", err)
	}
	seam, err := net.ListenUDP("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("bind relay seam: %v", err)
	}
	enginePort := engine.LocalAddr().(*net.UDPAddr).Port
	peer := netip.AddrPortFrom(
		netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(enginePort))

	tun := newFakeTun()
	stats := &counters{}
	stop := func() {}

	go pumpTunToSeam(tun, seam, peer, harnessMTU, stats, stop)
	go pumpSeamToTun(tun, seam, peer, harnessMTU, stats, stop)

	t.Cleanup(func() {
		close(tun.closed)
		_ = seam.Close()
		_ = engine.Close()
	})
	return &harness{tun: tun, engine: engine, stats: stats}
}

// seamAddr is the relay's seam address, which the stand-in engine writes to.
func (h *harness) seamAddr(t *testing.T) *net.UDPAddr {
	t.Helper()
	// Discovered by making the relay speak first: the relay's seam port is not
	// otherwise visible to the engine, which mirrors reality -- winn-datapath
	// learns it from device.host_port in the profile.
	h.tun.push(ipv4(48, 48))
	buf := make([]byte, seamReadBuffer)
	_ = h.engine.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err := h.engine.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("relay never spoke: %v", err)
	}
	if n != 48 {
		t.Fatalf("relay sent %d bytes, expected the 48-byte probe", n)
	}
	return from
}

// TestAPacketCrossesTheSeamInBothDirections is the loopback proof: one inner
// IPv4 packet out through the seam, one back in to the adapter, over real
// sockets.
func TestAPacketCrossesTheSeamInBothDirections(t *testing.T) {
	h := newHarness(t)
	relayAddr := h.seamAddr(t)

	// Outbound: adapter -> seam.
	outbound := ipv4(120, 120)
	outbound[12], outbound[13], outbound[14], outbound[15] = 10, 8, 1, 3 // src
	h.tun.push(outbound)

	buf := make([]byte, seamReadBuffer)
	_ = h.engine.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := h.engine.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("outbound packet never reached the engine: %v", err)
	}
	if n != len(outbound) {
		t.Fatalf("engine got %d bytes, sent %d", n, len(outbound))
	}
	if string(buf[:n]) != string(outbound) {
		t.Fatal("the packet was altered in flight; the seam must be byte-exact")
	}

	// Inbound: seam -> adapter.
	inbound := ipv4(200, 200)
	inbound[16], inbound[17], inbound[18], inbound[19] = 10, 8, 1, 3 // dst
	if _, err := h.engine.WriteToUDP(inbound, relayAddr); err != nil {
		t.Fatalf("write inbound: %v", err)
	}
	select {
	case delivered := <-h.tun.in:
		if string(delivered) != string(inbound) {
			t.Fatal("the inbound packet was altered before the adapter")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("inbound packet never reached the adapter")
	}

	if got := h.stats.tunToSeam.Load(); got != 2 {
		t.Errorf("tunToSeam = %d, want 2 (the probe and the packet)", got)
	}
	if got := h.stats.seamToTun.Load(); got != 1 {
		t.Errorf("seamToTun = %d, want 1", got)
	}
	if got := h.tun.released.Load(); got != 2 {
		t.Errorf("released %d ring packets, want 2: a leaked ring slot "+
			"eventually wedges the adapter", got)
	}
}

// TestTheSeamRefusesAForeignSender is the injection test. A second local socket
// writes a perfectly well-formed inner packet to the relay's seam; it must not
// reach the adapter, because it did not come from the engine.
func TestTheSeamRefusesAForeignSender(t *testing.T) {
	h := newHarness(t)
	relayAddr := h.seamAddr(t)

	attacker, err := net.ListenUDP("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("bind attacker: %v", err)
	}
	defer func() { _ = attacker.Close() }()

	if _, err := attacker.WriteToUDP(ipv4(100, 100), relayAddr); err != nil {
		t.Fatalf("attacker write: %v", err)
	}

	select {
	case injected := <-h.tun.in:
		t.Fatalf("a foreign %d-byte datagram was injected into the adapter",
			len(injected))
	case <-time.After(500 * time.Millisecond):
	}
	if got := h.stats.foreign.Load(); got != 1 {
		t.Errorf("foreign = %d, want 1", got)
	}
}

// TestAnOversizePacketNeverReachesTheAdapter is the MTU trap, exercised on the
// live datapath rather than only in the validator. A packet that would fit an
// adapter sized from the DIALLED carrier (1223) but not one sized from the plan
// floor (1139) must be dropped and counted, not delivered.
func TestAnOversizePacketNeverReachesTheAdapter(t *testing.T) {
	h := newHarness(t)
	relayAddr := h.seamAddr(t)

	oversize := ipv4(winn3DialledUDPv4InnerMTU, winn3DialledUDPv4InnerMTU)
	if _, err := h.engine.WriteToUDP(oversize, relayAddr); err != nil {
		t.Fatalf("write oversize: %v", err)
	}
	select {
	case <-h.tun.in:
		t.Fatalf("a %d-byte packet reached an adapter with a %d-byte MTU",
			len(oversize), harnessMTU)
	case <-time.After(500 * time.Millisecond):
	}
	if got := h.stats.dropOversize.Load(); got != 1 {
		t.Errorf("dropOversize = %d, want 1", got)
	}
}

// TestAnAwgDatagramNeverReachesTheSeam is the cleartext test, and the one that
// matters most. If this relay were ever paired with a winn/1 engine, or if the
// adapter handed over something that is not an inner IP packet, the bytes must
// stop here rather than travel to a gateway.
func TestAnAwgDatagramNeverReachesTheSeam(t *testing.T) {
	h := newHarness(t)
	_ = h.seamAddr(t)

	awg := make([]byte, 148)
	awg[0] = 0x01 // AmneziaWG/WireGuard handshake initiation
	h.tun.push(awg)

	buf := make([]byte, seamReadBuffer)
	_ = h.engine.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, _, err := h.engine.ReadFromUDP(buf); err == nil {
		t.Fatalf("a %d-byte non-IP datagram crossed the seam", n)
	}
	if got := h.stats.dropInvalid.Load(); got != 1 {
		t.Errorf("dropInvalid = %d, want 1", got)
	}
	if got := h.tun.released.Load(); got != 2 {
		t.Errorf("released %d ring packets, want 2: a refused packet must "+
			"still be released back to the ring", got)
	}
}

// TestAnOutOfOrderUDPFrameIsStillForwardedByteExact is the ordering-parity
// proof: UDP does not order datagrams, and neither the relay nor either carrier
// may reorder inner packets on top of that -- ordering belongs entirely to the
// session's token window (netlab/pump.go's DeliverPermuted tolerates exactly
// this reordering). For the Windows engine and the netlab pump to coordinate in
// lockstep, the relay must forward a well-formed frame no matter how it is
// sequenced against the one before it, byte-exact and with nothing dropped.
//
// So this test sends a BURST of two distinct inner packets whose logical order
// is the reverse of their write order (the second is the earlier frame), which
// is the burst shape UDP can hand the seam in either order. The relay must
// forward BOTH, intact, whichever arrival order the socket chose -- never
// dropping a frame because it is out of sequence, and never conflating two
// datagrams into one.
func TestAnOutOfOrderUDPFrameIsStillForwardedByteExact(t *testing.T) {
	h := newHarness(t)
	relayAddr := h.seamAddr(t)

	// Two distinct, well-formed inner IPv4 packets. Distinguishable payloads
	// so a byte-exact frame can be told apart from its neighbour, and a drop or
	// an alteration of either is visible rather than masked.
	a := ipv4(48, 48)
	b := ipv4(48, 48)
	a[20], b[20] = 0xaa, 0xbb
	for i := 21; i < len(a); i++ {
		a[i] = 0x01
		b[i] = 0x02
	}

	// Burst both without waiting for delivery between them: at the seam they
	// are two back-to-back datagrams, which is precisely the shape that may
	// arrive out of order.
	if _, err := h.engine.WriteToUDP(a, relayAddr); err != nil {
		t.Fatalf("write frame a: %v", err)
	}
	if _, err := h.engine.WriteToUDP(b, relayAddr); err != nil {
		t.Fatalf("write frame b: %v", err)
	}

	seenA, seenB := false, false
	deadline := time.Now().Add(3 * time.Second)
	for !(seenA && seenB) && time.Now().Before(deadline) {
		select {
		case delivered := <-h.tun.in:
			switch {
			case len(delivered) == len(a) && string(delivered) == string(a):
				seenA = true
			case len(delivered) == len(b) && string(delivered) == string(b):
				seenB = true
			default:
				t.Fatalf("adapter received an unrecognised %d-byte frame: "+
					"the relay altered or conflated a datagram", len(delivered))
			}
		case <-time.After(3 * time.Second):
			// The select's own timeout: a frame is missing from the burst.
		}
	}

	if !seenA || !seenB {
		t.Fatalf("out-of-order UDP burst lost a frame: a=%v b=%v; "+
			"the relay must forward every well-formed datagram regardless of "+
			"sequence, and leave reordering to the session token window",
			seenA, seenB)
	}
	if got := h.stats.seamToTun.Load(); got != 2 {
		t.Errorf("seamToTun = %d, want 2 (both burst frames forwarded)", got)
	}
}

// TestAFullSendRingDropsRatherThanWedges pins the behaviour when the host stack
// is not draining: drop and count, never block the seam reader.
func TestAFullSendRingDropsRatherThanWedges(t *testing.T) {
	h := newHarness(t)
	relayAddr := h.seamAddr(t)

	h.tun.ringFull.Store(true)
	if _, err := h.engine.WriteToUDP(ipv4(100, 100), relayAddr); err != nil {
		t.Fatalf("write: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for h.stats.dropRingFull.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.stats.dropRingFull.Load(); got != 1 {
		t.Fatalf("dropRingFull = %d, want 1", got)
	}

	// And the pump is still alive: once the ring drains, packets flow again.
	h.tun.ringFull.Store(false)
	if _, err := h.engine.WriteToUDP(ipv4(101, 101), relayAddr); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case <-h.tun.in:
	case <-time.After(3 * time.Second):
		t.Fatal("the seam reader wedged on a full send ring")
	}
}
