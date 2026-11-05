package tun

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// The false-promotion tests.
//
// A host promotes — installs the default route, IPv6 and DNS — on
// Gate.State() == StateCarrying && Stats().RxPackets > 0. On 2026-08-09 that
// predicate was measured true for a tunnel that had moved nothing, because
// cmd/winn-datapath's loopback-udp seam writes with an unconnected sendto and a
// sendto into a void succeeds. These tests hold both ends of the fix: the void
// must not promote, and a working tunnel must.
//
// Every test here drives the REAL Inbound and PumpOutbound paths. None of them
// calls a predicate helper directly, because a test that calls the thing it is
// testing proves only that the thing exists.

// promotionReady is the host predicate, written out here rather than imported,
// because the four hosts that compute it are in packages this package must not
// depend on. It is the conjunction from winn3_status.go §4.1.
func promotionReady(t *Tunnel) bool {
	return t.Gate().State() == StateCarrying && t.Stats().RxPackets > 0
}

// --- a device with the loopback seam's exact write semantics -----------------

// udpSeamDevice reproduces cmd/winn-datapath/winn3_device_loopback.go: an
// UNCONNECTED socket bound to loopback, writing to a pinned peer address.
//
// It is written out here rather than mocked because the defect lives in the
// syscall's semantics, not in anybody's Go. A mock that returned an error for a
// dead port would be a mock of the fix, and would prove nothing.
type udpSeamDevice struct {
	conn *net.UDPConn
	peer netip.AddrPort
	mtu  int
}

func newUDPSeamDevice(t *testing.T, peerPort int, mtu int) *udpSeamDevice {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("bind seam: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	//nolint:gosec // the caller supplies a port the kernel handed out
	pp := uint16(peerPort)
	return &udpSeamDevice{
		conn: conn,
		peer: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), pp),
		mtu:  mtu,
	}
}

func (d *udpSeamDevice) localPort() int {
	return d.conn.LocalAddr().(*net.UDPAddr).Port
}

// ReadPacket returns only datagrams from the pinned peer, as the seam does.
func (d *udpSeamDevice) ReadPacket(buf []byte) (int, error) {
	for {
		n, from, err := d.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return 0, err
		}
		if from != d.peer || n == 0 {
			continue
		}
		return n, nil
	}
}

func (d *udpSeamDevice) WritePacket(pkt []byte) (int, error) {
	n, err := d.conn.WriteToUDPAddrPort(pkt, d.peer)
	if err != nil {
		return n, errWrap(ErrDeviceWrite, "%v", err)
	}
	return n, nil
}

func (d *udpSeamDevice) MTU() int { return d.mtu }

// deadLoopbackPort returns a port number with nothing bound to it: it binds
// one, records it and closes it. Choosing an arbitrary number instead would
// risk hitting something that happened to be listening.
func deadLoopbackPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("bind to find a dead port: %v", err)
	}
	p := c.LocalAddr().(*net.UDPAddr).Port
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return p
}

func seamTunnel(t *testing.T, dev Device) *Tunnel {
	t.Helper()
	tn, err := New(Config{
		Assign:                  fixtureAssign(),
		Device:                  dev,
		Sink:                    &fakeSink{},
		Clock:                   newFakeClock(),
		CarrierFloorMessageSize: fixtureCarrierFloor,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return tn
}

// TestAWriteIntoAVoidIsNotAPromotion is the defect, in the direction that
// fails open.
//
// It also records the syscall behaviour that makes the defect possible, rather
// than asserting it in a comment: the write to the dead port must SUCCEED. If
// this host ever starts reporting an error there, the test says so instead of
// passing for a reason that has nothing to do with the fix.
func TestAWriteIntoAVoidIsNotAPromotion(t *testing.T) {
	dev := newUDPSeamDevice(t, deadLoopbackPort(t), fixtureInnerMTU)
	tn := seamTunnel(t, dev)
	tn.SetState(StateCarrying)

	pkt := arrivingV4(64)
	if err := tn.Inbound(pkt); err != nil {
		t.Fatalf("Inbound returned %v; the premise of this test is that the "+
			"write into a void SUCCEEDS, so a failure here means the defect "+
			"cannot be reproduced and the test below proves nothing", err)
	}

	st := tn.Stats()
	if st.RxDeviceWrites != 1 {
		t.Fatalf("RxDeviceWrites=%d, want 1: the datagram was written and that "+
			"must still be counted", st.RxDeviceWrites)
	}
	if st.RxDroppedDevice != 0 {
		t.Fatalf("RxDroppedDevice=%d: the device reported no error, which is "+
			"the whole problem", st.RxDroppedDevice)
	}
	if st.DeviceProven {
		t.Fatal("DeviceProven is true for a device that has never produced a packet")
	}
	if st.RxPackets != 0 {
		t.Fatalf("RxPackets=%d for a datagram nobody received", st.RxPackets)
	}
	if st.RxBytes != 0 {
		t.Fatalf("RxBytes=%d for a datagram nobody received", st.RxBytes)
	}
	if tn.Gate().State() != StateCarrying {
		t.Fatalf("gate is %s; the gate is not what this fix changes", tn.Gate().State())
	}
	if promotionReady(tn) {
		t.Fatal("promotion_ready is true on a tunnel that has moved nothing: " +
			"the host would install a default route into a void while the app " +
			"says connected")
	}
}

// TestManyWritesIntoAVoidNeverPromote. One packet not promoting could be an
// off-by-one somewhere. A hundred is the shape of a session that has been
// "connected" for a while and carried nothing.
func TestManyWritesIntoAVoidNeverPromote(t *testing.T) {
	dev := newUDPSeamDevice(t, deadLoopbackPort(t), fixtureInnerMTU)
	tn := seamTunnel(t, dev)
	tn.SetState(StateCarrying)

	for i := 0; i < 100; i++ {
		if err := tn.Inbound(arrivingV4(64)); err != nil {
			t.Fatalf("Inbound %d: %v", i, err)
		}
		if promotionReady(tn) {
			t.Fatalf("promoted after %d writes into a void", i+1)
		}
	}
	st := tn.Stats()
	if st.RxDeviceWrites != 100 || st.RxPackets != 0 || st.RxBytes != 0 {
		t.Fatalf("writes=%d delivered=%d bytes=%d, want 100, 0 and 0",
			st.RxDeviceWrites, st.RxPackets, st.RxBytes)
	}
	// The diagnosis an operator needs is the difference between the two.
	if !(st.RxDeviceWrites > 0 && st.RxPackets == 0 && !st.DeviceProven) {
		t.Fatalf("the misconfigured-seam signature is not readable from %+v", st)
	}
}

// TestAGenuineSeamStillPromotes is the other direction, and it is not optional:
// a promotion gate that never promotes is an outage, and this fix is only
// correct if it leaves a working tunnel working.
//
// The host half here is a real socket that does what a desktop host does —
// sends inner packets to the engine's seam port and receives them back.
func TestAGenuineSeamStillPromotes(t *testing.T) {
	host, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("bind host: %v", err)
	}
	defer host.Close()
	hostPort := host.LocalAddr().(*net.UDPAddr).Port

	dev := newUDPSeamDevice(t, hostPort, fixtureInnerMTU)
	tn := seamTunnel(t, dev)
	tn.SetState(StateCarrying)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = tn.PumpOutbound(ctx) }()

	// The host speaks first, which is what a host does: it relays a packet off
	// its real interface into the seam. That is the evidence a void cannot
	// produce. It is retried because the pump goroutine may not be parked in
	// ReadPacket yet and a datagram sent before it is has nowhere to land.
	engineAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: dev.localPort()}
	out := goodV4(64)
	deadline := time.Now().Add(10 * time.Second)
	for tn.Stats().DeviceReads == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the engine never read a packet from the host")
		}
		if _, err := host.WriteToUDP(out, engineAddr); err != nil {
			t.Fatalf("host write: %v", err)
		}
		time.Sleep(2 * time.Millisecond)
	}

	if !tn.DeviceProven() {
		t.Fatal("the device produced a packet and is still not proven")
	}
	if promotionReady(tn) {
		t.Fatal("promoted on a proven device with nothing delivered: RxPackets " +
			"is not carrying its half of the predicate")
	}

	// Now the answer comes back down the tunnel.
	if err := tn.Inbound(arrivingV4(64)); err != nil {
		t.Fatalf("Inbound: %v", err)
	}
	if err := host.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, MaxIPPacket)
	n, _, err := host.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the host never received the inner packet: %v", err)
	}
	if n == 0 {
		t.Fatal("the host received an empty datagram")
	}

	st := tn.Stats()
	if !st.DeviceProven {
		t.Fatal("DeviceProven is false on a seam both halves have used")
	}
	if st.RxPackets != 1 {
		t.Fatalf("RxPackets=%d, want 1: the reference promotion is RxPackets:1", st.RxPackets)
	}
	if st.RxBytes == 0 {
		t.Fatal("RxBytes is zero on a delivered packet")
	}
	if !promotionReady(tn) {
		t.Fatalf("a genuine session did not promote: %+v", st)
	}
}

// TestDeliveryNeedsAProvenDevice pins the ordering property that makes the fix
// safe: a delivery made BEFORE the device was proven is not thrown away, it is
// reported the moment the proof arrives.
//
// Without that, a gateway-side reflector — which can only be read from after it
// has been written to — would permanently undercount by one, and any host that
// receives before it transmits would lose a packet from its ledger for good.
func TestDeliveryNeedsAProvenDevice(t *testing.T) {
	f := newFixture(t).carrying()

	if err := f.tun.Inbound(arrivingV4(100)); err != nil {
		t.Fatalf("Inbound: %v", err)
	}
	st := f.tun.Stats()
	if st.RxDeviceWrites != 1 || st.RxPackets != 0 || st.DeviceProven {
		t.Fatalf("before the proof: writes=%d delivered=%d proven=%v, want 1, 0 and false",
			st.RxDeviceWrites, st.RxPackets, st.DeviceProven)
	}
	if f.dev.writeCount() != 1 {
		t.Fatalf("the device took %d packets, want 1: the packet must still be "+
			"written, only not counted as delivered", f.dev.writeCount())
	}

	// The device now produces a packet of its own, through the real pump.
	f.dev.queue(goodV4(100))
	_ = f.tun.PumpOutbound(context.Background())

	st = f.tun.Stats()
	if !st.DeviceProven {
		t.Fatal("a device that produced a packet is not proven")
	}
	if st.RxPackets != 1 {
		t.Fatalf("RxPackets=%d after the proof arrived, want 1: the earlier "+
			"delivery was discarded rather than deferred", st.RxPackets)
	}
	if st.RxBytes != uint64(100+IPv4HeaderMin) {
		t.Fatalf("RxBytes=%d, want %d", st.RxBytes, 100+IPv4HeaderMin)
	}
}

// TestProofDoesNotComeFromWriting is the negative that the two above cannot
// state between them: writing, on its own, in any quantity, never proves a
// device. It is the property the whole fix rests on, so it is asserted rather
// than assumed.
func TestProofDoesNotComeFromWriting(t *testing.T) {
	f := newFixture(t).carrying()
	for i := 0; i < 50; i++ {
		if err := f.tun.Inbound(arrivingV4(64)); err != nil {
			t.Fatalf("Inbound %d: %v", i, err)
		}
		if f.tun.DeviceProven() {
			t.Fatalf("write %d proved the device", i+1)
		}
	}
	// Outbound does not prove it either: those bytes came from the caller, not
	// from the device.
	for i := 0; i < 50; i++ {
		if err := f.tun.Outbound(goodV4(64)); err != nil {
			t.Fatalf("Outbound %d: %v", i, err)
		}
		if f.tun.DeviceProven() {
			t.Fatalf("Outbound call %d proved the device", i+1)
		}
	}
	if f.tun.Stats().RxPackets != 0 {
		t.Fatal("RxPackets moved without a proven device")
	}
}

// TestAFailedDeviceWriteIsStillNotADelivery. The two counters must not become a
// way to launder a device error into a delivery once the device is proven.
func TestAFailedDeviceWriteIsStillNotADelivery(t *testing.T) {
	f := newFixture(t).carrying()
	f.dev.queue(goodV4(100))
	_ = f.tun.PumpOutbound(context.Background())
	if !f.tun.DeviceProven() {
		t.Fatal("the pump did not prove the device")
	}

	f.dev.mu.Lock()
	f.dev.writeErr = errNoMoreReads
	f.dev.mu.Unlock()

	if err := f.tun.Inbound(arrivingV4(100)); err == nil {
		t.Fatal("Inbound returned nil for a device that refused the write")
	}
	st := f.tun.Stats()
	if st.RxPackets != 0 || st.RxDeviceWrites != 0 {
		t.Fatalf("a refused write was counted: delivered=%d writes=%d",
			st.RxPackets, st.RxDeviceWrites)
	}
	if st.RxDroppedDevice != 1 {
		t.Fatalf("RxDroppedDevice=%d, want 1", st.RxDroppedDevice)
	}
}
