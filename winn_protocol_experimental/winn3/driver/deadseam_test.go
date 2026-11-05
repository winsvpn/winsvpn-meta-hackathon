package driver

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// The promotion gate, driven through a real Loop.
//
// winn3/tun proves the counter; this proves the LAYER THE HOSTS USE reaches it.
// The distinction is not pedantry: measured on 2026-08-09, breaking the fix and
// running cmd/winn-datapath, cmd/winn3-gateway and cdatapath caught nothing at
// all — no shipping test anywhere noticed a promotion gate that promotes on a
// tunnel carrying nothing, which is why the defect existed. These two tests are
// the in-tree guard for that, one layer below the hosts and above the counter.
//
// The device here is a real unconnected UDP socket with the loopback seam's
// exact write semantics, not a mock. A mock that returned an error for a dead
// port would be a mock of the fix.

// dsSeamDevice is cmd/winn-datapath/winn3_device_loopback.go's write path: an
// UNCONNECTED socket bound to loopback, sending to a pinned peer.
type dsSeamDevice struct {
	conn *net.UDPConn
	peer netip.AddrPort
	mtu  int
}

func newDSSeamDevice(t *testing.T, peerPort, mtu int) *dsSeamDevice {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	//nolint:gosec // the port comes from the kernel
	pp := uint16(peerPort)
	return &dsSeamDevice{
		conn: conn,
		peer: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), pp),
		mtu:  mtu,
	}
}

func (d *dsSeamDevice) localPort() int { return d.conn.LocalAddr().(*net.UDPAddr).Port }

func (d *dsSeamDevice) ReadPacket(buf []byte) (int, error) {
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

func (d *dsSeamDevice) WritePacket(pkt []byte) (int, error) {
	return d.conn.WriteToUDPAddrPort(pkt, d.peer)
}

func (d *dsSeamDevice) MTU() int { return d.mtu }

// dsDeadPort binds a port and closes it, so the number names a port with
// nothing on it rather than one that merely looks unused.
func dsDeadPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	p := c.LocalAddr().(*net.UDPAddr).Port
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

// dsPromotionReady is §4.1 of the tun-layer contract — the conjunction the four
// hosts compute. It is written out because this package must not import them.
func dsPromotionReady(tn *tun.Tunnel) bool {
	return tn.Gate().State() == tun.StateCarrying && tn.Stats().RxPackets > 0
}

// dsSizing is the plan both halves are built over. It is deterministic, so a
// test can size its device before building the loops.
func dsSizing(t *testing.T) Sizing {
	t.Helper()
	// carrier.DefaultPathMTU rather than a literal: this rig has no opinion
	// about the path, and a literal 1280 has been inside the dead zone
	// NewSizing refuses since 2026-08-10.
	sz, err := NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	return sz
}

// dsPair builds a client and a gateway loop over a pipe pair, with the client's
// tun device supplied by the caller.
func dsPair(t *testing.T, clientDevice tun.Device) (cli, gw *Loop, gwDev *fakeDevice) {
	t.Helper()

	sz := dsSizing(t)
	gwStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	cliStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	gwPub, err := core.NewPublicKey(gwStatic.Public())
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	for i := range admission {
		admission[i] = byte(i*11 + 5)
	}
	params := core.GatewayParams{
		AdmissionKeys: [][]byte{admission},
		GatewayID:     []byte("winn3-deadseam-test"),
	}

	cliSess := session.Config{
		Core: core.Config{Gateway: params}, Static: cliStatic,
		GatewayStatic: gwPub, Padding: core.PadBucket,
	}
	gwSess := session.Config{
		Core: core.Config{Gateway: params}, Static: gwStatic,
		Accept: func([]byte) error { return nil }, Padding: core.PadBucket,
	}

	toGw, toCli, err := carrier.NewPipePair(carrier.PipeConfig{
		Class: carrier.ClassUDP, MaxMessageSize: sz.MessageSize, PathMTU: sz.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}

	cliInner := netip.AddrFrom4([4]byte{10, 64, 0, 2})
	gwInner := netip.AddrFrom4([4]byte{10, 64, 0, 3})
	router := netip.AddrFrom4([4]byte{10, 64, 0, 1})

	gwDev = newDevice(sz.InnerMTU)
	cliTun := tun.Config{
		Assign: tun.Assignment{V4: cliInner, RouterV4: router},
		Device: clientDevice, Clock: SessionClock{Clock: SystemClock{}}, ICMPBurst: 4,
	}
	gwTun := tun.Config{
		Assign: tun.Assignment{V4: gwInner, RouterV4: router},
		Device: gwDev, Clock: SessionClock{Clock: SystemClock{}}, ICMPBurst: 4,
	}

	cli, err = NewClient(Config{Session: cliSess, Sizing: sz, Carrier: toGw, Tun: &cliTun})
	if err != nil {
		t.Fatal(err)
	}
	gw, err = NewGateway(Config{Session: gwSess, Sizing: sz, Carrier: toCli, Tun: &gwTun})
	if err != nil {
		t.Fatal(err)
	}
	return cli, gw, gwDev
}

// dsInnerV4 builds a well-formed inner IPv4/UDP packet.
func dsInnerV4(src, dst netip.Addr, payload []byte) []byte {
	total := 28 + len(payload)
	b := make([]byte, total)
	b[0] = 0x45
	b[2], b[3] = byte(total>>8), byte(total)
	b[8] = 64
	b[9] = 17
	s, d := src.As4(), dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	b[20], b[21] = 0x30, 0x39
	b[22], b[23] = 0x30, 0x3a
	ulen := 8 + len(payload)
	b[24], b[25] = byte(ulen>>8), byte(ulen)
	copy(b[28:], payload)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	c := ^uint16(sum)
	b[10], b[11] = byte(c>>8), byte(c)
	return b
}

// TestALoopWithADeadSeamNeverPromotes is the defect at the layer the hosts use.
//
// The client's device.host_port names a loopback port nothing is bound to. The
// gateway sends it a genuine inner packet, which travels the whole chain and is
// written into the void by an unconnected sendto that succeeds. The gate is
// carrying. The host predicate must still be false.
func TestALoopWithADeadSeamNeverPromotes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dev := newDSSeamDevice(t, dsDeadPort(t), dsSizing(t).InnerMTU)
	cli, gw, gwDev := dsPair(t, dev)

	go func() { _ = cli.Run(ctx) }()
	go func() { _ = gw.Run(ctx) }()

	waitFor(t, 20*time.Second, "the client's gate to open", func() bool {
		return cli.Tunnel().Gate().State() == tun.StateCarrying
	})

	cliInner := netip.AddrFrom4([4]byte{10, 64, 0, 2})
	gwInner := netip.AddrFrom4([4]byte{10, 64, 0, 3})
	gwDev.offer(t, dsInnerV4(gwInner, cliInner, []byte("winn3 dead seam")))

	waitFor(t, 20*time.Second, "the packet to reach the client's tun layer", func() bool {
		return cli.Tunnel().Stats().RxDeviceWrites > 0
	})

	st := cli.Tunnel().Stats()
	t.Logf("MEASURED: RxOffered=%d RxDeviceWrites=%d RxPackets=%d DeviceReads=%d "+
		"DeviceProven=%v RxDroppedDevice=%d gate=%s",
		st.RxOffered, st.RxDeviceWrites, st.RxPackets, st.DeviceReads,
		st.DeviceProven, st.RxDroppedDevice, cli.Tunnel().Gate().State())

	if st.RxOffered == 0 {
		t.Fatal("nothing was offered to the client's tun layer; this test would " +
			"pass for the wrong reason")
	}
	if st.RxDroppedDevice != 0 {
		t.Fatalf("RxDroppedDevice=%d: the unconnected sendto reported an error, so "+
			"the defect's premise does not hold here and this proves nothing",
			st.RxDroppedDevice)
	}
	if st.DeviceReads != 0 || st.DeviceProven {
		t.Fatalf("the device was proven with nothing wired to it: reads=%d proven=%v",
			st.DeviceReads, st.DeviceProven)
	}
	if st.RxPackets != 0 {
		t.Fatalf("RxPackets=%d for datagrams nobody received", st.RxPackets)
	}
	if cli.Tunnel().Gate().State() != tun.StateCarrying {
		t.Fatalf("gate is %s; the gate is not what this fix changes",
			cli.Tunnel().Gate().State())
	}
	if dsPromotionReady(cli.Tunnel()) {
		t.Fatal("the promotion predicate is true on a tunnel that has moved " +
			"nothing: a host would install a default route into a void")
	}
}

// TestALoopWithALiveSeamStillPromotes is the direction that matters just as
// much. A promotion gate that never promotes is an outage.
func TestALoopWithALiveSeamStillPromotes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	host, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer host.Close()
	hostPort := host.LocalAddr().(*net.UDPAddr).Port

	dev := newDSSeamDevice(t, hostPort, dsSizing(t).InnerMTU)
	cli, gw, gwDev := dsPair(t, dev)
	go func() { _ = cli.Run(ctx) }()
	go func() { _ = gw.Run(ctx) }()

	waitFor(t, 20*time.Second, "the client's gate to open", func() bool {
		return cli.Tunnel().Gate().State() == tun.StateCarrying
	})

	cliInner := netip.AddrFrom4([4]byte{10, 64, 0, 2})
	gwInner := netip.AddrFrom4([4]byte{10, 64, 0, 3})

	// The host speaks first, as a host does: it relays a packet off its real
	// interface into the seam. That is the evidence a void cannot produce.
	engine := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: dev.localPort()}
	out := dsInnerV4(cliInner, gwInner, []byte("winn3 live seam"))
	deadline := time.Now().Add(20 * time.Second)
	for cli.Tunnel().Stats().DeviceReads == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the engine never read a packet from the host")
		}
		if _, err := host.WriteToUDP(out, engine); err != nil {
			t.Fatalf("host write: %v", err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	if dsPromotionReady(cli.Tunnel()) {
		t.Fatal("promoted on a proven device with nothing delivered: RxPackets is " +
			"not carrying its half of the predicate")
	}

	// Now the answer comes back down the tunnel.
	gwDev.offer(t, dsInnerV4(gwInner, cliInner, []byte("winn3 live seam reply")))

	waitFor(t, 20*time.Second, "the client to promote", func() bool {
		return dsPromotionReady(cli.Tunnel())
	})
	st := cli.Tunnel().Stats()
	t.Logf("MEASURED: RxOffered=%d RxDeviceWrites=%d RxPackets=%d DeviceReads=%d "+
		"DeviceProven=%v", st.RxOffered, st.RxDeviceWrites, st.RxPackets,
		st.DeviceReads, st.DeviceProven)
	if st.RxPackets == 0 {
		t.Fatal("promoted with RxPackets at zero")
	}
	if !st.DeviceProven {
		t.Fatal("promoted on a device that is not proven")
	}

	// And the host really received it, which is the claim RxPackets makes.
	if err := host.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, _, err := host.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the host never received the inner packet RxPackets claims: %v", err)
	}
	if n == 0 {
		t.Fatal("the host received an empty datagram")
	}
}
