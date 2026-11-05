package driver

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

func loopbackUDPPair(t testing.TB) (clientCar, gwCar *carrier.UDP) {
	t.Helper()
	aConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	bConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = aConn.Close()
		t.Fatal(err)
	}
	ac := carrier.UDPConfig{
		Conn: aConn,
		Peer: bConn.LocalAddr().(*net.UDPAddr),
	}
	bc := carrier.UDPConfig{
		Conn: bConn,
		Peer: aConn.LocalAddr().(*net.UDPAddr),
	}
	clientCar, err = carrier.NewUDP(ac)
	if err != nil {
		_ = aConn.Close()
		_ = bConn.Close()
		t.Fatal(err)
	}
	gwCar, err = carrier.NewUDP(bc)
	if err != nil {
		_ = clientCar.Close()
		_ = bConn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = clientCar.Close()
		_ = gwCar.Close()
	})
	return clientCar, gwCar
}

func TestBatchCarrierLoopE2E(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	cliCar, gwCar := loopbackUDPPair(t)

	if _, ok := any(cliCar).(carrier.BatchCarrier); !ok {
		t.Fatal("cliCar does not implement carrier.BatchCarrier")
	}

	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing:  sz,
		carrier: cliCar,
		local:   clientAddr(),
		router:  gatewayAddr(),
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing:  sz,
		carrier: gwCar,
		local:   gatewayAddr(),
		router:  clientAddr(),
	})
	defer cli.stop()
	defer gw.stop()

	cli.start(ctx)
	gw.start(ctx)

	cli.waitState(session.StateEstablished, 10*time.Second)
	gw.waitState(session.StateEstablished, 10*time.Second)

	waitFor(t, 5*time.Second, "client gate to open", func() bool {
		return cli.loop.Carrying() && cli.loop.Tunnel().Gate().State() == tunCarrying()
	})
	waitFor(t, 5*time.Second, "gateway gate to open", func() bool {
		return gw.loop.Carrying() && gw.loop.Tunnel().Gate().State() == tunCarrying()
	})

	const count = 64
	sent := make([]string, count)
	for i := 0; i < count; i++ {
		payload := []byte(fmt.Sprintf("winn3-batch-loop-c2g-packet-%04d", i))
		sent[i] = digest(payload)
		cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), payload))
	}

	for i := 0; i < count; i++ {
		pkt := gw.dev.take(t, 10*time.Second)
		gotDigest := digest(payloadOf(pkt))
		if gotDigest != sent[i] {
			t.Fatalf("packet %d mismatch: got %s, want %s", i, gotDigest, sent[i])
		}
	}

	backSent := make([]string, count)
	for i := 0; i < count; i++ {
		payload := []byte(fmt.Sprintf("winn3-batch-loop-g2c-packet-%04d", i))
		backSent[i] = digest(payload)
		gw.dev.offer(t, ipv4Packet(gatewayAddr(), clientAddr(), payload))
	}

	for i := 0; i < count; i++ {
		pkt := cli.dev.take(t, 10*time.Second)
		gotDigest := digest(payloadOf(pkt))
		if gotDigest != backSent[i] {
			t.Fatalf("return packet %d mismatch: got %s, want %s", i, gotDigest, backSent[i])
		}
	}

	cliStats := cli.loop.Stats()
	gwStats := gw.loop.Stats()

	if cliStats.SendFailed != 0 {
		t.Fatalf("client send failed: %d", cliStats.SendFailed)
	}
	if gwStats.SendFailed != 0 {
		t.Fatalf("gateway send failed: %d", gwStats.SendFailed)
	}
	if cliStats.InnerDelivered < count {
		t.Fatalf("client InnerDelivered (%d) < %d", cliStats.InnerDelivered, count)
	}
	if gwStats.InnerDelivered < count {
		t.Fatalf("gateway InnerDelivered (%d) < %d", gwStats.InnerDelivered, count)
	}
}

type benchDevice struct {
	mtu int
	in  chan []byte
	out chan []byte
}

func newBenchDevice(mtu int) *benchDevice {
	return &benchDevice{
		mtu: mtu,
		in:  make(chan []byte, 4096),
		out: make(chan []byte, 4096),
	}
}

func (d *benchDevice) ReadPacket(buf []byte) (int, error) {
	p := <-d.in
	return copy(buf, p), nil
}

func (d *benchDevice) WritePacket(pkt []byte) (int, error) {
	cp := append([]byte(nil), pkt...)
	select {
	case d.out <- cp:
	default:
	}
	return len(pkt), nil
}

func (d *benchDevice) MTU() int { return d.mtu }
func (d *benchDevice) Close()   {}

func BenchmarkBatchCarrierLoopThroughput(b *testing.B) {
	krGw, err := core.GenerateStaticKey()
	if err != nil {
		b.Fatal(err)
	}
	krCli, err := core.GenerateStaticKey()
	if err != nil {
		b.Fatal(err)
	}
	pub, err := core.NewPublicKey(krGw.Public())
	if err != nil {
		b.Fatal(err)
	}
	admission := make([]byte, 32)
	for i := range admission {
		admission[i] = byte(i * 7)
	}
	params := core.GatewayParams{
		AdmissionKeys: [][]byte{admission},
		GatewayID:     []byte("winn3-batch-loop-bench"),
	}

	sz, err := NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		b.Fatal(err)
	}

	cliDev := newBenchDevice(sz.InnerMTU)
	gwDev := newBenchDevice(sz.InnerMTU)

	cliCar, gwCar := loopbackUDPPair(b)

	cliCfg := Config{
		Session: session.Config{
			Core:          core.Config{Gateway: params},
			Static:        krCli,
			GatewayStatic: pub,
			Padding:       core.PadBucket,
		},
		Sizing:  sz,
		Carrier: cliCar,
		Tun: &tun.Config{
			Assign: tun.Assignment{V4: clientAddr(), RouterV4: gatewayAddr()},
			Device: cliDev,
		},
	}
	gwCfg := Config{
		Session: session.Config{
			Core:    core.Config{Gateway: params},
			Static:  krGw,
			Accept:  func([]byte) error { return nil },
			Padding: core.PadBucket,
		},
		Sizing:  sz,
		Carrier: gwCar,
		Tun: &tun.Config{
			Assign: tun.Assignment{V4: gatewayAddr(), RouterV4: clientAddr()},
			Device: gwDev,
		},
	}
	cliLoop, err := NewClient(cliCfg)
	if err != nil {
		b.Fatal(err)
	}
	gwLoop, err := NewGateway(gwCfg)
	if err != nil {
		b.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer cliLoop.Close()
	defer gwLoop.Close()

	go func() { _ = cliLoop.Run(ctx) }()
	go func() { _ = gwLoop.Run(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for !cliLoop.Carrying() || !gwLoop.Carrying() {
		if time.Now().After(deadline) {
			b.Fatal("tunnel did not reach carrying state")
		}
		time.Sleep(time.Millisecond)
	}

	payload := make([]byte, sz.InnerMTU-28)
	pkt := ipv4Packet(clientAddr(), gatewayAddr(), payload)

	const burst = 16
	b.SetBytes(int64(burst * len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for j := 0; j < burst; j++ {
			cliDev.in <- pkt
		}
		for j := 0; j < burst; j++ {
			<-gwDev.out
		}
	}
}
