package driver

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// floodDevice models the Android seam: a bounded ring in front of the tunnel
// that the host fills as fast as the tun hands it packets, and which DROPS
// rather than blocking when the engine falls behind. offered/dropped are the
// numbers the Ookla upload run is actually limited by.
type floodDevice struct {
	mtu     int
	in      chan []byte
	out     chan []byte
	offered atomic.Uint64
	dropped atomic.Uint64
	took    atomic.Uint64
}

func newFloodDevice(mtu, depth int) *floodDevice {
	return &floodDevice{
		mtu: mtu,
		in:  make(chan []byte, depth),
		out: make(chan []byte, 65536),
	}
}

func (d *floodDevice) offer(pkt []byte) {
	select {
	case d.in <- pkt:
		d.offered.Add(1)
	default:
		d.dropped.Add(1)
	}
}

func (d *floodDevice) ReadPacket(buf []byte) (int, error) {
	p, ok := <-d.in
	if !ok {
		return 0, context.Canceled
	}
	return copy(buf, p), nil
}

func (d *floodDevice) WritePacket(pkt []byte) (int, error) {
	d.took.Add(1)
	select {
	case d.out <- append([]byte(nil), pkt...):
	default:
	}
	return len(pkt), nil
}

func (d *floodDevice) MTU() int { return d.mtu }
func (d *floodDevice) Close()   {}

// runUploadSaturation floods the client tun for d and reports what arrived at
// the gateway, which is the only number that maps onto a speed test.
func runUploadSaturation(t *testing.T, hold time.Duration, ringDepth int) {
	t.Helper()

	krGw, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	krCli, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := core.NewPublicKey(krGw.Public())
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	for i := range admission {
		admission[i] = byte(i * 7)
	}
	params := core.GatewayParams{
		AdmissionKeys: [][]byte{admission},
		GatewayID:     []byte("winn3-upload-saturation"),
	}
	sz, err := NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}

	cliDev := newFloodDevice(sz.InnerMTU, ringDepth)
	gwDev := newFloodDevice(sz.InnerMTU, ringDepth)
	cliCar, gwCar := loopbackUDPPair(t)

	cliLoop, err := NewClient(Config{
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
	})
	if err != nil {
		t.Fatal(err)
	}
	gwLoop, err := NewGateway(Config{
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
	})
	if err != nil {
		t.Fatal(err)
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
			t.Fatal("tunnel did not reach carrying state")
		}
		time.Sleep(time.Millisecond)
	}

	payload := make([]byte, sz.InnerMTU-28)
	pkt := ipv4Packet(clientAddr(), gatewayAddr(), payload)

	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			cliDev.offer(pkt)
		}
	}()

	start := time.Now()
	time.Sleep(hold)
	close(stop)
	elapsed := time.Since(start)

	// Let whatever is in flight land before reading counters.
	time.Sleep(200 * time.Millisecond)

	delivered := gwDev.took.Load()
	offered := cliDev.offered.Load()
	ringDrop := cliDev.dropped.Load()
	cliTun := cliLoop.Tunnel().Stats()
	cliStats := cliLoop.Stats()

	goodput := float64(delivered) * float64(len(payload)) * 8 / elapsed.Seconds() / 1e6

	fmt.Printf(
		"\n=== upload saturation (ring=%d, sendqueue=%d, inner_mtu=%d, %.1fs) ===\n"+
			"  goodput at gateway : %8.1f Mbps  (%d packets)\n"+
			"  host ring offered  : %8d   dropped-before-engine %d\n"+
			"  tun device reads   : %8d\n"+
			"  tun tx accepted    : %8d\n"+
			"  tun tx DROPPED sink: %8d   <-- session send queue was full\n"+
			"  tun tx dropped other: %7d closed=%d invalid=%d oversize=%d\n"+
			"  carrier send failed: %8d   <-- sealed messages discarded\n"+
			"  carrier sent       : %8d\n",
		ringDepth, session.DefaultSendQueue, sz.InnerMTU, elapsed.Seconds(),
		goodput, delivered,
		offered, ringDrop,
		cliTun.DeviceReads,
		cliTun.TxPackets,
		cliTun.TxDroppedSink,
		cliTun.TxDroppedClosed+cliTun.TxDroppedInvalid+cliTun.TxDroppedOversize,
		cliTun.TxDroppedClosed, cliTun.TxDroppedInvalid, cliTun.TxDroppedOversize,
		cliStats.SendFailed, cliStats.MessagesSent,
	)
}

func TestUploadSaturationBaseline(t *testing.T) {
	runUploadSaturation(t, 3*time.Second, 2048)
}

// runUploadPaced offers packets at a fixed target rate, which is what a TCP
// flow at steady-state cwnd looks like. A bounded queue that drops here drops
// on the real link too.
func runUploadPaced(t *testing.T, hold time.Duration, ringDepth int, targetMbps float64) {
	t.Helper()

	krGw, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	krCli, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := core.NewPublicKey(krGw.Public())
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	for i := range admission {
		admission[i] = byte(i * 7)
	}
	params := core.GatewayParams{
		AdmissionKeys: [][]byte{admission},
		GatewayID:     []byte("winn3-upload-paced"),
	}
	sz, err := NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}

	cliDev := newFloodDevice(sz.InnerMTU, ringDepth)
	gwDev := newFloodDevice(sz.InnerMTU, ringDepth)
	cliCar, gwCar := loopbackUDPPair(t)

	cliLoop, err := NewClient(Config{
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
	})
	if err != nil {
		t.Fatal(err)
	}
	gwLoop, err := NewGateway(Config{
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
	})
	if err != nil {
		t.Fatal(err)
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
			t.Fatal("tunnel did not reach carrying state")
		}
		time.Sleep(time.Millisecond)
	}

	payload := make([]byte, sz.InnerMTU-28)
	pkt := ipv4Packet(clientAddr(), gatewayAddr(), payload)

	// Pace in 1 ms ticks, which is finer than any queue in the path.
	perTick := int(targetMbps * 1e6 / 8 / float64(len(payload)) / 1000)
	if perTick < 1 {
		perTick = 1
	}
	stop := make(chan struct{})
	go func() {
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				for i := 0; i < perTick; i++ {
					cliDev.offer(pkt)
				}
			}
		}
	}()

	start := time.Now()
	time.Sleep(hold)
	close(stop)
	elapsed := time.Since(start)
	time.Sleep(200 * time.Millisecond)

	delivered := gwDev.took.Load()
	offered := cliDev.offered.Load()
	ringDrop := cliDev.dropped.Load()
	cliTun := cliLoop.Tunnel().Stats()
	cliStats := cliLoop.Stats()

	goodput := float64(delivered) * float64(len(payload)) * 8 / elapsed.Seconds() / 1e6
	total := offered + ringDrop
	lossPct := 0.0
	if total > 0 {
		lossPct = float64(total-delivered) * 100 / float64(total)
	}

	fmt.Printf(
		"\n=== paced upload %.0f Mbps (ring=%d, sendqueue=%d, %d pkt/ms, %.1fs) ===\n"+
			"  delivered at gateway : %8.1f Mbps (%d pkts)\n"+
			"  end-to-end loss      : %8.3f %%\n"+
			"  ring drop            : %8d\n"+
			"  tx dropped at sink   : %8d   <-- session send queue full\n"+
			"  carrier send failed  : %8d\n",
		targetMbps, ringDepth, session.DefaultSendQueue, perTick, elapsed.Seconds(),
		goodput, delivered, lossPct, ringDrop, cliTun.TxDroppedSink, cliStats.SendFailed,
	)
}

func TestUploadPaced700(t *testing.T) {
	runUploadPaced(t, 4*time.Second, 2048, 700)
}

func TestUploadPacedSweep(t *testing.T) {
	for _, mbps := range []float64{700, 1000, 1500, 2000, 3000} {
		runUploadPaced(t, 3*time.Second, 2048, mbps)
	}
}
