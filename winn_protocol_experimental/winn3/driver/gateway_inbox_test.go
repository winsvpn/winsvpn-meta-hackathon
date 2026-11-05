package driver

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// runGatewayShapedUpload models cmd/winn3-gateway's REAL receive path, which
// the UDP-on-both-ends benchmark does not exercise at all:
//
//	client tun -> client session -> UDP  ==>  ONE demux goroutine doing one
//	ReadFromUDPAddrPort per datagram -> Pipe.Deliver into a per-session inbox
//	of Depth slots -> Gosched once and DROP on full -> session readLoop.
//
// The download direction never touches any of this, which is why a defect here
// collapses upload alone.
func runGatewayShapedUpload(
	t *testing.T, hold time.Duration, inboxDepth int, targetMbps float64,
) {
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
		GatewayID:     []byte("winn3-gateway-shaped"),
	}
	sz, err := NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}

	cliConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cliConn.Close() }()
	gwConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gwConn.Close() }()

	// Give both sockets the grant the installer's sysctls allow, so a kernel
	// drop cannot be mistaken for a user-space one.
	_ = cliConn.SetReadBuffer(8 << 20)
	_ = cliConn.SetWriteBuffer(8 << 20)
	_ = gwConn.SetReadBuffer(8 << 20)
	_ = gwConn.SetWriteBuffer(8 << 20)

	cliCar, err := carrier.NewUDP(carrier.UDPConfig{
		Conn: cliConn,
		Peer: gwConn.LocalAddr().(*net.UDPAddr),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cliCar.Close() }()

	cliAddr := cliConn.LocalAddr().(*net.UDPAddr)
	gwPipe, err := carrier.NewPipe(carrier.PipeConfig{
		Class: carrier.ClassUDP,
		Out: func(msg []byte) error {
			_, werr := gwConn.WriteToUDP(msg, cliAddr)
			return werr
		},
		MaxMessageSize: sz.MessageSize,
		PathMTU:        sz.PathMTU,
		Depth:          inboxDepth,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gwPipe.Close() }()

	cliDev := newFloodDevice(sz.InnerMTU, 2048)
	gwDev := newFloodDevice(sz.InnerMTU, 2048)

	cliLoop, err := NewClient(Config{
		Session: session.Config{
			Core:          core.Config{Gateway: params},
			Static:        krCli,
			GatewayStatic: pub,
			Padding:       core.PadBucket,
			SendQueue:     4096, // what cmd/winn-datapath ships on Android
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
			Core:      core.Config{Gateway: params},
			Static:    krGw,
			Accept:    func([]byte) error { return nil },
			Padding:   core.PadBucket,
			SendQueue: 16384, // what cmd/winn3-gateway ships
		},
		Sizing:  sz,
		Carrier: gwPipe,
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

	// The production demultiplexer, reproduced: one goroutine, one syscall per
	// datagram, one Gosched and then a silent drop when the inbox is full.
	var demuxDropped atomic.Uint64
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, rerr := gwConn.ReadFromUDPAddrPort(buf)
			if rerr != nil {
				return
			}
			if n == 0 {
				continue
			}
			derr := gwPipe.Deliver(buf[:n])
			if derr != nil {
				runtimeGosched()
				derr = gwPipe.Deliver(buf[:n])
			}
			if derr != nil {
				demuxDropped.Add(1)
			}
		}
	}()

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
	time.Sleep(300 * time.Millisecond)

	delivered := gwDev.took.Load()
	offered := cliDev.offered.Load() + cliDev.dropped.Load()
	cliTun := cliLoop.Tunnel().Stats()
	pipeStats := gwPipe.Stats()

	goodput := float64(delivered) * float64(len(payload)) * 8 / elapsed.Seconds() / 1e6
	loss := 0.0
	if offered > 0 {
		loss = float64(offered-delivered) * 100 / float64(offered)
	}

	fmt.Printf(
		"\n=== gateway-shaped upload %.0f Mbps (inbox=%d, %.1fs) ===\n"+
			"  delivered to gw tun : %8.1f Mbps (%d pkts)\n"+
			"  end-to-end loss     : %8.3f %%\n"+
			"  client tx drop sink : %8d\n"+
			"  client ring drop    : %8d\n"+
			"  GW INBOX RecvErrors : %8d   <-- Pipe.Deliver ErrQueueFull\n"+
			"  demux gave up on    : %8d   datagrams (dropped after Gosched)\n"+
			"  inbox delivered     : %8d\n",
		targetMbps, inboxDepth, elapsed.Seconds(),
		goodput, delivered, loss,
		cliTun.TxDroppedSink, cliDev.dropped.Load(),
		pipeStats.RecvErrors, demuxDropped.Load(), pipeStats.Delivered,
	)
}

func TestGatewayShapedUploadSweep(t *testing.T) {
	for _, mbps := range []float64{300, 600, 700, 900} {
		runGatewayShapedUpload(t, 3*time.Second, core.DefaultTokenWindow/2, mbps)
	}
}

func runtimeGosched() { runtime.Gosched() }
