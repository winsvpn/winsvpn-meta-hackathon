package driver

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

// Spain UDP-through-v3 died after exactly 4096 inner datagrams (seq 0–4095,
// contiguous) at ~8–17 Mbps, in two independent runs. This file asks whether
// that cliff exists in a loopback winn/3 session with no WAN, no kernel tun
// and no host VPN posture.
//
// If either test fails with the session leaving Established at ~4096
// deliveries, it is the regression gate for the fix. If both pass, the engine
// on loopback has no such packet-count death — evidence the Spain cause is
// path- or MTU-dependent (or rate-dependent in a way this rig does not
// reproduce), not a pure 2^12 counter in session/tun/carrier.

const (
	bug4096Cliff  = 4096
	bug4096Target = 8192
	// Wider than the target so a full DefaultSendQueue (256) or
	// DefaultPipeDepth (256) cannot be mistaken for session death.
	bug4096Queue = 16384
)

func bug4096Quiet(c *session.Config) {
	quietBackpressure(c)
	c.SendQueue = bug4096Queue
}

// TestLoopbackPipeSessionStaysAliveAt8192InnerDatagrams drives 8192 inner
// IPv4 datagrams across a PipePair UDP-class loopback (no socket) and
// requires the session still Established with all 8192 delivered to the
// gateway host device.
func TestLoopbackPipeSessionStaysAliveAt8192InnerDatagrams(t *testing.T) {
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{
		Class:   carrier.ClassUDP,
		PathMTU: carrier.DefaultPathMTU,
		Depth:   bug4096Queue,
	})
	if err != nil {
		t.Fatal(err)
	}
	driveInnerDatagramsPast4096(t, "pipe", cliCar, gwCar)
}

// TestLoopbackUDPSessionStaysAliveAt8192InnerDatagrams is the same drive
// over two real datagram sockets bound to 127.0.0.1. No default route, no
// utun, no NE provider. If the pipe test passes and this fails, the cliff
// is in the UDP carrier or the kernel socket, not a session counter.
func TestLoopbackUDPSessionStaysAliveAt8192InnerDatagrams(t *testing.T) {
	sz := planSizing(t)
	loopback := net.IPv4(127, 0, 0, 1)
	gwConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer gwConn.Close()
	cliConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer cliConn.Close()
	// Large enough that SO_RCVBUF is not the 4096 cliff. Failure of SetReadBuffer
	// is ignored: the kernel may cap it; the test still runs and reports counts.
	_ = gwConn.SetReadBuffer(16 << 20)
	_ = gwConn.SetWriteBuffer(16 << 20)
	_ = cliConn.SetReadBuffer(16 << 20)
	_ = cliConn.SetWriteBuffer(16 << 20)

	gwAddr := gwConn.LocalAddr().(*net.UDPAddr)
	cliAddr := cliConn.LocalAddr().(*net.UDPAddr)
	gwCar, err := carrier.NewUDP(carrier.UDPConfig{
		Conn: gwConn, Peer: cliAddr,
		MaxMessageSize: sz.MessageSize, PathMTU: sz.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	cliCar, err := carrier.NewUDP(carrier.UDPConfig{
		Conn: cliConn, Peer: gwAddr,
		MaxMessageSize: sz.MessageSize, PathMTU: sz.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	driveInnerDatagramsPast4096(t, "udp-loopback", cliCar, gwCar)
}

func driveInnerDatagramsPast4096(t *testing.T, label string, cliCar, gwCar carrier.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar,
		local: clientAddr(), router: gatewayAddr(),
		tweak: bug4096Quiet,
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar,
		local: gatewayAddr(), router: clientAddr(),
		tweak: bug4096Quiet,
	})
	defer cli.stop()
	defer gw.stop()

	cli.start(ctx)
	gw.start(ctx)
	cli.waitState(session.StateEstablished, 15*time.Second)
	gw.waitState(session.StateEstablished, 15*time.Second)
	waitFor(t, 5*time.Second, "client gate carrying", func() bool {
		return cli.loop.Carrying() && cli.loop.Tunnel().Gate().State() == tunCarrying()
	})

	var mu sync.Mutex
	seen := make([]bool, bug4096Target)
	var unique uint64
	var firstGapAt int = -1

	collect := func(pkt []byte) {
		pl := payloadOf(pkt)
		if len(pl) < 8 {
			return
		}
		seq := binary.BigEndian.Uint64(pl[:8])
		if seq >= uint64(bug4096Target) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !seen[seq] {
			seen[seq] = true
			unique++
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case p := <-gw.dev.out:
				collect(p)
			case <-gw.dev.closed:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Full inner MTU so coalescing cannot pack many datagrams into one
	// sealed message. An 8-byte payload delivered 8192 inner packets inside
	// ~225 outer messages and could not see a 4096 send-counter. Spain's
	// cliff was 4096 inner UDP datagrams near path MTU, one sealed message
	// each. InnerMTU-20 matches TestADeepSendQueueDrainsCompletely.
	if sz.InnerMTU < 28 {
		t.Fatalf("InnerMTU=%d is too small for an IPv4 header plus an 8-byte seq", sz.InnerMTU)
	}
	payload := make([]byte, sz.InnerMTU-20)

	offered := 0
	for i := 0; i < bug4096Target; i++ {
		failIfRunReturned(t, label, "offering", cli, gw, &mu, &unique)
		clear(payload)
		binary.BigEndian.PutUint64(payload, uint64(i))
		pkt := ipv4Packet(clientAddr(), gatewayAddr(), payload)
		select {
		case cli.dev.in <- pkt:
			offered++
		case err := <-cli.err:
			t.Fatalf("%s: client Run returned while offering seq %d (unique delivered %d): %v (session %s err %v)\n%s",
				label, i, loadUnique(&mu, &unique), err, cli.loop.Session().State(), cli.loop.Session().Err(), dump4096(cli, gw))
		case err := <-gw.err:
			t.Fatalf("%s: gateway Run returned while offering seq %d (unique delivered %d): %v (session %s err %v)\n%s",
				label, i, loadUnique(&mu, &unique), err, gw.loop.Session().State(), gw.loop.Session().Err(), dump4096(cli, gw))
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: device input blocked at seq %d (unique delivered %d); session cli=%s gw=%s\n%s",
				label, i, loadUnique(&mu, &unique), cli.loop.Session().State(), gw.loop.Session().State(), dump4096(cli, gw))
		case <-ctx.Done():
			t.Fatalf("%s: context done while offering seq %d: %v\n%s", label, i, ctx.Err(), dump4096(cli, gw))
		}
		if i+1 == bug4096Cliff {
			if cli.loop.Session().State() != session.StateEstablished ||
				gw.loop.Session().State() != session.StateEstablished {
				t.Fatalf("%s: session left Established at the 4096 offer cliff: cli=%s (%v) gw=%s (%v) unique=%d\n%s",
					label, cli.loop.Session().State(), cli.loop.Session().Err(),
					gw.loop.Session().State(), gw.loop.Session().Err(),
					loadUnique(&mu, &unique), dump4096(cli, gw))
			}
			t.Logf("%s: MEASURED still Established after offering 4096 full-MTU datagrams; unique delivered so far=%d\n%s",
				label, loadUnique(&mu, &unique), dump4096(cli, gw))
		}
	}

	deadline := time.Now().Add(45 * time.Second)
	var atCliff session.State
	var cliffLogged bool
	for time.Now().Before(deadline) {
		failIfRunReturned(t, label, "draining", cli, gw, &mu, &unique)
		n := loadUnique(&mu, &unique)
		if !cliffLogged && n >= bug4096Cliff {
			atCliff = cli.loop.Session().State()
			cliffLogged = true
			t.Logf("%s: MEASURED at %d unique deliveries: cli=%s gw=%s carrying=%v\n%s",
				label, n, cli.loop.Session().State(), gw.loop.Session().State(), cli.loop.Carrying(), dump4096(cli, gw))
		}
		if n >= uint64(bug4096Target) {
			break
		}
		if cli.loop.Session().State() != session.StateEstablished ||
			gw.loop.Session().State() != session.StateEstablished {
			t.Fatalf("%s: session left Established after %d unique deliveries (cliff is %d): cli=%s (%v) gw=%s (%v)\n%s",
				label, n, bug4096Cliff,
				cli.loop.Session().State(), cli.loop.Session().Err(),
				gw.loop.Session().State(), gw.loop.Session().Err(),
				dump4096(cli, gw))
		}
		time.Sleep(time.Millisecond)
	}

	n := loadUnique(&mu, &unique)
	mu.Lock()
	for i, ok := range seen {
		if !ok {
			firstGapAt = i
			break
		}
	}
	mu.Unlock()

	if n != uint64(bug4096Target) {
		extra := ""
		if n == uint64(bug4096Cliff) && firstGapAt == bug4096Cliff {
			extra = " this is the Spain 4096 cliff (seq 0-4095 then stop) reproduced on loopback."
		}
		t.Fatalf("%s: delivered %d unique of %d offered (first gap at seq %d); cli=%s gw=%s.%s\n%s",
			label, n, offered, firstGapAt, cli.loop.Session().State(), gw.loop.Session().State(), extra, dump4096(cli, gw))
	}
	if cli.loop.Session().State() != session.StateEstablished {
		t.Fatalf("%s: client is %s at %d deliveries, want Established: %v\n%s",
			label, cli.loop.Session().State(), n, cli.loop.Session().Err(), dump4096(cli, gw))
	}
	if gw.loop.Session().State() != session.StateEstablished {
		t.Fatalf("%s: gateway is %s at %d deliveries, want Established: %v\n%s",
			label, gw.loop.Session().State(), n, gw.loop.Session().Err(), dump4096(cli, gw))
	}
	if !cli.loop.Carrying() {
		t.Fatalf("%s: client Carrying() is false at %d deliveries\n%s", label, n, dump4096(cli, gw))
	}
	failIfRunReturned(t, label, "after 8192", cli, gw, &mu, &unique)

	// Gateway RxPackets stays 0 unless that device has been read (DeviceProven).
	// This drive never offers on the gateway device, so host delivery is the
	// unique payloads on gw.dev.out plus InnerDelivered / RxDeviceWrites.
	inner := gw.loop.Stats().InnerDelivered
	writes := gw.loop.Tunnel().Stats().RxDeviceWrites
	sent := cli.loop.Stats().MessagesSent
	t.Logf("%s: MEASURED alive at %d unique host deliveries; InnerDelivered=%d RxDeviceWrites=%d RxPackets=%d MessagesSent=%d InnerMTU=%d; at-cliff state=%s; offered=%d\n%s",
		label, n, inner, writes, gw.loop.Tunnel().Stats().RxPackets, sent, sz.InnerMTU, atCliff, offered, dump4096(cli, gw))
	if inner < uint64(bug4096Target) {
		t.Fatalf("%s: InnerDelivered=%d, want >= %d", label, inner, bug4096Target)
	}
	if writes < uint64(bug4096Target) {
		t.Fatalf("%s: RxDeviceWrites=%d, want >= %d", label, writes, bug4096Target)
	}
	// Handshake adds a handful of messages; coalescing would leave sent ~200.
	if sent < uint64(bug4096Target) {
		t.Fatalf("%s: MessagesSent=%d, want >= %d (one sealed message per full-MTU inner packet; a lower count means coalescing hid the 4096 counter)",
			label, sent, bug4096Target)
	}
}

func loadUnique(mu *sync.Mutex, unique *uint64) uint64 {
	mu.Lock()
	defer mu.Unlock()
	return *unique
}

func failIfRunReturned(t *testing.T, label, when string, cli, gw *endpoint, mu *sync.Mutex, unique *uint64) {
	t.Helper()
	select {
	case err := <-cli.err:
		t.Fatalf("%s: client Run returned %s (%d unique delivered): %v (session %s err %v)\n%s",
			label, when, loadUnique(mu, unique), err, cli.loop.Session().State(), cli.loop.Session().Err(), dump4096(cli, gw))
	case err := <-gw.err:
		t.Fatalf("%s: gateway Run returned %s (%d unique delivered): %v (session %s err %v)\n%s",
			label, when, loadUnique(mu, unique), err, gw.loop.Session().State(), gw.loop.Session().Err(), dump4096(cli, gw))
	default:
	}
}

func dump4096(cli, gw *endpoint) string {
	cs, gs := cli.loop.Stats(), gw.loop.Stats()
	ct, gt := cli.loop.Tunnel().Stats(), gw.loop.Tunnel().Stats()
	return fmt.Sprintf(
		"cli session=%s err=%v sent=%d recv=%d sendFail=%d innerDel=%d innerRej=%d txPkt=%d txSink=%d txClosed=%d rxPkt=%d rxOff=%d\n"+
			"gw session=%s err=%v sent=%d recv=%d sendFail=%d innerDel=%d innerRej=%d txPkt=%d txSink=%d txClosed=%d rxPkt=%d rxOff=%d rxDevDrop=%d",
		cli.loop.Session().State(), cli.loop.Session().Err(),
		cs.MessagesSent, cs.MessagesReceived, cs.SendFailed, cs.InnerDelivered, cs.InnerRejected,
		ct.TxPackets, ct.TxDroppedSink, ct.TxDroppedClosed, ct.RxPackets, ct.RxOffered,
		gw.loop.Session().State(), gw.loop.Session().Err(),
		gs.MessagesSent, gs.MessagesReceived, gs.SendFailed, gs.InnerDelivered, gs.InnerRejected,
		gt.TxPackets, gt.TxDroppedSink, gt.TxDroppedClosed, gt.RxPackets, gt.RxOffered, gt.RxDroppedDevice,
	)
}
