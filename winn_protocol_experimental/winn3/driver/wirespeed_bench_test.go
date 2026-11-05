package driver

import (
	"context"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// wireDevice is a tun.Device and tun.BatchDevice whose two directions are
// unbounded-throughput sinks rather than a ping-pong.
//
// The existing BenchmarkBatchCarrierLoopThroughput pushes sixteen packets and
// then blocks until all sixteen come out the far end, which measures the
// pipeline's ROUND-TRIP LATENCY divided by sixteen and calls the result
// throughput. MEASURED, Galaxy S26 Ultra, 2026-09-17: it reported 102 MB/s
// while the CPU profile showed a single core busy out of eight, because every
// stage spends most of its life waiting for the stage behind it to be asked
// for more work. A saturated link never behaves that way.
//
// This device instead lets the producer run ahead: the writer refills a free
// list and the reader drains it, so the seal batch, the sendmmsg vector and the
// receive batch all fill the way they do under a real transfer.
type wireDevice struct {
	mtu int

	free chan []byte
	in   chan []byte

	rxPackets atomic.Uint64
	rxBytes   atomic.Uint64

	closeOnce sync.Once
	done      chan struct{}
}

func newWireDevice(mtu, depth int) *wireDevice {
	d := &wireDevice{
		mtu:  mtu,
		free: make(chan []byte, depth),
		in:   make(chan []byte, depth),
		done: make(chan struct{}),
	}
	for i := 0; i < depth; i++ {
		d.free <- make([]byte, mtu)
	}
	return d
}

func (d *wireDevice) MTU() int { return d.mtu }

func (d *wireDevice) Close() {
	d.closeOnce.Do(func() { close(d.done) })
}

// offer hands one outbound packet to the engine, blocking only when the engine
// is genuinely behind. That backpressure is the point: it is what a real tun
// read loop feels when the crypto or the socket cannot keep up.
func (d *wireDevice) offer(pkt []byte) bool {
	var buf []byte
	select {
	case buf = <-d.free:
	case <-d.done:
		return false
	}
	buf = buf[:copy(buf[:cap(buf)], pkt)]
	select {
	case d.in <- buf:
		return true
	case <-d.done:
		return false
	}
}

func (d *wireDevice) ReadPacket(buf []byte) (int, error) {
	select {
	case p := <-d.in:
		n := copy(buf, p)
		d.recycle(p)
		return n, nil
	case <-d.done:
		return 0, errWireClosed
	}
}

func (d *wireDevice) ReadBatch(bufs [][]byte) ([]int, error) {
	if len(bufs) == 0 {
		return nil, nil
	}
	var first []byte
	select {
	case first = <-d.in:
	case <-d.done:
		return nil, errWireClosed
	}
	lengths := make([]int, 0, len(bufs))
	lengths = append(lengths, copy(bufs[0], first))
	d.recycle(first)
	for i := 1; i < len(bufs); i++ {
		select {
		case p := <-d.in:
			lengths = append(lengths, copy(bufs[i], p))
			d.recycle(p)
		default:
			return lengths, nil
		}
	}
	return lengths, nil
}

func (d *wireDevice) recycle(p []byte) {
	select {
	case d.free <- p[:cap(p)]:
	default:
	}
}

// WritePacket is the delivery sink. It counts and discards: a benchmark that
// queued delivered packets would measure the queue, and one that copied them
// would measure the copy.
func (d *wireDevice) WritePacket(pkt []byte) (int, error) {
	d.rxPackets.Add(1)
	d.rxBytes.Add(uint64(len(pkt)))
	return len(pkt), nil
}

var errWireClosed = wireClosedError{}

type wireClosedError struct{}

func (wireClosedError) Error() string { return "winn3: wire bench device closed" }

var (
	_ tun.Device      = (*wireDevice)(nil)
	_ tun.BatchDevice = (*wireDevice)(nil)
)

// benchWirePair builds a carrying client and gateway over a loopback UDP pair.
func benchWirePair(b *testing.B, depth int) (cli *wireDevice, gw *wireDevice, stop func()) {
	return benchWirePairQueue(b, depth, 0)
}

var benchProbe func()

var dumpStacks = os.Getenv("WINN_BENCH_STACKS") != ""

func benchWirePairQueue(b *testing.B, depth, sendQueue int) (cli *wireDevice, gw *wireDevice, stop func()) {
	b.Helper()
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
		admission[i] = byte(i*11 + 3)
	}
	params := core.GatewayParams{
		AdmissionKeys: [][]byte{admission},
		GatewayID:     []byte("winn3-wirespeed-bench"),
	}
	sz, err := NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		b.Fatal(err)
	}
	cliDev := newWireDevice(sz.InnerMTU, depth)
	gwDev := newWireDevice(sz.InnerMTU, depth)
	cliCar, gwCar := loopbackUDPPair(b)

	cliLoop, err := NewClient(Config{
		Session: session.Config{
			Core:          core.Config{Gateway: params},
			Static:        krCli,
			GatewayStatic: pub,
			Padding:       core.PadBucket,
			SendQueue:     sendQueue,
		},
		Sizing:  sz,
		Carrier: cliCar,
		Tun: &tun.Config{
			Assign: tun.Assignment{V4: clientAddr(), RouterV4: gatewayAddr()},
			Device: cliDev,
		},
	})
	if err != nil {
		b.Fatal(err)
	}
	gwLoop, err := NewGateway(Config{
		Session: session.Config{
			Core:    core.Config{Gateway: params},
			Static:    krGw,
			Accept:    func([]byte) error { return nil },
			Padding:   core.PadBucket,
			SendQueue: sendQueue,
		},
		Sizing:  sz,
		Carrier: gwCar,
		Tun: &tun.Config{
			Assign: tun.Assignment{V4: gatewayAddr(), RouterV4: clientAddr()},
			Device: gwDev,
		},
	})
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var cliErr, gwErr atomic.Value
	var cliDone, gwDone atomic.Bool
	go func() {
		if e := cliLoop.Run(ctx); e != nil {
			cliErr.Store(e.Error())
		}
		cliDone.Store(true)
	}()
	go func() {
		if e := gwLoop.Run(ctx); e != nil {
			gwErr.Store(e.Error())
		}
		gwDone.Store(true)
	}()

	deadline := time.Now().Add(15 * time.Second)
	for !cliLoop.Carrying() || !gwLoop.Carrying() {
		if time.Now().After(deadline) {
			cancel()
			b.Fatal("tunnel did not reach carrying state")
		}
		time.Sleep(time.Millisecond)
	}
	benchProbe = func() {
		b.Logf("client run finished=%v err=%v | gateway run finished=%v err=%v",
			cliDone.Load(), cliErr.Load(), gwDone.Load(), gwErr.Load())
		b.Logf("client state=%v carrying=%v | gateway state=%v carrying=%v",
			cliLoop.Session().State(), cliLoop.Carrying(),
			gwLoop.Session().State(), gwLoop.Carrying())
		cs, gs := cliLoop.Stats(), gwLoop.Stats()
		b.Logf("client sent=%d recv=%d sendFailed=%d | gateway sent=%d recv=%d sendFailed=%d innerDelivered=%d",
			cs.MessagesSent, cs.MessagesReceived, cs.SendFailed,
			gs.MessagesSent, gs.MessagesReceived, gs.SendFailed, gs.InnerDelivered)
		if t := cliLoop.Tunnel(); t != nil {
			st := t.Stats()
			b.Logf("client tun: reads=%d tx=%d dropSink=%d dropClosed=%d dropInvalid=%d",
				st.DeviceReads, st.TxPackets, st.TxDroppedSink, st.TxDroppedClosed, st.TxDroppedInvalid)
		}
		if dumpStacks {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			b.Logf("GOROUTINES:\n%s", buf[:n])
		}
	}
	return cliDev, gwDev, func() {
		cancel()
		cliDev.Close()
		gwDev.Close()
		_ = cliLoop.Close()
		_ = gwLoop.Close()
	}
}

// wireWindow is how many inner packets may be in flight between the producer
// and the far side's delivery counter.
//
// An open-loop producer measures nothing useful here. The session send queue
// drops when it is full (frameSink.SendData returns ErrQueueFull and the tun
// layer counts TxDroppedSink), so a producer that never waits simply discards
// the surplus and the benchmark reports how fast a for-loop can throw packets
// away. MEASURED, before this window existed: 20,000 packets offered, 1,216
// delivered, 18,784 dropped at the sink, and a throughput number that moved
// with the queue depth rather than with the datapath.
//
// A window is what a real TCP flow imposes. 4096 packets at the inner MTU is
// about 5.5 MB, comfortably above the bandwidth-delay product of a gigabit path
// with a 30 ms round trip, so the window bounds the queue rather than the rate.
const wireWindow = 4096

// runWireLoad offers packets until the deadline, keeping at most wireWindow of
// them unacknowledged, and reports the delivered rate.
func runWireLoad(b *testing.B, src *wireDevice, pkt []byte, sink *wireDevice, dur time.Duration) (pkts, bytes uint64, elapsed time.Duration) {
	start := time.Now()
	end := start.Add(dur)
	var offered uint64
	for time.Now().Before(end) {
		for i := 0; i < 256; i++ {
			for offered-sink.rxPackets.Load() >= wireWindow {
				if time.Now().After(end) {
					goto done
				}
				time.Sleep(20 * time.Microsecond)
			}
			if !src.offer(pkt) {
				goto done
			}
			offered++
		}
	}
done:
	// Drain the tail: what is already sealed and in flight still counts.
	drainUntil := time.Now().Add(250 * time.Millisecond)
	for sink.rxPackets.Load() < offered && time.Now().Before(drainUntil) {
		time.Sleep(200 * time.Microsecond)
	}
	elapsed = time.Since(start)
	return sink.rxPackets.Load(), sink.rxBytes.Load(), elapsed
}

func reportWire(b *testing.B, pkts, bytes uint64, elapsed time.Duration) {
	secs := elapsed.Seconds()
	b.ReportMetric(float64(bytes)*8/secs/1e9, "Gbit/s")
	b.ReportMetric(float64(pkts)/secs/1e6, "Mpps")
}

// BenchmarkWireSpeedUpload saturates the client-to-gateway direction, which is
// the shape of a real upload: one tun read loop feeding one session.
func BenchmarkWireSpeedUpload(b *testing.B) {
	cliDev, gwDev, stop := benchWirePair(b, wireWindow)
	defer stop()
	payload := make([]byte, cliDev.mtu-28)
	pkt := ipv4Packet(clientAddr(), gatewayAddr(), payload)
	b.ReportAllocs()
	b.ResetTimer()
	p, n, el := runWireLoad(b, cliDev, pkt, gwDev, 3*time.Second)
	b.StopTimer()
	if benchProbe != nil {
		benchProbe()
	}
	reportWire(b, p, n, el)
	if p == 0 {
		b.Fatal("no packets delivered")
	}
}

// BenchmarkWireSpeedDownload saturates the gateway-to-client direction. It is
// the direction that matters most for a consumer VPN and the one whose client
// side has to decrypt rather than encrypt.
func BenchmarkWireSpeedDownload(b *testing.B) {
	cliDev, gwDev, stop := benchWirePair(b, wireWindow)
	defer stop()
	payload := make([]byte, gwDev.mtu-28)
	pkt := ipv4Packet(gatewayAddr(), clientAddr(), payload)
	b.ReportAllocs()
	b.ResetTimer()
	p, n, el := runWireLoad(b, gwDev, pkt, cliDev, 3*time.Second)
	b.StopTimer()
	if benchProbe != nil {
		benchProbe()
	}
	reportWire(b, p, n, el)
	if p == 0 {
		b.Fatal("no packets delivered")
	}
}

// BenchmarkWireSpeedBidir runs both directions at once: bulk one way, bulk the
// other, sharing one crypto pool, one session lock and one socket per end.
func BenchmarkWireSpeedBidir(b *testing.B) {
	cliDev, gwDev, stop := benchWirePair(b, wireWindow)
	defer stop()
	payload := make([]byte, cliDev.mtu-28)
	up := ipv4Packet(clientAddr(), gatewayAddr(), payload)
	down := ipv4Packet(gatewayAddr(), clientAddr(), payload)
	b.ReportAllocs()
	b.ResetTimer()

	var wg sync.WaitGroup
	var dp, dn uint64
	var del time.Duration
	wg.Add(1)
	go func() {
		defer wg.Done()
		dp, dn, del = runWireLoad(b, gwDev, down, cliDev, 3*time.Second)
	}()
	up1, un, uel := runWireLoad(b, cliDev, up, gwDev, 3*time.Second)
	wg.Wait()
	b.StopTimer()
	if benchProbe != nil {
		benchProbe()
	}
	el := uel
	if del > el {
		el = del
	}
	reportWire(b, up1+dp, un+dn, el)
}

// BenchmarkWireSpeedSendQueue sweeps the session send-queue depth. The depth is
// the only thing standing between a scheduling hiccup and a dropped burst: at a
// gigabit with a 1.4 kB inner MTU the link moves about 89,000 packets a second,
// so 256 slots is 2.9 milliseconds of buffer and 2048 is 23.
func BenchmarkWireSpeedSendQueue(b *testing.B) {
	for _, q := range []int{256, 1024, 4096} {
		b.Run(itoa(q), func(b *testing.B) {
			cliDev, gwDev, stop := benchWirePairQueue(b, wireWindow, q)
			defer stop()
			payload := make([]byte, cliDev.mtu-28)
			pkt := ipv4Packet(clientAddr(), gatewayAddr(), payload)
			b.ReportAllocs()
			b.ResetTimer()
			p, n, el := runWireLoad(b, cliDev, pkt, gwDev, 3*time.Second)
			b.StopTimer()
			reportWire(b, p, n, el)
		})
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
