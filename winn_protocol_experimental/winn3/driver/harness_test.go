package driver

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Addresses are built from bytes rather than written in dotted form, the same
// convention winn3/tun uses, so that nothing in this tree contains a literal
// address. The inner range is RFC 1918; nothing here is any node this project
// runs, and no socket in this file leaves the loopback interface.

func v4a(a, b, c, d byte) netip.Addr { return netip.AddrFrom4([4]byte{a, b, c, d}) }

func clientAddr() netip.Addr { return v4a(10, 64, 0, 2) }
func gatewayAddr() netip.Addr {
	return v4a(10, 64, 0, 1)
}

// --- the host device ----------------------------------------------------------

var errDeviceClosed = errors.New("test device closed")

// fakeDevice stands in for utun / VpnService / WinTun. It honours the real
// contract: ReadPacket blocks, and it unblocks when the HOST closes the device,
// which is the lifecycle tun.Device documents and the reason the loop does not
// wait for the device pump.
type fakeDevice struct {
	mtu int
	in  chan []byte
	out chan []byte

	// writing and release make one WritePacket observable and blockable, which
	// is how a test holds a tun gate read-hold open across another goroutine's
	// Gate.Set and so observes the drain barrier from outside the tun package.
	block   atomic.Bool
	writing chan struct{}
	release chan struct{}

	closeOnce sync.Once
	closed    chan struct{}
}

func newDevice(mtu int) *fakeDevice {
	return &fakeDevice{
		mtu:     mtu,
		in:      make(chan []byte, 256),
		out:     make(chan []byte, 1024),
		writing: make(chan struct{}, 1),
		release: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (d *fakeDevice) ReadPacket(buf []byte) (int, error) {
	select {
	case p := <-d.in:
		return copy(buf, p), nil
	case <-d.closed:
		return 0, errDeviceClosed
	}
}

func (d *fakeDevice) WritePacket(pkt []byte) (int, error) {
	if d.block.Load() {
		select {
		case d.writing <- struct{}{}:
		default:
		}
		<-d.release
	}
	cp := append([]byte(nil), pkt...)
	select {
	case d.out <- cp:
		return len(pkt), nil
	case <-d.closed:
		return 0, errDeviceClosed
	default:
		// Never block the reader goroutine: it holds a gate read-hold, and a
		// blocked hold would wedge a teardown.
		return 0, errors.New("test device output is full")
	}
}

func (d *fakeDevice) MTU() int { return d.mtu }

func (d *fakeDevice) Close() { d.closeOnce.Do(func() { close(d.closed) }) }

// offer hands a packet to the device as though the host stack had generated it.
func (d *fakeDevice) offer(t *testing.T, pkt []byte) {
	t.Helper()
	select {
	case d.in <- pkt:
	case <-time.After(2 * time.Second):
		t.Fatal("device input is full")
	}
}

// take waits for one packet to be written to the host.
func (d *fakeDevice) take(t *testing.T, within time.Duration) []byte {
	t.Helper()
	select {
	case p := <-d.out:
		return p
	case <-time.After(within):
		t.Fatalf("no packet reached the host device within %s", within)
		return nil
	}
}

// --- inner packets ------------------------------------------------------------

// ipv4Packet builds a well-formed inner IPv4 packet with a correct header
// checksum, because the tun layer verifies it and a test that could not build a
// valid packet would be testing the builder.
func ipv4Packet(src, dst netip.Addr, payload []byte) []byte {
	total := 20 + len(payload)
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	binary.BigEndian.PutUint16(b[4:6], 0x1234)
	b[8] = 64 // TTL
	b[9] = 17 // UDP; nothing in this tree parses above the IP header
	s := src.As4()
	dd := dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], dd[:])
	binary.BigEndian.PutUint16(b[10:12], ipv4Checksum(b[:20]))
	copy(b[20:], payload)
	return b
}

func ipv4Checksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// payloadOf returns the bytes after the IPv4 header, which is what a digest
// comparison is about: the tunnel must deliver the packet it was given.
func payloadOf(pkt []byte) []byte {
	if len(pkt) < 20 {
		return nil
	}
	return pkt[20:]
}

// --- clocks -------------------------------------------------------------------

// stepClock is a manually advanced clock with real timers, used by the tests
// that need to control the session's schedule without sleeping.
type stepClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*stepTimer
}

func newStepClock() *stepClock {
	return &stepClock{now: time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)}
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *stepClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &stepTimer{at: c.now.Add(d), ch: make(chan time.Time, 1)}
	if d <= 0 {
		// A real time.Timer with a non-positive duration fires immediately. A
		// fake that queued it instead would mask a loop that spins on a
		// zero-length wait, which is the busy-wait this clock exists to detect.
		t.ch <- c.now
		return t
	}
	c.timers = append(c.timers, t)
	return t
}

func (c *stepClock) pendingTimers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

func (c *stepClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	live := c.timers[:0]
	var fire []*stepTimer
	for _, t := range c.timers {
		if !t.stopped.Load() && !now.Before(t.at) {
			fire = append(fire, t)
			continue
		}
		live = append(live, t)
	}
	c.timers = live
	c.mu.Unlock()
	for _, t := range fire {
		select {
		case t.ch <- now:
		default:
		}
	}
}

// stepTimer's stopped flag is atomic, and it has to be.
//
// Loop.waitForWork defers Stop, so it runs on the WRITE goroutine, on a timer
// that stepClock.Advance is concurrently scanning from the test goroutine under
// the clock's mutex. A plain bool is an unsynchronised write against that read
// and `go test -race` reports it on the first Pair-style run — the network-
// realism lane hit it immediately when it copied this clock into winn3/netlab.
// Taking the clock's mutex in Stop instead would be the other fix and is the
// worse one: Advance holds that mutex while it walks the timer list, so a Stop
// arriving mid-walk would serialise the loop behind the test's clock.
type stepTimer struct {
	at      time.Time
	ch      chan time.Time
	stopped atomic.Bool
}

func (t *stepTimer) C() <-chan time.Time { return t.ch }
func (t *stepTimer) Stop()               { t.stopped.Store(true) }

// --- endpoints ----------------------------------------------------------------

// keyring is one gateway's material plus one client's, shared by both halves of
// a pair exactly as the ML-DSA-signed descriptor would supply it.
type keyring struct {
	gwStatic  *core.StaticKey
	cliStatic *core.StaticKey
	gwPublic  *core.PublicKey
	params    core.GatewayParams
}

func newKeyring(t *testing.T) *keyring {
	t.Helper()
	gw, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	cli, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := core.NewPublicKey(gw.Public())
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	for i := range admission {
		admission[i] = byte(i * 7)
	}
	return &keyring{
		gwStatic:  gw,
		cliStatic: cli,
		gwPublic:  pub,
		params: core.GatewayParams{
			AdmissionKeys: [][]byte{admission},
			GatewayID:     []byte("winn3-driver-loopback-fixture"),
		},
	}
}

// endpoint is one half of a tunnel: a loop, its device, and the goroutine
// running it.
type endpoint struct {
	t    *testing.T
	loop *Loop
	dev  *fakeDevice
	err  chan error
}

type endpointOpts struct {
	sizing  Sizing
	carrier carrier.Conn
	clock   Clock
	local   netip.Addr
	router  netip.Addr
	tweak   func(*session.Config)
	noTun   bool
	// clamping wraps the test device in clampingDevice so it implements
	// tun.MTUSetter. The unwrapped fakeDevice does not: it models production
	// hosts that cannot SetMTU, which is why the mismatch tests still refuse.
	clamping bool
}

func newClientEndpoint(t *testing.T, kr *keyring, o endpointOpts) *endpoint {
	t.Helper()
	cfg := session.Config{
		Core:          core.Config{Gateway: kr.params},
		Static:        kr.cliStatic,
		GatewayStatic: kr.gwPublic,
		Padding:       core.PadBucket,
	}
	if o.tweak != nil {
		o.tweak(&cfg)
	}
	return newEndpoint(t, cfg, o, NewClient)
}

func newGatewayEndpoint(t *testing.T, kr *keyring, o endpointOpts) *endpoint {
	t.Helper()
	cfg := session.Config{
		Core:    core.Config{Gateway: kr.params},
		Static:  kr.gwStatic,
		Accept:  func([]byte) error { return nil },
		Padding: core.PadBucket,
	}
	if o.tweak != nil {
		o.tweak(&cfg)
	}
	return newEndpoint(t, cfg, o, NewGateway)
}

func newEndpoint(
	t *testing.T, sc session.Config, o endpointOpts,
	build func(Config) (*Loop, error),
) *endpoint {
	t.Helper()
	cfg := Config{Session: sc, Sizing: o.sizing, Carrier: o.carrier, Clock: o.clock}
	var dev *fakeDevice
	if !o.noTun {
		dev = newDevice(o.sizing.InnerMTU)
		clk := o.clock
		if clk == nil {
			clk = SystemClock{}
		}
		var device tun.Device = dev
		if o.clamping {
			device = &clampingDevice{fakeDevice: dev}
		}
		cfg.Tun = &tun.Config{
			Assign:    tun.Assignment{V4: o.local, RouterV4: o.router},
			Device:    device,
			Clock:     SessionClock{Clock: clk},
			ICMPBurst: 4,
		}
	}
	l, err := build(cfg)
	if err != nil {
		t.Fatalf("build loop: %v", err)
	}
	return &endpoint{t: t, loop: l, dev: dev, err: make(chan error, 1)}
}

func (e *endpoint) start(ctx context.Context) {
	go func() { e.err <- e.loop.Run(ctx) }()
}

func (e *endpoint) stop() {
	if e.dev != nil {
		e.dev.Close()
	}
}

// waitState blocks until the session reaches want, or fails the test.
func (e *endpoint) waitState(want session.State, within time.Duration) {
	e.t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if got := e.loop.Session().State(); got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	e.t.Fatalf("session is %s after %s, want %s (err %v)",
		e.loop.Session().State(), within, want, e.loop.Session().Err())
}

// waitRun waits for Run to return.
func (e *endpoint) waitRun(within time.Duration) error {
	e.t.Helper()
	select {
	case err := <-e.err:
		return err
	case <-time.After(within):
		e.t.Fatalf("Run did not return within %s", within)
		return nil
	}
}

// waitFor polls cond until it holds.
func waitFor(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", within, what)
}

// coreConfigFor is the core configuration both halves of a fixture share.
func coreConfigFor(kr *keyring) core.Config {
	return core.Config{Gateway: kr.params}
}

// tunCarrying is the tun layer's one carrying state, named here so tests that
// open a gate by hand do not have to import the package for one constant.
func tunCarrying() tun.State { return tun.StateCarrying }

// TestTheStepClockIsSafeAgainstAConcurrentStop is defect 5 of
// WINN3_NETWORK_REALISM_20260808.md §9.1, pinned.
//
// The bug was in this file: stepTimer.Stop() wrote a plain bool while
// stepClock.Advance read it under the clock's mutex. It is not hypothetical
// plumbing — Loop.waitForWork DEFERS Stop, so it runs on the write goroutine on
// a timer the test goroutine is concurrently scanning, and the netlab lane's
// `go test -race` reported it on the first run of its Pair rig.
//
// Reproducing it through a Loop needs a wake and an Advance to overlap, which is
// a scheduling coincidence: the defect went unnoticed here for exactly that
// reason while a busier rig hit it immediately. So this drives the two sides
// directly and hard. It is a test of a test helper, which is worth writing
// precisely once: a racy clock does not fail, it produces measurements nobody
// can trust.
func TestTheStepClockIsSafeAgainstAConcurrentStop(t *testing.T) {
	c := newStepClock()
	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// The shape waitForWork produces: build a timer, then Stop it from
			// this goroutine while the clock is being advanced from another.
			tm := c.NewTimer(time.Hour)
			tm.Stop()
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			c.Advance(time.Millisecond)
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()

	// The clock must still be functional afterwards, so that a mutation which
	// "fixes" the race by breaking Stop is not mistaken for a pass.
	tm := c.NewTimer(time.Second)
	c.Advance(2 * time.Second)
	select {
	case <-tm.C():
	case <-time.After(2 * time.Second):
		t.Fatal("a timer whose deadline passed never fired; the clock is broken, not merely safe")
	}
	stopped := c.NewTimer(time.Second)
	stopped.Stop()
	c.Advance(2 * time.Second)
	select {
	case <-stopped.C():
		t.Fatal("a stopped timer fired; Stop does nothing and the race was 'fixed' by removing it")
	default:
	}
}
