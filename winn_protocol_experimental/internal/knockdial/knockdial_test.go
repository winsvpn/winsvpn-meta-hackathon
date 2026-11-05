package knockdial

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/knock"
)

const testPacketSize = 1200

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating a test key: %v", err)
	}
	return key
}

// fakePacketDialer is a carrier.PacketSocketDialer that performs no I/O. It
// exists so the decorator's own behaviour can be observed without standing up a
// real carrier, which would need certificates, ECH material and a server.
type fakePacketDialer struct {
	kind     carrier.SocketKind
	useErr   error
	dialErr  error
	dialConn net.PacketConn

	mu        sync.Mutex
	supplied  net.PacketConn
	dialCount int
}

func (f *fakePacketDialer) Dial(ctx context.Context) (net.PacketConn, error) {
	f.mu.Lock()
	f.dialCount++
	f.mu.Unlock()
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	return f.dialConn, nil
}

func (f *fakePacketDialer) SuppliedSocketKind() carrier.SocketKind {
	if f.kind == "" {
		return carrier.SocketKindPacket
	}
	return f.kind
}

func (f *fakePacketDialer) HasSuppliedSocket() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.supplied != nil
}

func (f *fakePacketDialer) UseSuppliedSocket(conn net.PacketConn) error {
	if f.useErr != nil {
		return f.useErr
	}
	f.mu.Lock()
	f.supplied = conn
	f.mu.Unlock()
	return nil
}

func (f *fakePacketDialer) dials() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dialCount
}

// fakeStreamDialer is the HTTP/2 shape: a connected TCP socket.
type fakeStreamDialer struct{ supplied net.Conn }

func (f *fakeStreamDialer) Dial(context.Context) (net.PacketConn, error) {
	return nil, errors.New("not dialed in this test")
}
func (f *fakeStreamDialer) SuppliedSocketKind() carrier.SocketKind {
	return carrier.SocketKindStream
}
func (f *fakeStreamDialer) HasSuppliedSocket() bool { return f.supplied != nil }
func (f *fakeStreamDialer) UseSuppliedSocket(c net.Conn) error {
	f.supplied = c
	return nil
}

var _ carrier.StreamSocketDialer = (*fakeStreamDialer)(nil)

// recordingConn is a net.PacketConn that keeps a copy of everything written
// through it and forwards the write unchanged. It is how the tests capture the
// exact bytes that went on the wire without replacing the real send path.
type recordingConn struct {
	net.PacketConn
	mu      sync.Mutex
	written [][]byte
	targets []net.Addr
}

func (c *recordingConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.written = append(c.written, append([]byte(nil), p...))
	c.targets = append(c.targets, addr)
	c.mu.Unlock()
	return c.PacketConn.WriteTo(p, addr)
}

func (c *recordingConn) records() ([][]byte, []net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.written...), append([]net.Addr(nil), c.targets...)
}

// --- construction ---------------------------------------------------------

// TestStreamCarrierIsRefusedAtConstruction is the fail-closed boundary that
// matters most on Android: rather than quietly opening an unprotected UDP
// socket beside a protected TCP one, the whole dialer refuses to exist, before
// any I/O.
func TestStreamCarrierIsRefusedAtConstruction(t *testing.T) {
	_, err := New(&fakeStreamDialer{}, Config{
		Key: testKey(t), Target: "203.0.113.9:9110", PacketSize: testPacketSize,
	})
	if !errors.Is(err, ErrStreamCarrierUnsupported) {
		t.Fatalf("stream carrier error = %v, want ErrStreamCarrierUnsupported", err)
	}
}

// TestPacketDialerReportingAStreamKindIsRefused closes the gap between the two
// checks: a dialer can satisfy the packet interface and still declare it wants
// a stream socket, and the declared kind is what datapath acts on.
func TestPacketDialerReportingAStreamKindIsRefused(t *testing.T) {
	_, err := New(&fakePacketDialer{kind: carrier.SocketKindStream}, Config{
		Key: testKey(t), Target: "203.0.113.9:9110", PacketSize: testPacketSize,
	})
	if !errors.Is(err, ErrStreamCarrierUnsupported) {
		t.Fatalf("mismatched kind error = %v, want ErrStreamCarrierUnsupported", err)
	}
}

func TestConstructionRefusals(t *testing.T) {
	valid := Config{
		Key: testKey(t), Target: "203.0.113.9:9110", PacketSize: testPacketSize,
	}
	cases := map[string]struct {
		inner   carrier.SuppliedSocketDialer
		mutate  func(*Config)
		wantErr error
	}{
		"no inner dialer": {
			inner: nil, mutate: func(*Config) {}, wantErr: ErrInnerDialerRequired,
		},
		"no target": {
			inner:  &fakePacketDialer{},
			mutate: func(c *Config) { c.Target = "" }, wantErr: ErrTargetRequired,
		},
		"target without a port": {
			inner:  &fakePacketDialer{},
			mutate: func(c *Config) { c.Target = "203.0.113.9" },
		},
		"settle beyond the ceiling": {
			inner:   &fakePacketDialer{},
			mutate:  func(c *Config) { c.Settle = MaxSettle + time.Second },
			wantErr: ErrSettleTooLong,
		},
		"negative settle": {
			inner:  &fakePacketDialer{},
			mutate: func(c *Config) { c.Settle = -time.Second },
		},
		// The key and size are checked by building one throwaway knock at
		// construction, so a deployment learns here rather than by silently
		// never sending anything.
		"key too short": {
			inner:  &fakePacketDialer{},
			mutate: func(c *Config) { c.Key = []byte("short") },
		},
		"no key at all": {
			inner:  &fakePacketDialer{},
			mutate: func(c *Config) { c.Key = nil },
		},
		"packet smaller than the header": {
			inner:  &fakePacketDialer{},
			mutate: func(c *Config) { c.PacketSize = knock.HeaderSize - 1 },
		},
		"impossible freshness policy": {
			inner: &fakePacketDialer{},
			mutate: func(c *Config) {
				c.Options = knock.Options{BucketWindow: time.Minute, MaxSkew: time.Second}
			},
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			testCase.mutate(&cfg)
			dialer, err := New(testCase.inner, cfg)
			if err == nil {
				t.Fatalf("%s was accepted (dialer %v)", name, dialer)
			}
			if testCase.wantErr != nil && !errors.Is(err, testCase.wantErr) {
				t.Fatalf("error = %v, want %v", err, testCase.wantErr)
			}
		})
	}
}

// TestDecoratorHoldsNoSocketUntilOneIsSupplied is the property
// datapath.OpenWithCarrier depends on: it refuses a dialer that already holds a
// socket (ErrCarrierSocketReused), so wrapping must not make HasSuppliedSocket
// true on its own.
func TestDecoratorHoldsNoSocketUntilOneIsSupplied(t *testing.T) {
	inner := &fakePacketDialer{}
	dialer, err := New(inner, Config{
		Key: testKey(t), Target: "203.0.113.9:9110", PacketSize: testPacketSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dialer.HasSuppliedSocket() {
		t.Fatal("a freshly wrapped dialer reported holding a socket")
	}
	if dialer.SuppliedSocketKind() != carrier.SocketKindPacket {
		t.Fatalf("socket kind = %q, want %q",
			dialer.SuppliedSocketKind(), carrier.SocketKindPacket)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := dialer.UseSuppliedSocket(conn); err != nil {
		t.Fatal(err)
	}
	if !dialer.HasSuppliedSocket() || !inner.HasSuppliedSocket() {
		t.Fatal("the supplied socket did not reach the inner dialer")
	}
}

// TestSuppliedSocketErrorIsNotSwallowed keeps the decorator from recording a
// socket the carrier itself rejected, which would leave the knock going out
// over a socket the transport is not using.
func TestSuppliedSocketErrorIsNotSwallowed(t *testing.T) {
	refusal := errors.New("inner refused")
	dialer, err := New(&fakePacketDialer{useErr: refusal}, Config{
		Key: testKey(t), Target: "203.0.113.9:9110", PacketSize: testPacketSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := dialer.UseSuppliedSocket(conn); !errors.Is(err, refusal) {
		t.Fatalf("UseSuppliedSocket error = %v, want the inner refusal", err)
	}
	dialer.mu.Lock()
	recorded := dialer.packets
	dialer.mu.Unlock()
	if recorded != nil {
		t.Fatal("a socket the inner dialer refused was recorded anyway")
	}
}

// --- dialing --------------------------------------------------------------

// TestKnockGoesOutOnTheSuppliedSocket is the central claim of this package: the
// knock leaves the HOST'S OWN PROTECTED SOCKET, not one this code opened, and it
// is a well-formed knock addressed to the configured target.
func TestKnockGoesOutOnTheSuppliedSocket(t *testing.T) {
	key := testKey(t)
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	recorder := &recordingConn{PacketConn: client}

	inner := &fakePacketDialer{dialConn: target}
	dialer, err := New(inner, Config{
		Key:        key,
		Target:     target.LocalAddr().String(),
		PacketSize: testPacketSize,
		Settle:     time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dialer.UseSuppliedSocket(recorder); err != nil {
		t.Fatal(err)
	}
	if _, err := dialer.Dial(context.Background()); err != nil {
		t.Fatalf("dial: %v", err)
	}
	if inner.dials() != 1 {
		t.Fatalf("inner dialed %d times, want 1", inner.dials())
	}

	written, targets := recorder.records()
	if len(written) != 1 {
		t.Fatalf("wrote %d datagrams, want exactly 1", len(written))
	}
	if len(written[0]) != testPacketSize {
		t.Fatalf("knock was %d bytes, want %d", len(written[0]), testPacketSize)
	}
	if targets[0].String() != target.LocalAddr().String() {
		t.Fatalf("knock went to %s, want %s", targets[0], target.LocalAddr())
	}
	if _, _, err := knock.Verify(
		written[0], [][]byte{key}, time.Now(), knock.Options{},
	); err != nil {
		t.Fatalf("the datagram this package sent does not verify: %v", err)
	}

	// It really was received, not merely written.
	buf := make([]byte, 2048)
	if err := target.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, from, err := target.ReadFrom(buf)
	if err != nil {
		t.Fatalf("the target never received the knock: %v", err)
	}
	if n != testPacketSize {
		t.Fatalf("received %d bytes, want %d", n, testPacketSize)
	}
	if from.String() != recorder.LocalAddr().String() {
		t.Fatalf("knock came from %s, want the supplied socket %s",
			from, recorder.LocalAddr())
	}
}

// TestEveryDialSendsAFreshKnock: nonces are the replay key, so a second dial
// must not reuse the first dial's datagram.
func TestEveryDialSendsAFreshKnock(t *testing.T) {
	key := testKey(t)
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	recorder := &recordingConn{PacketConn: client}

	dialer, err := New(&fakePacketDialer{dialConn: target}, Config{
		Key: key, Target: target.LocalAddr().String(),
		PacketSize: testPacketSize, Settle: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dialer.UseSuppliedSocket(recorder); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := dialer.Dial(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	written, _ := recorder.records()
	if len(written) != 2 {
		t.Fatalf("wrote %d datagrams, want 2", len(written))
	}
	first, _, err := knock.Verify(written[0], [][]byte{key}, time.Now(), knock.Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := knock.Verify(written[1], [][]byte{key}, time.Now(), knock.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two dials reused one nonce; a captured knock would re-open the port")
	}
}

// TestDialProceedsWhenTheKnockCannotBeSent is the documented fallback. A client
// cannot tell a delivered knock from a dropped one — nothing is ever answered —
// so a local write failure must not be converted into a guaranteed dial
// failure.
func TestDialProceedsWhenTheKnockCannotBeSent(t *testing.T) {
	inner := &fakePacketDialer{}
	dialer, err := New(inner, Config{
		Key: testKey(t), Target: "203.0.113.9:9110", PacketSize: testPacketSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := dialer.UseSuppliedSocket(client); err != nil {
		t.Fatal(err)
	}
	dialer.sendVia = func(net.PacketConn, net.Addr, []byte, int, knock.Options) error {
		return errors.New("network unreachable")
	}
	// A failed knock must also skip the settle wait: there is nothing to settle.
	dialer.sleep = func(context.Context, time.Duration) {
		t.Fatal("settled after a knock that was never sent")
	}
	if _, err := dialer.Dial(context.Background()); err != nil {
		t.Fatalf("dial was aborted by a knock failure: %v", err)
	}
	if inner.dials() != 1 {
		t.Fatalf("inner dialed %d times, want 1", inner.dials())
	}
}

// TestNoSuppliedSocketUsesItsOwn covers the desktop and Linux route, where
// datapath installs nothing because allow_own_socket is set and outer traffic is
// excluded by route instead of by a protected descriptor. The knock is then
// exactly as protected as the transport, which is the rule this package follows.
func TestNoSuppliedSocketUsesItsOwn(t *testing.T) {
	inner := &fakePacketDialer{}
	dialer, err := New(inner, Config{
		Key: testKey(t), Target: "203.0.113.9:9110", PacketSize: testPacketSize,
		Settle: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	var ownCalls, viaCalls int
	dialer.sendOwn = func(context.Context, string, []byte, int, knock.Options) error {
		ownCalls++
		return nil
	}
	dialer.sendVia = func(net.PacketConn, net.Addr, []byte, int, knock.Options) error {
		viaCalls++
		return nil
	}
	if _, err := dialer.Dial(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ownCalls != 1 || viaCalls != 0 {
		t.Fatalf("own=%d via=%d, want own=1 via=0", ownCalls, viaCalls)
	}
}

// TestSettleIsBoundedByTheDialContext keeps a settle delay from outliving a
// cancelled connect attempt.
func TestSettleIsBoundedByTheDialContext(t *testing.T) {
	inner := &fakePacketDialer{}
	dialer, err := New(inner, Config{
		Key: testKey(t), Target: "203.0.113.9:9110", PacketSize: testPacketSize,
		Settle: MaxSettle,
	})
	if err != nil {
		t.Fatal(err)
	}
	dialer.sendOwn = func(context.Context, string, []byte, int, knock.Options) error {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := dialer.Dial(ctx); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed >= MaxSettle {
		t.Fatalf("settle waited %s despite a cancelled context", elapsed)
	}
}

func TestNilDialContextIsRefused(t *testing.T) {
	dialer, err := New(&fakePacketDialer{}, Config{
		Key: testKey(t), Target: "203.0.113.9:9110", PacketSize: testPacketSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	//nolint:staticcheck // passing nil is exactly what this test asserts about.
	if _, err := dialer.Dial(nil); err == nil {
		t.Fatal("a nil dial context was accepted")
	}
}

// TestDescribeForLogNeverNamesTheKey guards the standing rule that no key, and
// nothing derived from one, reaches a log line.
func TestDescribeForLogNeverNamesTheKey(t *testing.T) {
	key := testKey(t)
	dialer, err := New(&fakePacketDialer{}, Config{
		Key: key, Target: "203.0.113.9:9110", PacketSize: testPacketSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	line := dialer.DescribeForLog()
	// Both encodings a key could plausibly be spilled in: raw and hex. Even a
	// four-byte prefix appearing would be a leak worth failing on.
	for _, encoded := range []string{
		string(key), hex.EncodeToString(key), hex.EncodeToString(key[:4]),
	} {
		if strings.Contains(line, encoded) {
			t.Fatal("DescribeForLog emitted key material")
		}
	}
	if !strings.Contains(line, "203.0.113.9:9110") {
		t.Fatalf("DescribeForLog omitted the target it is supposed to name: %q", line)
	}
}

// --- interoperability with the real gate ----------------------------------

// TestKnockFromThisPackageOpensARealGate is the end-to-end proof that this
// decorator and internal/knock's server side agree: a real knock.Gate, wrapping
// a real UDP socket, authorizes the source this package knocked from — and a
// replay of the captured datagram, after the window lapses, does not re-open it.
//
// Real sockets, real Gate, no stubs on either side; only the gate's clock is
// controllable, so the window can be made to lapse without the test sleeping.
func TestKnockFromThisPackageOpensARealGate(t *testing.T) {
	key := testKey(t)
	// A wide skew tolerance so the clock can be pushed past the 90s grace
	// window without the replayed datagram failing on freshness instead of on
	// the replay check, which is the property under test.
	options := knock.Options{BucketWindow: 10 * time.Second, MaxSkew: 10 * time.Minute}

	gateConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gateConn.Close()

	var clockMu sync.Mutex
	clock := time.Now()
	gate, err := knock.NewGate([][]byte{key}, testPacketSize, knock.GateConfig{
		Options: options,
		Now: func() time.Time {
			clockMu.Lock()
			defer clockMu.Unlock()
			return clock
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		clock = clock.Add(d)
		clockMu.Unlock()
	}

	gated := gate.WrapPacketConn(gateConn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			if _, _, err := gated.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	defer func() {
		_ = gateConn.Close()
		<-done
	}()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	recorder := &recordingConn{PacketConn: client}

	dialer, err := New(&fakePacketDialer{}, Config{
		Key: key, Target: gateConn.LocalAddr().String(),
		PacketSize: testPacketSize, Options: options, Settle: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dialer.UseSuppliedSocket(recorder); err != nil {
		t.Fatal(err)
	}
	if _, err := dialer.Dial(context.Background()); err != nil {
		t.Fatal(err)
	}

	clientIP := netip.MustParseAddrPort(recorder.LocalAddr().String()).Addr().Unmap()
	if !waitFor(func() bool { return gate.Authorized(clientIP) }) {
		t.Fatal("a real gate did not authorize the source this package knocked from")
	}

	// Let the sliding window lapse. Grace defaults to 90s.
	advance(5 * time.Minute)
	if gate.Authorized(clientIP) {
		t.Fatal("the authorization window never lapsed")
	}

	// Replay the exact captured bytes from the same source address.
	written, _ := recorder.records()
	if len(written) != 1 {
		t.Fatalf("captured %d datagrams, want 1", len(written))
	}
	if _, err := recorder.PacketConn.WriteTo(written[0], gateConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	// The datagram still verifies cryptographically; only the nonce cache stops
	// it. Give the gate goroutine time to have processed it and confirm the port
	// stayed shut.
	time.Sleep(150 * time.Millisecond)
	if gate.Authorized(clientIP) {
		t.Fatal("a replayed knock re-opened the port")
	}
}

func waitFor(condition func() bool) bool {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return condition()
}
