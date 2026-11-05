package carrier

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// testSecret is a deterministic carrier secret. It is not a key: nothing in this
// tree ever loads it, and it exists so that two ends of a test agree.
func testSecret(t *testing.T) []byte {
	t.Helper()
	s := make([]byte, MinSecretSize)
	for i := range s {
		s[i] = byte(0x40 + i)
	}
	return s
}

// countingRand is a deterministic io.Reader. Tests that assert on framing must
// not depend on crypto/rand, or a failure becomes unreproducible.
type countingRand struct {
	mu sync.Mutex
	n  uint64
}

func (c *countingRand) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range p {
		c.n = c.n*6364136223846793005 + 1442695040888963407
		p[i] = byte(c.n >> 33)
	}
	return len(p), nil
}

// seqRand yields consecutive uint64 values big-endian. Used to probe the ends of
// a draw's support.
type seqRand struct {
	vals []uint64
	i    int
}

func (s *seqRand) Read(p []byte) (int, error) {
	if len(p) != 8 {
		return 0, io.ErrUnexpectedEOF
	}
	if s.i >= len(s.vals) {
		return 0, io.EOF
	}
	binary.BigEndian.PutUint64(p, s.vals[s.i])
	s.i++
	return 8, nil
}

// failingRand fails after n successful reads.
type failingRand struct {
	ok int
}

func (f *failingRand) Read(p []byte) (int, error) {
	if f.ok <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	f.ok--
	for i := range p {
		p[i] = 0x5a
	}
	return len(p), nil
}

// fakeClock is a clock the test advances by hand.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// countingConn wraps a net.Conn and records every Write as a separate entry.
//
// This is the instrument behind TestOneWritePerMessage. Counting writes rather
// than measuring segments is the right level: a test that measured TCP segments
// would be testing the kernel's coalescing, which varies by platform and by
// NODELAY, and would pass on a loopback that coalesces while the handset it
// models does not.
type countingConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
	reads  int
}

func (c *countingConn) Write(b []byte) (int, error) {
	cp := make([]byte, len(b))
	copy(cp, b)
	c.mu.Lock()
	c.writes = append(c.writes, cp)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.reads++
	c.mu.Unlock()
	return n, err
}

func (c *countingConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

func (c *countingConn) writtenBytes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, w := range c.writes {
		n += len(w)
	}
	return n
}

func (c *countingConn) writeAt(i int) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i >= len(c.writes) {
		return nil
	}
	cp := make([]byte, len(c.writes[i]))
	copy(cp, c.writes[i])
	return cp
}

// streamPair builds two stream carriers over a net.Pipe, each wrapped in a
// countingConn.
//
// net.Pipe is synchronous and unbuffered, which is a feature here: it makes a
// missing read or a split write show up as a deadlock rather than as a passing
// test, and it removes the kernel from a test about framing.
func streamPair(t *testing.T, class Class, opts ...func(*StreamConfig)) (
	client, gateway *Stream, clientConn, gatewayConn *countingConn,
) {
	t.Helper()
	a, b := net.Pipe()
	clientConn = &countingConn{Conn: a}
	gatewayConn = &countingConn{Conn: b}
	secret := testSecret(t)

	cc := StreamConfig{
		Conn: clientConn, Secret: secret, Role: RoleClient,
		Class: class, Rand: &countingRand{}, Clock: newFakeClock(),
	}
	gc := StreamConfig{
		Conn: gatewayConn, Secret: secret, Role: RoleGateway,
		Class: class, Rand: &countingRand{n: 99}, Clock: newFakeClock(),
	}
	for _, o := range opts {
		o(&cc)
		o(&gc)
	}
	var err error
	if client, err = NewStream(cc); err != nil {
		t.Fatalf("client stream: %v", err)
	}
	if gateway, err = NewStream(gc); err != nil {
		t.Fatalf("gateway stream: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = gateway.Close()
	})
	return client, gateway, clientConn, gatewayConn
}

// pumpSend runs Send on a goroutine, because net.Pipe blocks until the peer
// reads.
func pumpSend(t *testing.T, s *Stream, msg []byte) <-chan error {
	t.Helper()
	ch := make(chan error, 1)
	go func() { ch <- s.Send(context.Background(), msg) }()
	return ch
}

func mustRecv(t *testing.T, s *Stream) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg, err := s.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	return msg
}

func mustSendErr(t *testing.T, ch <-chan error) {
	t.Helper()
	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("Send: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send did not return")
	}
}

// message builds a plausible Winn3 message of n bytes: uniform-looking bytes,
// because that is what a sealed message is.
func message(n int, seed byte) []byte {
	b := make([]byte, n)
	v := uint64(seed) | 1
	for i := range b {
		v = v*6364136223846793005 + 1442695040888963407
		b[i] = byte(v >> 33)
	}
	return b
}

// loopbackUDP opens a UDP socket bound to loopback only.
//
// Loopback is not a convenience here, it is a constraint: every sibling lane
// depends on this machine's connectivity and no test in this package may open a
// listening socket on a routable interface.
func loopbackUDP(t testing.TB) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		conn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Skipf("no loopback UDP socket available: %v", err)
		}
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// loopbackTCP listens on loopback only.
func loopbackTCP(t *testing.T) *net.TCPListener {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("no loopback TCP listener available: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// stubReporter stands in for *session.Driver in tests of Observe.
//
// It is a stub rather than a real driver because Observe must not depend on a
// driver being constructible: the point of the interface is that this package
// reads three booleans and reaches nothing else.
type stubReporter struct {
	needsChange bool
	needsNew    bool
	narrowed    bool
	state       session.State
}

func (s stubReporter) NeedsCarrierChange() bool { return s.needsChange }
func (s stubReporter) NeedsNewSession() bool    { return s.needsNew }
func (s stubReporter) State() session.State     { return s.state }
func (s stubReporter) PathNarrowed() bool       { return s.narrowed }

// sizeSink records what Migrate told it, and can refuse.
type sizeSink struct {
	got    []int
	refuse error
}

func (s *sizeSink) SetMaxMessageSize(n int) error {
	if s.refuse != nil {
		return s.refuse
	}
	s.got = append(s.got, n)
	return nil
}
