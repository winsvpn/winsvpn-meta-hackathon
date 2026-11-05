package knock

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeClock lets a test move the Gate's notion of "now" independently of
// real elapsed wall-clock time, so grace-window and replay-window tests run
// in milliseconds instead of minutes.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{t: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func mustListenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func mustListenTCP(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(tcp): %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// readResult carries the outcome of one wrapped ReadFrom call to the
// goroutine driving it, so tests can assert without the call itself
// blocking the test body.
type readResult struct {
	n    int
	addr net.Addr
	data []byte
	err  error
}

func startReader(conn net.PacketConn) <-chan readResult {
	out := make(chan readResult, 8)
	go func() {
		for {
			buf := make([]byte, 4096)
			n, addr, err := conn.ReadFrom(buf)
			out <- readResult{n: n, addr: addr, data: append([]byte(nil), buf[:n]...), err: err}
			if err != nil {
				close(out)
				return
			}
		}
	}()
	return out
}

func expectNoRead(t *testing.T, results <-chan readResult, within time.Duration) {
	t.Helper()
	select {
	case r := <-results:
		t.Fatalf("expected no delivered datagram within %s, got n=%d addr=%v err=%v", within, r.n, r.addr, r.err)
	case <-time.After(within):
	}
}

func expectRead(t *testing.T, results <-chan readResult, within time.Duration) readResult {
	t.Helper()
	select {
	case r := <-results:
		if r.err != nil {
			t.Fatalf("wrapped ReadFrom returned an error: %v", r.err)
		}
		return r
	case <-time.After(within):
		t.Fatalf("expected a delivered datagram within %s, got none", within)
	}
	return readResult{}
}

func newTestGate(t *testing.T, keys [][]byte, packetSize int, cfg GateConfig) *Gate {
	t.Helper()
	gate, err := NewGate(keys, packetSize, cfg)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	return gate
}

func TestNewGateValidatesConfig(t *testing.T) {
	key := testKey(t, 1)
	if _, err := NewGate(nil, 256, GateConfig{}); err == nil {
		t.Fatal("NewGate accepted an empty key list")
	}
	if _, err := NewGate([][]byte{key}, HeaderSize-1, GateConfig{}); err == nil {
		t.Fatal("NewGate accepted a packetSize smaller than HeaderSize")
	}
	if _, err := NewGate([][]byte{[]byte("short")}, 256, GateConfig{}); err == nil {
		t.Fatal("NewGate accepted a too-short key")
	}
	if _, err := NewGate([][]byte{key}, 256, GateConfig{}); err != nil {
		t.Fatalf("NewGate rejected a valid minimal configuration: %v", err)
	}
}

// TestGateUDPUnauthorizedTrafficNeverForwarded proves the core discoverability
// claim experimentally: garbage of varying sizes from a source that has never
// knocked is never handed to the wrapped conn's caller.
func TestGateUDPUnauthorizedTrafficNeverForwarded(t *testing.T) {
	key := testKey(t, 1)
	server := mustListenUDP(t)
	gate := newTestGate(t, [][]byte{key}, 256, GateConfig{})
	wrapped := gate.WrapPacketConn(server)
	results := startReader(wrapped)

	client := mustListenUDP(t)
	serverAddr := server.LocalAddr()
	for _, size := range []int{1, 63, 255, 256, 257, 1200} {
		garbage := bytes.Repeat([]byte{0xAB}, size)
		if _, err := client.WriteTo(garbage, serverAddr); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}
	expectNoRead(t, results, 300*time.Millisecond)
}

// TestGateUDPValidKnockThenForwardsSubsequentTraffic proves the positive
// path: a real knock is consumed silently, and the very next datagram from
// the same source is delivered to the caller byte-for-byte.
func TestGateUDPValidKnockThenForwardsSubsequentTraffic(t *testing.T) {
	key := testKey(t, 1)
	server := mustListenUDP(t)
	gate := newTestGate(t, [][]byte{key}, 256, GateConfig{})
	wrapped := gate.WrapPacketConn(server)
	results := startReader(wrapped)

	client := mustListenUDP(t)
	serverAddr := server.LocalAddr()

	knockPacket, err := Build(key, 256, time.Now(), Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := client.WriteTo(knockPacket, serverAddr); err != nil {
		t.Fatalf("WriteTo(knock): %v", err)
	}
	// The knock itself must never be delivered to the caller.
	expectNoRead(t, results, 200*time.Millisecond)

	payload := []byte("this is a real QUIC-shaped datagram, not a knock")
	if _, err := client.WriteTo(payload, serverAddr); err != nil {
		t.Fatalf("WriteTo(payload): %v", err)
	}
	got := expectRead(t, results, 500*time.Millisecond)
	if !bytes.Equal(got.data, payload) {
		t.Fatalf("delivered payload = %q, want %q", got.data, payload)
	}
}

// TestGateUDPReplayedKnockDoesNotReopenPort is the direct experimental proof
// of the "same captured packet must not re-open the port" requirement: after
// the original authorization has expired, resending the exact same captured
// bytes must not authorize the source again.
func TestGateUDPReplayedKnockDoesNotReopenPort(t *testing.T) {
	key := testKey(t, 1)
	server := mustListenUDP(t)
	clock := newFakeClock(time.Now())
	gate := newTestGate(t, [][]byte{key}, 256, GateConfig{
		Grace: 200 * time.Millisecond,
		Now:   clock.Now,
	})
	wrapped := gate.WrapPacketConn(server)
	results := startReader(wrapped)

	client := mustListenUDP(t)
	serverAddr := server.LocalAddr()

	knockPacket, err := Build(key, 256, clock.Now(), Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := client.WriteTo(knockPacket, serverAddr); err != nil {
		t.Fatalf("WriteTo(knock): %v", err)
	}
	expectNoRead(t, results, 100*time.Millisecond) // give the reader goroutine time to process it

	clientIP, _ := addrIP(client.LocalAddr())
	if !gate.Authorized(clientIP) {
		t.Fatal("gate did not authorize the source after a valid knock")
	}

	// Let the grace window lapse (still well inside MaxSkew, so the packet
	// would still cryptographically verify if replay tracking did not
	// block it).
	clock.Advance(500 * time.Millisecond)
	if gate.Authorized(clientIP) {
		t.Fatal("authorization did not expire after the grace window")
	}

	// Replay the captured packet.
	if _, err := client.WriteTo(knockPacket, serverAddr); err != nil {
		t.Fatalf("WriteTo(replayed knock): %v", err)
	}
	expectNoRead(t, results, 200*time.Millisecond)
	if gate.Authorized(clientIP) {
		t.Fatal("a replayed, previously-used knock re-authorized the source")
	}

	// And the port must still refuse to forward ordinary traffic from that
	// source - the replay must not have reopened anything.
	if _, err := client.WriteTo([]byte("payload after replay"), serverAddr); err != nil {
		t.Fatalf("WriteTo(payload): %v", err)
	}
	expectNoRead(t, results, 200*time.Millisecond)
}

// TestGateUDPAuthorizationScopedByIPNotPort simulates the CGNAT / per-flow
// NAT-rebind case: a knock from one local port must authorize a later
// datagram from the same IP but a different local port.
func TestGateUDPAuthorizationScopedByIPNotPort(t *testing.T) {
	key := testKey(t, 1)
	server := mustListenUDP(t)
	gate := newTestGate(t, [][]byte{key}, 256, GateConfig{})
	wrapped := gate.WrapPacketConn(server)
	results := startReader(wrapped)

	serverAddr := server.LocalAddr()

	knockClient := mustListenUDP(t)
	knockPacket, err := Build(key, 256, time.Now(), Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := knockClient.WriteTo(knockPacket, serverAddr); err != nil {
		t.Fatalf("WriteTo(knock): %v", err)
	}
	expectNoRead(t, results, 150*time.Millisecond)

	// A second, independent local socket - a different source port, same
	// 127.0.0.1 source IP, standing in for a NAT that rebinds the port
	// between the knock and the real connection attempt.
	payloadClient := mustListenUDP(t)
	if knockClient.LocalAddr().(*net.UDPAddr).Port == payloadClient.LocalAddr().(*net.UDPAddr).Port {
		t.Fatal("test setup produced the same source port twice; not exercising the scenario")
	}
	payload := []byte("real connection attempt from a different NAT-assigned port")
	if _, err := payloadClient.WriteTo(payload, serverAddr); err != nil {
		t.Fatalf("WriteTo(payload): %v", err)
	}
	got := expectRead(t, results, 500*time.Millisecond)
	if !bytes.Equal(got.data, payload) {
		t.Fatalf("delivered payload = %q, want %q", got.data, payload)
	}
}

// TestGateUDPSlidingWindowKeepsActiveSessionAuthorized proves that ongoing
// forwarded traffic slides the authorization window forward indefinitely,
// and that genuine silence past the grace window closes it again.
func TestGateUDPSlidingWindowKeepsActiveSessionAuthorized(t *testing.T) {
	key := testKey(t, 1)
	server := mustListenUDP(t)
	clock := newFakeClock(time.Now())
	gate := newTestGate(t, [][]byte{key}, 256, GateConfig{
		Grace: 300 * time.Millisecond,
		Now:   clock.Now,
	})
	wrapped := gate.WrapPacketConn(server)
	results := startReader(wrapped)

	client := mustListenUDP(t)
	serverAddr := server.LocalAddr()

	knockPacket, err := Build(key, 256, clock.Now(), Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := client.WriteTo(knockPacket, serverAddr); err != nil {
		t.Fatalf("WriteTo(knock): %v", err)
	}
	expectNoRead(t, results, 100*time.Millisecond)

	// Simulate keepalives spaced past the original grace window but each
	// well inside a freshly-slid one, the way a live QUIC session's own
	// KeepAlivePeriod would.
	for i := 0; i < 4; i++ {
		clock.Advance(200 * time.Millisecond) // < grace (300ms)
		keepalive := []byte("keepalive")
		if _, err := client.WriteTo(keepalive, serverAddr); err != nil {
			t.Fatalf("WriteTo(keepalive %d): %v", i, err)
		}
		got := expectRead(t, results, 500*time.Millisecond)
		if !bytes.Equal(got.data, keepalive) {
			t.Fatalf("keepalive %d: delivered %q, want %q", i, got.data, keepalive)
		}
	}

	// Now go quiet for longer than grace: authorization must lapse.
	clock.Advance(400 * time.Millisecond)
	clientIP, _ := addrIP(client.LocalAddr())
	if gate.Authorized(clientIP) {
		t.Fatal("authorization survived a silence longer than the grace window")
	}
	if _, err := client.WriteTo([]byte("too late"), serverAddr); err != nil {
		t.Fatalf("WriteTo(too late): %v", err)
	}
	expectNoRead(t, results, 200*time.Millisecond)
}

// TestGateUDPRateLimitBoundsKnockAttempts proves invalid-knock floods from
// one source stop reaching signature verification once the configured
// per-source rate budget is exhausted.
func TestGateUDPRateLimitBoundsKnockAttempts(t *testing.T) {
	key := testKey(t, 1)
	server := mustListenUDP(t)

	var mu sync.Mutex
	reasons := map[string]int{}
	gate := newTestGate(t, [][]byte{key}, 256, GateConfig{
		RateCapacity:   2,
		RatePerMinute:  6,
		RateMaxSources: 10,
		OnKnockRejected: func(_ netip.Addr, reason string) {
			mu.Lock()
			reasons[reason]++
			mu.Unlock()
		},
	})
	wrapped := gate.WrapPacketConn(server)
	results := startReader(wrapped)

	client := mustListenUDP(t)
	serverAddr := server.LocalAddr()

	// Five well-formed-length but wrong-key attempts, back to back, well
	// within the same rate-limit refill interval.
	wrongKey := testKey(t, 2)
	for i := 0; i < 5; i++ {
		packet, err := Build(wrongKey, 256, time.Now(), Options{})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if _, err := client.WriteTo(packet, serverAddr); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}
	expectNoRead(t, results, 300*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if reasons[ReasonRateLimited] == 0 {
		t.Fatalf("expected some attempts to be rejected as rate-limited, got reasons=%v", reasons)
	}
	if reasons[ReasonUnauthenticated] == 0 {
		t.Fatalf("expected some attempts to reach and fail signature verification, got reasons=%v", reasons)
	}
	if reasons[ReasonUnauthenticated] > 2 {
		t.Fatalf(
			"rate limiter (capacity 2) let %d attempts reach signature verification, want at most 2",
			reasons[ReasonUnauthenticated],
		)
	}
}

// TestGateTCPUnauthorizedConnectionGetsNothing proves that an unauthorized
// TCP peer is accepted at the kernel level (unavoidable - see the package
// doc) but is handed nothing at all at the application layer: zero bytes,
// and the wrapped listener never surfaces the connection to its caller.
func TestGateTCPUnauthorizedConnectionGetsNothing(t *testing.T) {
	key := testKey(t, 1)
	rawListener := mustListenTCP(t)
	gate := newTestGate(t, [][]byte{key}, 256, GateConfig{})
	wrapped := gate.WrapListener(rawListener)

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := wrapped.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	conn, err := net.DialTimeout("tcp", rawListener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	select {
	case c := <-accepted:
		t.Fatalf("wrapped listener surfaced an unauthorized connection: %v", c.RemoteAddr())
	case <-time.After(300 * time.Millisecond):
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if n != 0 {
		t.Fatalf("unauthorized connection received %d bytes, want 0", n)
	}
	if err == nil {
		t.Fatal("expected the unauthorized connection to be closed, got no error reading it")
	}
}

// TestGateSharedBetweenTCPAndUDP proves the central design claim: one UDP
// knock authorizes both a subsequent UDP payload and a subsequent, entirely
// separate TCP connection from the same source IP - a client never has to
// guess which carrier will win the race before knocking.
func TestGateSharedBetweenTCPAndUDP(t *testing.T) {
	key := testKey(t, 1)
	udpServer := mustListenUDP(t)
	tcpServer := mustListenTCP(t)
	gate := newTestGate(t, [][]byte{key}, 256, GateConfig{})
	wrappedUDP := gate.WrapPacketConn(udpServer)
	wrappedTCP := gate.WrapListener(tcpServer)

	udpResults := startReader(wrappedUDP)
	tcpAccepted := make(chan net.Conn, 1)
	go func() {
		conn, err := wrappedTCP.Accept()
		if err == nil {
			tcpAccepted <- conn
		}
	}()

	// Client uses one local UDP socket for both the knock and, conceptually,
	// would be the same host's IP when it separately dials TCP.
	client := mustListenUDP(t)
	knockPacket, err := Build(key, 256, time.Now(), Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := client.WriteTo(knockPacket, udpServer.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(knock): %v", err)
	}
	expectNoRead(t, udpResults, 150*time.Millisecond)

	// UDP side: now forwards.
	payload := []byte("udp payload after shared knock")
	if _, err := client.WriteTo(payload, udpServer.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(payload): %v", err)
	}
	got := expectRead(t, udpResults, 500*time.Millisecond)
	if !bytes.Equal(got.data, payload) {
		t.Fatalf("udp payload = %q, want %q", got.data, payload)
	}

	// TCP side, same source IP (127.0.0.1), different socket entirely: must
	// also be let through by the SAME Gate, from the single knock above.
	tcpConn, err := net.DialTimeout("tcp", tcpServer.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("Dial(tcp): %v", err)
	}
	defer tcpConn.Close()

	select {
	case c := <-tcpAccepted:
		defer c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("wrapped TCP listener never accepted a connection authorized by the shared UDP knock")
	}
}

// TestSendKnockAcceptedByGate exercises the client-side Send helper against
// a real Gate-wrapped listener end to end, proving the client and server
// halves of this package actually interoperate rather than merely each
// having their own passing unit tests. Send closes its own socket right
// after writing (by design - see its doc), so proving it actually
// authorized 127.0.0.1 means sending the follow-up payload from a
// different, fresh socket.
func TestSendKnockAcceptedByGate(t *testing.T) {
	key := testKey(t, 1)
	server := mustListenUDP(t)
	gate := newTestGate(t, [][]byte{key}, 256, GateConfig{})
	wrapped := gate.WrapPacketConn(server)
	results := startReader(wrapped)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := Send(ctx, server.LocalAddr().String(), key, 256, Options{}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	expectNoRead(t, results, 200*time.Millisecond)

	follower := mustListenUDP(t)
	payload := []byte("payload after Send")
	if _, err := follower.WriteTo(payload, server.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(payload): %v", err)
	}
	got := expectRead(t, results, 500*time.Millisecond)
	if !bytes.Equal(got.data, payload) {
		t.Fatalf("delivered payload = %q, want %q", got.data, payload)
	}
}

// TestSendViaKnockAcceptedByGate exercises SendVia (the protect()-safe
// client helper used on platforms like Android - see its doc) against its
// own fresh Gate, so the effect is attributed to SendVia alone rather than
// conflated with TestSendKnockAcceptedByGate's use of Send.
func TestSendViaKnockAcceptedByGate(t *testing.T) {
	key := testKey(t, 1)
	server := mustListenUDP(t)
	gate := newTestGate(t, [][]byte{key}, 256, GateConfig{})
	wrapped := gate.WrapPacketConn(server)
	results := startReader(wrapped)

	local := mustListenUDP(t)
	if err := SendVia(local, server.LocalAddr(), key, 256, Options{}); err != nil {
		t.Fatalf("SendVia: %v", err)
	}
	expectNoRead(t, results, 200*time.Millisecond)

	payload := []byte("payload after SendVia, same socket")
	if _, err := local.WriteTo(payload, server.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(payload): %v", err)
	}
	got := expectRead(t, results, 500*time.Millisecond)
	if !bytes.Equal(got.data, payload) {
		t.Fatalf("delivered payload = %q, want %q", got.data, payload)
	}
}

// --- Fail-closed behaviour under bounded-memory pressure ---
//
// These call the unexported grant/markNonceUsed directly (this file is in
// package knock, not knock_test) rather than driving them through a socket,
// because what is being pinned is internal bookkeeping under a tiny,
// deliberately-exhausted bound - routing that through real sockets would
// add timing noise without adding confidence.

func TestConsiderAuthorizesSourceOnValidKnock(t *testing.T) {
	key := testKey(t, 1)
	var accepted []netip.Addr
	gate := newTestGate(t, [][]byte{key}, 256, GateConfig{
		OnKnockAccepted: func(ip netip.Addr) {
			accepted = append(accepted, ip)
		},
	})
	ip := netip.MustParseAddr("10.0.0.1")
	packet, err := Build(key, 256, time.Now(), Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !gate.Consider(packet, ip) {
		t.Fatal("Consider returned false for a valid knock")
	}
	if !gate.Authorized(ip) {
		t.Fatal("source was not authorized after Consider returned true")
	}
	if len(accepted) != 1 || accepted[0] != ip {
		t.Fatalf("OnKnockAccepted = %v, want [%v]", accepted, ip)
	}
}

func TestConsiderDoesNotReportSuccessWhenAuthorizedSetIsFull(t *testing.T) {
	// considerKnock used to return true and fire OnKnockAccepted after a
	// successful HMAC even when grant dropped the source because the
	// authorized set was at MaxAuthorizedSources. Consider's documented
	// contract is "whether it authorized that source"; spagate.Daemon.handle
	// treats a true return as a grant and calls enforcer.Authorize. A true
	// return here would open the kernel set for a source the in-process map
	// refused.
	key := testKey(t, 1)
	var accepted []netip.Addr
	var rejected []string
	gate := newTestGate(t, [][]byte{key}, 256, GateConfig{
		MaxAuthorizedSources: 1,
		Grace:                time.Minute,
		OnKnockAccepted: func(ip netip.Addr) {
			accepted = append(accepted, ip)
		},
		OnKnockRejected: func(_ netip.Addr, reason string) {
			rejected = append(rejected, reason)
		},
	})
	ipA := netip.MustParseAddr("10.0.0.1")
	ipB := netip.MustParseAddr("10.0.0.2")
	now := time.Now()

	packetA, err := Build(key, 256, now, Options{})
	if err != nil {
		t.Fatalf("Build(A): %v", err)
	}
	if !gate.Consider(packetA, ipA) {
		t.Fatal("first valid knock was not accepted")
	}
	if !gate.Authorized(ipA) {
		t.Fatal("ipA was not authorized after Consider")
	}

	packetB, err := Build(key, 256, now, Options{})
	if err != nil {
		t.Fatalf("Build(B): %v", err)
	}
	if gate.Consider(packetB, ipB) {
		t.Fatal("Consider returned true for a knock that could not be granted (authorized set full)")
	}
	if gate.Authorized(ipB) {
		t.Fatal("ipB was authorized past MaxAuthorizedSources")
	}
	if !gate.Authorized(ipA) {
		t.Fatal("ipA lost its grant when the second knock was refused")
	}
	if len(accepted) != 1 || accepted[0] != ipA {
		t.Fatalf("OnKnockAccepted = %v, want only ipA", accepted)
	}
	if len(rejected) != 1 || rejected[0] != ReasonCapacity {
		t.Fatalf("OnKnockRejected reasons = %v, want [%s]", rejected, ReasonCapacity)
	}
}

func TestGrantFailsClosedWhenAuthorizedSetIsFull(t *testing.T) {
	gate := newTestGate(t, [][]byte{testKey(t, 1)}, 256, GateConfig{
		MaxAuthorizedSources: 1,
		Grace:                time.Minute,
	})
	ipA := netip.MustParseAddr("10.0.0.1")
	ipB := netip.MustParseAddr("10.0.0.2")
	now := time.Now()

	if !gate.grant(ipA, now) {
		t.Fatal("first grant returned false")
	}
	if !gate.Authorized(ipA) {
		t.Fatal("ipA was not authorized after grant")
	}

	// The set is now at MaxAuthorizedSources (1) and ipA has not expired, so
	// pruning cannot free a slot: a second, different source must be
	// refused rather than silently evicting ipA or growing past the bound.
	if gate.grant(ipB, now) {
		t.Fatal("second grant returned true past MaxAuthorizedSources")
	}
	if gate.Authorized(ipB) {
		t.Fatal("gate granted authorization past MaxAuthorizedSources instead of failing closed")
	}
	if !gate.Authorized(ipA) {
		t.Fatal("the existing grant for ipA was lost when a second grant was refused")
	}

	// Re-granting the SAME already-present source (the "already exists"
	// branch) must still work even while the set is "full" with only
	// itself in it.
	if !gate.grant(ipA, now.Add(time.Second)) {
		t.Fatal("re-granting an already-authorized source returned false")
	}
	if !gate.Authorized(ipA) {
		t.Fatal("re-granting an already-authorized source was refused")
	}
}

func TestGrantRecoversCapacityAfterExpiry(t *testing.T) {
	gate := newTestGate(t, [][]byte{testKey(t, 1)}, 256, GateConfig{
		MaxAuthorizedSources: 1,
		Grace:                time.Millisecond,
	})
	ipA := netip.MustParseAddr("10.0.0.1")
	ipB := netip.MustParseAddr("10.0.0.2")
	now := time.Now()

	if !gate.grant(ipA, now) {
		t.Fatal("first grant returned false")
	}
	later := now.Add(time.Hour) // long past the 1ms grace
	if !gate.grant(ipB, later) {
		t.Fatal("grant after expiry returned false instead of recovering capacity")
	}
	if !gate.Authorized(ipB) {
		t.Fatal("grant did not recover capacity by pruning ipA's expired entry")
	}
}

func TestMarkNonceUsedFailsClosedWhenReplayCacheIsFull(t *testing.T) {
	gate := newTestGate(t, [][]byte{testKey(t, 1)}, 256, GateConfig{
		ReplayMaxNonces: 1,
	})
	now := time.Now()
	var nonceA, nonceB [NonceSize]byte
	nonceA[0] = 1
	nonceB[0] = 2

	if !gate.markNonceUsed(nonceA, now) {
		t.Fatal("first nonce, well under the limit, was rejected")
	}
	// The cache is now full (1/1) and nonceA has not expired, so a
	// DIFFERENT, never-seen nonce must still be refused - this is not a
	// replay, it is the bounded-memory fail-closed behaviour under
	// pressure.
	if gate.markNonceUsed(nonceB, now) {
		t.Fatal("gate accepted a fresh nonce past ReplayMaxNonces instead of failing closed")
	}
	// The exact same nonce again must also be refused, for the ordinary
	// replay reason.
	if gate.markNonceUsed(nonceA, now) {
		t.Fatal("gate accepted a literal replay of an already-used nonce")
	}
}

func TestMarkNonceUsedRecoversCapacityAfterExpiry(t *testing.T) {
	gate := newTestGate(t, [][]byte{testKey(t, 1)}, 256, GateConfig{
		ReplayMaxNonces: 1,
		Options:         Options{BucketWindow: time.Second, MaxSkew: time.Second},
	})
	var nonceA, nonceB [NonceSize]byte
	nonceA[0] = 1
	nonceB[0] = 2
	now := time.Now()
	if !gate.markNonceUsed(nonceA, now) {
		t.Fatal("first nonce was rejected")
	}
	// replayExpiry = 2*MaxSkew + BucketWindow = 3s here; go well past it.
	later := now.Add(time.Hour)
	if !gate.markNonceUsed(nonceB, later) {
		t.Fatal("markNonceUsed did not recover capacity by pruning nonceA's expired entry")
	}
}

// --- addrIP ---

type stringAddr struct {
	network string
	address string
}

func (a stringAddr) Network() string { return a.network }
func (a stringAddr) String() string  { return a.address }

func TestAddrIPHandlesGenericAddrTypes(t *testing.T) {
	ip, ok := addrIP(stringAddr{network: "test", address: "192.0.2.1:5555"})
	if !ok {
		t.Fatal("addrIP failed to parse a generic host:port Addr")
	}
	want := netip.MustParseAddr("192.0.2.1")
	if ip != want {
		t.Fatalf("addrIP = %v, want %v", ip, want)
	}
}

func TestAddrIPRejectsUnparseableInput(t *testing.T) {
	if _, ok := addrIP(stringAddr{network: "test", address: "not-a-host-port"}); ok {
		t.Fatal("addrIP accepted an address with no parseable host:port")
	}
	if _, ok := addrIP(stringAddr{network: "test", address: "not-an-ip:80"}); ok {
		t.Fatal("addrIP accepted a non-IP host")
	}
}

func TestAddrIPNormalizesIPv4MappedIPv6(t *testing.T) {
	udpAddr := &net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 1}
	ip, ok := addrIP(udpAddr)
	if !ok {
		t.Fatal("addrIP failed to parse an IPv4-mapped IPv6 UDPAddr")
	}
	if !ip.Is4() {
		t.Fatalf("addrIP did not unmap an IPv4-mapped address: got %v", ip)
	}
}

// --- client helper error paths ---

func TestSendRejectsBadKeyBeforeDialing(t *testing.T) {
	if err := Send(context.Background(), "127.0.0.1:1", []byte("short"), 256, Options{}); err == nil {
		t.Fatal("Send accepted a too-short key")
	}
}

func TestSendViaRejectsBadKey(t *testing.T) {
	local := mustListenUDP(t)
	if err := SendVia(local, local.LocalAddr(), []byte("short"), 256, Options{}); err == nil {
		t.Fatal("SendVia accepted a too-short key")
	}
}

func TestSendFailsOnUnresolvableAddress(t *testing.T) {
	key := testKey(t, 1)
	err := Send(context.Background(), "this is not a valid address", key, 256, Options{})
	if err == nil {
		t.Fatal("Send succeeded against an unresolvable address")
	}
}
