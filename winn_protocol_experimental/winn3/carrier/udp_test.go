package carrier

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// udpPair builds two datagram carriers on loopback, each with the other as an
// explicit peer.
//
// Explicit peers rather than connected sockets, because the explicit-peer path
// is the one with a userspace filter and therefore the one with a security
// property to test. Loopback only, and the connectivity every sibling lane
// depends on is untouched.
func udpPair(t testing.TB, opts ...func(*UDPConfig)) (a, b *UDP, aConn, bConn *net.UDPConn) {
	t.Helper()
	aConn = loopbackUDP(t)
	bConn = loopbackUDP(t)

	ac := UDPConfig{Conn: aConn, Peer: bConn.LocalAddr().(*net.UDPAddr), Clock: newFakeClock()}
	bc := UDPConfig{Conn: bConn, Peer: aConn.LocalAddr().(*net.UDPAddr), Clock: newFakeClock()}
	for _, o := range opts {
		o(&ac)
		o(&bc)
	}
	var err error
	if a, err = NewUDP(ac); err != nil {
		t.Fatalf("carrier a: %v", err)
	}
	if b, err = NewUDP(bc); err != nil {
		t.Fatalf("carrier b: %v", err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b, aConn, bConn
}

// TestUDPRoundTripsWithNoAddedBytes.
//
// A datagram carrier adds nothing. A message format that is already
// unconditionally uniform needs no framing, and adding any would put back the
// readable structure the format removes.
func TestUDPRoundTripsWithNoAddedBytes(t *testing.T) {
	t.Parallel()
	a, b, _, _ := udpPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, n := range []int{29, 100, 512, 1168} {
		want := message(n, byte(n))
		if err := a.Send(ctx, want); err != nil {
			t.Fatalf("send %d: %v", n, err)
		}
		got, err := b.Recv(ctx)
		if err != nil {
			t.Fatalf("recv %d: %v", n, err)
		}
		if string(got) != string(want) {
			t.Fatalf("%d-byte message did not survive", n)
		}
	}
	if s := a.Stats(); s.SentBytes != uint64(29+100+512+1168) {
		t.Fatalf("the carrier added bytes: sent %d for %d of payload",
			s.SentBytes, 29+100+512+1168)
	}
	if a.Class() != ClassUDP {
		t.Fatalf("class is %s", a.Class())
	}
}

// TestForeignDatagramsCannotHoldTheBlockedVerdictOff is the security property
// behind the sender filter, and it is the reason the filter is not bookkeeping.
//
// Stats.LastDelivered is the freshest evidence a policy layer has that a carrier
// is still carrying. An off-path attacker who has found the five-tuple — and on
// a datagram carrier finding it is not hard — could otherwise spray one packet a
// second, hold that evidence fresh, and PIN a user on a transport that is
// carrying nothing. That is failover suppression for the price of one spoofed
// packet per second, against exactly the users this protocol exists for.
func TestForeignDatagramsCannotHoldTheBlockedVerdictOff(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	a, b, _, bConn := udpPair(t, func(c *UDPConfig) { c.Clock = clock })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// One real message, so LastDelivered has a value to be held.
	if err := a.Send(ctx, message(200, 1)); err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, err := b.Recv(ctx); err != nil {
		t.Fatalf("recv: %v", err)
	}
	firstDelivery := b.Stats().LastDelivered

	// Now the attacker. A third socket, not the peer, spraying at the
	// five-tuple while the clock advances.
	attacker := loopbackUDP(t)
	for i := 0; i < 20; i++ {
		clock.advance(time.Second)
		if _, err := attacker.WriteToUDP(message(300, byte(i)), bConn.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatalf("attacker write: %v", err)
		}
	}
	// The real peer then sends nothing, so every Recv must time out rather than
	// return the attacker's traffic.
	for i := 0; i < 20; i++ {
		rctx, rcancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		msg, err := b.Recv(rctx)
		rcancel()
		if err == nil {
			t.Fatalf("a foreign datagram was delivered as a message (%d bytes)", len(msg))
		}
	}
	s := b.Stats()
	if s.Foreign != 20 {
		t.Fatalf("Foreign is %d, want 20", s.Foreign)
	}
	if s.Delivered != 1 {
		t.Fatalf("Delivered is %d; a foreign datagram counted as a delivery", s.Delivered)
	}
	if !s.LastDelivered.Equal(firstDelivery) {
		t.Fatal("a foreign datagram moved LastDelivered; a blocked carrier can be held open")
	}
}

// TestForeignFilterDetectorHasTeeth shows the test above is measuring the
// filter and not the loopback.
//
// If the two carriers happened not to be reachable from the attacker's socket,
// TestForeignDatagramsCannotHoldTheBlockedVerdictOff would pass for the wrong
// reason. Here the same third socket is made the configured peer, and the same
// datagrams must then be delivered.
func TestForeignFilterDetectorHasTeeth(t *testing.T) {
	t.Parallel()
	bConn := loopbackUDP(t)
	attacker := loopbackUDP(t)

	b, err := NewUDP(UDPConfig{
		Conn: bConn, Peer: attacker.LocalAddr().(*net.UDPAddr), Clock: newFakeClock(),
	})
	if err != nil {
		t.Fatalf("carrier: %v", err)
	}
	defer func() { _ = b.Close() }()

	if _, err := attacker.WriteToUDP(message(300, 1), bConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := b.Recv(ctx); err != nil {
		t.Fatalf("the same datagram was refused when the sender WAS the peer: %v", err)
	}
	if got := b.Stats().Foreign; got != 0 {
		t.Fatalf("Foreign is %d for the configured peer", got)
	}
}

// TestUDPDropsOversizeRatherThanTruncating.
//
// The read buffer is deliberately larger than the ceiling. Reading into a buffer
// exactly the size of the ceiling would truncate an oversize datagram instead of
// discarding it, and a truncated Winn3 message fails to open and looks identical
// to a forgery — which would make a path-MTU misconfiguration indistinguishable
// from an attack in the logs.
func TestUDPDropsOversizeRatherThanTruncating(t *testing.T) {
	t.Parallel()
	a, b, _, _ := udpPair(t, func(c *UDPConfig) { c.MaxMessageSize = 600; c.PathMTU = 1280 })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// a cannot send oversize through the carrier, so write past it.
	peer := b.conn.LocalAddr().(*net.UDPAddr)
	if _, err := a.conn.WriteToUDP(message(1200, 1), peer); err != nil {
		t.Fatalf("raw write: %v", err)
	}
	// Follow it with a legal message; only the second must arrive.
	if err := a.Send(ctx, message(500, 2)); err != nil {
		t.Fatalf("send: %v", err)
	}
	got, err := b.Recv(ctx)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if len(got) != 500 {
		t.Fatalf("got a %d-byte message; the oversize datagram was truncated rather than dropped", len(got))
	}
	if s := b.Stats(); s.Delivered != 1 || s.RecvErrors != 1 {
		t.Fatalf("counters are %+v; the oversize datagram was not counted as an error", s)
	}
}

// TestUDPRefusesOversizeAndEmptySends.
func TestUDPRefusesOversizeAndEmptySends(t *testing.T) {
	t.Parallel()
	a, _, _, _ := udpPair(t)
	ctx := context.Background()
	if err := a.Send(ctx, message(a.MaxMessageSize()+1, 1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversize returned %v", err)
	}
	if err := a.Send(ctx, nil); !errors.Is(err, ErrMessageEmpty) {
		t.Fatalf("empty returned %v", err)
	}
	if s := a.Stats(); s.Sent != 0 {
		t.Fatalf("a refused message was counted as sent: %+v", s)
	}
}

// TestUDPConfigRefusals.
func TestUDPConfigRefusals(t *testing.T) {
	t.Parallel()
	conn := loopbackUDP(t)
	peer := conn.LocalAddr().(*net.UDPAddr)
	cases := []struct {
		name string
		cfg  UDPConfig
		want error
	}{
		{"no conn", UDPConfig{}, ErrConfig},
		{"unconnected with no peer", UDPConfig{Conn: conn}, ErrConfig},
		{"below floor", UDPConfig{
			Conn: conn, Peer: peer, MaxMessageSize: session.MessageFloor() - 1,
		}, ErrSizeBelowFloor},
		{"above path", UDPConfig{
			Conn: conn, Peer: peer, MaxMessageSize: 9000, PathMTU: 1280,
		}, ErrSizeAbovePath},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewUDP(c.cfg); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
	if _, err := DialUDP(context.Background(), UDPConfig{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("DialUDP with no remote returned %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DialUDP(cancelled, UDPConfig{Remote: peer}); !errors.Is(err, context.Canceled) {
		t.Fatalf("DialUDP on a cancelled context returned %v", err)
	}
}

// TestDialUDPWritesNothing.
//
// A connected UDP socket is a kernel-side filter, not a handshake. A carrier
// that greeted its gateway would be a fixed-size first packet, fleet-wide — the
// measured failure of the protocol this replaces, in a different field.
func TestDialUDPWritesNothing(t *testing.T) {
	t.Parallel()
	gw := loopbackUDP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := DialUDP(ctx, UDPConfig{Remote: gw.LocalAddr().(*net.UDPAddr), Clock: newFakeClock()})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	if err := gw.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 2048)
	if n, _, err := gw.ReadFromUDP(buf); err == nil {
		t.Fatalf("dialing wrote %d bytes to the gateway", n)
	}
	if s := c.Stats(); s.Sent != 0 || s.SentBytes != 0 {
		t.Fatalf("dialing moved the send counters: %+v", s)
	}
	// And a connected carrier round trips.
	if err := c.Send(ctx, message(200, 1)); err != nil {
		t.Fatalf("send: %v", err)
	}
	_ = gw.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := gw.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("gateway read: %v", err)
	}
	if n != 200 {
		t.Fatalf("gateway got %d bytes, want 200", n)
	}
	if _, err := gw.WriteToUDP(message(300, 2), from); err != nil {
		t.Fatalf("gateway write: %v", err)
	}
	got, err := c.Recv(ctx)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if len(got) != 300 {
		t.Fatalf("client got %d bytes, want 300", len(got))
	}
}

// TestUDPDoesNotCloseASocketItDoesNotOwn.
//
// A gateway's socket serves every session on it. Closing a socket a carrier was
// merely lent would take down every other session as a side effect of one of
// them migrating — a failure that would look like the censor winning.
func TestUDPDoesNotCloseASocketItDoesNotOwn(t *testing.T) {
	t.Parallel()
	shared := loopbackUDP(t)
	peer := loopbackUDP(t)
	c, err := NewUDP(UDPConfig{
		Conn: shared, Peer: peer.LocalAddr().(*net.UDPAddr), Clock: newFakeClock(),
	})
	if err != nil {
		t.Fatalf("carrier: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := shared.WriteToUDP(message(10, 1), peer.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("the shared socket was closed by a borrower: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if err := c.Send(context.Background(), message(10, 1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Send after close returned %v", err)
	}
	if _, err := c.Recv(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Recv after close returned %v", err)
	}
	if err := c.SetMaxMessageSize(600); !errors.Is(err, ErrClosed) {
		t.Fatalf("SetMaxMessageSize after close returned %v", err)
	}
}

// TestUDPSendFailureIsNotFatal is the shape of the measured censorship failure.
//
// Under a censor dropping UDP the socket opens, every write succeeds, and the
// reads simply never return: there is NO error to fail over on. That is why a
// send error must not be treated as a dead carrier — the interesting case
// produces none, and a transient ENOBUFS is not the interesting case. Deciding a
// carrier is blocked is escalation.go's job, from datagram counts and clocks.
func TestUDPSendFailureIsNotFatal(t *testing.T) {
	t.Parallel()
	a, _, _, _ := udpPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cancelled, ccancel := context.WithCancel(context.Background())
	ccancel()
	if err := a.Send(cancelled, message(100, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled send returned %v", err)
	}
	if a.fatal() != nil {
		t.Fatalf("a cancelled send killed the carrier: %v", a.fatal())
	}
	if err := a.Send(ctx, message(100, 2)); err != nil {
		t.Fatalf("the carrier stopped working after a cancelled send: %v", err)
	}
}

// TestUDPSetMaxMessageSize.
func TestUDPSetMaxMessageSize(t *testing.T) {
	t.Parallel()
	a, _, _, _ := udpPair(t, func(c *UDPConfig) { c.PathMTU = 1500 })
	wide := a.MaxMessageSize()
	if err := a.SetMaxMessageSize(600); err != nil {
		t.Fatalf("narrow: %v", err)
	}
	if a.MaxMessageSize() != 600 {
		t.Fatalf("ceiling is %d, want 600", a.MaxMessageSize())
	}
	if err := a.SetMaxMessageSize(wide); err != nil {
		t.Fatalf("widen back: %v", err)
	}
	if err := a.SetMaxMessageSize(session.MessageFloor() - 1); !errors.Is(err, ErrSizeBelowFloor) {
		t.Fatalf("below floor returned %v", err)
	}
	if err := a.SetMaxMessageSize(9000); !errors.Is(err, ErrSizeAbovePath) {
		t.Fatalf("above path returned %v", err)
	}
}

// TestSameUDPAddrComparesAddressesNotBytes.
//
// The same address can be held as a 4-byte or a 16-byte slice. A byte comparison
// would reject the gateway's own datagrams on a dual-stack host, and a filter
// that discards everything is not a stricter filter, it is a broken carrier —
// one that would report a working gateway as blocked and fail over off it.
func TestSameUDPAddrComparesAddressesNotBytes(t *testing.T) {
	t.Parallel()
	four := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 443}
	sixteen := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To16(), Port: 443}
	if !sameUDPAddr(four, sixteen) {
		t.Fatal("the same address in two representations compared unequal")
	}
	if len(four.IP) == len(sixteen.IP) {
		t.Fatal("the two representations are the same length; the test proves nothing")
	}
	if sameUDPAddr(four, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 444}) {
		t.Fatal("a different port compared equal")
	}
	if sameUDPAddr(four, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 443}) {
		t.Fatal("a different address compared equal")
	}
	if sameUDPAddr(nil, four) || sameUDPAddr(four, nil) {
		t.Fatal("nil compared equal")
	}
}
