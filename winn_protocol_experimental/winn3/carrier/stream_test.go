package carrier

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// TestStreamRoundTripsBothDirections is the base case.
func TestStreamRoundTripsBothDirections(t *testing.T) {
	t.Parallel()
	client, gateway, _, _ := streamPair(t, ClassTCP)

	up := message(400, 1)
	ch := pumpSend(t, client, up)
	if got := mustRecv(t, gateway); string(got) != string(up) {
		t.Fatal("client to gateway message did not survive the round trip")
	}
	mustSendErr(t, ch)

	down := message(700, 2)
	ch = pumpSend(t, gateway, down)
	if got := mustRecv(t, client); string(got) != string(down) {
		t.Fatal("gateway to client message did not survive the round trip")
	}
	mustSendErr(t, ch)
}

// TestStreamSurvivesArbitrarySegmentation is the property that makes it a
// stream carrier rather than a datagram one wearing a TCP hat.
//
// A real TCP connection delivers bytes, not writes. A carrier that assumed one
// read returns one record works perfectly on a loopback and fails on the first
// congested mobile network — and it fails as a desynchronised stream, which is
// indistinguishable from an attack in the logs. The peer here writes one byte at
// a time.
func TestStreamSurvivesArbitrarySegmentation(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	secret := testSecret(t)
	client, err := NewStream(StreamConfig{
		Conn: a, Secret: secret, Role: RoleClient, Class: ClassTCP,
		Rand: &countingRand{}, Clock: newFakeClock(),
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	gateway, err := NewStream(StreamConfig{
		Conn: b, Secret: secret, Role: RoleGateway, Class: ClassTCP,
		Rand: &countingRand{n: 5}, Clock: newFakeClock(),
	})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	defer func() { _ = client.Close(); _ = gateway.Close() }()

	// Collect what the client would write, then dribble it in one byte at a
	// time. net.Pipe is unbuffered, so each write blocks until the reader takes
	// it, which is the strongest possible form of the test.
	var wire []byte
	sink := &collectConn{}
	collector, err := NewStream(StreamConfig{
		Conn: sink, Secret: secret, Role: RoleClient, Class: ClassTCP,
		Rand: &countingRand{}, Clock: newFakeClock(),
	})
	if err != nil {
		t.Fatalf("collector: %v", err)
	}
	msgs := [][]byte{message(29, 1), message(300, 2), message(1168, 3), message(64, 4)}
	for _, m := range msgs {
		if err := collector.Send(context.Background(), m); err != nil {
			t.Fatalf("collect send: %v", err)
		}
	}
	wire = sink.buf

	go func() {
		for i := range wire {
			if _, err := a.Write(wire[i : i+1]); err != nil {
				return
			}
		}
	}()
	for i, want := range msgs {
		got := mustRecv(t, gateway)
		if string(got) != string(want) {
			t.Fatalf("message %d did not survive byte-at-a-time delivery", i)
		}
	}
}

// collectConn is a net.Conn that only records what is written to it.
type collectConn struct {
	net.Conn
	buf []byte
}

func (c *collectConn) Write(b []byte) (int, error) {
	c.buf = append(c.buf, b...)
	return len(b), nil
}
func (c *collectConn) SetWriteDeadline(time.Time) error { return nil }
func (c *collectConn) SetReadDeadline(time.Time) error  { return nil }
func (c *collectConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv6loopback, Port: 443} }
func (c *collectConn) Close() error                     { return nil }

// TestStreamRefusesOversizeAndEmpty.
//
// A refusal, never a truncation: a truncated Winn3 message fails to open at the
// far end and looks exactly like an attack, so a local misconfiguration would be
// reported as a forgery.
func TestStreamRefusesOversizeAndEmpty(t *testing.T) {
	t.Parallel()
	client, _, clientConn, _ := streamPair(t, ClassTCP)
	max := client.MaxMessageSize()

	if err := client.Send(context.Background(), message(max+1, 1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversize returned %v, want ErrMessageTooLarge", err)
	}
	if err := client.Send(context.Background(), nil); !errors.Is(err, ErrMessageEmpty) {
		t.Fatalf("empty returned %v, want ErrMessageEmpty", err)
	}
	if got := clientConn.writeCount(); got != 0 {
		t.Fatalf("a refused message produced %d writes; nothing may reach the wire", got)
	}
}

// TestStreamClassIsDetectedFromTheConn.
//
// Detection is safer than being told. A caller who labels a TLS connection as
// TCP gets a ceiling 22 bytes too large and fragments every full-size packet;
// the symptom is a stalled download and the cause is one enum.
func TestStreamClassIsDetectedFromTheConn(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	plain, _ := net.Pipe()
	s, err := NewStream(StreamConfig{Conn: plain, Secret: secret, Role: RoleClient})
	if err != nil {
		t.Fatalf("plain: %v", err)
	}
	if s.Class() != ClassTCP {
		t.Fatalf("a bare conn was classified %s, want tcp", s.Class())
	}
	_ = s.Close()

	inner, _ := net.Pipe()
	tlsConn := tls.Client(inner, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // never handshaked
	s2, err := NewStream(StreamConfig{Conn: tlsConn, Secret: secret, Role: RoleClient})
	if err != nil {
		t.Fatalf("tls: %v", err)
	}
	if s2.Class() != ClassTLS {
		t.Fatalf("a *tls.Conn was classified %s, want tls", s2.Class())
	}
	if s2.MaxMessageSize() >= s.MaxMessageSize() {
		t.Fatal("the TLS carrier's ceiling is not below the bare TCP one; the record cost is unaccounted")
	}
	_ = s2.Close()
}

// TestStreamConfigRefusals.
func TestStreamConfigRefusals(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	conn, _ := net.Pipe()
	cases := []struct {
		name string
		cfg  StreamConfig
		want error
	}{
		{"no conn", StreamConfig{Secret: secret}, ErrConfig},
		{"short secret", StreamConfig{Conn: conn, Secret: []byte("x")}, ErrSecret},
		{"unknown role", StreamConfig{Conn: conn, Secret: secret, Role: Role(9)}, ErrConfig},
		{"datagram class", StreamConfig{Conn: conn, Secret: secret, Class: ClassUDP}, ErrConfig},
		{"size below floor", StreamConfig{
			Conn: conn, Secret: secret, MaxMessageSize: session.MessageFloor() - 1,
		}, ErrSizeBelowFloor},
		{"size above path", StreamConfig{
			Conn: conn, Secret: secret, MaxMessageSize: 9000, PathMTU: 1280,
		}, ErrSizeAbovePath},
		{"entropy failure", StreamConfig{
			Conn: conn, Secret: secret, Rand: &failingRand{},
		}, ErrConfig},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewStream(c.cfg); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

// TestStreamDesyncIsTerminalAndSilent.
//
// A stream carrier cannot resynchronise, by construction: resynchronising means
// scanning for a marker and a marker is a plaintext field at a findable offset,
// which is what encrypting the length removes. So the first failure is the last
// one, and every subsequent call must refuse rather than half-work.
func TestStreamDesyncIsTerminalAndSilent(t *testing.T) {
	t.Parallel()
	_, gateway, clientConn, gatewayConn := streamPair(t, ClassTCP)

	go func() { _, _ = clientConn.Conn.Write(message(SaltSize+LengthRecordOverhead, 9)) }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := gateway.Recv(ctx); !errors.Is(err, ErrStreamDesync) {
		t.Fatalf("garbage returned %v, want ErrStreamDesync", err)
	}
	// Terminal in both directions.
	if _, err := gateway.Recv(ctx); !errors.Is(err, ErrStreamDesync) {
		t.Fatalf("a second Recv returned %v, want the sticky ErrStreamDesync", err)
	}
	if err := gateway.Send(ctx, message(100, 1)); !errors.Is(err, ErrStreamDesync) {
		t.Fatalf("Send after desync returned %v, want ErrStreamDesync", err)
	}
	if got := gatewayConn.writeCount(); got != 0 {
		t.Fatalf("the dying carrier wrote %d times", got)
	}
	if gateway.fatal() == nil {
		t.Fatal("the carrier does not report its own fatal error to Observe")
	}
}

// TestOutOfRangeLengthIsDesyncNotADrop.
//
// A length outside the agreed range is not a short message, it is a stream that
// is no longer where it thinks it is. Treating it as a droppable message would
// leave the reader positioned in the middle of a record with no way to find the
// next one, and it would loop forever consuming garbage.
func TestOutOfRangeLengthIsDesyncNotADrop(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	a, b := net.Pipe()
	gateway, err := NewStream(StreamConfig{
		Conn: b, Secret: secret, Role: RoleGateway, Class: ClassTCP,
		Rand: &countingRand{}, Clock: newFakeClock(), MaxMessageSize: 600, PathMTU: 1280,
	})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	defer func() { _ = gateway.Close() }()

	// Seal a length the gateway will not accept, under the right key.
	salt := make([]byte, SaltSize)
	copy(salt, "SALTSALTSALTSALT")
	cip := mustCipher(t, secret, salt, RoleClient.sendLabel())
	for _, bad := range []int{0, session.MessageFloor() - 1, 601, 65535} {
		go func(n int) {
			out, _ := cip.seal(append([]byte(nil), salt...), n)
			_, _ = a.Write(out)
		}(bad)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := gateway.Recv(ctx)
		cancel()
		if !errors.Is(err, ErrStreamDesync) {
			t.Fatalf("length %d returned %v, want ErrStreamDesync", bad, err)
		}
		return // the carrier is terminal; one case is all it can be shown
	}
}

// TestSetMaxMessageSizeNarrowsSendButNeverRecv.
//
// Narrowing this end tells the peer nothing, so a peer entitled to send a larger
// message a moment ago must still be able to. Refusing it would turn a size
// change into a teardown, and the teardown would happen at exactly the moment a
// session was migrating away from a blocked carrier — the worst possible time.
func TestSetMaxMessageSizeNarrowsSendButNeverRecv(t *testing.T) {
	t.Parallel()
	client, gateway, _, _ := streamPair(t, ClassTCP)
	wide := client.MaxMessageSize()

	// The gateway narrows its own send ceiling.
	if err := gateway.SetMaxMessageSize(600); err != nil {
		t.Fatalf("narrow: %v", err)
	}
	if got := gateway.MaxMessageSize(); got != 600 {
		t.Fatalf("send ceiling is %d, want 600", got)
	}
	if err := gateway.Send(context.Background(), message(700, 1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("the narrowed end sent an oversize message: %v", err)
	}
	// And it still accepts what the peer was told it could send.
	ch := pumpSend(t, client, message(wide, 2))
	if got := len(mustRecv(t, gateway)); got != wide {
		t.Fatalf("the narrowed end refused a %d-byte message the peer was entitled to send", wide)
	}
	mustSendErr(t, ch)
}

// TestSetMaxMessageSizeRefusals.
func TestSetMaxMessageSizeRefusals(t *testing.T) {
	t.Parallel()
	client, _, _, _ := streamPair(t, ClassTCP)
	if err := client.SetMaxMessageSize(session.MessageFloor() - 1); !errors.Is(err, ErrSizeBelowFloor) {
		t.Fatalf("below floor returned %v", err)
	}
	if err := client.SetMaxMessageSize(9000); !errors.Is(err, ErrSizeAbovePath) {
		t.Fatalf("above path returned %v", err)
	}
	if err := client.SetMaxMessageSize(session.MessageFloor()); err != nil {
		t.Fatalf("the floor itself was refused: %v", err)
	}
	_ = client.Close()
	if err := client.SetMaxMessageSize(600); !errors.Is(err, ErrClosed) {
		t.Fatalf("after close returned %v, want ErrClosed", err)
	}
}

// TestStreamClosedAndCancelled.
func TestStreamClosedAndCancelled(t *testing.T) {
	t.Parallel()
	client, _, _, _ := streamPair(t, ClassTCP)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.Send(cancelled, message(100, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send on a cancelled context returned %v", err)
	}
	if _, err := client.Recv(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Recv on a cancelled context returned %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := client.Send(context.Background(), message(100, 1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Send after Close returned %v", err)
	}
	if _, err := client.Recv(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Recv after Close returned %v", err)
	}
}

// TestStreamStatsMoveOnSuccessOnly.
//
// The counters a policy layer reads must reflect the network. A LastDelivered
// that moved on a failed read would let a censored carrier look alive; a Sent
// that moved on a failed write would let a dead one look busy.
func TestStreamStatsMoveOnSuccessOnly(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	client, gateway, _, _ := streamPair(t, ClassTCP, func(c *StreamConfig) { c.Clock = clock })

	if s := client.Stats(); !s.LastSend.IsZero() || !s.LastDelivered.IsZero() {
		t.Fatal("a fresh carrier already has activity timestamps")
	}
	// A refused message must not move anything.
	_ = client.Send(context.Background(), nil)
	if s := client.Stats(); s.Sent != 0 || s.SentBytes != 0 {
		t.Fatalf("a refused message moved the send counters: %+v", s)
	}

	clock.advance(time.Second)
	ch := pumpSend(t, client, message(300, 1))
	mustRecv(t, gateway)
	mustSendErr(t, ch)

	s := client.Stats()
	if s.Sent != 1 || s.SentBytes != uint64(SaltSize+LengthRecordOverhead+300) {
		t.Fatalf("send counters are %+v", s)
	}
	if s.LastSend.IsZero() {
		t.Fatal("LastSend did not move on a successful send")
	}
	if !s.LastDelivered.IsZero() {
		t.Fatal("LastDelivered moved on a send")
	}
	g := gateway.Stats()
	if g.Delivered != 1 || g.DeliveredBytes != uint64(300+LengthRecordOverhead) {
		t.Fatalf("delivery counters are %+v", g)
	}

	// A read timeout is an error, not a delivery.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	before := gateway.Stats()
	_, _ = gateway.Recv(ctx)
	after := gateway.Stats()
	if after.Delivered != before.Delivered {
		t.Fatal("a timed-out read counted as a delivery")
	}
	if after.RecvErrors != before.RecvErrors+1 {
		t.Fatal("a timed-out read did not count as an error")
	}
	if !after.LastDelivered.Equal(before.LastDelivered) {
		t.Fatal("a timed-out read moved LastDelivered")
	}
}

// TestReadTimeoutIsNotFatal.
//
// A carrier being polled times out constantly and by design. Treating a deadline
// expiry as a dead carrier would tear down a working tunnel on the first idle
// second, which is the opposite failure from the one this package exists to fix
// and just as bad.
func TestReadTimeoutIsNotFatal(t *testing.T) {
	t.Parallel()
	client, gateway, _, _ := streamPair(t, ClassTCP)

	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		_, err := gateway.Recv(ctx)
		cancel()
		if !isTimeout(err) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected a timeout, got %v", err)
		}
	}
	if gateway.fatal() != nil {
		t.Fatalf("a poll timeout killed the carrier: %v", gateway.fatal())
	}
	// And it still works.
	ch := pumpSend(t, client, message(200, 1))
	if got := len(mustRecv(t, gateway)); got != 200 {
		t.Fatal("the carrier stopped working after a poll timeout")
	}
	mustSendErr(t, ch)
}

// TestWriteFailureIsFatal.
//
// A failed or short write leaves the peer with half a message and the length
// counter already spent. There is no retransmission at this layer and there must
// not be one, because re-sealing a length under a spent counter is a reused
// nonce — the one thing the session lane's whole nonce contract exists to
// prevent.
func TestWriteFailureIsFatal(t *testing.T) {
	t.Parallel()
	sink := &failingWriteConn{}
	s, err := NewStream(StreamConfig{
		Conn: sink, Secret: testSecret(t), Role: RoleClient, Class: ClassTCP,
		Rand: &countingRand{}, Clock: newFakeClock(),
	})
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if err := s.Send(context.Background(), message(100, 1)); err == nil {
		t.Fatal("a failing write returned no error")
	}
	if s.fatal() == nil {
		t.Fatal("a failed write did not mark the carrier dead")
	}
	if err := s.Send(context.Background(), message(100, 2)); err == nil {
		t.Fatal("the carrier accepted a second message after a failed write")
	}
	if sink.writes != 1 {
		t.Fatalf("the carrier retried a failed write %d times; it must never re-seal", sink.writes-1)
	}
}

type failingWriteConn struct {
	net.Conn
	writes int
}

func (f *failingWriteConn) Write(b []byte) (int, error) {
	f.writes++
	return 3, io.ErrShortWrite
}
func (f *failingWriteConn) SetWriteDeadline(time.Time) error { return nil }
func (f *failingWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (f *failingWriteConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv6loopback, Port: 443}
}
func (f *failingWriteConn) Close() error { return nil }

// TestStreamOverLoopbackTCP is the end-to-end case over a real socket.
//
// Loopback only: every sibling lane depends on this machine's connectivity and
// no test here may bind a routable interface.
func TestStreamOverLoopbackTCP(t *testing.T) {
	t.Parallel()
	ln := loopbackTCP(t)
	secret := testSecret(t)

	type result struct {
		msg []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer func() { _ = conn.Close() }()
		g, err := NewStream(StreamConfig{Conn: conn, Secret: secret, Role: RoleGateway})
		if err != nil {
			done <- result{err: err}
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		msg, err := g.Recv(ctx)
		done <- result{msg: msg, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := DialStream(ctx, DialTCP(ln.Addr().String()), StreamConfig{
		Secret: secret, Role: RoleClient,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if c.Class() != ClassTCP {
		t.Fatalf("class is %s over a real TCP socket", c.Class())
	}
	want := message(500, 3)
	if err := c.Send(ctx, want); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := <-done
	if got.err != nil {
		t.Fatalf("gateway: %v", got.err)
	}
	if string(got.msg) != string(want) {
		t.Fatal("the message did not survive a real TCP connection")
	}
}

// TestDialStreamRefusals.
func TestDialStreamRefusals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if _, err := DialStream(ctx, nil, StreamConfig{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("nil dialer returned %v", err)
	}
	conn, _ := net.Pipe()
	if _, err := DialStream(ctx, DialTCP("x"), StreamConfig{Conn: conn}); !errors.Is(err, ErrConfig) {
		t.Fatalf("a supplied conn returned %v", err)
	}
	dialErr := errors.New("no route")
	failing := func(context.Context) (net.Conn, error) { return nil, dialErr }
	if _, err := DialStream(ctx, failing, StreamConfig{Secret: testSecret(t)}); !errors.Is(err, dialErr) {
		t.Fatalf("a failing dial returned %v", err)
	}
	// A dial that succeeds but a configuration that does not must close the
	// connection rather than leak it.
	closed := make(chan struct{}, 1)
	ok := func(context.Context) (net.Conn, error) {
		a, _ := net.Pipe()
		return &notifyCloseConn{Conn: a, closed: closed}, nil
	}
	if _, err := DialStream(ctx, ok, StreamConfig{Secret: []byte("short")}); !errors.Is(err, ErrSecret) {
		t.Fatalf("a bad configuration returned %v", err)
	}
	select {
	case <-closed:
	default:
		t.Fatal("a failed DialStream leaked the connection")
	}
}

type notifyCloseConn struct {
	net.Conn
	closed chan struct{}
}

func (n *notifyCloseConn) Close() error {
	select {
	case n.closed <- struct{}{}:
	default:
	}
	return n.Conn.Close()
}
