package carrier

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestCancellationUnblocksABlockedRecv is a liveness property of the caller's
// loop, not a niceness.
//
// The session driver's loop blocks on the carrier until a message arrives or the
// driver's next deadline, whichever comes first. A carrier whose Recv could not
// be interrupted would hold that loop past the deadline — so a keepalive, a
// rekey or a probe would fire late, and "late" on a silence timer is a timing
// artefact of exactly the kind this protocol removes. It would also make Close
// hang on shutdown.
func TestCancellationUnblocksABlockedRecv(t *testing.T) {
	t.Parallel()
	t.Run("stream", func(t *testing.T) {
		t.Parallel()
		_, gateway, _, _ := streamPair(t, ClassTCP)
		assertCancelUnblocks(t, func(ctx context.Context) error {
			_, err := gateway.Recv(ctx)
			return err
		})
	})
	t.Run("udp", func(t *testing.T) {
		t.Parallel()
		_, b, _, _ := udpPair(t)
		assertCancelUnblocks(t, func(ctx context.Context) error {
			_, err := b.Recv(ctx)
			return err
		})
	})
}

// assertCancelUnblocks starts op on a context with no deadline, cancels it, and
// requires op to return promptly.
func assertCancelUnblocks(t *testing.T, op func(context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- op(ctx) }()

	// Give the read time to actually block, so the cancellation has something
	// to interrupt. Without this the test could pass by racing to the ctx.Err()
	// check at the top of Recv, which would prove nothing.
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("Recv returned %v before it was cancelled; it did not block", err)
	default:
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelling the context did not unblock Recv")
	}
}

// TestACancelledRecvDoesNotPoisonTheCarrier.
//
// The cancellation works by pushing the socket deadline into the past. If that
// deadline were left there, the next Recv would fail instantly forever — a
// carrier that works once and then silently stops, which on a handset reads as
// the censor having won.
func TestACancelledRecvDoesNotPoisonTheCarrier(t *testing.T) {
	t.Parallel()
	a, b, _, _ := udpPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = b.Recv(ctx)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	live, lcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer lcancel()
	if err := a.Send(live, message(200, 1)); err != nil {
		t.Fatalf("send: %v", err)
	}
	got, err := b.Recv(live)
	if err != nil {
		t.Fatalf("the carrier stayed poisoned after a cancelled Recv: %v", err)
	}
	if len(got) != 200 {
		t.Fatalf("got %d bytes", len(got))
	}
}

// TestWideningRaisesTheReceiveCeiling.
//
// SetMaxMessageSize is not only a narrowing tool. When a path turns out wider
// than planned, both ends may be told, and the receiving end must then accept
// what the peer has been authorised to send — otherwise the widening produces a
// desynchronised stream, which is terminal.
func TestWideningRaisesTheReceiveCeiling(t *testing.T) {
	t.Parallel()
	client, gateway, _, _ := streamPair(t, ClassTCP, func(c *StreamConfig) {
		c.MaxMessageSize = 600
		c.PathMTU = 1500
	})
	// Above the initial ceiling, so a receiver that had not been widened would
	// treat it as a desynchronised stream.
	const wide = 900
	if err := client.SetMaxMessageSize(wide); err != nil {
		t.Fatalf("widen sender: %v", err)
	}
	if err := gateway.SetMaxMessageSize(wide); err != nil {
		t.Fatalf("widen receiver: %v", err)
	}
	ch := pumpSend(t, client, message(wide, 1))
	if got := len(mustRecv(t, gateway)); got != wide {
		t.Fatalf("got %d bytes, want %d", got, wide)
	}
	mustSendErr(t, ch)
}

// TestDialUDPFailurePaths.
func TestDialUDPFailurePaths(t *testing.T) {
	t.Parallel()
	// A port zero on the loopback address is not dialable as a destination.
	if _, err := DialUDP(context.Background(), UDPConfig{
		Remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
	}); err == nil {
		t.Fatal("dialling port 0 succeeded")
	}
	// A configuration the carrier refuses must close the socket it opened rather
	// than leak a descriptor per attempt — which on a redial loop is a
	// descriptor leak proportional to how long a censor keeps blocking.
	gw := loopbackUDP(t)
	if _, err := DialUDP(context.Background(), UDPConfig{
		Remote:         gw.LocalAddr().(*net.UDPAddr),
		MaxMessageSize: 9000,
		PathMTU:        1280,
	}); !errors.Is(err, ErrSizeAbovePath) {
		t.Fatalf("a bad size returned %v", err)
	}
}

// TestUDPSendOnAClosedSocketErrorsWithoutKillingTheCarrier.
//
// The distinction matters because the measured censorship failure produces no
// send error at all. A carrier that treated any send error as fatal would fail
// over on a transient local condition and would still not fail over on the one
// case that motivated the whole feature.
func TestUDPSendOnAClosedSocketErrorsWithoutKillingTheCarrier(t *testing.T) {
	t.Parallel()
	conn := loopbackUDP(t)
	peer := loopbackUDP(t)
	c, err := NewUDP(UDPConfig{
		Conn: conn, Peer: peer.LocalAddr().(*net.UDPAddr),
		OwnsConn: true, Clock: newFakeClock(),
	})
	if err != nil {
		t.Fatalf("carrier: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close socket: %v", err)
	}
	if err := c.Send(context.Background(), message(100, 1)); err == nil {
		t.Fatal("a send on a closed socket returned no error")
	}
	if s := c.Stats(); s.SendErrors != 1 || s.Sent != 0 {
		t.Fatalf("counters are %+v", s)
	}
	if c.fatal() != nil {
		t.Fatalf("a send error killed the carrier: %v", c.fatal())
	}
	if _, err := c.Recv(context.Background()); err == nil {
		t.Fatal("a recv on a closed socket returned no error")
	}
	if s := c.Stats(); s.RecvErrors != 1 {
		t.Fatalf("recv error not counted: %+v", s)
	}
	_ = c.Close()
}

// TestDelayWithNoRandomSourceUsesTheSystemOne.
//
// Nil must mean crypto/rand rather than a zero value. A caller that forgot to
// set the field and got a deterministic schedule would emit a fleet-wide
// reconnect cadence — the exact failure Backoff exists to prevent, arrived at by
// omission.
func TestDelayWithNoRandomSourceUsesTheSystemOne(t *testing.T) {
	t.Parallel()
	b := Backoff{Base: time.Second, Cap: 8 * time.Second, Attempts: 5}
	seen := map[time.Duration]bool{}
	for i := 0; i < 64; i++ {
		d, err := b.Delay(20, nil)
		if err != nil {
			t.Fatalf("draw %d: %v", i, err)
		}
		if d <= 0 || d >= b.Cap {
			t.Fatalf("draw %d is %v, outside (0, %v)", i, d, b.Cap)
		}
		seen[d] = true
	}
	if len(seen) < 60 {
		t.Fatalf("only %d distinct draws in 64; the default source is not random", len(seen))
	}
}

// TestWindowIsBoundedEvenWhenMisconfigured.
//
// window is called after validate, so a base above the cap cannot be reached
// through the exported API. It is checked anyway, because the guard exists to
// stop a future refactor of validate from turning a misconfiguration into an
// unbounded reconnect delay — which would look like the tunnel never retrying at
// all.
func TestWindowIsBoundedEvenWhenMisconfigured(t *testing.T) {
	t.Parallel()
	b := Backoff{Base: time.Hour, Cap: time.Second, Attempts: 3}
	if got := b.window(0); got != time.Second {
		t.Fatalf("window(0) = %v, want the cap", got)
	}
}

// TestBackoffAttemptCapIsValidatedNotDefaultedAway.
//
// orDefault fills a zero Attempts, so the guard in validate is unreachable
// through Delay. It is checked directly because it is the §4.2 hard cap — the
// thing that stops a client feeding a dead transport forever — and a refactor
// that moved the defaulting would otherwise turn "attempts: -1" into an infinite
// retry loop with no test objecting.
func TestBackoffAttemptCapIsValidatedNotDefaultedAway(t *testing.T) {
	t.Parallel()
	b := Backoff{Base: time.Second, Cap: 8 * time.Second, Attempts: 0}
	if err := b.validate(); !errors.Is(err, ErrConfig) {
		t.Fatalf("a zero attempt cap validated: %v", err)
	}
	// And a fixed-interval configuration is refused through Delay too, not only
	// through the unexported validator.
	fixed := Backoff{Base: 2 * time.Second, Cap: 2 * time.Second, Attempts: 3}
	if _, err := fixed.Delay(0, &countingRand{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("Delay accepted a fixed interval: %v", err)
	}
}

// TestStreamRefusesToSealPastTheCounterCeiling.
//
// The ceiling is unreachable in practice, and the behaviour at it is not
// negotiable: continuing would reuse a (key, nonce) pair on the length key,
// which forfeits authentication for every record after it. The carrier must
// refuse and die rather than emit one more record, and it must not write
// anything on the way down.
func TestStreamRefusesToSealPastTheCounterCeiling(t *testing.T) {
	t.Parallel()
	client, _, clientConn, _ := streamPair(t, ClassTCP)
	client.sendCip.counter = MaxRecordsPerConnection

	err := client.Send(context.Background(), message(100, 1))
	if !errors.Is(err, ErrStreamExhausted) {
		t.Fatalf("got %v, want ErrStreamExhausted", err)
	}
	if got := clientConn.writeCount(); got != 0 {
		t.Fatalf("the exhausted carrier wrote %d times", got)
	}
	if !errors.Is(client.fatal(), ErrStreamExhausted) {
		t.Fatalf("the carrier's fatal error is %v", client.fatal())
	}
	if err := client.Send(context.Background(), message(100, 2)); !errors.Is(err, ErrStreamExhausted) {
		t.Fatalf("a second send returned %v; the refusal is not sticky", err)
	}
}

// TestNewPlanFloorWithNoClassesIsConservative.
//
// "We do not know which classes this session may migrate to" must produce the
// narrowest answer, not the widest. The opposite default is the black hole with
// extra steps.
func TestNewPlanFloorWithNoClassesIsConservative(t *testing.T) {
	t.Parallel()
	pf := NewPlanFloor(1280)
	if pf.MessageSize != MaxMessageSizeFor(ClassTLS, FamilyIPv6, 1280) {
		t.Fatalf("message size is %d, want the worst case", pf.MessageSize)
	}
	if pf.MinPathMTUForInnerIPv6 != MinPathMTUForInnerIPv6(ClassUnknown, FamilyIPv6) {
		t.Fatalf("inner-IPv6 requirement is %d", pf.MinPathMTUForInnerIPv6)
	}
	if pf.InnerIPv6 {
		t.Fatal("inner IPv6 claimed at a 1280-byte path")
	}
}

// TestStreamRecvRejectsAnUnkeyableSalt.
//
// The peer's salt is read before its first record. Deriving from it can only
// fail if the secret is bad, which the constructor already refuses — but the
// path exists and a future change to the key schedule could reach it, so it must
// fail as a receive error rather than as a nil-pointer dereference inside the
// packet loop.
func TestStreamRecvRejectsAnUnkeyableSalt(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	s, err := NewStream(StreamConfig{
		Conn: b, Secret: testSecret(t), Role: RoleGateway, Class: ClassTCP,
		Rand: &countingRand{}, Clock: newFakeClock(),
	})
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	defer func() { _ = s.Close() }()
	// Truncate the salt: the peer closes after eight bytes.
	go func() {
		_, _ = a.Write(make([]byte, 8))
		_ = a.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.Recv(ctx); err == nil {
		t.Fatal("a truncated salt was accepted")
	}
	if s.fatal() == nil {
		t.Fatal("a closed peer did not mark the carrier dead")
	}
}

// TestStreamRecvRejectsATruncatedMessage.
//
// A record whose length opens but whose body never arrives in full is a peer
// that died mid-message. It must be an error, never a short message handed up:
// a truncated Winn3 message fails to open at the session layer and is
// indistinguishable from a forgery there.
func TestStreamRecvRejectsATruncatedMessage(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	sink := &collectConn{}
	collector, err := NewStream(StreamConfig{
		Conn: sink, Secret: secret, Role: RoleClient, Class: ClassTCP,
		Rand: &countingRand{}, Clock: newFakeClock(),
	})
	if err != nil {
		t.Fatalf("collector: %v", err)
	}
	if err := collector.Send(context.Background(), message(400, 1)); err != nil {
		t.Fatalf("collect: %v", err)
	}
	wire := sink.buf[:len(sink.buf)-100] // 100 bytes of the message missing

	a, b := net.Pipe()
	gateway, err := NewStream(StreamConfig{
		Conn: b, Secret: secret, Role: RoleGateway, Class: ClassTCP,
		Rand: &countingRand{}, Clock: newFakeClock(),
	})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	defer func() { _ = gateway.Close() }()
	go func() {
		_, _ = a.Write(wire)
		_ = a.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := gateway.Recv(ctx); err == nil {
		t.Fatal("a truncated message was handed up")
	}
	if got := gateway.Stats().Delivered; got != 0 {
		t.Fatalf("Delivered is %d for a truncated message", got)
	}
}

// TestStreamRecvResumesAfterATimeoutMidRecord.
//
// TestReadTimeoutIsNotFatal covers an idle poll. This covers the expensive
// case: bytes have already been taken from the stream when the deadline
// fires. Without resume those bytes are discarded, the next Recv starts a
// new record over leftover socket data, and a live peer is desynchronised.
func TestStreamRecvResumesAfterATimeoutMidRecord(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	payload := message(200, 7)

	sink := &collectConn{}
	collector, err := NewStream(StreamConfig{
		Conn: sink, Secret: secret, Role: RoleClient, Class: ClassTCP,
		Rand: &countingRand{}, Clock: newFakeClock(),
	})
	if err != nil {
		t.Fatalf("collector: %v", err)
	}
	if err := collector.Send(context.Background(), payload); err != nil {
		t.Fatalf("collect: %v", err)
	}
	wire := append([]byte(nil), sink.buf...)
	if len(wire) <= SaltSize+LengthRecordOverhead {
		t.Fatalf("framed message is %d bytes, too short to split", len(wire))
	}

	t.Run("mid-salt", func(t *testing.T) {
		assertResumeAfterSplit(t, secret, payload, wire, 8)
	})
	t.Run("mid-body", func(t *testing.T) {
		// salt + length + half the body. The length counter is already spent
		// once the body starts, so a discarded partial here cannot be retried
		// by re-reading the length record.
		split := SaltSize + LengthRecordOverhead + 100
		assertResumeAfterSplit(t, secret, payload, wire, split)
	})
}

func assertResumeAfterSplit(t *testing.T, secret, payload, wire []byte, split int) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	gateway, err := NewStream(StreamConfig{
		Conn: b, Secret: secret, Role: RoleGateway, Class: ClassTCP,
		Rand: &countingRand{}, Clock: newFakeClock(),
	})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	t.Cleanup(func() { _ = gateway.Close() })

	firstDone := make(chan error, 1)
	go func() {
		_, err := a.Write(wire[:split])
		firstDone <- err
	}()

	short, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	_, err = gateway.Recv(short)
	cancel()
	if err == nil {
		t.Fatal("Recv returned a message from a partial record")
	}
	if !isTimeout(err) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("partial Recv returned %v, want a timeout", err)
	}
	if gateway.fatal() != nil {
		t.Fatalf("a mid-record poll timeout killed the carrier: %v", gateway.fatal())
	}
	if werr := <-firstDone; werr != nil {
		t.Fatalf("first write: %v", werr)
	}
	if split <= SaltSize {
		if gateway.recvSaltGot != split {
			t.Fatalf("after mid-salt timeout, recvSaltGot=%d, want %d; bytes were discarded or never read",
				gateway.recvSaltGot, split)
		}
	} else {
		wantBody := split - SaltSize - LengthRecordOverhead
		if gateway.recvCip == nil {
			t.Fatal("after mid-body timeout the salt was not kept; next Recv will re-read it from the body")
		}
		if gateway.recvBodyGot != wantBody {
			t.Fatalf("after mid-body timeout, recvBodyGot=%d, want %d", gateway.recvBodyGot, wantBody)
		}
	}

	restDone := make(chan error, 1)
	go func() {
		_, err := a.Write(wire[split:])
		restDone <- err
	}()

	got := mustRecv(t, gateway)
	if string(got) != string(payload) {
		t.Fatalf("resumed Recv got %d bytes, want the original %d-byte payload", len(got), len(payload))
	}
	if werr := <-restDone; werr != nil {
		t.Fatalf("rest write: %v", werr)
	}
}
