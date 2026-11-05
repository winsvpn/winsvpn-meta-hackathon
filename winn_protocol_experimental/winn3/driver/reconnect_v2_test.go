package driver

import (
	"context"
	"crypto/rand"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/dualsign"
	"winsvpn.local/winnprotocol/winn3/session"
)

// Round A2 v2 corrections to the reconnect supervisor: the budget reset reads
// authenticated RECEIVES only, a tunnel that has never established fails fast
// when a host opts in, and a peer's authenticated CLOSE with
// CloseDualAuthFailed is terminal.

// --- the authenticated-receive span ------------------------------------------

// sessionPair is a client and a gateway session driven by hand on the step
// clock, so a test decides exactly when each message is sealed and opened.
type sessionPair struct {
	t       *testing.T
	clk     *stepClock
	cli, gw *session.Driver
}

func newSessionPair(t *testing.T, tweakGateway func(*session.Config)) *sessionPair {
	t.Helper()
	kr := newKeyring(t)
	clk := newStepClock()
	size := planSizing(t).MessageSize
	cli, err := session.NewClient(session.Config{
		Core:           core.Config{Gateway: kr.params},
		Static:         kr.cliStatic,
		GatewayStatic:  kr.gwPublic,
		Padding:        core.PadBucket,
		Clock:          clk,
		MaxMessageSize: size,
	})
	if err != nil {
		t.Fatal(err)
	}
	gwCfg := session.Config{
		Core:           core.Config{Gateway: kr.params},
		Static:         kr.gwStatic,
		Accept:         func([]byte) error { return nil },
		Padding:        core.PadBucket,
		Clock:          clk,
		MaxMessageSize: size,
	}
	if tweakGateway != nil {
		tweakGateway(&gwCfg)
	}
	gw, err := session.NewGateway(gwCfg)
	if err != nil {
		t.Fatal(err)
	}
	return &sessionPair{t: t, clk: clk, cli: cli, gw: gw}
}

// seal polls everything from takes and returns it, unsent.
func (p *sessionPair) seal(from *session.Driver) [][]byte {
	p.t.Helper()
	var out [][]byte
	for range 512 {
		msg, err := from.Poll()
		if err != nil {
			p.t.Fatalf("poll: %v", err)
		}
		if msg == nil {
			return out
		}
		out = append(out, msg)
	}
	p.t.Fatal("poll did not quiesce")
	return nil
}

func (p *sessionPair) open(to *session.Driver, msgs [][]byte) {
	for _, m := range msgs {
		_, _ = to.Deliver(m)
	}
}

// exchange runs both directions until nothing moves.
func (p *sessionPair) exchange() {
	p.t.Helper()
	for range 64 {
		a, b := p.seal(p.cli), p.seal(p.gw)
		if len(a) == 0 && len(b) == 0 {
			return
		}
		p.open(p.gw, a)
		p.open(p.cli, b)
	}
	p.t.Fatal("pair did not quiesce")
}

func (p *sessionPair) span() time.Duration {
	first, last := p.cli.AuthenticatedSpan()
	if first.IsZero() || last.Before(first) {
		return 0
	}
	return last.Sub(first)
}

// spanRunner is a round whose ProvenFor is a live session's span.
type spanRunner struct {
	stubRunner
	span func() time.Duration
}

func (s *spanRunner) ProvenFor() time.Duration { return s.span() }

// roundsBuilt runs a supervisor whose first four rounds fail unproven and whose
// fifth reports the pair's span, then counts the rounds it built before its
// budget was spent. Five means the fifth round did not reset the budget.
func roundsBuilt(t *testing.T, span func() time.Duration) int {
	t.Helper()
	builds := 0
	rc, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			builds++
			if builds == 5 {
				return &spanRunner{stubRunner: stubRunner{err: session.ErrPeerUnreachable}, span: span}, nil
			}
			if builds > 20 {
				t.Fatal("the supervisor did not stop")
			}
			return &stubRunner{err: session.ErrPeerUnreachable}, nil
		},
		Attempts:   carrier.DefaultBackoffAttempts,
		ResetAfter: DefaultReconnectResetAfter,
		Sleep:      func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Run(context.Background()); !errors.Is(err, ErrReconnectExhausted) {
		t.Fatalf("Run returned %v, want ErrReconnectExhausted", err)
	}
	return builds
}

// TestALocallySealedRekeyAckDoesNotProveTheRound is the boundary case: the last
// authenticated receive is 59.9 s after first establishment, the REKEY_ACK that
// receive asked for is sealed at 60.1 s, and nothing further arrives. Sealing
// the ACK completes the rekey locally, and completing a rekey is an establish,
// so any span that read establish's bookkeeping would read 60.1 s. The round
// carried authenticated traffic for 59.9 s and must not reset the budget. A
// receive at 60.2 s then genuinely crosses the threshold and must.
func TestALocallySealedRekeyAckDoesNotProveTheRound(t *testing.T) {
	p := newSessionPair(t, func(c *session.Config) {
		// The gateway's time trigger lands between the 59 s and 59.9 s
		// exchanges below, so its REKEY_INIT is sealed, and opened by the
		// client, at 59.9 s.
		c.RekeyInterval = session.Draw{Min: 59050 * time.Millisecond, Mean: 59300 * time.Millisecond, Max: 59800 * time.Millisecond}
	})
	p.exchange()
	if p.cli.State() != session.StateEstablished || p.gw.State() != session.StateEstablished {
		t.Fatalf("pair did not establish: client %s, gateway %s", p.cli.State(), p.gw.State())
	}

	// Keep the session answering, as a live one does, up to 59 s.
	for _, step := range []time.Duration{10, 10, 10, 10, 10, 9} {
		p.clk.Advance(step * time.Second)
		p.exchange()
	}
	if p.gw.Stats().Rekeys != 0 || p.cli.Stats().Rekeys != 0 {
		t.Fatal("a rekey completed before 59.9 s; the boundary is not where this test says")
	}

	// 59.9 s: the gateway seals its REKEY_INIT and the client opens it. This
	// is the last authenticated receive the round will have.
	p.clk.Advance(900 * time.Millisecond)
	p.open(p.cli, p.seal(p.gw))

	// 60.1 s: the client seals the REKEY_ACK, which completes its rekey. The
	// ACK is never delivered and nothing else reaches the client.
	p.clk.Advance(200 * time.Millisecond)
	ack := p.seal(p.cli)
	if p.cli.Stats().Rekeys != 1 {
		t.Fatalf("the client completed %d rekeys when it sealed its ACK, want 1; the scenario is vacuous", p.cli.Stats().Rekeys)
	}
	if got := p.span(); got >= DefaultReconnectResetAfter {
		t.Fatalf("span after a locally sealed ACK at 60.1 s is %v; the last authenticated receive was at 59.9 s", got)
	}
	if n := roundsBuilt(t, p.span); n != carrier.DefaultBackoffAttempts {
		t.Fatalf("%d rounds built; a round that received for 59.9 s reset the budget", n)
	}

	// 60.2 s: the gateway opens the ACK, and the client opens what the
	// gateway sends back under the new epoch.
	p.clk.Advance(100 * time.Millisecond)
	p.open(p.gw, ack)
	p.open(p.cli, p.seal(p.gw))
	if got := p.span(); got < DefaultReconnectResetAfter {
		t.Fatalf("span after an authenticated receive at 60.2 s is %v, want at least %v", got, DefaultReconnectResetAfter)
	}
	if n := roundsBuilt(t, p.span); n != 2*carrier.DefaultBackoffAttempts {
		t.Fatalf("%d rounds built; a round that received for 60.2 s did not reset the budget", n)
	}
}

// --- fail fast before first establishment -----------------------------------

type establishedStub struct {
	stubRunner
	established bool
}

func (s *establishedStub) Established() bool { return s.established }

func (s *establishedStub) ProvenFor() time.Duration { return 0 }

// TestFailBeforeEstablishmentEndsAfterOneUnansweredRound: a tunnel whose first
// round never established ends after that round, with no further Build and no
// delay, and says why without guessing a cause.
func TestFailBeforeEstablishmentEndsAfterOneUnansweredRound(t *testing.T) {
	builds, sleeps := 0, 0
	unanswered := errWrap(ErrSessionFailed, "%w", session.ErrCarrierExhausted)
	rc, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			builds++
			return &establishedStub{stubRunner: stubRunner{err: unanswered}}, nil
		},
		Terminal:                TerminalRoundError,
		FailBeforeEstablishment: true,
		Sleep:                   func(context.Context, time.Duration) error { sleeps++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	runErr := rc.Run(context.Background())
	if builds != 1 || sleeps != 0 {
		t.Fatalf("%d builds and %d delays; a never-established tunnel must end after one round", builds, sleeps)
	}
	if !errors.Is(runErr, ErrReconnectNeverEstablished) || !errors.Is(runErr, session.ErrCarrierExhausted) {
		t.Fatalf("Run returned %v, want ErrReconnectNeverEstablished wrapping the round's error", runErr)
	}
}

// TestAnImmediatePostEstablishmentFailureIsRetried: a round that established
// and died at once has a zero span and is still a round that established, so
// every later failure spends the ordinary budget. Establishment is the
// historical fact, not ProvenFor > 0 and not the session's state now.
func TestAnImmediatePostEstablishmentFailureIsRetried(t *testing.T) {
	builds := 0
	rc, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			builds++
			return &establishedStub{
				stubRunner:  stubRunner{err: errWrap(ErrSessionFailed, "%w", session.ErrPeerUnreachable)},
				established: builds == 1,
			}, nil
		},
		Terminal:                TerminalRoundError,
		FailBeforeEstablishment: true,
		Sleep:                   func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Run(context.Background()); !errors.Is(err, ErrReconnectExhausted) {
		t.Fatalf("Run returned %v, want the ordinary exhaustion", err)
	}
	if builds != carrier.DefaultBackoffAttempts {
		t.Fatalf("%d builds, want the %d-round budget", builds, carrier.DefaultBackoffAttempts)
	}
}

// TestFailBeforeEstablishmentIsOptInAndYieldsToTerminal: a generic caller that
// does not opt in keeps retrying never-established rounds, and a terminal error
// keeps its own identity rather than being reported as never established.
func TestFailBeforeEstablishmentIsOptInAndYieldsToTerminal(t *testing.T) {
	builds := 0
	rc, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			builds++
			return &establishedStub{stubRunner: stubRunner{err: session.ErrCarrierExhausted}}, nil
		},
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Run(context.Background()); !errors.Is(err, ErrReconnectExhausted) || builds != carrier.DefaultBackoffAttempts {
		t.Fatalf("without the opt-in: %d builds, %v", builds, err)
	}

	terminal := errWrap(ErrSessionFailed, "%w", session.ErrHandshakeUnauthenticated)
	rc, err = NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			return &establishedStub{stubRunner: stubRunner{err: terminal}}, nil
		},
		Terminal:                TerminalRoundError,
		FailBeforeEstablishment: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Run(context.Background()); err != terminal {
		t.Fatalf("Run returned %v, want the terminal error itself", err)
	}
}

// --- a peer's authenticated CLOSE --------------------------------------------

// dualAuthExpectingClient makes the client require a dual-signature attestation
// the gateway is not configured to present, with a short handshake budget so
// its deadline passes on the step clock at once. The keys are the right size
// and are never used: no attestation ever arrives to verify.
func dualAuthExpectingClient(t *testing.T) func(*session.Config) {
	t.Helper()
	ed := make([]byte, dualsign.Ed25519PublicKeySize)
	ml := make([]byte, dualsign.MLDSA65PublicKeySize)
	if _, err := rand.Read(ed); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(ml); err != nil {
		t.Fatal(err)
	}
	return func(c *session.Config) {
		c.DualAuth = session.DualAuthConfig{Expected: true, Ed25519Public: ed, MLDSA65Public: ml}
		c.Retry = session.Retry{Base: 100 * time.Millisecond, Cap: 200 * time.Millisecond, Attempts: 2}
	}
}

// superviseGateway runs a Reconnect whose rounds are gateway loops on gwCar and
// returns a channel with its result and a counter of rounds built.
func superviseGateway(
	t *testing.T, ctx context.Context, kr *keyring, sz Sizing, gwCar carrier.Conn, clk Clock,
) (<-chan error, *atomic.Int64, *atomic.Pointer[Loop]) {
	t.Helper()
	var builds atomic.Int64
	var current atomic.Pointer[Loop]
	rc, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			builds.Add(1)
			gw := newGatewayEndpoint(t, kr, endpointOpts{sizing: sz, carrier: gwCar, clock: clk, noTun: true})
			// The FIRST round, which is the one the scenario acts on.
			current.CompareAndSwap(nil, gw.loop)
			return gw.loop, nil
		},
		Terminal: TerminalRoundError,
		Sleep:    func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- rc.Run(ctx) }()
	return done, &builds, &current
}

// TestAReceivedDualAuthCloseIsTerminal drives the real path: the client's
// attestation deadline passes, it closes with CloseDualAuthFailed, and the
// gateway's round ends on RECEIVING that CLOSE, which Loop.Run reports as a
// clean end. The supervisor must read the peer's reason and stop, not rebuild
// a session that would be refused the same way.
func TestAReceivedDualAuthCloseIsTerminal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sz := planSizing(t)
	kr := newKeyring(t)
	clk := newStepClock()
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{
		Class: carrier.ClassUDP, PathMTU: carrier.DefaultPathMTU, Clock: clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	done, builds, current := superviseGateway(t, ctx, kr, sz, gwCar, clk)
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, clock: clk, noTun: true, tweak: dualAuthExpectingClient(t),
	})
	cli.start(ctx)
	// Let the handshake finish on a frozen clock first. Only then does time
	// move, so the gateway cannot give up on a slow handshake (under -race)
	// before the client ever reaches its attestation wait.
	waitFor(t, 20*time.Second, "the gateway session to establish", func() bool {
		l := current.Load()
		return l != nil && l.Session().State() == session.StateEstablished
	})

	var runErr error
	deadline := time.Now().Add(20 * time.Second)
wait:
	for {
		select {
		case runErr = <-done:
			break wait
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the supervisor did not stop; %d gateway rounds built", builds.Load())
		}
		clk.Advance(100 * time.Millisecond)
		time.Sleep(2 * time.Millisecond)
	}
	if got := current.Load().PeerCloseReason(); got != session.CloseDualAuthFailed {
		t.Fatalf("the first gateway round ended on peer reason %s; the scenario did not produce the CLOSE", got)
	}
	if !errors.Is(runErr, session.ErrDualAuthFailed) || errors.Is(runErr, ErrReconnectExhausted) {
		t.Fatalf("the supervisor returned %v, want the terminal dual-auth failure", runErr)
	}
	if n := builds.Load(); n != 1 {
		t.Fatalf("%d gateway rounds built after a received CloseDualAuthFailed, want 1", n)
	}
}

// TestAReceivedNormalCloseStillRecovers: an orderly CLOSE is a reconnect
// condition by supervisor policy, although session.CloseNormal.NeedsNewSession
// is false: a gateway that restarts closes normally and its clients come back.
func TestAReceivedNormalCloseStillRecovers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sz := planSizing(t)
	kr := newKeyring(t)
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{
		Class: carrier.ClassUDP, PathMTU: carrier.DefaultPathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.CloseNormal.NeedsNewSession() {
		t.Fatal("the session layer now asks for a new session on CloseNormal; revisit this policy")
	}
	done, builds, current := superviseGateway(t, ctx, kr, sz, gwCar, SystemClock{})
	cli := newClientEndpoint(t, kr, endpointOpts{sizing: sz, carrier: cliCar, noTun: true})
	cli.start(ctx)
	cli.waitState(session.StateEstablished, 20*time.Second)
	first := current.Load()
	_ = cli.loop.Close()
	waitFor(t, 20*time.Second, "a second gateway round", func() bool { return builds.Load() >= 2 })
	if first.PeerCloseReason() != session.CloseNormal {
		t.Fatalf("the first gateway round ended on peer reason %s, want normal", first.PeerCloseReason())
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("the supervisor returned %v after a Stop", err)
	}
}

// TestLifecycleVocabulary pins every published state and cause to the facts
// that produce it, including the precedence: a Stop outranks a finished
// supervisor, a finished supervisor outranks recovery, and a successor that
// has only been published is still recovering until it has proven delivery.
func TestLifecycleVocabulary(t *testing.T) {
	exhausted := errWrap(ErrReconnectExhausted, "%w", session.ErrCarrierExhausted)
	never := errWrap(ErrReconnectNeverEstablished, "%w", session.ErrCarrierExhausted)
	terminal := errWrap(ErrSessionFailed, "%w", session.ErrHandshakeUnauthenticated)
	for _, tc := range []struct {
		facts        LifecycleFacts
		state, cause string
	}{
		{LifecycleFacts{}, LifecycleConnecting, ""},
		{LifecycleFacts{CurrentProven: true}, LifecycleConnected, ""},
		{LifecycleFacts{Recovering: true, CurrentProven: true}, LifecycleRecovering, ""},
		{LifecycleFacts{RoundEnded: true}, LifecycleRecovering, ""},
		{LifecycleFacts{RoundEnded: true, CurrentProven: true}, LifecycleConnected, ""},
		// v3: a proven round whose gate is latched down before its end is
		// recorded is recovering, never connecting.
		{LifecycleFacts{EverProven: true}, LifecycleRecovering, ""},
		// A proven live round whose gate a rekey is holding stays connected.
		{LifecycleFacts{RoundProvenLive: true, EverProven: true}, LifecycleConnected, ""},
		{LifecycleFacts{RoundProvenLive: true, RoundEnded: true, EverProven: true}, LifecycleConnected, ""},
		{LifecycleFacts{Recovering: true, RoundProvenLive: true, EverProven: true}, LifecycleRecovering, ""},
		{LifecycleFacts{Finished: true, RunErr: exhausted, Recovering: true}, LifecycleBlocked, LifecycleCauseBudgetSpent},
		{LifecycleFacts{Finished: true, RunErr: never}, LifecycleBlocked, LifecycleCauseNeverEstablished},
		{LifecycleFacts{Finished: true, RunErr: terminal}, LifecycleBlocked, LifecycleCauseTerminal},
		{LifecycleFacts{Finished: true, RunErr: context.Canceled}, LifecycleStopped, ""},
		{LifecycleFacts{Stopped: true, Finished: true, RunErr: exhausted}, LifecycleStopped, ""},
	} {
		state, cause := Lifecycle(tc.facts)
		if state != tc.state || cause != tc.cause {
			t.Errorf("Lifecycle(%+v) = %q/%q, want %q/%q", tc.facts, state, cause, tc.state, tc.cause)
		}
	}
}
