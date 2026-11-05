package driver

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

// The recovery-episode suite: the budget counts CONSECUTIVE failed rounds, a
// round that carried authenticated traffic for ResetAfter opens a new episode,
// Terminal ends the supervisor at once, and a Stop during a build drives
// nothing.

// provenStub is a round that dies at once after having carried authenticated
// traffic for proven.
type provenStub struct {
	stubRunner
	proven time.Duration
}

func (p *provenStub) ProvenFor() time.Duration { return p.proven }

// episodeSupervisor runs one supervisor over a scripted list of rounds and
// returns its error, the number of rounds built and the delays drawn.
func episodeSupervisor(
	t *testing.T, script []time.Duration, terminal func(error) bool,
) (err error, builds int, sleeps []time.Duration) {
	t.Helper()
	rc, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			if builds >= len(script) {
				t.Fatalf("round %d built past the end of a %d-round script", builds+1, len(script))
			}
			r := &provenStub{
				stubRunner: stubRunner{err: fmt.Errorf("round %d: %w", builds+1, session.ErrPeerUnreachable)},
				proven:     script[builds],
			}
			builds++
			return r, nil
		},
		Attempts:   carrier.DefaultBackoffAttempts,
		ResetAfter: DefaultReconnectResetAfter,
		Terminal:   terminal,
		Sleep: func(_ context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewReconnect: %v", err)
	}
	return rc.Run(context.Background()), builds, sleeps
}

// TestReconnectFiveFailedRoundsEndTheEpisode: five rounds that never proved
// themselves spend the budget, even though each one ran; 59 s is not 60.
func TestReconnectFiveFailedRoundsEndTheEpisode(t *testing.T) {
	short := DefaultReconnectResetAfter - time.Second
	script := []time.Duration{0, short, 0, short, 0, time.Hour}
	err, builds, sleeps := episodeSupervisor(t, script, TerminalRoundError)
	if !errors.Is(err, ErrReconnectExhausted) {
		t.Fatalf("Run returned %v, want ErrReconnectExhausted", err)
	}
	if !errors.Is(err, session.ErrPeerUnreachable) {
		t.Fatalf("the exhaustion error %v does not carry the last round's cause", err)
	}
	if builds != carrier.DefaultBackoffAttempts {
		t.Fatalf("%d rounds built, want the %d-round budget", builds, carrier.DefaultBackoffAttempts)
	}
	if len(sleeps) != carrier.DefaultBackoffAttempts-1 {
		t.Fatalf("%d delays drawn, want %d", len(sleeps), carrier.DefaultBackoffAttempts-1)
	}
}

// TestReconnectSixtySecondsOfProvenOperationResetsTheBudget: four failures, a
// round that carried authenticated traffic for a minute, and the next episode
// has all five rounds again. Without the reset the supervisor would give up on
// round five, which is a phone left unprotected after one bad minute a day.
func TestReconnectSixtySecondsOfProvenOperationResetsTheBudget(t *testing.T) {
	script := []time.Duration{
		0, 0, 0, 0, DefaultReconnectResetAfter, // episode one ends proven
		0, 0, 0, 0, 2 * DefaultReconnectResetAfter, // episode two ends proven
		0, 0, 0, 0, 0, // episode three spends the budget
	}
	err, builds, sleeps := episodeSupervisor(t, script, TerminalRoundError)
	if !errors.Is(err, ErrReconnectExhausted) {
		t.Fatalf("Run returned %v, want ErrReconnectExhausted", err)
	}
	if builds != len(script) {
		t.Fatalf("%d rounds built, want %d: a proven round did not reset the budget", builds, len(script))
	}
	// A proven round's death is followed by a FIRST-window draw, so the
	// episode that follows starts at the base again rather than at the cap.
	b := carrier.Backoff{Base: carrier.DefaultBackoffBase, Cap: carrier.DefaultBackoffCap}
	for _, i := range []int{4, 9} {
		if w := backoffWindow(b, 0); sleeps[i] <= 0 || sleeps[i] >= w {
			t.Fatalf("delay after proven round %d is %v, want inside (0, %v)", i+1, sleeps[i], w)
		}
	}
}

// TestReconnectTerminalRoundsBypassTheBudget: an error no rebuild can cure ends
// the supervisor on the round that produced it, unwrapped, with no delay drawn.
// An unanswered handshake is not one of them.
func TestReconnectTerminalRoundsBypassTheBudget(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		terminal bool
	}{
		{"unauthenticated", fmt.Errorf("%w: %w", ErrSessionFailed, session.ErrHandshakeUnauthenticated), true},
		{"dual-auth", fmt.Errorf("%w: %w", ErrSessionFailed, session.ErrDualAuthFailed), true},
		{"path-mtu", fmt.Errorf("%w: %w", ErrSessionFailed, session.ErrPathMTUMismatch), true},
		{"marked build refusal", fmt.Errorf("%w: key file missing", ErrReconnectTerminal), true},
		{"unanswered handshake", fmt.Errorf("%w: %w", ErrSessionFailed, session.ErrCarrierExhausted), false},
		{"peer unreachable", fmt.Errorf("%w: %w", ErrSessionFailed, session.ErrPeerUnreachable), false},
		{"spin guard", errWrap(ErrConfig, "the write loop woke 4097 times"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := TerminalRoundError(tc.err); got != tc.terminal {
				t.Fatalf("TerminalRoundError(%v) = %v, want %v", tc.err, got, tc.terminal)
			}
			var builds int
			rc, err := NewReconnect(ReconnectConfig{
				Build: func() (Runner, error) {
					builds++
					return &stubRunner{err: tc.err}, nil
				},
				Terminal: TerminalRoundError,
				Sleep:    func(context.Context, time.Duration) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			runErr := rc.Run(context.Background())
			if tc.terminal {
				if builds != 1 || runErr != tc.err {
					t.Fatalf("terminal error: %d builds, Run returned %v; want 1 build and the error itself", builds, runErr)
				}
				return
			}
			if builds != carrier.DefaultBackoffAttempts || !errors.Is(runErr, ErrReconnectExhausted) {
				t.Fatalf("retryable error: %d builds, Run returned %v", builds, runErr)
			}
		})
	}
}

// TestReconnectDoesNotDriveARoundBuiltDuringAStop: a Stop that lands while
// Build runs releases the round without Run, so it cannot emit a handshake.
func TestReconnectDoesNotDriveARoundBuiltDuringAStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var ran atomic.Bool
	built := &runProbe{ran: &ran}
	rc, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			cancel()
			return built, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
	if ran.Load() {
		t.Fatal("a round built during a Stop was driven")
	}
	if !built.closed.Load() {
		t.Fatal("a round built during a Stop was not closed")
	}
}

type runProbe struct {
	stubRunner
	ran *atomic.Bool
}

func (r *runProbe) Run(context.Context) error {
	r.ran.Store(true)
	return nil
}

// TestLoopProvenForIsTheSessionsAuthenticatedSpan measures ProvenFor on a real
// pair under the step clock. It grows while the peer answers and stops growing
// when the peer goes silent, however long the round is then held open: a
// session that established and then only waited out liveness proved nothing.
func TestLoopProvenForIsTheSessionsAuthenticatedSpan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
	// Rekeys inside the window, so a span that restarted at every ratchet
	// would be caught: the probes alone cross this volume trigger.
	cli := newClientEndpoint(t, kr, endpointOpts{sizing: sz, carrier: cliCar, clock: clk, noTun: true, tweak: rekeySoon(8)})
	gw := newGatewayEndpoint(t, kr, endpointOpts{sizing: sz, carrier: gwCar, clock: clk, noTun: true, tweak: rekeySoon(8)})
	if got := cli.loop.ProvenFor(); got != 0 {
		t.Fatalf("ProvenFor before the handshake is %v, want 0", got)
	}
	gwCtx, stopGateway := context.WithCancel(ctx)
	gw.start(gwCtx)
	cli.start(ctx)
	cli.waitState(session.StateEstablished, 20*time.Second)

	// Liveness probes are the authenticated traffic of an idle tunnel. Step the
	// clock and let each probe be answered.
	for range 13 {
		clk.Advance(3 * time.Second)
		time.Sleep(20 * time.Millisecond)
	}
	// Mid-window, drive the volume trigger with inner packets rather than
	// counting on how many probes the scheduler happened to exchange, so a
	// ratchet lands inside the window on every run.
	waitFor(t, 20*time.Second, "a rekey inside the window", func() bool {
		_ = cli.loop.SendInner([]byte{0x45})
		time.Sleep(2 * time.Millisecond)
		return cli.loop.Session().Stats().Rekeys > 0
	})
	for range 13 {
		clk.Advance(3 * time.Second)
		time.Sleep(20 * time.Millisecond)
	}
	proven := cli.loop.ProvenFor()
	if proven < DefaultReconnectResetAfter {
		t.Fatalf("ProvenFor after 78 s of an answering peer is %v, want at least %v", proven, DefaultReconnectResetAfter)
	}

	// The peer goes silent. The round is held open for as long again and
	// ProvenFor must not move.
	stopGateway()
	_ = gw.waitRun(10 * time.Second)
	for range 10 {
		clk.Advance(2 * time.Second)
		time.Sleep(10 * time.Millisecond)
	}
	if after := cli.loop.ProvenFor(); after > proven+5*time.Second {
		t.Fatalf("ProvenFor grew from %v to %v with nobody answering", proven, after)
	}
}
