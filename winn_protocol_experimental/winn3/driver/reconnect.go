package driver

// Reconnect re-runs a host-built tunnel on the §4.2 schedule after its session
// dies, so that an on-path adversary who drops the client's packets can neither
// induce a reconnect storm nor establish a recognisable cadence to block.
//
// # What the three lower layers already do, and what this one adds
//
// The scheduling primitives below this package are complete and are not
// restated here:
//
//   - winn3/session retransmits a handshake that gets no answer on its own
//     schedule (session.Retry, full jitter, hard attempt cap), and reports
//     NeedsCarrierChange() when that budget is spent.
//   - winn3/carrier.Redial redials a transport with the same shape when one dial
//     fails.
//   - datapath/failover.go (reached through driver/dpbridge, which this
//     package must not import) drives an ordered plan of carriers. The v1/v2
//     internal/carrier.Manager is not a layer of this protocol;
//     TestDriverIsStandalone fails the build if this package ever imports it.
//
// None of those covers the whole-tunnel case that this type does. Loop.Run
// returns when the session terminates — peer unreachable, carrier closed,
// graceful close — and until now every host that ran it had no in-process
// answer: the host either watched the process die and restarted it, or wrote
// its own ad-hoc retry. An ad-hoc retry is exactly the reconnect storm this
// file exists to prevent, because nothing about "reconnect the thing that
// dropped" forces it to be jittered or capped.
//
// This type is the missing layer: it owns the decision to build a FRESH tunnel
// (fresh session, fresh carrier) after a whole round fails, and it spaces those
// decisions with the one schedule this protocol has chosen — exponential, full
// jitter, hard cap — drawn from winn3/carrier.Backoff so there is a single
// backoff primitive in the tree rather than a second, drifting copy.
//
// # The contract with the host
//
// A supervisor cannot open a socket itself; on three of five platforms the host
// protects the transport before the datapath may touch it. So Build is the
// host's: it returns a ready Runner (a *Loop), and the supervisor calls Run on
// it once and Close once, on every round. The supervisor decides WHEN and
// WHETHER to build; the host decides how a tunnel is built.
//
// Reconnect is opt-in. Nothing in this package changes Loop.Run's own contract;
// a host that calls Loop.Run directly keeps its exact behaviour. This is the
// same default-off shape escalation.go, failover.go and dpbridge already use.
//
// # When the schedule is applied
//
// Rounds that fail at RUN time (the session established or at least ran, then
// died) and rounds that fail at BUILD time (the carrier would not dial) are
// treated the same way, because the client cannot tell the two apart and both
// are exactly the "the peer is not answering" failure this schedule exists to
// absorb. Only a cancelled context stops the loop: a peer CLOSE, a dead carrier
// and a build refusal are all reasons to re-establish, and a user's Stop is
// the one thing that is not.
//
// The round budget is separate from the delay cap. The DELAY between rounds is
// at most Backoff.Cap — in steady state a blocked client emits at most one
// rebuild per uniform (0, Cap) draw, which bounds the reconnect rate. The
// Attempts BUDGET says when the supervisor stops trying on this class and
// hands the decision up: spending it is §4.2's signal that the CARRIER CLASS
// must change, and a supervisor that retried the same class forever would be a
// beacon with a recognisable cadence even with jittered spacing.
//
// # Recovery episodes
//
// With ResetAfter set, the budget counts CONSECUTIVE failed rounds in one
// recovery episode rather than rounds for the life of the supervisor. A round
// whose session carried authenticated traffic for at least ResetAfter (read
// through ProvenRunner) proved the carrier class works; its death opens a new
// episode with the whole budget. A round that merely held a socket open proves
// nothing, which is why the span is the session's own evidence and not the
// time Run happened to take.
//
// # Rounds no rebuild can cure
//
// Terminal classifies an error that a fresh session would only repeat: a
// refused configuration, or credentials the peer cannot authenticate. Such an
// error ends the supervisor at once with no delay drawn, because retrying it
// five times is five more handshakes on the wire with a known answer.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

// Runner is the surface a Reconnect drives. *Loop satisfies it.
type Runner interface {
	// Run drives the tunnel until it terminates. It may return nil on a
	// graceful close; both nil and a non-nil error are reconnect conditions,
	// unless ctx was the reason it stopped.
	Run(ctx context.Context) error

	// Close releases the resources of a finished round. It must be safe to
	// call after Run has returned, and on a round whose Run was never called
	// (the context was cancelled between Build and Run).
	Close() error
}

// ProvenRunner is a Runner that can say how long its round carried
// authenticated traffic. *Loop satisfies it. A Runner that does not implement
// it never resets the round budget.
type ProvenRunner interface {
	Runner
	ProvenFor() time.Duration
}

// EstablishedRunner is a Runner that can say whether its session ever reached
// Established. *Loop satisfies it. FailBeforeEstablishment reads it.
type EstablishedRunner interface {
	Runner
	Established() bool
}

// PeerCloseRunner is a Runner that can report the reason in the peer's
// authenticated CLOSE. *Loop satisfies it.
//
// A received CLOSE ends Loop.Run with a nil error whatever its reason, because
// at the loop's layer every CLOSE is an orderly end. At this layer the reason
// matters: CloseDualAuthFailed is the peer saying this end's attestation did
// not verify, and a fresh session would present the same attestation. Run maps
// it to session.ErrDualAuthFailed before classifying the round. Every other
// reason, CloseNormal included, is a reconnect condition by this supervisor's
// policy while the owner still wants service, even though the session layer's
// NeedsNewSession reports false for CloseNormal: a gateway that restarts closes
// normally, and its clients must come back.
type PeerCloseRunner interface {
	Runner
	PeerCloseReason() session.CloseReason
}

// ReconnectConfig configures one reconnect supervisor.
type ReconnectConfig struct {
	// Build returns a READY tunnel for one round: a fresh session on a fresh
	// carrier. The supervisor calls it once per round and calls Run then Close
	// on the result. It must build a NEW tunnel each call; returning the same
	// *Loop twice would run one session twice. Required.
	Build func() (Runner, error)

	// Backoff is the exponential-full-jitter schedule used between rounds.
	// Zero fields take winn3/carrier's defaults (500 ms base, 8 s cap).
	Backoff carrier.Backoff

	// Attempts is the hard round budget. Spending it is §4.2's change-carrier
	// signal, and Run returns ErrReconnectExhausted wrapping the last round's
	// error. Zero means carrier.DefaultBackoffAttempts.
	Attempts int

	// Clock is the supervisor's wait primitive. Nil means SystemClock.
	Clock Clock

	// Rand supplies every jitter draw. Nil means crypto/rand.Reader. It must
	// not be a predictable generator: a seeded PRNG would make the spacing an
	// observer can predict, which is the metronome this schedule exists to
	// prevent.
	Rand io.Reader

	// Sleep replaces the wait between rounds. Tests use it to observe the
	// drawn delays deterministically. Nil means a Clock timer.
	Sleep func(ctx context.Context, d time.Duration) error

	// ResetAfter is how long a round must have carried authenticated traffic
	// (ProvenRunner.ProvenFor) for its end to open a new recovery episode with
	// the whole Attempts budget. Zero means the budget never resets, which is
	// this type's original behaviour: Attempts rounds for the supervisor's life.
	ResetAfter time.Duration

	// Terminal reports a round error no rebuild can cure. Run returns such an
	// error at once and unwrapped, with no delay drawn. Nil means every error
	// is retried. TerminalRoundError is the classifier the hosts use.
	Terminal func(error) bool

	// FailBeforeEstablishment ends the supervisor after the first round that
	// ends while no round of this supervisor has ever established (read
	// through EstablishedRunner), with ErrReconnectNeverEstablished wrapping
	// that round's error, and no further Build or delay. A tunnel that has
	// never once established is a configuration or reachability fact the
	// owner must hear about now, not after five more handshake budgets. Once
	// any round has established, later failures spend the episode budget as
	// usual. Terminal and cancellation take precedence. False keeps the
	// original behaviour for generic callers.
	FailBeforeEstablishment bool
}

// DefaultReconnectResetAfter is how long a round must carry authenticated
// traffic before its death opens a new recovery episode. A minute is long
// enough that a path which establishes and then dies on the first burst cannot
// reset the budget, and short enough that an ordinary mobile session that
// survived its first minute gets the whole budget back.
const DefaultReconnectResetAfter = 60 * time.Second

// Errors. Local to the supervisor; nothing here answers a peer.
var (
	// ErrReconnectExhausted is returned by Run when the round budget is spent.
	// It is §4.2's change-carrier-class signal at this layer: a supervisor
	// that retried the same carrier class forever would be a beacon.
	ErrReconnectExhausted = errors.New(
		"winn3/driver: reconnect budget spent; change carrier class",
	)

	// ErrReconnectTerminal marks a round error that no rebuild can cure. A
	// host's Build wraps a refusal in it when a fresh round would refuse the
	// same way, which is every Build failure for a host that touches no
	// network in Build.
	ErrReconnectTerminal = errors.New(
		"winn3/driver: the round failed in a way no rebuild can cure",
	)

	// ErrReconnectNeverEstablished is returned under FailBeforeEstablishment
	// when a round ended and no round had ever established. It records an
	// observation, that no session was established, and names no cause:
	// silence from a blocked path and silence from a gateway that will not
	// admit this client look the same from here.
	ErrReconnectNeverEstablished = errors.New(
		"winn3/driver: no session was ever established",
	)
)

// TerminalRoundError is the classifier the hosts give ReconnectConfig.Terminal.
//
// Terminal: anything marked ErrReconnectTerminal, a session configuration
// refusal, a handshake budget spent on messages that could not be
// authenticated (a peer that answers but cannot be authenticated is not helped
// by a new carrier), a failed dual-signature attestation, and two ends that
// planned at different path MTUs. NOT terminal: an unanswered handshake
// (ErrCarrierExhausted), a peer that stopped answering liveness, a dead carrier
// and a peer CLOSE, which are exactly the failures the schedule exists to
// absorb.
//
// driver.ErrConfig is deliberately absent. Run wraps the write loop's spin
// guard in it, and a runtime guard tripping is a reason to build a fresh
// session, not to leave the user unprotected; a Build that refuses a
// configuration marks its own error instead.
func TerminalRoundError(err error) bool {
	for _, target := range []error{
		ErrReconnectTerminal,
		session.ErrConfig,
		session.ErrHandshakeUnauthenticated,
		session.ErrDualAuthFailed,
		session.ErrPathMTUMismatch,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// ReconnectStats is the supervisor's own seat-of-the-pants counts.
type ReconnectStats struct {
	// Builds is how many rounds built a runner.
	Builds uint64

	// Failed is how many rounds ended in a failure worth backing off from.
	Failed uint64

	// Delays is how many reconnect delays were drawn (and waited).
	Delays uint64

	// LastDelay is the most recent reconnect delay drawn.
	LastDelay time.Duration
}

// Reconnect is one supervised reconnection loop.
type Reconnect struct {
	build      func() (Runner, error)
	backoff    carrier.Backoff
	attempts   int
	clock      Clock
	rand       io.Reader
	sleep      func(ctx context.Context, d time.Duration) error
	resetAfter time.Duration
	terminal   func(error) bool
	failFast   bool

	stats struct {
		builds atomic.Uint64
		failed atomic.Uint64
		delays atomic.Uint64
		lastNs atomic.Int64
	}
}

// NewReconnect validates the configuration and returns a supervisor.
func NewReconnect(cfg ReconnectConfig) (*Reconnect, error) {
	if cfg.Build == nil {
		return nil, errWrap(ErrConfig,
			"a reconnect supervisor needs a Build func: it cannot open sockets itself")
	}
	b := cfg.Backoff
	if b.Base == 0 {
		b.Base = carrier.DefaultBackoffBase
	}
	if b.Cap == 0 {
		b.Cap = carrier.DefaultBackoffCap
	}
	if b.Cap < b.Base {
		return nil, errWrap(ErrConfig,
			"reconnect backoff cap %v is below base %v", b.Cap, b.Base)
	}
	if b.Cap == b.Base {
		return nil, errWrap(ErrConfig,
			"reconnect backoff cap %v equals base %v: a schedule with no spread is a fixed reconnect interval",
			b.Cap, b.Base)
	}
	attempts := cfg.Attempts
	if attempts == 0 {
		attempts = carrier.DefaultBackoffAttempts
	}
	if attempts < 1 {
		return nil, errWrap(ErrConfig,
			"reconnect attempt budget %d must be at least 1", attempts)
	}
	if cfg.ResetAfter < 0 {
		return nil, errWrap(ErrConfig,
			"reconnect reset span %v must not be negative", cfg.ResetAfter)
	}
	clock := cfg.Clock
	if clock == nil {
		clock = SystemClock{}
	}
	randReader := cfg.Rand
	if randReader == nil {
		randReader = rand.Reader
	}
	return &Reconnect{
		build:      cfg.Build,
		backoff:    b,
		attempts:   attempts,
		clock:      clock,
		rand:       randReader,
		sleep:      cfg.Sleep,
		resetAfter: cfg.ResetAfter,
		terminal:   cfg.Terminal,
		failFast:   cfg.FailBeforeEstablishment,
	}, nil
}

// Run supervises the tunnel until the context is cancelled, the round budget
// is spent, or a round fails in a way Terminal says no rebuild can cure. It is
// the host's goroutine.
//
// Round n dials immediately on entry; between round n and round n+1 it waits a
// fresh draw from Backoff.Delay(n) — exponential, full jitter, capped. A
// cancelled context is the only thing that is not a reconnect reason: a user's
// Stop must not read as a failure to back off from.
func (r *Reconnect) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var last error
	// failures counts consecutive failed rounds in the current episode. A
	// proven round's end resets it to zero and is not itself one of them.
	failures := 0
	// everEstablished is the supervisor-lifetime fact FailBeforeEstablishment
	// reads. It is folded in from each round's own history after that round
	// ends, never from a round number or from a session's current state.
	everEstablished := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		rr, err := r.build()
		r.stats.builds.Add(1)
		if cerr := ctx.Err(); cerr != nil {
			// Cancelled while building. A Stop outranks whatever Build
			// returned, a refusal included: the owner's Stop is the outcome,
			// not a terminal or never-established verdict it arrived before.
			// A round that was built is released without being driven, so a
			// Stop can never put one more handshake on the wire.
			if err == nil && rr != nil {
				_ = rr.Close()
			}
			return cerr
		}
		proven := false
		if err != nil {
			last = err
		} else {
			runErr := rr.Run(ctx)
			if er, ok := rr.(EstablishedRunner); ok && er.Established() {
				everEstablished = true
			}
			if pr, ok := rr.(ProvenRunner); ok && r.resetAfter > 0 {
				proven = pr.ProvenFor() >= r.resetAfter
			}
			if pc, ok := rr.(PeerCloseRunner); ok {
				if reason := pc.PeerCloseReason(); reason == session.CloseDualAuthFailed {
					runErr = fmt.Errorf("%w: the peer closed the session (%s): %w",
						ErrSessionFailed, reason, session.ErrDualAuthFailed)
				}
			}
			closeErr := rr.Close()
			if err := ctx.Err(); err != nil {
				// User-initiated stop: Run ended because the caller asked it
				// to, not because the peer stopped answering. Not a failure to
				// back off from.
				return err
			}
			if closeErr != nil {
				// A successor must not run while the previous round still owns
				// a reader or output pump. Keep the supervisor blocked.
				return errWrap(ErrReconnectTerminal, "round teardown failed: %w", closeErr)
			}
			last = runErr
		}
		r.stats.failed.Add(1)
		if r.terminal != nil && last != nil && r.terminal(last) {
			return last
		}
		if r.failFast && !everEstablished {
			if last == nil {
				return ErrReconnectNeverEstablished
			}
			return errWrap(ErrReconnectNeverEstablished, "%w", last)
		}
		round := 0
		if proven {
			failures = 0
		} else {
			failures++
			if failures >= r.attempts {
				break
			}
			round = failures - 1
		}
		d, err := r.backoff.Delay(round, r.rand)
		if err != nil {
			// Entropy failure is fatal rather than papered over, for the same
			// reason winn3/session gives for its draws: falling back to a
			// weaker source would convert this schedule into a predictable one
			// exactly when nobody is looking.
			return err
		}
		r.stats.delays.Add(1)
		r.stats.lastNs.Store(int64(d))
		if err := r.wait(ctx, d); err != nil {
			return err
		}
	}
	if last == nil {
		// Every round closed cleanly and none was cancelled. The budget is
		// still spent; the message just has to not print a nil cause.
		last = ErrReconnectExhausted
	}
	return errWrap(ErrReconnectExhausted, "%w", last)
}

// The lifecycle vocabulary a supervised host publishes in its status
// document. It is machine-readable and closed: a host that meets a value it
// does not know must treat it as LifecycleBlocked.
const (
	// LifecycleConnecting: the tunnel has never proven delivery and no round
	// has ended. It is published only before first proof: once any round has
	// proven delivery the tunnel never returns to connecting.
	LifecycleConnecting = "connecting"
	// LifecycleConnected: the round read for this document has its own
	// delivery proof and is live. A round that has only established is not
	// connected, and after a recovery a successor is not connected until it
	// has delivered. A proven live round whose gate is momentarily held (a
	// rekey) stays connected, with promotion_ready false for that moment.
	LifecycleConnected = "connected"
	// LifecycleRecovering: the tunnel has proven delivery or lost a round,
	// and no live round is proven now: a round has ended or is ending, and no
	// successor has proven delivery yet, whether or not one is published. No
	// round's counters are published, promotion is not ready, and the host
	// keeps whatever capture it has installed: recovery never asks a promoted
	// host to narrow.
	LifecycleRecovering = "recovering"
	// LifecycleBlocked: the supervisor has finished and will build nothing
	// more. It persists until the owner stops the tunnel, carries its cause,
	// and needs the owner or the user to act. It authorises no fallback to
	// another protocol and no release of capture.
	LifecycleBlocked = "blocked"
	// LifecycleStopped: the owner stopped the tunnel.
	LifecycleStopped = "stopped"
)

// Causes published with LifecycleBlocked. Each names what this end observed
// and never infers why: a path that is blocked and a gateway that will not
// answer this client are the same observation here.
const (
	// LifecycleCauseNeverEstablished: under FailBeforeEstablishment, a round
	// ended before any round had established.
	LifecycleCauseNeverEstablished = "never_established"
	// LifecycleCauseBudgetSpent: the episode's consecutive-round budget was
	// spent (ErrReconnectExhausted), which is §4.2's change-carrier signal.
	LifecycleCauseBudgetSpent = "budget_spent"
	// LifecycleCauseTerminal: a round failed in a way Terminal says no rebuild
	// can cure, a refused configuration or failed authentication.
	LifecycleCauseTerminal = "terminal"
)

// LifecycleFacts is what a host knows about its supervised tunnel, read in one
// snapshot.
type LifecycleFacts struct {
	// Stopped: the owner closed the tunnel.
	Stopped bool
	// Finished: the supervisor's Run has returned, with RunErr.
	Finished bool
	RunErr   error
	// Recovering: a round has ended and no successor is published yet.
	Recovering bool
	// CurrentProven: the round read for this document has its gate carrying
	// and has delivered, which is the promotion predicate.
	CurrentProven bool
	// RoundProvenLive: that round has delivered and its gate is not latched
	// down, so it is live and proven even if a rekey is holding its gate.
	RoundProvenLive bool
	// RoundEnded: some round of this tunnel has ended, as recorded.
	RoundEnded bool
	// EverProven: some round of this tunnel has delivered, as recorded at a
	// round's end or as read from the round this document read. It is the
	// fact that keeps a tunnel whose proven round is dying, and whose end is
	// not yet recorded, from reading as a tunnel that never connected.
	EverProven bool
}

// Lifecycle derives the published state and, for LifecycleBlocked, its cause.
func Lifecycle(f LifecycleFacts) (state, cause string) {
	switch {
	case f.Stopped:
		return LifecycleStopped, ""
	case f.Finished:
		switch {
		case f.RunErr == nil || errors.Is(f.RunErr, context.Canceled):
			return LifecycleStopped, ""
		case errors.Is(f.RunErr, ErrReconnectNeverEstablished):
			return LifecycleBlocked, LifecycleCauseNeverEstablished
		case errors.Is(f.RunErr, ErrReconnectExhausted):
			return LifecycleBlocked, LifecycleCauseBudgetSpent
		default:
			return LifecycleBlocked, LifecycleCauseTerminal
		}
	case f.Recovering:
		return LifecycleRecovering, ""
	case f.CurrentProven, f.RoundProvenLive:
		return LifecycleConnected, ""
	case f.RoundEnded, f.EverProven:
		return LifecycleRecovering, ""
	default:
		return LifecycleConnecting, ""
	}
}

var (
	_ ProvenRunner      = (*Loop)(nil)
	_ EstablishedRunner = (*Loop)(nil)
	_ PeerCloseRunner   = (*Loop)(nil)
)

// Stats snapshots the supervisor's own counters.
func (r *Reconnect) Stats() ReconnectStats {
	return ReconnectStats{
		Builds:    r.stats.builds.Load(),
		Failed:    r.stats.failed.Load(),
		Delays:    r.stats.delays.Load(),
		LastDelay: time.Duration(r.stats.lastNs.Load()),
	}
}

// wait blocks for d or until ctx is done. The default goes through the Clock so
// the whole schedule stays deterministic under a fake clock; a configured Sleep
// replaces it for tests that want to observe each drawn delay.
func (r *Reconnect) wait(ctx context.Context, d time.Duration) error {
	if r.sleep != nil {
		return r.sleep(ctx, d)
	}
	t := r.clock.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C():
		return nil
	}
}
