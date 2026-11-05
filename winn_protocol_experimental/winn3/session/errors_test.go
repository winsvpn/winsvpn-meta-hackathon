package session

import (
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// establishedPair is a shorthand for the many error-path tests that need a live
// session before they can break something.
func establishedPair(t *testing.T) *pair {
	t.Helper()
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()
	return p
}

// TestAuthenticatedButUnparseableFramesTearTheSessionDown.
//
// An unopenable message is noise and is ignored. A message that OPENED and then
// failed to parse can only have come from the peer, so it is a protocol error
// and the session ends. Keeping the two apart is the whole reason Deliver
// returns no error for the first case and closes for the second.
func TestAuthenticatedButUnparseableFramesTearTheSessionDown(t *testing.T) {
	p := establishedPair(t)
	// Frame type 0 is reserved, so the core's strict parser rejects the stream.
	msg, err := p.cli.sess.Seal([]byte{0x00, 0x00, 0x00}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.gw.Deliver(msg); err != nil {
		t.Fatal(err)
	}
	if p.gw.State() == StateEstablished {
		t.Fatal("an unparseable frame stream left the session established")
	}
	if got := p.gw.LocalCloseReason(); got != CloseProtocolError {
		t.Errorf("close reason is %s, want %s", got, CloseProtocolError)
	}
	if !errors.Is(p.gw.Err(), ErrProtocol) {
		t.Errorf("error is %v, want ErrProtocol", p.gw.Err())
	}
}

func TestAssembleRefusesAnOversizedControlFrame(t *testing.T) {
	p := establishedPair(t)
	p.cli.ctrl = append(p.cli.ctrl, pendingFrame{
		typ:   core.FrameType(120),
		value: make([]byte, p.cli.cfg.maxPayload()),
	})
	if _, err := p.cli.assemble(p.clk.Now()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("assemble returned %v for a frame that cannot fit a message", err)
	}
}

func TestAssembleClosesWhenARatchetHookFails(t *testing.T) {
	p := establishedPair(t)
	boom := errors.New("ratchet refused")
	p.cli.ctrl = append(p.cli.ctrl, pendingFrame{
		typ:   core.FramePad,
		value: nil,
		after: func() error { return boom },
	})
	if _, err := p.cli.assemble(p.clk.Now()); err != nil {
		t.Fatalf("assemble returned %v; the failure belongs in the state, not the return", err)
	}
	if p.cli.State() == StateEstablished {
		t.Fatal("a failed ratchet hook left the session established")
	}
	if !errors.Is(p.cli.Err(), boom) {
		t.Errorf("error is %v, want the hook's error", p.cli.Err())
	}
}

func TestRekeyFrameEdgeCases(t *testing.T) {
	t.Run("ack without a pending rekey is ignored", func(t *testing.T) {
		p := establishedPair(t)
		if err := p.cli.onRekeyAck(make([]byte, 32)); err != nil {
			t.Fatalf("onRekeyAck returned %v", err)
		}
		if p.cli.State() != StateEstablished {
			t.Errorf("an unsolicited REKEY_ACK changed the state to %s", p.cli.State())
		}
	})

	t.Run("ack with a malformed ephemeral is a protocol error", func(t *testing.T) {
		p := establishedPair(t)
		if err := p.cli.startRekey(p.clk.Now()); err != nil {
			t.Fatal(err)
		}
		if err := p.cli.onRekeyAck([]byte{1, 2, 3}); !errors.Is(err, ErrProtocol) {
			t.Fatalf("onRekeyAck returned %v, want ErrProtocol", err)
		}
	})

	t.Run("init with a malformed ephemeral is a protocol error", func(t *testing.T) {
		p := establishedPair(t)
		if err := p.gw.onRekeyInit(p.clk.Now(), []byte{1, 2, 3, 4}); !errors.Is(err, ErrProtocol) {
			t.Fatalf("onRekeyInit returned %v, want ErrProtocol", err)
		}
	})

	t.Run("init outside established is ignored", func(t *testing.T) {
		p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
		p.drain()
		p.deliver() // gateway has a session but is still initiating
		if p.gw.State() != StateInitiating {
			t.Skip("setup did not land in the initiating state")
		}
		if err := p.gw.onRekeyInit(p.clk.Now(), make([]byte, 32)); err != nil {
			t.Fatalf("onRekeyInit returned %v", err)
		}
		if p.gw.State() != StateInitiating {
			t.Errorf("a rekey during the handshake changed the state to %s", p.gw.State())
		}
	})

	t.Run("a low-order ephemeral is refused", func(t *testing.T) {
		p := establishedPair(t)
		if err := p.gw.onRekeyInit(p.clk.Now(), make([]byte, 32)); err == nil {
			t.Fatal("an all-zero ephemeral was accepted; a forced zero secret authenticates nothing")
		}
	})
}

func TestCompletePQWithoutASecretFails(t *testing.T) {
	p := establishedPair(t)
	p.cli.pqSecret = nil
	if err := p.cli.completePQ(); !errors.Is(err, ErrPQFailed) {
		t.Fatalf("completePQ returned %v, want ErrPQFailed", err)
	}
}

// TestEntropyFailureIsNeverPaperedOver: every draw in this package feeds a timing
// decision, so a silent fallback to a weaker source would turn a memoryless
// schedule into a predictable one exactly when nobody is watching. Each of these
// paths must surface the failure instead.
func TestEntropyFailureIsNeverPaperedOver(t *testing.T) {
	t.Run("new client", func(t *testing.T) {
		p := newPair(t, nil)
		cfg := p.cli.cfg
		cfg.Rand = failingReader{}
		cfg.Core.Rand = failingReader{}
		if _, err := NewClient(cfg); err == nil {
			t.Fatal("a client was built with a dead entropy source")
		}
	})

	t.Run("shaper draw", func(t *testing.T) {
		floor := core.TransportOverhead() + frameHeaderSize
		if _, err := newShaper(core.PadBucket, nil, failingReader{}, floor, DefaultMaxMessageSize, DefaultBucketCount); err == nil {
			t.Fatal("a bucket ladder was drawn with a dead entropy source")
		}
	})

	t.Run("probe token", func(t *testing.T) {
		p := establishedPair(t)
		p.cli.cfg.Rand = failingReader{}
		if err := p.cli.queueProbe(p.clk.Now(), true); err == nil {
			t.Fatal("a probe token was drawn with a dead entropy source")
		}
	})

	t.Run("rekey ephemeral", func(t *testing.T) {
		p := establishedPair(t)
		p.cli.cfg.Rand = failingReader{}
		if err := p.cli.startRekey(p.clk.Now()); err == nil {
			t.Fatal("a rekey ephemeral was drawn with a dead entropy source")
		}
	})

	t.Run("rekey interval", func(t *testing.T) {
		p := establishedPair(t)
		p.cli.cfg.Rand = failingReader{}
		// establish runs only where a handshake or an in-band rekey completes
		// (CT-1 Amendment 3, N-5); drive it from the rekey's state.
		p.cli.state = StateRekeying
		if err := p.cli.establish(p.clk.Now()); err == nil {
			t.Fatal("a rekey interval was drawn with a dead entropy source")
		}
	})

	t.Run("silence redraw surfaces through Poll", func(t *testing.T) {
		p := establishedPair(t)
		p.cli.cfg.Rand = failingReader{}
		p.cli.silenceAt = p.clk.Now().Add(-time.Hour)
		if _, err := p.cli.Poll(); err == nil {
			t.Fatal("Poll swallowed an entropy failure in the silence redraw")
		}
	})

	t.Run("probe redraw surfaces through Poll", func(t *testing.T) {
		p := establishedPair(t)
		p.cli.cfg.Rand = failingReader{}
		p.cli.silenceAt = p.clk.Now().Add(time.Hour)
		p.cli.probeAt = p.clk.Now().Add(-time.Hour)
		if _, err := p.cli.Poll(); err == nil {
			t.Fatal("Poll swallowed an entropy failure in the probe redraw")
		}
	})

	t.Run("handshake backoff surfaces through Poll", func(t *testing.T) {
		p := newPair(t, nil)
		p.cli.cfg.Rand = failingReader{}
		p.cli.phaseAt = p.clk.Now().Add(-time.Hour)
		// Drain the initiation first so the retransmission path is reached.
		if _, err := p.cli.Poll(); err == nil {
			t.Fatal("Poll swallowed an entropy failure in the retry backoff")
		}
	})

	t.Run("post-handshake draws", func(t *testing.T) {
		p := newPair(t, nil)
		p.drain()
		p.cli.cfg.Rand = failingReader{}
		if err := p.cli.onHandshakeComplete(p.clk.Now()); err == nil {
			t.Fatal("the post-handshake draws succeeded with a dead entropy source")
		}
	})
}

func TestHandshakeBudgetPlateausAtTheCap(t *testing.T) {
	// Base doubles past the cap on the second attempt, so the budget must be
	// base + cap*(attempts-1) + one cap of slack, not an unbounded geometric sum.
	r := Retry{Base: time.Second, Cap: 2 * time.Second, Attempts: 4}
	got := handshakeBudget(r)
	want := time.Second + 2*time.Second + 2*time.Second + 2*time.Second + 2*time.Second
	if got != want {
		t.Errorf("handshakeBudget = %s, want %s", got, want)
	}
	if handshakeBudget(Retry{Base: time.Second, Cap: time.Hour, Attempts: 1}) != time.Second+time.Hour {
		t.Error("a single-attempt budget is wrong")
	}
}

func TestBackoffToleratesANegativeAttempt(t *testing.T) {
	v, err := drawBackoff(newDetRand("neg"), Retry{Base: time.Second, Cap: time.Second, Attempts: 1}, -3)
	if err != nil {
		t.Fatal(err)
	}
	if v < 0 || v > time.Second {
		t.Errorf("drawBackoff(-3) = %s", v)
	}
}

func TestNextDeadlineDuringRekey(t *testing.T) {
	p := establishedPair(t)
	if err := p.cli.startRekey(p.clk.Now()); err != nil {
		t.Fatal(err)
	}
	dl := p.cli.NextDeadline()
	if dl.IsZero() {
		t.Fatal("a rekeying session reports no deadline")
	}
	if !dl.After(p.clk.Now()) {
		t.Errorf("rekey deadline %s is not in the future", dl)
	}
	if earliest() != (time.Time{}) {
		t.Error("earliest of nothing is not the zero time")
	}
	if earliest(time.Time{}, time.Time{}) != (time.Time{}) {
		t.Error("earliest of zero times is not the zero time")
	}
}

// TestDataIsRefusedOutsideAStateThatCanCarryIt covers both directions of the
// StrictPQ gate: the sender does not queue it and the receiver does not deliver
// it upward.
func TestDataIsRefusedOutsideAStateThatCanCarryIt(t *testing.T) {
	p := establishedPair(t)
	if err := p.cli.startRekey(p.clk.Now()); err != nil {
		t.Fatal(err)
	}
	out, err := p.cli.handleFrames(p.clk.Now(), []core.Frame{{Type: core.FrameData, Value: []byte("mid-rekey")}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("a DATA frame was delivered upward during a rekey: %v", out)
	}
	if p.cli.Stats().DataFramesDropped != 1 {
		t.Errorf("DataFramesDropped is %d, want 1", p.cli.Stats().DataFramesDropped)
	}

	// New host data is refused while the epoch transition is unresolved. Inner
	// transports retransmit after the gate reopens; the session never accepts a
	// packet while it cannot name the epoch that will carry it.
	if err := p.cli.Enqueue([]byte("waiting")); !errors.Is(err, ErrState) {
		t.Fatalf("Enqueue during rekey returned %v, want ErrState", err)
	}
	msg, err := p.cli.Poll()
	if err != nil {
		t.Fatal(err)
	}
	if msg != nil && p.cli.Stats().DataFramesSent != 0 {
		t.Error("data was sealed under the old epoch after REKEY_INIT")
	}
}

func TestPollOnAFreshGatewayEmitsNothing(t *testing.T) {
	p := newPair(t, nil)
	msg, err := p.gw.Poll()
	if err != nil {
		t.Fatal(err)
	}
	if msg != nil {
		t.Fatal("a gateway emitted a message before any initiation arrived")
	}
	if !p.gw.NextDeadline().After(p.clk.Now()) {
		t.Error("a gateway holding no session has no expiry deadline")
	}
}

func TestCloseBeforeASessionExistsTerminatesImmediately(t *testing.T) {
	p := newPair(t, nil)
	if err := p.cli.Close(); err != nil {
		t.Fatal(err)
	}
	if p.cli.State() != StateClosed {
		t.Fatalf("state is %s; with no session there is nothing to seal a CLOSE into", p.cli.State())
	}
	msg, err := p.cli.Poll()
	if msg != nil || err != nil {
		t.Errorf("Poll after an immediate close returned %v, %v", msg, err)
	}
}

func TestCounterExhaustionCannotSealACloseFrame(t *testing.T) {
	// The hard ceiling is 2^32-2^16 messages, so it cannot be reached in a test.
	// What can be checked is the consequence: when the counter is the reason,
	// beginClose must go straight to terminal rather than queue a CLOSE it can
	// never seal. This is why the volume rekey trigger sits far below the
	// ceiling.
	p := establishedPair(t)
	p.cli.beginClose(CloseCounterExhausted, core.ErrCounterExhausted)
	if p.cli.State() != StateFailed {
		t.Fatalf("state is %s, want failed without a CLOSE attempt", p.cli.State())
	}
	if len(p.cli.ctrl) != 0 {
		t.Errorf("a CLOSE was queued for a session that cannot seal one: %d frames", len(p.cli.ctrl))
	}
	if !errors.Is(p.cli.Err(), core.ErrCounterExhausted) {
		t.Errorf("error is %v", p.cli.Err())
	}
	// A second beginClose must not overwrite the first.
	p.cli.beginClose(CloseNormal, nil)
	if p.cli.LocalCloseReason() != CloseCounterExhausted {
		t.Error("a later close overwrote the recorded reason")
	}
}

// gateRand is an io.Reader that can be flipped to fail after construction, so a
// gateway can be built (and can ReadInitiation) and then have WriteResponse
// fail on the same pointer the core Config captured.
type gateRand struct {
	mu   sync.Mutex
	fail bool
	r    io.Reader
}

func (g *gateRand) Read(p []byte) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fail {
		return 0, errFakeEntropy
	}
	return g.r.Read(p)
}

// TestAuthenticatedInitiationThenLocalResponseFailureIsLoud is the fail-closed
// half of a silent-degrade that used to look like a censor.
//
// WriteResponse runs AFTER ReadInitiation has authenticated the peer. Counting
// that failure as Unopenable made HandshakeFailure print the credential-
// mismatch text, and returning nil left the gateway silent until the handshake
// budget expired. Both are the wrong diagnosis in this product.
func TestAuthenticatedInitiationThenLocalResponseFailureIsLoud(t *testing.T) {
	src := &gateRand{r: rand.Reader}
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		gw.Rand = src
		gw.Core.Rand = src
	})
	msg, err := p.cli.Poll()
	if err != nil || msg == nil {
		t.Fatalf("client initiation: msg=%v err=%v", msg, err)
	}
	src.mu.Lock()
	src.fail = true
	src.mu.Unlock()

	_, err = p.gw.Deliver(msg)
	if err == nil {
		t.Fatal("Deliver returned nil after WriteResponse failed; the gateway looks like a censor")
	}
	if p.gw.Stats().Unopenable != 0 {
		t.Errorf("Unopenable is %d; a local WriteResponse failure is not an unauthenticated message", p.gw.Stats().Unopenable)
	}
	if p.gw.State() != StateFailed {
		t.Errorf("state is %s, want failed", p.gw.State())
	}
	if p.gw.Err() == nil {
		t.Fatal("Err() is nil; the operator has nothing to print")
	}
}
