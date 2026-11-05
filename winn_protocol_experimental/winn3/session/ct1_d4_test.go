package session

// CT-1 D4 tests that need the API D4 adds (and so do not build on the release
// tree): T13, the measured RTT and its floor, and connectBy binding.

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// TestCT1SupersessionWipesTheDeadGeneration is T13: after supersedeGeneration
// the old session object refuses to open (ErrWiped), and the PQ secret, both
// attestation halves, the control queue and the outstanding probes are gone.
// Queued DATA (never sealed) is kept, and the host still sees that this path
// answered (HasAuthenticatedReply).
func TestCT1SupersessionWipesTheDeadGeneration(t *testing.T) {
	for _, held := range []string{"ml-half", "ed-half"} {
		t.Run(held, func(t *testing.T) {
			a := newCT1Attestation(t, 1360)
			if held == "ml-half" {
				a.feed(t, a.ml...)
			} else {
				a.feed(t, a.ed)
			}
			cli := a.p.cli
			if err := cli.Enqueue([]byte{0x45, 0, 0, 20}); err != nil {
				t.Fatal(err)
			}
			now := a.p.clk.Now()
			cli.mu.Lock()
			old := cli.sess
			cli.ctrl = append(cli.ctrl, padFrame())
			cli.inflight[[pingTokenSize]byte{1}] = probeState{at: now}
			cli.pingPending = true
			cli.pqSecret = []byte{1, 2, 3, 4}
			secret := cli.pqSecret
			heldML, heldED := cli.dualMLSig, cli.dualEDSig
			cli.mu.Unlock()
			if (held == "ml-half" && heldML == nil) || (held == "ed-half" && heldED == nil) {
				t.Fatal("fixture: the attestation half is not held")
			}

			a.p.clk.Advance(cli.NextDeadline().Sub(now))
			msg, err := cli.Poll()
			if err != nil || msg == nil {
				t.Fatalf("the fire sent nothing: %v", err)
			}
			st := cli.Stats()
			if st.GenerationsSuperseded != 1 || st.HandshakeAttempts != 2 {
				t.Fatalf("superseded %d, attempts %d; want 1 and 2", st.GenerationsSuperseded, st.HandshakeAttempts)
			}
			probe := make([]byte, 64)
			if _, err := old.OpenInto(make([]byte, 64), probe); !errors.Is(err, core.ErrWiped) {
				t.Fatalf("OpenInto on the dead session returned %v, want ErrWiped", err)
			}
			if !cli.HasAuthenticatedReply() {
				t.Fatal("after a supersession the host would see a path that never answered")
			}
			cli.mu.Lock()
			defer cli.mu.Unlock()
			if cli.sess != nil || cli.pqEph != nil || cli.pqRx != nil || cli.pqSecret != nil {
				t.Fatal("the dead generation's session or PQ state survived")
			}
			for _, b := range secret {
				if b != 0 {
					t.Fatal("the PQ secret was not zeroed")
				}
			}
			if cli.dualEDSig != nil || cli.dualMLSig != nil || cli.dualMLRx != nil {
				t.Fatal("an attestation half of the dead generation survived")
			}
			for _, b := range append(append([]byte{}, heldED...), heldML...) {
				if b != 0 {
					t.Fatal("a held attestation half was not zeroed")
				}
			}
			if len(cli.ctrl) != 0 || len(cli.inflight) != 0 || cli.pingPending || cli.shape != nil || !cli.curGenAt.IsZero() {
				t.Fatal("the dead generation's queues, probes or shape survived")
			}
			if len(cli.data) != 1 {
				t.Fatalf("queued DATA was not kept (%d packets)", len(cli.data))
			}
		})
	}
}

// TestCT1MeasuredRTTFloorsTheLadder pins D4 steps 1, 2 and 4 directly: the
// handshake RTT is measured from the latest fresh initiation, every fire after
// a response waits at least that long, NextDeadline is phaseAt, and connectBy is
// the first send plus handshakeBudget.
func TestCT1MeasuredRTTFloorsTheLadder(t *testing.T) {
	for _, rtt := range ct1RTTs {
		t.Run(fmt.Sprintf("rtt=%v", rtt), func(t *testing.T) {
			r := ct1Run(t, ct1Opts{rtt: rtt, size: 1360, dual: true, seed: 3, dropGw: ct1DropFirst(1)})
			if r.failed != nil {
				t.Fatal(r.failed)
			}
			st := r.cli.Stats()
			if st.HandshakeRTT != rtt {
				t.Fatalf("HandshakeRTT %v, want the link's %v", st.HandshakeRTT, rtt)
			}
			for _, f := range r.fires {
				if r.sessionAt >= 0 && f.at > r.sessionAt && f.at-r.sessionAt < rtt && f.superseded {
					t.Fatalf("a supersession fired %v after the first session, under one RTT", f.at-r.sessionAt)
				}
			}
			if r.cli.connectBy.IsZero() {
				t.Fatal("connectBy was never set")
			}
		})
	}
}

// TestCT1ConnectByBindsBeforeTheLadder: with a ladder long enough (8 fires)
// and an RTT long enough (6 s, every PQ_CT lost) that the floored fires would
// run past handshakeBudget, the connect ends AT connectBy with fires to spare,
// sends no fresh initiation at or after it, and never fires more than
// Retry.Attempts. The anti-vacuity check requires that connectBy, not the
// ladder, ended at least one run.
func TestCT1ConnectByBindsBeforeTheLadder(t *testing.T) {
	retry := Retry{Base: 2 * time.Second, Cap: 8 * time.Second, Attempts: 8, FreshAfter: 9}
	budget := handshakeBudget(retry)
	for _, dual := range []bool{true, false} {
		t.Run(fmt.Sprintf("dual=%v", dual), func(t *testing.T) {
			bound := 0
			for i := 0; i < ct1Runs(); i++ {
				r := ct1RunWith(t, ct1Opts{rtt: 6 * time.Second, size: 1360, dual: dual, seed: 50 + i, untilTerminal: true, horizon: 2 * budget,
					dropGw: func(d ct1Dgram) bool { return d.kind == ct1PQCT }}, func(cli, _ *Config) { cli.Retry = retry })
				if !r.cliState.Terminal() {
					t.Fatalf("run %d: client %s, want closed", i, r.cliState)
				}
				connectBy := r.firstSendAt + budget
				if r.closedAt > connectBy {
					t.Fatalf("run %d: closed at %v, after connectBy %v", i, r.closedAt, connectBy)
				}
				for _, f := range r.freshAt {
					if f >= connectBy {
						t.Fatalf("run %d: a fresh initiation at %v, at or after connectBy %v", i, f, connectBy)
					}
				}
				if len(r.fires) > retry.Attempts {
					t.Fatalf("run %d: %d fires, more than Retry.Attempts", i, len(r.fires))
				}
				if r.cliReason != ct1ExpectedReason(r) {
					t.Fatalf("run %d: close reason %s in phase %d", i, r.cliReason, r.closePhase)
				}
				if r.closedAt == connectBy && len(r.fires) < retry.Attempts {
					bound++
				}
			}
			if bound == 0 {
				t.Fatal("connectBy never ended a run; the scenario does not exercise it")
			}
			t.Logf("connectBy ended %d/%d runs", bound, ct1Runs())
		})
	}
}

// TestCT1RetryPriorConfig is T17: a negative RTTPrior or FreshAfter is
// ErrConfig; an RTTPrior above MaxRTTPrior behaves as MaxRTTPrior (over 40
// seeded draws the first fire is never before 1 s and never after 1.5 s); zero
// is DefaultRTTPrior; a prior above Cap/Attempts is clamped to it (Amendment 3,
// Q4). The FreshAfter encoding itself is TestCT1FreshAfterEncoding.
func TestCT1RetryPriorConfig(t *testing.T) {
	newCli := func(r Retry, seed int) (*pair, error) {
		var err error
		p := newPairErr(t, func(cli, _ *Config) {
			cli.Retry = r
			cli.Rand = newDetRand(fmt.Sprintf("ct1-t17-%d", seed))
		}, &err)
		return p, err
	}
	for _, bad := range []Retry{{RTTPrior: -time.Millisecond}, {FreshAfter: -1}} {
		if _, err := newCli(bad, 0); !errors.Is(err, ErrConfig) {
			t.Fatalf("Retry %+v: err %v, want ErrConfig", bad, err)
		}
	}
	if got := (Retry{}).orDefault().RTTPrior; got != DefaultRTTPrior || DefaultRTTPrior != 400*time.Millisecond {
		t.Fatalf("default RTTPrior %v (DefaultRTTPrior %v), want 400ms", got, DefaultRTTPrior)
	}
	if got := (Retry{RTTPrior: 2 * time.Second}).orDefault().RTTPrior; got != MaxRTTPrior || MaxRTTPrior != time.Second {
		t.Fatalf("RTTPrior 2s became %v, want the %v clamp", got, MaxRTTPrior)
	}
	// Q4 (Amendment 3): the effective prior is clamped to Cap/Attempts, so a
	// ladder whose whole budget is below the prior still ends by exhausting
	// its fires, never at connectBy after one. 10 ms / 40 is 250 microseconds,
	// with the prior left at its default and with a stored measurement.
	for _, prior := range []time.Duration{0, 300 * time.Millisecond} {
		r := Retry{Base: 5 * time.Millisecond, Cap: 10 * time.Millisecond, Attempts: 40, RTTPrior: prior}
		if got := r.orDefault().RTTPrior; got != 250*time.Microsecond {
			t.Fatalf("Retry{Base 5ms, Cap 10ms, Attempts 40, RTTPrior %v}: effective prior %v, want 250µs", prior, got)
		}
	}
	// At the defaults Cap/Attempts is 1.6 s, above MaxRTTPrior: no change.
	if got := (Retry{RTTPrior: time.Second}).orDefault().RTTPrior; got != time.Second {
		t.Fatalf("RTTPrior 1s at the default ladder became %v, want unchanged", got)
	}
	for i := 0; i < 40; i++ {
		p, err := newCli(Retry{RTTPrior: 2 * time.Second}, i)
		if err != nil {
			t.Fatal(err)
		}
		first := p.cli.NextDeadline().Sub(p.clk.Now())
		if first < time.Second || first > time.Second+ct1Window(0) {
			t.Fatalf("seed %d: first fire %v after the first send, want within [1s, 1.5s]", i, first)
		}
	}
}

// newPairErr is newPair for a configuration that may be refused: the client's
// construction error is returned through errp instead of failing the test.
func newPairErr(t *testing.T, tweak func(cli, gw *Config), errp *error) *pair {
	t.Helper()
	clk := newClock()
	gwStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	cliStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	gwPub, err := core.NewPublicKey(gwStatic.Public())
	if err != nil {
		t.Fatal(err)
	}
	gp := gatewayParams(t)
	cliCfg := Config{Core: core.Config{Gateway: gp}, Static: cliStatic, GatewayStatic: gwPub, Padding: core.PadBucket, Clock: clk}
	tweak(&cliCfg, nil)
	cli, err := NewClient(cliCfg)
	if err != nil {
		*errp = err
		return nil
	}
	return &pair{t: t, clk: clk, cli: cli, cliStatic: cliStatic, gwPub: gwPub, gp: gp}
}
