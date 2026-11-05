package session

// CT-1 D6 tests (Amendment 3, A3.4) that build on the D5 API, so the Arbiter
// can drop them onto an unmodified D5 copy and show them red there: T19 and
// T20 by their timing, the T21 reorder matrix, T22 (N-4), T23 (N-5), T24
// (N-6), the T10 real-timer variant (N-7) and Claude's N-4 mutant pins (K1,
// K2, K3, K7, K10). New counters are read by name (ct1StatOr0). The tests that
// need the D6 API (the floor itself, the hold's internals) are in
// ct1_d6_api_test.go.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	mrand "math/rand"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/dualsign"
)

// --- helpers -------------------------------------------------------------------

// ct1Jitter delays each gateway datagram by a uniform draw on [0, j) from a
// per-run seeded stream: per-datagram reordering with no loss.
func ct1Jitter(j time.Duration, seed int) func(ct1Dgram) time.Duration {
	rng := mrand.New(mrand.NewSource(int64(seed) + 77))
	return func(ct1Dgram) time.Duration { return time.Duration(rng.Int63n(int64(j))) }
}

// ct1DualPair is a quiet pair at one plan floor, with dual auth when asked.
func ct1DualPair(t *testing.T, size int, dual bool) (*pair, ed25519.PrivateKey, []byte) {
	t.Helper()
	edPriv, edPub, mlSeed, mlPub := dualKeys(t)
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		gw.Silence = Draw{Min: quietHorizon, Mean: 2 * quietHorizon, Max: 3 * quietHorizon}
		cli.MaxMessageSize, gw.MaxMessageSize = size, size
		if dual {
			gw.DualAuth = DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
			cli.DualAuth = DualAuthConfig{Expected: true, Ed25519Public: edPub, MLDSA65Public: mlPub}
		}
	})
	return p, edPriv, mlSeed
}

// ct1Attest signs h with both keys and returns the attestation as the
// gateway frames it: one Ed25519 frame and the ML-DSA-65 chunks.
func ct1Attest(t *testing.T, edPriv ed25519.PrivateKey, mlSeed, h []byte, maxPayload int) (core.Frame, []core.Frame) {
	t.Helper()
	edSig, err := dualsign.SignEd25519(edPriv, h)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, mlSeed)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	mlSig, err := dualsign.SignMLDSA65(signer, h)
	if err != nil {
		t.Fatal(err)
	}
	var ml []core.Frame
	for _, c := range chunkBlob(core.FrameDualAuthML, mlSig, maxPayload-frameHeaderSize) {
		ml = append(ml, core.Frame{Type: c.typ, Value: c.value})
	}
	return core.Frame{Type: core.FrameDualAuthED, Value: edSig}, ml
}

// ct1Seal seals frames as one transport message under s (a test-only peer).
func ct1Seal(t *testing.T, s *core.Session, fs ...core.Frame) []byte {
	t.Helper()
	var plain []byte
	for _, f := range fs {
		var err error
		if plain, err = core.AppendFrame(plain, f.Type, f.Value); err != nil {
			t.Fatal(err)
		}
	}
	m, err := s.Seal(plain, 0)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), m...)
}

func ct1DataFrame() core.Frame {
	inner := make([]byte, 40)
	inner[0] = 0x45
	return core.Frame{Type: core.FrameData, Value: inner}
}

// ct1DeliverVia delivers msgs to d one by one through the scalar Deliver or
// through DeliverBatch (all of them in one batch, called again on the
// unprocessed suffix as the contract asks), and returns copies of the inner
// packets delivered.
func ct1DeliverVia(t *testing.T, d *Driver, path string, msgs ...[]byte) [][]byte {
	t.Helper()
	var out [][]byte
	if path == "scalar" {
		for _, m := range msgs {
			pkts, _ := d.Deliver(m)
			for _, p := range pkts {
				out = append(out, append([]byte(nil), p...))
			}
		}
		return out
	}
	slots := make([]ReceiveSlot, len(msgs))
	for i, m := range msgs {
		slots[i] = ReceiveSlot{Message: m, Scratch: make([]byte, len(m)), Packets: make([][]byte, 0, len(m)/frameHeaderSize+1)}
	}
	for i := 0; i < len(slots); {
		n, err := d.DeliverBatch(slots[i:])
		for k := i; k < i+n; k++ {
			for _, p := range slots[k].Packets {
				out = append(out, append([]byte(nil), p...))
			}
		}
		if err != nil || n == 0 {
			break
		}
		i += n
	}
	return out
}

var ct1Paths = []string{"scalar", "batch"}

// ct1PollAll drains d and returns how many messages it emitted.
func ct1PollAll(t *testing.T, d *Driver) int {
	t.Helper()
	n := 0
	for i := 0; i < 64; i++ {
		m, err := d.Poll()
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		if m == nil {
			return n
		}
		n++
	}
	t.Fatal("driver did not quiesce")
	return n
}

// ct1FirstSuperseding is the first ladder fire of a run that superseded a
// generation.
func ct1FirstSuperseding(r ct1Result) (ct1Fire, bool) {
	for _, f := range r.fires {
		if f.superseded {
			return f, true
		}
	}
	return ct1Fire{}, false
}

// ct1KarnFloor is the ruled pre-session floor after k unanswered pre-session
// fires (A3.3 Q1): max(b, min(b*2^k, floorCap)), floorCap 1 s at the defaults.
func ct1KarnFloor(b time.Duration, k int) time.Duration {
	limit := time.Second
	f := b
	for i := 0; i < k && f < limit; i++ {
		f *= 2
	}
	return max(b, min(f, limit))
}

// --- T19: Karn backoff of the pre-session floor ---------------------------------

// TestCT1KarnBackoffOfThePreSessionFloor is T19's timing half. With the first
// two initiations lost, fire 1 lands no earlier than the floor b after the
// first send and fire 2 no earlier than fire 1 + 2b; the connect carries on
// the third initiation. With every initiation lost, each pre-session fire k
// lands in [f(k), f(k) + window(k)) after the previous one, f(k) never above
// the 1 s floorCap, and the ladder still ends by exhaustion before connectBy
// with a carrier-change verdict. Both prior modes, RTT 30 and 300 ms. On D5 the
// second fire's floor is b, not 2b, so this is red there.
func TestCT1KarnBackoffOfThePreSessionFloor(t *testing.T) {
	retry := Retry{}.orDefault()
	for _, mode := range ct1Modes {
		for _, rtt := range []time.Duration{30 * time.Millisecond, 300 * time.Millisecond} {
			b := mode.floor(rtt)
			t.Run(fmt.Sprintf("%s/rtt=%v/two-lost-initiations", mode.name, rtt), func(t *testing.T) {
				for i := 0; i < ct1Runs(); i++ {
					n := 0
					r := ct1Run(t, ct1Opts{rtt: rtt, size: 1360, dual: true, seed: 5400 + i, prior: mode.prior(rtt),
						dropCli: func(d ct1Dgram) bool {
							if d.kind == ct1Initiation && n < 2 {
								n++
								return true
							}
							return false
						}})
					if r.failed != nil {
						t.Fatalf("run %d: %v", i, r.failed)
					}
					if r.hsAttempts != 3 || r.superseded != 0 || len(r.fires) < 2 {
						t.Fatalf("run %d: %d attempts, %d supersessions, %d fires; want 3, 0, at least 2", i, r.hsAttempts, r.superseded, len(r.fires))
					}
					if g := r.fires[0].at - r.firstSendAt; g < b {
						t.Fatalf("run %d: fire 1 at %v after the first send, under the floor %v", i, g, b)
					}
					if g := r.fires[1].at - r.fires[0].at; g < 2*b {
						t.Fatalf("run %d: fire 2 at %v after fire 1, under the doubled floor %v", i, g, 2*b)
					}
				}
			})
			t.Run(fmt.Sprintf("%s/rtt=%v/every-initiation-lost", mode.name, rtt), func(t *testing.T) {
				for i := 0; i < ct1Runs(); i++ {
					r := ct1Run(t, ct1Opts{rtt: rtt, size: 1360, dual: true, seed: 5500 + i, prior: mode.prior(rtt), untilTerminal: true,
						dropCli: func(d ct1Dgram) bool { return d.kind == ct1Initiation }})
					if !r.cliState.Terminal() || len(r.fires) != retry.Attempts {
						t.Fatalf("run %d: client %s after %d fires, want closed after %d", i, r.cliState, len(r.fires), retry.Attempts)
					}
					prev := r.firstSendAt
					for k, f := range r.fires {
						fk := ct1KarnFloor(b, k)
						if fk > time.Second {
							t.Fatalf("floor %v above floorCap", fk)
						}
						if g := f.at - prev; g < fk || g >= fk+ct1Window(k) {
							t.Fatalf("run %d: fire %d at %v after the previous, want in [%v, %v)", i, k+1, g, fk, fk+ct1Window(k))
						}
						prev = f.at
					}
					if connectBy := r.firstSendAt + handshakeBudget(retry); r.closedAt >= connectBy {
						t.Fatalf("run %d: closed at %v, not before connectBy %v", i, r.closedAt, connectBy)
					}
					if r.cliReason != CloseProtocolError || !r.needCarrier {
						t.Fatalf("run %d: reason %s carrier change %v", i, r.cliReason, r.needCarrier)
					}
				}
			})
		}
	}
}

// --- T20: the draw window resets when a response opens ----------------------------

// TestCT1FirstSupersessionDrawsTheFirstWindow is T20's timing half. A lost
// initiation spends one pre-session fire; the answered generation then loses
// its PQ_CT. The supersession fire is armed when the response opens and must
// draw from window(0): over every seed, its offset from that instant minus the
// post-response floor (RTT + allowance) lies in (0, Base]. On D5 the draw is
// at the attempt index (1), so a 1 s window shows.
func TestCT1FirstSupersessionDrawsTheFirstWindow(t *testing.T) {
	base := Retry{}.orDefault().Base
	for _, mode := range ct1Modes {
		for _, dual := range []bool{true, false} {
			for _, rtt := range []time.Duration{30 * time.Millisecond, 300 * time.Millisecond} {
				t.Run(fmt.Sprintf("%s/dual=%v/rtt=%v", mode.name, dual, rtt), func(t *testing.T) {
					floor := rtt + ct1FlightAllowance(1360)
					for i := 0; i < ct1Runs(); i++ {
						r := ct1Run(t, ct1Opts{rtt: rtt, size: 1360, dual: dual, seed: 5600 + i, prior: mode.prior(rtt),
							dropCli: ct1DropFirstWhere(func(d ct1Dgram) bool { return d.kind == ct1Initiation }),
							dropGw:  ct1DropFirstWhere(func(d ct1Dgram) bool { return d.kind == ct1PQCT })})
						if r.failed != nil {
							t.Fatalf("run %d: %v", i, r.failed)
						}
						sup, ok := ct1FirstSuperseding(r)
						if !ok || r.superseded != 1 || r.hsAttempts != 3 {
							t.Fatalf("run %d: %d supersessions, %d attempts; want 1 and 3", i, r.superseded, r.hsAttempts)
						}
						if off := sup.at - r.sessionAt - floor; off <= 0 || off > base {
							t.Fatalf("run %d: the supersession drew %v over its floor, want within (0, %v] (window(0))", i, off, base)
						}
					}
				})
			}
		}
	}
}

// --- T21: per-datagram reordering with dual auth ---------------------------------

// TestCT1ReorderedFlightCarries is T21's matrix, with its clause as Amendment 5
// A5.3 consolidated it: dual auth on, every gateway datagram delayed by a
// uniform draw on [0, j) (reordering with no loss), j 5, 20, 50 and 100 ms,
// RTT 30, 100 and 300 ms, both prior modes, both plan floors, 40 seeded runs.
//
//  1. Every run: no fail closed, carrying with a verified attestation, every
//     gateway transmission an answer, HoldRefused 0; no supersession at j <=
//     50 ms (and pqct-after-its-flight at zero generations, in
//     TestCT1ReorderingRecovers).
//  2. At 100 ms at most one supersession.
//     3'. Every pre-session fire is the response-jitter race and nothing else
//     (ct1PreSessionFiresAreTheRace); a run with no supersession then has
//     HandshakeAttempts == 1 + p and Unopenable == the responses delivered
//     minus the one that opened.
//     4'. A run with one supersession shows the inherent deadline tail and
//     nothing else (ct1OnlyTheDeadlineTail).
//  5. Per-cell counts are measurements.
//
// On D5 the 5 ms cells fail closed 9/40.
func TestCT1ReorderedFlightCarries(t *testing.T) {
	for _, mode := range ct1Modes {
		for _, size := range ct1Sizes {
			for _, rtt := range []time.Duration{30 * time.Millisecond, 100 * time.Millisecond, 300 * time.Millisecond} {
				for _, j := range []time.Duration{5 * time.Millisecond, 20 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond} {
					t.Run(fmt.Sprintf("%s/size=%d/rtt=%v/jitter=%v", mode.name, size, rtt, j), func(t *testing.T) {
						supDual, supPlain, pTotal, pRuns, both, staleHeld := 0, 0, 0, 0, 0, 0
						var holdOpened uint64
						for i := 0; i < ct1Runs(); i++ {
							r := ct1Run(t, ct1Opts{rtt: rtt, size: size, dual: true, seed: 7000 + i, prior: mode.prior(rtt), delayGw: ct1Jitter(j, i)})
							if r.failed != nil {
								t.Fatalf("run %d: %v (superseded %d)", i, r.failed, r.superseded)
							}
							if !r.dualVerified {
								t.Fatalf("run %d: carrying without a verified attestation", i)
							}
							ct1GatewayAnswersOnly(t, i, r)
							st := r.cli.Stats()
							if refused := ct1StatOr0(st, "HoldRefused"); refused != 0 {
								t.Fatalf("run %d: the hold refused %d honest datagram(s)", i, refused)
							}
							holdOpened += ct1StatOr0(st, "HoldOpened")
							p := ct1PreSessionFiresAreTheRace(t, i, r, mode.floor(rtt), rtt, j, mode.measured)
							pTotal += p
							if p > 0 {
								pRuns++
							}
							for _, rv := range r.cliRecvs {
								if rv.held && r.gwSends[rv.gwIdx].kind == ct1Response {
									staleHeld++
								}
							}
							switch {
							case r.superseded == 0:
								if want := ct1ResponsesDelivered(r) - 1; r.hsAttempts != uint64(1+p) || st.Unopenable != want {
									t.Fatalf("run %d: no supersession, %d pre-session fire(s): %d handshake attempts and %d unopenable; want %d and %d", i, p, r.hsAttempts, st.Unopenable, 1+p, want)
								}
							case j <= 50*time.Millisecond:
								t.Fatalf("run %d: reordering within %v superseded %d generation(s)", i, j, r.superseded)
							case r.superseded > 1:
								t.Fatalf("run %d: %v jitter superseded %d generations, want at most 1", i, j, r.superseded)
							default:
								supDual++
								if p > 0 {
									both++
									t.Logf("run %d: %d pre-session fire(s) and one supersession; 3' and 4' asserted", i, p)
								}
								ct1OnlyTheDeadlineTail(t, i, r, p)
							}
							if j > 50*time.Millisecond {
								rp := ct1Run(t, ct1Opts{rtt: rtt, size: size, seed: 7000 + i, prior: mode.prior(rtt), delayGw: ct1Jitter(j, i)})
								if rp.failed != nil {
									t.Fatalf("run %d without dual auth: %v", i, rp.failed)
								}
								if rp.superseded > 0 {
									supPlain++
								}
							}
						}
						// Measurements only (A5.3 item 5); every bound is asserted above.
						expect := float64(0)
						if mode.measured {
							expect = float64(j) / float64(2*ct1Window(0)) * float64(ct1Runs())
						}
						t.Logf("T21 cell: pre-session fires %d in %d/%d runs (first-fire rate expected about %.1f runs), superseded %d/%d with dual auth, %d/%d without (j > 50 ms only), both %d, HoldOpened %d, stale responses held %d",
							pTotal, pRuns, ct1Runs(), expect, supDual, ct1Runs(), supPlain, ct1Runs(), both, holdOpened, staleHeld)
					})
				}
			}
		}
	}
}

// ct1ResponsesDelivered counts the gateway's handshake responses the client
// received within the run.
func ct1ResponsesDelivered(r ct1Result) uint64 {
	n := uint64(0)
	for _, s := range r.gwSends {
		if s.kind == ct1Response && s.deliveredAt >= 0 {
			n++
		}
	}
	return n
}

// ct1PreSessionFiresAreTheRace is A5.3 item 3' (i) to (iii) for one run, and
// returns p, its pre-session fires. (i) The k-th landed no earlier than
// t_(k-1) + ct1KarnFloor(b, k-1), t_0 the first send. (ii) It landed before
// the client received the response to the initiation it replaced (that
// response is the gateway's generation k), or that response never arrived
// within the run. (iii) p is at most N(r, j), the k >= 0 with
// ct1KarnFloor(b, k) < r + j; zero in FIRST-CONTACT.
func ct1PreSessionFiresAreTheRace(t *testing.T, run int, r ct1Result, b, rtt, j time.Duration, measured bool) int {
	t.Helper()
	p := ct1PreSessionFires(r)
	n := 0
	for k, attempts := 0, (Retry{}).orDefault().Attempts; k < attempts && ct1KarnFloor(b, k) < rtt+j; k++ {
		n++
	}
	if p > n || (!measured && p != 0) {
		t.Fatalf("run %d: %d pre-session fire(s), want at most N(%v, %v) = %d (zero at first contact)", run, p, rtt, j, n)
	}
	prev := r.firstSendAt
	for k := 1; k <= p; k++ {
		f := r.fires[k-1]
		if floor := prev + ct1KarnFloor(b, k-1); f.at < floor {
			t.Fatalf("run %d: (i) pre-session fire %d at %v, before its Karn floor %v", run, k, f.at, floor)
		}
		for _, s := range r.gwSends {
			if s.kind == ct1Response && s.gen == k && s.deliveredAt >= 0 && f.at >= s.deliveredAt {
				t.Fatalf("run %d: (ii) pre-session fire %d at %v, after the response it replaced arrived at %v", run, k, f.at, s.deliveredAt)
			}
		}
		prev = f.at
	}
	return p
}

// ct1OnlyTheDeadlineTail is A5.3 item 4': a run that superseded exactly one
// generation under per-datagram jitter, after p pre-session fires, shows the
// inherent cause and nothing else. (a) The superseding fire was drawn at
// window index 0 and landed no earlier than sessionAt + (sessionAt - t_p) +
// allowance, the N-2 floor on the answered generation's measured round trip
// (t_p the last pre-session fire, or the first send when p == 0). (b) At
// least one of the superseded generation's flight datagrams (its PQ_CT or its
// attestation, sent before the fire) reached the client at or after the fire
// or never. (c') Unopenable == S + L + H: S the stale responses of replaced
// initiations delivered within the run, L that generation's flight datagrams
// delivered at or after the fire, H its attestation datagrams delivered
// before the fire if and only if its PQ_CT was delivered at or after the fire
// or never. (d') HandshakeAttempts == 2 + p and the last generation carried
// with no further supersession.
func ct1OnlyTheDeadlineTail(t *testing.T, run int, r ct1Result, p int) {
	t.Helper()
	sup, ok := ct1FirstSuperseding(r)
	if !ok || r.superseded != 1 || r.hsAttempts != uint64(2+p) || r.failed != nil {
		t.Fatalf("run %d: (d') %d supersessions, %d attempts, failed %v; want 1, %d, carrying", run, r.superseded, r.hsAttempts, r.failed, 2+p)
	}
	tp := r.firstSendAt
	if p > 0 {
		tp = r.fires[p-1].at
	}
	if floor := r.sessionAt + (r.sessionAt - tp) + ct1FlightAllowance(r.size); sup.drawIndex != 0 || sup.at < floor {
		t.Fatalf("run %d: (a) the superseding fire at %v drawn at window index %d, want index 0 and no earlier than the N-2 floor %v", run, sup.at, sup.drawIndex, floor)
	}
	gen := p + 1
	stale, late, lateDelivered, heldBefore, pqctLate := uint64(0), 0, uint64(0), uint64(0), false
	for _, s := range r.gwSends {
		if s.kind == ct1Response {
			if s.gen <= p && s.deliveredAt >= 0 {
				stale++
			}
			continue
		}
		if s.gen != gen || s.at >= sup.at {
			continue
		}
		after := s.deliveredAt < 0 || s.deliveredAt >= sup.at
		if after {
			late++
			if s.pos == 1 {
				pqctLate = true
			}
		}
		if s.deliveredAt >= sup.at {
			lateDelivered++
		}
		if !after && s.pos >= 2 {
			heldBefore++
		}
	}
	if late == 0 {
		t.Fatalf("run %d: (b) every flight datagram of generation %d arrived before the fire at %v: the flight was complete when it superseded", run, gen, sup.at)
	}
	want := stale + lateDelivered
	if pqctLate {
		want += heldBefore
	}
	if u := r.cli.Stats().Unopenable; u != want {
		t.Fatalf("run %d: (c') Unopenable %d, want S %d + L %d + H %d = %d (PQ_CT late %v)", run, u, stale, lateDelivered, map[bool]uint64{true: heldBefore}[pqctLate], want, pqctLate)
	}
}

// --- T22: connectBy binds every delivery path (N-4) -----------------------------

// TestCT1ConnectByBindsADelivery is T22. The datagram that would complete the
// connect (the last ML-DSA-65 chunk with dual auth, the PQ_CT without) is held
// back and delivered, with no Poll in between, one tick before connectBy, at
// it and one tick after it, through the scalar and the batch path. Before: the
// connect establishes. At and after: nothing in the message is processed, the
// connect closes with the reason of the phase it ran out in exactly as
// tickInitiating would, the attestation is not verified, and a later DATA
// message is not admitted. On D5 the at and after cells establish.
func TestCT1ConnectByBindsADelivery(t *testing.T) {
	for _, dual := range []bool{true, false} {
		for _, path := range ct1Paths {
			for _, c := range []struct {
				name   string
				off    time.Duration
				before bool
			}{{"one-tick-before", -time.Nanosecond, true}, {"at", 0, false}, {"one-tick-after", time.Nanosecond, false}} {
				t.Run(fmt.Sprintf("dual=%v/%s/%s", dual, path, c.name), func(t *testing.T) {
					p, _, _ := ct1DualPair(t, 1360, dual)
					var flight [][]byte
					p.filterToCli = func(idx int, m []byte) bool {
						if idx == 0 {
							return true
						}
						flight = append(flight, append([]byte(nil), m...))
						return false
					}
					p.run()
					p.filterToCli = nil
					if p.cli.sess == nil || len(flight) == 0 || p.cli.State() != StateInitiating {
						t.Fatalf("fixture: session %v, %d flight datagram(s), %s", p.cli.sess != nil, len(flight), p.cli.State())
					}
					for _, m := range flight[:len(flight)-1] {
						if _, err := p.cli.Deliver(m); err != nil {
							t.Fatal(err)
						}
					}
					if p.cli.State() != StateInitiating {
						t.Fatalf("fixture: %s before the last datagram", p.cli.State())
					}
					connectBy := p.cli.connectBy
					p.clk.Advance(connectBy.Add(c.off).Sub(p.clk.Now()))
					recv := p.cli.Stats().MessagesReceived
					pkts := ct1DeliverVia(t, p.cli, path, flight[len(flight)-1])
					if c.before {
						if p.cli.State() != StateEstablished || p.cli.Err() != nil || (dual && !p.cli.DualAuthVerified()) {
							t.Fatalf("one tick before connectBy: %s err %v verified %v", p.cli.State(), p.cli.Err(), p.cli.DualAuthVerified())
						}
						return
					}
					st := p.cli.State()
					if st == StateEstablished || p.cli.DualAuthVerified() || (st != StateClosing && !st.Terminal()) {
						t.Fatalf("a completion at connectBy%+v: state %s verified %v", c.off, st, p.cli.DualAuthVerified())
					}
					want := ClosePQFailed
					if dual {
						want = CloseDualAuthFailed
					}
					if got := p.cli.LocalCloseReason(); got != want {
						t.Fatalf("close reason %s, want %s (the phase it ran out in)", got, want)
					}
					if got := p.cli.Stats().MessagesReceived; got != recv || len(pkts) != 0 {
						t.Fatalf("the message delivered at connectBy%+v was processed (%d opened, %d packets)", c.off, got-recv, len(pkts))
					}
					if pkts := ct1DeliverVia(t, p.cli, path, ct1Seal(t, p.gw.sess, ct1DataFrame())); len(pkts) != 0 {
						t.Fatal("DATA was admitted after connectBy closed the connect")
					}
					if n := ct1PollAll(t, p.cli); n > 1 || !p.cli.State().Terminal() {
						t.Fatalf("after the close: %d message(s), state %s; want at most the CLOSE, then terminal", n, p.cli.State())
					}
				})
			}
		}
	}
}

// --- T23: a closing session never re-establishes (N-5) -----------------------------

// TestCT1ClosingSessionNeverReestablishes is T23.
//
//   - dual-auth: the correct Ed25519 frame and an ML-DSA-65 half over another
//     transcript fail verification and the client begins to close; before the
//     CLOSE flushes, the correct ML-DSA-65 chunks arrive under fresh counters,
//     then a DATA message. StateClosing persists, nothing is admitted, the
//     attestation stays unverified, the recorded cause and reason stand, and
//     the CLOSE then flushes.
//   - rekey: a client that has begun to close while its own rekey is in
//     flight receives the gateway's REKEY_ACK and then DATA under the new
//     epoch. establish refuses outside Initiating and Rekeying, so it stays
//     closing and admits nothing.
//
// Scalar and batch. On D5 both re-establish and admit the DATA.
func TestCT1ClosingSessionNeverReestablishes(t *testing.T) {
	for _, path := range ct1Paths {
		t.Run("dual-auth/"+path, func(t *testing.T) {
			p, edPriv, mlSeed := ct1DualPair(t, 1360, true)
			p.filterToCli = func(idx int, _ []byte) bool { return idx < 2 }
			p.run()
			p.filterToCli = nil
			if p.cli.State() != StateInitiating || p.cli.sess == nil || !p.cli.sess.PQRatcheted() || p.cli.dualDone {
				t.Fatalf("fixture: %s", p.cli.State())
			}
			h := p.cli.sess.TranscriptHash()
			other := sha256.Sum256([]byte("a different transcript"))
			goodED, goodML := ct1Attest(t, edPriv, mlSeed, h[:], p.gw.cfg.maxPayload())
			_, badML := ct1Attest(t, edPriv, mlSeed, other[:], p.gw.cfg.maxPayload())
			first := [][]byte{ct1Seal(t, p.gw.sess, goodED)}
			for _, f := range badML {
				first = append(first, ct1Seal(t, p.gw.sess, f))
			}
			ct1DeliverVia(t, p.cli, path, first...)
			if p.cli.State() != StateClosing || !errors.Is(p.cli.Err(), ErrDualAuthFailed) {
				t.Fatalf("fixture: a wrong ML-DSA-65 half left %s err %v", p.cli.State(), p.cli.Err())
			}
			var late [][]byte
			for _, f := range goodML {
				late = append(late, ct1Seal(t, p.gw.sess, f))
			}
			late = append(late, ct1Seal(t, p.gw.sess, ct1DataFrame()))
			if pkts := ct1DeliverVia(t, p.cli, path, late...); len(pkts) != 0 {
				t.Fatal("a closing session admitted DATA")
			}
			if p.cli.State() != StateClosing || p.cli.DualAuthVerified() {
				t.Fatalf("the correct half after a failed verification: %s verified %v", p.cli.State(), p.cli.DualAuthVerified())
			}
			if !errors.Is(p.cli.Err(), ErrDualAuthFailed) || p.cli.LocalCloseReason() != CloseDualAuthFailed {
				t.Fatalf("the recorded failure was overwritten: %v %s", p.cli.Err(), p.cli.LocalCloseReason())
			}
			if n := ct1PollAll(t, p.cli); n != 1 || p.cli.State() != StateFailed {
				t.Fatalf("the CLOSE: %d message(s), state %s; want 1 and failed", n, p.cli.State())
			}
		})
		t.Run("rekey/"+path, func(t *testing.T) {
			p, _, _ := ct1DualPair(t, 1360, false)
			p.establish()
			p.cli.mu.Lock()
			err := p.cli.startRekey(p.clk.Now())
			p.cli.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			ri, err := p.cli.Poll()
			if err != nil || ri == nil {
				t.Fatalf("no REKEY_INIT: %v", err)
			}
			if _, err := p.gw.Deliver(ri); err != nil {
				t.Fatal(err)
			}
			ack := ct1GwDrain(t, p.gw)
			if len(ack) != 1 || p.gw.Epoch() != p.cli.Epoch()+1 {
				t.Fatalf("fixture: %d message(s), epochs %d/%d", len(ack), p.gw.Epoch(), p.cli.Epoch())
			}
			if err := p.cli.Close(); err != nil || p.cli.State() != StateClosing {
				t.Fatalf("fixture: Close left %s (%v)", p.cli.State(), err)
			}
			ct1DeliverVia(t, p.cli, path, ack[0])
			if p.cli.State() != StateClosing {
				t.Fatalf("a REKEY_ACK moved a closing session to %s", p.cli.State())
			}
			if pkts := ct1DeliverVia(t, p.cli, path, ct1Seal(t, p.gw.sess, ct1DataFrame())); len(pkts) != 0 {
				t.Fatal("a closing session admitted DATA after a rekey")
			}
			if n := ct1PollAll(t, p.cli); n != 1 || p.cli.State() != StateClosed || p.cli.LocalCloseReason() != CloseNormal {
				t.Fatalf("the CLOSE: %d message(s), state %s reason %s", n, p.cli.State(), p.cli.LocalCloseReason())
			}
		})
	}
}

// --- T24: an attestation before the PQ ratchet is refused (N-6) ------------------

// ct1EpochZeroAttestation is a dual-auth pair whose client holds a session
// with its PQ ciphertext outstanding (the gateway never got the PQ_EK, so it
// is still on epoch 0), and a test-only attestation that signs the epoch-0
// transcript, sealed under epoch 0, with a DATA message behind it.
func ct1EpochZeroAttestation(t *testing.T) (*pair, []byte, []core.Frame, [][]byte) {
	t.Helper()
	p, edPriv, mlSeed := ct1DualPair(t, 1360, true)
	p.filterToGw = func(idx int, _ []byte) bool { return idx == 0 }
	p.run()
	p.filterToGw = nil
	if p.cli.sess == nil || p.cli.pqEph == nil || p.cli.sess.PQRatcheted() || p.gw.Epoch() != 0 {
		t.Fatal("fixture: the client should hold an epoch-0 session with its PQ ciphertext outstanding")
	}
	h := p.gw.sess.TranscriptHash()
	if h != p.cli.sess.TranscriptHash() {
		t.Fatal("fixture: transcripts differ")
	}
	ed, ml := ct1Attest(t, edPriv, mlSeed, h[:], p.gw.cfg.maxPayload())
	msgs := [][]byte{ct1Seal(t, p.gw.sess, ed)}
	for _, f := range ml {
		msgs = append(msgs, ct1Seal(t, p.gw.sess, f))
	}
	msgs = append(msgs, ct1Seal(t, p.gw.sess, ct1DataFrame()))
	return p, ed.Value, ml, msgs
}

// TestCT1AttestationBeforeTheRatchetIsRefused is T24: a test-only responder
// signs the epoch-0 transcript and sends a valid attestation, sealed under
// epoch 0, before any PQ_CT. The client refuses it with ErrProtocol and
// closes: it never establishes, admits no DATA, never reports the attestation
// verified, and transmits nothing but the CLOSE. Scalar and batch. The first
// such frame closes the session, whichever half it is; verifyDualAuth also
// asserts the ratchet. On D5 the client establishes at epoch 0 and admits the
// DATA.
func TestCT1AttestationBeforeTheRatchetIsRefused(t *testing.T) {
	for _, path := range ct1Paths {
		t.Run(path, func(t *testing.T) {
			p, _, _, msgs := ct1EpochZeroAttestation(t)
			sent := p.cli.Stats().MessagesSent
			var pkts [][]byte
			for _, m := range msgs {
				pkts = append(pkts, ct1DeliverVia(t, p.cli, path, m)...)
				if p.cli.State() == StateEstablished {
					t.Fatal("an epoch-0 attestation established the client")
				}
			}
			if len(pkts) != 0 || p.cli.DualAuthVerified() {
				t.Fatalf("%d packet(s) admitted, verified %v", len(pkts), p.cli.DualAuthVerified())
			}
			if !errors.Is(p.cli.Err(), ErrProtocol) {
				t.Fatalf("err %v, want ErrProtocol", p.cli.Err())
			}
			if n := ct1PollAll(t, p.cli); n > 1 || p.cli.Stats().MessagesSent-sent > 1 || !p.cli.State().Terminal() {
				t.Fatalf("after the refusal: %d message(s) polled, %d sent, state %s; want at most the CLOSE", n, p.cli.Stats().MessagesSent-sent, p.cli.State())
			}
		})
	}
	// Each DUAL_AUTH frame is refused on its own, in either order: the first
	// one that opens under epoch 0 closes the session.
	for _, first := range []string{"ed25519", "mldsa65"} {
		t.Run("closes-at-the-first-frame/"+first, func(t *testing.T) {
			p, _, _, msgs := ct1EpochZeroAttestation(t)
			m := msgs[0]
			if first == "mldsa65" {
				m = msgs[1]
			}
			p.cli.Deliver(m)
			if st := p.cli.State(); (st != StateClosing && !st.Terminal()) || !errors.Is(p.cli.Err(), ErrProtocol) {
				t.Fatalf("one epoch-0 %s frame left the client %s, err %v; want closing with ErrProtocol", first, st, p.cli.Err())
			}
		})
	}
	// verifyDualAuth asserts the ratchet itself, so no other caller can reach
	// establish on an epoch-0 session either.
	t.Run("verify-asserts-the-ratchet", func(t *testing.T) {
		p, ed, ml, _ := ct1EpochZeroAttestation(t)
		var mlSig []byte
		for _, f := range ml {
			mlSig = append(mlSig, f.Value[chunkOffsetSize:]...)
		}
		p.cli.mu.Lock()
		p.cli.dualEDSig = append([]byte(nil), ed...)
		err := p.cli.verifyDualAuth(mlSig)
		st, done := p.cli.state, p.cli.dualDone
		p.cli.mu.Unlock()
		if !errors.Is(err, ErrProtocol) || st != StateInitiating || done {
			t.Fatalf("verifyDualAuth on an epoch-0 session: err %v, state %s, done %v; want ErrProtocol, initiating, false", err, st, done)
		}
	})
}

// --- T10, real gateway timers (N-7) -----------------------------------------------

// ct1GatewayHandshakeAnswersOnly is T10 as Amendment 3 restated it (N-7) for
// a run whose gateway keeps its production timers. Handshake material (a
// response, a PQ_CT, anything that moved the gateway's handshake or PQ
// counters) leaves only as an answer: at the instant a client message that
// authenticated or opened reached the gateway. Every other gateway
// transmission is classified by the gateway's own counters and state: a
// liveness probe or keepalive (PingsSent moved), or the liveness detector's
// one verdict CLOSE after its drawn probes went unanswered (the gateway's
// local reason became CloseDesynchronised in that Poll, and it is the
// gateway's last transmission); either on a generation the client had
// abandoned (a later initiation or a closed client), and never a
// byte-identical copy of anything the gateway sent before. It returns how
// many probes or keepalives and how many verdict CLOSEs the run had.
func ct1GatewayHandshakeAnswersOnly(t *testing.T, run int, r ct1Result) (probes, closes int) {
	t.Helper()
	openedAt := map[time.Duration]bool{}
	for _, rv := range r.gwRecvs {
		if rv.opened {
			openedAt[rv.at] = true
		}
	}
	var before [][]byte
	for n, s := range r.gwSends {
		for _, q := range before {
			if bytes.Equal(q, s.msg) {
				t.Fatalf("run %d: gateway datagram %d at %v repeats an earlier one byte for byte", run, s.idx, s.at)
			}
		}
		before = append(before, s.msg)
		if openedAt[s.at] {
			continue
		}
		if s.kind == ct1Response || s.kind == ct1PQCT || s.hsDelta != 0 || s.pqDelta != 0 {
			t.Fatalf("run %d: handshake material (gateway datagram %d, kind %d) at %v answers no client message", run, s.idx, s.kind, s.at)
		}
		if !s.cliDone && s.cliAttempts <= uint64(s.gen) {
			t.Fatalf("run %d: a timer-driven gateway datagram at %v on generation %d, which the client has not abandoned (%d attempts)", run, s.at, s.gen, s.cliAttempts)
		}
		switch {
		case s.pingDelta > 0:
			probes++
		case s.gwReason == CloseDesynchronised && n == len(r.gwSends)-1 && r.gw.State().Terminal():
			closes++
		default:
			t.Fatalf("run %d: gateway datagram %d at %v answers nothing and is neither a probe, a keepalive nor the liveness verdict CLOSE (reason %s)", run, s.idx, s.at, s.gwReason)
		}
	}
	return probes, closes
}

// TestCT1GatewayTimersAnswerOnlyInTheHandshake is the T10 variant with the
// gateway's real liveness timers armed (A3.3 N-7): the T2 single losses
// (every gateway handshake datagram, dual auth, and the PQ_CT without) and the
// T7 exhaustion scripts, run on to 30 s after the client closes. The
// handshake-phase property holds in every run, and every later gateway
// transmission is a drawn liveness probe or keepalive on an abandoned
// generation. The variant is not vacuous: the exhaustion runs must show such
// transmissions.
func TestCT1GatewayTimersAnswerOnlyInTheHandshake(t *testing.T) {
	type script struct {
		name     string
		dual     bool
		terminal bool
		drop     func() func(ct1Dgram) bool
	}
	var scripts []script
	for k := 1; k < ct1GatewayHandshakeDatagrams(true); k++ {
		scripts = append(scripts, script{fmt.Sprintf("gw=%d", k), true, false, func() func(ct1Dgram) bool { return ct1DropFirst(k) }})
	}
	scripts = append(scripts,
		script{"gw=1/no-dual", false, false, func() func(ct1Dgram) bool { return ct1DropFirst(1) }},
		script{"every-ml", true, true, func() func(ct1Dgram) bool { return func(d ct1Dgram) bool { return d.pos >= 3 } }},
		script{"every-pqct", true, true, func() func(ct1Dgram) bool { return func(d ct1Dgram) bool { return d.kind == ct1PQCT } }},
		script{"every-pqct/no-dual", false, true, func() func(ct1Dgram) bool { return func(d ct1Dgram) bool { return d.kind == ct1PQCT } }},
		script{"every-response", true, true, func() func(ct1Dgram) bool { return func(d ct1Dgram) bool { return d.kind == ct1Response } }},
	)
	probesTotal, closesTotal := 0, 0
	for _, mode := range ct1Modes {
		for _, rtt := range []time.Duration{30 * time.Millisecond, 300 * time.Millisecond, 600 * time.Millisecond} {
			for _, sc := range scripts {
				t.Run(fmt.Sprintf("%s/rtt=%v/%s", mode.name, rtt, sc.name), func(t *testing.T) {
					for i := 0; i < ct1Runs(); i++ {
						o := ct1Opts{rtt: rtt, size: 1360, dual: sc.dual, seed: 5700 + i, prior: mode.prior(rtt), gwTimers: true, dropGw: sc.drop()}
						if sc.terminal {
							o.untilTerminal, o.tail, o.horizon = true, 30*time.Second, 90*time.Second
						}
						r := ct1Run(t, o)
						if !sc.terminal && r.failed != nil {
							t.Fatalf("run %d: %v", i, r.failed)
						}
						if sc.terminal && (!r.cliState.Terminal() || r.carrying != 0) {
							t.Fatalf("run %d: client %s carrying %v; want a closed connect", i, r.cliState, r.carrying)
						}
						p, c := ct1GatewayHandshakeAnswersOnly(t, i, r)
						probesTotal += p
						closesTotal += c
					}
				})
			}
		}
	}
	if probesTotal == 0 {
		t.Fatal("no gateway timer fired in any run: the variant did not exercise the real timers")
	}
	// Measurement only: the counts of timer-driven transmissions classified.
	t.Logf("timer-driven gateway transmissions classified: %d probes or keepalives, %d liveness verdict CLOSEs", probesTotal, closesTotal)
}

// --- Claude N-4: the surviving D5 mutants --------------------------------------------

// TestSeatCD5AnsweredThenDarkAfterTheRatchet (Seat C, D5 review; kills K3 and
// K7): the first generation's response and PQ_CT arrive, so the ratchet
// completes; its attestation and every later gateway datagram are lost. The
// connect must close dual-auth-failed with no carrier change.
func TestSeatCD5AnsweredThenDarkAfterTheRatchet(t *testing.T) {
	for _, mode := range ct1Modes {
		for _, rtt := range []time.Duration{30 * time.Millisecond, 300 * time.Millisecond} {
			t.Run(fmt.Sprintf("%s/rtt=%v", mode.name, rtt), func(t *testing.T) {
				for i := 0; i < ct1Runs(); i++ {
					gen := 0
					r := ct1Run(t, ct1Opts{rtt: rtt, size: 1360, dual: true, seed: 5100 + i, prior: mode.prior(rtt), untilTerminal: true,
						dropGw: func(d ct1Dgram) bool {
							if gen == 0 && d.kind == ct1Response {
								gen = d.gen
							}
							return !(d.gen == gen && d.pos <= 1)
						}})
					if r.superseded == 0 {
						t.Fatalf("run %d: fixture: no supersession", i)
					}
					if r.cliReason != CloseDualAuthFailed || r.needCarrier || !errors.Is(r.cli.Err(), ErrDualAuthFailed) {
						t.Fatalf("run %d: reason %s carrier %v err %v; want %s, false, ErrDualAuthFailed", i, r.cliReason, r.needCarrier, r.cli.Err(), CloseDualAuthFailed)
					}
				}
			})
		}
	}
}

// TestCT1ProgressNeverPullsTheFireEarlier pins N-2's "never moves the deadline
// earlier" (K2). A mid-flight ML-DSA-65 chunk of the first flight is lost.
// From the response to the supersession fire, the client's NextDeadline after
// every delivered datagram never decreases, the fire is no earlier than the
// deadline armed when the response opened (PQ_EK sent + hsRTT + allowance +
// its draw), and in particular no earlier than PQ_EK sent + hsRTT + allowance.
func TestCT1ProgressNeverPullsTheFireEarlier(t *testing.T) {
	for _, mode := range ct1Modes {
		for _, size := range ct1Sizes {
			for _, rtt := range []time.Duration{30 * time.Millisecond, 300 * time.Millisecond} {
				t.Run(fmt.Sprintf("%s/size=%d/rtt=%v", mode.name, size, rtt), func(t *testing.T) {
					for i := 0; i < ct1Runs(); i++ {
						r := ct1Run(t, ct1Opts{rtt: rtt, size: size, dual: true, seed: 5200 + i, prior: mode.prior(rtt),
							dropGw: ct1FirstPQFlight(func(d ct1Dgram) bool { return d.pos == 4 })})
						if r.failed != nil {
							t.Fatalf("run %d: %v", i, r.failed)
						}
						sup, ok := ct1FirstSuperseding(r)
						if !ok {
							t.Fatalf("run %d: fixture: no supersession", i)
						}
						ekSent := time.Duration(-1)
						for _, s := range r.cliSends {
							if s.kind == ct1PQEK {
								ekSent = s.at
								break
							}
						}
						if floor := ekSent + rtt + ct1FlightAllowance(size); ekSent < 0 || sup.at < floor {
							t.Fatalf("run %d: supersession at %v, before PQ_EK sent (%v) + hsRTT + allowance = %v", i, sup.at, ekSent, floor)
						}
						armed, prev := time.Duration(-1), time.Duration(-1)
						for _, rv := range r.cliRecvs {
							if rv.at < r.sessionAt || rv.at >= sup.at {
								continue
							}
							if armed < 0 {
								armed = rv.deadline
							}
							if rv.deadline < prev {
								t.Fatalf("run %d: a datagram at %v moved the next fire earlier, %v to %v", i, rv.at, prev, rv.deadline)
							}
							prev = rv.deadline
						}
						if armed < 0 || sup.at < armed {
							t.Fatalf("run %d: supersession at %v, before the deadline %v armed when the response opened", i, sup.at, armed)
						}
					}
				})
			}
		}
	}
}

// TestCT1ProgressRearmIsDrawn pins N-2's draw on the progress re-arm (K1). On
// a 256 kbit/s downlink (each flight datagram delayed by its position times
// one 1360-byte serialization, 42.5 ms) the last ML-DSA-65 chunk of the first
// flight is lost. The supersession fire is strictly more than one allowance
// after the last authenticated datagram (the draw is on an open interval, so
// no fire sits at a fixed offset from a received datagram), and over 40 seeds
// the offsets are not all equal.
func TestCT1ProgressRearmIsDrawn(t *testing.T) {
	rtt := 100 * time.Millisecond
	a := ct1FlightAllowance(1360)
	for _, mode := range ct1Modes {
		t.Run(mode.name, func(t *testing.T) {
			seen := map[time.Duration]bool{}
			for i := 0; i < ct1Runs(); i++ {
				r := ct1Run(t, ct1Opts{rtt: rtt, size: 1360, dual: true, seed: 5300 + i, prior: mode.prior(rtt),
					delayGw: func(d ct1Dgram) time.Duration {
						if d.pos > 0 {
							return time.Duration(d.pos) * a
						}
						return 0
					},
					dropGw: ct1FirstPQFlight(func(d ct1Dgram) bool { return d.pos == 5 })})
				if r.failed != nil {
					t.Fatalf("run %d: %v", i, r.failed)
				}
				sup, ok := ct1FirstSuperseding(r)
				if !ok {
					t.Fatalf("run %d: fixture: no supersession", i)
				}
				last := time.Duration(-1)
				for _, rv := range r.cliRecvs {
					if rv.opened && rv.at >= r.sessionAt && rv.at < sup.at {
						last = rv.at
					}
				}
				off := sup.at - last
				if last < 0 || off <= a {
					t.Fatalf("run %d: the fire %v after the last authenticated datagram, want more than one allowance (%v)", i, off, a)
				}
				seen[off] = true
			}
			if len(seen) < 2 {
				t.Fatalf("every fire sat at the same offset from the last datagram: %v", seen)
			}
		})
	}
}

// TestCT1ProgressRearmIsCappedAtConnectBy pins N-2's connectBy cap on the
// progress re-arm (K10). With dual auth, the PQ_CT arrives half an allowance
// before connectBy (no Poll in between), so its progress re-arm would land
// past it. The client's NextDeadline is connectBy, and a host that waits on
// NextDeadline sees the connect close at connectBy, dual-auth-failed.
func TestCT1ProgressRearmIsCappedAtConnectBy(t *testing.T) {
	for _, size := range ct1Sizes {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			for i := 0; i < 8; i++ {
				p, _, _ := ct1DualPair(t, size, true)
				var flight [][]byte
				p.filterToCli = func(idx int, m []byte) bool {
					if idx == 0 {
						return true
					}
					flight = append(flight, append([]byte(nil), m...))
					return false
				}
				p.run()
				p.filterToCli = nil
				connectBy := p.cli.connectBy
				p.clk.Advance(connectBy.Add(-ct1FlightAllowance(size) / 2).Sub(p.clk.Now()))
				if _, err := p.cli.Deliver(flight[0]); err != nil || !p.cli.sess.PQRatcheted() {
					t.Fatalf("fixture: the PQ_CT did not ratchet: %v", err)
				}
				if dl := p.cli.NextDeadline(); !dl.Equal(connectBy) {
					t.Fatalf("NextDeadline %v after a progress datagram, want connectBy %v", dl, connectBy)
				}
				p.clk.Advance(p.cli.NextDeadline().Sub(p.clk.Now()))
				ct1PollAll(t, p.cli)
				if !p.clk.Now().Equal(connectBy) || p.cli.LocalCloseReason() != CloseDualAuthFailed {
					t.Fatalf("closed at %v with %s, want connectBy %v and %s", p.clk.Now(), p.cli.LocalCloseReason(), connectBy, CloseDualAuthFailed)
				}
			}
		})
	}
}
