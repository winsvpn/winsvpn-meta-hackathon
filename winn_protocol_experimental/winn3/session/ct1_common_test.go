package session

// CT-1 tests (Amendment 1, A1.5) that build on the release tree's API: T1, T4,
// T5, T6, T12, the T10 guard inside every recovery run, and the acceptance set
// Sol's CT4 Turn 1 review asked for (burst loss, duplication, reordering, wrong
// signatures, cross-generation datagrams, abandoned handshakes) plus the
// FreshAfter 0 pin. The runner and the fail-first tests are in
// ct1_recovery_test.go; T13 needs the D4 API and is in ct1_d4_test.go.

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

func ct1EKChunks(size int) int {
	return len(chunkBlob(core.FramePQEK, make([]byte, core.PQEncapsulationKeySize), size-core.TransportOverhead()-frameHeaderSize))
}

// ct1Cells runs body over the prior mode x dual x size x RTT matrix with the
// cell's healthy carrying mean.
func ct1Cells(t *testing.T, duals []bool, body func(t *testing.T, mode ct1Mode, dual bool, size int, rtt, healthy time.Duration)) {
	for _, mode := range ct1Modes {
		for _, dual := range duals {
			for _, size := range ct1Sizes {
				for _, rtt := range ct1RTTs {
					healthy := ct1Healthy(t, size, rtt, dual, mode.prior(rtt))
					t.Run(fmt.Sprintf("%s/dual=%v/size=%d/rtt=%v", mode.name, dual, size, rtt), func(t *testing.T) {
						body(t, mode, dual, size, rtt, healthy)
					})
				}
			}
		}
	}
}

// ct1Recovers runs one loss script over a cell: every run reaches carrying,
// with a verified attestation under dual auth, every gateway transmission is an
// answer (T10), and exactly n generations are added within their bound. A run
// that fails closed because its ladder was spent is a FAILURE in every cell of
// both modes (Amendment 2 ruling 3; Amendment 3 removed the FIRST-CONTACT 600
// ms exemption), and with a measured prior no ladder fire may precede the
// response.
func ct1Recovers(t *testing.T, mode ct1Mode, dual bool, size int, rtt, healthy time.Duration, n int, mk func() ct1Opts) {
	t.Helper()
	ct1RecoversRange(t, mode, dual, size, rtt, healthy, 0, n, n, mk)
}

// ct1RecoversRange is ct1Recovers for a script whose cost depends on a draw
// (between nMin and nMax generations) and that delays the flight by slack.
func ct1RecoversRange(t *testing.T, mode ct1Mode, dual bool, size int, rtt, healthy, slack time.Duration, nMin, nMax int, mk func() ct1Opts) {
	t.Helper()
	for i := 0; i < ct1Runs(); i++ {
		o := mk()
		o.rtt, o.size, o.dual, o.seed, o.prior = rtt, size, dual, 4000+i, mode.prior(rtt)
		r := ct1Run(t, o)
		if ct1LadderSpent(r, nMax) {
			t.Fatalf("run %d: the ladder was spent before %d loss(es) could be recovered (%d pre-session fires): %v", i, nMax, ct1PreSessionFires(r), r.failed)
		}
		if r.failed != nil {
			t.Fatalf("run %d: %v", i, r.failed)
		}
		if mode.measured {
			if pf := ct1PreSessionFires(r); pf != 0 {
				t.Fatalf("run %d: %d ladder fire(s) before the response with a measured prior", i, pf)
			}
		}
		if dual && !r.dualVerified {
			t.Fatalf("run %d: carrying without a verified attestation", i)
		}
		ct1GatewayAnswersOnly(t, i, r)
		n := int(r.superseded)
		if n < nMin || n > nMax {
			t.Fatalf("run %d: %d generation(s) superseded, want %d to %d", i, n, nMin, nMax)
		}
		ct1GenerationsAdded(t, i, r, n, healthy, rtt, slack)
	}
}

// ct1FirstPQFlight applies match to the gateway datagrams of the first flight
// that carries a PQ_CT (the generation the client is actually using), and to
// nothing else.
func ct1FirstPQFlight(match func(ct1Dgram) bool) func(ct1Dgram) bool {
	gen := 0
	return func(d ct1Dgram) bool {
		if gen == 0 && d.kind == ct1PQCT {
			gen = d.gen
		}
		return gen != 0 && d.gen == gen && match(d)
	}
}

// --- T1 ----------------------------------------------------------------------

// TestCT1LostClientHandshakeDatagramRecovers is T1, re-tiered by Amendments 2
// and 3. A lost initiation is recovered by the first ladder fire, which is a
// fresh initiation (FreshAfter 0): in every cell of both modes, FIRST-CONTACT
// at 600 ms included, every run has HandshakeAttempts == 2, no supersession,
// and carries within healthy + floor + window(0). A lost chunk of the
// client's PQ_EK flight costs one generation.
func TestCT1LostClientHandshakeDatagramRecovers(t *testing.T) {
	ct1Cells(t, []bool{true, false}, func(t *testing.T, mode ct1Mode, dual bool, size int, rtt, healthy time.Duration) {
		t.Run("initiation", func(t *testing.T) {
			for i := 0; i < ct1Runs(); i++ {
				r := ct1Run(t, ct1Opts{rtt: rtt, size: size, dual: dual, seed: 2000 + i, prior: mode.prior(rtt),
					dropCli: ct1DropFirstWhere(func(d ct1Dgram) bool { return d.kind == ct1Initiation })})
				if r.failed != nil {
					t.Fatalf("run %d: %v", i, r.failed)
				}
				ct1GatewayAnswersOnly(t, i, r)
				if r.superseded != 0 {
					t.Fatalf("run %d: a lost initiation superseded a generation", i)
				}
				if r.hsAttempts != 2 {
					t.Fatalf("run %d: %d handshake attempts, want 2 (the original and one fresh initiation)", i, r.hsAttempts)
				}
				if bound := healthy + mode.floor(rtt) + ct1Window(0); r.carrying > bound {
					t.Fatalf("run %d: carrying at %v, past healthy %v + floor + window(0) = %v", i, r.carrying, healthy, bound)
				}
			}
		})
		for k := 1; k <= ct1EKChunks(size); k++ {
			t.Run(fmt.Sprintf("pqek-chunk-%d", k), func(t *testing.T) {
				ct1Recovers(t, mode, dual, size, rtt, healthy, 1, func() ct1Opts {
					return ct1Opts{dropCli: ct1DropFirstWhere(func(d ct1Dgram) bool { return d.kind == ct1PQEK && d.pos == k })}
				})
			})
		}
	})
}

// --- T4 ----------------------------------------------------------------------

// ct1DropThen loses the first datagram matching first, and then the first
// datagram matching second in a LATER gateway generation than that loss.
func ct1DropThen(first, second func(ct1Dgram) bool) func(ct1Dgram) bool {
	gen := 0
	doneSecond := false
	return func(d ct1Dgram) bool {
		if gen == 0 && first(d) {
			gen = d.gen
			return true
		}
		if gen != 0 && !doneSecond && d.gen > gen && second(d) {
			doneSecond = true
			return true
		}
		return false
	}
}

// TestCT1TwoLossesInOneHandshakeRecover is T4, re-tiered by Amendment 2: two
// post-response losses in two successive generations (PQ_CT then an ML-DSA-65
// chunk; the Ed25519 frame then the PQ_CT; without dual auth, PQ_CT twice) add
// two generations in EVERY run of every cell in both prior modes: the residual
// of fail-closed two-loss connects is zero (ruling 3; ct1RecoversRange fails
// on a spent ladder). With a measured prior no fire precedes the response, so
// the first supersession draws from window(0) and the second from window(1),
// the index-aware bound.
func TestCT1TwoLossesInOneHandshakeRecover(t *testing.T) {
	pos := func(p int) func(ct1Dgram) bool { return func(d ct1Dgram) bool { return d.pos == p } }
	ct1Cells(t, []bool{true, false}, func(t *testing.T, mode ct1Mode, dual bool, size int, rtt, healthy time.Duration) {
		if !dual {
			t.Run("pqct-then-pqct", func(t *testing.T) {
				ct1Recovers(t, mode, dual, size, rtt, healthy, 2, func() ct1Opts { return ct1Opts{dropGw: ct1DropThen(pos(1), pos(1))} })
			})
			return
		}
		t.Run("pqct-then-ml", func(t *testing.T) {
			ct1Recovers(t, mode, dual, size, rtt, healthy, 2, func() ct1Opts { return ct1Opts{dropGw: ct1DropThen(pos(1), pos(3))} })
		})
		t.Run("ed-then-pqct", func(t *testing.T) {
			ct1Recovers(t, mode, dual, size, rtt, healthy, 2, func() ct1Opts { return ct1Opts{dropGw: ct1DropThen(pos(2), pos(1))} })
		})
	})
}

// --- burst loss, duplication, reordering --------------------------------------

// TestCT1BurstLossRecovers: the gateway's whole post-response flight lost once,
// and the client's whole first PQ_EK flight lost once, each cost one
// generation.
func TestCT1BurstLossRecovers(t *testing.T) {
	ct1Cells(t, []bool{true, false}, func(t *testing.T, mode ct1Mode, dual bool, size int, rtt, healthy time.Duration) {
		t.Run("gateway-flight", func(t *testing.T) {
			ct1Recovers(t, mode, dual, size, rtt, healthy, 1, func() ct1Opts {
				return ct1Opts{dropGw: ct1FirstPQFlight(func(d ct1Dgram) bool { return d.pos >= 1 })}
			})
		})
		t.Run("client-key-flight", func(t *testing.T) {
			ct1Recovers(t, mode, dual, size, rtt, healthy, 1, func() ct1Opts {
				first := true
				return ct1Opts{dropCli: func(d ct1Dgram) bool {
					if d.kind != ct1PQEK || !first {
						return false
					}
					if d.pos == ct1EKChunks(size) {
						first = false
					}
					return true
				}}
			})
		})
	})
}

// TestCT1DuplicationIsHarmless: every datagram in both directions arrives
// twice; nothing is superseded and nothing is late.
func TestCT1DuplicationIsHarmless(t *testing.T) {
	ct1Cells(t, []bool{true, false}, func(t *testing.T, mode ct1Mode, dual bool, size int, rtt, healthy time.Duration) {
		ct1Recovers(t, mode, dual, size, rtt, healthy, 0, func() ct1Opts { return ct1Opts{dup: true} })
	})
}

// TestCT1ReorderingRecovers: the Ed25519 frame behind the ML-DSA-65 chunks is
// held, not refused, and costs nothing; the PQ ciphertext behind the
// attestation it unlocks makes the attestation unopenable on arrival, and the
// client holds it until the ratchet and opens it then, so that costs nothing
// either (A3.3 Q5: zero generations, inverted from D5's one).
func TestCT1ReorderingRecovers(t *testing.T) {
	ct1Cells(t, []bool{true}, func(t *testing.T, mode ct1Mode, dual bool, size int, rtt, healthy time.Duration) {
		late := func(p int) func() ct1Opts {
			return func() ct1Opts {
				first := ct1FirstPQFlight(func(d ct1Dgram) bool { return d.pos == p })
				return ct1Opts{delayGw: func(d ct1Dgram) time.Duration {
					if first(d) {
						return 5 * time.Millisecond
					}
					return 0
				}}
			}
		}
		// A fire that comes inside the 5 ms (a draw under 5 ms) supersedes
		// anyway, which is the design working: 0 or 1 generation.
		t.Run("ed-after-ml", func(t *testing.T) {
			ct1RecoversRange(t, mode, dual, size, rtt, healthy, 5*time.Millisecond, 0, 1, late(2))
		})
		t.Run("pqct-after-its-flight", func(t *testing.T) {
			ct1RecoversRange(t, mode, dual, size, rtt, healthy, 5*time.Millisecond, 0, 0, late(1))
		})
	})
}

// --- fail closed, and silent while failing ------------------------------------

// TestCT1WrongSignaturesNeverOpenTheGate: a gateway whose Ed25519 or ML-DSA-65
// key is not the one the client expects never gets the client established and
// never delivers an inner packet to it; the client closes CloseDualAuthFailed
// when the flight arrives, starts no new generation, and every gateway
// transmission is an answer.
func TestCT1WrongSignaturesNeverOpenTheGate(t *testing.T) {
	for _, mode := range ct1Modes {
		for _, which := range []string{"ed25519", "mldsa65"} {
			for _, size := range ct1Sizes {
				for _, rtt := range ct1RTTs {
					ct1WrongKeyCell(t, mode, which, size, rtt)
				}
			}
		}
	}
}

func ct1WrongKeyCell(t *testing.T, mode ct1Mode, which string, size int, rtt time.Duration) {
	t.Run(fmt.Sprintf("%s/%s/size=%d/rtt=%v", mode.name, which, size, rtt), func(t *testing.T) {
		for i := 0; i < ct1Runs(); i++ {
			r := ct1WrongKeyRun(t, which, size, rtt, 6000+i, mode.prior(rtt))
			if r.carrying != 0 || r.established != 0 || r.dualVerified {
				t.Fatalf("run %d: the gate opened on a wrong %s signature", i, which)
			}
			if r.cliReason != CloseDualAuthFailed {
				t.Fatalf("run %d: close reason %s, want %s", i, r.cliReason, CloseDualAuthFailed)
			}
			if r.superseded != 0 {
				t.Fatalf("run %d: an invalid signature pair started a new generation", i)
			}
			ct1GatewayAnswersOnly(t, i, r)
		}
	})
}

// ct1WrongKeyRun is ct1Run with the client expecting a different key of one
// family than the gateway signs with.
func ct1WrongKeyRun(t *testing.T, which string, size int, rtt time.Duration, seed int, prior time.Duration) ct1Result {
	t.Helper()
	edPriv, edPub, mlSeed, mlPub := dualKeys(t)
	_, otherEd, _, otherML := dualKeys(t)
	if which == "ed25519" {
		edPub = otherEd
	} else {
		mlPub = otherML
	}
	return ct1RunWith(t, ct1Opts{rtt: rtt, size: size, seed: seed, prior: prior, untilTerminal: true}, func(cli, gw *Config) {
		gw.DualAuth = DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
		cli.DualAuth = DualAuthConfig{Expected: true, Ed25519Public: edPub, MLDSA65Public: mlPub}
	})
}

// TestCT1AbandonedAfterTheCiphertextGetsNothing: a client that goes silent
// after its PQ_EK hears nothing more from the gateway beyond the flight that
// answered it, for a full minute.
func TestCT1AbandonedAfterTheCiphertextGetsNothing(t *testing.T) {
	for _, dual := range []bool{true, false} {
		for _, size := range ct1Sizes {
			t.Run(fmt.Sprintf("dual=%v/size=%d", dual, size), func(t *testing.T) {
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
				keyMsgs := ct1EKChunks(size)
				p.filterToGw = func(idx int, _ []byte) bool { return idx <= keyMsgs }
				p.run()
				if p.gw.Epoch() != 1 {
					t.Fatalf("fixture: the gateway did not ratchet (epoch %d)", p.gw.Epoch())
				}
				sent := p.gw.Stats().MessagesSent
				for s := 0; s < 60; s++ {
					p.clk.Advance(time.Second)
					p.run()
				}
				if got := p.gw.Stats().MessagesSent; got != sent {
					t.Fatalf("the gateway sent %d message(s) to a peer that went silent", got-sent)
				}
			})
		}
	}
}

// --- T5 and T6: a superseded generation is dead on both ends -------------------

// TestCT1SupersededGenerationIsDead is T5 and T6 on one scenario. The gateway's
// whole first flight after the response is lost, so the client supersedes the
// generation. The dead generation's datagrams (its PQ_CT, its Ed25519 frame,
// its ML-DSA-65 chunks, and a DATA frame sealed by the gateway's copy of the
// dead session) are delivered to the client before and after the new response:
// nothing is sent, no inner packet is delivered, and State, genSeq, lastOpened
// and dualDone do not move until the new generation's own attestation. The
// client's first initiation and its dead generation's PQ_EK, replayed 10 times
// to the gateway after the supersession and again after establishment, draw no
// transmission and move nothing.
func TestCT1SupersededGenerationIsDead(t *testing.T) {
	for _, dual := range []bool{true, false} {
		for _, size := range ct1Sizes {
			t.Run(fmt.Sprintf("dual=%v/size=%d", dual, size), func(t *testing.T) {
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
				var firstInit []byte
				var oldKeys, stale [][]byte
				p.filterToGw = func(idx int, m []byte) bool {
					if idx == 0 {
						firstInit = append([]byte(nil), m...)
					} else {
						oldKeys = append(oldKeys, append([]byte(nil), m...))
					}
					return true
				}
				p.filterToCli = func(idx int, m []byte) bool {
					if idx == 0 {
						return true
					}
					stale = append(stale, append([]byte(nil), m...))
					return false
				}
				p.run()
				if p.cli.sess == nil || p.gw.Epoch() != 1 || len(stale) == 0 {
					t.Fatalf("fixture: client session %v, gateway epoch %d, %d stale", p.cli.sess != nil, p.gw.Epoch(), len(stale))
				}
				inner := make([]byte, 40)
				inner[0] = 0x45
				plain, err := core.AppendFrame(nil, core.FrameData, inner)
				if err != nil {
					t.Fatal(err)
				}
				data, err := p.gw.sess.Seal(plain, 0)
				if err != nil {
					t.Fatal(err)
				}
				stale = append(stale, data)

				// The client's ladder fires: the generation is superseded.
				p.filterToGw, p.filterToCli = nil, nil
				p.clk.Advance(p.cli.NextDeadline().Sub(p.clk.Now()))
				fresh, err := p.cli.Poll()
				if err != nil || fresh == nil {
					t.Fatalf("no fresh initiation at the fire: %v", err)
				}
				if got := ct1StatOr0(p.cli.Stats(), "GenerationsSuperseded"); got != 1 || p.cli.sess != nil {
					t.Fatalf("the generation was not superseded (count %d, session %v)", got, p.cli.sess != nil)
				}
				fresh = append([]byte(nil), fresh...)

				staleIsDead := func(phase string) {
					t.Helper()
					st, seq, opened, recv := p.cli.State(), p.cli.genSeq, p.cli.lastOpened, p.cli.Stats().MessagesReceived
					for _, m := range stale {
						if pkts, _ := p.cli.Deliver(m); len(pkts) != 0 {
							t.Fatalf("%s: a dead-generation datagram delivered an inner packet", phase)
						}
					}
					if m, _ := p.cli.Poll(); m != nil {
						t.Fatalf("%s: the client transmitted after dead-generation datagrams", phase)
					}
					if p.cli.State() != st || p.cli.genSeq != seq || !p.cli.lastOpened.Equal(opened) || p.cli.dualDone ||
						p.cli.Stats().MessagesReceived != recv || p.cli.Err() != nil {
						t.Fatalf("%s: a dead-generation datagram moved the client", phase)
					}
				}
				replaysAreDead := func(phase string) {
					t.Helper()
					seq, st := p.gw.genSeq, p.gw.State()
					for j := 0; j < 10; j++ {
						for _, m := range append([][]byte{firstInit}, oldKeys...) {
							p.clk.Advance(2 * reinitCheckInterval)
							if pkts, _ := p.gw.Deliver(m); len(pkts) != 0 {
								t.Fatalf("%s: a replay delivered a packet", phase)
							}
						}
						// The gateway's pre-existing receive-stall probe can arm on
						// these unopenable replays once its peer has been quiet for
						// 1 s; it is a timer of its own, not an answer. Anything
						// else on the wire would be one.
						pings := p.gw.Stats().PingsSent
						if out := ct1GwDrain(t, p.gw); uint64(len(out)) != p.gw.Stats().PingsSent-pings {
							t.Fatalf("%s: the gateway answered a replay with %d message(s)", phase, len(out))
						}
					}
					if p.gw.genSeq != seq || p.gw.State() != st {
						t.Fatalf("%s: replays moved the gateway", phase)
					}
				}

				staleIsDead("before the new response")
				replaysAreDead("after the supersession")

				// The new generation's initiation and response (past the
				// gateway's reinitiation rate gate, which the replays just used).
				p.clk.Advance(2 * reinitCheckInterval)
				if _, err := p.gw.Deliver(fresh); err != nil {
					t.Fatal(err)
				}
				resp := ct1GwDrain(t, p.gw)
				if len(resp) != 1 {
					t.Fatalf("the gateway answered the fresh initiation with %d message(s)", len(resp))
				}
				if _, err := p.cli.Deliver(resp[0]); err != nil || p.cli.sess == nil {
					t.Fatalf("the new response did not open: %v", err)
				}
				for {
					m, err := p.cli.Poll()
					if err != nil {
						t.Fatal(err)
					}
					if m == nil {
						break
					}
					p.toGw = append(p.toGw, m)
				}
				staleIsDead("after the new response")

				p.establish()
				if dual && !p.cli.DualAuthVerified() {
					t.Fatal("the new generation established without its attestation")
				}
				replaysAreDead("after establishment")
			})
		}
	}
}

// --- T12: the signer's lifetime ------------------------------------------------

// TestCT1ReinitiationKeepsTheSignerAndTerminateWipesIt is T12 at the field
// level: admitReinitiation leaves the gateway's attestation credentials in
// place (the replacement must attest; T3 proves it end to end), and terminate
// destroys the signer and zeroes the driver's Ed25519 key. The NewSigner
// failure path cannot be reached through Config (normalise refuses a seed of
// the wrong size first, config.go DualAuthConfig.validate), so it is not driven
// here.
func TestCT1ReinitiationKeepsTheSignerAndTerminateWipesIt(t *testing.T) {
	edPriv, edPub, mlSeed, mlPub := dualKeys(t)
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		gw.DualAuth = DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
		cli.DualAuth = DualAuthConfig{Expected: true, Ed25519Public: edPub, MLDSA65Public: mlPub}
	})
	p.establish()
	signer, key := p.gw.dualMLSign, p.gw.dualEDPriv
	if signer == nil || len(key) == 0 {
		t.Fatal("fixture: the gateway holds no attestation credentials")
	}
	ini := p.newInitiator(t)
	if err := ini.SetInitFlags(core.HandshakeFlagDualAuth); err != nil {
		t.Fatal(err)
	}
	init, err := ini.WriteInitiation(nil, core.PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	p.clk.Advance(time.Millisecond)
	before := p.gw.Stats().HandshakeMessagesSent
	if _, err := p.gw.Deliver(init); err != nil {
		t.Fatal(err)
	}
	if out := ct1GwDrain(t, p.gw); len(out) != 1 || p.gw.Stats().HandshakeMessagesSent != before+1 {
		t.Fatalf("fixture: the re-initiation was not answered (%d message(s))", len(out))
	}
	if p.gw.dualMLSign != signer || !bytes.Equal(p.gw.dualEDPriv, edPriv) {
		t.Fatal("admitReinitiation destroyed the gateway's attestation credentials")
	}
	if !p.gw.RetireIfQuiet(p.gw.ReclaimView().Seq) {
		t.Fatal("fixture: the gateway did not terminate")
	}
	if p.gw.dualMLSign != nil || p.gw.dualEDPriv != nil {
		t.Fatal("terminate left the attestation credentials on the driver")
	}
	for _, b := range key {
		if b != 0 {
			t.Fatal("terminate did not zero the driver's copy of the Ed25519 private key")
		}
	}
}

// ct1GwDrain takes everything the gateway wants to send.
func ct1GwDrain(t *testing.T, gw *Driver) [][]byte {
	t.Helper()
	var out [][]byte
	for i := 0; i < 64; i++ {
		m, err := gw.Poll()
		if err != nil {
			t.Fatalf("gateway poll: %v", err)
		}
		if m == nil {
			return out
		}
		out = append(out, append([]byte(nil), m...))
	}
	t.Fatal("gateway did not quiesce")
	return nil
}

// --- FreshAfter 0 (Sol, CT4 Turn 1, CT-1 constraint 5; ruling A1.1 S6) ---------

// TestCT1FreshAfterEncoding pins the FreshAfter encoding Amendment 2 (A2.4
// step 3, ruling F-CT1-5) gives it: 0 is the default and means no copies, so
// the first pre-session retry is a fresh initiation; 1, 2 and 3 mean that many
// byte-identical copies first. (It replaces the Amendment 1 pin, under which 0
// meant the old default of two copies.)
func TestCT1FreshAfterEncoding(t *testing.T) {
	if got := (Retry{FreshAfter: 0}).freshAfter(); got != 0 || DefaultFreshAfter != 0 {
		t.Fatalf("Retry{FreshAfter: 0}.freshAfter() = %d (DefaultFreshAfter %d), want 0", got, DefaultFreshAfter)
	}
	for _, c := range []struct{ freshAfter, copies int }{{0, 0}, {1, 1}, {2, 2}, {3, 3}} {
		t.Run(fmt.Sprintf("FreshAfter=%d", c.freshAfter), func(t *testing.T) {
			p := newPair(t, func(cli, gw *Config) {
				cli.Retry = Retry{Base: time.Second, Cap: 2 * time.Second, Attempts: 8, FreshAfter: c.freshAfter}
			})
			var sent [][]byte
			for len(sent) < c.copies+2 {
				m, err := p.cli.Poll()
				if err != nil {
					t.Fatal(err)
				}
				if m != nil {
					sent = append(sent, append([]byte(nil), m...))
					continue
				}
				dl := p.cli.NextDeadline()
				if dl.IsZero() || p.cli.State().Terminal() {
					t.Fatalf("the ladder stopped after %d initiation(s)", len(sent))
				}
				p.clk.Advance(dl.Sub(p.clk.Now()))
			}
			for i := 1; i <= c.copies; i++ {
				if !bytes.Equal(sent[i], sent[0]) {
					t.Fatalf("retry %d is not a byte-identical copy", i)
				}
			}
			if bytes.Equal(sent[c.copies+1], sent[0]) {
				t.Fatalf("retry %d is still a copy; want the fresh initiation after %d copies", c.copies+1, c.copies)
			}
		})
	}
}
