package session

// Seat C (Round CT4, lane ct_1) adversarial checks on D4, copied into the lane
// at the Arbiter's instruction (N-2, N-3). TestSeatCMismatchedHalvesFailClosedInEitherOrder
// and TestSeatCGarbageAndReplaysNeverDriveSupersession assert; the Measure tests
// are opt-in measurements (SEATC_MEASURE=1). Adapted only where the lane's
// helpers gained the prior mode.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	mrand "math/rand"
	"os"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/dualsign"
)

// seatcConnect drives one connect over an instant link. Every step the
// attacker injects random datagrams and replays of every datagram either side
// has ever had DELIVERED (what an off-path observer of the far side, or an
// on-path replayer, can hold). dropFlight loses the first generation's gateway
// datagrams after the response once. attackerFirst puts the attacker's
// datagrams ahead of the genuine ones at the same instant.
type seatcOut struct {
	cliEstablished bool
	superseded     uint64
	hsAttempts     uint64
	gwSent         uint64
	gwHS           uint64
	cliErr         error
}

func seatcConnect(t *testing.T, dual, dropFlight, inject, attackerFirst bool, seed int64) seatcOut {
	t.Helper()
	edPriv, edPub, mlSeed, mlPub := dualKeys(t)
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		gw.Silence = Draw{Min: quietHorizon, Mean: 2 * quietHorizon, Max: 3 * quietHorizon}
		if dual {
			gw.DualAuth = DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
			cli.DualAuth = DualAuthConfig{Expected: true, Ed25519Public: edPub, MLDSA65Public: mlPub}
		}
	})
	rng := mrand.New(mrand.NewSource(seed))
	sizes := []int{1, 16, 63, 64, 120, 300, 700, 1200, 1360}
	var cliDelivered, gwDelivered [][]byte
	gwIdx := 0
	flight := 2
	if dual {
		flight = 6
	}
	for step := 0; step < 2000; step++ {
		var toGw, toCli [][]byte
		for {
			m, err := p.cli.Poll()
			if err != nil {
				t.Fatalf("client poll: %v", err)
			}
			if m == nil {
				break
			}
			toGw = append(toGw, bytes.Clone(m))
		}
		for {
			m, err := p.gw.Poll()
			if err != nil {
				t.Fatalf("gateway poll: %v", err)
			}
			if m == nil {
				break
			}
			i := gwIdx
			gwIdx++
			if dropFlight && i >= 1 && i < flight {
				continue
			}
			toCli = append(toCli, bytes.Clone(m))
		}
		genuine := len(toGw) + len(toCli)
		var atkGw, atkCli [][]byte
		if inject {
			for i := 0; i < 6; i++ {
				g := make([]byte, sizes[rng.Intn(len(sizes))])
				rng.Read(g)
				atkCli = append(atkCli, g)
				atkGw = append(atkGw, bytes.Clone(g))
			}
			for _, m := range gwDelivered {
				atkCli = append(atkCli, bytes.Clone(m))
			}
			for _, m := range cliDelivered {
				atkGw = append(atkGw, bytes.Clone(m))
			}
		}
		var gwIn, cliIn [][]byte
		if attackerFirst {
			gwIn, cliIn = append(atkGw, toGw...), append(atkCli, toCli...)
		} else {
			gwIn, cliIn = append(toGw, atkGw...), append(toCli, atkCli...)
		}
		for _, m := range gwIn {
			_, _ = p.gw.Deliver(m)
		}
		for _, m := range cliIn {
			_, _ = p.cli.Deliver(m)
		}
		cliDelivered = append(cliDelivered, toGw...)
		gwDelivered = append(gwDelivered, toCli...)
		if p.cli.State() == StateEstablished || p.cli.State().Terminal() {
			break
		}
		if genuine == 0 {
			dl := p.cli.NextDeadline()
			if dl.After(p.clk.Now()) {
				p.clk.Advance(dl.Sub(p.clk.Now()))
			} else {
				p.clk.Advance(2 * reinitCheckInterval)
			}
		} else {
			// Past the gateway's reinitiation rate gate between steps.
			p.clk.Advance(2 * reinitCheckInterval)
		}
	}
	st := p.cli.Stats()
	return seatcOut{
		cliEstablished: p.cli.State() == StateEstablished,
		superseded:     st.GenerationsSuperseded,
		hsAttempts:     st.HandshakeAttempts,
		gwSent:         p.gw.Stats().MessagesSent + p.gw.Stats().HandshakeMessagesSent,
		gwHS:           p.gw.Stats().HandshakeMessagesSent,
		cliErr:         p.cli.Err(),
	}
}

// Garbage and replays from an attacker never add a generation, never add a
// gateway transmission, and never stop a recovery, when the genuine datagram
// is not raced by the attacker inside the gateway's 1 ms reinitiation gate.
func TestSeatCGarbageAndReplaysNeverDriveSupersession(t *testing.T) {
	for _, dual := range []bool{true, false} {
		for _, drop := range []bool{false, true} {
			t.Run(fmt.Sprintf("dual=%v/dropFlight=%v", dual, drop), func(t *testing.T) {
				for seed := int64(1); seed <= 6; seed++ {
					clean := seatcConnect(t, dual, drop, false, false, seed)
					atk := seatcConnect(t, dual, drop, true, false, seed)
					if !clean.cliEstablished || !atk.cliEstablished {
						t.Fatalf("seed %d: established clean=%v attacked=%v (err %v)", seed, clean.cliEstablished, atk.cliEstablished, atk.cliErr)
					}
					want := uint64(0)
					if drop {
						want = 1
					}
					if atk.superseded != want || atk.hsAttempts != 1+want || clean.superseded != want {
						t.Fatalf("seed %d: superseded attacked %d clean %d attempts %d, want %d", seed, atk.superseded, clean.superseded, atk.hsAttempts, want)
					}
					if atk.gwSent != clean.gwSent || atk.gwHS != clean.gwHS {
						t.Fatalf("seed %d: gateway sent %d (%d responses) under attack, %d (%d) clean", seed, atk.gwSent, atk.gwHS, clean.gwSent, clean.gwHS)
					}
				}
			})
		}
	}
}

// Measurement only: the same with the attacker's datagrams first at the same
// instant (an off-path sprayer spoofing the client's address). Logs outcomes.
func TestSeatCAttackerRacesTheReinitGate(t *testing.T) {
	for _, dual := range []bool{true, false} {
		ok, sup := 0, uint64(0)
		var gw uint64
		for seed := int64(1); seed <= 6; seed++ {
			o := seatcConnect(t, dual, true, true, true, seed)
			if o.cliEstablished {
				ok++
			}
			sup += o.superseded
			gw += o.gwHS
		}
		t.Logf("dual=%v attacker-first: established %d/6, superseded total %d, gateway responses total %d", dual, ok, sup, gw)
	}
}

// --- ML-before-ED hold with mismatched halves ----------------------------------

func TestSeatCMismatchedHalvesFailClosedInEitherOrder(t *testing.T) {
	cases := []string{"ml-first/wrong-ed-bytes", "ml-first/ed-over-other-transcript", "ed-first/ml-over-other-transcript", "wrong-ml-held/correct-ed"}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			// Build an attestation fixture with keys we can sign arbitrary
			// messages with: re-derive from a fresh pair.
			edPriv, edPub, mlSeed, mlPub := dualKeys(t)
			p := newPair(t, func(cli, gw *Config) {
				quietConfig(cli)
				quietConfig(gw)
				gw.DualAuth = DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
				cli.DualAuth = DualAuthConfig{Expected: true, Ed25519Public: edPub, MLDSA65Public: mlPub}
			})
			p.filterToCli = func(idx int, _ []byte) bool { return idx < 2 }
			p.run()
			p.filterToCli = nil
			if p.cli.State() != StateInitiating || p.cli.sess == nil || !p.cli.sess.PQRatcheted() {
				t.Fatal("fixture")
			}
			h := p.cli.sess.TranscriptHash()
			other := sha256.Sum256([]byte("a previous generation's transcript"))
			signer, err := pqauth.NewSigner(pqauth.MLDSA65, mlSeed)
			if err != nil {
				t.Fatal(err)
			}
			defer signer.Destroy()
			sign := func(msg []byte) (core.Frame, []core.Frame) {
				ed, err := dualsign.SignEd25519(edPriv, msg)
				if err != nil {
					t.Fatal(err)
				}
				ml, err := dualsign.SignMLDSA65(signer, msg)
				if err != nil {
					t.Fatal(err)
				}
				var fs []core.Frame
				for _, c := range chunkBlob(core.FrameDualAuthML, ml, p.cli.cfg.maxPayload()-frameHeaderSize) {
					fs = append(fs, core.Frame{Type: c.typ, Value: c.value})
				}
				return core.Frame{Type: core.FrameDualAuthED, Value: ed}, fs
			}
			goodED, goodML := sign(h[:])
			badED, badML := sign(other[:])
			feed := func(fs ...core.Frame) {
				t.Helper()
				if _, err := p.cli.handleFrames(p.clk.Now(), fs, false); err != nil {
					t.Fatal(err)
				}
			}
			switch c {
			case "ml-first/wrong-ed-bytes":
				w := bytes.Clone(goodED.Value)
				w[3] ^= 0x10
				feed(goodML...)
				feed(core.Frame{Type: core.FrameDualAuthED, Value: w})
			case "ml-first/ed-over-other-transcript":
				feed(goodML...)
				feed(badED)
			case "ed-first/ml-over-other-transcript":
				feed(goodED)
				feed(badML...)
			case "wrong-ml-held/correct-ed":
				feed(badML...)
				feed(goodED)
			}
			if err := p.cli.Err(); !errors.Is(err, ErrDualAuthFailed) {
				t.Fatalf("err %v, want ErrDualAuthFailed", err)
			}
			if p.cli.LocalCloseReason() != CloseDualAuthFailed || p.cli.DualAuthVerified() {
				t.Fatalf("reason %s verified %v", p.cli.LocalCloseReason(), p.cli.DualAuthVerified())
			}
			// Let every clock the client has run out: no new generation.
			for i := 0; i < 10; i++ {
				p.clk.Advance(30 * time.Second)
				for {
					m, err := p.cli.Poll()
					if err != nil || m == nil {
						break
					}
				}
			}
			if st := p.cli.Stats(); st.GenerationsSuperseded != 0 || st.HandshakeAttempts != 1 {
				t.Fatalf("a bad pair started a new generation: superseded %d attempts %d", st.GenerationsSuperseded, st.HandshakeAttempts)
			}
		})
	}
}

// --- T2 strict-bound measurement (opt-in) --------------------------------------

// TestSeatCMeasureT2StrictBound logs, per cell, p95 carrying against the
// ruling's literal bound (healthy mean + RTT + 500 ms + 2 RTT) and the failed
// runs. Run with SEATC_MEASURE=1.
func TestSeatCMeasureT2StrictBound(t *testing.T) {
	if os.Getenv("SEATC_MEASURE") == "" {
		t.Skip("measurement")
	}
	cells, over, fails, total := 0, 0, 0, 0
	worst := time.Duration(0)
	for _, mode := range ct1Modes {
		for _, dual := range []bool{true, false} {
			for _, size := range ct1Sizes {
				for _, rtt := range ct1RTTs {
					healthy := ct1Healthy(t, size, rtt, dual, mode.prior(rtt))
					for k := 1; k < ct1GatewayHandshakeDatagrams(dual); k++ {
						var carry []time.Duration
						f := 0
						for i := 0; i < ct1Runs(); i++ {
							r := ct1Run(t, ct1Opts{rtt: rtt, size: size, dual: dual, seed: i, prior: mode.prior(rtt), dropGw: ct1DropFirst(k)})
							total++
							if r.failed != nil {
								f++
								continue
							}
							carry = append(carry, r.carrying)
						}
						fails += f
						cells++
						bound := healthy + rtt + 500*time.Millisecond + 2*rtt
						p95 := ct1P95(carry)
						mark := ""
						if p95 > bound {
							over++
							mark = " OVER"
							if p95-bound > worst {
								worst = p95 - bound
							}
						}
						t.Logf("%s dual=%v size=%d rtt=%v k=%d p95=%v bound=%v fails=%d%s", mode.name, dual, size, rtt, k, p95, bound, f, mark)
					}
				}
			}
		}
	}
	t.Logf("SUMMARY cells=%d over=%d worst_excess=%v failed_runs=%d/%d", cells, over, worst, fails, total)
}

// TestSeatCMeasureHealthySupersession: healthy connects (no loss) on a link
// whose gateway flight is slower than the response that set the floor:
// downlink serialization of the 5-datagram flight, or per-datagram jitter.
// Logs how many healthy runs superseded a live generation. SEATC_MEASURE=1.
func TestSeatCMeasureHealthySupersession(t *testing.T) {
	if os.Getenv("SEATC_MEASURE") == "" {
		t.Skip("measurement")
	}
	rtt := 100 * time.Millisecond
	type model struct {
		name string
		mk   func(seed int) func(ct1Dgram) time.Duration
	}
	ser := func(kbps int) model {
		per := time.Duration(1360*8*1000/kbps) * time.Microsecond * 1000 / 1000
		return model{fmt.Sprintf("serialization %d kbit/s (%v per datagram)", kbps, per), func(int) func(ct1Dgram) time.Duration {
			return func(d ct1Dgram) time.Duration {
				if d.pos > 0 {
					return time.Duration(d.pos) * per
				}
				return 0
			}
		}}
	}
	jit := func(j time.Duration) model {
		return model{fmt.Sprintf("uniform jitter 0..%v per gateway datagram", j), func(seed int) func(ct1Dgram) time.Duration {
			r := mrand.New(mrand.NewSource(int64(seed) + 77))
			return func(ct1Dgram) time.Duration { return time.Duration(r.Int63n(int64(j))) }
		}}
	}
	for _, m := range []model{ser(4000), ser(1000), ser(256), jit(20 * time.Millisecond), jit(50 * time.Millisecond), jit(100 * time.Millisecond)} {
		for _, dual := range []bool{true, false} {
			sup, failed, extra := 0, 0, time.Duration(0)
			var carry []time.Duration
			for i := 0; i < ct1Runs(); i++ {
				r := ct1Run(t, ct1Opts{rtt: rtt, size: 1360, dual: dual, seed: 7000 + i, delayGw: m.mk(i)})
				if r.superseded > 0 {
					sup++
				}
				if r.failed != nil {
					failed++
					continue
				}
				carry = append(carry, r.carrying)
			}
			_ = extra
			t.Logf("%s dual=%v rtt=%v: superseded %d/%d healthy runs, failed %d, mean carrying %v p95 %v",
				m.name, dual, rtt, sup, ct1Runs(), failed, ct1Mean(carry), ct1P95(carry))
		}
	}
}
