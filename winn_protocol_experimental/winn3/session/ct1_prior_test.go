package session

// CT-1 D5 tests (Amendment 2) that build on any tree: T16 and T18. They set the
// prior through ct1SetPrior, so on a tree without Retry.RTTPrior they run that
// tree's behaviour. T17 needs the D5 config API and is in ct1_d4_test.go; T14
// and T15 are in ct1_recovery_test.go.

import (
	"fmt"
	"testing"
	"time"
)

// TestCT1LateResponseCostsOneInitiation is T16, asserted in every cell of both
// prior modes, FIRST-CONTACT at 600 ms included (A3.3 TESTS item 3). The first
// response is delayed
// by floor + window(0) + RTT, so the first ladder fire (a fresh initiation)
// leaves before it arrives. The connect carries on the second initiation's
// response with HandshakeAttempts == 2 and no supersession; the late response
// is counted Unopenable and moves nothing; Stats.HandshakeRTT is the second
// initiation's round trip (A2.4 step 4); and the gateway sends exactly the two
// responses and their flight, every one an answer (T10).
func TestCT1LateResponseCostsOneInitiation(t *testing.T) {
	for _, mode := range ct1Modes {
		for _, dual := range []bool{true, false} {
			for _, rtt := range ct1RTTs {
				t.Run(fmt.Sprintf("%s/dual=%v/rtt=%v", mode.name, dual, rtt), func(t *testing.T) {
					late := mode.floor(rtt) + ct1Window(0) + rtt
					for i := 0; i < ct1Runs(); i++ {
						first := ct1DropFirstWhere(func(d ct1Dgram) bool { return d.kind == ct1Response })
						r := ct1Run(t, ct1Opts{rtt: rtt, size: 1360, dual: dual, seed: 3100 + i, prior: mode.prior(rtt),
							minRun: rtt + late + rtt,
							delayGw: func(d ct1Dgram) time.Duration {
								if first(d) {
									return late
								}
								return 0
							}})
						if r.failed != nil {
							t.Fatalf("run %d: %v", i, r.failed)
						}
						if r.hsAttempts != 2 || r.superseded != 0 {
							t.Fatalf("run %d: %d handshake attempts and %d supersessions, want 2 and 0", i, r.hsAttempts, r.superseded)
						}
						st := r.cli.Stats()
						if st.Unopenable != 1 {
							t.Fatalf("run %d: Unopenable %d, want exactly the late response", i, st.Unopenable)
						}
						if r.cli.State() != StateEstablished || r.cli.Err() != nil {
							t.Fatalf("run %d: the late response moved the client: %s %v", i, r.cli.State(), r.cli.Err())
						}
						if got := time.Duration(ct1StatOr0(st, "HandshakeRTT")); got != rtt {
							t.Fatalf("run %d: HandshakeRTT %v, want the second initiation's round trip %v", i, got, rtt)
						}
						responses, inits := 0, 0
						for _, s := range r.gwSends {
							if s.kind == ct1Response {
								responses++
							}
						}
						for _, s := range r.cliSends {
							if s.kind == ct1Initiation {
								inits++
							}
						}
						if responses != 2 || inits != 2 {
							t.Fatalf("run %d: %d initiations and %d responses, want 2 and 2", i, inits, responses)
						}
						ct1GatewayAnswersOnly(t, i, r)
					}
				})
			}
		}
	}
}

// TestCT1LadderUnderTheMaximumFloor is T18: with RTTPrior at MaxRTTPrior (1 s)
// and every response lost, the connect ends by exhausting its ladder at
// Retry.Attempts fires, before connectBy (the floor is not in handshakeBudget:
// at most 5 x 1 s + 15.5 s of draws, inside 23.5 s), with CloseProtocolError
// and a carrier-change verdict.
func TestCT1LadderUnderTheMaximumFloor(t *testing.T) {
	retry := Retry{}.orDefault()
	for _, dual := range []bool{true, false} {
		for _, rtt := range []time.Duration{30 * time.Millisecond, 300 * time.Millisecond, 600 * time.Millisecond} {
			t.Run(fmt.Sprintf("dual=%v/rtt=%v", dual, rtt), func(t *testing.T) {
				for i := 0; i < ct1Runs(); i++ {
					r := ct1Run(t, ct1Opts{rtt: rtt, size: 1360, dual: dual, seed: 3300 + i, prior: time.Second, untilTerminal: true,
						dropGw: func(d ct1Dgram) bool { return d.kind == ct1Response }})
					if !r.cliState.Terminal() {
						t.Fatalf("run %d: client %s, want closed", i, r.cliState)
					}
					if len(r.fires) != retry.Attempts {
						t.Fatalf("run %d: %d fires, want the ladder's %d", i, len(r.fires), retry.Attempts)
					}
					if connectBy := r.firstSendAt + handshakeBudget(retry); r.closedAt >= connectBy {
						t.Fatalf("run %d: closed at %v, not before connectBy %v", i, r.closedAt, connectBy)
					}
					if r.cliReason != CloseProtocolError || !r.needCarrier {
						t.Fatalf("run %d: reason %s, carrier change %v; want %s and true", i, r.cliReason, r.needCarrier, CloseProtocolError)
					}
					for _, f := range r.fires {
						if f.at < time.Second {
							t.Fatalf("run %d: a fire at %v, under the 1 s floor", i, f.at)
						}
					}
				}
			})
		}
	}
}

// TestCT1SlowDownlinkNeverSupersedesAHealthyConnect is Seat C N-2 as an
// assertion: on a lossless link whose gateway flight is serialized on a narrow
// downlink (each datagram after the response delayed by its position times the
// serialization time of one 1360-byte datagram), no healthy connect supersedes
// a live generation, at 4 Mbit/s, 1 Mbit/s and 256 kbit/s, RTT 100 ms, in both
// prior modes. Each authenticated datagram of the flight pushes the next fire
// out (noteHandshakeProgress), and the serialization gap is below the floor.
func TestCT1SlowDownlinkNeverSupersedesAHealthyConnect(t *testing.T) {
	rtt := 100 * time.Millisecond
	for _, mode := range ct1Modes {
		for _, kbps := range []int{4000, 1000, 256} {
			per := time.Duration(1360*8*1000/kbps) * time.Microsecond
			for _, dual := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%dkbps/dual=%v", mode.name, kbps, dual), func(t *testing.T) {
					for i := 0; i < ct1Runs(); i++ {
						r := ct1Run(t, ct1Opts{rtt: rtt, size: 1360, dual: dual, seed: 7000 + i, prior: mode.prior(rtt),
							delayGw: func(d ct1Dgram) time.Duration {
								if d.pos > 0 {
									return time.Duration(d.pos) * per
								}
								return 0
							}})
						if r.failed != nil {
							t.Fatalf("run %d: %v", i, r.failed)
						}
						if r.superseded != 0 || r.hsAttempts != 1 {
							t.Fatalf("run %d: a healthy connect on a %d kbit/s downlink superseded %d generation(s) (%d attempts)", i, kbps, r.superseded, r.hsAttempts)
						}
					}
				})
			}
		}
	}
}
