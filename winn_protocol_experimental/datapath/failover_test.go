package datapath

// Tests for multi-carrier failover.
//
// The argument, in the order the file makes it:
//
//  1. The socket rule and the plan's validation are inherited, not bypassed. In
//     particular a plan with no UDP-surviving successor is still refused when
//     it arrives through the failover constructor, which is the check that
//     stops the whole feature from being a decoration.
//  2. Plan order reaches the mobility engine as a priority spacing that is
//     large enough to survive latency noise and small enough to be overridden
//     by an actual failure. This is asserted against mobility's own weights, so
//     a change on either side breaks it.
//  3. The measured defect is survived END TO END: a censor that silently drops
//     UDP produces no socket error at all, so this is the case carrier.Manager
//     alone cannot see, and the case the whole file exists for.
//  4. A working tunnel is NEVER torn down. This is the class of error the
//     escalation lane's own tests caught — a verdict sourced from the wrong
//     counter would have declared a healthy carrier blocked — so it is tested
//     from both sides here: healthy does not switch, and stalled does not
//     switch either.
//  5. The gateway-sender filter still runs. The failover path turns
//     Engine.filterGatewaySender off because the Manager reports a synthetic
//     peer, so the check MOVED into directUDPConn. A moved security check that
//     nobody re-asserts is a deleted one.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/mobility"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

func failoverConfig(gateway string) Config {
	config := escalatingConfig(gateway)
	config.AllowOwnSocket = true
	// Budgets small enough that a test does not wait nine seconds for the
	// measured default. The RATIO to the review interval is what matters, and
	// the defaults are asserted separately by the escalation lane's tests.
	config.Escalation.MinOutbound = 1
	config.Escalation.BlockAfterMS = 150
	config.Escalation.StallAfterMS = 60_000
	return config
}

// fakeCarrierDialer stands in for an internal/carrier envelope dialer.
//
// It satisfies carrier.SuppliedSocketDialer so it goes through exactly the
// checks a real H2 dialer goes through, and it hands back a PacketConn wired to
// a loopback peer so a switch can be observed as traffic arriving somewhere
// new — rather than as a counter this test wrote itself.
type fakeCarrierDialer struct {
	kind  carrier.SocketKind
	peer  *net.UDPConn
	dials atomic.Int64
	fail  atomic.Bool
	// preloaded makes HasSuppliedSocket report true, which is how a dialer that
	// arrived already holding a host descriptor is simulated.
	preloaded bool
}

func (dialer *fakeCarrierDialer) Dial(ctx context.Context) (net.PacketConn, error) {
	dialer.dials.Add(1)
	if dialer.fail.Load() {
		return nil, errors.New("fake carrier refused")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	return &directUDPConn{
		PacketConn: conn,
		gateway:    dialer.peer.LocalAddr().(*net.UDPAddr),
	}, nil
}

func (dialer *fakeCarrierDialer) SuppliedSocketKind() carrier.SocketKind {
	if dialer.kind == "" {
		return carrier.SocketKindStream
	}
	return dialer.kind
}

func (dialer *fakeCarrierDialer) HasSuppliedSocket() bool { return dialer.preloaded }

func newFakeCarrier(t *testing.T) *fakeCarrierDialer {
	t.Helper()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	return &fakeCarrierDialer{peer: peer}
}

// blackHoleGateway is the censor. It is a bound UDP socket that never reads and
// never answers, which is what an `-p udp -j DROP` rule looks like from the
// client: the writes succeed, and nothing ever comes back. Binding it rather
// than using an unbound port matters — an unbound port would produce ICMP port
// unreachable, which IS an error and would let the Manager fail over for the
// wrong reason and make the test pass for the wrong reason.
func blackHoleGateway(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func openFailover(
	t *testing.T, config Config, candidates ...CarrierCandidate,
) (*Engine, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return OpenConfigWithFailover(ctx, config, candidates)
}

func directCandidate() CarrierCandidate {
	return CarrierCandidate{Carrier: CarrierDirectAWG}
}

func h2Candidate(dialer carrier.SuppliedSocketDialer) CarrierCandidate {
	return CarrierCandidate{
		Carrier:  CarrierHTTP2,
		Endpoint: "https://cdn.example.net/winn",
		Dialer:   dialer,
	}
}

// ---------------------------------------------------------------------------
// 1. The refusals are inherited, not bypassed
// ---------------------------------------------------------------------------

func TestFailoverRefusesWithoutAllowOwnSocket(t *testing.T) {
	gateway := blackHoleGateway(t)
	config := failoverConfig(gateway.LocalAddr().String())
	config.AllowOwnSocket = false
	fake := newFakeCarrier(t)
	engine, err := openFailover(t, config, directCandidate(), h2Candidate(fake))
	if !errors.Is(err, ErrOwnSocketRefused) {
		t.Fatalf("failover without allow_own_socket must be refused: %v", err)
	}
	if engine != nil {
		t.Fatal("a refused failover must return no engine")
	}
	// Checked before anything is built, so no carrier was dialed.
	if dials := fake.dials.Load(); dials != 0 {
		t.Fatalf("the socket rule must be checked before any dial, got %d", dials)
	}
}

func TestFailoverRefusesWithoutAPlan(t *testing.T) {
	gateway := blackHoleGateway(t)
	config := failoverConfig(gateway.LocalAddr().String())
	config.Escalation = EscalationConfig{}
	_, err := openFailover(t, config, directCandidate())
	if !errors.Is(err, ErrFailoverPlanRequired) {
		t.Fatalf("failover without a plan must be refused: %v", err)
	}
}

func TestFailoverRefusesWhenEscalationIsNotObserving(t *testing.T) {
	gateway := blackHoleGateway(t)
	config := failoverConfig(gateway.LocalAddr().String())
	config.Escalation.Mode = EscalationOff
	fake := newFakeCarrier(t)
	_, err := openFailover(t, config, directCandidate(), h2Candidate(fake))
	if !errors.Is(err, ErrFailoverObserveRequired) {
		t.Fatalf("failover in off mode must be refused: %v", err)
	}
}

// TestFailoverInheritsTheAllUDPRefusal is the anti-decoration check, arriving
// through the new door. direct-awg -> http3-connect-udp is refused by
// normalizeEscalationPlan, and the failover constructor must not have found a
// way around it: a plan whose every successor rides UDP is killed by the same
// one-line censor rule that killed the head.
func TestFailoverInheritsTheAllUDPRefusal(t *testing.T) {
	gateway := blackHoleGateway(t)
	config := failoverConfig(gateway.LocalAddr().String())
	config.Escalation.Plan = []string{CarrierDirectAWG, CarrierHTTP3}
	_, err := openFailover(t, config, directCandidate(),
		CarrierCandidate{
			Carrier:  CarrierHTTP3,
			Endpoint: "https://cdn.example.net/.well-known/masque/udp/{target_host}/{target_port}/",
			Dialer:   &fakeCarrierDialer{kind: carrier.SocketKindPacket},
		})
	if !errors.Is(err, ErrEscalationPlanAllUDP) &&
		!errors.Is(err, ErrEscalationTargetShelved) {
		t.Fatalf("an all-UDP plan must be refused through the failover door "+
			"too: %v", err)
	}
}

func TestFailoverRefusesPlanAndCandidateMismatches(t *testing.T) {
	gateway := blackHoleGateway(t)
	for name, testCase := range map[string]struct {
		mutate     func(*Config)
		candidates []CarrierCandidate
		want       error
	}{
		"plan entry with no candidate": {
			candidates: []CarrierCandidate{directCandidate()},
			want:       ErrFailoverCandidateMissing,
		},
		"candidate the plan does not name": {
			candidates: []CarrierCandidate{
				directCandidate(),
				h2Candidate(&fakeCarrierDialer{}),
				{
					Carrier:  CarrierHTTP3,
					Endpoint: "https://cdn.example.net/m/",
					Dialer:   &fakeCarrierDialer{kind: carrier.SocketKindPacket},
				},
			},
			want: ErrFailoverCandidateUnplanned,
		},
		"direct-awg given a dialer": {
			candidates: []CarrierCandidate{
				{Carrier: CarrierDirectAWG, Dialer: &fakeCarrierDialer{}},
				h2Candidate(&fakeCarrierDialer{}),
			},
			want: ErrFailoverCandidateDialer,
		},
		"envelope carrier with no dialer": {
			candidates: []CarrierCandidate{
				directCandidate(),
				{Carrier: CarrierHTTP2, Endpoint: "https://cdn.example.net/w"},
			},
			want: ErrFailoverCandidateDialer,
		},
		"dialer already holding a socket": {
			candidates: []CarrierCandidate{
				directCandidate(),
				h2Candidate(&fakeCarrierDialer{preloaded: true}),
			},
			want: ErrFailoverSuppliedSocket,
		},
		"dialer of the wrong socket kind": {
			candidates: []CarrierCandidate{
				directCandidate(),
				h2Candidate(&fakeCarrierDialer{kind: carrier.SocketKindPacket}),
			},
			want: ErrCarrierDialerMismatch,
		},
	} {
		config := failoverConfig(gateway.LocalAddr().String())
		if testCase.mutate != nil {
			testCase.mutate(&config)
		}
		_, err := openFailover(t, config, testCase.candidates...)
		if !errors.Is(err, testCase.want) {
			t.Fatalf("%s: want %v, got %v", name, testCase.want, err)
		}
	}
}

func TestFailoverRefusesADuplicateCandidate(t *testing.T) {
	gateway := blackHoleGateway(t)
	config := failoverConfig(gateway.LocalAddr().String())
	_, err := openFailover(t, config,
		directCandidate(), directCandidate(), h2Candidate(newFakeCarrier(t)))
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("a duplicated candidate must be refused: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 2. Plan order reaches mobility as a priority that means what it should
// ---------------------------------------------------------------------------

// TestPlanOrderBecomesMobilityPriority is written against mobility's OWN
// weights rather than against literals, because the property that matters is a
// relationship between two packages and either side can move.
//
// The failure it exists to catch is a plausible one: setting Priority to the
// plan index. mobility.Engine.score adds Priority to rttMillis*LatencyWeight,
// so with a step of 1 the plan order would be swamped by a few milliseconds of
// latency jitter and the datapath would wander onto the fallback carrier for no
// reason. The two assertions below pin the step between "bigger than latency"
// and "smaller than one hard failure".
func TestPlanOrderBecomesMobilityPriority(t *testing.T) {
	gateway := blackHoleGateway(t)
	gatewayAddr, err := net.ResolveUDPAddr("udp", gateway.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	config := failoverConfig(gateway.LocalAddr().String())
	if config, err = config.normalize(); err != nil {
		t.Fatal(err)
	}
	ordered, direct, err := planCandidates(
		config.Escalation.Plan,
		[]CarrierCandidate{directCandidate(), h2Candidate(newFakeCarrier(t))},
		gatewayAddr,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 2 {
		t.Fatalf("want 2 ordered candidates, got %d", len(ordered))
	}
	if len(direct) != 1 {
		t.Fatalf("want 1 direct leg, got %d", len(direct))
	}
	if ordered[0].Path.ID != CarrierDirectAWG ||
		ordered[1].Path.ID != CarrierHTTP2 {
		t.Fatalf("candidates are not in plan order: %q then %q",
			ordered[0].Path.ID, ordered[1].Path.ID)
	}
	if ordered[0].Path.Priority != 0 ||
		ordered[1].Path.Priority != planPriorityStep {
		t.Fatalf("priorities are not the plan's order: %v, %v",
			ordered[0].Path.Priority, ordered[1].Path.Priority)
	}
	if ordered[0].Path.Carrier != mobility.DirectUDP ||
		ordered[1].Path.Carrier != mobility.HTTP2 {
		t.Fatalf("mobility carriers are wrong: %v, %v",
			ordered[0].Path.Carrier, ordered[1].Path.Carrier)
	}

	weights := mobility.DefaultConfig()
	// A healthy but slow head must keep its place. Half a second of round trip
	// is far worse than anything this carrier sees in practice, and it must
	// still outrank the successor.
	const implausiblySlowRTTMillis = 500.0
	if implausiblySlowRTTMillis*weights.LatencyWeight >= planPriorityStep {
		t.Fatalf("planPriorityStep %v is small enough that latency alone "+
			"reorders the plan; a slow primary would be abandoned",
			planPriorityStep)
	}
	// One hard failure must demote past the next plan entry, or a dead carrier
	// would be retried ahead of a live one forever.
	if weights.FailurePenalty <= planPriorityStep {
		t.Fatalf("planPriorityStep %v is large enough that a failed carrier "+
			"still outranks its successor (FailurePenalty %v)",
			planPriorityStep, weights.FailurePenalty)
	}
}

// ---------------------------------------------------------------------------
// 3. The measured defect, survived end to end
// ---------------------------------------------------------------------------

// TestFailoverSurvivesTheSilentUDPBlock is the headline.
//
// The censor here produces NO error: the black-hole gateway is bound, so writes
// succeed and reads simply never return. That is what makes the test worth
// having — carrier.Manager's own failover is driven by dial and socket errors,
// of which there are none, so this passes only if the escalation verdict is
// what moved the session.
//
// The switch is observed as traffic arriving at the successor's peer socket,
// not as an internal counter, so a Manager that reported a switch it had not
// performed would still fail.
func TestFailoverSurvivesTheSilentUDPBlock(t *testing.T) {
	gateway := blackHoleGateway(t)
	successor := newFakeCarrier(t)
	config := failoverConfig(gateway.LocalAddr().String())

	engine, err := openFailover(t, config,
		directCandidate(), h2Candidate(successor))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = engine.Close() }()

	// Keep the tunnel trying, exactly as an AWG engine retrying its initiation
	// would. Every one of these leaves and none is answered.
	deadline := time.Now().Add(20 * time.Second)
	var switched bool
	for time.Now().Before(deadline) && !switched {
		if _, err := engine.WriteInbound([]byte("initiation")); err != nil {
			t.Fatalf("write inbound: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
		if successor.dials.Load() > 0 {
			switched = true
		}
	}
	if !switched {
		assessment, _ := engine.AssessEscalation()
		t.Fatalf("the session never left the blocked carrier; verdict was %q "+
			"(%s), recommended %q", assessment.Verdict, assessment.Reason,
			assessment.Recommended)
	}

	// And traffic must now actually reach the successor.
	_ = successor.peer.SetReadDeadline(time.Now().Add(10 * time.Second))
	buffer := make([]byte, 2048)
	var arrived bool
	for attempt := 0; attempt < 50 && !arrived; attempt++ {
		if _, err := engine.WriteInbound([]byte("after-switch")); err != nil {
			t.Fatalf("write inbound after switch: %v", err)
		}
		_ = successor.peer.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		count, _, readErr := successor.peer.ReadFromUDP(buffer)
		if readErr == nil && count > 0 {
			arrived = true
		}
	}
	if !arrived {
		t.Fatal("the switch was performed but no datagram reached the successor")
	}

	// The verdict must now name the carrier the session is actually on, or a
	// host reading it would be told about a carrier that is no longer in use.
	assessment, assessed := engine.AssessEscalation()
	if !assessed {
		t.Fatal("escalation stopped reporting after the switch")
	}
	if assessment.Carrier != CarrierHTTP2 {
		t.Fatalf("the verdict still names %q after switching to %q",
			assessment.Carrier, CarrierHTTP2)
	}
	if assessment.Transport != TransportTCP.String() {
		t.Fatalf("the verdict reports transport %q for %q",
			assessment.Transport, CarrierHTTP2)
	}
}

// TestFailoverRetriesWhenTheSuccessorWillNotDial proves make-before-break: a
// successor that refuses to dial must leave the session where it is rather than
// leaving it with nothing.
func TestFailoverRetriesWhenTheSuccessorWillNotDial(t *testing.T) {
	gateway := blackHoleGateway(t)
	successor := newFakeCarrier(t)
	successor.fail.Store(true)
	config := failoverConfig(gateway.LocalAddr().String())

	engine, err := openFailover(t, config,
		directCandidate(), h2Candidate(successor))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = engine.Close() }()

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := engine.WriteInbound([]byte("initiation")); err != nil {
			t.Fatalf("write inbound: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if successor.dials.Load() == 0 {
		t.Fatal("the supervisor never attempted the successor")
	}
	// The engine must still be usable: a failed probe must not have torn the
	// session down.
	if _, err := engine.WriteInbound([]byte("still alive")); err != nil {
		t.Fatalf("a failed switch tore down the session: %v", err)
	}
	assessment, _ := engine.AssessEscalation()
	if assessment.Carrier != CarrierDirectAWG {
		t.Fatalf("a failed probe renamed the carrier to %q", assessment.Carrier)
	}
}

// ---------------------------------------------------------------------------
// 4. A working tunnel is never torn down
// ---------------------------------------------------------------------------

// TestFailoverNeverSwitchesAWorkingCarrier is the counterpart to the bug the
// escalation lane's tests caught. There, a verdict sourced from a counter that
// moved on the HOST's read rather than on arrival would have called a working
// carrier blocked. Here the consequence of that class of error is no longer a
// misleading status field: it is a live tunnel being torn down and rebuilt on a
// slower carrier, on a handset, in Myanmar.
//
// So the gateway answers every datagram, and the assertion is that the
// successor is never dialed at all — over a window many times the block budget.
func TestFailoverNeverSwitchesAWorkingCarrier(t *testing.T) {
	gateway := blackHoleGateway(t)
	successor := newFakeCarrier(t)
	config := failoverConfig(gateway.LocalAddr().String())

	engine, err := openFailover(t, config,
		directCandidate(), h2Candidate(successor))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = engine.Close() }()

	// The gateway answers. This is the only difference from the test above.
	answering := make(chan struct{})
	var answerWg sync.WaitGroup
	answerWg.Add(1)
	go func() {
		defer answerWg.Done()
		buffer := make([]byte, 2048)
		for {
			select {
			case <-answering:
				return
			default:
			}
			_ = gateway.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			count, sender, readErr := gateway.ReadFromUDP(buffer)
			if readErr != nil {
				continue
			}
			_, _ = gateway.WriteToUDP(buffer[:count], sender)
		}
	}()
	defer func() { close(answering); answerWg.Wait() }()

	// Ten times the 150 ms block budget, and well past the 1 s review interval.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := engine.WriteInbound([]byte("keepalive")); err != nil {
			t.Fatalf("write inbound: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	if dials := successor.dials.Load(); dials != 0 {
		assessment, _ := engine.AssessEscalation()
		t.Fatalf("a working carrier was escalated away from (%d dials); "+
			"verdict %q: %s", dials, assessment.Verdict, assessment.Reason)
	}
	assessment, assessed := engine.AssessEscalation()
	if !assessed || assessment.Verdict != VerdictHealthy {
		t.Fatalf("an answering gateway must be healthy, got %q: %s",
			assessment.Verdict, assessment.Reason)
	}
}

// TestFailoverDoesNotSwitchOnAStalledCarrier keeps the two verdicts apart where
// it counts. A carrier that WAS carrying traffic and went quiet may be a
// handover, a suspend or a radio gap; rebuilding the transport is the wrong
// response and would drop a session that was about to resume.
func TestFailoverDoesNotSwitchOnAStalledCarrier(t *testing.T) {
	gateway := blackHoleGateway(t)
	successor := newFakeCarrier(t)
	config := failoverConfig(gateway.LocalAddr().String())
	// Long enough that the window below cannot reach it.
	config.Escalation.StallAfterMS = 60_000

	engine, err := openFailover(t, config,
		directCandidate(), h2Candidate(successor))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = engine.Close() }()

	// One answer, once. After that the gateway goes silent, which is a stall
	// and not a block: something did come back.
	if _, err := engine.WriteInbound([]byte("initiation")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	_ = gateway.SetReadDeadline(time.Now().Add(5 * time.Second))
	count, sender, err := gateway.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("gateway never saw the initiation: %v", err)
	}
	if _, err = gateway.WriteToUDP(buffer[:count], sender); err != nil {
		t.Fatal(err)
	}
	// Let the pump take it, so lastRxUnixNano is stamped.
	time.Sleep(300 * time.Millisecond)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := engine.WriteInbound([]byte("unanswered")); err != nil {
			t.Fatalf("write inbound: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if dials := successor.dials.Load(); dials != 0 {
		assessment, _ := engine.AssessEscalation()
		t.Fatalf("a stalled carrier was escalated (%d dials); verdict %q: %s",
			dials, assessment.Verdict, assessment.Reason)
	}
}

// ---------------------------------------------------------------------------
// 5. The gateway-sender filter moved and must still run
// ---------------------------------------------------------------------------

// TestDirectLegStillRefusesForeignSenders is the moved-security-check test.
//
// Engine.filterGatewaySender is off on the failover path because the Manager
// reports a synthetic peer for every carrier. The check did not go away: it now
// lives in directUDPConn, where the real sender address is known. An off-path
// sender injecting bytes the host would hand to its AWG engine is exactly what
// it stops, and Status must still count the drop under the same name.
func TestDirectLegStillRefusesForeignSenders(t *testing.T) {
	gateway := blackHoleGateway(t)
	successor := newFakeCarrier(t)
	config := failoverConfig(gateway.LocalAddr().String())
	// Do not let the supervisor move the session during the test.
	config.Escalation.BlockAfterMS = 600_000

	engine, err := openFailover(t, config,
		directCandidate(), h2Candidate(successor))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = engine.Close() }()

	// Learn the socket the direct leg opened by making it send one datagram.
	if _, err := engine.WriteInbound([]byte("initiation")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	_ = gateway.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, engineAddr, err := gateway.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("gateway never saw the initiation: %v", err)
	}

	// An off-path sender writes to that same socket.
	attacker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = attacker.Close() }()
	for range 5 {
		if _, err = attacker.WriteToUDP([]byte("injected"), engineAddr); err != nil {
			t.Fatal(err)
		}
	}

	// The injected datagrams must be dropped and counted, and none of them may
	// reach the host.
	var status Status
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err = json.Unmarshal([]byte(engine.StatusJSON()), &status); err != nil {
			t.Fatal(err)
		}
		if status.RxForeign > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status.RxForeign == 0 {
		t.Fatal("the direct leg accepted datagrams from an off-path sender: " +
			"the gateway filter did not survive the move into directUDPConn")
	}
	if status.RxDatagrams != 0 {
		t.Fatalf("injected datagrams reached the host: rx_datagrams=%d",
			status.RxDatagrams)
	}
}

// TestDirectUDPConnWritesToTheGatewayOnANilAddress pins the other adaptation.
// carrier.Manager calls WriteTo with a nil address because an envelope carrier
// has exactly one destination; a plain UDPConn errors on that, so the leg binds
// the gateway itself. Without this the direct leg would fail on its first write
// and the failure would look like a censor.
func TestDirectUDPConnWritesToTheGatewayOnANilAddress(t *testing.T) {
	gateway := blackHoleGateway(t)
	gatewayAddr := gateway.LocalAddr().(*net.UDPAddr)
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	conn := &directUDPConn{PacketConn: socket, gateway: gatewayAddr}
	defer func() { _ = conn.Close() }()

	if _, err = conn.WriteTo([]byte("nil-addressed"), nil); err != nil {
		t.Fatalf("a nil address must be bound to the gateway: %v", err)
	}
	buffer := make([]byte, 64)
	_ = gateway.SetReadDeadline(time.Now().Add(5 * time.Second))
	count, _, err := gateway.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("gateway did not receive the nil-addressed write: %v", err)
	}
	if string(buffer[:count]) != "nil-addressed" {
		t.Fatalf("gateway received %q", buffer[:count])
	}
}

func TestSameUDPEndpointHandlesMappedAddresses(t *testing.T) {
	gateway := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9110}
	for name, testCase := range map[string]struct {
		sender net.Addr
		want   bool
	}{
		"same v4": {&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9110}, true},
		"v4-mapped v6": {
			&net.UDPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 9110}, true,
		},
		"different port": {
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9111}, false,
		},
		"different address": {
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 9110}, false,
		},
		"not a UDP address": {&net.TCPAddr{
			IP: net.IPv4(127, 0, 0, 1), Port: 9110,
		}, false},
		"nil sender": {nil, false},
	} {
		if got := sameUDPEndpoint(testCase.sender, gateway); got != testCase.want {
			t.Fatalf("%s: sameUDPEndpoint = %v, want %v",
				name, got, testCase.want)
		}
	}
	if sameUDPEndpoint(&net.UDPAddr{}, nil) {
		t.Fatal("a nil gateway must never match")
	}
}

// ---------------------------------------------------------------------------
// 6. Default-off, and lifecycle
// ---------------------------------------------------------------------------

// TestOpenIsUnchangedByTheFailoverAdditions is the byte-identity requirement.
// An engine built the way every existing host builds one must produce the same
// status document it did before this file existed: no escalation key, and no
// key belonging to failover either.
func TestOpenIsUnchangedByTheFailoverAdditions(t *testing.T) {
	gateway := newLoopbackGateway(t)
	socket := newCarrierSocket(t)
	config := testConfig(gateway.LocalAddr())
	blob, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	file, err := socket.File()
	if err != nil {
		t.Fatal(err)
	}
	_ = socket.Close()
	engine, err := Open(blob, int(file.Fd()))
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = engine.Close() }()

	raw := engine.StatusJSON()
	for _, forbidden := range []string{
		"carrier_escalation", "failover", "recommended",
	} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("the default status document gained %q: %s",
				forbidden, raw)
		}
	}
	if _, assessed := engine.AssessEscalation(); assessed {
		t.Fatal("a default engine must compute no verdict")
	}
}

// TestFailoverCloseIsCleanUnderTheRaceDetector runs Close while the supervisor
// is active and status readers are running, which is where a missing wait or an
// unguarded policy read would show up.
func TestFailoverCloseIsCleanUnderTheRaceDetector(t *testing.T) {
	gateway := blackHoleGateway(t)
	successor := newFakeCarrier(t)
	config := failoverConfig(gateway.LocalAddr().String())

	engine, err := openFailover(t, config,
		directCandidate(), h2Candidate(successor))
	if err != nil {
		t.Fatal(err)
	}

	var group sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		group.Add(1)
		go func() {
			defer group.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = engine.StatusJSON()
				_, _ = engine.AssessEscalation()
			}
		}()
	}
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = engine.WriteInbound([]byte("traffic"))
				time.Sleep(time.Millisecond)
			}
		}()
	}
	// Long enough for the supervisor to have concluded blocked and started
	// switching, so Close lands on a live switch rather than an idle loop.
	time.Sleep(1500 * time.Millisecond)
	if err := engine.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	close(stop)
	group.Wait()

	if err := engine.Close(); err != nil {
		t.Fatalf("close must be idempotent: %v", err)
	}
}

func TestFailoverRejectsANilContext(t *testing.T) {
	gateway := blackHoleGateway(t)
	config := failoverConfig(gateway.LocalAddr().String())
	//nolint:staticcheck // deliberately nil: the guard is what is under test.
	if _, err := OpenConfigWithFailover(nil, config, nil); err == nil {
		t.Fatal("a nil context must be refused")
	}
	blob, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	//nolint:staticcheck // deliberately nil.
	if _, err := OpenWithFailover(nil, blob, nil); err == nil {
		t.Fatal("a nil context must be refused by the JSON entry point too")
	}
}

// TestOpenWithFailoverParsesJSON exercises the blob entry point, which is the
// one a host that already holds a serialized configuration will use.
func TestOpenWithFailoverParsesJSON(t *testing.T) {
	gateway := blackHoleGateway(t)
	config := failoverConfig(gateway.LocalAddr().String())
	blob, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	engine, err := OpenWithFailover(ctx, blob, []CarrierCandidate{
		directCandidate(), h2Candidate(newFakeCarrier(t)),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = engine.Close()

	if _, err = OpenWithFailover(ctx, []byte("{"), nil); err == nil {
		t.Fatal("malformed JSON must be refused")
	}
}

func TestFailoverSessionIDFallsBackToAGeneratedOne(t *testing.T) {
	config := failoverConfig("127.0.0.1:9110")
	// The datapath's session ID is opaque and is usually NOT 32 hex characters,
	// which is what mobility requires. The failover path must not fail on that,
	// and must not fabricate a constant that would make two sessions look alike.
	first := failoverSessionID(config)
	if !mobility.ValidSessionID(first) {
		t.Fatalf("generated session ID %q is not valid for mobility", first)
	}
	if second := failoverSessionID(config); second == first {
		t.Fatal("two sessions were given the same generated ID")
	}
	config.SessionID = "0123456789abcdef0123456789abcdef"
	if got := failoverSessionID(config); got != config.SessionID {
		t.Fatalf("a valid configured session ID must be kept, got %q", got)
	}
}

func TestAnyEnvelopeCarrierDecidesCoverTraffic(t *testing.T) {
	directOnly := []carrier.Candidate{
		{Path: mobility.Path{ID: CarrierDirectAWG, Carrier: mobility.DirectUDP}},
	}
	if anyEnvelopeCarrier(directOnly) {
		t.Fatal("a direct-only plan has nothing that can pad")
	}
	mixed := append([]carrier.Candidate(nil), directOnly...)
	mixed = append(mixed, carrier.Candidate{
		Path: mobility.Path{ID: CarrierHTTP2, Carrier: mobility.HTTP2},
	})
	if !anyEnvelopeCarrier(mixed) {
		t.Fatal("a plan containing an envelope carrier must enable cover traffic")
	}
}

func TestContainsString(t *testing.T) {
	plan := []string{CarrierDirectAWG, CarrierHTTP2}
	if !containsString(plan, CarrierHTTP2) {
		t.Fatal("http2 is in the plan")
	}
	if containsString(plan, CarrierHTTP3) {
		t.Fatal("http3 is not in the plan")
	}
	if containsString(nil, CarrierHTTP2) {
		t.Fatal("nothing is in an empty plan")
	}
}

var _ atomic.Uint64

// ---------------------------------------------------------------------------
// 7. The remaining branches, each for its own reason
// ---------------------------------------------------------------------------

// TestDirectDialerDeclaresItsSocketShape covers the interface methods. They
// exist so the direct leg satisfies the same contract the envelope dialers do,
// and their values are load-bearing: a direct leg that claimed to already hold
// a socket would be refused by the very guard that protects the envelope
// carriers.
func TestDirectDialerDeclaresItsSocketShape(t *testing.T) {
	dialer := &directUDPDialer{
		gateway: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9110},
	}
	if kind := dialer.SuppliedSocketKind(); kind != carrier.SocketKindPacket {
		t.Fatalf("the direct leg is a packet socket, reported %q", kind)
	}
	if dialer.HasSuppliedSocket() {
		t.Fatal("the direct leg opens its own socket and never holds a " +
			"supplied one; reporting otherwise would make it look like a " +
			"host-protected descriptor")
	}
}

func TestDirectDialerHonoursACancelledContext(t *testing.T) {
	dialer := &directUDPDialer{
		gateway: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9110},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dialer.Dial(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled dial must not open a socket: %v", err)
	}
}

// TestDirectDialerSurfacesASocketFailure proves the leg does not swallow an
// inability to open a socket. A silently nil conn here would surface much later
// as an unexplained pump error.
func TestDirectDialerSurfacesASocketFailure(t *testing.T) {
	original := socketOpener
	socketOpener = func(string, string) (net.PacketConn, error) {
		return nil, errors.New("no descriptors")
	}
	defer func() { socketOpener = original }()

	dialer := &directUDPDialer{
		gateway: &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9110},
	}
	conn, err := dialer.Dial(context.Background())
	if err == nil {
		t.Fatal("a socket failure must be returned")
	}
	if conn != nil {
		t.Fatal("a failed dial must return no connection")
	}
	if !strings.Contains(err.Error(), "no descriptors") {
		t.Fatalf("the underlying failure was lost: %v", err)
	}
}

// TestPlanCandidatesRefusesAnEndpointlessEnvelopeCarrier: mobility.New requires
// an endpoint on every path, so an empty one would surface as a manager
// construction failure with no indication of which candidate was at fault.
func TestPlanCandidatesRefusesAnEndpointlessEnvelopeCarrier(t *testing.T) {
	gatewayAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820}
	_, _, err := planCandidates(
		[]string{CarrierDirectAWG, CarrierHTTP2},
		[]CarrierCandidate{
			directCandidate(),
			{Carrier: CarrierHTTP2, Dialer: &fakeCarrierDialer{}},
		},
		gatewayAddr,
	)
	if err == nil || !strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("an endpointless candidate must be refused: %v", err)
	}
}

// TestPlanCandidatesRefusesACarrierWithNoDialerInThisBuild covers the branch
// normalizeEscalationPlan makes unreachable. It is reached here by calling
// planCandidates directly, because the guard's whole value is that it stays
// correct if that function ever changes.
func TestPlanCandidatesRefusesACarrierWithNoDialerInThisBuild(t *testing.T) {
	gatewayAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820}
	_, _, err := planCandidates(
		[]string{CarrierDirectAWG, "websocket-tls"},
		[]CarrierCandidate{
			directCandidate(),
			{Carrier: "websocket-tls", Endpoint: "wss://x.invalid/",
				Dialer: &fakeCarrierDialer{}},
		},
		gatewayAddr,
	)
	if !errors.Is(err, ErrEscalationPlanUnusable) {
		t.Fatalf("a carrier with no dialer in this build must be refused: %v",
			err)
	}
}

// TestFailoverReportsWhenNoCarrierBecomesReady is the fail-closed path at
// construction: every candidate refuses, so there is no engine and no socket
// left behind. A partially built engine here would be one holding a Manager
// nobody would ever Close.
func TestFailoverReportsWhenNoCarrierBecomesReady(t *testing.T) {
	gateway := blackHoleGateway(t)
	head := newFakeCarrier(t)
	head.fail.Store(true)
	successor := newFakeCarrier(t)
	successor.fail.Store(true)

	config := failoverConfig(gateway.LocalAddr().String())
	config.Carrier = CarrierHTTP3
	config.Escalation.Plan = []string{CarrierHTTP3, CarrierHTTP2}
	head.kind = carrier.SocketKindPacket

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	engine, err := OpenConfigWithFailover(ctx, config, []CarrierCandidate{
		{
			Carrier:  CarrierHTTP3,
			Endpoint: "https://cdn.example.net/.well-known/masque/udp/{target_host}/{target_port}/",
			Dialer:   head,
		},
		h2Candidate(successor),
	})
	if err == nil {
		_ = engine.Close()
		t.Fatal("no carrier could dial; the open must fail")
	}
	if engine != nil {
		t.Fatal("a failed open must return no engine")
	}
	if !strings.Contains(err.Error(), "no carrier in the plan became ready") {
		t.Fatalf("the failure must name what happened: %v", err)
	}
}

// TestFailoverStopsAtTheEndOfThePlan is the anti-thrash guarantee. When the
// last carrier in the plan is also blocked there is nothing left to recommend,
// and the supervisor must sit still rather than re-switching between exhausted
// candidates once a second for the life of the session.
func TestFailoverStopsAtTheEndOfThePlan(t *testing.T) {
	gateway := blackHoleGateway(t)
	// The successor's peer is a black hole too: it dials fine and then carries
	// nothing, which is the same censor applied to both carriers.
	successor := newFakeCarrier(t)
	config := failoverConfig(gateway.LocalAddr().String())

	engine, err := openFailover(t, config,
		directCandidate(), h2Candidate(successor))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = engine.Close() }()

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := engine.WriteInbound([]byte("initiation")); err != nil {
			t.Fatalf("write inbound: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	assessment, assessed := engine.AssessEscalation()
	if !assessed {
		t.Fatal("escalation stopped reporting")
	}
	if assessment.Carrier != CarrierHTTP2 {
		t.Fatalf("the session should have escalated once, to %q; it is on %q",
			CarrierHTTP2, assessment.Carrier)
	}
	if assessment.Recommended != "" {
		t.Fatalf("the plan is exhausted but %q is still recommended",
			assessment.Recommended)
	}
	// One switch, and only one. Repeated dials would be the supervisor
	// thrashing between exhausted candidates.
	if dials := successor.dials.Load(); dials > 2 {
		t.Fatalf("the supervisor thrashed: %d dials of the last plan entry",
			dials)
	}
}

// ---------------------------------------------------------------------------
// 8. The defensive guards, reached the only way they can be
// ---------------------------------------------------------------------------
//
// The three checks below are unreachable through the exported constructors,
// because Config.normalize has already made them impossible. They are still
// tested, by calling the unexported openWithFailover with a configuration that
// never went through normalize, because that is exactly the situation they
// exist for: a future change to normalize, or a new construction path, must not
// be able to turn a malformed plan into a running engine. An untested guard is
// a guard nobody knows is wired.

func unnormalizedFailoverConfig(gateway string) Config {
	return Config{
		Contract:        ContractVersion,
		Payload:         PayloadAWGDatagram,
		Carrier:         CarrierDirectAWG,
		GatewayEndpoint: gateway,
		MaxDatagram:     1500,
		QueueDepth:      64,
		AllowOwnSocket:  true,
		Escalation: EscalationConfig{
			Mode:         EscalationObserve,
			Plan:         []string{CarrierDirectAWG, CarrierHTTP2},
			MinOutbound:  1,
			BlockAfterMS: 150,
			StallAfterMS: 60_000,
		},
	}
}

func TestFailoverRefusesAnUnresolvableGatewayEndpoint(t *testing.T) {
	config := unnormalizedFailoverConfig("not-an-endpoint")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := openWithFailover(ctx, config, []CarrierCandidate{
		directCandidate(), h2Candidate(newFakeCarrier(t)),
	})
	if err == nil || !strings.Contains(err.Error(), "gateway endpoint") {
		t.Fatalf("an unresolvable gateway must be refused: %v", err)
	}
}

// TestFailoverRefusesAPlanThatWouldDuplicateAMobilityPath covers the manager
// construction guard. A plan naming a carrier twice is refused by
// normalizeEscalationPlan, so this reaches the guard behind it — the one that
// would otherwise let a duplicated path ID reach mobility.New.
func TestFailoverRefusesAPlanThatWouldDuplicateAMobilityPath(t *testing.T) {
	gateway := blackHoleGateway(t)
	config := unnormalizedFailoverConfig(gateway.LocalAddr().String())
	config.Escalation.Plan = []string{
		CarrierDirectAWG, CarrierHTTP2, CarrierHTTP2,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := openWithFailover(ctx, config, []CarrierCandidate{
		directCandidate(), h2Candidate(newFakeCarrier(t)),
	})
	if err == nil || !strings.Contains(err.Error(), "failover manager") {
		t.Fatalf("a plan that duplicates a mobility path must be refused: %v",
			err)
	}
}

// TestFailoverSessionIDGeneratorFailureIsNotPaperedOver. A fabricated constant
// here would make every session on a device look like the same session to the
// mobility engine, so the failure must propagate as an empty string that
// mobility.New refuses with a clear message rather than being defaulted.
func TestFailoverSessionIDGeneratorFailureIsNotPaperedOver(t *testing.T) {
	original := sessionIDGenerator
	sessionIDGenerator = func() (string, error) {
		return "", errors.New("no entropy")
	}
	defer func() { sessionIDGenerator = original }()

	config := unnormalizedFailoverConfig("127.0.0.1:51820")
	if got := failoverSessionID(config); got != "" {
		t.Fatalf("a failed generator must not fabricate an ID, got %q", got)
	}
	// And the engine must refuse to start rather than run with it.
	gateway := blackHoleGateway(t)
	config.GatewayEndpoint = gateway.LocalAddr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := openWithFailover(ctx, config, []CarrierCandidate{
		directCandidate(), h2Candidate(newFakeCarrier(t)),
	})
	if err == nil || !strings.Contains(err.Error(), "failover manager") {
		t.Fatalf("an engine must not start without a session ID: %v", err)
	}
}
