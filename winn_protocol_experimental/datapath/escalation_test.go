package datapath

// Tests for carrier escalation.
//
// The argument these tests carry, in the order the file makes it:
//
//  1. A carrier's IP transport is stated in code, so "does this survive a UDP
//     block" is answered by the package rather than by a reader's guess.
//  2. A plan that does NOT survive a UDP block is refused at configuration
//     time. This is the test that stops the whole feature from being a
//     decoration: direct-awg -> http3-connect-udp looks like a fallback and is
//     not one, because both ride UDP.
//  3. The verdict reproduces the measured defect — scenario B, datagrams
//     leaving and nothing returning — and distinguishes it from a link that
//     worked and then went quiet.
//  4. Off is genuinely off: an engine whose configuration does not name
//     carrier_escalation emits a status document with no escalation key at
//     all, byte for byte.

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func escalatingConfig(gateway string) Config {
	return Config{
		Contract:        ContractVersion,
		Payload:         PayloadAWGDatagram,
		Carrier:         CarrierDirectAWG,
		GatewayEndpoint: gateway,
		SessionID:       "escalation-test",
		Escalation: EscalationConfig{
			Mode: EscalationObserve,
			Plan: []string{CarrierDirectAWG, CarrierHTTP2},
		},
	}
}

// TestCarrierTransportIsStatedForEveryCarrierThatHasADialer pins the mapping
// the whole file rests on. http3-connect-udp being UDP is the entry that most
// needs to be explicit: it is the carrier a reader is most likely to assume is
// an alternative to direct-awg under a censor, and it is not one.
func TestCarrierTransportIsStatedForEveryCarrierThatHasADialer(t *testing.T) {
	for _, testCase := range []struct {
		carrier   string
		transport CarrierTransport
		survives  bool
	}{
		{CarrierDirectAWG, TransportUDP, false},
		{CarrierHTTP3, TransportUDP, false},
		{CarrierHTTP2, TransportTCP, true},
		// The four carriers config.go refuses as unimplemented. They are
		// deliberately unknown rather than guessed at from their names.
		{"websocket-tls", TransportUnknown, false},
		{"reality-xhttp", TransportUnknown, false},
		{"native-two-hop", TransportUnknown, false},
		{"privacy-two-hop", TransportUnknown, false},
		{"", TransportUnknown, false},
		{"totally-made-up", TransportUnknown, false},
	} {
		t.Run(testCase.carrier, func(t *testing.T) {
			if got := CarrierTransportOf(testCase.carrier); got != testCase.transport {
				t.Fatalf("CarrierTransportOf(%q) = %v, want %v",
					testCase.carrier, got, testCase.transport)
			}
			if got := CarrierSurvivesUDPBlock(testCase.carrier); got != testCase.survives {
				t.Fatalf("CarrierSurvivesUDPBlock(%q) = %v, want %v",
					testCase.carrier, got, testCase.survives)
			}
		})
	}
	if got := TransportUnknown.String(); got != "unknown" {
		t.Fatalf("TransportUnknown.String() = %q", got)
	}
	if got := TransportUDP.String(); got != "udp" {
		t.Fatalf("TransportUDP.String() = %q", got)
	}
	if got := TransportTCP.String(); got != "tcp" {
		t.Fatalf("TransportTCP.String() = %q", got)
	}
}

// TestPlanWithNoUDPSurvivingSuccessorIsRefused is the load-bearing validation
// test. Both refused plans below would pass every other check in the file.
func TestPlanWithNoUDPSurvivingSuccessorIsRefused(t *testing.T) {
	for name, plan := range map[string][]string{
		"only the carrier in use": {CarrierDirectAWG},
		"udp then more udp":       {CarrierDirectAWG, CarrierHTTP3},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewEscalationPolicy(EscalationConfig{
				Mode: EscalationObserve, Plan: plan,
			}, CarrierDirectAWG)
			if plan[len(plan)-1] == CarrierHTTP3 {
				// The shelved-target rule fires first for this one, which is
				// the stricter and more informative refusal of the two.
				if !errors.Is(err, ErrEscalationTargetShelved) {
					t.Fatalf("plan %v: err = %v, want ErrEscalationTargetShelved",
						plan, err)
				}
				return
			}
			if !errors.Is(err, ErrEscalationPlanAllUDP) {
				t.Fatalf("plan %v: err = %v, want ErrEscalationPlanAllUDP",
					plan, err)
			}
		})
	}
}

// TestHTTP3IsLegalAsAPlanHeadAndIllegalAsATarget encodes the runbook's ruling
// precisely. The distinction matters: a session may legitimately be RUNNING on
// http3-connect-udp for mobility and still deserve a verdict about it, but
// nothing may ESCALATE to it under a censor.
func TestHTTP3IsLegalAsAPlanHeadAndIllegalAsATarget(t *testing.T) {
	if _, err := NewEscalationPolicy(EscalationConfig{
		Mode: EscalationObserve,
		Plan: []string{CarrierHTTP3, CarrierHTTP2},
	}, CarrierHTTP3); err != nil {
		t.Fatalf("http3 as plan head: unexpected error %v", err)
	}
	_, err := NewEscalationPolicy(EscalationConfig{
		Mode: EscalationObserve,
		Plan: []string{CarrierDirectAWG, CarrierHTTP2, CarrierHTTP3},
	}, CarrierDirectAWG)
	if !errors.Is(err, ErrEscalationTargetShelved) {
		t.Fatalf("http3 as target: err = %v, want ErrEscalationTargetShelved", err)
	}
}

func TestPlanValidationRefusesMalformedPlans(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		mode    EscalationMode
		plan    []string
		carrier string
		want    error
	}{
		{
			name: "unknown mode", mode: "aggressive",
			plan:    []string{CarrierDirectAWG, CarrierHTTP2},
			carrier: CarrierDirectAWG, want: ErrEscalationModeUnknown,
		},
		{
			name: "observe with no plan", mode: EscalationObserve,
			plan: nil, carrier: CarrierDirectAWG,
			want: ErrEscalationPlanRequired,
		},
		{
			name:    "plan does not start with the carrier in use",
			mode:    EscalationObserve,
			plan:    []string{CarrierHTTP2, CarrierDirectAWG},
			carrier: CarrierDirectAWG, want: ErrEscalationPlanHead,
		},
		{
			name: "duplicate entry", mode: EscalationObserve,
			plan:    []string{CarrierDirectAWG, CarrierHTTP2, CarrierHTTP2},
			carrier: CarrierDirectAWG, want: ErrEscalationPlanDuplicate,
		},
		{
			name: "unimplemented carrier as target", mode: EscalationObserve,
			plan:    []string{CarrierDirectAWG, "websocket-tls"},
			carrier: CarrierDirectAWG, want: ErrEscalationPlanUnusable,
		},
		{
			name: "unknown carrier as target", mode: EscalationObserve,
			plan:    []string{CarrierDirectAWG, "carrier-pigeon"},
			carrier: CarrierDirectAWG, want: ErrEscalationPlanUnusable,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewEscalationPolicy(EscalationConfig{
				Mode: testCase.mode, Plan: testCase.plan,
			}, testCase.carrier)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("err = %v, want %v", err, testCase.want)
			}
		})
	}
}

func TestPlanValidationRefusesEmptyEntriesAndOverlongPlans(t *testing.T) {
	_, err := NewEscalationPolicy(EscalationConfig{
		Mode: EscalationObserve,
		Plan: []string{CarrierDirectAWG, "   "},
	}, CarrierDirectAWG)
	if err == nil || !strings.Contains(err.Error(), "entry 1 is empty") {
		t.Fatalf("blank entry: err = %v, want an empty-entry refusal", err)
	}

	overlong := make([]string, MaxEscalationPlan+1)
	for index := range overlong {
		overlong[index] = CarrierDirectAWG
	}
	_, err = NewEscalationPolicy(EscalationConfig{
		Mode: EscalationObserve, Plan: overlong,
	}, CarrierDirectAWG)
	if err == nil || !strings.Contains(err.Error(), "maximum is") {
		t.Fatalf("overlong plan: err = %v, want a length refusal", err)
	}
}

// TestOffModeStillValidatesAPlanItIsGiven is the staging property: a fleet can
// ship the plan in one release and enable it in the next without discovering
// at THAT moment that the plan was malformed all along.
func TestOffModeStillValidatesAPlanItIsGiven(t *testing.T) {
	_, err := NewEscalationPolicy(EscalationConfig{
		Mode: EscalationOff,
		Plan: []string{CarrierDirectAWG, CarrierHTTP3},
	}, CarrierDirectAWG)
	if !errors.Is(err, ErrEscalationTargetShelved) {
		t.Fatalf("err = %v, want the plan validated even when off", err)
	}

	policy, err := NewEscalationPolicy(EscalationConfig{}, CarrierDirectAWG)
	if err != nil {
		t.Fatalf("absent escalation must normalize: %v", err)
	}
	if policy.Active() || policy.Mode() != EscalationOff {
		t.Fatalf("absent escalation must be inactive and off, got %v/%v",
			policy.Active(), policy.Mode())
	}
}

func TestNormalizeFillsDefaultsAndRefusesNegativeBudgets(t *testing.T) {
	normalized, err := EscalationConfig{
		Mode: EscalationObserve,
		Plan: []string{CarrierDirectAWG, CarrierHTTP2},
	}.normalize(CarrierDirectAWG)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if normalized.MinOutbound != DefaultMinOutbound {
		t.Fatalf("MinOutbound = %d, want %d",
			normalized.MinOutbound, DefaultMinOutbound)
	}
	if normalized.BlockAfterMS != DefaultBlockAfter.Milliseconds() {
		t.Fatalf("BlockAfterMS = %d, want %d",
			normalized.BlockAfterMS, DefaultBlockAfter.Milliseconds())
	}
	if normalized.StallAfterMS != DefaultStallAfter.Milliseconds() {
		t.Fatalf("StallAfterMS = %d, want %d",
			normalized.StallAfterMS, DefaultStallAfter.Milliseconds())
	}
	// The stall budget must stay comfortably above the measured 25 s keepalive
	// metronome, or a single lost keepalive becomes a false stall on a live
	// tunnel. Asserted rather than left to the constant's comment.
	if DefaultStallAfter < 3*25*time.Second {
		t.Fatalf("DefaultStallAfter %s is under three keepalive intervals",
			DefaultStallAfter)
	}

	for _, bad := range []EscalationConfig{
		{Mode: EscalationObserve, BlockAfterMS: -1,
			Plan: []string{CarrierDirectAWG, CarrierHTTP2}},
		{Mode: EscalationObserve, StallAfterMS: -1,
			Plan: []string{CarrierDirectAWG, CarrierHTTP2}},
	} {
		if _, err := bad.normalize(CarrierDirectAWG); err == nil {
			t.Fatalf("negative budget accepted: %+v", bad)
		}
	}
}

// TestVerdictReproducesTheMeasuredUDPBlock walks the exact shape of scenario B
// from WINN3_OVER_THE_STEALTH_LEG_MEASURED_AND_THE_FOUR_REFUSALS_20260807.md
// §3: datagrams leave, nothing returns, forever.
func TestVerdictReproducesTheMeasuredUDPBlock(t *testing.T) {
	policy, err := NewEscalationPolicy(EscalationConfig{
		Mode: EscalationObserve,
		Plan: []string{CarrierDirectAWG, CarrierHTTP2},
	}, CarrierDirectAWG)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	// Before the budget is spent nothing may be claimed, however many
	// datagrams have left.
	early := policy.Evaluate(LinkObservation{
		Elapsed: 2 * time.Second, Outbound: 24,
	})
	if early.Verdict != VerdictPending {
		t.Fatalf("early verdict = %q, want pending", early.Verdict)
	}
	if early.Recommended != "" {
		t.Fatalf("pending must recommend nothing, got %q", early.Recommended)
	}

	// Scenario B proper: 24 initiations over two minutes, zero received.
	blocked := policy.Evaluate(LinkObservation{
		Elapsed: 120 * time.Second, Outbound: 24,
	})
	if blocked.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %q, want blocked (%s)", blocked.Verdict, blocked.Reason)
	}
	if blocked.Recommended != CarrierHTTP2 {
		t.Fatalf("recommended = %q, want %q", blocked.Recommended, CarrierHTTP2)
	}
	if !blocked.RecommendedSurvivesUDPBlock {
		t.Fatal("the recommendation must survive the block that triggered it")
	}
	if blocked.Transport != "udp" || blocked.Carrier != CarrierDirectAWG {
		t.Fatalf("assessment mislabels the carrier: %+v", blocked)
	}
	if !strings.Contains(blocked.Reason, "not one") {
		t.Fatalf("reason must state the evidence, got %q", blocked.Reason)
	}
}

func TestVerdictBoundariesRequireBothBudgets(t *testing.T) {
	policy, err := NewEscalationPolicy(EscalationConfig{
		Mode:         EscalationObserve,
		Plan:         []string{CarrierDirectAWG, CarrierHTTP2},
		MinOutbound:  3,
		BlockAfterMS: 9000,
	}, CarrierDirectAWG)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	for _, testCase := range []struct {
		name        string
		observation LinkObservation
		want        Verdict
	}{
		{
			name: "time spent but too few datagrams",
			observation: LinkObservation{
				Elapsed: 60 * time.Second, Outbound: 2,
			},
			want: VerdictPending,
		},
		{
			name: "datagrams sent but time not spent",
			observation: LinkObservation{
				Elapsed: 8999 * time.Millisecond, Outbound: 300,
			},
			want: VerdictPending,
		},
		{
			name: "both budgets exactly met",
			observation: LinkObservation{
				Elapsed: 9 * time.Second, Outbound: 3,
			},
			want: VerdictBlocked,
		},
		{
			name: "an idle tunnel that sent nothing is never blocked",
			observation: LinkObservation{
				Elapsed: time.Hour, Outbound: 0,
			},
			want: VerdictPending,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got := policy.Evaluate(testCase.observation)
			if got.Verdict != testCase.want {
				t.Fatalf("verdict = %q, want %q (%s)",
					got.Verdict, testCase.want, got.Reason)
			}
		})
	}
}

// TestHealthyAndStalledAreDistinguished is the property that keeps a working
// tunnel from being torn down. A link that has received anything recently is
// healthy no matter what the other numbers say.
func TestHealthyAndStalledAreDistinguished(t *testing.T) {
	policy, err := NewEscalationPolicy(EscalationConfig{
		Mode: EscalationObserve,
		Plan: []string{CarrierDirectAWG, CarrierHTTP2},
	}, CarrierDirectAWG)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	healthy := policy.Evaluate(LinkObservation{
		Elapsed:     10 * time.Minute,
		Outbound:    10000,
		InboundSeen: true,
		// One missed keepalive. Ordinary, and must not be a stall.
		SinceInbound: 26 * time.Second,
	})
	if healthy.Verdict != VerdictHealthy {
		t.Fatalf("verdict = %q, want healthy (%s)", healthy.Verdict, healthy.Reason)
	}
	if healthy.Recommended != "" {
		t.Fatalf("a healthy link must recommend nothing, got %q",
			healthy.Recommended)
	}

	stalled := policy.Evaluate(LinkObservation{
		Elapsed:      10 * time.Minute,
		Outbound:     10000,
		InboundSeen:  true,
		SinceInbound: DefaultStallAfter + time.Second,
	})
	if stalled.Verdict != VerdictStalled {
		t.Fatalf("verdict = %q, want stalled (%s)", stalled.Verdict, stalled.Reason)
	}
	if stalled.Recommended != CarrierHTTP2 {
		t.Fatalf("recommended = %q, want %q", stalled.Recommended, CarrierHTTP2)
	}

	// Exactly at the budget is still healthy: the comparison is <=, so a
	// carrier is given the whole budget rather than all but an instant of it.
	edge := policy.Evaluate(LinkObservation{
		Elapsed: time.Hour, Outbound: 10, InboundSeen: true,
		SinceInbound: DefaultStallAfter,
	})
	if edge.Verdict != VerdictHealthy {
		t.Fatalf("verdict at the budget = %q, want healthy", edge.Verdict)
	}
}

// TestSuccessorIsEmptyAtTheEndOfThePlan proves the verdict still lands when
// there is nothing left to recommend. A blocked carrier at the end of the plan
// is a real and reportable state, not an error.
func TestSuccessorIsEmptyAtTheEndOfThePlan(t *testing.T) {
	policy, err := NewEscalationPolicy(EscalationConfig{
		Mode: EscalationObserve,
		Plan: []string{CarrierDirectAWG, CarrierHTTP2},
	}, CarrierDirectAWG)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	// Evaluate as though the session had already escalated onto the tail
	// entry. Reaching into the unexported field is deliberate: the plan is
	// validated against the carrier the session STARTED on, so there is no
	// exported way to construct "already on the last carrier", and that state
	// is exactly what this test is about.
	policy.carrier = CarrierHTTP2
	assessment := policy.Evaluate(LinkObservation{
		Elapsed: time.Minute, Outbound: 50,
	})
	if assessment.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %q, want blocked", assessment.Verdict)
	}
	if assessment.Recommended != "" {
		t.Fatalf("recommended = %q, want empty at the end of the plan",
			assessment.Recommended)
	}
	if assessment.RecommendedSurvivesUDPBlock {
		t.Fatal("no recommendation cannot survive anything")
	}
}

func TestPlanAccessorReturnsACopy(t *testing.T) {
	policy, err := NewEscalationPolicy(EscalationConfig{
		Mode: EscalationObserve,
		Plan: []string{CarrierDirectAWG, CarrierHTTP2},
	}, CarrierDirectAWG)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	plan := policy.Plan()
	plan[0] = "tampered"
	if policy.Plan()[0] != CarrierDirectAWG {
		t.Fatal("Plan() must not expose the policy's own slice")
	}
}

// TestDefaultConfigEmitsNoEscalationKey is the byte-identity guarantee. An
// existing node's status document must be exactly what it was.
func TestDefaultConfigEmitsNoEscalationKey(t *testing.T) {
	gateway := newLoopbackGateway(t)
	engine, err := OpenWithPacketConn(
		testConfig(gateway.LocalAddr()), newCarrierSocket(t),
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	raw := engine.StatusJSON()
	if strings.Contains(raw, "carrier_escalation") {
		t.Fatalf("default status must carry no escalation key:\n%s", raw)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("status is not JSON: %v", err)
	}
	if _, present := decoded["carrier_escalation"]; present {
		t.Fatal("default status must not contain carrier_escalation")
	}
	if assessment, assessed := engine.AssessEscalation(); assessed {
		t.Fatalf("default engine must assess nothing, got %+v", assessment)
	}
}

// TestObserveModeSurfacesTheVerdictInStatus is the other half: once a node
// opts in, the verdict is there for a host to read.
func TestObserveModeSurfacesTheVerdictInStatus(t *testing.T) {
	gateway := newLoopbackGateway(t)
	config := escalatingConfig(gateway.LocalAddr().String())
	normalized, err := config.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	engine, err := OpenWithPacketConn(normalized, newCarrierSocket(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	status := engine.Status()
	if status.Escalation == nil {
		t.Fatal("observe mode must publish an escalation assessment")
	}
	// A fresh engine has sent nothing, so the only honest verdict is pending.
	if status.Escalation.Verdict != VerdictPending {
		t.Fatalf("fresh engine verdict = %q, want pending",
			status.Escalation.Verdict)
	}
	if status.Escalation.Carrier != CarrierDirectAWG ||
		status.Escalation.Transport != "udp" {
		t.Fatalf("assessment mislabels the carrier: %+v", status.Escalation)
	}
	if !strings.Contains(engine.StatusJSON(), "carrier_escalation") {
		t.Fatal("observe mode status JSON must carry the escalation key")
	}
}

// TestEngineObservationMapsCountersToWireDirection guards the one place a
// reader is most likely to get it backwards: the engine's "inbound" counter is
// what LEAVES this machine.
func TestEngineObservationMapsCountersToWireDirection(t *testing.T) {
	gateway := newLoopbackGateway(t)
	config := escalatingConfig(gateway.LocalAddr().String())
	normalized, err := config.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	engine, err := OpenWithPacketConn(normalized, newCarrierSocket(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	for range 5 {
		if _, err := engine.WriteInbound([]byte("datagram-to-gateway")); err != nil {
			t.Fatalf("WriteInbound: %v", err)
		}
	}
	observation := engine.observeLink(time.Now().UTC())
	if observation.Outbound != 5 {
		t.Fatalf("Outbound = %d, want the 5 datagrams that left",
			observation.Outbound)
	}
	if observation.InboundSeen {
		t.Fatal("InboundSeen = true; nothing has answered")
	}
	if observation.SinceInbound != 0 {
		t.Fatalf("SinceInbound = %s, want 0 when nothing has arrived",
			observation.SinceInbound)
	}
	if observation.Elapsed < 0 {
		t.Fatalf("Elapsed = %s, must never be negative", observation.Elapsed)
	}
}

// TestReceivedDatagramMakesTheLinkHealthy closes the loop through a real
// socket: a gateway that answers moves the verdict off pending and populates
// the last-received clock, which is the field that separates blocked from
// stalled. Everything above this test drives the policy directly; this one
// proves the engine feeds it correctly.
func TestReceivedDatagramMakesTheLinkHealthy(t *testing.T) {
	gateway := newLoopbackGateway(t)
	config := escalatingConfig(gateway.LocalAddr().String())
	normalized, err := config.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	socket := newCarrierSocket(t)
	engine, err := OpenWithPacketConn(normalized, socket)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	// Send one out so the gateway learns our address, then answer it.
	if _, err := engine.WriteInbound([]byte("hello-gateway")); err != nil {
		t.Fatalf("WriteInbound: %v", err)
	}
	buffer := make([]byte, 2048)
	if err := gateway.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, from, err := gateway.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("gateway read: %v", err)
	}
	if _, err := gateway.WriteToUDP([]byte("answer"), from); err != nil {
		t.Fatalf("gateway write: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		observation := engine.observeLink(time.Now().UTC())
		if observation.InboundSeen {
			if observation.SinceInbound < 0 {
				t.Fatalf("SinceInbound = %s, must never be negative",
					observation.SinceInbound)
			}
			assessment, assessed := engine.AssessEscalation()
			if !assessed {
				t.Fatal("observe mode must assess")
			}
			if assessment.Verdict != VerdictHealthy {
				t.Fatalf("verdict = %q, want healthy (%s)",
					assessment.Verdict, assessment.Reason)
			}
			if assessment.Recommended != "" {
				t.Fatalf("a healthy link must recommend nothing, got %q",
					assessment.Recommended)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("gateway answer never reached the engine")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestParseConfigRejectsAnInvalidPlan proves the validation is reachable from
// the JSON entry point a host actually uses, not only from the Go constructor.
func TestParseConfigRejectsAnInvalidPlan(t *testing.T) {
	blob := []byte(`{
		"contract": "` + ContractVersion + `",
		"payload": "` + PayloadAWGDatagram + `",
		"carrier": "` + CarrierDirectAWG + `",
		"gateway_endpoint": "127.0.0.1:9110",
		"carrier_escalation": {
			"mode": "observe",
			"plan": ["` + CarrierDirectAWG + `", "` + CarrierHTTP3 + `"]
		}
	}`)
	if _, err := ParseConfig(blob); !errors.Is(err, ErrEscalationTargetShelved) {
		t.Fatalf("ParseConfig err = %v, want ErrEscalationTargetShelved", err)
	}

	good := []byte(`{
		"contract": "` + ContractVersion + `",
		"payload": "` + PayloadAWGDatagram + `",
		"carrier": "` + CarrierDirectAWG + `",
		"gateway_endpoint": "127.0.0.1:9110",
		"carrier_escalation": {
			"mode": "observe",
			"plan": ["` + CarrierDirectAWG + `", "` + CarrierHTTP2 + `"]
		}
	}`)
	parsed, err := ParseConfig(good)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if parsed.Escalation.Mode != EscalationObserve {
		t.Fatalf("mode = %q, want observe", parsed.Escalation.Mode)
	}
	if parsed.Escalation.MinOutbound != DefaultMinOutbound {
		t.Fatalf("defaults were not filled: %+v", parsed.Escalation)
	}
}

// TestConfigWithoutEscalationKeyStillParses is the compatibility test: every
// configuration written before this field existed must behave as it did.
func TestConfigWithoutEscalationKeyStillParses(t *testing.T) {
	blob := []byte(`{
		"contract": "` + ContractVersion + `",
		"payload": "` + PayloadAWGDatagram + `",
		"carrier": "` + CarrierDirectAWG + `",
		"gateway_endpoint": "127.0.0.1:9110"
	}`)
	parsed, err := ParseConfig(blob)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if parsed.Escalation.Mode != EscalationOff {
		t.Fatalf("mode = %q, want off", parsed.Escalation.Mode)
	}
	if len(parsed.Escalation.Plan) != 0 {
		t.Fatalf("plan = %v, want empty", parsed.Escalation.Plan)
	}
	if parsed.Escalation.MinOutbound != 0 || parsed.Escalation.BlockAfterMS != 0 {
		t.Fatalf("an absent escalation must stay entirely zero: %+v",
			parsed.Escalation)
	}
}

// TestConcurrentStatusAndTrafficIsRaceFree exercises the new atomic under -race
// together with the readers that consume it.
func TestConcurrentStatusAndTrafficIsRaceFree(t *testing.T) {
	gateway := newLoopbackGateway(t)
	config := escalatingConfig(gateway.LocalAddr().String())
	normalized, err := config.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	engine, err := OpenWithPacketConn(normalized, newCarrierSocket(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	var waitGroup sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = engine.StatusJSON()
					_, _ = engine.AssessEscalation()
				}
			}
		}()
	}
	for range 2 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = engine.WriteInbound([]byte("concurrent"))
				}
			}
		}()
	}
	time.Sleep(150 * time.Millisecond)
	close(stop)
	waitGroup.Wait()
}
