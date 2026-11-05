package datapath

// Carrier escalation: v3's own answer to a censor that drops UDP.
//
// # The defect this exists to close
//
// WINN3_OVER_THE_STEALTH_LEG_MEASURED_AND_THE_FOUR_REFUSALS_20260807.md §3
// measured a netns rig whose censor is one line, `-p udp -j DROP`. Scenario B
// is v3 on its only proven carrier: 24 handshake initiations leave, none is
// answered, the session never acquires a peer, 100% loss. The datapath sat in
// that state indefinitely and reported nothing an orchestrator could act on.
//
// The reason is structural rather than accidental, and it is worth naming
// because it is what this file changes:
//
//   - Open builds exactly one carrier and refuses every other (engine.go, the
//     `config.Carrier != CarrierDirectAWG` guard), and OpenWithCarrier builds
//     exactly the one carrier the configuration names (carrier.go,
//     suppliedSocketCarriers lookup). Neither has a second attempt.
//   - Both return as soon as the pump goroutine starts. Nothing in the package
//     ever decides that a carrier has failed, so there is no failure for a
//     caller to observe and no successor for it to try.
//
// So v3 had no equivalent of the decision that keeps v1 alive under the same
// censor. This file supplies the missing half that belongs in the datapath: a
// verdict on whether the current carrier is carrying anything, and an ordered
// plan naming which of v3's own carriers to try next. It does not perform the
// switch — see "What this deliberately does not do" below.
//
// # Carrier-neutral by construction
//
// The evidence this file reads is datagram counts and clock readings. It reads
// no header, classifies no packet and names no inner protocol. That is a
// deliberate constraint, not an accident of what was easy:
//
// The engine also maintains richer counters — TxHandshakeInitiations and
// RxHandshakeResponses — and they describe scenario B more precisely than
// datagram totals do. They are NOT used here, because they are produced by
// classify.go, which is a reader of AmneziaWG header types and prefix padding
// (classify.go: "Winn carries these datagrams; it does not hold the keys and
// cannot verify a single one of them"). Building the escalation verdict on
// those counters would give a component whose whole purpose is v3's transport
// independence a dependency on the protocol v3 is replacing, and would require
// rewriting it when classify.go goes. Datagram totals and elapsed time mean the
// same thing under any inner protocol, so this file is finished rather than
// pending.
//
// # What this deliberately does not do
//
// It does not switch carriers. A switch tears down a live socket and builds
// another, and on three of five platforms the replacement socket must be opened
// and protected by the HOST before the datapath may touch it (carrier.go's
// socket rule). A datapath that reconnected itself would be opening sockets the
// host never protected, which is the class of bug that routes the outer traffic
// back into the tunnel. So this file produces a verdict and a recommendation;
// acting on it stays with the caller that owns the sockets.
//
// EscalationOff is the default and, in that mode, this file reads nothing,
// allocates nothing and adds no field to Status. An existing node that does not
// name carrier_escalation in its configuration is byte-for-byte unchanged.

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// EscalationMode selects how much of this machinery runs.
type EscalationMode string

const (
	// EscalationOff is the default and the mode every existing configuration
	// gets. No verdict is computed, no plan is validated beyond the emptiness
	// check, and Status carries no escalation object at all — so the status
	// document an existing host parses is unchanged to the byte.
	EscalationOff EscalationMode = "off"

	// EscalationObserve computes the verdict and publishes it in Status,
	// changing nothing else. The carrier in use, the socket, and every datagram
	// on the wire are identical to EscalationOff; the only difference is that a
	// host can now read what the datapath concluded and decide for itself.
	//
	// This is the mode a fleet turns on first, because it answers "how often
	// does this actually happen, and to whom" with evidence rather than with
	// the single netns run that motivated the file.
	EscalationObserve EscalationMode = "observe"
)

// Verdict is what the datapath concluded about the carrier it is using.
type Verdict string

const (
	// VerdictPending means not enough has happened yet to say anything. A fresh
	// engine is always pending; so is one that has not yet spent the policy's
	// budget.
	VerdictPending Verdict = "pending"

	// VerdictHealthy means datagrams have arrived from the far side and the
	// link has not since gone quiet for longer than the policy allows.
	VerdictHealthy Verdict = "healthy"

	// VerdictBlocked means datagrams left, nothing ever came back, and the
	// budget is spent. This is scenario B exactly: the carrier has never
	// carried anything in either direction and waiting longer has not helped.
	VerdictBlocked Verdict = "blocked"

	// VerdictStalled means the link WAS carrying traffic and then stopped for
	// longer than the policy allows. It is kept distinct from VerdictBlocked
	// because the two have different causes and deserve different responses: a
	// blocked carrier was never viable on this network and escalating is
	// right, whereas a stalled one may be a handover, a suspend, or a censor
	// that switched on mid-session.
	VerdictStalled Verdict = "stalled"
)

// CarrierTransport is the IP transport a carrier rides on. It is the only
// property that decides whether a carrier can survive a censor who drops UDP,
// so it is stated in code rather than left implicit in the carrier's name.
type CarrierTransport uint8

const (
	// TransportUnknown is returned for any carrier this package cannot place.
	TransportUnknown CarrierTransport = iota
	TransportUDP
	TransportTCP
)

// String renders the transport for status and error messages.
func (transport CarrierTransport) String() string {
	switch transport {
	case TransportUDP:
		return "udp"
	case TransportTCP:
		return "tcp"
	default:
		return "unknown"
	}
}

// CarrierTransportOf reports which IP transport a carrier rides.
//
// Only the three carriers that have a dialer are placed. The four names
// config.go refuses as unimplemented are deliberately left TransportUnknown
// rather than guessed at from their names: a plan is validated against what
// exists in code, and a carrier with no dialer cannot be escalated to whatever
// its name suggests it would ride on.
func CarrierTransportOf(name string) CarrierTransport {
	switch name {
	case CarrierDirectAWG:
		// Raw UDP datagrams to the gateway endpoint.
		return TransportUDP
	case CarrierHTTP3:
		// HTTP/3 CONNECT-UDP is QUIC, which is UDP. A censor who drops UDP
		// takes this down exactly as it takes down direct-awg; the two are not
		// alternatives to each other against this adversary.
		return TransportUDP
	case CarrierHTTP2:
		// A single long-lived HTTP/2 stream over TLS over TCP. The only carrier
		// in the list that a UDP drop does not touch.
		return TransportTCP
	default:
		return TransportUnknown
	}
}

// CarrierSurvivesUDPBlock reports whether a carrier still works when the
// network drops UDP. An unknown carrier is reported as not surviving, because
// the safe default for "we cannot tell" is not to promise survival.
func CarrierSurvivesUDPBlock(name string) bool {
	return CarrierTransportOf(name) == TransportTCP
}

var (
	// ErrEscalationModeUnknown is returned for a mode this package does not
	// implement. It is deliberately not tolerant: a host that misspells
	// "observe" must learn immediately rather than silently get "off" and
	// believe it is collecting evidence it is not collecting.
	ErrEscalationModeUnknown = errors.New(
		"winn datapath carrier escalation mode is unknown: use " +
			string(EscalationOff) + " or " + string(EscalationObserve),
	)

	// ErrEscalationPlanRequired is returned when observe mode is selected with
	// no plan. Observing without a plan would produce a verdict naming no
	// successor, which is a diagnosis nobody can act on.
	ErrEscalationPlanRequired = errors.New(
		"winn datapath carrier escalation plan is required in " +
			string(EscalationObserve) + " mode",
	)

	// ErrEscalationPlanHead is returned when the plan does not begin with the
	// carrier the configuration actually selected. The plan describes what to
	// do about THIS session, so its first entry is the carrier this session is
	// using; a plan starting elsewhere would report progress through a sequence
	// the session is not in.
	ErrEscalationPlanHead = errors.New(
		"winn datapath carrier escalation plan must begin with the " +
			"configured carrier",
	)

	// ErrEscalationPlanDuplicate is returned for a plan naming a carrier twice.
	// Retrying a carrier that already failed is a loop, not an escalation.
	ErrEscalationPlanDuplicate = errors.New(
		"winn datapath carrier escalation plan names a carrier twice",
	)

	// ErrEscalationPlanUnusable is returned for a plan entry that has no dialer
	// in this build — both genuinely unknown names and the four that config.go
	// refuses as unimplemented. Naming one would produce a recommendation the
	// caller cannot honour.
	ErrEscalationPlanUnusable = errors.New(
		"winn datapath carrier escalation plan names a carrier with no dialer",
	)

	// ErrEscalationTargetShelved is returned when http3-connect-udp appears as
	// an escalation TARGET.
	//
	// CONSOLIDATED_ROLLOUT_RUNBOOK_20260807.md shelved it as a
	// censorship-bypass transport and kept the code as a mobility component:
	// QUIC on UDP/443 cannot be CDN-fronted, so it re-exposes the node's real
	// address, and its own contract disclaims the censorship claim. Escalating
	// to it under a censor is therefore doubly wrong — it is UDP, so it does
	// not survive the block that triggered the escalation, and reaching for it
	// under censorship is the use the runbook shelved.
	//
	// It stays legal as a plan HEAD, because a session may legitimately be
	// running on it for mobility and still want a verdict about it.
	ErrEscalationTargetShelved = errors.New(
		"winn datapath carrier escalation plan escalates to " + CarrierHTTP3 +
			", which the rollout runbook shelved as a censorship transport " +
			"and which rides UDP in any case",
	)

	// ErrEscalationPlanAllUDP is returned when no entry after the head can
	// survive a UDP block.
	//
	// This is the check that stops this file from being decoration. A plan of
	// direct-awg then http3-connect-udp looks like resilience and provides
	// none: both ride UDP, so the single iptables line that killed the first
	// kills the second. Refusing it at configuration time is the difference
	// between a fallback and the appearance of one.
	ErrEscalationPlanAllUDP = errors.New(
		"winn datapath carrier escalation plan has no carrier that survives " +
			"a UDP block: every entry after the first rides UDP, so one " +
			"drop-UDP rule takes the whole plan down",
	)
)

// EscalationConfig is the optional carrier_escalation object in Config.
//
// Every field is omitempty and the zero value is EscalationOff, so a
// configuration that does not mention it parses, normalizes and behaves exactly
// as it did before this file existed.
type EscalationConfig struct {
	// Mode is EscalationOff when empty.
	Mode EscalationMode `json:"mode,omitempty"`

	// Plan is the ordered list of v3 carriers, beginning with the one this
	// session is using. It names carriers only; it never names an inner
	// protocol and never names a component outside this module.
	Plan []string `json:"plan,omitempty"`

	// MinOutbound is how many datagrams must have left before silence is
	// allowed to mean anything. Zero selects DefaultMinOutbound.
	MinOutbound uint64 `json:"min_outbound,omitempty"`

	// BlockAfterMS is how long a carrier that has never received anything is
	// given before the verdict becomes VerdictBlocked. Zero selects
	// DefaultBlockAfter.
	BlockAfterMS int64 `json:"block_after_ms,omitempty"`

	// StallAfterMS is how long a carrier that WAS receiving may be silent
	// before the verdict becomes VerdictStalled. Zero selects
	// DefaultStallAfter.
	StallAfterMS int64 `json:"stall_after_ms,omitempty"`
}

const (
	// DefaultMinOutbound is three datagrams.
	//
	// One is too few: a single datagram that is never answered is the ordinary
	// appearance of a packet lost on a mobile link. Three that leave with
	// nothing at all returning, together with the time budget below, is the
	// shape of scenario B rather than the shape of loss.
	DefaultMinOutbound uint64 = 3

	// DefaultBlockAfter is nine seconds.
	//
	// Two measurements bound this. A healthy response arrived 2.667 ms after
	// the initiation on a real handset over real Wi-Fi to a real remote gateway
	// (WINN3_ALT_INITIATION_20260808.md §2.2), so nine seconds is more than
	// three orders of magnitude of headroom over a working link. At the other
	// end, scenario B's 24 retries at the AmneziaWG retry cadence is roughly
	// two minutes of a session that is already dead. Nine seconds is chosen to
	// sit far above the first number and far below the second: long enough that
	// a slow network is not called blocked, short enough that a user is not
	// asked to stare at a dead tunnel for two minutes.
	DefaultBlockAfter = 9 * time.Second

	// DefaultStallAfter is seventy-five seconds — three keepalive intervals at
	// the measured 25.000 s metronome (WINN3_ALT_INITIATION_20260808.md §2.2).
	//
	// One interval would false-positive on a single lost keepalive, which is
	// ordinary. Three means the far side has missed every keepalive in the
	// window, which no working link does. It is deliberately generous: a false
	// stall on a live tunnel is worse than a late one, because the recommended
	// response is to rebuild a session that was working.
	DefaultStallAfter = 75 * time.Second

	// MaxEscalationPlan caps the plan length. There are three carriers with
	// dialers; a plan longer than that is necessarily malformed.
	MaxEscalationPlan = 8
)

// normalize validates the escalation configuration against the carrier the
// session is actually using and fills the defaults.
//
// It is a method on the escalation object but takes the carrier, because every
// interesting rule here is a relationship between the plan and the session
// rather than a property of the plan alone.
func (escalation EscalationConfig) normalize(
	carrierName string,
) (EscalationConfig, error) {
	switch escalation.Mode {
	case "", EscalationOff:
		// The default path, and the one every existing configuration takes.
		// A plan supplied alongside mode "off" is still checked for internal
		// sanity below rather than ignored, so that a fleet can stage the plan
		// in one release and turn the mode on in the next WITHOUT discovering
		// at that moment that the plan was malformed all along.
		escalation.Mode = EscalationOff
		if len(escalation.Plan) == 0 {
			return EscalationConfig{Mode: EscalationOff}, nil
		}
	case EscalationObserve:
		if len(escalation.Plan) == 0 {
			return EscalationConfig{}, ErrEscalationPlanRequired
		}
	default:
		return EscalationConfig{}, fmt.Errorf(
			"%w (got %q)", ErrEscalationModeUnknown, escalation.Mode,
		)
	}

	plan, err := normalizeEscalationPlan(escalation.Plan, carrierName)
	if err != nil {
		return EscalationConfig{}, err
	}
	escalation.Plan = plan

	if escalation.MinOutbound == 0 {
		escalation.MinOutbound = DefaultMinOutbound
	}
	if escalation.BlockAfterMS == 0 {
		escalation.BlockAfterMS = DefaultBlockAfter.Milliseconds()
	}
	if escalation.StallAfterMS == 0 {
		escalation.StallAfterMS = DefaultStallAfter.Milliseconds()
	}
	if escalation.BlockAfterMS < 0 || escalation.StallAfterMS < 0 {
		return EscalationConfig{}, errors.New(
			"winn datapath carrier escalation budgets must not be negative",
		)
	}
	return escalation, nil
}

func normalizeEscalationPlan(
	plan []string, carrierName string,
) ([]string, error) {
	if len(plan) > MaxEscalationPlan {
		return nil, fmt.Errorf(
			"winn datapath carrier escalation plan has %d entries, the "+
				"maximum is %d", len(plan), MaxEscalationPlan,
		)
	}
	normalized := make([]string, 0, len(plan))
	seen := make(map[string]bool, len(plan))
	for index, raw := range plan {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			return nil, fmt.Errorf(
				"winn datapath carrier escalation plan entry %d is empty",
				index,
			)
		}
		if seen[entry] {
			return nil, fmt.Errorf(
				"%w (%q)", ErrEscalationPlanDuplicate, entry,
			)
		}
		seen[entry] = true
		if CarrierTransportOf(entry) == TransportUnknown {
			return nil, fmt.Errorf(
				"%w (%q)", ErrEscalationPlanUnusable, entry,
			)
		}
		if index > 0 && entry == CarrierHTTP3 {
			return nil, ErrEscalationTargetShelved
		}
		normalized = append(normalized, entry)
	}
	if normalized[0] != carrierName {
		return nil, fmt.Errorf(
			"%w: plan begins with %q, the session uses %q",
			ErrEscalationPlanHead, normalized[0], carrierName,
		)
	}
	survives := false
	for _, entry := range normalized[1:] {
		if CarrierSurvivesUDPBlock(entry) {
			survives = true
			break
		}
	}
	if !survives {
		return nil, fmt.Errorf(
			"%w (plan: %s)", ErrEscalationPlanAllUDP,
			strings.Join(normalized, " -> "),
		)
	}
	return normalized, nil
}

// LinkObservation is the evidence a verdict is computed from.
//
// Four numbers, none of which names a protocol. This is the whole input surface
// on purpose: anything richer would couple the verdict to whatever is inside
// the datagrams, and the point of this file is that it does not care.
type LinkObservation struct {
	// Elapsed is how long the engine has been open.
	Elapsed time.Duration

	// Outbound is how many datagrams the engine has sent toward the gateway.
	Outbound uint64

	// InboundSeen reports whether anything has ever arrived FROM THE NETWORK.
	//
	// A bool rather than a count, and sourced from the receive path rather than
	// from the delivery path, and both of those are deliberate. The engine's
	// rx_datagrams counter increments in deliver(), which runs when the HOST
	// calls ReadOutbound — not when the datagram arrives. A host that is slow
	// to read, or that has stopped reading, would leave that counter at zero
	// while the gateway was answering perfectly well, and this file would
	// diagnose a working carrier as blocked and recommend tearing it down.
	//
	// The receive path's own clock has no such ambiguity: it is stamped on the
	// pump, when the datagram comes off the socket. Whether the far side is
	// answering is exactly what that clock knows and exactly what the verdict
	// needs, so the observation carries the fact rather than a count that means
	// something subtly different.
	InboundSeen bool

	// SinceInbound is the time since the most recent datagram arrived from the
	// network. It is meaningless, and ignored, when InboundSeen is false.
	SinceInbound time.Duration
}

// Assessment is the verdict together with what follows from it.
type Assessment struct {
	// Verdict is the conclusion.
	Verdict Verdict `json:"verdict"`

	// Reason states the evidence in one human-readable clause. It exists
	// because every failure this file diagnoses previously presented to a user
	// as an undifferentiated connect timeout.
	Reason string `json:"reason"`

	// Carrier is the carrier the session is using.
	Carrier string `json:"carrier"`

	// Transport is that carrier's IP transport.
	Transport string `json:"transport"`

	// Recommended names the carrier the plan says to try next. It is empty
	// unless the verdict warrants a change and the plan has a successor.
	Recommended string `json:"recommended,omitempty"`

	// RecommendedSurvivesUDPBlock states plainly whether the recommendation
	// actually helps against the adversary that triggered it. A plan validated
	// by normalize always has such a successor, but this is reported rather
	// than assumed so that a caller reading only the assessment can tell.
	RecommendedSurvivesUDPBlock bool `json:"recommended_survives_udp_block"`
}

// EscalationPolicy is a normalized EscalationConfig bound to a carrier, ready
// to evaluate observations.
type EscalationPolicy struct {
	mode        EscalationMode
	carrier     string
	plan        []string
	minOutbound uint64
	blockAfter  time.Duration
	stallAfter  time.Duration
}

// NewEscalationPolicy validates the configuration and returns the policy.
func NewEscalationPolicy(
	escalation EscalationConfig, carrierName string,
) (EscalationPolicy, error) {
	normalized, err := escalation.normalize(carrierName)
	if err != nil {
		return EscalationPolicy{}, err
	}
	return EscalationPolicy{
		mode:        normalized.Mode,
		carrier:     carrierName,
		plan:        normalized.Plan,
		minOutbound: normalized.MinOutbound,
		blockAfter:  time.Duration(normalized.BlockAfterMS) * time.Millisecond,
		stallAfter:  time.Duration(normalized.StallAfterMS) * time.Millisecond,
	}, nil
}

// Mode reports the configured mode.
func (policy EscalationPolicy) Mode() EscalationMode { return policy.mode }

// Active reports whether the policy computes anything at all.
func (policy EscalationPolicy) Active() bool {
	return policy.mode == EscalationObserve && len(policy.plan) > 0
}

// Plan returns a copy of the ordered plan. A copy, because the policy is
// handed to callers that must not be able to reorder the sequence a validated
// configuration established.
func (policy EscalationPolicy) Plan() []string {
	return append([]string(nil), policy.plan...)
}

// successor returns the next carrier after the one in use.
func (policy EscalationPolicy) successor() string {
	for index, entry := range policy.plan {
		if entry == policy.carrier && index+1 < len(policy.plan) {
			return policy.plan[index+1]
		}
	}
	return ""
}

// Evaluate turns one observation into an assessment.
//
// The rules, in the order they are applied and with the reason each comes
// before the next:
//
//  1. Inbound traffic that is recent enough means healthy. Checked first
//     because a working link must never be reported as anything else, whatever
//     the other numbers say.
//  2. Inbound traffic that has stopped for longer than stallAfter means
//     stalled.
//  3. No inbound traffic ever, with the outbound and time budgets both spent,
//     means blocked. Both budgets are required: time alone would call a
//     just-opened idle tunnel blocked, and count alone would call a fast burst
//     on a slow link blocked.
//  4. Anything else is pending, which includes every engine that has not yet
//     had the chance to prove itself either way.
func (policy EscalationPolicy) Evaluate(
	observation LinkObservation,
) Assessment {
	assessment := Assessment{
		Verdict:   VerdictPending,
		Carrier:   policy.carrier,
		Transport: CarrierTransportOf(policy.carrier).String(),
	}
	switch {
	case observation.InboundSeen && observation.SinceInbound <= policy.stallAfter:
		assessment.Verdict = VerdictHealthy
		assessment.Reason = fmt.Sprintf(
			"the gateway is answering; most recent datagram %s ago",
			observation.SinceInbound.Round(time.Second),
		)
		return assessment

	case observation.InboundSeen:
		assessment.Verdict = VerdictStalled
		assessment.Reason = fmt.Sprintf(
			"carrier %s was carrying traffic and has received nothing for "+
				"%s, longer than the %s budget",
			policy.carrier,
			observation.SinceInbound.Round(time.Second),
			policy.stallAfter,
		)

	case observation.Outbound >= policy.minOutbound &&
		observation.Elapsed >= policy.blockAfter:
		assessment.Verdict = VerdictBlocked
		assessment.Reason = fmt.Sprintf(
			"carrier %s rides %s; %d datagrams sent over %s and not one "+
				"received, so nothing is getting through in either direction",
			policy.carrier,
			CarrierTransportOf(policy.carrier),
			observation.Outbound,
			observation.Elapsed.Round(time.Second),
		)

	default:
		assessment.Reason = fmt.Sprintf(
			"%d of %d datagrams sent, %s of %s elapsed, nothing received yet",
			observation.Outbound, policy.minOutbound,
			observation.Elapsed.Round(time.Second), policy.blockAfter,
		)
		return assessment
	}

	if successor := policy.successor(); successor != "" {
		assessment.Recommended = successor
		assessment.RecommendedSurvivesUDPBlock =
			CarrierSurvivesUDPBlock(successor)
	}
	return assessment
}

// escalationPolicyFromNormalized builds the policy for an engine.
//
// It TRUSTS its argument and performs no validation, so it must only be called
// with a Config that has been through normalize. That is the case at its single
// call site, newEngine, which every construction path reaches only after
// ParseConfig or Config.normalize has run. Re-validating here would mean
// newEngine either returned an error it cannot return or swallowed one.
func escalationPolicyFromNormalized(config Config) EscalationPolicy {
	escalation := config.Escalation
	if escalation.Mode != EscalationObserve {
		// Off, and the plan is not consulted. Returning the zero policy rather
		// than a populated inactive one keeps "not configured" and "configured
		// off" identical from every observer's point of view.
		return EscalationPolicy{}
	}
	return EscalationPolicy{
		mode:        escalation.Mode,
		carrier:     config.Carrier,
		plan:        append([]string(nil), escalation.Plan...),
		minOutbound: escalation.MinOutbound,
		blockAfter:  time.Duration(escalation.BlockAfterMS) * time.Millisecond,
		stallAfter:  time.Duration(escalation.StallAfterMS) * time.Millisecond,
	}
}

// observeLink reads the engine's counters into an observation.
//
// Two naming traps live here, so both are written out once rather than left
// for every future reader to rediscover:
//
//   - The engine's counter names run OPPOSITE to the wire direction this file
//     cares about. inboundDatagrams counts host-to-gateway datagrams, which is
//     what LEAVES this machine, and is what Status publishes as tx_datagrams.
//   - The arrival side deliberately does NOT read outboundDatagrams, even
//     though its name and its rx_datagrams label both suggest it should. That
//     counter moves in deliver(), on the host's ReadOutbound call, not on
//     arrival. See LinkObservation.InboundSeen for why using it would let a
//     slow host be reported as a blocked carrier.
func (engine *Engine) observeLink(now time.Time) LinkObservation {
	observation := LinkObservation{
		Elapsed:  now.Sub(engine.openedAt),
		Outbound: engine.counters.inboundDatagrams.Load(),
	}
	if nanos := engine.counters.lastRxUnixNano.Load(); nanos != 0 {
		observation.InboundSeen = true
		observation.SinceInbound = now.Sub(time.Unix(0, nanos).UTC())
	}
	// A clock that moved backwards between the store and this read would make
	// a live link look silent for a negative duration, which compares as
	// "recent" and is harmless, or make Elapsed negative, which would keep the
	// verdict pending forever. Clamping both at zero costs nothing and removes
	// the whole class.
	observation.Elapsed = max(observation.Elapsed, 0)
	observation.SinceInbound = max(observation.SinceInbound, 0)
	return observation
}

// AssessEscalation reports the datapath's verdict on the carrier in use.
//
// The second return is false when escalation is off, which is the default and
// which means no verdict was computed at all. Callers must not read the
// assessment in that case: it is the zero value, and reporting VerdictPending
// for a node that was never asked to assess anything would be a claim the
// datapath did not make.
func (engine *Engine) AssessEscalation() (Assessment, bool) {
	policy := engine.escalationPolicy()
	if !policy.Active() {
		return Assessment{}, false
	}
	return policy.Evaluate(engine.observeLink(time.Now().UTC())), true
}

// escalationPolicy reads the current policy under the lock.
//
// The lock exists for failover.go, which rebinds the policy to the successor
// after a carrier switch. On every other path the policy is written once in
// newEngine and this is an uncontended read lock.
func (engine *Engine) escalationPolicy() EscalationPolicy {
	engine.escalationMu.RLock()
	defer engine.escalationMu.RUnlock()
	return engine.escalation
}

// rebindEscalation points the policy at a different carrier in the same plan.
//
// Only failover.go calls this, and only after carrier.Manager has actually
// activated the successor. It exists because the assessment names the carrier
// it is about: leaving the policy bound to the plan head after a switch would
// make a host read "carrier direct-awg is healthy" about a session that is on
// http2-stream, and would make successor() recommend the carrier the session
// had just moved to.
//
// The plan, the budgets and the mode are all carried over unchanged. Only the
// carrier the policy is bound to moves, so a rebind cannot widen what the
// configuration validated.
func (engine *Engine) rebindEscalation(carrierName string) {
	engine.escalationMu.Lock()
	defer engine.escalationMu.Unlock()
	engine.escalation.carrier = carrierName
}
