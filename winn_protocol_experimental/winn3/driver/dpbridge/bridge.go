// Package dpbridge is the naming adapter between a winn3 carrier and the
// committed carrier-escalation decision in datapath/escalation.go.
//
// It decides nothing. Every rule about when a carrier is blocked, when it is
// merely stalled, which successor the plan names and whether that successor
// survives a UDP block already exists in datapath/escalation.go, was reviewed
// there, and is called from here rather than restated. What this package
// supplies is the three things that genuinely do not exist yet:
//
//   - a mapping from carrier.Class onto the datapath's carrier vocabulary;
//   - a conversion from a carrier.Signal into a datapath.LinkObservation; and
//   - the two facts that must be read together — the datagram verdict and the
//     session's own §4.2 signal — carried in one value so a caller cannot read
//     one and forget the other.
//
// # Why this is a separate package
//
// winn3/ is standalone. Nothing under it may import datapath/, or the
// standalone protocol reacquires the dependency graph the ruling removed, and
// winn3/carrier holds an AST test that fails the build if it ever does. The
// driver loop is under winn3/ and obeys the same rule. This subpackage is the
// one place the two vocabularies meet, it is a leaf, and a host that does not
// run the datapath never imports it.
//
// # The two signals are different facts
//
// session.NeedsCarrierChange() is the §4.2 NORMATIVE signal: the handshake
// attempt budget was spent on this carrier, so the carrier CLASS must change.
// It is a statement about a session.
//
// datapath's Assessment is an EVIDENTIAL verdict computed from datagram counts
// and elapsed time. It is a statement about a link, and it is the one that can
// tell a carrier that never carried anything (blocked) from one that carried
// traffic and stopped (stalled).
//
// They can disagree, and when they do both are right about different things —
// a session whose handshake budget is spent on a carrier that is demonstrably
// delivering datagrams is a gateway problem, not a censorship problem. Merging
// them here would erase that distinction, so Evidence carries both and the
// caller that owns the sockets decides.
package dpbridge

import (
	"time"

	"winsvpn.local/winnprotocol/datapath"
	"winsvpn.local/winnprotocol/winn3/carrier"
)

// CarrierName maps a winn3 carrier class onto the datapath's carrier name.
//
// The mapping is the one winn3/carrier's handoff §6 records, and it is a
// mapping of NAMES, not of policy:
//
//	ClassUDP          -> direct-awg   (raw UDP datagrams to the gateway)
//	ClassTCP, TLS     -> http2-stream (the only TCP carrier the datapath has)
//	ClassUnknown      -> ""           (never guessed)
//
// http3-connect-udp is not a target of this mapping. It rides UDP, so it is not
// an alternative to ClassUDP against the adversary that motivates escalation,
// and normalizeEscalationPlan refuses it anywhere but the head of a plan.
//
// An unknown class maps to the empty string rather than to a plausible
// name. datapath.CarrierTransportOf("") is TransportUnknown and
// CarrierSurvivesUDPBlock("") is false, so an unmapped class cannot end up
// promising survival it has not got.
func CarrierName(class carrier.Class) string {
	switch class {
	case carrier.ClassUDP:
		return datapath.CarrierDirectAWG
	case carrier.ClassTCP, carrier.ClassTLS:
		return datapath.CarrierHTTP2
	default:
		return ""
	}
}

// Plan maps an ordered class plan onto an ordered datapath plan.
//
// It de-duplicates while preserving order, because winn3 distinguishes ClassTCP
// from ClassTLS and the datapath has one TCP carrier: a v3 plan of
// [UDP, TCP, TLS] is [direct-awg, http2-stream] in the datapath's vocabulary,
// and normalizeEscalationPlan refuses a plan that names one carrier twice.
//
// Collapsing two classes onto one name loses nothing the escalation decision
// uses. That decision turns on CarrierTransportOf, and TCP and TLS ride the same
// transport; the difference between them is 22 bytes of overhead, which is the
// sizing layer's business and is already charged by carrier.Floor.
func Plan(classes []carrier.Class) []string {
	out := make([]string, 0, len(classes))
	seen := make(map[string]bool, len(classes))
	for _, c := range classes {
		name := CarrierName(c)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// NewPolicy builds the committed escalation policy for a v3 migration plan.
//
// cfg is the host's datapath.EscalationConfig — mode and budgets. Its Plan is
// overwritten from classes, because the plan the escalation decision validates
// must be the same plan the message-size floor was computed over; two plans that
// can drift apart is how a session escalates onto a carrier the floor never
// covered.
//
// Every validation rule is datapath's: plan head must be the carrier in use, no
// duplicates, no unusable names, at least one successor that survives a UDP
// block. None of them is repeated here.
func NewPolicy(
	cfg datapath.EscalationConfig, classes []carrier.Class, inUse carrier.Class,
) (datapath.EscalationPolicy, error) {
	cfg.Plan = Plan(classes)
	return datapath.NewEscalationPolicy(cfg, CarrierName(inUse))
}

// Observation converts a carrier.Signal into the evidence the committed policy
// reasons over.
//
// The one subtle field is InboundSeen, and the subtlety is the same bug the
// escalation lane shipped once and the carrier lane closed by construction:
// datapath.LinkObservation documents that InboundSeen must be sourced from the
// RECEIVE path rather than from the delivery path, because a host that is slow
// to drain a queue would otherwise look censored. carrier.Stats.Delivered and
// LastDelivered move on ARRIVAL AT THE CARRIER and never on the caller getting
// round to reading, so they are the correct source, and foreign datagrams move
// neither — which is what stops an off-path attacker from holding a blocked
// carrier's health indicator up.
//
// A carrier that counted an arrival but left no timestamp is treated as having
// seen inbound traffic just now, not as having seen none. The two readings fail
// in opposite directions and only one of them tears down a working tunnel.
// # The second subtle field is the one that is not there: Foreign
//
// A NAT rebind and a wholesale UDP block are byte-for-byte identical in a
// datagram carrier's counters — Foreign climbing at line rate, Delivered frozen,
// LastDelivered stuck at the instant of the change — and they want opposite
// responses. A rebind wants the return path updated; a block wants a
// carrier-class escalation. Escalating on a rebind costs a mobile user a
// re-handshake and ~43 s of dead tunnel every time they change cell, which on a
// handset in Myanmar is most of the day.
//
// Foreign cannot be the discriminator, and the temptation to make it one is the
// trap. An off-path attacker who has found the five-tuple produces exactly the
// same Foreign climb, so reading "Foreign is moving, therefore the peer moved"
// would reintroduce the failover-suppression attack the carrier lane closed by
// construction — and worse, would suggest following the attacker's address.
//
// carrier.Stats.PeerMoves is the discriminator, and the whole reason it exists.
// Only carrier.UDP.SetPeer moves it, and SetPeer's contract is that it is called
// from the source of a datagram that DISPATCHED, which is an AEAD decision. So a
// peer move is authenticated inbound traffic — strictly stronger evidence than
// Delivered, which only says a message ARRIVED — and it is folded in below as
// exactly that. A rebound carrier therefore presents to the escalation policy as
// a link that is hearing from its peer, which is what it is, and the policy's
// own rules then decline to escalate without this package restating any of them.
func Observation(sig carrier.Signal, openedAt, now time.Time) datapath.LinkObservation {
	obs := datapath.LinkObservation{
		Outbound: sig.Stats.Sent,
	}
	if !openedAt.IsZero() {
		if d := now.Sub(openedAt); d > 0 {
			obs.Elapsed = d
		}
	}
	// The freshest AUTHENTICATED evidence of inbound life, which is the later of
	// "a message arrived" and "the peer proved it had moved".
	inbound := sig.Stats.LastDelivered
	if sig.Stats.LastPeerMove.After(inbound) {
		inbound = sig.Stats.LastPeerMove
	}
	switch {
	case !inbound.IsZero():
		obs.InboundSeen = true
		if d := now.Sub(inbound); d > 0 {
			obs.SinceInbound = d
		}
	case sig.Stats.Delivered > 0 || sig.Stats.PeerMoves > 0:
		// A carrier that counted an arrival but left no timestamp is treated as
		// having seen inbound traffic just now, not as having seen none.
		obs.InboundSeen = true
	}
	return obs
}

// Rebound reports whether this carrier's return path was moved on authenticated
// evidence recently enough to explain the counters the policy is looking at.
//
// It is separate from Observation so that a caller can SEE the distinction
// rather than only feel it in the verdict. "Do not escalate" and "do not
// escalate BECAUSE the user changed cell" are the same action and very different
// diagnoses, and a support engineer reading a status page needs the second.
//
// The window is the carrier's own age when that is shorter than within, because
// a carrier opened after the move cannot have been affected by it.
func Rebound(sig carrier.Signal, openedAt, now time.Time, within time.Duration) bool {
	if sig.Stats.PeerMoves == 0 || sig.Stats.LastPeerMove.IsZero() {
		return false
	}
	if !openedAt.IsZero() && sig.Stats.LastPeerMove.Before(openedAt) {
		return false
	}
	age := now.Sub(sig.Stats.LastPeerMove)
	return age >= 0 && age <= within
}

// DefaultRebindWindow is how long a peer move stays a live explanation for a
// quiet carrier.
//
// It is the session's own liveness budget — MaxLostProbes x Probe.Max at the
// shipping defaults, which is 80 s — because that is exactly how long a session
// will tolerate the silence a rebind causes before it gives up. A shorter window
// would let the escalation policy reach a blocked verdict while the session was
// still recovering from a rebind; a longer one would keep excusing a carrier that
// really had been blocked since.
const DefaultRebindWindow = 80 * time.Second

// Evidence is the datagram verdict and the session's own signal, side by side.
//
// It combines nothing. The two are different claims about different things
// (§ the package comment) and a caller that acts on one must be able to see the
// other; putting them in one value is how that is enforced without inventing a
// rule about which wins.
type Evidence struct {
	// Assessment is datapath's verdict, verbatim, including its Reason string
	// and its Recommended successor.
	Assessment datapath.Assessment

	// NeedsCarrierChange is session.Driver's §4.2 signal, passed through
	// unmodified: the handshake budget was spent on this carrier.
	NeedsCarrierChange bool

	// NeedsNewSession is session.Driver's unrecoverable-session signal, passed
	// through unmodified. A carrier change does not help a session that must be
	// rebuilt.
	NeedsNewSession bool

	// CarrierErr is the carrier's own last fatal error. A dead carrier and a
	// session that wants a different carrier are different facts.
	CarrierErr error

	// Rebound reports that this carrier's return path was moved to a new peer
	// address on authenticated evidence, inside the rebind window. It is the
	// answer to "why is this carrier quiet", and it is the answer that must NOT
	// produce a carrier-class escalation: the user changed cell, the transport
	// is fine, and escalating would cost them a re-handshake for it.
	Rebound bool

	// PathNarrowed is the session's size-aware liveness verdict: full-size round
	// trips fail while small ones succeed.
	//
	// It is carried beside the datagram verdict for the same reason
	// NeedsCarrierChange is — they are different claims about different things.
	// A narrowed path produces a PERFECTLY HEALTHY datagram assessment, because
	// every write succeeds and small traffic flows both ways, so a caller that
	// read only the Assessment would conclude the link was fine while every
	// large transfer on it silently died. There is no counter in datapath's
	// vocabulary for this, which is why it arrives beside the verdict rather
	// than inside it.
	PathNarrowed bool
}

// Assess runs the committed policy over one observation and pairs the result
// with the session's own signals.
func Assess(
	policy datapath.EscalationPolicy, sig carrier.Signal, openedAt, now time.Time,
) Evidence {
	return Evidence{
		Assessment:         policy.Evaluate(Observation(sig, openedAt, now)),
		NeedsCarrierChange: sig.NeedsChange,
		NeedsNewSession:    sig.NeedsNewSession,
		CarrierErr:         sig.CarrierErr,
		Rebound:            Rebound(sig, openedAt, now, DefaultRebindWindow),
		PathNarrowed:       sig.PathNarrowed,
	}
}

// ClassFor maps a datapath carrier name back to the winn3 class a host must
// dial to satisfy it. It is the inverse of CarrierName over the two names that
// have a v3 carrier.
//
// http2-stream maps to ClassTLS rather than ClassTCP: the datapath's HTTP/2
// carrier is TLS, and a host that dialled bare TCP for it would be 22 bytes
// wider than the plan floor charged. Bare ClassTCP exists in winn3 for tests and
// for an L4-fronted deployment, and neither has a datapath name.
func ClassFor(name string) carrier.Class {
	switch name {
	case datapath.CarrierDirectAWG:
		return carrier.ClassUDP
	case datapath.CarrierHTTP2:
		return carrier.ClassTLS
	default:
		return carrier.ClassUnknown
	}
}
