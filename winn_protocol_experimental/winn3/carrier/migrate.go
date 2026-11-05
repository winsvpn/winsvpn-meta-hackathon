package carrier

import (
	"winsvpn.local/winnprotocol/winn3/session"
)

// Carrier migration: moving a live session from one transport to another
// without re-handshaking.
//
// §5.4 of the design makes this free at the cryptographic layer — the session
// holds no address and no socket, so a migration is a pointer assignment — and
// that is the structural answer to a censor who blocks UDP wholesale. What it is
// not free at is the SIZE layer, and that is what this file is about.
//
// # The trap
//
// The tun lane named it precisely: size the session to the carrier it dialled,
// and the first UDP→TLS failover silently black holes every full-size flow while
// the tunnel still reports "up". Small packets keep working. Large transfers
// stall. The user's report is "the VPN is slow", from a country where nobody can
// attach a debugger, and the maintainer's dashboard says the session is healthy.
//
// The numbers are not marginal. At the IPv6 minimum path MTU a UDP carrier over
// IPv4 carries a 1252-byte message and a TLS carrier over IPv6 carries 1168.
// A session built for the first and migrated to the second is 84 bytes over on
// every full-size packet.
//
// # The answer, in the order it should be reached for
//
//  1. PIN THE FLOOR AND NEVER MOVE IT. Build the driver and the tun device with
//     Floor(pathMTU, every class this session may migrate to). Migration then
//     needs no size change at all. This is the primary API and it should be the
//     normal case.
//
//     There is a second reason to prefer it that has nothing to do with black
//     holes: a message-size distribution that shifts at the exact instant a
//     session moves from one transport to another is a correlator. §5.4 wants a
//     session to survive a carrier change unlinkably; changing the shaper at the
//     same moment hands an observer a free hint that the two flows are one.
//     Migration at a pinned floor changes nothing an observer can see except the
//     transport itself.
//
//  2. WHEN THE FLOOR COULD NOT BE KNOWN, SHRINK EXPLICITLY. A path MTU measured
//     after the fact, or a carrier class added mid-session, leaves a driver sized
//     for a carrier that no longer exists. Migrate tells the session, through
//     MessageSizeSink.
//
//  3. WHEN THE SESSION CANNOT BE TOLD, REFUSE. Migrate returns
//     ErrMigrationWouldBlackHole rather than completing a migration whose
//     symptom would be invisible. Refusing is actionable — the caller can tear
//     down and re-handshake at the smaller size, which the session supports —
//     and completing is not, because nothing downstream would ever report it.
//
// # The winn3/session seam
//
// *session.Driver implements MessageSizeSink. The interface keeps carrier from
// owning or reaching the session's cryptographic state: migration may adjust the
// message ceiling and padding shaper, but it cannot change keys, nonces or epoch.

// MessageSizeSink is the seam. A session that can be told its carrier's ceiling
// changed satisfies it.
//
// It is an interface rather than a concrete type so this package can request the
// one size change migration needs without acquiring the rest of session.Driver.
type MessageSizeSink interface {
	// SetMaxMessageSize sets the largest message the session may emit.
	//
	// Two invariants the implementation owes its caller, both of which the
	// session lane already identified:
	//
	//   - it must recompute the padding shaper, because a top padding bucket
	//     above the carrier's ceiling would round a small packet up past what
	//     the carrier can send, and
	//   - it must refuse to shrink below what an already-queued frame needs,
	//     because a queued inner packet that no longer fits has nowhere to go
	//     and dropping it silently is the black hole one layer in.
	SetMaxMessageSize(n int) error
}

// Remedy is what a caller may do about a migration that could not be completed
// safely. It is a description of the options, not an instruction.
type Remedy uint8

const (
	// RemedyNone means nothing needs doing.
	RemedyNone Remedy = iota

	// RemedyTellSession means the session must be told the new ceiling before
	// this migration is safe. Reached when the destination is narrower and no
	// sink was supplied.
	RemedyTellSession

	// RemedyRehandshake means the session cannot be adjusted and must be torn
	// down and rebuilt at the narrower size. Reached when a sink was supplied
	// and refused.
	RemedyRehandshake
)

// String renders the remedy for status and error messages.
func (r Remedy) String() string {
	switch r {
	case RemedyTellSession:
		return "tell-session"
	case RemedyRehandshake:
		return "rehandshake"
	default:
		return "none"
	}
}

// Migration describes what a migration did or would do. It contains no decision
// about whether to have attempted it.
type Migration struct {
	// From and To are the classes either side of the move.
	From, To Class
	// SessionSize is the ceiling the session was built with.
	SessionSize int
	// CarrierSize is the destination carrier's ceiling.
	CarrierSize int
	// Narrows reports that the destination cannot carry what the session was
	// built to emit. This is the black-hole condition.
	Narrows bool
	// SizeApplied reports that the session was successfully told the new
	// ceiling.
	SizeApplied bool
	// Remedy is what the caller may do if the migration was refused.
	Remedy Remedy
}

// Migrate moves a live session from one carrier to another.
//
// sessionSize is the ceiling the session was built with — session.Config's
// MaxMessageSize, or the Floor it was pinned to. sink may be nil for callers
// without a mutable session; Migrate makes that absence fail closed whenever the
// destination is narrower.
//
// It does not close the old carrier. Closing is the caller's, because the caller
// may want to hold a UDP socket open across a probe of the new one, and a carrier
// that closed its predecessor would make that impossible.
//
// It does not widen. A destination that can carry more than the session emits is
// not a problem to solve: the session keeps emitting what it emitted, the tun
// MTU stays where the host configured it, and nothing observable changes at the
// moment of the move. Widening would buy payload at the cost of a size
// discontinuity exactly where an observer is already looking.
func Migrate(sink MessageSizeSink, from, to Conn, sessionSize int) (Migration, error) {
	m := Migration{SessionSize: sessionSize}
	if sessionSize < session.MessageFloor() {
		return m, wrap(ErrConfig, "session size %d is below the %d-byte floor",
			sessionSize, session.MessageFloor())
	}
	if to == nil {
		return m, wrap(ErrConfig, "no destination carrier")
	}
	if from != nil {
		m.From = from.Class()
	}
	m.To = to.Class()
	m.CarrierSize = to.MaxMessageSize()

	if m.CarrierSize >= sessionSize {
		// The destination is at least as wide. Nothing to do, and deliberately
		// nothing done: see the note on widening above.
		return m, nil
	}

	m.Narrows = true
	if sink == nil {
		m.Remedy = RemedyTellSession
		return m, wrap(ErrMigrationWouldBlackHole,
			"%s carries %d bytes, session emits up to %d, and the session cannot be told",
			m.To, m.CarrierSize, sessionSize)
	}
	if err := sink.SetMaxMessageSize(m.CarrierSize); err != nil {
		m.Remedy = RemedyRehandshake
		return m, wrap(ErrMigrationWouldBlackHole,
			"%s carries %d bytes and the session refused to narrow to it: %v",
			m.To, m.CarrierSize, err)
	}
	m.SizeApplied = true
	return m, nil
}

// PlanFloor is the size a session should be built with when it may migrate
// across classes, and the inner MTU that implies.
//
// It exists so that a caller does not have to remember to consult two functions
// in the right order. The two numbers are the whole of the host's sizing
// obligation: build the session at MessageSize and the tun device at InnerMTU,
// and no migration this plan allows can black hole.
type PlanFloor struct {
	// MessageSize is Floor over the plan's classes.
	MessageSize int
	// InnerMTU is the tun device MTU that MessageSize implies.
	InnerMTU int
	// InnerIPv6 reports whether the tunnel can carry inner IPv6 at this floor.
	// False is common and is not a defect: at a 1280-byte outer path inner IPv6
	// is impossible for any tunnel.
	InnerIPv6 bool
	// MinPathMTUForInnerIPv6 is the outer path MTU the narrowest class in the
	// plan would need before inner IPv6 becomes possible.
	MinPathMTUForInnerIPv6 int
}

// NewPlanFloor computes the sizing floor for a migration plan.
//
// The inner-IPv6 answer is computed for the NARROWEST class in the plan, not for
// the one being dialled, for the same reason the message floor is: a tunnel that
// carried inner IPv6 until it failed over and then black holed every full-size
// v6 packet is the original trap wearing a v6 hat.
func NewPlanFloor(pathMTU int, classes ...Class) PlanFloor {
	pf := PlanFloor{MessageSize: Floor(pathMTU, classes...)}
	pf.InnerMTU = InnerMTU(pf.MessageSize)
	pf.InnerIPv6 = pf.InnerMTU >= ipv6MinimumLinkMTU

	if len(classes) == 0 {
		classes = []Class{ClassUnknown}
	}
	for _, class := range classes {
		for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
			need := MinPathMTUForInnerIPv6(class, family)
			if need > pf.MinPathMTUForInnerIPv6 {
				pf.MinPathMTUForInnerIPv6 = need
			}
		}
	}
	return pf
}

// ipv6MinimumLinkMTU is RFC 8200's requirement of every link that carries IPv6,
// applied to the tun interface, which is a link. It is session's constant by
// another name; deriving from it keeps a third copy of the RFC floor from
// drifting across the two packages.
const ipv6MinimumLinkMTU = session.IPv6MinimumLinkMTU
