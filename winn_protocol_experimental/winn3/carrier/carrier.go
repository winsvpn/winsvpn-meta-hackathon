package carrier

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// Carrier is §4.2's contract, verbatim and deliberately small.
//
// Four methods is the whole reason a session can outlive the transport that
// carried it. The session holds no socket, so swapping the thing underneath it
// is a pointer assignment rather than a re-handshake — which is the structural
// answer to a censor who blocks UDP wholesale.
type Carrier interface {
	// Send puts one message on the wire. It does not modify msg and does not
	// retain it after returning.
	Send(ctx context.Context, msg []byte) error

	// Recv returns the next message. The returned slice is owned by the caller.
	Recv(ctx context.Context) ([]byte, error)

	// MaxMessageSize is the largest message this carrier will accept, chosen so
	// that the wrapped packet fits the path without fragmenting.
	MaxMessageSize() int

	// Close releases the transport. It is safe to call more than once and it
	// unblocks any Send or Recv in progress.
	Close() error
}

// Conn is what every carrier in this package provides: the §4.2 contract plus
// the three things a live migration and a policy layer need.
//
// The split is not decoration. Carrier is what winn3/session's caller loop
// consumes and it must stay at four methods, because anything a carrier can be
// asked is something a future carrier has to implement. Conn is what this
// package's own migration code consumes.
type Conn interface {
	Carrier

	// Class reports what kind of transport this is. It is a fact about the
	// carrier, not a recommendation about which to use.
	Class() Class

	// SetMaxMessageSize narrows or widens the ceiling on a live carrier. It
	// refuses a size the path cannot carry unfragmented and refuses a size below
	// the session's message floor.
	SetMaxMessageSize(n int) error

	// Stats reports what this carrier has seen. Every counter moves on arrival
	// at the carrier, never on the caller getting round to reading.
	Stats() Stats
}

// Class is the transport a carrier rides.
//
// This mirrors datapath.CarrierTransport deliberately rather than importing it.
// winn3/ is standalone: nothing under it may depend on datapath/, or the
// standalone protocol acquires the dependency graph the ruling removed. The two
// enumerations must agree in meaning, and §6 of the handoff records the mapping.
type Class uint8

const (
	// ClassUnknown is the zero value and is never a valid carrier class. An
	// absent class must not silently select an overhead, because selecting the
	// wrong one produces fragmentation rather than an error.
	ClassUnknown Class = iota

	// ClassUDP is one Winn3 message per UDP datagram. No added bytes at all.
	ClassUDP

	// ClassTCP is the §4.2 encrypted-length record layer over a bare TCP
	// connection. Useful for tests and for a deployment behind an L4 fronting
	// service; a real hostile network wants ClassTLS.
	ClassTCP

	// ClassTLS is the same record layer inside TLS over TCP.
	ClassTLS
)

// String renders the class for status and error messages.
func (c Class) String() string {
	switch c {
	case ClassUDP:
		return "udp"
	case ClassTCP:
		return "tcp"
	case ClassTLS:
		return "tls"
	default:
		return "unknown"
	}
}

// Stream reports whether this class has to restore message boundaries, and
// therefore whether the §4.2 encrypted-length rule applies to it.
func (c Class) Stream() bool { return c == ClassTCP || c == ClassTLS }

// SurvivesUDPBlock reports whether this class still works on a network that
// drops UDP.
//
// An unknown class is reported as not surviving. The safe default for "we
// cannot tell" is not to promise survival — the same choice
// datapath.CarrierSurvivesUDPBlock makes, for the same reason.
//
// This is classification, not policy: it says what a carrier is, not which one
// to pick. The choice lives in datapath/escalation.go.
func (c Class) SurvivesUDPBlock() bool { return c == ClassTCP || c == ClassTLS }

// Family is the IP address family a carrier resolved to. It changes the header
// overhead by 20 bytes, which is the difference between a message that fits the
// IPv6 minimum link MTU and one that fragments.
type Family uint8

const (
	// FamilyUnknown is the zero value. Like ClassUnknown it never selects an
	// overhead; Overhead charges the worse of the two families for it, because
	// over-reserving costs payload and under-reserving costs fragments.
	FamilyUnknown Family = iota
	FamilyIPv4
	FamilyIPv6
)

// String renders the family for status and error messages.
func (f Family) String() string {
	switch f {
	case FamilyIPv4:
		return "ipv4"
	case FamilyIPv6:
		return "ipv6"
	default:
		return "unknown"
	}
}

// FamilyOf resolves an address to its family.
//
// It reads the address rather than the network name because a "udp" or "tcp"
// network resolves to either family and a carrier that assumed IPv4 from the
// network string would under-reserve 20 bytes on every IPv6 path — enough to
// fragment at the IPv6 minimum MTU, which is both a performance failure and a
// distinctive one.
func FamilyOf(addr net.Addr) Family {
	var ip net.IP
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	case *net.IPAddr:
		ip = a.IP
	default:
		if addr == nil {
			return FamilyUnknown
		}
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return FamilyUnknown
		}
		ip = net.ParseIP(host)
	}
	if ip == nil {
		return FamilyUnknown
	}
	if ip.To4() != nil {
		return FamilyIPv4
	}
	return FamilyIPv6
}

// Stats is what a carrier has observed. It carries no verdict.
//
// The counters that matter are Delivered and LastDelivered, and the definition
// of "delivered" is the load-bearing part. A sibling lane shipped a bug where a
// datagram counter moved when the host got round to reading rather than when the
// datagram arrived; on this path the same mistake would make a live tunnel look
// blocked, or a blocked one look live. So:
//
//   - Delivered moves when a message ARRIVES AT THE CARRIER, and only then. For
//     a socket-backed carrier that is the read which produced it, because there
//     is no queue in between; for Pipe, whose transport is a queue, it is
//     Deliver and not Recv. Bytes that arrive and turn out not to be a message
//     do not move it at all.
//   - Foreign moves instead for a datagram from an address that is not the
//     peer. That distinction is a security property, not bookkeeping: if foreign
//     datagrams moved LastDelivered, an off-path attacker who found the
//     five-tuple could spray packets to keep a blocked carrier looking healthy
//     and pin a user on it. Under a censor that is the whole attack.
//
// None of these is proof of liveness. A censor can replay ciphertext and a
// carrier has no key with which to notice. Liveness is the session's PONG, and
// the policy layer must not substitute a carrier counter for it.
type Stats struct {
	// Sent is messages successfully written to the transport.
	Sent uint64
	// SentBytes is on-wire bytes for those messages, including this carrier's
	// own framing but not the IP or TCP headers below it.
	SentBytes uint64
	// Delivered is messages that arrived at this carrier as messages.
	Delivered uint64
	// DeliveredBytes is on-wire bytes for those messages.
	DeliveredBytes uint64
	// SendErrors and RecvErrors count failed operations.
	SendErrors uint64
	RecvErrors uint64
	// InboxHighWater is the deepest a Pipe's inbox has been, in messages,
	// read at each admission. It sizes the inbox from measurement: a depth
	// that never neared it is memory spent on nothing. Pipe only; the other
	// carriers leave it zero.
	InboxHighWater uint64
	// InboxSojourn splits the messages Recv and RecvBatch took out of a
	// Pipe's inbox by how long each waited there, from its admission in
	// Deliver to the read that took it. Bucket i, for i >= 1, counts waits
	// of 2^i to 2^(i+1)-1 hundred-microsecond units: [0.2,0.4) ms, [0.4,0.8),
	// ..., [102.4,204.8); bucket 0 counts waits under 0.2 ms and the last
	// bucket 204.8 ms and over. InboxSojournMaxUS is the longest wait, in
	// microseconds. Together they are the standing delay the inbox depth
	// adds to the uplink, which a loaded ping through the tunnel cannot
	// separate from the radio and the phone's own queues. They move on the
	// read, by definition; a queue nobody drains scores nothing. Pipe only;
	// the other carriers leave them zero.
	InboxSojourn      [InboxSojournBuckets]uint64
	InboxSojournMaxUS uint64
	// TxGSOCalls is sendmsg calls that carried a UDP_SEGMENT super-datagram,
	// TxGSOSegments the datagrams those calls carried, and TxBatchCalls the
	// plain sendmmsg calls beside them. TxGSODisabled reports that the kernel
	// refused UDP_SEGMENT permanently on this socket. The connected UDP
	// carrier on linux and android fills them; every other carrier leaves
	// them zero. They exist so an arm that switches the GSO path can prove
	// from the status document which path ran.
	TxGSOCalls    uint64
	TxGSOSegments uint64
	TxBatchCalls  uint64
	TxGSODisabled bool
	// Foreign counts datagrams discarded because they came from an address that
	// is not the configured peer. Datagram carriers only.
	//
	// Foreign moving is NOT evidence that the peer moved. It is exactly as
	// consistent with an off-path attacker who found the five-tuple, and letting
	// it stand as mobility evidence would hand that attacker the return path.
	// See PeerMoves for the evidence that does distinguish the two.
	Foreign uint64
	// PeerMoves counts times the return path was moved to a new address, and
	// LastPeerMove is when the most recent move happened. Datagram carriers with
	// an explicit peer only.
	//
	// This is the ONE counter in this struct that no unauthenticated party can
	// move. SetPeer's contract is that a caller may call it only after a datagram
	// from that address has DISPATCHED — that is, opened under the session AEAD —
	// so a mover already holds the session key and is by definition the peer.
	// That is what makes it the evidence separating a NAT rebind from a censor:
	//
	//   Foreign climbing, Delivered frozen, PeerMoves frozen  -> could be either;
	//                                                            treat as a block
	//   PeerMoves moved                                       -> the peer moved,
	//                                                            authenticated
	//
	// Without it the two are byte-for-byte identical in these counters, and they
	// want opposite responses: a rebind wants the peer address updated, a block
	// wants a carrier-class escalation. Escalating on a rebind costs a mobile
	// user a re-handshake every time they change cell.
	PeerMoves    uint64
	LastPeerMove time.Time
	// LastSend and LastDelivered are the times of the most recent success in
	// each direction. Zero means never.
	LastSend      time.Time
	LastDelivered time.Time
}

// Errors. Every one is local. Nothing in this package is ever turned into an
// observable response to a peer: a carrier that answered a malformed stream with
// anything at all would reopen the probe oracle §4.3 closes.
var (
	// ErrConfig is an invalid carrier configuration.
	ErrConfig = errors.New("winn3/carrier: invalid configuration")

	// ErrClosed is returned by every method once Close has been called.
	ErrClosed = errors.New("winn3/carrier: carrier is closed")

	// ErrMessageTooLarge is returned by Send for a message above
	// MaxMessageSize. It is a refusal, never a truncation: a truncated message
	// fails to open at the far end and looks exactly like an attack.
	ErrMessageTooLarge = errors.New("winn3/carrier: message exceeds the carrier maximum")

	// ErrMessageEmpty is returned by Send for a zero-length message. There is no
	// legal empty Winn3 message — the floor is session.MessageFloor() — and a
	// zero-length record on a stream is indistinguishable from a desynchronised
	// one.
	ErrMessageEmpty = errors.New("winn3/carrier: message is empty")

	// ErrSizeBelowFloor is returned by SetMaxMessageSize for a size that cannot
	// carry the smallest message the session will ever emit.
	ErrSizeBelowFloor = errors.New("winn3/carrier: size is below the session message floor")

	// ErrSizeAbovePath is returned by SetMaxMessageSize for a size whose wrapped
	// packet would not fit the carrier's path. Accepting it would trade a clear
	// error for silent fragmentation, and a fragmented Winn3 message is itself a
	// distinctive fingerprint.
	ErrSizeAbovePath = errors.New("winn3/carrier: size exceeds what this path carries unfragmented")

	// ErrStreamDesync is returned when a sealed length record does not open. A
	// stream carrier cannot resynchronise, by construction and on purpose: a
	// resynchronisation marker would be a plaintext field at a findable offset,
	// which is the fingerprint the encrypted length exists to remove. The
	// carrier is dead and the caller must replace it.
	ErrStreamDesync = errors.New("winn3/carrier: stream length record did not authenticate")

	// ErrStreamExhausted is returned when a stream's length-record counter
	// reaches its ceiling. Continuing would reuse a (key, nonce) pair.
	ErrStreamExhausted = errors.New("winn3/carrier: stream length counter exhausted")

	// ErrSecret is returned for a carrier secret that is too short to key the
	// length layer.
	ErrSecret = errors.New("winn3/carrier: carrier secret is too short")

	// ErrMigrationWouldBlackHole is returned by Migrate when the destination
	// carrier is narrower than the session was built for and the session cannot
	// be told. See §5 of the handoff.
	ErrMigrationWouldBlackHole = errors.New(
		"winn3/carrier: migration would silently black hole full-size flows")
)

func wrap(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{sentinel}, args...)...)
}

// Clock is winn3/session's clock, aliased rather than redefined.
//
// Two packages in one protocol defining two clock interfaces is how their
// notions of "now" drift apart, and the 25.000-second metronome was a timing
// policy living in the wrong layer. There is one clock type in this protocol.
type Clock = session.Clock

// SystemClock is winn3/session's system clock.
type SystemClock = session.SystemClock

// Reporter is the part of *session.Driver this package reads.
//
// It is deliberately three methods wide. A carrier does not need the driver and
// must not acquire it: the session holds the keys and this package must never be
// able to reach them. What it needs is the §4.2 normative signal and enough
// state to say whether the signal is still meaningful.
type Reporter interface {
	// NeedsCarrierChange reports that the handshake budget was spent on this
	// carrier. It is the signal, not the decision.
	NeedsCarrierChange() bool
	// NeedsNewSession reports that the session is unrecoverable and a fresh
	// handshake is required.
	NeedsNewSession() bool
	// State is the session state machine's current state.
	State() session.State
	// PathNarrowed reports that the session has proven the path carries small
	// messages and not full-size ones.
	//
	// It is here because it is the one liveness fact no carrier counter can
	// reach. A narrowed outer path leaves every counter in this package
	// motionless — the writes succeed, because a DF path reports nothing — while
	// every full-size flow black holes. Only the session, which gets round trips
	// answered in two size classes, can see it, and only a policy layer can act
	// on it.
	PathNarrowed() bool
}

// The driver must satisfy Reporter. This assertion is the coordination point
// between the two lanes: if winn3/session narrows any of these three methods,
// this package fails to build rather than silently losing the carrier-change
// signal, which would strand a fleet on a blocked transport with no symptom.
var _ Reporter = (*session.Driver)(nil)

// Signal is what this package reports upward. It contains no decision.
//
// Everything here is an observation. Which carrier class to try next, in what
// order, and whether to try at all are computed by datapath/escalation.go from a
// wider evidence base than a single carrier has — plan validity, mobility
// priority, the all-UDP refusal — and acted on by datapath/failover.go.
// Recomputing any of that here would give the fleet two opinions that disagree
// under exactly the conditions that make disagreement expensive.
type Signal struct {
	// Class is the carrier the observation came from.
	Class Class
	// NeedsChange is the driver's NeedsCarrierChange(), passed through
	// unmodified.
	NeedsChange bool
	// NeedsNewSession is the driver's NeedsNewSession(), passed through
	// unmodified.
	NeedsNewSession bool
	// State is the driver's state at the moment of observation.
	State session.State
	// PathNarrowed is the driver's size-aware liveness verdict, passed through
	// unmodified: full-size round trips fail and small ones succeed. It is not a
	// failure — the session is established and small traffic works — which is
	// exactly why it has to be carried: it is otherwise invisible.
	PathNarrowed bool
	// CarrierErr is the carrier's own last fatal error, if it has one. A dead
	// carrier and a session that wants a different carrier are different facts
	// and the policy layer treats them differently.
	CarrierErr error
	// Stats is the carrier's counters at the moment of observation.
	Stats Stats
}

// Observe reads the driver's carrier-change signal and the carrier's own health
// and returns them together.
//
// It chooses nothing, and it is a plain function rather than a method so that
// the absence of state — and therefore the absence of a policy that could
// accumulate in it — is visible at the call site.
func Observe(r Reporter, c Conn) Signal {
	sig := Signal{}
	if c != nil {
		sig.Class = c.Class()
		sig.Stats = c.Stats()
		if d, ok := c.(interface{ fatal() error }); ok {
			sig.CarrierErr = d.fatal()
		}
	}
	if r != nil {
		sig.NeedsChange = r.NeedsCarrierChange()
		sig.NeedsNewSession = r.NeedsNewSession()
		sig.State = r.State()
		sig.PathNarrowed = r.PathNarrowed()
	}
	return sig
}

// checkSize is the shared SetMaxMessageSize validation. pathCeiling is the
// largest message this carrier's class and family can wrap without fragmenting.
func checkSize(n, pathCeiling int) error {
	if n < session.MessageFloor() {
		return wrap(ErrSizeBelowFloor, "%d is below the %d-byte floor", n, session.MessageFloor())
	}
	if n > pathCeiling {
		return wrap(ErrSizeAbovePath, "%d exceeds the %d-byte ceiling for this path", n, pathCeiling)
	}
	return nil
}
