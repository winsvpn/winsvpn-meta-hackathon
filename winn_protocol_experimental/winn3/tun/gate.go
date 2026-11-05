package tun

import "sync"

// State is the session's carrying state, as the tun layer needs to see it.
//
// The tun layer never infers this. It does not watch epochs, it does not count
// handshake messages and it does not decide whether StrictPQ has been
// satisfied — all of that is the session driver's, and a second implementation
// of the same judgement in a second package is how two layers come to disagree
// about whether a tunnel is up. The driver states the state; this layer
// enforces it.
type State uint8

const (
	// StateDown is the zero value, deliberately. A Gate that was never
	// configured, a struct that was allocated and not initialised, and a
	// session that has been torn down all read the same, and that reading is
	// "carry nothing".
	StateDown State = iota

	// StateHandshaking means a handshake is in flight. No inner packet exists
	// yet that could legitimately cross.
	StateHandshaking

	// StateEpoch0 means the handshake completed but the post-quantum ratchet
	// has not. Under StrictPQ — the design's default — no DATA frame may be
	// sent in this state, and the tun layer treats it as closed. A driver
	// running FastPQ reports StateCarrying at epoch 0 instead; that is the
	// driver's decision to own and label, not this layer's to second-guess.
	StateEpoch0

	// StateCarrying is the ONLY state in which an inner packet may move.
	StateCarrying

	// StateRekeying means an epoch change is in flight. Inner packets stop.
	// The alternative — carrying across the ratchet — means either sending
	// under a key the peer is about to discard or holding packets in a queue
	// that survives the transition, and the second is how a packet gets emitted
	// under the wrong epoch.
	StateRekeying

	// StateClosed is terminal: a CLOSE frame was sent or received.
	StateClosed
)

// MayCarry reports whether inner packets may cross in this state.
//
// It is written as a whitelist of exactly one value and not as a blacklist,
// and TestOnlyOneStateCarries walks all 256 byte values to prove it stayed
// that way. A blacklist is the shape that fails open when somebody adds a
// state and forgets to add a case, which is precisely the mistake this
// property cannot afford.
func (s State) MayCarry() bool { return s == StateCarrying }

// String is THE SOURCE OF TRUTH for the gate-state vocabulary that crosses the
// engine→host boundary.
//
// ===========================================================================
// WHY THAT SENTENCE IS LOAD-BEARING AND NOT A DOC COMMENT
// ===========================================================================
//
// These six strings are not diagnostics. cmd/winn-datapath publishes the
// result of this method as `gate_state` in the engine's status document, and
// every host on every platform decides whether to promote a tunnel by
// comparing that field against a name it holds a copy of:
//
//	android/app/.../WinnV3StagedStart.kt          WinnV3GateState(val wire:)
//	android/devicecheck/.../WinnV3StagedStart.kt  the same enum, second copy
//	windows/runner/winn3_posture.h                kCarryingGate
//	apple/WinsTunnelCore/WinsWinn3HostContract.swift  carryingState
//	linux/runner/linux_winn3_host.cc              via winn3_posture.h's constant
//
// Until 2026-08-09 nothing pinned those copies to this switch. Renaming
// `carrying` here made all of them parse an unrecognised name, every
// `mayCarry()` answer false, and the promotion never fire — while the tunnel
// handshook, rekeyed and moved bytes exactly as designed. It fails CLOSED and
// SILENTLY, which under the Myanmar threat model is indistinguishable from the
// censor, because a v3 gateway never answers an unauthenticated datagram and
// so there is no second opinion to consult.
//
// [DeclaredStates] and [ParseState] exist so the vocabulary can be WALKED
// rather than restated, and winn3/conform's
// TestTheGateStateVocabularyIsTheSameOnEveryHost derives its expectations from
// this method and reads each host's own source. Change a name here and that
// test names the mismatch and every host affected. Change a host's literal and
// it fails the other way. Do not add a state without adding it to
// [DeclaredStates]; TestEveryNamedStateIsDeclaredAndEveryDeclaredStateIsNamed
// walks all 256 byte values to make that impossible to forget.
func (s State) String() string {
	switch s {
	case StateDown:
		return "down"
	case StateHandshaking:
		return "handshaking"
	case StateEpoch0:
		return "epoch0"
	case StateCarrying:
		return "carrying"
	case StateRekeying:
		return "rekeying"
	case StateClosed:
		return "closed"
	default:
		return InvalidStateName
	}
}

// InvalidStateName is what [State.String] calls a value that is not a declared
// state.
//
// It is a SENTINEL and never a state name. [ParseState] refuses it for that
// reason: a host that echoed back a name it did not recognise must not be able
// to round-trip it into a State, and the one State it must never arrive at is
// StateCarrying.
const InvalidStateName = "invalid"

// DeclaredStates is the vocabulary, in ordinal order, in ONE place.
//
// Everything that needs the set of names walks this rather than restating it:
// [ParseState] below, the tun package's own tests, and winn3/conform's
// cross-host guard. Four hosts holding four hand-copied lists of these strings
// is exactly the defect closed on 2026-08-09, and a second hand-written list
// inside Go would be the same mistake one layer down.
func DeclaredStates() []State {
	return []State{
		StateDown,
		StateHandshaking,
		StateEpoch0,
		StateCarrying,
		StateRekeying,
		StateClosed,
	}
}

// ParseState is the inverse of [State.String], and it is DERIVED from
// [State.String] rather than written beside it.
//
// Two implementations of one mapping is how the mapping comes to disagree with
// itself, so this walks [DeclaredStates] and compares each name rather than
// carrying a second switch. It is the reference every host's own parser
// mirrors, and the shape it mirrors is the important part:
//
//   - The match is EXACT. No trimming, no case folding, no prefix. A host may
//     normalise before it calls its own equivalent — Android's fromWire trims
//     and lowercases — but the vocabulary itself has one spelling.
//   - An unrecognised name returns ok=false and StateDown, the zero value,
//     which does not carry. It never returns StateCarrying and never returns a
//     "closest" state. A parser that defaults is the shape that fails OPEN the
//     moment the other side of the seam adds a name, and this seam's whole
//     purpose is that it fails closed.
//   - [InvalidStateName] is not accepted. It is what String() says about a
//     value that is not a state; parsing it back into one would make the
//     sentinel a seventh member of the vocabulary.
func ParseState(name string) (State, bool) {
	for _, s := range DeclaredStates() {
		if s.String() == name {
			return s, true
		}
	}
	return StateDown, false
}

// Gate is the fail-closed authority, and the only thing in this package that
// permits an inner packet to move.
//
// It is not a boolean read under a mutex. The interesting failure is not
// "reads a stale value" — it is the time-of-check-to-time-of-use window
// between deciding a packet may cross and actually handing it to the session:
// a session that tore down inside that window has a packet in flight that the
// teardown believed it had stopped. The obvious implementations all have that
// window.
//
// So Gate is a drain barrier. Enter takes a read hold; Set and exclude take
// the write lock and therefore BLOCK until every hold outstanding at the
// moment of the call has been released, and no new hold can be taken while
// they wait. When Set(StateDown) returns, there is no packet anywhere in this
// package still on its way to the session or to the device.
// ClampInnerMTU uses exclude for the same reason: the inner MTU must not
// change under an in-flight packet. TestGateDrainsInFlightSenders,
// TestNoPacketCrossesAfterTheGateCloses and
// TestClampInnerMTUHoldsTheGateUntilSetMTUReturns pin the three halves.
//
// The cost is real and is accepted: a slow FrameSink.SendData delays a state
// change for as long as it runs. For a kill switch that is the correct
// trade — a teardown that returns before its traffic has stopped has reported
// a safety property it does not have.
type Gate struct {
	mu    sync.RWMutex
	state State
	gen   uint64
}

// NewGate returns a gate that is closed. There is no constructor that returns
// an open one; a session must reach StateCarrying explicitly.
func NewGate() *Gate { return &Gate{} }

// Set moves the gate to s and returns only after every in-flight hold has
// drained. Safe to call from any goroutine.
func (g *Gate) Set(s State) {
	g.mu.Lock()
	if g.state != s {
		g.gen++
	}
	g.state = s
	g.mu.Unlock()
}

// State reports the current state.
func (g *Gate) State() State {
	g.mu.RLock()
	s := g.state
	g.mu.RUnlock()
	return s
}

// Generation counts transitions. It exists for diagnostics and for tests that
// need to say "this packet was accepted under that state", not for control
// flow.
func (g *Gate) Generation() uint64 {
	g.mu.RLock()
	n := g.gen
	g.mu.RUnlock()
	return n
}

// enter takes a hold if the gate permits carrying. On true the caller MUST
// call leave exactly once; on false it holds nothing.
func (g *Gate) enter() bool {
	g.mu.RLock()
	if !g.state.MayCarry() {
		g.mu.RUnlock()
		return false
	}
	return true
}

func (g *Gate) leave() { g.mu.RUnlock() }

// exclude takes the write lock, draining every enter() hold, and returns the
// state observed under that lock. The caller MUST call unlock. Do not call
// State, Set, Generation, enter or leave until unlock runs: those take the
// same mutex and would deadlock on this goroutine.
func (g *Gate) exclude() (state State, unlock func()) {
	g.mu.Lock()
	return g.state, g.mu.Unlock
}
