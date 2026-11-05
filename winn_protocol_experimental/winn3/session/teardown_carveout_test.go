package session

import (
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// TestNewFromSessionCloseObservationTeardownCarveOut pins the deterministic
// teardown of a driver adopted through NewFromSession when it observes a peer's
// CLOSE, driven entirely by the injected step clock.
//
// Two properties are why this test exists, and neither is covered by the
// NewClient/NewGateway pair tests:
//
//  1. The teardown carve-out. A session that commits to closing must not wait
//     out its next scheduled deadline to say so. StateClosing reports NextDeadline
//     at Now, not at the far-future silence/probe/rekey deadline, so the queued
//     CLOSE is emitted on the very next Poll. Without the carve-out a teardown
//     would be parked behind a timer that on a healthy session is hours away --
//     the difference between a teardown a step clock can drive to a deterministic
//     end and one that depends on when a timer happens to fire.
//
//  2. The CLOSE is observed and acted on deterministically by the peer. The end
//     that receives it sees PeerCloseReason, asks for a new session and reaches a
//     terminal state immediately, no matter how far its own scheduled deadline is.
//     The adoption seam matters here: NewFromSession builds a driver around an
//     already-handshaken session, and the Retry schedule that Config inherits must
//     not make an observed CLOSE look like a handshake worth retrying -- the
//     driver tears down, it does not re-enter the initiating phase.
func TestNewFromSessionCloseObservationTeardownCarveOut(t *testing.T) {
	cliSess, gwSess, cliStatic, gwStatic, gwPub, initiatorStatic := coreHandshake(t)
	clk := newClock()

	cliCfg := Config{
		Core:          core.Config{Gateway: gatewayParams(t)},
		Static:        cliStatic,
		GatewayStatic: gwPub,
		Padding:       core.PadBucket,
		Clock:         clk,
		Rand:          newDetRand("teardown-cli"),
		Retry:         Retry{Base: time.Second, Cap: 4 * time.Second, Attempts: 3},
	}
	gwCfg := Config{
		Core:    core.Config{Gateway: gatewayParams(t)},
		Static:  gwStatic,
		Accept:  func([]byte) error { return nil },
		Padding: core.PadBucket,
		Clock:   clk,
		Rand:    newDetRand("teardown-gw"),
	}

	// Both ends park silence/probe/rekey at quietHorizon so their scheduled
	// deadlines are hours in the future: any teardown that happened by waiting
	// for a deadline instead of carving out would never complete inside a test.
	quietConfig(&cliCfg)
	quietConfig(&gwCfg)
	cliCfg.Silence = silentDraw()
	gwCfg.Silence = silentDraw()

	cliDrv, err := NewFromSession(cliCfg, cliSess, nil)
	if err != nil {
		t.Fatalf("NewFromSession initiator: %v", err)
	}
	gwDrv, err := NewFromSession(gwCfg, gwSess, initiatorStatic)
	if err != nil {
		t.Fatalf("NewFromSession responder: %v", err)
	}

	// Drive the adopted pair through the post-quantum ratchet to Established,
	// the same way the production loop would, using only Poll and Deliver.
	for i := 0; i < 40 && (cliDrv.State() != StateEstablished || gwDrv.State() != StateEstablished); i++ {
		for {
			msg, err := cliDrv.Poll()
			if err != nil {
				t.Fatalf("cli poll: %v", err)
			}
			if msg == nil {
				break
			}
			if _, err := gwDrv.Deliver(msg); err != nil {
				t.Fatalf("gw deliver: %v", err)
			}
		}
		for {
			msg, err := gwDrv.Poll()
			if err != nil {
				t.Fatalf("gw poll: %v", err)
			}
			if msg == nil {
				break
			}
			if _, err := cliDrv.Deliver(msg); err != nil {
				t.Fatalf("cli deliver: %v", err)
			}
		}
		clk.Advance(2 * time.Second)
	}
	if cliDrv.State() != StateEstablished || gwDrv.State() != StateEstablished {
		t.Fatalf("adopted pair did not establish: cli %s gw %s (err %v / %v)",
			cliDrv.State(), gwDrv.State(), cliDrv.Err(), gwDrv.Err())
	}

	// Both ends now have a scheduled deadline hours in the future. Prove it, so
	// the carve-out below is measured against a real parked deadline and not a
	// zero.
	now := clk.Now()
	cliScheduled := cliDrv.NextDeadline()
	if cliScheduled.IsZero() || !cliScheduled.After(now) {
		t.Fatalf("established client scheduled deadline %s is not in the future of %s; the carve-out has nothing to carve out of",
			cliScheduled, now)
	}

	// The gateway commits to a liveness-driven teardown that requires a new
	// session. Its CLOSE is queued, not yet on the wire: StateClosing.
	gwDrv.beginClose(CloseDesynchronised, ErrPeerUnreachable)
	if gwDrv.State() != StateClosing {
		t.Fatalf("gateway state is %s after committing to teardown, want closing", gwDrv.State())
	}
	if !gwDrv.NeedsNewSession() {
		t.Error("gateway committed to a desync teardown but did not ask for a new session")
	}

	// THE CARVE-OUT: even though the gateway's scheduled deadline is hours away,
	// NextDeadline must report Now so the queued CLOSE is emitted on the very
	// next Poll. If this regresses to the scheduled deadline, the test fails.
	dl := gwDrv.NextDeadline()
	if dl.IsZero() {
		t.Fatal("a closing gateway reports no deadline; the CLOSE would never be polled")
	}
	if dl.After(now) {
		t.Fatalf("closing gateway deadline %s is in the future of %s; teardown is parked behind the scheduled deadline instead of carving out",
			dl, now)
	}

	// Emit the CLOSE and deliver it to the peer.
	var closeMsg []byte
	for i := 0; i < 4 && closeMsg == nil; i++ {
		m, err := gwDrv.Poll()
		if err != nil {
			t.Fatalf("gw poll while closing: %v", err)
		}
		closeMsg = m
	}
	if closeMsg == nil {
		t.Fatal("the closing gateway emitted no CLOSE on the next Poll")
	}
	// Once the CLOSE is built, the gateway runs its after-hook and terminates.
	if !gwDrv.State().Terminal() {
		t.Errorf("gateway state is %s after emitting its CLOSE, want terminal", gwDrv.State())
	}

	// The CLOSE-observation: the client opens the message and learns from the
	// frame. Its own scheduled deadline is still hours away -- the observation
	// must tear it down immediately, not after waiting out that deadline.
	if _, err := cliDrv.Deliver(closeMsg); err != nil {
		t.Fatalf("client deliver of CLOSE: %v", err)
	}
	if !cliDrv.State().Terminal() {
		t.Fatalf("client state is %s after observing CLOSE, want terminal", cliDrv.State())
	}
	if got := cliDrv.PeerCloseReason(); got != CloseDesynchronised {
		t.Errorf("client saw peer close reason %s, want %s", got, CloseDesynchronised)
	}
	if !cliDrv.NeedsNewSession() {
		t.Error("client did not ask for a new session after observing a desync CLOSE")
	}
	if !cliDrv.NextDeadline().IsZero() {
		t.Error("a terminal client still reports a deadline")
	}
	// The observed CLOSE must not re-enter the retry loop: Poll stays quiet and
	// the driver does not spend its handshake budget.
	if msg, err := cliDrv.Poll(); msg != nil || err != nil {
		t.Errorf("terminal client poll returned %v, %v; teardown must not retry", msg, err)
	}
	if cliDrv.NeedsCarrierChange() {
		t.Error("an observed CLOSE surfaced as a carrier change; that is the handshake-budget signal, not a teardown")
	}
}

// pollFor returns the next non-nil message a driver wants to send. The closing
// driver below emits exactly one message -- its queued CLOSE -- so the first
// non-nil is the CLOSE and the drive is deterministic.
func pollFor(t *testing.T, d *Driver) []byte {
	t.Helper()
	for i := 0; i < 4; i++ {
		m, err := d.Poll()
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		if m != nil {
			return m
		}
	}
	return nil
}

// establishAdoptedPair drives an adopted NewFromSession pair through the
// post-quantum ratchet to StateEstablished the same way the production loop
// does, using only Poll and Deliver on the injected step clock.
func establishAdoptedPair(t *testing.T, cliDrv, gwDrv *Driver, clk *testClock) {
	t.Helper()
	for i := 0; i < 40 && (cliDrv.State() != StateEstablished || gwDrv.State() != StateEstablished); i++ {
		for {
			msg, err := cliDrv.Poll()
			if err != nil {
				t.Fatalf("cli poll: %v", err)
			}
			if msg == nil {
				break
			}
			if _, err := gwDrv.Deliver(msg); err != nil {
				t.Fatalf("gw deliver: %v", err)
			}
		}
		for {
			msg, err := gwDrv.Poll()
			if err != nil {
				t.Fatalf("gw poll: %v", err)
			}
			if msg == nil {
				break
			}
			if _, err := cliDrv.Deliver(msg); err != nil {
				t.Fatalf("cli deliver: %v", err)
			}
		}
		clk.Advance(2 * time.Second)
	}
	if cliDrv.State() != StateEstablished || gwDrv.State() != StateEstablished {
		t.Fatalf("adopted pair did not establish: cli %s gw %s (err %v / %v)",
			cliDrv.State(), gwDrv.State(), cliDrv.Err(), gwDrv.Err())
	}
}

// newTeardownAdoptedPair builds the two adopted drivers and establishes them,
// mirroring the setup of TestNewFromSessionCloseObservationTeardownCarveOut but
// kept separate so a teardown test does not have to carry an observation test.
func newTeardownAdoptedPair(t *testing.T) (cliDrv, gwDrv *Driver, clk *testClock) {
	t.Helper()
	cliSess, gwSess, cliStatic, gwStatic, gwPub, initiatorStatic := coreHandshake(t)
	clk = newClock()

	cliCfg := Config{
		Core:          core.Config{Gateway: gatewayParams(t)},
		Static:        cliStatic,
		GatewayStatic: gwPub,
		Padding:       core.PadBucket,
		Clock:         clk,
		Rand:          newDetRand("teardown-inflight-cli"),
		Retry:         Retry{Base: time.Second, Cap: 4 * time.Second, Attempts: 3},
	}
	gwCfg := Config{
		Core:    core.Config{Gateway: gatewayParams(t)},
		Static:  gwStatic,
		Accept:  func([]byte) error { return nil },
		Padding: core.PadBucket,
		Clock:   clk,
		Rand:    newDetRand("teardown-inflight-gw"),
	}
	quietConfig(&cliCfg)
	quietConfig(&gwCfg)
	cliCfg.Silence = silentDraw()
	gwCfg.Silence = silentDraw()

	var err error
	cliDrv, err = NewFromSession(cliCfg, cliSess, nil)
	if err != nil {
		t.Fatalf("NewFromSession initiator: %v", err)
	}
	gwDrv, err = NewFromSession(gwCfg, gwSess, initiatorStatic)
	if err != nil {
		t.Fatalf("NewFromSession responder: %v", err)
	}
	establishAdoptedPair(t, cliDrv, gwDrv, clk)
	return cliDrv, gwDrv, clk
}

// TestTeardownCarveOutRefusesWorkAndAccountsQueuedInflightData pins the
// in-flight-teardown carve-out on the OUTBOUND side of a local Close.
//
// The observation test above tears down over a quiet wire. This one starts with
// traffic genuinely in flight: packets accepted by Enqueue while Established but
// not yet assembled into a message when Close commits.
//
// The requirement is stated as "drained OR refused, never dropped silently with
// a false success", and of the two this session refuses. Two guarantees hold:
//
//  1. REFUSED after commit. Once Close() has committed the driver to closing,
//     Enqueue must answer ErrClosed rather than accept a packet it will discard.
//     A packet that can never reach the wire must not be reported as accepted;
//     that is the false success this carve-out forbids.
//
//  2. ACCOUNTED at teardown, never dropped silently. The packets accepted
//     BEFORE Close() are already past the point of refusal -- their Enqueue
//     returned nil -- so the driver cannot un-accept them. What it must not do
//     is let them vanish with no trace. Every one of them is counted into
//     Stats.DataFramesDropped, the same counter that records DATA refused
//     because the session was not in a state that may carry them, so a teardown
//     that refused N live packets is visible to an operator in the same place
//     as every other refused frame.
//
// The test asserts the exact accounting (the counter rises by exactly the number
// of packets in flight and by no more), asserts none of them were drained onto
// the wire, and asserts the teardown still completes through the carve-out -- the
// queued CLOSE is emitted on the next Poll and reaches the peer.
func TestTeardownCarveOutRefusesWorkAndAccountsQueuedInflightData(t *testing.T) {
	cliDrv, gwDrv, clk := newTeardownAdoptedPair(t)

	const n = 5
	for i := 0; i < n; i++ {
		if err := cliDrv.Enqueue([]byte{byte(i + 1)}); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	before := cliDrv.Stats().DataFramesDropped

	// Commit to an orderly teardown while those packets are still queued and
	// not one of them has been assembled into a message.
	if err := cliDrv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if cliDrv.State() != StateClosing {
		t.Fatalf("state after Close is %s, want closing", cliDrv.State())
	}

	// Guarantee 1: refused after commit. No further packet is accepted while the
	// CLOSE is still queued, so no packet is handed a success that will become a
	// silent drop.
	if err := cliDrv.Enqueue([]byte("late")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Enqueue after Close returned %v, want ErrClosed", err)
	}

	// The carve-out itself: NextDeadline is Now while closing, so the very next
	// Poll yields the CLOSE. Nothing about the queued data precedes it.
	if dl := cliDrv.NextDeadline(); dl.IsZero() || dl.After(clk.Now()) {
		t.Fatalf("closing client deadline %s is not at now %s; teardown is parked", dl, clk.Now())
	}
	closeMsg := pollFor(t, cliDrv)
	if closeMsg == nil {
		t.Fatal("the closing client emitted no CLOSE on the next Poll")
	}
	if !cliDrv.State().Terminal() {
		t.Fatalf("client state is %s after emitting its CLOSE, want terminal", cliDrv.State())
	}
	if _, err := gwDrv.Deliver(closeMsg); err != nil {
		t.Fatalf("gateway deliver of CLOSE: %v", err)
	}
	if !gwDrv.State().Terminal() {
		t.Fatalf("gateway state is %s after receiving CLOSE, want terminal", gwDrv.State())
	}
	if got := gwDrv.PeerCloseReason(); got != CloseNormal {
		t.Errorf("gateway saw peer close reason %s, want %s", got, CloseNormal)
	}

	// Guarantee 2: the in-flight packets are accounted for, not silently dropped.
	after := cliDrv.Stats().DataFramesDropped
	if got := after - before; got != uint64(n) {
		t.Errorf("DataFramesDropped rose by %d over a teardown that discarded %d queued packets; the drop must be accounted, not silent",
			got, n)
	}

	// And they were not drained onto the wire: refusing a teardown's in-flight
	// traffic must not be mistaken for having sent it. The client sent exactly
	// the CLOSE; no queued data frame preceded or followed it onto the link.
	if cliDrv.Stats().DataFramesSent != 0 {
		t.Errorf("client sent %d data frames during teardown; in-flight packets must be refused, not drained",
			cliDrv.Stats().DataFramesSent)
	}
}

// TestTeardownCarveOutAccountsQueuedDataWhenPeerCloseArrives pins the same
// accounting on the PEER-CLOSE path: data queued and accepted while Established,
// discarded because a CLOSE arrived before it could be sent, must land in
// Stats.DataFramesDropped rather than vanish without a trace.
//
// This is the inbound half of the in-flight carve-out. It exercises the
// terminate() discard path directly (an observed CLOSE calls terminate without
// going through beginClose), so it is the guard that keeps peer-close teardowns
// honest as well as local ones.
func TestTeardownCarveOutAccountsQueuedDataWhenPeerCloseArrives(t *testing.T) {
	cliDrv, gwDrv, _ := newTeardownAdoptedPair(t)

	const n = 4
	for i := 0; i < n; i++ {
		if err := cliDrv.Enqueue([]byte{byte(i + 1)}); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	before := cliDrv.Stats().DataFramesDropped

	// The peer commits to its own orderly close; its queued CLOSE, not any data,
	// arrives at the client while the client's packets are still in flight.
	if err := gwDrv.Close(); err != nil {
		t.Fatalf("gateway Close: %v", err)
	}
	closeMsg := pollFor(t, gwDrv)
	if closeMsg == nil {
		t.Fatal("the closing gateway emitted no CLOSE on the next Poll")
	}
	if _, err := cliDrv.Deliver(closeMsg); err != nil {
		t.Fatalf("client deliver of CLOSE: %v", err)
	}
	if !cliDrv.State().Terminal() {
		t.Fatalf("client state is %s after observing CLOSE, want terminal", cliDrv.State())
	}
	if got := cliDrv.PeerCloseReason(); got != CloseNormal {
		t.Errorf("client saw peer close reason %s, want %s", got, CloseNormal)
	}

	// The client's queued packets were discarded on observation; the discard is
	// accounted, not silent.
	after := cliDrv.Stats().DataFramesDropped
	if got := after - before; got != uint64(n) {
		t.Errorf("DataFramesDropped rose by %d over a peer-close that discarded %d queued packets; the drop must be accounted, not silent",
			got, n)
	}
}

