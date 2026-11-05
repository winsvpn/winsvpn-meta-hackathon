package session

import (
	"errors"
	"testing"
	"time"
)

// TestDroppedRekeyAckWhenGatewayInitiatesClosesTheClientWithRekeyUnconfirmed
// is the role-reversed sibling of
// TestDroppedRekeyAckAdvancesOnlyTheResponderThenInitiatorTimesOut, and pins
// the F-03 rekey-ACK-loss blackhole fix.
//
// That test has the CLIENT call startRekey, so the client's tun/session gate
// stays StateRekeying (MayCarry false) until ErrRekeyFailed. This test has the
// GATEWAY call startRekey. The client is the rekey responder: onRekeyInit
// queues FrameRekeyAck with after=completeRekey, assemble runs that hook
// before carrier Send, and completeRekey → establish returns the client to
// StateEstablished on the new epoch. The ACK is then dropped.
//
// What the client used to observe was the worst realistic rekey failure,
// because it is the shape a censor produces: Established, Epoch advanced,
// Enqueue accepting packets for an epoch the gateway cannot open, silently and
// forever. F-03 changes the contract: the client commits because the
// ACK is the peer's only trigger, but it arms a confirmation deadline
// (rekeyConfirmAt = commit + RekeyTimeout). Any message the gateway seals
// under the new epoch clears it; nothing arriving means the ACK never landed.
// On expiry the client closes LOUDLY with CloseRekeyUnconfirmed /
// ErrRekeyUnconfirmed, so the app layer tears the tunnel down visibly and
// reconnects instead of carrying into silence. The responder-side behavior is
// intact: the gateway still waits out its own rekeyEnd and fails
// CloseRekeyFailed / ErrRekeyFailed, and its CLOSE remains sealed under the
// old epoch (unopenable to the client).
func TestDroppedRekeyAckWhenGatewayInitiatesClosesTheClientWithRekeyUnconfirmed(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		gw.RekeyTimeout = 5 * time.Second
		cli.RekeyTimeout = 5 * time.Second
	})
	p.establish()
	cliEpoch := p.cli.Epoch()
	gwEpoch := p.gw.Epoch()
	if cliEpoch != gwEpoch {
		t.Fatalf("precondition: epochs already diverged: client %d gateway %d", cliEpoch, gwEpoch)
	}
	unopenableBefore := p.gw.Stats().Unopenable
	p.resetDelivered()

	start := p.nToGw
	// Drop only the ACK. `idx < start` also swallows every later client→gateway
	// message, so the DATA this test Enqueues never reaches Deliver and
	// Unopenable stays 0 — a false FAIL of a characterisation that is still true.
	p.filterToGw = func(idx int, _ []byte) bool { return idx != start }
	if err := p.gw.startRekey(p.clk.Now()); err != nil {
		t.Fatal(err)
	}
	p.run()

	if p.gw.State() != StateRekeying {
		t.Fatalf("gateway state is %s after a dropped ACK, want rekeying", p.gw.State())
	}
	if p.cli.State() != StateEstablished {
		t.Fatalf("client state is %s after sending ACK, want established", p.cli.State())
	}
	if p.cli.Epoch() != cliEpoch+1 {
		t.Fatalf("client epoch is %d, want %d (ratchet already installed)", p.cli.Epoch(), cliEpoch+1)
	}
	if p.gw.Epoch() != gwEpoch {
		t.Fatalf("gateway epoch is %d, want still %d (ACK never arrived)", p.gw.Epoch(), gwEpoch)
	}
	if p.cli.Stats().Rekeys != 1 {
		t.Fatalf("client Rekeys is %d, want 1", p.cli.Stats().Rekeys)
	}
	if p.gw.Stats().Rekeys != 0 {
		t.Fatalf("gateway Rekeys is %d, want 0", p.gw.Stats().Rekeys)
	}
	// F-03: the confirmation deadline is armed the moment the client committed,
	// because it has no other evidence the gateway followed.
	if p.cli.rekeyConfirmAt.IsZero() {
		t.Fatal("client rekeyConfirmAt is not armed after committing via the sealed ACK")
	}

	if got := p.cli.DataPlaneState(); got != StateRekeying {
		t.Fatalf("client data-plane state is %s after an unconfirmed ACK, want rekeying", got)
	}
	// Inside the bound the control plane is established but DATA and optional
	// cover are refused; accepting either would advertise a path that is known
	// to be black-holed.
	const payload = "must-blackhole-after-lost-ack"
	if err := p.cli.Enqueue([]byte(payload)); !errors.Is(err, ErrState) {
		t.Fatalf("Enqueue on the unconfirmed rekey responder returned %v, want ErrState", err)
	}
	if err := p.cli.EmitCover(); !errors.Is(err, ErrState) {
		t.Fatalf("EmitCover on the unconfirmed rekey responder returned %v, want ErrState", err)
	}
	p.run()
	if len(p.atGw) != 0 {
		t.Fatalf("gateway delivered %d inner packets after a lost ACK; the new-epoch DATA must be unopenable", len(p.atGw))
	}
	if p.gw.Stats().Unopenable != unopenableBefore {
		t.Fatalf("gateway Unopenable moved to %d from %d; held DATA must not be emitted",
			p.gw.Stats().Unopenable, unopenableBefore)
	}
	if p.cli.Stats().DataFramesSent != 0 {
		t.Fatalf("client sent %d DATA frames while rekey confirmation was pending", p.cli.Stats().DataFramesSent)
	}
	if p.cli.Err() != nil {
		t.Fatalf("client Err is %v before the confirmation deadline; the verdict must wait for the bound", p.cli.Err())
	}

	// Cross the bound. Both ends fail, each with its own verdict: the gateway
	// at rekeyEnd (unchanged), the client at its confirmation deadline (new).
	for i := 0; i < 10 && !p.gw.State().Terminal(); i++ {
		p.clk.Advance(2 * time.Second)
		p.run()
	}
	if !p.gw.State().Terminal() {
		t.Fatalf("gateway state is %s after the rekey timeout", p.gw.State())
	}
	if got := p.gw.LocalCloseReason(); got != CloseRekeyFailed {
		t.Errorf("gateway close reason is %s, want %s", got, CloseRekeyFailed)
	}
	if err := p.gw.Err(); !errors.Is(err, ErrRekeyFailed) {
		t.Errorf("gateway error is %v, want ErrRekeyFailed", err)
	}
	if !p.gw.NeedsNewSession() {
		t.Error("a failed rekey did not ask the gateway for a new session")
	}
	if p.gw.NeedsCarrierChange() {
		t.Error("a lost REKEY_ACK is not a dead carrier; gateway NeedsCarrierChange must stay false")
	}

	// The client no longer carries silently: this is the F-03 assertion that
	// replaces the old "stays Established with Err() == nil" characterisation.
	if !p.cli.State().Terminal() {
		t.Fatalf("client state is %s after the confirmation deadline; F-03 demands a loud close, not a silent carry", p.cli.State())
	}
	if got := p.cli.LocalCloseReason(); got != CloseRekeyUnconfirmed {
		t.Errorf("client close reason is %s, want %s", got, CloseRekeyUnconfirmed)
	}
	if err := p.cli.Err(); !errors.Is(err, ErrRekeyUnconfirmed) {
		t.Errorf("client error is %v, want ErrRekeyUnconfirmed", err)
	}
	if errors.Is(p.cli.Err(), ErrRekeyFailed) {
		t.Error("client unwrapped ErrRekeyFailed; that sentinel belongs to the initiator that waited out rekeyEnd")
	}
	if !p.cli.NeedsNewSession() {
		t.Error("an unconfirmed rekey commit must ask the client for a new session")
	}
	if p.cli.NeedsCarrierChange() {
		t.Error("client NeedsCarrierChange must stay false")
	}
	// The gateway's CLOSE is sealed under the old epoch, so the client never
	// parses a peer reason: it never arrives outside the dropped-ACK shape.
	if p.cli.PeerCloseReason() != 0 {
		t.Errorf("client opened a CLOSE reason %s; the CLOSE is under the old epoch and must be unopenable", p.cli.PeerCloseReason())
	}
}

// TestDelayedRekeyAckWithinTheUnconfirmedDeadlineStillConverges is the middle
// case F-03 must not break: the ACK is held back (delayed, not gone) and
// delivered inside the bound. The gateway then ratchets, its next sealed
// message confirms the new epoch to the client, the deadline clears, and the
// session converges with no close on either end — data still crosses.
func TestDelayedRekeyAckWithinTheUnconfirmedDeadlineStillConverges(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		gw.RekeyTimeout = 5 * time.Second
		cli.RekeyTimeout = 5 * time.Second
	})
	p.establish()
	startEpoch := p.cli.Epoch()
	p.resetDelivered()

	start := p.nToGw
	var ack []byte
	p.filterToGw = func(idx int, msg []byte) bool {
		if idx == start {
			ack = append([]byte(nil), msg...)
			return false
		}
		return true
	}
	if err := p.gw.startRekey(p.clk.Now()); err != nil {
		t.Fatal(err)
	}
	p.run()

	if p.cli.State() != StateEstablished || p.cli.Epoch() != startEpoch+1 {
		t.Fatalf("client is %s at epoch %d after sealing the ACK, want established at %d",
			p.cli.State(), p.cli.Epoch(), startEpoch+1)
	}
	if p.gw.State() != StateRekeying || p.gw.Epoch() != startEpoch {
		t.Fatalf("gateway is %s at epoch %d while the ACK is held, want rekeying at %d",
			p.gw.State(), p.gw.Epoch(), startEpoch)
	}
	if ack == nil {
		t.Fatal("the ACK was not captured; the filter never saw it")
	}
	if p.cli.rekeyConfirmAt.IsZero() {
		t.Fatal("client rekeyConfirmAt is not armed while the ACK is in flight")
	}
	if got := p.cli.DataPlaneState(); got != StateRekeying {
		t.Fatalf("client data-plane state is %s while the ACK is in flight, want rekeying", got)
	}

	// The deadline is 5s. Cross part of it with the ACK still held: nothing
	// may close on either end.
	p.clk.Advance(2 * time.Second)
	p.run()
	if p.cli.State() != StateEstablished || p.cli.Err() != nil {
		t.Fatalf("client is %s (%v) 2s into a 5s confirmation bound; the delayed ACK must not close it yet",
			p.cli.State(), p.cli.Err())
	}
	if p.gw.State() != StateRekeying {
		t.Fatalf("gateway is %s 2s into its own rekey bound", p.gw.State())
	}

	// Deliver the held ACK inside the bound. The gateway ratchets.
	p.toGw = append(p.toGw, ack)
	p.run()
	if p.gw.State() != StateEstablished || p.gw.Epoch() != startEpoch+1 {
		t.Fatalf("gateway is %s at epoch %d after the held ACK arrived, want established at %d",
			p.gw.State(), p.gw.Epoch(), startEpoch+1)
	}
	if p.gw.Stats().Rekeys != 1 {
		t.Fatalf("gateway Rekeys is %d, want 1", p.gw.Stats().Rekeys)
	}

	// onRekeyAck queues a mandatory new-epoch PING, so an idle connection
	// confirms without depending on application DATA.
	if !p.cli.rekeyConfirmAt.IsZero() {
		t.Fatal("client rekeyConfirmAt is still armed after the mandatory new-epoch probe")
	}
	if got := p.cli.DataPlaneState(); got != StateEstablished {
		t.Fatalf("client data-plane state is %s after confirmation, want established", got)
	}

	// Application DATA crosses only after that control-plane confirmation.
	if err := p.gw.Enqueue([]byte("confirm")); err != nil {
		t.Fatalf("gateway Enqueue after the delayed rekey: %v", err)
	}
	p.run()
	if len(p.atCli) != 1 {
		t.Fatalf("client received %d inner packets from the gateway post-convergence, want 1", len(p.atCli))
	}

	// Now cross what would have been the deadline, twice over. A converged
	// rekey must not close.
	p.clk.Advance(9 * time.Second)
	p.run()
	if p.cli.State() != StateEstablished || p.cli.Err() != nil {
		t.Fatalf("client is %s (%v) after the converged rekey crossed the erstwhile deadline", p.cli.State(), p.cli.Err())
	}
	if p.gw.State() != StateEstablished || p.gw.Err() != nil {
		t.Fatalf("gateway is %s (%v) after the converged rekey crossed the erstwhile deadline", p.gw.State(), p.gw.Err())
	}
	if got := p.cli.LocalCloseReason(); got != 0 {
		t.Errorf("client closed with %s despite convergence", got)
	}
	if p.cli.Epoch() != p.gw.Epoch() {
		t.Fatalf("epochs diverged after convergence: client %d, gateway %d", p.cli.Epoch(), p.gw.Epoch())
	}

	// And the session still carries.
	p.resetDelivered()
	if err := p.cli.Enqueue([]byte("after convergence")); err != nil {
		t.Fatalf("client Enqueue after the converged rekey: %v", err)
	}
	p.run()
	if len(p.atGw) != 1 {
		t.Errorf("gateway received %d packets after the converged rekey, want 1", len(p.atGw))
	}
}
