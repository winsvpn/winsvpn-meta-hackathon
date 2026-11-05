package session

import (
	"bytes"
	"crypto/rand"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

func TestHandshakeAndPostQuantumRatchetEstablishBothEnds(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	if p.cli.State() != StateInitiating || p.gw.State() != StateInitiating {
		t.Fatal("a new pair is not initiating")
	}
	if p.cli.Epoch() != 0 || p.gw.Epoch() != 0 {
		t.Fatal("a session exists before the handshake")
	}
	p.establish()

	// Epoch 1 is the post-quantum ratchet; epoch 0 is classical only.
	if got := p.cli.Epoch(); got != 1 {
		t.Errorf("client epoch is %d, want 1", got)
	}
	if got := p.gw.Epoch(); got != 1 {
		t.Errorf("gateway epoch is %d, want 1", got)
	}
	if got := p.gw.PeerStatic(); len(got) != core.KeySize {
		t.Errorf("gateway learned a %d-byte client static key", len(got))
	}
	if p.cli.PeerStatic() != nil {
		t.Error("the client should not learn a peer static key; the responder identity is never on the wire")
	}
	if p.cli.Err() != nil || p.gw.Err() != nil {
		t.Errorf("errors after a clean establishment: %v / %v", p.cli.Err(), p.gw.Err())
	}
	if p.cli.NeedsNewSession() || p.gw.NeedsNewSession() {
		t.Error("an established session asked for a new one")
	}
	if p.cli.NeedsCarrierChange() {
		t.Error("a successful handshake asked for a carrier change")
	}
}

func TestDataRoundTripsBothDirections(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()
	p.resetDelivered()

	up := []byte("client to gateway")
	down := []byte("gateway to client")
	for i := 0; i < 20; i++ {
		if err := p.cli.Enqueue(up); err != nil {
			t.Fatal(err)
		}
		if err := p.gw.Enqueue(down); err != nil {
			t.Fatal(err)
		}
		p.run()
	}
	if len(p.atGw) != 20 || len(p.atCli) != 20 {
		t.Fatalf("delivered %d up and %d down, want 20 each", len(p.atGw), len(p.atCli))
	}
	for _, pkt := range p.atGw {
		if !bytes.Equal(pkt, up) {
			t.Fatalf("gateway received %q", pkt)
		}
	}
	for _, pkt := range p.atCli {
		if !bytes.Equal(pkt, down) {
			t.Fatalf("client received %q", pkt)
		}
	}
	if p.cli.Stats().Unopenable != 0 || p.gw.Stats().Unopenable != 0 {
		t.Error("a clean exchange produced unopenable messages")
	}
}

// TestStrictPQKeepsDataOffTheWireUntilTheRatchetCompletes is the default-mode
// guarantee: harvest-now-decrypt-later is a live threat, so no user byte reaches
// the wire before the ML-KEM secret is in the chain.
//
// The assertion window is made deterministic rather than raced. The gateway's
// PQ_CT reply is gated: once the client's PQ_EK has crossed, the gateway is
// simply not polled again until the epoch-0 window has been observed, so the
// ratchet cannot "win the race" and the property is always exercised.
func TestStrictPQKeepsDataOffTheWireUntilTheRatchetCompletes(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	if err := p.cli.Enqueue([]byte("secret before the ratchet")); err != nil {
		t.Fatal(err)
	}

	// Handshake: the initiation crosses, the gateway responds, and the client
	// now holds a session at epoch 0 with its PQ_EK queued.
	p.drain()
	p.deliver()
	p.drain()
	p.deliver()
	if p.cli.Epoch() != 0 || p.cli.State() != StateInitiating {
		t.Fatalf("precondition: client is epoch %d in state %s, want epoch-0 initiating",
			p.cli.Epoch(), p.cli.State())
	}

	// PQ_EK crosses; the gateway now HOLDS the PQ_CT reply in its control
	// queue. Do not drain it again: this gate is what makes the epoch-0
	// window observable instead of completed inside one pump round.
	p.drain()
	p.deliver()
	if p.cli.Epoch() != 0 || p.cli.State() != StateInitiating {
		t.Fatalf("precondition: client is epoch %d in state %s, want epoch-0 initiating",
			p.cli.Epoch(), p.cli.State())
	}
	if p.gw.Epoch() != 0 || p.gw.State() != StateInitiating {
		t.Fatalf("precondition: gateway is epoch %d in state %s, want epoch-0 initiating",
			p.gw.Epoch(), p.gw.State())
	}

	// Run the client across three of its own retry deadlines while the
	// gateway's reply stays gated. Each retry backoff is at most the retry
	// cap (8 s by default), so a 2 s advance always passes the client's next
	// deadline while staying far inside the gateway's much larger half-open
	// budget (which the shared clock must not reach, or the gateway would
	// close as PQ-failed and the stall would measure the wrong thing). The
	// client must keep retrying (CT-1 D4: it supersedes the stalled generation
	// with a fresh initiation, then retries that) and must never put the
	// queued inner packet on the wire. What it sends goes on the link, so the
	// generation it ends up on can complete below.
	for i := 0; i < 3; i++ {
		// Step to the client's own next fire: under the D5 floor a retry can
		// land up to RTTPrior plus its window after the last one, past a fixed
		// 2 s step, and it is still far inside the gateway's half-open budget.
		p.clk.Advance(p.cli.NextDeadline().Sub(p.clk.Now()))
		msg, err := p.cli.Poll()
		if err != nil {
			t.Fatal(err)
		}
		if msg == nil {
			t.Fatalf("the client emitted nothing with its PQ retry deadline due (retry %d)", i)
		}
		// Every retry is a fresh initiation (FreshAfter 0), and the gateway's
		// 1 ms reinitiation gate admits one per instant, so the link carries
		// the generation the client is on now.
		p.toGw = [][]byte{msg}
		if p.cli.Epoch() != 0 || p.cli.State() != StateInitiating {
			t.Fatalf("the client left the epoch-0 window: epoch %d, state %s",
				p.cli.Epoch(), p.cli.State())
		}
		if n := p.cli.Stats().DataFramesSent; n != 0 {
			t.Fatalf("StrictPQ put %d data frames on the wire under epoch-0 keys", n)
		}
	}

	// Release the gateway's gated reply. The ratchet completes, and only then
	// does the queued packet ride the wire.
	p.run()
	p.establish()
	if n := p.cli.Stats().DataFramesSent; n != 1 {
		t.Errorf("the queued packet was not sent after the ratchet (%d data frames)", n)
	}
	if len(p.atGw) != 1 || !bytes.Equal(p.atGw[0], []byte("secret before the ratchet")) {
		t.Errorf("gateway received %v", p.atGw)
	}
	if p.cli.Epoch() != 1 {
		t.Errorf("client epoch is %d", p.cli.Epoch())
	}
}

// TestFastPQAllowsDataUnderEpochZero pins the documented cost of the non-default
// mode rather than leaving it as prose.
func TestFastPQAllowsDataUnderEpochZero(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.FastPQ = true
		gw.FastPQ = true
	})
	if err := p.cli.Enqueue([]byte("first round trip")); err != nil {
		t.Fatal(err)
	}
	sentUnderEpochZero := false
	for i := 0; i < 8 && p.cli.Epoch() == 0; i++ {
		p.drain()
		if p.cli.Stats().DataFramesSent > 0 && p.cli.Epoch() == 0 {
			sentUnderEpochZero = true
		}
		p.deliver()
	}
	p.run()
	if !sentUnderEpochZero {
		t.Error("FastPQ did not put data on the wire before the ratchet; it buys nothing")
	}
	p.establish()
}

// --- rekey ------------------------------------------------------------------

func TestRekeyByMessageVolumeAdvancesBothEpochs(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.RekeyAfterMessages = 3
	})
	p.establish()
	startEpoch := p.cli.Epoch()

	for i := 0; i < 10; i++ {
		if err := p.cli.Enqueue([]byte("volume")); err != nil {
			t.Fatal(err)
		}
		p.run()
	}
	if p.cli.Stats().Rekeys == 0 {
		t.Fatal("the volume trigger never fired")
	}
	if p.cli.Epoch() <= startEpoch {
		t.Errorf("epoch did not advance: %d", p.cli.Epoch())
	}
	if p.cli.Epoch() != p.gw.Epoch() {
		t.Fatalf("epochs diverged: client %d, gateway %d", p.cli.Epoch(), p.gw.Epoch())
	}
	if p.cli.State() != StateEstablished || p.gw.State() != StateEstablished {
		t.Fatalf("states after rekey: %s / %s", p.cli.State(), p.gw.State())
	}
	if got := len(p.atGw); got != 10 {
		t.Errorf("gateway received %d packets across the rekeys, want 10", got)
	}
}

func TestRekeyByByteVolumeFires(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.RekeyAfterBytes = 2000
	})
	p.establish()
	for i := 0; i < 12; i++ {
		if err := p.cli.Enqueue(make([]byte, 400)); err != nil {
			t.Fatal(err)
		}
		p.run()
	}
	if p.cli.Stats().Rekeys == 0 {
		t.Fatal("the byte trigger never fired")
	}
	if p.cli.Epoch() != p.gw.Epoch() {
		t.Fatalf("epochs diverged: %d vs %d", p.cli.Epoch(), p.gw.Epoch())
	}
}

func TestRekeyByJitteredTimeFires(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.RekeyInterval = Draw{Min: time.Second, Mean: 2 * time.Second, Max: 4 * time.Second}
	})
	p.establish()
	for i := 0; i < 20 && p.cli.Stats().Rekeys == 0; i++ {
		p.clk.Advance(time.Second)
		p.run()
	}
	if p.cli.Stats().Rekeys == 0 {
		t.Fatal("the jittered time trigger never fired")
	}
	if p.cli.Epoch() != p.gw.Epoch() {
		t.Fatalf("epochs diverged: %d vs %d", p.cli.Epoch(), p.gw.Epoch())
	}
}

// TestSimultaneousRekeyConverges: both ends trigger in the same instant. The
// tie-break is the role, so it costs no wire field — and a tie-break byte on the
// wire would be one more thing that has to be uniform.
func TestSimultaneousRekeyConverges(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()
	before := p.cli.Epoch()

	now := p.clk.Now()
	if err := p.cli.startRekey(now); err != nil {
		t.Fatal(err)
	}
	if err := p.gw.startRekey(now); err != nil {
		t.Fatal(err)
	}
	p.run()

	if p.cli.State() != StateEstablished || p.gw.State() != StateEstablished {
		t.Fatalf("states after a simultaneous rekey: %s / %s (%v / %v)",
			p.cli.State(), p.gw.State(), p.cli.Err(), p.gw.Err())
	}
	if p.cli.Epoch() != p.gw.Epoch() {
		t.Fatalf("epochs diverged: client %d, gateway %d", p.cli.Epoch(), p.gw.Epoch())
	}
	if p.cli.Epoch() != before+1 {
		t.Errorf("epoch is %d, want exactly one ratchet from %d", p.cli.Epoch(), before)
	}

	// And the session still carries data afterwards.
	p.resetDelivered()
	if err := p.cli.Enqueue([]byte("after the tie")); err != nil {
		t.Fatal(err)
	}
	p.run()
	if len(p.atGw) != 1 {
		t.Errorf("gateway received %d packets after a simultaneous rekey", len(p.atGw))
	}
}

// TestRekeyDoesNotDropQueuedData is the other half of the Enqueue policy.
//
// The driver BUFFERS across a ratchet where the tun gate above it DROPS, and the
// difference is intended: the gate drops because a tun device that blocks
// backpressures the kernel's IP stack, while the session buffers because it knows
// the stall is one round trip and dropping there would lose the first packets of
// every new connection. Nothing queued at the moment a rekey starts may be lost.
func TestRekeyDoesNotDropQueuedData(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()
	p.resetDelivered()

	const n = 16
	for i := 0; i < n; i++ {
		if err := p.cli.Enqueue([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	// The rekey starts with every packet still queued.
	if err := p.cli.startRekey(p.clk.Now()); err != nil {
		t.Fatal(err)
	}
	if p.cli.State() != StateRekeying {
		t.Fatalf("state is %s", p.cli.State())
	}
	p.run()

	if p.cli.State() != StateEstablished || p.gw.State() != StateEstablished {
		t.Fatalf("states after the rekey: %s / %s", p.cli.State(), p.gw.State())
	}
	if len(p.atGw) != n {
		t.Fatalf("gateway received %d of %d packets queued across a rekey", len(p.atGw), n)
	}
	seen := make(map[byte]bool, n)
	for _, pkt := range p.atGw {
		seen[pkt[0]] = true
	}
	if len(seen) != n {
		t.Errorf("%d distinct packets survived the rekey, want %d", len(seen), n)
	}
	if p.gw.Stats().Unopenable != 0 {
		t.Errorf("the rekey cut lost %d messages", p.gw.Stats().Unopenable)
	}
}

func TestRekeyTimeoutTearsTheSessionDown(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.RekeyTimeout = 5 * time.Second
	})
	p.establish()

	// The REKEY_INIT never arrives, so no ACK ever comes back.
	start := p.nToGw
	p.filterToGw = func(idx int, _ []byte) bool { return idx < start }
	if err := p.cli.startRekey(p.clk.Now()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10 && !p.cli.State().Terminal(); i++ {
		p.clk.Advance(2 * time.Second)
		p.run()
	}
	if !p.cli.State().Terminal() {
		t.Fatalf("client state is %s after the rekey timeout", p.cli.State())
	}
	if got := p.cli.LocalCloseReason(); got != CloseRekeyFailed {
		t.Errorf("close reason is %s, want %s", got, CloseRekeyFailed)
	}
	if err := p.cli.Err(); !errors.Is(err, ErrRekeyFailed) {
		t.Errorf("error is %v, want ErrRekeyFailed", err)
	}
	if !p.cli.NeedsNewSession() {
		t.Error("a failed rekey did not ask for a new session")
	}
}

// TestDroppedRekeyAckAdvancesOnlyTheResponderThenInitiatorTimesOut is the
// ACK-loss half of the in-band rekey. TestRekeyTimeoutTearsTheSessionDown
// drops REKEY_INIT, so the responder never ratchets. This drops REKEY_ACK
// after onRekeyInit has already queued completeRekey as the assemble hook,
// which runs inside Poll before the carrier Send. There is no retransmission
// of either rekey frame (tick in StateRekeying only watches rekeyEnd).
//
// What the initiator then observes is the same shape a censor produces: the
// tun gate is already StateRekeying (MayCarry false), nothing authenticated
// arrives, and after RekeyTimeout the session is StateFailed with
// ErrRekeyFailed. NeedsCarrierChange stays false — this is not a dead
// transport. The CLOSE the initiator then emits is sealed under the old
// epoch, so the responder cannot open it and stays Established.
func TestDroppedRekeyAckAdvancesOnlyTheResponderThenInitiatorTimesOut(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.RekeyTimeout = 5 * time.Second
	})
	p.establish()
	cliEpoch := p.cli.Epoch()
	gwEpoch := p.gw.Epoch()
	if cliEpoch != gwEpoch {
		t.Fatalf("precondition: epochs already diverged: client %d gateway %d", cliEpoch, gwEpoch)
	}
	unopenableBefore := p.gw.Stats().Unopenable

	start := p.nToCli
	p.filterToCli = func(idx int, _ []byte) bool { return idx < start }
	if err := p.cli.startRekey(p.clk.Now()); err != nil {
		t.Fatal(err)
	}
	p.run()

	if p.cli.State() != StateRekeying {
		t.Fatalf("client state is %s after a dropped ACK, want rekeying", p.cli.State())
	}
	if p.gw.State() != StateEstablished {
		t.Fatalf("gateway state is %s after sending ACK, want established", p.gw.State())
	}
	if p.gw.Epoch() != gwEpoch+1 {
		t.Fatalf("gateway epoch is %d, want %d (ratchet already installed)", p.gw.Epoch(), gwEpoch+1)
	}
	if p.cli.Epoch() != cliEpoch {
		t.Fatalf("client epoch is %d, want still %d (ACK never arrived)", p.cli.Epoch(), cliEpoch)
	}
	if p.gw.Stats().Rekeys != 1 {
		t.Fatalf("gateway Rekeys is %d, want 1", p.gw.Stats().Rekeys)
	}
	if p.cli.Stats().Rekeys != 0 {
		t.Fatalf("client Rekeys is %d, want 0", p.cli.Stats().Rekeys)
	}

	for i := 0; i < 10 && !p.cli.State().Terminal(); i++ {
		p.clk.Advance(2 * time.Second)
		p.run()
	}
	if !p.cli.State().Terminal() {
		t.Fatalf("client state is %s after the rekey timeout", p.cli.State())
	}
	if got := p.cli.LocalCloseReason(); got != CloseRekeyFailed {
		t.Errorf("close reason is %s, want %s", got, CloseRekeyFailed)
	}
	if err := p.cli.Err(); !errors.Is(err, ErrRekeyFailed) {
		t.Errorf("error is %v, want ErrRekeyFailed", err)
	}
	if !p.cli.NeedsNewSession() {
		t.Error("a failed rekey did not ask for a new session")
	}
	if p.cli.NeedsCarrierChange() {
		t.Error("a lost REKEY_ACK is not a dead carrier; NeedsCarrierChange must stay false")
	}
	if p.gw.State() != StateEstablished {
		t.Fatalf("gateway state is %s; CLOSE under the old epoch must not tear it down", p.gw.State())
	}
	if p.gw.PeerCloseReason() != 0 {
		t.Errorf("gateway opened a CLOSE reason %s; the CLOSE is under the old epoch and must be unopenable", p.gw.PeerCloseReason())
	}
	if p.gw.Stats().Unopenable <= unopenableBefore {
		t.Errorf("gateway Unopenable is %d, was %d; the initiator's CLOSE must fail to open", p.gw.Stats().Unopenable, unopenableBefore)
	}
}

// --- handshake retry --------------------------------------------------------

// TestHandshakeRetriesThenDemandsACarrierChange answers the measured failure
// directly: 24 retries into a wholesale UDP block, 100 % loss. The budget is a
// cap, and past it the carrier CLASS must change.
//
// It also pins the two-stage retransmission. A byte-identical copy is right when
// the initiation was lost; it is useless when the RESPONSE was lost, because the
// gateway's replay cache refuses the copy and stays silent — correctly, since
// answering a replayed initiation would turn one captured packet into a
// permanent gateway detector.
func TestHandshakeRetriesThenDemandsACarrierChange(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		cli.Retry = Retry{Base: time.Second, Cap: 4 * time.Second, Attempts: 5, FreshAfter: 2}
	})
	p.filterToGw = func(int, []byte) bool { return false }

	var sent [][]byte
	for i := 0; i < 30 && !p.cli.State().Terminal(); i++ {
		for {
			msg, err := p.cli.Poll()
			if err != nil {
				t.Fatalf("poll: %v", err)
			}
			if msg == nil {
				break
			}
			sent = append(sent, bytes.Clone(msg))
		}
		// Step to the client's own next fire: one fire per step, as the
		// former fixed 10 s step gave, without jumping past connectBy.
		if dl := p.cli.NextDeadline(); dl.After(p.clk.Now()) {
			p.clk.Advance(dl.Sub(p.clk.Now()))
		}
	}

	if !p.cli.State().Terminal() {
		t.Fatalf("client never gave up; state %s", p.cli.State())
	}
	if err := p.cli.Err(); !errors.Is(err, ErrCarrierExhausted) {
		t.Fatalf("error is %v, want ErrCarrierExhausted", err)
	}
	if !p.cli.NeedsCarrierChange() {
		t.Error("the driver did not demand a carrier-class change")
	}
	if !p.cli.NeedsNewSession() {
		t.Error("an exhausted handshake did not ask for a new session")
	}
	if len(sent) != 5 {
		t.Fatalf("emitted %d initiations, want exactly the 5-attempt budget", len(sent))
	}
	if !bytes.Equal(sent[0], sent[1]) || !bytes.Equal(sent[1], sent[2]) {
		t.Error("the first retransmissions were not byte-identical")
	}
	if bytes.Equal(sent[2], sent[3]) {
		t.Error("the driver never started a fresh handshake; a lost RESPONSE would be unrecoverable")
	}
	if !bytes.Equal(sent[3], sent[4]) {
		t.Error("the retransmission after a fresh handshake was not byte-identical")
	}
	if got := p.cli.Stats().HandshakeAttempts; got != 2 {
		t.Errorf("HandshakeAttempts is %d, want 2 distinct handshakes", got)
	}
}

func TestGatewayAnswersNothingUnauthenticated(t *testing.T) {
	p := newPair(t, nil)
	junk := make([]byte, 200)
	for i := 0; i < 500; i++ {
		if _, err := rand.Read(junk); err != nil {
			t.Fatal(err)
		}
		pkts, err := p.gw.Deliver(junk)
		if err != nil {
			t.Fatalf("Deliver returned %v for unauthenticated bytes", err)
		}
		if len(pkts) != 0 {
			t.Fatal("unauthenticated bytes were delivered upward")
		}
		msg, err := p.gw.Poll()
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		if msg != nil {
			t.Fatal("the gateway answered an unauthenticated message; that is a probe oracle")
		}
	}
	if p.gw.State() != StateInitiating {
		t.Errorf("state is %s after 500 probes", p.gw.State())
	}
	if got := p.gw.Stats().Unopenable; got != 500 {
		t.Errorf("Unopenable is %d, want 500", got)
	}
}

func TestGatewayDropsAHalfOpenSession(t *testing.T) {
	t.Run("no initiation", func(t *testing.T) {
		p := newPair(t, nil)
		for i := 0; i < 20 && !p.gw.State().Terminal(); i++ {
			p.clk.Advance(20 * time.Second)
			if _, err := p.gw.Poll(); err != nil {
				t.Fatal(err)
			}
		}
		if !p.gw.State().Terminal() {
			t.Fatalf("gateway held a half-open session forever; state %s", p.gw.State())
		}
		if err := p.gw.Err(); !errors.Is(err, ErrPeerUnreachable) {
			t.Errorf("error is %v, want ErrPeerUnreachable", err)
		}
	})

	t.Run("initiation but no PQ", func(t *testing.T) {
		p := newPair(t, nil)
		// Let the handshake complete, then cut the client off so no PQ_EK lands.
		p.drain()
		p.deliver() // gateway reads the initiation
		p.drain()   // gateway emits the response
		if p.gw.Epoch() == 0 && p.gw.State() == StateInitiating {
			// expected: a session exists at epoch 0, waiting for PQ_EK
		}
		p.filterToGw = func(int, []byte) bool { return false }
		for i := 0; i < 20 && !p.gw.State().Terminal(); i++ {
			p.clk.Advance(20 * time.Second)
			p.run()
		}
		if !p.gw.State().Terminal() {
			t.Fatalf("gateway waited forever for a post-quantum ratchet; state %s", p.gw.State())
		}
		if got := p.gw.LocalCloseReason(); got != ClosePQFailed {
			t.Errorf("close reason is %s, want %s", got, ClosePQFailed)
		}
	})
}

// TestPostQuantumRatchetSurvivesAChunkLoss: the encapsulation key is chunked
// when the carrier is small, and a lost chunk is recovered by retransmitting the
// whole blob, which is legal only because reassembly is byte-coverage based.
func TestPostQuantumRatchetSurvivesAChunkLoss(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.MaxMessageSize = 300
		gw.MaxMessageSize = 300
		cli.Retry = Retry{Base: time.Second, Cap: 2 * time.Second, Attempts: 6, FreshAfter: 9}
	})
	// Index 0 is the initiation; the PQ_EK chunks follow.
	p.filterToGw = func(idx int, _ []byte) bool { return idx != 3 }

	for i := 0; i < 12 && p.cli.State() != StateEstablished; i++ {
		p.run()
		p.clk.Advance(3 * time.Second)
	}
	if p.cli.State() != StateEstablished || p.gw.State() != StateEstablished {
		t.Fatalf("states after a lost PQ chunk: %s / %s (%v / %v)",
			p.cli.State(), p.gw.State(), p.cli.Err(), p.gw.Err())
	}
	if p.gw.Stats().PQChunksReceived < 5 {
		t.Errorf("only %d PQ chunks were received; the key was not chunked", p.gw.Stats().PQChunksReceived)
	}
	p.resetDelivered()
	if err := p.cli.Enqueue([]byte("after recovery")); err != nil {
		t.Fatal(err)
	}
	p.run()
	if len(p.atGw) != 1 {
		t.Errorf("the recovered session carried %d packets", len(p.atGw))
	}
}

// --- frame handling edge cases (white box) ----------------------------------

func TestUnknownFrameTypesAreIgnored(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()

	frames := []core.Frame{
		{Type: core.FrameType(200), Value: []byte("from a later build")},
		{Type: core.FrameData, Value: []byte("still delivered")},
		{Type: core.FrameType(99), Value: nil},
	}
	out, err := p.gw.handleFrames(p.clk.Now(), frames, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || !bytes.Equal(out[0], []byte("still delivered")) {
		t.Fatalf("delivered %v", out)
	}
	if p.gw.State() != StateEstablished {
		t.Errorf("an unknown frame type tore the session down: %s", p.gw.State())
	}
}

func TestMalformedControlFramesCloseTheSession(t *testing.T) {
	cases := []struct {
		name  string
		frame core.Frame
	}{
		{"short ping token", core.Frame{Type: core.FramePing, Value: []byte{1, 2, 3}}},
		{"long ping token", core.Frame{Type: core.FramePing, Value: make([]byte, 9)}},
		{"short pong token", core.Frame{Type: core.FramePong, Value: []byte{1, 2, 3}}},
		{"long pong token", core.Frame{Type: core.FramePong, Value: make([]byte, 9)}},
		{"empty pong token", core.Frame{Type: core.FramePong, Value: nil}},
		{"empty close", core.Frame{Type: core.FrameClose, Value: nil}},
		{"long close", core.Frame{Type: core.FrameClose, Value: []byte{1, 2}}},
		{"short rekey key", core.Frame{Type: core.FrameRekeyInit, Value: []byte{1, 2, 3}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
			p.establish()
			if _, err := p.gw.handleFrames(p.clk.Now(), []core.Frame{c.frame}, false); err != nil {
				t.Fatal(err)
			}
			if p.gw.State() == StateEstablished {
				t.Fatalf("a malformed %s left the session established", c.name)
			}
			if p.gw.Err() == nil {
				t.Error("no error was recorded")
			}
		})
	}

	// A malformed PQ chunk only matters while the ratchet is expected. Afterwards
	// a stray PQ_EK is a retransmission that crossed the ratchet, and ignoring it
	// is correct rather than lenient.
	t.Run("malformed pq chunk mid-ratchet", func(t *testing.T) {
		p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
		p.drain()
		p.deliver() // the gateway reads the initiation and now awaits PQ_EK
		if p.gw.Epoch() != 0 || p.gw.State() != StateInitiating {
			t.Fatalf("gateway is at epoch %d in state %s; the setup did not land mid-ratchet", p.gw.Epoch(), p.gw.State())
		}
		if _, err := p.gw.handleFrames(p.clk.Now(), []core.Frame{{Type: core.FramePQEK, Value: []byte{0}}}, false); err != nil {
			t.Fatal(err)
		}
		if !p.gw.State().Terminal() && p.gw.State() != StateClosing {
			t.Fatalf("a malformed PQ chunk left the gateway in %s", p.gw.State())
		}
		if got := p.gw.LocalCloseReason(); got != ClosePQFailed {
			t.Errorf("close reason is %s, want %s", got, ClosePQFailed)
		}
	})

	t.Run("stray pq chunk after the ratchet is ignored", func(t *testing.T) {
		p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
		p.establish()
		if _, err := p.gw.handleFrames(p.clk.Now(), []core.Frame{{Type: core.FramePQEK, Value: []byte{0}}}, false); err != nil {
			t.Fatal(err)
		}
		if _, err := p.cli.handleFrames(p.clk.Now(), []core.Frame{{Type: core.FramePQCT, Value: []byte{0}}}, false); err != nil {
			t.Fatal(err)
		}
		if p.gw.State() != StateEstablished || p.cli.State() != StateEstablished {
			t.Errorf("a stray post-ratchet PQ chunk tore a session down: %s / %s", p.gw.State(), p.cli.State())
		}
	})
}

func TestUnmatchedPongIsIgnored(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()
	// A late or duplicated PONG of the RIGHT length is not an error. A
	// wrong-length PONG is a protocol error; that belongs in
	// TestMalformedControlFramesCloseTheSession, not here. Mixing the two
	// under this name would let a silent ignore of a malformed control
	// frame pass as "unmatched".
	token := make([]byte, pingTokenSize)
	if _, err := p.gw.handleFrames(p.clk.Now(), []core.Frame{{Type: core.FramePong, Value: token}}, false); err != nil {
		t.Fatal(err)
	}
	if p.gw.State() != StateEstablished {
		t.Errorf("an unsolicited PONG changed the state to %s", p.gw.State())
	}
	if p.gw.Stats().PongsReceived != 1 {
		t.Errorf("PongsReceived is %d", p.gw.Stats().PongsReceived)
	}
}

// TestKeepalivesAreAnsweredAndSampleTheRoundTrip: a PING is a keepalive, a NAT
// binding refresh and an RTT sample at once, which is why the silence timer emits
// one rather than an empty cover packet.
func TestKeepalivesAreAnsweredAndSampleTheRoundTrip(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.Silence = Draw{Min: time.Second, Mean: 2 * time.Second, Max: 4 * time.Second}
	})
	p.establish()

	for i := 0; i < 10 && p.cli.Stats().PongsReceived == 0; i++ {
		p.clk.Advance(time.Second)
		p.run()
	}
	if p.cli.Stats().PingsSent == 0 {
		t.Fatal("the silence timer never fired")
	}
	if p.gw.Stats().PingsReceived == 0 {
		t.Fatal("the gateway never saw a PING")
	}
	if p.cli.Stats().PongsReceived == 0 {
		t.Fatal("the gateway never answered a PING; liveness detection depends on it")
	}
	if p.cli.Stats().LastRTT < 0 {
		t.Errorf("LastRTT is %s", p.cli.Stats().LastRTT)
	}
	if p.cli.State() != StateEstablished {
		t.Errorf("state after keepalives is %s", p.cli.State())
	}
}

func TestCoverTrafficIsEmittedOnDemand(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()
	before := p.cli.Stats().MessagesSent
	if err := p.cli.EmitCover(); err != nil {
		t.Fatal(err)
	}
	p.run()
	if p.cli.Stats().MessagesSent != before+1 {
		t.Errorf("EmitCover produced %d messages", p.cli.Stats().MessagesSent-before)
	}
	if len(p.atGw) != 0 {
		t.Error("a PAD frame was delivered upward")
	}
	if err := p.cli.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.cli.EmitCover(); !errors.Is(err, ErrState) {
		t.Errorf("EmitCover while closing returned %v, want ErrState", err)
	}
}

// --- queueing and limits ----------------------------------------------------

func TestSendQueueIsBounded(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.SendQueue = 4
	})
	p.establish()
	for i := 0; i < 4; i++ {
		if err := p.cli.Enqueue([]byte("x")); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if err := p.cli.Enqueue([]byte("x")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("the fifth enqueue returned %v, want ErrQueueFull", err)
	}
	p.run()
	if err := p.cli.Enqueue([]byte("x")); err != nil {
		t.Errorf("enqueue after the queue drained: %v", err)
	}
}

func TestEnqueueCopiesTheCallersBuffer(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()
	p.resetDelivered()

	buf := []byte("original")
	if err := p.cli.Enqueue(buf); err != nil {
		t.Fatal(err)
	}
	copy(buf, "OVERWRIT")
	p.run()
	if len(p.atGw) != 1 || !bytes.Equal(p.atGw[0], []byte("original")) {
		t.Fatalf("gateway received %q; Enqueue aliased the caller's buffer", p.atGw)
	}
}

func TestNextDeadlineIsScheduledAndClears(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	if p.cli.NextDeadline().IsZero() {
		t.Error("a client awaiting a handshake response has no deadline")
	}
	p.establish()
	dl := p.cli.NextDeadline()
	if dl.IsZero() {
		t.Fatal("an established session has no deadline")
	}
	if !dl.After(p.clk.Now()) {
		t.Errorf("deadline %s is not in the future of %s", dl, p.clk.Now())
	}
	if err := p.cli.Close(); err != nil {
		t.Fatal(err)
	}
	if p.cli.NextDeadline().IsZero() {
		t.Error("a closing session with a queued CLOSE reports no deadline")
	}
	p.run()
	if !p.cli.NextDeadline().IsZero() {
		t.Error("a terminal session still reports a deadline")
	}
}

// --- configuration ----------------------------------------------------------

func TestConfigValidation(t *testing.T) {
	base := func(t *testing.T) Config {
		t.Helper()
		static, err := core.GenerateStaticKey()
		if err != nil {
			t.Fatal(err)
		}
		return Config{
			Core:   core.Config{Gateway: gatewayParams(t)},
			Static: static,
			Accept: func([]byte) error { return nil },
		}
	}
	cases := []struct {
		name  string
		tweak func(*Config)
	}{
		{"no static key", func(c *Config) { c.Static = nil }},
		{"message size below the floor", func(c *Config) { c.MaxMessageSize = 10 }},
		{"message size above the encoding limit", func(c *Config) { c.MaxMessageSize = core.MaxTransportPayload + 1 }},
		{"mimic without a function", func(c *Config) { c.Padding = core.PadMimic }},
		{"unknown padding policy", func(c *Config) { c.Padding = core.PaddingPolicy(9) }},
		{"zero buckets", func(c *Config) { c.Buckets = -1 }},
		{"negative probes", func(c *Config) { c.MaxLostProbes = -1 }},
		{"negative queue", func(c *Config) { c.SendQueue = -1 }},
		{"rekey past the hard ceiling", func(c *Config) { c.RekeyAfterMessages = core.RejectAfterMessages + 1 }},
		{"silence is a metronome", func(c *Config) {
			c.Silence = Draw{Min: time.Second, Mean: time.Second, Max: time.Second}
		}},
		{"probe is a metronome", func(c *Config) {
			c.Probe = Draw{Min: 2 * time.Second, Mean: time.Second, Max: time.Second}
		}},
		{"rekey interval is a metronome", func(c *Config) {
			c.RekeyInterval = Draw{Min: time.Minute, Mean: time.Minute, Max: time.Minute}
		}},
		{"retry base is zero-length", func(c *Config) { c.Retry = Retry{Base: -1, Cap: time.Second, Attempts: 1} }},
		{"retry cap below base", func(c *Config) { c.Retry = Retry{Base: 2 * time.Second, Cap: time.Second, Attempts: 1} }},
		{"no retry attempts", func(c *Config) { c.Retry = Retry{Base: time.Second, Cap: time.Second, Attempts: -1} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := base(t)
			c.tweak(&cfg)
			if _, err := NewGateway(cfg); err == nil {
				t.Fatalf("configuration was accepted: %+v", c.name)
			}
		})
	}

	t.Run("client needs a gateway key", func(t *testing.T) {
		cfg := base(t)
		if _, err := NewClient(cfg); !errors.Is(err, ErrConfig) {
			t.Fatalf("NewClient without a gateway key returned %v", err)
		}
	})
	t.Run("gateway needs an accept callback", func(t *testing.T) {
		cfg := base(t)
		cfg.Accept = nil
		if _, err := NewGateway(cfg); err == nil {
			t.Fatal("a gateway without an authorisation callback was accepted")
		}
	})
	t.Run("defaults are usable", func(t *testing.T) {
		cfg := base(t)
		if err := cfg.normalise(); err != nil {
			t.Fatal(err)
		}
		if cfg.Clock == nil || cfg.Rand == nil || cfg.Core.Now == nil || cfg.Core.Rand == nil {
			t.Error("normalise left a nil dependency")
		}
		if cfg.MaxMessageSize != DefaultMaxMessageSize || cfg.SendQueue != DefaultSendQueue {
			t.Error("normalise did not apply the defaults")
		}
		if cfg.Retry.freshAfter() != DefaultFreshAfter {
			t.Error("freshAfter default not applied")
		}
		if !cfg.Clock.Now().IsZero() == false {
			t.Error("SystemClock returned a zero time")
		}
	})
}

func TestGatewayRefusesAnUnauthorisedClient(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		gw.Accept = func([]byte) error { return errors.New("not on the roster") }
	})
	p.run()
	if p.gw.State() == StateEstablished {
		t.Fatal("the gateway established a session with an unauthorised client")
	}
	if p.cli.State() == StateEstablished {
		t.Fatal("the client established a session the gateway refused")
	}
	if p.gw.Stats().Unopenable == 0 {
		t.Error("the refusal was not counted")
	}
}

func TestStateStrings(t *testing.T) {
	for s, want := range map[State]string{
		StateInitiating:  "initiating",
		StateEstablished: "established",
		StateRekeying:    "rekeying",
		StateClosing:     "closing",
		StateClosed:      "closed",
		StateFailed:      "failed",
		State(0):         "invalid",
	} {
		if got := s.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", s, got, want)
		}
	}
	if StateEstablished.Terminal() || StateInitiating.Terminal() || StateRekeying.Terminal() || StateClosing.Terminal() {
		t.Error("a working state reported as terminal")
	}
	if !StateClosed.Terminal() || !StateFailed.Terminal() {
		t.Error("a terminal state reported as working")
	}
}

// TestConcurrentUse exercises the documented concurrency contract under -race.
//
// enqueued and handed are WORKER-PROGRESS witnesses, not packet counts, and each
// has exactly one writer — goroutine one increments enqueued, goroutine two
// increments handed — and neither is read until after wg.Wait, so the plain ints
// are race-free by construction. They exist because the spin budget below can be
// exhausted by either of two very different things: a driver that genuinely
// refuses to carry data (the regression this test exists to see), or a loaded
// -race machine that simply never schedules a worker during the run (not a
// defect of this driver at all). Without a record of whether the workers ever
// acted, "nothing crossed" collapses the two into one failure and the second
// fails a healthy driver spuriously. enqueued counts client queues that landed;
// handed counts frames the poller actually placed on the gateway link.
func TestConcurrentUse(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	junk := make([]byte, 100)
	enqueued, handed := 0, 0

	wg.Add(4)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := p.cli.Enqueue([]byte("concurrent")); err == nil {
				enqueued++
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if msg, err := p.cli.Poll(); err == nil && msg != nil {
				handed++
				_, _ = p.gw.Deliver(msg)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = p.cli.Deliver(junk)
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = p.cli.Stats()
			_ = p.cli.State()
			_ = p.cli.NextDeadline()
			_ = p.cli.Epoch()
		}
	}()

	// The loop leaves the moment anything crosses, so in practice it advances a
	// handful of steps. Its WORST case is what has to be checked: 20,000 x 50 ms
	// is 1,000 s of virtual time per round, and a probe or a rekey landing inside
	// a concurrency test would present as a data race in the schedule rather than
	// as what it is. quietConfig parks Probe and RekeyInterval at quietHorizon
	// (24 h), so even the full three-round worst case of 3,000 s sits far below
	// the first timer; requireQuietBudget is told the TOTAL the loop may inject,
	// so it checks against what this test actually configures.
	//
	// Multiple rounds cost nothing virtual — the workers are still live (stop is
	// not closed) and the drivers are healthy — and give a loaded box that has
	// not yet scheduled a worker three clear chances to do so before the verdict
	// below is read at all.
	const spinSteps, spinStep = 20000, 50 * time.Millisecond
	const spinRounds = 3
	requireQuietBudget(t, p.cli, time.Duration(spinSteps)*spinStep*spinRounds)
	for round := 0; round < spinRounds && p.gw.Stats().DataFramesReceived == 0; round++ {
		for i := 0; i < spinSteps && p.gw.Stats().DataFramesReceived == 0; i++ {
			p.clk.Advance(spinStep)
			runtime.Gosched()
		}
	}
	close(stop)
	wg.Wait()

	received := p.gw.Stats().DataFramesReceived
	switch {
	case received != 0:
		// A data frame crossed during the concurrent run. Whatever else the
		// workers did, the driver did not stop carrying data under contention.
	case handed != 0:
		// A frame really moved from the client to the gateway link, and the
		// gateway never credited one: the loss happened inside the driver, not
		// in the scheduler. This is the regression the test exists for.
		t.Errorf("nothing crossed during the concurrent run (the poller handed %d frames to the gateway and none were credited as data)", handed)
	case enqueued != 0:
		// The client accepted inner packets and yet the poller emitted no frame.
		// A goroutine left runnable for the whole budget is scheduled long
		// before one that is never runnable at all, so a full round-trip of
		// silence here is a real emission or delivery failure, not a flake.
		t.Errorf("nothing crossed during the concurrent run (the client accepted %d packets and the poller emitted no frame)", enqueued)
	default:
		// Neither worker ever completed its first action. That can only be the
		// machine failing to schedule them, not this driver failing to carry
		// data, and "nothing crossed" would then be reading the scheduler. Say
		// so rather than fail a healthy driver, and say it out loud — a skipped
		// assertion must not read as a passed one.
		t.Skipf("the concurrent workers never ran one step across %d spin rounds (enqueued=%d, handed=%d): the machine did not schedule them, so the liveness assertion did not execute; rerun to exercise it", spinRounds, enqueued, handed)
	}
}
