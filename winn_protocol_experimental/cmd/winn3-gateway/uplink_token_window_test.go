package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
)

// TestTheGatewaySurvivesTheUplinkDropRunsMeasuredUnderStarvation is the L12
// regression. On a starved gateway at 700 Mbit/s, readLoop dropped runs of 804
// to 1720 consecutive client messages at the full session inbox, and every one
// of those runs stranded the client-to-gateway direction: all later client
// messages were unopenable and the session died on liveness about 3 s later.
// The longest run measured was 5729 under uplink-only overload and 13,858
// under 1500 Mbit/s each way, which killed both such sessions at W=16384.
//
// The session is built from buildSessionConfig, the production constructor,
// and handshaken through its shared responder, so the window under test is the
// one the binary serves with. Each case loses a contiguous run of client
// messages the gateway never sees, then requires the next messages to open.
func TestTheGatewaySurvivesTheUplinkDropRunsMeasuredUnderStarvation(t *testing.T) {
	cases := []struct {
		name string
		// recentLoss drops one message and then delivers
		// core.DefaultTokenWindow/2 - 1 before the run. That keeps the low edge
		// pinned at the hole for the longest a default window allows, which is
		// the steady state of a lossy overload, and halves the survivable run.
		recentLoss bool
		run        int
	}{
		{"clean_run_of_1024_measured_fatal", false, 1024},
		{"clean_run_of_1720_measured_fatal", false, 1720},
		{"run_of_804_after_a_recent_loss_measured_fatal", true, 804},
		{"run_of_2759_after_a_recent_loss", true, 2759},
		{"run_of_5729_after_a_recent_loss_uplink_1500", true, 5729},
		{"run_of_13858_after_a_recent_loss_bidirectional_1500_largest_measured", true, 13858},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cli, gw := productionUplinkPair(t)
			seal := func() []byte {
				m, err := cli.Seal([]byte("uplink"), 0)
				if err != nil {
					t.Fatalf("Seal: %v", err)
				}
				return m
			}
			open := func(stage string, m []byte) {
				t.Helper()
				if _, err := gw.Open(m); err != nil {
					t.Fatalf("%s: the gateway could not open a client message after a lost run of %d "+
						"(recent loss %v): %v. The uplink is stranded; production answers this with a "+
						"liveness teardown", stage, tc.run, tc.recentLoss, err)
				}
			}
			for i := 0; i < 8; i++ {
				open("warm-up", seal())
			}
			if tc.recentLoss {
				_ = seal() // lost
				for i := 0; i < core.DefaultTokenWindow/2-1; i++ {
					open("settle after the single loss", seal())
				}
			}
			for i := 0; i < tc.run; i++ {
				_ = seal() // dropped at the full inbox, never delivered
			}
			for i := 0; i < 16; i++ {
				open("after the run", seal())
			}
		})
	}
}

// TestTheUplinkRunTestCanFail is the anti-vacuity arm: a run past the widened
// window must still strand the direction, so the test above is measuring the
// window and not a session that opens anything.
func TestTheUplinkRunTestCanFail(t *testing.T) {
	cli, gw := productionUplinkPair(t)
	for i := 0; i < gatewayTokenWindow; i++ {
		if _, err := cli.Seal([]byte("uplink"), 0); err != nil {
			t.Fatal(err)
		}
	}
	m, err := cli.Seal([]byte("uplink"), 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = gw.Open(m)
	if err == nil {
		t.Fatalf("the gateway opened a message %d past its low edge; the window is not %d",
			gatewayTokenWindow, gatewayTokenWindow)
	}
	if !errors.Is(err, core.ErrUnauthenticated) {
		t.Fatalf("a message %d past the low edge was refused for the wrong reason: %v; "+
			"only the window's own refusal (core.ErrUnauthenticated) proves the window is %d",
			gatewayTokenWindow, err, gatewayTokenWindow)
	}
}

// productionUplinkPair handshakes a client initiator against the gateway's
// production session config and returns (client, gateway) transport sessions.
func productionUplinkPair(t *testing.T) (*core.Session, *core.Session) {
	t.Helper()
	opts := operatorValueOptions(t)
	cfg, err := buildSessionConfig(opts)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Responder == nil {
		t.Fatal("buildSessionConfig returned no shared responder")
	}
	dir := filepath.Dir(opts.staticPath)
	cliStatic, err := core.NewStaticKey(readTestKey(t, filepath.Join(dir, "client.key")))
	if err != nil {
		t.Fatal(err)
	}
	gwPub, err := core.NewPublicKey(readTestKey(t, filepath.Join(dir, "static.pub")))
	if err != nil {
		t.Fatal(err)
	}
	ini, err := core.NewInitiator(core.Config{
		Gateway: core.GatewayParams{
			AdmissionKeys: [][]byte{readTestSecret(t, filepath.Join(dir, "admission.key"))},
			GatewayID:     cfg.Core.Gateway.GatewayID,
		},
	}, cliStatic, gwPub)
	if err != nil {
		t.Fatal(err)
	}
	init, err := ini.WriteInitiation(nil, core.PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := cfg.Responder.ReadInitiation(init)
	if err != nil {
		t.Fatalf("ReadInitiation: %v", err)
	}
	resp, gw, err := hs.WriteResponse(nil, core.PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	cli, _, err := ini.ReadResponse(resp)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	t.Cleanup(func() { cli.Wipe(); gw.Wipe() })
	// Sanity: one message each way opens.
	m, err := gw.Seal([]byte("down"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := cli.Open(m); err != nil || !bytes.Equal(got, []byte("down")) {
		t.Fatalf("downlink sanity: %q %v", got, err)
	}
	return cli, gw
}

// fixedStepClock is an injected session clock that moves only when told to.
type fixedStepClock struct{ t time.Time }

func (c *fixedStepClock) Now() time.Time { return c.t }

// driverPair is a client and a PRODUCTION gateway session driver joined by an
// in-memory link. The gateway half is session.NewGateway over the exact
// session.Config that buildSessionConfig returns (shared responder, token
// window, send queue), sized the way driver.newLoop sizes it. The client half
// mirrors cmd/winn-datapath's client (core.MaxTokenWindow).
type driverPair struct {
	t   *testing.T
	clk *fixedStepClock
	cli *session.Driver
	gw  *session.Driver
}

func newProductionDriverPair(t *testing.T, tweakClient func(*session.Config)) *driverPair {
	t.Helper()
	opts := operatorValueOptions(t)
	gwCfg, err := buildSessionConfig(opts)
	if err != nil {
		t.Fatal(err)
	}
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	// Start at the wall clock: the shared responder buildSessionConfig built
	// judges admission-tag freshness on the real clock, so a client on an
	// arbitrary fixed date would be answered with silence.
	clk := &fixedStepClock{t: time.Now()}
	gwCfg.MaxMessageSize, gwCfg.PathMTU, gwCfg.Clock = sizing.MessageSize, sizing.PathMTU, clk
	dir := filepath.Dir(opts.staticPath)
	cliStatic, err := core.NewStaticKey(readTestKey(t, filepath.Join(dir, "client.key")))
	if err != nil {
		t.Fatal(err)
	}
	gwPub, err := core.NewPublicKey(readTestKey(t, filepath.Join(dir, "static.pub")))
	if err != nil {
		t.Fatal(err)
	}
	cliCfg := session.Config{
		Core: core.Config{
			Gateway: core.GatewayParams{
				AdmissionKeys: [][]byte{readTestSecret(t, filepath.Join(dir, "admission.key"))},
				GatewayID:     gwCfg.Core.Gateway.GatewayID,
			},
			TokenWindow: core.MaxTokenWindow,
		},
		Static:         cliStatic,
		GatewayStatic:  gwPub,
		Padding:        core.PadBucket,
		SendQueue:      65536,
		MaxMessageSize: sizing.MessageSize,
		PathMTU:        sizing.PathMTU,
		Clock:          clk,
	}
	if tweakClient != nil {
		tweakClient(&cliCfg)
	}
	cli, err := session.NewClient(cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := session.NewGateway(gwCfg)
	if err != nil {
		t.Fatal(err)
	}
	p := &driverPair{t: t, clk: clk, cli: cli, gw: gw}
	t.Cleanup(func() { _ = cli.Close(); _ = gw.Close() })
	p.settle("handshake and PQ ratchet", func() bool {
		return cli.State() == session.StateEstablished && gw.State() == session.StateEstablished &&
			cli.Epoch() >= 1 && cli.Epoch() == gw.Epoch()
	})
	return p
}

// exchange moves every pending message both ways once and returns the inner
// packets the gateway released.
func (p *driverPair) exchange() (atGateway int) {
	p.t.Helper()
	for i := 0; i < 4096; i++ {
		m, err := p.cli.Poll()
		if err != nil {
			p.t.Fatalf("client poll: %v", err)
		}
		if m == nil {
			break
		}
		pkts, _ := p.gw.Deliver(m)
		atGateway += len(pkts)
	}
	for i := 0; i < 4096; i++ {
		m, err := p.gw.Poll()
		if err != nil {
			p.t.Fatalf("gateway poll: %v", err)
		}
		if m == nil {
			break
		}
		_, _ = p.cli.Deliver(m)
	}
	return atGateway
}

func (p *driverPair) settle(what string, done func() bool) {
	p.t.Helper()
	for i := 0; i < 2000; i++ {
		if done() {
			return
		}
		p.exchange()
		p.clk.t = p.clk.t.Add(time.Millisecond)
	}
	p.t.Fatalf("%s did not complete: client %v epoch %d, gateway %v epoch %d",
		what, p.cli.State(), p.cli.Epoch(), p.gw.State(), p.gw.Epoch())
}

// sealUplink queues one inner packet at the client and returns the sealed
// message without delivering it.
func (p *driverPair) sealUplink(payload []byte) []byte {
	p.t.Helper()
	if err := p.cli.Enqueue(payload); err != nil {
		p.t.Fatalf("client enqueue: %v", err)
	}
	m, err := p.cli.Poll()
	if err != nil || m == nil {
		p.t.Fatalf("client poll after enqueue: %v %v", m == nil, err)
	}
	return append([]byte(nil), m...)
}

// TestARekeyAtTheWidenedGatewayWindowRejectsReplaysAndKeepsCarrying forces an
// in-band rekey through the production session path (the client's monotone
// RekeyAfterMessages knob, the same startRekey/onRekeyInit/onRekeyAck frames a
// time or volume trigger uses) with the gateway at gatewayTokenWindow, and
// checks the four epoch properties Round K asked for:
//
//   - a pre-rekey gap past the old 1024 cliff is survived;
//   - after the rekey, a previous-epoch message the gateway never saw, still
//     inside its window, is refused (so no retained replay state can be the
//     reason), and so is a delivered previous-epoch message replayed;
//   - a message of the new epoch opens once and its duplicate is refused;
//   - a post-rekey gap past the old cliff is survived and carriage continues.
func TestARekeyAtTheWidenedGatewayWindowRejectsReplaysAndKeepsCarrying(t *testing.T) {
	const rekeyAfter = 30000
	p := newProductionDriverPair(t, func(c *session.Config) { c.RekeyAfterMessages = rekeyAfter })
	payload := bytes.Repeat([]byte{0x45}, 1200)
	epoch0 := p.gw.Epoch()

	// Pre-rekey: open some, lose a contiguous run of 5000, open again.
	var oldEpochMsg []byte
	for i := 0; i < 64; i++ {
		m := p.sealUplink(payload)
		if pkts, _ := p.gw.Deliver(m); len(pkts) != 1 {
			t.Fatalf("pre-rekey message %d did not open", i)
		}
		oldEpochMsg = m
	}
	for i := 0; i < 5000; i++ {
		_ = p.sealUplink(payload)
	}
	m := p.sealUplink(payload)
	if pkts, _ := p.gw.Deliver(m); len(pkts) != 1 {
		t.Fatal("the gateway did not open a message after a 5000-message gap; the widened window is not in effect")
	}

	// Drive the client to its rekey trigger with delivered traffic, one
	// message behind: each sealed message is delivered only after the next
	// one is sealed. When a Poll starts the rekey, the message sealed just
	// before it is WITHHELD: an old-epoch message the gateway has never seen
	// and that is still inside its window (every earlier message arrived).
	// The loop is bounded by a message budget, not by the rekey happening.
	var withheld []byte
	for sent := 0; p.cli.Epoch() == epoch0; sent++ {
		if sent > 2*rekeyAfter {
			t.Fatalf("no rekey started within %d messages of a %d-message trigger", sent, rekeyAfter)
		}
		m := p.sealUplink(payload)
		if p.cli.State() == session.StateRekeying {
			// This Poll started the rekey; m may carry the REKEY_INIT.
			_, _ = p.gw.Deliver(m)
			break
		}
		if withheld != nil {
			if pkts, _ := p.gw.Deliver(withheld); len(pkts) != 1 {
				t.Fatalf("pre-rekey message %d did not open", sent)
			}
		}
		withheld = m
	}
	if withheld == nil || p.cli.State() != session.StateRekeying {
		t.Fatalf("the rekey did not start: client %v epoch %d", p.cli.State(), p.cli.Epoch())
	}
	p.settle("rekey confirmation", func() bool {
		return p.cli.State() == session.StateEstablished && p.gw.State() == session.StateEstablished &&
			p.cli.Epoch() == epoch0+1 && p.gw.Epoch() == epoch0+1
	})
	if got := p.gw.Stats().Rekeys; got < 1 {
		t.Fatalf("gateway counted %d rekeys; the forced rekey did not run through the session path", got)
	}

	// An UNSEEN, still-in-window previous-epoch message must be refused: no
	// retained replay state can be what rejects it, because it was never
	// delivered. Only the epoch change can.
	before := p.gw.Stats().Unopenable
	if pkts, _ := p.gw.Deliver(withheld); len(pkts) != 0 {
		t.Fatal("the gateway released an unseen message sealed under the previous epoch after the rekey")
	}
	if p.gw.Stats().Unopenable != before+1 {
		t.Fatalf("the unseen previous-epoch message was not counted unopenable (%d -> %d)", before, p.gw.Stats().Unopenable)
	}
	// And a previous-epoch message that WAS delivered is refused on replay.
	before = p.gw.Stats().Unopenable
	if pkts, _ := p.gw.Deliver(oldEpochMsg); len(pkts) != 0 {
		t.Fatal("the gateway released a replayed previous-epoch message after the rekey")
	}
	if p.gw.Stats().Unopenable != before+1 {
		t.Fatalf("the replayed previous-epoch message was not counted unopenable (%d -> %d)", before, p.gw.Stats().Unopenable)
	}

	// A new-epoch message opens once; its duplicate is refused.
	fresh := p.sealUplink(payload)
	if pkts, _ := p.gw.Deliver(fresh); len(pkts) != 1 {
		t.Fatal("the first new-epoch message did not open")
	}
	if pkts, _ := p.gw.Deliver(fresh); len(pkts) != 0 {
		t.Fatal("the gateway released a duplicate of a new-epoch message")
	}

	// A post-rekey gap past the old cliff is survived, and carriage continues.
	for i := 0; i < 6000; i++ {
		_ = p.sealUplink(payload)
	}
	for i := 0; i < 16; i++ {
		if pkts, _ := p.gw.Deliver(p.sealUplink(payload)); len(pkts) != 1 {
			t.Fatalf("message %d after a 6000-message post-rekey gap did not open", i)
		}
	}
}

// TestARekeyThatBeginsAfterTheMeasuredUKUplinkGapCompletes is the field
// incident from lane L14 (UK gateway, 2026-09-23 14:28 UTC). An upload burst
// lost about 1,260 consecutive client messages before the gateway read them.
// At core.DefaultTokenWindow that strands the uplink, so the client's next
// time-triggered REKEY_INIT (queued once, driver.go startRekey) was
// unopenable and the session died on the 15 s rekey timeout. Here the rekey
// is forced through the production path (the client's RekeyAfterMessages
// knob, the same startRekey an expired rekeyAt calls) after the same gap, and
// must complete, with carriage afterwards.
func TestARekeyThatBeginsAfterTheMeasuredUKUplinkGapCompletes(t *testing.T) {
	const (
		ukGap      = 1260
		rekeyAfter = 2000
	)
	p := newProductionDriverPair(t, func(c *session.Config) { c.RekeyAfterMessages = rekeyAfter })
	payload := bytes.Repeat([]byte{0x45}, 1200)
	epoch0 := p.gw.Epoch()
	for i := 0; i < 64; i++ {
		if pkts, _ := p.gw.Deliver(p.sealUplink(payload)); len(pkts) != 1 {
			t.Fatalf("warm-up message %d did not open", i)
		}
	}
	for i := 0; i < ukGap; i++ {
		_ = p.sealUplink(payload) // lost before the gateway read it
	}
	// Normal traffic resumes; the client reaches its rekey trigger with the
	// gap behind it. Every message, the REKEY_INIT included, must open.
	deadline := p.clk.t.Add(session.DefaultRekeyTimeout + 5*time.Second)
	for p.cli.Epoch() == epoch0 || p.gw.Epoch() == epoch0 || p.cli.Epoch() != p.gw.Epoch() {
		if p.cli.State() == session.StateEstablished {
			_ = p.cli.Enqueue(payload)
		}
		p.exchange()
		p.clk.t = p.clk.t.Add(5 * time.Millisecond)
		if st := p.cli.State(); st.Terminal() {
			t.Fatalf("the client session ended during a rekey that began %d messages after a %d-message "+
				"uplink gap: %v (%v). This is the UK incident: the gateway could not open the REKEY_INIT",
				rekeyAfter, ukGap, st, p.cli.Err())
		}
		if p.clk.t.After(deadline) {
			t.Fatalf("no rekey completed within the %s rekey timeout after a %d-message uplink gap: client "+
				"%v epoch %d, gateway %v epoch %d, gateway unopenable %d",
				session.DefaultRekeyTimeout, ukGap, p.cli.State(), p.cli.Epoch(), p.gw.State(), p.gw.Epoch(),
				p.gw.Stats().Unopenable)
		}
	}
	p.settle("rekey confirmation", func() bool {
		return p.cli.State() == session.StateEstablished && p.gw.State() == session.StateEstablished
	})
	for i := 0; i < 16; i++ {
		if pkts, _ := p.gw.Deliver(p.sealUplink(payload)); len(pkts) != 1 {
			t.Fatalf("post-rekey message %d did not open", i)
		}
	}
}

// TestTheWidenedWindowBoundaryWithAPinnedLowEdge pins the recent-loss cliff
// at gatewayTokenWindow/2 - 1 exactly. A hole pins the low edge; 16,383 more
// messages then arrive without forcing it forward (forcing starts at a
// distance of W/2 = 16,384). The window then ends W-1 counters above the
// hole, so after the pinned run the last survivable gap is W/2 - 1 = 16,383
// and a gap of 16,384 is the first refused.
func TestTheWidenedWindowBoundaryWithAPinnedLowEdge(t *testing.T) {
	half := gatewayTokenWindow / 2
	for _, tc := range []struct {
		name  string
		gap   int
		opens bool
	}{
		{"last_accepted_gap_W/2-1", half - 1, true},
		{"first_refused_gap_W/2", half, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, gw := productionUplinkPair(t)
			seal := func() []byte {
				m, err := cli.Seal([]byte("uplink"), 0)
				if err != nil {
					t.Fatalf("Seal: %v", err)
				}
				return m
			}
			for i := 0; i < 8; i++ {
				if _, err := gw.Open(seal()); err != nil {
					t.Fatalf("warm-up %d: %v", i, err)
				}
			}
			_ = seal() // the hole: this counter is the pinned low edge
			for i := 0; i < half-1; i++ {
				if _, err := gw.Open(seal()); err != nil {
					t.Fatalf("pinned-edge advance %d of %d: %v", i+1, half-1, err)
				}
			}
			for i := 0; i < tc.gap; i++ {
				_ = seal() // lost
			}
			_, err := gw.Open(seal())
			switch {
			case tc.opens && err != nil:
				t.Fatalf("after a pinned low edge and a %d-message gap the next message was refused: %v; "+
					"the recent-loss tolerance is below W/2-1 = %d", tc.gap, err, half-1)
			case !tc.opens && err == nil:
				t.Fatalf("after a pinned low edge and a %d-message gap the next message opened; "+
					"the window is wider than %d or the edge was not pinned", tc.gap, gatewayTokenWindow)
			case !tc.opens && !errors.Is(err, core.ErrUnauthenticated):
				t.Fatalf("the first gap past the window was refused for the wrong reason: %v", err)
			}
		})
	}
}
