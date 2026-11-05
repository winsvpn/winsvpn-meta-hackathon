package session

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// Regression tests for the L06 v3-core verification round (Gemini L06 and
// Muse L06 true positives). Each names the finding it pins.

// failAfterRand serves remaining reads from base, then fails every read.
type failAfterRand struct {
	base      io.Reader
	remaining int
	err       error
}

func (r *failAfterRand) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, r.err
	}
	r.remaining--
	return r.base.Read(p)
}

// Gemini F-1 (PQ_EK part) / Muse F-4 (PQ_EK half): once beginClose has run no
// handshake-phase handler runs (CT-1 Amendment 3, N-5). A closing responder
// must not encapsulate against a late PQ_EK and queue PQ_CT behind its CLOSE.
func TestL06VerifyClosingResponderIgnoresPQEK(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	init, err := p.cli.Poll()
	if err != nil || init == nil {
		t.Fatalf("initiation: %v", err)
	}
	if _, err := p.gw.Deliver(init); err != nil {
		t.Fatal(err)
	}
	resp, err := p.gw.Poll()
	if err != nil || resp == nil {
		t.Fatalf("response: %v", err)
	}
	if _, err := p.cli.Deliver(resp); err != nil {
		t.Fatal(err)
	}
	var ek [][]byte
	for i := 0; i < 16; i++ {
		m, err := p.cli.Poll()
		if err != nil {
			t.Fatal(err)
		}
		if m == nil {
			break
		}
		ek = append(ek, m)
	}
	if len(ek) == 0 {
		t.Fatal("setup: no PQ_EK flight")
	}
	if err := p.gw.Close(); err != nil {
		t.Fatal(err)
	}
	ctrlAtClose := len(p.gw.ctrl)
	for _, m := range ek {
		if _, err := p.gw.Deliver(m); err != nil {
			t.Fatal(err)
		}
	}
	if len(p.gw.ctrl) != ctrlAtClose || p.gw.pqSecret != nil || p.gw.Stats().PQChunksReceived != 0 {
		t.Fatalf("closing gateway consumed PQ_EK: ctrl %d -> %d, secret set %v, chunks received %d",
			ctrlAtClose, len(p.gw.ctrl), p.gw.pqSecret != nil, p.gw.Stats().PQChunksReceived)
	}
	msg, err := p.gw.Poll()
	if err != nil || msg == nil {
		t.Fatalf("close flush: msg=%v err=%v", msg != nil, err)
	}
	if !p.gw.State().Terminal() {
		t.Fatalf("gateway state %s after the CLOSE flush, want terminal", p.gw.State())
	}
}

// Gemini F-1 (admitReinitiation part): a probe queued and not yet popped when
// a fresh initiation supersedes the session must not leave pingPending set,
// or the new generation never probes again; and queued DATA discarded by the
// supersession is counted, as beginClose and terminate count it.
func TestL06VerifyReinitiationClearsPendingProbeAndCountsQueuedData(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		gw.Silence = Draw{Min: 100 * time.Millisecond, Mean: 200 * time.Millisecond, Max: 300 * time.Millisecond}
	})
	p.establish()
	if err := p.gw.Enqueue([]byte("queued before the re-initiation")); err != nil {
		t.Fatal(err)
	}
	// A probe queued but not yet assembled, as onRekeyAck leaves one between
	// Deliver and the next Poll.
	p.gw.mu.Lock()
	if err := p.gw.queueProbe(p.clk.Now(), true); err != nil {
		p.gw.mu.Unlock()
		t.Fatal(err)
	}
	p.gw.mu.Unlock()
	droppedBefore := p.gw.Stats().DataFramesDropped

	p.clk.Advance(time.Second)
	cli2, err := NewClient(p.cli.cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.cli = cli2
	// The fresh initiation reaches the gateway before it polls again, so
	// the queued packet and probe are still queued when it is adopted.
	init, err := p.cli.Poll()
	if err != nil || init == nil {
		t.Fatalf("replacement initiation: %v", err)
	}
	if _, err := p.gw.Deliver(init); err != nil {
		t.Fatal(err)
	}
	p.establish()
	if got := p.gw.Stats().DataFramesDropped - droppedBefore; got != 1 {
		t.Errorf("re-initiation discarded 1 queued packet but DataFramesDropped moved by %d", got)
	}
	pings := p.gw.Stats().PingsSent
	p.clk.Advance(2 * time.Second)
	if _, err := p.gw.Poll(); err != nil {
		t.Fatal(err)
	}
	if p.gw.Stats().PingsSent <= pings {
		t.Fatalf("no probe after the silence timer fired on the new generation (pingPending stuck); PingsSent %d", pings)
	}
}

// Gemini F-4 (deliverHandshake part): a local failure in onHandshakeComplete
// after the handshake authenticated latches StateFailed and terminates, on
// both roles, instead of leaving the driver Initiating with Err() nil.
func TestL06VerifyHandshakeCompleteFailureLatches(t *testing.T) {
	errEntropy := errors.New("injected entropy failure")

	t.Run("responder", func(t *testing.T) {
		edPriv, edPub, mlSeed, mlPub := dualKeys(t)
		p := newPair(t, func(cli, gw *Config) {
			quietConfig(cli)
			quietConfig(gw)
			cli.DualAuth = DualAuthConfig{Expected: true, Ed25519Public: edPub, MLDSA65Public: mlPub}
			gw.DualAuth = DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
			gw.Core.Rand = newDetRand("l06-verify-gw-core")
			gw.Rand = &failAfterRand{base: newDetRand("l06-verify-gw"), err: errEntropy}
		})
		init, err := p.cli.Poll()
		if err != nil || init == nil {
			t.Fatalf("initiation: %v", err)
		}
		if _, err := p.gw.Deliver(init); !errors.Is(err, errEntropy) {
			t.Fatalf("gateway Deliver err %v, want the injected failure", err)
		}
		if p.gw.State() != StateFailed || !errors.Is(p.gw.Err(), errEntropy) {
			t.Fatalf("gateway state %s err %v, want failed with the injected failure", p.gw.State(), p.gw.Err())
		}
		if p.gw.dualEDPriv != nil || p.gw.dualMLSign != nil {
			t.Fatal("failed gateway kept its attestation signing keys")
		}
		if out, err := p.gw.Poll(); out != nil || err != nil {
			t.Fatalf("failed gateway emitted %d bytes (err %v)", len(out), err)
		}
	})

	t.Run("initiator", func(t *testing.T) {
		var cliRand *failAfterRand
		p := newPair(t, func(cli, gw *Config) {
			quietConfig(cli)
			quietConfig(gw)
			cli.Padding = core.PadNone
			cli.Core.Rand = newDetRand("l06-verify-cli-core")
			cliRand = &failAfterRand{base: newDetRand("l06-verify-cli"), remaining: 1 << 20, err: errEntropy}
			cli.Rand = cliRand
		})
		init, err := p.cli.Poll()
		if err != nil || init == nil {
			t.Fatalf("initiation: %v", err)
		}
		if _, err := p.gw.Deliver(init); err != nil {
			t.Fatal(err)
		}
		resp, err := p.gw.Poll()
		if err != nil || resp == nil {
			t.Fatalf("response: %v", err)
		}
		// onHandshakeComplete draws Silence and Probe, generates the PQ
		// ephemeral and queues PQ_EK, then fails in armRetry: the failure
		// lands after pqEph and ctrl are populated.
		cliRand.remaining = 2
		if _, err := p.cli.Deliver(resp); !errors.Is(err, errEntropy) {
			t.Fatalf("client Deliver err %v, want the injected failure", err)
		}
		if p.cli.State() != StateFailed || !errors.Is(p.cli.Err(), errEntropy) {
			t.Fatalf("client state %s err %v, want failed with the injected failure", p.cli.State(), p.cli.Err())
		}
		if p.cli.pqEph != nil || len(p.cli.ctrl) != 0 {
			t.Fatalf("failed client kept PQ state: pqEph %v ctrl %d", p.cli.pqEph != nil, len(p.cli.ctrl))
		}
	})
}

// Gemini F-4 (newFromSession part): a failed adoption returns an error on
// both branches. The discarded driver cannot be inspected from here; the
// deferred wipeDualCredentials in newFromSession is exercised (and run under
// -race) by these failures.
func TestL06VerifyFailedAdoptionReturnsError(t *testing.T) {
	errEntropy := errors.New("injected entropy failure")
	edPriv, _, mlSeed, _ := dualKeys(t)
	_, gwSess, _, gwStatic, _, initiatorStatic := coreHandshake(t)
	cfg := Config{
		Core:     core.Config{Gateway: gatewayParams(t), Rand: newDetRand("l06-adopt-core")},
		Static:   gwStatic,
		Accept:   func([]byte) error { return nil },
		Clock:    newClock(),
		Padding:  core.PadBucket,
		Rand:     &failAfterRand{base: newDetRand("l06-adopt"), err: errEntropy},
		DualAuth: DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed},
	}
	if d, err := NewGatewayFromSession(cfg, gwSess, initiatorStatic); !errors.Is(err, errEntropy) || d != nil {
		t.Fatalf("adoption with failing entropy: driver %v err %v", d != nil, err)
	}
}

// Gemini F-7 / Muse F-2: Authenticates answers for every message the session
// can carry (not only those under a 2048-byte scratch) and in every live
// state the peer sends in, including Initiating and Rekeying.
func TestL06VerifyAuthenticatesLargeMessagesAndLiveStates(t *testing.T) {
	t.Run("large", func(t *testing.T) {
		p := newPair(t, func(cli, gw *Config) {
			quietConfig(cli)
			quietConfig(gw)
			cli.MaxMessageSize = 4096
			gw.MaxMessageSize = 4096
		})
		p.establish()
		if err := p.cli.Enqueue(bytes.Repeat([]byte{0x42}, 3000)); err != nil {
			t.Fatal(err)
		}
		msg, err := p.cli.Poll()
		if err != nil || msg == nil {
			t.Fatalf("poll: %v", err)
		}
		if len(msg) <= 2072 {
			t.Fatalf("setup: message is %d bytes, want above 2072", len(msg))
		}
		if !p.gw.Authenticates(msg) {
			t.Fatalf("Authenticates false for a genuine %d-byte message", len(msg))
		}
		for i, b := range p.gw.openBuf[:len(msg)] {
			if b != 0 {
				t.Fatalf("Authenticates left plaintext in its scratch at %d", i)
			}
		}
		if _, err := p.gw.Deliver(msg); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("initiating", func(t *testing.T) {
		p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
		init, _ := p.cli.Poll()
		if _, err := p.gw.Deliver(init); err != nil {
			t.Fatal(err)
		}
		resp, _ := p.gw.Poll()
		if _, err := p.cli.Deliver(resp); err != nil {
			t.Fatal(err)
		}
		ek, err := p.cli.Poll()
		if err != nil || ek == nil {
			t.Fatalf("PQ_EK: %v", err)
		}
		if p.gw.State() != StateInitiating {
			t.Fatalf("setup: gateway %s, want initiating", p.gw.State())
		}
		if !p.gw.Authenticates(ek) {
			t.Fatal("Authenticates false for the client's PQ_EK while the gateway is initiating")
		}
	})

	t.Run("rekeying", func(t *testing.T) {
		p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
		p.establish()
		p.gw.mu.Lock()
		err := p.gw.startRekey(p.clk.Now())
		p.gw.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if err := p.cli.Enqueue([]byte("roaming during the gateway's rekey")); err != nil {
			t.Fatal(err)
		}
		msg, err := p.cli.Poll()
		if err != nil || msg == nil {
			t.Fatalf("poll: %v", err)
		}
		if p.gw.State() != StateRekeying {
			t.Fatalf("setup: gateway %s, want rekeying", p.gw.State())
		}
		if !p.gw.Authenticates(msg) {
			t.Fatal("Authenticates false for a genuine message while the gateway is rekeying")
		}
	})
}

// Muse F-1: PollInto with a dst below the message it must seal loses nothing:
// the queued packet is still sealed and delivered, and a queued CLOSE is
// still sent rather than swallowed.
func TestL06VerifyPollIntoShortBufferLosesNothing(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()
	inner := []byte("hello inner packet")
	if err := p.cli.Enqueue(inner); err != nil {
		t.Fatal(err)
	}
	msg, err := p.cli.PollInto(make([]byte, 0, 10))
	if err != nil || msg == nil {
		t.Fatalf("short-dst PollInto: msg %v err %v", msg != nil, err)
	}
	got, err := p.gw.Deliver(msg)
	if err != nil || len(got) != 1 || !bytes.Equal(got[0], inner) {
		t.Fatalf("gateway got %d packets (err %v), want the queued one", len(got), err)
	}
	if err := p.cli.Close(); err != nil {
		t.Fatal(err)
	}
	msg, err = p.cli.PollInto(make([]byte, 0, 10))
	if err != nil || msg == nil {
		t.Fatalf("short-dst PollInto with a queued CLOSE: msg %v err %v", msg != nil, err)
	}
	if _, err := p.gw.Deliver(msg); err != nil {
		t.Fatal(err)
	}
	if !p.gw.State().Terminal() || p.gw.PeerCloseReason() != CloseNormal {
		t.Fatalf("gateway state %s reason %v: the CLOSE did not arrive", p.gw.State(), p.gw.PeerCloseReason())
	}
}

// Muse F-3: epoch > 0 does not imply the PQ ratchet happened (core.Session.Rekey
// also advances it); adopting such a session must not open the data plane on
// classical-only secrecy.
func TestL06VerifyAdoptedClassicalEpochStillNeedsPQ(t *testing.T) {
	cliSess, gwSess, cliStatic, _, gwPub, _ := coreHandshake(t)
	secret := make([]byte, core.KeySize)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	if err := cliSess.Rekey(append([]byte(nil), secret...)); err != nil {
		t.Fatal(err)
	}
	if err := gwSess.Rekey(append([]byte(nil), secret...)); err != nil {
		t.Fatal(err)
	}
	if cliSess.PQRatcheted() || cliSess.Epoch() != 1 {
		t.Fatalf("setup: pq %v epoch %d, want a classical epoch 1", cliSess.PQRatcheted(), cliSess.Epoch())
	}
	d, err := NewFromSession(Config{
		Core:          core.Config{Gateway: gatewayParams(t)},
		Static:        cliStatic,
		GatewayStatic: gwPub,
		Clock:         newClock(),
		Rand:          newDetRand("l06-adopt-classical"),
	}, cliSess, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.State() == StateEstablished || d.dataMayFlow() {
		t.Fatalf("adopted classical-only epoch-1 session opened the data plane: state %s", d.State())
	}
}

// Gemini F-3 (admission part): with every queued packet already in the ready
// window (SendQueue at or below readyWindow) an arrival at the cap drops the
// window head, never the arrival, as the flow-queue contract states.
func TestL06VerifyFQAdmitAtCapWithEmptyFlowQueues(t *testing.T) {
	p := stage5Pair(t)
	p.cli.cfg.SendQueue = 8
	p.cli.SetSendQueueFQ()
	for i := 0; i < 8; i++ {
		if err := p.cli.Enqueue(fqPacket(1, 9, 6, 1200, uint16(i))); err != nil {
			t.Fatal(err)
		}
	}
	p.cli.FillSendWindow()
	if err := p.cli.Enqueue(fqPacket(2, 9, 1, 84, 0xffff)); err != nil {
		t.Fatalf("sparse arrival at the cap refused: %v", err)
	}
	st := p.cli.Stats()
	if st.DataQueueOverflow != 1 || st.DataQueueDepth != 8 {
		t.Fatalf("overflow %d depth %d, want 1 and 8", st.DataQueueOverflow, st.DataQueueDepth)
	}
}
