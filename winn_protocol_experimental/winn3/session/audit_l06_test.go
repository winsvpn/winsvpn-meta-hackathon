package session

import (
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/dualsign"
)

// TestAuditDualAuthSurvivesReinitiation pins the gateway's attestation
// credentials across admitReinitiation (CT-1 ruling D3, Astra F-1): a client
// that re-initialises against the same responder Driver (a lost response, a
// fresh socket that lands on the same address) must receive a verifiable
// attestation for the replacement generation, and the credentials must die
// only when the Driver itself terminates (terminate's wipeDualCredentials).
// It is the audit's own reproduction, kept beside CT-1's
// TestCT1ReinitiationKeepsTheSignerAndTerminateWipesIt: here the replacement
// is a new client Driver, not a supersession inside one.
func TestAuditDualAuthSurvivesReinitiation(t *testing.T) {
	edPriv, edPub, mlSeed, mlPub := dualKeys(t)
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		gw.DualAuth = DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
		cli.DualAuth = DualAuthConfig{Expected: true, Ed25519Public: edPub, MLDSA65Public: mlPub}
	})
	p.establish()
	replacement, err := NewClient(p.cli.cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.clk.Advance(time.Millisecond)
	runResponder(t, replacement, p.gw)
	if replacement.State() != StateEstablished || !replacement.DualAuthVerified() {
		t.Fatalf("reconnect client=%s verified=%v gateway=%s signer_present=%v",
			replacement.State(), replacement.DualAuthVerified(), p.gw.State(), p.gw.dualMLSign != nil)
	}
	if err := p.gw.Close(); err != nil {
		t.Fatal(err)
	}
	runResponder(t, replacement, p.gw)
	if !p.gw.State().Terminal() {
		t.Fatalf("gateway state=%s after close, want terminal", p.gw.State())
	}
	if p.gw.dualMLSign != nil || p.gw.dualEDPriv != nil {
		t.Fatal("terminal gateway retains attestation credentials")
	}
}

// TestAuditPongQueueBounded (Astra F-2): an authenticated peer that packs
// every message with PINGs must not grow the control queue without bound while
// the writer is behind; PONG is optional and is shed at the bound. CT-1 does
// not touch the PING handler, so this bound is the audit's own fix.
func TestAuditPongQueueBounded(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name := "scalar"
		if batch {
			name = "batch"
		}
		t.Run(name, func(t *testing.T) {
			p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
			p.establish()
			var token [pingTokenSize]byte
			plain := make([]byte, 0, p.cli.cfg.maxPayload())
			for len(plain)+frameHeaderSize+len(token) <= p.cli.cfg.maxPayload() {
				var err error
				plain, err = core.AppendFrame(plain, core.FramePing, token[:])
				if err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 64; i++ {
				msg, err := p.cli.sess.Seal(plain, 0)
				if err != nil {
					t.Fatal(err)
				}
				if batch {
					slots := []ReceiveSlot{{Message: msg, Scratch: make([]byte, len(msg)), Packets: make([][]byte, 0, len(msg)/frameHeaderSize)}}
					if n, err := p.gw.DeliverBatch(slots); err != nil || n != 1 {
						t.Fatalf("deliver batch: n=%d err=%v", n, err)
					}
				} else if _, err := p.gw.Deliver(msg); err != nil {
					t.Fatal(err)
				}
			}
			if len(p.gw.ctrl) > maxQueuedControlForPong {
				t.Fatalf("64 authenticated datagrams retained %d control frames; data queue=%d", len(p.gw.ctrl), p.gw.queuedDataLen())
			}
			if p.gw.State() != StateEstablished {
				t.Fatalf("gateway state=%s", p.gw.State())
			}
			// An honest probe still gets its answer once the queue drains.
			p.run()
			if p.gw.State() != StateEstablished || p.cli.State() != StateEstablished {
				t.Fatalf("after drain gateway=%s client=%s", p.gw.State(), p.cli.State())
			}
		})
	}
}

// TestAuditAdoptedClientCannotSkipExpectedAttestation (Sol F-1): the adoption
// seam must not silently drop DualAuth.Expected. CT-1 does not touch
// newFromSession's DualAuth handling.
func TestAuditAdoptedClientCannotSkipExpectedAttestation(t *testing.T) {
	cliSess, _, cliStatic, _, gwPub, _ := coreHandshake(t)
	secret := make([]byte, core.PQSharedKeySize)
	if err := cliSess.MixPQ(secret); err != nil {
		t.Fatal(err)
	}
	_, edPub, _, mlPub := dualKeys(t)
	cfg := Config{
		Core:          core.Config{Gateway: gatewayParams(t)},
		Static:        cliStatic,
		GatewayStatic: gwPub,
		Clock:         newClock(),
		Rand:          newDetRand("audit-adopt-dual"),
		DualAuth:      DualAuthConfig{Expected: true, Ed25519Public: edPub, MLDSA65Public: mlPub},
	}
	d, err := NewFromSession(cfg, cliSess, nil)
	if err == nil {
		t.Fatalf("adopted client accepted completed PQ session without any dual signatures: state=%s dualDone=%t", d.State(), d.dualDone)
	}
}

// TestAuditAdoptedUnratchetedClientWaitsForAttestation (Sol F-1): an adopted
// epoch-0 initiator with Expected set must hold the gate for the attestation,
// which CT-1's completePQ and verifyDualAuth then enforce as for NewClient.
func TestAuditAdoptedUnratchetedClientWaitsForAttestation(t *testing.T) {
	cliSess, _, cliStatic, _, gwPub, _ := coreHandshake(t)
	_, edPub, _, mlPub := dualKeys(t)
	cfg := Config{
		Core:          core.Config{Gateway: gatewayParams(t)},
		Static:        cliStatic,
		GatewayStatic: gwPub,
		Clock:         newClock(),
		Rand:          newDetRand("audit-adopt-dual-epoch0"),
		DualAuth:      DualAuthConfig{Expected: true, Ed25519Public: edPub, MLDSA65Public: mlPub},
	}
	d, err := NewFromSession(cfg, cliSess, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !d.dualClient || d.dualMLVeriy == nil {
		t.Fatal("adopted epoch-0 client dropped DualAuth.Expected")
	}
}

// pumpToAttestation drives a dual-auth pair to the point where both ends hold
// a ratcheted session and the client still waits for the attestation, without
// delivering any attestation frame.
func pumpToAttestation(t *testing.T, p *pair) {
	t.Helper()
	init, err := p.cli.Poll()
	if err != nil || init == nil {
		t.Fatalf("initiation: %v", err)
	}
	if _, err := p.gw.Deliver(init); err != nil {
		t.Fatal(err)
	}
	response, err := p.gw.Poll()
	if err != nil || response == nil {
		t.Fatalf("response: %v", err)
	}
	if _, err := p.cli.Deliver(response); err != nil {
		t.Fatal(err)
	}
	for {
		msg, err := p.cli.Poll()
		if err != nil {
			t.Fatal(err)
		}
		if msg == nil {
			break
		}
		if _, err := p.gw.Deliver(msg); err != nil {
			t.Fatal(err)
		}
	}
	for !p.gw.sess.PQRatcheted() {
		msg, err := p.gw.Poll()
		if err != nil || msg == nil {
			t.Fatalf("PQ ciphertext: %v", err)
		}
		if _, err := p.cli.Deliver(msg); err != nil {
			t.Fatal(err)
		}
	}
	if !p.cli.sess.PQRatcheted() || p.cli.State() != StateInitiating || p.cli.dualDone {
		t.Fatal("setup did not leave the client ratcheted and waiting for attestation")
	}
}

func auditSignTranscript(t *testing.T, edPriv []byte, mlSeed []byte, h [32]byte) (edSig, mlSig []byte) {
	t.Helper()
	edSig, err := dualsign.SignEd25519(edPriv, h[:])
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, mlSeed)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	mlSig, err = dualsign.SignMLDSA65(signer, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return edSig, mlSig
}

// auditDeliverFrame seals one frame under the gateway's current keys and
// hands it to the client, scalar or batch.
func auditDeliverFrame(t *testing.T, p *pair, batch bool, typ core.FrameType, value []byte) {
	t.Helper()
	plain, err := core.AppendFrame(nil, typ, value)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := p.gw.sess.Seal(plain, 0)
	if err != nil {
		t.Fatal(err)
	}
	if batch {
		slots := []ReceiveSlot{{Message: wire, Scratch: make([]byte, len(wire)), Packets: make([][]byte, 0, len(wire)/frameHeaderSize+1)}}
		if _, err := p.cli.DeliverBatch(slots); err != nil {
			t.Fatal(err)
		}
		return
	}
	if _, err := p.cli.Deliver(wire); err != nil {
		t.Fatal(err)
	}
}

// TestAuditClosingCannotReestablishFromLateDualAuth (Sol F-2, CT-1 Amendment
// 3, N-5): once a dual-auth failure has queued CLOSE, a later valid
// attestation must not reopen the session. CT-1 closes this with the
// StateClosing guards on the PQ_CT and DUAL_AUTH cases of handleFramesInto
// and the state guard in establish; this is the audit's trigger (a malformed
// Ed25519 half) beside CT-1's T23 (a wrong ML-DSA-65 half).
func TestAuditClosingCannotReestablishFromLateDualAuth(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name := "scalar"
		if batch {
			name = "batch"
		}
		t.Run(name, func(t *testing.T) {
			edPriv, edPub, mlSeed, mlPub := dualKeys(t)
			p := newPair(t, func(cli, gw *Config) {
				quietConfig(cli)
				quietConfig(gw)
				gw.DualAuth = DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
				cli.DualAuth = DualAuthConfig{Expected: true, Ed25519Public: edPub, MLDSA65Public: mlPub}
			})
			pumpToAttestation(t, p)
			auditDeliverFrame(t, p, batch, core.FrameDualAuthED, []byte{1})
			if p.cli.State() != StateClosing {
				t.Fatalf("malformed attestation left client %s, want closing", p.cli.State())
			}
			edSig, mlSig := auditSignTranscript(t, edPriv, mlSeed, p.gw.sess.TranscriptHash())
			auditDeliverFrame(t, p, batch, core.FrameDualAuthED, edSig)
			for _, frame := range chunkBlob(core.FrameDualAuthML, mlSig, 1024) {
				auditDeliverFrame(t, p, batch, frame.typ, frame.value)
			}
			if p.cli.State() != StateClosing || p.cli.DualAuthVerified() || p.cli.dataMayFlow() {
				t.Fatalf("late valid attestation reopened client after failure: state=%s verified=%t dataAllowed=%t",
					p.cli.State(), p.cli.DualAuthVerified(), p.cli.dataMayFlow())
			}
			msg, err := p.cli.Poll()
			if err != nil || msg == nil {
				t.Fatalf("close poll: msg=%v err=%v", msg != nil, err)
			}
			if !p.cli.State().Terminal() {
				t.Fatalf("client state=%s after flushing CLOSE, want terminal", p.cli.State())
			}
		})
	}
}

// TestAuditDualAuthCannotEstablishBeforePQRatchet (Sol F-3, CT-1 Amendment 3,
// N-6): an attestation that opens under epoch 0 can never be honest and must
// close the session instead of opening the data plane without the PQ ratchet.
// CT-1's dualAuthAfterRatchet refuses it on the open-time epoch (D7, Q5).
func TestAuditDualAuthCannotEstablishBeforePQRatchet(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name := "scalar"
		if batch {
			name = "batch"
		}
		t.Run(name, func(t *testing.T) {
			edPriv, edPub, mlSeed, mlPub := dualKeys(t)
			p := newPair(t, func(cli, gw *Config) {
				quietConfig(cli)
				quietConfig(gw)
				gw.DualAuth = DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
				cli.DualAuth = DualAuthConfig{Expected: true, Ed25519Public: edPub, MLDSA65Public: mlPub}
			})
			init, err := p.cli.Poll()
			if err != nil || init == nil {
				t.Fatalf("initiation: %v", err)
			}
			if _, err := p.gw.Deliver(init); err != nil {
				t.Fatal(err)
			}
			response, err := p.gw.Poll()
			if err != nil || response == nil {
				t.Fatalf("response: %v", err)
			}
			if _, err := p.cli.Deliver(response); err != nil {
				t.Fatal(err)
			}
			if p.cli.sess == nil || p.cli.sess.PQRatcheted() || p.gw.sess == nil || p.gw.sess.PQRatcheted() {
				t.Fatal("handshake setup did not leave both peers at epoch zero")
			}
			edSig, mlSig := auditSignTranscript(t, edPriv, mlSeed, p.gw.sess.TranscriptHash())
			auditDeliverFrame(t, p, batch, core.FrameDualAuthED, edSig)
			for _, frame := range chunkBlob(core.FrameDualAuthML, mlSig, 1024) {
				auditDeliverFrame(t, p, batch, frame.typ, frame.value)
			}
			if p.cli.State() != StateClosing || p.cli.DualAuthVerified() || p.cli.dataMayFlow() {
				t.Fatalf("epoch-zero attestation left state=%s verified=%t dataAllowed=%t",
					p.cli.State(), p.cli.DualAuthVerified(), p.cli.dataMayFlow())
			}
			for i := 0; i < 16; i++ {
				msg, err := p.cli.Poll()
				if err != nil {
					t.Fatal(err)
				}
				if msg == nil {
					break
				}
				if p.cli.State() == StateEstablished {
					t.Fatal("client established while flushing its CLOSE")
				}
			}
			if !p.cli.State().Terminal() {
				t.Fatalf("client state=%s after flushing, want terminal", p.cli.State())
			}
		})
	}
}
