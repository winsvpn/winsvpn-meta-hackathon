package session

// CT-1 D7: the DUAL_AUTH gate reads the epoch a message opened under (Q5),
// and a closing responder is moved by neither a fresh initiation nor a
// REKEY_INIT (Q6). Scalar and batch delivery throughout.

import (
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// --- T25: DUAL_AUTH frames sealed under epoch 0 behind the ratchet frame (Q5) ---

// ct1PQOutstanding is a dual-auth pair whose client holds an epoch-0 session
// with its PQ ciphertext outstanding (the gateway never got the PQ_EK), plus
// a ciphertext and shared secret encapsulated to the client's key by a
// test-only gateway that holds the signing keys.
func ct1PQOutstanding(t *testing.T) (p *pair, edPriv []byte, mlSeed []byte, ct, ss []byte) {
	t.Helper()
	p, ed, ml := ct1DualPair(t, 1360, true)
	p.filterToGw = func(idx int, _ []byte) bool { return idx == 0 }
	p.run()
	p.filterToGw = nil
	if p.cli.sess == nil || p.cli.pqEph == nil || p.cli.sess.PQRatcheted() || p.gw.Epoch() != 0 {
		t.Fatal("fixture: the client should hold an epoch-0 session with its PQ ciphertext outstanding")
	}
	ct, ss, err := core.PQEncapsulate(p.cli.pqEph.EncapsulationKey())
	if err != nil {
		t.Fatal(err)
	}
	return p, ed, ml, ct, ss
}

// ct1RefusedAtOpen asserts the outcome Q5 requires after the epoch-0 frames
// were delivered: never established, never verified, no DATA, ErrProtocol
// recorded with CloseDualAuthFailed, and nothing transmitted but the CLOSE.
func ct1RefusedAtOpen(t *testing.T, p *pair, pkts [][]byte, sent uint64) {
	t.Helper()
	if p.cli.State() == StateEstablished || p.cli.DualAuthVerified() {
		t.Fatalf("DUAL_AUTH frames that opened under epoch 0 established the client: %s, verified %v", p.cli.State(), p.cli.DualAuthVerified())
	}
	if len(pkts) != 0 {
		t.Fatalf("%d DATA packet(s) admitted", len(pkts))
	}
	if !errors.Is(p.cli.Err(), ErrProtocol) || p.cli.LocalCloseReason() != CloseDualAuthFailed {
		t.Fatalf("err %v reason %s, want ErrProtocol and %s", p.cli.Err(), p.cli.LocalCloseReason(), CloseDualAuthFailed)
	}
	if n := ct1PollAll(t, p.cli); n > 1 || p.cli.Stats().MessagesSent-sent > 1 || !p.cli.State().Terminal() {
		t.Fatalf("after the refusal: %d message(s) polled, %d sent, state %s; want at most the CLOSE", n, p.cli.Stats().MessagesSent-sent, p.cli.State())
	}
}

// TestCT1AttestationOpenedUnderEpochZeroIsRefused is T25 (D7, Q5). A3.3 N-6
// rules that a DUAL_AUTH frame that OPENS on an initiator whose session has
// not ratcheted is ErrProtocol. The ratchet can complete inside the message
// that carries the frame: its PQ_CT chunk is handled first. So the gate must
// read the epoch at open, as the DATA gate already does. Three shapes, each
// scalar and batch:
//   - one-message: one epoch-0 message [PQ_CT (whole), ED, ML (whole), DATA];
//   - ed-rides-the-pqct: at the 1360 floor, the epoch-0 ratchet datagram
//     carries the last PQ_CT byte and the Ed25519 frame; the ML-DSA-65 chunks
//     follow under epoch 1, as an honest gateway would send them;
//   - ml-rides-the-pqct: the same with the first ML-DSA-65 chunk riding the
//     last PQ_CT byte and the Ed25519 frame following under epoch 1.
//
// On D6a every shape leaves the client established and verified.
func TestCT1AttestationOpenedUnderEpochZeroIsRefused(t *testing.T) {
	for _, path := range ct1Paths {
		t.Run("one-message/"+path, func(t *testing.T) {
			p, edPriv, mlSeed, ct, _ := ct1PQOutstanding(t)
			h := p.gw.sess.TranscriptHash()
			ed, ml := ct1Attest(t, edPriv, mlSeed, h[:], 8000)
			pq := chunkBlob(core.FramePQCT, ct, 8000)
			if len(pq) != 1 || len(ml) != 1 {
				t.Fatalf("fixture: %d PQ_CT chunk(s), %d ML-DSA-65 chunk(s), want 1 and 1", len(pq), len(ml))
			}
			msg := ct1Seal(t, p.gw.sess, core.Frame{Type: pq[0].typ, Value: pq[0].value}, ed, ml[0], ct1DataFrame())
			if p.gw.sess.Epoch() != 0 {
				t.Fatal("fixture: the sealing session left epoch 0")
			}
			sent := p.cli.Stats().MessagesSent
			pkts := ct1DeliverVia(t, p.cli, path, msg)
			if !p.cli.sess.PQRatcheted() && p.cli.State() != StateClosing && !p.cli.State().Terminal() {
				t.Fatalf("fixture: the PQ_CT in the message did not ratchet the client (%s)", p.cli.State())
			}
			ct1RefusedAtOpen(t, p, pkts, sent)
		})
		for _, rider := range []string{"ed-rides-the-pqct", "ml-rides-the-pqct"} {
			t.Run(rider+"/"+path, func(t *testing.T) {
				p, edPriv, mlSeed, ct, ss := ct1PQOutstanding(t)
				h := p.gw.sess.TranscriptHash()
				// Room for the PQ_CT tail frame beside the first ML-DSA-65
				// chunk in one datagram at this floor.
				ed, ml := ct1Attest(t, edPriv, mlSeed, h[:], p.gw.cfg.maxPayload()-32)
				head := chunkBlob(core.FramePQCT, ct[:len(ct)-1], 8000)
				if len(head) != 1 {
					t.Fatalf("fixture: %d head chunk(s)", len(head))
				}
				tail := make([]byte, chunkOffsetSize+1)
				tail[0], tail[1] = byte((len(ct)-1)>>8), byte(len(ct)-1)
				tail[2] = ct[len(ct)-1]
				tailFrame := core.Frame{Type: core.FramePQCT, Value: tail}
				m1 := ct1Seal(t, p.gw.sess, core.Frame{Type: core.FramePQCT, Value: head[0].value})
				var m2 []byte
				var rest []core.Frame
				if rider == "ed-rides-the-pqct" {
					m2 = ct1Seal(t, p.gw.sess, tailFrame, ed)
					rest = ml
				} else {
					m2 = ct1Seal(t, p.gw.sess, tailFrame, ml[0])
					rest = append(append([]core.Frame{}, ml[1:]...), ed)
				}
				if len(m1) > 1360 || len(m2) > 1360 {
					t.Fatalf("fixture: datagrams of %d and %d bytes exceed the 1360 floor", len(m1), len(m2))
				}
				if err := p.gw.sess.MixPQ(ss); err != nil {
					t.Fatal(err)
				}
				msgs := [][]byte{m1, m2}
				for _, f := range rest {
					msgs = append(msgs, ct1Seal(t, p.gw.sess, f))
				}
				msgs = append(msgs, ct1Seal(t, p.gw.sess, ct1DataFrame()))
				sent := p.cli.Stats().MessagesSent
				var pkts [][]byte
				for _, m := range msgs {
					pkts = append(pkts, ct1DeliverVia(t, p.cli, path, m)...)
					if p.cli.State() == StateEstablished {
						t.Fatal("a DUAL_AUTH frame that opened under epoch 0 completed the attestation")
					}
				}
				ct1RefusedAtOpen(t, p, pkts, sent)
			})
		}
	}
	// Non-regression for the open-time capture: the same split with every
	// DUAL_AUTH frame sealed under epoch 1 establishes and verifies, so the
	// gate refuses the epoch, not the shape.
	for _, path := range ct1Paths {
		t.Run("epoch-1-attestation-establishes/"+path, func(t *testing.T) {
			p, edPriv, mlSeed, ct, ss := ct1PQOutstanding(t)
			h := p.gw.sess.TranscriptHash()
			ed, ml := ct1Attest(t, edPriv, mlSeed, h[:], p.gw.cfg.maxPayload())
			msgs := [][]byte{}
			for _, c := range chunkBlob(core.FramePQCT, ct, p.gw.cfg.maxPayload()-frameHeaderSize) {
				msgs = append(msgs, ct1Seal(t, p.gw.sess, core.Frame{Type: c.typ, Value: c.value}))
			}
			if err := p.gw.sess.MixPQ(ss); err != nil {
				t.Fatal(err)
			}
			msgs = append(msgs, ct1Seal(t, p.gw.sess, ed))
			for _, f := range ml {
				msgs = append(msgs, ct1Seal(t, p.gw.sess, f))
			}
			ct1DeliverVia(t, p.cli, path, msgs...)
			if p.cli.State() != StateEstablished || !p.cli.DualAuthVerified() || p.cli.Err() != nil {
				t.Fatalf("an epoch-1 attestation: %s, verified %v, err %v; want established and verified", p.cli.State(), p.cli.DualAuthVerified(), p.cli.Err())
			}
		})
	}
}

// --- T26 and T27: a closing responder stays closing (Q6) -------------------------

// ct1ClosingGateway establishes a quiet pair and puts the gateway into
// StateClosing with its CLOSE still queued: by a host Close (reason normal,
// no error) or by an authenticated malformed PING from the client (reason
// protocol-error, ErrProtocol).
func ct1ClosingGateway(t *testing.T, cause string) *pair {
	t.Helper()
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()
	switch cause {
	case "host-close":
		if err := p.gw.Close(); err != nil {
			t.Fatal(err)
		}
	case "protocol-error":
		p.cli.mu.Lock()
		p.cli.ctrl = append(p.cli.ctrl, pendingFrame{typ: core.FramePing, value: []byte{1}})
		p.cli.mu.Unlock()
		m, err := p.cli.Poll()
		if err != nil || m == nil {
			t.Fatalf("fixture: no malformed PING (%v)", err)
		}
		p.gw.Deliver(m)
	default:
		t.Fatalf("fixture: unknown cause %q", cause)
	}
	if p.gw.State() != StateClosing {
		t.Fatalf("fixture: gateway %s, want closing", p.gw.State())
	}
	return p
}

// TestCT1ClosingGatewayRefusesAFreshInitiation is T26 (D7, Q6, Sol's second
// counterexample). While a gateway's CLOSE is queued, a fresh authenticated
// initiation from the same client reaches deliverUnopenable on both receive
// paths. admitReinitiation must not run: on D6a it drops the queued CLOSE,
// moves the gateway to StateInitiating, zeroes localReason and answers with a
// handshake response. Here the gateway stays closing with its recorded reason
// and error, sends no handshake message, and its next datagram is the CLOSE.
func TestCT1ClosingGatewayRefusesAFreshInitiation(t *testing.T) {
	for _, cause := range []string{"host-close", "protocol-error"} {
		for _, path := range ct1Paths {
			t.Run(cause+"/"+path, func(t *testing.T) {
				p := ct1ClosingGateway(t, cause)
				reason, errBefore := p.gw.LocalCloseReason(), p.gw.Err()
				hsSent := p.gw.Stats().HandshakeMessagesSent
				ini := p.newInitiator(t)
				initMsg, err := ini.WriteInitiation(nil, core.PadAuto)
				if err != nil {
					t.Fatal(err)
				}
				p.clk.Advance(2 * time.Millisecond)
				ct1DeliverVia(t, p.gw, path, initMsg)
				if st := p.gw.State(); st != StateClosing {
					t.Fatalf("a fresh initiation moved a closing gateway to %s", st)
				}
				if p.gw.LocalCloseReason() != reason || !errors.Is(p.gw.Err(), errBefore) || (errBefore == nil) != (p.gw.Err() == nil) {
					t.Fatalf("the recorded close (%s, %v) became (%s, %v)", reason, errBefore, p.gw.LocalCloseReason(), p.gw.Err())
				}
				out, err := p.gw.Poll()
				if err != nil || out == nil {
					t.Fatalf("no CLOSE flushed: %v", err)
				}
				if sess, _, rerr := ini.ReadResponse(out); rerr == nil && sess != nil {
					t.Fatal("the closing gateway answered the fresh initiation with a handshake response")
				}
				if n := p.gw.Stats().HandshakeMessagesSent; n != hsSent {
					t.Fatalf("handshake messages sent moved from %d to %d", hsSent, n)
				}
				want := StateClosed
				if errBefore != nil {
					want = StateFailed
				}
				if p.gw.State() != want || p.gw.LocalCloseReason() != reason {
					t.Fatalf("after the flush: %s reason %s, want %s reason %s", p.gw.State(), p.gw.LocalCloseReason(), want, reason)
				}
				if extra, _ := p.gw.Poll(); extra != nil {
					t.Fatal("a terminal gateway sent another datagram")
				}
			})
		}
	}
}

// TestCT1ClosingGatewayIgnoresRekeyInit is T27 (D7, Q6, Sol's first
// counterexample). The gateway starts its own rekey (rekeyPend set), then the
// host closes it before anything flushes, and the client's simultaneous
// REKEY_INIT arrives. On D6a the responder passes onRekeyInit's checks and
// becomes StateRekeying; NextDeadline then reports rekeyEnd, and a Poll at
// that deadline rewrites the recorded normal close as rekey-failed with
// ErrRekeyFailed. Here the gateway stays closing, NextDeadline is now, and
// the flush, immediate or at the deadline, ends it closed with reason normal
// and no error. Scalar and batch.
func TestCT1ClosingGatewayIgnoresRekeyInit(t *testing.T) {
	for _, flush := range []string{"poll-now", "poll-at-next-deadline"} {
		for _, path := range ct1Paths {
			t.Run(flush+"/"+path, func(t *testing.T) {
				p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
				p.establish()
				now := p.clk.Now()
				p.gw.mu.Lock()
				err := p.gw.startRekey(now)
				pend := p.gw.rekeyPend
				p.gw.mu.Unlock()
				if err != nil || !pend {
					t.Fatalf("fixture: gateway startRekey: %v, rekeyPend %v", err, pend)
				}
				if err := p.gw.Close(); err != nil {
					t.Fatal(err)
				}
				p.cli.mu.Lock()
				err = p.cli.startRekey(now)
				p.cli.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				ri, err := p.cli.Poll()
				if err != nil || ri == nil {
					t.Fatalf("fixture: no REKEY_INIT (%v)", err)
				}
				if p.gw.State() != StateClosing {
					t.Fatalf("fixture: gateway %s, want closing", p.gw.State())
				}
				ct1DeliverVia(t, p.gw, path, ri)
				if st := p.gw.State(); st != StateClosing {
					t.Fatalf("a REKEY_INIT moved a closing gateway to %s", st)
				}
				if dl := p.gw.NextDeadline(); dl.After(p.clk.Now()) {
					t.Fatalf("a closing gateway's next deadline is %v ahead, want now", dl.Sub(p.clk.Now()))
				}
				if flush == "poll-at-next-deadline" {
					// Where D6a's NextDeadline (rekeyEnd) would send the host.
					p.clk.Advance(p.gw.cfg.RekeyTimeout)
				}
				n := ct1PollAll(t, p.gw)
				if n != 1 || p.gw.State() != StateClosed || p.gw.LocalCloseReason() != CloseNormal || p.gw.Err() != nil {
					t.Fatalf("after the flush: %d datagram(s), %s, reason %s, err %v; want 1, closed, normal, nil", n, p.gw.State(), p.gw.LocalCloseReason(), p.gw.Err())
				}
			})
		}
	}
}
