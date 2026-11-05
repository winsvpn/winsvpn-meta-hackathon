package session

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// TestFreshInitiationWipesDisplacedHandshakeSecrets is the key-lifecycle half
// of TestLostHandshakeResponseIsRecoveredByAFreshInitiation.
//
// Retry.FreshAfter replaces the live Initiator with a new ephemeral. The
// displaced object still holds the X25519 handshake ephemeral and the chaining
// key. If the gateway already accepted the old initiation (response lost), it
// still holds the matching session. Dropping the pointer without Initiator.Wipe
// leaves that forward-secrecy secret in the client's heap until GC while the
// process keeps running — the failure Driver.terminate already refuses for the
// Close path, and the hole this test exists to close.
//
// Client-visible on the recovery path: nothing (the fresh handshake
// establishes). The assertion is that the displaced Initiator returns ErrWiped,
// not that connectivity broke.
func TestFreshInitiationWipesDisplacedHandshakeSecrets(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.Retry = Retry{Base: time.Second, Cap: 2 * time.Second, Attempts: 8, FreshAfter: 2}
		gw.Retry = Retry{Base: time.Minute, Cap: time.Minute, Attempts: 8}
	})
	// Nothing reaches the gateway, so the client must retransmit then rotate.
	// That is the initiation-lost half; the response-lost half is the same
	// client-side rotation and is the one that leaves a live gateway session.
	p.filterToGw = func(int, []byte) bool { return false }

	p.drain()
	displaced := p.cli.ini
	if displaced == nil {
		t.Fatal("NewClient left ini nil")
	}
	first, err := displaced.Retransmit()
	if err != nil || len(first) == 0 {
		t.Fatalf("displaced Retransmit before rotation: err=%v len=%d", err, len(first))
	}

	rotated := false
	for i := 0; i < 16 && p.cli.State() == StateInitiating; i++ {
		dl := p.cli.NextDeadline()
		if dl.IsZero() {
			t.Fatal("client has no retry deadline while still initiating")
		}
		now := p.clk.Now()
		if dl.After(now) {
			p.clk.Advance(dl.Sub(now) + time.Nanosecond)
		}
		p.drain()
		if p.cli.ini != displaced {
			rotated = true
			break
		}
	}
	if !rotated {
		t.Fatal("client never rotated onto a fresh Initiator; FreshAfter did not fire")
	}

	if _, err := displaced.Retransmit(); !errors.Is(err, core.ErrWiped) {
		t.Fatalf("displaced Retransmit after rotation returned %v, want ErrWiped (freshInitiation must Wipe the old Initiator)", err)
	}
	if _, err := displaced.WriteInitiation(nil, core.PadAuto); !errors.Is(err, core.ErrWiped) {
		t.Fatalf("displaced WriteInitiation after rotation returned %v, want ErrWiped", err)
	}
	if _, _, err := displaced.ReadResponse(first); !errors.Is(err, core.ErrWiped) {
		t.Fatalf("displaced ReadResponse after rotation returned %v, want ErrWiped", err)
	}

	if p.cli.ini == nil {
		t.Fatal("rotation left ini nil")
	}
	live, err := p.cli.ini.Retransmit()
	if err != nil || len(live) == 0 {
		t.Fatalf("live Retransmit: err=%v len=%d", err, len(live))
	}
	if bytes.Equal(live, first) {
		t.Fatal("fresh initiation was byte-identical to the displaced one; the ephemeral did not change")
	}
}

// TestDriverCloseWipesCoreSessionKeys is the assertion
// TestCloseAfterCancelledRunWipesSessionKeys is named for and does not make.
// That test checks Deliver returns ErrClosed, which Driver.Deliver does on
// State.Terminal() before touching Session — so a terminate that flipped
// state and skipped Session.Wipe would still pass.
//
// Close queues a CLOSE whose after-hook is terminate. One Poll seals it and
// runs the hook. RecvDemuxKey must then be zeros and Seal must return ErrWiped.
func TestDriverCloseWipesCoreSessionKeys(t *testing.T) {
	p := establishedPair(t)
	sess := p.cli.sess
	if sess == nil {
		t.Fatal("established pair has no session")
	}
	keyBefore, _ := sess.RecvDemuxKey()
	if keyBefore == [core.KeySize]byte{} {
		t.Fatal("RecvDemuxKey was all zeros before Close; the handshake did not install a demux key")
	}

	if err := p.cli.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8 && !p.cli.State().Terminal(); i++ {
		if _, err := p.cli.Poll(); err != nil {
			t.Fatalf("Poll after Close: %v", err)
		}
	}
	if !p.cli.State().Terminal() {
		t.Fatalf("state is %s after Close+Poll, want terminal", p.cli.State())
	}

	key, epoch := sess.RecvDemuxKey()
	if key != [core.KeySize]byte{} || epoch != 0 {
		t.Fatalf("RecvDemuxKey after Close is non-zero (epoch %d); terminate skipped Wipe", epoch)
	}
	if _, err := sess.Seal([]byte("after-wipe"), 0); !errors.Is(err, core.ErrWiped) {
		t.Fatalf("Seal after Close returned %v, want ErrWiped", err)
	}
	if _, err := p.cli.Deliver([]byte("after-wipe")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Deliver after Close returned %v, want ErrClosed", err)
	}
}

// TestPeerCloseWipesPendingRekeySharedSecret is the hole freshInitiation's
// Wipe did not cover: onRekeyInit used to capture the ECDH secret only in
// pendingFrame.after. A peer CLOSE (rekey initiator timed out, ACK never
// sent) calls terminate, which dropped ctrl and left that slice in the heap
// until GC — the next epoch's DH secret, while the process kept running.
//
// Client-visible: the session is terminal (peer CLOSE). The assertion is that
// Driver.rekeySecret is gone, not that connectivity broke.
func TestPeerCloseWipesPendingRekeySharedSecret(t *testing.T) {
	p := establishedPair(t)
	if err := p.gw.startRekey(p.clk.Now()); err != nil {
		t.Fatal(err)
	}
	initMsg, err := p.gw.Poll()
	if err != nil || initMsg == nil {
		t.Fatalf("gateway Poll after startRekey: err=%v empty=%v", err, initMsg == nil)
	}
	if _, err := p.cli.Deliver(initMsg); err != nil {
		t.Fatalf("client Deliver of RekeyInit: %v", err)
	}
	if p.cli.State() != StateRekeying {
		t.Fatalf("client state is %s after RekeyInit, want rekeying", p.cli.State())
	}
	if !secretHeld(p.cli.rekeySecret) {
		t.Fatal("onRekeyInit left rekeySecret empty; terminate cannot wipe a secret that lives only in the after-closure")
	}

	p.gw.beginClose(CloseRekeyFailed, ErrRekeyFailed)
	closeMsg, err := p.gw.Poll()
	if err != nil || closeMsg == nil {
		t.Fatalf("gateway Poll after beginClose: err=%v empty=%v", err, closeMsg == nil)
	}
	if _, err := p.cli.Deliver(closeMsg); err != nil && !errors.Is(err, ErrClosed) {
		t.Fatalf("client Deliver of CLOSE: %v", err)
	}
	if !p.cli.State().Terminal() {
		t.Fatalf("client state is %s after peer CLOSE, want terminal", p.cli.State())
	}
	if secretHeld(p.cli.rekeySecret) {
		t.Fatal("terminate left the pending rekey DH secret reachable on the driver")
	}
}

func secretHeld(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}
