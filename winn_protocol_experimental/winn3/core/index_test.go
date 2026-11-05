package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// This file pins the seam added for the gateway session table: RecvDemuxKey and
// OpenAt (docs/handoff/WINN3_CORE_GATEWAY_HOOKS_20260808.md).
//
// OpenAt takes a counter chosen OUTSIDE the core, which is exactly the shape
// that could quietly undo two of this package's load-bearing properties: that
// the AEAD is the only thing which accepts a message, and that no (key, nonce)
// pair is ever used twice. Everything here exists to make a regression in
// either one a test failure rather than a review finding.

// --- RecvDemuxKey -------------------------------------------------------------

// TestRecvDemuxKeyNamesExactlyTheTokensOpenWouldRecognise is the whole point of
// the accessor: an external index built from it must recognise the same
// datagrams the session's own private window would have.
//
// It is asserted against REAL Seal output rather than against demuxToken, so it
// cannot pass by restating the derivation to itself. If the accessor returned
// the wrong direction's key — the single most likely mistake, since the send
// key sits one field away — every comparison here fails.
func TestRecvDemuxKeyNamesExactlyTheTokensOpenWouldRecognise(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	// gw receives what cli sends, so gw's receive demux key must name cli's
	// sealed tokens.
	key, epoch := gw.RecvDemuxKey()
	if epoch != 0 {
		t.Fatalf("a fresh session reports epoch %d, want 0", epoch)
	}
	if key == ([KeySize]byte{}) {
		t.Fatal("the receive demux key is all zeroes")
	}

	var sendKey [KeySize]byte
	gw.sendMu.Lock()
	sendKey = gw.sendDemux
	gw.sendMu.Unlock()
	if key == sendKey {
		t.Fatal("RecvDemuxKey returned the SEND demux key: an index built from it would " +
			"recognise nothing this session ever receives")
	}

	const messages = 200
	for i := 0; i < messages; i++ {
		msg, err := cli.Seal([]byte{byte(i)}, 0)
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		want := demuxToken(&key, uint64(i))
		if !bytes.Equal(msg[:DemuxTokenSize], want[:]) {
			t.Fatalf("message %d carries token %x, but the key from RecvDemuxKey names %x",
				i, msg[:DemuxTokenSize], want)
		}
		if _, err := gw.Open(msg); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
}

// TestRecvDemuxKeyIsACopyAndTracksTheRatchet covers the two ways an index built
// from this accessor goes stale: a caller mutating what it was handed, and a
// ratchet the caller did not notice.
func TestRecvDemuxKeyIsACopyAndTracksTheRatchet(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	key0, epoch0 := gw.RecvDemuxKey()

	// A copy. Scribbling on the returned array must not reach the session.
	scribble := key0
	for i := range scribble {
		scribble[i] ^= 0xFF
	}
	again, _ := gw.RecvDemuxKey()
	if again != key0 {
		t.Fatal("RecvDemuxKey handed out a reference: mutating the returned key changed the session")
	}

	secret := bytes.Repeat([]byte{0x42}, KeySize)
	if err := cli.Rekey(secret); err != nil {
		t.Fatalf("client rekey: %v", err)
	}
	if err := gw.Rekey(secret); err != nil {
		t.Fatalf("gateway rekey: %v", err)
	}

	key1, epoch1 := gw.RecvDemuxKey()
	if epoch1 != epoch0+1 {
		t.Fatalf("after one ratchet the reported epoch is %d, want %d", epoch1, epoch0+1)
	}
	if key1 == key0 {
		t.Fatal("the receive demux key did not change across a ratchet, so an index " +
			"rebuilt at the ratchet would still be naming the old epoch's tokens")
	}

	// The new key must name the new epoch's tokens, and the counter must have
	// restarted at zero — an index that re-based on the key but not on the
	// counter would be just as broken.
	msg, err := cli.Seal([]byte("after"), 0)
	if err != nil {
		t.Fatalf("seal after rekey: %v", err)
	}
	want := demuxToken(&key1, 0)
	if !bytes.Equal(msg[:DemuxTokenSize], want[:]) {
		t.Fatalf("the first message of epoch %d carries token %x, the rebased key names %x",
			epoch1, msg[:DemuxTokenSize], want)
	}
}

// --- OpenAt: what it trusts ---------------------------------------------------

// TestOpenAtAgreesWithOpen is the differential test. Open and OpenAt share
// openCounterLocked precisely so they cannot drift, and this is what would
// notice if someone un-shared them.
//
// Two identical sessions are driven with identical traffic, one through each
// method, and are required to produce identical plaintext, identical errors and
// identical accounting.
func TestOpenAtAgreesWithOpen(t *testing.T) {
	ha := newHarness(t)
	cliA, gwA := ha.completeHandshake(t)
	hb := newHarness(t)
	cliB, gwB := hb.completeHandshake(t)

	// Same seed, so the two harnesses are byte-for-byte identical; that is what
	// makes the comparison meaningful.
	payloads := [][]byte{
		nil,
		[]byte("a"),
		bytes.Repeat([]byte{0x9E}, 1200),
		[]byte("winn3"),
	}

	for i := 0; i < 300; i++ {
		p := payloads[i%len(payloads)]
		padTo := 0
		if i%3 == 0 {
			padTo = TransportOverhead() + len(p) + 17
		}

		msgA, err := cliA.Seal(p, padTo)
		if err != nil {
			t.Fatalf("seal A %d: %v", i, err)
		}
		msgB, err := cliB.Seal(p, padTo)
		if err != nil {
			t.Fatalf("seal B %d: %v", i, err)
		}
		if !bytes.Equal(msgA, msgB) {
			t.Fatalf("the two harnesses diverged at message %d; this test compares nothing", i)
		}

		gotA, errA := gwA.Open(msgA)
		gotB, errB := gwB.OpenAt(msgB, uint64(i))
		if !bytes.Equal(gotA, gotB) || !errors.Is(errB, errA) && !(errA == nil && errB == nil) {
			t.Fatalf("message %d: Open gave (%x, %v), OpenAt gave (%x, %v)", i, gotA, errA, gotB, errB)
		}
		if !bytes.Equal(gotA, p) && !(len(gotA) == 0 && len(p) == 0) {
			t.Fatalf("message %d: round trip gave %x, want %x", i, gotA, p)
		}
		if gwA.RecvdBytes() != gwB.RecvdBytes() {
			t.Fatalf("message %d: byte accounting diverged, %d against %d",
				i, gwA.RecvdBytes(), gwB.RecvdBytes())
		}
	}

	// Rejections must agree too, not just acceptances.
	short := make([]byte, TransportOverhead()-1)
	if _, err := gwA.Open(short); !errors.Is(err, ErrShortMessage) {
		t.Fatalf("Open on a short message: %v", err)
	}
	if _, err := gwB.OpenAt(short, 0); !errors.Is(err, ErrShortMessage) {
		t.Fatalf("OpenAt on a short message: %v", err)
	}
}

// TestOpenAtTrustsTheAEADAndNotTheCounter is the core security claim.
//
// A message sealed at counter C must open at C and at NOTHING ELSE, and every
// wrong answer must come from the AEAD rather than from anything that inspected
// the counter. The test walks every counter the window will accept and requires
// exactly one success.
//
// It then requires that all those failures changed nothing: the messages the
// session has not yet been given still open afterwards. That is the difference
// between "an attacker-chosen counter buys a failed open" and "an
// attacker-chosen counter can burn a slot a real packet needs".
func TestOpenAtTrustsTheAEADAndNotTheCounter(t *testing.T) {
	h := newHarness(t, func(hh *harness) {
		hh.clientCf.TokenWindow = 32
		hh.gwCf.TokenWindow = 32
	})
	cli, gw := h.completeHandshake(t)

	const target = 7
	msgs := make([][]byte, 16)
	for i := range msgs {
		m, err := cli.Seal([]byte(fmt.Sprintf("payload-%d", i)), 0)
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		msgs[i] = m
	}

	// Every in-window counter except the true one must be refused by the AEAD.
	successes := 0
	for c := uint64(0); c < 32; c++ {
		if c == target {
			continue
		}
		if _, err := gw.OpenAt(msgs[target], c); err == nil {
			successes++
			t.Errorf("a message sealed at counter %d opened at counter %d", target, c)
		} else if !errors.Is(err, ErrDecrypt) {
			t.Fatalf("counter %d: got %v, want ErrDecrypt — the rejection must be the "+
				"AEAD's, not a counter comparison's", c, err)
		}
	}
	if successes != 0 {
		t.Fatalf("%d wrong counters opened the message", successes)
	}

	// The AAD is the token exactly as it arrived. Flip one bit of it and the
	// AEAD must refuse even though the counter is right — if the AAD were ever
	// dropped, or re-derived from the counter instead of read from the wire,
	// this is what would notice.
	tampered := append([]byte(nil), msgs[target]...)
	tampered[3] ^= 0x01
	if _, err := gw.OpenAt(tampered, target); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("a message with a tampered demux token opened at its true counter: %v", err)
	}

	// A flipped ciphertext byte, same requirement.
	tampered = append([]byte(nil), msgs[target]...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := gw.OpenAt(tampered, target); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("a message with a tampered body opened: %v", err)
	}

	// None of that consumed anything: every message still opens, in order, at
	// its own counter.
	for i, m := range msgs {
		got, err := gw.OpenAt(m, uint64(i))
		if err != nil {
			t.Fatalf("message %d no longer opens after the failed attempts: %v", i, err)
		}
		if want := fmt.Sprintf("payload-%d", i); string(got) != want {
			t.Fatalf("message %d opened to %q, want %q", i, got, want)
		}
	}
}

// TestOpenAtRejectionsAreIndistinguishable holds the line Open holds.
//
// Open answers an unknown token, a replay and pure noise with one error, on
// purpose, so that no caller can build an oracle out of the distinction. OpenAt
// must mirror that exactly, and it must in particular NOT single out a replay —
// a distinct ErrReplay here would tell whoever could reach it that a counter had
// once carried a real packet.
//
// The mirror is exact, including its one seam. Open answers a KNOWN token whose
// body fails with ErrDecrypt, which is a different error from an unknown token;
// OpenAt answers an in-window counter whose body fails the same way. That
// distinction is local, it is identical to the one Open already has, and
// nothing is ever written back on either path — see the note on silence in
// doc.go. This test pins both halves so that neither drifts.
func TestOpenAtRejectionsAreIndistinguishable(t *testing.T) {
	h := newHarness(t, func(hh *harness) {
		hh.clientCf.TokenWindow = 32
		hh.gwCf.TokenWindow = 32
	})
	cli, gw := h.completeHandshake(t)

	msg, err := cli.Seal([]byte("one"), 0)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := gw.OpenAt(msg, 0); err != nil {
		t.Fatalf("genuine open: %v", err)
	}
	// Consuming counter 0 slid the window to [1, 33).

	cases := []struct {
		name    string
		counter uint64
	}{
		{"already consumed", 0},
		{"just past the high edge", 33},
		{"far past the high edge", 1 << 40},
		{"the counter ceiling", ^uint64(0)},
	}
	var first error
	for i, tc := range cases {
		_, err := gw.OpenAt(msg, tc.counter)
		if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("%s: got %v, want ErrUnauthenticated", tc.name, err)
		}
		if errors.Is(err, ErrReplay) {
			t.Fatalf("%s: a replay is being reported as a replay; that is an oracle", tc.name)
		}
		if i == 0 {
			first = err
			continue
		}
		if err != first {
			t.Fatalf("%s returned %v where a consumed counter returns %v; the two are "+
				"distinguishable and the caller can tell a replay from noise", tc.name, err, first)
		}
	}

	// The seam, pinned: an in-window counter that no message has claimed yet is
	// refused by the AEAD, exactly as Open refuses a known token with a bad body.
	if _, err := gw.OpenAt(msg, 20); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("an in-window counter gave %v, want ErrDecrypt from the AEAD", err)
	}
	fresh, err := cli.Seal([]byte("two"), 0)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	bad := append([]byte(nil), fresh...)
	bad[len(bad)-1] ^= 0x01
	if _, err := gw.Open(bad); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Open on a known token with a bad body gave %v, want ErrDecrypt", err)
	}
}

// --- OpenAt: replay -----------------------------------------------------------

// brokenIndex is a caller-side index that never erases anything: it hands back
// the same counter for the same message forever. It stands in for the §7
// contract in which "the caller owns replay", and for any caller that has that
// bug.
type brokenIndex struct{ counters map[string]uint64 }

func (b *brokenIndex) remember(msg []byte, counter uint64) {
	if b.counters == nil {
		b.counters = make(map[string]uint64)
	}
	b.counters[string(msg[:DemuxTokenSize])] = counter
}

func (b *brokenIndex) lookup(msg []byte) (uint64, bool) {
	c, ok := b.counters[string(msg[:DemuxTokenSize])]
	return c, ok
}

// TestOpenAtCannotBeUsedToReplay is the reason the replay filter did not move
// out with the lookup.
//
// The caller here is deliberately broken in the exact way the §7 sketch would
// have permitted: it resolves consumed counters forever and erases nothing. If
// anti-replay lived in the caller, every one of these deliveries would succeed.
// The session must refuse all of them, in both configurations, and must go on
// accepting the messages it has not seen.
func TestOpenAtCannotBeUsedToReplay(t *testing.T) {
	for _, mode := range []struct {
		name   string
		window int
	}{
		{"core keeps its own index", 32},
		{"the caller owns the index", CallerOwnsTokenWindow},
	} {
		t.Run(mode.name, func(t *testing.T) {
			h := newHarness(t, func(hh *harness) {
				hh.clientCf.TokenWindow = 32
				hh.gwCf.TokenWindow = mode.window
			})
			cli, gw := h.completeHandshake(t)

			idx := &brokenIndex{}
			const n = 24
			msgs := make([][]byte, n)
			for i := range msgs {
				m, err := cli.Seal([]byte{byte(i)}, 0)
				if err != nil {
					t.Fatalf("seal %d: %v", i, err)
				}
				msgs[i] = m
				idx.remember(m, uint64(i))
			}

			delivered := 0
			for i, m := range msgs {
				c, ok := idx.lookup(m)
				if !ok {
					t.Fatalf("the test index lost message %d", i)
				}
				if _, err := gw.OpenAt(m, c); err != nil {
					t.Fatalf("first delivery of message %d: %v", i, err)
				}
				delivered++

				// The broken index still offers it. Ten more times.
				for k := 0; k < 10; k++ {
					if _, err := gw.OpenAt(m, c); !errors.Is(err, ErrUnauthenticated) {
						t.Fatalf("replay %d of message %d was accepted (%v); the session's "+
							"replay filter is not doing the work, the caller is", k, i, err)
					}
				}
			}
			if delivered != n {
				t.Fatalf("delivered %d of %d messages", delivered, n)
			}

			// And a replay much later, after the window has slid well past.
			if _, err := gw.OpenAt(msgs[0], 0); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("a long-delayed replay of counter 0 was accepted: %v", err)
			}
		})
	}
}

// TestOpenAtAcceptsAtMostOneMessagePerNonce extends
// TestNonceIsNeverReusedAcrossEpochs to the receive side.
//
// That test rules out a (key, nonce) pair being used twice by Seal. It cannot
// see OpenAt, because OpenAt never seals — and it is on the receive side that a
// caller-supplied counter could do the damage. The receive-side counterpart of
// the invariant is:
//
//	at most one message is ever ACCEPTED under one (key, nonce) pair.
//
// If two distinct ciphertexts were both accepted at one nonce, a receiver would
// be treating two plaintexts as authentic under a single Poly1305 one-time key
// — the same catastrophe seen from the other end, and the one thing a caller
// naming its own counters could plausibly cause.
//
// The test drives real traffic across three epochs and, at every counter, has
// an adversary try to force exactly that: a corrupted body at the true counter
// before the genuine message, a replay of the genuine message after it, and a
// different genuine ciphertext offered at the spent counter. Every accepted
// open is recorded against the (key, nonce) pair independently re-derived from
// the chain, and a repeat is a failure.
func TestOpenAtAcceptsAtMostOneMessagePerNonce(t *testing.T) {
	const (
		epochs           = 3
		messagesPerEpoch = 80
	)

	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	accepted := make(map[[KeySize + AEADNonceSize]byte]nonceUse, epochs*messagesPerEpoch)
	lowestCounter := make(map[uint32]uint64, epochs)

	record := func(key [KeySize]byte, nonce [AEADNonceSize]byte, use nonceUse) {
		t.Helper()
		var pair [KeySize + AEADNonceSize]byte
		copy(pair[:KeySize], key[:])
		copy(pair[KeySize:], nonce[:])
		if prev, dup := accepted[pair]; dup {
			t.Fatalf("NONCE REUSE ON THE RECEIVE SIDE: two messages were accepted under "+
				"the same (key, nonce) pair — first at %s, again at %s. A caller-supplied "+
				"counter has been allowed to place a second plaintext under one Poly1305 "+
				"one-time key.", prev, use)
		}
		accepted[pair] = use
		if c, ok := lowestCounter[use.epoch]; !ok || use.counter < c {
			lowestCounter[use.epoch] = use.counter
		}
	}

	payload := bytes.Repeat([]byte{0x3C}, 64)

	for e := 0; e < epochs; e++ {
		// One message is sealed ahead so there is always a genuine ciphertext
		// belonging to a DIFFERENT counter to offer at a spent one.
		pending, pendingUse := (func() ([]byte, nonceUse) {
			_, _, ct, use := sealAndRecord(t, cli, payload)
			return ct, use
		})()

		for i := 0; i < messagesPerEpoch; i++ {
			ct, use := pending, pendingUse
			key, nonce, next, nextUse := sealAndRecord(t, cli, payload)
			_ = key
			_ = nonce

			// Re-derive the pair for the message we are about to open. It is the
			// receive direction of gw, which is the send direction of cli.
			ckey, cnonce := recvPairFor(t, cli, use.epoch, use.counter)

			// 1. A corrupted body at the true counter. Must fail, and must
			//    leave the counter available for the genuine message.
			bad := append([]byte(nil), ct...)
			bad[len(bad)-1] ^= 0x80
			if _, err := gw.OpenAt(bad, use.counter); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("epoch %d counter %d: a corrupted body gave %v, want ErrDecrypt",
					use.epoch, use.counter, err)
			}

			// 2. The genuine open.
			got, err := gw.OpenAt(ct, use.counter)
			if err != nil {
				t.Fatalf("epoch %d counter %d: genuine open failed: %v", use.epoch, use.counter, err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("epoch %d counter %d: opened to the wrong plaintext", use.epoch, use.counter)
			}
			record(ckey, cnonce, use)

			// 3. The same message again at the same counter.
			if _, err := gw.OpenAt(ct, use.counter); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("epoch %d counter %d: a replay was accepted (%v)", use.epoch, use.counter, err)
			}

			// 4. A DIFFERENT genuine ciphertext offered at the spent counter.
			//    This is the sharpest form: real crypto, real session, wrong
			//    nonce, and the nonce is already spent.
			if _, err := gw.OpenAt(next, use.counter); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("epoch %d: the message from counter %d was accepted at spent counter %d (%v)",
					use.epoch, nextUse.counter, use.counter, err)
			}

			pending, pendingUse = next, nextUse
		}

		// Drain the one still in flight so the epoch ends clean.
		ckey, cnonce := recvPairFor(t, cli, pendingUse.epoch, pendingUse.counter)
		if _, err := gw.OpenAt(pending, pendingUse.counter); err != nil {
			t.Fatalf("epoch %d: draining counter %d: %v", pendingUse.epoch, pendingUse.counter, err)
		}
		record(ckey, cnonce, pendingUse)

		if e == epochs-1 {
			break
		}
		secret := bytes.Repeat([]byte{byte(0x20 + e)}, KeySize)
		if err := cli.Rekey(secret); err != nil {
			t.Fatalf("client rekey into epoch %d: %v", e+1, err)
		}
		if err := gw.Rekey(secret); err != nil {
			t.Fatalf("gateway rekey into epoch %d: %v", e+1, err)
		}
	}

	// The test must not be able to pass by doing less work than it claims.
	want := epochs * (messagesPerEpoch + 1)
	if len(accepted) != want {
		t.Fatalf("recorded %d accepted (key, nonce) pairs, expected %d", len(accepted), want)
	}
	if len(lowestCounter) != epochs {
		t.Fatalf("saw %d epochs, expected %d", len(lowestCounter), epochs)
	}
	for epoch, low := range lowestCounter {
		if low != 0 {
			t.Fatalf("epoch %d: the lowest counter accepted was %d, not 0; the counter is "+
				"not restarting with the epoch, so this test is not exercising the "+
				"cross-epoch case it exists for", epoch, low)
		}
	}
}

// recvPairFor re-derives, from the chain, the (key, nonce) pair a receiver must
// use for one counter of the sender's current epoch. It is independent of what
// the session installed, in the same spirit as sealAndRecord: a pair recorded
// from the session's own fields would only be restating the session to itself.
func recvPairFor(t *testing.T, sender *Session, epoch uint32, counter uint64) ([KeySize]byte, [AEADNonceSize]byte) {
	t.Helper()

	sender.chainMu.Lock()
	ch := sender.ch
	cur := sender.epoch
	sender.chainMu.Unlock()
	if cur != epoch {
		t.Fatalf("recvPairFor asked for epoch %d while the sender is at %d", epoch, cur)
	}

	dir := dirI2R
	if sender.role == RoleResponder {
		dir = dirR2I
	}
	dk := deriveDirection(&ch, epoch, dir)

	var nonce [AEADNonceSize]byte
	copy(nonce[:nonceSaltSize], dk.salt[:])
	binary.BigEndian.PutUint64(nonce[nonceSaltSize:], counter)
	return dk.key, nonce
}

// TestConcurrentIndexAccessAndRatchet is the seam's concurrency contract.
//
// A gateway reads RecvDemuxKey from whichever goroutine is rebuilding an index
// and calls OpenAt from its dispatch loop, while a session driver ratchets from
// a third. RecvDemuxKey therefore has to return a key and the epoch that key
// belongs to as ONE value: a torn read pairs a fresh key with a stale epoch
// number, an index gets rebuilt under the wrong label, and every subsequent
// packet of that session is dropped for a reason nothing reports.
//
// Reporting that as "the race detector is quiet" would be weak, because the
// detector only sees what the schedule happens to interleave. So every observed
// pair is checked against the key that epoch is independently known to have,
// derived here from the chain by mirroring what ratchet does. A torn read fails
// this test whether or not -race is watching.
func TestConcurrentIndexAccessAndRatchet(t *testing.T) {
	const epochs = 8

	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	secret := func(e int) []byte { return bytes.Repeat([]byte{byte(0xA0 + e)}, KeySize) }

	// The gateway is the responder, so its RECEIVE direction is i2r.
	gw.chainMu.Lock()
	ch := gw.ch
	gw.chainMu.Unlock()
	expected := make([][KeySize]byte, epochs)
	for e := 0; e < epochs; e++ {
		expected[e] = deriveDirection(&ch, uint32(e), dirI2R).demux
		ch.mixSecret(secret(e), labelRekey)
	}
	if expected[0] == expected[1] {
		t.Fatal("the expected keys do not vary by epoch; this test would pass on a stuck accessor")
	}

	stop := make(chan struct{})
	ready := make(chan struct{})
	readerDone := make(chan error, 1)
	dispatchDone := make(chan error, 1)
	var readyOnce sync.Once
	var observed atomic.Uint64 // one bit per epoch actually seen

	go func() { // the index builder
		for {
			select {
			case <-stop:
				readerDone <- nil
				return
			default:
			}
			key, epoch := gw.RecvDemuxKey()
			if int(epoch) >= epochs {
				readerDone <- fmt.Errorf("RecvDemuxKey reported epoch %d, beyond the %d this "+
					"test drives", epoch, epochs)
				return
			}
			if key != expected[epoch] {
				readerDone <- fmt.Errorf("RecvDemuxKey paired the key of some other epoch with "+
					"epoch %d: an index built from that pair names tokens no packet carries", epoch)
				return
			}
			observed.Or(1 << epoch)
			readyOnce.Do(func() { close(ready) })
		}
	}()

	// The reader must be live before the first ratchet, or it races nothing.
	<-ready

	go func() { // the dispatch loop
		noise := make([]byte, TransportOverhead()+8)
		for i := 0; i < 50000; i++ {
			noise[0] = byte(i)
			noise[9] = byte(i >> 8)
			// Whatever the ratchet is doing underneath, this must never panic
			// and must never claim to have opened noise.
			if plain, err := gw.OpenAt(noise, uint64(i%64)); err == nil {
				dispatchDone <- fmt.Errorf("OpenAt opened %d bytes of noise at counter %d",
					len(plain), i%64)
				return
			}
		}
		dispatchDone <- nil
	}()

	for e := 0; e < epochs-1; e++ {
		if err := gw.Rekey(secret(e)); err != nil {
			t.Fatalf("ratchet into epoch %d: %v", e+1, err)
		}
		runtime.Gosched()
	}
	if err := <-dispatchDone; err != nil {
		close(stop)
		<-readerDone
		t.Fatal(err)
	}
	close(stop)
	if err := <-readerDone; err != nil {
		t.Fatal(err)
	}

	seen := observed.Load()
	if seen&1 == 0 {
		t.Fatal("the index builder never observed epoch 0, so it never raced the ratchet")
	}
	if seen&(1<<(epochs-1)) == 0 {
		t.Fatalf("the index builder never observed the final epoch (mask %b)", seen)
	}

	// The session is still usable afterwards: bring the client up to the same
	// epoch and require a real message through OpenAt.
	for e := 0; e < epochs-1; e++ {
		if err := cli.Rekey(secret(e)); err != nil {
			t.Fatalf("client ratchet into epoch %d: %v", e+1, err)
		}
	}
	key, epoch := gw.RecvDemuxKey()
	if epoch != epochs-1 {
		t.Fatalf("after %d ratchets the epoch is %d", epochs-1, epoch)
	}
	msg, err := cli.Seal([]byte("still here"), 0)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	want := demuxToken(&key, 0)
	if !bytes.Equal(msg[:DemuxTokenSize], want[:]) {
		t.Fatal("the final key does not name the final epoch's tokens")
	}
	got, err := gw.OpenAt(msg, 0)
	if err != nil {
		t.Fatalf("OpenAt after the ratchets: %v", err)
	}
	if string(got) != "still here" {
		t.Fatalf("opened to %q", got)
	}
}

// --- the caller-owned configuration -------------------------------------------

// TestCallerOwnsWindowDropsTheIndexAndKeepsTheFilter states the contract of the
// new configuration in one place: the lookup is gone, the filter is not.
func TestCallerOwnsWindowDropsTheIndexAndKeepsTheFilter(t *testing.T) {
	h := newHarness(t, func(hh *harness) {
		hh.clientCf.TokenWindow = 64
		hh.gwCf.TokenWindow = CallerOwnsTokenWindow
	})
	cli, gw := h.completeHandshake(t)

	msg, err := cli.Seal([]byte("hello"), 0)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Open cannot work and says which mistake was made rather than reporting a
	// live datagram as noise.
	if _, err := gw.Open(msg); !errors.Is(err, ErrCallerOwnsWindow) {
		t.Fatalf("Open on a caller-owned session: got %v, want ErrCallerOwnsWindow", err)
	}
	if errors.Is(err, ErrUnauthenticated) {
		t.Fatal("a configuration mistake is being reported as an unauthenticated packet")
	}

	// OpenAt does.
	got, err := gw.OpenAt(msg, 0)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("opened to %q", got)
	}

	// The window holds no tokens at all — that is the memory the mode exists to
	// save — and holds every counter's replay state.
	gw.recvMu.Lock()
	indexed := gw.recvWindow.indexed()
	live := len(gw.recvWindow.tokens)
	size := gw.recvWindow.size
	gw.recvMu.Unlock()
	if indexed || live != 0 {
		t.Fatalf("a caller-owned session still holds %d indexed tokens", live)
	}
	if size != DefaultTokenWindow {
		t.Fatalf("the retained replay filter is %d wide, want %d", size, DefaultTokenWindow)
	}

	// Reordering still works, out to the window, and replay still does not.
	msgs := make([][]byte, 40)
	for i := range msgs {
		m, err := cli.Seal([]byte{byte(i)}, 0)
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		msgs[i] = m
	}
	for i := len(msgs) - 1; i >= 0; i-- {
		if _, err := gw.OpenAt(msgs[i], uint64(i+1)); err != nil {
			t.Fatalf("reordered delivery of message %d: %v", i, err)
		}
	}
	for i := range msgs {
		if _, err := gw.OpenAt(msgs[i], uint64(i+1)); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("replay of message %d was accepted", i)
		}
	}
}

// TestCallerOwnedSessionSurvivesItsOwnRatchet: the mode must not quietly break
// the ratchet, which resets both the demux key and the counter.
func TestCallerOwnedSessionSurvivesItsOwnRatchet(t *testing.T) {
	h := newHarness(t, func(hh *harness) {
		hh.gwCf.TokenWindow = CallerOwnsTokenWindow
	})
	cli, gw := h.completeHandshake(t)

	for e := 0; e < 3; e++ {
		key, epoch := gw.RecvDemuxKey()
		if epoch != uint32(e) {
			t.Fatalf("expected epoch %d, got %d", e, epoch)
		}
		for i := 0; i < 20; i++ {
			m, err := cli.Seal([]byte{byte(e), byte(i)}, 0)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			want := demuxToken(&key, uint64(i))
			if !bytes.Equal(m[:DemuxTokenSize], want[:]) {
				t.Fatalf("epoch %d message %d: token does not match the rebased key", e, i)
			}
			got, err := gw.OpenAt(m, uint64(i))
			if err != nil {
				t.Fatalf("epoch %d message %d: %v", e, i, err)
			}
			if len(got) != 2 || got[0] != byte(e) || got[1] != byte(i) {
				t.Fatalf("epoch %d message %d opened to %x", e, i, got)
			}
		}
		if e == 2 {
			break
		}
		secret := bytes.Repeat([]byte{byte(0x70 + e)}, KeySize)
		if err := cli.Rekey(secret); err != nil {
			t.Fatalf("client rekey: %v", err)
		}
		if err := gw.Rekey(secret); err != nil {
			t.Fatalf("gateway rekey: %v", err)
		}
	}
}

// TestCallerOwnsTokenWindowIsTheOnlyNonSizeValue: the sentinel must be accepted
// and nothing near it may be.
func TestCallerOwnsTokenWindowIsTheOnlyNonSizeValue(t *testing.T) {
	h := newHarness(t)

	ok := h.gwCf
	ok.TokenWindow = CallerOwnsTokenWindow
	if err := ok.validate(true); err != nil {
		t.Fatalf("CallerOwnsTokenWindow was rejected: %v", err)
	}

	for _, bad := range []int{-2, -1000, 2, MinTokenWindow - 1, MaxTokenWindow + 1} {
		c := h.gwCf
		c.TokenWindow = bad
		if err := c.validate(true); !errors.Is(err, ErrConfig) {
			t.Fatalf("TokenWindow %d was accepted", bad)
		}
	}
}

// TestACallerOwnedSessionDerivesNoTokens guards a property that is invisible to
// every other test here, because it is a COST rather than a behaviour.
//
// The counter-only window is the indexed one with its map switched off, and
// `delete` on a nil map is a silent no-op. So a future editor can remove either
// nil guard in replay.go, change nothing observable, and quietly put a full
// HMAC back on the gateway's hot path for every packet — twice, once in consume
// and once in retireLow — for a map that does not exist. The gateway lane found
// exactly this class of thing (its §8 bug 2: sixteen allocations per packet
// that no test could see) and it found it with allocation counts, so that is
// what this uses.
//
// demuxToken calls hmac.New, which allocates about eight objects. An OpenAt
// that opens, decrypts and returns a plaintext needs a handful. The ceiling
// separates the two by a wide margin and is not a benchmark.
func TestACallerOwnedSessionDerivesNoTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation measurement")
	}

	h := newHarness(t, func(hh *harness) {
		hh.gwCf.TokenWindow = CallerOwnsTokenWindow
	})
	cli, gw := h.completeHandshake(t)

	const n = 3000
	msgs := make([][]byte, n)
	payload := bytes.Repeat([]byte{0x11}, 64)
	for i := range msgs {
		m, err := cli.Seal(payload, 0)
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		msgs[i] = m
	}

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i, m := range msgs {
		if _, err := gw.OpenAt(m, uint64(i)); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
	runtime.ReadMemStats(&after)

	perOpen := float64(after.Mallocs-before.Mallocs) / float64(n)
	t.Logf("caller-owned OpenAt: %.2f allocations per opened datagram (window slides every open)", perOpen)

	const ceiling = 6.0
	if perOpen > ceiling {
		t.Fatalf("a caller-owned open costs %.2f allocations, ceiling %.1f. The window is "+
			"deriving demux tokens it has no map to put them in — check the nil guards in "+
			"consume and retireLow. This is invisible to every other test in this file and "+
			"it lands on the gateway's hottest path.", perOpen, ceiling)
	}
}

// --- the two window modes must not drift --------------------------------------

// TestTheCounterOnlyWindowAgreesWithTheIndexedOne is the anti-drift test for the
// one structure that carries anti-replay.
//
// The counter-only window is the same type with its map switched off, so there
// is no second implementation to drift — but a future editor could easily
// introduce one, or could add a map-dependent step to the slide. Both modes are
// driven with the same randomised consume sequences and are required to accept
// and reject identically at every counter, including the edges.
func TestTheCounterOnlyWindowAgreesWithTheIndexedOne(t *testing.T) {
	key := [KeySize]byte{0x11, 0x22, 0x33}

	for _, size := range []int{16, 32, 64} {
		for seed := int64(1); seed <= 25; seed++ {
			indexed := newTokenWindow(&key, size)
			counterOnly := newCounterWindow(size)
			rng := rand.New(rand.NewSource(seed*1000 + int64(size)))

			for step := 0; step < 400; step++ {
				// Draw a counter that is sometimes in the window, sometimes not.
				c := indexed.low + uint64(rng.Intn(size+size/2))
				if rng.Intn(8) == 0 {
					c = uint64(rng.Int63n(1 << 20))
				}

				gotIndexed := indexed.holds(c)
				gotCounter := counterOnly.holds(c)
				if gotIndexed != gotCounter {
					t.Fatalf("size %d seed %d step %d: holds(%d) is %v indexed, %v counter-only "+
						"(lows %d / %d)", size, seed, step, c, gotIndexed, gotCounter,
						indexed.low, counterOnly.low)
				}

				// holds must be exactly map membership in the indexed window.
				tok := demuxToken(&key, c)
				_, inMap := indexed.tokens[tok]
				if inMap != gotIndexed {
					t.Fatalf("size %d seed %d step %d: holds(%d)=%v but map membership is %v",
						size, seed, step, c, gotIndexed, inMap)
				}

				if gotIndexed {
					indexed.consume(c)
					counterOnly.consume(c)
				}
				if indexed.low != counterOnly.low {
					t.Fatalf("size %d seed %d step %d: low edges diverged, %d against %d",
						size, seed, step, indexed.low, counterOnly.low)
				}
			}

			if counterOnly.live() != 0 {
				t.Fatalf("the counter-only window materialised %d tokens", counterOnly.live())
			}
		}
	}
}

// --- the memory the seam exists to save ---------------------------------------

// TestDroppingTheIndexIsWhereTheMemoryGoes measures what §6.9 of the design
// document now claims, rather than asserting it from arithmetic.
//
// The gateway handoff measured core's private window at 37.5 to 51.8 bytes per
// token. Keeping the replay filter and dropping the map should leave roughly one
// byte per counter plus the session itself, so the ratio at a large window
// should be an order of magnitude at least. The bound is deliberately loose —
// this is a guard against the saving silently disappearing, not a benchmark.
func TestDroppingTheIndexIsWhereTheMemoryGoes(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation measurement")
	}

	measure := func(windowSize int, n int) uint64 {
		t.Helper()
		sessions := make([]*Session, 0, n)
		runtime.GC()
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for i := 0; i < n; i++ {
			ch := newChain([]byte{byte(i), byte(i >> 8), 0x5A})
			s, err := newSession(RoleResponder, ch, windowSize)
			if err != nil {
				t.Fatalf("session %d: %v", i, err)
			}
			sessions = append(sessions, s)
		}
		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(sessions)
		return (after.HeapAlloc - before.HeapAlloc) / uint64(n)
	}

	const n = 2000
	withIndex := measure(DefaultTokenWindow, n)
	withoutIndex := measure(CallerOwnsTokenWindow, n)

	t.Logf("core receive state per session: %d B with its own %d-token index, %d B with the "+
		"index dropped (%.1fx)", withIndex, DefaultTokenWindow, withoutIndex,
		float64(withIndex)/float64(withoutIndex))

	if withoutIndex == 0 || withIndex/withoutIndex < 10 {
		t.Fatalf("dropping the index saved only %d B against %d B per session; the seam is "+
			"no longer buying what §6.9 says it buys", withIndex-withoutIndex, withIndex)
	}
}
