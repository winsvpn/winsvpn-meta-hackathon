package core

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// TestNonceAndReplayGeometryIsNotTwelveBits is the 4096-datagram-death
// hypothesis aimed at this package: a 12-bit sequence or a non-sliding 4096-slot
// replay bitmap would wrap or pin at exactly seq 4096.
//
// The shipping transport nonce is 12 BYTES (4-byte salt || 8-byte big-endian
// uint64 counter), the receive window is DefaultTokenWindow=1024 and slides, the
// soft rekey is 2^28 messages, and the hard refuse is 2^32-2^16. None of those
// is 4096. This test round-trips 5000 messages — past the suspected cliff —
// and requires the counter, the rekey trigger and the hard ceiling to still be
// the pinned values.
func TestNonceAndReplayGeometryIsNotTwelveBits(t *testing.T) {
	if AEADNonceSize != 12 {
		t.Fatalf("AEADNonceSize=%d, want 12 bytes (not 12 bits)", AEADNonceSize)
	}
	if nonceSaltSize != 4 {
		t.Fatalf("nonceSaltSize=%d, want 4 (the other 8 bytes of the nonce are the counter)", nonceSaltSize)
	}
	if AEADNonceSize != nonceSaltSize+8 {
		t.Fatalf("nonce is not salt||uint64: AEADNonceSize=%d nonceSaltSize=%d", AEADNonceSize, nonceSaltSize)
	}
	if DefaultTokenWindow == 4096 {
		t.Fatal("DefaultTokenWindow is 4096; a non-sliding window of that size would die at seq 4096")
	}
	if DefaultTokenWindow != 1024 {
		t.Fatalf("DefaultTokenWindow=%d, want 1024", DefaultTokenWindow)
	}
	if RekeyAfterMessages == 4096 {
		t.Fatal("RekeyAfterMessages is 4096; volume rekey would fire at the observed cliff")
	}
	if RekeyAfterMessages != uint64(1)<<28 {
		t.Fatalf("RekeyAfterMessages=%d, want 1<<28", RekeyAfterMessages)
	}
	if RejectAfterMessages == 4096 {
		t.Fatal("RejectAfterMessages is 4096; Seal would hard-refuse at the observed cliff")
	}
	if RejectAfterMessages != uint64(1<<32)-(1<<16) {
		t.Fatalf("RejectAfterMessages=%d, want (1<<32)-(1<<16)", RejectAfterMessages)
	}

	const n = 5000
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	for i := 0; i < n; i++ {
		payload := []byte(fmt.Sprintf("m%d", i))
		msg, err := cli.Seal(payload, 0)
		if err != nil {
			t.Fatalf("Seal at counter %d: %v (a 12-bit nonce or 4096-wide hard ceiling would fail here)", i, err)
		}
		got, err := gw.Open(msg)
		if err != nil {
			t.Fatalf("Open at counter %d: %v (a non-sliding 4096-slot window would fail at 4096)", i, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("counter %d round-tripped wrong", i)
		}
	}
	if got := cli.SendCounter(); got != uint64(n) {
		t.Fatalf("SendCounter=%d, want %d", got, n)
	}
	if cli.NeedsRekey() {
		t.Fatal("NeedsRekey is true after 5000 messages; the soft trigger must sit at 2^28, not near 4096")
	}
	if _, err := cli.Seal([]byte("one more"), 0); errors.Is(err, ErrCounterExhausted) {
		t.Fatal("ErrCounterExhausted after 5000 seals; the hard refuse is RejectAfterMessages, not 4096")
	}
}

// TestTokenWindowSlidesPast4096 drains 5000 consecutive counters through a
// DefaultTokenWindow-sized indexed window. A bitmap that never slid would
// reject counter 1024 at the shipping size, or 4096 at a 12-bit size.
func TestTokenWindowSlidesPast4096(t *testing.T) {
	var key [KeySize]byte
	copy(key[:], bytes.Repeat([]byte{0x3c}, KeySize))
	w := newTokenWindow(&key, DefaultTokenWindow)
	const n = 5000
	for c := uint64(0); c < n; c++ {
		tok := demuxToken(&key, c)
		got, ok := w.lookup(tok[:])
		if !ok {
			t.Fatalf("counter %d fell out of the window (size=%d low=%d); a non-sliding window dies here",
				c, w.size, w.low)
		}
		if got != c {
			t.Fatalf("token for %d mapped to %d", c, got)
		}
		w.consume(c)
	}
	if w.low != n {
		t.Fatalf("after draining 0..%d low=%d, want %d (window did not slide)", n, w.low, n)
	}
}

// TestANonSliding4096WindowWouldDropCounter4096 is the negative control for
// the 12-bit hypothesis: a FRESH window of size 4096 holds counters 0..4095
// and not 4096. After consume(0) slides, counter 4096 is admitted. Shipping
// consume does slide, so this cliff is not the live behaviour — it is what a
// frozen 4096-slot window would look like.
func TestANonSliding4096WindowWouldDropCounter4096(t *testing.T) {
	var key [KeySize]byte
	copy(key[:], bytes.Repeat([]byte{0xa1}, KeySize))
	w := newTokenWindow(&key, 4096)

	tok4096 := demuxToken(&key, 4096)
	if _, ok := w.lookup(tok4096[:]); ok {
		t.Fatal("a fresh 4096-wide window held counter 4096; the initial fill is 0..4095")
	}
	tok4095 := demuxToken(&key, 4095)
	if c, ok := w.lookup(tok4095[:]); !ok || c != 4095 {
		t.Fatalf("fresh 4096-wide window must hold counter 4095, got (%d,%v)", c, ok)
	}

	w.consume(0)
	if c, ok := w.lookup(tok4096[:]); !ok || c != 4096 {
		t.Fatal("after consume(0) the window did not admit counter 4096; consume is what makes 4096 not a cliff")
	}
	tok0 := demuxToken(&key, 0)
	if _, ok := w.lookup(tok0[:]); ok {
		t.Fatal("consumed counter 0 was not erased")
	}
}
