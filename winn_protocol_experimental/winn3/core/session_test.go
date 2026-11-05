package core

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestTransportRoundTrip(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	for i := 0; i < 64; i++ {
		payload := []byte(fmt.Sprintf("message %d", i))
		msg, err := cli.Seal(payload, 0)
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		if len(msg) != TransportOverhead()+len(payload) {
			t.Fatalf("message %d is %d bytes, expected %d", i, len(msg), TransportOverhead()+len(payload))
		}
		got, err := gw.Open(msg)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("message %d round-tripped wrong", i)
		}
	}
	if n := cli.SendCounter(); n != 64 {
		t.Fatalf("send counter is %d, expected 64", n)
	}
}

func TestTransportEmptyPayload(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)
	msg, err := cli.Seal(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gw.Open(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected an empty payload, got %d bytes", len(got))
	}
}

func TestTransportPadding(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	payload := []byte("short")
	for _, target := range []int{TransportOverhead() + len(payload), 100, 576, 1400} {
		msg, err := cli.Seal(payload, target)
		if err != nil {
			t.Fatalf("target %d: %v", target, err)
		}
		if len(msg) != target {
			t.Fatalf("target %d produced %d bytes", target, len(msg))
		}
		got, err := gw.Open(msg)
		if err != nil {
			t.Fatalf("target %d open: %v", target, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("target %d: padding leaked into the payload", target)
		}
	}

	if _, err := cli.Seal(payload, 4); !errors.Is(err, ErrTargetLenTooSmall) {
		t.Fatalf("expected ErrTargetLenTooSmall, got %v", err)
	}
	if _, err := cli.Seal(make([]byte, MaxTransportPayload+1), 0); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
	}
}

// TestTransportReordering: every counter inside the window is acceptable in any
// order, which is what lets one format serve both a lossy datagram carrier and
// a reliable ordered stream carrier.
func TestTransportReordering(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	const n = 200
	msgs := make([][]byte, n)
	for i := range msgs {
		m, err := cli.Seal([]byte(fmt.Sprintf("p%03d", i)), 0)
		if err != nil {
			t.Fatal(err)
		}
		msgs[i] = m
	}
	// Deliver backwards.
	for i := n - 1; i >= 0; i-- {
		got, err := gw.Open(msgs[i])
		if err != nil {
			t.Fatalf("reordered open %d: %v", i, err)
		}
		if want := fmt.Sprintf("p%03d", i); string(got) != want {
			t.Fatalf("reordered payload %d is %q", i, got)
		}
	}
}

// TestTransportReplayRejected: the token window IS the replay filter. A
// consumed token is erased, so a replay finds nothing.
func TestTransportReplayRejected(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	msg, err := cli.Seal([]byte("once"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Open(msg); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := gw.Open(msg); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("replay %d: expected ErrUnauthenticated, got %v", i, err)
		}
	}
}

// TestCorruptedMessageDoesNotConsumeToken: a bit-flipped copy arriving first
// must not invalidate the genuine packet behind it.
func TestCorruptedMessageDoesNotConsumeToken(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	msg, err := cli.Seal([]byte("genuine"), 0)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), msg...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := gw.Open(bad); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
	got, err := gw.Open(msg)
	if err != nil {
		t.Fatalf("the genuine packet was lost to a corrupted copy: %v", err)
	}
	if string(got) != "genuine" {
		t.Fatalf("payload is %q", got)
	}
}

func TestTransportShortAndForeignMessages(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	if _, err := gw.Open(nil); !errors.Is(err, ErrShortMessage) {
		t.Fatalf("expected ErrShortMessage, got %v", err)
	}
	if _, err := gw.Open(make([]byte, TransportOverhead()-1)); !errors.Is(err, ErrShortMessage) {
		t.Fatalf("expected ErrShortMessage, got %v", err)
	}
	// Random bytes of a plausible length: an unknown token, indistinguishable
	// from a replay and from noise, and reported identically.
	noise := make([]byte, 200)
	if _, err := gw.Open(noise); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}

	// A message from a genuinely unrelated session: different statics,
	// different admission key, different gateway id.
	other := newHarnessSeeded(t, "-other")
	otherCli, _ := other.completeHandshake(t)
	foreign, err := otherCli.Seal([]byte("not yours"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Open(foreign); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated for a foreign session, got %v", err)
	}
	_ = cli
}

// TestWindowForcedAdvance proves the progress guarantee: one permanently lost
// packet at the low edge must not pin the window and end the session.
func TestWindowForcedAdvance(t *testing.T) {
	h := newHarness(t, func(hh *harness) {
		hh.clientCf.TokenWindow = 32
		hh.gwCf.TokenWindow = 32
	})
	cli, gw := h.completeHandshake(t)

	// Drop counter 0 entirely, then send well past the window.
	first, err := cli.Seal([]byte("lost"), 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = first // never delivered

	for i := 1; i < 300; i++ {
		m, err := cli.Seal([]byte(fmt.Sprintf("k%d", i)), 0)
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		got, err := gw.Open(m)
		if err != nil {
			t.Fatalf("open %d after a dropped packet 0: %v", i, err)
		}
		if want := fmt.Sprintf("k%d", i); string(got) != want {
			t.Fatalf("payload %d is %q", i, got)
		}
	}

	// And the long-lost packet is now outside the window, so it cannot be
	// resurrected as a replay.
	if _, err := gw.Open(first); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a packet from far behind the window must not be accepted, got %v", err)
	}
}

// TestBurstLossBeyondWindowDesynchronises documents a real limitation rather
// than hiding it: because the counter is implicit in the token, a receiver that
// misses more than one full window of CONSECUTIVE packets can no longer place
// the ones that follow. The driver's obligation is to notice the silence and
// re-handshake; there is no in-band recovery.
func TestBurstLossBeyondWindowDesynchronises(t *testing.T) {
	h := newHarness(t, func(hh *harness) {
		hh.clientCf.TokenWindow = 32
		hh.gwCf.TokenWindow = 32
	})
	cli, gw := h.completeHandshake(t)

	for i := 0; i < 40; i++ {
		if _, err := cli.Seal([]byte("dropped"), 0); err != nil {
			t.Fatal(err)
		}
	}
	m, err := cli.Seal([]byte("after the gap"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Open(m); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected desynchronisation after a full-window burst loss, got %v", err)
	}
}

func TestCounterExhaustion(t *testing.T) {
	h := newHarness(t)
	cli, _ := h.completeHandshake(t)

	cli.sendMu.Lock()
	cli.sendCounter = RejectAfterMessages - 1
	cli.sendMu.Unlock()

	if _, err := cli.Seal([]byte("last"), 0); err != nil {
		t.Fatalf("the final permitted message must succeed: %v", err)
	}
	if _, err := cli.Seal([]byte("one too many"), 0); !errors.Is(err, ErrCounterExhausted) {
		t.Fatalf("expected ErrCounterExhausted, got %v", err)
	}
}

func TestNeedsRekey(t *testing.T) {
	h := newHarness(t)
	cli, _ := h.completeHandshake(t)
	if cli.NeedsRekey() {
		t.Fatal("a fresh session must not want a rekey")
	}
	cli.sendMu.Lock()
	cli.sendCounter = RekeyAfterMessages
	cli.sendMu.Unlock()
	if !cli.NeedsRekey() {
		t.Fatal("the soft volume trigger did not fire")
	}
}

// --- ratchets ---------------------------------------------------------------

func TestRekeyRatchet(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	// Traffic under epoch 0.
	pre, err := cli.Seal([]byte("epoch zero"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Open(pre); err != nil {
		t.Fatal(err)
	}

	secret := bytes.Repeat([]byte{0x42}, KeySize)
	if err := cli.Rekey(secret); err != nil {
		t.Fatal(err)
	}
	if err := gw.Rekey(secret); err != nil {
		t.Fatal(err)
	}
	if cli.Epoch() != 1 || gw.Epoch() != 1 {
		t.Fatalf("epochs are %d and %d after a rekey", cli.Epoch(), gw.Epoch())
	}
	if cli.SendCounter() != 0 {
		t.Fatal("the send counter must reset with the epoch")
	}

	post, err := cli.Seal([]byte("epoch one"), 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gw.Open(post)
	if err != nil {
		t.Fatalf("post-rekey traffic failed: %v", err)
	}
	if string(got) != "epoch one" {
		t.Fatalf("post-rekey payload is %q", got)
	}

	// An old-epoch packet must not verify under the new epoch.
	if _, err := gw.Open(pre); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("an epoch-0 packet was accepted after the ratchet: %v", err)
	}

	if err := cli.Rekey([]byte{1, 2, 3}); !errors.Is(err, ErrConfig) {
		t.Fatalf("a short rekey secret must be refused, got %v", err)
	}
}

// TestDivergentRatchetBreaksTheSession: if the two ends ratchet on different
// secrets they must simply stop understanding each other, with no fallback and
// no error signal on the wire.
func TestDivergentRatchetBreaksTheSession(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	if err := cli.Rekey(bytes.Repeat([]byte{1}, KeySize)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Rekey(bytes.Repeat([]byte{2}, KeySize)); err != nil {
		t.Fatal(err)
	}
	msg, err := cli.Seal([]byte("mismatched"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Open(msg); err == nil {
		t.Fatal("a divergent ratchet must not produce a working session")
	}
}

func TestPQRatchet(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	if cli.PQRatcheted() || gw.PQRatcheted() {
		t.Fatal("a fresh session must not claim a post-quantum ratchet")
	}

	// The exchange as the driver would carry it: PQ_EK from the client, PQ_CT
	// from the gateway, both as ordinary frames inside the transport AEAD.
	pq, err := GeneratePQEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	ek := pq.EncapsulationKey()
	if len(ek) != PQEncapsulationKeySize {
		t.Fatalf("encapsulation key is %d bytes, expected %d", len(ek), PQEncapsulationKeySize)
	}

	ekFrame, err := AppendFrame(nil, FramePQEK, ek)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := cli.Seal(ekFrame, 0)
	if err != nil {
		t.Fatal(err)
	}
	received, err := gw.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := ParseFrames(received)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || frames[0].Type != FramePQEK {
		t.Fatalf("expected one PQ_EK frame, got %+v", frames)
	}

	ct, ssGateway, err := PQEncapsulate(frames[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != PQCiphertextSize {
		t.Fatalf("ciphertext is %d bytes, expected %d", len(ct), PQCiphertextSize)
	}

	ctFrame, err := AppendFrame(nil, FramePQCT, ct)
	if err != nil {
		t.Fatal(err)
	}
	sealedCT, err := gw.Seal(ctFrame, 0)
	if err != nil {
		t.Fatal(err)
	}
	back, err := cli.Open(sealedCT)
	if err != nil {
		t.Fatal(err)
	}
	ctFrames, err := ParseFrames(back)
	if err != nil {
		t.Fatal(err)
	}
	ssClient, err := pq.Decapsulate(ctFrames[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ssClient, ssGateway) {
		t.Fatal("the two ends derived different post-quantum secrets")
	}

	if err := cli.MixPQ(ssClient); err != nil {
		t.Fatal(err)
	}
	if err := gw.MixPQ(ssGateway); err != nil {
		t.Fatal(err)
	}
	if !cli.PQRatcheted() || !gw.PQRatcheted() {
		t.Fatal("the post-quantum ratchet did not register")
	}
	if cli.Epoch() != 1 {
		t.Fatalf("epoch is %d after the post-quantum ratchet, expected 1", cli.Epoch())
	}

	msg, err := cli.Seal([]byte("hybrid"), 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gw.Open(msg)
	if err != nil {
		t.Fatalf("post-quantum epoch traffic failed: %v", err)
	}
	if string(got) != "hybrid" {
		t.Fatalf("payload is %q", got)
	}

	if err := cli.MixPQ(ssClient); !errors.Is(err, ErrPQAlreadyRatchet) {
		t.Fatalf("a second post-quantum ratchet must be refused, got %v", err)
	}
}

func TestPQArgumentValidation(t *testing.T) {
	h := newHarness(t)
	cli, _ := h.completeHandshake(t)

	if err := cli.MixPQ([]byte{1, 2, 3}); !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
	if _, _, err := PQEncapsulate([]byte{1, 2, 3}); !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig for a short encapsulation key, got %v", err)
	}
	// An all-zero encapsulation key is a VALID FIPS 203 encoding (every
	// coefficient is zero and survives the modulus check), so it is accepted.
	// What is rejected is an encoding that fails that check.
	if _, _, err := PQEncapsulate(make([]byte, PQEncapsulationKeySize)); err != nil {
		t.Fatalf("an all-zero encapsulation key is a valid encoding: %v", err)
	}
	if _, _, err := PQEncapsulate(bytes.Repeat([]byte{0xFF}, PQEncapsulationKeySize)); !errors.Is(err, ErrConfig) {
		t.Fatalf("a non-canonical encapsulation key must be refused, got %v", err)
	}
	pq, err := GeneratePQEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pq.Decapsulate([]byte{1}); !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
	// ML-KEM is designed so that a wrong ciphertext yields an unpredictable but
	// valid-looking key rather than an error; the mismatch surfaces as a failed
	// AEAD one layer up. Assert the shape, not an error.
	junk := make([]byte, PQCiphertextSize)
	ss, err := pq.Decapsulate(junk)
	if err != nil {
		t.Fatalf("implicit rejection should not error: %v", err)
	}
	if len(ss) != PQSharedKeySize {
		t.Fatalf("implicit rejection returned %d bytes", len(ss))
	}
}

// --- concurrency ------------------------------------------------------------

// TestConcurrentSealOpen is the -race workhorse: one sender goroutine and one
// receiver goroutine on each session, which is exactly how a driver uses it.
func TestConcurrentSealOpen(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	const n = 500
	toGateway := make(chan []byte, n)
	toClient := make(chan []byte, n)
	var wg sync.WaitGroup

	wg.Add(4)
	go func() {
		defer wg.Done()
		defer close(toGateway)
		for i := 0; i < n; i++ {
			m, err := cli.Seal([]byte(fmt.Sprintf("c%d", i)), 0)
			if err != nil {
				t.Errorf("client seal %d: %v", i, err)
				return
			}
			toGateway <- m
		}
	}()
	go func() {
		defer wg.Done()
		defer close(toClient)
		for i := 0; i < n; i++ {
			m, err := gw.Seal([]byte(fmt.Sprintf("g%d", i)), 0)
			if err != nil {
				t.Errorf("gateway seal %d: %v", i, err)
				return
			}
			toClient <- m
		}
	}()
	go func() {
		defer wg.Done()
		for m := range toGateway {
			if _, err := gw.Open(m); err != nil {
				t.Errorf("gateway open: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for m := range toClient {
			if _, err := cli.Open(m); err != nil {
				t.Errorf("client open: %v", err)
				return
			}
		}
	}()
	wg.Wait()
}

// TestConcurrentResponder: one Responder serves many handshakes at once.
func TestConcurrentResponder(t *testing.T) {
	h := newHarness(t)

	const n = 24
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			gwPub, err := NewPublicKey(h.gateway.Public())
			if err != nil {
				t.Errorf("gateway public: %v", err)
				return
			}
			cfg := h.clientCf
			cfg.Rand = newDetReader(fmt.Sprintf("client-rand-%d", i))
			ini, err := NewInitiator(cfg, h.client, gwPub)
			if err != nil {
				t.Errorf("initiator %d: %v", i, err)
				return
			}
			msg1, err := ini.WriteInitiation(nil, PadAuto)
			if err != nil {
				t.Errorf("initiation %d: %v", i, err)
				return
			}
			rh, err := h.resp.ReadInitiation(msg1)
			if err != nil {
				t.Errorf("read initiation %d: %v", i, err)
				return
			}
			msg2, gwSess, err := rh.WriteResponse(nil, PadAuto)
			if err != nil {
				t.Errorf("response %d: %v", i, err)
				return
			}
			cliSess, _, err := ini.ReadResponse(msg2)
			if err != nil {
				t.Errorf("read response %d: %v", i, err)
				return
			}
			m, err := cliSess.Seal([]byte("ok"), 0)
			if err != nil {
				t.Errorf("seal %d: %v", i, err)
				return
			}
			if _, err := gwSess.Open(m); err != nil {
				t.Errorf("open %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestRoleString(t *testing.T) {
	if RoleInitiator.String() != "initiator" || RoleResponder.String() != "responder" {
		t.Fatal("role names are wrong")
	}
}
