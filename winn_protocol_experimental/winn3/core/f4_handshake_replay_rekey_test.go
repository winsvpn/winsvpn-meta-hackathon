package core

// Lane F4: handshake replay + rekey fuzz/smoke.
//
// Three concerns, one file:
//
//  1. Replay rejection. A transcript the responder has already accepted must
//     come back as ErrReplay for as long as the admission tag itself still
//     verifies (the cache lifetime is coupled to the freshness span). An old
//     transcript whose freshness bucket is outside MaxSkew is refused as
//     ErrUnauthenticated, the same sentinel as a wrong key. SetAdmissionKeys
//     must not reopen the window the way rebuilding a Responder would.
//     Concurrent deliveries of one message must not crash. The
//     IsReplayedInitiation peek must agree with ReadInitiation.
//
//  2. Rekey. After the handshake both ends advance epochs in lockstep via
//     Session.Rekey and keep exchanging traffic in both directions; the
//     wrong-length secret is refused and the old epoch's tokens stop opening.
//
//  3. A fuzz target on the handshake parser that pins the replay invariant
//     while it mutates: any input ReadInitiation accepts must be refused as
//     ErrReplay on a second identical delivery. A mutation that is accepted
//     twice, or accepted once and not answered, is a finding.
//
// Helpers are namespaced f4* so sibling lanes in this package cannot collide.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

// f4Rand is a deterministic CSPRNG-shaped reader: SHA-256 in counter mode over
// a seed. It carries a mutex because the Responder is shared across the
// concurrent fuzz workers and reads its configured reader from every one.
type f4Rand struct {
	mu    sync.Mutex
	seed  string
	ctr   uint64
	block []byte
}

func (r *f4Rand) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for n < len(p) {
		if len(r.block) == 0 {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], r.ctr)
			r.ctr++
			h := sha256.New()
			h.Write([]byte(r.seed))
			h.Write(c[:])
			r.block = h.Sum(nil)
		}
		k := copy(p[n:], r.block)
		r.block = r.block[k:]
		n += k
	}
	return n, nil
}

var f4FixedNow = time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)

type f4Harness struct {
	client   *StaticKey
	gateway  *StaticKey
	clientCf Config
	gwCf     Config
	resp     *Responder
	now      time.Time
}

func (h *f4Harness) clock() time.Time { return h.now }

func f4NewHarness(tb testing.TB) *f4Harness {
	tb.Helper()
	client, err := GenerateStaticKeyFrom(&f4Rand{seed: "f4-client-static"})
	if err != nil {
		tb.Fatalf("f4 client static: %v", err)
	}
	gateway, err := GenerateStaticKeyFrom(&f4Rand{seed: "f4-gateway-static"})
	if err != nil {
		tb.Fatalf("f4 gateway static: %v", err)
	}
	admission := bytes.Repeat([]byte{0xA7}, 32)
	gwParams := GatewayParams{
		AdmissionKeys: [][]byte{admission},
		GatewayID:     []byte("gw-f4-1"),
		TagSize:       DefaultTagSize,
	}
	h := &f4Harness{client: client, gateway: gateway, now: f4FixedNow}
	h.clientCf = Config{
		Gateway: gwParams,
		Rand:    &f4Rand{seed: "f4-client-rand"},
		Now:     h.clock,
	}
	h.gwCf = Config{
		Gateway: gwParams,
		Rand:    &f4Rand{seed: "f4-gateway-rand"},
		Now:     h.clock,
	}
	resp, err := NewResponder(h.gwCf, gateway, func(pub []byte) error {
		if !bytes.Equal(pub, client.Public()) {
			return errors.New("unknown client")
		}
		return nil
	})
	if err != nil {
		tb.Fatalf("f4 responder: %v", err)
	}
	h.resp = resp
	return h
}

func (h *f4Harness) initiator(tb testing.TB) *Initiator {
	tb.Helper()
	gwPub, err := NewPublicKey(h.gateway.Public())
	if err != nil {
		tb.Fatalf("f4 gateway public: %v", err)
	}
	i, err := NewInitiator(h.clientCf, h.client, gwPub)
	if err != nil {
		tb.Fatalf("f4 initiator: %v", err)
	}
	return i
}

// f4Complete runs one full handshake and returns both sessions plus the raw
// initiation bytes, which are the reusable transcript for the replay tests.
func (h *f4Harness) complete(tb testing.TB) (*Session, *Session, []byte) {
	tb.Helper()
	ini := h.initiator(tb)
	msg1, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		tb.Fatalf("f4 write initiation: %v", err)
	}
	rh, err := h.resp.ReadInitiation(msg1)
	if err != nil {
		tb.Fatalf("f4 read initiation: %v", err)
	}
	msg2, gwSess, err := rh.WriteResponse(nil, PadAuto)
	if err != nil {
		tb.Fatalf("f4 write response: %v", err)
	}
	cliSess, _, err := ini.ReadResponse(msg2)
	if err != nil {
		tb.Fatalf("f4 read response: %v", err)
	}
	return cliSess, gwSess, msg1
}

// --- replay smoke -----------------------------------------------------------

// TestF4ReplayRejectsDuplicate pins the core anti-detector property: after a
// transcript is accepted once it is refused on every later delivery, and the
// IsReplayedInitiation peek agrees with the acceptance.
func TestF4ReplayRejectsDuplicate(t *testing.T) {
	h := f4NewHarness(t)
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}

	if h.resp.IsReplayedInitiation(msg) {
		t.Fatal("peek reported a replay before the message was ever accepted")
	}
	if _, err := h.resp.ReadInitiation(msg); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if !h.resp.IsReplayedInitiation(msg) {
		t.Fatal("peek did not report a replay after the message was accepted")
	}
	for i := 0; i < 3; i++ {
		if _, err := h.resp.ReadInitiation(msg); !errors.Is(err, ErrReplay) {
			t.Fatalf("delivery %d: expected ErrReplay, got %v", i+2, err)
		}
	}
}

// TestF4ReplayRejectsOldTranscript is the other half of "duplicate/old
// transcript refused". Duplicate bytes inside the freshness span are ErrReplay
// (the cache). Bytes whose bucket is outside MaxSkew never reach the cache:
// verifyAdmission returns ErrUnauthenticated, indistinguishable from a wrong
// key. There is no distinct ErrStale on the wire, by design (admission.go).
func TestF4ReplayRejectsOldTranscript(t *testing.T) {
	window, spread, err := (Freshness{}).resolve()
	if err != nil {
		t.Fatalf("default freshness: %v", err)
	}
	span := time.Duration(2*spread+1) * window

	t.Run("unseen-outside-skew", func(t *testing.T) {
		h := f4NewHarness(t)
		ini := h.initiator(t)
		msg, err := ini.WriteInitiation(nil, PadAuto)
		if err != nil {
			t.Fatal(err)
		}
		h.now = f4FixedNow.Add(10 * time.Minute)
		if _, err := h.resp.ReadInitiation(msg); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("old unseen transcript: expected ErrUnauthenticated, got %v", err)
		}
		if h.resp.IsReplayedInitiation(msg) {
			t.Fatal("peek reported a replay for a transcript that never authenticated")
		}
		// The responder is not poisoned: a fresh initiation at the new clock works.
		h.clientCf.Now = h.clock
		fresh := h.initiator(t)
		freshMsg, err := fresh.WriteInitiation(nil, PadAuto)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.resp.ReadInitiation(freshMsg); err != nil {
			t.Fatalf("fresh initiation at the advanced clock: %v", err)
		}
	})

	t.Run("accepted-at-earliest-then-duplicate-until-expiry", func(t *testing.T) {
		// Write at centre, accept at the earliest candidate bucket. The cache
		// lifetime equals the tag-acceptance span, so a duplicate is ErrReplay
		// until that instant and ErrUnauthenticated at it. Same coupling as
		// TestRotationDoesNotResetTheFreshnessCoupling, without a rotation.
		h := f4NewHarness(t)
		ini := h.initiator(t)
		msg, err := ini.WriteInitiation(nil, PadAuto)
		if err != nil {
			t.Fatal(err)
		}
		earliest := f4FixedNow.Add(-time.Duration(spread) * window)
		h.now = earliest
		if _, err := h.resp.ReadInitiation(msg); err != nil {
			t.Fatalf("first delivery at earliest bucket: %v", err)
		}
		h.now = earliest.Add(span - time.Nanosecond)
		if _, err := h.resp.ReadInitiation(msg); !errors.Is(err, ErrReplay) {
			t.Fatalf("duplicate still inside the freshness span: expected ErrReplay, got %v", err)
		}
		h.now = earliest.Add(span)
		if _, err := h.resp.ReadInitiation(msg); err == nil {
			t.Fatal("old transcript was accepted at the freshness expiry instant")
		} else if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("at expiry the admission tag must refuse, got %v", err)
		}
	})
}

// TestF4ReplaySurvivesAdmissionRotation: SetAdmissionKeys must swap the live
// key set WITHOUT discarding the replay cache. That is the whole point of the
// seam versus constructing a new Responder; rebuilding would re-open the
// freshness window and turn a captured packet into a clock. A transcript
// accepted before the rotation must therefore still be ErrReplay after it.
func TestF4ReplaySurvivesAdmissionRotation(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0x01}, 32)
	newKey := bytes.Repeat([]byte{0x02}, 32)

	h := f4NewHarness(t)
	h.gwCf.Gateway.AdmissionKeys = [][]byte{oldKey}
	h.clientCf.Gateway.AdmissionKeys = [][]byte{oldKey}

	var err error
	h.resp, err = NewResponder(h.gwCf, h.gateway, func(pub []byte) error {
		if !bytes.Equal(pub, h.client.Public()) {
			return errors.New("unknown client")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.resp.ReadInitiation(msg); err != nil {
		t.Fatalf("accept before rotation: %v", err)
	}

	// Rotate to {new, old}: overlap so a packet still sealed under the old key
	// passes admission and reaches the replay check.
	if err := h.resp.SetAdmissionKeys([][]byte{newKey, oldKey}); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if _, err := h.resp.ReadInitiation(msg); !errors.Is(err, ErrReplay) {
		t.Fatalf("old transcript after rotation: expected ErrReplay, got %v", err)
	}
	if h.resp.AdmissionKeyCount() != 2 {
		t.Fatalf("rotation did not install two keys, got %d", h.resp.AdmissionKeyCount())
	}
}

// TestF4ReplayConcurrentDuplicate exercises the handshake-replay race window:
// many copies of one message delivered together must never crash, race or
// produce any error other than a clean ErrReplay for the losers, and exactly
// one copy must be accepted. The early seen check remains a cheap screen; the
// authoritative check-and-consume happens atomically in remember after the
// message has proven itself.
func TestF4ReplayConcurrentDuplicate(t *testing.T) {
	h := f4NewHarness(t)
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}

	const n = 64
	start := make(chan struct{})
	results := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			runtime.Gosched()
			_, err := h.resp.ReadInitiation(msg)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, ErrReplay) {
			t.Fatalf("unexpected error from a concurrent delivery: %v", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("exactly one concurrent delivery must be accepted, got %d", accepted)
	}
}

// --- rekey smoke ------------------------------------------------------------

// TestF4RekeyBothDirections advances both ends of a completed handshake
// through an in-band rekey and checks traffic keeps flowing in both directions,
// the epoch advances on both sides, the old epoch's tokens no longer open, and
// a wrong-length secret is refused.
func TestF4RekeyBothDirections(t *testing.T) {
	h := f4NewHarness(t)
	cli, gw, _ := h.complete(t)

	epoch0 := cli.Epoch()
	if gw.Epoch() != epoch0 {
		t.Fatalf("epochs diverged at handshake: cli=%d gw=%d", epoch0, gw.Epoch())
	}

	secret := sha256.Sum256([]byte("f4 rekey secret"))

	// A message sealed under the pre-rekey epoch, captured before the ratchet.
	// After the rekey, installEpoch replaces the receive window and keys on the
	// peer, so this old-epoch token must no longer open.
	stale := sha256.Sum256([]byte("f4 stale epoch payload"))
	staleMsg, err := cli.Seal(stale[:], 0)
	if err != nil {
		t.Fatal(err)
	}

	if err := cli.Rekey(secret[:]); err != nil {
		t.Fatalf("client rekey: %v", err)
	}
	if err := gw.Rekey(secret[:]); err != nil {
		t.Fatalf("gateway rekey: %v", err)
	}
	if cli.Epoch() != epoch0+1 || gw.Epoch() != epoch0+1 {
		t.Fatalf("epochs did not advance together: cli=%d gw=%d", cli.Epoch(), gw.Epoch())
	}

	// The stale pre-rekey message must no longer open after the ratchet.
	// Session.Open reports a retired epoch the same way as a bad token:
	// ErrUnauthenticated. A distinct ErrReplay would be a probe oracle.
	if _, err := gw.Open(staleMsg); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("pre-rekey message after ratchet: expected ErrUnauthenticated, got %v", err)
	}

	// Fresh traffic in both directions through the new epoch.
	for _, dir := range []struct {
		name string
		from *Session
		to   *Session
	}{
		{"client to gateway", cli, gw},
		{"gateway to client", gw, cli},
	} {
		payload := []byte("f4 rekey " + dir.name)
		sealed, err := dir.from.Seal(payload, 0)
		if err != nil {
			t.Fatalf("%s seal after rekey: %v", dir.name, err)
		}
		got, err := dir.to.Open(sealed)
		if err != nil {
			t.Fatalf("%s open after rekey: %v", dir.name, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("%s payload mismatch after rekey", dir.name)
		}
	}

	// A rekey with the wrong secret size is refused before it can desync us.
	if err := cli.Rekey(make([]byte, 16)); !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig for a short rekey secret, got %v", err)
	}
	if err := cli.Rekey(nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig for a nil rekey secret, got %v", err)
	}
}

// --- handshake parser fuzz --------------------------------------------------

// FuzzF4HandshakeReplayReject drives the handshake parser while pinning the
// replay invariant: any input ReadInitiation accepts must be refused as
// ErrReplay on a second identical delivery, and must be answerable once.
//
// The Responder is shared across iterations, exactly as the gateway would be:
// it is documented safe for concurrent use, its reject path is the one
// unauthenticated bytes take, and no fuzzer mutant can pass the admission HMAC
// (it is keyed over the body), so the replay cache is never what decides an
// input on first delivery. On the seed itself the double delivery is the
// duplicate-refusal property.
func FuzzF4HandshakeReplayReject(f *testing.F) {
	h := f4NewHarness(f)
	ini := h.initiator(f)
	msg1, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(msg1)
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add(bytes.Repeat([]byte{0}, 64))
	f.Add(bytes.Repeat([]byte{0xFF}, 200))
	// Structural length bounds: tag-sized (admission never runs), ceiling, and
	// one past the ceiling. These are the parser's first two rejects.
	f.Add(bytes.Repeat([]byte{0xAA}, DefaultTagSize))
	f.Add(bytes.Repeat([]byte{0xBB}, MaxHandshakeMessage))
	f.Add(bytes.Repeat([]byte{0xCC}, MaxHandshakeMessage+1))
	trunc := append([]byte(nil), msg1[:len(msg1)/2]...)
	f.Add(trunc)
	oversized := append(append([]byte(nil), msg1...), 0x00)
	f.Add(oversized)
	flippedHead := append([]byte(nil), msg1...)
	flippedHead[0] ^= 0x01
	f.Add(flippedHead)
	flippedTail := append([]byte(nil), msg1...)
	flippedTail[len(flippedTail)-1] ^= 0x80
	f.Add(flippedTail)
	f.Fuzz(func(t *testing.T, msg []byte) {
		hs, err := h.resp.ReadInitiation(msg)
		if err != nil {
			return
		}
		// Accepted once: a second identical delivery must be refused.
		if _, again := h.resp.ReadInitiation(msg); !errors.Is(again, ErrReplay) {
			t.Fatalf("accepted initiation was not refused on replay: %v", again)
		}
		// And the accepted message must be usable exactly once.
		if _, _, err := hs.WriteResponse([]byte("f4"), PadAuto); err != nil {
			t.Fatalf("accepted initiation could not respond: %v", err)
		}
	})
}
