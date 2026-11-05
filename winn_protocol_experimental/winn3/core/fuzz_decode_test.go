package core

// Fuzz targets for the v3 handshake and transport-session DECODE paths.
//
// Added 2026-08-10 as lane bld_session_fuzz. Each Fuzz function runs its seed
// corpus as an ordinary test on every `go test` invocation. Interesting inputs
// the fuzzing engine discovers are flushed from the Go build cache into
// testdata/fuzz/ so the coverage corpus stays part of the suite rather than
// living only in the machine's cache.
//
// The rigs deliberately do NOT reuse the harness helpers in handshake_test.go:
// they are self-contained so a saved fuzz input reproduces in a fresh process,
// and so a sibling lane editing the other test file cannot silently change what
// these targets measure.
//
// Per-iteration cost is kept minimal on purpose — the box this ships on was
// measured at load average >200 with dozens of live lanes, and a fuzz target
// that rebuilds a full handshake every iteration runs at ~16 execs/sec there.
// Where state is safe to share (Responder is documented safe for concurrent
// use; Session.Open is mutex-guarded) one rig is built and shared; only the
// Initiator, whose ReadResponse is single-use, is rebuilt per call.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"
)

// fuzzRand is a deterministic CSPRNG-shaped reader: SHA-256 in counter mode over
// a seed. It carries a mutex for the same reason detReader in handshake_test.go
// does: a Responder outsources WriteResponse's random draws to its configured
// reader, and fuzz workers call into a shared rig concurrently.
type fuzzRand struct {
	mu    sync.Mutex
	seed  string
	ctr   uint64
	block []byte
}

func (r *fuzzRand) Read(p []byte) (int, error) {
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

var fuzzFixedNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

// fuzzRig is one matched initiator/responder pair with its handshake run once.
// Two rigs built from the same seeds are byte-identical, so an outer rig's seed
// bytes open in an inner rig built fresh for a fuzz iteration.
type fuzzRig struct {
	client   *StaticKey
	gateway  *StaticKey
	clientCf Config
	gwCf     Config
	resp     *Responder
	ini      *Initiator
	initMsg  []byte
	respMsg  []byte
	cliSess  *Session
	gwSess   *Session
}

func newFuzzRig(tb testing.TB) *fuzzRig {
	tb.Helper()
	client, err := GenerateStaticKeyFrom(&fuzzRand{seed: "fuzz-client-static"})
	if err != nil {
		tb.Fatalf("fuzz client static: %v", err)
	}
	gateway, err := GenerateStaticKeyFrom(&fuzzRand{seed: "fuzz-gateway-static"})
	if err != nil {
		tb.Fatalf("fuzz gateway static: %v", err)
	}

	admission := bytes.Repeat([]byte{0xA7}, 32)
	gwParams := GatewayParams{
		AdmissionKeys: [][]byte{admission},
		GatewayID:     []byte("gw-fuzz-1"),
		TagSize:       DefaultTagSize,
	}

	clientCf := Config{
		Gateway: gwParams,
		Rand:    &fuzzRand{seed: "fuzz-client-rand"},
		Now:     func() time.Time { return fuzzFixedNow },
	}
	gwCf := Config{
		Gateway: gwParams,
		Rand:    &fuzzRand{seed: "fuzz-gateway-rand"},
		Now:     func() time.Time { return fuzzFixedNow },
	}

	resp, err := NewResponder(gwCf, gateway, func(pub []byte) error {
		if !bytes.Equal(pub, client.Public()) {
			return errors.New("unknown client")
		}
		return nil
	})
	if err != nil {
		tb.Fatalf("fuzz responder: %v", err)
	}

	gwPub, err := NewPublicKey(gateway.Public())
	if err != nil {
		tb.Fatalf("fuzz gateway public: %v", err)
	}
	ini, err := NewInitiator(clientCf, client, gwPub)
	if err != nil {
		tb.Fatalf("fuzz initiator: %v", err)
	}

	initMsg, err := ini.WriteInitiation([]byte("fuzz client hint"), PadAuto)
	if err != nil {
		tb.Fatalf("fuzz initiation: %v", err)
	}
	rh, err := resp.ReadInitiation(initMsg)
	if err != nil {
		tb.Fatalf("fuzz read initiation: %v", err)
	}
	respMsg, gwSess, err := rh.WriteResponse([]byte("fuzz gateway hint"), PadAuto)
	if err != nil {
		tb.Fatalf("fuzz write response: %v", err)
	}
	cliSess, _, err := ini.ReadResponse(respMsg)
	if err != nil {
		tb.Fatalf("fuzz read response: %v", err)
	}

	return &fuzzRig{
		client:   client,
		gateway:  gateway,
		clientCf: clientCf,
		gwCf:     gwCf,
		resp:     resp,
		ini:      ini,
		initMsg:  initMsg,
		respMsg:  respMsg,
		cliSess:  cliSess,
		gwSess:   gwSess,
	}
}

// fuzzRigFreshInitiator returns a new single-use Initiator configured like the
// rig's. WriteInitiation has not been called on it yet.
//
// The name is namespaced to this file because the package test scope is shared
// across sibling lanes: a sibling's handshake_rotation_fresh_vector_test.go
// declares its own 7-arg freshInitiator, and two same-named helpers in one
// package fail to compile. Renaming here keeps the two rigs independent.
func fuzzRigFreshInitiator(tb testing.TB, rig *fuzzRig) *Initiator {
	tb.Helper()
	gwPub, err := NewPublicKey(rig.gateway.Public())
	if err != nil {
		tb.Fatalf("fuzz gateway public: %v", err)
	}
	ini, err := NewInitiator(rig.clientCf, rig.client, gwPub)
	if err != nil {
		tb.Fatalf("fuzz initiator: %v", err)
	}
	return ini
}

// --- handshake payload decode ----------------------------------------------

func FuzzDecodeHandshakePayload(f *testing.F) {
	wellFormed, err := encodeHandshakePayload(0, []byte("winn3-client-hint"), 16)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wellFormed)
	f.Add([]byte{})
	f.Add(make([]byte, handshakePayloadHeaderSize))
	f.Add([]byte{1, 0, 4, 'a', 'b', 'c'})
	// Length-overflow guards: flags=0 (valid) but the declared payload length
	// exceeds what the buffer can hold. These are what make the
	// `handshakePayloadHeaderSize+n > len(plain)` guard reachable; without them
	// the seed corpus only ever exercises the flags and happy paths.
	f.Add([]byte{0, 0xFF, 0xFF})
	f.Add([]byte{0, 0x01, 0x00})
	f.Add([]byte{0, 0x00, 0x04, 'a', 'b'})
	// A valid payload at the exact boundary of its header: flags(1) + length(2)
	// + a 3-byte payload fills the buffer with NO padding, so the
	// `handshakePayloadHeaderSize+n > len(plain)` guard is reached as a
	// strict-equal ACCEPT rather than only as the overflow reject the seeds
	// above target. This is a distinct decode corpus entry: it decodes to the
	// full "abc" and pins that the boundary is inclusive. The padded seeds
	// above all sit strictly inside the buffer, so none of them proves the
	// equality arm of the guard actually passes.
	boundary, err := encodeHandshakePayload(0, []byte("abc"), 0)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(boundary)

	// Length-ceiling seeds (added 2026-08-11, lane gen_winn3_core_fuzz).
	//
	// Every length-overflow seed above ({0,0xFF,0xFF}, {0,0x01,0x00},
	// {0,0x00,0x04,'a','b'}) is rejected by the BUFFER guard,
	// `handshakePayloadHeaderSize+n > len(plain)`, because the declared length
	// runs past the end of that particular slice. None of them reaches the
	// OTHER ceiling, `n > MaxHandshakePayload`, on its own — that branch needs
	// enough buffer to hold the declared length so only the 256-byte value
	// ceiling can reject it. The fuzzer cannot cheaply grow a 257-byte value in
	// place, so the ceiling guard was unreachable from mutation; these two
	// seeds pin it directly.
	//
	// exactCeiling: n == MaxHandshakePayload (256) with a full-length value and
	// padding beyond — the equality ACCEPT arm of `n > MaxHandshakePayload`.
	exactCeiling := make([]byte, 0, 3+MaxHandshakePayload+8)
	exactCeiling = append(exactCeiling, 0x00, 0x01, 0x00) // 256 big-endian
	exactCeiling = append(exactCeiling, bytes.Repeat([]byte{0x42}, MaxHandshakePayload)...)
	f.Add(exactCeiling)
	// ceilingOverflow: n == 257 with a buffer large enough to hold it, so it is
	// the LENGTH CEILING that rejects (n > MaxHandshakePayload), not the buffer.
	// Two flags threaded through the header must never let a 257-byte value
	// through: the length guard is over the declared length, independent of
	// whether the buffer happens to be big enough.
	ceilingOverflow := make([]byte, 0, 3+257+16)
	ceilingOverflow = append(ceilingOverflow, 0x00, 0x01, 0x01) // 257 big-endian
	ceilingOverflow = append(ceilingOverflow, bytes.Repeat([]byte{0x43}, 257)...)
	f.Add(ceilingOverflow)
	f.Fuzz(func(t *testing.T, plain []byte) {
		payload, _, err := decodeHandshakePayload(plain)
		if err != nil {
			return
		}
		if len(payload) > MaxHandshakePayload {
			t.Fatalf("decoded %d bytes, ceiling %d", len(payload), MaxHandshakePayload)
		}
	})
}

// --- handshake decode through a real responder ------------------------------
//
// The Responder is shared across iterations: it is documented safe for
// concurrent use, its reject path is the path unauthenticated bytes take, and
// no mutant in the corpus can pass admission (the HMAC is over the body) so the
// replay cache is not what decides any of these inputs.

func FuzzResponderReadInitiation(f *testing.F) {
	seedRig := newFuzzRig(f)
	f.Add(seedRig.initMsg)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0}, 64))
	f.Add(bytes.Repeat([]byte{0xFF}, 200))
	f.Fuzz(func(t *testing.T, msg []byte) {
		hs, err := seedRig.resp.ReadInitiation(msg)
		if err != nil {
			return
		}
		// A decoded handshake is also asked to build its response; that is the
		// other half of the decode path's downstream state.
		if _, _, writeErr := hs.WriteResponse([]byte("hint"), PadAuto); writeErr != nil {
			t.Fatalf("decoded handshake could not respond: %v", writeErr)
		}
	})
}

// --- handshake decode through a real initiator ------------------------------
//
// ReadResponse is single-use per Initiator, so a fresh one is built (and its
// initiation written) for every call. That is the minimum state the decode path
// requires and the most expensive part of this target.

func FuzzInitiatorReadResponse(f *testing.F) {
	seedRig := newFuzzRig(f)
	f.Add(seedRig.respMsg)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0}, 32))
	f.Fuzz(func(t *testing.T, msg []byte) {
		ini := fuzzRigFreshInitiator(t, seedRig)
		if _, err := ini.WriteInitiation(nil, PadAuto); err != nil {
			t.Fatalf("fuzz initiation: %v", err)
		}
		sess, _, err := ini.ReadResponse(msg)
		if err != nil {
			return
		}
		if sess.Role() != RoleInitiator {
			t.Fatalf("response opened a %s session, want initiator", sess.Role())
		}
	})
}

// --- transport session decode -----------------------------------------------
//
// The receive Session is shared: Open is mutex-guarded and the only inputs that
// can consume its window are exact valid messages, which are exactly the seeds.

func FuzzSessionOpen(f *testing.F) {
	seedRig := newFuzzRig(f)
	for i := 0; i < 3; i++ {
		sealed, err := seedRig.gwSess.Seal([]byte("inner ip packet"), 0)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(sealed)
	}
	// replay.go's distinct-nonce handling: a transport message is bound to a
	// SINGLE nonce (the demux token and the AEAD nonce both derive from the
	// counter), so a message at a distinct counter is a distinct nonce and is
	// accepted once, while a replayed copy of the same token must be refused.
	// Seed one distict nonce and then its exact replay: opening the first
	// consumes the token, and opening the duplicate is the case the replay
	// window has to reject.
	distinctOne, err := seedRig.gwSess.Seal([]byte("distinct nonce packet"), 0)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(distinctOne)
	f.Add(distinctOne)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0}, TransportOverhead()))
	f.Fuzz(func(t *testing.T, msg []byte) {
		if len(msg) > MaxTransportPayload+TransportOverhead() {
			return
		}
		plain, err := seedRig.cliSess.Open(msg)
		if err != nil {
			return
		}
		if len(plain) > MaxTransportPayload {
			t.Fatalf("opened %d bytes, ceiling %d", len(plain), MaxTransportPayload)
		}
	})
}

// --- frame stream decode ----------------------------------------------------

func FuzzParseFrames(f *testing.F) {
	var seed []byte
	var err error
	for _, fr := range []struct {
		t FrameType
		v []byte
	}{
		{FrameData, []byte("inner ip")},
		{FramePad, nil},
		{FramePing, bytes.Repeat([]byte{1}, 8)},
		{FrameClose, []byte{1}},
	} {
		seed, err = AppendFrame(seed, fr.t, fr.v)
		if err != nil {
			f.Fatal(err)
		}
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{1, 0, 0})
	f.Add([]byte{1, 0, 4, 'a'})
	// A valid first frame followed by a truncated second frame: the strict
	// decoder must reject the WHOLE message, not deliver the leading frame.
	// The single-frame seeds cannot reach that trailing-partial-frame loop.
	f.Add([]byte{1, 0, 4, 'a', 'b', 'c', 'd', 1, 0, 9, 'x', 'y'})
	// Maximum non-reserved frame type byte: 0xFF is a valid uint8 that is not
	// the reserved zero type, so it must parse, never be mistaken for reserved.
	f.Add([]byte{0xFF, 0x00, 0x00})
	// Well-formed type-0 headers: b[0]==0 with a declared length that FITS the
	// buffer. These are the only inputs that reach the reserved-type rejection
	// for its own sake — every earlier zero-leading seed ([]byte{0},
	// 72ee3882ead7384a's "\x0000") fails the header-size or length-overflow
	// check first, so a decoder that silently DROPPED the type-0 guard would
	// behave identically on them. A valid-length zero frame forces the guard:
	// if it is removed, the frame parses, and the round-trip re-encode trips
	// AppendFrame's own type-0 refusal.
	f.Add([]byte{0, 0, 0})
	f.Add([]byte{0, 0, 1, 'x'})
	f.Add([]byte{0, 0x01, 0x00, 'a', 'b'})
	f.Add([]byte{0, 0, 4, 'a', 'b', 'c', 'd'})

	// Extended seed corpus (added 2026-08-11, lane gen_winn3_fuzz_corpus).
	//
	// Every valid frame type in one stream, so the parse loop and the
	// round-trip re-encode are exercised across the whole type space in a
	// single input rather than one type at a time. The four-type seed above
	// stops at FrameClose; 5..9 (PQ rekey pairs and the ratchet) were not
	// reachable from a seed that round-trips.
	var allTypes []byte
	for _, t := range []FrameType{
		FrameData, FramePad, FramePing, FramePong,
		FramePQEK, FramePQCT, FrameRekeyInit, FrameRekeyAck, FrameClose,
	} {
		var err error
		allTypes, err = AppendFrame(allTypes, t, []byte{byte(t)})
		if err != nil {
			f.Fatal(err)
		}
	}
	f.Add(allTypes)

	// A multi-frame stream split at every byte boundary as its own seed: each
	// truncation cuts at a different offset into a header or a value, so the
	// three reject paths (short header, reserved type, length runs past the
	// buffer) are all reached without relying on the fuzzer mutating a full
	// stream into place. Round-trip holds only for the intact prefix, so the
	// seeds that re-encode are the ones that parse.
	multiFrame, err := AppendFrame(nil, FrameData, []byte("round trip"))
	if err != nil {
		f.Fatal(err)
	}
	multiFrame, err = AppendFrame(multiFrame, FramePing, []byte{1, 2, 3, 4})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(multiFrame)
	for cut := 1; cut < len(multiFrame); cut++ {
		f.Add(append([]byte(nil), multiFrame[:cut]...))
	}
	for cut := 1; cut <= len(multiFrame); cut++ {
		f.Add(append([]byte(nil), multiFrame[len(multiFrame)-cut:]...))
	}

	// Length-field ceiling: a 0xFFFF-byte value is the largest a length field
	// can express, and it must survive the parse/re-encode round-trip byte for
	// byte (the fuzzer cannot cheaply grow 64KiB in place, so this bound was
	// unreachable from mutation).
	ceiling, err := AppendFrame(nil, FrameData, bytes.Repeat([]byte{0x5A}, MaxFrameValue))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ceiling)
	f.Add(ceiling[:len(ceiling)-1])
	f.Add(ceiling[:frameHeaderSize])

	// Zero-length value on each type: an empty data/ping/close frame is legal
	// and must re-encode identically. Only FramePad already appears as an empty
	// value in the seeds above.
	for _, t := range []FrameType{
		FrameData, FramePing, FramePong, FrameClose,
	} {
		empty, err := AppendFrame(nil, t, nil)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(empty)
	}

	// Malformed-truncation seeds (added 2026-08-11, lane
	// gen_winn3_core_frame_fuzz).
	//
	// Two distinct ways a stream can be cut short, added so the strict decoder's
	// reject paths are pinned by fixed seeds rather than left to mutation:
	//
	// trailingHdr: a well-formed first frame followed by a 2-byte partial second
	// header. This reaches the loop's `len(b) < frameHeaderSize` trailing-header
	// reject AFTER a frame has already been accepted, which the single-partial
	// seeds (which fail on the very first header) cannot. A decoder that
	// stop-at-first-error (delivers the leading frame and ignores the dangling
	// bytes) would parse this, so the whole-stream strictness guard is the one
	// being pinned.
	trailingHdr := []byte{byte(FrameData), 0, 1, 'x', byte(FramePad), 0}
	f.Add(trailingHdr)

	// truncBody: a valid header whose declared length runs EXACTLY one byte past
	// the buffer end (type 1, length 3, only 2 value bytes present). This is the
	// boundary of the `frameHeaderSize+n > len(b)` overflow guard on a
	// non-reserved type, distinct from the earlier {1,0,4,'a'} seed whose length
	// falls three bytes short. Closing the fencepost (decode↔body-count) is the
	// property it pins.
	truncBody := []byte{byte(FrameData), 0, 3, 'a', 'b'}
	f.Add(truncBody)

	f.Fuzz(func(t *testing.T, b []byte) {
		frames, err := ParseFrames(b)
		if err != nil {
			return
		}
		// Round-trip property: the strict decoder's output re-encodes to
		// exactly the bytes it was given.
		var re []byte
		for _, fr := range frames {
			re, err = AppendFrame(re, fr.Type, fr.Value)
			if err != nil {
				t.Fatalf("decoded frame did not re-encode: %v", err)
			}
		}
		if !bytes.Equal(re, b) {
			t.Fatalf("round-trip mismatch: %x != %x", re, b)
		}
	})
}

// FuzzSessionDistinctNonces fuzzes the transport decode path for replay.go's
// distinct-nonce handling: every transport message is tied to a DISTINCT nonce
// (its demux token and its AEAD nonce both derive from the counter), and the
// tokenWindow therefore accepts each distinct nonce at most once and slides on
// consumption. The seeds below are a SPREAD of distinct valid messages at
// several counters, not just counter 0, so the fuzzer reaches the window's
// consume/slide decode path on genuinely accepted messages instead of only the
// reject path.
//
// The name deliberately does NOT begin with FuzzDecode: `go test -fuzz=FuzzDecode`
// is a regex and Go refuses to fuzz when the pattern matches more than one
// target (measured: it errors with "will not fuzz, -fuzz matches more than one
// fuzz test" and the whole run FAILS). FuzzDecodeHandshakePayload already owns
// that prefix, so this transport target carries a distinct name and is fuzzed
// on its own with `-fuzz=FuzzSessionDistinctNonces`.
//
// The receive Session is shared, for the same per-iteration cost reason the
// other transport targets state: Open is mutex-guarded and the only inputs that
// consume its window are exact valid messages.
//
// On a successful decode the plaintext must also satisfy the frame-decoder
// property its seeds were built from: a strict frame stream decodes to frames
// that re-encode to exactly the same bytes.
func FuzzSessionDistinctNonces(f *testing.F) {
	seedRig := newFuzzRig(f)
	for i := 0; i < 8; i++ {
		var pl []byte
		pl, err := AppendFrame(nil, FrameData, []byte{'a' + byte(i)})
		if err != nil {
			f.Fatal(err)
		}
		sealed, err := seedRig.gwSess.Seal(pl, 0)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(sealed)
	}
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0}, TransportOverhead()))
	// A length-overflow guard shaped like a valid token prefix: correct
	// nonce-length token, but the frame it would decode into a stream is
	// truncated. This is what makes the tok-known-but-AEAD-broken and the
	// truncated-message guards reachable from the transport decode path.
	f.Add(bytes.Repeat([]byte{0}, DemuxTokenSize+4))
	// A distinct nonce far ahead of the window's low edge: consuming it hits
	// replay.go's forceAdvance path (counter >= low+half retires the low edge
	// forward), so the window's consume/slide decode path is reached on a
	// genuinely-accepted displaced nonce rather than only on contiguous
	// counters. Without it the transport seeds stop at counter 7 and never
	// exercise the force-advance branch on a message that is actually accepted.
	for i := 0; i < DefaultTokenWindow; i++ {
		sealed, err := seedRig.gwSess.Seal([]byte("high-edge nonce packet"), 0)
		if err != nil {
			f.Fatal(err)
		}
		if i == DefaultTokenWindow-1 {
			f.Add(sealed)
		}
	}
	f.Fuzz(func(t *testing.T, msg []byte) {
		if len(msg) > MaxTransportPayload+TransportOverhead() {
			return
		}
		plain, err := seedRig.cliSess.Open(msg)
		if err != nil {
			return
		}
		if len(plain) > MaxTransportPayload {
			t.Fatalf("opened %d bytes, ceiling %d", len(plain), MaxTransportPayload)
		}
		frames, err := ParseFrames(plain)
		if err != nil {
			return
		}
		var re []byte
		for _, fr := range frames {
			re, err = AppendFrame(re, fr.Type, fr.Value)
			if err != nil {
				t.Fatalf("decoded frame did not re-encode: %v", err)
			}
		}
		if !bytes.Equal(re, plain) {
			t.Fatalf("round-trip mismatch: %x != %x", re, plain)
		}
	})
}

// TestDecodeHandshakePayloadFailClosedOnFlippedHeader pins the handshake
// payload decoder's fail-closed behaviour on a single-bit corruption in the
// header's flags byte (byte 0). Flags are reserved and must be zero; ANY bit
// set must reject the message with ErrDecrypt and never hand back a payload
// through a corrupted header.
//
// internal_test.go's TestDecodeHandshakePayloadRejects covers only the single
// hardcoded flag value 0x01. This sweep flips every one of the byte's eight
// bits individually, so stripping the `plain[0] != 0` guard from
// decodeHandshakePayload turns this test red regardless of which flag bit an
// attacker flips — a mutation the single 0x01 case cannot see (a 0x02-only
// guard would pass it).
func TestDecodeHandshakePayloadFailClosedOnFlippedHeader(t *testing.T) {
	valid := []byte{0x00, 0x00, 0x04, 'a', 'b', 'c', 'd'}
	out, _, err := decodeHandshakePayload(valid)
	if err != nil || string(out) != "abcd" {
		t.Fatalf("control: valid payload must decode, got (%q, %v)", out, err)
	}
	// New semantics (DUAL_SIGNATURE_SPEC): bit 0 (HandshakeFlagDualAuth) is a
	// defined capability flag and must DECODE, reporting the flag; every other
	// bit is unknown and must fail closed.
	dual := append([]byte(nil), valid...)
	dual[0] |= HandshakeFlagDualAuth
	got, flags, err := decodeHandshakePayload(dual)
	if err != nil || flags != HandshakeFlagDualAuth || string(got) != "abcd" {
		t.Fatalf("dual-auth flag must decode with flag set, got (%q, %#02x, %v)", got, flags, err)
	}
	for bit := uint(1); bit < 8; bit++ {
		flipped := append([]byte(nil), valid...)
		flipped[0] ^= 1 << bit
		if _, _, err := decodeHandshakePayload(flipped); !errors.Is(err, ErrDecrypt) {
			t.Errorf("flag bit %d flipped: decode returned (%v), want ErrDecrypt (fail closed)", bit, err)
		}
	}
}

// TestDecodeHandshakePayloadLengthCeiling pins the length-ceiling guard's two
// arms, the way the FuzzDecodeHandshakePayload seed corpus cannot by itself.
//
// The fuzz property only asserts on ACCEPTED inputs (`len(payload) <=
// MaxHandshakePayload`), so a mutation that widens the ceiling to `n >=
// MaxHandshakePayload` silently turns the n==256 ACCEPT arm into a reject and
// the fuzzer reports nothing — the reject path returns early with no assertion.
// This test asserts both arms explicitly: n == 256 must DECODE to exactly 256
// bytes (the equality-accept bound), and n == 257 with enough buffer to hold it
// must be refused by the LENGTH ceiling (not the buffer guard). Stripping the
// ceiling check, or widening it by one, turns this test red.
func TestDecodeHandshakePayloadLengthCeiling(t *testing.T) {
	exact := make([]byte, 0, 3+MaxHandshakePayload+8)
	exact = append(exact, 0x00, 0x01, 0x00)
	exact = append(exact, bytes.Repeat([]byte{0x42}, MaxHandshakePayload)...)
	out, _, err := decodeHandshakePayload(exact)
	if err != nil {
		t.Fatalf("n==MaxHandshakePayload must decode, got %v", err)
	}
	if len(out) != MaxHandshakePayload {
		t.Fatalf("decoded %d bytes, want exactly %d (equality-accept arm)", len(out), MaxHandshakePayload)
	}

	over := make([]byte, 0, 3+MaxHandshakePayload+16+8)
	over = append(over, 0x00, 0x01, 0x01) // 257 big-endian
	over = append(over, bytes.Repeat([]byte{0x43}, MaxHandshakePayload+1)...)
	if _, _, err := decodeHandshakePayload(over); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("n==MaxHandshakePayload+1 must be refused by the length ceiling, got %v (fail open)", err)
	}
}
