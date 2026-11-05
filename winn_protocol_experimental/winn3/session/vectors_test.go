package session

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// Known-answer vectors for everything this package puts on the wire.
//
// The transport envelope's vectors live in the core's vectors_test.go; what this
// package owns is the frame stream INSIDE the AEAD, the chunk framing of the
// post-quantum blobs, and the schedules that decide when a message is emitted.
// All of those are wire-visible in the sense that matters: a change to any of
// them changes what an observer sees, either as bytes or as timing.
//
// The same caveat the core states applies here and is worth repeating rather
// than assuming a reader will go and find it: these vectors were produced by this
// implementation. Until a second implementation regenerates them they catch
// drift and nothing more.

// TestFrameHeaderSizeMatchesCore proves this package's copy of the core's
// unexported TLV header size is right.
//
// A silently wrong constant here would break nothing visibly. It would just put
// every message a few bytes off its padding target, which no functional test
// would notice and which is exactly a length-shaping bug.
func TestFrameHeaderSizeMatchesCore(t *testing.T) {
	empty, err := core.AppendFrame(nil, core.FramePad, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != frameHeaderSize {
		t.Fatalf("core encodes an empty frame in %d bytes, this package assumes %d", len(empty), frameHeaderSize)
	}
	withValue, err := core.AppendFrame(nil, core.FrameData, []byte("1234567"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(withValue) - 7; got != frameHeaderSize {
		t.Fatalf("core's frame overhead is %d bytes, this package assumes %d", got, frameHeaderSize)
	}
}

// TestFrameStreamVector pins the exact bytes of a frame stream containing one of
// every frame this driver emits.
//
// It is the drift detector for the frame layer: a changed type number, a changed
// length endianness, a reordered chunk offset or an accidental extra byte all
// show up here as a diff, and any of them would be a silent interoperability
// break between a client and a gateway on different builds.
func TestFrameStreamVector(t *testing.T) {
	token := [pingTokenSize]byte{0, 1, 2, 3, 4, 5, 6, 7}
	rekeyPub := make([]byte, 32)
	for i := range rekeyPub {
		rekeyPub[i] = 0xaa
	}
	ackPub := make([]byte, 32)
	for i := range ackPub {
		ackPub[i] = 0xbb
	}

	frames := []pendingFrame{
		{typ: core.FrameData, value: []byte("winn3")},
		padFrame(),
		pingFrame(token, false),
		pongFrame(token[:], false),
		chunkBlob(core.FramePQEK, []byte("abc"), 5)[0],
		chunkBlob(core.FramePQCT, []byte("z"), 64)[0],
		{typ: core.FrameRekeyInit, value: rekeyPub},
		{typ: core.FrameRekeyAck, value: ackPub},
		closeFrame(CloseDesynchronised),
	}

	var stream []byte
	for _, f := range frames {
		var err error
		stream, err = core.AppendFrame(stream, f.typ, f.value)
		if err != nil {
			t.Fatal(err)
		}
	}

	want := "010005" + "77696e6e33" + // DATA "winn3"
		"020000" + // PAD, empty
		"030008" + "0001020304050607" + // PING
		"040008" + "0001020304050607" + // PONG, echoing the token verbatim
		"050005" + "0000" + "616263" + // PQ_EK chunk, offset 0, "abc"
		"060003" + "0000" + "7a" + // PQ_CT chunk, offset 0, "z"
		"070020" + strings.Repeat("aa", 32) + // REKEY_INIT ephemeral
		"080020" + strings.Repeat("bb", 32) + // REKEY_ACK ephemeral
		"090001" + "02" // CLOSE(CloseDesynchronised)

	if got := hex.EncodeToString(stream); got != want {
		t.Errorf("frame stream vector drifted\n got %s\nwant %s", got, want)
	}

	// The stream must round trip through the core's strict parser unchanged.
	parsed, err := core.ParseFrames(stream)
	if err != nil {
		t.Fatalf("the pinned stream does not parse: %v", err)
	}
	if len(parsed) != len(frames) {
		t.Fatalf("parsed %d frames, encoded %d", len(parsed), len(frames))
	}
	for i, f := range parsed {
		if f.Type != frames[i].Type() {
			t.Errorf("frame %d parsed as type %d, encoded as %d", i, f.Type, frames[i].typ)
		}
	}
}

// Type is a tiny accessor so the vector test can compare without reaching into
// the struct twice.
func (p pendingFrame) Type() core.FrameType { return p.typ }

// TestChunkFramingVector pins how a blob larger than one message is split.
//
// Equal-sized chunks with an explicit offset, not greedy packing and not
// arrival-order concatenation. The offset is what makes reassembly reorder-safe,
// and the transport tolerates reorder by design, so this is load bearing rather
// than defensive.
func TestChunkFramingVector(t *testing.T) {
	blob := make([]byte, 10)
	for i := range blob {
		blob[i] = byte('A' + i)
	}
	chunks := chunkBlob(core.FramePQEK, blob, 6) // 2 offset bytes + 4 payload
	if len(chunks) != 3 {
		t.Fatalf("split a 10-byte blob into %d chunks with a 4-byte payload budget, want 3", len(chunks))
	}
	want := []string{
		"0000" + "41424344",
		"0004" + "45464748",
		"0008" + "494a",
	}
	for i, c := range chunks {
		if c.typ != core.FramePQEK {
			t.Errorf("chunk %d has type %d", i, c.typ)
		}
		if got := hex.EncodeToString(c.value); got != want[i] {
			t.Errorf("chunk %d is %s, want %s", i, got, want[i])
		}
	}

	// A blob that fits exactly must not produce a trailing empty chunk.
	exact := chunkBlob(core.FramePQCT, blob, chunkOffsetSize+len(blob))
	if len(exact) != 1 {
		t.Errorf("an exactly-fitting blob produced %d chunks", len(exact))
	}

	// Real sizes: the default carrier moves an ML-KEM-768 encapsulation key in
	// one message, which is the whole reason the handshake stays small.
	cfg := Config{MaxMessageSize: DefaultMaxMessageSize}
	budget := cfg.MaxMessageSize - core.TransportOverhead() - frameHeaderSize
	if n := len(chunkBlob(core.FramePQEK, make([]byte, core.PQEncapsulationKeySize), budget)); n != 1 {
		t.Errorf("a %d-byte encapsulation key needs %d chunks at the default MTU, want 1", core.PQEncapsulationKeySize, n)
	}
	if n := len(chunkBlob(core.FramePQCT, make([]byte, core.PQCiphertextSize), budget)); n != 1 {
		t.Errorf("a %d-byte ciphertext needs %d chunks at the default MTU, want 1", core.PQCiphertextSize, n)
	}
}

// TestScheduleVectors pins the timing draws against a fixed entropy stream.
//
// These numbers are the F2 defence made concrete. If a refactor changes the
// sampler — a different inverse CDF, a clamp reintroduced, a different number of
// bytes consumed per draw — the distribution tests in jitter_test.go might still
// pass while the actual schedule changed. This catches that.
func TestScheduleVectors(t *testing.T) {
	r := newDetRand("winn3 session vectors v1")
	d := Draw{Min: 5 * time.Second, Mean: 15 * time.Second, Max: 45 * time.Second}
	wantExp := []time.Duration{
		7129418534, 7986732470, 20336783174, 16026508895,
		9932995903, 38311446036, 26921150975, 31331096610,
	}
	for i, want := range wantExp {
		got, err := drawTruncExp(r, d)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("silence draw %d is %d (%s), want %d (%s)", i, int64(got), got, int64(want), want)
		}
	}

	r2 := newDetRand("winn3 session backoff v1")
	ret := Retry{Base: 500 * time.Millisecond, Cap: 8 * time.Second, Attempts: 5}
	wantBackoff := []time.Duration{
		106454682, 663889682, 1227612651, 2573516409, 7494530952, 3092991732,
	}
	for attempt, want := range wantBackoff {
		got, err := drawBackoff(r2, ret, attempt)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("backoff attempt %d is %d (%s), want %d (%s)", attempt, int64(got), got, int64(want), want)
		}
	}

	r3 := newDetRand("winn3 session intn v1")
	wantIntn := []int{86, 62, 0, 95, 84, 0, 41, 71}
	for i, want := range wantIntn {
		got, err := drawIntn(r3, 100)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("drawIntn %d is %d, want %d", i, got, want)
		}
	}
}

// TestCloseReasonWireValues pins the one-byte reason codes. They travel inside
// the AEAD, so they disclose nothing to an observer, but a client and a gateway
// on different builds must agree on them or a desynchronisation teardown reads
// as an orderly shutdown and the peer never re-handshakes.
func TestCloseReasonWireValues(t *testing.T) {
	want := map[CloseReason]byte{
		CloseNormal:           1,
		CloseDesynchronised:   2,
		CloseRekeyFailed:      3,
		ClosePQFailed:         4,
		CloseCounterExhausted: 5,
		CloseProtocolError:    6,
		CloseRekeyUnconfirmed: 8,
	}
	for reason, code := range want {
		if byte(reason) != code {
			t.Errorf("%s encodes as %d, want %d", reason, byte(reason), code)
		}
		f := closeFrame(reason)
		if len(f.value) != 1 || f.value[0] != code {
			t.Errorf("close frame for %s is %v", reason, f.value)
		}
		if reason.String() == "unknown" {
			t.Errorf("reason %d has no name", code)
		}
	}
	if CloseNormal.NeedsNewSession() {
		t.Error("an orderly close should not demand a new session")
	}
	for reason := range want {
		if reason != CloseNormal && !reason.NeedsNewSession() {
			t.Errorf("%s should demand a new session", reason)
		}
	}
	if CloseReason(0).String() != "unknown" || CloseReason(200).String() != "unknown" {
		t.Error("unnamed reasons should render as unknown")
	}
}
