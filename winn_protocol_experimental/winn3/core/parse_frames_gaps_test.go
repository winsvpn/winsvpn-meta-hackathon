package core

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// TestParseFramesTypeZeroWinsOverOversizeLength pins check order.
//
// ParseFrames rejects type 0 before it looks at the length. A decoder that
// swapped those tests would report a length error for a reserved type whose
// length also overruns, which is a parsing differential: two implementations
// would disagree about WHY the message died, and a mixed-version fleet that
// logged the distinction would fingerprint itself.
func TestParseFramesTypeZeroWinsOverOversizeLength(t *testing.T) {
	in := rawTLV(0, 0xFFFF, []byte{1})
	got, err := ParseFrames(in)
	if err == nil {
		t.Fatalf("type 0 with an oversize length was accepted (%d frames)", len(got))
	}
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("error is %v, want ErrDecrypt", err)
	}
	// The type-0 check must fire FIRST. A decoder that only looked at length
	// would still return ErrDecrypt ("frame claims 65535 bytes..."), and a
	// test that only checked errors.Is(err, ErrDecrypt) would stay green.
	if !strings.Contains(err.Error(), "type 0") {
		t.Fatalf("error is %v, want the type-0 refusal (not a length error)", err)
	}
	if len(got) != 0 {
		t.Fatalf("error path delivered %d frame(s)", len(got))
	}
}

// TestParseFramesEveryDefinedTypeRoundTripsEmpty pins that the TLV codec
// does not special-case any defined type. handleFrames may refuse an empty
// PING or CLOSE; ParseFrames must not, or a mixed-version peer that emits
// an empty control frame would look like a decrypt failure.
func TestParseFramesEveryDefinedTypeRoundTripsEmpty(t *testing.T) {
	types := []FrameType{
		FrameData, FramePad, FramePing, FramePong,
		FramePQEK, FramePQCT, FrameRekeyInit, FrameRekeyAck, FrameClose,
	}
	var buf []byte
	for _, typ := range types {
		var err error
		buf, err = AppendFrame(buf, typ, nil)
		if err != nil {
			t.Fatalf("AppendFrame(%d, empty): %v", typ, err)
		}
	}
	got, err := ParseFrames(buf)
	if err != nil {
		t.Fatalf("defined-type empty stream was rejected: %v", err)
	}
	if len(got) != len(types) {
		t.Fatalf("parsed %d frames, want %d", len(got), len(types))
	}
	for i, typ := range types {
		if got[i].Type != typ {
			t.Fatalf("frame %d type %d, want %d", i, got[i].Type, typ)
		}
		if len(got[i].Value) != 0 {
			t.Fatalf("frame %d value is %d bytes, want empty", i, len(got[i].Value))
		}
	}
}

// TestParseFramesDoesNotPanicOnHostileHeaders is the DoS pin: a panic in
// ParseFrames is a session crash on post-AEAD plaintext. These inputs are
// the ones that would slice-panic if the length check were removed or
// written as an unchecked conversion.
func TestParseFramesDoesNotPanicOnHostileHeaders(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{1},
		{1, 0},
		{1, 0, 1},                         // header claiming 1 body byte, none present
		{0, 0xff, 0xff},                   // type 0, n=0xFFFF, no body
		{byte(FrameData), 0xff, 0xff},     // n=0xFFFF, no body
		{byte(FrameData), 0x00, 0x00, 1},  // empty data then a trailing byte
		append([]byte{byte(FramePad), 0, 0}, make([]byte, 2)...),
	}
	for i, in := range cases {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Errorf("case %d panicked: %v", i, rec)
				}
			}()
			_, _ = ParseFrames(in)
		}()
	}
}

// TestParseFramesLengthExactlyRemainingIsOneFrame is the other fencepost
// from TestParseFramesExactFillIsAccepted, for a two-frame stream whose
// second frame consumes the rest of the buffer with n=0.
func TestParseFramesLengthExactlyRemainingIsOneFrame(t *testing.T) {
	var hdr [frameHeaderSize]byte
	hdr[0] = byte(FramePad)
	binary.BigEndian.PutUint16(hdr[1:], 0)
	in := append(rawTLV(byte(FrameData), 2, []byte{'a', 'b'}), hdr[:]...)
	got, err := ParseFrames(in)
	if err != nil {
		t.Fatalf("exact-remaining second frame was rejected: %v", err)
	}
	if len(got) != 2 || got[0].Type != FrameData || got[1].Type != FramePad {
		t.Fatalf("parsed %+v", got)
	}
}
