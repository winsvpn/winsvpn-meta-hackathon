package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// rawTLV is type(1) || length(2 BE) || value, with no AppendFrame checks.
// Hostile cases (type 0, a length that does not match the value) have to be
// built this way; AppendFrame refuses them.
func rawTLV(typ byte, n uint16, value []byte) []byte {
	var hdr [frameHeaderSize]byte
	hdr[0] = typ
	binary.BigEndian.PutUint16(hdr[1:], n)
	return append(hdr[:], value...)
}

func mustAppend(t *testing.T, dst []byte, typ FrameType, value []byte) []byte {
	t.Helper()
	out, err := AppendFrame(dst, typ, value)
	if err != nil {
		t.Fatalf("AppendFrame(%d, %d bytes): %v", typ, len(value), err)
	}
	return out
}

// TestParseFramesAdversarialInputs is the table the existing
// TestParseFramesIsStrict is not. That test checks only errors.Is(err,
// ErrDecrypt) and discards the returned slice, so a decoder that delivered
// the leading frames and then failed would still pass. A panic in this
// parser is a session DoS: it sits on the post-AEAD plaintext path
// (session.Driver.handleFrames).
func TestParseFramesAdversarialInputs(t *testing.T) {
	good := mustAppend(t, nil, FrameData, []byte("ok"))

	cases := []struct {
		name    string
		in      []byte
		accept  bool
		nFrames int
		types   []FrameType
	}{
		// --- accept (including "already correct" pins) ---
		{"empty nil", nil, true, 0, nil},
		{"empty slice", []byte{}, true, 0, nil},
		{"one empty pad", rawTLV(byte(FramePad), 0, nil), true, 1, []FrameType{FramePad}},
		{"one empty data", rawTLV(byte(FrameData), 0, nil), true, 1, []FrameType{FrameData}},
		{"one data byte, length exact", rawTLV(byte(FrameData), 1, []byte{'x'}), true, 1, []FrameType{FrameData}},
		{"two frames", mustAppend(t, good, FramePad, nil), true, 2, []FrameType{FrameData, FramePad}},
		{"unknown type 200", rawTLV(200, 5, []byte("later")), true, 1, []FrameType{200}},
		{"type 255 empty", rawTLV(255, 0, nil), true, 1, []FrameType{255}},
		{"empty ping", rawTLV(byte(FramePing), 0, nil), true, 1, []FrameType{FramePing}},
		{"empty close", rawTLV(byte(FrameClose), 0, nil), true, 1, []FrameType{FrameClose}},
		{"pad then data", mustAppend(t, mustAppend(t, nil, FramePad, nil), FrameData, []byte{1}), true, 2, []FrameType{FramePad, FrameData}},

		// --- reject, and the whole message is discarded ---
		{"one trailing byte", append(append([]byte(nil), good...), 0x01), false, 0, nil},
		{"two trailing bytes", append(append([]byte(nil), good...), 0x01, 0x02), false, 0, nil},
		{"type 0 empty value", rawTLV(0, 0, nil), false, 0, nil},
		{"type 0 with a fitting body", rawTLV(0, 1, []byte{'x'}), false, 0, nil},
		{"type 0 after a good frame", append(append([]byte(nil), good...), rawTLV(0, 0, nil)...), false, 0, nil},
		{"length past the buffer by 1", rawTLV(byte(FrameData), 3, []byte{'a', 'b'}), false, 0, nil},
		{"length 0xFFFF with one body byte", rawTLV(byte(FrameData), 0xFFFF, []byte{1}), false, 0, nil},
		{"header claiming n=1 with no body", rawTLV(byte(FrameData), 1, nil), false, 0, nil},
		{"good then oversize second", append(append([]byte(nil), good...), rawTLV(byte(FrameData), 0xFFFF, []byte{1})...), false, 0, nil},
		{"zero-filled 16 bytes", make([]byte, 16), false, 0, nil},
		{"single 0x00", []byte{0}, false, 0, nil},
		{"two 0x00", []byte{0, 0}, false, 0, nil},
		{"truncated second header after pad", append(rawTLV(byte(FramePad), 0, nil), byte(FrameData), 0), false, 0, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseFrames(tc.in)
			if tc.accept {
				if err != nil {
					t.Fatalf("accepted case returned %v", err)
				}
				if len(got) != tc.nFrames {
					t.Fatalf("parsed %d frames, want %d", len(got), tc.nFrames)
				}
				for i, want := range tc.types {
					if got[i].Type != want {
						t.Fatalf("frame %d type %d, want %d", i, got[i].Type, want)
					}
				}
				return
			}
			if err == nil {
				t.Fatalf("malformed input was accepted (%d frames)", len(got))
			}
			if !errors.Is(err, ErrDecrypt) {
				t.Fatalf("error is %v, want ErrDecrypt", err)
			}
			// THE property TestParseFramesIsStrict does not check: a failure
			// discards every frame, including any well-formed prefix.
			if len(got) != 0 {
				t.Fatalf("error path delivered %d frame(s); the whole message must be discarded", len(got))
			}
		})
	}
}

// TestParseFramesExactFillIsAccepted pins the fencepost on
// `frameHeaderSize+n > len(b)`. Changing that to `>=` would reject a
// well-formed frame whose value runs to the last byte.
func TestParseFramesExactFillIsAccepted(t *testing.T) {
	in := rawTLV(byte(FrameData), 4, []byte("abcd"))
	if len(in) != frameHeaderSize+4 {
		t.Fatalf("fixture is %d bytes, want %d", len(in), frameHeaderSize+4)
	}
	got, err := ParseFrames(in)
	if err != nil {
		t.Fatalf("exact-fill frame was rejected: %v", err)
	}
	if len(got) != 1 || string(got[0].Value) != "abcd" {
		t.Fatalf("parsed %+v", got)
	}
}

// TestParseFramesMaxLengthValueRoundTrips pins the 16-bit length ceiling.
// n is a uint16 so frameHeaderSize+n cannot overflow an int on this
// architecture; the risk is a decoder that treats 0xFFFF as "too big" or
// that slices past the buffer.
func TestParseFramesMaxLengthValueRoundTrips(t *testing.T) {
	value := bytes.Repeat([]byte{0x5A}, MaxFrameValue)
	in := mustAppend(t, nil, FrameData, value)
	got, err := ParseFrames(in)
	if err != nil {
		t.Fatalf("max-length value was rejected: %v", err)
	}
	if len(got) != 1 || !bytes.Equal(got[0].Value, value) {
		t.Fatalf("max-length round-trip failed: %d frames, value len %d", len(got), len(got[0].Value))
	}
}

// TestParseFramesValueAliasesTheBuffer pins the documented alias. handleFrames
// copies FrameData before keeping it; a later change that stopped aliasing
// would be safe but must be deliberate.
func TestParseFramesValueAliasesTheBuffer(t *testing.T) {
	in := rawTLV(byte(FrameData), 3, []byte("abc"))
	got, err := ParseFrames(in)
	if err != nil || len(got) != 1 {
		t.Fatalf("parse: %v frames=%d", err, len(got))
	}
	in[frameHeaderSize] = 'Z'
	if got[0].Value[0] != 'Z' {
		t.Fatal("Value did not alias the input; the Frame comment says it does")
	}
}

// TestParseFramesManyEmptyPadsStayLinear is the allocation bound: each frame
// costs a 3-byte header, so a stream of empty pads cannot allocate unbounded
// relative to the input. A panic here is a DoS on a valid (if noisy) message.
func TestParseFramesManyEmptyPadsStayLinear(t *testing.T) {
	const n = 200
	var buf []byte
	for i := 0; i < n; i++ {
		buf = mustAppend(t, buf, FramePad, nil)
	}
	got, err := ParseFrames(buf)
	if err != nil {
		t.Fatalf("empty-pad stream was rejected: %v", err)
	}
	if len(got) != n {
		t.Fatalf("parsed %d frames, want %d", len(got), n)
	}
	if len(buf) != n*frameHeaderSize {
		t.Fatalf("encoded size %d, want %d", len(buf), n*frameHeaderSize)
	}
}

// TestAppendFrameStillRefusesTypeZeroAndOversize is the encoder half of the
// same contract, so a round-trip fuzzer cannot be the only thing keeping
// type 0 off the wire.
func TestAppendFrameStillRefusesTypeZeroAndOversize(t *testing.T) {
	if _, err := AppendFrame(nil, 0, []byte("x")); !errors.Is(err, ErrConfig) {
		t.Fatalf("type 0: %v, want ErrConfig", err)
	}
	if _, err := AppendFrame(nil, FrameData, make([]byte, MaxFrameValue+1)); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversize: %v, want ErrPayloadTooLarge", err)
	}
}
