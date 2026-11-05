package duplex

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// TestReaderAdversarialHeaders covers the duplex WNN3 header the existing
// TestReaderRejectsMalformedHeaders table does not: a truncated header (under-
// read), opcode 0, a uint32 length of 0xFFFFFFFF (the unbounded-allocation
// shape), an empty Create (structurally legal at this layer), and the failure
// latch. A panic or a 4 GiB make() here is a DoS on the host-engine channel.
func TestReaderAdversarialHeaders(t *testing.T) {
	cases := []struct {
		name   string
		stream []byte
		role   bool // acceptEngineToHost
		want   error
	}{
		{"opcode zero", frame(Magic, Version, Opcode(0), 0, 0), false, ErrInvalidFrame},
		{"uint32 max length on inbound", frame(Magic, Version, OpInbound, 0xFFFFFFFF, 0), false, ErrPayloadTooLarge},
		{"uint32 max length on create", frame(Magic, Version, OpCreate, 0xFFFFFFFF, 0), false, ErrPayloadTooLarge},
		{"length MaxPayload+1", frame(Magic, Version, OpInbound, MaxPayload+1, 0), false, ErrPayloadTooLarge},
		{"empty inbound", frame(Magic, Version, OpInbound, 0, 0), false, ErrInvalidFrame},
		{"empty outbound as host", frame(Magic, Version, OpOutbound, 0, 0), true, ErrInvalidFrame},
		{"create as host reader", frame(Magic, Version, OpCreate, 0, 0), true, ErrInvalidFrame},
		{"close-ack as engine reader", frame(Magic, Version, OpCloseAck, 0, 0), false, ErrInvalidFrame},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := NewReader(bytes.NewReader(tc.stream), tc.role).Read()
			if err == nil {
				t.Fatal("malformed header was accepted")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestReaderTruncatedHeaderIsNotCleanEOF is the under-read case. io.ReadFull
// on a short header returns ErrUnexpectedEOF; treating that as io.EOF would
// make a cut stream look like an orderly shutdown.
func TestReaderTruncatedHeaderIsNotCleanEOF(t *testing.T) {
	full := frame(Magic, Version, OpStatusRequest, 0, 0)
	for n := 1; n < HeaderSize; n++ {
		t.Run("header bytes "+itoa(n), func(t *testing.T) {
			_, _, err := NewReader(bytes.NewReader(full[:n]), false).Read()
			if err == nil {
				t.Fatal("a truncated header was accepted")
			}
			if errors.Is(err, io.EOF) {
				t.Fatal("truncated header was reported as clean EOF")
			}
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("error = %v, want wrapped io.ErrUnexpectedEOF", err)
			}
		})
	}
	_, _, err := NewReader(bytes.NewReader(nil), false).Read()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("empty stream = %v, want io.EOF", err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestReaderAcceptsEmptyCreate pins the frame-layer rule: Create is neither
// mustBeEmpty nor mustBeNonEmpty, so a zero-length payload is structurally
// valid here. decodeWinn3Create refuses the JSON later. Collapsing that
// distinction into a frame-layer rejection would break a host that sends
// "{}" as two bytes, which is a different case, but a zero-length Create
// must stay a decode error at the document layer, not a panic here.
func TestReaderAcceptsEmptyCreate(t *testing.T) {
	opcode, payload, err := NewReader(
		bytes.NewReader(frame(Magic, Version, OpCreate, 0, 0)), false,
	).Read()
	if err != nil {
		t.Fatalf("empty Create was rejected at the frame layer: %v", err)
	}
	if opcode != OpCreate || payload != nil {
		t.Fatalf("opcode=%s payload=%q", opcode, payload)
	}
}

// TestReaderFailureLatches pins that a second Read after a bad header does
// not walk onto the following bytes. TestReaderNeverResynchronises already
// covers the "good frame behind a bad one" shape; this one asserts the
// latched error is the SAME error, so a caller that ignores it cannot
// observe a later success.
func TestReaderFailureLatches(t *testing.T) {
	var stream bytes.Buffer
	stream.Write(frame(0xDEADBEEF, Version, OpInbound, 0, 0))
	good := &bytes.Buffer{}
	if err := NewWriter(good).Write(OpStatusRequest, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	stream.Write(good.Bytes())

	reader := NewReader(bytes.NewReader(stream.Bytes()), false)
	_, _, first := reader.Read()
	if !errors.Is(first, ErrInvalidFrame) {
		t.Fatalf("first = %v, want ErrInvalidFrame", first)
	}
	_, _, second := reader.Read()
	if second == nil {
		t.Fatal("second Read succeeded after a terminal error")
	}
	if !errors.Is(second, first) {
		t.Fatalf("latched error = %v, first = %v", second, first)
	}
}

// TestReaderDoesNotReadBodyWhenLengthIsIllegal is the allocation/DoS pin:
// a declared length of 0xFFFFFFFF must be rejected from the 16-byte header
// alone. The fixture has no body. If the decoder allocated or ReadFull'd
// before the MaxPayload check, this would hang or try to make a 4 GiB
// buffer. It must return ErrPayloadTooLarge from header bytes only.
func TestReaderDoesNotReadBodyWhenLengthIsIllegal(t *testing.T) {
	hdr := frame(Magic, Version, OpInbound, 0xFFFFFFFF, 0)
	if len(hdr) != HeaderSize {
		t.Fatalf("fixture is %d bytes, want header only", len(hdr))
	}
	_, _, err := NewReader(bytes.NewReader(hdr), false).Read()
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("error = %v, want ErrPayloadTooLarge (must not have waited for a body)", err)
	}
}

// TestWriterAndReaderAgreeOnLittleEndianLength is a silent-accept pin: a
// big-endian length of 1 with a little-endian decoder would read length
// 0x01000000 (16 MiB) and either reject as oversize or try to read 16 MiB.
func TestWriterAndReaderAgreeOnLittleEndianLength(t *testing.T) {
	var stream bytes.Buffer
	if err := NewWriter(&stream).Write(OpInbound, []byte{'A'}); err != nil {
		t.Fatal(err)
	}
	got := stream.Bytes()
	if binary.LittleEndian.Uint32(got[8:12]) != 1 {
		t.Fatalf("length field = %d, want 1 little-endian", binary.LittleEndian.Uint32(got[8:12]))
	}
	if binary.BigEndian.Uint32(got[8:12]) == 1 && binary.LittleEndian.Uint32(got[8:12]) != 1 {
		t.Fatal("length field is big-endian")
	}
	opcode, payload, err := NewReader(bytes.NewReader(got), false).Read()
	if err != nil || opcode != OpInbound || !bytes.Equal(payload, []byte{'A'}) {
		t.Fatalf("round-trip opcode=%s payload=%q err=%v", opcode, payload, err)
	}
}
