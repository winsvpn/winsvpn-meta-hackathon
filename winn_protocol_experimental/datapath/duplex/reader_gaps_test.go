package duplex

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// TestReaderGapsAdversarialHeaders covers the duplex cases
// TestReaderAdversarialHeaders and TestReaderRejectsMalformedHeaders leave
// unnamed: version 0, opcode 0xFFFF, empty Error / CreateAck (structurally
// legal), CloseAck with a declared payload, and a truncated body of length 1.
func TestReaderGapsAdversarialHeaders(t *testing.T) {
	cases := []struct {
		name   string
		stream []byte
		role   bool
		want   error
		accept bool
		opcode Opcode
	}{
		{"version 0", frame(Magic, 0, OpInbound, 1, 0), false, ErrInvalidFrame, false, 0},
		{"opcode 0xFFFF", frame(Magic, Version, Opcode(0xFFFF), 0, 0), false, ErrInvalidFrame, false, 0},
		{"close-ack with declared payload", frame(Magic, Version, OpCloseAck, 4, 0), true, ErrInvalidFrame, false, 0},
		{"status-request with declared payload", frame(Magic, Version, OpStatusRequest, 1, 0), false, ErrInvalidFrame, false, 0},
		{"empty error as host reader", frame(Magic, Version, OpError, 0, 0), true, nil, true, OpError},
		{"empty create-ack as host reader", frame(Magic, Version, OpCreateAck, 0, 0), true, nil, true, OpCreateAck},
		{"empty status-response as host reader", frame(Magic, Version, OpStatusResponse, 0, 0), true, nil, true, OpStatusResponse},
		{"truncated inbound body of 1 declared byte", frame(Magic, Version, OpInbound, 1, 0), false, io.ErrUnexpectedEOF, false, 0},
		{"inbound exact MaxPayload header with no body", frame(Magic, Version, OpInbound, MaxPayload, 0), false, io.ErrUnexpectedEOF, false, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("Read panicked: %v", rec)
				}
			}()
			opcode, payload, err := NewReader(bytes.NewReader(tc.stream), tc.role).Read()
			if tc.accept {
				if err != nil {
					t.Fatalf("accepted case returned %v", err)
				}
				if opcode != tc.opcode {
					t.Fatalf("opcode=%s, want %s", opcode, tc.opcode)
				}
				if payload != nil && len(payload) != 0 {
					t.Fatalf("empty opcode delivered %d bytes", len(payload))
				}
				return
			}
			if err == nil {
				t.Fatalf("malformed header was accepted (opcode=%s payload=%d)", opcode, len(payload))
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestReaderPayloadAliasesTheBuffer pins the documented alias. handleCreate
// copies the Create document before anything can block; a later change that
// stopped aliasing would be safe but must be deliberate.
func TestReaderPayloadAliasesTheBuffer(t *testing.T) {
	var stream bytes.Buffer
	if err := NewWriter(&stream).Write(OpInbound, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	reader := NewReader(bytes.NewReader(stream.Bytes()), false)
	_, payload, err := reader.Read()
	if err != nil || string(payload) != "abc" {
		t.Fatalf("read: %q %v", payload, err)
	}
	// Second read of a following frame overwrites the buffer. Write another.
	var second bytes.Buffer
	if err := NewWriter(&second).Write(OpInbound, []byte("XYZ")); err != nil {
		t.Fatal(err)
	}
	// Rebuild a stream of two frames so the second Read reuses the buffer.
	var both bytes.Buffer
	if err := NewWriter(&both).Write(OpInbound, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := NewWriter(&both).Write(OpInbound, []byte("XYZ")); err != nil {
		t.Fatal(err)
	}
	r := NewReader(bytes.NewReader(both.Bytes()), false)
	_, first, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	held := first
	_, _, err = r.Read()
	if err != nil {
		t.Fatal(err)
	}
	if string(held) == "abc" {
		// If the implementation copied, the pin is that aliasing stopped.
		// The comment on Read says it aliases; fail so the change is visible.
		t.Fatal("payload did not alias the internal buffer; Read's comment says it does")
	}
}

// TestWriterRefusesEmptyOutbound pins the encoder half of mustBeNonEmpty so
// a round-trip fuzzer cannot be the only thing keeping a zero-length
// datagram off the channel.
func TestWriterRefusesEmptyOutbound(t *testing.T) {
	if err := NewWriter(io.Discard).Write(OpOutbound, nil); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("empty outbound: %v, want ErrInvalidFrame", err)
	}
	if err := NewWriter(io.Discard).Write(OpCloseAck, []byte("x")); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("payload on close-ack: %v, want ErrInvalidFrame", err)
	}
}
