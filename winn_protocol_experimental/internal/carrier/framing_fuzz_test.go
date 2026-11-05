package carrier

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// FuzzReadFrameStream reads a whole attacker-supplied byte stream as a
// sequence of length-prefixed H2 carrier frames, rather than the single frame
// the existing FuzzReadFrame target covers. Reading repeatedly is what exposes
// resynchronisation behaviour: after a rejected frame the reader's position is
// attacker-chosen, so this target pins down that every subsequent accepted
// frame still respects the buffer and MTU bounds and that the loop always makes
// forward progress.
func FuzzReadFrameStream(fuzzer *testing.F) {
	fuzzer.Add([]byte{0, 3, 'a', 'b', 'c', 0, 1, 'd'}, DefaultMaxDatagram)
	// An invalid length prefix followed by bytes that themselves look like a
	// valid frame: the shape of a resynchronisation attack.
	fuzzer.Add([]byte{0xff, 0xff, 0, 2, 'x', 'y'}, DefaultMaxDatagram)
	fuzzer.Add([]byte{0, 0, 0, 1, 'z'}, DefaultMaxDatagram)
	fuzzer.Add([]byte{}, DefaultMaxDatagram)

	fuzzer.Fuzz(func(t *testing.T, data []byte, maximum int) {
		if maximum < 1 || maximum > AbsoluteMaxDatagram {
			maximum = DefaultMaxDatagram
		}
		reader := bytes.NewReader(data)
		buffer := make([]byte, AbsoluteMaxDatagram)

		for range 64 {
			before := reader.Len()
			count, err := readFrameInto(reader, buffer, maximum)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					return
				}
				// A framing rejection must still have made forward progress,
				// otherwise a caller that retries would spin forever on the
				// same bytes.
				if reader.Len() == before {
					t.Fatalf("framing error made no forward progress at %d bytes remaining", before)
				}
				return
			}
			if count <= 0 {
				t.Fatalf("accepted a frame of length %d", count)
			}
			if count > maximum {
				t.Fatalf("accepted a %d byte frame over the %d byte limit", count, maximum)
			}
			if count > len(buffer) {
				t.Fatalf("accepted a %d byte frame into a %d byte buffer", count, len(buffer))
			}
			if reader.Len() >= before {
				t.Fatalf("a successful read consumed nothing: %d then %d", before, reader.Len())
			}
		}
	})
}

// TestReadFrameIntoDoesNotConsumeBodyOnInvalidLength pins the exact
// resynchronisation behaviour of the H2 frame reader.
//
// On an invalid length prefix readFrameInto returns an error having consumed
// only the two header bytes, leaving the stream positioned inside the body the
// peer declared. The reader therefore does NOT self-resynchronise: a caller
// that retries on the same reader will parse a length prefix from an
// attacker-chosen offset.
//
// This is currently safe only because every production caller latches:
// h2PacketConn.ReadFrom surfaces the error, envelopePacketConn.ReadFrom returns
// it rather than looping, and the relay loop in relay.go terminates the relay
// on a read error. This test exists so that a future caller which retries
// instead of latching fails here first. See the hardening report for the
// proposed defence-in-depth fix inside readFrameInto.
func TestReadFrameIntoDoesNotConsumeBodyOnInvalidLength(t *testing.T) {
	// Length prefix 0xffff exceeds the MTU, so the frame is rejected. The four
	// trailing bytes are a well-formed 2-byte frame that a resynchronising
	// reader would happily accept.
	stream := []byte{0xff, 0xff, 0x00, 0x02, 'x', 'y'}
	reader := bytes.NewReader(stream)
	buffer := make([]byte, AbsoluteMaxDatagram)

	if _, err := readFrameInto(reader, buffer, DefaultMaxDatagram); err == nil {
		t.Fatal("expected the oversized length prefix to be rejected")
	}
	if remaining := reader.Len(); remaining != len(stream)-2 {
		t.Fatalf("expected only the 2 header bytes to be consumed, %d of %d remain",
			remaining, len(stream))
	}

	// Demonstrate the consequence: a retry accepts a frame the peer positioned.
	count, err := readFrameInto(reader, buffer, DefaultMaxDatagram)
	if err != nil {
		t.Fatalf("retry after a framing error returned %v", err)
	}
	if count != 2 || string(buffer[:count]) != "xy" {
		t.Fatalf("retry produced %d bytes (%q); the reader resynchronised on peer-chosen data",
			count, buffer[:count])
	}
}

// TestReadFrameIntoRejectsZeroAndOversizeLengths locks the two length checks
// that keep an attacker-supplied 16-bit prefix from driving an allocation or an
// empty-frame loop.
func TestReadFrameIntoRejectsZeroAndOversizeLengths(t *testing.T) {
	buffer := make([]byte, AbsoluteMaxDatagram)
	for _, testCase := range []struct {
		name   string
		stream []byte
	}{
		{"zero length", []byte{0x00, 0x00, 'a'}},
		{"over MTU", []byte{0x05, 0xdd, 'a'}},
		{"maximum uint16", []byte{0xff, 0xff, 'a'}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := readFrameInto(
				bytes.NewReader(testCase.stream), buffer, DefaultMaxDatagram,
			)
			if err == nil {
				t.Fatal("expected the length prefix to be rejected")
			}
		})
	}
}

// TestDecodeEnvelopeRejectsTruncatedPayloadClaim locks the envelope length
// check. The 16-bit payload length is attacker-supplied and is used to slice
// the received buffer, so a claim larger than the datagram must be rejected
// rather than clamped.
func TestDecodeEnvelopeRejectsTruncatedPayloadClaim(t *testing.T) {
	encoded, err := encodeEnvelope(envelopeData, 1, []byte("abc"), envelopeHeaderSize+3)
	if err != nil {
		t.Fatal(err)
	}
	// Claim 300 payload bytes while supplying 3.
	encoded[6] = 0x01
	encoded[7] = 0x2c
	if _, err := decodeEnvelope(encoded, DefaultMaxDatagram); err == nil {
		t.Fatal("expected an over-long payload claim to be rejected")
	}
}
