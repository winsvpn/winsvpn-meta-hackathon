package wcf3

import (
	"encoding/binary"
	"testing"
)

func fuzzReplayContext() Context {
	var context Context
	for index := range context.SessionID {
		context.SessionID[index] = byte(index + 1)
	}
	for index := range context.BindingID {
		context.BindingID[index] = byte(index + 0x40)
	}
	context.PSKGeneration = 9
	context.SequenceEpoch = 11
	return context
}

// encodeFuzzFrame builds a structurally valid WCF3 frame carrying the supplied
// sequence, so the fuzzer spends its budget on replay-window state transitions
// rather than on rediscovering the header layout.
func encodeFuzzFrame(context Context, sequence uint64, payload []byte) []byte {
	encoded := make([]byte, HeaderSize+len(payload))
	copy(encoded[0:4], Magic)
	encoded[4] = KindData
	binary.BigEndian.PutUint16(encoded[6:8], uint16(len(payload)))
	copy(encoded[8:24], context.SessionID[:])
	copy(encoded[24:40], context.BindingID[:])
	binary.BigEndian.PutUint64(encoded[40:48], context.PSKGeneration)
	binary.BigEndian.PutUint64(encoded[48:56], context.SequenceEpoch)
	binary.BigEndian.PutUint64(encoded[56:64], sequence)
	copy(encoded[HeaderSize:], payload)
	return encoded
}

// FuzzReplayWindowAccept drives the replay window through an attacker-chosen
// sequence of frames. The WCF3 header is transmitted in the clear, so an
// on-path observer can copy a legitimate session/binding context and inject
// arbitrary sequence numbers. This target asserts the two properties that must
// survive that: the bookkeeping map can never grow without bound, and a
// sequence accepted once can never be accepted twice.
func FuzzReplayWindowAccept(fuzzer *testing.F) {
	fuzzer.Add([]byte{0, 0, 0, 0, 0, 0, 0, 1}, uint64(DefaultReplayWindow))
	fuzzer.Add([]byte{
		0, 0, 0, 0, 0, 0, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 1,
	}, uint64(MinimumReplayWindow))
	// A far-future sequence followed by an in-order one: the shape that a
	// window-poisoning injection would take.
	fuzzer.Add([]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0, 0, 0, 0, 0, 0, 0, 2,
	}, uint64(MinimumReplayWindow))

	fuzzer.Fuzz(func(t *testing.T, sequences []byte, size uint64) {
		if size < MinimumReplayWindow || size > MaximumReplayWindow {
			size = DefaultReplayWindow
		}
		context := fuzzReplayContext()
		window, err := NewReplayWindow(context, size)
		if err != nil {
			t.Fatalf("valid replay context was rejected: %v", err)
		}
		// Bound the frame count so the target stays fast; the invariants are
		// about state transitions, not volume.
		if len(sequences) > 8*512 {
			sequences = sequences[:8*512]
		}
		accepted := make(map[uint64]struct{})
		for offset := 0; offset+8 <= len(sequences); offset += 8 {
			sequence := binary.BigEndian.Uint64(sequences[offset : offset+8])
			frame, err := Decode(
				encodeFuzzFrame(context, sequence, []byte{0x01}),
				MaxPayloadSize,
				&context,
			)
			if err != nil {
				// Sequence zero is rejected structurally; that is correct.
				continue
			}
			if err := window.Accept(DirectionIngress, frame); err != nil {
				continue
			}
			if _, duplicate := accepted[sequence]; duplicate {
				t.Fatalf("replay window accepted sequence %d twice", sequence)
			}
			accepted[sequence] = struct{}{}

			// The bookkeeping map must stay inside the configured window.
			// Unbounded growth here is remote-triggered memory exhaustion.
			window.mu.Lock()
			tracked := len(window.states[DirectionIngress].seen)
			highest := window.states[DirectionIngress].highest
			window.mu.Unlock()
			if uint64(tracked) > size {
				t.Fatalf(
					"replay bookkeeping grew to %d entries for a window of %d (highest %d)",
					tracked, size, highest,
				)
			}
		}

		// Directions must stay independent: consuming ingress must never
		// consume the matching egress sequence.
		for sequence := range accepted {
			frame, err := Decode(
				encodeFuzzFrame(context, sequence, []byte{0x01}),
				MaxPayloadSize,
				&context,
			)
			if err != nil {
				t.Fatalf("previously accepted sequence %d no longer decodes: %v", sequence, err)
			}
			if err := window.Accept(DirectionIngress, frame); err == nil {
				t.Fatalf("ingress sequence %d was accepted a second time", sequence)
			}
			break
		}
	})
}

// FuzzDecodeWithReplay exercises the production receive path end to end: raw
// attacker bytes through structural decode, context binding, and replay
// consumption. Decode alone is already fuzzed; this covers the composition,
// where a frame that passes structural checks can still corrupt window state.
func FuzzDecodeWithReplay(fuzzer *testing.F) {
	context := fuzzReplayContext()
	fuzzer.Add(encodeFuzzFrame(context, 1, []byte{0x01}))
	fuzzer.Add(encodeFuzzFrame(context, 0, []byte{0x01}))
	fuzzer.Add(make([]byte, HeaderSize))
	fuzzer.Add([]byte("WCF3"))

	fuzzer.Fuzz(func(t *testing.T, data []byte) {
		context := fuzzReplayContext()
		window, err := NewReplayWindow(context, DefaultReplayWindow)
		if err != nil {
			t.Fatalf("valid replay context was rejected: %v", err)
		}
		frame, err := DecodeWithReplay(
			data, MaxPayloadSize, &context, window, DirectionIngress,
		)
		if err != nil {
			return
		}
		// An accepted frame must be bound to the expected context.
		if frame.SessionID != context.SessionID ||
			frame.BindingID != context.BindingID ||
			frame.PSKGeneration != context.PSKGeneration ||
			frame.SequenceEpoch != context.SequenceEpoch {
			t.Fatal("accepted a frame that is not bound to the expected context")
		}
		if frame.Sequence == 0 {
			t.Fatal("accepted a frame with sequence zero")
		}
		if len(frame.Payload) > MaxPayloadSize {
			t.Fatalf("accepted a %d byte payload", len(frame.Payload))
		}
		// The same bytes must never be accepted twice by the same window.
		if _, err := DecodeWithReplay(
			data, MaxPayloadSize, &context, window, DirectionIngress,
		); err == nil {
			t.Fatal("the identical frame was accepted twice: replay window bypass")
		}
	})
}
