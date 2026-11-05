package session

import (
	"bytes"
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

func TestBatchFrameStorageTracksObservedPlaintextAndReuses(t *testing.T) {
	p := stage5Pair(t)
	var previous *core.Frame
	largest, previousCapacity, replacements := 0, 0, 0
	for _, size := range []int{24, 27, 30, 60, 90, 180, 360, 720, 1200, 40, 1200} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		message := stage5Message(t, p.cli, core.FrameData, payload)
		input := stage5Input(message)
		n, err := p.gw.DeliverBatch(input)
		if err != nil || n != 1 || len(input[0].Packets) != 1 || !bytes.Equal(input[0].Packets[0], payload) {
			t.Fatalf("size %d: deliver n=%d err=%v packets=%d", size, n, err, len(input[0].Packets))
		}
		needed := (frameHeaderSize + size) / frameHeaderSize
		largest = max(largest, needed)
		frames := p.gw.batch.frames
		if cap(frames) < needed || cap(frames) > 2*largest {
			t.Fatalf("size %d: retained frame slots=%d outside observed bound [%d,%d]", size, cap(frames), needed, 2*largest)
		}
		storage := frames[:cap(frames)]
		current := &storage[0]
		if previousCapacity >= needed && current != previous {
			t.Fatalf("size %d replaced sufficient reusable storage", size)
		}
		if current != previous {
			replacements++
		}
		for i, frame := range storage {
			if frame.Type != 0 || frame.Value != nil {
				t.Fatalf("size %d: frame slot %d retains a decoded value", size, i)
			}
		}
		previous = current
		previousCapacity = cap(frames)
	}
	if replacements > 7 {
		t.Fatalf("gradual valid message growth caused %d storage allocations; want at most 7", replacements)
	}
}

func TestBatchFrameStorageCoversMultipleValidFrames(t *testing.T) {
	p := stage5Pair(t)
	var plain []byte
	var err error
	const count = 16
	for i := 0; i < count; i++ {
		plain, err = core.AppendFrame(plain, core.FrameData, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
	}
	message, err := p.cli.sess.Seal(plain, 0)
	if err != nil {
		t.Fatal(err)
	}
	input := stage5Input(message)
	n, err := p.gw.DeliverBatch(input)
	if err != nil || n != 1 || len(input[0].Packets) != count {
		t.Fatalf("deliver n=%d err=%v packets=%d", n, err, len(input[0].Packets))
	}
	for i, packet := range input[0].Packets {
		if !bytes.Equal(packet, []byte{byte(i)}) {
			t.Fatalf("packet %d has incorrect content", i)
		}
	}
	if cap(p.gw.batch.frames) != len(plain)/frameHeaderSize {
		t.Fatalf("frame capacity %d does not follow observed plaintext", cap(p.gw.batch.frames))
	}
}
