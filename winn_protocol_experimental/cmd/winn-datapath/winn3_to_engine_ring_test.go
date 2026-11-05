package main

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func TestToEngineRing_BasicPushPop(t *testing.T) {
	ring := newToEngineRing(16)
	p1 := []byte("packet1")
	p2 := []byte("packet2")

	acc, open := ring.pushOne(p1)
	if !acc || !open {
		t.Fatalf("pushOne failed: acc=%v open=%v", acc, open)
	}
	acc, open = ring.pushOne(p2)
	if !acc || !open {
		t.Fatalf("pushOne failed: acc=%v open=%v", acc, open)
	}

	if ring.depth() != 2 {
		t.Fatalf("depth = %d, want 2", ring.depth())
	}

	dst := make([][]byte, 4)
	n, ok := ring.popBatch(dst)
	if !ok || n != 2 {
		t.Fatalf("popBatch failed: ok=%v n=%d, want 2", ok, n)
	}
	if !bytes.Equal(dst[0], p1) || !bytes.Equal(dst[1], p2) {
		t.Fatalf("content mismatch: got %s, %s", dst[0], dst[1])
	}
	if ring.depth() != 0 {
		t.Fatalf("depth after pop = %d, want 0", ring.depth())
	}
}

func TestToEngineRing_BatchPushAndPopWrap(t *testing.T) {
	ring := newToEngineRing(16)

	// Fill 12 items
	pkts1 := make([][]byte, 12)
	for i := 0; i < 12; i++ {
		pkts1[i] = []byte{byte(i)}
	}
	n, open := ring.pushBatch(pkts1)
	if !open || n != 12 {
		t.Fatalf("pushBatch failed: open=%v n=%d, want 12", open, n)
	}

	// Drain 8 items (head advances to 8)
	dst := make([][]byte, 8)
	n, ok := ring.popBatch(dst)
	if !ok || n != 8 {
		t.Fatalf("popBatch failed: ok=%v n=%d, want 8", ok, n)
	}
	for i := 0; i < 8; i++ {
		if dst[i][0] != byte(i) {
			t.Fatalf("popBatch byte mismatch at %d: got %d", i, dst[i][0])
		}
	}

	// Push 10 more items (wraps around ring)
	pkts2 := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		pkts2[i] = []byte{byte(12 + i)}
	}
	n, open = ring.pushBatch(pkts2)
	if !open || n != 10 {
		t.Fatalf("pushBatch wrap failed: open=%v n=%d, want 10", open, n)
	}
	// count should now be 4 + 10 = 14
	if ring.depth() != 14 {
		t.Fatalf("depth = %d, want 14", ring.depth())
	}

	// Drain all 14 items across wrap boundary
	dstAll := make([][]byte, 16)
	n, ok = ring.popBatch(dstAll)
	if !ok || n != 14 {
		t.Fatalf("popBatch all failed: ok=%v n=%d, want 14", ok, n)
	}
	for i := 0; i < 14; i++ {
		want := byte(8 + i)
		if dstAll[i][0] != want {
			t.Fatalf("popBatch wrap verify failed at %d: got %d, want %d", i, dstAll[i][0], want)
		}
	}
}

func TestToEngineRing_TailDropOnCapacity(t *testing.T) {
	ring := newToEngineRing(8)
	pkts := make([][]byte, 12)
	for i := 0; i < 12; i++ {
		pkts[i] = []byte{byte(i)}
	}

	n, open := ring.pushBatch(pkts)
	if !open || n != 8 {
		t.Fatalf("pushBatch overflow: open=%v n=%d, want 8 (accepted cap)", open, n)
	}
	if ring.depth() != 8 {
		t.Fatalf("depth = %d, want 8", ring.depth())
	}

	// Verify head preserved (0 to 7)
	dst := make([][]byte, 8)
	n, ok := ring.popBatch(dst)
	if !ok || n != 8 {
		t.Fatalf("popBatch failed: ok=%v n=%d", ok, n)
	}
	for i := 0; i < 8; i++ {
		if dst[i][0] != byte(i) {
			t.Fatalf("head preserved check failed at %d: got %d, want %d", i, dst[i][0], i)
		}
	}
}

func TestToEngineRing_CloseGracefulDrain(t *testing.T) {
	ring := newToEngineRing(8)
	p := []byte("backlog")
	ring.pushOne(p)

	// Close the ring
	ring.close()

	// New pushes must fail
	acc, open := ring.pushOne([]byte("rejected"))
	if acc || open {
		t.Fatalf("push after close succeeded: acc=%v open=%v", acc, open)
	}

	// Backlog must still be drainable
	dst := make([][]byte, 4)
	n, ok := ring.popBatch(dst)
	if !ok || n != 1 {
		t.Fatalf("pop backlog failed: ok=%v n=%d, want 1", ok, n)
	}
	if !bytes.Equal(dst[0], p) {
		t.Fatalf("backlog payload mismatch")
	}

	// Next pop when empty must report closed (false)
	n, ok = ring.popBatch(dst)
	if ok || n != 0 {
		t.Fatalf("pop on empty closed ring returned ok=%v n=%d, want false/0", ok, n)
	}
}

func TestToEngineRing_ConcurrentProducerConsumer(t *testing.T) {
	const capacity = 256
	const totalPackets = 100000
	ring := newToEngineRing(capacity)

	var wg sync.WaitGroup
	wg.Add(2)

	// Producer
	go func() {
		defer wg.Done()
		batch := make([][]byte, 32)
		sent := 0
		for sent < totalPackets {
			k := len(batch)
			if sent+k > totalPackets {
				k = totalPackets - sent
			}
			for i := 0; i < k; i++ {
				batch[i] = []byte{byte((sent + i) & 0xff)}
			}
			n, open := ring.pushBatch(batch[:k])
			if !open {
				return
			}
			sent += n
			if n < k {
				time.Sleep(50 * time.Microsecond)
			}
		}
		ring.close()
	}()

	// Consumer
	received := 0
	go func() {
		defer wg.Done()
		dst := make([][]byte, 64)
		for {
			n, ok := ring.popBatch(dst)
			if !ok {
				break
			}
			received += n
		}
	}()

	wg.Wait()
	if received != totalPackets {
		t.Fatalf("received %d packets, want %d", received, totalPackets)
	}
}

func TestToEngineRing_DrainGatingAccumulation(t *testing.T) {
	ring := newToEngineRing(128)

	// Test 1: Single packet drain completes within maxPark + grace margin
	p1 := []byte("lone_packet")
	ring.pushOne(p1)

	dst := make([][]byte, 64)
	start := time.Now()
	n, ok := ring.popBatch(dst)
	elapsed := time.Since(start)

	if !ok || n != 1 {
		t.Fatalf("popBatch single packet failed: ok=%v n=%d, want 1", ok, n)
	}
	if !bytes.Equal(dst[0], p1) {
		t.Fatalf("popBatch single packet content mismatch")
	}
	// Max park is 250 µs; test that it doesn't hang indefinitely (e.g. < 50ms)
	if elapsed > 50*time.Millisecond {
		t.Fatalf("popBatch single packet took %v, want <= 50ms", elapsed)
	}

	// Test 2: Full lowWater burst (32 packets) pops immediately without parking
	pkts := make([][]byte, 32)
	for i := 0; i < 32; i++ {
		pkts[i] = []byte{byte(i)}
	}
	ring.pushBatch(pkts)

	start = time.Now()
	n, ok = ring.popBatch(dst)
	elapsed = time.Since(start)

	if !ok || n != 32 {
		t.Fatalf("popBatch lowWater burst failed: ok=%v n=%d, want 32", ok, n)
	}
	// Immediate pop should be well under 1ms
	if elapsed > 10*time.Millisecond {
		t.Fatalf("popBatch lowWater burst took %v, want <= 10ms", elapsed)
	}
}

