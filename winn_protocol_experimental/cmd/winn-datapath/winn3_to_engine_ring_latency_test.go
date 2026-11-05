package main

import (
	"testing"
	"time"
)

// With the default low-water mark, a packet already in the ring is drained at
// once: the reader never waits for more packets to arrive. The park is set to
// an hour so any wait at all fails the test rather than slowing it.
func TestToEngineRingDefaultDrainsSparsePacketsWithoutParking(t *testing.T) {
	t.Setenv("WINN3_DRAIN_LOW_WATER", "")
	for _, count := range []int{1, 3, 15} {
		ring := newToEngineRing(64)
		ring.maxPark = time.Hour
		packets := make([][]byte, count)
		for i := range packets {
			packets[i] = []byte{byte(i)}
		}
		if n, ok := ring.pushBatch(packets); !ok || n != count {
			t.Fatalf("push %d: n=%d ok=%v", count, n, ok)
		}
		done := make(chan int, 1)
		go func() {
			n, _ := ring.popBatch(make([][]byte, 64))
			done <- n
		}()
		select {
		case n := <-done:
			if n != count {
				t.Fatalf("drained %d of %d", n, count)
			}
		case <-time.After(2 * time.Second):
			ring.close()
			<-done
			t.Fatalf("%d queued packets waited for more to arrive", count)
		}
		if got := ring.Telemetry().WakePark; got != 0 {
			t.Fatalf("park fired %d times with packets ready", got)
		}
	}
}

// The A/B switch still restores the old gate.
func TestToEngineRingLowWaterOverrideStillParks(t *testing.T) {
	t.Setenv("WINN3_DRAIN_LOW_WATER", "16")
	ring := newToEngineRing(64)
	if ring.lowWater != 16 {
		t.Fatalf("override gave low water %d, want 16", ring.lowWater)
	}
	ring.maxPark = 20 * time.Millisecond
	if _, ok := ring.pushOne([]byte{1}); !ok {
		t.Fatal("push refused")
	}
	started := time.Now()
	if n, ok := ring.popBatch(make([][]byte, 8)); !ok || n != 1 {
		t.Fatalf("pop: n=%d ok=%v", n, ok)
	}
	if time.Since(started) < 10*time.Millisecond {
		t.Fatal("the override did not park a lone packet")
	}
}
