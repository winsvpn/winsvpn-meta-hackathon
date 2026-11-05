//go:build darwin && winn3_batch_test

package main

import "testing"

// The batch entry points on the same forced-publish boundary as the scalar
// ones in winn_datapath_winn3_recovery_v2_test.go.

func registerRecoveringTunnel(t *testing.T) (int64, *winn3Tunnel, *winn3Round) {
	t.Helper()
	tunnel, _, r2 := manualRecoveringTunnel(t)
	h := nextHandle.Add(1)
	winn3Mu.Lock()
	winn3Registry[h] = tunnel
	winn3Mu.Unlock()
	t.Cleanup(func() {
		winn3Mu.Lock()
		delete(winn3Registry, h)
		winn3Mu.Unlock()
	})
	return h, tunnel, r2
}

func TestABatchEnqueueOnARetiredDeviceIsAbsorbedAcrossAPublish(t *testing.T) {
	h, tunnel, r2 := registerRecoveringTunnel(t)
	publishAt(tunnel, r2)
	b := newNativeBatch(4, 64)
	defer b.free()
	for i := range 4 {
		b.setPacket(i, batchIP(4, byte(i)))
	}
	if n := b.enqueue(h, 4, 24); n != 4 {
		t.Fatalf("a batch write during recovery returned %d, want it absorbed (4)", n)
	}
	if tunnel.rounds.Load() != 2 {
		t.Fatal("the hook did not publish round two; the race was not forced")
	}
}

func TestABatchDequeueOnARetiredDeviceMovesToTheSuccessorAcrossAPublish(t *testing.T) {
	h, tunnel, r2 := registerRecoveringTunnel(t)
	publishAt(tunnel, r2)
	b := newNativeBatch(4, 2048)
	defer b.free()
	if n := b.dequeue(h, 4, 24, 200); n != errTimeout {
		t.Fatalf("a batch read across the publish returned %d, want the timeout code %d", n, errTimeout)
	}
	if tunnel.rounds.Load() != 2 {
		t.Fatal("the hook did not publish round two; the race was not forced")
	}
}
