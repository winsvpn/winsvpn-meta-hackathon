package core

import "testing"

// Every late message lands in the bucket of its displacement below the highest
// counter consumed, and the buckets sum to reordered.
func TestReorderDepthBucketsByDisplacement(t *testing.T) {
	// 4096, not 1024: a window tolerates displacements up to size/2 - 1, so
	// the last bucket (512 and up) needs a window wider than 1024.
	w := newCounterWindow(4096)
	for _, c := range []uint64{0, 1, 2, 10} {
		w.consumeKnown(c, nil)
	}
	w.consumeKnown(9, nil) // 10 - 9 = 1: bucket 0
	w.consumeKnown(8, nil) // 10 - 8 = 2: bucket 1
	w.consumeKnown(3, nil) // 10 - 3 = 7: bucket 2
	w.consumeKnown(500, nil)
	w.consumeKnown(11, nil) // 500 - 11 = 489: bucket 8
	w.consumeKnown(1000, nil)
	w.consumeKnown(488, nil) // 1000 - 488 = 512: the last bucket
	want := ReorderDepth{1, 1, 1, 0, 0, 0, 0, 0, 1, 1}
	if w.depth != want {
		t.Fatalf("depth %v, want %v", w.depth, want)
	}
	var sum uint64
	for _, n := range w.depth {
		sum += n
	}
	if sum != w.reordered || w.reordered != 5 {
		t.Fatalf("depth sums to %d, reordered is %d, want 5 and 5", sum, w.reordered)
	}
}

// The session keeps every epoch's depth, as RecvFlow keeps reordered.
func TestReorderDepthAddFolds(t *testing.T) {
	a := ReorderDepth{1, 2}
	a.Add(ReorderDepth{3, 0, 0, 0, 0, 0, 0, 0, 0, 4})
	if a != (ReorderDepth{4, 2, 0, 0, 0, 0, 0, 0, 0, 4}) {
		t.Fatalf("fold gave %v", a)
	}
}
