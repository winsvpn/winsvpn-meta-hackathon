package core

import (
	"testing"
	"time"
)

// Muse L06 F-6: resolve computes spread from the full bucket window while
// bucketIndex counts whole seconds, so a fractional window (1500 ms at 60 s
// skew: spread 40, effective bucket 1 s) verified against a span narrower
// than the configured MaxSkew. A fractional window is refused instead.
func TestFreshnessRefusesFractionalBucketWindow(t *testing.T) {
	if _, _, err := (Freshness{BucketWindow: 1500 * time.Millisecond, MaxSkew: time.Minute}).resolve(); err == nil {
		t.Fatal("fractional bucket window resolved; bucketIndex would narrow the acceptance span")
	}
	if _, _, err := (Freshness{BucketWindow: 2 * time.Second, MaxSkew: time.Minute}).resolve(); err != nil {
		t.Fatalf("whole-second bucket window refused: %v", err)
	}
	if _, _, err := (Freshness{}).resolve(); err != nil {
		t.Fatalf("default freshness refused: %v", err)
	}
}
