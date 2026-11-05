package main

import (
	"context"
	"testing"
	"time"
)

func TestFrameAwaitBoundsStalledOutputPumpDuringRecovery(t *testing.T) {
	done := make(chan struct{})
	start := time.Now()
	if winn3FrameAwait(context.Background(), done) {
		t.Fatal("an output pump that never exited was reported as retired")
	}
	if elapsed := time.Since(start); elapsed > winn3FrameCloseGrace+time.Second {
		t.Fatalf("stalled output pump took %v to reject, close grace is %v", elapsed, winn3FrameCloseGrace)
	}
}
