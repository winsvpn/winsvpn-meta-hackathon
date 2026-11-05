package main

import (
	"os"
	"strings"
	"testing"
)

// The receive-order counters and the live send queue depth reach the frame
// status document when they moved, round-trip through the host-side parser,
// and stay out of a document where they are zero (the frame census
// convention: the perf line reads an absent key in a fresh document as zero).
func TestOuterFlowAndSendQueueDepthArePublishedOnlyWhenNonzero(t *testing.T) {
	raw, err := winn3EncodeStatus(winn3Status{
		Event:          "posture",
		OuterReordered: 3,
		OuterLost:      5,
		SendQueueDepth: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{`"outer_reordered":3`, `"outer_lost":5`, `"send_queue_depth":7`} {
		if !strings.Contains(string(raw), member) {
			t.Fatalf("status %s does not carry %s", raw, member)
		}
	}
	back, err := decodeWinn3Status(raw)
	if err != nil {
		t.Fatalf("host-side parser refused the document: %v", err)
	}
	if back.OuterReordered != 3 || back.OuterLost != 5 || back.SendQueueDepth != 7 {
		t.Fatalf("decoded %d, %d, %d; want 3, 5, 7", back.OuterReordered, back.OuterLost, back.SendQueueDepth)
	}
	raw, err = winn3EncodeStatus(winn3Status{Event: "posture"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"outer_reordered", "outer_lost", "send_queue_depth"} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("status %s carries %s at zero", raw, key)
		}
	}

	src, err := os.ReadFile("winn3_frame.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, copied := range []string{
		"status.OuterReordered = stats.OuterReordered",
		"status.OuterLost = stats.OuterLost",
		"status.SendQueueDepth = stats.DataQueueDepth",
	} {
		if !strings.Contains(string(src), copied) {
			t.Fatalf("the frame server no longer copies %q from Loop.Stats; the key would never appear", copied)
		}
	}
}
