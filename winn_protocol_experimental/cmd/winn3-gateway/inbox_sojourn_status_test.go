package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
)

// TUNNEL-SPEED-2 Turn 13: the status document carries the inbox sojourn
// beside pipe_inbox_high_water, so a depth arm reads the delay the inbox
// itself adds instead of a loaded ping that also carries the radio and the
// phone's queues. Both keys are published at zero like their neighbours.
func TestInboxSojournKeysReachTheWireAndSurviveZero(t *testing.T) {
	var hist [carrier.InboxSojournBuckets]uint64
	hist[0], hist[5], hist[carrier.InboxSojournBuckets-1] = 7, 3, 1
	encoded, err := json.Marshal(serveStatus{
		Event:                 "posture",
		PipeInboxHighWater:    3463,
		PipeInboxSojourn:      hist,
		PipeInboxSojournMaxUS: 81920,
	})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	got, ok := back["pipe_inbox_sojourn"].([]any)
	if !ok || len(got) != carrier.InboxSojournBuckets {
		t.Fatalf("pipe_inbox_sojourn must be a %d-bucket array: %s", carrier.InboxSojournBuckets, encoded)
	}
	for i, v := range got {
		if v.(float64) != float64(hist[i]) {
			t.Fatalf("pipe_inbox_sojourn[%d] = %v, want %d: %s", i, v, hist[i], encoded)
		}
	}
	if back["pipe_inbox_sojourn_max_us"] != float64(81920) {
		t.Fatalf("pipe_inbox_sojourn_max_us = %v, want 81920: %s", back["pipe_inbox_sojourn_max_us"], encoded)
	}
	zero, err := json.Marshal(serveStatus{Event: "posture"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		`"pipe_inbox_sojourn":[0,0,0,0,0,0,0,0,0,0,0,0]`,
		`"pipe_inbox_sojourn_max_us":0`,
	} {
		if !strings.Contains(string(zero), key) {
			t.Fatalf("%s omitted at zero (omitempty would hide an inbox nobody has read): %s", key, zero)
		}
	}
}

// serveStatusOf folds the per-session carrier stats in one loop; this pin
// keeps the two sojourn fields in it (sum of histograms, max of maxima),
// next to the high water they are read against.
func TestServeStatusFoldsTheInboxSojourn(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"out.PipeInboxHighWater = max(out.PipeInboxHighWater, pst.InboxHighWater)",
		"out.PipeInboxSojourn[i] += pst.InboxSojourn[i]",
		"out.PipeInboxSojournMaxUS = max(out.PipeInboxSojournMaxUS, pst.InboxSojournMaxUS)",
	} {
		if !strings.Contains(string(src), line) {
			t.Fatalf("main.go no longer folds %q into the status", line)
		}
	}
}

// The per-session memory bill charges carrier.PipeSlotBytes per inbox slot.
// The slot is a slab pointer plus an admission time: two words, so the inbox
// term at 8192 is 64 KiB above the pointer-only figure the Turn 11 notes
// recorded (2,080 B per slot there, 2,088 B here).
func TestInboxSlotBillCountsTheAdmissionTime(t *testing.T) {
	const word = 8
	if carrier.PipeSlotBytes != 2*word {
		t.Fatalf("carrier.PipeSlotBytes = %d, want %d", carrier.PipeSlotBytes, 2*word)
	}
	perSlot := carrier.PipeBufferSlabBytes + carrier.PipeSlotBytes + 24
	if perSlot != 2088 {
		t.Fatalf("per-slot inbox bill = %d B, want 2088", perSlot)
	}
}
