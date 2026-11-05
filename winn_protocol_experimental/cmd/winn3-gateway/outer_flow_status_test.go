package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestGatewayStatusPublishesOuterFlowAndSendQueue pins the counters the
// tunnel-speed measurement plan reads every second: authenticated uplink
// messages that arrived after a later one (outer_reordered), uplink counters
// that never opened (outer_lost, which includes pipe_recv_errors), and the
// downlink send queue now and at its deepest. They are published at zero,
// like pipe_recv_errors, because an absent key would read as "this build
// cannot count" and a zero must read as "nothing happened".
func TestGatewayStatusPublishesOuterFlowAndSendQueue(t *testing.T) {
	encoded, err := json.Marshal(serveStatus{
		Event:              "posture",
		OuterReordered:     3,
		OuterLost:          5,
		SendQueueDepth:     7,
		SendQueueHighWater: 11,
		PipeRecvErrors:     2,
	})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]float64{
		"outer_reordered":       3,
		"outer_lost":            5,
		"send_queue_depth":      7,
		"send_queue_high_water": 11,
		"pipe_recv_errors":      2,
	} {
		if back[key] != want {
			t.Fatalf("%s is %v, want %v: %s", key, back[key], want, encoded)
		}
	}

	zero, err := json.Marshal(serveStatus{Event: "posture"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"outer_reordered", "outer_lost", "send_queue_depth", "send_queue_high_water"} {
		if !strings.Contains(string(zero), `"`+key+`":0`) {
			t.Fatalf("%s is omitted at zero: %s", key, zero)
		}
	}

	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	for _, n := range []string{
		"out.OuterReordered += ls.OuterReordered",
		"out.OuterLost += ls.OuterLost",
		"out.SendQueueDepth += ls.DataQueueDepth",
		"out.SendQueueHighWater = max(out.SendQueueHighWater, ls.DataQueueHighWater)",
	} {
		if !strings.Contains(body, n) {
			t.Fatalf("status() no longer copies %q from Loop.Stats; the JSON key would be a permanent zero", n)
		}
	}
}

// outer_reorder_depth is the displacement split of outer_reordered, published
// as a ten-bucket array even at zero, and status() sums it over the sessions.
func TestGatewayStatusPublishesOuterReorderDepth(t *testing.T) {
	st := serveStatus{Event: "posture"}
	st.OuterReorderDepth[0], st.OuterReorderDepth[5], st.OuterReorderDepth[9] = 7, 3, 1
	encoded, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"outer_reorder_depth":[7,0,0,0,0,3,0,0,0,1]`) {
		t.Fatalf("outer_reorder_depth not published as the bucket array: %s", encoded)
	}
	zero, err := json.Marshal(serveStatus{Event: "posture"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(zero), `"outer_reorder_depth":[0,0,0,0,0,0,0,0,0,0]`) {
		t.Fatalf("outer_reorder_depth is omitted at zero: %s", zero)
	}
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "out.OuterReorderDepth.Add(ls.OuterReorderDepth)") {
		t.Fatal("status() no longer sums Loop.Stats().OuterReorderDepth")
	}
}
