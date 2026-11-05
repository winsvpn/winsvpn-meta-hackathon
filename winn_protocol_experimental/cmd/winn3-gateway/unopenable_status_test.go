package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestGatewayStatusPublishesUnopenable pins the operator document against the
// same spray-looks-like-traffic failure the client document now names.
//
// cmd/winn3-gateway demultiplexes on peer address and feeds each session
// through carrier.Pipe.Deliver. A junk datagram that is the right size to
// look like an initiation still allocates a session; after that, every
// unopenable datagram increments both Pipe.Delivered and
// Loop.MessagesReceived. Without unopenable on serveStatus the gateway
// reports it is talking.
func TestGatewayStatusPublishesUnopenable(t *testing.T) {
	encoded, err := json.Marshal(serveStatus{
		Event:            "posture",
		Unopenable:       11,
		PathNarrowedFor:  2,
		MessagesReceived: 11,
	})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	if back["unopenable"] != float64(11) {
		t.Fatalf("unopenable is %v, want 11: %s", back["unopenable"], encoded)
	}
	if back["path_narrowed_for"] != float64(2) {
		t.Fatalf("path_narrowed_for is %v, want 2: %s", back["path_narrowed_for"], encoded)
	}
	if back["messages_received"] != float64(11) {
		t.Fatalf("messages_received is %v, want 11: %s", back["messages_received"], encoded)
	}

	zero, err := json.Marshal(serveStatus{Event: "posture"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(zero), `"unopenable":0`) {
		t.Fatalf("unopenable is omitted at zero: %s", zero)
	}
	if !strings.Contains(string(zero), `"path_narrowed_for":0`) {
		t.Fatalf("path_narrowed_for is omitted at zero: %s", zero)
	}

	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	for _, n := range []string{
		"out.Unopenable += ls.Unopenable",
		"out.PathNarrowedFor += ls.PathNarrowedFor",
	} {
		if !strings.Contains(body, n) {
			t.Fatalf("status() no longer copies %q from Loop.Stats; the JSON key would be a permanent zero", n)
		}
	}
}
