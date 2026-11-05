//go:build darwin

package main

import (
	"encoding/json"
	"testing"

	"winsvpn.local/winnprotocol/winn3/driver"
)

// A zero loop supplies status counters only. No driver, device pump or socket runs.
func TestWinn3RuntimeCompletionStatusPreservesOwnerGuard(t *testing.T) {
	tunnel := &winn3Tunnel{loop: &driver.Loop{}, dev: &abiDevice{}, done: make(chan struct{})}
	read := func(want bool) {
		t.Helper()
		var document map[string]any
		if err := json.Unmarshal([]byte(tunnel.statusJSON()), &document); err != nil {
			t.Fatal(err)
		}
		if got, ok := document["winn3_runtime_completed"].(bool); !ok || got != want {
			t.Fatalf("completion = %v, want boolean %v", document["winn3_runtime_completed"], want)
		}
		if document["closed"] != false || tunnel.closed.Load() {
			t.Fatal("runtime sample changed owner-close guard")
		}
	}
	read(false)
	close(tunnel.done)
	read(true)
	read(true)
	if !tunnel.closed.CompareAndSwap(false, true) {
		t.Fatal("owner guard no longer claimable")
	}
}
