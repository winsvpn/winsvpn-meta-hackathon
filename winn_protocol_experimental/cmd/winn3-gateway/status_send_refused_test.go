package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The device verification procedure requires send_refused to stay unchanged
// through an injected drop, so the gateway must publish it.
func TestTheStatusDocumentPublishesSendRefused(t *testing.T) {
	raw, err := json.Marshal(serveStatus{SendRefused: 7})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"send_refused":7`) {
		t.Fatalf("status document does not publish send_refused: %s", raw)
	}
}
