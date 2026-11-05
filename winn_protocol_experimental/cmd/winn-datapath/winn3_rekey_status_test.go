package main

import (
	"strings"
	"testing"
)

// The rekey resend counter reaches the status document when it moved, and a
// session that never lost an INIT publishes no new key at all.
func TestRekeyInitResendsIsPublishedOnlyWhenNonzero(t *testing.T) {
	raw, err := winn3EncodeStatus(winn3Status{RekeyInitResends: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"rekey_init_resends":3`) {
		t.Fatalf("status %s does not carry rekey_init_resends", raw)
	}
	raw, err = winn3EncodeStatus(winn3Status{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "rekey_init_resends") {
		t.Fatalf("status %s carries rekey_init_resends at zero", raw)
	}
}
