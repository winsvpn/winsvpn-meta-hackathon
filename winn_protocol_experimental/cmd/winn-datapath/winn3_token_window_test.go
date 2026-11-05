package main

import (
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

// The client's gateway-to-client token window bounds the burst loss a session
// survives (W-1 clean, W/2-1 after a recent loss). It must be wider than the
// core default, and legal.
func TestTheClientReceiveTokenWindowIsWidened(t *testing.T) {
	dir := t.TempDir()
	keys, err := loadWinn3Keys(writeKeys(t, dir, validKeys(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := keys.sessionConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Core.TokenWindow != winn3ClientTokenWindow {
		t.Fatalf("client token window = %d, want %d", cfg.Core.TokenWindow, winn3ClientTokenWindow)
	}
	if winn3ClientTokenWindow <= core.DefaultTokenWindow || winn3ClientTokenWindow > core.MaxTokenWindow {
		t.Fatalf("client token window %d must be in (%d, %d]", winn3ClientTokenWindow, core.DefaultTokenWindow, core.MaxTokenWindow)
	}
}
