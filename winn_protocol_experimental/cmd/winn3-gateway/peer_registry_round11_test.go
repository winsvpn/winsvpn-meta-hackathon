package main

import (
	"bytes"
	"testing"
	"time"
)

func TestPeerRegistryLookupRequiresBothAuthorityIndexes(t *testing.T) {
	f := newAuthorityFixture(t, 0)
	var key [32]byte
	copy(key[:], f.key)
	if addr, ok := f.registry.innerForPeer(f.key); !ok || addr != f.addr {
		t.Fatalf("nonexpiring peer = %v, %v", addr, ok)
	}
	for _, bad := range [][]byte{nil, f.key[:31], append(bytes.Clone(f.key), 0), bytes.Repeat([]byte{0xff}, 32)} {
		if addr, ok := f.registry.innerForPeer(bad); ok || addr.IsValid() {
			t.Fatalf("invalid or foreign key authorized: %v, %v", addr, ok)
		}
	}
	f.registry.mu.Lock()
	delete(f.registry.notAfter, key)
	f.registry.mu.Unlock()
	if _, ok := f.registry.innerForPeer(f.key); ok {
		t.Fatal("missing expiry authorization accepted")
	}
	f.registry.mu.Lock()
	f.registry.notAfter[key] = time.Now().Unix()
	f.registry.mu.Unlock()
	if _, ok := f.registry.innerForPeer(f.key); ok {
		t.Fatal("expired authorization accepted at its boundary")
	}
	f.registry.mu.Lock()
	f.registry.notAfter[key] = time.Now().Unix() + 3600
	f.registry.mu.Unlock()
	if _, ok := f.registry.innerForPeer(f.key); !ok {
		t.Fatal("future expiry rejected")
	}
	f.registry.mu.Lock()
	delete(f.registry.byKey, key)
	f.registry.mu.Unlock()
	if _, ok := f.registry.innerForPeer(f.key); ok {
		t.Fatal("orphaned expiry authorizes an absent peer")
	}
}
