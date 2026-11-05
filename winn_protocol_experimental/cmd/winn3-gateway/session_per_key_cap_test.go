package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestOneClientKeyCannotHoldEverySessionSlot: a single enrolled client key
// must not be able to occupy every -max-sessions slot of a node. Five
// sessions of one key are offered to a five-slot gateway; a client of a
// SECOND key must still be admitted, and the first key must never hold more
// than four slots. On the pre-fix tree the fifth same-key session takes the
// last slot, every one of the five answers its liveness probes, no reclaim
// rule applies, and the second key is refused in silence for as long as the
// first key keeps answering probes.
func TestOneClientKeyCannotHoldEverySessionSlot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*supersedeSafety)
	defer cancel()
	const perKey = 4
	r := newReclaimRig(t, perKey+1, nil)
	r.serve(t, ctx)

	for i := 0; i < perKey; i++ {
		cli := startTestClient(t, ctx, r.opts)
		waitFor(t, supersedeSafety, "a same-key client to carry", func() bool { return carrying(cli) })
		roundTrip(t, cli, "hold")
	}
	views := r.srv.slotViews()
	if len(views) != perKey {
		t.Fatalf("the gateway holds %d sessions, want %d", len(views), perKey)
	}
	firstKey := append([]byte(nil), views[0].view.PeerStatic...)

	// A fifth session of the same key. Whether the gateway admits it or
	// refuses it, it must not cost a client of another key its slot.
	fifth := startTestClient(t, ctx, r.opts)
	time.Sleep(2 * time.Second)

	dir2 := t.TempDir()
	if err := runKeygen(dir2, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	other := r.opts
	other.dir = dir2
	other.inner = testClientInner2
	cli := startTestClient(t, ctx, other)
	waitFor(t, 40*time.Second, "a client of a second key to carry beside a key that tried to fill the table",
		func() bool { return carrying(cli) })

	same := 0
	for _, v := range r.srv.slotViews() {
		if bytes.Equal(v.view.PeerStatic, firstKey) {
			same++
		}
	}
	if same > perKey {
		t.Fatalf("the first key holds %d slots, want at most %d", same, perKey)
	}
	_ = fifth
}

// TestRegistryRefusesAKeyAtThePerKeyCap is the accept-time half: with the
// server's cap wired into the registry (as runServe wires it under -forward),
// the fifth handshake of one key is refused by authorize, before any response
// is built, and a sixth key is still admitted.
func TestRegistryRefusesAKeyAtThePerKeyCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.json")
	keyA := bytes.Repeat([]byte{0x11}, 32)
	keyB := bytes.Repeat([]byte{0x22}, 32)
	doc := fmt.Sprintf(`{"version":1,"peers":[{"static_public":%q,"inner_v4":"10.64.0.2","not_after":0},{"static_public":%q,"inner_v4":"10.64.0.3","not_after":0}]}`,
		base64.StdEncoding.EncodeToString(keyA), base64.StdEncoding.EncodeToString(keyB))
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := newPeerRegistry(path, netip.MustParsePrefix("10.64.0.0/24"), netip.MustParseAddr("10.64.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &server{}
	reg.admit = srv.keyMayOpenSession
	for i := 0; i < maxSessionsPerKey; i++ {
		if err := reg.authorize(keyA); err != nil {
			t.Fatalf("handshake %d of key A refused: %v", i+1, err)
		}
	}
	if err := reg.authorize(keyA); !errors.Is(err, errPeerSessionCap) {
		t.Fatalf("handshake %d of key A: got %v, want errPeerSessionCap", maxSessionsPerKey+1, err)
	}
	if err := reg.authorize(keyB); err != nil {
		t.Fatalf("key B refused while key A is at its cap: %v", err)
	}
	// The ticker's rebuild from an empty table clears the optimistic count.
	srv.peers = map[netip.AddrPort]*peerSession{}
	srv.enforcePerKeyCap()
	if err := reg.authorize(keyA); err != nil {
		t.Fatalf("key A refused after its sessions left the table: %v", err)
	}
}
