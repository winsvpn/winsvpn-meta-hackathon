package main

import (
	"encoding/base64"
	"fmt"
	"testing"

	"winsvpn.local/winnprotocol/winn3/driver"
)

func TestRound10ForwardReplacesStaleAuthorityOwner(t *testing.T) {
	for _, oldAddress := range []string{"", "10.10.0.3"} {
		name := "revoked"
		if oldAddress != "" {
			name = "reassigned"
		}
		t.Run(name, func(t *testing.T) {
			old := newAuthorityFixture(t, 0)
			next := newAuthorityFixture(t, 0)
			peers := fmt.Sprintf(`{"static_public":%q,"inner_v4":%q,"not_after":0}`,
				base64.StdEncoding.EncodeToString(next.key), old.addr.String())
			if oldAddress != "" {
				peers += fmt.Sprintf(`,{"static_public":%q,"inner_v4":%q,"not_after":0}`,
					base64.StdEncoding.EncodeToString(old.key), oldAddress)
			}
			replaceAuthority(t, old.registry.path, `{"version":1,"peers":[`+peers+`]}`)
			dueAuthorityRefresh(old.registry)
			if _, ok := old.table.lookup(old.addr); ok {
				t.Fatal("stale owner still receives return traffic")
			}

			writer := &fakeInnerWriter{}
			device := newGatewayForwardDevice(writer, old.table, old.device.MTU(), old.registry)
			device.bind(next.loop)
			t.Cleanup(func() { _ = device.Close() })
			before := old.table.Stats()
			pkt := ipv4Packet(t, old.addr.String(), "8.8.8.8")
			if n, err := device.WritePacket(pkt); err != nil || n != len(pkt) {
				t.Fatalf("authorized replacement blocked by stale owner: write = %d, %v", n, err)
			}
			if len(writer.written) != 1 {
				t.Fatal("replacement packet did not reach the shared writer")
			}
			if got, ok := old.table.lookup(old.addr); !ok || got != next.loop {
				t.Fatal("return traffic does not route to the authorized replacement")
			}
			after := old.table.Stats()
			if after.Size != before.Size || after.Learned != before.Learned+1 ||
				after.Forgotten != before.Forgotten+1 || after.Collisions != before.Collisions {
				t.Fatalf("stale eviction counters: before = %+v, after = %+v", before, after)
			}
			if err := old.device.Close(); err != nil {
				t.Fatal(err)
			}
			if got, ok := old.table.lookup(old.addr); !ok || got != next.loop {
				t.Fatal("old session cleanup removed the replacement owner")
			}
			if got := old.table.Stats(); got != after {
				t.Fatalf("old session cleanup changed replacement counters: %+v", got)
			}
		})
	}
}

func TestRound10ForwardPreservesAuthorizedOwner(t *testing.T) {
	owner := newAuthorityFixture(t, 0)
	claimant := newAuthorityFixture(t, 0)
	before := owner.table.Stats()
	if owner.table.learn(owner.addr, claimant.loop) {
		t.Fatal("different authenticated session displaced an authorized owner")
	}
	if got, ok := owner.table.lookup(owner.addr); !ok || got != owner.loop {
		t.Fatal("collision changed the authorized return path")
	}
	want := before
	want.Collisions++
	if got := owner.table.Stats(); got != want {
		t.Fatalf("collision counters = %+v, want %+v", got, want)
	}
	if !owner.table.learn(owner.addr, owner.loop) {
		t.Fatal("same owner could not relearn its address")
	}
}

func TestRound10ForwardKeepsOwnerWithoutAuthorityEvidence(t *testing.T) {
	for _, name := range []string{"no_registry", "nil_owner", "no_session"} {
		t.Run(name, func(t *testing.T) {
			f := newAuthorityFixture(t, 0)
			var existing *driver.Loop = f.loop
			switch name {
			case "no_registry":
				f.table.registry = nil
			case "nil_owner":
				existing = nil
			case "no_session":
				existing = fakeLoop()
			}
			f.table.byAddr[f.addr] = existing
			before := f.table.Stats()
			if f.table.learn(f.addr, fakeLoop()) {
				t.Fatal("owner replaced without registry evidence of lost authority")
			}
			if got := f.table.byAddr[f.addr]; got != existing {
				t.Fatal("collision changed the existing mapping")
			}
			want := before
			want.Collisions++
			if got := f.table.Stats(); got != want {
				t.Fatalf("collision counters = %+v, want %+v", got, want)
			}
		})
	}
}

func TestRound10ForwardSamePeerReconnectDisplacesStaleOwner(t *testing.T) {
	f1 := newAuthorityFixture(t, 0)
	f2 := newAuthorityFixture(t, 0)
	table := f1.table
	addr := f1.addr

	// Initially f1.loop owns addr
	if got, ok := table.lookup(addr); !ok || got != f1.loop {
		t.Fatalf("initial lookup = %v, want f1.loop", got)
	}

	// If f2 (different peer) tries to claim addr, it collides:
	beforeCollisions := table.Stats().Collisions
	if table.learn(addr, f2.loop) {
		t.Fatal("different authenticated peer was allowed to displace authorized owner")
	}
	if table.Stats().Collisions != beforeCollisions+1 {
		t.Fatalf("Collisions = %d, want %d", table.Stats().Collisions, beforeCollisions+1)
	}

	// Now create a fresh second session loop for the exact same client static key
	reconnected := f1.newPeerLoop(t)
	if reconnected == f1.loop {
		t.Fatal("expected distinct loop instance for reconnected session")
	}

	beforeLearned := table.Stats().Learned
	beforeForgotten := table.Stats().Forgotten
	if !table.learn(addr, reconnected) {
		t.Fatal("reconnected session for same peer could not displace stale session")
	}
	if got, ok := table.lookup(addr); !ok || got != reconnected {
		t.Fatalf("lookup after reconnect = %v, want reconnected loop", got)
	}
	if table.Stats().Learned != beforeLearned+1 {
		t.Fatalf("Learned = %d, want %d", table.Stats().Learned, beforeLearned+1)
	}
	if table.Stats().Forgotten != beforeForgotten+1 {
		t.Fatalf("Forgotten = %d, want %d", table.Stats().Forgotten, beforeForgotten+1)
	}
}
