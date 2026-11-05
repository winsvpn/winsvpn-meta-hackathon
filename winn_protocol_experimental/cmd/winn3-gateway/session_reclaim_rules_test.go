package main

import (
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// rv builds a ReclaimView for the rule tests. established is this generation's
// establishment instant (zero for not-yet-established); lastAuth is the last
// authenticated receive.
func rv(state session.State, peer []byte, established, lastAuth time.Time, probe time.Duration, unopenable uint64) session.ReclaimView {
	return session.ReclaimView{
		State:         state,
		Authenticated: len(peer) > 0,
		Established:   !established.IsZero(),
		CurGenAt:      established,
		LastAuthRecv:  lastAuth,
		PeerStatic:    peer,
		ProbeMax:      probe,
		Unopenable:    unopenable,
	}
}

// TestReclaimClassification pins the rule table directly, including the cases
// the integration tests cannot reach deterministically.
func TestReclaimClassification(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	peer := []byte("client-static-key-32-bytes-long!")
	probe := 20 * time.Second
	Z := time.Time{}
	cases := []struct {
		name string
		v    session.ReclaimView
		want reclaimClass
	}{
		{"nothing delivered yet", rv(session.StateInitiating, nil, Z, Z, probe, 0), notReclaimable},
		{"refused what it was handed", rv(session.StateInitiating, nil, Z, Z, probe, 1), reclaimFailed},
		{"key holder completing first handshake", rv(session.StateInitiating, peer, Z, Z, probe, 1), notReclaimable},
		{"authenticated re-initiation in flight", rv(session.StateInitiating, peer, Z, now.Add(-time.Hour), probe, 0), notReclaimable},
		{"closing", rv(session.StateClosing, peer, now.Add(-time.Hour), now, probe, 0), reclaimFailed},
		{"failed", rv(session.StateFailed, nil, Z, Z, probe, 0), reclaimFailed},
		{"established, heard 39 s ago", rv(session.StateEstablished, peer, now.Add(-time.Hour), now.Add(-39*time.Second), probe, 0), notReclaimable},
		{"established, heard 40 s ago", rv(session.StateEstablished, peer, now.Add(-time.Hour), now.Add(-40*time.Second), probe, 0), reclaimQuiet},
		{"established, nothing since establishing 40 s ago", rv(session.StateEstablished, peer, now.Add(-40*time.Second), Z, probe, 0), reclaimQuiet},
		{"rekeying, heard 5 min ago", rv(session.StateRekeying, peer, now.Add(-time.Hour), now.Add(-5*time.Minute), probe, 0), reclaimQuiet},
	}
	for _, c := range cases {
		if got := classifySlot(c.v, now); got != c.want {
			t.Errorf("%s: class %d, want %d", c.name, got, c.want)
		}
	}

	a, b, f := &peerSession{}, &peerSession{}, &peerSession{}
	views := []slotView{
		{ps: a, view: rv(session.StateEstablished, peer, now.Add(-time.Hour), now.Add(-50*time.Second), probe, 0)},
		{ps: b, view: rv(session.StateEstablished, peer, now.Add(-time.Hour), now.Add(-90*time.Second), probe, 0)},
	}
	if v, ok := pickReclaimVictim(views, now); !ok || v.ps != b {
		t.Fatal("the idlest silent session was not chosen")
	}
	views = append(views, slotView{ps: f, view: rv(session.StateInitiating, nil, time.Time{}, time.Time{}, probe, 3)})
	if v, ok := pickReclaimVictim(views, now); !ok || v.ps != f {
		t.Fatal("a failed half-open was not preferred over a silent established session")
	}
	if _, ok := pickReclaimVictim(views[:0], now); ok {
		t.Fatal("a victim was chosen from an empty table")
	}
}

// TestSupersedeRule pins the supersede predicate: only under a confirmed,
// forwarding-owning newest session, and only strictly older established
// sessions of the same key.
func TestSupersedeRule(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	peer := []byte("client-static-key-32-bytes-long!")
	other := []byte("another-client-static-key-32byte")
	probe := 20 * time.Second
	older, newer, alien := &peerSession{}, &peerSession{}, &peerSession{}

	// newer is confirmed usable (a receive after establishing) and owns forwarding.
	base := []slotView{
		{ps: older, view: rv(session.StateEstablished, peer, now.Add(-time.Minute), now.Add(-30*time.Second), probe, 0)},
		{ps: newer, view: rv(session.StateEstablished, peer, now.Add(-5*time.Second), now.Add(-1*time.Second), probe, 0)},
		{ps: alien, view: rv(session.StateEstablished, other, now.Add(-time.Hour), now.Add(-10*time.Minute), probe, 0)},
	}
	ownsNewer := func(v slotView) bool { return v.ps == newer }

	got := supersedePairs(base, ownsNewer)
	if len(got) != 1 || got[0].old.ps != older || got[0].newer.ps != newer {
		t.Fatalf("supersedePairs = %d, want exactly {older,newer} of the shared key", len(got))
	}

	// Newer not confirmed usable: nothing has opened since it established.
	unconfirmed := append([]slotView(nil), base...)
	unconfirmed[1].view.LastAuthRecv = unconfirmed[1].view.CurGenAt
	if got := supersedePairs(unconfirmed, ownsNewer); len(got) != 0 {
		t.Fatal("an older session was superseded by a newer one whose keys are not confirmed usable")
	}

	// Newer confirmed but does not own forwarding: the downlink has not moved.
	if got := supersedePairs(base, func(slotView) bool { return false }); len(got) != 0 {
		t.Fatal("an older session was superseded before the replacement owned forwarding")
	}

	// Newer never established: supersedes nothing.
	notEstablished := append([]slotView(nil), base...)
	notEstablished[1].view = rv(session.StateInitiating, peer, time.Time{}, now.Add(-1*time.Second), probe, 0)
	if got := supersedePairs(notEstablished, ownsNewer); len(got) != 0 {
		t.Fatal("a session whose newest generation never established superseded an established one")
	}
}
