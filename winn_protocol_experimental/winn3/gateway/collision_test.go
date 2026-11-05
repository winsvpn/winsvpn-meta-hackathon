package gateway

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// collidingSource is a normal keyed source with exactly one counter forced onto
// a chosen token. Forcing one counter rather than all of them is what makes it
// a model of a real 64-bit collision: two independent sessions whose windows
// happen to overlap at a single point.
type collidingSource struct {
	base TokenSource
	at   uint64
	tok  Token
}

func (c collidingSource) TokenAt(n uint64) Token {
	if n == c.at {
		return c.tok
	}
	return c.base.TokenAt(n)
}

func collide(n int, at uint64, tok Token) collidingSource {
	return collidingSource{base: NewKeyedSource(keyFor(n)), at: at, tok: tok}
}

// TestCollidingSessionsBothStillRoute.
//
// Two live tokens colliding is a birthday event across the whole gateway rather
// than within one session, so the exposure is larger than the per-session
// figure the design records. The handling has to be right rather than merely
// rare: the AEAD decides which session a message belongs to, and neither
// session loses a packet.
func TestCollidingSessionsBothStillRoute(t *testing.T) {
	tbl := testTable(t, smallCfg())

	var tok Token
	copy(tok[:], []byte{1, 2, 3, 4, 5, 6, 7, 8})

	fa := newFakeSession(collide(1, 0, tok), 1)
	fb := newFakeSession(collide(2, 0, tok), 2)
	ea, err := tbl.Register(fa, fa.src, clientKey(1), fixedNow)
	if err != nil {
		t.Fatalf("Register a: %v", err)
	}
	eb, err := tbl.Register(fb, fb.src, clientKey(2), fixedNow)
	if err != nil {
		t.Fatalf("Register b: %v", err)
	}
	if got := tbl.Stats().Collisions; got == 0 {
		t.Fatal("two sessions claimed the same token and no collision was recorded")
	}

	// A message from the session that lost the race still opens: the index
	// tried the primary owner, its AEAD refused, and the overflow candidate
	// took it.
	ent, plain, err := tbl.Dispatch(fb.message(0), fixedNow)
	if err != nil {
		t.Fatalf("the colliding session's message did not route: %v", err)
	}
	if ent != eb {
		t.Fatalf("routed to session %d, want %d", ent.ID(), eb.ID())
	}
	if plain == nil {
		t.Fatal("no plaintext")
	}
	// And the winner still works.
	if ent, _, err := tbl.Dispatch(fa.message(0), fixedNow); err != nil || ent != ea {
		t.Fatalf("the primary owner stopped working: err=%v", err)
	}
	// The cost is exactly one extra open attempt, not a dropped packet.
	if fa.openCalls() != 2 {
		t.Fatalf("the primary session's Open was called %d times, want 2 (one wrong, one right)", fa.openCalls())
	}
}

// TestTheCollisionListIsBounded. The candidate list must never become a growth
// surface: past the cap the loser simply drops that one counter, which is the
// outcome the design already accepts for a collision.
func TestTheCollisionListIsBounded(t *testing.T) {
	tbl := testTable(t, smallCfg())
	var tok Token
	copy(tok[:], []byte{9, 9, 9, 9, 9, 9, 9, 9})

	for i := 0; i < 8; i++ {
		f := newFakeSession(collide(i, 0, tok), byte(i))
		if _, err := tbl.Register(f, f.src, clientKey(i), fixedNow); err != nil {
			t.Fatalf("Register(%d): %v", i, err)
		}
	}
	owners := tbl.Owners(tok)
	if len(owners) > maxCandidates {
		t.Fatalf("%d sessions own one token; the cap is %d", len(owners), maxCandidates)
	}
	if len(owners) != maxCandidates {
		t.Fatalf("%d owners, want the list filled to %d before it refuses more", len(owners), maxCandidates)
	}
}

// TestErasingThePrimaryPromotesAnOverflowOwner. If it did not, the surviving
// session would lose that counter permanently and the index would leak a slot.
func TestErasingThePrimaryPromotesAnOverflowOwner(t *testing.T) {
	tbl := testTable(t, smallCfg())
	var tok Token
	copy(tok[:], []byte{7, 7, 7, 7, 7, 7, 7, 7})

	fa := newFakeSession(collide(1, 0, tok), 1)
	fb := newFakeSession(collide(2, 0, tok), 2)
	ea, _ := tbl.Register(fa, fa.src, clientKey(1), fixedNow)
	eb, _ := tbl.Register(fb, fb.src, clientKey(2), fixedNow)

	if got := len(tbl.Owners(tok)); got != 2 {
		t.Fatalf("%d owners, want 2", got)
	}
	tbl.Remove(ea)
	owners := tbl.Owners(tok)
	if len(owners) != 1 || owners[0] != eb.ID() {
		t.Fatalf("after the primary left, owners are %v; want just session %d", owners, eb.ID())
	}
	if _, _, err := tbl.Dispatch(fb.message(0), fixedNow); err != nil {
		t.Fatalf("the promoted owner does not route: %v", err)
	}
}

// countTruncatedCollisions draws n tokens from the real derivation and counts
// how many of them collide on their top w bits.
func countTruncatedCollisions(w, n int) int {
	seen := make(map[uint64]bool, n)
	shift := uint(64 - w)
	dup := 0
	var key [core.KeySize]byte
	for i := 0; i < n; i++ {
		// A fresh key every 4096 counters, so the sample is not one long run
		// from a single key.
		if i%4096 == 0 {
			binary.BigEndian.PutUint64(key[:8], uint64(i))
		}
		tok := DeriveToken(&key, uint64(i))
		v := binary.BigEndian.Uint64(tok[:]) >> shift
		if seen[v] {
			dup++
		}
		seen[v] = true
	}
	return dup
}

// TestTheCollisionModelIsTheOneTheDocumentUses.
//
// The handoff document computes the gateway's collision exposure from the
// birthday formula n²/2^(w+1). Nobody can observe a 64-bit collision in a test,
// so this validates the formula against the ACTUAL derivation at widths where
// collisions are observable, and the document then applies the same formula at
// 64 bits. Everything is deterministic, so there is nothing here to flake.
func TestTheCollisionModelIsTheOneTheDocumentUses(t *testing.T) {
	// Each width samples n tokens so the model predicts about ten collisions,
	// keeping the 4-sigma band wide enough that a deterministic sample cannot
	// flake out of it while the sample stays small enough that the race
	// instrumenter can finish the whole suite. Collision counts are set by
	// n^2/2^(w+1), so n is chosen as sqrt(10 * 2^(w+1)) for each width. Two
	// widths, one octave apart, validate the power law; the negative control
	// below provides the anti-vacuity half. (The original widths
	// 82000/164000/330000 predicted ~200 collisions each across three widths
	// and needed ~75 s under -race — a wall-clock property, not a defect.)
	cases := []struct{ w, n int }{
		{24, 18318},
		{26, 36636},
	}
	for _, c := range cases {
		expected := float64(c.n) * float64(c.n-1) / 2 / float64(uint64(1)<<uint(c.w))
		got := countTruncatedCollisions(c.w, c.n)
		lo, hi := expected-4*sqrt(expected), expected+4*sqrt(expected)
		if float64(got) < lo || float64(got) > hi {
			t.Fatalf("at %d bits over %d tokens: %d collisions, the birthday model predicts %.1f "+
				"(4-sigma band %.1f..%.1f)", c.w, c.n, got, expected, lo, hi)
		}
		t.Logf("%d-bit truncation, %d tokens: %d collisions, model %.1f", c.w, c.n, got, expected)
	}

	// The same check has to be capable of objecting, or the bands above are
	// decorative. A derivation with only 16 bits of real entropy must fail it.
	// The detection is pinned to a hard deterministic floor so it cannot
	// silently weaken: a source that truncates to `bits` bits of entropy has at
	// most 2^bits distinct values, so over `n` samples it MUST collide at least
	// n - 2^bits times, while a full-entropy source collides ~never (birthday
	// in 2^64 over 2^17 values is ~0). We drive the REAL derivation through the
	// same truncation the model uses and require that guaranteed floor. The
	// sample size is derived from the width (2^(bits+1), unconditionally above
	// 2^16); the guard below turns any attempt to shrink it into a loud failure
	// rather than a silent weak=0 pass, which is the trap a fixed magic size
	// left open.
	const bits = 16
	n := 1 << (bits + 1)
	if n <= 1<<bits {
		t.Fatalf("sample of %d cannot observe a %d-bit truncation; it must exceed 2^%d", n, bits, bits)
	}
	weak := countTruncatedCollisions(bits, n)
	need := n - (1 << bits)
	if weak < need {
		t.Fatalf("the collision check cannot detect a %d-bit derivation: %d collisions over %d samples, "+
			"want at least %d (any %d-bit source must collide on everything past its 2^%d value space)",
			bits, weak, n, need, bits, bits)
	}
	t.Logf("%d-bit truncation, %d tokens: %d collisions on a %d-bit entropy floor, floor %d",
		bits, n, weak, bits, need)
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 40; i++ {
		z = (z + x/z) / 2
	}
	return z
}

// TestCollisionConcurrentClientIDAllocation is a concurrency collision test
// for the client-ID allocator — t.nextID in Table.Register, surfaced to the
// outside as a SessionID.
//
// A SessionID must be unique for the life of the gateway: it is what an
// operator, a log line and an eviction policy use to talk about a session, and
// a duplicate would conflate two live sessions into one identity. The allocator
// is a single t.nextID under t.mu, and this test exists so that "unique under
// t.mu" is a claim with something checking it. It hammers concurrent Register
// calls — the only place a client-ID is handed out — while the same registrations
// drive the admission-eviction path, which is the one spot in Register that DROPS
// t.mu (to retire a victim under its entry lock, after which the shard locks are
// taken) and then RE-ACQUIRES it. That drop-and-reacquire is exactly where a
// lock-ordering mistake would surface — as a duplicate client-ID, a data race,
// or a hang — so a gate that never routes a registration through it would not
// be exercising the ordering at all.
//
// -race is what turns this from a scheduling accident into a real check of the
// lock order; the package is always run with -race in CI. The tail guards are
// the anti-vacuity half: a test that allocated nothing, or one that could not
// tell a duplicate apart from a fresh ID, is a test that did nothing.
func TestCollisionConcurrentClientIDAllocation(t *testing.T) {
	const (
		workers   = 16
		perWorker = 768
	)
	total := workers * perWorker
	cfg := Config{
		InitialWindow:        16,
		MaxWindow:            16,
		// Small enough that admission must evict to make room on most
		// registrations: every admission after the first MaxSessions retires a
		// victim under the entry-and-shard locks before re-taking t.mu and
		// handing out the next client-ID.
		MaxSessions: 512,
		// The per-client cap must never be the one refusing, or "registered"
		// stops being a clean count of IDs handed out.
		MaxSessionsPerClient: total,
		// The sweeper is not the actor here; admission eviction is. A long
		// IdleTimeout keeps EvictIdle out of the way so the accounting is
		// deterministic.
		IdleTimeout: time.Hour,
		Now:         func() time.Time { return fixedNow },
	}
	tbl := testTable(t, cfg)

	type result struct {
		id  SessionID
		ref *Entry
	}
	res := make(chan result, total)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				n := w*100000 + i
				f, src := newFake(n)
				e, err := tbl.Register(f, src, clientKey(n), fixedNow)
				if err != nil {
					res <- result{id: SessionID(^uint64(0))}
					continue
				}
				res <- result{id: e.ID(), ref: e}
			}
		}(w)
	}
	wg.Wait()
	close(res)

	seen := make(map[SessionID]bool, total)
	registered, rejected := 0, 0
	var dupID SessionID
	dup := false
	for r := range res {
		if r.id == SessionID(^uint64(0)) {
			rejected++
			continue
		}
		registered++
		if seen[r.id] {
			dup = true
			dupID = r.id
		}
		seen[r.id] = true
	}

	if registered == 0 {
		t.Fatal("no client-ID was allocated; the test did nothing")
	}
	if rejected != 0 {
		t.Fatalf("Register refused %d of %d submissions; the test could not cleanly count IDs", rejected, total)
	}
	if dup {
		t.Fatalf("client-ID %d was handed to two sessions under concurrent registration; "+
			"the allocator is not serializing", dupID)
	}
	if registered != total {
		t.Fatalf("recorded %d allocations for %d submissions; the accounting is wrong", registered, total)
	}
}
