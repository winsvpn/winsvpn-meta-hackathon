package gateway

import (
	"testing"
	"time"
)

// The idle sweep and the liveness stamp have to agree about one instant, and
// until this file nothing in the package checked that they did.
//
// EvictIdle arms no timer of its own. It derives a cutoff from the caller's
// clock — `now.Add(-IdleTimeout)` — and takes every session whose lastSeen is
// at or before it, which is the same statement as "age >= IdleTimeout". The
// ARMING half of the pair is the stamp: Table.Register records the instant a
// session was admitted and Entry.openLocked records the instant a message
// OPENED, and nothing else moves it. So the pair is
// (lastSeen = the instant of the event, taken when age reaches IdleTimeout),
// and the two halves can only be checked against each other AT the instant.
//
// TestEvictIdleReclaimsOnlyTheSilent sweeps at 61 s against a 60 s timeout, and
// TestTheTableHoldsNoSocketAndNoTimer sweeps at 2 s against 1 s. Both margins
// are right for what those tests are about — noise must not renew a lease, and
// a frozen clock must evict nothing — but neither touches the instant, and
// measured on 2026-08-09 with `go test -overlay` the whole gateway package
// stayed green (exit 0, no --- FAIL: line) with `lastSeen <= cutoff` narrowed
// to `<`. That is the shape this file closes: a threshold cleared by a margin
// asserts that eviction happens eventually, never that it happens on time.
//
// Which side of the boundary is right is settled by the rest of the tree rather
// than by taste. table.go's sweep is inclusive today; dpbridge.Rebound is
// inclusive at both ends (`age >= 0 && age <= within`); every deadline in
// winn3/session arms with `now.Add(d)` and fires with `!now.Before(...)`, and
// its one exclusive comparison — the inflight probe expiry — was a defect and
// was fixed to `>=` on 2026-08-09. An exclusive sweep would also make
// IdleTimeout not a timeout: a session silent for exactly the configured budget
// would be kept, and the documented figure would really be IdleTimeout plus one
// tick.

// TestASessionIsIdleTheInstantItHasBeenSilentForTheWholeTimeout pins the
// boundary from both sides, one nanosecond either way, so that a later edit
// cannot move it in either direction without saying so.
//
// The middle row is the one that matters. The two outer rows exist so that a
// mutation which simply broke eviction, or one which evicted everything, cannot
// read as a pass on the middle row alone.
func TestASessionIsIdleTheInstantItHasBeenSilentForTheWholeTimeout(t *testing.T) {
	const timeout = time.Minute

	for _, tc := range []struct {
		name string
		age  func(d time.Duration) time.Duration
		want bool // want the subject evicted
	}{
		{"one tick short of the timeout", func(d time.Duration) time.Duration { return d - 1 }, false},
		{"exactly on the timeout", func(d time.Duration) time.Duration { return d }, true},
		{"one tick past the timeout", func(d time.Duration) time.Duration { return d + 1 }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := smallCfg()
			cfg.IdleTimeout = timeout
			tbl := testTable(t, cfg)

			// The subject: admitted at fixedNow and silent ever since.
			subject, _ := registerFake(t, tbl, 1)

			// The ARMING side of the pair, asserted exactly.
			//
			// Every row below is expressed relative to the subject's lastSeen,
			// so a change that moved the STAMP instead of the comparison —
			// admitting a session with a backdated or rounded lastSeen — would
			// move all three rows with it and be invisible. This is the
			// assertion that makes the arming half addressable, and it is the
			// same thing winn3/session's probe boundary test does when it pins
			// NextDeadline to sent+Probe.Max exactly.
			if got := subject.LastSeen(); !got.Equal(fixedNow) {
				t.Fatalf("Register stamped lastSeen at %s for a session admitted at %s, a difference of %s; "+
					"the idle clock must start at the instant of the event and nowhere else",
					got.UTC(), fixedNow.UTC(), got.Sub(fixedNow))
			}

			age := tc.age(timeout)
			sweep := fixedNow.Add(age)
			// The fixture asserts its own arithmetic. A subject that is not the
			// age this row claims would make the row pass for the wrong reason.
			if got := sweep.Sub(subject.LastSeen()); got != age {
				t.Fatalf("the subject is %s old at the sweep, wanted %s (IdleTimeout is %s)",
					got, age, timeout)
			}

			// A companion, touched so that it is exactly ONE TICK short of the
			// timeout at the same sweep, in every row. It must survive every
			// time. Without it, a sweep that took everything would read as a
			// pass on the two rows that expect a taking.
			companion, cf := registerFake(t, tbl, 2)
			touch := sweep.Add(-timeout + 1)
			if _, _, err := tbl.Dispatch(cf.message(0), touch); err != nil {
				t.Fatalf("the companion's message did not route: %v", err)
			}
			// The other half of the arming, on the path that carries the whole
			// anti-liveness-forgery property: lastSeen moves when a message
			// OPENS, and it moves to the instant of that message rather than to
			// some rounded neighbour of it.
			if got := companion.LastSeen(); !got.Equal(touch) {
				t.Fatalf("a message opened at %s left lastSeen at %s, a difference of %s; the liveness "+
					"stamp is the instant of the message", touch.UTC(), got.UTC(), got.Sub(touch))
			}

			before := tbl.Stats()
			took := tbl.EvictIdle(sweep)

			wantTook := 0
			if tc.want {
				wantTook = 1
			}
			cutoff := sweep.Add(-timeout)
			if got := subject.Closed(); got != tc.want || took != wantTook {
				t.Fatalf("a session silent for exactly %s under a %s IdleTimeout was evicted=%v and the "+
					"sweep took %d, want %v and %d. The sweep at %s has cutoff %s; the subject's lastSeen "+
					"is %s, which is %s from the cutoff. IdleTimeout is the WHOLE budget a session may "+
					"spend silent, so it is spent AT the timeout and not one tick past it — the same "+
					"argument that moved winn3/session's probe expiry to an inclusive test.",
					age, timeout, got, took, tc.want, wantTook,
					sweep.UTC(), cutoff.UTC(), subject.LastSeen().UTC(), cutoff.Sub(subject.LastSeen()))
			}
			if companion.Closed() {
				t.Fatalf("the companion was %s old at a %s timeout — one tick short of the budget — and "+
					"was evicted anyway; the sweep is taking sessions whose budget is not spent",
					sweep.Sub(companion.LastSeen()), timeout)
			}

			// The ledger has to agree with the verdict, because the memory bill
			// is the reason eviction exists at all.
			s := tbl.Stats()
			wantSessions := 2 - wantTook
			if s.Sessions != wantSessions || tbl.Sessions() != wantSessions {
				t.Fatalf("%d sessions after a sweep that took %d of 2, want %d", s.Sessions, took, wantSessions)
			}
			if want := wantSessions * 16; s.IndexedTokens != want {
				t.Fatalf("reserved capacity is %d tokens after a sweep that took %d of 2 sessions of 16, "+
					"want %d; an eviction that does not return its window leaks the gateway's hottest "+
					"structure", s.IndexedTokens, took, want)
			}
			if got := s.Evicted - before.Evicted; got != uint64(wantTook) {
				t.Fatalf("the sweep took %d sessions and reported %d in Stats().Evicted; memory pressure "+
					"that is invisible is memory pressure that is a surprise", took, got)
			}

			// And it is settled rather than oscillating: sweeping the same
			// instant again takes nothing more.
			if again := tbl.EvictIdle(sweep); again != 0 {
				t.Fatalf("a second sweep at the same instant %s took %d more sessions after the first "+
					"took %d; the sweep is not idempotent at its own boundary",
					sweep.UTC(), again, took)
			}
		})
	}
}
