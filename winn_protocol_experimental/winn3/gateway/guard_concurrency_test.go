package gateway

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestTheConcurrentAdmissionBudgetIsNotOverspent.
//
// Cost admission is a claim that the gateway-wide meter converts an unbounded
// flood into a bounded CPU bill. Under concurrency that claim must hold exactly:
// everything rides on the bucket's refill-and-spend being atomic, because the
// failure shape this guards is two goroutines reading "there is a token" and both
// spending the same one. A broken lock lets concurrent spenders draw B + more
// tokens from a burst of B.
//
// The test pins the strong form: at ONE instant (a single `now` from the injected
// clock, so no goroutine can earn a refill), exactly `burst` admissions succeed,
// no matter how many goroutines contend for them. The bucket is deliberately
// drained through zero, so a lock that let a pair double-spend would push the
// count past burst and fail the deterministic bound.
func TestTheConcurrentAdmissionBudgetIsNotOverspent(t *testing.T) {
	const burst = 37
	b := newBucket(1000, burst)

	var allowed atomic.Int64
	const workers, per = 16, 50000
	now := time.Unix(1_700_000_000, 0) // fixed: no refill can accrue

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if b.allow(now) {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	if got := allowed.Load(); got != burst {
		t.Fatalf("at a fixed instant %d concurrent spenders drained %d admissions from a burst of %d; "+
			"the gateway-wide budget was overspent (or never metered)", workers*per, got, burst)
	}

	// And a single further call at the SAME instant must not refill: the clock
	// did not move, so the budget is still spent.
	if b.allow(now) {
		t.Fatal("a fixed-instant call after the burst drained the bucket refilled it")
	}
}

// TestTheConcurrentPerSourceBudgetIsolation.
//
// The per-source structure exists so one loud source cannot consume the
// gateway-wide budget for everyone else. Under concurrency the invariant is the
// same as the single-threaded case: the loud source is capped by its own cell's
// burst while a distinct source, at the same instant, still gets its own full
// budget and is not starved. A per-cell lock that leaked (or a design that
// serialised every source onto one counter) would break one of the two halves.
func TestTheConcurrentPerSourceBudgetIsolation(t *testing.T) {
	g := newSourceGuard(4096, 5, 5)
	now := time.Unix(1_700_000_000, 0) // fixed instant, no refill

	const workers, per = 16, 20000
	loudSrc, quietSrc := []byte("the-loud-concurrent-source"), []byte("the-quiet-concurrent-source")

	var loud, quiet atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if g.allow(loudSrc, now) {
					loud.Add(1)
				}
				if g.allow(quietSrc, now) {
					quiet.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	// The loud source, hammered by every worker, may draw at most its 5-token
	// cell — never the workers*per admissions its raw attempt count implies.
	if got := loud.Load(); got > 5 {
		t.Fatalf("one source drew %d admissions at a fixed instant from a 5-token cell", got)
	}

	// The quiet source, contended with all of them, still gets its own full 5:
	// it was not starved by the loud one.
	if got := quiet.Load(); got != 5 {
		t.Fatalf("a distinct source got %d admissions alongside a loud flood, want its own full 5; "+
			"the per-source meter is not isolated", got)
	}
}

// TestTokenDerivationIsDeterministicUnderConcurrency.
//
// token.go's TokenSource contract says an implementation must be deterministic
// and safe for concurrent use: the table calls TokenAt for the same counter more
// than once and requires the same answer both times. KeyedSource is immutable,
// but immutability is a claim until a concurrency test watches many goroutines
// derive the same counters at once and demands they all agree with a
// single-threaded reference — a data race on the (nominally read-only) pad
// arrays would mint wrong tokens without any panic, and a bad token is a
// silently dropped packet on the gateway's hot path.
func TestTokenDerivationIsDeterministicUnderConcurrency(t *testing.T) {
	ks := NewKeyedSource(keyFor(77))

	const n = 2000
	ref := make(map[uint64]Token, n)
	for c := uint64(0); c < n; c++ {
		ref[c] = ks.TokenAt(c)
	}

	var mismatches atomic.Int64
	const workers = 16
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := uint64(0); c < n; c++ {
				if got := ks.TokenAt(c); got != ref[c] {
					mismatches.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	if got := mismatches.Load(); got != 0 {
		t.Fatalf("%d of %d concurrent derivations disagreed with the single-threaded reference; "+
			"KeyedSource.TokenAt is not deterministic under concurrency", got, n*workers)
	}
}

// TestGuardRefillIsAtomicUnderConcurrentAccess.
//
// The two fixed-instant tests above pin the hard cap: at a single `now` no refill
// can accrue, so exactly a burst's worth of admissions succeed. They leave the
// refill path itself untested under concurrency. Spend and refill ride the same
// lock, but they are different code: a lock that correctly serialised spend could
// still double-credit a refill the moment the clock advances — two goroutines
// read the same `last`, each accrue the same delta, and each spend a token that
// refill funded only once. That double-credit is exactly what a broken lock looks
// like on a moving clock, and it is invisible to a test that never moves the
// clock.
//
// The bound asserted here is deterministic and independent of how the scheduler
// interleaves the goroutines: the total number of admissions a bucket can hand
// out over the whole run can never exceed its initial burst plus the integral of
// the refill rate over the simulated elapsed time. Simulated time only ever moves
// forward (each worker advances a shared counter before deriving its instant), so
// the credited refill telescopes to at most rate * (max instant − 1) seconds, and
// every one of those terms is a constant in the test — no wall-clock timing
// enters the assertion, so it cannot flake as the load varies. A regression that
// dropped the lock fails this test two ways at once: `-race` flags the concurrent
// read/write on `toks`/`last`, and the double-credit pushes allowed past the
// metered ceiling.
func TestGuardRefillIsAtomicUnderConcurrentAccess(t *testing.T) {
	const burst = 7
	const rate = 5.0 // tokens per second
	const step = time.Second
	b := newBucket(int(rate), burst)

	const workers, per = 16, 20000
	base := time.Unix(1_700_000_000, 0)

	var inst atomic.Int64
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				n := inst.Add(1)
				if b.allow(base.Add(time.Duration(n) * step)) {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	// Total simulated elapsed is bounded by the last instant ever handed out, and
	// the bucket caps at its burst, so the metered ceiling on admissions is the
	// starting burst plus at most rate * elapsed (the +1 pads for the first call,
	// which refills from an empty `last` to the full burst). A double-credit on
	// the refill path breaks this ceiling no matter how the run interleaved.
	maxInst := inst.Load()
	ceiling := int64(burst) + int64(rate*float64(maxInst+1))
	if got := allowed.Load(); got > ceiling {
		t.Fatalf("%d concurrent refill-spend cycles handed out %d admissions from a burst of %d at "+
			"%.0f/s over %d simulated seconds, exceeding the metered ceiling %d; the refill path double-credited",
			workers*per, got, burst, rate, maxInst, ceiling)
	}
}

// TestGuardSourceCellsRefillAtomicallyAndStayIsolatedUnderConcurrency.
//
// The gateway shapes its admission meter as two objects — a gateway-wide bucket
// and a per-source guard of fixed cells — and the concurrency guarantee has to
// hold on both. Everything that rides on a single bucket (the fixed-instant cap
// and the refill path) is already pinned by the tests above. What they do not
// cover is the per-source structure under a MOVING clock: the cells each carry
// their own bucket and their own lock, and it is those locks, exercised from
// many goroutines on many distinct sources at once, that this test drives.
//
// The bound is deterministic and scheduler-independent, so it cannot flake as
// load varies: total admissions a source can be handed over the whole run can
// never exceed its cell's starting burst plus the integral of the refill rate
// over the simulated elapsed time. Each call advances a shared atomic counter
// before deriving its `now`, so simulated time only ever moves forward and the
// credited refill telescopes to at most rate * (max instant - 1) seconds. The
// cell table is 2^16 entries with only a handful of distinct sources, so each
// source is effectively the sole occupant of its own cell and the ceiling below
// is binding, not a loose statistical bound.
//
// A regression that dropped a cell's lock fails this test two ways: -race flags
// the concurrent read/write on that cell's `toks`/`last` directly, and the
// resulting double-spend or double-credit pushes a source past its metered
// ceiling even if the interleaving never trips the race detector.
func TestGuardSourceCellsRefillAtomicallyAndStayIsolatedUnderConcurrency(t *testing.T) {
	const cells, rate, burst = 1 << 16, 1000, 40
	g := newSourceGuard(cells, rate, burst)
	base := time.Unix(1_700_000_000, 0)
	const step = time.Millisecond

	const nSrc = 16
	srcs := make([][]byte, nSrc)
	for s := range srcs {
		srcs[s] = []byte(fmt.Sprintf("guard-concurrency-source-%02d", s))
	}

	var inst atomic.Int64
	var counts [nSrc]atomic.Int64
	const workers, per = 16, 4000
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				n := inst.Add(1)
				now := base.Add(time.Duration(n) * step)
				for s := range srcs {
					if g.allow(srcs[s], now) {
						counts[s].Add(1)
					}
				}
			}
		}()
	}
	wg.Wait()

	maxInst := inst.Load()
	elapsed := time.Duration(maxInst) * step
	ceiling := int64(burst) + int64(rate*elapsed.Seconds()) + 2
	for s := 0; s < nSrc; s++ {
		if got := counts[s].Load(); got > ceiling {
			t.Fatalf("source %q was handed %d admissions over %s from a %d-token cell at %d/s, "+
				"past its metered ceiling %d; a per-cell lock leaked or the refill double-credited",
				srcs[s], got, elapsed, burst, rate, ceiling)
		}
	}
}
