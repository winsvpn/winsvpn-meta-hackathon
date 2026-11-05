package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConcurrentDispatchRegistrationAndEviction.
//
// A gateway is a machine that does all three of these at once, on every core it
// has, forever. Under -race this is the test that says the lock order in
// table.go is the lock order the code actually takes; without it, the shard and
// entry locks are a claim in a comment.
func TestConcurrentDispatchRegistrationAndEviction(t *testing.T) {
	cfg := Config{
		InitialWindow:        16,
		MaxWindow:            128,
		MaxSessions:          256,
		MaxSessionsPerClient: 256,
		IdleTimeout:          time.Millisecond,
		Now:                  func() time.Time { return fixedNow },
	}
	tbl := testTable(t, cfg)

	// Two clocks, and the gap between them is what makes this test deterministic.
	//
	// The sweeper evicts at fixedNow+1s against a 1ms IdleTimeout, so its cutoff
	// is fixedNow+999ms: ANY entry whose lastSeen is fixedNow is doomed. That
	// used to include the steady-state sessions, because registerFake registers
	// at fixedNow and the readers dispatched at fixedNow too — and lastSeen
	// "moves only when a message OPENS" (entry.go:40), so a reader could not
	// hold its own session alive against a horizon a full second ahead of it.
	// Every steady session was therefore evicted almost immediately, every
	// subsequent Dispatch missed, `routed` stayed 0, and the "the test did
	// nothing" guard fired. On a quiet machine the readers simply got a few
	// hits in before the sweeper's first pass won the race; under load they did
	// not. The flake was scheduling deciding a race the clocks had already lost.
	//
	// Putting the readers' traffic ABOVE the sweeper's cutoff removes the race
	// rather than widening the window on it: the steady sessions are provably
	// immortal and the churn sessions are provably doomed, so all three
	// activities — dispatch, registration, eviction — genuinely overlap on
	// every run instead of on lucky ones. That overlap is the whole point; this
	// is the -race test that proves table.go's lock order is the order the code
	// actually takes.
	trafficNow := fixedNow.Add(2 * time.Second)

	const steady = 24
	fakes := make([]*fakeSession, steady)
	for i := 0; i < steady; i++ {
		_, fakes[i] = registerFake(t, tbl, i)
		// Prime lastSeen to the readers' clock. registerFake stamps fixedNow,
		// which is below the sweeper's cutoff, so without this the sweeper
		// could still take all 24 before the first reader is scheduled.
		if _, _, err := tbl.Dispatch(fakes[i].message(0), trafficNow); err != nil {
			t.Fatalf("priming steady session %d: %v", i, err)
		}
	}

	var wg sync.WaitGroup
	var routed, churned, swept atomic.Int64
	stop := make(chan struct{})

	// Readers: the datapath.
	for g := 0; g < 8; g++ {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := fakes[g%steady]
			// c starts at 1 because counter 0 was spent priming lastSeen above.
			for c := uint64(1); ; c++ {
				select {
				case <-stop:
					return
				default:
				}
				if _, _, err := tbl.Dispatch(f.message(c), trafficNow); err == nil {
					routed.Add(1)
				}
				// Noise from a peer nobody can authenticate, on the same path.
				// It must NOT hold the session alive: lastSeen moves only when a
				// message opens, and that is a DoS property, not an accident.
				tbl.Dispatch(f.message(c^0xDEADBEEF), trafficNow) //nolint:errcheck
			}
		}()
	}

	// Writers: handshakes completing and sessions leaving.
	for g := 0; g < 4; g++ {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				f, src := newFake(1000 + g*1000 + i%97)
				e, err := tbl.Register(f, src, clientKey(1000+g), fixedNow)
				if err != nil {
					continue
				}
				churned.Add(1)
				tbl.Dispatch(f.message(0), fixedNow) //nolint:errcheck
				if i%3 == 0 {
					tbl.Remove(e)
				}
				// A ratchet arriving while a sweeper may be retiring the same
				// entry. Either outcome is correct; a data race is not, and
				// that is what -race is here to say.
				e.Rekeyed(NewKeyedSource(keyFor(7777 + i))) //nolint:errcheck
			}
		}()
	}

	// A sweeper, and a reader of the counters an operator would be watching.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			swept.Add(int64(tbl.EvictIdle(fixedNow.Add(time.Second))))
			_ = tbl.Stats()
			_ = tbl.MapEntries()
		}
	}()

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	if routed.Load() == 0 || churned.Load() == 0 {
		t.Fatalf("the test did nothing: %d routed, %d registered", routed.Load(), churned.Load())
	}
	// The third leg. Dispatch and registration were already guarded above;
	// eviction was not, and it is the one the two clocks could silently switch
	// off — raise the sweeper's horizon or lower the churn writers' and the
	// doomed set is empty on every pass, leaving a test that still routes,
	// still churns, still passes, and no longer overlaps a sweeper with either.
	// That is the same vacuous shape the guard above exists to prevent, so it
	// gets the same treatment.
	//
	// This counts what THE SWEEPER returned, not Stats().Evicted. The first
	// version of this guard read Stats().Evicted and was vacuous: admission
	// also evicts to make room (DisableEvictOnAdmit defaults to eviction on),
	// so the counter stays non-zero with the sweeper disabled entirely. A
	// mutant that moved the sweeper's horizon an hour into the past survived
	// it. EvictIdle's own return value is the only number that isolates this
	// goroutine.
	if swept.Load() == 0 {
		t.Fatalf("the sweeper reclaimed nothing across %d dispatches: eviction never raced the datapath", routed.Load())
	}
	// The accounting has to survive all of that: never negative, never above
	// the budget, and never more live map entries than reserved capacity.
	s := tbl.Stats()
	if s.IndexedTokens < 0 || s.IndexedTokens > s.TokenBudget {
		t.Fatalf("reserved capacity %d is outside 0..%d after the churn", s.IndexedTokens, s.TokenBudget)
	}
	if got := tbl.MapEntries(); got > s.IndexedTokens {
		t.Fatalf("%d live index entries against %d reserved tokens", got, s.IndexedTokens)
	}
	tbl.Close()
	if got := tbl.MapEntries(); got != 0 {
		t.Fatalf("%d tokens survived Close after concurrent churn", got)
	}
	if got := tbl.IndexedTokens(); got != 0 {
		t.Fatalf("reserved capacity is %d after Close", got)
	}
}

// TestTheDatapathSourceHoldsNoSocketNoTimerAndNoLog.
//
// The core package pins the same property for itself and the reasoning carries:
// a timer in here is a timer nobody can make deterministic, a socket in here is
// a socket the carrier does not control, and a log line in here is a per-packet
// side effect on a path a censor can drive. Time enters this package as a
// parameter and leaves as a comparison.
func TestTheDatapathSourceHoldsNoSocketNoTimerAndNoLog(t *testing.T) {
	forbidden := []string{
		"net.", "os.", "log.", "fmt.Print",
		"time.After", "time.Tick", "time.NewTimer", "time.NewTicker", "time.Sleep",
		"go func", "rand.",
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, line := range strings.Split(string(b), "\n") {
			code := line
			if i := strings.Index(code, "//"); i >= 0 {
				code = code[:i]
			}
			for _, bad := range forbidden {
				if strings.Contains(code, bad) {
					t.Errorf("%s contains %q: %s", f, bad, strings.TrimSpace(line))
				}
			}
		}
	}
	if checked < 5 {
		t.Fatalf("only %d source files were scanned; the glob is wrong and this test is passing for free", checked)
	}
	// time.Now itself is allowed in exactly one place — the injected clock's
	// fallback — and nowhere else.
	if n := countInCode(t, "params.go", "time.Now"); n != 1 {
		t.Fatalf("params.go calls time.Now %d times, want exactly the one fallback", n)
	}
	for _, f := range []string{"table.go", "entry.go", "gateway.go", "guard.go", "token.go"} {
		if countInCode(t, f, "time.Now") != 0 {
			t.Errorf("%s reaches for the wall clock; every entry point must take time as a parameter", f)
		}
	}
	// The scan must be capable of objecting, or it is decorative.
	if countInCode(t, "params.go", "func (c Config) clock") != 1 {
		t.Fatal("the source scan cannot find a construct it should; its comment stripping is broken")
	}
}

// countInCode counts occurrences outside comments.
func countInCode(t *testing.T, file, needle string) int {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		n += strings.Count(line, needle)
	}
	return n
}

// TestTheIndexIsSpreadAcrossItsShards.
//
// Sharding is not a correctness property — a table with one shard routes every
// packet to the right session — so nothing else in this file would notice if the
// shard index stopped depending on the token. What it would cost is the whole
// point of having shards: one lock in front of the gateway's hottest structure,
// taken by every arriving datagram on every core. This pins the spread, so a
// regression there is a test failure rather than a mystery at scale.
func TestTheIndexIsSpreadAcrossItsShards(t *testing.T) {
	// Half the sessions and half the shards keep the SAME per-shard expected
	// load (1024 tokens/shard) and therefore the same statistics as the original
	// 256x256x64 shape, at a quarter of the publishes — the 4-sigma band is what
	// protects the assertion, and it is unchanged. The race instrumenter makes
	// every derive count twice.
	const sessions, window = 128, 256
	cfg := Config{
		InitialWindow:        window,
		MaxWindow:            window,
		MaxSessions:          sessions,
		MaxSessionsPerClient: sessions,
		Shards:               32,
		Now:                  func() time.Time { return fixedNow },
	}
	tbl := testTable(t, cfg)
	for i := 0; i < sessions; i++ {
		registerFake(t, tbl, i)
	}

	total := sessions * window
	expected := float64(total) / float64(len(tbl.shards))
	lo, hi := expected*0.85, expected*1.15
	for i := range tbl.shards {
		n := float64(len(tbl.shards[i].m))
		if n < lo || n > hi {
			t.Fatalf("shard %d holds %.0f of %d tokens; an even spread is %.0f "+
				"(a shard index that ignores the token puts everything in one place)",
				i, n, total, expected)
		}
	}

	// And each session's own window is spread too, so no single session's
	// traffic serialises on one lock.
	_, f := registerFake(t, tbl, 9999)
	seen := map[*shard]bool{}
	for c := uint64(0); c < window; c++ {
		seen[tbl.shardFor(f.src.TokenAt(c))] = true
	}
	if len(seen) < len(tbl.shards)/2 {
		t.Fatalf("one session's %d-token window lands in only %d of %d shards",
			window, len(seen), len(tbl.shards))
	}
}
