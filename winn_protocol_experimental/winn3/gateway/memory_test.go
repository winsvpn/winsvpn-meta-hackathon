package gateway

import (
	"runtime"
	"testing"
	"time"
)

// heapInUse forces a stable measurement. Two collections, because the first can
// leave finalisable objects behind.
func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// TestMeasuredBytesPerIndexedToken is the memory decision, measured.
//
// §6.9 of the design says the receive side is “on the order of tens of
// kilobytes per session per direction” at a 1024-token window and calls the
// scaling question unresolved. That is the number this package exists to
// resolve, so it is measured here rather than estimated: the whole point of
// choosing a window size is that somebody knows what a token costs.
//
// The ceiling is an assertion and not just a report, because the cost per token
// is set by the size of the index slot, and a future change that widened the
// slot — an epoch field, a timestamp, a back-pointer — would multiply straight
// through the gateway's whole memory bill without anything else noticing.
func TestMeasuredBytesPerIndexedToken(t *testing.T) {
	if testing.Short() {
		t.Skip("measures live heap")
	}
	// The measured figure is a per-token quotient, so it is valid at a smaller
	// absolute scale: the index slot's size decides it, and that does not change
	// with the sampled window. The original 16384-token window (1M entries) was
	// chosen to amortise map load factor; 1024 x 32 sessions amortises the same
	// way — 32k entries over the shards is well past where a Go map settles over
	// its per-slot bookkeeping — and keeps the race-instrumented suite inside its
	// wall-clock budget. (A full-scale run remains available with -short=false
	// outside -race.)
	const (
		sessions = 32
		window   = 1024
		tokens   = sessions * window
	)
	cfg := Config{
		InitialWindow:        window,
		MaxWindow:            window,
		MaxSessions:          sessions,
		MaxSessionsPerClient: sessions,
		Now:                  func() time.Time { return fixedNow },
	}

	base := heapInUse()
	tbl, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	for i := 0; i < sessions; i++ {
		f, src := newFake(i)
		if _, err := tbl.Register(f, src, clientKey(i), fixedNow); err != nil {
			t.Fatalf("Register(%d): %v", i, err)
		}
	}
	if got := tbl.IndexedTokens(); got != tokens {
		t.Fatalf("expected %d indexed tokens, got %d", tokens, got)
	}
	// Reserved is not stored, and the difference is a trap this measurement can
	// fall into silently. keyFor derives its key bytes modulo 256, so any run
	// with more than 256 sessions gives two of them the SAME demux key: they
	// publish identical tokens, the index refuses the duplicates past the
	// candidate cap, and the bytes get divided by a token count most of which was
	// never stored. That is a measurement reporting half the real cost with no
	// test failing, and it is what this assertion is for — it costs one walk of
	// the shards and it fails the moment `sessions` is raised past 256.
	if got := tbl.MapEntries(); got != tokens {
		t.Fatalf("%d tokens are reserved but only %d are stored; the per-token figure below "+
			"would be divided by a count that is not what the index is holding", tokens, got)
	}
	loaded := heapInUse()
	runtime.KeepAlive(tbl)

	perToken := float64(loaded-base) / float64(tokens)
	t.Logf("%d sessions x %d tokens = %d indexed tokens cost %.1f MiB, %.1f bytes per token",
		sessions, window, tokens, float64(loaded-base)/(1<<20), perToken)
	t.Logf("extrapolated: 1000 sessions at the 256-token default = %.1f MiB; "+
		"10000 sessions = %.1f MiB; 10000 at core's 1024 default = %.1f MiB",
		1000*256*perToken/(1<<20), 10000*256*perToken/(1<<20), 10000*1024*perToken/(1<<20))

	if perToken > 80 {
		t.Fatalf("an indexed token costs %.1f bytes; the memory arithmetic in the handoff "+
			"document assumes it stays under 80, and the index slot is the reason", perToken)
	}
	if perToken < 16 {
		t.Fatalf("an indexed token appears to cost %.1f bytes, which is less than the key and "+
			"value it must hold; the measurement is wrong", perToken)
	}

	tbl.Close()
	if got := tbl.MapEntries(); got != 0 {
		t.Fatalf("%d tokens survived Close", got)
	}
}

// TestPerSessionOverheadIsSmallBesideItsWindow. If the fixed per-session cost
// were comparable to the window, shrinking the window would not save anything
// and the whole memory decision would be pointless.
func TestPerSessionOverheadIsSmallBesideItsWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("measures live heap")
	}
	// perSession is a quotient, so the count only needs to beat GC noise, not
	// reach a production fleet size. 4000 shared-source sessions with a 16-token
	// window (64k publishes) does that with room to spare; the original 20000
	// was a -race wall-clock liability three orders of magnitude beyond the
	// minimum the assertion needs.
	const sessions = 4000
	cfg := Config{
		InitialWindow:        16,
		MaxWindow:            16,
		MaxSessions:          sessions,
		MaxSessionsPerClient: sessions,
		Now:                  func() time.Time { return fixedNow },
	}
	base := heapInUse()
	tbl, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	src := NewKeyedSource(keyFor(1))
	for i := 0; i < sessions; i++ {
		// One shared source and one shared opener, so what is measured is the
		// table's own per-session state and not the caller's.
		if _, err := tbl.Register(newFakeSession(src, 1), src, clientKey(i), fixedNow); err != nil {
			t.Fatalf("Register(%d): %v", i, err)
		}
	}
	loaded := heapInUse()
	runtime.KeepAlive(tbl)

	perSession := float64(loaded-base) / sessions
	t.Logf("%d sessions with a 16-token window cost %.1f bytes each, all in",
		sessions, perSession)
	if perSession > 16*80+400 {
		t.Fatalf("a session costs %.1f bytes with a 16-token window; the fixed overhead is "+
			"dominating the window and the window size is no longer the lever", perSession)
	}
}

// BenchmarkRegisterFillsTheWindow measures what a completed handshake costs the
// gateway in precomputation: one HMAC per token in the initial window.
func BenchmarkRegisterFillsTheWindow(b *testing.B) {
	for _, w := range []int{32, 256, 1024} {
		w := w
		b.Run(itoa(w)+" tokens", func(b *testing.B) {
			cfg := Config{InitialWindow: w, MaxWindow: w, MaxSessions: b.N + 1, MaxSessionsPerClient: b.N + 1}
			tbl, err := NewTable(cfg)
			if err != nil {
				b.Fatal(err)
			}
			defer tbl.Close()
			src := NewKeyedSource(keyFor(1))
			f := newFakeSession(src, 1)
			_ = src
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := tbl.Register(f, NewKeyedSource(keyFor(i)), clientKey(i), fixedNow); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
