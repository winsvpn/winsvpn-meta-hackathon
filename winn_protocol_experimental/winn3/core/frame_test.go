package core

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf []byte
	want := []struct {
		typ FrameType
		val []byte
	}{
		{FrameData, []byte("an inner ip packet")},
		{FramePing, nil},
		{FramePad, bytes.Repeat([]byte{0}, 40)},
		{FrameRekeyInit, bytes.Repeat([]byte{0xAB}, KeySize)},
		{FrameClose, []byte{1}},
	}
	var err error
	for _, w := range want {
		buf, err = AppendFrame(buf, w.typ, w.val)
		if err != nil {
			t.Fatalf("append %v: %v", w.typ, err)
		}
	}

	got, err := ParseFrames(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d frames, expected %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Type != w.typ {
			t.Fatalf("frame %d type is %d, expected %d", i, got[i].Type, w.typ)
		}
		if !bytes.Equal(got[i].Value, w.val) {
			t.Fatalf("frame %d value mismatch", i)
		}
	}
}

func TestParseFramesEmpty(t *testing.T) {
	got, err := ParseFrames(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no frames, got %d", len(got))
	}
}

// TestParseFramesIsStrict: leniency here would be a parsing differential
// between implementations, and a parsing differential is a fingerprint.
func TestParseFramesIsStrict(t *testing.T) {
	good, err := AppendFrame(nil, FrameData, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"trailing partial header": append(append([]byte(nil), good...), 0x01, 0x02),
		"reserved type zero":      {0x00, 0x00, 0x00},
		"length past the buffer":  {byte(FrameData), 0xFF, 0xFF, 0x01},
		"zero-filled buffer":      make([]byte, 16),
	}
	for name, b := range cases {
		if _, err := ParseFrames(b); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: expected a decode error, got %v", name, err)
		}
	}
}

func TestAppendFrameRejects(t *testing.T) {
	if _, err := AppendFrame(nil, 0, nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("frame type 0 must be refused, got %v", err)
	}
	if _, err := AppendFrame(nil, FrameData, make([]byte, MaxFrameValue+1)); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
	}
}

// --- token window -----------------------------------------------------------

func TestTokenWindowBasics(t *testing.T) {
	var key [KeySize]byte
	copy(key[:], bytes.Repeat([]byte{0x5A}, KeySize))
	w := newTokenWindow(&key, 16)

	if w.live() != 16 {
		t.Fatalf("a fresh window holds %d tokens, expected 16", w.live())
	}
	tok := demuxToken(&key, 0)
	c, ok := w.lookup(tok[:])
	if !ok || c != 0 {
		t.Fatalf("lookup of counter 0 returned (%d,%v)", c, ok)
	}
	if _, ok := w.lookup([]byte{1, 2, 3}); ok {
		t.Fatal("a wrong-length token must not match")
	}
	unknown := demuxToken(&key, 9999)
	if _, ok := w.lookup(unknown[:]); ok {
		t.Fatal("a counter far outside the window must not match")
	}

	// Consuming the low edge slides the window by exactly one.
	w.consume(0)
	if _, ok := w.lookup(tok[:]); ok {
		t.Fatal("a consumed token must be erased")
	}
	next := demuxToken(&key, 16)
	if c, ok := w.lookup(next[:]); !ok || c != 16 {
		t.Fatal("the window did not admit a new counter at the high edge")
	}
	if w.live() != 16 {
		t.Fatalf("window holds %d tokens after a slide, expected 16", w.live())
	}
}

func TestTokenWindowOutOfRangeConsumeIsIgnored(t *testing.T) {
	var key [KeySize]byte
	w := newTokenWindow(&key, 16)
	before := w.live()
	w.consume(1000)
	w.consume(^uint64(0))
	if w.live() != before {
		t.Fatal("consuming an out-of-range counter changed the window")
	}
}

// TestTokenWindowForcedAdvance: a counter half a window ahead forces the low
// edge forward, which is what guarantees progress when a packet at the low edge
// is lost forever.
//
// Note the arithmetic below rather than the phrase "half a window": consuming 12
// at a 16-token window retires the low edge to 12 − 8 + 1 = 5, so the surviving
// displacement is `size/2 − 1` and not `size/2`. The netlab lane swept the
// boundary at a 256-token window and measured a hard cliff at 127/128.
func TestTokenWindowForcedAdvance(t *testing.T) {
	var key [KeySize]byte
	w := newTokenWindow(&key, 16)

	w.consume(12) // >= low + 8, so it forces low to 12 - 8 + 1 = 5
	if w.low != 5 {
		t.Fatalf("low edge is %d, expected 5", w.low)
	}
	old := demuxToken(&key, 0)
	if _, ok := w.lookup(old[:]); ok {
		t.Fatal("a counter behind the forced low edge must be gone")
	}
	if w.live() != 15 {
		// 16 slots minus the one just consumed at 12
		t.Fatalf("window holds %d tokens, expected 15", w.live())
	}
}

func TestTokenWindowContiguousDrain(t *testing.T) {
	var key [KeySize]byte
	w := newTokenWindow(&key, 32)
	for c := uint64(0); c < 1000; c++ {
		tok := demuxToken(&key, c)
		got, ok := w.lookup(tok[:])
		if !ok {
			t.Fatalf("counter %d fell out of the window", c)
		}
		if got != c {
			t.Fatalf("token for %d mapped to %d", c, got)
		}
		w.consume(c)
		if _, ok := w.lookup(tok[:]); ok {
			t.Fatalf("counter %d was not retired", c)
		}
	}
}

// --- replay cache -----------------------------------------------------------

// mustReplayCache builds a cache with a lifetime the test asserts is valid.
// newReplayCache refuses a non-positive lifetime; the refusal itself is
// TestTheReplayCacheRefusesALifetimeItCannotHonour in invariants_test.go.
func mustReplayCache(t *testing.T, lifetime time.Duration) *replayCache {
	t.Helper()
	c, err := newReplayCache(lifetime)
	if err != nil {
		t.Fatalf("newReplayCache(%s): %v", lifetime, err)
	}
	return c
}

func TestReplayCacheExpiry(t *testing.T) {
	c := mustReplayCache(t, 30*time.Second)
	var k [32]byte
	k[0] = 1
	base := fixedNow

	if c.seen(k, base) {
		t.Fatal("an empty cache reported a hit")
	}
	if err := c.remember(k, base); err != nil {
		t.Fatal(err)
	}
	if !c.seen(k, base.Add(time.Second)) {
		t.Fatal("a fresh entry was not seen")
	}
	if c.seen(k, base.Add(time.Hour)) {
		t.Fatal("an expired entry is still reported")
	}
}

// TestReplayCacheDefaultLifetime is gone deliberately. It asserted that a zero
// lifetime was silently replaced with 2*DefaultMaxSkew — a constant with no
// relationship to the acceptance window the cache has to cover. That
// substitution is now a construction-time refusal, and what replaces this test
// is TestTheReplayCacheRefusesALifetimeItCannotHonour in invariants_test.go,
// which asserts the refusal AND the reason it matters.

func TestReplayCacheIsBounded(t *testing.T) {
	c := mustReplayCache(t, time.Hour)
	now := fixedNow
	refused := 0
	for i := 0; i < maxReplayEntries+maxReplayEntries/4; i++ {
		var k [32]byte
		k[0] = byte(i)
		k[1] = byte(i >> 8)
		k[2] = byte(i >> 16)
		if err := c.remember(k, now); err != nil {
			if !errors.Is(err, ErrReplayJournal) {
				t.Fatal(err)
			}
			refused++
		}
	}
	if n := c.size(); n > maxReplayEntries {
		t.Fatalf("cache grew to %d entries, past the %d bound", n, maxReplayEntries)
	}
	if refused == 0 {
		t.Fatal("the bounded cache did not fail new admission closed at capacity")
	}
}

func TestBucketIndexFloorsTowardNegativeInfinity(t *testing.T) {
	w := 10 * time.Second
	cases := []struct {
		unix int64
		want int64
	}{
		{0, 0}, {9, 0}, {10, 1}, {-1, -1}, {-10, -1}, {-11, -2},
	}
	for _, tc := range cases {
		got := bucketIndex(time.Unix(tc.unix, 0), w)
		if got != tc.want {
			t.Errorf("bucketIndex(%d) = %d, want %d", tc.unix, got, tc.want)
		}
	}
}

func TestCandidateBucketsAreNearestFirst(t *testing.T) {
	got := candidateBuckets(100, 2)
	want := []int64{100, 99, 101, 98, 102}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
