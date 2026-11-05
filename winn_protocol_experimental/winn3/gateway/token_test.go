package gateway

import (
	"encoding/hex"
	"math"
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

func katKey() *[core.KeySize]byte {
	var k [core.KeySize]byte
	for i := range k {
		k[i] = byte(i)
	}
	return &k
}

// TestDeriveTokenIsThePinnedConstruction pins the exact derivation.
//
// This package computes demux tokens itself because core does not export the
// function that computes them, so there are now two implementations of one
// construction in the tree and nothing but a test standing between them. These
// vectors are that test. Every one of them changes if the label changes, if the
// counter encoding changes from big-endian, if the truncation moves, or if the
// label and counter are concatenated in the other order — which is to say, for
// every plausible way the two copies could drift apart.
func TestDeriveTokenIsThePinnedConstruction(t *testing.T) {
	vectors := []struct {
		counter uint64
		want    string
	}{
		{0, "8f14566e5d841520"},
		{1, "9286fe09d0ef3c33"},
		{255, "a36a1b9f32bfa82e"},
		{1 << 32, "1a80d2b5d60520ce"},
		{1<<64 - 1, "0a18f1feac4d2a43"},
	}
	k := katKey()
	for _, v := range vectors {
		got := DeriveToken(k, v.counter)
		if hex.EncodeToString(got[:]) != v.want {
			t.Errorf("DeriveToken(counter=%d) = %s, want %s", v.counter, hex.EncodeToString(got[:]), v.want)
		}
	}
}

// TestKeyedSourceAssumesTheDemuxKeyFitsOneHMACBlock is the runtime twin of
// keyedSourceKeyFitsHMACBlock. The compile-time array does not compile if
// KeySize exceeds the HMAC block; this test names the same fact so a reader
// of the suite sees it without opening token.go.
func TestKeyedSourceAssumesTheDemuxKeyFitsOneHMACBlock(t *testing.T) {
	if core.KeySize > blockSize {
		t.Fatalf("KeySize=%d exceeds HMAC block %d; TokenAt would silently disagree with DeriveToken on every counter",
			core.KeySize, blockSize)
	}
}

// TestTokenSizeMatchesTheWireFormat guards the one number that ties this
// package to the wire: a token IS the transport header, all eight bytes of it.
func TestTokenSizeMatchesTheWireFormat(t *testing.T) {
	if len(Token{}) != core.DemuxTokenSize {
		t.Fatalf("Token is %d bytes, the wire says %d", len(Token{}), core.DemuxTokenSize)
	}
	if core.DemuxTokenSize != 8 {
		t.Fatalf("the whole collision analysis assumes a 64-bit token; core says %d bytes", core.DemuxTokenSize)
	}
}

// TestDeriveTokenSeparatesEveryInput checks the two separations the table's
// correctness rests on: two counters under one key differ, and one counter
// under two keys differs. A derivation that ignored the counter would still
// pass a naive round-trip test and would silently make every session's window a
// single token.
func TestDeriveTokenSeparatesEveryInput(t *testing.T) {
	k := katKey()
	seen := map[Token]uint64{}
	for c := uint64(0); c < 4096; c++ {
		tok := DeriveToken(k, c)
		if prev, dup := seen[tok]; dup {
			t.Fatalf("counters %d and %d derive the same token", prev, c)
		}
		seen[tok] = c
	}

	var k2 [core.KeySize]byte
	copy(k2[:], k[:])
	k2[31] ^= 1
	for c := uint64(0); c < 256; c++ {
		if DeriveToken(k, c) == DeriveToken(&k2, c) {
			t.Fatalf("a one-bit key change left counter %d's token unchanged", c)
		}
	}
}

// TestKeyedSourceCopiesItsKey. A source that aliased the caller's key would
// re-key every session the moment the caller zeroed its own copy, which is
// exactly what a careful caller does.
func TestKeyedSourceCopiesItsKey(t *testing.T) {
	k := katKey()
	src := NewKeyedSource(k)
	before := src.TokenAt(7)
	for i := range k {
		k[i] = 0
	}
	if src.TokenAt(7) != before {
		t.Fatal("KeyedSource aliased the caller's key instead of copying it")
	}
	if src.TokenAt(7) != DeriveToken(katKey(), 7) {
		t.Fatal("KeyedSource does not agree with DeriveToken")
	}
}

// TestTokenLeadingByteIsUniform checks the assumption the shard index rests on.
//
// The table shards on the leading byte with no hashing at all, which is free and
// exactly uniform *because a token is a PRF output*. If that ever stopped being
// true — a different truncation, a counter leaking into the top byte — one shard
// would carry the load of many and the lock it protects would become the
// gateway's ceiling. A chi-square over 256 buckets catches that; the threshold
// is the 1-in-10^6 tail for 255 degrees of freedom, so this does not flake.
func TestTokenLeadingByteIsUniform(t *testing.T) {
	// The chi-square statistic has a fixed number of degrees of freedom (255),
	// so its threshold does not scale with the sample: 32768 tokens mean an
	// expected 128 per bucket, well past the ~5 that keeps the approximation
	// honest, and the 1-in-10^6 tail is as 1-in-10^6 here as it was at 262144.
	// The smaller sample is what keeps the race-instrumented suite inside its
	// wall-clock budget; the skewed control below scales with it and stays far
	// past the threshold.
	const n = 32768
	k := katKey()
	var counts [256]int
	for c := uint64(0); c < n; c++ {
		counts[DeriveToken(k, c)[0]]++
	}
	expected := float64(n) / 256
	chi := 0.0
	for _, got := range counts {
		d := float64(got) - expected
		chi += d * d / expected
	}
	if chi > 400 {
		t.Fatalf("leading-byte distribution is not uniform: chi-square %.1f over 256 buckets", chi)
	}
	// And the same test must be capable of objecting. A deliberately skewed
	// generator has to fail it, or the threshold above is decorative. The skew
	// empties five buckets entirely, contributing ~5*(n/256) on its own — at
	// this sample that is ~640 against a 400 threshold, deterministic because
	// the skew itself is deterministic.
	var skewed [256]int
	for c := 0; c < n; c++ {
		skewed[c%251]++
	}
	skewChi := 0.0
	for _, got := range skewed {
		d := float64(got) - expected
		skewChi += d * d / expected
	}
	if skewChi <= 400 {
		t.Fatalf("the uniformity check cannot detect a skew it should: chi-square %.1f", skewChi)
	}
	if math.IsNaN(chi) {
		t.Fatal("chi-square is NaN")
	}
}

// TestTheFastPathAgreesWithTheObviousOne.
//
// KeyedSource does HMAC by hand so that it allocates nothing on a path every
// packet takes. Hand-rolled HMAC is exactly the kind of thing that is right for
// the first thousand inputs and wrong at a block boundary, so this checks it
// against crypto/hmac over a long run of counters, at several key shapes, and
// at the counter extremes.
func TestTheFastPathAgreesWithTheObviousOne(t *testing.T) {
	keys := []*[core.KeySize]byte{katKey(), keyFor(0), keyFor(1), keyFor(255), {}}
	all := keys[len(keys)-1]
	for i := range all {
		all[i] = 0xFF
	}
	for ki, k := range keys {
		src := NewKeyedSource(k)
		for _, c := range []uint64{0, 1, 2, 63, 64, 65, 127, 128, 255, 256,
			1<<31 - 1, 1 << 31, 1<<32 - 1, 1 << 32, 1<<63 - 1, 1<<64 - 1} {
			if got, want := src.TokenAt(c), DeriveToken(k, c); got != want {
				t.Fatalf("key %d counter %d: fast path %x, crypto/hmac %x", ki, c, got, want)
			}
		}
		for c := uint64(0); c < 3000; c++ {
			if src.TokenAt(c) != DeriveToken(k, c) {
				t.Fatalf("key %d: the two implementations diverge at counter %d", ki, c)
			}
		}
	}
}

// TestTokenDerivationAllocatesNothing. The table calls TokenAt twice for every
// datagram that opens; an allocation here is an allocation on every packet of
// every session on the gateway.
func TestTokenDerivationAllocatesNothing(t *testing.T) {
	src := NewKeyedSource(katKey())
	var sink Token
	if allocs := testing.AllocsPerRun(5000, func() {
		sink = src.TokenAt(12345)
	}); allocs != 0 {
		t.Fatalf("TokenAt allocated %.2f objects per call", allocs)
	}
	if sink != DeriveToken(katKey(), 12345) {
		t.Fatal("the measured call did not produce the right token")
	}
}

// TestGatewayTokenIsSingleUseAgainstDoubleSpend pins the single-use contract
// from the spend side, the way a wallet would: a demux token that has been
// spent once must not spend again. The double-spend is the same byte-identical
// datagram arriving twice. The first copy routes; every later copy must be a
// Miss, absorbed by the index and never reaching the session's crypto — which
// is exactly what erasing a token on consumption buys, and what would survive
// only as an OpenFailed (a more expensive rejection) if the erase were dropped.
func TestGatewayTokenIsSingleUseAgainstDoubleSpend(t *testing.T) {
	tbl := testTable(t, smallCfg())
	_, f := registerFake(t, tbl, 1)

	if !deliver(t, tbl, f, 2) {
		t.Fatal("the first copy of a token should route: it is the only spend")
	}
	if _, _, ok := tbl.Lookup(f.src.TokenAt(2)); ok {
		t.Fatal("a spent token is still indexed; the double-spend can route again")
	}

	before := f.openCalls()
	for i := 0; i < 3; i++ {
		if deliver(t, tbl, f, 2) {
			t.Fatal("a double-spend of a consumed token routed")
		}
	}
	if f.openCalls() != before {
		t.Fatalf("a double-spend reached the session's crypto %d times; the index must absorb it",
			f.openCalls()-before)
	}

	s := tbl.Stats()
	if s.Dispatched != 1 {
		t.Fatalf("Dispatched=%d, want 1: only the genuine first copy may be delivered", s.Dispatched)
	}
	if s.Missed < 3 {
		t.Fatalf("Missed=%d, want at least 3 (one per double-spend replay): a double-spend must be a Miss", s.Missed)
	}
	if s.OpenFailed != 0 {
		t.Fatalf("OpenFailed=%d, want 0: a double-spend absorbed by the index must never reach the AEAD", s.OpenFailed)
	}
}
