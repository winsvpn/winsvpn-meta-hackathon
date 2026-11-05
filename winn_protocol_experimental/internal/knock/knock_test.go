package knock

import (
	"bytes"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func testKey(t *testing.T, seed byte) []byte {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func TestBuildVerifyRoundTrip(t *testing.T) {
	key := testKey(t, 1)
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	packet, err := Build(key, 1200, now, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(packet) != 1200 {
		t.Fatalf("len(packet) = %d, want 1200", len(packet))
	}
	nonce, keyIndex, err := Verify(packet, [][]byte{key}, now, Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if keyIndex != 0 {
		t.Fatalf("keyIndex = %d, want 0", keyIndex)
	}
	if !bytes.Equal(nonce[:], packet[:NonceSize]) {
		t.Fatalf("returned nonce does not match the packet's nonce field")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	key := testKey(t, 1)
	wrong := testKey(t, 2)
	now := time.Now()
	packet, err := Build(key, 1200, now, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, _, err := Verify(packet, [][]byte{wrong}, now, Options{}); err == nil {
		t.Fatal("Verify succeeded against the wrong key")
	}
}

func TestVerifyAcceptsEitherKeyDuringRotation(t *testing.T) {
	oldKey := testKey(t, 1)
	newKey := testKey(t, 2)
	now := time.Now()

	oldPacket, err := Build(oldKey, 1200, now, Options{})
	if err != nil {
		t.Fatalf("Build(old): %v", err)
	}
	newPacket, err := Build(newKey, 1200, now, Options{})
	if err != nil {
		t.Fatalf("Build(new): %v", err)
	}

	// Server configured with [current, previous] during an overlap window.
	keys := [][]byte{newKey, oldKey}

	if _, keyIndex, err := Verify(oldPacket, keys, now, Options{}); err != nil {
		t.Fatalf("Verify(old packet): %v", err)
	} else if keyIndex != 1 {
		t.Fatalf("old packet matched keyIndex %d, want 1", keyIndex)
	}
	if _, keyIndex, err := Verify(newPacket, keys, now, Options{}); err != nil {
		t.Fatalf("Verify(new packet): %v", err)
	} else if keyIndex != 0 {
		t.Fatalf("new packet matched keyIndex %d, want 0", keyIndex)
	}
}

func TestVerifyRejectsTimestampBeyondSkew(t *testing.T) {
	key := testKey(t, 1)
	now := time.Now()
	opts := Options{BucketWindow: 10 * time.Second, MaxSkew: 60 * time.Second}
	packet, err := Build(key, 1200, now, opts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	future := now.Add(5 * time.Minute)
	if _, _, err := Verify(packet, [][]byte{key}, future, opts); err == nil {
		t.Fatal("Verify accepted a packet far outside the skew window")
	}
	past := now.Add(-5 * time.Minute)
	if _, _, err := Verify(packet, [][]byte{key}, past, opts); err == nil {
		t.Fatal("Verify accepted a packet far outside the skew window (past)")
	}
}

func TestVerifyAcceptsWithinSkewBoundary(t *testing.T) {
	key := testKey(t, 1)
	now := time.Now()
	opts := Options{BucketWindow: 10 * time.Second, MaxSkew: 60 * time.Second}
	packet, err := Build(key, 1200, now, opts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// Just inside the tolerated skew.
	nearFuture := now.Add(55 * time.Second)
	if _, _, err := Verify(packet, [][]byte{key}, nearFuture, opts); err != nil {
		t.Fatalf("Verify rejected a packet within the skew window: %v", err)
	}
	nearPast := now.Add(-55 * time.Second)
	if _, _, err := Verify(packet, [][]byte{key}, nearPast, opts); err != nil {
		t.Fatalf("Verify rejected a packet within the skew window (past): %v", err)
	}
}

func TestVerifyRejectsShortPacket(t *testing.T) {
	key := testKey(t, 1)
	now := time.Now()
	short := make([]byte, HeaderSize-1)
	if _, _, err := Verify(short, [][]byte{key}, now, Options{}); err != ErrPacketSize {
		t.Fatalf("Verify(short) err = %v, want ErrPacketSize", err)
	}
}

func TestVerifyRejectsTamperedTag(t *testing.T) {
	key := testKey(t, 1)
	now := time.Now()
	packet, err := Build(key, 1200, now, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	tampered := append([]byte(nil), packet...)
	tampered[NonceSize] ^= 0xFF // flip a bit inside the tag
	if _, _, err := Verify(tampered, [][]byte{key}, now, Options{}); err == nil {
		t.Fatal("Verify accepted a packet with a tampered tag")
	}
}

func TestVerifyAcceptsWhenOnlyPaddingIsTampered(t *testing.T) {
	// Padding carries no meaning and is not covered by the MAC by
	// construction, but flipping it must not change the nonce or tag bytes
	// the MAC does cover, and correspondingly must not change the verdict.
	// Named Accepts, not Rejects: the body requires Verify to succeed. The
	// previous name claimed the opposite of what it asserted.
	key := testKey(t, 1)
	now := time.Now()
	packet, err := Build(key, 1200, now, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	tampered := append([]byte(nil), packet...)
	tampered[HeaderSize] ^= 0xFF
	if _, _, err := Verify(tampered, [][]byte{key}, now, Options{}); err != nil {
		t.Fatalf("Verify rejected a packet with only padding tampered: %v", err)
	}
}

func TestBuildRejectsPacketSizeBelowHeader(t *testing.T) {
	key := testKey(t, 1)
	if _, err := Build(key, HeaderSize-1, time.Now(), Options{}); err == nil {
		t.Fatal("Build accepted a packetSize smaller than HeaderSize")
	}
}

func TestBuildRejectsShortKey(t *testing.T) {
	if _, err := Build([]byte("short"), 1200, time.Now(), Options{}); err == nil {
		t.Fatal("Build accepted a key shorter than minKeySize")
	}
}

func TestVerifyRejectsNoKeys(t *testing.T) {
	key := testKey(t, 1)
	packet, err := Build(key, 1200, time.Now(), Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, _, err := Verify(packet, nil, time.Now(), Options{}); err == nil {
		t.Fatal("Verify accepted with an empty key list")
	}
}

func TestOptionsRejectsExcessiveSkewToBucketRatio(t *testing.T) {
	key := testKey(t, 1)
	opts := Options{BucketWindow: time.Second, MaxSkew: time.Hour * 24 * 365}
	if _, err := Build(key, 1200, time.Now(), opts); err == nil {
		t.Fatal("Build accepted an Options combination requiring an unbounded number of time buckets")
	}
}

func TestOptionsRejectsSkewShorterThanBucketWindow(t *testing.T) {
	key := testKey(t, 1)
	opts := Options{BucketWindow: time.Minute, MaxSkew: time.Second}
	if _, err := Build(key, 1200, time.Now(), opts); err == nil {
		t.Fatal("Build accepted MaxSkew < BucketWindow")
	}
}

func TestBuildProducesDistinctNoncesAndPadding(t *testing.T) {
	key := testKey(t, 1)
	now := time.Now()
	first, err := Build(key, 1200, now, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	second, err := Build(key, 1200, now, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if bytes.Equal(first[:NonceSize], second[:NonceSize]) {
		t.Fatal("two Build calls at the same instant produced the same nonce")
	}
	if bytes.Equal(first, second) {
		t.Fatal("two Build calls produced byte-identical packets")
	}
}

func TestBuildOutputHasNoObviouslyStructuredCleartext(t *testing.T) {
	// This is not a statistical entropy test. It only pins the property the
	// design depends on: nothing in the header or padding is a small-range,
	// slowly-changing value (like a raw Unix timestamp would be), which
	// would be the case if a future edit accidentally started writing one
	// in cleartext next to the nonce and tag.
	key := testKey(t, 1)
	now := time.Now()
	packet, err := Build(key, 256, now, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	nowUnix := now.Unix()
	for offset := 0; offset+8 <= len(packet); offset++ {
		var v int64
		for i := 0; i < 8; i++ {
			v = v<<8 | int64(packet[offset+i])
		}
		if v > nowUnix-10 && v < nowUnix+10 {
			t.Fatalf(
				"found a plausible cleartext timestamp (%d, near now=%d) at byte offset %d",
				v, nowUnix, offset,
			)
		}
	}
}

func TestSignatureSizesConfirmMLDSAIsUnsuitableForOneUDPDatagram(t *testing.T) {
	// This is a live regression test for the package doc's central design
	// argument ("Why HMAC-SHA256 and not ML-DSA"), not a restatement of it:
	// it imports the real circl packages this tree pins and checks their
	// actual SignatureSize constants, so a future circl upgrade that
	// shrank ML-DSA signatures below the UDP-safe ceiling would fail this
	// test and force the reasoning to be re-examined, rather than leaving
	// a comment that quietly went stale.
	//
	// safeUDPPayloadCeiling mirrors carrier.H3InitialPacketSize's own
	// ceiling (maximumQUICPacketSize, internal/carrier/h3.go). It is
	// duplicated rather than imported so this leaf package's tests do not
	// gain a dependency on internal/carrier merely to read one constant.
	const safeUDPPayloadCeiling = 1452

	if mldsa65.SignatureSize <= safeUDPPayloadCeiling {
		t.Fatalf(
			"ML-DSA-65 SignatureSize is now %d, no longer exceeding the %d-byte safe UDP payload ceiling; re-examine the package doc's crypto rationale",
			mldsa65.SignatureSize, safeUDPPayloadCeiling,
		)
	}
	if mldsa87.SignatureSize <= safeUDPPayloadCeiling {
		t.Fatalf(
			"ML-DSA-87 SignatureSize is now %d, no longer exceeding the %d-byte safe UDP payload ceiling; re-examine the package doc's crypto rationale",
			mldsa87.SignatureSize, safeUDPPayloadCeiling,
		)
	}
	t.Logf(
		"ML-DSA-65 signature = %d bytes, ML-DSA-87 signature = %d bytes, safe UDP ceiling = %d bytes",
		mldsa65.SignatureSize, mldsa87.SignatureSize, safeUDPPayloadCeiling,
	)
}

func TestBucketIndexIsMonotonicAcrossTheEpoch(t *testing.T) {
	window := 10 * time.Second
	before := time.Unix(-25, 0) // pre-epoch, exercises the defensive branch
	after := time.Unix(-5, 0)
	if bucketIndex(before, window) > bucketIndex(after, window) {
		t.Fatalf(
			"bucketIndex not monotonic across the epoch: bucketIndex(%v)=%d > bucketIndex(%v)=%d",
			before, bucketIndex(before, window), after, bucketIndex(after, window),
		)
	}
	// A packet built just before the epoch must still verify just before it,
	// exercising the pre-epoch branch through the public API rather than
	// only the unexported helper.
	key := testKey(t, 1)
	opts := Options{BucketWindow: window, MaxSkew: 60 * time.Second}
	packet, err := Build(key, 1200, before, opts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, _, err := Verify(packet, [][]byte{key}, before, opts); err != nil {
		t.Fatalf("Verify rejected a pre-epoch packet against its own build time: %v", err)
	}
}

func TestBucketSpreadRoundsUpPartialBuckets(t *testing.T) {
	// 65s of skew at a 10s window must cover 7 buckets each side (0..69s),
	// not 6 (0..59s) - a caller who asked for 65s of tolerance must get at
	// least 65s, not silently less.
	got := bucketSpread(65*time.Second, 10*time.Second)
	if got != 7 {
		t.Fatalf("bucketSpread(65s, 10s) = %d, want 7", got)
	}
	exact := bucketSpread(60*time.Second, 10*time.Second)
	if exact != 6 {
		t.Fatalf("bucketSpread(60s, 10s) = %d, want 6 (no rounding needed)", exact)
	}
}
