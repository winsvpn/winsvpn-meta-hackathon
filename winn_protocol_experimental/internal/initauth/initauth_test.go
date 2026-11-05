package initauth

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// fleetProfile is the obfuscation profile every measured capture in
// docs/handoff/ was taken under: S1 = 16, H1 = 11 as a scalar, which is the
// degenerate range 11-11. An initiation is therefore 164 bytes with 0B 00 00 00
// at offset 16, which is exactly what a censor was measured seeing.
var fleetProfile = Profile{S1: 16, H1Start: 11, H1End: 11}

// strongProfile is the shape the per-node generator draws when
// AWG_STRONG_OBFUSCATION is enabled: a wider S1 and a full-width header value.
// It is here to prove this package is not accidentally written against S1 = 16.
var strongProfile = Profile{S1: 82, H1Start: 20078186, H1End: 20078186}

func testKey(t *testing.T, seed byte) []byte {
	t.Helper()
	k := make([]byte, 32)
	for i := range k {
		k[i] = seed ^ byte(i*7+1)
	}
	return k
}

// makeInitiation builds a datagram shaped exactly like an AmneziaWG handshake
// initiation under the profile: S1 bytes of prefix, then the 148-byte body
// beginning with the little-endian header word.
func makeInitiation(t testing.TB, p Profile) []byte {
	t.Helper()
	d, err := buildInitiation(p)
	if err != nil {
		t.Fatalf("rand: %v", err)
	}
	return d
}

// buildInitiation is the same thing without a testing handle, for goroutines
// and benchmarks.
func buildInitiation(p Profile) ([]byte, error) {
	d := make([]byte, p.InitiationSize())
	if _, err := rand.Read(d); err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(d[p.S1:p.S1+4], p.H1Start)
	// mac2 is all zeros unless the responder issued a cookie, which is what
	// every capture in the handoffs observed.
	copy(d[len(d)-16:], make([]byte, 16))
	return d, nil
}

func TestSealedInitiationVerifiesAndTouchesNothingButThePrefixNobodyReads(t *testing.T) {
	key := testKey(t, 0x5a)
	now := time.Unix(1_780_000_000, 0)

	original := makeInitiation(t, fleetProfile)
	sealed := append([]byte(nil), original...)

	if err := Seal(sealed, key, fleetProfile, now, Options{}); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if len(sealed) != len(original) {
		t.Fatalf("length changed: %d -> %d", len(original), len(sealed))
	}
	if len(sealed) != 164 {
		t.Fatalf("fleet profile initiation should be 164 bytes on the wire, got %d", len(sealed))
	}
	if !bytes.Equal(sealed[fleetProfile.S1:], original[fleetProfile.S1:]) {
		t.Fatal("Seal modified the message body; only the S1 prefix may change")
	}
	if bytes.Equal(sealed[:fleetProfile.S1], original[:fleetProfile.S1]) {
		t.Fatal("Seal left the prefix untouched, so nothing was authenticated")
	}
	// The header word four bytes past the prefix is the fleet-wide tell this
	// package deliberately does NOT fix. Prove it is unchanged, so nobody later
	// reads a fingerprint improvement into this code that it does not make.
	if got := binary.LittleEndian.Uint32(sealed[16:20]); got != 11 {
		t.Fatalf("header word at offset 16 changed to %d; this package must not touch it", got)
	}

	idx, err := Verify(sealed, [][]byte{key}, fleetProfile, now, Options{})
	if err != nil {
		t.Fatalf("Verify of a freshly sealed initiation: %v", err)
	}
	if idx != 0 {
		t.Fatalf("key index = %d, want 0", idx)
	}
}

func TestSealingWorksOnTheWiderStrongProfileToo(t *testing.T) {
	key := testKey(t, 0x11)
	now := time.Unix(1_780_000_123, 0)

	d := makeInitiation(t, strongProfile)
	if got := len(d); got != 230 {
		t.Fatalf("strong profile initiation should be 230 bytes (82+148), got %d", got)
	}
	if err := Seal(d, key, strongProfile, now, Options{}); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// 82 bytes needs three HMAC blocks, so this also exercises the expansion
	// path that a 16-byte prefix never reaches.
	if _, err := Verify(d, [][]byte{key}, strongProfile, now, Options{}); err != nil {
		t.Fatalf("Verify under the strong profile: %v", err)
	}
}

func TestAPrefixCapturedFromOneInitiationDoesNotAuthenticateAnother(t *testing.T) {
	key := testKey(t, 0x77)
	now := time.Unix(1_780_000_000, 0)

	captured := makeInitiation(t, fleetProfile)
	if err := Seal(captured, key, fleetProfile, now, Options{}); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// A different handshake attempt: different ephemeral key, different
	// everything, and the attacker pastes the captured prefix onto it.
	forged := makeInitiation(t, fleetProfile)
	copy(forged[:fleetProfile.S1], captured[:fleetProfile.S1])

	if _, err := Verify(forged, [][]byte{key}, fleetProfile, now, Options{}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a cut-and-pasted prefix verified; err = %v", err)
	}
}

func TestEveryBodyMutationBreaksVerificationIncludingTheHeaderWordItself(t *testing.T) {
	key := testKey(t, 0x2c)
	now := time.Unix(1_780_000_000, 0)

	base := makeInitiation(t, fleetProfile)
	if err := Seal(base, key, fleetProfile, now, Options{}); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Walk every byte of the body, and every byte of the prefix. Nothing in the
	// datagram may be malleable: the tag covers the body, and the prefix IS the
	// tag.
	for i := range base {
		mutated := append([]byte(nil), base...)
		mutated[i] ^= 0x01
		if i >= int(fleetProfile.S1) && i < int(fleetProfile.S1)+4 {
			// Flipping the header word takes the datagram out of the profile's
			// shape entirely, which the cheap pre-filter rejects. Same outcome,
			// different reason, and the error must be identical.
			if _, err := Verify(mutated, [][]byte{key}, fleetProfile, now, Options{}); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("byte %d (header word) mutation verified", i)
			}
			continue
		}
		if _, err := Verify(mutated, [][]byte{key}, fleetProfile, now, Options{}); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("byte %d mutation verified", i)
		}
	}
}

func TestVerificationToleratesClockSkewInsideTheWindowAndRefusesOutside(t *testing.T) {
	key := testKey(t, 0x3d)
	opts := Options{BucketWindow: 10 * time.Second, MaxSkew: 60 * time.Second}
	sealedAt := time.Unix(1_780_000_000, 0)

	d := makeInitiation(t, fleetProfile)
	if err := Seal(d, key, fleetProfile, sealedAt, opts); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for _, skew := range []time.Duration{
		-55 * time.Second, -30 * time.Second, 0, 30 * time.Second, 55 * time.Second,
	} {
		if _, err := Verify(d, [][]byte{key}, fleetProfile, sealedAt.Add(skew), opts); err != nil {
			t.Fatalf("skew %s should verify: %v", skew, err)
		}
	}
	for _, skew := range []time.Duration{-10 * time.Minute, 10 * time.Minute} {
		if _, err := Verify(d, [][]byte{key}, fleetProfile, sealedAt.Add(skew), opts); err == nil {
			t.Fatalf("skew %s should not verify", skew)
		}
	}
}

func TestEveryRejectionReturnsTheSameErrorSoNoOracleCanBeBuiltFromIt(t *testing.T) {
	key := testKey(t, 0x91)
	other := testKey(t, 0x92)
	now := time.Unix(1_780_000_000, 0)

	good := makeInitiation(t, fleetProfile)
	if err := Seal(good, key, fleetProfile, now, Options{}); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tooShort := good[:len(good)-1]
	tooLong := append(append([]byte(nil), good...), 0x00)
	wrongHeader := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(wrongHeader[16:20], 12)
	staleClock := good

	cases := map[string]struct {
		datagram []byte
		keys     [][]byte
		at       time.Time
	}{
		"wrong length, short": {tooShort, [][]byte{key}, now},
		"wrong length, long":  {tooLong, [][]byte{key}, now},
		"wrong header word":   {wrongHeader, [][]byte{key}, now},
		"wrong key":           {good, [][]byte{other}, now},
		"outside the skew":    {staleClock, [][]byte{key}, now.Add(time.Hour)},
	}
	for name, tc := range cases {
		_, err := Verify(tc.datagram, tc.keys, fleetProfile, tc.at, Options{})
		if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("%s: err = %v, want ErrUnauthenticated exactly", name, err)
		}
		if err.Error() != ErrUnauthenticated.Error() {
			t.Fatalf("%s: error text %q differs from the common rejection text, which is an oracle", name, err.Error())
		}
	}
}

func TestTagLengthIsAuthenticatedSoTwoS1ValuesCannotBeConfused(t *testing.T) {
	key := testKey(t, 0x44)
	now := time.Unix(1_780_000_000, 0)

	// The same body, sealed for a node configured with S1 = 32 and for a node
	// configured with S1 = 16. Without the tag length in the MAC input the
	// narrow tag would be a prefix of the wide one, and a datagram sealed for
	// one node would verify at the other.
	body := make([]byte, AWGInitiationBodySize)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("rand: %v", err)
	}
	binary.LittleEndian.PutUint32(body[:4], 11)

	wide := make([]byte, 32)
	narrow := make([]byte, 16)
	tagInto(key, bucketIndex(now, defaultBucketWindow), 32, body, wide)
	tagInto(key, bucketIndex(now, defaultBucketWindow), 16, body, narrow)

	if bytes.Equal(wide[:16], narrow) {
		t.Fatal("the 16-byte tag is a prefix of the 32-byte tag; the tag length is not authenticated")
	}
}

func TestAProfileWithNoRoomReportsItRatherThanSealingSomethingUseless(t *testing.T) {
	legacy := Profile{S1: 0, H1Start: 1, H1End: 1}
	if legacy.CanSeal() {
		t.Fatal("S1=0 must not be sealable")
	}
	err := legacy.Validate()
	if !errors.Is(err, ErrProfileCannotSeal) {
		t.Fatalf("Validate: %v, want ErrProfileCannotSeal", err)
	}

	tiny := Profile{S1: MinTagSize - 1, H1Start: 11, H1End: 11}
	if tiny.CanSeal() {
		t.Fatalf("S1=%d must not be sealable", MinTagSize-1)
	}
	huge := Profile{S1: MaxTagSize + 1, H1Start: 11, H1End: 11}
	if huge.CanSeal() {
		t.Fatal("an S1 past the ceiling must not be sealable")
	}
	inverted := Profile{S1: 16, H1Start: 20, H1End: 10}
	if inverted.CanSeal() {
		t.Fatal("an inverted header range must not be sealable")
	}
}

func TestTheShapeTestRejectsBackgroundScanTrafficBeforeAnyCryptography(t *testing.T) {
	// The measured junk datagrams, the measured handshake response, the
	// measured transport datagram, and a generic scan payload. None of these is
	// initiation-shaped, so none of them may reach an HMAC.
	for name, size := range map[string]int{
		"junk 1 (measured 27 B)":          27,
		"junk 2 (measured 16 B)":          16,
		"handshake response (172 B)":      172,
		"transport keepalive (32 B)":      32,
		"modal transport data (1312 B)":   1312,
		"empty datagram":                  0,
		"one byte short of an initiation": 163,
	} {
		d := make([]byte, size)
		if size >= 20 {
			binary.LittleEndian.PutUint32(d[16:20], 11)
		}
		if fleetProfile.IsInitiationShaped(d) {
			t.Fatalf("%s was treated as initiation-shaped", name)
		}
	}

	// Right length, wrong header word: the other half of the pre-filter.
	d := make([]byte, 164)
	binary.LittleEndian.PutUint32(d[16:20], 44)
	if fleetProfile.IsInitiationShaped(d) {
		t.Fatal("a transport header word at the initiation offset was treated as an initiation")
	}

	// A header RANGE must admit every value inside it and nothing outside.
	ranged := Profile{S1: 16, H1Start: 1000, H1End: 2000}
	for _, word := range []uint32{1000, 1500, 2000} {
		binary.LittleEndian.PutUint32(d[16:20], word)
		if !ranged.IsInitiationShaped(d) {
			t.Fatalf("header word %d inside the range was rejected", word)
		}
	}
	for _, word := range []uint32{999, 2001} {
		binary.LittleEndian.PutUint32(d[16:20], word)
		if ranged.IsInitiationShaped(d) {
			t.Fatalf("header word %d outside the range was accepted", word)
		}
	}
}

func TestSealedPrefixesAreDistinctAcrossHandshakesAndCarryNoFixedBytes(t *testing.T) {
	// The fingerprint claim this whole package rests on is that the S1 field
	// looks exactly as it did before: uniform random, with nothing constant at
	// any offset. This is the same test the Android and Linux fingerprint
	// handoffs applied to the transport header, where it found 14 of 16 bytes
	// constant or trivially predictable. Here it must find none.
	key := testKey(t, 0x6b)
	now := time.Unix(1_780_000_000, 0)

	const samples = 512
	seen := make(map[string]struct{}, samples)
	distinctPerOffset := make([]map[byte]struct{}, fleetProfile.S1)
	for i := range distinctPerOffset {
		distinctPerOffset[i] = make(map[byte]struct{})
	}
	lengths := make(map[int]int)

	for i := 0; i < samples; i++ {
		d := makeInitiation(t, fleetProfile)
		if err := Seal(d, key, fleetProfile, now, Options{}); err != nil {
			t.Fatalf("Seal: %v", err)
		}
		lengths[len(d)]++
		prefix := d[:fleetProfile.S1]
		if _, dup := seen[string(prefix)]; dup {
			t.Fatal("two handshakes produced the same prefix")
		}
		seen[string(prefix)] = struct{}{}
		for off, b := range prefix {
			distinctPerOffset[off][b] = struct{}{}
		}
	}

	if len(lengths) != 1 {
		t.Fatalf("sealing produced more than one datagram size: %v", lengths)
	}
	if lengths[164] != samples {
		t.Fatalf("expected every sample at 164 bytes, got %v", lengths)
	}
	for off, values := range distinctPerOffset {
		// With 512 samples over a byte-valued field, a healthy offset lands on
		// most of the 256 values. Anything approaching a constant is a tell.
		if len(values) < 200 {
			t.Fatalf("offset %d took only %d distinct values across %d samples; it is not uniform", off, len(values), samples)
		}
	}
}

func TestBucketIndexFloorsTowardNegativeInfinityOnBothSidesOfTheEpoch(t *testing.T) {
	w := 10 * time.Second
	cases := []struct {
		unix int64
		want int64
	}{
		{0, 0}, {9, 0}, {10, 1}, {-1, -1}, {-10, -1}, {-11, -2},
	}
	for _, tc := range cases {
		if got := bucketIndex(time.Unix(tc.unix, 0), w); got != tc.want {
			t.Fatalf("bucketIndex(%d) = %d, want %d", tc.unix, got, tc.want)
		}
	}
}

func TestCandidateBucketsAreOrderedNearestFirstSoTheCommonCaseIsOneHMAC(t *testing.T) {
	got := candidateBuckets(100, 3)
	want := []int64{100, 99, 101, 98, 102, 97, 103}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestOptionsRefuseAConfigurationThatWouldMakeVerificationExpensive(t *testing.T) {
	if _, _, err := (Options{BucketWindow: 500 * time.Millisecond, MaxSkew: time.Minute}).resolve(); err == nil {
		t.Fatal("a sub-second bucket window should be refused")
	}
	if _, _, err := (Options{BucketWindow: time.Minute, MaxSkew: time.Second}).resolve(); err == nil {
		t.Fatal("a skew below the bucket window should be refused")
	}
	if _, _, err := (Options{BucketWindow: time.Second, MaxSkew: 24 * time.Hour}).resolve(); err == nil {
		t.Fatal("a skew wide enough to blow the candidate ceiling should be refused")
	}
}

func TestShortKeysAreRefusedAtEveryEntryPoint(t *testing.T) {
	short := []byte("tooshort")
	d := makeInitiation(t, fleetProfile)
	if err := Seal(d, short, fleetProfile, time.Now(), Options{}); !errors.Is(err, ErrKeyTooShort) {
		t.Fatalf("Seal with a short key: %v", err)
	}
	if _, err := Verify(d, [][]byte{short}, fleetProfile, time.Now(), Options{}); !errors.Is(err, ErrKeyTooShort) {
		t.Fatalf("Verify with a short key: %v", err)
	}
	if _, err := Verify(d, nil, fleetProfile, time.Now(), Options{}); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("Verify with no keys: %v", err)
	}
}

func TestARotationOverlapAdmitsBothTheOldAndTheNewKey(t *testing.T) {
	oldKey := testKey(t, 0x01)
	newKey := testKey(t, 0x02)
	now := time.Unix(1_780_000_000, 0)

	onOld := makeInitiation(t, fleetProfile)
	if err := Seal(onOld, oldKey, fleetProfile, now, Options{}); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	onNew := makeInitiation(t, fleetProfile)
	if err := Seal(onNew, newKey, fleetProfile, now, Options{}); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	keys := [][]byte{newKey, oldKey} // most current first
	if idx, err := Verify(onNew, keys, fleetProfile, now, Options{}); err != nil || idx != 0 {
		t.Fatalf("new key: idx=%d err=%v", idx, err)
	}
	if idx, err := Verify(onOld, keys, fleetProfile, now, Options{}); err != nil || idx != 1 {
		t.Fatalf("old key: idx=%d err=%v", idx, err)
	}

	// And a rotation that ships with only the new key takes every client still
	// on the old one offline at once. Pin that, so nobody ships it by accident
	// believing the gate is forgiving.
	if _, err := Verify(onOld, [][]byte{newKey}, fleetProfile, now, Options{}); err == nil {
		t.Fatal("a single-key rotation silently kept working; it must not")
	}
}

// TestTheWireConstructionIsPinnedByAKnownAnswer freezes the exact bytes this
// package commits to. Anything that changes the label, the version, the field
// order, the endianness or the expansion breaks this test, which is the point:
// the two ends are configured independently and a silent change of construction
// is a fleet-wide handshake failure with no error message anywhere.
func TestTheWireConstructionIsPinnedByAKnownAnswer(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	body := make([]byte, AWGInitiationBodySize)
	for i := range body {
		body[i] = byte(255 - i)
	}
	binary.LittleEndian.PutUint32(body[:4], 11)

	out := make([]byte, 16)
	tagInto(key, 178_000_000, 16, body, out)

	const want = "619073a238b2dc229c863029cd4c50aa"
	if got := hex.EncodeToString(out); got != want {
		t.Fatalf("wire construction changed:\n got %s\nwant %s", got, want)
	}
}

func BenchmarkVerifyRejectsAnUnauthenticatedInitiation(b *testing.B) {
	key := make([]byte, 32)
	keys := [][]byte{key}
	d := make([]byte, fleetProfile.InitiationSize())
	binary.LittleEndian.PutUint32(d[16:20], 11)
	now := time.Unix(1_780_000_000, 0)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Verify(d, keys, fleetProfile, now, Options{})
	}
}

func BenchmarkVerifyAcceptsAFreshlySealedInitiation(b *testing.B) {
	key := make([]byte, 32)
	keys := [][]byte{key}
	now := time.Unix(1_780_000_000, 0)
	d := make([]byte, fleetProfile.InitiationSize())
	binary.LittleEndian.PutUint32(d[16:20], 11)
	if err := Seal(d, key, fleetProfile, now, Options{}); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Verify(d, keys, fleetProfile, now, Options{}); err != nil {
			b.Fatal(err)
		}
	}
}
