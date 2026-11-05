package carrier

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

// TestLengthRecordIsEighteenBytes pins §4.2's stated cost.
//
// Two bytes of plaintext, eighteen on the wire. The number appears in the
// session lane's own reasoning about what a stream carrier must subtract from
// the path, so it is not free to drift here.
func TestLengthRecordIsEighteenBytes(t *testing.T) {
	t.Parallel()
	if LengthRecordOverhead != 18 {
		t.Fatalf("LengthRecordOverhead is %d, §4.2 says 18", LengthRecordOverhead)
	}
	lc := mustCipher(t, testSecret(t), []byte("0123456789abcdef"), dirClientToGateway)
	out, err := lc.seal(nil, 1234)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(out) != LengthRecordOverhead {
		t.Fatalf("sealed length is %d bytes, want %d", len(out), LengthRecordOverhead)
	}
}

func mustCipher(t *testing.T, secret, salt []byte, label string) *lengthCipher {
	t.Helper()
	lc, err := newLengthCipher(secret, salt, label)
	if err != nil {
		t.Fatalf("newLengthCipher: %v", err)
	}
	return lc
}

// TestLengthRoundTrips is the base case, across the whole representable range.
func TestLengthRoundTrips(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	salt := []byte("0123456789abcdef")
	send := mustCipher(t, secret, salt, dirClientToGateway)
	recv := mustCipher(t, secret, salt, dirClientToGateway)

	for _, n := range []int{0, 1, 29, 255, 256, 1168, 1232, 1443, 65535} {
		out, err := send.seal(nil, n)
		if err != nil {
			t.Fatalf("seal %d: %v", n, err)
		}
		got, err := recv.openLength(out)
		if err != nil {
			t.Fatalf("open %d: %v", n, err)
		}
		if got != n {
			t.Fatalf("round trip: sealed %d, opened %d", n, got)
		}
	}
}

// TestDirectionsAreKeyedApart is what lets both counters start at zero.
//
// If the two directions shared a key, the client's record i and the gateway's
// record i would be the same (key, nonce) pair sealing two different lengths —
// which for ChaCha20-Poly1305 leaks their XOR and, far worse, forfeits
// authentication for the key. The test is that the wrong direction cannot open
// the right one's record, which is the observable form of "different key".
func TestDirectionsAreKeyedApart(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	salt := []byte("0123456789abcdef")
	c2s := mustCipher(t, secret, salt, dirClientToGateway)
	s2c := mustCipher(t, secret, salt, dirGatewayToClient)

	out, err := c2s.seal(nil, 1000)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := s2c.openLength(out); !errors.Is(err, ErrStreamDesync) {
		t.Fatalf("the gateway direction opened a client record: %v", err)
	}
}

// TestRoleLabelsAreOppositeAtTheTwoEnds is the wiring around that.
//
// Getting these the same way round at both ends is the whole of the direction
// handling, and getting it wrong produces a carrier that works perfectly in a
// loopback test where both ends are the same role and fails only against a real
// peer.
func TestRoleLabelsAreOppositeAtTheTwoEnds(t *testing.T) {
	t.Parallel()
	if RoleClient.sendLabel() != RoleGateway.recvLabel() {
		t.Fatal("the client's send label is not the gateway's receive label")
	}
	if RoleGateway.sendLabel() != RoleClient.recvLabel() {
		t.Fatal("the gateway's send label is not the client's receive label")
	}
	if RoleClient.sendLabel() == RoleGateway.sendLabel() {
		t.Fatal("both roles seal under the same label")
	}
	if RoleClient.String() != "client" || RoleGateway.String() != "gateway" {
		t.Fatal("role strings are wrong")
	}
}

// TestSaltChangesTheKey is what makes a second connection safe.
//
// A key derived from a long-lived secret with a counter starting at zero would
// reuse a (key, nonce) pair on every connection after the first. The
// per-connection salt is what prevents that, and the test is that a record
// sealed under one salt does not open under another.
func TestSaltChangesTheKey(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	a := mustCipher(t, secret, []byte("aaaaaaaaaaaaaaaa"), dirClientToGateway)
	b := mustCipher(t, secret, []byte("bbbbbbbbbbbbbbbb"), dirClientToGateway)

	out, err := a.seal(nil, 512)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := b.openLength(out); !errors.Is(err, ErrStreamDesync) {
		t.Fatalf("a record opened under a different connection salt: %v", err)
	}
}

// TestSecretChangesTheKey pins the per-gateway scoping.
//
// §4.1 scopes the initiation's indistinguishability to the gateway's admission
// key and says so plainly rather than claiming more. The stream layer inherits
// exactly that scoping, and inherits its most important property: burning one
// gateway does not burn the fleet, because the secret is per gateway and never
// fleet-wide.
func TestSecretChangesTheKey(t *testing.T) {
	t.Parallel()
	salt := []byte("0123456789abcdef")
	s1 := testSecret(t)
	s2 := append([]byte(nil), s1...)
	s2[0] ^= 1

	a := mustCipher(t, s1, salt, dirClientToGateway)
	b := mustCipher(t, s2, salt, dirClientToGateway)
	out, err := a.seal(nil, 512)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := b.openLength(out); !errors.Is(err, ErrStreamDesync) {
		t.Fatalf("a record opened under another gateway's secret: %v", err)
	}
}

// TestNonceNeverRepeats is the property everything else rests on.
//
// It records the actual nonce the cipher produces rather than trusting the
// counter, because the failure that matters is a nonce repeat, and a counter
// that increments correctly while the nonce is built from the wrong slice of it
// is a real and silent way to get one.
func TestNonceNeverRepeats(t *testing.T) {
	t.Parallel()
	lc := mustCipher(t, testSecret(t), []byte("0123456789abcdef"), dirClientToGateway)
	seen := map[string]int{}
	const rounds = 4096
	for i := 0; i < rounds; i++ {
		n, err := lc.nonce()
		if err != nil {
			t.Fatalf("nonce %d: %v", i, err)
		}
		seen[hex.EncodeToString(n[:])]++
	}
	if len(seen) != rounds {
		t.Fatalf("%d distinct nonces across %d draws; a nonce repeated", len(seen), rounds)
	}
}

// TestNonceWitnessHasTeeth feeds the same detector a cipher whose counter has
// been rewound and requires it to object.
//
// A rewound counter is exactly what a "reconnect and reuse the cipher" refactor
// would produce, and it is the mistake the test above exists for. Without this,
// TestNonceNeverRepeats could pass against an implementation that emitted a
// constant nonce, if the constant were somehow unique per draw — and more
// realistically, it could pass against a broken detector.
func TestNonceWitnessHasTeeth(t *testing.T) {
	t.Parallel()
	lc := mustCipher(t, testSecret(t), []byte("0123456789abcdef"), dirClientToGateway)
	seen := map[string]int{}
	for i := 0; i < 64; i++ {
		if i == 32 {
			lc.counter = 0 // the mutation: a rewound counter
		}
		n, err := lc.nonce()
		if err != nil {
			t.Fatalf("nonce %d: %v", i, err)
		}
		seen[hex.EncodeToString(n[:])]++
	}
	if len(seen) == 64 {
		t.Fatal("the nonce witness did not notice a rewound counter")
	}
	if len(seen) != 32 {
		t.Fatalf("expected exactly 32 distinct nonces after a rewind, got %d", len(seen))
	}
}

// TestNonceLayoutIsSaltThenCounter pins the construction against core's.
//
// The split is the same shape core uses for its transport nonce — a derived,
// never-transmitted prefix followed by a big-endian counter — so that two
// directions and two connections cannot collide even if a counter were
// mishandled somewhere.
func TestNonceLayoutIsSaltThenCounter(t *testing.T) {
	t.Parallel()
	lc := mustCipher(t, testSecret(t), []byte("0123456789abcdef"), dirClientToGateway)
	first, err := lc.nonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	second, err := lc.nonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	if !bytes.Equal(first[:lengthNonceSaltBytes], second[:lengthNonceSaltBytes]) {
		t.Fatal("the nonce salt changed between records")
	}
	if !bytes.Equal(first[:lengthNonceSaltBytes], lc.nonceSalt[:]) {
		t.Fatal("the nonce prefix is not the derived salt")
	}
	if got := binary.BigEndian.Uint64(first[lengthNonceSaltBytes:]); got != 0 {
		t.Fatalf("first counter is %d, want 0", got)
	}
	if got := binary.BigEndian.Uint64(second[lengthNonceSaltBytes:]); got != 1 {
		t.Fatalf("second counter is %d, want 1", got)
	}
}

// TestCounterExhaustionRefusesRatherThanWrapping.
//
// The ceiling is unreachable in practice — 2^48 records at a million a second is
// nine years — and it exists for the reason core's RejectAfterMessages does: the
// alternative to a hard refusal is a wrap, and a wrapped counter is a reused
// nonce. There is no "one more record" path, in either direction.
func TestCounterExhaustionRefusesRatherThanWrapping(t *testing.T) {
	t.Parallel()
	lc := mustCipher(t, testSecret(t), []byte("0123456789abcdef"), dirClientToGateway)
	lc.counter = MaxRecordsPerConnection - 1
	if _, err := lc.seal(nil, 100); err != nil {
		t.Fatalf("the last legal record was refused: %v", err)
	}
	if _, err := lc.seal(nil, 100); !errors.Is(err, ErrStreamExhausted) {
		t.Fatalf("sealing past the ceiling returned %v, want ErrStreamExhausted", err)
	}

	open := mustCipher(t, testSecret(t), []byte("0123456789abcdef"), dirClientToGateway)
	open.counter = MaxRecordsPerConnection
	if _, err := open.openLength(make([]byte, LengthRecordOverhead)); !errors.Is(err, ErrStreamExhausted) {
		t.Fatalf("opening past the ceiling returned %v, want ErrStreamExhausted", err)
	}
}

// TestTamperedRecordIsRefused. Every single-bit flip must fail to open: the
// record is authenticated, not merely encrypted, so a censor cannot rewrite a
// length to make a receiver desynchronise on demand.
func TestTamperedRecordIsRefused(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	salt := []byte("0123456789abcdef")
	send := mustCipher(t, secret, salt, dirClientToGateway)
	out, err := send.seal(nil, 1168)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for i := range out {
		for bit := 0; bit < 8; bit++ {
			bad := append([]byte(nil), out...)
			bad[i] ^= 1 << bit
			recv := mustCipher(t, secret, salt, dirClientToGateway)
			if _, err := recv.openLength(bad); !errors.Is(err, ErrStreamDesync) {
				t.Fatalf("byte %d bit %d opened: %v", i, bit, err)
			}
		}
	}
}

// TestShortSecretIsRefused. A floor against an accidentally-empty secret, in the
// same spirit as core's minAdmissionKeySize.
func TestShortSecretIsRefused(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, MinSecretSize - 1} {
		if _, err := newLengthCipher(make([]byte, MinSecretSize), []byte("x"), dirClientToGateway); err != nil {
			t.Fatalf("a long enough secret was refused: %v", err)
		}
		if _, err := newLengthCipher(make([]byte, n), []byte("x"), dirClientToGateway); !errors.Is(err, ErrSecret) {
			t.Fatalf("%d-byte secret returned %v, want ErrSecret", n, err)
		}
	}
}

// TestMalformedRecordLengthIsRefused. A record that is not exactly eighteen
// bytes is a desynchronised stream, not a short read: there is nothing to
// recover to.
func TestMalformedRecordLengthIsRefused(t *testing.T) {
	t.Parallel()
	lc := mustCipher(t, testSecret(t), []byte("0123456789abcdef"), dirClientToGateway)
	for _, n := range []int{0, 17, 19, 64} {
		if _, err := lc.openLength(make([]byte, n)); !errors.Is(err, ErrStreamDesync) {
			t.Fatalf("%d-byte record returned %v, want ErrStreamDesync", n, err)
		}
	}
}

// TestOpenErrorSaysNothingUseful.
//
// Nothing in this package is ever written back to a peer, and the error string
// is the one thing that might escape into a log a support ticket carries. It
// must not name the counter or the record: a peer that could learn where a
// receiver's counter is could steer it.
func TestOpenErrorSaysNothingUseful(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	salt := []byte("0123456789abcdef")
	send := mustCipher(t, secret, salt, dirClientToGateway)
	out, _ := send.seal(nil, 512)
	out[0] ^= 0xff

	recv := mustCipher(t, secret, salt, dirClientToGateway)
	recv.counter = 7
	_, err := recv.openLength(out)
	if err == nil {
		t.Fatal("tampered record opened")
	}
	if got := err.Error(); got != ErrStreamDesync.Error() {
		t.Fatalf("error is %q; it must carry no detail beyond the sentinel", got)
	}
}
