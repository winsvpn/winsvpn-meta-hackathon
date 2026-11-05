package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// This file pins the two properties the independent key-schedule review
// (docs/handoff/WINN3_KEY_SCHEDULE_REVIEW_20260808.md) found to be correct by
// reading but asserted by no test: nonce uniqueness across epochs (M2) and the
// exact coincidence of the admission-tag acceptance window with the handshake
// replay cache lifetime (L5).
//
// Both are here rather than in session_test.go / handshake_test.go because they
// are invariants of the design rather than behaviours of one type, and because
// anyone asking "where is nonce reuse ruled out?" should find the answer in one
// place.

// --- M2: cross-epoch nonce distinctness --------------------------------------

// nonceUse names one (key, nonce) pair actually used by a Seal, so that a
// repeat can be reported as two identified events rather than as a bare
// "duplicate found".
type nonceUse struct {
	epoch   uint32
	role    Role
	counter uint64
}

func (u nonceUse) String() string {
	return fmt.Sprintf("epoch %d, %s sending, counter %d", u.epoch, u.role, u.counter)
}

// sealAndRecord seals one message and returns the (key, nonce) pair the AEAD
// actually used.
//
// The pair is PROVEN rather than asserted. It is re-derived independently from
// the session's chaining key — the same derivation installEpoch performs, but
// written out here — and is then used, with nothing else, to open the very
// ciphertext Seal has just produced. If this re-derivation ever drifted from
// what the session installs, that open would fail and the test would say so
// instead of quietly recording pairs that no longer correspond to reality.
// Without that step this test would only be restating deriveDirection to
// itself.
func sealAndRecord(t *testing.T, s *Session, payload []byte) ([KeySize]byte, [AEADNonceSize]byte, []byte, nonceUse) {
	t.Helper()

	s.chainMu.Lock()
	epoch := s.epoch
	ch := s.ch
	s.chainMu.Unlock()

	dir := dirI2R
	if s.role == RoleResponder {
		dir = dirR2I
	}
	dk := deriveDirection(&ch, epoch, dir)

	s.sendMu.Lock()
	counter := s.sendCounter
	installedSalt := s.sendSalt
	s.sendMu.Unlock()

	ct, err := s.Seal(payload, 0)
	if err != nil {
		t.Fatalf("seal at epoch %d, counter %d: %v", epoch, counter, err)
	}

	if dk.salt != installedSalt {
		t.Fatalf("epoch %d %s: the re-derived salt does not match the installed one, "+
			"so this test is no longer tracking what Seal does", epoch, dir)
	}

	var nonce [AEADNonceSize]byte
	copy(nonce[:nonceSaltSize], dk.salt[:])
	binary.BigEndian.PutUint64(nonce[nonceSaltSize:], counter)

	aead, err := chacha20poly1305.New(dk.key[:])
	if err != nil {
		t.Fatalf("aead from the re-derived key: %v", err)
	}
	token := ct[:DemuxTokenSize]
	if _, err := aead.Open(nil, nonce[:], ct[DemuxTokenSize:], token); err != nil {
		t.Fatalf("the recorded (key, nonce) does not open the ciphertext it was recorded for "+
			"(epoch %d, counter %d): %v", epoch, counter, err)
	}

	return dk.key, nonce, ct, nonceUse{epoch: epoch, role: s.role, counter: counter}
}

// TestNonceIsNeverReusedAcrossEpochs is the direct assertion of the single
// highest-consequence property in the protocol: no (key, nonce) pair is ever
// used twice.
//
// A single reused nonce under ChaCha20-Poly1305 leaks the XOR of the two
// plaintexts and hands over the Poly1305 one-time key, and it does so silently.
// Nothing else in this package fails if that happens.
// TestTransportIsUnconditionallyUniform would trip on a counter that was
// completely stuck, because every ciphertext would then be identical; it would
// not notice a counter that reset periodically or two epochs that collided.
//
// The test drives many messages in both directions across several ratchets —
// one post-quantum, the rest rekeys — and asserts four things, in descending
// order of how catastrophic a failure would be:
//
//  1. no (key, nonce) pair is used twice. This is the invariant itself.
//  2. no full nonce is used twice. This is belt-and-braces: it is stronger than
//     security requires, because a repeated nonce under a fresh key is safe. It
//     is asserted anyway because the per-epoch salt is exactly the belt a future
//     editor might remove ("the key changes anyway"), and it is safe to remove
//     ONLY while key derivation stays per-epoch. Assertion 2 fails the moment
//     the belt goes, which is the moment to have the conversation — not later,
//     when someone also touches the key derivation.
//  3. no two (epoch, direction) pairs share a traffic key, a nonce salt or a
//     demux key.
//  4. the counter really does restart at zero in every epoch, so that 1 is
//     doing real work and not passing merely because counters never repeat.
//
// Everything here is deterministic: the harness draws from detReader and the
// ratchet secrets are fixed, so this test either passes forever or fails
// forever. In particular the pairwise distinctness of the 4-byte salts in 3 is
// not a probabilistic claim about this run.
func TestNonceIsNeverReusedAcrossEpochs(t *testing.T) {
	const (
		epochs           = 6
		messagesPerEpoch = 300
	)

	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	type origin struct{ epoch, dir string }

	pairSeen := make(map[[KeySize + AEADNonceSize]byte]nonceUse, 2*epochs*messagesPerEpoch)
	nonceSeen := make(map[[AEADNonceSize]byte]nonceUse, 2*epochs*messagesPerEpoch)
	keySeen := make(map[[KeySize]byte]string, 2*epochs)
	saltSeen := make(map[[nonceSaltSize]byte]string, 2*epochs)
	demuxSeen := make(map[[KeySize]byte]string, 2*epochs)
	lowestCounter := make(map[string]uint64, 2*epochs)

	record := func(key [KeySize]byte, nonce [AEADNonceSize]byte, use nonceUse) {
		t.Helper()

		var pair [KeySize + AEADNonceSize]byte
		copy(pair[:KeySize], key[:])
		copy(pair[KeySize:], nonce[:])
		if prev, dup := pairSeen[pair]; dup {
			t.Fatalf("NONCE REUSE: the same (key, nonce) pair was used twice — "+
				"first at %s, again at %s. Under ChaCha20-Poly1305 this leaks the XOR of "+
				"the two plaintexts and forges the authenticator.", prev, use)
		}
		pairSeen[pair] = use

		if prev, dup := nonceSeen[nonce]; dup {
			t.Fatalf("the same nonce was used twice — first at %s, again at %s. "+
				"That is not a break while the two epochs use different keys, but the "+
				"per-epoch nonce salt is the reason it cannot happen, and it has just "+
				"stopped being per-epoch. Restore it, or establish that key derivation "+
				"is still strictly per-epoch before removing this assertion.", prev, use)
		}
		nonceSeen[nonce] = use

		where := fmt.Sprintf("epoch %d, %s sending", use.epoch, use.role)
		if c, ok := lowestCounter[where]; !ok || use.counter < c {
			lowestCounter[where] = use.counter
		}
	}

	recordEpochKeys := func(s *Session) {
		t.Helper()
		s.chainMu.Lock()
		epoch := s.epoch
		ch := s.ch
		s.chainMu.Unlock()

		for _, dir := range []string{dirI2R, dirR2I} {
			dk := deriveDirection(&ch, epoch, dir)
			where := fmt.Sprintf("epoch %d %s", epoch, dir)
			if prev, dup := keySeen[dk.key]; dup {
				t.Fatalf("KEY REUSE: %s and %s derive the same traffic key. Two epochs "+
					"sharing a key is what makes a repeated counter catastrophic.", prev, where)
			}
			keySeen[dk.key] = where
			if prev, dup := saltSeen[dk.salt]; dup {
				t.Fatalf("%s and %s derive the same nonce salt; the salt is no longer "+
					"per-epoch (see the comment on assertion 2)", prev, where)
			}
			saltSeen[dk.salt] = where
			if prev, dup := demuxSeen[dk.demux]; dup {
				t.Fatalf("%s and %s derive the same demux key, so their tokens would "+
					"collide and a stale packet could be placed in the wrong epoch", prev, where)
			}
			demuxSeen[dk.demux] = where
		}
	}

	payload := bytes.Repeat([]byte{0x5A}, 96)

	for e := 0; e < epochs; e++ {
		// Both ends are at the same epoch and derive from the same chain, so
		// recording from one end covers both directions of this epoch.
		recordEpochKeys(cli)

		for i := 0; i < messagesPerEpoch; i++ {
			key, nonce, ct, use := sealAndRecord(t, cli, payload)
			record(key, nonce, use)
			if _, err := gw.Open(ct); err != nil {
				t.Fatalf("gateway could not open client message %d of epoch %d: %v", i, e, err)
			}

			key, nonce, ct, use = sealAndRecord(t, gw, payload)
			record(key, nonce, use)
			if _, err := cli.Open(ct); err != nil {
				t.Fatalf("client could not open gateway message %d of epoch %d: %v", i, e, err)
			}
		}

		if e == epochs-1 {
			break
		}

		// The first ratchet is the post-quantum one, the rest are rekeys, which
		// is the real session lifecycle. Fixed secrets keep the run
		// deterministic; TestPQRatchet already covers a genuine ML-KEM exchange.
		var err error
		if e == 0 {
			secret := bytes.Repeat([]byte{0xC3}, PQSharedKeySize)
			if err = cli.MixPQ(secret); err == nil {
				err = gw.MixPQ(secret)
			}
		} else {
			secret := bytes.Repeat([]byte{byte(0x10 + e)}, KeySize)
			if err = cli.Rekey(secret); err == nil {
				err = gw.Rekey(secret)
			}
		}
		if err != nil {
			t.Fatalf("ratchet into epoch %d: %v", e+1, err)
		}
		if cli.Epoch() != uint32(e+1) || gw.Epoch() != uint32(e+1) {
			t.Fatalf("after ratchet %d the epochs are %d and %d", e+1, cli.Epoch(), gw.Epoch())
		}
	}

	// The test must not be able to pass by doing less work than it claims.
	wantPairs := 2 * epochs * messagesPerEpoch
	if len(pairSeen) != wantPairs {
		t.Fatalf("recorded %d (key, nonce) pairs, expected %d", len(pairSeen), wantPairs)
	}
	if len(keySeen) != 2*epochs {
		t.Fatalf("recorded %d traffic keys, expected %d", len(keySeen), 2*epochs)
	}

	// Assertion 4. If the counter did not restart at zero in every epoch, the
	// counter alone would already separate every nonce and assertions 1 and 2
	// would be passing for a reason that has nothing to do with the epoch keys.
	if len(lowestCounter) != 2*epochs {
		t.Fatalf("saw %d (epoch, direction) senders, expected %d", len(lowestCounter), 2*epochs)
	}
	for where, low := range lowestCounter {
		if low != 0 {
			t.Fatalf("%s: the lowest counter used was %d, not 0. The counter is not "+
				"restarting with the epoch, so this test is not exercising the "+
				"cross-epoch case it exists for.", where, low)
		}
	}
}

// TestEpochNumberSeparatesKeysWithoutHelpFromTheChain pins the redundant half
// of the epoch separation, which nothing else can see.
//
// Two separations run across an epoch boundary, and it is easy to believe there
// is only one. mixSecret advances ck at every ratchet, AND epochInfo puts the
// epoch number into every info string. Today the first is what makes two epochs
// cryptographically independent; the second is redundant, and redundant enough
// that deleting the epoch number from epochInfo entirely would not change a
// single key — because ck has moved anyway — and
// TestNonceIsNeverReusedAcrossEpochs would not notice. That was measured, not
// assumed: mutating epochInfo to a fixed epoch leaves that test green.
//
// Redundant is not worthless. It is the layer that still separates two epochs
// if a ratchet ever installs an epoch WITHOUT advancing ck — a resumption path,
// a rekey that reuses a cached secret, or a plain bug. The review's §5 names
// "the salt made stable across epochs while key derivation is changed" as one
// of the two things that would overturn its verdict, and that is exactly this
// layer going away.
//
// Holding ck fixed is the only way to observe it, so that is what this does.
func TestEpochNumberSeparatesKeysWithoutHelpFromTheChain(t *testing.T) {
	ch := newChain(bytes.Repeat([]byte{0x11}, KeySize))

	for _, dir := range []string{dirI2R, dirR2I} {
		a := deriveDirection(&ch, 0, dir)
		b := deriveDirection(&ch, 1, dir)
		if a.key == b.key {
			t.Fatalf("%s: two epochs derive the same traffic key from an unchanged "+
				"chaining key; the epoch number no longer separates epochs on its own", dir)
		}
		if a.salt == b.salt {
			t.Fatalf("%s: two epochs derive the same nonce salt from an unchanged "+
				"chaining key. The salt is now stable across epochs, and it is safe ONLY "+
				"while every ratchet also advances ck. Restore the epoch number to "+
				"epochInfo, or establish that no path can install an epoch without "+
				"advancing the chain.", dir)
		}
		if a.demux == b.demux {
			t.Fatalf("%s: two epochs derive the same demux key from an unchanged "+
				"chaining key; their tokens would collide", dir)
		}
	}

	// The same argument applies between the two directions of one epoch, which
	// share a chaining key by construction and are separated by nothing else.
	i2r := deriveDirection(&ch, 0, dirI2R)
	r2i := deriveDirection(&ch, 0, dirR2I)
	if i2r.key == r2i.key || i2r.salt == r2i.salt || i2r.demux == r2i.demux {
		t.Fatal("the two directions of one epoch share derived material; send and " +
			"receive would use one key, and each side's counter would collide with the other's")
	}
}

// TestNonceReuseDetectorHasTeeth is the self-test for the test above.
//
// A test that can only pass is worth nothing, and the assertions above are all
// negative ones. This constructs the exact failure mode M2 guards against — the
// per-epoch salt made stable while the counter restarts, so two epochs collide
// on a nonce — and confirms the detection logic fires on it. It uses the same
// map-of-pairs check, applied to hand-built pairs, so it does not need to
// damage the production derivation to prove the point.
func TestNonceReuseDetectorHasTeeth(t *testing.T) {
	stableSalt := [nonceSaltSize]byte{0xDE, 0xAD, 0xBE, 0xEF}
	sharedKey := [KeySize]byte{}

	seen := make(map[[KeySize + AEADNonceSize]byte]nonceUse)
	collided := false
	for _, e := range []uint32{0, 1} {
		for c := uint64(0); c < 4; c++ {
			var nonce [AEADNonceSize]byte
			copy(nonce[:nonceSaltSize], stableSalt[:]) // salt no longer per-epoch
			binary.BigEndian.PutUint64(nonce[nonceSaltSize:], c)

			var pair [KeySize + AEADNonceSize]byte
			copy(pair[:KeySize], sharedKey[:]) // key no longer per-epoch either
			copy(pair[KeySize:], nonce[:])

			if _, dup := seen[pair]; dup {
				collided = true
			}
			seen[pair] = nonceUse{epoch: e, role: RoleInitiator, counter: c}
		}
	}
	if !collided {
		t.Fatal("the (key, nonce) duplicate check did not fire on a construction that " +
			"reuses both the key and the salt across epochs; the M2 test cannot be trusted")
	}
}

// --- L6: the PSK is what closes gateway-side KCI -----------------------------

// TestRequirePSKRefusesAPSKLessProfile pins the opt-in guard added for L6.
//
// The finding: with the gateway's static private key, an attacker can compute
// both es and ss for any client whose public key they know, so they can
// impersonate that client to the REAL gateway and have the session attributed
// to an innocent subscriber. The PSK is the only value in that chain they do
// not hold. It is optional today, and making it mandatory outright would refuse
// every currently enrolled client — see the findings document — so what ships
// here is the switch, defaulted off, not the mandate.
//
// The test is the honest half of that: it proves the switch actually refuses,
// so that turning it on later is a one-line change with a tested meaning rather
// than a hope.
func TestRequirePSKRefusesAPSKLessProfile(t *testing.T) {
	// Default off: a PSK-less profile is built exactly as before.
	h := newHarness(t)
	if h.clientCf.RequirePSK || h.gwCf.RequirePSK {
		t.Fatal("RequirePSK must default to off; on by default would refuse every enrolled client")
	}
	h.completeHandshake(t)

	// Switched on with no PSK: both roles refuse at construction, before any
	// wire byte exists. These configs are built by hand rather than through
	// newHarness, because newHarness constructs a Responder eagerly and the
	// whole point here is that construction fails.
	gwPub, err := NewPublicKey(h.gateway.Public())
	if err != nil {
		t.Fatal(err)
	}
	strictClient, strictGw := h.clientCf, h.gwCf
	strictClient.RequirePSK, strictGw.RequirePSK = true, true
	strictClient.PSK, strictGw.PSK = nil, nil

	if _, err := NewInitiator(strictClient, h.client, gwPub); !errors.Is(err, ErrConfig) {
		t.Fatalf("an initiator requiring a PSK and holding none must refuse, got %v", err)
	}
	if _, err := NewResponder(strictGw, h.gateway, func([]byte) error { return nil }); !errors.Is(err, ErrConfig) {
		t.Fatalf("a responder requiring a PSK and holding none must refuse, got %v", err)
	}

	// Switched on WITH a PSK: an ordinary session, and the KCI hole is closed
	// because k2 now depends on a value gateway-key compromise does not yield.
	psk := bytes.Repeat([]byte{0x9E}, KeySize)
	ok := newHarness(t, func(hh *harness) {
		hh.clientCf.RequirePSK, hh.gwCf.RequirePSK = true, true
		hh.clientCf.PSK, hh.gwCf.PSK = psk, psk
	})
	cli, gw := ok.completeHandshake(t)
	msg, err := cli.Seal([]byte("psk-bound"), 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gw.Open(msg)
	if err != nil {
		t.Fatalf("a PSK-bound session must carry traffic normally: %v", err)
	}
	if string(got) != "psk-bound" {
		t.Fatalf("payload came back as %q", got)
	}

	// A wrong-length PSK is still refused for the old reason, not the new one.
	if err := (Config{Gateway: ok.gwCf.Gateway, RequirePSK: true, PSK: []byte{1, 2, 3}}).validate(true); !errors.Is(err, ErrConfig) {
		t.Fatalf("a short PSK must still be refused, got %v", err)
	}
}

// --- I1: the byte-budget rekey trigger ---------------------------------------

// TestByteBudgetRekeyTrigger pins the second soft rekey trigger, which the
// design document has always specified (§5.3, "bytes: after a configured byte
// budget") and which the code did not enforce: sentBytes and recvdBytes were
// incremented and never read by anything.
//
// A documented policy the code does not implement is worse than an undocumented
// one, because it reads as a guarantee. This test is what stops it drifting back.
func TestByteBudgetRekeyTrigger(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	if cli.NeedsRekey() {
		t.Fatal("a fresh session must not want a rekey")
	}
	if cli.SentBytes() != 0 || cli.RecvdBytes() != 0 {
		t.Fatalf("a fresh session has sent %d and received %d bytes", cli.SentBytes(), cli.RecvdBytes())
	}

	// The counters must track on-wire bytes, overhead and padding included,
	// because that is what an exposure budget is measured in.
	msg, err := cli.Seal([]byte("nine byte"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := cli.SentBytes(); got != uint64(len(msg)) {
		t.Fatalf("SentBytes is %d after sealing a %d-byte message", got, len(msg))
	}
	if _, err := gw.Open(msg); err != nil {
		t.Fatal(err)
	}
	if got := gw.RecvdBytes(); got != uint64(len(msg)) {
		t.Fatalf("RecvdBytes is %d after opening a %d-byte message", got, len(msg))
	}

	// A message that does not open must not be counted: it was not necessarily
	// ours, and letting a stranger drive our rekey schedule would hand them a
	// way to force key churn.
	junk := make([]byte, len(msg))
	copy(junk, msg)
	junk[0] ^= 0xFF
	if _, err := gw.Open(junk); err == nil {
		t.Fatal("a message with a mangled token must not open")
	}
	if got := gw.RecvdBytes(); got != uint64(len(msg)) {
		t.Fatalf("a rejected message moved RecvdBytes to %d", got)
	}

	// The trigger itself, at the boundary.
	cli.sendMu.Lock()
	cli.epochSentBytes = RekeyAfterBytes - 1
	cli.sendMu.Unlock()
	if cli.NeedsRekey() {
		t.Fatal("the byte trigger fired one byte early")
	}
	cli.sendMu.Lock()
	cli.epochSentBytes = RekeyAfterBytes
	cli.sendMu.Unlock()
	if !cli.NeedsRekey() {
		t.Fatal("the byte budget was reached and the trigger did not fire")
	}

	// And it must be independent of the message trigger, not a restatement of
	// it: the counter here is far below RekeyAfterMessages.
	if cli.SendCounter() >= RekeyAfterMessages {
		t.Fatal("the message trigger was also satisfied, so this proves nothing about bytes")
	}
}

func TestByteBudgetResetsAfterRekeyWhileLifetimeCounterPersists(t *testing.T) {
	h := newHarness(t)
	cli, _ := h.completeHandshake(t)

	cli.sendMu.Lock()
	cli.sentBytes = RekeyAfterBytes
	cli.epochSentBytes = RekeyAfterBytes
	cli.sendMu.Unlock()
	if !cli.NeedsRekey() {
		t.Fatal("byte budget did not request a rekey")
	}

	before := cli.SentBytes()
	if err := cli.Rekey(bytes.Repeat([]byte{0x5a}, KeySize)); err != nil {
		t.Fatal(err)
	}
	if cli.NeedsRekey() {
		t.Fatal("new epoch inherited the previous epoch byte trigger")
	}
	if got := cli.SentBytes(); got != before {
		t.Fatalf("lifetime sent byte counter changed from %d to %d during rekey", before, got)
	}
}

// --- L5: the freshness window and the replay lifetime coincide ---------------

// TestReplayWindowCoversTheWholeAcceptanceWindow pins the coupling the review
// called correct but fragile: the admission tag is acceptable over exactly
// (2*spread+1)*window of real time, and the handshake replay cache remembers an
// accepted body for exactly that same span. Because the earliest instant a tag
// can first be accepted is `spread` buckets before its own bucket, a cache
// stamped at that earliest instant expires at precisely the instant the tag
// stops verifying. There is therefore no gap in which a captured initiation is
// both forgotten and still valid.
//
// That is two formulas in two files — Freshness.resolve and the lifetime
// computed in NewResponder — holding a numerical identity that nothing else
// enforces. This test walks the boundary in the worst case (a gateway whose
// clock is maximally behind, so the first acceptance is as early as it can be)
// and fails if either formula moves relative to the other.
func TestReplayWindowCoversTheWholeAcceptanceWindow(t *testing.T) {
	h := newHarness(t)

	window, spread, err := h.gwCf.Gateway.Fresh.resolve()
	if err != nil {
		t.Fatalf("resolve freshness: %v", err)
	}
	span := time.Duration(2*spread+1) * window // both the acceptance span and the cache lifetime

	// The arithmetic below assumes the initiation is written at a bucket
	// boundary, which makes every instant it names exact rather than
	// approximate. fixedNow is midnight-aligned, so it is.
	if bucketIndex(fixedNow, window) != fixedNow.Unix()/int64(window/time.Second) {
		t.Fatal("fixedNow is not on a bucket boundary; the boundary arithmetic here would be off by a fraction of a bucket")
	}

	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatalf("write initiation: %v", err)
	}

	// The earliest instant at which this tag can be accepted at all, and the
	// instant at which it stops being acceptable.
	earliest := fixedNow.Add(-time.Duration(spread) * window)
	expiry := earliest.Add(span)

	// A gateway whose clock is maximally behind accepts it here, at the very
	// start of the acceptance window. This is the worst case for the coupling:
	// the cache is stamped as early as it can possibly be stamped.
	h.now = earliest
	if _, err := h.resp.ReadInitiation(msg); err != nil {
		t.Fatalf("the maximally-early acceptance must succeed, got %v", err)
	}

	// Walk the whole acceptance window and past it. The identical bytes must be
	// refused at every single step.
	step := window / 4
	for at := earliest; at.Before(expiry.Add(2 * window)); at = at.Add(step) {
		h.now = at
		_, err := h.resp.ReadInitiation(msg)
		if err == nil {
			t.Fatalf("a captured initiation was accepted a second time at %s "+
				"(%s after the first acceptance)", at, at.Sub(earliest))
		}
		if at.Before(expiry) {
			if !errors.Is(err, ErrReplay) {
				t.Fatalf("at %s (inside the acceptance window) the refusal must come from "+
					"the replay cache, got %v", at.Sub(earliest), err)
			}
		} else if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("at %s (past the acceptance window) the refusal must come from the "+
				"tag no longer verifying, got %v", at.Sub(earliest), err)
		}
	}

	// The handover instant itself, to the nanosecond, against a responder with
	// an EMPTY cache. This is what makes the loop above non-vacuous: it proves
	// the tag is genuinely still live one nanosecond before expiry — so the
	// ErrReplay there was the cache doing real work and not the tag having
	// already died — and genuinely dead at expiry, which is the same instant the
	// cache is entitled to forget it.
	fresh := func(t *testing.T) *Responder {
		t.Helper()
		r, err := NewResponder(h.gwCf, h.gateway, func(pub []byte) error {
			if !bytes.Equal(pub, h.client.Public()) {
				return errors.New("unknown client")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("fresh responder: %v", err)
		}
		return r
	}

	h.now = expiry.Add(-time.Nanosecond)
	if _, err := fresh(t).ReadInitiation(msg); err != nil {
		t.Fatalf("one nanosecond before expiry the tag must still verify, got %v. "+
			"The acceptance window is now SHORTER than the replay lifetime: harmless, "+
			"but the two formulas have come apart.", err)
	}

	h.now = expiry
	if _, err := fresh(t).ReadInitiation(msg); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("at expiry the tag must no longer verify, got %v. The acceptance window "+
			"is now LONGER than the replay cache lifetime, which opens a real replay gap: "+
			"a captured initiation the cache has forgotten but the tag still accepts.", err)
	}
}

// TestTheReplayCacheRefusesALifetimeItCannotHonour is the other half of L5.
//
// The test above pins that the two formulas AGREE. This one pins that there is
// no third formula — that the cache cannot be built with a lifetime nobody
// computed from the freshness parameters.
//
// The history matters, because the defect here is not the one it looks like.
// newReplayCache used to answer a non-positive lifetime by substituting
// DefaultMaxSkew*2. That was NOT a silent disable: a lifetime left at zero would
// have been, since seen() compares now.Sub(at) < c.lifetime and every such
// comparison is false at zero, so the cache would have reported no hit ever. The
// substitution was load-bearing. What was wrong with it is subtler — 120s is a
// constant, and the span the cache must cover is (2*spread+1)*window, so on any
// gateway configured with a wider-than-default skew the substituted lifetime is
// strictly shorter than the acceptance window. That is exactly the gap the test
// above calls "a real replay gap".
//
// So the fix is a refusal rather than a better default: there is no value this
// constructor could invent that would be right for every Freshness.
//
// The second half is the part that keeps this honest. A guard on an unreachable
// path is worth very little, and this one IS unreachable from production today —
// so rather than assert that in a comment, the test derives the floor from
// Freshness.resolve itself and fails if the arithmetic ever moves close enough
// for a real configuration to reach the refusal.
func TestTheReplayCacheRefusesALifetimeItCannotHonour(t *testing.T) {
	for _, lifetime := range []time.Duration{
		0,
		-time.Nanosecond,
		-DefaultMaxSkew,
	} {
		c, err := newReplayCache(lifetime)
		if err == nil {
			t.Fatalf("newReplayCache(%s) built a cache. A non-positive lifetime makes seen() "+
				"compare now.Sub(at) against it and return false for every entry, which is "+
				"replay protection silently switched off; and any constant substituted for it "+
				"is decoupled from the acceptance window it has to cover.", lifetime)
		}
		if !errors.Is(err, ErrConfig) {
			t.Fatalf("newReplayCache(%s) refused with %v, want an ErrConfig", lifetime, err)
		}
		if c != nil {
			t.Fatalf("newReplayCache(%s) returned both an error and a cache", lifetime)
		}
	}

	// A positive lifetime is honoured exactly, with no rounding or substitution
	// left anywhere in the constructor.
	for _, lifetime := range []time.Duration{time.Nanosecond, time.Second, time.Hour} {
		c, err := newReplayCache(lifetime)
		if err != nil {
			t.Fatalf("newReplayCache(%s): %v", lifetime, err)
		}
		if c.lifetime != lifetime {
			t.Fatalf("newReplayCache(%s) built a cache with lifetime %s; the constructor is "+
				"still substituting a value of its own", lifetime, c.lifetime)
		}
	}

	// The refusal is unreachable from NewResponder, and this is why: resolve
	// guarantees window >= 1s and skew >= window, so spread >= 1 and the lifetime
	// is at least 3s. Asserted rather than stated, over the extreme configuration
	// (the narrowest legal window, the smallest legal skew), because if the
	// freshness arithmetic ever changed so that a real gateway COULD compute a
	// non-positive lifetime, this file should say so loudly rather than let a
	// gateway fail to start in production.
	narrowest := Freshness{BucketWindow: time.Second, MaxSkew: time.Second}
	window, spread, err := narrowest.resolve()
	if err != nil {
		t.Fatalf("the narrowest legal freshness does not resolve: %v", err)
	}
	if floor := time.Duration(2*spread+1) * window; floor < 3*time.Second {
		t.Fatalf("the narrowest legal freshness yields a replay lifetime of %s; the refusal in "+
			"newReplayCache has stopped being unreachable from NewResponder, which means a "+
			"real gateway configuration can now fail to start", floor)
	}

	// And the whole path really does hold: a responder built on that extreme
	// configuration constructs, which is the end-to-end statement that the guard
	// refuses nothing legitimate.
	h := newHarness(t)
	cfg := h.gwCf
	cfg.Gateway.Fresh = narrowest
	if _, err := NewResponder(cfg, h.gateway, func([]byte) error { return nil }); err != nil {
		t.Fatalf("a responder at the narrowest legal freshness was refused: %v; the replay "+
			"lifetime guard is rejecting a configuration the freshness rules allow", err)
	}
}

// --- L1: the admission layer never contributes to integrity ------------------
//
// The review's L1 is not a vulnerability and this test does not claim to find
// one. The transcript hash h commits to protocolLabel, the responder's static
// public key, the ephemeral, the sealed static and the sealed payload — and to
// none of the admission parameters: not the tag, not the never-transmitted
// bucket, not tagLen, not gatewayID, not the whitening keystream. That omission
// is deliberate, it is now stated as a named non-goal in doc.go, and this is the
// test that stops it drifting.
//
// What TestGatewayIDBindsTheTag and TestTagSizeBindsTheTag already prove is that
// the OUTER tag rejects a cross-parameter message. That is a useful property and
// it is not this one. Neither of them would notice if the cryptographic core
// quietly came to depend on the outer tag for its integrity, because in both of
// them the outer tag rejects first and nothing downstream is ever exercised.
//
// So these tests do the opposite. Every message below is minted under the
// RECEIVING gateway's own admission key, its own gateway id, its own tag length
// and a bucket of the test's choosing, so it passes the admission layer
// legitimately and by construction — the technique TestLowOrderEphemeralRejected
// uses to reach the cryptography. Whatever happens next is the core's own doing.
// This is as close as an in-package test can get to deleting the admission layer
// and asking whether the handshake is still sound.

// resealUnder re-wraps an already-recovered handshake body as a complete on-wire
// initiation under an arbitrary admission profile, at an arbitrary bucket
// offset. It performs no cryptography of its own on the body: the body goes in
// unmodified and comes out whitened under whatever profile was asked for.
func resealUnder(t *testing.T, body []byte, g GatewayParams, at time.Time, bucketShift int64) []byte {
	t.Helper()
	window, _, err := g.Fresh.resolve()
	if err != nil {
		t.Fatalf("resolve freshness: %v", err)
	}
	return sealAdmission(body, g.AdmissionKeys[0], g.GatewayID, g.tagSize(),
		bucketIndex(at, window)+bucketShift)
}

// TestInnerCryptoRejectsCrossGatewayInitiation pins L1: the handshake's
// integrity must never depend on the admission tag.
//
// Gateway A and gateway B share one admission key. That is not a contrived
// shape — GatewayParams.AdmissionKeys is plural precisely so that a key rotation
// can have one key live on more than one gateway at once, and the whole reason
// gatewayID is an authenticated tag input is that this happens. Under a shared
// key, an initiation minted for A can be re-wrapped for B by anyone holding the
// key, which means the outer tag is exactly as strong as a secret that every
// client of the fleet segment holds. The core must not be relying on it.
func TestInnerCryptoRejectsCrossGatewayInitiation(t *testing.T) {
	a := newHarnessSeeded(t, "-l1-a")
	shared := a.gwCf.Gateway.AdmissionKeys[0]

	// B is a genuinely different gateway: its own static key, its own gateway
	// id, a different tag length — and A's admission key.
	b := newHarnessSeeded(t, "-l1-b", func(hh *harness) {
		hh.gwCf.Gateway.AdmissionKeys = [][]byte{shared}
		hh.gwCf.Gateway.TagSize = MinTagSize
	})
	if bytes.Equal(a.gateway.Public(), b.gateway.Public()) {
		t.Fatal("the two harnesses share a gateway static key, so 'cross gateway' means " +
			"nothing here and every assertion below is vacuous")
	}
	if a.gwCf.Gateway.tagSize() == b.gwCf.Gateway.tagSize() {
		t.Fatal("the two gateways were meant to differ in tag length")
	}

	ini := a.initiator(t)
	msg, err := ini.WriteInitiation([]byte("l1 probe"), PadAuto)
	if err != nil {
		t.Fatalf("write initiation: %v", err)
	}

	// The plaintext body A's client actually produced: ephemeral || sealed
	// static || sealed payload. Nothing below ever alters it except where a
	// subtest says it does.
	body, _, _, err := verifyAdmission(msg, a.gwCf.Gateway, a.now)
	if err != nil {
		t.Fatalf("A's own initiation did not verify at A: %v", err)
	}

	t.Run("cross gateway with the admission layer satisfied", func(t *testing.T) {
		crossed := resealUnder(t, body, b.gwCf.Gateway, b.now, 0)

		// First: establish that the outer layer is NOT what rejects. B's
		// admission check accepts this message and hands back A's body intact.
		// If this ever starts failing, the assertion after it proves nothing.
		got, ki, _, err := verifyAdmission(crossed, b.gwCf.Gateway, b.now)
		if err != nil {
			t.Fatalf("the cross-gateway message does not pass B's admission layer (%v), so "+
				"this test would be re-proving TestGatewayIDBindsTheTag instead of the "+
				"property it exists for", err)
		}
		if ki != 0 || !bytes.Equal(got, body) {
			t.Fatalf("B's admission layer recovered a different body (key index %d)", ki)
		}

		// Second, and this is the finding: the core rejects it anyway, and the
		// rejection is an AEAD authentication failure, not an admission failure.
		// newChain seeds the transcript on the RESPONDER's static public key and
		// the first stage key descends from es = DH(eph, R_static), so the key
		// that would have to open CStatic at B is not the key it was sealed
		// under at A. Remove the entire admission layer and this still holds.
		rh, err := b.resp.ReadInitiation(crossed)
		if !errors.Is(err, ErrDecrypt) {
			t.Fatalf("expected the INNER AEAD to reject a cross-gateway initiation with "+
				"ErrDecrypt, got %v. The handshake's integrity has come to depend on the "+
				"admission tag, which is a fleet-segment obfuscation secret and not an "+
				"identity; see the non-goal in doc.go", err)
		}
		if rh != nil {
			t.Fatal("a rejected initiation returned a handshake")
		}
	})

	t.Run("a tampered body under a freshly computed tag", func(t *testing.T) {
		// An admission-key holder can always recompute the tag over a mutation,
		// so the outer tag protects the body against nobody who matters. This is
		// the same message an attacker would get for free if the outer tag were
		// deleted outright. Both inner AEADs must catch it on their own.
		ephLen := DefaultEphemeralCodec.WireSize()
		for _, tc := range []struct {
			name string
			off  int
		}{
			{"sealed static", ephLen},
			{"sealed payload", ephLen + KeySize + AEADTagSize},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tampered := append([]byte(nil), body...)
				tampered[tc.off] ^= 0x01

				forged := resealUnder(t, tampered, a.gwCf.Gateway, a.now, 0)
				if _, _, _, err := verifyAdmission(forged, a.gwCf.Gateway, a.now); err != nil {
					t.Fatalf("the tampered message must still satisfy A's admission layer, "+
						"or the mutation is being caught by the wrapper we are trying to "+
						"take out of the picture: %v", err)
				}
				if _, err := a.resp.ReadInitiation(forged); !errors.Is(err, ErrDecrypt) {
					t.Fatalf("a one-bit mutation of the %s field under a valid tag must be "+
						"rejected by the inner AEAD with ErrDecrypt, got %v", tc.name, err)
				}
			})
		}
	})

	t.Run("the same body re-bucketed is still accepted by its own gateway", func(t *testing.T) {
		// The positive control, and the reason the assertions above are not
		// vacuous. If resealUnder damaged the body, or if the two harnesses
		// disagreed about something unrelated to gateway identity, every
		// rejection above would be explained by that instead of by the property
		// under test. Here the same body, re-wrapped by the same helper at a
		// DIFFERENT bucket, completes a handshake.
		//
		// It also states the boundary of the invariant honestly: the bucket
		// really is not transcript-bound, and a legitimately re-bucketed body
		// really is accepted. That is harmless — it is the same body, from the
		// same client, to the same gateway, inside the same skew window, and a
		// second delivery is what the replay cache is for.
		rewrapped := resealUnder(t, body, a.gwCf.Gateway, a.now, -1)
		if bytes.Equal(rewrapped, msg) {
			t.Fatal("the re-bucketed message is byte-identical to the original, so the " +
				"bucket is not reaching the tag and this control proves nothing")
		}
		rh, err := a.resp.ReadInitiation(rewrapped)
		if err != nil {
			t.Fatalf("A refused a faithfully re-sealed copy of a body its own client "+
				"produced (%v); the cross-gateway rejection above is then unexplained", err)
		}
		if !bytes.Equal(rh.InitiatorStatic(), a.client.Public()) {
			t.Fatal("the accepted handshake recovered the wrong client identity")
		}
	})
}

// TestAdmissionParametersAreInvisibleToTheCore is the other half of the
// invariant, and the half that keeps the statement in doc.go honest rather than
// decorative.
//
// Saying "the core does not depend on the admission layer" is only meaningful if
// the core genuinely cannot see it. Here one gateway — one static key, one
// client — is presented under two entirely different admission profiles:
// different gateway id, different tag length, different bucket. The core accepts
// both, because from its point of view nothing changed. That is correct: a
// gateway is its static key, and gatewayID/tagLen/bucket are wire parameters of
// the wrapper, not identity.
//
// It is also the sharpest available check that the rejection in the test above
// is caused by the gateway static key and by nothing incidental to the harness.
//
// One qualification, found by writing this test and recorded at the point it
// bites: tagLen is additionally the width of the response's first field, so the
// two ends must agree on it to frame a reply. That is a framing dependency and
// not an integrity one, and the second half below states it precisely.
func TestAdmissionParametersAreInvisibleToTheCore(t *testing.T) {
	a := newHarnessSeeded(t, "-l1-a")

	// Same seed, so the same gateway static key and the same authorised client —
	// deliberately, this is the same cryptographic endpoint — but a completely
	// different admission profile.
	twin := newHarnessSeeded(t, "-l1-a", func(hh *harness) {
		hh.gwCf.Gateway.GatewayID = []byte("gw-l1-twin")
		hh.gwCf.Gateway.TagSize = MinTagSize
	})
	if !bytes.Equal(a.gateway.Public(), twin.gateway.Public()) {
		t.Fatal("the twin was meant to share A's static key")
	}
	if bytes.Equal(a.gwCf.Gateway.GatewayID, twin.gwCf.Gateway.GatewayID) {
		t.Fatal("the twin was meant to carry a different gateway id")
	}

	ini := a.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatalf("write initiation: %v", err)
	}
	body, _, _, err := verifyAdmission(msg, a.gwCf.Gateway, a.now)
	if err != nil {
		t.Fatalf("A's own initiation did not verify at A: %v", err)
	}

	// Re-wrapped under the twin's profile, at a shifted bucket, with a 16-byte
	// tag instead of a 32-byte one. Every admission parameter differs.
	rewrapped := resealUnder(t, body, twin.gwCf.Gateway, twin.now, 2)
	if len(rewrapped) != MinTagSize+len(body) {
		t.Fatalf("re-wrapped message is %d bytes, expected %d", len(rewrapped), MinTagSize+len(body))
	}

	rh, err := twin.resp.ReadInitiation(rewrapped)
	if err != nil {
		t.Fatalf("the core refused a message whose only differences from an accepted one "+
			"are admission parameters (%v). Either the transcript has started binding the "+
			"admission layer, or an accept decision has started consulting it; both break "+
			"the non-goal stated in doc.go", err)
	}
	if !bytes.Equal(rh.InitiatorStatic(), a.client.Public()) {
		t.Fatal("wrong client identity recovered through a re-wrapped admission profile")
	}

	// The whole session completes across a changed profile too, with one honest
	// qualification that this test exists to record rather than paper over.
	//
	// tagLen is not only an authenticated tag input; it is also the WIDTH OF THE
	// FIRST FIELD of the response, and the response is parsed by offset. So the
	// two ends must agree on it to frame the reply at all — in exactly the way
	// Freshness is shared configuration and not negotiated, and for the same
	// reason: there is no field to carry it and no error to report a mismatch.
	// That is a framing dependency, not an integrity one. The response tag is
	// keyed from the chain (labelRespTag), which never saw the admission key, so
	// a tagLen disagreement costs a dropped reply and never a forged one.
	//
	// So the completion half varies the parameters that are genuinely invisible
	// end to end — gateway id and bucket — and keeps the field width agreed.
	peer := newHarnessSeeded(t, "-l1-a", func(hh *harness) {
		hh.gwCf.Gateway.GatewayID = []byte("gw-l1-peer")
	})
	ini2 := a.initiator(t)
	msg2, err := ini2.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatalf("write second initiation: %v", err)
	}
	body2, _, _, err := verifyAdmission(msg2, a.gwCf.Gateway, a.now)
	if err != nil {
		t.Fatalf("A's second initiation did not verify at A: %v", err)
	}
	rh2, err := peer.resp.ReadInitiation(resealUnder(t, body2, peer.gwCf.Gateway, peer.now, -2))
	if err != nil {
		t.Fatalf("the core refused a re-wrapped initiation under a different gateway id "+
			"and bucket: %v", err)
	}
	resp, gwSess, err := rh2.WriteResponse(nil, PadAuto)
	if err != nil {
		t.Fatalf("write response: %v", err)
	}
	cliSess, _, err := ini2.ReadResponse(resp)
	if err != nil {
		t.Fatalf("the initiator could not complete against a gateway whose gateway id and "+
			"bucket it does not share: %v", err)
	}
	sealed, err := cliSess.Seal([]byte("l1"), 0)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := gwSess.Open(sealed); err != nil {
		t.Fatalf("the two sessions do not agree on keys: %v", err)
	}
}

// --- L7: the ephemeral codec sits inside the integrity boundary --------------

// TestElligatorDoesNotDependOnTheAdmissionLayer pins the non-goal in doc.go
// against the change this file makes.
//
// The ephemeral encoding sits INSIDE the boundary that says "delete the entire
// admission layer and the cryptographic core must remain exactly as sound as it
// is today". A codec that consulted the admission key, the gateway identity,
// the freshness bucket or the tag would move a piece of the core outside that
// boundary, and it would do so invisibly: the handshake would still round-trip.
//
// The test makes it visible. One client key and one ephemeral draw are run
// under two admission profiles that share NOTHING — different admission key,
// different gateway identity, different tag length, different clock and
// therefore a different bucket — and the ephemeral field of the recovered body
// must be byte-identical. It cannot be, if anything about the admission layer
// reached the codec.
func TestElligatorDoesNotDependOnTheAdmissionLayer(t *testing.T) {
	ephField := func(seed string, mutate func(*harness)) []byte {
		t.Helper()
		h := newHarnessSeeded(t, seed, func(hh *harness) {
			hh.clientCf.Codec = Elligator2Codec
			hh.gwCf.Codec = Elligator2Codec
			mutate(hh)
		})
		ini := h.initiator(t)
		msg, err := ini.WriteInitiation(nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", seed, err)
		}
		body, _, _, err := verifyAdmission(msg, h.gwCf.Gateway, h.now)
		if err != nil {
			t.Fatalf("%s: %v", seed, err)
		}
		return body[:Elligator2Codec.WireSize()]
	}

	base := ephField("-ell-inv", func(*harness) {})
	twin := ephField("-ell-inv", func(hh *harness) {
		hh.gwCf.Gateway.AdmissionKeys = [][]byte{bytes.Repeat([]byte{0x5C}, 32)}
		hh.clientCf.Gateway.AdmissionKeys = [][]byte{bytes.Repeat([]byte{0x5C}, 32)}
		hh.gwCf.Gateway.GatewayID = []byte("a-completely-different-gateway")
		hh.clientCf.Gateway.GatewayID = []byte("a-completely-different-gateway")
		hh.gwCf.Gateway.TagSize = MinTagSize
		hh.clientCf.Gateway.TagSize = MinTagSize
		hh.now = hh.now.Add(9999)
	})

	if !bytes.Equal(base, twin) {
		t.Fatalf("the elligator ephemeral field changed when only admission parameters "+
			"changed:\n  %x\n  %x\nSomething in the admission layer has reached the "+
			"ephemeral codec, which breaks the non-goal stated in doc.go", base, twin)
	}

	// The other direction of the same invariant: an Elligator2 initiation
	// re-wrapped under a foreign admission profile is still accepted by the
	// core, because the core never looked at the wrapper. This is the
	// Elligator2 analogue of TestAdmissionParametersAreInvisibleToTheCore.
	a := newHarnessSeeded(t, "-ell-rewrap", func(hh *harness) {
		hh.clientCf.Codec = Elligator2Codec
		hh.gwCf.Codec = Elligator2Codec
	})
	peer := newHarnessSeeded(t, "-ell-rewrap", func(hh *harness) {
		hh.clientCf.Codec = Elligator2Codec
		hh.gwCf.Codec = Elligator2Codec
		hh.gwCf.Gateway.GatewayID = []byte("gw-ell-peer")
	})
	ini := a.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	body, _, _, err := verifyAdmission(msg, a.gwCf.Gateway, a.now)
	if err != nil {
		t.Fatal(err)
	}
	rh, err := peer.resp.ReadInitiation(resealUnder(t, body, peer.gwCf.Gateway, peer.now, -1))
	if err != nil {
		t.Fatalf("the core refused an Elligator2 initiation whose only difference is its "+
			"admission wrapper: %v", err)
	}
	if !bytes.Equal(rh.InitiatorStatic(), a.client.Public()) {
		t.Fatal("wrong client identity recovered through a re-wrapped Elligator2 initiation")
	}
}

// --- L8: admission-key rotation must not re-open the replay window -----------
//
// Found by the hub lane while designing rotation
// (docs/handoff/HUB_V3_DESCRIPTORS_ROTATION_20260808.md §4.4). Before
// Responder.SetAdmissionKeys existed, rotating a live gateway meant constructing
// a new Responder, which discards the handshake replay cache.
//
// The first consequence is that a captured initiation becomes a working gateway
// detector again for (2*spread+1)*window — 130 s at the defaults — which is
// precisely the property the cache exists to remove.
//
// The second is worse and is why these tests are invariants rather than
// behaviours: the window opens AT THE ROTATION INSTANT, so it is a CLOCK. An
// observer replaying one captured initiation on a schedule learns when the
// gateway rotated. Rotation is otherwise invisible — the admission key is used
// only in the initiation and never again, so an established session never
// touches it and a rotation emits no packet at all — and the rotation mechanism
// would have been the one thing giving it a signature.

// rotationHarness builds a gateway holding `first` and a client for whichever
// key it is handed, with a shared clock the test drives.
func rotationHarness(t *testing.T, seed string) (*harness, []byte, []byte) {
	t.Helper()
	oldKey := bytes.Repeat([]byte{0xA1}, 32)
	newKey := bytes.Repeat([]byte{0xB2}, 32)
	h := newHarnessSeeded(t, seed, func(hh *harness) {
		hh.clientCf.Gateway.AdmissionKeys = [][]byte{oldKey}
		hh.gwCf.Gateway.AdmissionKeys = [][]byte{oldKey}
	})
	return h, oldKey, newKey
}

// TestRotationPreservesTheReplayCache is the test that would have failed before
// SetAdmissionKeys existed, and it is written so that it cannot pass vacuously.
//
// It captures one genuine initiation, has the gateway accept it, rotates the key
// set, and then requires the identical bytes to be refused at EVERY instant of
// the acceptance window on both sides of the rotation boundary — including at
// the rotation instant itself, which is the instant the defect made special.
//
// The control at the end is the load-bearing half: the same replay, against a
// Responder rebuilt the old way, MUST be accepted. Without it this test would
// still pass if the replay cache stopped working altogether, or if the captured
// message had never been acceptable in the first place.
func TestRotationPreservesTheReplayCache(t *testing.T) {
	h, oldKey, newKey := rotationHarness(t, "-rot-cache")

	window, spread, err := h.gwCf.Gateway.Fresh.resolve()
	if err != nil {
		t.Fatal(err)
	}
	span := time.Duration(2*spread+1) * window

	ini := h.initiator(t)
	captured, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatalf("write initiation: %v", err)
	}

	// Accept it once, at the earliest instant its tag is acceptable — the worst
	// case for the coupling, because the cache entry is stamped as early as it
	// can be.
	earliest := fixedNow.Add(-time.Duration(spread) * window)
	h.now = earliest
	if _, err := h.resp.ReadInitiation(captured); err != nil {
		t.Fatalf("the genuine initiation was refused: %v", err)
	}

	// Rotate IN PLACE, mid-window, to a two-key overlap.
	h.now = fixedNow
	if err := h.resp.SetAdmissionKeys([][]byte{newKey, oldKey}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if n := h.resp.AdmissionKeyCount(); n != 2 {
		t.Fatalf("after rotation the gateway holds %d keys, expected 2", n)
	}

	// The identical bytes must be refused at every step across the whole
	// acceptance window and past its end, with the rotation instant inside it.
	expiry := earliest.Add(span)
	step := window / 4
	for at := earliest; at.Before(expiry.Add(2 * window)); at = at.Add(step) {
		h.now = at
		if _, err := h.resp.ReadInitiation(captured); err == nil {
			t.Fatalf("a captured initiation was accepted a second time at %s, %s after "+
				"the rotation. The rotation discarded or partitioned the replay cache, "+
				"which hands a censor a gateway detector and a rotation clock at once",
				at, at.Sub(fixedNow))
		}
	}

	// Rotate again, this time retiring the old key, and check the cache still
	// remembers across a second rotation.
	if err := h.resp.SetAdmissionKeys([][]byte{newKey}); err != nil {
		t.Fatalf("second rotation: %v", err)
	}
	h.now = earliest
	if _, err := h.resp.ReadInitiation(captured); err == nil {
		t.Fatal("the captured initiation was accepted after a second rotation")
	}

	// THE CONTROL. The old rotation route — build a new Responder — accepts it.
	// This is the defect, asserted, so that the test above cannot quietly become
	// a test of nothing.
	rebuiltCf := h.gwCf
	rebuiltCf.Gateway.AdmissionKeys = [][]byte{newKey, oldKey}
	rebuilt, err := NewResponder(rebuiltCf, h.gateway, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	h.now = earliest
	if _, err := rebuilt.ReadInitiation(captured); err != nil {
		t.Fatalf("the control failed: rebuilding the Responder was supposed to accept "+
			"the replay, and did not (%v). Either the captured message is not what this "+
			"test thinks it is, or the test above proves nothing", err)
	}
}

// TestRotationDoesNotResetTheFreshnessCoupling.
//
// The acceptance window and the replay-cache lifetime are the same span by
// construction, (2*spread+1)*window. A rotation that preserved the cache but
// reset the freshness state — or the reverse — would reintroduce the same hole
// through the other door, and TestRotationPreservesTheReplayCache would not
// necessarily see it, because it drives one captured message.
//
// So this drives the boundary directly: the cache entry laid down before the
// rotation must expire at exactly the same instant it would have without one,
// and the tag must stop being acceptable at that same instant. If the rotation
// had restarted the cache's clock, the entry would outlive the tag and this
// would catch it.
func TestRotationDoesNotResetTheFreshnessCoupling(t *testing.T) {
	h, oldKey, newKey := rotationHarness(t, "-rot-fresh")
	window, spread, err := h.gwCf.Gateway.Fresh.resolve()
	if err != nil {
		t.Fatal(err)
	}
	span := time.Duration(2*spread+1) * window

	ini := h.initiator(t)
	captured, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	earliest := fixedNow.Add(-time.Duration(spread) * window)
	h.now = earliest
	if _, err := h.resp.ReadInitiation(captured); err != nil {
		t.Fatalf("first acceptance: %v", err)
	}

	// Rotate halfway through the span.
	h.now = earliest.Add(span / 2)
	if err := h.resp.SetAdmissionKeys([][]byte{newKey, oldKey}); err != nil {
		t.Fatal(err)
	}

	// One nanosecond before the entry expires: refused as a replay, because the
	// tag is still acceptable and the cache still holds it.
	h.now = earliest.Add(span - time.Nanosecond)
	if _, err := h.resp.ReadInitiation(captured); !errors.Is(err, ErrReplay) {
		t.Fatalf("just inside the window the refusal must be ErrReplay, got %v. "+
			"A different error means the cache forgot before the tag expired, which is "+
			"the hole this pair of quantities exists to close", err)
	}

	// At and past expiry: the tag itself is no longer acceptable, so the refusal
	// changes hands to the admission check. Either way it is refused, and the
	// handover is what the two quantities coinciding buys.
	h.now = earliest.Add(span)
	if _, err := h.resp.ReadInitiation(captured); err == nil {
		t.Fatal("the captured initiation was accepted at the expiry instant")
	} else if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("at expiry the tag must be the thing that refuses, got %v", err)
	}
}

// TestRotationAcceptsBothLiveKeysDuringTheOverlap: the point of holding two keys
// is that clients which have not yet fetched the new descriptor keep working.
// Both must be accepted, and neither must be preferred in a way an observer
// could see (see TestRotationRejectCostIsIndependentOfKeyOrder).
func TestRotationAcceptsBothLiveKeysDuringTheOverlap(t *testing.T) {
	h, oldKey, newKey := rotationHarness(t, "-rot-overlap")
	if err := h.resp.SetAdmissionKeys([][]byte{newKey, oldKey}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		key  []byte
	}{{"client still on the old key", oldKey}, {"client on the new key", newKey}} {
		cf := h.clientCf
		cf.Gateway.AdmissionKeys = [][]byte{tc.key}
		gwPub, err := NewPublicKey(h.gateway.Public())
		if err != nil {
			t.Fatal(err)
		}
		ini, err := NewInitiator(cf, h.client, gwPub)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := ini.WriteInitiation(nil, PadAuto)
		if err != nil {
			t.Fatal(err)
		}
		rh, err := h.resp.ReadInitiation(msg)
		if err != nil {
			t.Fatalf("%s: refused during the overlap: %v", tc.name, err)
		}
		// And the whole exchange completes, so the overlap is not merely an
		// admission-level courtesy.
		resp, gwSess, err := rh.WriteResponse(nil, PadAuto)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		cliSess, _, err := ini.ReadResponse(resp)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		sealed, err := cliSess.Seal([]byte("overlap"), 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := gwSess.Open(sealed); err != nil {
			t.Fatalf("%s: sessions disagree: %v", tc.name, err)
		}
	}

	// A retired key stops working, which is the other half of a rotation.
	if err := h.resp.SetAdmissionKeys([][]byte{newKey}); err != nil {
		t.Fatal(err)
	}
	ini := h.initiator(t) // still configured with oldKey
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.resp.ReadInitiation(msg); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a retired key must stop being accepted, got %v", err)
	}
}

// TestRotationRejectCostIsIndependentOfKeyOrder is a COST assertion, and it
// exists because a cost-only regression here is a flood amplifier that no
// correctness test would notice — the exact shape of defect that has escaped a
// first pass three times on this protocol.
//
// It uses allocation counts rather than wall-clock time, so it is deterministic
// rather than flaky. verifyAdmission allocates one whitening keystream per key
// tried, so the count is a direct, exact witness of "every key really was
// tried": if an early exit ever appeared, the count would drop.
//
// Three things are pinned:
//
//  1. Two keys cost strictly more than one. Without this the other two
//     assertions could both hold while nothing was being tried at all.
//  2. The cost does not depend on the ORDER of the key set. If it did, a
//     rejection under a freshly rotated set would be distinguishable from one
//     under a settled set, which is a rotation clock by another route.
//  3. A rotated Responder costs exactly what a freshly constructed one with the
//     same key set costs. The rotation seam itself must be free.
func TestRotationRejectCostIsIndependentOfKeyOrder(t *testing.T) {
	h, oldKey, newKey := rotationHarness(t, "-rot-cost")

	// A datagram that matches nothing: the unauthenticated reject path.
	junk := bytes.Repeat([]byte{0x5E}, 200)
	measure := func(r *Responder) float64 {
		return testing.AllocsPerRun(50, func() {
			if _, err := r.ReadInitiation(junk); err == nil {
				t.Fatal("junk was accepted")
			}
		})
	}

	oneKey := measure(h.resp)

	if err := h.resp.SetAdmissionKeys([][]byte{newKey, oldKey}); err != nil {
		t.Fatal(err)
	}
	twoKeysNewFirst := measure(h.resp)
	if err := h.resp.SetAdmissionKeys([][]byte{oldKey, newKey}); err != nil {
		t.Fatal(err)
	}
	twoKeysOldFirst := measure(h.resp)

	if twoKeysNewFirst <= oneKey {
		t.Fatalf("two keys cost %v allocations and one costs %v; if the second key were "+
			"really being tried the cost would rise, so the reject path is exiting early",
			twoKeysNewFirst, oneKey)
	}
	if twoKeysNewFirst != twoKeysOldFirst {
		t.Fatalf("the reject path costs %v allocations with the new key first and %v with "+
			"the old key first. A cost that depends on key order lets an observer see "+
			"where in a rotation the gateway is", twoKeysNewFirst, twoKeysOldFirst)
	}

	// A freshly built Responder with the same key set must cost the same, so the
	// rotation seam adds nothing.
	freshCf := h.gwCf
	freshCf.Gateway.AdmissionKeys = [][]byte{oldKey, newKey}
	fresh, err := NewResponder(freshCf, h.gateway, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got := measure(fresh); got != twoKeysOldFirst {
		t.Fatalf("a rotated Responder costs %v allocations and a freshly built one with "+
			"the same keys costs %v; the rotation seam is not free", twoKeysOldFirst, got)
	}
}

// TestRotationSeamIsFreeOnTheHotPath pins the seam itself rather than the key
// set: reading the live key set through the atomic pointer must allocate
// nothing, so that rotation costs the packet path zero.
//
// Measured against verifyAdmission called directly with the same parameters,
// which is the same work minus the seam. Any allocation the seam introduced —
// copying the key set per packet, say, which is the obvious careless
// implementation — shows up as a difference here and nowhere else.
func TestRotationSeamIsFreeOnTheHotPath(t *testing.T) {
	h, _, _ := rotationHarness(t, "-rot-hot")
	junk := bytes.Repeat([]byte{0x77}, 200)

	viaResponder := testing.AllocsPerRun(50, func() {
		if _, err := h.resp.ReadInitiation(junk); err == nil {
			t.Fatal("junk was accepted")
		}
	})
	params := h.gwCf.Gateway
	direct := testing.AllocsPerRun(50, func() {
		if _, _, _, err := verifyAdmission(junk, params, h.now); err == nil {
			t.Fatal("junk was accepted")
		}
	})
	if viaResponder != direct {
		t.Fatalf("ReadInitiation costs %v allocations on the reject path and a direct "+
			"verifyAdmission with the same parameters costs %v. The rotation seam is "+
			"allocating per packet, which is a flood amplifier no correctness test sees",
			viaResponder, direct)
	}
}

// TestRotationIsInvisibleToTheCore keeps the doc.go non-goal honest for this
// change too.
//
// SetAdmissionKeys touches the admission layer, which sits OUTSIDE the integrity
// boundary. It must therefore be unobservable to anything inside it: a handshake
// already in flight must complete across a rotation, and an established session
// must keep working, because the admission key is used once in the initiation
// and never again.
//
// That last property is not incidental — it is what makes rotation emit no
// packet at all, and it is the property the discarded-cache defect would have
// undermined from the other side.
func TestRotationIsInvisibleToTheCore(t *testing.T) {
	h, oldKey, newKey := rotationHarness(t, "-rot-core")

	// A handshake that starts before the rotation and finishes after it.
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	rh, err := h.resp.ReadInitiation(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.resp.SetAdmissionKeys([][]byte{newKey}); err != nil {
		t.Fatal(err)
	}
	resp, gwSess, err := rh.WriteResponse(nil, PadAuto)
	if err != nil {
		t.Fatalf("a response could not be written after the key set rotated underneath "+
			"the handshake: %v", err)
	}
	cliSess, _, err := ini.ReadResponse(resp)
	if err != nil {
		t.Fatalf("the initiator could not complete across a rotation: %v", err)
	}

	// And the session keeps working across two further rotations.
	for i, keys := range [][][]byte{{oldKey, newKey}, {oldKey}} {
		if err := h.resp.SetAdmissionKeys(keys); err != nil {
			t.Fatal(err)
		}
		sealed, err := cliSess.Seal([]byte("still here"), 0)
		if err != nil {
			t.Fatal(err)
		}
		got, err := gwSess.Open(sealed)
		if err != nil {
			t.Fatalf("rotation %d broke an established session: %v", i, err)
		}
		if string(got) != "still here" {
			t.Fatalf("rotation %d corrupted the payload: %q", i, got)
		}
	}
}

// TestSetAdmissionKeysRefusals covers the seam's contract, including the two
// things it must refuse structurally rather than by check.
func TestSetAdmissionKeysRefusals(t *testing.T) {
	h, oldKey, newKey := rotationHarness(t, "-rot-refuse")

	if err := h.resp.SetAdmissionKeys(nil); !errors.Is(err, ErrConfig) {
		t.Errorf("an empty key set must be refused, got %v", err)
	}
	if err := h.resp.SetAdmissionKeys([][]byte{bytes.Repeat([]byte{1}, 16)}); !errors.Is(err, ErrConfig) {
		t.Errorf("a short key must be refused, got %v", err)
	}
	// The reject-path budget. At the default spread of 6 each key costs 13
	// HMACs, so five keys is 65 and over the 64 ceiling.
	_, spread, err := h.gwCf.Gateway.Fresh.resolve()
	if err != nil {
		t.Fatal(err)
	}
	perKey := 2*spread + 1
	tooMany := make([][]byte, MaxAdmissionHMACs/perKey+1)
	for i := range tooMany {
		tooMany[i] = bytes.Repeat([]byte{byte(i)}, 32)
	}
	if err := h.resp.SetAdmissionKeys(tooMany); !errors.Is(err, ErrConfig) {
		t.Errorf("%d keys at %d HMACs each is over the %d ceiling and must be refused, got %v",
			len(tooMany), perKey, MaxAdmissionHMACs, err)
	}
	// One fewer is inside the budget and must be allowed, so the ceiling is a
	// ceiling and not a blanket refusal.
	if err := h.resp.SetAdmissionKeys(tooMany[:len(tooMany)-1]); err != nil {
		t.Errorf("%d keys is inside the budget and must be allowed: %v", len(tooMany)-1, err)
	}

	// A refused rotation must leave the previous set live, not a partial one.
	if err := h.resp.SetAdmissionKeys([][]byte{newKey, oldKey}); err != nil {
		t.Fatal(err)
	}
	if err := h.resp.SetAdmissionKeys([][]byte{[]byte("short")}); err == nil {
		t.Fatal("expected a refusal")
	}
	if n := h.resp.AdmissionKeyCount(); n != 2 {
		t.Fatalf("a refused rotation changed the live set to %d keys", n)
	}

	// Freshness is not rotatable, and that is enforced by there being no
	// parameter for it. This asserts the signature rather than a behaviour,
	// because the guarantee IS the signature.
	var _ func([][]byte) error = h.resp.SetAdmissionKeys
}

// TestResponderDoesNotAliasTheCallersKeys: the Responder is safe for concurrent
// use, so a caller that keeps and mutates the slice it passed in must not be
// able to change a key underneath a running verification. That is a data race
// with a security consequence rather than merely a crash, so the key set is
// deep-copied on both entry points.
func TestResponderDoesNotAliasTheCallersKeys(t *testing.T) {
	h, oldKey, newKey := rotationHarness(t, "-rot-alias")

	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate the slice the harness handed to NewResponder.
	h.gwCf.Gateway.AdmissionKeys[0] = bytes.Repeat([]byte{0xFF}, 32)
	if _, err := h.resp.ReadInitiation(msg); err != nil {
		t.Fatalf("mutating the caller's slice changed the gateway's key set: %v", err)
	}

	// And the slice handed to SetAdmissionKeys.
	rotating := [][]byte{append([]byte(nil), newKey...), append([]byte(nil), oldKey...)}
	if err := h.resp.SetAdmissionKeys(rotating); err != nil {
		t.Fatal(err)
	}
	rotating[1] = bytes.Repeat([]byte{0xEE}, 32)
	copy(rotating[0], bytes.Repeat([]byte{0xDD}, 32))

	ini2 := h.initiator(t) // still on oldKey
	msg2, err := ini2.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.resp.ReadInitiation(msg2); err != nil {
		t.Fatalf("mutating the rotating slice changed the live key set: %v", err)
	}
}

// TestRotationUnderConcurrentTraffic runs rotations against concurrent
// verifications, which is the situation a real gateway is in: rotation arrives
// from the control plane while packets keep landing. Under -race this is the
// test that would catch the data race the hub lane predicted from mutating the
// key slice directly.
//
// # Why this cannot pass vacuously
//
// Two things could make it green without proving anything and both are closed.
//
// The first is that no rotation happens at all — the rotator goroutine is
// started but never scheduled — leaving the readers to verify against a static
// key set. The rotations counter and the guard at the end of this function
// exist for that and for nothing else.
//
// The second is the suspicion this test has to survive, because it ENTERS the
// overlap before offering new-key traffic rather than racing into it: that
// pre-installing the key made it blind to a real rotation defect. It did not.
// Mutation-tested 2026-08-09 — replacing the atomic publish in
// SetAdmissionKeys with a TORN one:
//
//	next := make([][]byte, len(keys))
//	r.keys.Store(&next)                  // published with nil elements
//	copy(next, copyAdmissionKeys(keys))  // filled afterwards
//
// is caught by this test on 5 runs out of 5. A rotation that briefly exposes an
// incomplete key set still fails here. What no longer fails here is a client
// arriving before the gateway was ever given its key, which is not a race and
// not a defect. Four further mutants — installing only the first key, reading
// the construction-time key set on the hot path, exiting early after the first
// key, and suppressing the rotation counter — are all caught as well.
//
// # The measurement trap, for whoever investigates this next
//
// This test was flaky (4 failures in 24 runs on a loaded machine) until
// 2026-08-09, always on the new-key initiations and never on the old. If you
// instrument it, sample the key set BEFORE the read and not after. The rotator
// completes roughly ten rotations per MICROSECOND, so a sample taken after a
// refusal reports something like keyCount=2, rotations=165 — which reads
// exactly like an atomicity bug in SetAdmissionKeys and is not one. It is the
// rotator running during the read. Sampled before the read, every refusal
// showed rotations=0 and keyCount=1: the gateway had simply not been handed
// newKey yet.
//
// Freshness was the other suspect and it cannot be involved here. harness.clock
// returns a frozen field, so an initiation is built and read in the same bucket
// by construction, and widening the acceptance span from 130 s to three hours
// changed nothing.
func TestRotationUnderConcurrentTraffic(t *testing.T) {
	h, oldKey, newKey := rotationHarness(t, "-rot-conc")

	// Pre-build initiations under both keys so the workers do no key-dependent
	// work of their own.
	build := func(key []byte, n int) [][]byte {
		out := make([][]byte, 0, n)
		for i := 0; i < n; i++ {
			cf := h.clientCf
			cf.Gateway.AdmissionKeys = [][]byte{key}
			cf.Rand = newDetReader(fmt.Sprintf("rot-conc-%x-%d", key[0], i))
			gwPub, err := NewPublicKey(h.gateway.Public())
			if err != nil {
				t.Fatal(err)
			}
			ini, err := NewInitiator(cf, h.client, gwPub)
			if err != nil {
				t.Fatal(err)
			}
			msg, err := ini.WriteInitiation(nil, PadAuto)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, msg)
		}
		return out
	}
	oldMsgs := build(oldKey, 40)
	newMsgs := build(newKey, 40)
	junk := bytes.Repeat([]byte{0x13}, 180)

	// ENTER THE OVERLAP BEFORE OFFERING NEW-KEY TRAFFIC.
	//
	// rotationHarness starts the gateway holding oldKey ALONE. Until the first
	// SetAdmissionKeys lands, a newKey initiation is refused because the gateway
	// genuinely does not hold that key yet — which is the protocol behaving
	// exactly as specified, not a rotation race. Racing the readers against the
	// rotator's first store made this test fail on 4 runs in 24 on a loaded
	// machine, always on the new-key initiations and never on the old, because
	// oldKey is in every set including the initial one. Under saturation the
	// rotator went unscheduled for as long as 950 µs, and 20 consecutive
	// new-key reads were refused in that gap.
	//
	// A gateway is in the overlap for the whole of a real rotation; the control
	// plane installs the new key before any client is issued it. Installing it
	// here first is therefore the accurate fixture, not a loosened one — the
	// rotator below still flips the order underneath the readers for the whole
	// run, so the concurrent swap this test exists to exercise is unchanged.
	if err := h.resp.SetAdmissionKeys([][]byte{newKey, oldKey}); err != nil {
		t.Fatalf("entering the overlap: %v", err)
	}

	var wg sync.WaitGroup
	var rotations atomic.Int64
	stop := make(chan struct{})

	// Rotator: flips between the two overlap orders, never leaving zero keys
	// live and never retiring a key a reader might be mid-way through.
	wg.Add(1)
	go func() {
		defer wg.Done()
		sets := [][][]byte{
			{newKey, oldKey},
			{oldKey, newKey},
		}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := h.resp.SetAdmissionKeys(sets[i%len(sets)]); err != nil {
				t.Errorf("rotation failed: %v", err)
				return
			}
			rotations.Add(1)
		}
	}()

	// Readers: genuine traffic under both keys plus a flood of junk. Every
	// message is distinct, so a success is a success and never a replay.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < len(oldMsgs); i += 4 {
				if _, err := h.resp.ReadInitiation(oldMsgs[i]); err != nil {
					t.Errorf("old-key initiation %d refused during rotation: %v", i, err)
				}
				if _, err := h.resp.ReadInitiation(newMsgs[i]); err != nil {
					t.Errorf("new-key initiation %d refused during rotation: %v", i, err)
				}
				if _, err := h.resp.ReadInitiation(junk); err == nil {
					t.Error("junk was accepted during rotation")
				}
			}
		}(w)
	}

	// Let the readers finish, then stop the rotator.
	done := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(stop)
		close(done)
	}()
	<-done
	wg.Wait()

	if n := h.resp.AdmissionKeyCount(); n != 2 {
		t.Fatalf("the gateway ended the run holding %d keys", n)
	}

	// THE ANTI-VACUITY GUARD, and the reason pre-installing the overlap does not
	// weaken this test. Everything above would also pass if the rotator
	// goroutine had never been scheduled once — the same starvation that caused
	// the old flake, landing on the other side of the race. Without this, a
	// green run would not distinguish "rotation is safe under concurrent
	// traffic" from "no rotation happened".
	if n := rotations.Load(); n == 0 {
		t.Fatal("no rotation completed while the readers ran, so this test " +
			"exercised a static key set and asserted nothing about rotation")
	}
}

// initiationInitiator builds an Initiator sealed under a specific admission key,
// with a per-seed deterministic random stream so that two callers asking for the
// same key still produce distinct messages.
func initiationInitiator(h *harness, t *testing.T, key []byte, seed string) *Initiator {
	t.Helper()
	cf := h.clientCf
	cf.Gateway.AdmissionKeys = [][]byte{key}
	cf.Rand = newDetReader(seed)
	gwPub, err := NewPublicKey(h.gateway.Public())
	if err != nil {
		t.Fatal(err)
	}
	ini, err := NewInitiator(cf, h.client, gwPub)
	if err != nil {
		t.Fatal(err)
	}
	return ini
}

// initiationUnder builds one initiation message under a specific admission key.
func initiationUnder(h *harness, t *testing.T, key []byte, seed string) []byte {
	t.Helper()
	ini := initiationInitiator(h, t, key, seed)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// TestRotationSurvivesManyEpochs advances the admission key set through many
// rotation epochs and asserts the two invariants that make rotation safe hold at
// EVERY step, not just the first.
//
// # Why it exists
//
// The single-rotation tests pin the seam at its first use. A rotation mechanism
// can survive one round and still be wrong in a way that only shows at a later
// epoch: a rotation that drops or partitions the replay cache only when it is a
// later key being retired, or an overlap that silently shrinks to the newest key
// alone, would pass every one-rotation test while still handing a censor a
// working gateway detector and rotation clock on a later rotation. Real gateways
// rotate on a schedule, so "the first rotation is safe" is not the property that
// matters — "every rotation is safe" is.
//
// # What it pins, per epoch
//
// With k0..kN the key generations, at each rotation to epoch i (live set {ki,
// ki-1}):
//
//  1. REPLAY SURVIVES ROTATION. Every epoch accepts one genuine initiation, and
//     then — at the NEXT rotation, while the accepting key is still in the live
//     set — the identical bytes must be refused as ErrReplay. This is checked at
//     EVERY rotation boundary, not just the first. If any rotation discarded the
//     replay cache, reset its clock, or partitioned it by key, one of these
//     refusals would flip to an acceptance: the exact defect rotation exists to
//     prevent, now measured across twelve epochs rather than once.
//
//  2. MIXTURE DURING THE OVERLAP IS EXACT. The overlap holds exactly the two
//     newest keys. Fresh initiations under BOTH live keys are accepted, while an
//     initiation under EVERY retired key is refused as ErrUnauthenticated.
//     Asserting both the acceptance and the refusal is what keeps this from
//     passing vacuously in either direction.
//
// # Controls
//
// The load-bearing negative is inside the loop: replaying the previous epoch's
// captured bytes must stay a refusal while its key is live. That is the
// assertion that would fail the moment any rotation stopped preserving the
// cache. It is balanced by positive acceptances every epoch (the freshly added
// key's initiation is accepted during its overlap) and by a full handshake to a
// working transport session under each of the two final live keys, so a run that
// refused everything would not be green.
func TestRotationSurvivesManyEpochs(t *testing.T) {
	const epochs = 12
	keys := make([][]byte, epochs)

	h, oldKey, _ := rotationHarness(t, "-rot-many")
	keys[0] = oldKey
	for i := 1; i < epochs; i++ {
		keys[i] = bytes.Repeat([]byte{byte(0xC0 + i)}, 32)
	}

	// Every message is distinct and is sealed under its own epoch key, so a
	// success is a success and never a replay of a neighbouring epoch.
	msgs := make([][]byte, epochs)
	for i := 0; i < epochs; i++ {
		msgs[i] = initiationUnder(h, t, keys[i], fmt.Sprintf("rot-many-%d", i))
	}

	// Accept the epoch-0 initiation once, genuinely. This is the first capture;
	// each epoch in turn accepts the next epoch's message, so that at every
	// rotation the message from the PREVIOUS epoch is the one whose replay must
	// survive — its key is still live in the incoming overlap.
	if _, err := h.resp.ReadInitiation(msgs[0]); err != nil {
		t.Fatalf("the genuine epoch-0 initiation was refused: %v", err)
	}

	// Rotate through epochs 1..N-1 as a two-key overlap, checking both halves of
	// the invariant at every step.
	for i := 1; i < epochs; i++ {
		if err := h.resp.SetAdmissionKeys([][]byte{keys[i], keys[i-1]}); err != nil {
			t.Fatalf("rotation to epoch %d: %v", i, err)
		}
		if n := h.resp.AdmissionKeyCount(); n != 2 {
			t.Fatalf("after rotation to epoch %d the gateway holds %d keys, expected 2", i, n)
		}

		// REPLAY SURVIVES: the message captured and accepted under the previous
		// epoch's key — which is still live in this overlap — must stay a
		// refusal. A rotation that discarded or partitioned the replay cache
		// would make this an acceptance. Note this is checked across EVERY
		// rotation boundary, so a defect that only fired on a later rotation is
		// caught here rather than on the first one.
		if _, err := h.resp.ReadInitiation(msgs[i-1]); !errors.Is(err, ErrReplay) {
			t.Fatalf("after rotation to epoch %d the captured epoch-%d initiation was %v, "+
				"expected ErrReplay. Its key is still live, so a non-ErrReplay result "+
				"means a rotation discarded or partitioned the replay cache", i, i-1, err)
		}

		// MIXTURE: fresh traffic under both live keys is accepted. The newly
		// added key's acceptance also seeds the next replay-survival check.
		previousLive := initiationUnder(h, t, keys[i-1], fmt.Sprintf("rot-many-live-%d", i-1))
		if _, err := h.resp.ReadInitiation(previousLive); err != nil {
			t.Fatalf("a fresh epoch-%d initiation was refused during epoch %d's overlap: %v", i-1, i, err)
		}
		if _, err := h.resp.ReadInitiation(msgs[i]); err != nil {
			t.Fatalf("an epoch-%d initiation was refused during its overlap: %v", i, err)
		}

		// MIXTURE: every retired key is refused, so the overlap is exactly the
		// two newest keys and retirement is enforced at every prior generation.
		if i >= 2 {
			for retired := 0; retired < i-1; retired++ {
				if _, err := h.resp.ReadInitiation(msgs[retired]); !errors.Is(err, ErrUnauthenticated) {
					t.Fatalf("after rotation to epoch %d an epoch-%d initiation was %v, expected "+
						"ErrUnauthenticated: only epochs %d and %d are live, and a key outside "+
						"them must not be accepted", i, retired, err, i-1, i)
				}
			}
		}
	}

	// After the last rotation the live set is exactly the two newest keys.
	if n := h.resp.AdmissionKeyCount(); n != 2 {
		t.Fatalf("after all rotations the gateway holds %d keys, expected 2", n)
	}

	// The captured epoch-0 initiation stays dead even after its key has been
	// retired entirely.
	if _, err := h.resp.ReadInitiation(msgs[0]); err == nil {
		t.Fatal("the captured epoch-0 initiation was accepted after its key was retired")
	}

	// POSITIVE CONTROL: the mixture is only evidence if the live keys carry a
	// real handshake to a working transport session. Complete one under each of
	// the two final live keys.
	for _, i := range []int{epochs - 2, epochs - 1} {
		ini := initiationInitiator(h, t, keys[i], fmt.Sprintf("rot-many-final-%d", i))
		msg, err := ini.WriteInitiation(nil, PadAuto)
		if err != nil {
			t.Fatal(err)
		}
		rh, err := h.resp.ReadInitiation(msg)
		if err != nil {
			t.Fatalf("epoch-%d handshake refused in the settled state: %v", i, err)
		}
		resp, gwSess, err := rh.WriteResponse(nil, PadAuto)
		if err != nil {
			t.Fatal(err)
		}
		cliSess, _, err := ini.ReadResponse(resp)
		if err != nil {
			t.Fatalf("epoch-%d initiator could not complete: %v", i, err)
		}
		sealed, err := cliSess.Seal([]byte("mix"), 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := gwSess.Open(sealed); err != nil {
			t.Fatalf("epoch-%d sessions disagree: %v", i, err)
		}
	}
}

// --- Params: the handshake parameters the conformance gate pins --------------
//
// winn3/conform is a CROSS-HOST suite: it feeds the SAME operator configuration
// into two hosts and fails if their derivations diverge. Every value in
// params.go participates in that bargain, and most of them do so twice — once
// as an input to the transcript hash (so two ends configured differently fail
// to decrypt rather than negotiate) and once as a literal byte on the wire. A
// silent edit to any of them does not surface as a local error: the handshake
// still round-trips end to end, it just does so only between two endpoints
// that happen to share the new value, and the whole fleet interoperates with
// itself while agreeing with nothing else.
//
// That is the failure this file exists to make loud. Each assertion below pins
// a value at the exact figure the conformance gate and the specification rely
// on, plus the cross-constant relationships that keep them coherent, so that a
// bound widened or a size drifted is caught even when both ends of the edit
// agree with each other.
//
// The values are the committed ones; they are restated here only so that a
// future editor who changes params.go is forced to change this file too and
// thereby claim the change in a committed test, exactly as
// TestSuiteIdentityIsPinned does for the three transcript labels.
func TestPinnedHandshakeParamsInvariant(t *testing.T) {
	// --- transcript identity: anything here moves every key in the protocol.
	if WireVersion != "winn/3" {
		t.Errorf("WireVersion = %q, want pinned %q", WireVersion, "winn/3")
	}
	if Suite != "winn3-x25519-mlkem768-chacha20poly1305-sha256" {
		t.Errorf("Suite = %q, want pinned %q", Suite, "winn3-x25519-mlkem768-chacha20poly1305-sha256")
	}
	if protocolLabel != "winn/3 winn3-x25519-mlkem768-chacha20poly1305-sha256" {
		t.Errorf("protocolLabel = %q, want pinned %q", protocolLabel, "winn/3 winn3-x25519-mlkem768-chacha20poly1305-sha256")
	}
	// The label must also be nothing other than the lone concatenation of the
	// two names above; an edit that moves both sides together must still fail.
	if protocolLabel != WireVersion+" "+Suite {
		t.Errorf("protocolLabel (%q) is not WireVersion + \" \" + Suite (%q); "+
			"the transcript label has come apart from its components", protocolLabel, WireVersion+" "+Suite)
	}

	// --- primitive sizes that appear on the wire.
	if KeySize != 32 {
		t.Errorf("KeySize = %d, want 32", KeySize)
	}
	if AEADTagSize != 16 {
		t.Errorf("AEADTagSize = %d, want 16", AEADTagSize)
	}
	if AEADNonceSize != 12 {
		t.Errorf("AEADNonceSize = %d, want 12", AEADNonceSize)
	}
	if nonceSaltSize != 4 {
		t.Errorf("nonceSaltSize = %d, want 4", nonceSaltSize)
	}
	if DemuxTokenSize != 8 {
		t.Errorf("DemuxTokenSize = %d, want 8", DemuxTokenSize)
	}
	if hashSize != 32 {
		t.Errorf("hashSize = %d, want 32", hashSize)
	}
	if minAdmissionKeySize != 32 {
		t.Errorf("minAdmissionKeySize = %d, want 32", minAdmissionKeySize)
	}
	if transportHeaderSize != 2 {
		t.Errorf("transportHeaderSize = %d, want 2", transportHeaderSize)
	}

	// The nonce is built as nonceSaltSize bytes of salt followed by an 8-byte
	// big-endian counter (session.go Seal/Open). This identity is how the two
	// halves of the AEAD nonce stay the size the wire expects.
	if AEADNonceSize != nonceSaltSize+8 {
		t.Errorf("AEADNonceSize (%d) != nonceSaltSize (%d) + 8-byte counter; "+
			"the transport nonce geometry has drifted", AEADNonceSize, nonceSaltSize)
	}
	// The hard ceiling must be representable in that 8-byte counter (and below
	// the 2^63 overflow line of a uint64 send counter).
	if RejectAfterMessages >= uint64(1)<<48 {
		t.Errorf("RejectAfterMessages = %d, which no longer fits the 8-byte nonce counter", RejectAfterMessages)
	}

	// Transport overhead is the demand a session places on the path MTU:
	// demux token || 2-byte header || payload || tag.
	if got := TransportOverhead(); got != DemuxTokenSize+transportHeaderSize+AEADTagSize {
		t.Errorf("TransportOverhead() = %d, not DemuxTokenSize+transportHeaderSize+AEADTagSize = %d",
			got, DemuxTokenSize+transportHeaderSize+AEADTagSize)
	}
	if got := TransportOverhead(); got != 26 {
		t.Errorf("TransportOverhead() = %d, want 26", got)
	}

	// --- admission tag bounds and the default that must sit inside them.
	if MinTagSize != 16 || MaxTagSize != 32 || DefaultTagSize != 32 {
		t.Errorf("admission tag bounds drifted: min=%d max=%d default=%d (want 16/32/32)",
			MinTagSize, MaxTagSize, DefaultTagSize)
	}
	if DefaultTagSize < MinTagSize || DefaultTagSize > MaxTagSize {
		t.Errorf("DefaultTagSize (%d) is outside [MinTagSize=%d, MaxTagSize=%d]; "+
			"the shipping default no longer validates", DefaultTagSize, MinTagSize, MaxTagSize)
	}

	// --- token window: the sentinel must live outside the legal range so that
	// no real size can be mistaken for it, and the default must be legal.
	if MinTokenWindow != 16 || MaxTokenWindow != 1<<16 || DefaultTokenWindow != 1024 {
		t.Errorf("token window drifted: min=%d max=%d default=%d (want 16/65536/1024)",
			MinTokenWindow, MaxTokenWindow, DefaultTokenWindow)
	}
	if CallerOwnsTokenWindow >= MinTokenWindow {
		t.Errorf("CallerOwnsTokenWindow (%d) is inside [MinTokenWindow=%d, ...]; "+
			"the external-index sentinel collides with a legal window size",
			CallerOwnsTokenWindow, MinTokenWindow)
	}
	if DefaultTokenWindow < MinTokenWindow || DefaultTokenWindow > MaxTokenWindow {
		t.Errorf("DefaultTokenWindow (%d) is outside the legal [%d, %d] range",
			DefaultTokenWindow, MinTokenWindow, MaxTokenWindow)
	}

	// --- rekey schedule: soft must precede hard, and bytes must be a budget.
	if RekeyAfterMessages != uint64(1)<<28 {
		t.Errorf("RekeyAfterMessages = %d, want 1<<28", RekeyAfterMessages)
	}
	if RejectAfterMessages != uint64(1<<32)-(1<<16) {
		t.Errorf("RejectAfterMessages = %d, want (1<<32)-(1<<16)", RejectAfterMessages)
	}
	if RekeyAfterBytes != uint64(1)<<36 {
		t.Errorf("RekeyAfterBytes = %d, want 1<<36", RekeyAfterBytes)
	}
	if RekeyAfterMessages >= RejectAfterMessages {
		t.Errorf("RekeyAfterMessages (%d) is not below RejectAfterMessages (%d); the soft trigger no longer precedes the hard ceiling",
			RekeyAfterMessages, RejectAfterMessages)
	}

	// --- freshness defaults: the bucket must be >= 1s (resolve's floor) and
	// the skew must be >= the bucket (resolve's other refusal), or the shipped
	// defaults could never be resolved.
	if DefaultBucketWindow != 10*time.Second || DefaultMaxSkew != 60*time.Second {
		t.Errorf("freshness defaults drifted: bucket=%s skew=%s (want 10s/60s)",
			DefaultBucketWindow, DefaultMaxSkew)
	}
	if DefaultBucketWindow < time.Second {
		t.Errorf("DefaultBucketWindow (%s) is below the 1s floor Freshness.resolve enforces",
			DefaultBucketWindow)
	}
	if DefaultMaxSkew < DefaultBucketWindow {
		t.Errorf("DefaultMaxSkew (%s) is below DefaultBucketWindow (%s); the shipped skew would be refused",
			DefaultMaxSkew, DefaultBucketWindow)
	}

	// --- handshake message geometry: the payload bound must sit inside the
	// message bound, and the message bound must stay well under the IPv6
	// minimum link MTU so an initiation can never fragment.
	if MaxHandshakePayload != 256 || MaxHandshakeMessage != 1024 {
		t.Errorf("handshake geometry drifted: payload=%d message=%d (want 256/1024)",
			MaxHandshakePayload, MaxHandshakeMessage)
	}
	if handshakePayloadHeaderSize != 3 {
		t.Errorf("handshakePayloadHeaderSize = %d, want 3", handshakePayloadHeaderSize)
	}
	if MaxHandshakePayload > MaxHandshakeMessage {
		t.Errorf("MaxHandshakePayload (%d) exceeds MaxHandshakeMessage (%d)",
			MaxHandshakePayload, MaxHandshakeMessage)
	}
	if MaxHandshakeMessage >= 1280 {
		t.Errorf("MaxHandshakeMessage (%d) is no longer under the 1280-byte IPv6 minimum MTU; "+
			"an initiation can now fragment, which is a fingerprint this design exists to avoid",
			MaxHandshakeMessage)
	}
	if maxBucketCandidates != 4096 {
		t.Errorf("maxBucketCandidates = %d, want 4096", maxBucketCandidates)
	}
}
