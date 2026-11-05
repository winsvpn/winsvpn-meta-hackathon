package core

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

// Tests in this file cover error paths where being wrong is expensive: a
// flood-amplifier at gateway construction, a concurrent MixPQ that silently
// desynchronises the epoch, and a few contracts that comments have gotten
// wrong. They live in their own file so they do not collide with other lanes
// editing handshake_test.go / session_test.go / invariants_test.go.

// TestNewResponderEnforcesTheRejectPathBudget closes the construction hole
// MaxAdmissionHMACs used to have: SetAdmissionKeys refused an over-budget key
// set, NewResponder did not. A gateway that never rotated therefore ran with
// an unbounded reject path, and a gateway that later tried to rotate onto the
// same set discovered SetAdmissionKeys would refuse the keys it was already
// using.
//
// The bound is a Responder property, not a GatewayParams.validate property:
// an initiator does not pay the reject-path cost, so a wide-skew client config
// must still construct.
func TestNewResponderEnforcesTheRejectPathBudget(t *testing.T) {
	h := newHarness(t)
	accept := func([]byte) error { return nil }

	_, spread, err := h.gwCf.Gateway.Fresh.resolve()
	if err != nil {
		t.Fatal(err)
	}
	perKey := 2*spread + 1
	tooMany := make([][]byte, MaxAdmissionHMACs/perKey+1)
	for i := range tooMany {
		tooMany[i] = bytes.Repeat([]byte{byte(i + 1)}, 32)
	}

	over := h.gwCf
	over.Gateway.AdmissionKeys = tooMany
	if _, err := NewResponder(over, h.gateway, accept); !errors.Is(err, ErrConfig) {
		t.Fatalf("%d keys at %d HMACs each must be refused at construction, got %v",
			len(tooMany), perKey, err)
	}
	// validate is not where the bound lives. If this starts failing, the check
	// was moved into GatewayParams.validate and will now refuse a wide-skew
	// initiator — the thing the comment on MaxAdmissionHMACs says not to do.
	if err := over.Gateway.validate(true); err != nil {
		t.Fatalf("validate must still accept an over-budget key set (the bound is a Responder property), got %v", err)
	}

	inside := h.gwCf
	inside.Gateway.AdmissionKeys = tooMany[:len(tooMany)-1]
	resp, err := NewResponder(inside, h.gateway, accept)
	if err != nil {
		t.Fatalf("%d keys is inside the budget and must construct: %v", len(tooMany)-1, err)
	}
	if n := resp.AdmissionKeyCount(); n != len(tooMany)-1 {
		t.Fatalf("constructed with %d keys, want %d", n, len(tooMany)-1)
	}

	// One key, spread 32: (2*32+1)=65 > 64. Freshness.resolve allows it
	// (maxBucketCandidates is 4096); NewResponder must not.
	wide := h.gwCf
	wide.Gateway.Fresh = Freshness{BucketWindow: time.Second, MaxSkew: 32 * time.Second}
	if _, err := NewResponder(wide, h.gateway, accept); !errors.Is(err, ErrConfig) {
		t.Fatalf("one key at spread 32 (65 HMACs) must be refused at construction, got %v", err)
	}
	just := h.gwCf
	just.Gateway.Fresh = Freshness{BucketWindow: time.Second, MaxSkew: 31 * time.Second}
	if _, err := NewResponder(just, h.gateway, accept); err != nil {
		t.Fatalf("one key at spread 31 (63 HMACs) must construct: %v", err)
	}
}

// TestConcurrentMixPQAdvancesEpochOnce would flake-fail before the MixPQ lock
// fix: two MixPQ calls could both pass pqDone==false, both ratchet, and leave
// Epoch()==2 with PQRatcheted true. The peer that MixPQ'd once then cannot
// open. The driver serialises MixPQ under Driver.mu, so this is a public-API
// race rather than a live datapath one; the session comment still says
// ratchets exclude both directions, and the previous code did not.
func TestConcurrentMixPQAdvancesEpochOnce(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5A}, PQSharedKeySize)
	const rounds = 32
	for round := 0; round < rounds; round++ {
		h := newHarness(t)
		cli, gw := h.completeHandshake(t)

		errs := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		for i := 0; i < 2; i++ {
			go func() {
				defer wg.Done()
				errs <- cli.MixPQ(secret)
			}()
		}
		wg.Wait()
		close(errs)

		var ok, already, other int
		for err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrPQAlreadyRatchet):
				already++
			default:
				other++
				t.Errorf("round %d: unexpected MixPQ error: %v", round, err)
			}
		}
		if ok != 1 || already != 1 || other != 0 {
			t.Fatalf("round %d: concurrent MixPQ: %d success, %d already, %d other; want 1, 1, 0",
				round, ok, already, other)
		}
		if cli.Epoch() != 1 {
			t.Fatalf("round %d: epoch %d after concurrent MixPQ, want 1", round, cli.Epoch())
		}
		if !cli.PQRatcheted() {
			t.Fatalf("round %d: PQRatcheted is false after a successful MixPQ", round)
		}

		if err := gw.MixPQ(secret); err != nil {
			t.Fatalf("round %d: peer MixPQ: %v", round, err)
		}
		msg, err := cli.Seal([]byte("after"), 0)
		if err != nil {
			t.Fatalf("round %d: seal: %v", round, err)
		}
		got, err := gw.Open(msg)
		if err != nil {
			t.Fatalf("round %d: open after concurrent MixPQ: %v", round, err)
		}
		if string(got) != "after" {
			t.Fatalf("round %d: payload %q", round, got)
		}
	}
}

// TestRoleStringDoesNotInventResponder: an out-of-range Role used to render as
// "responder", so a log line could not tell a real responder from a corrupted
// value. TestRoleString only checked the two named constants.
func TestRoleStringDoesNotInventResponder(t *testing.T) {
	if RoleInitiator.String() != "initiator" {
		t.Fatalf("RoleInitiator: %q", RoleInitiator.String())
	}
	if RoleResponder.String() != "responder" {
		t.Fatalf("RoleResponder: %q", RoleResponder.String())
	}
	got := Role(99).String()
	if got == "responder" || got == "initiator" {
		t.Fatalf("unknown role rendered as a real role: %q", got)
	}
	if got != "role(99)" {
		t.Fatalf("unknown role rendered as %q, want role(99)", got)
	}
}

// TestParseFramesUnknownTypeIsAccepted pins the mixed-version contract:
// ParseFrames is strict about trailing junk, type 0, and length overflow, and
// deliberately not strict about type numbers this build does not know. The
// driver ignores unknown types (session.TestUnknownFrameTypesAreIgnored). A
// change that started returning ErrDecrypt here would fragment a mixed-version
// fleet.
func TestParseFramesUnknownTypeIsAccepted(t *testing.T) {
	buf, err := AppendFrame(nil, FrameType(200), []byte("later-build"))
	if err != nil {
		t.Fatal(err)
	}
	buf, err = AppendFrame(buf, FrameData, []byte("still-delivered"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseFrames(buf)
	if err != nil {
		t.Fatalf("unknown frame type must parse, got %v", err)
	}
	if len(got) != 2 || got[0].Type != 200 || string(got[1].Value) != "still-delivered" {
		t.Fatalf("parsed %+v", got)
	}
}

// TestSealDoesNotHonourPadAuto: PadAuto is a handshake padding request. Seal
// treats any non-zero padTo as an on-wire target length, so PadAuto (-1) is
// below the minimum and must fail closed rather than emit an unpadded
// transport message that a caller thought was padded.
func TestSealDoesNotHonourPadAuto(t *testing.T) {
	h := newHarness(t)
	cli, _ := h.completeHandshake(t)
	if _, err := cli.Seal([]byte("x"), PadAuto); !errors.Is(err, ErrTargetLenTooSmall) {
		t.Fatalf("Seal(PadAuto) must fail closed, got %v", err)
	}
}
