package core

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// This file asserts the gate-failure semantics of the admission tag, at the
// unit level, directly against verifyAdmission. The admission tag is the FIRST
// gate a handshake initiation must pass (handshake.go: "admission tag fails ->
// dropped before any asymmetric operation"), so its failure behaviour is what a
// gateway presents to an unauthenticated datagram and is the arrive-no-write
// boundary of the whole responder.
//
// The semantics asserted here, each against the grouped evidence below:
//
//  1. A datagram that authenticates is accepted and its plaintext body is
//     recovered unmodified (the positive control the reject cases must not
//     break).
//  2. Every authentication failure - wrong key, wrong gateway identity, or a
//     clock so far out of skew that no candidate bucket matches - collapses to
//     the SAME sentinel, ErrUnauthenticated. There is deliberately no
//     distinction an observer could turn into an oracle.
//  3. Only the two structural length bounds escape that sentinel, and do so
//     mechanically (len<=tagLen, len>MaxHandshakeMessage) before any key is
//     even consulted, so they cost nothing and leak nothing about the key set.

func TestAdmissionGateRejectSemantics(t *testing.T) {
	h := newHarness(t)
	g := h.gwCf.Gateway
	window := DefaultBucketWindow
	tagLen := DefaultTagSize

	body := bytes.Repeat([]byte{0x42}, 64)
	seedBucket := bucketIndex(h.now, window)
	valid := sealAdmission(body, g.AdmissionKeys[0], g.GatewayID, tagLen, seedBucket)

	// Positive control: the correct key, identity and bucket must verify and
	// recover the exact plaintext body. If this fails the reject cases below
	// are meaningless - the gate is rejecting everything, not selectively.
	{
		got, ki, b, err := verifyAdmission(valid, g, h.now)
		if err != nil {
			t.Fatalf("positive control: verifyAdmission rejected a correctly sealed message: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("positive control: body corrupted, got %x want %x", got, body)
		}
		if ki != 0 {
			t.Fatalf("positive control: key index = %d, want 0 (single live key)", ki)
		}
		if b != seedBucket {
			t.Fatalf("positive control: bucket = %d, want %d", b, seedBucket)
		}
	}

	// Grouped authentication failures: each must come back as ErrUnauthenticated
	// and never as any other value, and they must be indistinguishable from one
	// another.
	authenticatedFailures := []struct {
		name string
		g    GatewayParams
		now  time.Time
	}{
		{
			name: "wrong admission key",
			g: func() GatewayParams {
				gg := g
				gg.AdmissionKeys = [][]byte{bytes.Repeat([]byte{0x5C}, 32)}
				return gg
			}(),
			now: h.now,
		},
		{
			name: "wrong gateway identity",
			g: func() GatewayParams {
				gg := g
				gg.GatewayID = []byte("gw-test-other")
				return gg
			}(),
			now: h.now,
		},
		{
			name: "clock far outside skew",
			g:    g,
			now:  h.now.Add(DefaultMaxSkew + DefaultBucketWindow),
		},
	}
	for _, tc := range authenticatedFailures {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := verifyAdmission(valid, tc.g, tc.now)
			if err == nil {
				t.Fatal("gate accepted a message that must be rejected")
			}
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("rejection %v, want ErrUnauthenticated", err)
			}
			if errors.Is(err, ErrShortMessage) || errors.Is(err, ErrLongMessage) {
				t.Fatalf("authentication failure misclassified as a structural error: %v", err)
			}
		})
	}

	// The no-oracle property: the three rejections above are indistinguishable
	// to a caller. Asserting that each is ErrUnauthenticated and is none of the
	// structural errors is the direct statement of it.
	t.Run("rejections are indistinguishable", func(t *testing.T) {
		wrongKey, _ := func() (GatewayParams, time.Time) {
			gg := g
			gg.AdmissionKeys = [][]byte{bytes.Repeat([]byte{0x5C}, 32)}
			return gg, h.now
		}()
		_, _, _, e1 := verifyAdmission(valid, wrongKey, h.now)
		_, _, _, e2 := verifyAdmission(valid, g, h.now.Add(DefaultMaxSkew+DefaultBucketWindow))
		if e1 == nil || e2 == nil {
			t.Fatal("expected two rejections, got a pass")
		}
		if e1.Error() != e2.Error() {
			t.Fatalf("wrong-key rejection (%v) distinguishable from out-of-skew rejection (%v)", e1, e2)
		}
	})

	// Structural bounds: these are the only two rejections that are NOT the
	// authentication sentinel, and they must fire before the key set is even
	// consulted, so they carry no information about the key.
	structural := []struct {
		name    string
		msg     []byte
		wantErr error
	}{
		{"nil message", nil, ErrShortMessage},
		{"shorter than the tag", make([]byte, tagLen-1), ErrShortMessage},
		{"exactly tag length", make([]byte, tagLen), ErrShortMessage},
		{"message over the ceiling", make([]byte, MaxHandshakeMessage+1), ErrLongMessage},
	}
	for _, tc := range structural {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := verifyAdmission(tc.msg, g, h.now)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}
