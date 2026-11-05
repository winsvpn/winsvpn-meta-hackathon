package session

// The path-MTU 1450 seam, delivered as a tested unit.
//
// owner-gated decision #4 in the continuity brief is "raise path_mtu to 1450
// fleet-wide" once silent-refusal #3 is closed. Nothing in this package had
// pinned what a 1450-byte planning path MTU actually buys a session, or that a
// session keeps honouring it AFTER the carrier shrinks. This file pins both.
//
// The seam has three pieces, and they straddle the same two sites the rest of
// the path-MTU work lives across:
//
//   - params: Config.PathMTU is the PLANNING number and Config.MaxMessageSize
//     is the plan floor it is derived from. This test derives the floor with
//     MaxMessageSizeForPath(1450, overhead) -- the single documented translation
//     from "a 1450 path" to "this session's message ceiling" -- so that a change
//     to either constant cannot drift from the other without this test naming
//     the byte count that got away.
//   - carrier: the CARRIER wraps the Winn3 message, and it is the wrapped packet
//     that has to fit the path. So the assertion that matters for a 1450 planned
//     path is not "the message is small" but "message + carrier header never
//     cross 1450", and it has to hold for the full-size message AND for every
//     message the session emits after the carrier asks it to shrink.

import (
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

// TestPathMtu1450SizesTheSessionAndIsNeverExceeded pins the 1450 seam across
// both carrier overheads, before and after a shrink.
//
// The POST-SHRINK half is the half that has no other owner in this package:
// SetMaxMessageSize narrows the ceiling and the shaper clamps its ladder, and a
// clamp that let a post-shrink packet drift back above the planned 1450 would
// be silent-refusal #3 arriving one session later -- under the exact flag the
// owner wants to raise. So the test asserts, for a full-size packet at the sized
// ceiling and again at the post-shrink ceiling, that the emitted message plus
// its carrier header is never strictly greater than 1450.
func TestPathMtu1450SizesTheSessionAndIsNeverExceeded(t *testing.T) {
	t.Parallel()
	const pathMTU = 1450

	for _, ov := range []struct {
		name     string
		overhead int
	}{
		{"udp-over-ipv6", CarrierOverheadUDPIPv6},
		{"udp-over-ipv4", CarrierOverheadUDPIPv4},
	} {
		t.Run(ov.name, func(t *testing.T) {
			// Sizing: the 1450 path MTU, translated by the documented helper,
			// is the ceiling the session is built at.
			ceiling := MaxMessageSizeForPath(pathMTU, ov.overhead)
			if ceiling <= 0 {
				t.Fatalf("MaxMessageSizeForPath(%d, %d) = %d; a 1450 path must size to a positive ceiling",
					pathMTU, ov.overhead, ceiling)
			}
			if ceiling+ov.overhead > pathMTU {
				t.Fatalf("the %d-byte ceiling plus %d carrier bytes is %d, strictly past the %d path MTU "+
					"it was sized for; the session plans wider than 1450 can carry",
					ceiling, ov.overhead, ceiling+ov.overhead, pathMTU)
			}

			// The full session at the 1450 seam: both ends planned at 1450, and
			// both carry the ceiling the helper sized. This exercises the
			// handshake path-MTU notice and the guarded minimum together under
			// the exact number the owner wants to ship.
			p := established(t, func(cli, gw *Config) {
				cli.PathMTU = pathMTU
				cli.MaxMessageSize = ceiling
				gw.PathMTU = pathMTU
				gw.MaxMessageSize = ceiling
			})

			// A full-size inner packet is sealed to EXACTLY the 1450-sized
			// ceiling, never more, and the wrapped packet still fits 1450.
			if err := p.cli.Enqueue(make([]byte, InnerMTU(ceiling))); err != nil {
				t.Fatal(err)
			}
			msg, err := p.cli.Poll()
			if err != nil {
				t.Fatal(err)
			}
			if msg == nil {
				t.Fatal("a full-size inner packet at the 1450 seam produced no message")
			}
			if len(msg) != ceiling {
				t.Fatalf("a full-size 1450 packet was sealed to %d, want exactly the %d-byte ceiling "+
					"MaxMessageSizeForPath(1450, %d) sized", len(msg), ceiling, ov.overhead)
			}
			if len(msg)+ov.overhead > pathMTU {
				t.Fatalf("the full-size %d-byte message plus %d carrier bytes is %d, strictly past the "+
					"%d path MTU it was sized for", len(msg), ov.overhead, len(msg)+ov.overhead, pathMTU)
			}

			// POST-SHRINK: the carrier narrows the session, and the packets the
			// session emits from here on must never cross the 1450 it planned at.
			narrower := ceiling - 100
			if err := p.cli.SetMaxMessageSize(narrower); err != nil {
				t.Fatalf("SetMaxMessageSize(%d): %v", narrower, err)
			}
			if err := p.cli.Enqueue(make([]byte, InnerMTU(narrower))); err != nil {
				t.Fatal(err)
			}
			msg, err = p.cli.Poll()
			if err != nil {
				t.Fatal(err)
			}
			if msg == nil {
				t.Fatal("a post-shrink full-size packet produced no message")
			}
			if len(msg) > narrower {
				t.Fatalf("a post-shrink packet was sealed to %d bytes, above the %d-byte post-shrink "+
					"ceiling it must clamp to", len(msg), narrower)
			}
			if len(msg)+ov.overhead > pathMTU {
				t.Fatalf("a post-shrink packet of %d bytes plus %d carrier bytes is %d, strictly past "+
					"the %d path MTU the session was sized for", len(msg), ov.overhead, len(msg)+ov.overhead, pathMTU)
			}
			// The session is still live and still on the 1450 seam after the
			// shrink: the other direction neither refused nor collapsed.
			if got := p.cli.State(); got != StateEstablished {
				t.Fatalf("client state after a 1450 shrink is %s, want established", got)
			}
		})
	}
}

// TestPathMtu1450TakesTheMinimumOfLocalAndPeer is the take-min half of
// silent-refusal instance #3, pinned at the 1450 seam the owner wants to ship.
//
// A 1450-planned path only carries when BOTH ends plan no wider than the
// session's negotiation, and the number both can carry at is the smaller of the
// two claims. This test holds that the negotiated path MTU picks that smaller
// number whether the narrow end is the peer or this end, and that an agreeing
// pair stays at 1450 without shrinking the seam. It is the direct statement of
// "raise path_mtu to 1450 fleet-wide" having a take-min behaviour behind it:
// if either end still plans at the old 1280, the negotiated number must be
// 1280, never 1450 — otherwise a 1450 carrier over-sends against a 1280 peer
// and the black hole re-opens.
func TestPathMtu1450TakesTheMinimumOfLocalAndPeer(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		local, peer int
		want        int
		wantBoth    bool
	}{
		{"the seam agrees at 1450", 1450, 1450, 1450, true},
		{"the peer still plans at 1280", 1450, 1280, 1280, true},
		{"this end still plans at 1280", 1280, 1450, 1280, true},
		{"an intermediate narrower peer", 1450, 1400, 1400, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, both := NegotiatedPathMTU(tc.local, tc.peer)
			if both != tc.wantBoth {
				t.Fatalf("bothClaimed = %v, want %v for %d vs %d", both, tc.wantBoth, tc.local, tc.peer)
			}
			if got != tc.want {
				t.Fatalf("NegotiatedPathMTU(%d, %d) = %d, want the smaller %d", tc.local, tc.peer, got, tc.want)
			}
			// The minimum can never sit above either claiming end, or a full-size
			// 1450 message could be sent at a number a peer cannot carry.
			if got > tc.local || got > tc.peer {
				t.Fatalf("negotiated %d exceeds a claiming end (%d, %d)", got, tc.local, tc.peer)
			}
		})
	}
}

// TestSizedFor1450StillFitsTheFloor sanity-checks the arithmetic the seam rests
// on, so a future relabelling of the overheads cannot silently move the 1450
// ceiling onto or past the path floor that the InnerMTU half of this file uses.
func TestSizedFor1450StillFitsTheFloor(t *testing.T) {
	t.Parallel()
	for _, ov := range []int{CarrierOverheadUDPIPv6, CarrierOverheadUDPIPv4} {
		ceiling := MaxMessageSizeForPath(1450, ov)
		if inner := InnerMTU(ceiling); inner < 0 {
			t.Fatalf("InnerMTU(%d) = %d; the 1450-seam ceiling cannot carry any inner packet",
				ceiling, inner)
		}
		if ceiling > core.MaxTransportPayload {
			t.Fatalf("the 1450-seam ceiling %d exceeds the transport encoding limit %d",
				ceiling, core.MaxTransportPayload)
		}
	}
}
