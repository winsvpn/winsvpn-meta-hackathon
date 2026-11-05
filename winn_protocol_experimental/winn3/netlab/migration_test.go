package netlab

import (
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
)

// Property 5: the 84-byte migration trap.
//
//	Floor(1280, UDP, TCP, TLS) = 1168   against 1252 for a dialled UDP/IPv4 carrier
//	                                    = 84 bytes
//
// Eighty-four bytes that black hole every full-size flow on the FIRST migration
// while the tunnel still reads "up". The driver lane pins the floor
// structurally and asserts the gap arithmetically. What has never been tested
// is whether a full-size flow actually survives a live migration across a path
// that only carries the floor — which is the whole claim.
//
// This file runs the SAME constrained path against two sessions: one pinned at
// the plan floor and one pinned at the carrier it dialled. Same impairment,
// same traffic, opposite outcomes. That pairing is what makes the first result
// evidence rather than a green row.
//
// ON THE 1280s IN THIS FILE — READ BEFORE CHANGING ANY OF THEM (2026-08-10)
//
// The fleet planning default moved 1280 → 1450, and 1280 stopped being one
// number doing two jobs. It had been BOTH the path the session planned at and
// the path the impairment presented, and they were equal only because the
// default happened to sit on the IPv6 minimum. The two jobs have to be told
// apart now, and this file contains both:
//
//   - PLANNING, and therefore coupled to the default: the path these tests
//     migrate ONTO and cap the link at. The claim being tested is "a message at
//     the plan floor, wrapped by the widest carrier in the plan, exactly fills
//     the path it was planned for" — an identity between the floor and the
//     path, not a fact about the number 1280. These now read Sizing.PathMTU so
//     the identity is structural and cannot drift again.
//   - ARITHMETIC REFERENCE, and therefore fixed: TestTheGapIsExactlyEightyFourBytes
//     below prices the gap at the IPv6 minimum path. That is a statement about
//     header overheads, it is true at 1280 whatever the fleet plans at, and it
//     must NOT be moved.
//
// Nothing here models a path NARROWING under an established session — that is
// pathmtu_test.go's subject, and its caps are impairments in the strict sense
// and are left alone.

// tlsOuterOverhead is what a TLS-over-TCP carrier over IPv6 wraps around a
// message, from WINN3_CARRIERS_20260808.md §5.2: 40 IPv6 + 20 TCP + 12 RFC 7323
// timestamps + 22 TLS record + 18 sealed length.
const tlsOuterOverhead = 112

// TestTheGapIsExactlyEightyFourBytes prices the gap at the IPv6 minimum path.
//
// The 1280s here are the arithmetic reference and are deliberately NOT the
// planning default: the gap is a difference between two overheads (112 for
// TLS/IPv6 against 28 for UDP/IPv4) and is therefore the same 84 bytes at every
// path MTU. Pinning it at the IPv6 minimum keeps the absolute floor and ceiling
// numbers in the assertion messages, which is what makes a drift in the carrier
// lane's header constants fail HERE, with both numbers named, rather than
// somewhere downstream as a stalled transfer.
func TestTheGapIsExactlyEightyFourBytes(t *testing.T) {
	t.Parallel()
	floor := carrier.Floor(1280, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS)
	dialled := carrier.MaxMessageSizeFor(carrier.ClassUDP, carrier.FamilyIPv4, 1280)
	if got := dialled - floor; got != 84 {
		t.Fatalf("the gap between a dialled UDP/IPv4 carrier (%d) and the plan floor (%d) is %d, "+
			"not 84; every number in this file is derived from that gap", dialled, floor, got)
	}
	if floor+tlsOuterOverhead != 1280 {
		t.Fatalf("a %d-byte message inside a TLS/IPv6 carrier is a %d-byte packet, not 1280; "+
			"the constrained path in these tests is not the IPv6 minimum after all",
			floor, floor+tlsOuterOverhead)
	}
}

// TestAFullSizeFlowSurvivesALiveUDPToTLSMigration is the proof the driver lane
// could not produce on loopback.
//
// The destination path carries exactly what the session PLANNED for, to the
// byte: a session pinned at the plan floor emits messages that are exactly the
// planning path MTU once the widest carrier in the plan has wrapped them, so a
// full-size flow must cross that path without losing a packet.
//
// That identity is the subject, not any particular number. At the fleet default
// of 1450 it reads 1338 + 112 = 1450; at the 1280 this test was written against
// it read 1168 + 112 = 1280. Asserting the identity rather than the constants is
// what stops the test drifting into vacuity the next time the default moves —
// which is exactly what it did on 2026-08-10, when a floor of 1338 was still
// being measured against a hardcoded 1280-byte cap.
func TestAFullSizeFlowSurvivesALiveUDPToTLSMigration(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})

	// The plan floor must exactly fill the planning path once TLS — the widest
	// class in the shipping plan, and so the class that sets the floor — has
	// wrapped it. If this does not hold, every byte-exact assertion below is
	// measuring something other than a full-size flow.
	if p.Sizing.MessageSize+tlsOuterOverhead != p.Sizing.PathMTU {
		t.Fatalf("a %d-byte message inside a TLS/IPv6 carrier is a %d-byte packet against a "+
			"%d-byte planning path; the plan floor does not fill the path it was planned for, "+
			"so this test cannot show that a full-size flow survives the migration",
			p.Sizing.MessageSize, p.Sizing.MessageSize+tlsOuterOverhead, p.Sizing.PathMTU)
	}
	epochBefore := p.Client.Loop.Session().Epoch()

	sent := p.OfferInner(40, p.FullPayload())
	if got := p.Collect(sent, 40*time.Second); got != sent {
		t.Fatalf("delivered %d of %d on UDP before the migration", got, sent)
	}

	if err := p.MigrateTo(carrier.ClassTLS, p.Sizing.PathMTU); err != nil {
		t.Fatalf("migration to TLS was refused: %v", err)
	}
	if err := p.ProveCarrying(30 * time.Second); err != nil {
		t.Fatalf("the TLS carrier never carried after the migration: %v", err)
	}
	// The new path is exactly the planning path for a TLS carrier, and one byte
	// more is gone. This is NOT a narrowing — the path is the width the session
	// was planned for — so a single dropped packet here is the plan floor being
	// wrong, not the network being small.
	p.ToGateway.Arm(Impairment{MaxOuterPacket: p.Sizing.PathMTU, OuterOverhead: tlsOuterOverhead})
	p.ToClient.Arm(Impairment{MaxOuterPacket: p.Sizing.PathMTU, OuterOverhead: tlsOuterOverhead})

	sent2 := p.OfferInner(120, p.FullPayload())
	got2 := p.Collect(sent2, 30*time.Second)
	st := p.ToGateway.Stats()

	if st.MaxOuterSeen != p.Sizing.PathMTU {
		t.Fatalf("the largest outer packet on the TLS path was %d, want exactly %d; the flow "+
			"was not full-size and this test would pass on a session sized to anything",
			st.MaxOuterSeen, p.Sizing.PathMTU)
	}
	if st.DroppedOversize != 0 {
		t.Fatalf("%d full-size messages were too big for the destination path AFTER a migration "+
			"the plan floor was supposed to make safe. That is the 84-byte black hole, and the "+
			"plan floor did not close it.", st.DroppedOversize)
	}
	if got2 != sent2 {
		t.Fatalf("delivered %d of %d full-size packets across a live UDP to TLS migration "+
			"(link %+v)", got2, sent2, st)
	}
	if p.Client.Loop.Session().Epoch() != epochBefore {
		t.Fatalf("the epoch moved from %d to %d across the migration; a carrier swap must not "+
			"cost a re-handshake or the design's structural answer to a UDP block does not exist",
			epochBefore, p.Client.Loop.Session().Epoch())
	}
	if p.Client.Loop.Session().State() != session.StateEstablished ||
		p.Gateway.Loop.Session().State() != session.StateEstablished {
		t.Fatalf("client=%s gateway=%s after the migration",
			p.Client.Loop.Session().State(), p.Gateway.Loop.Session().State())
	}
	if m := p.Client.Loop.Stats().Migrations; m != 1 {
		t.Fatalf("the loop counted %d migrations, want 1", m)
	}
}

// TestASessionSizedToTheDialledCarrierBlackHolesOnTheSamePath is the teeth, and
// it is the 84 bytes made visible.
//
// The impairment is byte-for-byte the same as the test above — the planning
// path MTU, whatever the fleet default is — and that is the whole argument, so
// the two must be changed together or not at all. The only change is the
// migration plan, and therefore the pinned message size: a plan naming UDP
// alone floors 64 bytes HIGHER than the shipping plan, because it never had to
// charge the stream carrier's 18-byte sealed length or TLS's 22-byte record.
// Those 64 bytes are a difference between overheads, so they are the same 64 at
// any path MTU: 1232 against 1168 at the 1280 this was written for, 1402
// against 1338 at today's 1450.
//
// Two things then happen, and the second is why this failure is so hard to
// diagnose from a distance:
//
//  1. driver.Loop.Migrate REFUSES the move, because the plan does not name TLS.
//     That refusal is the structural pin working, and it is actionable.
//  2. If a host reached around it — dialled a TLS carrier itself, or measured a
//     path MTU after the fact — every full-size message is 64 bytes too wide
//     and vanishes, with no error at any layer.
func TestASessionSizedToTheDialledCarrierBlackHolesOnTheSamePath(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{Plan: []carrier.Class{carrier.ClassUDP}})

	// The excess is the subject: a session pinned to its dialled UDP carrier
	// emits messages that are this many bytes too wide once a TLS carrier has
	// wrapped them, on the very path it planned for. 112 − 48 = 64, at every
	// path MTU.
	excess := p.Sizing.MessageSize + tlsOuterOverhead - p.Sizing.PathMTU
	if excess != 64 {
		t.Fatalf("a UDP-only plan floors at %d, which a TLS/IPv6 carrier makes a %d-byte packet "+
			"against the %d-byte path it planned for — %d bytes over, want 64. The trap this "+
			"test exists to measure is not the size it was measured at.",
			p.Sizing.MessageSize, p.Sizing.MessageSize+tlsOuterOverhead, p.Sizing.PathMTU, excess)
	}

	// 1. The structural refusal.
	gp, err := carrier.NewPipe(carrier.PipeConfig{
		Class: carrier.ClassTLS, PathMTU: p.Sizing.PathMTU, Depth: 16, Clock: SessionClockOf(p.Clock),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Client.Loop.Migrate(gp); err == nil {
		t.Fatalf("the loop migrated a session pinned at %d onto a TLS carrier at the same path, "+
			"which carries %d. That is the black hole, completed rather than refused, and "+
			"nothing downstream would ever report it.",
			p.Sizing.MessageSize, p.Sizing.PathMTU-tlsOuterOverhead)
	}

	// 2. What it would have cost. Same cap, same overhead, same traffic.
	p.ToGateway.Arm(Impairment{MaxOuterPacket: p.Sizing.PathMTU, OuterOverhead: tlsOuterOverhead})

	sent := p.OfferInner(80, p.FullPayload())
	got := p.Collect(sent, 6*time.Second)
	st := p.ToGateway.Stats()

	if st.DroppedOversize == 0 {
		t.Fatalf("nothing was dropped at a %d-byte TLS path for a session emitting %d-byte "+
			"messages (%d + %d = %d); the teeth test has no teeth",
			p.Sizing.PathMTU, p.Sizing.MessageSize, p.Sizing.MessageSize, tlsOuterOverhead,
			p.Sizing.MessageSize+tlsOuterOverhead)
	}
	if got != 0 {
		t.Fatalf("%d of %d full-size packets crossed a path that cannot carry them", got, sent)
	}
	if p.Client.Loop.Stats().SendFailed != 0 {
		t.Fatal("the carrier reported a send failure; the whole point is that it does not")
	}
	if p.Client.Loop.Session().State() != session.StateEstablished {
		t.Fatalf("the session is %s; the finding is that it stays UP",
			p.Client.Loop.Session().State())
	}
	t.Logf("FINDING (the 64 bytes over the plan floor, measured): a session pinned to its DIALLED "+
		"carrier emits %d-byte messages; wrapped by a TLS/IPv6 carrier that is %d bytes against "+
		"a %d-byte path, so %d of %d full-size packets vanished with zero errors and the session "+
		"still reports %s", p.Sizing.MessageSize, p.Sizing.MessageSize+tlsOuterOverhead,
		p.Sizing.PathMTU, sent-got, sent, p.Client.Loop.Session().State())
}

// TestEveryOrderedPairInThePlanSurvivesAConstrainedPath generalises the first
// result: the plan floor's promise is about EVERY class in the plan, so a
// migration between any two of them must survive a path at the floor. Checking
// one ordered pair proves the mechanism; checking all of them proves the floor.
func TestEveryOrderedPairInThePlanSurvivesAConstrainedPath(t *testing.T) {
	t.Parallel()
	plan := []carrier.Class{carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS}
	// The fleet default, not a literal: NewSizing refuses a planning path MTU
	// inside the inner-IPv6 dead zone, so the 1280 this read until 2026-08-10 is
	// not a configuration a host may hold at all any more.
	sz, err := driver.NewSizing(carrier.DefaultPathMTU, plan...)
	if err != nil {
		t.Fatal(err)
	}
	// The floor must fit inside every class's budget at the planning path MTU,
	// across BOTH families, because a migration can change family as easily as
	// class — a handset moving from a v4-only cellular network to a v6-only one.
	for _, c := range plan {
		for _, f := range []carrier.Family{carrier.FamilyIPv4, carrier.FamilyIPv6} {
			ceiling := carrier.MaxMessageSizeFor(c, f, sz.PathMTU)
			if sz.MessageSize > ceiling {
				t.Fatalf("the plan floor is %d but a %s/%s carrier at a %d-byte path carries "+
					"%d; a migration to it black holes every full-size flow",
					sz.MessageSize, c, f, sz.PathMTU, ceiling)
			}
		}
	}

	// And the live version for the pair that actually costs the 84 bytes.
	for _, to := range []carrier.Class{carrier.ClassTCP, carrier.ClassTLS} {
		t.Run(to.String(), func(t *testing.T) {
			p := burstPair(t, PairConfig{})
			if err := p.MigrateTo(to, p.Sizing.PathMTU); err != nil {
				t.Fatalf("migration to %s refused: %v", to, err)
			}
			if err := p.ProveCarrying(30 * time.Second); err != nil {
				t.Fatalf("the %s carrier never carried after the migration: %v", to, err)
			}
			over := tlsOuterOverhead
			if to == carrier.ClassTCP {
				over = 90 // 40 IPv6 + 20 TCP + 12 timestamps + 18 sealed length
			}
			p.ToGateway.Arm(Impairment{MaxOuterPacket: p.Sizing.PathMTU, OuterOverhead: over})
			p.ToClient.Arm(Impairment{MaxOuterPacket: p.Sizing.PathMTU, OuterOverhead: over})

			sent := p.OfferInner(60, p.FullPayload())
			got := p.Collect(sent, 30*time.Second)
			if st := p.ToGateway.Stats(); st.DroppedOversize != 0 || got != sent {
				t.Fatalf("delivered %d of %d full-size packets after migrating to %s on a "+
					"%d-byte path: link %+v, client loop %+v, gateway loop %+v, "+
					"client=%s gateway=%s", got, sent, to, p.Sizing.PathMTU, st,
					p.Client.Loop.Stats(), p.Gateway.Loop.Stats(),
					p.Client.Loop.Session().State(), p.Gateway.Loop.Session().State())
			}
		})
	}
}
