package session

import (
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

func testShaper(t *testing.T, policy core.PaddingPolicy, mimic MimicFunc) *shaper {
	t.Helper()
	floor := core.TransportOverhead() + frameHeaderSize
	s, err := newShaper(policy, mimic, rand.Reader, floor, DefaultMaxMessageSize, DefaultBucketCount)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestBucketLaddersDifferPerSession is the point of drawing them per session.
//
// A fleet-wide ladder would be a fleet-wide constant expressed in lengths
// instead of bytes: every client's length histogram identical, which is failure
// F1 wearing a different hat. This mirrors the core's PadAuto fleet test.
func TestBucketLaddersDifferPerSession(t *testing.T) {
	const sessions = 1000
	seen := make(map[string]int, sessions)
	for i := 0; i < sessions; i++ {
		s := testShaper(t, core.PadBucket, nil)
		seen[fmt.Sprint(s.buckets)]++
	}
	if len(seen) < sessions/2 {
		t.Errorf("only %d distinct bucket ladders across %d sessions", len(seen), sessions)
	}
	for ladder, n := range seen {
		if frac := float64(n) / sessions; frac > 0.1 {
			t.Errorf("ladder %s is shared by %.1f%% of sessions", ladder, frac*100)
		}
	}
}

// TestBucketTargetsAreOnlyBoundaries: if a target were ever something other than
// a drawn boundary, the ladder would not be shaping anything.
func TestBucketTargetsAreOnlyBoundaries(t *testing.T) {
	floor := core.TransportOverhead() + frameHeaderSize
	for trial := 0; trial < 200; trial++ {
		s := testShaper(t, core.PadBucket, nil)
		boundary := make(map[int]bool, len(s.buckets))
		for _, b := range s.buckets {
			boundary[b] = true
			if b <= floor || b > DefaultMaxMessageSize {
				t.Fatalf("boundary %d outside (%d,%d]", b, floor, DefaultMaxMessageSize)
			}
		}
		for _, i := range s.buckets {
			if i != DefaultMaxMessageSize {
				continue
			}
			goto haveCeiling
		}
		t.Fatal("the ceiling is not a boundary; a full-size message would have no target")
	haveCeiling:
		for minLen := floor; minLen <= DefaultMaxMessageSize; minLen += 7 {
			target, err := s.target(minLen)
			if err != nil {
				t.Fatal(err)
			}
			if target == 0 {
				if minLen < DefaultMaxMessageSize {
					t.Fatalf("no padding target for a %d-byte message below the ceiling", minLen)
				}
				continue
			}
			if target < minLen {
				t.Fatalf("target %d is below the %d-byte minimum", target, minLen)
			}
			if target > DefaultMaxMessageSize {
				t.Fatalf("target %d exceeds the carrier ceiling", target)
			}
			if !boundary[target] {
				t.Fatalf("target %d is not a drawn boundary %v", target, s.buckets)
			}
		}
	}
}

// TestBucketLadderSpansTheRange checks the stratification.
//
// A purely random draw would sometimes put every boundary near the top, which
// would round a 60-byte interactive packet up to a full 1280-byte message and
// cost real bandwidth on a handset on a metered connection.
func TestBucketLadderSpansTheRange(t *testing.T) {
	floor := core.TransportOverhead() + frameHeaderSize
	span := DefaultMaxMessageSize - floor
	for trial := 0; trial < 500; trial++ {
		s := testShaper(t, core.PadBucket, nil)
		if len(s.buckets) < 2 {
			t.Fatalf("ladder has %d boundaries", len(s.buckets))
		}
		if lowest := s.buckets[0]; lowest > floor+span/2 {
			t.Fatalf("lowest boundary %d is above the midpoint; small packets would be padded to the ceiling", lowest)
		}
	}
}

func TestPadNoneAddsNothing(t *testing.T) {
	s := testShaper(t, core.PadNone, nil)
	for _, n := range []int{30, 200, 1279, 1280} {
		target, err := s.target(n)
		if err != nil {
			t.Fatal(err)
		}
		if target != 0 {
			t.Errorf("PadNone returned target %d for a %d-byte message", target, n)
		}
	}
}

// TestMimicTargetsAreClamped: a padding policy must never be able to make a
// message unsendable, so a carrier-supplied target outside the possible range is
// clamped rather than rejected.
func TestMimicTargetsAreClamped(t *testing.T) {
	cases := []struct {
		name   string
		mimic  MimicFunc
		minLen int
		want   int
	}{
		{"below minimum", func(int, int, io.Reader) int { return 1 }, 100, 0},
		{"above ceiling", func(int, int, io.Reader) int { return 1 << 20 }, 100, DefaultMaxMessageSize},
		{"negative", func(int, int, io.Reader) int { return -5 }, 100, 0},
		{"exactly minimum", func(minLen, _ int, _ io.Reader) int { return minLen }, 100, 0},
		{"in range", func(int, int, io.Reader) int { return 400 }, 100, 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := testShaper(t, core.PadMimic, c.mimic)
			got, err := s.target(c.minLen)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("target = %d, want %d", got, c.want)
			}
		})
	}
}

// TestShaperNeverPadsAtOrAboveTheCeiling: a full-size message has nowhere to go,
// and a target below the minimum is a core.Seal error, so the shaper must return
// zero rather than a number.
func TestShaperNeverPadsAtOrAboveTheCeiling(t *testing.T) {
	for _, policy := range []core.PaddingPolicy{core.PadNone, core.PadBucket, core.PadMimic} {
		s := testShaper(t, policy, func(int, int, io.Reader) int { return 1 << 20 })
		for _, n := range []int{DefaultMaxMessageSize, DefaultMaxMessageSize + 1, DefaultMaxMessageSize + 5000} {
			got, err := s.target(n)
			if err != nil {
				t.Fatal(err)
			}
			if got != 0 {
				t.Errorf("policy %d returned target %d for a %d-byte message at or above the ceiling", policy, got, n)
			}
		}
	}
}

// TestShaperDegeneratesSafely: a carrier whose message size leaves no room to
// pad must still produce a usable shaper rather than an empty ladder or a panic.
func TestShaperDegeneratesSafely(t *testing.T) {
	floor := core.TransportOverhead() + frameHeaderSize
	for _, ceiling := range []int{floor, floor + 1, floor + 3} {
		s, err := newShaper(core.PadBucket, nil, rand.Reader, floor, ceiling, DefaultBucketCount)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.buckets) == 0 {
			t.Fatalf("ceiling %d produced an empty ladder", ceiling)
		}
		got, err := s.target(floor)
		if err != nil {
			t.Fatal(err)
		}
		if got != 0 && (got < floor || got > ceiling) {
			t.Errorf("ceiling %d gave target %d for a %d-byte message", ceiling, got, floor)
		}
	}
}

// emittedLengths drives 240 distinct inner packet sizes through an established
// pair configured with one padding policy, and returns the histogram of on-wire
// message lengths.
//
// Policy is applied by assignment rather than by leaving the field alone, so a
// caller can pass core.PadDefault and measure what an omitted policy actually
// does on the wire.
func emittedLengths(t *testing.T, policy core.PaddingPolicy) map[int]int {
	t.Helper()
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.Padding = policy
		gw.Padding = policy
	})
	p.establish()
	lengths := make(map[int]int)
	for i := 0; i < 240; i++ {
		// Inner sizes spread across the whole range, one byte apart.
		if err := p.cli.Enqueue(make([]byte, 40+i)); err != nil {
			t.Fatal(err)
		}
		for {
			msg, err := p.cli.Poll()
			if err != nil {
				t.Fatal(err)
			}
			if msg == nil {
				break
			}
			lengths[len(msg)]++
		}
	}
	return lengths
}

// TestPaddingActuallyShapesTheWire is the end-to-end check: with PadBucket, the
// lengths a session emits must collapse onto a handful of values rather than
// tracking the inner packet sizes one for one.
func TestPaddingActuallyShapesTheWire(t *testing.T) {
	bucketed := emittedLengths(t, core.PadBucket)
	unpadded := emittedLengths(t, core.PadNone)

	if len(unpadded) < 200 {
		t.Fatalf("PadNone produced %d distinct lengths for 240 distinct inner sizes; it is supposed to leak them", len(unpadded))
	}
	if len(bucketed) >= len(unpadded) {
		t.Errorf("PadBucket produced %d distinct lengths and PadNone %d; bucketing did not shape anything",
			len(bucketed), len(unpadded))
	}
	if len(bucketed) > DefaultBucketCount+1 {
		t.Errorf("PadBucket produced %d distinct lengths, more than the %d drawn boundaries",
			len(bucketed), DefaultBucketCount)
	}
}

// TestAnOmittedPaddingPolicyStillShapesTheWire is the regression test for a zero
// value that used to mean "no length shaping at all".
//
// core.PadDefault is the zero value of Config.Padding, and normalise must
// resolve it to core.PadBucket. The assertion is deliberately end to end rather
// than a compare on the struct field: driver.Config embeds a session.Config and
// hands it down untouched, so the property that actually protects a user is what
// reaches the wire when a host never mentions padding — not what the field says
// afterwards.
func TestAnOmittedPaddingPolicyStillShapesTheWire(t *testing.T) {
	lengths := emittedLengths(t, core.PadDefault)
	if len(lengths) > DefaultBucketCount+1 {
		t.Errorf("a config that never set Padding produced %d distinct lengths for 240 distinct inner sizes, "+
			"more than the %d drawn boundaries: the omitted policy did not shape the wire and inner packet "+
			"sizes are leaking", len(lengths), DefaultBucketCount)
	}
}

// TestNormaliseResolvesOnlyTheZeroPolicy pins both halves of the sentinel.
//
// The zero value must become the design default, and every policy the caller
// named must survive untouched. The second half is the one a naive fix breaks:
// when PadNone was itself the zero value, "default every zero to PadBucket"
// silently overrode callers who had deliberately turned shaping off, which is
// how a security fix becomes a different correctness bug.
func TestNormaliseResolvesOnlyTheZeroPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   core.PaddingPolicy
		want core.PaddingPolicy
	}{
		{"an omitted policy becomes the design default", core.PadDefault, core.PadBucket},
		{"an explicit PadNone is left alone", core.PadNone, core.PadNone},
		{"an explicit PadBucket is left alone", core.PadBucket, core.PadBucket},
		{"an explicit PadMimic is left alone", core.PadMimic, core.PadMimic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{
				Static:  mustStatic(t),
				Padding: tc.in,
				Mimic:   func(minLen, maxLen int, _ io.Reader) int { return minLen },
			}
			if err := c.normalise(); err != nil {
				t.Fatalf("normalise: %v", err)
			}
			if c.Padding != tc.want {
				t.Errorf("normalise turned policy %d into %d, want %d", tc.in, c.Padding, tc.want)
			}
		})
	}
}

// padBucketEstablished drives a pair to Established under the default shaping
// policy with every timer parked at quietHorizon, so that an Enqueue/Poll pair
// emits exactly the message for that inner packet and nothing else.
func padBucketEstablished(t *testing.T) *pair {
	t.Helper()
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.Padding = core.PadBucket
		gw.Padding = core.PadBucket
	})
	p.establish()
	return p
}

// emitInner enqueues one inner packet and returns the single message emitted
// for it. Exactly one message is part of the contract this rig provides: a
// quiet established session has nothing queued but the packet, so a second
// message would mean the driver is adding cover the test did not ask for and
// the length being measured is contaminated.
func emitInner(t *testing.T, d *Driver, inner int) []byte {
	t.Helper()
	if err := d.Enqueue(make([]byte, inner)); err != nil {
		t.Fatalf("enqueue %d-byte inner packet: %v", inner, err)
	}
	var msg []byte
	for i := 0; i < 2; i++ {
		m, err := d.Poll()
		if err != nil {
			t.Fatalf("poll for %d-byte inner packet: %v", inner, err)
		}
		if m == nil {
			break
		}
		if msg != nil {
			t.Fatalf("a %d-byte inner packet produced more than one message; the rig is not quiet", inner)
		}
		msg = m
	}
	if msg == nil {
		t.Fatalf("no message was emitted for a %d-byte inner packet", inner)
	}
	return msg
}

// TestPaddingNeverExceedsNegotiatedFrameCapacity is the absolute bound on the
// wire. Bucketing must add cover, never overflow: no inner packet the driver
// accepts may come out of Seal LONGER than the session's negotiated
// MaxMessageSize, and a renegotiation that narrows the ceiling must not leave a
// stale boundary above it that lets a padded message escape the new capacity.
func TestPaddingNeverExceedsNegotiatedFrameCapacity(t *testing.T) {
	p := padBucketEstablished(t)
	d := p.cli

	d.mu.Lock()
	orig := d.cfg.MaxMessageSize
	d.mu.Unlock()

	for _, ceiling := range []int{orig, orig - 300} {
		if ceiling < orig {
			if err := d.SetMaxMessageSize(ceiling); err != nil {
				t.Fatalf("SetMaxMessageSize(%d): %v", ceiling, err)
			}
		}
		for inner := 1; inner <= InnerMTU(ceiling); inner++ {
			msg := emitInner(t, d, inner)
			if len(msg) > ceiling {
				t.Fatalf("a %d-byte inner packet was sealed to %d bytes against the negotiated "+
					"%d-byte capacity", inner, len(msg), ceiling)
			}
		}
	}
}

// TestPaddingNeverDropsToZeroOnLargeTraffic is the negative the whole length
// shaping subsystem exists to prevent, measured on the wire.
//
// Near capacity a message still has room to be rounded UP to the session's
// maximum, and a PadBucket ladder always ends in the ceiling. A drawn boundary
// cannot land above floor + stride*(count-1) + stride/2, so any minLen above
// that line meets ONLY the ceiling: those messages are deterministically sealed
// to the full negotiated size rather than sent at their own length. If the
// shaper ever collapsed to "send it as-is" there, the largest and most
// fingerprintable traffic would leak its exact length.
func TestPaddingNeverDropsToZeroOnLargeTraffic(t *testing.T) {
	p := padBucketEstablished(t)
	d := p.cli

	d.mu.Lock()
	ceiling := d.cfg.MaxMessageSize
	d.mu.Unlock()

	floor := core.TransportOverhead() + frameHeaderSize
	stride := (ceiling - floor) / DefaultBucketCount
	topStart := floor + stride*(DefaultBucketCount-1) + stride/2 + 1
	if topStart >= ceiling {
		t.Skipf("no deterministic padding window under a %d-byte ceiling", ceiling)
	}
	for minLen := topStart; minLen < ceiling; minLen++ {
		inner := minLen - floor
		msg := emitInner(t, d, inner)
		if len(msg) != ceiling {
			t.Fatalf("a %d-byte inner packet (needing %d bytes) was sealed to %d, want the "+
				"%d-byte negotiated maximum; padding collapsed on large traffic",
				inner, minLen, len(msg), ceiling)
		}
		if pad := len(msg) - minLen; pad < 1 {
			t.Fatalf("a %d-byte message near capacity was carried unpadded", minLen)
		}
	}
}

// TestPaddingBucketAnswersEveryMinimumBelowTheCeiling is the exhaustive version
// of the step sweep in TestBucketTargetsAreOnlyBoundaries, which walks by seven
// and never visits the top of the range: the largest sizes below the ceiling
// are exactly the ones where a collapse to "no padding" is invisible to +7
// sampling yet visible to an observer watching the biggest traffic round up.
// Every minimum strictly below the ceiling must draw a target, because the
// ladder always contains the ceiling itself.
func TestPaddingBucketAnswersEveryMinimumBelowTheCeiling(t *testing.T) {
	floor := core.TransportOverhead() + frameHeaderSize
	for trial := 0; trial < 25; trial++ {
		s := testShaper(t, core.PadBucket, nil)
		for minLen := floor; minLen < DefaultMaxMessageSize; minLen++ {
			target, err := s.target(minLen)
			if err != nil {
				t.Fatal(err)
			}
			if target == 0 {
				t.Fatalf("ladder %v returned no-padding for a %d-byte minimum below the %d-byte ceiling",
					s.buckets, minLen, DefaultMaxMessageSize)
			}
			if target < minLen {
				t.Fatalf("target %d is below the %d-byte minimum", target, minLen)
			}
			if target > DefaultMaxMessageSize {
				t.Fatalf("target %d exceeds the %d-byte ceiling", target, DefaultMaxMessageSize)
			}
		}

		// The far side of the contract: a message that already needs the ceiling
		// has no room to pad, and the no-padding sentinel is the right answer.
		if target, err := s.target(DefaultMaxMessageSize); err != nil || target != 0 {
			t.Fatalf("at the ceiling target = %d, err = %v; want the no-padding sentinel", target, err)
		}
	}
}
