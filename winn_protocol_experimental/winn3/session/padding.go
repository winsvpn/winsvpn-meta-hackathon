package session

import (
	"io"
	"sort"

	"winsvpn.local/winnprotocol/winn3/core"
)

// shaper turns "this message needs at least N bytes on the wire" into "seal it
// to exactly T bytes".
//
// It is per session, because the whole point of PadBucket is that two clients do
// not share a length histogram. A fleet-wide bucket ladder would be a fleet-wide
// constant expressed in lengths instead of bytes, which is failure F1 wearing a
// different hat.
type shaper struct {
	policy  core.PaddingPolicy
	mimic   MimicFunc
	rnd     io.Reader
	floor   int
	ceiling int
	buckets []int // ascending, last element is always ceiling
}

// newShaper draws this session's shape.
//
// The boundary draw is stratified and then jittered rather than purely random:
// stratification guarantees the ladder actually spans the range (a purely random
// draw sometimes puts every boundary near the top, which would round small
// interactive packets up to full MTU and cost real bandwidth on a handset), and
// the jitter is what makes the ladder this session's own.
func newShaper(policy core.PaddingPolicy, mimic MimicFunc, rnd io.Reader, floor, ceiling, count int) (*shaper, error) {
	s := &shaper{policy: policy, mimic: mimic, rnd: rnd, floor: floor, ceiling: ceiling}
	if policy != core.PadBucket {
		return s, nil
	}
	span := ceiling - floor
	if span <= 0 || count < 1 {
		s.buckets = []int{ceiling}
		return s, nil
	}
	stride := span / count
	seen := make(map[int]bool, count)
	for i := 1; i < count; i++ {
		base := floor + stride*i
		// Jitter uniformly across one stride, centred on the stratum boundary.
		var off int
		if stride > 1 {
			n, err := drawIntn(rnd, stride)
			if err != nil {
				return nil, err
			}
			off = n - stride/2
		}
		b := base + off
		if b <= floor {
			b = floor + 1
		}
		if b >= ceiling {
			b = ceiling - 1
		}
		if !seen[b] {
			seen[b] = true
			s.buckets = append(s.buckets, b)
		}
	}
	// The ceiling is always a boundary. Without it a message larger than every
	// drawn boundary would have no target, and the carrier's limit is a hard
	// edge rather than a policy choice.
	s.buckets = append(s.buckets, ceiling)
	sort.Ints(s.buckets)
	return s, nil
}

// setCeiling moves the top of the ladder after the carrier's ceiling changed.
//
// The drawn boundaries are CLAMPED rather than redrawn. Redrawing would give
// this session a new length histogram at the exact moment its path changed,
// which is a correlator handed to an observer for free; clamping keeps the shape
// the session already had and only removes the boundaries the path can no longer
// carry. The ceiling is always a boundary, for the same reason it is one at
// construction: a message larger than every drawn boundary must still have a
// target.
func (s *shaper) setCeiling(n int) {
	s.ceiling = n
	if s.buckets == nil {
		return
	}
	kept := s.buckets[:0]
	for _, b := range s.buckets {
		if b < n {
			kept = append(kept, b)
		}
	}
	s.buckets = append(kept, n)
}

// target reports the on-wire length to seal to, given the minimum this message
// can occupy. Zero means "no padding", which core.Session.Seal reads as such.
func (s *shaper) target(minLen int) (int, error) {
	if minLen >= s.ceiling {
		return 0, nil
	}
	switch s.policy {
	case core.PadNone:
		return 0, nil

	case core.PadBucket:
		for _, b := range s.buckets {
			if b >= minLen {
				return b, nil
			}
		}
		return s.ceiling, nil

	case core.PadMimic:
		t := s.mimic(minLen, s.ceiling, s.rnd)
		// A padding policy must never be able to make a message unsendable, so
		// a target outside the possible range is clamped rather than rejected.
		if t < minLen {
			t = minLen
		}
		if t > s.ceiling {
			t = s.ceiling
		}
		if t == minLen {
			return 0, nil
		}
		return t, nil
	}
	return 0, nil
}
