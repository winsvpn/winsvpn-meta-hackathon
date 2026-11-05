package main

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Clock separates the two questions this controller asks about time, because
// they have different trust properties and conflating them is how a soak
// silently restarts its own duration.
//
//	MonotonicElapsed  how much of the soak has been served. Must never go
//	                  backwards, must not be steerable by an operator or by
//	                  NTP. Within one process Go's monotonic reading gives
//	                  exactly that.
//	WallNow           what a human calls this instant. Steerable, and treated
//	                  as such: it is used for timestamps and for detecting
//	                  rollback, never for deciding whether the soak is over.
//
// The honest limitation, stated here because it shapes checkpoint.go: the
// monotonic clock has no meaning across a reboot, so a resumed run cannot
// measure the gap it was down. It carries forward the elapsed time it had
// already accumulated and starts a fresh monotonic segment. Downtime is
// therefore NOT counted as soak time, which is the conservative direction: a
// resumed run serves at least its full duration of actual running, never less.
type Clock interface {
	MonotonicElapsed() time.Duration
	WallNow() time.Time
	// Sleep returns ctx.Err() if the context finishes first, nil if the
	// full duration elapsed. A non-positive duration returns immediately,
	// after one cancellation check.
	Sleep(ctx context.Context, d time.Duration) error
}

// realClock reads the process's monotonic clock.
//
// origin is captured with time.Now(), which embeds a monotonic reading;
// time.Since(origin) is documented to subtract monotonic readings when both
// operands carry them. Nothing here consults the wall clock for elapsed time.
type realClock struct {
	origin time.Time
}

func newRealClock() *realClock {
	return &realClock{origin: time.Now()}
}

func (c *realClock) MonotonicElapsed() time.Duration {
	return time.Since(c.origin)
}

func (c *realClock) WallNow() time.Time {
	return time.Now()
}

func (c *realClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// fakeClock is a deterministic Clock. It lives in the non-test build because
// -dry-run projects a schedule with it: the projection and the real loop must
// walk the identical code, or the dry run is describing a program that does
// not exist.
type fakeClock struct {
	mu       sync.Mutex
	elapsed  time.Duration
	wall     time.Time
	sleeps   []time.Duration
	autoWake bool
}

func newFakeClock(wall time.Time) *fakeClock {
	return &fakeClock{wall: wall, autoWake: true}
}

func (c *fakeClock) MonotonicElapsed() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.elapsed
}

func (c *fakeClock) WallNow() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wall
}

// Advance moves both clocks forward by d. Monotonic time is not permitted to
// move backwards even in a fake: a test that could rewind it would be testing
// a machine that cannot exist, and would let a real backwards-motion bug pass.
func (c *fakeClock) Advance(d time.Duration) {
	if d < 0 {
		panic("fakeClock: monotonic time cannot move backwards")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.elapsed += d
	c.wall = c.wall.Add(d)
}

// SetWall moves ONLY the wall clock, in either direction. This is how a clock
// rollback is simulated: the operator's clock jumps, the monotonic count does
// not, and the controller must notice.
func (c *fakeClock) SetWall(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = t
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	c.mu.Lock()
	c.sleeps = append(c.sleeps, d)
	wake := c.autoWake
	c.mu.Unlock()
	if wake {
		c.Advance(d)
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

// Sleeps returns the durations Sleep was asked for, in order. Tests assert the
// cadence was actually honoured rather than assuming it.
func (c *fakeClock) Sleeps() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]time.Duration, len(c.sleeps))
	copy(out, c.sleeps)
	return out
}

var errClockRollback = errors.New("wall clock moved backwards")
