package netlab

import (
	"sync"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/winn3/driver"
)

// StepClock is a manually advanced clock with real channels.
//
// It is the driver lane's stepClock, rebuilt here because that one lives in a
// _test.go file and is therefore not importable. Two properties are carried
// over deliberately, and the second is a bug this rig would otherwise inherit:
//
//   - Advance fires every timer whose deadline has passed, so a test drives a
//     probe budget of four twenty-second probes in microseconds rather than in
//     eighty seconds.
//   - A timer created with a NON-POSITIVE duration fires AT ONCE, exactly as
//     time.NewTimer does. The driver lane's mutation #20 survived its first run
//     precisely because its fake queued such a timer instead of firing it,
//     which masked a loop that polls instead of waiting. A fake that is more
//     forgiving than the real thing hides the class of bug it was built to
//     find.
type StepClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*stepTimer
}

// NewStepClock starts at a fixed instant so that a failing run is reproducible
// from its log.
func NewStepClock() *StepClock {
	return &StepClock{now: time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)}
}

// Now implements session.Clock, tun.Clock and driver.Clock.
func (c *StepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// NewTimer implements driver.Clock.
func (c *StepClock) NewTimer(d time.Duration) driver.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &stepTimer{at: c.now.Add(d), ch: make(chan time.Time, 1)}
	if d <= 0 {
		t.ch <- c.now
		return t
	}
	c.timers = append(c.timers, t)
	return t
}

// Advance moves the clock and fires every timer that has come due.
func (c *StepClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	live := c.timers[:0]
	var fire []*stepTimer
	for _, t := range c.timers {
		if !t.stopped.Load() && !now.Before(t.at) {
			fire = append(fire, t)
			continue
		}
		live = append(live, t)
	}
	c.timers = live
	c.mu.Unlock()
	for _, t := range fire {
		select {
		case t.ch <- now:
		default:
		}
	}
}

// stepTimer's stopped flag is atomic, and that is not decoration.
//
// driver.Loop.waitForWork calls Stop from the WRITE goroutine on a timer this
// clock's Advance is concurrently reading from the test goroutine. The obvious
// implementation — a plain bool, which is what the driver lane's own
// harness_test.go stepTimer has — is an unsynchronised write against a read
// under a different mutex, and `go test -race` reports it on the first run of
// this package's Pair rig. See §8 of WINN3_NETWORK_REALISM_20260808.md: that
// harness is a sibling lane's territory and was not touched, but the same shape
// is there.
type stepTimer struct {
	at      time.Time
	ch      chan time.Time
	stopped atomic.Bool
}

func (t *stepTimer) C() <-chan time.Time { return t.ch }
func (t *stepTimer) Stop()               { t.stopped.Store(true) }

// SessionClockOf adapts a StepClock to the Now()-only interface the session and
// tun layers take.
func SessionClockOf(c *StepClock) driver.SessionClock { return driver.SessionClock{Clock: c} }
