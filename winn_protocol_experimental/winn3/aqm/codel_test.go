package aqm

import (
	"testing"
	"time"
)

const ms = time.Millisecond

func TestDisabledNeverDrops(t *testing.T) {
	var c CoDel
	for now := time.Duration(0); now < 2*time.Second; now += ms {
		if c.Decide(now, time.Second, 1000) {
			t.Fatalf("a zero CoDel dropped at %v", now)
		}
	}
}

func TestBelowTargetNeverDrops(t *testing.T) {
	c := NewCoDel(DefaultTarget, DefaultInterval)
	for now := time.Duration(0); now < 5*time.Second; now += 100 * time.Microsecond {
		if c.Decide(now, DefaultTarget-time.Microsecond, 4096) {
			t.Fatalf("dropped a packet below target at %v", now)
		}
	}
}

func TestASinglePacketQueueIsNeverDropped(t *testing.T) {
	c := NewCoDel(DefaultTarget, DefaultInterval)
	for now := time.Duration(0); now < 5*time.Second; now += ms {
		if c.Decide(now, time.Second, 1) {
			t.Fatalf("dropped the only queued packet at %v", now)
		}
	}
}

// The first drop waits one full interval above target, and the control law
// then shortens the spacing as interval/sqrt(count).
func TestFirstDropAfterOneIntervalThenControlLaw(t *testing.T) {
	c := NewCoDel(DefaultTarget, DefaultInterval)
	var drops []time.Duration
	for now := time.Duration(0); now <= 400*ms; now += 100 * time.Microsecond {
		for c.Decide(now, 20*ms, 1000) {
			drops = append(drops, now)
		}
	}
	if len(drops) < 3 {
		t.Fatalf("want at least 3 drops in 400 ms of a standing 20 ms queue, got %v", drops)
	}
	if drops[0] < DefaultInterval || drops[0] > DefaultInterval+ms {
		t.Fatalf("first drop at %v, want one interval (%v) after the queue first stood above target", drops[0], DefaultInterval)
	}
	// RFC 8289: entering the dropping state sets count 1, so the second drop
	// is interval/sqrt(1) after the first and the third interval/sqrt(2)
	// after the second, each within one 100 us step.
	if d := drops[1] - (drops[0] + DefaultInterval); d < 0 || d > 200*time.Microsecond {
		t.Fatalf("second drop at %v, want %v", drops[1], drops[0]+DefaultInterval)
	}
	spacing := float64(DefaultInterval) / 1.4142135623730951
	want := drops[1] + time.Duration(spacing)
	if d := drops[2] - want; d < 0 || d > 200*time.Microsecond {
		t.Fatalf("third drop at %v, want %v (interval/sqrt(2) after the second)", drops[2], want)
	}
	for i := 2; i < len(drops); i++ {
		if drops[i]-drops[i-1] > drops[i-1]-drops[i-2]+200*time.Microsecond {
			t.Fatalf("drop spacing grew while the queue stood: %v", drops)
		}
	}
}

// Leaving the dropping state needs only one head at or under target.
func TestLeavesDroppingWhenSojournFalls(t *testing.T) {
	c := NewCoDel(DefaultTarget, DefaultInterval)
	now := time.Duration(0)
	for ; now <= 150*ms; now += ms {
		c.Decide(now, 30*ms, 500)
	}
	if !c.Dropping() {
		t.Fatal("not dropping after 150 ms of a 30 ms standing queue")
	}
	if c.Decide(now, ms, 500) {
		t.Fatal("dropped a head under target")
	}
	if c.Dropping() {
		t.Fatal("still dropping after a head under target")
	}
}

// A drop never removes two packets in a row while the control-law spacing is
// above the caller's dequeue spacing: the bound on a contiguous outer gap
// caused by the controller on the receive inbox.
func TestDropsAreSpacedNotBursty(t *testing.T) {
	c := NewCoDel(DefaultTarget, DefaultInterval)
	consecutive, worst := 0, 0
	// A 40k packets/s dequeue against a 10 ms standing queue for 2 s.
	for now := time.Duration(0); now < 2*time.Second; now += 25 * time.Microsecond {
		if c.Decide(now, 10*ms, 400) {
			consecutive++
			worst = max(worst, consecutive)
			continue
		}
		consecutive = 0
	}
	if worst > 1 {
		t.Fatalf("CoDel dropped %d head packets in a row at 40k/s", worst)
	}
}

func TestEmptyRestartsTheInterval(t *testing.T) {
	c := NewCoDel(DefaultTarget, DefaultInterval)
	c.Decide(0, 20*ms, 10)
	c.Empty()
	// 99 ms later, a fresh above-target head must wait its own interval.
	if c.Decide(99*ms, 20*ms, 10) {
		t.Fatal("dropped before a fresh interval had elapsed after Empty")
	}
}
