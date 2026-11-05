package main

import (
	"sync"
	"time"
)

// freeBandwidthBurstBytes is the bucket depth for a rate of mbps Mbit/s: one
// hundred milliseconds of the rate (mbps * 125000 bytes/second / 10). A
// policer whose burst cannot cover one path round trip starves a single TCP
// flow well below the advertised rate, so the burst is derived, not tuned:
// at 100 Mbit/s it is 1,250,000 bytes, and no operator knob exists to shrink
// it. The absolute cap keeps the largest permitted rate inside 64 MiB.
func freeBandwidthBurstBytes(mbps int) int {
	burst := mbps * 12500
	if burst > 67108864 {
		burst = 67108864
	}
	if burst < 1 {
		burst = 1
	}
	return burst
}

// peerBandwidth accounts inner IP bytes, with independent directional budgets.
// It is registry-owned, so a new transport or handshake cannot mint a burst.
// Paid bindings hold nil and never read a clock or acquire a bucket lock.
type peerBandwidth struct {
	up   byteBucket
	down byteBucket
}

type byteBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  int
	credit float64
	last   time.Time
}

func newPeerBandwidth(mbps int) *peerBandwidth {
	if mbps == 0 {
		return nil
	}
	now := time.Now()
	burst := freeBandwidthBurstBytes(mbps)
	makeBucket := func() byteBucket {
		return byteBucket{rate: float64(mbps) * 125000, burst: burst, credit: float64(burst), last: now}
	}
	return &peerBandwidth{up: makeBucket(), down: makeBucket()}
}

func (p *peerBandwidth) allow(n int, down bool) bool {
	if p == nil {
		return true
	}
	if down {
		return p.down.allowAt(n, time.Now())
	}
	return p.up.allowAt(n, time.Now())
}

// allowAt never queues, sleeps, borrows future credit, or replenishes a burst
// on refusal. The bound for any interval T is rate*T + burst inner bytes.
func (b *byteBucket) allowAt(n int, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.After(b.last) {
		b.credit = min(float64(b.burst), b.credit+now.Sub(b.last).Seconds()*b.rate)
		b.last = now
	}
	if n <= 0 || n > b.burst || float64(n) > b.credit {
		return false
	}
	b.credit -= float64(n)
	return true
}
