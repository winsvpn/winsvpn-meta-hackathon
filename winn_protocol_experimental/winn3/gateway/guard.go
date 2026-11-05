package gateway

import (
	"hash/maphash"
	"sync"
	"time"
)

// The admission work budget.
//
// A datagram that misses the token index has one place left to go: the
// handshake admission check. That check is cheap by the standards of public-key
// cryptography and expensive by the standards of a packet — core un-whitens the
// whole body with a keystream expansion and computes at least one HMAC, per
// admission key. At a hundred thousand datagrams a second that is real CPU, and
// an adversary in Myanmar who can generate that load for free must not be able
// to convert it into a gateway that stops answering real clients.
//
// So the expensive path is metered, in two places at once:
//
//   - a gateway-wide bucket, which is the operator's decision about how much
//     CPU they are willing to sell to unauthenticated traffic;
//   - a fixed-size array of per-source cells, which stops one source consuming
//     the gateway-wide budget on its own.
//
// The per-source structure is a fixed array rather than a map on purpose. A map
// keyed on source address is itself an exhaustion target — the classic mistake
// of defending against a flood by allocating state per flooder. The array never
// grows, never allocates, and is indexed by a per-process randomly seeded hash
// so that an attacker cannot choose which cell they land in and therefore
// cannot aim collisions at a victim.
//
// What this deliberately does NOT meter is established sessions. They dispatch
// through the token index, which is O(1) and unmetered, so a handshake flood
// costs a connected user in Myanmar nothing at all. That is the property worth
// having, and it is pinned by a test.

// bucket is a token bucket with an injected clock.
type bucket struct {
	mu    sync.Mutex
	rate  float64 // tokens per second
	burst float64
	toks  float64
	last  time.Time
}

func newBucket(rate, burst int) *bucket {
	return &bucket{rate: float64(rate), burst: float64(burst), toks: float64(burst)}
}

// allow spends one token if there is one. A zero or negative rate is unmetered.
func (b *bucket) allow(now time.Time) bool {
	if b == nil || b.rate <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.last = now
	}
	if d := now.Sub(b.last); d > 0 {
		b.toks += d.Seconds() * b.rate
		if b.toks > b.burst {
			b.toks = b.burst
		}
		b.last = now
	}
	if b.toks < 1 {
		return false
	}
	b.toks--
	return true
}

// sourceGuard is the fixed-size per-source meter.
type sourceGuard struct {
	seed  maphash.Seed
	cells []bucket
	mask  uint64
}

func newSourceGuard(cells, rate, burst int) *sourceGuard {
	n := 1
	for n < cells {
		n <<= 1
	}
	g := &sourceGuard{seed: maphash.MakeSeed(), cells: make([]bucket, n), mask: uint64(n - 1)}
	for i := range g.cells {
		g.cells[i].rate = float64(rate)
		g.cells[i].burst = float64(burst)
		g.cells[i].toks = float64(burst)
	}
	return g
}

// allow meters one admission attempt from a source.
//
// An empty source is treated as "unknown" and shares one cell. A carrier that
// cannot name its peer — a stream carrier that has already demultiplexed, say —
// simply gets the gateway-wide budget, which is the correct conservative
// answer rather than an exemption.
func (g *sourceGuard) allow(src []byte, now time.Time) bool {
	if g == nil || len(g.cells) == 0 || g.cells[0].rate <= 0 {
		return true
	}
	h := maphash.Bytes(g.seed, src)
	return g.cells[h&g.mask].allow(now)
}
