package main

import (
	"hash/maphash"
	"net/netip"
	"sync"
	"time"
)

// The admission work budget for this binary's read loop.
//
// A datagram from an address that holds no session has one place to go: the
// admission screen (core.Responder.ScreenInitiation). That screen un-whitens
// the whole body and computes one HMAC per candidate freshness bucket per
// admission key, with deliberately no early exit on the reject path
// (winn3/core verifyAdmission). In this binary the screen runs on the single
// socket reader (server.readLoop), the same goroutine that delivers every
// established session's datagrams into its pipe, so an unmetered screen lets
// unauthenticated junk spend the reader that connected users depend on:
// measured 13.3_us and 197 allocations per maximum-size junk datagram on a
// fast arm64 host, against the roughly 11_us per packet the whole reader has
// at one gigabit (91,041 packets per second at the plan floor's inner MTU).
//
// winn3/gateway meters exactly this path (gateway.Handle: a global bucket
// plus fixed per-source cells, defaults in winn3/gateway/params.go), but
// this binary demultiplexes by address and does not use that front door, so
// it needs the same budget in its own reader. The rates below are the
// gateway package's defaults, kept identical so the two front doors spend
// the same CPU on unauthenticated traffic.
//
// The meter is consulted only for an address that holds no session, after
// the length check and before the screen. Established sessions are never
// metered: they dispatch through known() and Pipe.Deliver, so a handshake
// flood costs a connected user nothing, which is the property
// winn3/gateway's guard exists to provide. A refusal here is silence toward
// the peer, counted for the operator (see serveStatus.AdmissionThrottled).
//
// The per-source structure is a fixed array rather than a map, for
// winn3/gateway's stated reason: a map keyed on source address is itself an
// exhaustion target. The array never grows, never allocates after
// construction, and is indexed by a per-process randomly seeded hash of the
// source address and port, so an attacker cannot choose which cell they
// land in. Keying on the address and port, not the address alone, matches
// the gateway package's opaque-source metering and does not make every
// client behind one carrier-grade NAT address share one cell.

const (
	// 2000 caps junk screening near 3% of a fast core (10 to 15% of a
	// 2.0 GHz fleet core) on the reader that live sessions share; a full
	// 253-client reconnect storm stays well inside it (audit L07 I-1).
	admissionRate        = 2000 // screens per second, gateway-wide
	admissionBurst       = 2000
	admissionSourceRate  = 20 // screens per second, per source cell
	admissionSourceBurst = 40
	admissionSourceCells = 4096
)

// admissionBucket is a token bucket with an injected clock, the same shape
// as winn3/gateway's bucket.
type admissionBucket struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	toks  float64
	last  time.Time
}

func (b *admissionBucket) allow(now time.Time) bool {
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

// admissionMeter is the two-level work budget: one gateway-wide bucket and
// a fixed array of per-source cells. Both must allow before a screen runs.
type admissionMeter struct {
	global admissionBucket
	seed   maphash.Seed
	cells  []admissionBucket
	mask   uint64
}

func newAdmissionMeter() *admissionMeter {
	n := 1
	for n < admissionSourceCells {
		n <<= 1
	}
	m := &admissionMeter{
		seed:  maphash.MakeSeed(),
		cells: make([]admissionBucket, n),
		mask:  uint64(n - 1),
	}
	m.global = admissionBucket{
		rate: admissionRate, burst: admissionBurst, toks: admissionBurst,
	}
	for i := range m.cells {
		m.cells[i] = admissionBucket{
			rate: admissionSourceRate, burst: admissionSourceBurst, toks: admissionSourceBurst,
		}
	}
	return m
}

// allow spends one screen from both budgets for a datagram from src. The
// source cell is checked first, so datagrams already refused by their own
// cell cannot spend the global budget every other new client needs.
func (m *admissionMeter) allow(src netip.AddrPort, now time.Time) bool {
	if m == nil {
		return true
	}
	var key [18]byte
	addr := src.Addr().Unmap().As16()
	copy(key[:16], addr[:])
	key[16] = byte(src.Port() >> 8)
	key[17] = byte(src.Port())
	h := maphash.Bytes(m.seed, key[:])
	if !m.cells[h&m.mask].allow(now) {
		return false
	}
	return m.global.allow(now)
}
