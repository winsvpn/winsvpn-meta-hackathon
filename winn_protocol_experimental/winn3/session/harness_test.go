package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// testClock is the injected policy clock. Every timing test in this package is
// deterministic because of it: no test sleeps, and no test races a real timer.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *testClock {
	return &testClock{t: time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// detRand is a reproducible byte stream for known-answer vectors. It is a
// counter-mode SHA-256 expansion of a seed, which is enough for a KAT and is
// obviously not fit for production; Config.Rand documents why.
type detRand struct {
	seed []byte
	ctr  uint64
	buf  []byte
}

func newDetRand(seed string) *detRand { return &detRand{seed: []byte(seed)} }

func (r *detRand) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(r.buf) == 0 {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], r.ctr)
			r.ctr++
			h := sha256.Sum256(append(append([]byte{}, r.seed...), c[:]...))
			r.buf = h[:]
		}
		k := copy(p[n:], r.buf)
		r.buf = r.buf[k:]
		n += k
	}
	return len(p), nil
}

// --- a driver pair over an in-memory link -----------------------------------

// pair runs a client driver and a gateway driver against each other with no
// sockets and no goroutines, so a test can drop, reorder, duplicate or inject
// messages exactly and repeatably.
type pair struct {
	t   *testing.T
	clk *testClock

	cli *Driver
	gw  *Driver

	toGw  [][]byte
	toCli [][]byte

	atGw  [][]byte
	atCli [][]byte

	// filters run on every message leaving a driver. Returning false drops it.
	filterToGw  func(idx int, msg []byte) bool
	filterToCli func(idx int, msg []byte) bool

	nToGw  int
	nToCli int

	// Retained so a test can build a fresh initiation from the SAME client
	// static key and gateway params, which is what a re-initiation is.
	cliStatic *core.StaticKey
	gwPub     *core.PublicKey
	gp        core.GatewayParams
}

// newInitiator builds a fresh core.Initiator with the pair's client static key
// and gateway params: its WriteInitiation is a re-initiation the pair's gateway
// authenticates as the same peer.
func (p *pair) newInitiator(t *testing.T) *core.Initiator {
	t.Helper()
	clk := p.clk
	ini, err := core.NewInitiator(core.Config{
		Gateway: p.gp,
		Now:     func() time.Time { return clk.Now() },
	}, p.cliStatic, p.gwPub)
	if err != nil {
		t.Fatal(err)
	}
	return ini
}

func gatewayParams(t *testing.T) core.GatewayParams {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return core.GatewayParams{
		AdmissionKeys: [][]byte{key},
		GatewayID:     []byte("winn3-session-test-gateway"),
	}
}

// newPair builds a client and a gateway sharing one clock and one gateway
// profile. tweak may adjust both configs before they are used.
func newPair(t *testing.T, tweak func(cli, gw *Config)) *pair {
	t.Helper()
	clk := newClock()

	gwStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	cliStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	gwPub, err := core.NewPublicKey(gwStatic.Public())
	if err != nil {
		t.Fatal(err)
	}
	gp := gatewayParams(t)

	cliCfg := Config{
		Core:          core.Config{Gateway: gp},
		Static:        cliStatic,
		GatewayStatic: gwPub,
		Padding:       core.PadBucket,
		Clock:         clk,
	}
	gwCfg := Config{
		Core:    core.Config{Gateway: gp},
		Static:  gwStatic,
		Accept:  func([]byte) error { return nil },
		Padding: core.PadBucket,
		Clock:   clk,
	}
	if tweak != nil {
		tweak(&cliCfg, &gwCfg)
	}

	cli, err := NewClient(cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := NewGateway(gwCfg)
	if err != nil {
		t.Fatal(err)
	}
	return &pair{t: t, clk: clk, cli: cli, gw: gw, cliStatic: cliStatic, gwPub: gwPub, gp: gp}
}

// drain takes everything both drivers want to send and puts it on the link,
// applying the filters.
func (p *pair) drain() int {
	p.t.Helper()
	moved := 0
	for i := 0; i < 512; i++ {
		msg, err := p.cli.Poll()
		if err != nil {
			p.t.Fatalf("client poll: %v", err)
		}
		if msg == nil {
			break
		}
		idx := p.nToGw
		p.nToGw++
		if p.filterToGw == nil || p.filterToGw(idx, msg) {
			p.toGw = append(p.toGw, msg)
		}
		moved++
	}
	for i := 0; i < 512; i++ {
		msg, err := p.gw.Poll()
		if err != nil {
			p.t.Fatalf("gateway poll: %v", err)
		}
		if msg == nil {
			break
		}
		idx := p.nToCli
		p.nToCli++
		if p.filterToCli == nil || p.filterToCli(idx, msg) {
			p.toCli = append(p.toCli, msg)
		}
		moved++
	}
	return moved
}

// deliver hands everything on the link to its destination.
func (p *pair) deliver() int {
	p.t.Helper()
	moved := 0
	toGw, toCli := p.toGw, p.toCli
	p.toGw, p.toCli = nil, nil
	for _, m := range toGw {
		pkts, err := p.gw.Deliver(m)
		if err != nil {
			continue // terminal; the test asserts on state
		}
		p.atGw = append(p.atGw, pkts...)
		moved++
	}
	for _, m := range toCli {
		pkts, err := p.cli.Deliver(m)
		if err != nil {
			continue
		}
		p.atCli = append(p.atCli, pkts...)
		moved++
	}
	return moved
}

// run alternates drain and deliver until nothing moves, up to a bound.
func (p *pair) run() {
	p.t.Helper()
	for i := 0; i < 64; i++ {
		a := p.drain()
		b := p.deliver()
		if a == 0 && b == 0 {
			return
		}
	}
	p.t.Fatal("pair did not quiesce")
}

// establish runs the handshake and the post-quantum ratchet to completion.
func (p *pair) establish() {
	p.t.Helper()
	p.run()
	if got := p.cli.State(); got != StateEstablished {
		p.t.Fatalf("client state is %s, want established (err %v)", got, p.cli.Err())
	}
	if got := p.gw.State(); got != StateEstablished {
		p.t.Fatalf("gateway state is %s, want established (err %v)", got, p.gw.Err())
	}
}

func (p *pair) resetDelivered() {
	p.atGw = nil
	p.atCli = nil
}
