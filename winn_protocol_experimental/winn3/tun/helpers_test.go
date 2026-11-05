package tun

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// --- addresses ---------------------------------------------------------------
//
// Built from bytes rather than written as text so that nothing in this tree
// ever contains a literal address in dotted form. The inner ranges are private
// (RFC 1918 / RFC 3849 documentation prefix); the "somewhere else" ranges are
// documentation ranges. None of them is any node this project runs.

func v4a(a, b, c, d byte) netip.Addr { return netip.AddrFrom4([4]byte{a, b, c, d}) }

// docV6 builds an address in the RFC 3849 documentation prefix.
func docV6(last byte) netip.Addr {
	var a [16]byte
	a[0], a[1], a[2], a[3] = 0x20, 0x01, 0x0d, 0xb8
	a[15] = last
	return netip.AddrFrom16(a)
}

// ulaV6 builds a unique-local address, which is what a gateway would normally
// assign for an inner IPv6.
func ulaV6(last byte) netip.Addr {
	var a [16]byte
	a[0] = 0xfd
	a[15] = last
	return netip.AddrFrom16(a)
}

func mappedV6(a, b, c, d byte) netip.Addr {
	var x [16]byte
	x[10], x[11] = 0xff, 0xff
	x[12], x[13], x[14], x[15] = a, b, c, d
	return netip.AddrFrom16(x)
}

func compatV6(last byte) netip.Addr {
	var x [16]byte
	x[14] = 0x10
	x[15] = last
	return netip.AddrFrom16(x)
}

// --- fixture -----------------------------------------------------------------

const (
	// fixtureCarrierFloor is a UDP-over-IPv6 carrier on a 1500-byte path:
	// 1500 - 48 = 1452.
	fixtureCarrierFloor = 1452

	// fixtureInnerMTU is what that leaves after this package's overhead.
	// TestInnerMTUArithmetic checks the subtraction rather than trusting it.
	fixtureInnerMTU = 1423
)

func fixtureAssign() Assignment {
	return Assignment{
		V4:       v4a(10, 64, 0, 2),
		RouterV4: v4a(10, 64, 0, 1),
		V6:       ulaV6(2),
		RouterV6: ulaV6(1),
	}
}

// peers, used as the far end of a legitimate flow.
func peerV4() netip.Addr { return v4a(198, 51, 100, 7) }
func peerV6() netip.Addr { return docV6(0x77) }

type fixture struct {
	t     *testing.T
	tun   *Tunnel
	dev   *fakeDevice
	sink  *fakeSink
	clock *fakeClock
	gate  *Gate
}

func newFixture(t *testing.T, mutate ...func(*Config)) *fixture {
	t.Helper()
	dev := &fakeDevice{mtu: fixtureInnerMTU}
	sink := &fakeSink{}
	clock := newFakeClock()
	gate := NewGate()
	cfg := Config{
		Assign:                  fixtureAssign(),
		Device:                  dev,
		Sink:                    sink,
		Clock:                   clock,
		Gate:                    gate,
		CarrierFloorMessageSize: fixtureCarrierFloor,
	}
	for _, m := range mutate {
		m(&cfg)
	}
	tn, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &fixture{t: t, tun: tn, dev: dev, sink: sink, clock: clock, gate: gate}
}

// carrying opens the gate. Nothing in this package opens it implicitly.
func (f *fixture) carrying() *fixture {
	f.gate.Set(StateCarrying)
	return f
}

// quiet asserts that nothing at all has moved: no packet to the session, no
// packet to the host. It is the assertion the fail-closed tests are made of, so
// it deliberately checks BOTH sinks every time rather than whichever one the
// caller happened to think about.
func (f *fixture) quiet(what string) {
	f.t.Helper()
	if n := f.sink.count(); n != 0 {
		f.t.Fatalf("%s: %d packet(s) reached the session; expected none", what, n)
	}
	if n := f.dev.writeCount(); n != 0 {
		f.t.Fatalf("%s: %d packet(s) were written to the host device; expected none", what, n)
	}
}

// --- fake device -------------------------------------------------------------

var errNoMoreReads = errors.New("fake device: read queue is empty")

type fakeDevice struct {
	mu       sync.Mutex
	mtu      int
	written  [][]byte
	writeErr error
	shortBy  int
	onWrite  func(pkt []byte)

	readQueue [][]byte
	readIdx   int
	readErr   error

	// overreport makes ReadPacket claim it copied more than it did, which is
	// what a buggy or hostile device implementation looks like.
	overreport int
}

func (d *fakeDevice) MTU() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.mtu
}

func (d *fakeDevice) ReadPacket(buf []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.readIdx >= len(d.readQueue) {
		if d.readErr != nil {
			return 0, d.readErr
		}
		return 0, errNoMoreReads
	}
	p := d.readQueue[d.readIdx]
	d.readIdx++
	return copy(buf, p) + d.overreport, nil
}

func (d *fakeDevice) WritePacket(pkt []byte) (int, error) {
	d.mu.Lock()
	hook := d.onWrite
	d.mu.Unlock()
	if hook != nil {
		hook(pkt)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.writeErr != nil {
		return 0, d.writeErr
	}
	d.written = append(d.written, append([]byte(nil), pkt...))
	if d.shortBy > 0 {
		return len(pkt) - d.shortBy, nil
	}
	return len(pkt), nil
}

func (d *fakeDevice) writeCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.written)
}

func (d *fakeDevice) lastWrite() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.written) == 0 {
		return nil
	}
	return d.written[len(d.written)-1]
}

func (d *fakeDevice) allWrites() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([][]byte(nil), d.written...)
}

func (d *fakeDevice) queue(pkts ...[]byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.readQueue = append(d.readQueue, pkts...)
}

// --- fake sink ---------------------------------------------------------------

type fakeSink struct {
	mu      sync.Mutex
	sent    [][]byte
	aliases [][]byte
	err     error
	onSend  func(pkt []byte)
}

func (s *fakeSink) SendData(pkt []byte) error {
	s.mu.Lock()
	hook, err := s.onSend, s.err
	s.mu.Unlock()
	if hook != nil {
		hook(pkt)
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.aliases = append(s.aliases, pkt)
	s.sent = append(s.sent, append([]byte(nil), pkt...))
	return nil
}

func (s *fakeSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

func (s *fakeSink) all() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.sent...)
}

func (s *fakeSink) last() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sent) == 0 {
		return nil
	}
	return s.sent[len(s.sent)-1]
}

func (s *fakeSink) allAliases() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.aliases...)
}

func (s *fakeSink) setHook(f func([]byte)) {
	s.mu.Lock()
	s.onSend = f
	s.mu.Unlock()
}

// --- fake clock --------------------------------------------------------------

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1_754_000_000, 0).UTC()}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// --- packet builders ---------------------------------------------------------

type v4cfg struct {
	src, dst netip.Addr
	payload  int

	ihlWords    byte // 0 means 5
	useTotal    bool
	total       int
	ttl         byte // 0 means 64
	zeroTTL     bool
	proto       byte // 0 means UDP
	df          bool
	mf          bool
	fragOff     uint16
	reserved    bool
	badChecksum bool
	trailer     int // bytes appended past the declared total length
}

func (c v4cfg) build() []byte {
	ihl := IPv4HeaderMin
	if c.ihlWords != 0 {
		ihl = int(c.ihlWords) * 4
	}
	total := ihl + c.payload
	if c.useTotal {
		total = c.total
	}
	size := ihl + c.payload
	if total > size {
		size = total
	}
	buf := make([]byte, size+c.trailer)
	buf[0] = 0x40 | byte(ihl/4)
	binary.BigEndian.PutUint16(buf[2:4], uint16(total))

	var flags byte
	if c.df {
		flags |= 0x40
	}
	if c.mf {
		flags |= 0x20
	}
	if c.reserved {
		flags |= 0x80
	}
	binary.BigEndian.PutUint16(buf[6:8], uint16(flags)<<8|(c.fragOff&0x1fff))

	ttl := byte(64)
	if c.ttl != 0 {
		ttl = c.ttl
	}
	if c.zeroTTL {
		ttl = 0
	}
	buf[8] = ttl

	proto := byte(17)
	if c.proto != 0 {
		proto = c.proto
	}
	buf[9] = proto

	s, d := c.src.As4(), c.dst.As4()
	copy(buf[12:16], s[:])
	copy(buf[16:20], d[:])
	binary.BigEndian.PutUint16(buf[10:12], checksum(buf[:ihl]))
	if c.badChecksum {
		buf[10] ^= 0xff
	}
	// Recognisable filler, so a truncation test can tell payload from tail.
	for i := ihl; i < len(buf); i++ {
		buf[i] = byte(0xa0 + i%16)
	}
	return buf
}

type v6cfg struct {
	src, dst netip.Addr
	payload  int

	useLen   bool
	plen     int
	hopLimit byte // 0 means 64
	zeroHop  bool
	next     byte // 0 means UDP
	trailer  int
}

func (c v6cfg) build() []byte {
	plen := c.payload
	if c.useLen {
		plen = c.plen
	}
	size := IPv6HeaderLen + c.payload
	if IPv6HeaderLen+plen > size {
		size = IPv6HeaderLen + plen
	}
	buf := make([]byte, size+c.trailer)
	buf[0] = 0x60
	binary.BigEndian.PutUint16(buf[4:6], uint16(plen))
	next := byte(17)
	if c.next != 0 {
		next = c.next
	}
	buf[6] = next
	hop := byte(64)
	if c.hopLimit != 0 {
		hop = c.hopLimit
	}
	if c.zeroHop {
		hop = 0
	}
	buf[7] = hop
	s, d := c.src.As16(), c.dst.As16()
	copy(buf[8:24], s[:])
	copy(buf[24:40], d[:])
	for i := IPv6HeaderLen; i < len(buf); i++ {
		buf[i] = byte(0xa0 + i%16)
	}
	return buf
}

// goodV4 is a well-formed outbound IPv4 packet from this tunnel's address.
func goodV4(payload int) []byte {
	return v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: payload, df: true}.build()
}

// goodV6 is a well-formed outbound IPv6 packet from this tunnel's address.
func goodV6(payload int) []byte {
	return v6cfg{src: fixtureAssign().V6, dst: peerV6(), payload: payload}.build()
}

// arrivingV4 and arrivingV6 are well-formed packets coming the other way.
func arrivingV4(payload int) []byte {
	return v4cfg{src: peerV4(), dst: fixtureAssign().V4, payload: payload}.build()
}

func arrivingV6(payload int) []byte {
	return v6cfg{src: peerV6(), dst: fixtureAssign().V6, payload: payload}.build()
}
