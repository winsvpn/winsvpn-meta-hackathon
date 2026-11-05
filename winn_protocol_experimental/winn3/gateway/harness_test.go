package gateway

import (
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// fixedNow is midnight-aligned so that the freshness bucket arithmetic in the
// admission tests is exact rather than approximate.
var fixedNow = time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

// testGatewayPathMTU is the planning path MTU the MTU-agnostic tests build their
// gateways at. A gateway can no longer be constructed without one, and these
// tests never read the notice, so any legal value would do; the narrowest legal
// claim is chosen so that a test that DOES assert on a notice cannot silently
// share a constant with a harness that does not care.
const testGatewayPathMTU = MinPathMTUForInnerIPv6

// --- a synthetic session, for the table tests -------------------------------
//
// The table's job is routing, and routing can be tested without cryptography as
// long as the stand-in is honest about the three things the real session does
// that the table depends on: it refuses a message it did not produce, it
// refuses a second copy of one it already opened, and it changes no state when
// it refuses. This one does all three, and the integration tests then repeat
// the whole exercise against real core sessions so that the stand-in cannot be
// hiding anything.

const fakeMsgLen = 40

type fakeSession struct {
	src TokenSource
	// id makes two sessions' messages differ even when their tokens collide,
	// which is what the real AEAD does and what the collision tests need.
	id byte

	mu     sync.Mutex
	opened map[uint64]bool
	reject map[uint64]bool
	calls  int
}

func newFakeSession(src TokenSource, id byte) *fakeSession {
	return &fakeSession{src: src, id: id, opened: map[uint64]bool{}, reject: map[uint64]bool{}}
}

// message renders a datagram for a counter: token, then the counter in the
// clear, then filler. The counter in the body stands in for what the real AEAD
// recovers from the nonce.
func (f *fakeSession) message(counter uint64) []byte {
	m := make([]byte, fakeMsgLen)
	t := f.src.TokenAt(counter)
	copy(m, t[:])
	binary.BigEndian.PutUint64(m[core.DemuxTokenSize:], counter)
	for i := core.DemuxTokenSize + 8; i < len(m); i++ {
		m[i] = byte(counter) ^ byte(i) ^ f.id
	}
	return m
}

func (f *fakeSession) Open(msg []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if len(msg) != fakeMsgLen {
		return nil, core.ErrShortMessage
	}
	counter := binary.BigEndian.Uint64(msg[core.DemuxTokenSize:])
	want := f.src.TokenAt(counter)
	for i := range want {
		if want[i] != msg[i] {
			return nil, core.ErrUnauthenticated
		}
	}
	if f.reject[counter] {
		return nil, core.ErrDecrypt
	}
	for i := core.DemuxTokenSize + 8; i < len(msg); i++ {
		if msg[i] != byte(counter)^byte(i)^f.id {
			return nil, core.ErrDecrypt
		}
	}
	if f.opened[counter] {
		return nil, core.ErrReplay
	}
	f.opened[counter] = true
	return msg[core.DemuxTokenSize+8:], nil
}

func (f *fakeSession) openCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// keyFor makes a distinct, deterministic demux key per test subject.
func keyFor(n int) *[core.KeySize]byte {
	var k [core.KeySize]byte
	for i := range k {
		k[i] = byte(n*7 + i*13 + 1)
	}
	return &k
}

func newFake(n int) (*fakeSession, TokenSource) {
	src := NewKeyedSource(keyFor(n))
	return newFakeSession(src, byte(n)), src
}

// clientKey makes a distinct 32-byte stand-in for a client static public key.
// Distinct for every n, not just for small n: the per-client session cap keys
// on this, so two "different" clients that collided would silently turn a
// many-client test into a four-session one.
func clientKey(n int) []byte {
	b := make([]byte, core.KeySize)
	binary.BigEndian.PutUint64(b, uint64(n))
	for i := 8; i < len(b); i++ {
		b[i] = byte(n*31 + i)
	}
	return b
}

// testTable builds a table with test-friendly limits, failing the test rather
// than returning an error nobody checks.
func testTable(t *testing.T, cfg Config) *Table {
	t.Helper()
	tbl, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	t.Cleanup(tbl.Close)
	return tbl
}

// registerFake admits one synthetic session.
func registerFake(t *testing.T, tbl *Table, n int) (*Entry, *fakeSession) {
	t.Helper()
	f, src := newFake(n)
	e, err := tbl.Register(f, src, clientKey(n), fixedNow)
	if err != nil {
		t.Fatalf("Register(%d): %v", n, err)
	}
	return e, f
}

// --- a real core handshake, for the integration tests -----------------------

type realHarness struct {
	t   *testing.T
	now time.Time

	gwStatic  *core.StaticKey
	admission []byte
	gwCfg     core.Config
	resp      *core.Responder
	gw        *Gateway

	mu sync.Mutex
}

// harvestSource is a TokenSource built from tokens observed on real ciphertexts
// rather than derived from a key.
//
// It exists because core.Session does not export its receive demux key, so the
// production KeyedSource cannot be wired up yet. Harvesting the true sequence
// from real seals gives the table exactly the same input it will get in
// production, which is what makes the integration tests real: the crypto, the
// tokens and the dispatch are all genuine, and only the way the sequence
// reaches the table is a stand-in.
//
// Counters beyond the harvested run return a deterministic filler token. The
// table asks for tokens up to the top of the window whether or not a message
// with that counter exists, and consistency is all it needs from them.
type harvestSource struct {
	mu   sync.Mutex
	real map[uint64]Token
	fill [core.KeySize]byte
}

func newHarvestSource(seed int) *harvestSource {
	h := &harvestSource{real: map[uint64]Token{}}
	copy(h.fill[:], keyFor(1000 + seed)[:])
	return h
}

func (h *harvestSource) record(counter uint64, msg []byte) {
	var tok Token
	copy(tok[:], msg[:core.DemuxTokenSize])
	h.mu.Lock()
	h.real[counter] = tok
	h.mu.Unlock()
}

func (h *harvestSource) TokenAt(counter uint64) Token {
	h.mu.Lock()
	tok, ok := h.real[counter]
	h.mu.Unlock()
	if ok {
		return tok
	}
	return DeriveToken(&h.fill, counter)
}

func newRealHarness(t *testing.T, cfg Config) *realHarness {
	t.Helper()
	h := &realHarness{t: t, now: fixedNow}

	var err error
	h.gwStatic, err = core.GenerateStaticKey()
	if err != nil {
		t.Fatalf("gateway static key: %v", err)
	}
	h.admission = make([]byte, core.KeySize)
	for i := range h.admission {
		h.admission[i] = byte(0xA0 + i)
	}
	h.gwCfg = core.Config{
		Gateway: core.GatewayParams{
			AdmissionKeys: [][]byte{h.admission},
			GatewayID:     []byte("winn3-gateway-table-test"),
			TagSize:       core.DefaultTagSize,
		},
		Now: func() time.Time { return h.clock() },
	}
	h.resp, err = core.NewResponder(h.gwCfg, h.gwStatic, func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}

	if cfg.Now == nil {
		cfg.Now = func() time.Time { return h.clock() }
	}
	h.gw, err = New(cfg, testGatewayPathMTU, h.resp, h.binder())
	if err != nil {
		t.Fatalf("New gateway: %v", err)
	}
	t.Cleanup(h.gw.Table().Close)
	return h
}

func (h *realHarness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *realHarness) setNow(at time.Time) {
	h.mu.Lock()
	h.now = at
	h.mu.Unlock()
}

// binder is what the front door uses when it completes a handshake itself.
//
// It hands over a fresh, empty harvest source. That is honest for the front-door
// tests, which are about admission, capacity and silence rather than about
// transport dispatch: the window that gets published is a consistent sequence
// that no real message will ever match, so those sessions occupy the table
// exactly as real ones do and route nothing. The transport-dispatch tests use
// newClient, which knows the true sequence.
func (h *realHarness) binder() Binder {
	n := 0
	var mu sync.Mutex
	return func(sess *core.Session) (Opener, TokenSource, error) {
		mu.Lock()
		n++
		seed := 500000 + n
		mu.Unlock()
		return sess, newHarvestSource(seed), nil
	}
}

// refusingBinder is the failure path: a binder that cannot produce a token
// sequence. The gateway must then answer nothing at all.
func refusingBinder() Binder {
	return func(*core.Session) (Opener, TokenSource, error) {
		return nil, nil, errors.New("binder refused")
	}
}

// client is one end-to-end client: its own static key, its own real session,
// and a pre-sealed run of real transport messages.
type client struct {
	static  *core.StaticKey
	sess    *core.Session
	gwSess  *core.Session
	msgs    [][]byte
	initMsg []byte
	source  *harvestSource
	entry   *Entry
}

// newClient runs a real handshake and pre-seals `seal` real transport messages,
// harvesting their tokens, and only then registers the gateway session.
//
// The order matters and is the reason the handshake is driven directly against
// core here rather than through Handle: a session's keys do not exist until the
// handshake completes on BOTH ends, so the true token sequence cannot be known
// until after the client has read the response. Registering first and learning
// the tokens afterwards would publish the wrong window. Handle's own handshake
// path is exercised separately, by the front-door tests.
func (h *realHarness) newClient(t *testing.T, n, seal int) *client {
	t.Helper()

	cs, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatalf("client static key: %v", err)
	}
	gwPub, err := core.NewPublicKey(h.gwStatic.Public())
	if err != nil {
		t.Fatalf("gateway public key: %v", err)
	}
	ini, err := core.NewInitiator(h.clientConfig(), cs, gwPub)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	initMsg, err := ini.WriteInitiation(nil, core.PadAuto)
	if err != nil {
		t.Fatalf("WriteInitiation: %v", err)
	}
	hs, err := h.resp.ReadInitiation(initMsg)
	if err != nil {
		t.Fatalf("ReadInitiation: %v", err)
	}
	reply, gwSess, err := hs.WriteResponse(nil, core.PadAuto)
	if err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	cliSess, _, err := ini.ReadResponse(reply)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	c := &client{static: cs, sess: cliSess, gwSess: gwSess, initMsg: initMsg, source: newHarvestSource(n)}
	for i := 0; i < seal; i++ {
		msg, err := cliSess.Seal([]byte{byte(i), byte(i >> 8), 0x5A}, 0)
		if err != nil {
			t.Fatalf("client %d: Seal(%d): %v", n, i, err)
		}
		c.source.record(uint64(i), msg)
		c.msgs = append(c.msgs, msg)
	}

	c.entry, err = h.gw.Table().Register(gwSess, c.source, cs.Public(), h.clock())
	if err != nil {
		t.Fatalf("client %d: Register: %v", n, err)
	}
	return c
}

// clientConfig is the wire profile a real client is configured with: the same
// admission key, gateway id and tag size the gateway holds, because none of
// those is negotiated and there is no field on the wire to carry them.
func (h *realHarness) clientConfig() core.Config {
	return core.Config{
		Gateway: core.GatewayParams{
			AdmissionKeys: [][]byte{h.admission},
			GatewayID:     h.gwCfg.Gateway.GatewayID,
			TagSize:       core.DefaultTagSize,
		},
		Now: func() time.Time { return h.clock() },
	}
}

// initiation mints a fresh, genuinely authenticating initiation from a brand
// new client identity, for the front-door tests.
func (h *realHarness) initiation(t *testing.T) []byte {
	t.Helper()
	cs, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatalf("client static key: %v", err)
	}
	gwPub, err := core.NewPublicKey(h.gwStatic.Public())
	if err != nil {
		t.Fatalf("gateway public key: %v", err)
	}
	ini, err := core.NewInitiator(h.clientConfig(), cs, gwPub)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	msg, err := ini.WriteInitiation(nil, core.PadAuto)
	if err != nil {
		t.Fatalf("WriteInitiation: %v", err)
	}
	return msg
}
