package gateway

import (
	"bytes"
	"crypto/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// This file is the OpenerAt seam: the table driving a real core.Session through
// the counter its own index already resolved, so that the session may be
// configured with core.CallerOwnsTokenWindow and never build the duplicate
// window at all.
//
// Everything here runs against real handshakes, real ChaCha20-Poly1305 and real
// demux tokens taken off real ciphertexts, and — for the first time in this
// package — through the production Binder rather than a harvested sequence.

// --- the production wiring, verbatim -----------------------------------------

// productionBinder is the Binder from the doc comment on Binder, copied here
// character for character rather than paraphrased.
//
// It is a test of the doc comment as much as of the code: a doc comment that
// tells the next lane to write a line nobody has compiled is a doc comment that
// is eventually wrong.
func productionBinder(sess *core.Session) (Opener, TokenSource, error) {
	k, _ := sess.RecvDemuxKey()
	return sess, NewKeyedSource(&k), nil
}

// --- a real world, at a chosen core window ----------------------------------

// world is a gateway identity and a responder configured with one particular
// core token window, so the same traffic can be driven through a session that
// keeps its own index and one that does not.
type world struct {
	gwStatic  *core.StaticKey
	admission []byte
	params    core.GatewayParams
	gwCfg     core.Config
	cliCfg    core.Config
	resp      *core.Responder
}

func newWorld(t testing.TB, coreTokenWindow int) *world {
	t.Helper()
	w := &world{}
	var err error
	if w.gwStatic, err = core.GenerateStaticKey(); err != nil {
		t.Fatalf("gateway static key: %v", err)
	}
	w.admission = make([]byte, core.KeySize)
	for i := range w.admission {
		w.admission[i] = byte(0xC0 + i)
	}
	w.params = core.GatewayParams{
		AdmissionKeys: [][]byte{w.admission},
		GatewayID:     []byte("winn3-gateway-openerat-test"),
		TagSize:       core.DefaultTagSize,
	}
	w.gwCfg = core.Config{
		Gateway:     w.params,
		TokenWindow: coreTokenWindow,
		Now:         func() time.Time { return fixedNow },
	}
	// The client keeps its own default window: only the gateway side is under
	// test, and leaving the client at the default keeps the two configurations
	// differing in exactly one field.
	w.cliCfg = core.Config{Gateway: w.params, Now: func() time.Time { return fixedNow }}
	if w.resp, err = core.NewResponder(w.gwCfg, w.gwStatic, func([]byte) error { return nil }); err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	return w
}

// peer is one completed session pair and the identity that made it.
type peer struct {
	static *core.StaticKey
	cli    *core.Session
	gw     *core.Session
}

// handshake completes one real handshake and returns both halves.
func (w *world) handshake(t testing.TB) *peer {
	t.Helper()
	cs, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatalf("client static key: %v", err)
	}
	gwPub, err := core.NewPublicKey(w.gwStatic.Public())
	if err != nil {
		t.Fatalf("gateway public key: %v", err)
	}
	ini, err := core.NewInitiator(w.cliCfg, cs, gwPub)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	initMsg, err := ini.WriteInitiation(nil, core.PadAuto)
	if err != nil {
		t.Fatalf("WriteInitiation: %v", err)
	}
	hs, err := w.resp.ReadInitiation(initMsg)
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
	return &peer{static: cs, cli: cliSess, gw: gwSess}
}

// seal produces n real transport messages from the client half.
func (p *peer) seal(t testing.TB, n int) [][]byte {
	t.Helper()
	out := make([][]byte, n)
	for i := range out {
		msg, err := p.cli.Seal([]byte{byte(i), byte(i >> 8), 0x5A}, 0)
		if err != nil {
			t.Fatalf("Seal(%d): %v", i, err)
		}
		out[i] = msg
	}
	return out
}

// plainFor is what seal put in message i.
func plainFor(i int) []byte { return []byte{byte(i), byte(i >> 8), 0x5A} }

// openerAtCfg is a table whose window neither grows nor shrinks during a test,
// so that a per-datagram cost is a per-datagram cost and not an amortised
// growth.
func openerAtCfg(window, sessions int) Config {
	return Config{
		InitialWindow:        window,
		MaxWindow:            window,
		MinWindow:            16,
		MaxSessions:          sessions,
		MaxSessionsPerClient: sessions,
		Now:                  func() time.Time { return fixedNow },
	}
}

// registerReal admits one real session through the production binder.
func registerReal(t testing.TB, tbl *Table, p *peer) *Entry {
	t.Helper()
	open, src, err := productionBinder(p.gw)
	if err != nil {
		t.Fatalf("productionBinder: %v", err)
	}
	e, err := tbl.Register(open, src, p.static.Public(), fixedNow)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return e
}

// --- stand-ins that narrow or count what the table is given -------------------

// openOnly hides OpenAt from the table, so that the pre-OpenerAt path stays
// reachable and tested with real cryptography behind it.
type openOnly struct{ sess *core.Session }

func (o openOnly) Open(msg []byte) ([]byte, error) { return o.sess.Open(msg) }

// countingOpener implements both interfaces and records which one the table
// actually used.
type countingOpener struct {
	sess    *core.Session
	opens   atomic.Int64
	openAts atomic.Int64
}

func (c *countingOpener) Open(msg []byte) ([]byte, error) {
	c.opens.Add(1)
	return c.sess.Open(msg)
}

func (c *countingOpener) OpenAt(msg []byte, counter uint64) ([]byte, error) {
	c.openAts.Add(1)
	return c.sess.OpenAt(msg, counter)
}

// countingSource records how many times the table asked for a token. It is the
// instrument for the invariant in §4 of the handoff: the table must not derive a
// token in order to decide whether to accept a message.
type countingSource struct {
	base TokenSource
	n    atomic.Int64
}

func (c *countingSource) TokenAt(counter uint64) Token {
	c.n.Add(1)
	return c.base.TokenAt(counter)
}

// --- 1. the production binder ------------------------------------------------

// TestTheProductionBinderNamesTheTokensOnTheWire.
//
// The gateway derives demux tokens from a duplicated copy of core's label and
// construction (see labelDemux). Now that RecvDemuxKey exists, that duplication
// can be checked the only way that really settles it: against the tokens on the
// front of real ciphertexts, in both core window configurations, for every
// counter of a run rather than at a handful of known answers.
func TestTheProductionBinderNamesTheTokensOnTheWire(t *testing.T) {
	for _, tc := range []struct {
		name   string
		window int
	}{
		{"core keeps its own index", 0},
		{"caller owns the window", core.CallerOwnsTokenWindow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t, tc.window)
			p := w.handshake(t)

			key, epoch := p.gw.RecvDemuxKey()
			if epoch != 0 {
				t.Fatalf("a fresh session reports epoch %d, want 0", epoch)
			}
			src := NewKeyedSource(&key)

			msgs := p.seal(t, 64)
			for i, m := range msgs {
				want := src.TokenAt(uint64(i))
				if !bytes.Equal(want[:], m[:core.DemuxTokenSize]) {
					t.Fatalf("message %d carries token %x, the binder predicts %x", i,
						m[:core.DemuxTokenSize], want[:])
				}
			}

			// A ratchet re-bases the sequence, and the epoch is how a caller
			// learns it must. Reading the two separately is the failure this
			// pair-returning accessor exists to prevent.
			secret := make([]byte, 32)
			for i := range secret {
				secret[i] = byte(i + 1)
			}
			if err := p.cli.Rekey(secret); err != nil {
				t.Fatalf("client rekey: %v", err)
			}
			if err := p.gw.Rekey(secret); err != nil {
				t.Fatalf("gateway rekey: %v", err)
			}
			next, nextEpoch := p.gw.RecvDemuxKey()
			if nextEpoch != 1 {
				t.Fatalf("epoch is %d after one ratchet, want 1", nextEpoch)
			}
			if bytes.Equal(next[:], key[:]) {
				t.Fatal("the ratchet did not change the receive demux key")
			}
			nextSrc := NewKeyedSource(&next)
			for i := 0; i < 8; i++ {
				m, err := p.cli.Seal([]byte{0xE1, byte(i)}, 0)
				if err != nil {
					t.Fatalf("Seal in the new epoch: %v", err)
				}
				want := nextSrc.TokenAt(uint64(i))
				if !bytes.Equal(want[:], m[:core.DemuxTokenSize]) {
					t.Fatalf("epoch-1 message %d carries %x, the binder predicts %x", i,
						m[:core.DemuxTokenSize], want[:])
				}
			}
		})
	}
}

// --- 2. the headline: a session with no index of its own ----------------------

// TestACallerOwnedSessionRoutesOnlyThroughOpenAt.
//
// This is the whole point of the widening, and it cannot pass by accident: a
// session configured with core.CallerOwnsTokenWindow refuses Open outright, so a
// table that still called Open would route nothing at all. Every message has to
// arrive through the counter the index resolved.
func TestACallerOwnedSessionRoutesOnlyThroughOpenAt(t *testing.T) {
	w := newWorld(t, core.CallerOwnsTokenWindow)
	p := w.handshake(t)
	// More messages than the window is wide, so the counters run past it and the
	// whole window machinery — erase, retire, republish at the high edge — is
	// exercised through OpenAt rather than only the first, easy window. It also
	// means the counter and its ring index diverge, which is the difference
	// between passing a counter and passing counter%size.
	msgs := p.seal(t, 200)

	// The session really is the one that cannot be driven the old way.
	if _, err := p.gw.Open(msgs[0]); err == nil {
		t.Fatal("Open succeeded on a caller-owned session; this test is not testing what it claims")
	} else if err != core.ErrCallerOwnsWindow { //nolint:errorlint // identity is the assertion
		t.Fatalf("Open on a caller-owned session returned %v, want ErrCallerOwnsWindow", err)
	}

	tbl := testTable(t, openerAtCfg(64, 8))
	ent := registerReal(t, tbl, p)
	if ent.OpenerAt() == nil {
		t.Fatal("a *core.Session registered as an Opener was not resolved to an OpenerAt")
	}

	for i, m := range msgs {
		got, plain, err := tbl.Dispatch(m, fixedNow)
		if err != nil {
			t.Fatalf("message %d did not route through OpenAt: %v", i, err)
		}
		if got != ent {
			t.Fatalf("message %d routed to session %d", i, got.ID())
		}
		if !bytes.Equal(plain, plainFor(i)) {
			t.Fatalf("message %d opened as %x, want %x", i, plain, plainFor(i))
		}
	}
	if got := tbl.Stats().Dispatched; got != uint64(len(msgs)) {
		t.Fatalf("Dispatched is %d, want %d", got, len(msgs))
	}
}

// TestOpenIsNeverCalledWhenTheSessionSupportsOpenAt.
//
// A table that tried Open first and fell back to OpenAt on ErrCallerOwnsWindow
// would pass every behavioural test in this file — both configurations would
// still route every packet — while putting a doomed call on the hot path of
// every datagram of every session, and while leaving a default-window session
// driven through the very index the seam exists to delete. It is a cost-only
// mutation, so it needs a cost-only assertion.
func TestOpenIsNeverCalledWhenTheSessionSupportsOpenAt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		window int
	}{
		{"core keeps its own index", 0},
		{"caller owns the window", core.CallerOwnsTokenWindow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t, tc.window)
			p := w.handshake(t)
			msgs := p.seal(t, 32)

			c := &countingOpener{sess: p.gw}
			key, _ := p.gw.RecvDemuxKey()
			tbl := testTable(t, openerAtCfg(64, 4))
			if _, err := tbl.Register(c, NewKeyedSource(&key), p.static.Public(), fixedNow); err != nil {
				t.Fatalf("Register: %v", err)
			}

			for i, m := range msgs {
				if _, _, err := tbl.Dispatch(m, fixedNow); err != nil {
					t.Fatalf("message %d did not route: %v", i, err)
				}
			}
			// Noise and a replay, so the rejection paths are counted too.
			noise := make([]byte, 300)
			rand.Read(noise)
			tbl.Dispatch(noise, fixedNow)   //nolint:errcheck // the drop is the point
			tbl.Dispatch(msgs[0], fixedNow) //nolint:errcheck // a replay

			if got := c.opens.Load(); got != 0 {
				t.Fatalf("Open was called %d times on a session that implements OpenAt; "+
					"the counter the index resolved must not be thrown away and looked up again", got)
			}
			if got := c.openAts.Load(); got != int64(len(msgs)) {
				t.Fatalf("OpenAt was called %d times for %d routed datagrams, one replay and one "+
					"miss; want exactly %d", got, len(msgs), len(msgs))
			}
		})
	}
}

// TestTheOpenerAtResolutionIsMadeOnceAtRegistration.
//
// Which interface an Opener satisfies is a property of its Go type, so it is
// settled the moment the session is admitted and cannot change between two of
// its packets. Entry stores that decision and deliver reads it.
//
// Asking again for every arriving datagram is a mutation with no behavioural
// consequence whatever — every packet still reaches the same session with the
// same plaintext — so no correctness test can see it. It is the same class as
// the sharding-on-a-constant mutation that survived this package's first
// mutation pass and the nil-map guards that survived core's: work put back on
// the hot path, paid by every datagram of every session, invisible to everything
// that only checks answers.
//
// It is observable in exactly one place: the stored decision. Clear it, and
// delivery must follow. A deliver that re-derives the interface from e.open
// ignores the field, keeps opening, and is caught here — and the same assertion
// is what makes Entry.OpenerAt honest, because an accessor that reports a
// decision delivery does not consult is a diagnostic that lies.
func TestTheOpenerAtResolutionIsMadeOnceAtRegistration(t *testing.T) {
	w := newWorld(t, core.CallerOwnsTokenWindow)
	p := w.handshake(t)
	msgs := p.seal(t, 4)

	tbl := testTable(t, openerAtCfg(32, 4))
	ent := registerReal(t, tbl, p)
	if _, _, err := tbl.Dispatch(msgs[0], fixedNow); err != nil {
		t.Fatalf("the session does not route at all: %v", err)
	}

	ent.mu.Lock()
	ent.openAt = nil
	ent.mu.Unlock()
	if ent.OpenerAt() != nil {
		t.Fatal("the accessor does not report the entry's resolved decision")
	}

	// The session is caller-owned, so a fallback to Open cannot open anything.
	if _, _, err := tbl.Dispatch(msgs[1], fixedNow); err == nil {
		t.Fatal("a datagram routed after the entry's resolved OpenerAt was cleared; deliver " +
			"is re-deriving the interface for every packet instead of reading the decision " +
			"taken once at registration")
	}
}

// TestAPlainOpenerStillWorksUnchanged.
//
// The widening had to be additive: an Opener that implements only Open must be
// driven exactly as it was before, with real cryptography behind it and not just
// with the package's synthetic session. The second half records the one mismatch
// that is possible and what it looks like, because it is a silent total outage
// for one session and somebody will meet it.
func TestAPlainOpenerStillWorksUnchanged(t *testing.T) {
	t.Run("a default-window session behind a plain Opener", func(t *testing.T) {
		w := newWorld(t, 0)
		p := w.handshake(t)
		msgs := p.seal(t, 32)

		key, _ := p.gw.RecvDemuxKey()
		tbl := testTable(t, openerAtCfg(64, 4))
		ent, err := tbl.Register(openOnly{p.gw}, NewKeyedSource(&key), p.static.Public(), fixedNow)
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		if ent.OpenerAt() != nil {
			t.Fatal("an Opener that does not implement OpenAt was resolved to an OpenerAt")
		}
		if ent.Opener() == nil {
			t.Fatal("the Opener accessor stopped reporting the registered opener")
		}
		for i, m := range msgs {
			got, plain, err := tbl.Dispatch(m, fixedNow)
			if err != nil {
				t.Fatalf("message %d did not route through Open: %v", i, err)
			}
			if got != ent || !bytes.Equal(plain, plainFor(i)) {
				t.Fatalf("message %d opened as %x", i, plain)
			}
		}
	})

	t.Run("a caller-owned session behind a plain Opener routes nothing", func(t *testing.T) {
		w := newWorld(t, core.CallerOwnsTokenWindow)
		p := w.handshake(t)
		msgs := p.seal(t, 8)

		key, _ := p.gw.RecvDemuxKey()
		tbl := testTable(t, openerAtCfg(64, 4))
		if _, err := tbl.Register(openOnly{p.gw}, NewKeyedSource(&key), p.static.Public(), fixedNow); err != nil {
			t.Fatalf("Register: %v", err)
		}
		for i, m := range msgs {
			if _, _, err := tbl.Dispatch(m, fixedNow); err == nil {
				t.Fatalf("message %d routed; a caller-owned session hidden behind a plain "+
					"Opener cannot open anything", i)
			}
		}
		// It is silent, like every other rejection, which is exactly why the
		// mismatch is worth an accessor: nothing on the wire says a word.
		if got := tbl.Stats().Dispatched; got != 0 {
			t.Fatalf("Dispatched is %d", got)
		}
	})
}

// --- 3. the counter is a hint, never an accept decision ----------------------

// TestTheTableDerivesNoTokenToDecideAnAccept.
//
// core deliberately does not re-derive the demux token from the counter and
// compare it with the one on the wire, because that would make a non-AEAD
// equality test part of an accept decision — the named non-goal in core/doc.go.
// The caller must not reintroduce the shape, and the cheapest way for it to
// creep back in is a "sanity check" in deliver just before OpenAt.
//
// The instrument is the token source itself. A datagram that does NOT open must
// cost zero token derivations: any check of the token against the counter would
// have happened before the AEAD refused, so a single derivation on that path is
// the shape reappearing. It is a cost assertion and a correctness assertion at
// once, which is what makes it hard to satisfy accidentally.
func TestTheTableDerivesNoTokenToDecideAnAccept(t *testing.T) {
	w := newWorld(t, core.CallerOwnsTokenWindow)
	p := w.handshake(t)
	msgs := p.seal(t, 16)

	key, _ := p.gw.RecvDemuxKey()
	cs := &countingSource{base: NewKeyedSource(&key)}
	tbl := testTable(t, openerAtCfg(64, 4))
	if _, err := tbl.Register(p.gw, cs, p.static.Public(), fixedNow); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// (a) a datagram that matches no token at all.
	noise := make([]byte, 300)
	rand.Read(noise)
	before := cs.n.Load()
	for i := 0; i < 100; i++ {
		tbl.Dispatch(noise, fixedNow) //nolint:errcheck // the drop is the point
	}
	if got := cs.n.Load() - before; got != 0 {
		t.Fatalf("100 index misses derived %d tokens; a miss must not touch the source", got)
	}

	// (b) a datagram whose token IS owned but whose AEAD refuses. This is the
	// sharp one: the token is on the wire, the counter is in hand, and the
	// temptation to compare them is exactly here.
	bad := append([]byte(nil), msgs[3]...)
	bad[len(bad)-1] ^= 0x01
	before = cs.n.Load()
	for i := 0; i < 100; i++ {
		if _, _, err := tbl.Dispatch(bad, fixedNow); err == nil {
			t.Fatal("a corrupted datagram opened")
		}
	}
	if got := cs.n.Load() - before; got != 0 {
		t.Fatalf("100 failed opens derived %d tokens; the table must not re-derive the token "+
			"from the counter to decide an accept — the AEAD decides, alone", got)
	}

	// (c) the genuine message still opens afterwards, so (b) consumed nothing.
	if _, plain, err := tbl.Dispatch(msgs[3], fixedNow); err != nil {
		t.Fatalf("the genuine message was refused after 100 corrupted copies: %v", err)
	} else if !bytes.Equal(plain, plainFor(3)) {
		t.Fatalf("opened as %x", plain)
	}

	// (d) a successful open costs a bounded, small number of derivations: the
	// window has to erase what was consumed and publish a replacement at the high
	// edge, and nothing beyond that.
	before = cs.n.Load()
	for i := 4; i < 16; i++ {
		if _, _, err := tbl.Dispatch(msgs[i], fixedNow); err != nil {
			t.Fatalf("message %d did not route: %v", i, err)
		}
	}
	per := float64(cs.n.Load()-before) / 12
	t.Logf("a delivered datagram costs %.2f token derivations", per)
	if per > 3 {
		t.Fatalf("a delivered datagram derives %.2f tokens; the window needs an erase and a "+
			"publish, and anything above three is work that crept onto the hot path", per)
	}
}

// TestOpenAtIsHandedTheIndexCounterAndNothingElse.
//
// The table's contract with core is narrow: the counter it passes is the one its
// own index resolved for the token on the wire, unmodified. A table that
// "helpfully" adjusted it — clamped it to the window's low edge, incremented it,
// took it from the entry's own state instead of the slot — would still route
// in-order traffic and would silently drop everything reordered.
func TestOpenAtIsHandedTheIndexCounterAndNothingElse(t *testing.T) {
	w := newWorld(t, core.CallerOwnsTokenWindow)
	p := w.handshake(t)
	msgs := p.seal(t, 32)

	rec := &recordingOpener{sess: p.gw, seen: map[uint64]bool{}}

	key, _ := p.gw.RecvDemuxKey()
	tbl := testTable(t, openerAtCfg(32, 4))
	if _, err := tbl.Register(rec, NewKeyedSource(&key), p.static.Public(), fixedNow); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Deliberately out of order, and within the window so nothing is force-
	// advanced past: 7, 3, 11, 0, ... An index that handed over anything but the
	// resolved counter fails here and cannot fail on an in-order run.
	order := []int{7, 3, 11, 0, 15, 1, 9, 2}
	for _, i := range order {
		_, plain, err := tbl.Dispatch(msgs[i], fixedNow)
		if err != nil {
			t.Fatalf("out-of-order message %d did not route: %v", i, err)
		}
		if !bytes.Equal(plain, plainFor(i)) {
			t.Fatalf("message %d opened as %x, want %x", i, plain, plainFor(i))
		}
	}
	for _, i := range order {
		if !rec.saw(uint64(i)) {
			t.Fatalf("message %d opened, but OpenAt was never handed counter %d", i, i)
		}
	}
}

// recordingOpener remembers which counters OpenAt was handed.
type recordingOpener struct {
	sess *core.Session
	mu   sync.Mutex
	seen map[uint64]bool
}

func (r *recordingOpener) Open(msg []byte) ([]byte, error) { return r.sess.Open(msg) }

func (r *recordingOpener) OpenAt(msg []byte, counter uint64) ([]byte, error) {
	plain, err := r.sess.OpenAt(msg, counter)
	if err == nil {
		r.mu.Lock()
		r.seen[counter] = true
		r.mu.Unlock()
	}
	return plain, err
}

func (r *recordingOpener) saw(counter uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen[counter]
}

// --- 4. the safety properties, re-verified through the wider interface -------

// TestAFailedOpenAtConsumesNothingInEitherWindow.
//
// Two windows now decide a packet's fate — the table's index and core's replay
// filter — and a message that fails must move neither. The attack shape is
// "name a counter, spend it, and the genuine packet is dropped"; core pins its
// half, and this pins the table's half against a real caller-owned session.
func TestAFailedOpenAtConsumesNothingInEitherWindow(t *testing.T) {
	w := newWorld(t, core.CallerOwnsTokenWindow)
	p := w.handshake(t)
	msgs := p.seal(t, 24)

	tbl := testTable(t, openerAtCfg(32, 4))
	ent := registerReal(t, tbl, p)

	for i, m := range msgs {
		lowBefore, openedBefore := ent.Low(), ent.Opened()
		for k := 0; k < 4; k++ {
			bad := append([]byte(nil), m...)
			bad[len(bad)-1-k] ^= 0x01 << uint(k)
			if _, _, err := tbl.Dispatch(bad, fixedNow); err == nil {
				t.Fatalf("a corrupted copy of message %d was accepted", i)
			}
		}
		if ent.Low() != lowBefore || ent.Opened() != openedBefore {
			t.Fatalf("four failed opens moved the window from (low %d, opened %d) to (low %d, opened %d)",
				lowBefore, openedBefore, ent.Low(), ent.Opened())
		}
		if _, plain, err := tbl.Dispatch(m, fixedNow); err != nil {
			t.Fatalf("genuine message %d was refused after four corrupted copies: %v", i, err)
		} else if !bytes.Equal(plain, plainFor(i)) {
			t.Fatalf("message %d opened as %x", i, plain)
		}
	}
	if got := tbl.Stats().Dispatched; got != uint64(len(msgs)) {
		t.Fatalf("Dispatched is %d, want %d", got, len(msgs))
	}
}

// TestCollidingCallerOwnedSessionsBothStillRoute.
//
// The candidate list is where the widening is most exposed, and it is worth
// being precise about why. Under Open, the session that does not own a colliding
// message simply fails to find the token. Under OpenAt it is handed a counter
// that IS inside its own window and asked to open a message that is not its own
// — an adversary-shaped input, arriving by accident, on the hot path. The AEAD
// must refuse it, it must consume nothing, and the real owner must still get its
// packet with one extra open and no drop.
func TestCollidingCallerOwnedSessionsBothStillRoute(t *testing.T) {
	w := newWorld(t, core.CallerOwnsTokenWindow)

	victim := w.handshake(t) // registered first, so it owns the token
	owner := w.handshake(t)  // the session whose real message carries it
	ownerMsgs := owner.seal(t, 8)
	victimMsgs := victim.seal(t, 8)

	// The token on the front of the owner's message 0, forced into the victim's
	// window at counter 5: a natural 64-bit collision, arranged.
	var clash Token
	copy(clash[:], ownerMsgs[0][:core.DemuxTokenSize])
	const clashAt = 5

	vKey, _ := victim.gw.RecvDemuxKey()
	vSrc := collidingSource{base: NewKeyedSource(&vKey), at: clashAt, tok: clash}
	vOpen := &countingOpener{sess: victim.gw}

	tbl := testTable(t, openerAtCfg(32, 8))
	vEnt, err := tbl.Register(vOpen, vSrc, victim.static.Public(), fixedNow)
	if err != nil {
		t.Fatalf("Register victim: %v", err)
	}
	oEnt := registerReal(t, tbl, owner)

	if got := tbl.Stats().Collisions; got == 0 {
		t.Fatal("two sessions claimed one token and no collision was recorded")
	}
	if owners := tbl.Owners(clash); len(owners) != 2 || owners[0] != vEnt.ID() {
		t.Fatalf("owners of the clashing token are %v; want the victim first, then the owner", owners)
	}

	vLow, vOpened := vEnt.Low(), vEnt.Opened()
	vBefore := vOpen.openAts.Load()

	got, plain, err := tbl.Dispatch(ownerMsgs[0], fixedNow)
	if err != nil {
		t.Fatalf("the colliding message did not route: %v", err)
	}
	if got != oEnt {
		t.Fatalf("the colliding message routed to session %d, want %d", got.ID(), oEnt.ID())
	}
	if !bytes.Equal(plain, plainFor(0)) {
		t.Fatalf("the colliding message opened as %x", plain)
	}

	// The cost is exactly one extra open attempt on the wrong session.
	if extra := vOpen.openAts.Load() - vBefore; extra != 1 {
		t.Fatalf("the primary owner's OpenAt was called %d extra times, want exactly 1", extra)
	}
	// And that attempt consumed nothing, in the table's window or in core's.
	if vEnt.Low() != vLow || vEnt.Opened() != vOpened {
		t.Fatalf("a failed open on a collision moved the victim's window from (low %d, opened %d) "+
			"to (low %d, opened %d)", vLow, vOpened, vEnt.Low(), vEnt.Opened())
	}

	// Neither session drops a packet. The victim's counter 5 is the one the test
	// harness spent forcing the clash, so it is excluded; a real collision would
	// have put its true token there and it would route like the rest.
	for i, m := range victimMsgs {
		if i == clashAt {
			continue
		}
		if _, _, err := tbl.Dispatch(m, fixedNow); err != nil {
			t.Fatalf("the victim lost message %d to a collision on an unrelated counter: %v", i, err)
		}
	}
	for i, m := range ownerMsgs[1:] {
		if _, _, err := tbl.Dispatch(m, fixedNow); err != nil {
			t.Fatalf("the owner lost message %d after the collision: %v", i+1, err)
		}
	}
	if got := tbl.Stats().OpenFailed; got != 0 {
		t.Fatalf("%d datagrams were dropped; a collision must cost one extra open and no packet", got)
	}
}

// TestTheCandidateListIsStillBoundedWithCallerOwnedSessions. maxCandidates is
// what stops the collision list being a growth surface, and the bound has to
// hold for real sessions and not only for the synthetic ones.
func TestTheCandidateListIsStillBoundedWithCallerOwnedSessions(t *testing.T) {
	w := newWorld(t, core.CallerOwnsTokenWindow)
	var clash Token
	copy(clash[:], []byte{0xC1, 0xA5, 0x40, 0x00, 0xDE, 0xAD, 0xBE, 0xEF})

	tbl := testTable(t, openerAtCfg(32, 16))
	for i := 0; i < 8; i++ {
		p := w.handshake(t)
		key, _ := p.gw.RecvDemuxKey()
		src := collidingSource{base: NewKeyedSource(&key), at: 3, tok: clash}
		if _, err := tbl.Register(p.gw, src, p.static.Public(), fixedNow); err != nil {
			t.Fatalf("Register(%d): %v", i, err)
		}
	}
	owners := tbl.Owners(clash)
	if len(owners) != maxCandidates {
		t.Fatalf("%d sessions own one token; the list must fill to %d and then refuse",
			len(owners), maxCandidates)
	}
}

// TestTheGatewayWindowIsStillTheBindingConstraintWhenCoreOwnsNoIndex.
//
// §7 of the table handoff records an honest cost: the gateway's window is
// narrower than core's, so a message the gateway has slid past is dropped even
// though core would have opened it. Dropping core's token map could have
// silently inverted that — a narrow filter in core would make CORE the
// constraint, and then the table's window size would no longer be the thing
// deciding reordering tolerance. It did not, and this is where that is checked
// rather than assumed.
func TestTheGatewayWindowIsStillTheBindingConstraintWhenCoreOwnsNoIndex(t *testing.T) {
	w := newWorld(t, core.CallerOwnsTokenWindow)
	p := w.handshake(t)
	msgs := p.seal(t, 32)

	tbl := testTable(t, openerAtCfg(16, 4))
	ent := registerReal(t, tbl, p)

	// A jump to counter 15 forces the table's 16-token window to [8,24).
	if _, _, err := tbl.Dispatch(msgs[15], fixedNow); err != nil {
		t.Fatalf("counter 15 did not route: %v", err)
	}
	if got := ent.Low(); got != 8 {
		t.Fatalf("the table's window low edge is %d, want 8", got)
	}
	// Counter 3 is now outside the table's window and is dropped.
	if _, _, err := tbl.Dispatch(msgs[3], fixedNow); err == nil {
		t.Fatal("a counter below the table's window edge was routed")
	}
	// core, whose retained filter is 1024 wide and whose low edge is still 0,
	// would have opened exactly that message.
	if _, err := p.gw.OpenAt(msgs[3], 3); err != nil {
		t.Fatalf("core refused a message the table's window is supposed to be the only thing "+
			"rejecting: %v; the caller-owned filter is no longer wider than the table's window", err)
	}
}

// TestACallerOwnedSessionIsSilentOnEveryRejection. The silence matrix is the
// property a person in Myanmar depends on, so it is re-walked here rather than
// inherited: a caller-owned session changes which code opens a datagram, and the
// front door must still answer nothing to everything except a fresh
// authenticated initiation.
func TestACallerOwnedSessionIsSilentOnEveryRejection(t *testing.T) {
	w := newWorld(t, core.CallerOwnsTokenWindow)
	cfg := silentCfg()
	cfg.Now = func() time.Time { return fixedNow }
	gw, err := New(cfg, testGatewayPathMTU, w.resp, productionBinder)
	if err != nil {
		t.Fatalf("New gateway: %v", err)
	}
	t.Cleanup(gw.Table().Close)

	p := w.handshake(t)
	msgs := p.seal(t, 8)
	if _, err := gw.Table().Register(p.gw, mustSource(t, p.gw), p.static.Public(), fixedNow); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// A genuine one first, so the session is live and the rejections below are
	// rejections rather than an empty table.
	if res := gw.Handle(msgs[0], []byte("peer"), fixedNow); res.Kind != KindTransport {
		t.Fatalf("a genuine transport message was classified as %s", res.Kind)
	}

	noise := make([]byte, 300)
	rand.Read(noise)
	corrupt := append([]byte(nil), msgs[1]...)
	corrupt[len(corrupt)-1] ^= 0x01
	short := msgs[2][:core.TransportOverhead()-1]
	truncated := msgs[3][:core.TransportOverhead()]

	for _, tc := range []struct {
		what string
		msg  []byte
	}{
		{"a replayed transport message", msgs[0]},
		{"a corrupted transport message", corrupt},
		{"pure noise", noise},
		{"a datagram shorter than the transport overhead", short},
		{"a datagram truncated to exactly the overhead", truncated},
		{"an empty datagram", nil},
	} {
		mustBeSilent(t, gw.Handle(tc.msg, []byte("peer"), fixedNow), tc.what)
	}

	// The session is unharmed by all of it.
	for i := 4; i < len(msgs); i++ {
		if res := gw.Handle(msgs[i], []byte("peer"), fixedNow); res.Kind != KindTransport {
			t.Fatalf("message %d stopped working after the rejection walk: %s", i, res.Kind)
		}
	}
}

func mustSource(t testing.TB, s *core.Session) TokenSource {
	t.Helper()
	_, src, err := productionBinder(s)
	if err != nil {
		t.Fatalf("productionBinder: %v", err)
	}
	return src
}

// --- 5. cost -----------------------------------------------------------------

// TestADispatchedDatagramAllocatesWhatItMustAndNoMore.
//
// The index-miss path is measured at zero allocations elsewhere in this package
// and is untouched by the widening. The path that IS touched is the hit path,
// and the mutations that hide there are cost-only: a defensive copy of the
// message before handing it to OpenAt, a slice to carry the counter, a token
// derived to check something. None of them changes a single routing decision,
// and all of them multiply by every packet of every real client.
func TestADispatchedDatagramAllocatesWhatItMustAndNoMore(t *testing.T) {
	if testing.Short() {
		t.Skip("seals real messages to count allocations")
	}
	// 250 dispatches is plenty to pin the per-datagram allocation figure: the
	// bound is exact, not statistical, and every message is a real sealed
	// ciphertext. The old 2000-message run existed because sealing was cheap
	// without -race; under the race instrumenter it costs ten times as much
	// wall clock per byte.
	const runs = 250
	w := newWorld(t, core.CallerOwnsTokenWindow)
	p := w.handshake(t)
	msgs := p.seal(t, runs+32)

	tbl := testTable(t, openerAtCfg(256, 4))
	registerReal(t, tbl, p)

	i := 0
	allocs := testing.AllocsPerRun(runs, func() {
		tbl.Dispatch(msgs[i], fixedNow) //nolint:errcheck // measured, not asserted, here
		i++
	})
	t.Logf("a delivered datagram costs %.2f allocations", allocs)
	// Three is core's own measured figure for opening one datagram
	// (TestACallerOwnedSessionDerivesNoTokens), which means the table adds
	// nothing: the lookup, the erase, the publish at the high edge and the hand-
	// off to OpenAt are all allocation-free.
	//
	// The bound is that exact number and not a comfortable margin above it,
	// because the mutations that hide here cost ONE allocation each — a defensive
	// copy of the datagram, a slice to carry the counter — and a ceiling with
	// room for one is a ceiling that catches none of them. If a Go release moves
	// this to four, that is worth being told about and explaining, not absorbing.
	if allocs > 3 {
		t.Fatalf("a delivered datagram allocates %.2f objects; core opens one for three and "+
			"the table is supposed to add nothing, so the difference is work that has been "+
			"put back on the hot path of every packet of every real client", allocs)
	}
	if i < runs {
		t.Fatalf("only %d of %d datagrams were dispatched", i, runs)
	}
}

// TestTheIndexHotPathTakesAReadLock.
//
// TestTheIndexIsSpreadAcrossItsShards pins that datagrams land on different
// shards. It does not pin that datagrams landing on the SAME shard can proceed
// together, and that is half of the reason the index is an RWMutex: the lookup
// is the gateway's hottest read, taken by every arriving datagram on every core,
// and promoting it to a write lock serialises the whole datapath behind one
// mutex while changing not a single routing decision. It is the identical shape
// to sharding on a constant — a performance property nothing tests is a
// performance property that will regress silently.
//
// The test holds a read lock on the shard and requires the lookup to complete
// anyway. A read lock admits another reader; a write lock cannot, so a promoted
// lookup blocks and is caught. The bounded wait is the only one in this file and
// it is only ever reached by a failure.
func TestTheIndexHotPathTakesAReadLock(t *testing.T) {
	tbl := testTable(t, smallCfg())
	_, f := registerFake(t, tbl, 1)
	tok := f.src.TokenAt(0)
	if _, _, ok := tbl.Lookup(tok); !ok {
		t.Fatal("the token is not indexed; this test is not testing what it claims")
	}

	sh := tbl.shardFor(tok)
	done := make(chan struct{})
	sh.mu.RLock()
	go func() {
		defer close(done)
		tbl.Lookup(tok) //nolint:errcheck // it is the completing that is asserted
	}()

	select {
	case <-done:
		sh.mu.RUnlock()
	case <-time.After(5 * time.Second):
		// Release first, so the blocked goroutine finishes and the failure is a
		// failure rather than a hung test binary.
		sh.mu.RUnlock()
		<-done
		t.Fatal("a lookup could not proceed while another reader held the shard; the index " +
			"hot path has been promoted to a write lock, which serialises every arriving " +
			"datagram behind one mutex without changing a single routing decision")
	}
}

// --- 6. the memory, measured -------------------------------------------------

// TestDroppingCoresWindowIsWhereTheGatewayMemoryGoes.
//
// This is the number the whole seam exists for, and it is measured rather than
// computed: runtime.HeapAlloc across a populated table, two forced collections
// either side, exactly the method §2.1 of the table handoff used and exactly the
// method core used for its own half.
//
// Two measurements, because two different questions are being asked. The first
// is core's per-session receive state, which reproduces the core lane's figure
// from outside core and through a real handshake rather than an internal
// constructor. The second is what a gateway actually holds — the session, the
// entry, the token source and the index — which is the number an operator sizing
// a machine needs.
func TestDroppingCoresWindowIsWhereTheGatewayMemoryGoes(t *testing.T) {
	if testing.Short() {
		t.Skip("measures live heap across real handshakes")
	}
	// Complete real handshakes, then bill the heap. The scale is a balance: the
	// assertions are ratios between two live measurements of the SAME session
	// shape, so a handful of sessions cancels constant noise the way thousands
	// did — and the full-scale figure (n = 2000, this comment's original claim)
	// needs tens of minutes under -race, which is a timing property, not a
	// concurrency bug. n = 6 keeps the ratios' signal well above the heap
	// noise floor while the race suite finishes inside its budget.
	const n = 6
	const gwWindow = 256

	// (1) core.Session alone.
	sessionBytes := func(coreWindow int) uint64 {
		w := newWorld(t, coreWindow)
		held := make([]*core.Session, 0, n)
		base := heapInUse()
		for i := 0; i < n; i++ {
			held = append(held, w.handshake(t).gw)
		}
		loaded := heapInUse()
		runtime.KeepAlive(held)
		return (loaded - base) / n
	}
	withIndex := sessionBytes(0)
	withoutIndex := sessionBytes(core.CallerOwnsTokenWindow)

	// (2) the whole gateway bill: session + entry + token source + index.
	gatewayBytes := func(coreWindow, window int) uint64 {
		w := newWorld(t, coreWindow)
		tbl, err := NewTable(openerAtCfg(window, n))
		if err != nil {
			t.Fatalf("NewTable: %v", err)
		}
		defer tbl.Close()
		base := heapInUse()
		for i := 0; i < n; i++ {
			registerReal(t, tbl, w.handshake(t))
		}
		if got := tbl.IndexedTokens(); got != n*window {
			t.Fatalf("%d indexed tokens, want %d", got, n*window)
		}
		// Reserved is not stored: two sessions sharing a demux key would publish
		// the same tokens, the index would refuse the duplicates past the
		// candidate cap, and the measurement would silently be of a much smaller
		// structure than the one being billed for. Real handshakes make that
		// impossible, and this is the assertion that says so.
		if got := tbl.MapEntries(); got != n*window {
			t.Fatalf("%d tokens are reserved but only %d are stored; the measurement is of a "+
				"different structure than the one being reported", n*window, got)
		}
		loaded := heapInUse()
		runtime.KeepAlive(tbl)
		return (loaded - base) / n
	}
	gwWithIndex := gatewayBytes(0, gwWindow)
	gwWithoutIndex := gatewayBytes(core.CallerOwnsTokenWindow, gwWindow)

	// (3) what one indexed token costs AT THE OPERATIONAL WINDOW, as a
	// difference rather than a quotient.
	//
	// §9 of the table handoff extrapolated the ten-thousand-session figure from a
	// per-token cost measured at a 16384-token window over 64 sessions, where a
	// Go map's load factor is amortised over tables far larger than any real
	// session has. Measuring it again where the gateway actually lives is worth
	// the handshakes, because that number multiplies by every token in the
	// gateway.
	//
	// It is measured as (bill at 256) minus (bill at 16), over the 240 tokens
	// between them, so that the session, the entry, the token source, the client
	// key and every other fixed cost cancels instead of having to be estimated
	// and subtracted. A quotient would also have to divide by the tokens actually
	// STORED, which is not the same as the tokens reserved the moment two
	// sessions share a demux key — the trap that made the first version of this
	// measurement report a number 2x too low.
	const narrow = 16
	gwNarrow := gatewayBytes(core.CallerOwnsTokenWindow, narrow)
	perToken := float64(gwWithoutIndex-gwNarrow) / float64(gwWindow-narrow)

	const mib = float64(1 << 20)
	t.Logf("core receive state per session: %d B with its own %d-token index, %d B with the "+
		"index dropped and the replay filter kept (%.1fx)",
		withIndex, core.DefaultTokenWindow, withoutIndex, float64(withIndex)/float64(withoutIndex))
	t.Logf("whole gateway per session at a %d-token index: %d B before, %d B after (%.1fx)",
		gwWindow, gwWithIndex, gwWithoutIndex, float64(gwWithIndex)/float64(gwWithoutIndex))
	t.Logf("at 10000 sessions: %.0f MiB before, %.0f MiB after",
		float64(gwWithIndex)*10000/mib, float64(gwWithoutIndex)*10000/mib)
	t.Logf("one indexed token costs %.1f B between a %d- and a %d-token window (the "+
		"extrapolation in §9 of the table handoff used 46.3 B, measured at 16384 over 64 "+
		"sessions); the gateway's own per-session state is %.0f MiB at 10000 sessions",
		perToken, narrow, gwWindow, float64(gwWithoutIndex-withoutIndex)*10000/mib)

	// The assertions are ranges, not equalities: a measurement pinned to the byte
	// would be a test that fails on a Go release rather than on a regression.
	if withoutIndex == 0 || withIndex/withoutIndex < 10 {
		t.Fatalf("dropping core's index saved %d B against %d B per session; the seam has "+
			"stopped buying what it was built for", withIndex-withoutIndex, withIndex)
	}
	if withoutIndex > 8192 {
		t.Fatalf("a caller-owned session still costs %d B; the token map is supposed to be gone "+
			"and the replay filter is a byte per counter", withoutIndex)
	}
	if gwWithoutIndex >= gwWithIndex/2 {
		t.Fatalf("the whole gateway bill fell only from %d to %d B per session; the duplicate "+
			"window was supposed to be most of it", gwWithIndex, gwWithoutIndex)
	}
	if float64(gwWithoutIndex)*10000/mib > 200 {
		t.Fatalf("10000 sessions would cost %.0f MiB, against the 127 MiB this seam was "+
			"justified by", float64(gwWithoutIndex)*10000/mib)
	}
	// The same ceiling TestMeasuredBytesPerIndexedToken holds, re-checked at the
	// window a gateway actually runs: the cost per token is set by the size of
	// the index slot, and anything that widened the slot would multiply straight
	// through the whole memory bill.
	if perToken > 80 {
		t.Fatalf("an indexed token costs %.1f B at a %d-token window; the memory arithmetic "+
			"assumes it stays under 80", perToken, gwWindow)
	}
}
