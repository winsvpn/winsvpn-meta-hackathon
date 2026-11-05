package gateway

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// TestAnUnauthenticatedDatagramAllocatesNothing.
//
// This is requirement one, measured rather than asserted. A censor in Myanmar
// can generate arbitrary traffic at a gateway for free; if each datagram bought
// even one small allocation, the gateway's garbage collector would become the
// attack surface. The index-miss path must allocate zero bytes.
func TestAnUnauthenticatedDatagramAllocatesNothing(t *testing.T) {
	cfg := smallCfg()
	cfg.MaxSessions = 200
	tbl := testTable(t, cfg)
	for i := 0; i < 200; i++ {
		registerFake(t, tbl, i)
	}

	noise := make([]byte, 1200)
	rand.Read(noise)
	now := fixedNow

	if allocs := testing.AllocsPerRun(2000, func() {
		tbl.Dispatch(noise, now) //nolint:errcheck // the drop is the point
	}); allocs != 0 {
		t.Fatalf("an index miss allocated %.2f objects per datagram; it must allocate none", allocs)
	}

	// And the same is true through the front door, on the path a flood actually
	// takes once the admission budget is spent.
	cfg2 := smallCfg()
	cfg2.AdmissionRate = 1
	cfg2.AdmissionBurst = 1
	h := newRealHarness(t, cfg2)
	h.gw.Handle(noise, []byte("peer"), now) // spend the burst
	if allocs := testing.AllocsPerRun(2000, func() {
		h.gw.Handle(noise, []byte("peer"), now)
	}); allocs != 0 {
		t.Fatalf("a throttled datagram allocated %.2f objects; the flood path must allocate none", allocs)
	}
}

// TestAnUnauthenticatedFloodCreatesNoState.
//
// The classic mistake in flood defence is to allocate state per flooder. This
// walks enough distinct garbage datagrams from distinct sources past the
// gateway and demands that not one byte of per-peer or per-token state
// exists afterwards. The volume is intentionally modest: the assertion is
// existence-of-state, which a handful of datagrams crosses as well as a
// six-figure flood does, and the race instrumenter stretches every call.
// (The suite originally ran 200000 here; the count does not change what the
// test is checking, so under -race it was all wall clock and no signal.)
const floodVolume = 2000

func TestAnUnauthenticatedFloodCreatesNoState(t *testing.T) {
	if testing.Short() {
		t.Skip("flood volume")
	}
	cfg := smallCfg()
	cfg.allowUnmetered = true
	cfg.AdmissionRate = -1
	cfg.SourceRate = -1
	h := newRealHarness(t, cfg)
	c := h.newClient(t, 1, 4)

	before := h.gw.Table().Stats()
	guardCells := len(h.gw.guard.cells)

	msg := make([]byte, 300)
	src := make([]byte, 16)
	for i := 0; i < floodVolume; i++ {
		binary.BigEndian.PutUint64(msg, uint64(i)*0x9E3779B97F4A7C15)
		binary.BigEndian.PutUint64(msg[8:], uint64(i))
		binary.BigEndian.PutUint64(src, uint64(i))
		if res := h.gw.Handle(msg, src, h.clock()); res.Reply != nil || res.Kind != KindDropped {
			t.Fatalf("garbage datagram %d produced %s with a reply", i, res.Kind)
		}
	}

	after := h.gw.Table().Stats()
	if after.Sessions != before.Sessions {
		t.Fatalf("the flood created %d sessions", after.Sessions-before.Sessions)
	}
	if after.IndexedTokens != before.IndexedTokens {
		t.Fatalf("the flood moved the token bill from %d to %d", before.IndexedTokens, after.IndexedTokens)
	}
	if got := h.gw.Table().MapEntries(); got != before.IndexedTokens {
		t.Fatalf("the index holds %d tokens after the flood, want %d", got, before.IndexedTokens)
	}
	if len(h.gw.guard.cells) != guardCells {
		t.Fatalf("the per-source meter grew from %d cells to %d; it must be fixed size",
			guardCells, len(h.gw.guard.cells))
	}
	// The one session that existed before the flood still works.
	if res := h.gw.Handle(c.msgs[0], []byte("real"), h.clock()); res.Kind != KindTransport {
		t.Fatalf("the established session stopped working after the flood: %s", res.Kind)
	}
}

// TestEstablishedSessionsAreUnaffectedByAHandshakeFlood.
//
// This is the property that decides whether a flood is an inconvenience or an
// outage for the people using the tunnel. Established sessions dispatch through
// the token index, which is O(1) and unmetered; only the handshake path is
// metered. So a flood that completely exhausts the admission budget must not
// cost a connected user a single packet.
func TestEstablishedSessionsAreUnaffectedByAHandshakeFlood(t *testing.T) {
	cfg := silentCfg()
	cfg.AdmissionRate = 1
	cfg.AdmissionBurst = 1
	cfg.SourceRate = 1
	cfg.SourceBurst = 1
	h := newRealHarness(t, cfg)
	c := h.newClient(t, 1, 64)

	noise := make([]byte, 400)
	rand.Read(noise)
	for i := 0; i < 5000; i++ {
		binary.BigEndian.PutUint64(noise, uint64(i))
		h.gw.Handle(noise, []byte("flooder"), h.clock())
	}
	if h.gw.Stats().Throttled == 0 {
		t.Fatal("the flood never hit the budget; this test is not testing what it claims")
	}

	for i, m := range c.msgs {
		res := h.gw.Handle(m, []byte("real-peer"), h.clock())
		if res.Kind != KindTransport {
			t.Fatalf("message %d of an established session was dropped during a flood: %s", i, res.Kind)
		}
		if res.Entry != c.entry {
			t.Fatalf("message %d was routed to the wrong session", i)
		}
	}
}

// TestTheAdmissionMeterBoundsExpensiveWork.
//
// The expensive rejection path is the one that reaches core's admission check,
// which expands a keystream over the whole body and computes an HMAC. The meter
// is what converts an unbounded flood into a bounded CPU bill, and this measures
// the bound rather than trusting it.
func TestTheAdmissionMeterBoundsExpensiveWork(t *testing.T) {
	cfg := silentCfg()
	cfg.AdmissionRate = 100
	cfg.AdmissionBurst = 10
	cfg.SourceRate = -1 // isolate the gateway-wide budget
	h := newRealHarness(t, cfg)

	noise := make([]byte, 400)
	rand.Read(noise)

	// One second of wall clock, ten thousand datagrams. At 100/s with a burst
	// of 10, at most 110 may reach the expensive check.
	for i := 0; i < 10000; i++ {
		at := fixedNow.Add(time.Duration(i) * 100 * time.Microsecond)
		h.setNow(at)
		binary.BigEndian.PutUint64(noise, uint64(i))
		h.gw.Handle(noise, []byte("flooder"), at)
	}
	s := h.gw.Stats()
	if s.Unauthenticated > 111 {
		t.Fatalf("%d of 10000 flood datagrams reached the expensive admission check; "+
			"the budget allows at most 111", s.Unauthenticated)
	}
	if s.Unauthenticated < 50 {
		t.Fatalf("only %d datagrams reached admission; the meter is refusing work it should allow, "+
			"which would deny service to real clients", s.Unauthenticated)
	}
	if s.Throttled+s.Unauthenticated != 10000 {
		t.Fatalf("10000 datagrams were accounted for as %d throttled + %d unauthenticated",
			s.Throttled, s.Unauthenticated)
	}
}

// TestOneSourceCannotSpendTheWholeBudget.
//
// The gateway-wide budget alone would let a single loud source starve everyone
// else. The per-source cells stop that, and — this is the part that has to be
// right — they do it with fixed memory and a per-process random seed, so an
// attacker can neither exhaust the structure nor aim their collisions at a
// chosen victim.
func TestOneSourceCannotSpendTheWholeBudget(t *testing.T) {
	cfg := silentCfg()
	cfg.AdmissionRate = 100000
	cfg.AdmissionBurst = 100000
	cfg.SourceRate = 5
	cfg.SourceBurst = 5
	h := newRealHarness(t, cfg)

	noise := make([]byte, 400)
	rand.Read(noise)
	for i := 0; i < 500; i++ {
		binary.BigEndian.PutUint64(noise, uint64(i))
		h.gw.Handle(noise, []byte("the-loud-one"), h.clock())
	}
	loud := h.gw.Stats().Unauthenticated
	if loud > 5 {
		t.Fatalf("one source got %d admission checks from a 5-token cell", loud)
	}

	// A different source, at the same instant, is unaffected: it has its own
	// cell and the gateway-wide budget is untouched.
	before := h.gw.Stats().Unauthenticated
	h.gw.Handle(noise, []byte("someone-else"), h.clock())
	if h.gw.Stats().Unauthenticated == before {
		t.Fatal("a quiet source was throttled by a loud one's behaviour")
	}
	// A real client behind a different source still connects during the flood.
	if res := h.gw.Handle(h.initiation(t), []byte("a-real-client"), h.clock()); res.Kind != KindHandshake {
		t.Fatalf("a real client could not connect during a single-source flood: %s", res.Kind)
	}
}

// TestASourceFloodRefusedByItsCellLeavesTheGlobalBudget.
//
// The library twin of cmd/winn3-gateway's
// TestAdmissionMeterSourceFloodPreservesGlobalBudget (R1 astra-2, R22 Y1 F5).
// A datagram its own source cell refuses must not spend the gateway-wide token
// every other new client needs, or one source at line rate keeps the global
// budget drained through refusals that never reach the screen.
func TestASourceFloodRefusedByItsCellLeavesTheGlobalBudget(t *testing.T) {
	cfg := silentCfg()
	cfg.AdmissionRate = 1 // the clock is fixed, so no token is refilled
	cfg.AdmissionBurst = 20
	cfg.SourceRate = 1
	cfg.SourceBurst = 5
	h := newRealHarness(t, cfg)

	noise := make([]byte, 400)
	rand.Read(noise)
	for i := 0; i < 500; i++ {
		binary.BigEndian.PutUint64(noise, uint64(i))
		h.gw.Handle(noise, []byte("the-loud-one"), h.clock())
	}
	if got := h.gw.Stats().Unauthenticated; got != uint64(cfg.SourceBurst) {
		t.Fatalf("the loud source reached the screen %d times, want its cell's %d", got, cfg.SourceBurst)
	}
	if got, want := h.gw.global.toks, float64(cfg.AdmissionBurst-cfg.SourceBurst); got != want {
		t.Fatalf("datagrams refused by their own cell spent the global budget: %.0f tokens left, want %.0f",
			got, want)
	}
	// A source that hashes into the loud one's cell is refused by that cell
	// and spends nothing, so trying a few is enough to find another cell.
	for i := 0; i < 64; i++ {
		src := []byte("a-real-client-" + string(rune('A'+i)))
		if res := h.gw.Handle(h.initiation(t), src, h.clock()); res.Kind == KindHandshake {
			return
		}
	}
	t.Fatal("no real client was admitted after one source's refused flood")
}

// TestPrecomputationIsProportionalToUseNotToClaims.
//
// Requirement two, at gateway scale. Ten thousand sessions that completed a
// handshake and then went quiet hold ten thousand INITIAL windows — an eighth
// of what they would hold if a claimed session bought a full one. The full
// window is only ever reached by a session that has authenticated a full
// window's worth of packets.
func TestPrecomputationIsProportionalToUseNotToClaims(t *testing.T) {
	cfg := Config{
		InitialWindow:        32,
		MaxWindow:            256,
		MaxSessions:          10000,
		MaxSessionsPerClient: 10000,
		Now:                  func() time.Time { return fixedNow },
	}
	// The assertions are proportional, not absolute — each silent session must
	// reserve exactly one initial window (32 tokens), which holds at any session
	// count. 1000 sessions (32k publishes) is well past the noise floor while
	// the race-instrumented suite stays inside its budget; the original 10000
	// was a wall-clock liability, not a correctness threshold.
	const sessions = 1000
	tbl := testTable(t, cfg)

	for i := 0; i < sessions; i++ {
		f, src := newFake(i)
		if _, err := tbl.Register(f, src, clientKey(i%2500), fixedNow); err != nil {
			t.Fatalf("Register(%d): %v", i, err)
		}
	}
	got := tbl.IndexedTokens()
	if got != sessions*32 {
		t.Fatalf("%d silent sessions reserved %d tokens, want %d", sessions, got, sessions*32)
	}
	const full = sessions * 256
	if got >= full {
		t.Fatalf("silent sessions cost %d tokens, as much as %d fully grown ones", got, full)
	}
	if ratio := float64(full) / float64(got); ratio != 8 {
		t.Fatalf("the claimed-to-used memory ratio is %.2f, want 8", ratio)
	}
}

// BenchmarkDispatchMiss is the cost of a datagram a censor sends.
func BenchmarkDispatchMiss(b *testing.B) {
	b.StopTimer()
	cfg := Config{InitialWindow: 256, MaxWindow: 256, MaxSessions: 5000, MaxSessionsPerClient: 5000}
	tbl, err := NewTable(cfg)
	if err != nil {
		b.Fatal(err)
	}
	// Close is deferred AFTER StopTimer so that retiring 1.28M tokens is not
	// counted as the cost of the datagrams. It is not a detail: it is what was
	// making this benchmark report ten allocations for a path that has none.
	defer tbl.Close()
	defer b.StopTimer()
	for i := 0; i < 5000; i++ {
		f, src := newFake(i)
		if _, err := tbl.Register(f, src, clientKey(i), fixedNow); err != nil {
			b.Fatal(err)
		}
	}
	noise := make([]byte, 1200)
	rand.Read(noise)
	b.ReportAllocs()
	b.ResetTimer()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		tbl.Dispatch(noise, fixedNow) //nolint:errcheck
	}
}

// BenchmarkDispatchHit is the cost of a datagram from a real client.
func BenchmarkDispatchHit(b *testing.B) {
	b.StopTimer()
	cfg := Config{InitialWindow: 256, MaxWindow: 256, MaxSessions: 5000, MaxSessionsPerClient: 5000}
	tbl, err := NewTable(cfg)
	if err != nil {
		b.Fatal(err)
	}
	defer tbl.Close()
	defer b.StopTimer()
	var f *fakeSession
	for i := 0; i < 5000; i++ {
		ff, src := newFake(i)
		if _, err := tbl.Register(ff, src, clientKey(i), fixedNow); err != nil {
			b.Fatal(err)
		}
		if i == 2500 {
			f = ff
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		tbl.Dispatch(f.message(uint64(i)), fixedNow) //nolint:errcheck
	}
}

// --- the admission meter's own configuration ---------------------------------

// mustResponder builds the minimum core responder New needs, so that a
// configuration can be pushed through the real constructor rather than through a
// harness that fails the test on any error.
func mustResponder(t *testing.T) *core.Responder {
	t.Helper()
	static, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatalf("static key: %v", err)
	}
	admission := make([]byte, core.KeySize)
	for i := range admission {
		admission[i] = byte(0xC0 + i)
	}
	resp, err := core.NewResponder(core.Config{
		Gateway: core.GatewayParams{
			AdmissionKeys: [][]byte{admission},
			GatewayID:     []byte("winn3-gateway-rate-check"),
			TagSize:       core.DefaultTagSize,
		},
		Now: func() time.Time { return fixedNow },
	}, static, func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	return resp
}

func nopBinder() Binder {
	return func(*core.Session) (Opener, TokenSource, error) { return nil, nil, nil }
}

// TestANegativeWorkBudgetIsRefused closes the hole the zero-value idiom left
// open.
//
// rateOf reads a negative rate as "unmetered", which is only ever right in a
// test: it disables the meter outright, with no error and no counter. Every
// field that feeds it must refuse a negative value on any path that did not
// deliberately opt in, and the refusal must name the field so an operator can
// find it.
func TestANegativeWorkBudgetIsRefused(t *testing.T) {
	for _, field := range []struct {
		name string
		set  func(*Config)
	}{
		{"AdmissionRate", func(c *Config) { c.AdmissionRate = -1 }},
		{"AdmissionBurst", func(c *Config) { c.AdmissionBurst = -1 }},
		{"SourceRate", func(c *Config) { c.SourceRate = -1 }},
		{"SourceBurst", func(c *Config) { c.SourceBurst = -1 }},
	} {
		t.Run(field.name, func(t *testing.T) {
			cfg := smallCfg()
			field.set(&cfg)
			g, err := New(cfg, testGatewayPathMTU, mustResponder(t), nopBinder())
			if err == nil {
				t.Cleanup(g.Table().Close)
				t.Fatalf("a %s of -1 was accepted; the admission DoS meter is silently disabled", field.name)
			}
			if !errors.Is(err, ErrConfig) {
				t.Errorf("refusing %s gave %v, want an ErrConfig", field.name, err)
			}
			if !strings.Contains(err.Error(), field.name) {
				t.Errorf("the refusal for %s does not name the field, so an operator cannot find it: %v", field.name, err)
			}
		})
	}
}

// TestADeserialisedNegativeRateIsRefused states the threat exactly.
//
// The dangerous value does not arrive as a Go literal written by someone who
// read the doc comment; it arrives in a config file or a control-plane payload.
// The opt-in that keeps the test escape hatch alive is an unexported field, so a
// reflective decoder cannot reach it at any depth, and a deserialised -1 must
// therefore fail closed rather than turn the gateway's DoS meter off.
func TestADeserialisedNegativeRateIsRefused(t *testing.T) {
	const doc = `{"AdmissionRate":-1,"MaxSessions":64,"InitialWindow":16,"MaxWindow":64,"MinWindow":16}`

	var cfg Config
	if err := json.Unmarshal([]byte(doc), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Guard the test itself: if the decoder silently ignored the field there
	// would be nothing here to measure and this would pass while broken.
	if cfg.AdmissionRate != -1 {
		t.Fatalf("the decoder set AdmissionRate to %d, not -1; this test is measuring nothing", cfg.AdmissionRate)
	}

	g, err := New(cfg, testGatewayPathMTU, mustResponder(t), nopBinder())
	if err == nil {
		t.Cleanup(g.Table().Close)
		t.Fatal("a deserialised AdmissionRate of -1 was accepted; the gateway-wide DoS meter is silently off")
	}
	if !errors.Is(err, ErrConfig) {
		t.Errorf("refusal is %v, want an ErrConfig", err)
	}
}

// TestZeroRatesStillTakeTheDefault guards the over-correction.
//
// Zero is the forgiving half of the idiom and the half every hand-written and
// deserialised config actually relies on. Refusing negatives must not turn an
// omitted rate into an error or, worse, into an unmetered zero.
func TestZeroRatesStillTakeTheDefault(t *testing.T) {
	cfg := smallCfg() // names no rate at all
	g, err := New(cfg, testGatewayPathMTU, mustResponder(t), nopBinder())
	if err != nil {
		t.Fatalf("a config that names no rates was refused: %v", err)
	}
	t.Cleanup(g.Table().Close)

	if got, want := g.global.rate, float64(DefaultAdmissionRate); got != want {
		t.Errorf("gateway-wide rate is %v, want the %v default", got, want)
	}
	if got, want := g.global.burst, float64(DefaultAdmissionBurst); got != want {
		t.Errorf("gateway-wide burst is %v, want the %v default", got, want)
	}
	if g.global.rate <= 0 {
		t.Error("the gateway-wide meter is unmetered after an omitted rate; that is the bug this guards")
	}
}

// TestADeserialisedZeroCostConfigIsNotAdmittedUnmetered pins the zero half of
// the deserialised threat that TestADeserialisedNegativeRateIsRefused covers.
//
// A control-plane payload that names every cost field zero is a "free gateway"
// request — the operator's work budgets wiped to nothing. Zero is the forgiving
// half of rateOf's idiom (it means "use the default"), so such a config is
// admitted, but it MUST be admitted at the non-zero defaults, never as an
// unmetered zero. This is the regression guard for the invariant that a decoded
// "no cost" config cannot actually become a no-cost gateway: if any default
// ever drifted to zero, or the decode path silently zeroed a single meter, this
// goes red. It is deliberately the mirror of the negative test so the pair
// refuses both failure modes rather than just one.
func TestADeserialisedZeroCostConfigIsNotAdmittedUnmetered(t *testing.T) {
	const doc = `{"AdmissionRate":0,"AdmissionBurst":0,"SourceRate":0,"SourceBurst":0,"SourceCells":0,"MaxSessions":64,"InitialWindow":16,"MaxWindow":64,"MinWindow":16}`

	var cfg Config
	if err := json.Unmarshal([]byte(doc), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Guard the test itself: if the decoder did not land on zero there is
	// nothing here to measure and this would pass while broken.
	if cfg.AdmissionRate != 0 || cfg.SourceBurst != 0 {
		t.Fatalf("the decoder did not deliver a zero-cost config (AdmissionRate=%d SourceBurst=%d); measuring nothing",
			cfg.AdmissionRate, cfg.SourceBurst)
	}

	g, err := New(cfg, testGatewayPathMTU, mustResponder(t), nopBinder())
	if err != nil {
		t.Fatalf("a deserialised zero-cost config was refused; zero means the defaults, not an error: %v", err)
	}
	t.Cleanup(g.Table().Close)

	// Every meter must have resolved to its (non-zero) default. A single zero
	// here is a silently-unmetered gateway built from a "no cost" payload.
	if got, want := g.global.rate, float64(DefaultAdmissionRate); got != want {
		t.Errorf("gateway-wide rate is %v, want the %v default", got, want)
	}
	if got, want := g.global.burst, float64(DefaultAdmissionBurst); got != want {
		t.Errorf("gateway-wide burst is %v, want the %v default", got, want)
	}
	if g.global.rate <= 0 || g.global.burst <= 0 {
		t.Error("the gateway-wide meter is unmetered after a zero-cost config; the no-cost gateway was admitted")
	}
	// DefaultSourceCells is a power of two (4096), which is exactly what the
	// source guard rounds to, so equality is the right assertion here.
	if got, want := len(g.guard.cells), DefaultSourceCells; got != want {
		t.Errorf("per-source cells are %d, want the %d default", got, want)
	}
	if got, want := g.guard.cells[0].rate, float64(DefaultSourceRate); got != want {
		t.Errorf("per-source rate is %v, want the %v default", got, want)
	}
	if got, want := g.guard.cells[0].burst, float64(DefaultSourceBurst); got != want {
		t.Errorf("per-source burst is %v, want the %v default", got, want)
	}
	if g.guard.cells[0].rate <= 0 || g.guard.cells[0].burst <= 0 {
		t.Error("the per-source meter is unmetered after a zero-cost config; the no-cost gateway was admitted")
	}
}

// TestTheUnmeteredEscapeHatchStillWorks keeps the in-test mechanism honest.
//
// Several tests in this package legitimately turn one meter off to isolate
// another, per field. Closing the production hole must not remove that, or the
// fix would have been bought by deleting coverage elsewhere.
func TestTheUnmeteredEscapeHatchStillWorks(t *testing.T) {
	cfg := smallCfg()
	cfg.allowUnmetered = true
	cfg.AdmissionRate = -1
	// SourceRate deliberately left at zero: the hatch must stay per field.
	g, err := New(cfg, testGatewayPathMTU, mustResponder(t), nopBinder())
	if err != nil {
		t.Fatalf("an opted-in negative rate was refused: %v", err)
	}
	t.Cleanup(g.Table().Close)

	if g.global.rate != 0 {
		t.Errorf("gateway-wide rate is %v, want 0 (unmetered)", g.global.rate)
	}
	if len(g.guard.cells) == 0 {
		t.Fatal("the per-source guard has no cells")
	}
	if got, want := g.guard.cells[0].rate, float64(DefaultSourceRate); got != want {
		t.Errorf("per-source rate is %v, want the %v default; the hatch is not per field", got, want)
	}
}

// TestTheGuardRefusesAClientThatExceedsItsBudgets is the per-client budget,
// tested through the front door rather than only at the table.
//
// The per-subscriber cap (MaxSessionsPerClient) and the memory ceiling
// (TokenBudget) are both enforced inside Table.Register, and both are reached
// from Handle through the same silence an admission flood gets. What the
// existing table-level tests do not pin is that a real handshake which has
// already passed admission is turned away the instant it would put one
// subscriber over its cap or spend the last token — the guard is enforced on
// the datapath, before any response is built, and it is measured in g.refused,
// not in a single rejected Register call.
func TestTheGuardRefusesAClientThatExceedsItsBudgets(t *testing.T) {
	// sendInitiation drives a fresh handshake from the given static key through
	// the front door and returns the decision. Reusing one static key across
	// calls is what lets one identity try to exceed his cap.
	sendInitiation := func(h *realHarness, cs *core.StaticKey) Result {
		t.Helper()
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
		return h.gw.Handle(msg, []byte("peer"), h.clock())
	}

	t.Run("maxPerClient", func(t *testing.T) {
		cfg := silentCfg()
		cfg.MaxSessionsPerClient = 2
		cfg.MaxSessions = 32
		cfg.DisableEvictOnAdmit = true // isolate the per-client cap from table eviction
		h := newRealHarness(t, cfg)

		cs, err := core.GenerateStaticKey()
		if err != nil {
			t.Fatalf("static key: %v", err)
		}
		for i := 0; i < 2; i++ {
			if res := sendInitiation(h, cs); res.Kind != KindHandshake || res.Reply == nil {
				t.Fatalf("in-budget handshake %d was refused: %s", i, res.Kind)
			}
		}
		// The third session for the same subscriber is past the cap: it must be
		// answered with exactly nothing, and counted as refused.
		if res := sendInitiation(h, cs); res.Kind != KindDropped || res.Reply != nil {
			t.Fatalf("an over-cap handshake was answered: %s", res.Kind)
		}
		if got := h.gw.Stats().Refused; got != 1 {
			t.Fatalf("Refused is %d, want 1", got)
		}
		if got := h.gw.Stats().Handshakes; got != 2 {
			t.Fatalf("Handshakes is %d, want 2", got)
		}
		// A different subscriber is unaffected: the cap is per client, not
		// global, and the refusal did not take the gateway down.
		if res := sendInitiation(h, h.otherStatic(t)); res.Kind != KindHandshake {
			t.Fatalf("an unaffected client was refused after one client hit its cap: %s", res.Kind)
		}
	})

	t.Run("tokenBudget", func(t *testing.T) {
		cfg := silentCfg()
		cfg.TokenBudget = 32 // two 16-token initial windows, no room for a third
		cfg.MaxSessionsPerClient = 8
		cfg.MaxSessions = 32
		cfg.DisableEvictOnAdmit = true // do not let eviction refund the budget
		h := newRealHarness(t, cfg)

		for i := 0; i < 2; i++ {
			if res := sendInitiation(h, h.otherStatic(t)); res.Kind != KindHandshake {
				t.Fatalf("in-budget handshake %d was refused: %s", i, res.Kind)
			}
		}
		// A third distinct client, with the budget fully reserved, must get the
		// identical silence and be counted as refused.
		if res := sendInitiation(h, h.otherStatic(t)); res.Kind != KindDropped || res.Reply != nil {
			t.Fatalf("a handshake past the token budget was answered: %s", res.Kind)
		}
		if got := h.gw.Stats().Refused; got != 1 {
			t.Fatalf("Refused is %d, want 1", got)
		}
		if got := h.gw.Table().IndexedTokens(); got != 32 {
			t.Fatalf("indexed tokens are %d after the budget filled, want 32", got)
		}
	})
}

// otherStatic mints a fresh client identity for a handshake.
func (h *realHarness) otherStatic(t *testing.T) *core.StaticKey {
	t.Helper()
	cs, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatalf("static key: %v", err)
	}
	return cs
}
