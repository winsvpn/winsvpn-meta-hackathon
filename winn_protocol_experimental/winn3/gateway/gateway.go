package gateway

import (
	"errors"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
)

// Binder turns the session core hands back at the end of a handshake into the
// two things the table needs: something that can open a datagram, and the
// sequence of demux tokens that datagram will be labelled with.
//
// It is a parameter rather than a fixed implementation so that a caller can
// supply the sequence from somewhere other than the key — a test harvesting
// tokens off real ciphertexts, a replay of a capture — but in production it is
// one line, and this is it:
//
//	func(s *core.Session) (Opener, TokenSource, error) {
//	        k, _ := s.RecvDemuxKey()
//	        return s, NewKeyedSource(&k), nil
//	}
//
// Two things about that line are load-bearing.
//
// The key must never leave the process. It decrypts nothing, but it names every
// datagram of that session's receive direction for the life of the epoch, so a
// copy in a log line, a metrics label or a crash dump is a session-linking
// oracle. NewKeyedSource copies it, so the local k may be zeroed.
//
// The epoch RecvDemuxKey returns alongside the key is not decoration. A ratchet
// installs a fresh demux key and restarts the counter at zero, so a token
// sequence means nothing outside the epoch it was derived in: read the pair in
// one call, and when the epoch changes, build a fresh KeyedSource and hand it to
// Entry.Rekeyed. Reading the key separately from its epoch number is how an
// index gets rebuilt under the wrong label and drops every subsequent packet in
// silence.
//
// The session core hands back satisfies OpenerAt as well as Opener, so the
// table drives it through the counter the index already resolved. That is what
// makes core.CallerOwnsTokenWindow available to whoever builds the
// core.Config — see the package doc.
type Binder func(sess *core.Session) (Opener, TokenSource, error)

// Kind says what a datagram turned out to be.
type Kind uint8

const (
	// KindDropped is every rejection: noise, a probe, a replay, a corrupted
	// packet, a message for an evicted session, a throttled admission attempt,
	// and a handshake refused for capacity. They are one Kind because they are
	// one thing on the wire — nothing.
	KindDropped Kind = iota
	// KindTransport is a datagram that opened under a live session.
	KindTransport
	// KindHandshake is a fresh initiation that authenticated. It is the only
	// Kind that ever carries a Reply.
	KindHandshake
)

func (k Kind) String() string {
	switch k {
	case KindTransport:
		return "transport"
	case KindHandshake:
		return "handshake"
	default:
		return "dropped"
	}
}

// Result is what one arriving datagram produced.
//
// Reply is the ONLY field that becomes bytes on the wire, and it is non-nil
// only for KindHandshake. Every rejection leaves it nil. That is not a
// convention, it is the protocol: a gateway that answers an unauthenticated
// datagram is a gateway that a censor can find by sending it one.
type Result struct {
	Kind      Kind
	Entry     *Entry
	Plaintext []byte
	Reply     []byte
}

// Gateway is the front door: one carrier hands it datagrams, it decides what
// each one is, and it dispatches or stays silent.
type Gateway struct {
	cfg    Config
	tbl    *Table
	resp   *core.Responder
	bind   Binder
	global *bucket
	guard  *sourceGuard

	handshakes atomic.Uint64
	throttled  atomic.Uint64
	refused    atomic.Uint64
	unauth     atomic.Uint64

	// respPadTo is the padding target for the response. PadAuto by default,
	// because a fixed response length is a fixed field by another name.
	respPadTo int

	// notice is this responder's path-MTU claim, encoded once in New and then
	// only read. New refuses every path MTU that cannot be stated — a
	// non-positive value (the old "make no claim" escape hatch) and any value
	// beyond the notice's 16-bit ceiling, where EncodePathMTUNotice would return
	// nil — so this is NEVER nil: every gateway this package can construct
	// states a number, and a gateway that made no claim — the fail-open half of
	// silent-refusal #3 — is unconstructable rather than merely documented
	// against.
	//
	// One slice shared by every concurrent Handle is safe because nothing
	// downstream writes to it: core.encodeHandshakePayload copies the payload
	// into a fresh buffer. Encoding it per handshake would be seven bytes of
	// garbage per admission on the one path a flood can reach.
	notice []byte
}

// New builds a gateway front door around a core responder and a table.
//
// pathMTU is REQUIRED. It is the planning path MTU this gateway sized itself
// at and the number it states to every client in the handshake response
// payload — see Config's comment for why it is an argument rather than a field.
// New refuses any value that cannot be stated: a non-positive one (no claim),
// one inside the dead zone, or one beyond the notice's 16-bit ceiling
// (checkPathMTU), so a gateway built here always emits a notice. Whoever wires
// this package into a datapath must pass the number their Sizing was built at;
// there is no no-claim configuration to fall back on.
func New(cfg Config, pathMTU int, resp *core.Responder, bind Binder) (*Gateway, error) {
	if resp == nil {
		return nil, errWrap(ErrConfig, "gateway needs a *core.Responder")
	}
	if bind == nil {
		return nil, errWrap(ErrConfig, "gateway needs a Binder; see the doc comment for the one-line production form")
	}
	if err := cfg.checkRates(); err != nil {
		return nil, err
	}
	if err := checkPathMTU(pathMTU); err != nil {
		return nil, err
	}
	tbl, err := NewTable(cfg)
	if err != nil {
		return nil, err
	}
	g := &Gateway{
		cfg:       cfg,
		tbl:       tbl,
		resp:      resp,
		bind:      bind,
		global:    newBucket(rateOf(cfg.AdmissionRate, DefaultAdmissionRate), rateOf(cfg.AdmissionBurst, DefaultAdmissionBurst)),
		guard:     newSourceGuard(cellsOf(cfg.SourceCells), rateOf(cfg.SourceRate, DefaultSourceRate), rateOf(cfg.SourceBurst, DefaultSourceBurst)),
		respPadTo: core.PadAuto,
		notice:    session.EncodePathMTUNotice(pathMTU),
	}
	return g, nil
}

// checkRates refuses a negative work budget on any path that did not opt in.
//
// Zero still means "use the default", which is the forgiving half of the idiom
// and the one a hand-written or deserialised config actually relies on. Negative
// is the dangerous half: it disables a meter outright, with no error and no
// counter, so it is gated behind an unexported field a decoder cannot reach.
func (c Config) checkRates() error {
	if c.allowUnmetered {
		return nil
	}
	switch {
	case c.AdmissionRate < 0:
		return negativeRate("AdmissionRate", c.AdmissionRate)
	case c.AdmissionBurst < 0:
		return negativeRate("AdmissionBurst", c.AdmissionBurst)
	case c.SourceRate < 0:
		return negativeRate("SourceRate", c.SourceRate)
	case c.SourceBurst < 0:
		return negativeRate("SourceBurst", c.SourceBurst)
	}
	return nil
}

func negativeRate(name string, v int) error {
	return errWrap(ErrConfig,
		"%s is %d; a negative work budget disables the admission DoS meter entirely, "+
			"which is only ever right in a test. Use 0 for the default", name, v)
}

func rateOf(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0 // unmetered; reachable only via Config.allowUnmetered
	default:
		return v
	}
}

func cellsOf(v int) int {
	if v <= 0 {
		return DefaultSourceCells
	}
	return v
}

// Table exposes the session table, for eviction sweeps and operator counters.
func (g *Gateway) Table() *Table { return g.tbl }

// Handle is the whole datapath decision for one arriving datagram.
//
// src is the carrier's opaque name for the peer — an address, a connection id,
// whatever the carrier has. It is used for one thing only: metering the
// expensive admission path per source. It is never stored, never indexed, and
// never compared to anything, so nothing here is a stable per-peer correlator.
//
// The order of the two paths is chosen for cost, and it is the reason an
// unauthenticated datagram is nearly free:
//
//  1. Too short to be a transport message at all: dropped on a length compare.
//  2. Token index: one shard-local map lookup. A hit costs one AEAD open; a
//     miss costs nothing and falls through.
//  3. Admission: metered, then core's tag check. This is the only path that can
//     ever produce a byte, and only for an initiation that authenticated.
//
// A datagram whose token hits but whose AEAD fails does not fall through to
// step 3. Dispatch returns ErrSession for that case and ErrNoRoute only for a
// true miss (or a datagram too short to be transport). Handle follows that
// distinction: only ErrNoRoute continues to admission.
//
// Copying the 8-byte demux token off the wire is enough to HIT the index. The
// session key is needed only to OPEN. A stream of forgeries aimed at a token
// observed on a small transport datagram (anything ≤ MaxHandshakeMessage, which
// keepalives and short frames are) would therefore spend the admission budget
// if this path fell through — and would not need the session key to do it.
// The 2⁻⁶⁴ coincidence in which a genuine initiation shares a live token is
// dropped here; that client retransmits with a fresh ephemeral.
func (g *Gateway) Handle(msg []byte, src []byte, now time.Time) Result {
	if len(msg) < core.TransportOverhead() {
		g.tbl.stats.tooShort.Add(1)
		return Result{}
	}

	ent, plain, err := g.tbl.Dispatch(msg, now)
	if err == nil {
		return Result{Kind: KindTransport, Entry: ent, Plaintext: plain}
	}
	// Token hit, AEAD refused (ErrSession today). Not an initiation. Falling
	// through would let a token copied off the wire spend the admission meter.
	if !errors.Is(err, ErrNoRoute) {
		return Result{}
	}

	// The handshake path. Length first: it is a comparison, and it removes
	// every datagram that could not be an initiation whatever its contents,
	// before any budget is spent or any keystream is expanded.
	if len(msg) > core.MaxHandshakeMessage {
		return Result{}
	}
	// The source cell is checked first, so datagrams already refused by their
	// own cell cannot spend the global budget every other new client needs
	// (cmd/winn3-gateway's admissionMeter.allow, R1 astra-2).
	if !g.guard.allow(src, now) || !g.global.allow(now) {
		g.throttled.Add(1)
		return Result{}
	}

	h, err := g.resp.ReadInitiation(msg)
	if err != nil {
		// Noise, a probe, a replay of a captured initiation, a wrong key, a
		// clock outside the skew window, an unauthorised client static key.
		// core returns different errors for an operator's benefit; the peer
		// gets the identical nothing for all of them.
		g.unauth.Add(1)
		return Result{}
	}
	defer h.Wipe()

	// Capacity is checked before the response is built, so that a full gateway
	// spends nothing further and — much more importantly — emits nothing. A
	// refused client sees exactly what a probe sees.
	if !g.tbl.admissible(h.InitiatorStatic()) {
		g.refused.Add(1)
		return Result{}
	}

	// The responder's half of silent-refusal instance #3, CLOSED HERE ON
	// 2026-08-10.
	//
	// Until this line took g.notice it passed nil, and the comment that stood
	// here said so: "a client talking to THIS responder gets no path-MTU check
	// at all". That was the fail-OPEN half of the only instance in that family
	// that does not merely look like a censor — a mismatched session
	// establishes, carries small packets, and black-holes every full-size one
	// while both ends go on reporting the gate carrying.
	//
	// The check is the INITIATOR's (session.Driver.refusePathMTUMismatch); all
	// this end owes it is a truthful statement of the path MTU this gateway
	// planned at. The number New was constructed with is that number and nothing
	// here derives it: a gateway that sized itself at one number and claimed
	// another would manufacture the refusal rather than report it.
	//
	// g.notice is never nil: New refuses every path MTU that cannot be stated —
	// a non-positive one and anything beyond the notice's 16-bit ceiling — so a
	// no-claim gateway cannot be constructed in this package at all. The client side's tolerance
	// of a peer that predates the notice is pinned by
	// TestAnOldPeerThatSendsNoHandshakePayloadStillConnects in the driver
	// package. Raising a client default without this line emitting first is what
	// re-creates the defect, so this is the gate the 1450 move is hung on — not
	// the other way round.
	reply, sess, err := h.WriteResponse(g.notice, g.respPadTo)
	if err != nil {
		g.refused.Add(1)
		return Result{}
	}
	open, srcTok, err := g.bind(sess)
	if err != nil || open == nil || srcTok == nil {
		sess.Wipe()
		g.refused.Add(1)
		return Result{}
	}
	entry, err := g.tbl.Register(open, srcTok, h.InitiatorStatic(), now)
	if err != nil {
		sess.Wipe()
		if w, ok := srcTok.(interface{ Wipe() }); ok {
			w.Wipe()
		}
		g.refused.Add(1)
		return Result{}
	}
	g.handshakes.Add(1)
	return Result{Kind: KindHandshake, Entry: entry, Reply: reply}
}

// GatewayStats is the front door's own accounting.
type GatewayStats struct {
	Handshakes uint64
	// Unauthenticated counts datagrams that reached core's admission check and
	// failed it. Throttled counts datagrams that did not reach it because the
	// work budget was spent. Refused counts authenticated initiations the table
	// had no room for.
	Unauthenticated uint64
	Throttled       uint64
	Refused         uint64
}

// Stats snapshots the front door.
func (g *Gateway) Stats() GatewayStats {
	return GatewayStats{
		Handshakes:      g.handshakes.Load(),
		Unauthenticated: g.unauth.Load(),
		Throttled:       g.throttled.Load(),
		Refused:         g.refused.Load(),
	}
}
