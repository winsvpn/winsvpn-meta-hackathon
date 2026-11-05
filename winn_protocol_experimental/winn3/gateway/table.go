package gateway

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

func errWrap(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", sentinel, fmt.Sprintf(format, args...))
}

// SessionID names a live session inside this gateway. It never appears on the
// wire; it exists so that an operator, a log line and an eviction policy have
// something to talk about. The protocol's whole point is that the wire has no
// such thing.
type SessionID uint64

// maxCandidates bounds how many sessions may share one 64-bit token.
//
// Two live tokens colliding is a birthday event across the whole gateway, not
// across one session, so it is rarer than it is frequent but it is not
// negligible at scale — the handoff document works the numbers. Carrying a
// bounded candidate list turns the collision from “one session drops one
// packet” into “one extra AEAD attempt, then the right session opens it”. The
// bound matters because it is what stops the list being a growth surface; three
// live tokens colliding is a 128-bit birthday event and will not happen.
const maxCandidates = 4

// slot is one token's owner. It is 16 bytes, and it is multiplied by every
// token in the gateway, so its size is a design constraint rather than an
// implementation detail.
type slot struct {
	ent     *Entry
	counter uint64
}

// shard is one stripe of the global token index.
//
// Sharding on the leading byte of the token is exactly uniform and costs no
// hashing, because a demux token is a PRF output. It also means a session's
// window is spread evenly across every shard, so no session can be starved by
// another's lock.
type shard struct {
	mu sync.RWMutex
	m  map[Token]slot
	// ov holds the second and subsequent owners of a colliding token. It is
	// empty in every run that does not deliberately force a collision, and the
	// hot path checks len(ov) — an O(1) map length — rather than looking in it.
	ov map[Token][]slot
}

// Table is the gateway session table: the structure that turns an eight-byte
// PRF output into the one session out of many that can open it.
//
// It is safe for concurrent use. Lock order is Entry.mu then shard.mu; a shard
// lock is never held while an Entry lock is taken, and never held across a call
// into an Opener.
type Table struct {
	cfg Config

	shardMask uint32
	shards    []shard

	mu       sync.RWMutex
	sessions map[SessionID]*Entry
	perStat  map[[core.KeySize]byte]int
	nextID   SessionID
	closed   bool

	liveTokens atomic.Int64
	budget     int64

	stats stats
}

type stats struct {
	dispatched atomic.Uint64
	missed     atomic.Uint64
	openFailed atomic.Uint64
	collisions atomic.Uint64
	grown      atomic.Uint64
	evicted    atomic.Uint64
	refused    atomic.Uint64
	tooShort   atomic.Uint64
	budgetHit  atomic.Uint64
}

// Stats is a snapshot for an operator. Every field is a count of a decision the
// table made, because a gateway whose degradation is invisible is a gateway
// whose degradation is a surprise.
type Stats struct {
	Sessions int
	// IndexedTokens is the reserved window capacity across all sessions, which
	// is the memory bill; TokenBudget is the ceiling it is measured against.
	IndexedTokens int
	TokenBudget   int

	// Dispatched counts datagrams that reached a session and opened.
	Dispatched uint64
	// Missed counts datagrams whose token matched no live entry: noise, probes,
	// replays of a consumed token, and messages for a session that has gone.
	// They are one number because they are one thing to the peer.
	Missed uint64
	// OpenFailed counts datagrams whose token matched but whose AEAD did not.
	OpenFailed uint64
	// Collisions counts insertions that found the token already owned.
	Collisions uint64
	// Grown counts window growths; Evicted counts sessions reclaimed; Refused
	// counts registrations turned away; TooShort counts datagrams rejected on
	// length before any lookup at all; BudgetHit counts growths declined
	// because the token budget was spent.
	Grown     uint64
	Evicted   uint64
	Refused   uint64
	TooShort  uint64
	BudgetHit uint64
}

// NewTable builds a table. It holds no socket, no timer and no goroutine.
func NewTable(cfg Config) (*Table, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	n := cfg.shards()
	t := &Table{
		cfg:       cfg,
		shardMask: uint32(n - 1),
		shards:    make([]shard, n),
		sessions:  make(map[SessionID]*Entry),
		perStat:   make(map[[core.KeySize]byte]int),
		budget:    int64(cfg.tokenBudget()),
	}
	for i := range t.shards {
		t.shards[i].m = make(map[Token]slot)
		t.shards[i].ov = make(map[Token][]slot)
	}
	return t, nil
}

func (t *Table) shardFor(tok Token) *shard {
	// A demux token is a PRF output, so its leading byte is uniform and needs no
	// further hashing. There is no algorithmic-complexity attack here for the
	// same reason there is none on the map itself: an attacker who cannot
	// compute tokens cannot steer them, and Go's map seed is per process.
	return &t.shards[uint32(tok[0])&t.shardMask]
}

// --- index primitives -------------------------------------------------------

// insert publishes one token. It reports whether the token was already owned.
func (t *Table) insert(tok Token, s slot) (collided bool) {
	sh := t.shardFor(tok)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, dup := sh.m[tok]; !dup {
		sh.m[tok] = s
		return false
	}
	ov := sh.ov[tok]
	if len(ov)+1 >= maxCandidates {
		// Refuse rather than grow. The session that loses the race simply
		// cannot receive that one counter: it drops one packet and its window
		// advances past it, which is the same cost the design already accepts
		// for a collision. Unbounded is the only outcome not on the table.
		return true
	}
	sh.ov[tok] = append(ov, s)
	return true
}

// erase withdraws one token belonging to a specific entry and counter.
func (t *Table) erase(tok Token, ent *Entry, counter uint64) {
	sh := t.shardFor(tok)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if s, ok := sh.m[tok]; ok && s.ent == ent && s.counter == counter {
		ov := sh.ov[tok]
		if len(ov) == 0 {
			delete(sh.m, tok)
			return
		}
		sh.m[tok] = ov[0]
		if len(ov) == 1 {
			delete(sh.ov, tok)
		} else {
			sh.ov[tok] = ov[1:]
		}
		return
	}
	ov := sh.ov[tok]
	for i, s := range ov {
		if s.ent == ent && s.counter == counter {
			ov = append(ov[:i:i], ov[i+1:]...)
			if len(ov) == 0 {
				delete(sh.ov, tok)
			} else {
				sh.ov[tok] = ov
			}
			return
		}
	}
}

// primary reads a token's first owner, and reports whether this shard is
// carrying any collisions at all.
//
// It returns values rather than a slice on purpose: this is the hot path, and a
// slice here would put an allocation on every arriving datagram, including
// every datagram a censor sends. `hasOverflow` is an O(1) map length, and it is
// false in every run that does not deliberately force a collision, so the
// collision handling costs a predictable branch and nothing else.
func (t *Table) primary(tok Token) (s slot, found, hasOverflow bool) {
	sh := t.shardFor(tok)
	sh.mu.RLock()
	s, found = sh.m[tok]
	hasOverflow = len(sh.ov) != 0
	sh.mu.RUnlock()
	return s, found, hasOverflow
}

// overflowFor copies out the second and subsequent owners of a colliding token.
// The copy is deliberate: the shard lock must not be held while an Opener runs.
func (t *Table) overflowFor(tok Token, buf []slot) []slot {
	sh := t.shardFor(tok)
	sh.mu.RLock()
	buf = append(buf[:0], sh.ov[tok]...)
	sh.mu.RUnlock()
	return buf
}

// --- registration -----------------------------------------------------------

// Register admits a completed session.
//
// It is called only after a handshake has authenticated, which is what makes
// the precomputation that follows safe to pay for: the peer held the gateway's
// admission key and completed an X25519 exchange under a client static key the
// gateway's AcceptFunc approved. Even then the session gets only
// InitialWindow tokens; the rest is earned by opening messages.
//
// clientStatic is the peer's static public key, used solely for the
// per-subscriber session cap. It never reaches the index and never reaches the
// wire.
func (t *Table) Register(open Opener, src TokenSource, clientStatic []byte, now time.Time) (*Entry, error) {
	if open == nil || src == nil {
		return nil, errWrap(ErrConfig, "Register needs both an Opener and a TokenSource")
	}
	var ck [core.KeySize]byte
	copy(ck[:], clientStatic)

	initial := t.cfg.initialWindow()

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, ErrClosed
	}
	if t.perStat[ck] >= t.cfg.maxPerClient() {
		t.mu.Unlock()
		t.stats.refused.Add(1)
		return nil, errWrap(ErrCapacity, "client already holds %d sessions", t.cfg.maxPerClient())
	}
	// evicted is the session admission displaced, if any. Its INDEX teardown is
	// deferred to after t.mu is dropped; its BUDGET is returned below, inline.
	var evicted *Entry
	if len(t.sessions) >= t.cfg.maxSessions() {
		victim := t.idlestLocked()
		if t.cfg.DisableEvictOnAdmit || victim == nil {
			t.mu.Unlock()
			t.stats.refused.Add(1)
			return nil, errWrap(ErrCapacity, "%d sessions is the ceiling", t.cfg.maxSessions())
		}
		t.removeLocked(victim)
		// The victim's tokens go back to the budget HERE, under the same t.mu
		// hold that removed it from t.sessions, and the reservation below is
		// taken before t.mu is released again.
		//
		// Both halves of that are load-bearing, and this function used to do
		// neither. It dropped t.mu between removeLocked and the victim's
		// release, so a concurrent Register saw a table with room in
		// t.sessions but a budget still charged for a session that was already
		// gone, and refused a client that should have been admitted. Closing
		// only that gap is not enough: if the lock is dropped between the
		// release and the reserve, another goroutine takes the slack this one
		// just created and THIS registration is the one spuriously refused.
		// Removal, release and reservation are therefore a single critical
		// section, and the observable state moves straight from "victim holds
		// the tokens" to "the new session does".
		//
		// What is NOT done here is the victim's window teardown — a full window
		// of TokenAt derivation plus a shard lock per token. That runs after
		// t.mu is dropped, because holding the table's global lock across it
		// would trade a correctness bug for a scalability one. The victim is
		// unreachable through t.sessions from this point, so nothing can
		// register it, evict it again, or hand it out.
		victim.releaseBudget()
		evicted = victim
	}
	if !t.reserve(int64(initial)) {
		t.mu.Unlock()
		if evicted != nil {
			evicted.retireAll()
			t.stats.evicted.Add(1)
		}
		t.stats.refused.Add(1)
		t.stats.budgetHit.Add(1)
		return nil, errWrap(ErrCapacity, "token budget %d is spent", t.cfg.tokenBudget())
	}
	t.nextID++
	ent := &Entry{
		id:     t.nextID,
		tbl:    t,
		client: ck,
		open:   open,
		src:    src,
		size:   initial,
	}
	// Recorded before the entry is reachable: from here on, whoever retires it
	// returns exactly what it took, whether that is this window or a grown one.
	ent.budgetHeld.Store(int64(initial))
	// Resolved once, here, and never again: see the field comment on Entry. An
	// Opener that also implements OpenerAt is driven through the counter the
	// index resolved, which is what lets its session drop the duplicate window
	// (core.CallerOwnsTokenWindow) and what makes that configuration safe to
	// choose — the table adapts to the session rather than the session having to
	// match a decision the table made.
	if oa, ok := open.(OpenerAt); ok {
		ent.openAt = oa
	}
	ent.consumed = make([]bool, initial)
	ent.lastSeen.Store(now.UnixNano())

	// The entry's own lock is taken BEFORE it becomes reachable, and held until
	// its window is published.
	//
	// Without that, an eviction sweep or a Close could find the entry in
	// t.sessions, retire it, and finish — all before this goroutine published a
	// single token. The publish would then insert a full window belonging to an
	// entry nobody holds a reference to and nothing will ever retire: the index
	// leaks one window per race, permanently, on the gateway's hottest
	// structure. The concurrency test found exactly that.
	ent.mu.Lock()
	t.sessions[ent.id] = ent
	t.perStat[ck]++
	t.mu.Unlock()

	if !ent.closed {
		ent.publish(0, initial)
	}
	ent.mu.Unlock()

	// The displaced session's index teardown, off the table lock and off the new
	// entry's lock. Two entry locks are never held at once, so two goroutines
	// evicting each other's victims cannot deadlock.
	if evicted != nil {
		evicted.retireAll()
		t.stats.evicted.Add(1)
	}
	return ent, nil
}

// reserve takes n tokens from the budget, or reports that it cannot.
func (t *Table) reserve(n int64) bool {
	for {
		cur := t.liveTokens.Load()
		if cur+n > t.budget {
			return false
		}
		if t.liveTokens.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

func (t *Table) release(n int64) { t.liveTokens.Add(-n) }

func (t *Table) idlestLocked() *Entry {
	var victim *Entry
	var oldest int64
	for _, e := range t.sessions {
		ls := e.lastSeen.Load()
		if victim == nil || ls < oldest {
			victim, oldest = e, ls
		}
	}
	return victim
}

func (t *Table) removeLocked(e *Entry) {
	if _, ok := t.sessions[e.id]; !ok {
		return
	}
	delete(t.sessions, e.id)
	if n := t.perStat[e.client]; n <= 1 {
		delete(t.perStat, e.client)
	} else {
		t.perStat[e.client] = n - 1
	}
}

// Remove withdraws a session and every token it owns.
func (t *Table) Remove(e *Entry) {
	if e == nil {
		return
	}
	t.mu.Lock()
	t.removeLocked(e)
	t.mu.Unlock()
	e.retireAll()
}

// EvictIdle reclaims every session that has not opened a message within
// IdleTimeout. It returns how many it took.
//
// It is a method rather than a goroutine because this package owns no timer:
// the caller decides when, and the tests therefore need no sleep.
func (t *Table) EvictIdle(now time.Time) int {
	cutoff := now.Add(-t.cfg.idleTimeout()).UnixNano()
	t.mu.Lock()
	var doomed []*Entry
	for _, e := range t.sessions {
		if e.lastSeen.Load() <= cutoff {
			doomed = append(doomed, e)
		}
	}
	for _, e := range doomed {
		t.removeLocked(e)
	}
	t.mu.Unlock()
	for _, e := range doomed {
		e.retireAll()
	}
	t.stats.evicted.Add(uint64(len(doomed)))
	return len(doomed)
}

// Close retires every session. The table refuses further registration
// afterwards and dispatch finds nothing, which is to say it is silent.
func (t *Table) Close() {
	t.mu.Lock()
	t.closed = true
	all := make([]*Entry, 0, len(t.sessions))
	for _, e := range t.sessions {
		all = append(all, e)
	}
	t.sessions = make(map[SessionID]*Entry)
	t.perStat = make(map[[core.KeySize]byte]int)
	t.mu.Unlock()
	for _, e := range all {
		e.retireAll()
	}
}

// --- dispatch ---------------------------------------------------------------

// Dispatch routes one arriving datagram to the session that can open it.
//
// This is the hot path, and its cost for a datagram nobody can authenticate is
// the point of the whole design: a length comparison, one shard-local map
// lookup, and a return. No allocation, no key material, no asymmetric
// operation, no per-source state, and — the part that matters to a person in
// Myanmar — no byte written back on any path.
//
// A miss is returned as ErrNoRoute whether the datagram was noise, a probe, a
// replay of a token this session already consumed, or a message for a session
// that has been evicted. Those are one thing to the peer, and Handle treats
// them as the only reason to try the handshake path.
//
// A token that matched a live entry whose AEAD then refused is ErrSession, not
// ErrNoRoute. Collapsing the two used to make Handle fall through to admission
// on every forged copy of a live-token datagram. The peer still sees silence
// either way; the operator and the admission meter must not.
func (t *Table) Dispatch(msg []byte, now time.Time) (*Entry, []byte, error) {
	if len(msg) < core.TransportOverhead() {
		t.stats.tooShort.Add(1)
		return nil, nil, ErrNoRoute
	}
	var tok Token
	copy(tok[:], msg[:core.DemuxTokenSize])

	s, found, hasOverflow := t.primary(tok)
	if !found {
		t.stats.missed.Add(1)
		return nil, nil, ErrNoRoute
	}
	if plain, ok := s.ent.deliver(msg, s.counter, now); ok {
		t.stats.dispatched.Add(1)
		return s.ent, plain, nil
	}
	if hasOverflow {
		// A 64-bit token owned by two live sessions at once. Rare enough to be
		// worked out arithmetically in the handoff document, frequent enough at
		// gateway scale to be worth handling rather than dropping: the AEAD
		// decides which owner it belongs to, at the cost of one extra open.
		var buf [maxCandidates]slot
		for _, c := range t.overflowFor(tok, buf[:0]) {
			if plain, ok := c.ent.deliver(msg, c.counter, now); ok {
				t.stats.dispatched.Add(1)
				return c.ent, plain, nil
			}
		}
	}
	t.stats.openFailed.Add(1)
	return nil, nil, ErrSession
}

// admissible is the cheap pre-check the front door makes before it builds a
// handshake response, so that a gateway with no room spends nothing further and
// — the part that matters — emits nothing. Register remains authoritative; this
// can be wrong by one under a race and that is harmless.
func (t *Table) admissible(clientStatic []byte) bool {
	var ck [core.KeySize]byte
	copy(ck[:], clientStatic)

	t.mu.RLock()
	closed := t.closed
	n := len(t.sessions)
	perClient := t.perStat[ck]
	t.mu.RUnlock()

	if closed {
		return false
	}
	if perClient >= t.cfg.maxPerClient() {
		return false
	}
	if n >= t.cfg.maxSessions() {
		// A full table admits by evicting the idlest session, whose released
		// reservation (never below InitialWindow) seats the newcomer, so the
		// token check below would refuse a client Register would admit.
		return !t.cfg.DisableEvictOnAdmit
	}
	return t.liveTokens.Load()+int64(t.cfg.initialWindow()) <= t.budget
}

// Lookup reports which session owns a token, without delivering anything. It
// exists for tests and for operator tooling; the datapath uses Dispatch.
func (t *Table) Lookup(tok Token) (*Entry, uint64, bool) {
	s, found, _ := t.primary(tok)
	if !found {
		return nil, 0, false
	}
	return s.ent, s.counter, true
}

// Owners lists every session that currently holds a token, primary first. It
// exists so that the collision tests can see what the index actually did.
func (t *Table) Owners(tok Token) []SessionID {
	s, found, _ := t.primary(tok)
	if !found {
		return nil
	}
	out := []SessionID{s.ent.ID()}
	var buf [maxCandidates]slot
	for _, c := range t.overflowFor(tok, buf[:0]) {
		out = append(out, c.ent.ID())
	}
	return out
}

// Sessions reports the live session count.
func (t *Table) Sessions() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

// IndexedTokens reports the total window capacity currently reserved across
// every session: the gateway's memory bill, in the units it is actually spent
// in. The number of live map entries is at most this and is briefly less,
// because a consumed token is erased before its replacement at the high edge is
// inserted. Capacity is what is bounded, because capacity is what has to fit.
func (t *Table) IndexedTokens() int { return int(t.liveTokens.Load()) }

// MapEntries counts the tokens actually present in the index. It walks every
// shard and is for tests and operator tooling, not for the datapath.
func (t *Table) MapEntries() int {
	n := 0
	for i := range t.shards {
		sh := &t.shards[i]
		sh.mu.RLock()
		n += len(sh.m)
		for _, ov := range sh.ov {
			n += len(ov)
		}
		sh.mu.RUnlock()
	}
	return n
}

// Stats snapshots the counters.
func (t *Table) Stats() Stats {
	t.mu.RLock()
	n := len(t.sessions)
	t.mu.RUnlock()
	return Stats{
		Sessions:      n,
		IndexedTokens: int(t.liveTokens.Load()),
		TokenBudget:   int(t.budget),
		Dispatched:    t.stats.dispatched.Load(),
		Missed:        t.stats.missed.Load(),
		OpenFailed:    t.stats.openFailed.Load(),
		Collisions:    t.stats.collisions.Load(),
		Grown:         t.stats.grown.Load(),
		Evicted:       t.stats.evicted.Load(),
		Refused:       t.stats.refused.Load(),
		TooShort:      t.stats.tooShort.Load(),
		BudgetHit:     t.stats.budgetHit.Load(),
	}
}
