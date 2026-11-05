package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/winn3/core/replaystore"
)

// --- handshake replay -------------------------------------------------------
//
// PERSISTED REPLAY JOURNAL (F-02)
//
// The in-process replay window below is the only thing standing between a
// captured initiation and a reusable gateway detector, and historically it
// emptied on restart: the same captured 169-byte initiation re-answered by a
// restarted gateway was the one restart-sensitive fingerprint the fleet still
// had. The journal closes it.
//
// Usage (library default OFF; production gateway serve requires the journal):
//
//   - set the environment variable WINN3_REPLAY_JOURNAL to an absolute file
//     path. The production installer (server/wins_winn3_gateway_install.sh)
//     enables it by default for both new installs and upgrades:
//     WINN3_GATEWAY_REPLAY_JOURNAL resolves to 1 when unset, provisions the
//     directory and file, and gives the unit StateDirectory=winn3-gateway so
//     the restricted sandbox still permits writes. Production serve refuses
//     WINN3_GATEWAY_REPLAY_JOURNAL=0; durable replay is not an opt-out.
//   - cmd/winn3-gateway reads WINN3_REPLAY_JOURNAL into core.Config.ReplayJournal
//     and refuses a non-absolute path at startup (a relative journal would be
//     created inside the process's working directory); library callers may
//     leave the field empty.
//
// File format: an append-only sequence of 40-byte records,
//
//	initiation-hash  [32 bytes: SHA-256 over the handshake body]
//	expiry           [ 8 bytes: big-endian unix seconds]
//
// written with O_APPEND and fsync'd on every remember(). Before the append, the
// same record is fsync'd to a same-directory .pending file. The pending record
// is removed only after the journal append is durable; startup folds any
// surviving pending record into the journal with the same crash-atomic rewrite
// used for pruning. Expiry is floored to the whole second, so a journal entry
// never outlives the in-memory window; the boundary second may forget it up to
// 1s early, which is a narrowing and never a widening of the replay defence.
//
// Load (gateway start, NewResponder): the whole file is parsed, bounded by
// the store's size and record-count caps. The store refuses a symbolic link
// or non-regular file, a journal with an insecure mode (anything but
// 0600/0640) or foreign ownership, and any file above the bound, all before
// reading. A file whose length is not a multiple of 40, or that fails to
// read, REFUSES the gateway start (fail-closed): a torn journal must not
// silently weaken the gate. Live records (expiry in the future, judged by
// this responder's clock) are kept, expired ones pruned, and the file
// rewritten to live-only. An empty file is a valid empty journal.
//
// Bounded growth: prune-on-load above, plus a hard max-entries admission cap.
// An unexpired replay key is never shed merely to admit another handshake.
// At capacity, admission remains closed until the earliest key expires; the
// durable journal then rewrites to the exact live set.
//
// The prune/cap rewrite is crash-atomic in the store: the new bytes land in a
// same-directory temp file, are fsynced, renamed over the journal, and the
// directory is fsynced, so a crash mid-rewrite leaves either the old whole
// journal or the new whole journal, never the empty file a kill between a
// truncate and a write used to leave (that empty file loaded silently as a
// wiped replay window, which is exactly the WeakenedGate this journal exists
// to close).
//
// Failure policy: a persist, sync, or pathname-identity failure is sticky and
// rejects the handshake whose replay key could not be committed, plus every
// later new handshake on that Responder. A failed durable append installs
// neither admission nor an in-memory cache entry. Live-set capacity and transient
// ENOSPC before the compact journal is mutated are not sticky: that handshake
// is refused, and a later handshake may be admitted once expiry GCs a slot or
// space returns. Responder.ReplayJournalError() exposes the first sticky
// storage error to operators. The pending record makes restart conservative:
// it is recovered into the journal before startup succeeds, so a closed writer
// cannot turn the rejected initiation into an accepted replay after restart.

// ErrReplayJournal reports that durable replay admission is unavailable. It is
// local-only, like the other core errors: callers must preserve the gateway's
// silent failure posture and must not signal this distinction to a peer.
var ErrReplayJournal = errors.New("winn3: replay journal persistence failed")

// maxReplayEntries bounds the handshake replay cache, and is the same term the
// persisted journal's writer cap counts. It is taken from the replaystore
// package rather than restated, so the in-memory bound above and the store's
// load-time record cap cannot drift apart.
//
// Overflowing it requires a flood from someone who already holds the gateway
// admission key, and the consequence of an eviction is that one captured
// initiation could be replayed inside its skew window. That buys the attacker a
// wasted half-open session and nothing else: they do not hold the ephemeral
// private key, so they cannot complete or use it. It is a DoS cost, not a
// confidentiality break, and it is recorded as such in the design document.
const maxReplayEntries = replaystore.MaxRecords

// replayCache refuses a handshake initiation whose body has already been seen
// inside the freshness window.
//
// It exists for a reason that is easy to miss: without it, a prober who
// captured one real initiation could replay it and observe a response, turning
// a single captured packet into a permanent, reusable gateway detector. Silence
// to unauthenticated traffic is worth nothing if authenticated traffic can be
// recorded and replayed by anyone.
//
// It is memory-bounded. Without a journal it does not survive a restart, so a
// gateway restart reopens a replay window of at most the freshness lifetime —
// which is exactly what the persisted journal (F-02) exists to close. With one
// configured, the window survives restarts and the cache is primed from disk.
type replayCache struct {
	mu         sync.Mutex
	lifetime   time.Duration
	entries    map[[32]byte]time.Time
	lastSweep  time.Time
	nextExpiry time.Time
	journal    *replayJournal
}

// newReplayCache builds the cache, or refuses.
//
// A non-positive lifetime is a hard error rather than a quietly substituted
// default, and the distinction is worth more than it looks.
//
// The lifetime is not a free parameter. It must be exactly the span in which a
// captured initiation can still verify — (2*spread+1)*window — and that is a
// quantity only the caller can compute, because only the caller holds the
// resolved Freshness. Any constant this constructor invented in its place would
// be decoupled from the acceptance window by construction. The constant it used
// to invent was DefaultMaxSkew*2, which is 120s; on a gateway configured with a
// wider-than-default skew that is strictly SHORTER than the acceptance window,
// and a replay cache shorter than the acceptance window is precisely the gap
// TestReplayWindowCoversTheWholeAcceptanceWindow exists to rule out: a captured
// initiation the cache has forgotten but the admission tag still accepts.
//
// Note what the old fallback did NOT do: it did not disable replay protection.
// A lifetime that stayed zero would have — seen() compares now.Sub(at) against
// it and every comparison would be false — so the substitution was protecting
// against a genuine silent-off, just with a value that could be wrong. This
// refuses instead, because there is no value that would be right.
//
// It was also unreachable from production: Freshness.resolve guarantees
// window >= 1s and spread >= 1, so the lifetime NewResponder computes is at
// least 3s. This closes a latent trap rather than a live defect.
func newReplayCache(lifetime time.Duration) (*replayCache, error) {
	if lifetime <= 0 {
		return nil, errWrap(ErrConfig,
			"replay cache lifetime is %s; it must be positive and must equal the admission "+
				"tag acceptance span, which only the caller can compute", lifetime)
	}
	return &replayCache{
		lifetime: lifetime,
		entries:  make(map[[32]byte]time.Time),
	}, nil
}

// newReplayCacheWithJournal builds the cache and loads the persisted journal at
// path into it. This is F-02: the replay window now survives a restart. `now`
// is the prune instant — the caller's clock, so an injected test clock is
// honoured and a fixed clock does not expire a journal it just wrote.
//
// A journal that cannot be read or that is not a whole number of records
// refuses the constructor (fail-closed): a torn journal must not silently
// weaken the gate. See the journal contract at the top of this file.
func newReplayCacheWithJournal(lifetime time.Duration, path string, now time.Time) (*replayCache, error) {
	return newReplayCacheWithJournalLimit(lifetime, path, now, maxReplayEntries)
}

func newReplayCacheWithJournalLimit(lifetime time.Duration, path string, now time.Time, cap int) (*replayCache, error) {
	c, err := newReplayCache(lifetime)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return c, nil
	}
	j, err := openReplayJournal(path, now, lifetime, cap)
	if err != nil {
		return nil, err
	}
	c.journal = j
	for k, at := range j.entries {
		c.entries[k] = at
		c.noteExpiryLocked(at)
	}
	return c, nil
}

// --- persisted journal ------------------------------------------------------

// replayJournalRecordSize is one journal record: 32-byte SHA-256 initiation
// hash + 8-byte big-endian unix expiry. It must agree with
// replaystore.RecordSize, which is the package that actually touches the file:
// this layer holds the policy and no environment access (pinned by
// TestCoreHasNoTimersOrSockets).
const replayJournalRecordSize = replaystore.RecordSize

// replayJournal is the append-only on-disk half of the replay window.
//
// All mutation happens under the owning cache's mutex; the bytes go through
// the replaystore package so the core stays environment-free.
type replayJournal struct {
	w       replayJournalWriter
	records int // records currently on disk, tracked so the cap rewrite is cheap
	cap     int // rewrite ceiling (maxReplayEntries; tests shrink it)
	entries map[[32]byte]time.Time
}

type replayJournalWriter interface {
	Append(replaystore.Record, int64) error
	Rewrite([]replaystore.Record, int64) error
	VerifyPath() error
	Err() error
}

// openReplayJournal loads path, refuses a torn, insecure, symlinked or
// oversized file, prunes expired records by rewriting the file to live-only,
// and returns the journal primed for appends.
func openReplayJournal(path string, now time.Time, lifetime time.Duration, cap int) (*replayJournal, error) {
	live, w, err := replaystore.OpenWithLimit(path, now, cap)
	if err != nil {
		return nil, errWrap(ErrConfig, "%v", err)
	}
	j := &replayJournal{w: w, cap: cap, entries: make(map[[32]byte]time.Time, len(live))}
	for _, r := range live {
		j.entries[r.Key] = time.Unix(r.Expiry, 0).Add(-lifetime)
	}
	// Prune-on-load: the file shrinks to the live window here, so growth is
	// bounded by the cap rewrite from the first boot, not the first cap hit.
	if err := j.rewrite(j.entries, lifetime, now, nil); err != nil {
		_ = w.Close()
		return nil, errWrap(ErrConfig, "replay journal %s: %v", path, err)
	}
	return j, nil
}

// append writes one record and fsyncs. Caller holds the cache mutex.
func (j *replayJournal) append(key [32]byte, expiry, nowUnix int64) error {
	if err := j.w.Append(replaystore.Record{Key: key, Expiry: expiry}, nowUnix); err != nil {
		return err
	}
	j.records++
	return nil
}

// rewrite replaces the file with the given live entries. Caller holds the
// cache mutex. Expired entries are dropped, but an unexpired replay key is
// never shed merely to admit another handshake. The
// replacement is crash-atomic (see the store's Rewrite): a crash anywhere in
// it leaves the old or the new whole journal on disk, never an empty one.
func (j *replayJournal) rewrite(entries map[[32]byte]time.Time, lifetime time.Duration, now time.Time, required *[32]byte) error {
	if err := j.w.Err(); err != nil {
		return err
	}
	nowUnix := now.Unix()
	recs := make([]replaystore.Record, 0, len(entries))
	if required != nil {
		if at, ok := entries[*required]; ok {
			expiry := at.Add(lifetime).Unix()
			if expiry > nowUnix {
				recs = append(recs, replaystore.Record{Key: *required, Expiry: expiry})
			}
		}
	}
	for k, at := range entries {
		if required != nil && k == *required {
			continue
		}
		expiry := at.Add(lifetime).Unix()
		if expiry <= nowUnix {
			continue
		}
		recs = append(recs, replaystore.Record{Key: k, Expiry: expiry})
	}
	if err := j.w.Rewrite(recs, nowUnix); err != nil {
		return err
	}
	j.records = len(recs)
	return nil
}

// journalError reports the first sticky persist/sync/identity failure, or nil.
// Live-set capacity and retryable pre-mutation space errors are not stored
// here: those refuse only the handshake that hit them.
func (j *replayJournal) journalError() error {
	if j == nil {
		return nil
	}
	return j.w.Err()
}

// seen reports whether this body has already been accepted and is still inside
// the window. It does not insert.
func (c *replayCache) seen(key [32]byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(now)
	at, ok := c.entries[key]
	if !ok {
		return false
	}
	return now.Sub(at) < c.lifetime
}

// remember atomically consumes one proven body and, when configured, makes its
// replay key durable before admission succeeds. It is called only after the
// message has proven itself cryptographically, so that a key holder cannot fill
// the cache or journal with packets that never pass.
func (c *replayCache) remember(key [32]byte, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(now)
	if at, ok := c.entries[key]; ok && now.Sub(at) < c.lifetime {
		return ErrReplay
	}
	if c.journal != nil {
		if err := c.journal.journalError(); err != nil {
			return errWrap(ErrReplayJournal, "%w", err)
		}
	}
	limit := maxReplayEntries
	if c.journal != nil && c.journal.cap < limit {
		limit = c.journal.cap
	}
	if len(c.entries) >= limit &&
		(c.nextExpiry.IsZero() || !now.Before(c.nextExpiry)) {
		// The periodic sweep is rate-limited to keep ordinary admission O(1).
		// At the security cap, however, entries can have staggered lifetimes:
		// an entry may expire before the next periodic sweep is due. Recheck the
		// full set before refusing so expired keys never turn a healthy durable
		// journal into a false capacity refusal.
		c.sweepExpiredLocked(now)
	}
	if len(c.entries) >= limit {
		// Never evict an unexpired replay key to make room: doing so lets a
		// captured initiation become acceptable inside its replay lifetime. Fail
		// this admission closed until expiry GCs a slot. Do not latch the
		// Responder: gateway admitsNewHandshakes() consults ReplayJournalError(),
		// so a capacity latch would permanently refuse even after the live set
		// shrinks.
		return errWrap(ErrReplayJournal, "replay cache reached the %d-entry security cap", limit)
	}
	if c.journal != nil {
		// F-02: durable commit before the in-memory insert. A failed append
		// must not leave a committed-looking cache entry: that would report
		// ErrReplay for a handshake that was never admitted, then vanish on
		// restart so the same initiation became admissible. If the following
		// cap rewrite fails, either the old journal (which now contains key)
		// or the new crash-atomic replacement (which is required to retain
		// key) survives.
		if err := c.journal.append(key, now.Add(c.lifetime).Unix(), now.Unix()); err != nil {
			return errWrap(ErrReplayJournal, "%w", err)
		}
	}
	c.entries[key] = now
	c.noteExpiryLocked(now)
	if c.journal != nil && c.journal.records > c.journal.cap {
		if err := c.journal.rewrite(c.entries, c.lifetime, now, &key); err != nil {
			return errWrap(ErrReplayJournal, "%w", err)
		}
	}
	return nil
}

// journalError reports the first sticky journal persist failure, or nil.
// For tests and for the Responder's operator-facing accessor.
func (c *replayCache) journalError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.journal.journalError()
}

// verifyJournalPath binds operator readiness to the descriptors held by the
// active writer. Unlike an external cached inode, this remains correct after
// the writer performs a legitimate crash-atomic snapshot replacement.
func (c *replayCache) verifyJournalPath() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.journal == nil {
		return nil
	}
	if err := c.journal.journalError(); err != nil {
		return err
	}
	return c.journal.w.VerifyPath()
}

func (c *replayCache) sweepLocked(now time.Time) {
	if now.Sub(c.lastSweep) < c.lifetime {
		return
	}
	c.lastSweep = now
	c.sweepExpiredLocked(now)
}

func (c *replayCache) sweepExpiredLocked(now time.Time) {
	c.nextExpiry = time.Time{}
	for k, at := range c.entries {
		if now.Sub(at) >= c.lifetime {
			delete(c.entries, k)
			continue
		}
		c.noteExpiryLocked(at)
	}
}

func (c *replayCache) noteExpiryLocked(at time.Time) {
	expires := at.Add(c.lifetime)
	if c.nextExpiry.IsZero() || expires.Before(c.nextExpiry) {
		c.nextExpiry = expires
	}
}

// size is for tests.
func (c *replayCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// --- transport demux tokens -------------------------------------------------

// demuxToken derives the per-packet transport token for a counter.
//
// This one function is why a Winn3 transport message carries no counter, no
// session index, no type byte, no length and no version: the token IS the
// counter, encoded so that only a holder of the direction's demux key can
// compute or recognise it.
func demuxToken(key *[KeySize]byte, counter uint64) [DemuxTokenSize]byte {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(labelDemux))
	mac.Write(ctr[:])
	sum := mac.Sum(nil)
	var t [DemuxTokenSize]byte
	copy(t[:], sum[:DemuxTokenSize])
	return t
}

// tokenWindow is the receive side: a precomputed set of the next `size`
// expected tokens.
//
// It is simultaneously three things, which is what makes it worth its memory:
//
//   - the demultiplexer, since a token identifies its counter in O(1)
//   - the anti-replay filter, EXACTLY and with no bitmap arithmetic, because a
//     token is erased when it is consumed and a replayed packet then finds
//     nothing
//   - the reordering tolerance, since every counter in the window is equally
//     acceptable in any order
//
// The cost is real and is the design's known scaling weakness: roughly `size`
// map entries per session per direction on the gateway.
//
// The token map is OPTIONAL. When `tokens` is nil the same structure is still
// all three of the things above except the demultiplexer: the sliding, the
// force-advance and the exact replay filter are carried by `low` and
// `consumed`, which cost one byte per counter rather than the ~38 bytes an
// indexed token costs. That is the mode Session.OpenAt runs in when an external
// index owns the demultiplexing (see CallerOwnsTokenWindow) — the replay
// filter STAYS HERE, it is only the lookup that moves out.
type tokenWindow struct {
	key      [KeySize]byte
	prf      *demuxPRF
	size     int
	low      uint64
	tokens   map[[DemuxTokenSize]byte]uint64
	consumed []bool

	// next is one past the highest counter consumed. reordered counts
	// counters consumed after a higher one, and lost the counters below next
	// that have not been consumed. Both see only messages that authenticated,
	// so neither is confused with noise or a replay: reordered is reordering
	// on the path, and lost is every message dropped before it was opened,
	// on the wire or in a receive queue. A late message that fills a hole
	// moves it from lost to reordered.
	next      uint64
	reordered uint64
	lost      uint64
	// depth is reordered split by displacement: how far below the highest
	// consumed counter each late message landed (ReorderDepth).
	depth ReorderDepth
}

// ReorderDepthBuckets is the number of displacement buckets in ReorderDepth.
const ReorderDepthBuckets = 10

// ReorderDepth counts late messages by displacement d = (highest counter
// consumed) - (late counter), d >= 1. Bucket i holds 2^i <= d < 2^(i+1), and
// the last bucket everything from 512 up: [1], [2,3], [4,7], ..., [256,511],
// [512,inf). A window scores displacements up to size/2 - 1 only (consume),
// so the last bucket fills only in windows wider than 1024, as the gateway's
// 32768 is. The shape says where an inversion came from. A sender that swaps
// messages inside one send batch or one segmentation-offload super-buffer
// (at most 45 messages, carrier/udp_gso_linux.go) can only produce d <= 44;
// a second path with its own delay produces d near rate x skew, which at
// 50,000 messages/s and a 2 ms skew is about 100.
type ReorderDepth [ReorderDepthBuckets]uint64

func (r *ReorderDepth) add(d uint64) {
	i := bits.Len64(d) - 1
	if i < 0 {
		i = 0
	}
	if i >= ReorderDepthBuckets {
		i = ReorderDepthBuckets - 1
	}
	r[i]++
}

// Add folds o into r.
func (r *ReorderDepth) Add(o ReorderDepth) {
	for i := range r {
		r[i] += o[i]
	}
}

func newTokenWindow(key *[KeySize]byte, size int) *tokenWindow {
	w := &tokenWindow{
		size:     size,
		tokens:   make(map[[DemuxTokenSize]byte]uint64, size),
		consumed: make([]bool, size),
		prf:      newDemuxPRF(key),
	}
	copy(w.key[:], key[:])
	for c := uint64(0); c < uint64(size); c++ {
		w.tokens[w.prf.token(c)] = c
	}
	return w
}

func (w *tokenWindow) wipe() {
	if w == nil {
		return
	}
	w.key = [KeySize]byte{}
	w.prf = nil
	w.tokens = nil
	w.consumed = nil
}

// newCounterWindow builds the same window with no token index and no demux key:
// the replay filter and the reordering tolerance, and nothing else.
//
// It is deliberately the SAME type running the SAME slide logic rather than a
// second implementation of it. A parallel implementation of a replay filter is
// a thing that drifts, and the drift is silent until it is a vulnerability.
// TestTheCounterOnlyWindowAgreesWithTheIndexedOne requires the two modes to
// accept and reject identically over long randomised sequences.
//
// Note that `key` stays zero here: in this mode no demux key is copied into the
// window at all, because nothing in it derives a token.
func newCounterWindow(size int) *tokenWindow {
	return &tokenWindow{
		size:     size,
		consumed: make([]bool, size),
	}
}

// indexed reports whether this window can map a token to a counter. A
// counter-only window cannot, and Open says so rather than reporting every
// datagram as unauthenticated.
func (w *tokenWindow) indexed() bool { return w.tokens != nil }

// holds reports whether a counter is currently acceptable: inside the window
// and not already consumed. It is exactly map membership in an indexed window —
// the bound and the consumed test are the same two facts that decide whether
// `tokens` still carries an entry — and it is the whole filter in a
// counter-only one.
//
// The bound is written identically to consume's so that the two cannot disagree
// about the edges of the window.
func (w *tokenWindow) holds(counter uint64) bool {
	if !w.inWindow(counter) {
		return false
	}
	return !w.consumed[int(counter%uint64(w.size))]
}

// inWindow reports whether a counter is inside the sliding window, allowing
// for the counter namespace to wrap past the uint64 ceiling at the packet
// boundary.
//
// The membership test is the modular forward distance from the low edge:
// (counter − low) mod 2^64 in [0, size). Written as a single unsigned
// subtraction this is wrap-safe by construction, where the obvious literal
// `counter >= low && counter < low+size` is not — when low is within `size` of
// the ceiling, `low+size` overflows to a small value and both comparisons read
// every real in-window counter as out of range. TestTokenWindowWrap keeps the
// window at the ceiling so that literal error cannot hide behind the fact that
// real counters never reach 2^64.
func (w *tokenWindow) inWindow(counter uint64) bool {
	return counter-w.low < uint64(w.size)
}

// lookup maps a token to its counter.
func (w *tokenWindow) lookup(token []byte) (uint64, bool) {
	if len(token) != DemuxTokenSize {
		return 0, false
	}
	var t [DemuxTokenSize]byte
	copy(t[:], token)
	c, ok := w.tokens[t]
	return c, ok
}

// consume retires a counter and slides the window.
//
// Two rules keep it live. Contiguous consumption from the low edge slides
// naturally. And a counter far ahead of the low edge FORCES the window forward,
// because otherwise one permanently lost packet at the low edge would pin the
// window and every counter past low+size would be rejected — a single dropped
// datagram would end the session. Forcing bounds reordering tolerance, which is
// the standard trade and is the same one a sliding-bitmap filter makes
// implicitly.
//
// The bound is `size/2 − 1`, NOT `size/2`, and the difference is this line's
// `+1`: consuming counter c retires the low edge to `c − half + 1`, so a message
// displaced by exactly `half` is already below the edge when it arrives. The
// tolerance is therefore 127 at a 256-token window and 511 at the shipping
// DefaultTokenWindow of 1024. It was documented as `size/2` in three places
// until the network-realism lane swept the boundary and measured the cliff. The
// window is one NARROWER than was advertised, never wider, so this was a
// documentation defect and not a security one — but a reader sizing a window
// against a measured reordering depth would have been off by one in the
// direction that loses packets.
func (w *tokenWindow) consume(counter uint64) {
	var tok [DemuxTokenSize]byte
	if w.tokens != nil && w.prf != nil {
		tok = w.prf.token(counter)
	}
	w.consumeKnown(counter, tok[:])
}

// consumeKnown uses the already authenticated wire token, avoiding a second PRF.
func (w *tokenWindow) consumeKnown(counter uint64, token []byte) {
	if !w.inWindow(counter) {
		return
	}
	if ahead := counter - w.next; ahead < 1<<63 {
		w.lost += ahead
		w.next = counter + 1
	} else {
		w.reordered++
		w.depth.add(w.next - 1 - counter)
		if w.lost > 0 {
			w.lost--
		}
	}
	if w.tokens != nil {
		var tok [DemuxTokenSize]byte
		copy(tok[:], token)
		delete(w.tokens, tok)
	}
	w.consumed[int(counter%uint64(w.size))] = true

	if half := uint64(w.size / 2); counter-w.low >= half {
		w.forceAdvance(counter - half + 1)
	}
	for w.consumed[int(w.low%uint64(w.size))] {
		w.retireLow()
	}
}

// retireLow drops the low counter and admits one new counter at the high edge.
func (w *tokenWindow) retireLow() {
	idx := int(w.low % uint64(w.size))
	if w.tokens != nil && !w.consumed[idx] && w.prf != nil {
		delete(w.tokens, w.prf.token(w.low))
	}
	w.consumed[idx] = false
	w.low++
	next := w.low + uint64(w.size) - 1
	// next is admitted unconditionally: near the counter ceiling it wraps to a
	// small value that is the correct in-window counter at the packet boundary,
	// so a `next >= w.low` guard here would silently drop the high edge exactly
	// when the window needs it. The nil test is the counter-only mode, which
	// admits the counter without paying an HMAC to name it.
	if w.tokens != nil && w.prf != nil {
		w.tokens[w.prf.token(next)] = next
	}
}

// forceAdvance retires the low edge forward until it reaches newLow, counting
// steps as the modular forward distance so the loop survives the counter
// wrapping past the uint64 ceiling.
func (w *tokenWindow) forceAdvance(newLow uint64) {
	steps := newLow - w.low
	for i := uint64(0); i < steps; i++ {
		w.retireLow()
	}
}

// live reports how many tokens are currently accepted. For tests.
func (w *tokenWindow) live() int { return len(w.tokens) }
