package initauth

// The server half: an admission filter that sits in front of amneziawg-go and
// decides, per datagram, whether it may reach the AWG state machine at all.
//
// # Why the grant is scoped to the 4-tuple, and why that is not the mistake
// # the firewall design was warned off
//
// docs/handoff/SPA_ALTERNATIVE_INITIATION_ASSESSMENT_20260805.md §5.1 credits
// ../knock for keying authorisation on the source IP and NEVER on the 4-tuple,
// because a CGNAT that rebinds the source port between the knock and the
// connect would otherwise strand the client. That is the correct rule for a
// scheme where the knock and the traffic leave DIFFERENT sockets, and ../knock
// is right to follow it.
//
// It does not apply here, and the difference is the whole reason this package
// exists. The authenticator IS the handshake initiation. There is no interval
// between authorising and connecting in which a NAT could rebind, because there
// is no second packet: the bytes that authorise and the bytes that connect are
// the same bytes on the same socket. The external port the gateway observes is
// therefore the NAT mapping for that exact client socket.
//
// So scoping the grant to the observed 4-tuple is available here, and taking it
// closes the wall that SPA_DECISION_20260806.md §3 called information-theoretic:
// a co-resident investigator behind the same CGNAT egress holds a DIFFERENT
// mapping, gets a different observed source port, and is simply not admitted.
// There is no per-address window for them to race, because there is no
// per-address grant at all.
//
// The residual, stated honestly: a CGNAT may rebind a mapping mid-session, and
// when it does, the flow arrives on a 4-tuple with no grant and is dropped.
// AmneziaWG then re-handshakes — it retries forever, and a dropping censor was
// measured drawing 24 initiation retries out of it — and the retry carries a
// fresh authenticator, so the new mapping is granted within one handshake
// interval. The failure is a reconnect, not a lockout.
//
// # The fail-open posture, and where it deliberately inverts ../knock
//
// ../knock's Gate fails CLOSED when its replay cache is full: it drops the
// grant rather than grow past the cap. That is right for a firewall gate, where
// admitting an unverified source defeats the entire purpose.
//
// This gate fails OPEN on every table-exhaustion path, and the inversion is
// deliberate. What lies behind this gate is amneziawg-go, which authenticates
// every datagram cryptographically on its own account. Admitting one datagram
// too many costs a MAC1 check that ends in a silent discard. Refusing one
// datagram too few costs a real user in Myanmar their connection, silently,
// with no diagnosis available to them or to the operator — which is precisely
// the failure SPA_DECISION_20260806.md §6 had to add a whole guard to catch.
// Between those two, this product takes the CPU cycle every time.

import (
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Mode selects what the Gate does with its own verdict.
type Mode uint8

const (
	// ModeObserve verifies every datagram, keeps full state, updates every
	// counter — and admits everything regardless. A node running in observe
	// mode is byte-for-byte the node running with no gate at all, so it can be
	// switched on anywhere with no risk, and its counters answer "what would
	// enforcing have done" before anything is enforced.
	//
	// This is the zero value on purpose. A Gate that was constructed carelessly
	// cannot dark a node.
	ModeObserve Mode = iota

	// ModeRequire drops datagrams the Gate did not admit.
	ModeRequire
)

func (m Mode) String() string {
	switch m {
	case ModeObserve:
		return "observe"
	case ModeRequire:
		return "require"
	default:
		return "unknown"
	}
}

// Outcome is what the Gate decided, independently of whether the mode caused it
// to act on that decision.
type Outcome uint8

const (
	// OutcomeEstablished: the source 4-tuple holds a live grant. This is the
	// steady state and it costs no cryptography.
	OutcomeEstablished Outcome = iota

	// OutcomeAuthenticated: an initiation verified, and the 4-tuple is now
	// granted.
	OutcomeAuthenticated

	// OutcomeUnauthenticated: initiation-shaped, but no key and no in-skew
	// bucket produced the observed prefix.
	OutcomeUnauthenticated

	// OutcomeReplay: verified, but this exact initiation body has been seen
	// before. A captured initiation replayed from another socket lands here.
	OutcomeReplay

	// OutcomeRateLimited: too many initiation attempts from this source
	// address, refused before any cryptography.
	OutcomeRateLimited

	// OutcomeNoGrant: not initiation-shaped and no live grant. AmneziaWG's junk
	// datagrams land here before their initiation arrives, which is correct:
	// amneziawg-go discards junk in any case, so dropping it changes nothing
	// the far end would have done.
	OutcomeNoGrant
)

func (o Outcome) String() string {
	switch o {
	case OutcomeEstablished:
		return "established"
	case OutcomeAuthenticated:
		return "authenticated"
	case OutcomeUnauthenticated:
		return "unauthenticated"
	case OutcomeReplay:
		return "replay"
	case OutcomeRateLimited:
		return "rate_limited"
	case OutcomeNoGrant:
		return "no_grant"
	default:
		return "unknown"
	}
}

// Admits reports whether this outcome is one the Gate would let through when
// enforcing.
func (o Outcome) Admits() bool {
	return o == OutcomeEstablished || o == OutcomeAuthenticated
}

// Default limits. The rate figures are sized against a CGNAT egress rather than
// against a single subscriber, because under this threat model one source
// address is thousands of people: a 5,000-subscriber egress in which every
// subscriber reconnects every 300 s offers 1,000 initiations a minute, so the
// ceiling below leaves better than 2x headroom before a real carrier is
// throttled. Undersizing this locks out a whole carrier silently, which is the
// single worst thing this file could do.
const (
	// DefaultGrace is how long a 4-tuple grant survives with no admitted
	// traffic. It slides forward on every admitted datagram.
	//
	// Sliding is safe here and was not safe in the firewall design, for the
	// reason set out at the top of this file: the grant names one client
	// socket, not one carrier's egress address, so extending it on that
	// client's own traffic extends nothing for anybody else. 180 s is seven
	// keepalive intervals at the measured 25 s metronome, so a live session
	// never lapses, and a dead one is forgotten in three minutes.
	DefaultGrace = 180 * time.Second

	DefaultMaxGrants        = 100_000
	DefaultMaxReplayEntries = 100_000
	DefaultRateCapacity     = 240
	DefaultRatePerMinute    = 2_400
	DefaultRateMaxSources   = 65_536

	// DefaultMinRejectedBeforeDemote and DefaultDemoteAfter are the two
	// thresholds of the self-demotion guard, and BOTH must be crossed.
	//
	// The pairing is the load-bearing choice, and it is taken directly from
	// SPA_DECISION_20260806.md §6, where a bare count would have handed any
	// single source a remote kill switch. The count filters a quiet node: a few
	// background scans overnight against a gateway with no users is not a
	// lockout. The window filters a busy moment: a burst that resolves itself
	// is not a lockout either. Crossing both means that for five unbroken
	// minutes, thousands of initiations were refused and not one was accepted —
	// which is not a scan, it is a misconfiguration, and the safe response to a
	// misconfiguration is to stop gating.
	DefaultMinRejectedBeforeDemote = 2_000
	DefaultDemoteAfter             = 5 * time.Minute
)

// Limits are the Gate's resource and safety bounds. A zero value takes every
// default above.
type Limits struct {
	Grace            time.Duration
	MaxGrants        int
	MaxReplayEntries int
	RateCapacity     int
	RatePerMinute    int
	RateMaxSources   int

	// MinRejectedBeforeDemote and DemoteAfter drive the self-demotion guard.
	// Setting either to a negative value disables the guard, which should only
	// ever be done in a test.
	MinRejectedBeforeDemote int64
	DemoteAfter             time.Duration
}

func (l Limits) resolve() Limits {
	if l.Grace == 0 {
		l.Grace = DefaultGrace
	}
	if l.MaxGrants == 0 {
		l.MaxGrants = DefaultMaxGrants
	}
	if l.MaxReplayEntries == 0 {
		l.MaxReplayEntries = DefaultMaxReplayEntries
	}
	if l.RateCapacity == 0 {
		l.RateCapacity = DefaultRateCapacity
	}
	if l.RatePerMinute == 0 {
		l.RatePerMinute = DefaultRatePerMinute
	}
	if l.RateMaxSources == 0 {
		l.RateMaxSources = DefaultRateMaxSources
	}
	if l.MinRejectedBeforeDemote == 0 {
		l.MinRejectedBeforeDemote = DefaultMinRejectedBeforeDemote
	}
	if l.DemoteAfter == 0 {
		l.DemoteAfter = DefaultDemoteAfter
	}
	return l
}

// Counters are cumulative. Nothing here is ever sent anywhere; they exist so an
// operator can answer "would enforcing break anything" from observe mode, and
// "is anything wrong" from enforcing mode.
type Counters struct {
	Established     uint64
	Authenticated   uint64
	Unauthenticated uint64
	Replay          uint64
	RateLimited     uint64
	NoGrant         uint64

	// AdmittedWhileObserving counts datagrams that were let through only
	// because the Gate was observing. It is the single number that answers
	// "what would switching to require mode cost me right now".
	AdmittedWhileObserving uint64

	// GrantsShed and ReplayShed count entries evicted under table pressure, and
	// RateSourcesShed the same for the limiter. A nonzero value here is not an
	// error — it is the fail-open posture working — but a persistently rising
	// one means the tables are undersized for the traffic.
	GrantsShed      uint64
	ReplayShed      uint64
	RateSourcesShed uint64

	// Demotions counts self-demotions from require to observe. Any value above
	// zero should page someone.
	Demotions uint64
}

// Snapshot is a consistent read of the Gate's state.
type Snapshot struct {
	Mode        Mode
	Counters    Counters
	Grants      int
	ReplayCache int
	DemotedAt   time.Time
	DemoteWhy   string
}

// Config constructs a Gate.
type Config struct {
	// Keys are the shared secrets, most current first. More than one key is
	// how a rotation overlaps; a rotation that ships with a single key takes
	// every client still on the old key offline at once, silently and
	// simultaneously.
	Keys [][]byte

	// Profile is the deployment's S1 and H1 values. They must match the
	// AmneziaWG configuration the gateway is actually running.
	Profile Profile

	Options Options
	Limits  Limits

	// Mode is the starting mode. The zero value is ModeObserve.
	Mode Mode

	// Now is injectable for tests. Nil means time.Now.
	Now func() time.Time

	// OnOutcome, if set, is called for every decision. It must not block and
	// must not write anything to any socket: the Gate's silence on every
	// rejection path is the property that leaves an active prober with no
	// oracle, and a logger that answers differently per outcome would hand one
	// back.
	OnOutcome func(src netip.AddrPort, outcome Outcome, admitted bool)

	// OnDemote, if set, is called once when the self-demotion guard trips.
	OnDemote func(why string)
}

// Gate is the admission filter. It is safe for concurrent use.
type Gate struct {
	keys    [][]byte
	profile Profile
	opts    Options
	limits  Limits
	now     func() time.Time

	onOutcome func(netip.AddrPort, Outcome, bool)
	onDemote  func(string)

	replayTTL time.Duration

	mu        sync.Mutex
	mode      Mode
	counters  Counters
	grants    map[netip.AddrPort]time.Time
	replay    map[[32]byte]time.Time
	limiter   map[netip.Addr]*tokenBucket
	demotedAt time.Time
	demoteWhy string

	// rejectedStreak counts consecutive rejections with no accept between
	// them; streakSince is when the streak began. Any accept clears both.
	rejectedStreak int64
	streakSince    time.Time
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// NewGate validates the configuration and returns a Gate.
//
// It refuses a configuration it cannot honour rather than silently degrading,
// because every degradation available here is invisible on the wire: a
// mismatched profile, a short key or an out-of-range skew all present to a
// client as a dropped packet and to an operator as a healthy daemon that
// authorises nobody.
func NewGate(cfg Config) (*Gate, error) {
	if err := cfg.Profile.Validate(); err != nil {
		return nil, err
	}
	if err := checkKeys(cfg.Keys); err != nil {
		return nil, err
	}
	window, spread, err := cfg.Options.resolve()
	if err != nil {
		return nil, err
	}
	limits := cfg.Limits.resolve()
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	keys := make([][]byte, len(cfg.Keys))
	for i, k := range cfg.Keys {
		keys[i] = append([]byte(nil), k...)
	}

	g := &Gate{
		keys:    keys,
		profile: cfg.Profile,
		opts:    cfg.Options,
		limits:  limits,
		now:     now,

		onOutcome: cfg.OnOutcome,
		onDemote:  cfg.OnDemote,

		// An initiation can only verify inside the skew window, so a replay
		// entry cannot usefully outlive it. Two spreads plus one bucket is the
		// widest span any single datagram can be accepted across.
		replayTTL: time.Duration(2*spread+1) * window,

		mode:    cfg.Mode,
		grants:  make(map[netip.AddrPort]time.Time),
		replay:  make(map[[32]byte]time.Time),
		limiter: make(map[netip.Addr]*tokenBucket),
	}
	g.streakSince = now()
	return g, nil
}

// Mode reports the Gate's current mode, which may differ from the configured
// one if the self-demotion guard has tripped.
func (g *Gate) Mode() Mode {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.mode
}

// Snapshot reads the Gate's state.
func (g *Gate) Snapshot() Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	return Snapshot{
		Mode:        g.mode,
		Counters:    g.counters,
		Grants:      len(g.grants),
		ReplayCache: len(g.replay),
		DemotedAt:   g.demotedAt,
		DemoteWhy:   g.demoteWhy,
	}
}

// Consider decides one datagram and returns both the verdict and whether the
// current mode acts on it.
//
// It is the whole decision procedure, exported so that a host embedding this in
// something other than a net.PacketConn — a subprocess relay, a test rig — gets
// exactly the same semantics as WrapPacketConn.
func (g *Gate) Consider(src netip.AddrPort, datagram []byte) (outcome Outcome, admit bool) {
	now := g.now()
	src = normaliseAddrPort(src)

	g.mu.Lock()
	outcome = g.decideLocked(src, datagram, now)
	admit = outcome.Admits() || g.mode == ModeObserve

	switch outcome {
	case OutcomeEstablished:
		g.counters.Established++
	case OutcomeAuthenticated:
		g.counters.Authenticated++
	case OutcomeUnauthenticated:
		g.counters.Unauthenticated++
	case OutcomeReplay:
		g.counters.Replay++
	case OutcomeRateLimited:
		g.counters.RateLimited++
	case OutcomeNoGrant:
		g.counters.NoGrant++
	}
	if !outcome.Admits() && admit {
		g.counters.AdmittedWhileObserving++
	}

	g.updateDemotionStreakLocked(outcome, now)
	onOutcome := g.onOutcome
	g.mu.Unlock()

	if onOutcome != nil {
		onOutcome(src, outcome, admit)
	}
	return outcome, admit
}

// decideLocked runs the decision procedure. The ORDER is the design:
//
//  1. A live grant short-circuits everything, so the steady state costs one map
//     lookup and no cryptography, and a handshake retry inside a live session is
//     never gated on a key that may have rotated underneath it.
//  2. Otherwise the cheap shape test — exact length, header word in range —
//     runs before anything expensive, so ordinary internet background scan
//     traffic costs nothing at all.
//  3. Rate limiting runs before verification, so a flood cannot be turned into
//     a CPU-exhaustion vector by shaping it like an initiation.
//  4. Verification, then replay. Replay last, because a datagram that does not
//     verify must not be allowed to consume replay-table space.
func (g *Gate) decideLocked(src netip.AddrPort, datagram []byte, now time.Time) Outcome {
	if expiry, ok := g.grants[src]; ok && expiry.After(now) {
		g.grants[src] = now.Add(g.limits.Grace)
		return OutcomeEstablished
	}

	if !g.profile.IsInitiationShaped(datagram) {
		return OutcomeNoGrant
	}

	if !g.allowRateLocked(src.Addr(), now) {
		return OutcomeRateLimited
	}

	if _, err := Verify(datagram, g.keys, g.profile, now, g.opts); err != nil {
		return OutcomeUnauthenticated
	}

	key, err := ReplayKey(datagram, g.profile)
	if err != nil {
		return OutcomeUnauthenticated
	}
	if seen, ok := g.replay[key]; ok && seen.After(now) {
		return OutcomeReplay
	}

	g.pruneReplayLocked(now)
	if len(g.replay) >= g.limits.MaxReplayEntries {
		// Fail open: shed and carry on. See the posture note at the top of this
		// file. Losing replay coverage costs an attacker's captured initiation
		// one delivery to a state machine that will reject it; refusing here
		// would cost a real client their handshake.
		g.shedReplayLocked()
	}
	g.replay[key] = now.Add(g.replayTTL)

	g.pruneGrantsLocked(now)
	if len(g.grants) >= g.limits.MaxGrants {
		g.shedGrantsLocked()
	}
	g.grants[src] = now.Add(g.limits.Grace)
	return OutcomeAuthenticated
}

// updateDemotionStreakLocked implements the two-threshold guard. Any accepted
// initiation, and any datagram from an established flow, clears the streak —
// because either one proves the gate is admitting somebody.
func (g *Gate) updateDemotionStreakLocked(outcome Outcome, now time.Time) {
	if outcome.Admits() {
		g.rejectedStreak = 0
		g.streakSince = now
		return
	}
	if g.mode != ModeRequire {
		return
	}
	if g.limits.MinRejectedBeforeDemote < 0 || g.limits.DemoteAfter < 0 {
		return
	}
	// The window is measured from the first rejection of this streak, not
	// from start-up or the last admit: otherwise a gate that sat idle for
	// DemoteAfter demotes on the first burst, which is the remote kill
	// switch the two-threshold pairing exists to prevent.
	if g.rejectedStreak == 0 {
		g.streakSince = now
	}
	g.rejectedStreak++
	if g.rejectedStreak < g.limits.MinRejectedBeforeDemote {
		return
	}
	if now.Sub(g.streakSince) < g.limits.DemoteAfter {
		return
	}

	g.mode = ModeObserve
	g.demotedAt = now
	g.demoteWhy = "no initiation was admitted for " + g.limits.DemoteAfter.String() +
		" across " + strconv.FormatInt(g.rejectedStreak, 10) +
		" consecutive rejections; gate self-demoted to observe"
	g.counters.Demotions++
	g.rejectedStreak = 0
	g.streakSince = now
	if g.onDemote != nil {
		// Deliberately called with the lock held: the demotion must be visible
		// in Snapshot before anything reacts to the callback, and the contract
		// on OnDemote is that it does not block.
		g.onDemote(g.demoteWhy)
	}
}

func (g *Gate) allowRateLocked(ip netip.Addr, now time.Time) bool {
	perSecond := float64(g.limits.RatePerMinute) / 60.0
	capacity := float64(g.limits.RateCapacity)

	tb, ok := g.limiter[ip]
	if !ok {
		if len(g.limiter) >= g.limits.RateMaxSources {
			g.pruneLimiterLocked(now)
		}
		if len(g.limiter) >= g.limits.RateMaxSources {
			// Shed rather than refuse. ../ratelimit refuses a NEW source when
			// its table is full, which SPA_DECISION_20260806.md §6 showed is a
			// silent lockout an attacker can hold open indefinitely by
			// re-touching forged addresses. Evicting instead means a flood
			// costs the attacker's own entries, not a real client's admission.
			g.shedLimiterLocked()
		}
		tb = &tokenBucket{tokens: capacity, last: now}
		g.limiter[ip] = tb
	}

	elapsed := now.Sub(tb.last).Seconds()
	if elapsed > 0 {
		tb.tokens += elapsed * perSecond
		if tb.tokens > capacity {
			tb.tokens = capacity
		}
		tb.last = now
	}
	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}

// The prune/shed pair below is the standard two-stage table discipline: prune
// removes anything genuinely expired and is exact; shed evicts a bounded random
// sample and is approximate. Go randomises map iteration order, so a short
// sample is a real random sample, and evicting the oldest of it approximates
// least-recently-used at O(1) per call rather than O(n).
const shedSample = 8

func (g *Gate) pruneGrantsLocked(now time.Time) {
	for k, expiry := range g.grants {
		if !expiry.After(now) {
			delete(g.grants, k)
		}
	}
}

func (g *Gate) shedGrantsLocked() {
	var victim netip.AddrPort
	var oldest time.Time
	seen := 0
	for k, expiry := range g.grants {
		if seen == 0 || expiry.Before(oldest) {
			victim, oldest = k, expiry
		}
		seen++
		if seen >= shedSample {
			break
		}
	}
	if seen > 0 {
		delete(g.grants, victim)
		g.counters.GrantsShed++
	}
}

func (g *Gate) pruneReplayLocked(now time.Time) {
	for k, expiry := range g.replay {
		if !expiry.After(now) {
			delete(g.replay, k)
		}
	}
}

func (g *Gate) shedReplayLocked() {
	var victim [32]byte
	var oldest time.Time
	seen := 0
	for k, expiry := range g.replay {
		if seen == 0 || expiry.Before(oldest) {
			victim, oldest = k, expiry
		}
		seen++
		if seen >= shedSample {
			break
		}
	}
	if seen > 0 {
		delete(g.replay, victim)
		g.counters.ReplayShed++
	}
}

func (g *Gate) pruneLimiterLocked(now time.Time) {
	idle := g.limits.Grace
	for k, tb := range g.limiter {
		if now.Sub(tb.last) > idle {
			delete(g.limiter, k)
		}
	}
}

func (g *Gate) shedLimiterLocked() {
	var victim netip.Addr
	var oldest time.Time
	seen := 0
	for k, tb := range g.limiter {
		if seen == 0 || tb.last.Before(oldest) {
			victim, oldest = k, tb.last
		}
		seen++
		if seen >= shedSample {
			break
		}
	}
	if seen > 0 {
		delete(g.limiter, victim)
		g.counters.RateSourcesShed++
	}
}

// WrapPacketConn returns a net.PacketConn that delivers only datagrams the Gate
// admits. Everything else is consumed and discarded WITHOUT a reply of any
// kind — no ICMP, no error, no timing difference between the rejection reasons.
// This is the property that leaves an active prober with no oracle, and it is
// why every rejection path above returns the same shape of nothing.
//
// The wrapper is transparent in every other respect: it does not resize, copy
// or modify an admitted datagram, so amneziawg-go behind it receives exactly the
// bytes the client sent, S1 prefix and all. Nothing downstream needs to know
// this exists.
func (g *Gate) WrapPacketConn(inner net.PacketConn) net.PacketConn {
	return &gatedPacketConn{PacketConn: inner, gate: g}
}

type gatedPacketConn struct {
	net.PacketConn
	gate *Gate
}

func (c *gatedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		src, ok := addrPortOf(addr)
		if !ok {
			// An address this wrapper cannot parse cannot be granted or
			// scoped, so there is no safe way to enforce on it. Pass it
			// through: fail open, consistent with the rest of this file. In
			// practice a UDP listener always yields a *net.UDPAddr.
			return n, addr, nil
		}
		if _, admit := c.gate.Consider(src, p[:n]); admit {
			return n, addr, nil
		}
	}
}

func addrPortOf(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		ap := v.AddrPort()
		if !ap.IsValid() {
			return netip.AddrPort{}, false
		}
		return normaliseAddrPort(ap), true
	default:
		ap, err := netip.ParseAddrPort(a.String())
		if err != nil || !ap.IsValid() {
			return netip.AddrPort{}, false
		}
		return normaliseAddrPort(ap), true
	}
}

// normaliseAddrPort unmaps 4-in-6 so that the same client reaching a
// dual-stack listener is one grant rather than two.
func normaliseAddrPort(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
