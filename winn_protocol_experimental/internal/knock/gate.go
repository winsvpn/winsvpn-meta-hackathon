package knock

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/ratelimit"
)

// Rejection reasons passed to GateConfig.OnKnockRejected and used internally
// for TCP's parallel path. These are for operator-side metrics only - see
// the package doc on why nothing distinguishes them on the wire.
const (
	ReasonLength          = "length"
	ReasonRateLimited     = "rate_limited"
	ReasonUnauthenticated = "unauthenticated"
	ReasonReplay          = "replay"
	ReasonTCPUnauthorized = "tcp_unauthorized"
	// ReasonCapacity is a verified knock that could not be recorded because
	// the authorized-address set is at MaxAuthorizedSources with no expired
	// entry to prune. Distinct from ReasonReplay: the nonce was fresh.
	ReasonCapacity = "capacity"
)

const (
	// defaultGrace is 2x this tree's shipped quic.Config.MaxIdleTimeout
	// (45s, see cmd/winn-carrier-server/main.go). See GateConfig.Grace.
	defaultGrace = 90 * time.Second

	defaultRateCapacity    = 4
	defaultRatePerMinute   = 6
	defaultRateMaxSources  = 100000
	defaultReplayMaxNonces = 100000
	defaultAuthMaxSources  = 100000
)

// GateConfig configures a Gate. Every field has a documented default; the
// zero value is usable.
type GateConfig struct {
	Options

	// Grace is how long a source address stays authorized after the most
	// recently observed knock or forwarded datagram/connection from it - a
	// sliding window, not a one-shot timer. It should comfortably exceed
	// this deployment's quic.Config.MaxIdleTimeout: every forwarded
	// datagram slides the window forward, so an active session's own
	// keepalives (KeepAlivePeriod, well under MaxIdleTimeout) keep it
	// authorized indefinitely, and only a source that has gone quieter than
	// a live connection ever would falls back out. Zero uses the default
	// (90s).
	Grace time.Duration

	// RateCapacity/RatePerMinute/RateMaxSources bound how often a single
	// source address may even reach signature verification, and how many
	// distinct source addresses are tracked at all. Zero uses the defaults
	// (burst 4, refill 6/minute, 100,000 tracked sources). Reuses
	// internal/ratelimit.BucketLimiter unchanged - the same type
	// cmd/winn-carrier-server already uses for post-auth establishment
	// limiting.
	RateCapacity   int
	RatePerMinute  float64
	RateMaxSources int

	// ReplayMaxNonces bounds the replay cache. Zero uses the default
	// (100,000).
	ReplayMaxNonces int

	// MaxAuthorizedSources bounds the authorized-address set. Zero uses the
	// default (100,000).
	MaxAuthorizedSources int

	// Now is a clock override for tests. Nil uses time.Now.
	Now func() time.Time

	// OnKnockAccepted and OnKnockRejected are optional metrics hooks. They
	// must not block and must never be given the packet contents or any
	// value derived from a key - only the coarse reason and the source
	// address, which the operator's own connection log already has.
	OnKnockAccepted func(netip.Addr)
	OnKnockRejected func(addr netip.Addr, reason string)
}

// Gate is the stateful server-side half of this package: it decides, per
// source address, whether a listener may hand a caller anything at all.
//
// # Scoping, and why it is deliberately coarse
//
// Authorization is keyed by source IP address alone, never by port and
// never by full 4-tuple. Two things force this:
//
//   - A client behind CGNAT, or behind a NAT that rebinds ports per flow,
//     will knock from one source port and connect from another. Scoping by
//     4-tuple would make the knock useless for exactly the population -
//     Myanmar mobile networks - this mechanism exists for.
//   - A client's knock and its connection attempt can be reordered in
//     flight; UDP gives no ordering guarantee. IP-scoping tolerates this
//     without the client needing to wait for an acknowledgement that, by
//     design (see the package doc), never comes.
//
// The consequence, stated plainly: everyone sharing a CGNAT IP with a
// legitimate user gets that IP's authorization window too, and can reach
// the listeners behind this gate - but not the tunnel itself, since
// carrierauth and mTLS are unchanged and still gate that. This is the same
// tradeoff every IP-scoped SPA or unlisted-bridge-line design makes; it is
// not a defect specific to this implementation.
//
// # Sliding window, and the connection-migration limitation
//
// Grace slides forward on every forwarded datagram or accepted connection,
// so a live, ordinarily-behaving session never ages out of authorization.
// What this v1 does NOT support: a client whose public IP changes mid
// session (a real event for mobile users, see internal/mobility) will have
// its migration probe from the new address dropped as an unrecognized
// knock attempt, because the new address was never authorized. It must
// knock again from the new address before migrating. Recognizing an
// established QUIC connection ID from a new source address, independent of
// IP-authorization state, is the natural v2 and is left to whoever owns
// internal/mobility - it needs that package's connection-ID handling, which
// this package deliberately does not depend on.
//
// # Concurrency
//
// A Gate is safe for concurrent use, including concurrently wrapping
// multiple listeners (e.g. the H2 TCP listener and the H3 UDP socket) so
// that one knock authorizes both, which is the point: a client should never
// need to know in advance which carrier will win the race.
type Gate struct {
	packetSize int
	options    Options
	keys       [][]byte
	grace      time.Duration
	now        func() time.Time

	limiter *ratelimit.BucketLimiter

	mu           sync.Mutex
	authorized   map[netip.Addr]time.Time
	authMax      int
	replay       map[[NonceSize]byte]time.Time
	replayMax    int
	replayExpiry time.Duration

	onAccepted func(netip.Addr)
	onRejected func(netip.Addr, string)
}

// NewGate builds a Gate. keys lists every SPA key currently accepted, most
// current first (see Verify's doc on rotation overlap). packetSize must
// match what Build is told to produce - see the package doc on why that has
// no safe default.
func NewGate(keys [][]byte, packetSize int, cfg GateConfig) (*Gate, error) {
	if len(keys) == 0 {
		return nil, errNoKeys
	}
	for _, key := range keys {
		if err := validateKey(key); err != nil {
			return nil, err
		}
	}
	if packetSize < HeaderSize {
		return nil, fmt.Errorf(
			"knock: packetSize %d is smaller than the %d-byte header",
			packetSize, HeaderSize,
		)
	}
	if packetSize > maxSafePacketSize {
		return nil, errPacketTooBig
	}
	resolvedOptions, err := cfg.Options.resolve()
	if err != nil {
		return nil, err
	}

	grace := cfg.Grace
	if grace <= 0 {
		grace = defaultGrace
	}
	rateCapacity := cfg.RateCapacity
	if rateCapacity <= 0 {
		rateCapacity = defaultRateCapacity
	}
	ratePerMinute := cfg.RatePerMinute
	if ratePerMinute <= 0 {
		ratePerMinute = defaultRatePerMinute
	}
	rateMaxSources := cfg.RateMaxSources
	if rateMaxSources <= 0 {
		rateMaxSources = defaultRateMaxSources
	}
	replayMax := cfg.ReplayMaxNonces
	if replayMax <= 0 {
		replayMax = defaultReplayMaxNonces
	}
	authMax := cfg.MaxAuthorizedSources
	if authMax <= 0 {
		authMax = defaultAuthMaxSources
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	limiter, err := ratelimit.New(rateCapacity, ratePerMinute, rateMaxSources)
	if err != nil {
		return nil, fmt.Errorf("knock: rate limiter: %w", err)
	}

	keysCopy := make([][]byte, len(keys))
	for i, k := range keys {
		keysCopy[i] = append([]byte(nil), k...)
	}

	// The replay cache only ever needs to remember a nonce for as long as
	// it could still verify: the full skew window on each side, plus one
	// bucket of margin.
	replayExpiry := 2*resolvedOptions.MaxSkew + resolvedOptions.BucketWindow

	return &Gate{
		packetSize:   packetSize,
		options:      resolvedOptions,
		keys:         keysCopy,
		grace:        grace,
		now:          now,
		limiter:      limiter,
		authorized:   make(map[netip.Addr]time.Time),
		authMax:      authMax,
		replay:       make(map[[NonceSize]byte]time.Time),
		replayMax:    replayMax,
		replayExpiry: replayExpiry,
		onAccepted:   cfg.OnKnockAccepted,
		onRejected:   cfg.OnKnockRejected,
	}, nil
}

// Authorized reports whether ip is currently authorized, without extending
// its window. Exposed for metrics and tests; WrapPacketConn and
// WrapListener are what production code should use to act on this.
func (g *Gate) Authorized(ip netip.Addr) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.authorizedLocked(ip, g.now())
}

func (g *Gate) authorizedLocked(ip netip.Addr, now time.Time) bool {
	expiry, ok := g.authorized[ip]
	if !ok {
		return false
	}
	if !expiry.After(now) {
		delete(g.authorized, ip)
		return false
	}
	return true
}

// authorizeIfKnown reports whether ip is currently authorized and, only if
// so, slides its window forward. It never grants authorization to a source
// that does not already have it - that only happens via a successful knock,
// through grant.
func (g *Gate) authorizeIfKnown(ip netip.Addr, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.authorizedLocked(ip, now) {
		return false
	}
	g.authorized[ip] = now.Add(g.grace)
	return true
}

// grant authorizes ip, bounded by authMax. Called only from a successful
// knock. It returns false without modifying the set when a new source
// cannot be added because the set is full of unexpired entries; the
// caller must treat that as a rejection, not a success.
func (g *Gate) grant(ip netip.Addr, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.authorized[ip]; !exists && len(g.authorized) >= g.authMax {
		g.pruneAuthorizedLocked(now)
		if len(g.authorized) >= g.authMax {
			return false // fail closed: drop the grant rather than grow unbounded
		}
	}
	g.authorized[ip] = now.Add(g.grace)
	return true
}

func (g *Gate) pruneAuthorizedLocked(now time.Time) {
	for ip, expiry := range g.authorized {
		if !expiry.After(now) {
			delete(g.authorized, ip)
		}
	}
}

// markNonceUsed reports whether nonce is fresh (true) or a replay (false).
// A fresh nonce is recorded as used; a replay is left alone (nothing to
// update).
func (g *Gate) markNonceUsed(nonce [NonceSize]byte, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if existing, ok := g.replay[nonce]; ok && existing.After(now) {
		return false
	}
	if len(g.replay) >= g.replayMax {
		g.pruneReplayLocked(now)
		if len(g.replay) >= g.replayMax {
			return false // fail closed
		}
	}
	g.replay[nonce] = now.Add(g.replayExpiry)
	return true
}

func (g *Gate) pruneReplayLocked(now time.Time) {
	for nonce, expiry := range g.replay {
		if !expiry.After(now) {
			delete(g.replay, nonce)
		}
	}
}

func (g *Gate) reject(ip netip.Addr, reason string) {
	if g.onRejected != nil {
		g.onRejected(ip, reason)
	}
}

// considerKnock processes one datagram from an address not currently
// authorized. It always consumes the datagram - the return value is for
// tests and internal bookkeeping only; nothing is ever written back to the
// network from here, on any path, which is the fail-closed property this
// whole package exists to provide.
func (g *Gate) considerKnock(data []byte, ip netip.Addr, now time.Time) bool {
	if len(data) != g.packetSize {
		g.reject(ip, ReasonLength)
		return false
	}
	if allowed, _ := g.limiter.Allow(ip.String()); !allowed {
		g.reject(ip, ReasonRateLimited)
		return false
	}
	nonce, _, err := Verify(data, g.keys, now, g.options)
	if err != nil {
		g.reject(ip, ReasonUnauthenticated)
		return false
	}
	if !g.markNonceUsed(nonce, now) {
		g.reject(ip, ReasonReplay)
		return false
	}
	if !g.grant(ip, now) {
		// Nonce is already recorded. Retrying this datagram cannot help;
		// the client must knock again once a slot is free.
		g.reject(ip, ReasonCapacity)
		return false
	}
	if g.onAccepted != nil {
		g.onAccepted(ip)
	}
	return true
}

// Consider processes one datagram from ip as a knock attempt and reports
// whether it authorized that source. It is the same decision WrapPacketConn
// makes internally, exposed for a caller that enforces authorization
// somewhere other than a Go listener - notably cmd/winn-knockd, which
// translates a grant into an nftables set element so the kernel can gate a
// port this process does not own (udp/9110's AmneziaWG, Xray's tcp/80 and
// tcp/443) rather than one it is wrapping.
//
// Everything the wrapped path does, this does, in the same order and with
// the same fail-closed behaviour: exact-length check before any crypto,
// per-source rate limit before verification, HMAC verification against every
// configured key across the freshness window, then replay rejection. Nothing
// is ever written back to the network from here, on any path - that remains
// this package's central property, and a caller must not answer either.
//
// It deliberately does NOT consult the existing authorization state first,
// the way gatedPacketConn.ReadFrom does: a re-knock from an already
// authorized source is fully verified again and, on success, re-fires
// OnKnockAccepted so the caller can slide its own enforcement window
// forward. The replay cache still rejects a captured copy of the same
// datagram, so this cannot be used to refresh a grant without the key.
func (g *Gate) Consider(data []byte, ip netip.Addr) bool {
	return g.considerKnock(data, ip, g.now())
}

// WrapPacketConn returns a net.PacketConn suitable for handing to
// quic-go/http3.Server.Serve (not ListenAndServe - the caller must bind the
// socket itself so it can be wrapped before quic-go ever reads from it,
// exactly as internal/carrier's own supplied-socket dialers already require
// callers to do on the client side).
//
// Every inbound datagram from a source not currently authorized is treated
// as a knock attempt and is always consumed: accepted or rejected, nothing
// is ever written back and nothing is ever handed to the caller's ReadFrom.
// A datagram from an authorized source is passed through untouched and
// slides that source's authorization window forward. WriteTo and everything
// else delegate to inner unmodified.
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
		ip, ok := addrIP(addr)
		if !ok {
			continue // cannot attribute a source; drop and keep reading
		}
		now := c.gate.now()
		if c.gate.authorizeIfKnown(ip, now) {
			return n, addr, nil
		}
		c.gate.considerKnock(p[:n], ip, now)
		// Either outcome, the datagram was consumed, not forwarded. Loop for
		// the next one - ReadFrom must never return here, or an
		// unauthorized peer's datagram would reach quic-go after all.
	}
}

// WrapListener returns a net.Listener suitable for handing to
// http.Server.ServeTLS (or any other Accept-loop consumer).
//
// TCP has a hard limit this method does not try to hide: the kernel
// completes the SYN/ACK for any inbound connection before this process's
// Accept() is even called, so a raw SYN scan still sees an open port. What
// this removes is everything after that: a connection from an unauthorized
// source is accepted (unavoidably) and immediately closed with zero bytes
// written - no TLS handshake, no cover certificate, nothing an active
// prober can fingerprint from the application layer. A connection from an
// authorized source is handed to the caller unmodified and slides that
// source's window forward exactly like a forwarded UDP datagram does.
func (g *Gate) WrapListener(inner net.Listener) net.Listener {
	return &gatedListener{Listener: inner, gate: g}
}

type gatedListener struct {
	net.Listener
	gate *Gate
}

func (l *gatedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip, ok := addrIP(conn.RemoteAddr())
		now := l.gate.now()
		if ok && l.gate.authorizeIfKnown(ip, now) {
			return conn, nil
		}
		_ = conn.Close()
		if ok {
			l.gate.reject(ip, ReasonTCPUnauthorized)
		}
	}
}

// addrIP extracts the bare IP address (never the port) from a net.Addr,
// normalizing IPv4-in-IPv6 representations so the same client is never
// tracked under two different keys.
func addrIP(a net.Addr) (netip.Addr, bool) {
	var ipBytes net.IP
	switch v := a.(type) {
	case *net.UDPAddr:
		ipBytes = v.IP
	case *net.TCPAddr:
		ipBytes = v.IP
	default:
		host, _, err := net.SplitHostPort(a.String())
		if err != nil {
			return netip.Addr{}, false
		}
		parsed, err := netip.ParseAddr(host)
		if err != nil {
			return netip.Addr{}, false
		}
		return parsed.Unmap(), true
	}
	addr, ok := netip.AddrFromSlice(ipBytes)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
