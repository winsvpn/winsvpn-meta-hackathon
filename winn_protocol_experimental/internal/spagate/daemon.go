package spagate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/internal/knock"
)

// Counters are the daemon's operator-visible metrics. Every field is a coarse
// count. Nothing here is derived from a key, and no client address is retained.
type Counters struct {
	// Received counts datagrams read from the knock socket.
	Received atomic.Uint64

	// Accepted counts knocks that passed every check in knock.Gate.
	Accepted atomic.Uint64

	// Rejected counts knocks that did not, broken out by the reason strings
	// internal/knock already defines (length, rate_limited, unauthenticated,
	// replay, capacity). Deliberately NOT distinguishable on the wire - see
	// internal/knock's package doc - only here, on the operator's side.
	RejectedLength          atomic.Uint64
	RejectedRateLimited     atomic.Uint64
	RejectedUnauthenticated atomic.Uint64
	RejectedReplay          atomic.Uint64
	// RejectedCapacity counts knocks that verified but could not be recorded
	// in knock.Gate's userspace authorized-address map. That map is not the
	// authority here (the kernel set is); handle still grants at the kernel.
	// A nonzero value means the userspace map hit MaxAuthorized.
	RejectedCapacity atomic.Uint64
	// RejectedUnclassified counts a rejection reason this package does not
	// yet name, so a new knock.Reason cannot vanish from operator metrics.
	RejectedUnclassified atomic.Uint64

	// EnforceFailed counts accepted knocks whose firewall update failed. This
	// is the one that matters operationally: a nonzero value means a client
	// holding a valid key was verified and still did not get in.
	EnforceFailed atomic.Uint64

	// Unattributable counts datagrams whose source address could not be parsed.
	Unattributable atomic.Uint64
}

// Snapshot is a plain-value copy of Counters for logging.
type Snapshot struct {
	Received                uint64
	Accepted                uint64
	RejectedLength          uint64
	RejectedRateLimited     uint64
	RejectedUnauthenticated uint64
	RejectedReplay          uint64
	RejectedCapacity        uint64
	RejectedUnclassified    uint64
	EnforceFailed           uint64
	Unattributable          uint64
}

// Snapshot reads every counter. It is not atomic across fields; it is for
// logging, not for accounting.
func (c *Counters) Snapshot() Snapshot {
	return Snapshot{
		Received:                c.Received.Load(),
		Accepted:                c.Accepted.Load(),
		RejectedLength:          c.RejectedLength.Load(),
		RejectedRateLimited:     c.RejectedRateLimited.Load(),
		RejectedUnauthenticated: c.RejectedUnauthenticated.Load(),
		RejectedReplay:          c.RejectedReplay.Load(),
		RejectedCapacity:        c.RejectedCapacity.Load(),
		RejectedUnclassified:    c.RejectedUnclassified.Load(),
		EnforceFailed:           c.EnforceFailed.Load(),
		Unattributable:          c.Unattributable.Load(),
	}
}

// String renders a snapshot as one log line.
func (s Snapshot) String() string {
	return fmt.Sprintf(
		"received=%d accepted=%d rejected_length=%d rejected_rate_limited=%d "+
			"rejected_unauthenticated=%d rejected_replay=%d rejected_capacity=%d "+
			"rejected_unclassified=%d enforce_failed=%d unattributable=%d",
		s.Received, s.Accepted, s.RejectedLength, s.RejectedRateLimited,
		s.RejectedUnauthenticated, s.RejectedReplay, s.RejectedCapacity,
		s.RejectedUnclassified, s.EnforceFailed, s.Unattributable,
	)
}

// Config configures a Daemon.
type Config struct {
	// Gate is the verifier. Required. It is built by the caller so that this
	// package never loads or holds a key file itself.
	Gate *knock.Gate

	// Enforcer applies a grant. Required.
	Enforcer Enforcer

	// PacketSize is the exact knock size, which must match every client's.
	// Required, and it must equal the size the Gate was built with.
	PacketSize int

	// Grace is how long an authorization lasts without renewal. The kernel
	// re-arms it on every matching packet (see the package doc), so this is a
	// silence timeout, not a session limit. Zero uses DefaultGrace.
	Grace time.Duration

	// Log receives operator-facing lines. It must never be given packet
	// contents or anything derived from a key. Nil discards.
	Log func(format string, args ...any)

	// Counters is where this daemon records its metrics. It is supplied rather
	// than created because the caller also wires it into the Gate's rejection
	// hook (see NewGateFor), and because Counters holds atomics and therefore
	// must never be copied. Nil allocates a fresh one.
	Counters *Counters

	// Now supplies the current time for the rate-limiter lockout detector. Nil
	// uses time.Now. It exists so a test can drive RateLimitedLockoutWindow
	// without sleeping for it; production must leave it nil.
	Now func() time.Time
}

// DefaultGrace is how long an authorization survives SILENCE.
//
// It is deliberately far longer than internal/knock's own 90s default, and the
// reason is the asymmetry of the two failure costs. In knock's in-process Gate
// an expired window costs the client one extra knock on its next dial. Here it
// costs a firewall lockout: the source must re-knock before ANY packet is
// admitted, and a client that cannot knock - a sleeping phone, or any direct
// AmneziaWG client, which has no knock path at all - simply cannot come back.
//
// The window slides in-kernel on every admitted packet, so this bounds silence,
// not session length. Thirty minutes is chosen to comfortably exceed a mobile
// doze interval and the 120s nf_conntrack_udp_timeout_stream that would
// otherwise be the only thing holding a sleeping client's flow open.
const DefaultGrace = 30 * time.Minute

// Daemon reads knock datagrams from one socket and turns each verified knock
// into a firewall authorization.
//
// It never writes to the socket. internal/knock's central property is that
// success and failure are indistinguishable on the wire, and a daemon that
// answered anything - even an ICMP-triggering close - would destroy it.
type Daemon struct {
	gate       *knock.Gate
	enforcer   Enforcer
	packetSize int
	grace      time.Duration
	log        func(format string, args ...any)

	// Counters is exported so a caller can log or export it. It is a pointer
	// because it holds atomics, which must never be copied.
	Counters *Counters

	// consecutiveFailures counts enforcement failures with no success between
	// them. See MaxConsecutiveEnforceFailures.
	consecutiveFailures atomic.Int64

	// consecutiveRateLimited counts rate-limited rejections with no accepted
	// knock between them, and rateLimitedSince is when that streak began, as
	// Unix nanoseconds (0 when no streak is running). Together they detect the
	// rate-limiter exhaustion lockout. See MaxConsecutiveRateLimited.
	consecutiveRateLimited atomic.Int64
	rateLimitedSince       atomic.Int64

	// now supplies the current time. See Config.Now.
	now func() time.Time
}

// New builds a Daemon.
func New(cfg Config) (*Daemon, error) {
	if cfg.Gate == nil {
		return nil, errors.New("spagate: a knock.Gate is required")
	}
	if cfg.Enforcer == nil {
		return nil, errors.New("spagate: an Enforcer is required")
	}
	if cfg.PacketSize < knock.HeaderSize {
		return nil, fmt.Errorf(
			"spagate: packet size %d is smaller than the %d-byte knock header",
			cfg.PacketSize, knock.HeaderSize,
		)
	}
	grace := cfg.Grace
	if grace <= 0 {
		grace = DefaultGrace
	}
	logFunc := cfg.Log
	if logFunc == nil {
		logFunc = func(string, ...any) {}
	}
	counters := cfg.Counters
	if counters == nil {
		counters = new(Counters)
	}
	nowFunc := cfg.Now
	if nowFunc == nil {
		nowFunc = time.Now
	}
	return &Daemon{
		gate:       cfg.Gate,
		enforcer:   cfg.Enforcer,
		packetSize: cfg.PacketSize,
		grace:      grace,
		log:        logFunc,
		Counters:   counters,
		now:        nowFunc,
	}, nil
}

// Serve reads from conn until ctx is cancelled or conn returns a permanent
// error. It takes ownership of nothing: the caller opens and closes conn.
//
// A read error that is temporary is logged and retried; a permanent one ends
// the loop and is returned. Ending the loop is the correct response, not a
// silent degradation: a daemon that stopped verifying while its firewall rules
// stayed installed would lock every user out, so it must exit and let the
// supervisor's ExecStopPost tear the gate down. See the package doc.
func (d *Daemon) Serve(ctx context.Context, conn net.PacketConn) error {
	// One byte larger than a knock, so an oversized datagram arrives as
	// packetSize+1 bytes and fails the exact-length check instead of being
	// silently truncated to a valid length by the kernel.
	buffer := make([]byte, d.packetSize+1)

	// Unblock the read when the context is cancelled.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Now())
		case <-done:
		}
	}()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("spagate: reading knock socket: %w", err)
		}
		d.Counters.Received.Add(1)
		ip, ok := addrIP(addr)
		if !ok {
			d.Counters.Unattributable.Add(1)
			continue
		}
		if err := d.handle(ctx, buffer[:n], ip); err != nil {
			return err
		}
	}
}

// MaxConsecutiveEnforceFailures is how many verified knocks may fail to reach
// the firewall, with none succeeding, before Serve gives up and exits.
//
// # Why exiting is the correct response
//
// Every safety mechanism protecting this gate watches DAEMON LIVENESS:
// systemd's Restart, ExecStopPost, and the watchdog's `systemctl is-active`
// check. None of them watches whether authorization actually WORKS. A daemon
// whose every Authorize fails - an nft too old to parse the renewal
// transaction, a table deleted underneath it, CAP_NET_ADMIN dropped - is
// perfectly healthy by all three measures while admitting nobody. That is a
// silent total lockout that no existing mechanism can see.
//
// Exiting converts it into the one condition they all handle: the daemon is
// gone, so ExecStopPost reverts the gate and the node fails OPEN. A few
// consecutive failures with no successes in between is deliberately chosen over
// a ratio, so that a single transient failure alongside working traffic never
// takes the gate down.
const MaxConsecutiveEnforceFailures = 3

// ErrEnforcementBroken is returned by Serve when enforcement is failing
// consistently. See MaxConsecutiveEnforceFailures.
var ErrEnforcementBroken = errors.New(
	"spagate: every verified knock is failing to reach the firewall; exiting so " +
		"the supervisor tears the gate down rather than leaving a healthy daemon " +
		"that authorizes nobody",
)

// MaxConsecutiveRateLimited and RateLimitedLockoutWindow together detect the
// rate-limiter exhaustion lockout described in the Limits type doc.
//
// # The hole this closes
//
// MaxConsecutiveEnforceFailures catches "healthy daemon that authorizes
// nobody" only when Authorize is REACHED and fails. Rate-limiter exhaustion
// walks around it: the limiter runs BEFORE verification, so a full limiter
// table means Consider returns false, Authorize is never called, no
// enforcement failure is ever recorded, and the daemon stays perfectly healthy
// by every measure the design relies on. systemd sees a running unit,
// ExecStopPost does not fire, and the watchdog's `systemctl is-active` check
// passes -- while the gate stays installed and admits nobody. The one counter
// that reveals it, RejectedRateLimited, was incremented and acted on by
// nothing.
//
// # Why BOTH a count and a window, and why they are so much larger than
// MaxConsecutiveEnforceFailures
//
// Rate limiting is NORMAL under load. A busy CGNAT egress can legitimately
// exhaust its own bucket while every other source is authorized fine, so the
// count-of-3 shape that is correct for enforcement failures would here be a
// remotely triggerable daemon kill: any source able to spend its own bucket
// could take the gate down. Both bounds must therefore be crossed:
//
//   - the COUNT filters a quiet node, where a handful of rate-limited
//     background scans trickling in overnight with no real users must not look
//     like a lockout;
//   - the WINDOW filters a busy moment, where a burst of rate-limited packets
//     is ordinary and resolves on its own.
//
// Crossing both means: for five unbroken minutes, thousands of knocks were
// refused before verification and not one single knock was accepted. On a node
// admitting anyone at all, one successful knock resets the streak. That is a
// lockout, not load.
//
// # Why exiting is still the right response
//
// Identical to the enforcement case: exiting hands the condition to
// ExecStopPost, which reverts the gate, and the node fails OPEN. This does let
// an off-path spoofer turn SPA off by flooding -- but the Limits type doc
// already records that such a spoofer "hands an off-path spoofer a way to hold
// SPA off deterministically" via the OOM path, so this adds no new property.
// It replaces a SILENT lockout of every legitimate user with a LOGGED
// fail-open, which is the trade this daemon's whole safety model already makes
// everywhere else.
const (
	MaxConsecutiveRateLimited = 2000
	RateLimitedLockoutWindow  = 5 * time.Minute
)

// ErrRateLimiterExhausted is returned by Serve when the pre-verification rate
// limiter appears to be locking every source out. See MaxConsecutiveRateLimited.
var ErrRateLimiterExhausted = errors.New(
	"spagate: the pre-verification rate limiter has refused every knock for a " +
		"sustained period with none accepted, which is the exhaustion lockout; " +
		"exiting so the supervisor tears the gate down rather than leaving a " +
		"healthy daemon that authorizes nobody",
)

// handle runs one datagram through the gate and, if it authorizes, through the
// enforcer. It reports whether enforcement is now broken badly enough to stop.
func (d *Daemon) handle(ctx context.Context, data []byte, ip netip.Addr) error {
	// Read the rate-limit and capacity counters across Consider so the
	// rejection REASON is available here. The Gate reports reasons only
	// through the OnKnockRejected hook, which NewGateFor wires to these same
	// Counters; a caller who wires the Gate to a different Counters simply
	// never trips the detector, which fails safe rather than firing spuriously.
	rateLimitedBefore := d.Counters.RejectedRateLimited.Load()
	capacityBefore := d.Counters.RejectedCapacity.Load()
	if !d.gate.Consider(data, ip) {
		// The Gate's OnKnockRejected hook already counted the reason; nothing
		// is logged per rejected packet, because a public UDP port receives
		// enough background noise that per-packet logging is itself a
		// denial-of-service vector against the node's disk.
		if d.Counters.RejectedRateLimited.Load() != rateLimitedBefore {
			return d.noteRateLimited()
		}
		if d.Counters.RejectedCapacity.Load() != capacityBefore {
			// Verified knock; Gate.grant failed because the userspace
			// authorized-address map is full. That map is not the authority
			// here — the kernel set is — so dropping the grant would silently
			// lock out a client holding a valid key while every watchdog
			// still sees a healthy daemon. Authorize anyway.
			d.log("spa: verified knock from %s; userspace authorization map is "+
				"full, granting at the kernel", ip)
			return d.grantVerified(ctx, ip)
		}
		// A rejection for any OTHER reason - wrong length, bad tag, replay - is
		// background noise and deliberately does NOT reset the streak. Only an
		// accepted knock proves the limiter is still admitting new sources.
		return nil
	}
	return d.grantVerified(ctx, ip)
}

// grantVerified records an accepted knock and asks the enforcer to open the
// kernel set. Shared by the Consider-true path and the ReasonCapacity path,
// which is a verified knock that the userspace map could not record.
func (d *Daemon) grantVerified(ctx context.Context, ip netip.Addr) error {
	d.Counters.Accepted.Add(1)
	// One accepted knock is proof the limiter is not locking sources out.
	d.consecutiveRateLimited.Store(0)
	d.rateLimitedSince.Store(0)
	if err := d.enforcer.Authorize(ctx, ip, d.grace); err != nil {
		d.Counters.EnforceFailed.Add(1)
		failures := d.consecutiveFailures.Add(1)
		// Logged with the address but never the packet: an operator debugging
		// "my key works but I cannot connect" needs to see this line, and the
		// address is already in their connection log.
		d.log("spa: verified knock from %s but firewall update FAILED (%d in a "+
			"row): %v", ip, failures, err)
		if failures >= MaxConsecutiveEnforceFailures {
			return fmt.Errorf("%w: last error: %v", ErrEnforcementBroken, err)
		}
		return nil
	}
	d.consecutiveFailures.Store(0)
	d.log("spa: authorized %s for %s", ip, d.grace)
	return nil
}

// noteRateLimited records one rate-limited rejection and reports whether the
// limiter now looks exhausted. See MaxConsecutiveRateLimited.
func (d *Daemon) noteRateLimited() error {
	streak := d.consecutiveRateLimited.Add(1)
	now := d.now()
	// CompareAndSwap rather than a plain Store: only the packet that STARTS a
	// streak sets its origin, so a concurrent reader cannot push the start
	// forward and hold the window permanently open.
	d.rateLimitedSince.CompareAndSwap(0, now.UnixNano())
	if streak < MaxConsecutiveRateLimited {
		return nil
	}
	since := d.rateLimitedSince.Load()
	if since == 0 || now.Sub(time.Unix(0, since)) < RateLimitedLockoutWindow {
		return nil
	}
	return fmt.Errorf(
		"%w: %d consecutive rate-limited rejections over %s with none accepted",
		ErrRateLimiterExhausted, streak, now.Sub(time.Unix(0, since)).Truncate(time.Second),
	)
}

// Limits are the anti-abuse bounds the Gate enforces before verification.
//
// # Why these are exposed here at all
//
// internal/knock chose its defaults for a context that fails CLOSED, where
// exhausting a bound costs a client one retry. This daemon runs in a context
// that must fail OPEN, where exhausting a bound denies authorization to every
// new source while the daemon stays healthy - so no watchdog fires, no revert
// happens, and the node looks fine. Inheriting those defaults silently was a
// real defect, and these knobs exist so an operator can size them for a node
// rather than discovering them in an incident.
//
// # The limitation you cannot tune away
//
// The rate limiter is keyed by source address and runs BEFORE verification, so
// it is driven by unauthenticated, trivially spoofable input. An attacker who
// floods more than MaxSources distinct forged source addresses inside the
// limiter's idle window can fill the table and deny authorization to every new
// legitimate source, at negligible cost and with no reply ever sent back.
// Raising MaxSources raises the attacker's cost linearly ONLY up to the
// process's memory ceiling. Past that the failure changes character rather than
// getting harder: each tracked source costs roughly 128 bytes of heap (measured
// ~11.3 MB heap / ~26.8 MB RSS at 100k, ~134 MB / ~166 MB at 1<<20), so a
// MaxSources set above what MemoryMax allows means the daemon is OOM-killed
// before the bound is reached. That is still fail-open rather than a lockout,
// but it hands an off-path spoofer a way to hold SPA off deterministically,
// since StartLimitBurst will settle the unit in a failed state. Keep MaxSources
// and the unit's MemoryMax sized together.
//
// Removing the attack properly means making internal/ratelimit shed load
// instead of refusing new keys when full, which is a change to a shared,
// reviewed component and is deliberately NOT made here.
//
// # CGNAT
//
// Authorization is scoped by source address, so one Myanmar CGNAT egress
// address is ONE bucket shared by everyone behind it. knock's defaults (burst
// 4, 6/minute) are far too tight for that population; the defaults below are
// widened accordingly. This trades a larger unauthenticated verification budget
// per address for not locking out a shared egress, which is the right trade
// when HMAC verification is the cheap operation it is here.
type Limits struct {
	// RateBurst and RatePerMinute bound how often ONE source address may reach
	// signature verification.
	RateBurst     int
	RatePerMinute float64

	// MaxSources bounds how many distinct source addresses the rate limiter
	// tracks. See the type doc: this is the exhaustion surface.
	MaxSources int

	// MaxAuthorized bounds the Gate's own authorization map. The kernel's set
	// is the real authority, so this mostly bounds memory.
	MaxAuthorized int

	// MaxReplayNonces bounds the replay cache.
	MaxReplayNonces int
}

// DefaultLimits are sized for a public node fronting a CGNAT-heavy population,
// not for knock's original fail-closed context. See Limits.
func DefaultLimits() Limits {
	return Limits{
		// A CGNAT egress is ONE source address for every subscriber behind it,
		// and knockdial re-knocks before every dial, so the per-address rate has
		// to cover the whole population's reconnect rate, not one user's. Size
		// it as (subscribers behind the egress) / (mean reconnect interval): a
		// 5,000-subscriber egress reconnecting every 300s needs ~1,000/min.
		// Rejection happens BEFORE verification and is silent, so undersizing
		// this locks those users out with no diagnostic anywhere.
		RateBurst:     120,
		RatePerMinute: 1200,

		// NOT raised to 1<<20. At ~128 bytes of heap per tracked source that is
		// ~134 MB heap / ~166 MB RSS, which exceeds the unit's MemoryMax and
		// gets the daemon OOM-killed before the limit is ever reached -- turning
		// a bounded refusal into a remotely triggerable process kill. 1<<18 is
		// ~33 MB heap / ~42 MB RSS against a 512 MB ceiling. See Limits.
		MaxSources:      1 << 18,
		MaxAuthorized:   1 << 18,
		MaxReplayNonces: 1 << 18,
	}
}

// countRejection increments the operator counter for one knock.Gate rejection
// reason. Unknown reasons go to RejectedUnclassified so they cannot vanish.
func countRejection(counters *Counters, reason string) {
	if counters == nil {
		return
	}
	switch reason {
	case knock.ReasonLength:
		counters.RejectedLength.Add(1)
	case knock.ReasonRateLimited:
		counters.RejectedRateLimited.Add(1)
	case knock.ReasonUnauthenticated:
		counters.RejectedUnauthenticated.Add(1)
	case knock.ReasonReplay:
		counters.RejectedReplay.Add(1)
	case knock.ReasonCapacity:
		counters.RejectedCapacity.Add(1)
	default:
		counters.RejectedUnclassified.Add(1)
	}
}

// NewGateFor builds the knock.Gate this daemon needs, wiring the rejection
// reasons internal/knock reports into counters.
//
// keys is the deployment's SPA key list, most current first, exactly as
// knock.NewGate documents; the caller loads it with knock.LoadKeysFromFile and
// this function never sees a path.
func NewGateFor(
	keys [][]byte, packetSize int, options knock.Options,
	grace time.Duration, limits Limits, counters *Counters,
) (*knock.Gate, error) {
	return knock.NewGate(keys, packetSize, knock.GateConfig{
		Options: options,
		// The Gate keeps its own authorization map with this grace, which the
		// daemon does not consult - the kernel's set is the authority. Passing
		// it anyway keeps the two windows nominally identical so a future
		// reader is not led to believe they diverge on purpose.
		Grace:                grace,
		RateCapacity:         limits.RateBurst,
		RatePerMinute:        limits.RatePerMinute,
		RateMaxSources:       limits.MaxSources,
		MaxAuthorizedSources: limits.MaxAuthorized,
		ReplayMaxNonces:      limits.MaxReplayNonces,
		OnKnockRejected: func(_ netip.Addr, reason string) {
			countRejection(counters, reason)
		},
	})
}

// addrIP extracts the bare source IP, normalising IPv4-in-IPv6 so one client is
// never tracked under two keys. It mirrors internal/knock's own addrIP, which
// is unexported there.
func addrIP(a net.Addr) (netip.Addr, bool) {
	if udp, ok := a.(*net.UDPAddr); ok {
		addr, ok := netip.AddrFromSlice(udp.IP)
		if !ok {
			return netip.Addr{}, false
		}
		return addr.Unmap(), true
	}
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
