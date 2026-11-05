package gateway

import (
	"errors"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
)

// Defaults for the token index.
//
// The reasoning for every one of these is in the handoff document
// (WINN3_GATEWAY_TABLE_20260808.md, “the memory decision”); the short version
// is in the comments here so that a reader of the code is not sent away.
const (
	// DefaultInitialWindow is how many tokens a freshly registered session gets
	// before it has proved anything.
	//
	// It is small on purpose. A session exists because a handshake completed,
	// and a handshake completes only for a peer holding the gateway's admission
	// key and a client static key the gateway accepts — but an *enrolled* peer
	// can still open sessions in a loop, and a full window per claimed session
	// is exactly the unbounded-precomputation lever we refuse to hand over. 32
	// tokens is enough to carry the post-quantum ratchet exchange and the first
	// packets; anything more has to be earned.
	DefaultInitialWindow = 32

	// DefaultMaxWindow is the ceiling a session can grow to.
	//
	// core's DefaultTokenWindow is 1024. This is 256, and the difference is the
	// memory decision: 1024 tokens per session buys reordering tolerance of 511
	// packets — `size/2 − 1`, not `size/2`, because the force-advance rule
	// retires the low edge to `counter − half + 1`; see Entry.consumeLocked —
	// which no real path needs, and costs four times the index. At 256 the
	// tolerance is 127, measured at the cliff by the network-realism lane. What
	// 1024 does buy that 256 does not is survival of a longer consecutive loss
	// burst (§6.10) — and a 256-packet consecutive burst is already an outage
	// that the driver's liveness timer must handle anyway.
	DefaultMaxWindow = 256

	// DefaultMinWindow is the floor under memory pressure. Below this the window
	// stops being a reordering tolerance at all.
	DefaultMinWindow = core.MinTokenWindow

	// DefaultMaxSessions caps the number of live sessions.
	DefaultMaxSessions = 10000

	// DefaultMaxSessionsPerClient stops one enrolled subscriber occupying the
	// whole table. Real clients need more than one because a migration or a
	// rekey can briefly overlap; they do not need many.
	DefaultMaxSessionsPerClient = 4

	// DefaultShards is the number of index shards. Tokens are PRF outputs, so
	// sharding on the leading byte is exactly uniform and costs no hashing.
	DefaultShards = 64
)

// Defaults for the admission work budget. These meter the *expensive*
// rejection path — the one that un-whitens a body and computes an HMAC — so
// that an unauthenticated flood cannot buy an unbounded share of the gateway's
// CPU. They do not meter established sessions, which dispatch through the token
// index and are unaffected by any flood.
const (
	DefaultAdmissionRate  = 20000 // verifications per second, gateway-wide
	DefaultAdmissionBurst = 20000
	DefaultSourceRate     = 20 // verifications per second, per source cell
	DefaultSourceBurst    = 40
	DefaultSourceCells    = 4096
)

// DefaultIdleTimeout is how long a session may go without opening a message
// before it becomes eligible for eviction. It is deliberately longer than any
// keepalive interval the session driver uses.
const DefaultIdleTimeout = 5 * time.Minute

// Errors. Every one of these is reported to the gateway's own caller and to
// nobody else. None of them ever becomes a byte on the wire.
var (
	ErrConfig = errors.New("winn3/gateway: invalid configuration")

	// ErrNoRoute means the datagram matched no live token. It is the answer to
	// noise, to a replay of a token already consumed, to a probe, and to a
	// message for a session that has gone. Handle is entitled to try the
	// handshake path on this error and on no other Dispatch error. A corrupted
	// datagram whose token is still live is not this: that is ErrSession.
	ErrNoRoute = errors.New("winn3/gateway: no route for datagram")

	// ErrThrottled is not returned by any function in this package. Handle
	// counts the condition in Stats().Throttled and returns KindDropped. The
	// sentinel exists so an operator-facing wrapper could wrap it; collapsing
	// it into ErrNoRoute on the wire is still required — throttling is silence.
	ErrThrottled = errors.New("winn3/gateway: admission budget exhausted")

	// ErrCapacity means the table refused to take on a new session. The peer
	// learns nothing: the handshake simply goes unanswered.
	ErrCapacity = errors.New("winn3/gateway: table at capacity")

	ErrClosed = errors.New("winn3/gateway: table is closed")

	// ErrSession means a live token matched and Open/OpenAt then refused.
	// Dispatch returns it for that case. Handle must not treat it as a miss:
	// falling through would spend the admission budget on a token copied off
	// the wire. On the wire it is still silence.
	ErrSession = errors.New("winn3/gateway: session refused the message")
)

// Config is the gateway table's operating envelope.
//
// Every limit here has a defined behaviour at its boundary, and none of them is
// a panic. A gateway that runs out of memory is a gateway that stopped serving
// the people who depend on it, so the limits are chosen to be reached and
// survived rather than to be theoretical.
type Config struct {
	// InitialWindow, MaxWindow and MinWindow bound the per-session forward
	// token window. Zero means the corresponding default.
	InitialWindow int
	MaxWindow     int
	MinWindow     int

	// TokenBudget caps the total number of indexed tokens across all sessions,
	// which is the gateway's memory bill in the units it is actually spent in.
	// Zero means MaxSessions * MaxWindow, i.e. no independent constraint.
	//
	// When the budget is reached, windows stop growing. That is the whole
	// degradation: sessions keep working with a smaller reordering tolerance,
	// which costs retransmission on a reordering path and nothing at all on an
	// orderly one.
	TokenBudget int

	// MaxSessions caps live sessions; MaxSessionsPerClient caps them per client
	// static key. Zero means the defaults.
	MaxSessions          int
	MaxSessionsPerClient int

	// Shards is the token index shard count, rounded up to a power of two and
	// capped at 256 (a token has 256 possible leading bytes). Zero means
	// DefaultShards.
	Shards int

	// IdleTimeout is how long a session may be silent before eviction may
	// reclaim it. Zero means DefaultIdleTimeout.
	IdleTimeout time.Duration

	// EvictOnAdmit allows Register to reclaim the idlest session when the table
	// is full. It defaults to on: refusing a new client because an abandoned
	// session is holding a slot is the wrong trade for a censorship-
	// circumvention tunnel, where the client that cannot connect is a person.
	// Set DisableEvictOnAdmit to turn it off.
	DisableEvictOnAdmit bool

	// Admission work budget. Zero means the defaults. A negative value means
	// unmetered, which is only ever right in a test, and New refuses it unless
	// the config opted in through allowUnmetered.
	AdmissionRate  int
	AdmissionBurst int
	SourceRate     int
	SourceBurst    int
	SourceCells    int

	// allowUnmetered opts this config into the negative-means-unmetered
	// encoding described above.
	//
	// It is unexported on purpose, and that is the whole mechanism:
	// encoding/json, the YAML decoders and every other reflective decoder can
	// only reach exported fields, so a configuration that arrived from disk or
	// from the control plane cannot set it at any depth. A negative rate in
	// such a configuration is therefore a refusal rather than a silently
	// disabled gateway-wide DoS meter, while a test inside this package sets
	// the field directly and keeps per-field granularity.
	allowUnmetered bool

	// PathMTU is deliberately NOT a field of Config, and that absence is the
	// mechanism. Config is the operating envelope of the token table, which has
	// no opinion about the path MTU; the path MTU is a claim the gateway front
	// door must make, so New takes it as a required argument and refuses a value
	// below MinPathMTUForInnerIPv6 (including zero) or beyond the notice's
	// ceiling (maxPathMTUNoticeValue) rather than defaulting it.
	//
	// A gateway that could be constructed without stating a number would emit no
	// path-MTU notice and hand every client a session with no mismatch check at
	// all — the fail-open half of silent-refusal #3, reopened. Keeping the field
	// out of Config makes omission a compile error; refusing zero at New makes a
	// value that is only "unset at runtime" a construction error, and refusing a
	// value the notice cannot state closes the same hole at the high end. Either
	// alone could be walked around by a caller who ignores errors; together they
	// are the difference between "documented not to" and "cannot".
	//
	// Now supplies the clock. Nil means time.Now. Injected rather than reached
	// for, so that every test in this package is deterministic and there is no
	// sleep anywhere in them.
	Now func() time.Time
}

// MinPathMTUForInnerIPv6 is the narrowest path MTU this gateway will serve.
//
// 1280–1420 is a 141-value DEAD ZONE. A session there resolves, bootstraps and
// carries — and can never promote, because the inner interface MTU it implies
// falls below the 1280-byte floor RFC 8200 requires of any link carrying IPv6
// and the kernel refuses the interface outright: ipv6_add_dev() returns -EINVAL.
// That is the KERNEL's refusal, not one platform's, and desktop Linux has it
// too.
//
// 1421 is where it ends: 1280 + 29 bytes of v3 overhead + 112 for the widest
// class a full migration plan may reach (TLS over IPv6). It is the value
// carrier.NewPlanFloor(_, ClassUDP, ClassTCP, ClassTLS).MinPathMTUForInnerIPv6
// computes, and winn3/driver.NewSizing refuses below the PLAN-AWARE form of it,
// which is the same number for the shipping plan and lower for a narrower one.
//
// This package cannot be plan-aware — a dispatch library holds no migration
// plan — so it takes the conservative constant. A gateway is the end whose
// claim every client must match, so serving a dead-zone claim would drag every
// agreeing client into the dead zone with it. Refusing at the door is cheaper
// than diagnosing that.
//
// It is also the floor below which New refuses construction outright: a
// gateway at any value in [0, 1420] — including zero, the old "make no claim"
// — is unconstructable. See checkPathMTU.
const MinPathMTUForInnerIPv6 = 1421

func (c Config) initialWindow() int {
	if c.InitialWindow == 0 {
		return DefaultInitialWindow
	}
	return c.InitialWindow
}

func (c Config) maxWindow() int {
	if c.MaxWindow == 0 {
		return DefaultMaxWindow
	}
	return c.MaxWindow
}

func (c Config) minWindow() int {
	if c.MinWindow == 0 {
		return DefaultMinWindow
	}
	return c.MinWindow
}

func (c Config) maxSessions() int {
	if c.MaxSessions == 0 {
		return DefaultMaxSessions
	}
	return c.MaxSessions
}

func (c Config) maxPerClient() int {
	if c.MaxSessionsPerClient == 0 {
		return DefaultMaxSessionsPerClient
	}
	return c.MaxSessionsPerClient
}

func (c Config) tokenBudget() int {
	if c.TokenBudget == 0 {
		return c.maxSessions() * c.maxWindow()
	}
	return c.TokenBudget
}

func (c Config) idleTimeout() time.Duration {
	if c.IdleTimeout == 0 {
		return DefaultIdleTimeout
	}
	return c.IdleTimeout
}

func (c Config) shards() int {
	n := c.Shards
	if n == 0 {
		n = DefaultShards
	}
	if n > 256 {
		n = 256
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

func (c Config) clock() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

// validate rejects a configuration that cannot work, rather than letting it
// half-work at three in the morning.
func (c Config) validate() error {
	if c.initialWindow() < c.minWindow() {
		return errWrap(ErrConfig, "initial window %d is below the minimum %d", c.initialWindow(), c.minWindow())
	}
	if c.maxWindow() < c.initialWindow() {
		return errWrap(ErrConfig, "max window %d is below the initial window %d", c.maxWindow(), c.initialWindow())
	}
	if c.minWindow() < core.MinTokenWindow {
		return errWrap(ErrConfig, "min window %d is below core's floor %d", c.minWindow(), core.MinTokenWindow)
	}
	if c.maxWindow() > core.MaxTokenWindow {
		return errWrap(ErrConfig, "max window %d is above core's ceiling %d", c.maxWindow(), core.MaxTokenWindow)
	}
	if c.maxSessions() < 1 {
		return errWrap(ErrConfig, "max sessions %d must be positive", c.maxSessions())
	}
	if c.maxPerClient() < 1 {
		return errWrap(ErrConfig, "max sessions per client %d must be positive", c.maxPerClient())
	}
	if c.tokenBudget() < c.initialWindow() {
		return errWrap(ErrConfig, "token budget %d cannot seat even one session's initial window %d",
			c.tokenBudget(), c.initialWindow())
	}
	if c.idleTimeout() <= 0 {
		return errWrap(ErrConfig, "idle timeout %s must be positive", c.idleTimeout())
	}
	return nil
}

// checkPathMTU refuses a path MTU this gateway cannot honestly serve.
//
// The check lives in New rather than in Config.validate, because the path MTU
// is not part of the table envelope: it is a REQUIRED argument to New, and it
// is the one value a caller must not be able to omit.
//
// Three families are refused, all of them because they would put a gateway on
// the wire with NO claim — a client talking to it gets no mismatch check at
// all, silent-refusal instance #3 reopened on every client:
//
//   - non-positive values: a zero or negative path MTU is the old "make no
//     claim" escape hatch. This package is wired into no datapath today, so the
//     only thing that made a no-claim gateway safe was that nobody had wired it
//     in yet. A caller that does not know its path MTU must measure it or
//     decide it; passing zero is how the fail-open half of the defect comes
//     back.
//   - values inside the dead zone (MinPathMTUForInnerIPv6's shadow): a session
//     planned there resolves, bootstraps and carries, and can NEVER promote,
//     because the inner interface MTU it implies falls below the IPv6 floor and
//     the kernel refuses the interface. A gateway is the end every client must
//     match, so serving a dead-zone claim drags every agreeing client into the
//     zone with it.
//   - values the notice cannot state (beyond maxPathMTUNoticeValue): the wire
//     record's mtu field is 16 bits, so beyond 0xFFFF the encoder returns no
//     claim at all. Refusing here closes the same fail-open as zero, at the
//     other end of the range, so that "every gateway this package constructs
//     states a number" is true for every input, not just the obvious ones.
//
// Each family gets a different message, so the three cases read differently to
// an operator rather than collapsing into one "bad number" refusal.
func checkPathMTU(pathMTU int) error {
	switch {
	case pathMTU <= 0:
		return errWrap(ErrConfig, "path MTU is %d: a gateway must state the path MTU it planned "+
			"at, and a zero or negative value makes no claim at all — a client talking to it "+
			"would get no mismatch check, which is the fail-open half of silent-refusal #3. "+
			"Measure it or decide it; passing 0 is how that defect reopens. Use %d or more (the "+
			"fleet default is %d)", pathMTU, MinPathMTUForInnerIPv6, carrier.DefaultPathMTU)
	case pathMTU > maxPathMTUNoticeValue:
		return errWrap(ErrConfig,
			"path MTU %d cannot be stated: the wire notice's mtu field is a 16-bit big-endian "+
				"integer, so %d is the largest claim a gateway can make, and a gateway that "+
				"emitted no notice would give every client no mismatch check — the fail-open "+
				"half of silent-refusal #3. Choose a value in [%d, %d]",
			pathMTU, maxPathMTUNoticeValue, MinPathMTUForInnerIPv6, maxPathMTUNoticeValue)
	case pathMTU < MinPathMTUForInnerIPv6:
		return errWrap(ErrConfig,
			"path MTU %d is inside the %d-%d dead zone: a session planned there resolves, "+
				"bootstraps and carries, and can NEVER promote, because the inner interface "+
				"MTU it implies is below the %d-byte floor RFC 8200 requires of a link "+
				"carrying IPv6 and ipv6_add_dev() returns -EINVAL. A gateway is the end every "+
				"client must match, so serving this claim takes every agreeing client into the "+
				"dead zone with it. Use %d or more (the fleet default is %d)",
			pathMTU, minDeadZonePathMTU, MinPathMTUForInnerIPv6-1, minDeadZonePathMTU,
			MinPathMTUForInnerIPv6, carrier.DefaultPathMTU)
	}
	return nil
}

// minDeadZonePathMTU is the low edge of the dead zone, and it is RFC 8200's
// floor rather than a number of this package's own: below it nothing carries
// IPv6 anywhere, inner or outer, so the zone cannot start lower.
const minDeadZonePathMTU = 1280

// maxPathMTUNoticeValue is the largest path MTU a gateway can honestly state.
//
// The wire notice's mtu field is a 16-bit big-endian integer (see
// session.pathMTUNoticeSize), so the largest value session.EncodePathMTUNotice
// can emit is 0xFFFF, and anything larger makes it return nil — a "no claim".
// A constructed gateway whose notice is nil emits nothing and hands every
// client no mismatch check at all: the fail-open half of silent-refusal #3,
// exactly as if zero had been accepted. New refuses it here, which is what
// makes the same contract true at both ends of this package — zero says "makes
// no claim" and is a construction error, and a value the notice cannot state
// is also a construction error, because both would put a no-claim gateway on
// the wire.
const maxPathMTUNoticeValue = 0xFFFF
