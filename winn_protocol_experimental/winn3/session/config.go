package session

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/dualsign"
)

// Clock is the driver's only source of time.
//
// It is an interface rather than a call to time.Now so that every timing policy
// in this package — the silence timer, the probe schedule, the rekey interval,
// the handshake backoff — is deterministic under test. A timing defence that
// cannot be tested deterministically is a timing defence nobody will believe,
// and this package's whole reason for existing is that the shipped stack's
// timing was measured and found to be a metronome.
//
// It is deliberately NOT a timer. There is no After, no Tick and no Sleep. The
// driver reports NextDeadline and the caller decides how to wait.
type Clock interface {
	Now() time.Time
}

// SystemClock reads the wall clock. It is the production Clock.
type SystemClock struct{}

// Now implements Clock.
func (SystemClock) Now() time.Time { return time.Now() }

// Defaults. Every one of these is a policy number, and every policy number that
// controls when a packet is emitted is a RANGE rather than a value.
const (
	// IPv6MinimumLinkMTU is the floor RFC 8200 requires of every link that
	// carries IPv6. It is the worst case a path can present without something
	// already being broken, so it is the conservative planning number for the
	// OUTER packet.
	IPv6MinimumLinkMTU = 1280

	// Carrier header overheads, for MaxMessageSizeForPath. MaxMessageSize bounds
	// the Winn3 MESSAGE; the carrier then wraps it, and it is the wrapped packet
	// that has to fit the path.
	CarrierOverheadUDPIPv6 = 40 + 8
	CarrierOverheadUDPIPv4 = 20 + 8

	// DefaultMaxMessageSize is the on-wire ceiling for one Winn3 MESSAGE when
	// the carrier does not say otherwise.
	//
	// It is IPv6MinimumLinkMTU minus CarrierOverheadUDPIPv6, and the subtraction
	// is the entire point. An earlier version of this constant was 1280 with a
	// comment claiming that made a message unfragmentable at the IPv6 minimum
	// MTU. That was one layer off and simply false: 1280 bytes of message inside
	// a UDP/IPv6 datagram is a 1328-byte packet, 48 bytes over the floor the
	// comment invoked. A fragmented Winn3 message is itself a distinctive
	// fingerprint and fragments are widely dropped, so the claim mattered.
	//
	// What this value guarantees, precisely: over a UDP/IPv6 carrier on a path
	// at the IPv6 minimum, a full-size Winn3 message produces an unfragmented
	// packet. Over UDP/IPv4 it is 20 bytes conservative. Over a carrier with
	// different overhead — TLS-over-TCP, HTTP/3 — it guarantees nothing, and
	// that carrier MUST call MaxMessageSizeForPath rather than take this default.
	//
	// What it does NOT guarantee, stated because the number invites the
	// assumption: it does not make the tunnel able to carry inner IPv6. See
	// MinPathMTUForInnerIPv6.
	DefaultMaxMessageSize = IPv6MinimumLinkMTU - CarrierOverheadUDPIPv6

	// Silence-timer draw. The old fixed keepalive was 25.000 s; 25 s sits inside
	// this support on purpose. Excluding it would create a new tell — "this flow
	// is never quiet for about 25 seconds" is as much a signature as "this flow
	// is quiet for exactly 25 seconds".
	DefaultSilenceMin  = 5 * time.Second
	DefaultSilenceMean = 15 * time.Second
	DefaultSilenceMax  = 45 * time.Second

	// Liveness probe spacing, used only once inbound has gone quiet.
	DefaultProbeMin  = 3 * time.Second
	DefaultProbeMean = 8 * time.Second
	DefaultProbeMax  = 20 * time.Second

	// DefaultMaxLostProbes is how many consecutive unanswered PING probes
	// declare the peer unreachable. Four probes at the default spacing is
	// roughly half a minute typical and eighty seconds worst case.
	DefaultMaxLostProbes = 4

	// Rekey time trigger. Jittered, never fixed: a fixed rekey interval is the
	// 25.000-second metronome again, only slower.
	DefaultRekeyIntervalMin  = 5 * time.Minute
	DefaultRekeyIntervalMean = 15 * time.Minute
	DefaultRekeyIntervalMax  = 45 * time.Minute

	// DefaultRekeyAfterBytes is the byte-volume trigger.
	DefaultRekeyAfterBytes uint64 = 1 << 32

	// DefaultRekeyTimeout bounds an in-band rekey exchange. On expiry the
	// session closes and the fallback is a full handshake, which is also what a
	// fresh session looks like, so the failure mode adds no new observable.
	DefaultRekeyTimeout = 15 * time.Second

	// Handshake and PQ retransmission: exponential with FULL jitter and a hard
	// attempt cap, answering the measured 24-retry failure directly.
	DefaultRetryBase     = 500 * time.Millisecond
	DefaultRetryCap      = 8 * time.Second
	DefaultRetryAttempts = 5

	// DefaultRTTPrior is the retry floor before this connect has measured its
	// own handshake round trip, when the host has no measurement to this
	// gateway (Retry.RTTPrior zero). The fleet measures 30 to 300 ms from
	// Myanmar; cellular jitter needs the headroom. MaxRTTPrior clamps a stale
	// or inflated prior: it is data, not a misconfiguration.
	DefaultRTTPrior = 400 * time.Millisecond
	MaxRTTPrior     = time.Second

	// DefaultBucketCount is how many length buckets a PadBucket session draws.
	DefaultBucketCount = 6
)

// Errors. Every one is LOCAL, in the same sense as the core's: nothing here is
// ever turned into an observable response to a peer. A driver that answered an
// unauthenticated message with anything at all would reopen the probe oracle
// the whole design exists to close.
var (
	ErrConfig           = errors.New("winn3/session: invalid configuration")
	ErrState            = errors.New("winn3/session: operation not valid in this state")
	ErrClosed           = errors.New("winn3/session: session is closed")
	ErrInnerTooLarge    = errors.New("winn3/session: inner packet exceeds the carrier message size")
	ErrQueueFull        = errors.New("winn3/session: send queue is full")
	ErrPeerUnreachable  = errors.New("winn3/session: peer did not answer liveness probes")
	ErrCarrierExhausted = errors.New("winn3/session: handshake attempts exhausted on this carrier")
	ErrProtocol         = errors.New("winn3/session: peer violated the frame protocol")
	ErrRekeyFailed      = errors.New("winn3/session: in-band rekey did not complete")
	// ErrRekeyUnconfirmed is F-03's fail-loud verdict: this end installed the
	// rekeyed epoch by sealing the REKEY_ACK and the peer never confirmed it
	// within RekeyTimeout. Distinct from ErrRekeyFailed, which stays the
	// initiator's own rekeyEnd verdict.
	ErrRekeyUnconfirmed = errors.New("winn3/session: rekey committed locally but the peer never confirmed the new epoch")
	ErrPQFailed         = errors.New("winn3/session: post-quantum ratchet did not complete")
	ErrDualAuthFailed   = errors.New("winn3/session: dual-signature attestation failed")

	// ErrPathMTUMismatch is silent-refusal instance #3 made loud. The two ends
	// planned at different path MTUs, which produces a session that establishes
	// and then black-holes every full-size packet while both ends report the
	// gate carrying. See winn3/session/pathmtu.go.
	ErrPathMTUMismatch = errors.New("winn3/session: the two ends planned at different path MTUs")

	// ErrHandshakeUnauthenticated is ErrCarrierExhausted's sibling and exists
	// only so that the two can be told apart.
	//
	// ErrCarrierExhausted says "change the carrier class", which is the right
	// advice for a censor blocking UDP and the WRONG advice for a typo in a
	// key. Measured on 2026-08-09, a wrong gateway static key, a mismatched
	// admission secret, a divergent gateway id and a gateway that refuses
	// admission produced byte-identical client outcomes to a total block:
	// ErrCarrierExhausted with NeedsCarrierChange() true, in all five cases.
	//
	// This error is returned instead when messages DID arrive and none of them
	// could be authenticated. It does not set NeedsCarrierChange, because
	// changing carrier class cannot help a peer that is answering.
	//
	// It names the observation and not the cause on purpose: "nothing that
	// arrived could be opened" is a fact this end measured. A credential
	// mismatch is the likeliest reading of it and a mangling middlebox is
	// another, and the error text says so rather than picking one.
	ErrHandshakeUnauthenticated = errors.New("winn3/session: the handshake budget was spent on messages that could not be authenticated")

	// ErrReclaimed is the local verdict a session ends with when a host's
	// session table retires it under pressure to admit another peer, or because
	// a newer generation of the same peer superseded it. It never becomes a byte
	// on the wire: RetireIfQuiet terminates the session directly, without a
	// CLOSE, exactly as an immediate no-session teardown does. The host that
	// drove the retirement is the reader; the peer sees only the silence every
	// other refusal path already produces.
	ErrReclaimed = errors.New("winn3/session: session retired by the host to reclaim its slot")
)

// Draw is a truncated-exponential draw: a memoryless interval with a floor and
// a ceiling.
//
// Exponential because it is memoryless — an observer learns nothing about the
// next interval from the last one, which is precisely the property a fixed
// interval maximally lacks. Truncated because an unbounded draw would sometimes
// leave a NAT binding to expire and sometimes emit two packets a millisecond
// apart, and neither is acceptable.
//
// The truncation is honest about its own cost: it bounds the support, so an
// observer with a long capture can estimate Min and Max. §4.4 of the design says
// so and this package does not claim otherwise. What it does claim, and holds
// with a test, is that there is no spike.
type Draw struct {
	Min  time.Duration
	Mean time.Duration
	Max  time.Duration
}

func (d Draw) orDefault(min, mean, max time.Duration) Draw {
	if d.Min == 0 {
		d.Min = min
	}
	if d.Mean == 0 {
		d.Mean = mean
	}
	if d.Max == 0 {
		d.Max = max
	}
	return d
}

func (d Draw) validate(what string) error {
	if d.Min <= 0 {
		return wrap(ErrConfig, "%s min is %s, must be positive", what, d.Min)
	}
	if d.Max <= d.Min {
		return wrap(ErrConfig, "%s max %s is not above min %s; a single value is a metronome", what, d.Max, d.Min)
	}
	if d.Mean <= 0 {
		return wrap(ErrConfig, "%s mean is %s, must be positive", what, d.Mean)
	}
	return nil
}

// Retry is exponential backoff with full jitter and a hard attempt cap.
//
// Full jitter, not "exponential plus a little noise": the delay is uniform on
// [0, backoff]. Decorrelated retries across a fleet matter as much as the
// backoff itself, because a synchronised retry cadence is a fleet-wide timing
// signature even when each individual delay is growing.
//
// Attempts is a cap, not a suggestion. On reaching it the driver stops and
// reports that the CARRIER CLASS must change. The measured failure this answers
// is 24 retries into a wholesale UDP block: a retry schedule that never
// abandons a dead transport is not resilience, it is a beacon with a
// recognisable cadence.
type Retry struct {
	Base     time.Duration
	Cap      time.Duration
	Attempts int

	// FreshAfter is how many byte-identical retransmissions precede a genuinely
	// new handshake with a fresh ephemeral. Zero, the default, means none: every
	// pre-session retry is a fresh initiation. Negative is refused.
	//
	// The two failure cases are indistinguishable to the client. A
	// byte-identical copy is right when the INITIATION was lost, and useless
	// when the RESPONSE was lost: the gateway's replay cache refuses the copy and
	// stays silent, correctly, because answering a replayed initiation would
	// turn one captured packet into a permanent gateway detector. A fresh
	// initiation serves both cases; with the RTTPrior floor under the first
	// retry it no longer races a response that is merely in flight.
	FreshAfter int

	// RTTPrior is the host's prior for the handshake round trip to this
	// gateway: Stats.HandshakeRTT of the last established connect to the same
	// gateway identity, never a probe. It floors every retry until this
	// connect's own response opens and its measured RTT replaces it. Zero
	// means DefaultRTTPrior; above MaxRTTPrior, or above Cap/Attempts, it is
	// clamped; negative is refused. It is a floor under a full-jitter draw and
	// is not itself jittered: the fire lands uniformly on (prior, prior +
	// window). Each unanswered pre-session fire doubles the next pre-session
	// floor up to the same clamp (see Driver.retryFloor).
	RTTPrior time.Duration
}

func (r Retry) orDefault() Retry {
	if r.Base == 0 {
		r.Base = DefaultRetryBase
	}
	if r.Cap == 0 {
		r.Cap = DefaultRetryCap
	}
	if r.Attempts == 0 {
		r.Attempts = DefaultRetryAttempts
	}
	if r.RTTPrior == 0 {
		r.RTTPrior = DefaultRTTPrior
	}
	if r.RTTPrior > MaxRTTPrior {
		r.RTTPrior = MaxRTTPrior
	}
	// The floors of a full ladder must fit in the one Cap of slack
	// handshakeBudget leaves above the draws, so that a connect always ends by
	// exhausting its ladder before connectBy. A prior above Cap/Attempts is
	// clamped to it, as data, never refused (CT-1 Amendment 3, Q4). At the
	// defaults that is 1.6 s, above MaxRTTPrior, so nothing changes there.
	if r.Attempts > 0 && r.RTTPrior > r.Cap/time.Duration(r.Attempts) {
		r.RTTPrior = r.Cap / time.Duration(r.Attempts)
	}
	return r
}

// floorCap is the ceiling of the doubled pre-session floor (Karn backoff):
// MaxRTTPrior, or Cap/Attempts when that is smaller, the same bound the prior
// itself is clamped to.
func (r Retry) floorCap() time.Duration {
	c := MaxRTTPrior
	if r.Attempts > 0 && r.Cap/time.Duration(r.Attempts) < c {
		c = r.Cap / time.Duration(r.Attempts)
	}
	return c
}

// DualAuthConfig provisions the dual-signature session attestation. See
// docs/DUAL_SIGNATURE_SPEC.md for the wire design and the backward-compat
// matrix.
type DualAuthConfig struct {
	Expected       bool
	Ed25519Private []byte // 64-byte ed25519 private key (server; signs)
	MLDSA65Seed    []byte // 32-byte ML-DSA-65 seed (server; signs)
	Ed25519Public  []byte // 32-byte peer ed25519 public key (client; verifies)
	MLDSA65Public  []byte // dualsign.MLDSA65PublicKeySize peer key (client)
}

// validate enforces role-appropriate, exactly-sized dual-auth configuration so
// a half-provisioned node or a half-specified client fails at construction, not
// mid-session.
func (d DualAuthConfig) validate() error {
	edSigPinned := len(d.Ed25519Private) == dualsign.Ed25519PrivateKeySize
	mlSeedPinned := len(d.MLDSA65Seed) == dualsign.MLDSA65SeedSize
	hasServer := len(d.Ed25519Private) > 0 || len(d.MLDSA65Seed) > 0
	if (len(d.Ed25519Private) > 0) != (len(d.MLDSA65Seed) > 0) {
		return fmt.Errorf("dualauth: configure both the ed25519 private key and the mldsa65 seed, or neither")
	}
	if len(d.Ed25519Private) > 0 && !edSigPinned {
		return fmt.Errorf("dualauth: ed25519 private key must be %d bytes", dualsign.Ed25519PrivateKeySize)
	}
	if len(d.MLDSA65Seed) > 0 && !mlSeedPinned {
		return fmt.Errorf("dualauth: mldsa65 seed must be %d bytes", dualsign.MLDSA65SeedSize)
	}
	if d.Expected && hasServer {
		return errors.New("dualauth: a client that expects the attestation configures public keys, not signing keys")
	}
	if d.Expected {
		if len(d.Ed25519Public) != dualsign.Ed25519PublicKeySize {
			return fmt.Errorf("dualauth: expected peer ed25519 public key must be %d bytes", dualsign.Ed25519PublicKeySize)
		}
		if len(d.MLDSA65Public) != dualsign.MLDSA65PublicKeySize {
			return fmt.Errorf("dualauth: expected peer mldsa65 public key must be %d bytes", dualsign.MLDSA65PublicKeySize)
		}
	}
	return nil
}

func (r Retry) validate() error {
	if r.Base <= 0 {
		return wrap(ErrConfig, "retry base is %s, must be positive", r.Base)
	}
	if r.Cap < r.Base {
		return wrap(ErrConfig, "retry cap %s is below base %s", r.Cap, r.Base)
	}
	if r.Attempts < 1 {
		return wrap(ErrConfig, "retry attempts is %d, must be at least 1", r.Attempts)
	}
	if r.RTTPrior < 0 {
		return wrap(ErrConfig, "retry RTT prior is %s, must not be negative", r.RTTPrior)
	}
	if r.FreshAfter < 0 {
		return wrap(ErrConfig, "retry fresh-after is %d, must not be negative", r.FreshAfter)
	}
	return nil
}

// MimicFunc is the PadMimic hook. The carrier knows what its cover protocol
// looks like; this package does not, and does not pretend to.
//
// It is handed the minimum on-wire length this message can take and the
// carrier's ceiling, and returns a target length in [minLen, maxLen]. A return
// outside that range is clamped, because a padding policy must never be able to
// make a message unsendable.
type MimicFunc func(minLen, maxLen int, rnd io.Reader) int

// Config configures one session driver.
type Config struct {
	// Core is handed to winn3/core for the handshake. Its Rand and Now are
	// filled in from this Config's Rand and Clock when they are nil, so that a
	// deterministic test configures one clock and one entropy source, not three.
	Core core.Config

	// GatewayStatic is the gateway's static X25519 public key, learned from the
	// ML-DSA-65-signed descriptor the control plane already ships. Client only.
	GatewayStatic *core.PublicKey

	// Static is this end's static X25519 key pair.
	Static *core.StaticKey

	// Accept decides whether a client static key may open a session. Gateway
	// only, and required there: the core refuses a responder without one,
	// deliberately, because "authenticated" and "authorised" are different
	// questions and a gateway that conflates them serves anyone who ever held a
	// key.
	//
	// Ignored when Responder is set: that Responder already holds the callback
	// it was built with.
	Accept core.AcceptFunc

	// Responder, when non-nil, is the handshake responder this gateway session
	// ADOPTS instead of constructing its own from Core/Static/Accept. Gateway
	// only; NewClient ignores it.
	//
	// # Why this seam exists, and why it is a security field rather than a
	// performance one
	//
	// A *core.Responder owns the handshake replay cache, and core documents
	// that cache as being "per gateway rather than per session". A host that
	// builds one Responder per PEER therefore partitions the cache by peer, and
	// a partitioned replay cache is not a replay cache: an attacker who
	// captured one real initiation can replay it from a second transport
	// address, land in a fresh empty partition, and be answered. That is a
	// remote gateway detector, and it defeats the property every other part of
	// this protocol's silence design is built to provide.
	//
	// cmd/winn3-gateway is exactly such a host — it demultiplexes on
	// netip.AddrPort and calls driver.NewGateway per address — and it had that
	// defect until this field existed. winn3/gateway.Gateway does not, because
	// gateway.New takes one *core.Responder for the whole front door.
	//
	// So: any host that runs more than one gateway-side Driver against the SAME
	// static key and admission key set MUST build one Responder with
	// NewSharedResponder and set it here on every Driver. core.Responder is
	// documented safe for concurrent use, including concurrently with
	// SetAdmissionKeys, so sharing costs nothing but a pointer.
	//
	// It does NOT cost a roaming client anything. The replay cache is keyed on
	// SHA-256 of the recovered initiation body, and that body carries a
	// per-handshake ephemeral public key. A client that rebinds to a new
	// address and re-initiates sends a FRESH ephemeral, which hashes
	// differently and is admitted. Only a bit-identical replay is refused,
	// which is precisely the attack and precisely not the roam.
	Responder *core.Responder

	// MaxMessageSize is the carrier's on-wire message ceiling. Zero means
	// DefaultMaxMessageSize.
	MaxMessageSize int

	// PathMTU is the PLANNING path MTU this end sized itself at, and it is what
	// the two ends compare across the handshake. Zero means this end makes no
	// claim and checks none, which is exactly the behaviour this package had
	// before the check existed.
	//
	// It is not used for arithmetic here — MaxMessageSize is already the plan
	// floor, computed once in winn3/driver over every class the session may
	// escalate to. This field carries the INPUT that floor was derived from,
	// because that is the number the far end can meaningfully compare against:
	// two ends on the same path MTU with different migration plans have
	// different message sizes and are both correct, while two ends on different
	// path MTUs are the black hole silent-refusal instance #3 describes.
	//
	// winn3/driver sets it from Sizing.PathMTU and refuses a caller that set it
	// by hand, for the same reason it owns MaxMessageSize: one site, auditable.
	PathMTU int

	// ApplyNegotiatedPathMTU lets refusePathMTUMismatch shrink this end to
	// min(local, peer) when that shrink is safe (see ShrinkToPeerPathMTU)
	// instead of refusing. winn3/driver owns this flag: it is true only when
	// there is no tun, or when tun.Device implements tun.MTUSetter, so a
	// shrink here is always paired with a device MTU clamp before the gate
	// opens. The zero value (false) is the 2026-08-09 loud refusal, which is
	// what every production Device that cannot SetMTU still gets.
	ApplyNegotiatedPathMTU bool

	// Padding selects the length-shaping policy. The zero value is
	// core.PadDefault, which normalise resolves to core.PadBucket, the design's
	// default. Turning length shaping off requires naming core.PadNone.
	Padding core.PaddingPolicy

	// Mimic supplies target lengths under core.PadMimic. Required for it.
	Mimic MimicFunc

	// Buckets is how many boundaries a PadBucket session draws. Zero means
	// DefaultBucketCount.
	Buckets int

	// Silence is the keepalive silence-timer draw.
	Silence Draw

	// Probe is the liveness-probe spacing draw, used once inbound goes quiet.
	Probe Draw

	// MaxLostProbes is how many unanswered probes declare the peer unreachable.
	MaxLostProbes int

	// RekeyInterval is the jittered time trigger for the in-band ratchet.
	RekeyInterval Draw

	// RekeyAfterMessages and RekeyAfterBytes are the volume triggers. Zero means
	// core.RekeyAfterMessages and DefaultRekeyAfterBytes.
	RekeyAfterMessages uint64
	RekeyAfterBytes    uint64

	// RekeyTimeout bounds one in-band rekey exchange.
	RekeyTimeout time.Duration

	// Retry is the handshake and PQ-ratchet retransmission schedule.

	// DualAuth carries the dual-signature session attestation configuration
	// (docs/DUAL_SIGNATURE_SPEC.md). Server side: Ed25519Private and
	// MLDSA65Seed, both or neither. Client side: Expected plus both peer
	// public keys.
	DualAuth DualAuthConfig
	Retry    Retry

	// FastPQ allows DATA frames under epoch-0 keys, before the post-quantum
	// ratchet has completed.
	//
	// The default is false, which is StrictPQ: no DATA on the wire until the
	// ML-KEM secret is in the chain. FastPQ saves one round trip and is honestly
	// labelled as accepting that the first RTT lacks post-quantum forward
	// secrecy. Harvest-now-decrypt-later is a live threat, so the default is the
	// slow one.
	//
	// It is incompatible with DualAuth.Expected, and normalise refuses the
	// combination: the dual-signature attestation can only lift the gate AFTER
	// the post-quantum ratchet has completed, which is exactly the epoch-0
	// window FastPQ wants to open for data.
	FastPQ bool

	// SendQueue bounds how many inner packets may wait for the wire. Zero means
	// a small default. A bound is required: an unbounded queue in front of a
	// stalled carrier is a memory exhaustion path.
	SendQueue int

	// Clock is the policy clock. Nil means SystemClock.
	Clock Clock

	// Rand supplies every random draw in this package: bucket boundaries,
	// silence thresholds, probe spacing, backoff jitter, PING tokens. Nil means
	// crypto/rand.Reader.
	//
	// It must not be a predictable generator. An observer who can guess the seed
	// predicts every keepalive, which converts a memoryless schedule back into a
	// metronome that only looks random. TestSessionHasNoTimersOrSockets bans the
	// standard library's non-cryptographic generator from this package's source
	// for the same reason.
	Rand io.Reader
}

// DefaultSendQueue is the send-queue bound when Config.SendQueue is zero.
const DefaultSendQueue = 256

func (c *Config) normalise() error {
	if c.Clock == nil {
		c.Clock = SystemClock{}
	}
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	if c.Core.Rand == nil {
		c.Core.Rand = c.Rand
	}
	if c.Core.Now == nil {
		clk := c.Clock
		c.Core.Now = func() time.Time { return clk.Now() }
	}
	if c.MaxMessageSize == 0 {
		c.MaxMessageSize = DefaultMaxMessageSize
	}
	if c.Buckets == 0 {
		c.Buckets = DefaultBucketCount
	}
	// An omitted policy resolves to the design's default. This is the one
	// defaulted field where getting it wrong is a security regression rather
	// than a performance one, so it is not left to the caller's diligence:
	// driver.Config passes an embedded session.Config straight through, and a
	// host that never mentions padding would otherwise ship PadNone.
	if c.Padding == core.PadDefault {
		c.Padding = core.PadBucket
	}
	if c.MaxLostProbes == 0 {
		c.MaxLostProbes = DefaultMaxLostProbes
	}
	if c.RekeyAfterMessages == 0 {
		c.RekeyAfterMessages = core.RekeyAfterMessages
	}
	if c.RekeyAfterBytes == 0 {
		c.RekeyAfterBytes = DefaultRekeyAfterBytes
	}
	if c.RekeyTimeout == 0 {
		c.RekeyTimeout = DefaultRekeyTimeout
	}
	if c.SendQueue == 0 {
		c.SendQueue = DefaultSendQueue
	}
	c.Silence = c.Silence.orDefault(DefaultSilenceMin, DefaultSilenceMean, DefaultSilenceMax)
	c.Probe = c.Probe.orDefault(DefaultProbeMin, DefaultProbeMean, DefaultProbeMax)
	c.RekeyInterval = c.RekeyInterval.orDefault(DefaultRekeyIntervalMin, DefaultRekeyIntervalMean, DefaultRekeyIntervalMax)
	c.Retry = c.Retry.orDefault()

	if c.Static == nil {
		return wrap(ErrConfig, "a static key is required")
	}
	// The floor is what it takes to seal a single empty PAD frame. Below it the
	// driver could not emit a cover packet, so no timing policy would be
	// expressible at all.
	if floor := core.TransportOverhead() + frameHeaderSize; c.MaxMessageSize < floor {
		return wrap(ErrConfig, "max message size %d is below the %d-byte floor", c.MaxMessageSize, floor)
	}
	if c.MaxMessageSize > core.MaxTransportPayload {
		return wrap(ErrConfig, "max message size %d exceeds %d", c.MaxMessageSize, core.MaxTransportPayload)
	}
	if c.Padding == core.PadMimic && c.Mimic == nil {
		return wrap(ErrConfig, "PadMimic requires a Mimic function")
	}
	if c.Padding > core.PadMimic {
		return wrap(ErrConfig, "padding policy %d is not a policy", c.Padding)
	}
	if c.Buckets < 1 {
		return wrap(ErrConfig, "bucket count %d must be positive", c.Buckets)
	}
	if c.MaxLostProbes < 1 {
		return wrap(ErrConfig, "max lost probes %d must be positive", c.MaxLostProbes)
	}
	if c.SendQueue < 1 {
		return wrap(ErrConfig, "send queue %d must be positive", c.SendQueue)
	}
	if c.RekeyAfterMessages > core.RejectAfterMessages {
		return wrap(ErrConfig, "rekey after %d messages is past the hard ceiling %d", c.RekeyAfterMessages, core.RejectAfterMessages)
	}
	if err := c.Silence.validate("silence"); err != nil {
		return err
	}
	if err := c.Probe.validate("probe"); err != nil {
		return err
	}
	if err := c.RekeyInterval.validate("rekey interval"); err != nil {
		return err
	}
	if err := c.DualAuth.validate(); err != nil {
		return err
	}
	if c.FastPQ && c.DualAuth.Expected {
		return wrap(ErrConfig, "dualauth: FastPQ and DualAuth.Expected are mutually exclusive; "+
			"the attestation can only open the gate after the post-quantum ratchet, "+
			"which is the epoch-0 window FastPQ wants to open for data")
	}
	return c.Retry.validate()
}

// maxPayload is the largest frame stream one message can carry.
func (c *Config) maxPayload() int { return c.MaxMessageSize - core.TransportOverhead() }

// MessageFloor is the smallest Winn3 message this driver will ever emit: the
// transport overhead plus one empty PAD frame. A carrier that cannot move this
// many bytes cannot express a timing policy at all.
func MessageFloor() int { return core.TransportOverhead() + frameHeaderSize }

// MaxMessageSizeForPath converts a measured or assumed path MTU into the
// MaxMessageSize that keeps the carrier's packet unfragmented.
//
// Use it rather than the default whenever the carrier is anything but UDP over
// IPv6, or whenever the path MTU is actually known. The default is a worst-case
// planning number; a real path is usually 1500 and leaving 220 bytes per packet
// on the floor is a real cost on a metered mobile connection.
//
// carrierOverhead is the bytes the carrier adds around the message:
// CarrierOverheadUDPIPv6, CarrierOverheadUDPIPv4, or the carrier's own figure.
// A stream carrier implementing the §4.2 encrypted-length rule adds 18 bytes per
// record on top of its transport headers.
func MaxMessageSizeForPath(pathMTU, carrierOverhead int) int {
	n := pathMTU - carrierOverhead
	if n < MessageFloor() {
		return MessageFloor()
	}
	if n > core.MaxTransportPayload {
		return core.MaxTransportPayload
	}
	return n
}

// InnerMTU is the largest inner IP packet a session with this MaxMessageSize can
// carry, and therefore the MTU the tun layer must configure.
//
// It is exported so the tun lane does not have to re-derive it. Two lanes
// deriving the same number independently is corroboration once; keeping it that
// way is how the two drift apart later.
func InnerMTU(maxMessageSize int) int {
	n := maxMessageSize - core.TransportOverhead() - frameHeaderSize
	if n < 0 {
		return 0
	}
	return n
}

// MinPathMTUForInnerIPv6 is the outer path MTU required before this tunnel can
// carry inner IPv6 at all.
//
// RFC 8200 requires every link carrying IPv6 to offer at least 1280 bytes, and
// InnerMTU has to meet that. The number is worth stating plainly because it is
// easy to assume the wrong thing from DefaultMaxMessageSize: at a 1280-byte
// outer path, inner IPv6 is impossible for ANY tunnel, this one included —
// 1280 bytes of inner packet plus 29 bytes of Winn3 plus the carrier's own
// header cannot fit in 1280. It needs 1357 over UDP/IPv6 or 1337 over UDP/IPv4.
// That is a property of tunnelling, not a defect here, but a caller that wants
// inner IPv6 must check it rather than discover it as a silent black hole.
func MinPathMTUForInnerIPv6(carrierOverhead int) int {
	return IPv6MinimumLinkMTU + core.TransportOverhead() + frameHeaderSize + carrierOverhead
}

// winn3ProtocolVersion is the single spelling of the protocol version a winn/3
// carrier INI section is emitted with.
//
// One constant, one spelling. Hosts that grep for "winn/3" in the emitted
// document see it; a second literal anywhere would be a second fact about the
// same thing, and facts about the same thing that can drift always do.
const winn3ProtocolVersion = "winn/3"

// Carrier is one carrier class name as the migration plan spells it. It is the
// string the emitted `carrier` key carries.
const (
	CarrierUDP = "udp"
	CarrierTCP = "tcp"
	CarrierTLS = "tls"
)

// EmitWinn3INI renders the `[winn/3]` carrier section of a host profile as a
// full INI document, deriving every value from the session Config and the
// carrier it was built over rather than restating a caller's assertion.
//
// carrier names the carrier class in the plan's spelling (CarrierUDP,
// CarrierTCP or CarrierTLS) and stealth marks the cover/obfuscated mode. The
// document spells the three keys the winn/3 carrier contract requires —
// protocol_version, carrier, stealth — followed by the two sizing numbers this
// Config already pinned for exactly that carrier: max_message_size (run through
// this Config's normalisation rules) and inner_mtu (derived from it with
// InnerMTU).
//
// The values are a function of the session, not constants: protocol_version is
// winn3ProtocolVersion, carrier and stealth come from the arguments, and the
// two sizing numbers change when this Config is edited. A caller that changes
// MaxMessageSize and re-emits gets a different email/document, which is the
// point — the emission records the config it actually carries.
func (c *Config) EmitWinn3INI(carrier string, stealth bool) string {
	normalised := *c
	// Validation errors are irrelevant to the emission: the values we read
	// (MaxMessageSize, and InnerMTU off it) are set before any refusal fires.
	_ = normalised.normalise()

	var b strings.Builder
	b.WriteString("[winn/3]\n")
	fmt.Fprintf(&b, "protocol_version=%s\n", winn3ProtocolVersion)
	fmt.Fprintf(&b, "carrier=%s\n", carrier)
	fmt.Fprintf(&b, "stealth=%t\n", stealth)
	fmt.Fprintf(&b, "max_message_size=%d\n", normalised.MaxMessageSize)
	fmt.Fprintf(&b, "inner_mtu=%d\n", InnerMTU(normalised.MaxMessageSize))
	return b.String()
}

// Winn3INISection is the `[winn/3]` carrier section that EmitWinn3INI renders,
// read back into fields by ParseWinn3INI. It is the inverse of the emitter: the
// protocol selection, the carrier, stealth, and the two sizing numbers the
// Config pinned for exactly that carrier.
//
// It is deliberately a SECTION, not a whole Config. The section carries protocol
// selection, carrier, stealth and the two sizing numbers; the Config's keys,
// draws and retry schedule are never written to a host profile and never read
// back from one.
type Winn3INISection struct {
	ProtocolVersion string
	Carrier         string
	Stealth         bool
	MaxMessageSize  int
	InnerMTU        int
}

// ParseWinn3INI is the inverse of EmitWinn3INI: it reads a `[winn/3]` carrier
// section back into fields. It is the parse half of the emit/parse round trip.
//
// It is strict about the two things that would otherwise launder an emitting
// bug into a green: the document must open with the section header, and every
// one of the five keys the emitter writes must be present. A serializer that
// silently stops writing a key therefore fails the round trip here — a missing
// key is an error, not an omitted field — instead of reporting a hidden green.
// The protocol_version must equal winn3ProtocolVersion, and inner_mtu must be
// exactly the derivation of max_message_size, so a drifted or self-inconsistent
// document is refused rather than returned.
func ParseWinn3INI(doc string) (Winn3INISection, error) {
	var s Winn3INISection
	lines := strings.Split(doc, "\n")
	if len(lines) == 0 || lines[0] != "[winn/3]" {
		return s, wrap(ErrConfig, "document does not open a [winn/3] section")
	}
	seen := map[string]bool{}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return s, wrap(ErrConfig, "malformed line %q in [winn/3] section", line)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if seen[key] {
			return s, wrap(ErrConfig, "duplicate key %q in [winn/3] section", key)
		}
		seen[key] = true
		switch key {
		case "protocol_version":
			s.ProtocolVersion = val
		case "carrier":
			s.Carrier = val
		case "stealth":
			switch val {
			case "true":
				s.Stealth = true
			case "false":
				s.Stealth = false
			default:
				return s, wrap(ErrConfig, "stealth=%q is not a boolean", val)
			}
		case "max_message_size":
			n, err := strconv.Atoi(val)
			if err != nil {
				return s, wrap(ErrConfig, "max_message_size=%q is not an integer: %v", val, err)
			}
			s.MaxMessageSize = n
		case "inner_mtu":
			n, err := strconv.Atoi(val)
			if err != nil {
				return s, wrap(ErrConfig, "inner_mtu=%q is not an integer: %v", val, err)
			}
			s.InnerMTU = n
		}
	}
	for _, required := range []string{"protocol_version", "carrier", "stealth", "max_message_size", "inner_mtu"} {
		if !seen[required] {
			return s, wrap(ErrConfig, "[winn/3] section is missing key %q", required)
		}
	}
	if s.ProtocolVersion != winn3ProtocolVersion {
		return s, wrap(ErrConfig, "protocol_version=%q is not %q", s.ProtocolVersion, winn3ProtocolVersion)
	}
	if want := InnerMTU(s.MaxMessageSize); s.InnerMTU != want {
		return s, wrap(ErrConfig, "inner_mtu=%d is not the derivation of max_message_size=%d (want %d); "+
			"the document is not self-consistent", s.InnerMTU, s.MaxMessageSize, want)
	}
	return s, nil
}
