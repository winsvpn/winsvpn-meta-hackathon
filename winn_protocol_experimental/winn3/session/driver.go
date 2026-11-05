package session

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/dualsign"
)

// State is the session state machine.
//
// The four working states are Initiating, Established, Rekeying and Closing.
// Closed and Failed are terminal and exist so that a caller can tell an orderly
// shutdown from a session that has to be rebuilt.
//
// Initiating deliberately spans BOTH the handshake and the post-quantum ratchet.
// That is not a shortcut: in the default strict mode no DATA frame may reach the
// wire until the ML-KEM secret is in the chain, so "the point at which user data
// may flow" and "the point at which the ratchet is done" are the same point, and
// giving them two names would invite a caller to write to a session that cannot
// carry the write.
type State uint8

const (
	// StateInitiating covers the handshake and, in strict mode, the
	// post-quantum ratchet that follows it. No DATA leaves in this state.
	StateInitiating State = iota + 1

	// StateEstablished is the only state in which DATA frames flow.
	StateEstablished

	// StateRekeying spans an in-band REKEY_INIT/REKEY_ACK exchange. Nothing
	// optional is emitted in this state — see the epoch-cut rule on
	// mayEmitOptional.
	StateRekeying

	// StateClosing means a CLOSE frame is queued and has not yet reached the
	// wire.
	StateClosing

	// StateClosed is an orderly end.
	StateClosed

	// StateFailed is an end that calls for a new session.
	StateFailed
)

func (s State) String() string {
	switch s {
	case StateInitiating:
		return "initiating"
	case StateEstablished:
		return "established"
	case StateRekeying:
		return "rekeying"
	case StateClosing:
		return "closing"
	case StateClosed:
		return "closed"
	case StateFailed:
		return "failed"
	}
	return "invalid"
}

// Terminal reports whether no further progress is possible.
func (s State) Terminal() bool { return s == StateClosed || s == StateFailed }

// Stats is the driver's counters. Everything an operator or a test needs to tell
// a healthy session from a sick one is here, and nothing here is ever put on the
// wire.
type Stats struct {
	MessagesSent     uint64
	MessagesReceived uint64
	BytesSent        uint64
	BytesReceived    uint64
	PadBytesSent     uint64

	HandshakeMessagesSent uint64
	HandshakeAttempts     uint64

	DataFramesSent     uint64
	DataFramesReceived uint64
	// DataFramesDropped counts DATA frames refused because the session was not
	// in a state that may carry them. This includes expected local offers during
	// a rekey hold; outside a visible state transition it can mean a caller
	// ignored admission or the two ends disagree about StrictPQ.
	DataFramesDropped uint64
	// DataQueueHighWater is the deepest the send queue has been: inner packets
	// accepted by Enqueue and not yet sealed. Near Config.SendQueue it means
	// sealing and sending, not the network, set the pace, and the queue was
	// adding that many packets of delay to every flow behind it.
	DataQueueHighWater uint64
	// DataQueueDepth is the send queue's depth when Stats was read: inner
	// packets accepted and not yet sealed. Next to DataQueueHighWater it says
	// whether a backlog is standing now or only stood once.
	DataQueueDepth uint64
	// DataQueueDropped counts packets dropped from the send-queue head by
	// CoDel (sendqueue_codel.go) because their sojourn exceeded the target.
	// Nonzero under load is expected while TCP converges onto the true
	// bottleneck rate; a rate that grows without throughput falling is the
	// queue doing its job, and a rate that grows while throughput falls is
	// the target set below the path's real delay.
	DataQueueDropped uint64
	// DataQueueOverflow counts inner packets SetSendQueueFQ dropped from the
	// head of its fattest bucket to admit an arrival at the SendQueue cap. A
	// FIFO session refuses the arrival instead (ErrQueueFull). Under
	// SetSendQueueFQ, DataQueueDropped counts the per-bucket CoDel drops.
	DataQueueOverflow uint64
	// OuterReordered counts authenticated messages the current core session
	// opened after one with a higher counter, and OuterLost the counters below
	// the highest opened that never arrived. Read from the core session at
	// Stats time; a fresh re-initiation restarts both.
	OuterReordered uint64
	OuterLost      uint64
	// OuterReorderDepth splits OuterReordered by displacement
	// (core.ReorderDepth).
	OuterReorderDepth core.ReorderDepth

	PingsSent     uint64
	PingsReceived uint64
	PongsReceived uint64
	// ProbesLost counts liveness probes of EITHER size class that expired
	// unanswered. Reaching Config.MaxLostProbes consecutively is the necessary
	// half of the unreachable verdict; the sufficient half is that nothing
	// authenticated arrived meanwhile. See tickEstablished.
	ProbesLost uint64

	// WideProbesSent counts liveness probes sent in a message sealed to the full
	// message ceiling, and WideProbesLost how many of those expired unanswered.
	//
	// The pair is the size-aware liveness signal. A path that has narrowed
	// underneath a live session carries every small message and black holes every
	// full-size one, so a detector whose probes are small cannot see it at all —
	// which is exactly the state the network-realism lane measured: established,
	// gate carrying, 200 full-size packets lost, no counter anywhere moving.
	WideProbesSent   uint64
	WideProbesLost   uint64
	NarrowProbesLost uint64

	// PathNarrowedFor counts how many times this session concluded that the path
	// carries small messages and not full-size ones. It is a verdict, not a
	// teardown: re-handshaking over a narrowed path lands in the same place.
	PathNarrowedFor uint64

	Rekeys           uint64
	PQChunksSent     uint64
	PQChunksReceived uint64

	// RekeyInitResends counts REKEY_INIT frames re-sent while this end, as the
	// rekey initiator, waited for the peer's ACK. Nonzero means the network
	// lost an INIT (or the ACK was slower than the first resend) and the
	// resend, not the timeout, decided how the rekey ended.
	RekeyInitResends uint64

	// Unopenable counts messages the transport could not open: noise, a scan, a
	// replay, or the far side of a burst loss beyond the token window. It is
	// NOT a teardown trigger — see the note on tickEstablished for why an
	// error-driven teardown would hand an off-path attacker a kill switch.
	// A datagram a client holds while its PQ ciphertext is outstanding (see
	// HoldOpened) is counted once, when it is finally dropped unopened, not
	// on arrival.
	Unopenable uint64

	// HandshakeRTT is this connect's measured handshake round trip: from the
	// latest fresh initiation leaving to its response opening. It floors every
	// retry draw after the first response (see armRetry). Zero until a
	// response opens; never persisted by the driver.
	HandshakeRTT time.Duration

	// GenerationsSuperseded counts handshake generations this client
	// abandoned while the PQ ciphertext or the attestation was outstanding,
	// replacing each with a fresh initiation (see supersedeGeneration).
	GenerationsSuperseded uint64

	// HoldOpened counts datagrams this client held while its PQ ciphertext
	// was outstanding and that opened once the ratchet had completed (the
	// gateway's epoch-1 attestation arriving ahead of its epoch-0 PQ_CT).
	// HoldRefused counts datagrams that could not be held because the hold
	// was full; each is also counted Unopenable. See holdEarly.
	HoldOpened  uint64
	HoldRefused uint64

	LastRTT time.Duration
}

// Driver is the frame-level session driver: one logical Winn3 session, with no
// socket, no timer and no goroutine of its own.
//
// Enqueue, Poll and Deliver are safe to call concurrently.
type Driver struct {
	assembly []byte
	cfg      Config
	role     core.Role

	mu    sync.Mutex
	batch *driverBatch

	state       State
	failed      error
	localReason CloseReason
	peerReason  CloseReason
	needCarrier bool

	// handshake
	ini        *core.Initiator
	resp       *core.Responder
	hsOut      [][]byte
	peerStatic []byte
	attempt    int
	sinceFresh int
	phaseAt    time.Time

	// Client connect clocks. hsSentAt is when the latest fresh initiation
	// left (hsSentPending until it has), hsRTT the measured round trip to its
	// response, connectBy the one deadline for the whole connect (first
	// initiation sent plus handshakeBudget), and replied whether any response
	// opened during this connect. None is reset by a response, a ratchet or a
	// new generation.
	hsSentAt      time.Time
	hsSentPending bool
	hsRTT         time.Duration
	connectBy     time.Time
	replied       bool
	// reached is the furthest handshake phase any generation of this connect
	// reached: 1 a response opened (PQ ciphertext outstanding), 2 the PQ
	// ratchet completed with the attestation outstanding. A connect that runs
	// out after a supersession closes with that phase's reason.
	reached int
	// preFires is the number of consecutive unanswered pre-session fires of
	// the current generation (Karn backoff of the pre-session floor, see
	// retryFloor); drawIdx is the index of the full-jitter window the next
	// fire draws from. Both advance on a fire and return to zero the moment a
	// response opens; drawIdx is also reset wherever attempt is. attempt
	// alone still counts every fire and bounds the connect (CT-1 Amendment 3,
	// Q1).
	preFires int
	drawIdx  int

	// hold keeps, while this client's PQ ciphertext is outstanding, copies of
	// datagrams that did not open under the current keys: the gateway seals
	// its attestation under epoch 1, so on a path that reorders it can arrive
	// ahead of the epoch-0 PQ_CT that installs the key it needs. At most
	// holdMax entries of at most MaxMessageSize bytes, ciphertext only; each
	// is retried once through the ordinary open path after the ratchet (see
	// drainHold) and the hold is cleared on supersession, terminate,
	// establish and after the drain (CT-1 Amendment 3, Q5).
	hold [][]byte

	// reinitAt is the next time a fresh-reinitiation check may run. A responder
	// only attempts one against a message that fails to open, and never more
	// often than reinitCheckInterval apart, so an off-path spray cannot tax the
	// responder's AEAD path per datagram. See admitReinitiation.
	reinitAt time.Time

	sess *core.Session

	// pathMTUAgreed is the min-of-both-ends number the initiator TOOK when both
	// ends stated a planning path MTU — instance #3's take-the-minimum half,
	// which refusePathMTUMismatch records here before it guards on it. It is
	// nonzero only when both ends made a claim; zero means no agreement was
	// reached, which is also what a peer that predates the notice leaves it as.
	// The refusal proceeds only when this number differs from neither end's
	// claim, and it is the value any future seam that re-applies an interface
	// MTU at the negotiated value would have to apply. Not exported: the future
	// seam lives one layer up, and the number is pinned here by tests in this
	// package so it cannot drift from the refusal that consumes it.
	pathMTUAgreed int

	// frames waiting for a message
	ctrl     []pendingFrame
	data     [][]byte
	dataBase [][]byte // zero-length view retaining reusable FIFO storage
	// dataAt mirrors data entry for entry: the enqueue time of data[i], kept
	// aligned by appendQueuedAt beside every appendQueuedData and by
	// consumeQueuedData on the way out. It feeds CoDel's head-sojourn signal
	// (sendqueue_codel.go) and exists only while data does.
	dataAt      []time.Time
	dataAtBase  []time.Time
	codel       codelState
	pingPending bool
	openBuf     []byte

	// Send-queue fair queueing (SetSendQueueFQ, sendfq.go). When fqOn is set,
	// Enqueue stores into fq and d.data is only the ready window FillSendWindow
	// refills before each poll; the FIFO CoDel in sendqueue_codel.go stands
	// down, because each bucket runs its own. Guarded by mu; fqOn is also read
	// without it.
	fqOn   atomic.Bool
	fq     *sendFQ
	fqBase time.Time

	// post-quantum ratchet
	pqEph    *core.PQEphemeral
	pqRx     *blobRx
	pqSecret []byte

	// dual-signature attestation (docs/DUAL_SIGNATURE_SPEC.md)
	dualClient  bool
	dualDone    bool
	dualEDPub   ed25519.PublicKey
	dualMLVeriy *pqauth.Verifier
	dualEDPriv  ed25519.PrivateKey
	dualMLSign  *pqauth.Signer
	dualEDSig   []byte
	dualMLRx    *blobRx
	dualMLSig   []byte // client: a complete ML-DSA-65 half held until the Ed25519 half arrives

	// in-band rekey
	rekeyPriv  *ecdh.PrivateKey
	rekeyPend  bool
	rekeyAt    time.Time
	rekeyEnd   time.Time
	epochBytes uint64
	// rekeyResendAt is when the pending REKEY_INIT is next re-sent, and
	// rekeyResends how many times it has been. Both are meaningful only while
	// rekeyPend holds rekeyPriv; see resendRekeyInit.
	rekeyResendAt time.Time
	rekeyResends  int
	// rekeyConfirmAt is the rekey-ACK-loss blackhole fix (F-03). It is armed
	// only in the one place where an end commits to a new epoch WITHOUT having
	// witnessed anything sealed under it: the ACK-sealing path of onRekeyInit,
	// for either role. The ACK receiver immediately sends a new-epoch probe;
	// until that or another authenticated message arrives, the sender cannot
	// know that the peer ratcheted. If confirmation never arrives,
	// the client is inside the exact blackhole the rekey_ackloss tests used to
	// pin: its own epoch is ahead, every message it emits is unopenable at the
	// gateway, and the gateway's traffic is unopenable here — a carrying
	// tunnel delivering nothing, indefinitely, with every liveness probe
	// quiet. The deadline bounds that: began by the same RekeyTimeout the
	// initiator's rekeyEnd uses, and cleared the instant ANY message opens
	// post-ratchet (which proves the peer holds the new epoch — see Deliver).
	// On expiry the ACK sender fails loudly with CloseRekeyUnconfirmed so the
	// app layer tears down and reconnects instead of advertising a black-holed
	// path. This applies to either protocol role.
	rekeyConfirmAt time.Time
	// rekeySecret is the ECDH shared secret of an in-flight ratchet. onRekeyInit
	// stashes it here before queuing FrameRekeyAck so terminate / admitReinitiation
	// can zeroise it if the ACK is never sealed. Leaving it only in the after
	// closure meant a peer CLOSE (or a reconnect) dropped ctrl and left the next
	// epoch's DH secret in the heap until GC.
	rekeySecret []byte

	shape *shaper

	// timing
	silence    time.Duration
	silenceAt  time.Time
	probeEvery time.Duration
	probeAt    time.Time
	lastSent   time.Time
	lastOpened time.Time
	// establishedAt is when this session FIRST reached Established. A ratchet
	// does not move it. With lastAuthRecv it bounds the span over which the
	// session carried authenticated traffic; see AuthenticatedSpan.
	establishedAt time.Time
	// lastAuthRecv is when a transport message from the peer last OPENED. It
	// is not lastOpened: establish, and so every rekey completion including
	// the one a locally sealed REKEY_ACK triggers, resets lastOpened as
	// liveness bookkeeping. Only the two open sites move this one.
	lastAuthRecv time.Time
	// curGenAt is when the CURRENT handshake generation reached Established.
	// Unlike establishedAt it is RESET when a fresh re-initiation installs a new
	// crypto session (admitReinitiation) and re-stamped when that generation
	// establishes, and it is PRESERVED across an ordinary in-band rekey. It is
	// the marker a session-table reclaim policy reads to tell a freshly
	// re-established session from an old quiet one, and to protect an
	// authenticated generation that is still completing its handshake (curGenAt
	// zero while a peer static is known). See ReclaimView.
	curGenAt time.Time
	// curGenID identifies the CURRENT generation. It advances exactly where a
	// new generation establishes (the one site that stamps a zero curGenAt: the
	// first establishment and the completion of every fresh re-initiation) and
	// nowhere else, so it stays fixed across authenticated receives and in-band
	// rekeys. Unlike curGenAt it cannot collide: an injected Clock may return
	// the same instant for two establishments, and a timestamp then cannot tell
	// the selected generation from a later one (Round Q Turn 5, OI-Q2).
	curGenID uint64
	// genSeq increments under d.mu on every authenticated receive, on a fresh
	// re-initiation, and on every establishment. A reclaim policy snapshots it
	// with ReclaimView and hands it back to RetireIfQuiet, which refuses the
	// retirement if it has moved: that makes "is this session still idle" and
	// the retirement itself one decision taken under this lock, atomic with the
	// receive and re-initiation paths that would make retiring it wrong.
	genSeq uint64
	// lastUnopenable is when an Established session last received a message
	// it could not open, and lastStallProbe when it last probed because of
	// that. With lastOpened they mark a receive stall; see receiveStalled.
	lastUnopenable time.Time
	nextStallProbe time.Time
	inflight       map[[pingTokenSize]byte]probeState
	lost           int
	// silentLost counts probes lost that were sent at or after the last
	// authenticated receive. Any opened message resets it, so an old
	// unanswered probe cannot hold the dead-path verdict open forever.
	silentLost int

	// The size-aware half of the liveness detector.
	//
	// lostWide is the wide ladder; lastProbeWide drives the alternation that
	// keeps both ladders supplied with round-trip evidence once the wide one
	// starts failing; lostSince is when the OLDEST still-unresolved lost probe
	// was sent, which is the instant every "has anything arrived since" question
	// is asked against; narrowOKAt is when a NARROW probe was last answered.
	lostWide      int
	lastProbeWide bool
	lostSince     time.Time
	narrowOKAt    time.Time
	narrowed      bool

	stats Stats
}

// probeState is one outstanding liveness probe: when it was sent, and whether it
// rode a full-size message.
type probeState struct {
	at   time.Time
	wide bool
}

// NewClient builds the initiating half of a session and writes its handshake
// initiation, which the first Poll returns.
func NewClient(cfg Config) (*Driver, error) {
	if err := cfg.normalise(); err != nil {
		return nil, err
	}
	if cfg.GatewayStatic == nil {
		return nil, wrap(ErrConfig, "a client needs the gateway static public key")
	}
	if len(cfg.DualAuth.Ed25519Private) > 0 || len(cfg.DualAuth.MLDSA65Seed) > 0 {
		return nil, wrap(ErrConfig, "dualauth: signing keys are server-only")
	}
	d := newDriver(cfg, core.RoleInitiator)
	if cfg.DualAuth.Expected {
		d.dualClient = true
		d.dualEDPub = ed25519.PublicKey(append([]byte(nil), cfg.DualAuth.Ed25519Public...))
		mlv, err := pqauth.NewVerifier(pqauth.MLDSA65, cfg.DualAuth.MLDSA65Public)
		if err != nil {
			return nil, wrap(ErrConfig, "dualauth: %v", err)
		}
		d.dualMLVeriy = mlv
	}
	if err := d.freshInitiation(cfg.Clock.Now()); err != nil {
		return nil, err
	}
	return d, nil
}

// NewSharedResponder builds the one handshake responder a multi-peer gateway
// host must share across every Driver it creates, for Config.Responder.
//
// It exists so that the shared object is normalised EXACTLY as NewGateway would
// have normalised it. Building it by calling core.NewResponder directly is the
// obvious alternative and it is subtly wrong: Config.normalise is what fills
// Core.Rand and Core.Now from this package's Rand and Clock, so a caller who
// skipped it would hand core a profile with a nil clock and a nil entropy
// source — and would do so for the object that owns the replay cache, whose
// entire correctness is a function of that clock.
//
// cfg is taken by value and the normalisation does not escape, so passing the
// same Config here and then to NewGateway is correct and is the intended use:
//
//	resp, err := session.NewSharedResponder(cfg)
//	cfg.Responder = resp   // now every NewGateway(cfg) shares one replay cache
//
// See Config.Responder for why a host that skips this has a gateway detector.
func NewSharedResponder(cfg Config) (*core.Responder, error) {
	if err := cfg.normalise(); err != nil {
		return nil, err
	}
	return core.NewResponder(cfg.Core, cfg.Static, cfg.Accept)
}

// NewGateway builds the responding half of a session. It emits nothing until an
// initiation is delivered to it, which is the whole point: a gateway that
// answers anything unauthenticated is a probe oracle.
//
// If cfg.Responder is set it is adopted; otherwise one is built from
// cfg.Core/Static/Accept. A host that builds MORE THAN ONE gateway Driver
// against the same keys must set it — see Config.Responder.
func NewGateway(cfg Config) (*Driver, error) {
	if err := cfg.normalise(); err != nil {
		return nil, err
	}
	// A supplied Responder is ADOPTED, not rebuilt. See Config.Responder: a
	// host that serves many peers through separate Drivers must share one, or
	// its replay cache is partitioned per Driver and a captured initiation
	// replayed into a fresh partition is answered.
	resp := cfg.Responder
	if resp == nil {
		var err error
		resp, err = core.NewResponder(cfg.Core, cfg.Static, cfg.Accept)
		if err != nil {
			return nil, err
		}
	}
	if cfg.DualAuth.Expected {
		return nil, wrap(ErrConfig, "dualauth: Expected is client-only; the gateway presents the attestation")
	}
	d := newDriver(cfg, core.RoleResponder)
	if len(cfg.DualAuth.Ed25519Private) > 0 {
		d.dualEDPriv = ed25519.PrivateKey(append([]byte(nil), cfg.DualAuth.Ed25519Private...))
		sg, err := pqauth.NewSigner(pqauth.MLDSA65, cfg.DualAuth.MLDSA65Seed)
		if err != nil {
			// The driver is discarded; its copy of the key must not outlive it.
			d.wipeDualCredentials()
			return nil, wrap(ErrConfig, "dualauth: %v", err)
		}
		d.dualMLSign = sg
	}
	d.resp = resp
	// The gateway does not retransmit; the client drives. This is the bound on
	// how long a half-open session may hold state, and it is deliberately the
	// whole of the client's retry budget plus one, so that a gateway never
	// evicts a client that is still legitimately trying.
	d.phaseAt = cfg.Clock.Now().Add(handshakeBudget(cfg.Retry))
	return d, nil
}

// NewGatewayFromSession builds a gateway-side driver around an already
// established core.Session produced externally — for example by
// gateway.Gateway.Handle, which owns the handshake and the token index.
//
// It is the composition seam that lets the two halves be composed without
// allocating session state for unauthenticated datagrams. The gateway's token
// index decides admission and routing; this constructor adopts the resulting
// session for the frame layer without repeating the handshake, without
// re-running admission, and without changing any byte on the wire.
//
// cfg is normalised as for NewGateway, but the handshake responder is not
// constructed: the session already exists, so Accept is not required here even
// though NewGateway requires it. sess must be non-nil and its role must be
// RoleResponder. peerStatic, when non-nil, is the authenticated initiator
// static that gateway.Gateway.Handle already checked; it is copied and made
// available via PeerStatic. A nil peerStatic is allowed and simply leaves
// PeerStatic nil.
//
// The driver starts in StateInitiating at epoch 0 (strict-PQ) and follows the
// same post-handshake path as a driver that had just opened its own
// initiation: shape and timers are drawn, the ML-KEM receiver is armed, and
// the session reaches StateEstablished only after the PQ ratchet completes.
// If sess is already PQ-ratcheted (PQRatcheted, not merely Epoch > 0), the
// driver is established immediately.
func NewGatewayFromSession(cfg Config, sess *core.Session, peerStatic []byte) (*Driver, error) {
	if sess == nil {
		return nil, wrap(ErrConfig, "session is nil")
	}
	if sess.Role() != core.RoleResponder {
		return nil, wrap(ErrConfig, "session role is %s, want responder", sess.Role())
	}
	return newFromSession(cfg, sess, peerStatic)
}

// NewFromSession builds a driver around an already-established core.Session.
// The driver's role is taken from sess.Role(). It is the generic form of
// NewGatewayFromSession: a gateway caller should prefer NewGatewayFromSession
// because it documents intent, but either composes correctly.
//
// peerStatic, when non-nil, is copied as the peer's static public key. For a
// responder role it is the initiator's static that was already authenticated
// by the external handshake; for an initiator role it is typically nil.
func NewFromSession(cfg Config, sess *core.Session, peerStatic []byte) (*Driver, error) {
	if sess == nil {
		return nil, wrap(ErrConfig, "session is nil")
	}
	return newFromSession(cfg, sess, peerStatic)
}

// newFromSession is the shared adoption path. It does not change the
// handshake, the framing, the crypto, or any wire bytes: it draws the same
// shape and timers that onHandshakeComplete does, and leaves Poll/Deliver to
// drive the post-quantum ratchet that the externally-owned handshake has not
// yet completed.
func newFromSession(cfg Config, sess *core.Session, peerStatic []byte) (*Driver, error) {
	if err := cfg.normalise(); err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, wrap(ErrConfig, "session is nil")
	}
	role := sess.Role()
	// DualAuth is honoured exactly as NewClient and NewGateway honour it.
	// An already ratcheted initiator can never see the attestation, which is
	// sent once at the ratchet, so Expected there is refused, not dropped.
	if role == core.RoleInitiator {
		if len(cfg.DualAuth.Ed25519Private) > 0 || len(cfg.DualAuth.MLDSA65Seed) > 0 {
			return nil, wrap(ErrConfig, "dualauth: signing keys are server-only")
		}
		if cfg.DualAuth.Expected && (sess.PQRatcheted() || sess.Epoch() != 0) {
			return nil, wrap(ErrConfig, "dualauth: cannot verify the attestation on an already ratcheted session")
		}
	} else if cfg.DualAuth.Expected {
		return nil, wrap(ErrConfig, "dualauth: Expected is client-only; the gateway presents the attestation")
	}
	d := newDriver(cfg, role)
	if role == core.RoleInitiator && cfg.DualAuth.Expected {
		d.dualClient = true
		d.dualEDPub = ed25519.PublicKey(append([]byte(nil), cfg.DualAuth.Ed25519Public...))
		mlv, err := pqauth.NewVerifier(pqauth.MLDSA65, cfg.DualAuth.MLDSA65Public)
		if err != nil {
			return nil, wrap(ErrConfig, "dualauth: %v", err)
		}
		d.dualMLVeriy = mlv
	}
	if role == core.RoleResponder && len(cfg.DualAuth.Ed25519Private) > 0 {
		d.dualEDPriv = ed25519.PrivateKey(append([]byte(nil), cfg.DualAuth.Ed25519Private...))
		sg, err := pqauth.NewSigner(pqauth.MLDSA65, cfg.DualAuth.MLDSA65Seed)
		if err != nil {
			// The driver is discarded; its copy of the key must not outlive it.
			d.wipeDualCredentials()
			return nil, wrap(ErrConfig, "dualauth: %v", err)
		}
		d.dualMLSign = sg
	}
	built := false
	defer func() {
		if !built {
			// The driver is discarded; its copies of the signing keys must
			// not outlive it, as on the NewSigner failure above.
			d.wipeDualCredentials()
		}
	}()
	d.sess = sess
	if len(peerStatic) > 0 {
		cp := make([]byte, len(peerStatic))
		copy(cp, peerStatic)
		d.peerStatic = cp
	}
	now := cfg.Clock.Now()
	// If the session has already completed its post-quantum ratchet, there is
	// no initiating phase to wait out: draw the production timers and establish
	// at once. Otherwise follow the same path as deliverHandshake's
	// onHandshakeComplete, which arms the PQ receiver (responder) or queues the
	// PQ encapsulation key (initiator). The test is PQRatcheted alone:
	// core.Session.Rekey also advances the epoch, and an epoch reached that
	// way never mixed the ML-KEM secret (StrictPQ).
	if sess.PQRatcheted() {
		floor := core.TransportOverhead() + frameHeaderSize
		sh, err := newShaper(cfg.Padding, cfg.Mimic, cfg.Rand, floor, cfg.MaxMessageSize, cfg.Buckets)
		if err != nil {
			return nil, err
		}
		d.shape = sh
		if d.silence, err = drawTruncExp(cfg.Rand, cfg.Silence); err != nil {
			return nil, err
		}
		if d.probeEvery, err = drawTruncExp(cfg.Rand, cfg.Probe); err != nil {
			return nil, err
		}
		d.lastSent = now
		d.lastOpened = now
		d.silentLost = 0
		d.silenceAt = now.Add(d.silence)
		d.probeAt = now.Add(d.probeEvery)
		d.attempt, d.drawIdx = 0, 0
		if err := d.establish(now); err != nil {
			return nil, err
		}
		built = true
		return d, nil
	}
	if err := d.onHandshakeComplete(now); err != nil {
		return nil, err
	}
	built = true
	return d, nil
}

func newDriver(cfg Config, role core.Role) *Driver {
	return &Driver{
		cfg:      cfg,
		role:     role,
		state:    StateInitiating,
		inflight: make(map[[pingTokenSize]byte]probeState),
	}
}

// handshakeBudget is the total wall time a client may spend on one carrier
// before the carrier CLASS must change, plus one cap for slack.
func handshakeBudget(r Retry) time.Duration {
	total := time.Duration(0)
	w := r.Base
	for i := 0; i < r.Attempts; i++ {
		total += w
		if w < r.Cap {
			w *= 2
			if w > r.Cap {
				w = r.Cap
			}
		}
	}
	return total + r.Cap
}

// freshInitiation builds a brand new Initiator and its initiation.
//
// A byte-identical retransmission would recover a lost INITIATION, since the
// gateway never saw it, but it is useless when the RESPONSE was lost: the
// gateway's replay cache refuses the copy and stays silent, correctly, since
// answering a replayed initiation would turn one captured packet into a
// permanent gateway detector (§4.3). The client cannot tell the two cases
// apart. With the default Retry.FreshAfter of zero every pre-session fire is a
// genuinely new handshake with a fresh ephemeral, which passes the replay cache
// and recovers both; an explicit FreshAfter above zero sends that many
// byte-identical copies first. A gateway driver that already holds this
// peer's half-open session admits the fresh initiation by superseding that
// session in place (admitReinitiation).
func (d *Driver) freshInitiation(now time.Time) error {
	ini, err := core.NewInitiator(d.cfg.Core, d.cfg.Static, d.cfg.GatewayStatic)
	if err != nil {
		return err
	}
	if d.dualClient {
		if err := ini.SetInitFlags(core.HandshakeFlagDualAuth); err != nil {
			ini.Wipe()
			return err
		}
	}
	msg, err := ini.WriteInitiation(nil, core.PadAuto)
	if err != nil {
		ini.Wipe()
		return err
	}
	// The previous handshake's ephemeral is the forward-secrecy secret of an
	// attempt the gateway may already have accepted (the lost-response case
	// FreshAfter exists to recover). Replacing d.ini without Wipe leaves that
	// secret in the heap until GC while this process keeps running.
	// Driver.terminate already Wipes; this is the other writer of d.ini.
	old := d.ini
	d.ini = ini
	old.Wipe()
	d.hsOut = append(d.hsOut, msg)
	d.sinceFresh = 0
	d.hsSentPending = true
	d.stats.HandshakeAttempts++
	return d.armRetry(now)
}

// DefaultFreshAfter is how many byte-identical retransmissions precede a
// genuinely new handshake: none. Every pre-session retry is fresh, which
// recovers a lost initiation and a lost response alike; the RTTPrior floor is
// what keeps it from racing a response that is merely in flight.
const DefaultFreshAfter = 0

// freshAfter is Retry.FreshAfter as written: zero means no copies.
func (r Retry) freshAfter() int { return r.FreshAfter }

// armRetry schedules the next fire of the connect's one retry ladder: a floor
// plus a full-jitter draw. The floor is this connect's measured handshake RTT
// once a response has opened, and before that the host's prior
// (Retry.RTTPrior, DefaultRTTPrior when unknown). It is what keeps a fire from
// preceding a response or a flight that is still in flight on a path at or
// below the floor; it is a measured or supplied value under a draw, not a
// fixed interval. A fire is never scheduled past connectBy, where
// tickInitiating ends the connect.
//
// The draw is taken from the window at drawIdx, not at attempt: drawIdx
// returns to zero when a response opens, so the first fire after a response
// (the one that supersedes a generation whose flight was lost) always draws
// from the first window, however many pre-session fires came before it.
// attempt still counts every fire and alone bounds the connect.
func (d *Driver) armRetry(now time.Time) error {
	back, err := drawBackoff(d.cfg.Rand, d.cfg.Retry, d.drawIdx)
	if err != nil {
		return err
	}
	floor := d.retryFloor()
	if d.sess != nil {
		// The round trip was measured with a small response; the PQ
		// ciphertext answering it is a full-size message, so on a narrow
		// downlink it lands up to one datagram's serialization later.
		floor += d.flightAllowance()
	}
	d.phaseAt = now.Add(floor + back)
	if !d.connectBy.IsZero() && d.phaseAt.After(d.connectBy) {
		d.phaseAt = d.connectBy
	}
	return nil
}

// retryFloor is the floor under the next fire's draw. Its base is this
// connect's measured handshake RTT once a response has opened, and the host's
// prior (Retry.RTTPrior after its clamps) before that. While no session is
// held, in the pre-session phase of any generation, each consecutive
// unanswered pre-session fire doubles it, Karn's backoff of a minimum
// retransmission timeout: f(k) = max(base, min(base*2^k, Retry.floorCap())).
// An unanswered fire is no evidence about the path's RTT, so the next one
// waits longer before it can race that fire's own response: a lossless
// pre-session phase on a path below twice the base spends at most one fire.
// A measured base above the cap is this connect's truth and is not clamped.
// The floor is a measured or supplied value, doubled, under an unchanged
// full-width draw, so there is no fixed interval and no atom at a bound.
func (d *Driver) retryFloor() time.Duration {
	base := d.hsRTT
	if base == 0 {
		base = d.cfg.Retry.RTTPrior
	}
	if d.sess != nil || d.preFires == 0 {
		return base
	}
	limit := d.cfg.Retry.floorCap()
	f := base
	for i := 0; i < d.preFires && f < limit; i++ {
		f *= 2
	}
	return max(base, min(f, limit))
}

// handshakeFlightRate is the slowest downlink, in bits per second, the client
// paces its post-response deadline for: one full-size datagram of the
// gateway's flight takes MaxMessageSize*8/handshakeFlightRate to arrive (42.5
// ms at 1360 bytes). Below it a healthy flight may be superseded, which costs a
// generation but never correctness. Seat C (CT4, N-2) measured supersessions
// of healthy connects at 1 Mbit/s and 256 kbit/s without it; every fire draw is
// on an open interval, so at exactly this rate no fire coincides with a
// datagram's arrival.
const handshakeFlightRate = 256_000

func (d *Driver) flightAllowance() time.Duration {
	return time.Duration(int64(d.cfg.MaxMessageSize) * 8 * int64(time.Second) / handshakeFlightRate)
}

// noteHandshakeProgress is called when an authenticated datagram of the
// CURRENT generation advances the handshake while the client is initiating: a
// PQ_CT chunk, the Ed25519 frame, an ML-DSA-65 chunk. It keeps the next fire
// at least one flight allowance plus a draw on (0, allowance) after it, so a
// flight whose datagrams are spaced by a slow downlink is never superseded
// while it is still arriving, and the fire never sits at a fixed offset from a
// received datagram. It spends no fire, never moves the deadline earlier, and
// is capped at connectBy like every other arm. Only authenticated progress
// moves it: unopenable datagrams, replays and a superseded generation's
// datagrams never reach here, and the gateway sends one flight per
// generation, so the number of re-arms is bounded by that flight.
func (d *Driver) noteHandshakeProgress() error {
	if d.role != core.RoleInitiator || d.state != StateInitiating {
		return nil
	}
	u, err := unitOpen(d.cfg.Rand)
	if err != nil {
		return err
	}
	a := d.flightAllowance()
	next := d.cfg.Clock.Now().Add(a + time.Duration(u*float64(a)))
	if !d.connectBy.IsZero() && next.After(d.connectBy) {
		next = d.connectBy
	}
	if next.After(d.phaseAt) {
		d.phaseAt = next
	}
	return nil
}

// --- accessors --------------------------------------------------------------

// State reports the state machine state.
// DualAuthVerified reports whether this client verified the dual-signature
// session attestation. False when the session never required one and for
// gateways, which present the attestation rather than verify it.
func (d *Driver) DualAuthVerified() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dualDone
}

func (d *Driver) State() State {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state
}

// DataPlaneState projects the control-plane state onto safe packet admission.
// A rekey ACK sender installs the new epoch before it knows the peer received
// that ACK. Until any message opens under the new epoch, Established would
// advertise a path whose packets the peer may be unable to open.
func (d *Driver) DataPlaneState() State {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state == StateEstablished && !d.rekeyConfirmAt.IsZero() {
		return StateRekeying
	}
	return d.state
}

// Err reports why the session failed, or nil.
func (d *Driver) Err() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.failed
}

// PeerCloseReason reports the reason the peer gave in a CLOSE frame, or zero.
func (d *Driver) PeerCloseReason() CloseReason {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.peerReason
}

// NeedsNewSession reports whether the caller should build a fresh Driver.
func (d *Driver) NeedsNewSession() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.failed != nil || (d.peerReason != 0 && d.peerReason.NeedsNewSession())
}

// NeedsCarrierChange reports the §4.2 normative condition: the handshake retry
// budget was exhausted on this carrier, so the caller must change carrier CLASS
// rather than retry. A retry schedule that never abandons a dead transport is
// not resilience; it is a beacon with a recognisable cadence.
func (d *Driver) NeedsCarrierChange() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.needCarrier
}

// PathMTUAgreed is the min-of-both-ends number refusePathMTUMismatch recorded
// when both ends claimed a planning path MTU. Zero means no agreement: an old
// peer, a zero Config.PathMTU, or a handshake that has not yet completed.
func (d *Driver) PathMTUAgreed() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pathMTUAgreed
}

// MaxMessageSize is the on-wire ceiling this driver is currently using. After
// a successful apply it is the shrunk value, not the number NewClient was
// built with.
func (d *Driver) MaxMessageSize() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg.MaxMessageSize
}

// PeerStatic reports the peer's static public key once the handshake has
// completed. Gateway side only; nil before that.
func (d *Driver) PeerStatic() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.peerStatic
}

// HasAuthenticatedReply reports whether the client opened the gateway's
// handshake response. It lets the host leave a working UDP path alone.
func (d *Driver) HasAuthenticatedReply() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	// replied, not d.sess alone: a superseded generation leaves d.sess nil
	// until the fresh one is answered, and the path that answered the first
	// one is still a working path the host must leave alone.
	return d.role == core.RoleInitiator && (d.sess != nil || d.replied)
}

// RetryOnNewCarrier starts a fresh initiation after a silent path change.
// Freshness matters if the old initiation reached the gateway and its reply
// was lost: replaying the same body on TCP would hit the shared replay cache.
func (d *Driver) RetryOnNewCarrier() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.role != core.RoleInitiator || d.sess != nil || d.state.Terminal() {
		return nil
	}
	d.hsOut = nil
	return d.freshInitiation(d.cfg.Clock.Now())
}

// Epoch reports the current ratchet epoch, or zero before a session exists.
func (d *Driver) Epoch() uint32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess == nil {
		return 0
	}
	return d.sess.Epoch()
}

// AuthenticatedSpan reports when this session first reached Established and
// when a transport message from the peer last opened under it. first is zero
// before the session has established; last is zero until something opened.
// last - first is the span over which the session carried authenticated
// traffic, which is what a reconnect supervisor reads to decide that a round
// proved itself: a session that established and then went silent until
// liveness failed has a short span however long it was held open, and local
// work (sealing, a rekey completing, a timer) never lengthens it.
func (d *Driver) AuthenticatedSpan() (first, last time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.establishedAt.IsZero() {
		return time.Time{}, time.Time{}
	}
	return d.establishedAt, d.lastAuthRecv
}

// ReclaimView is a COHERENT snapshot of everything a host's session-table
// reclaim policy needs, read under one hold of the driver lock so no two fields
// can disagree about the same instant. Seq is handed back to RetireIfQuiet,
// which commits the retirement only if it has not moved since.
type ReclaimView struct {
	// State is the driver's state at the snapshot.
	State State
	// Authenticated is true once an initiation from the peer has authenticated
	// (peerStatic known). It stays true across the whole life of the session,
	// including a fresh re-initiation of the same peer.
	Authenticated bool
	// Established is true once the CURRENT generation reached Established. It is
	// false during the initial handshake AND during a fresh re-initiation, so an
	// authenticated-but-not-established view is a generation still completing.
	Established bool
	// CurGenAt is the current generation's establishment time (zero until it
	// establishes); CurGenID identifies that generation (see curGenID);
	// LastAuthRecv is when the peer's traffic last opened.
	CurGenAt     time.Time
	CurGenID     uint64
	LastAuthRecv time.Time
	// PeerStatic is a copy of the peer's static key, for per-key grouping. Nil
	// before an initiation authenticates.
	PeerStatic []byte
	// ProbeMax is the liveness-probe ceiling, the unit a quiet-timeout is quoted
	// in; Unopenable counts messages that arrived and could not be opened.
	ProbeMax   time.Duration
	Unopenable uint64
	// Seq is the generation-and-activity sequence at the snapshot.
	Seq uint64
}

// ReclaimView returns the coherent snapshot described above.
func (d *Driver) ReclaimView() ReclaimView {
	d.mu.Lock()
	defer d.mu.Unlock()
	var peer []byte
	if len(d.peerStatic) > 0 {
		peer = append(peer, d.peerStatic...)
	}
	return ReclaimView{
		State:         d.state,
		Authenticated: len(d.peerStatic) > 0,
		Established:   !d.curGenAt.IsZero(),
		CurGenAt:      d.curGenAt,
		CurGenID:      d.curGenID,
		LastAuthRecv:  d.lastAuthRecv,
		PeerStatic:    peer,
		ProbeMax:      d.cfg.Probe.Max,
		Unopenable:    d.stats.Unopenable,
		Seq:           d.genSeq,
	}
}

// RetireIfQuiet ends this session, without a CLOSE, ONLY if genSeq still equals
// seq, the value a ReclaimView snapshot carried. It is the commit half of an
// atomic reclaim: the check and the teardown happen under one hold of the
// driver lock, so an authenticated receive or a fresh re-initiation that lands
// between the snapshot and here has already moved genSeq and the retirement is
// refused. It reports whether the session is now terminal.
//
// A session that is already terminal returns true: its slot is free to reclaim.
// The teardown is terminate(), the same wipe an immediate no-session close
// runs, so keys do not outlive the decision and nothing reaches the wire.
func (d *Driver) RetireIfQuiet(seq uint64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.Terminal() {
		return true
	}
	if d.genSeq != seq {
		return false
	}
	if d.failed == nil {
		d.failed = ErrReclaimed
	}
	d.terminate()
	return true
}

// lockTwo locks two DISTINCT driver mutexes in a fixed order (by address), so
// two goroutines that lock the same pair cannot deadlock. CommitSupersede is the
// only code that holds two driver mutexes at once; every other path holds one,
// so there is no lock-order cycle among driver mutexes. The caller unlocks both.
func lockTwo(a, b *Driver) {
	if uintptr(unsafe.Pointer(a)) < uintptr(unsafe.Pointer(b)) {
		a.mu.Lock()
		b.mu.Lock()
	} else {
		b.mu.Lock()
		a.mu.Lock()
	}
}

func unlockTwo(a, b *Driver) {
	a.mu.Unlock()
	b.mu.Unlock()
}

// CommitSupersede is the ATOMIC retirement commit for the one-active-session-
// per-key policy: it terminates victim, without a CLOSE, only if BOTH the
// victim's eligibility and the replacement's validity still hold at this instant,
// checked under both drivers' locks so neither can transition between the check
// and the termination.
//
// It holds both driver mutexes (lockTwo, fixed order) across the whole decision.
// Because Deliver, Close, admitReinitiation and establish each take a single
// driver mutex, a fresh re-initiation of the replacement, its teardown, or a
// receive on either session cannot interleave with this commit: they wait for
// the lock this holds, and their effects show as a moved genSeq or a changed
// state that the checks below reject.
//
// victimSeq is the victim's sequence captured at SELECTION, and the commit
// refuses if it has moved: a victim that received, re-initiated or established
// since selection must be reclassified, never retired on a stale view.
//
// The replacement is revalidated from its CURRENT state under its lock, not by
// its selected sequence: it must still be the same identity (replacementPeer),
// the same generation (its curGenID equals replacementGenID, the generation
// captured at selection, so a re-initiation or a re-establishment since
// selection refuses even when the injected clock gave both establishments the
// same instant), in a live established or rekeying state, confirmed usable
// (an authenticated receive strictly after that establishment), and strictly
// newer than the victim. An authenticated receive changes none of these, so a
// busy replacement cannot defer supersede; requiring its sequence to stand
// still did, on every sweep that traffic landed between selection and commit
// (Round Q Turn 4, OI-Q4). Any failure leaves both sessions untouched.
//
// It takes no lock other than the two driver mutexes, so it cannot deadlock with
// the table lock or the forwarding-table lock; the caller holds the server lock
// across it to keep the forwarding-ownership check and the table bookkeeping part
// of the same decision.
func CommitSupersede(victim, replacement *Driver, victimSeq, replacementGenID uint64, replacementPeer []byte) bool {
	if victim == nil || replacement == nil || victim == replacement {
		return false
	}
	lockTwo(victim, replacement)
	defer unlockTwo(victim, replacement)

	// Replacement validity, under its lock, from its current state.
	if replacement.state != StateEstablished && replacement.state != StateRekeying {
		return false
	}
	if replacement.curGenAt.IsZero() || replacement.curGenID != replacementGenID {
		return false
	}
	if !replacement.lastAuthRecv.After(replacement.curGenAt) {
		return false
	}
	if len(replacement.peerStatic) == 0 || !bytes.Equal(replacement.peerStatic, replacementPeer) {
		return false
	}
	// Victim eligibility, under its lock: unchanged since selection (so still the
	// established, authenticated generation it was selected as), and strictly
	// older than the replacement.
	if victim.genSeq != victimSeq {
		return false
	}
	if victim.state.Terminal() {
		return false
	}
	if victim.curGenAt.IsZero() || !victim.curGenAt.Before(replacement.curGenAt) {
		return false
	}
	if victim.failed == nil {
		victim.failed = ErrReclaimed
	}
	victim.terminate()
	return true
}

// Stats returns a snapshot of the counters.
func (d *Driver) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.stats
	st.DataQueueDepth = uint64(d.queuedDataLen())
	if d.sess != nil {
		st.OuterReordered, st.OuterLost = d.sess.RecvFlow()
		st.OuterReorderDepth = d.sess.RecvReorderDepth()
	}
	return st
}

// HoldsToken reports whether token is in the underlying session's receive window.
func (d *Driver) HoldsToken(token []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess == nil {
		return false
	}
	return d.sess.HoldsToken(token)
}

// Authenticates reports whether msg opens under the session keys without
// consuming the replay counter or updating state.
func (d *Driver) Authenticates(msg []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Any live state the peer can send in: Initiating (PQ exchange) and
	// Rekeying carry authenticated messages too, and a roaming datagram that
	// fails here is dropped as a stranger.
	if d.sess == nil || d.state.Terminal() || d.state == StateClosing {
		return false
	}
	if len(msg) < core.TransportOverhead() {
		return false
	}
	// The scratch must hold any message the session can open, as on the
	// Deliver path (openAndHandle), not a fixed 2048 bytes: PreviewOpen
	// answers io.ErrShortBuffer above that. openBuf is only used under d.mu.
	if cap(d.openBuf) < 65536 {
		d.openBuf = make([]byte, 65536)
	}
	slot := core.OpenSlot{
		Msg: msg,
		Dst: d.openBuf,
	}
	_, err := d.sess.PreviewOpen(&slot)
	clear(d.openBuf[:min(len(msg), len(d.openBuf))])
	return err == nil
}

// ReceiveCounter resolves one inbound message's receive counter without
// consuming its token, opening it, or moving any counter. It exists for the
// receive resequencer (winn3/driver/reseq.go), which needs the counter to
// restore counter order ABOVE the delivery path. A message that does not
// resolve under the current epoch (noise, a replay, a pre-handshake datagram)
// reports false and the caller delivers it immediately, exactly as the
// non-resequenced path would.
func (d *Driver) ReceiveCounter(msg []byte) (uint64, bool) {
	d.mu.Lock()
	sess := d.sess
	d.mu.Unlock()
	if sess == nil {
		return 0, false
	}
	return sess.ResolveCounter(msg)
}

// ReceiveEpoch reports the epoch of the core session currently receiving.
// Counters restart at each epoch install, so a receive resequencer tracking
// counters must reset when this value changes; a session replacement installs
// a fresh core session and changes it the same way.
func (d *Driver) ReceiveEpoch() uint32 {
	d.mu.Lock()
	sess := d.sess
	d.mu.Unlock()
	if sess == nil {
		return 0
	}
	return sess.Epoch()
}

// --- application side -------------------------------------------------------

// dataBufSize is the pooled inner-packet slab. It covers every inner MTU this
// protocol negotiates (the plan floor is ~1.2 kB and the ceiling is a 1500-byte
// path), so the make() fallback below is a jumbo-frame path and not a hot one.
const dataBufSize = 2048

// DataBufferSlabBytes is the capacity used by the pooled send-payload allocator.
const DataBufferSlabBytes = dataBufSize

// The pool holds *[dataBufSize]byte, NOT *[]byte, and that is the whole point.
//
// MEASURED, Galaxy S26 Ultra (SM-S948U1), 2026-09-17, alloc_objects profile of
// BenchmarkBatchCarrierLoopThroughput: sync.Pool.Put through recycleDataBuf was
// 30% of every object this datapath allocated. A *[]byte pool cannot avoid it:
// Put(&b) takes the address of a local slice HEADER, so every recycle escapes a
// fresh 24-byte header to the heap and then hands the GC a pointer to chase. An
// array pointer is already one word, so it enters the empty interface with no
// boxing allocation at all, and the slice is rebuilt from it on the way out.
//
// The same reconstruction trick the frame device uses (winn3_frame_device.go's
// recycle), for the same reason and with the same cap() guard: a slice whose
// capacity is not exactly dataBufSize did not come from here.
var dataBufPool = sync.Pool{
	New: func() any { return new([dataBufSize]byte) },
}

func (d *Driver) getDataBuf(size int) []byte {
	if size <= dataBufSize {
		bp := dataBufPool.Get().(*[dataBufSize]byte)
		return bp[:size]
	}
	return make([]byte, size)
}

// recycleDataBuf wipes the plaintext this buffer carried and returns the slab.
//
// Only the bytes that were WRITTEN are cleared, not the whole slab. getDataBuf
// hands back b[:size] and Enqueue immediately fills all of it, so no reader can
// ever observe a byte past len(b); clearing the remaining ~650 bytes was
// 89k x 650 = 58 MB/s of memset at a gigabit and wiped nothing that was there.
// The wipe itself stays: this is inner-packet plaintext and a pooled buffer
// outlives the session that filled it.
func (d *Driver) recycleDataBuf(b []byte) {
	clear(b)
	if cap(b) != dataBufSize {
		return
	}
	dataBufPool.Put((*[dataBufSize]byte)(b[:dataBufSize]))
}

// appendQueuedData reuses retired prefix slots only when at least half the
// storage is free. Otherwise append grows the live suffix. This amortizes
// compaction over prior consumption instead of copying the backlog per drain.
// The caller holds d.mu and has already checked the live queue limit.
func (d *Driver) appendQueuedData(p []byte) {
	if len(d.data) == cap(d.data) {
		if cap(d.dataBase) > 0 && len(d.data) <= cap(d.dataBase)/2 {
			storage := d.dataBase[:cap(d.dataBase)]
			n := copy(storage, d.data)
			clear(storage[n:])
			d.data = storage[:n]
		} else {
			d.data = append(d.data, p)
			d.dataBase = d.data[:0]
			return
		}
	}
	d.data = append(d.data, p)
}

// consumeQueuedData retires only the consumed prefix. Callers hold d.mu.
func (d *Driver) consumeQueuedData(n int) {
	for i, p := range d.data[:n] {
		d.recycleDataBuf(p)
		d.data[i] = nil
	}
	d.data = d.data[n:]
	d.dataAt = d.dataAt[n:]
	if len(d.data) == 0 {
		d.data = d.dataBase[:0]
		d.dataAt = d.dataAtBase[:0]
	}
}

func (d *Driver) discardQueuedData() {
	if d.fq != nil {
		d.fq.drain(d.recycleDataBuf)
	}
	d.consumeQueuedData(len(d.data))
	d.data = nil
	d.dataBase = nil
	d.dataAt = nil
	d.dataAtBase = nil
	d.codel = codelState{}
}

// Enqueue offers one inner IP packet for transmission.
//
// The packet is copied, so the caller may reuse its buffer. An inner packet is
// never split across messages: there is no reassembly layer in v1, and inventing
// one here would put a fragment offset inside the AEAD that the tun lane's MTU
// discovery is the correct place to avoid needing.
func (d *Driver) Enqueue(inner []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.Terminal() || d.state == StateClosing {
		return ErrClosed
	}
	if d.state == StateRekeying || !d.rekeyConfirmAt.IsZero() {
		d.stats.DataFramesDropped++
		return wrap(ErrState, "data is refused while the rekey epoch is unconfirmed")
	}
	if frameHeaderSize+len(inner) > d.cfg.maxPayload() {
		return wrap(ErrInnerTooLarge, "inner packet is %d bytes, message payload budget is %d", len(inner), d.cfg.maxPayload()-frameHeaderSize)
	}
	if d.fq != nil {
		p := d.getDataBuf(len(inner))
		copy(p, inner)
		if err := d.fqAdmit(p); err != nil {
			return err
		}
		d.noteDataQueueDepth()
		return nil
	}
	if len(d.data) >= d.cfg.SendQueue {
		return ErrQueueFull
	}
	p := d.getDataBuf(len(inner))
	copy(p, inner)
	now := d.cfg.Clock.Now()
	d.appendQueuedData(p)
	d.appendQueuedAt(now)
	d.noteDataQueueDepth()
	return nil
}

// noteDataQueueDepth raises DataQueueHighWater. Callers hold d.mu.
func (d *Driver) noteDataQueueDepth() {
	if depth := uint64(d.queuedDataLen()); depth > d.stats.DataQueueHighWater {
		d.stats.DataQueueHighWater = depth
	}
}

// EnqueueBatch offers multiple inner IP packets for transmission.
//
// The lock is held once for the entire batch rather than once per datagram.
func (d *Driver) EnqueueBatch(inners [][]byte) (int, error) {
	if len(inners) == 0 {
		return 0, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	// Registered after the unlock, so it runs before it, with d.mu held, on
	// every return: a batch the queue takes only in part still raises the
	// high-water mark.
	defer d.noteDataQueueDepth()
	if d.state.Terminal() || d.state == StateClosing {
		return 0, ErrClosed
	}
	if d.state == StateRekeying || !d.rekeyConfirmAt.IsZero() {
		d.stats.DataFramesDropped += uint64(len(inners))
		return 0, wrap(ErrState, "data is refused while the rekey epoch is unconfirmed")
	}
	maxPayload := d.cfg.maxPayload()
	maxSendQueue := d.cfg.SendQueue
	now := d.cfg.Clock.Now()
	var enqueued int
	for i, inner := range inners {
		if frameHeaderSize+len(inner) > maxPayload {
			return enqueued, wrap(ErrInnerTooLarge, "inner packet %d is %d bytes, message payload budget is %d", i, len(inner), maxPayload-frameHeaderSize)
		}
		if d.fq != nil {
			p := d.getDataBuf(len(inner))
			copy(p, inner)
			if err := d.fqAdmit(p); err != nil {
				return enqueued, err
			}
			enqueued++
			continue
		}
		if len(d.data) >= maxSendQueue {
			return enqueued, ErrQueueFull
		}
		p := d.getDataBuf(len(inner))
		copy(p, inner)
		d.appendQueuedData(p)
		d.appendQueuedAt(now)
		enqueued++
	}
	return enqueued, nil
}

// EmitCover queues one content-free cover message.
//
// It exists for PadMimic carriers, which shape a flow to a target distribution
// and therefore sometimes need a packet at a moment when the session has nothing
// to say. It is not the keepalive path: keepalives ride the silence timer and
// carry a PING so that they also sample liveness.
func (d *Driver) EmitCover() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state != StateEstablished || !d.rekeyConfirmAt.IsZero() {
		return wrap(ErrState, "cover traffic is only emitted while established, state is %s", d.state)
	}
	d.ctrl = append(d.ctrl, padFrame())
	return nil
}

// Close asks for an orderly teardown. The CLOSE frame rides in an ordinary
// message, so a closing session does not look different from a busy one.
func (d *Driver) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.Terminal() || d.state == StateClosing {
		return nil
	}
	d.beginClose(CloseNormal, nil)
	return nil
}

// HasPendingWork reports whether the session has queued packets, control frames
// or handshake messages ready to be emitted by Poll/PollBatchInto without waiting
// for a timer.
func (d *Driver) HasPendingWork() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.Terminal() {
		return false
	}
	if len(d.hsOut) > 0 || len(d.ctrl) > 0 {
		return true
	}
	return d.dataMayFlow() && d.queuedDataLen() > 0
}

// --- the pump ---------------------------------------------------------------

// Poll returns the next message for the carrier, or nil when there is nothing
// to send. The caller drains it in a loop.
//
// A terminal session returns (nil, nil), not ErrClosed. The cause lives in
// Err() and the state in State(); winn3/driver.Loop.writeLoop checks
// Terminal() after a nil Poll and wraps StateFailed as ErrSessionFailed.
// Deliver, by contrast, returns ErrClosed on a terminal session. A caller
// that only inspects Poll's error will miss a failed session.
func (d *Driver) Poll() ([]byte, error) {
	return d.PollInto(nil)
}

// PollInto is the zero-allocation variant of Poll, sealing directly into dst.
// When dst has sufficient capacity, no allocations are performed.
func (d *Driver) PollInto(dst []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pollIntoLocked(dst)
}

func (d *Driver) pollIntoLocked(dst []byte) ([]byte, error) {
	if d.state.Terminal() {
		return nil, nil
	}
	now := d.cfg.Clock.Now()
	if err := d.tick(now); err != nil {
		return nil, err
	}
	if d.state.Terminal() {
		return nil, nil
	}
	if len(d.hsOut) > 0 {
		msg := d.hsOut[0]
		d.hsOut = d.hsOut[1:]
		d.stats.HandshakeMessagesSent++
		d.noteSent(now, len(msg), 0)
		if d.role == core.RoleInitiator {
			if d.hsSentPending {
				d.hsSentAt, d.hsSentPending = now, false
			}
			if d.connectBy.IsZero() {
				d.connectBy = now.Add(handshakeBudget(d.cfg.Retry))
			}
		}
		return msg, nil
	}
	return d.assembleInto(now, dst)
}

// NextDeadline reports when Poll should be called again in the absence of any
// carrier activity. A zero time means "nothing is scheduled; wait on the
// carrier alone".
//
// This is the whole of the driver's relationship with time. It never wakes
// itself, which is what keeps the timing policy in one layer.
func (d *Driver) NextDeadline() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch d.state {
	case StateInitiating:
		return d.phaseAt
	case StateRekeying:
		if d.rekeyPend && d.rekeyPriv != nil {
			return earliest(d.rekeyEnd, d.rekeyResendAt)
		}
		return d.rekeyEnd
	case StateClosing:
		// A CLOSE is queued; the deadline has already passed.
		return d.cfg.Clock.Now()
	case StateEstablished:
		now := d.cfg.Clock.Now()
		best := earliest(d.silenceAt, d.probeAt, d.rekeyAt, d.rekeyConfirmAt)
		lossAfter := d.probeLossAfter(now)
		for _, st := range d.inflight {
			best = earliest(best, st.at.Add(lossAfter))
		}
		// Future instants only. A past deadline that the next Poll does not
		// consume is the self-deadlock described in tickEstablished.
		if d.lastUnopenable.After(d.lastOpened) {
			if t := d.lastOpened.Add(stallQuiet); t.After(now) {
				best = earliest(best, t)
			}
		}
		if t := d.nextStallProbe; d.receiveStalled(now) && t.After(now) {
			best = earliest(best, t)
		}
		return best
	}
	return time.Time{}
}

func earliest(ts ...time.Time) time.Time {
	var best time.Time
	for _, t := range ts {
		if t.IsZero() {
			continue
		}
		if best.IsZero() || t.Before(best) {
			best = t
		}
	}
	return best
}

// Deliver consumes one message from the carrier and returns the inner packets it
// carried.
//
// A message that cannot be opened returns no packets and NO ERROR. That is
// deliberate and it is the same discipline the core applies: an unopenable
// message is noise, a scan, a replay, or the far side of a desynchronisation,
// and the four are indistinguishable by construction. A caller that could tell
// them apart could be turned into an oracle. The count is in Stats.Unopenable
// for operators; it is not a signal on the wire and it is not a teardown
// trigger.
//
// An authenticated protocol error (unparseable frames, a malformed PING, PONG
// or CLOSE) also returns no error: beginClose records the cause in Err() and
// the caller must observe State(). The exceptions that DO return an error are
// a session already terminal (ErrClosed), a path-MTU mismatch
// (ErrPathMTUMismatch), and a local failure to write a handshake response
// after an initiation authenticated.
func (d *Driver) Deliver(msg []byte) ([][]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.Terminal() {
		return nil, ErrClosed
	}
	now := d.cfg.Clock.Now()

	// The connect's one deadline binds a delivery exactly as it binds a
	// fire: a completion that arrives at or after connectBy, before the next
	// Poll, must not establish (CT-1 Amendment 3, N-4).
	if d.connectExpired(now) {
		d.closeConnectExhausted()
		return nil, nil
	}

	if d.sess == nil {
		return nil, d.deliverHandshake(now, msg)
	}

	res, _, err := d.openAndHandle(now, msg, false)
	if err != nil {
		return res, err
	}
	return d.drainHold(now, res)
}

// connectExpired reports a client still initiating at or after its
// connectBy. Caller must hold d.mu.
func (d *Driver) connectExpired(now time.Time) bool {
	return d.role == core.RoleInitiator && d.state == StateInitiating &&
		!d.connectBy.IsZero() && !now.Before(d.connectBy)
}

// openAndHandle is the ordinary open path of a transport message: open under
// the current keys, account, parse and handle the frames. A message that does
// not open goes to deliverUnopenable, except a held one being retried, which
// is only counted (see drainHold). opened reports whether it authenticated.
// Caller must hold d.mu, with d.sess non-nil.
func (d *Driver) openAndHandle(now time.Time, msg []byte, held bool) (res [][]byte, opened bool, err error) {
	if cap(d.openBuf) < 65536 {
		d.openBuf = make([]byte, 65536)
	}
	plain, err := d.sess.OpenInto(d.openBuf, msg)
	if err != nil {
		if held {
			d.stats.Unopenable++
			return nil, false, nil
		}
		// A message that does not open under the current session keys is, for a
		// responder, exactly the shape of a FRESH handshake initiation from a
		// peer whose carrier died and who re-initialised a brand-new session
		// (same static keys, fresh ephemeral). The responder must admit it and
		// supersede the old session, or a reconnecting client is permanently
		// refused — indistinguishable from a censor, and the exact failure the
		// reconnect contract exists to prevent. core.Responder dedupes replays,
		// so an attacker replaying a captured initiation is refused before any
		// state is touched. See admitReinitiation.
		//
		// The check is rate-gated so that an off-path spray of handshake-sized
		// garbage cannot tax the responder's AEAD path once per datagram: only
		// one attempt per reinitCheckInterval happens, and a client that is
		// genuinely reconnecting retransmits its initiation on its own Retry
		// schedule, which lands it inside a later window.
		return nil, false, d.deliverUnopenable(now, msg)
	}
	d.lastOpened = now
	d.lastAuthRecv = now
	d.genSeq++
	d.silentLost = 0
	// Anything that opens here was sealed under a key the peer could only
	// hold after its ratchet, so an armed rekey-confirmation deadline has
	// been answered: the peer holds the new epoch. See rekeyConfirmAt.
	d.rekeyConfirmAt = time.Time{}
	// NOTE: d.lost is deliberately NOT reset here. It counts unanswered ROUND
	// TRIPS, and inbound traffic proves only the inbound direction. Resetting it
	// on any opened message would make the one-way case undetectable: an end
	// whose outbound direction has desynchronised still receives its peer
	// perfectly well, and would sit there forever believing the tunnel worked.
	// Only a matching PONG clears it.
	d.stats.MessagesReceived++
	d.stats.BytesReceived += uint64(len(msg))

	dataAllowedAtOpen := d.dataMayFlow()
	// The epoch this message opened under, captured before any of its frames
	// can ratchet the session (Q5).
	openedPreRatchet := !d.sess.PQRatcheted()

	frames, err := core.ParseFrames(plain)
	if err != nil {
		// Authenticated but unparseable. This can only have come from the peer,
		// so it is a protocol error rather than noise, and the session ends.
		d.beginClose(CloseProtocolError, wrap(ErrProtocol, "peer sent an unparseable frame stream: %v", err))
		if d.openBuf != nil && len(plain) <= len(d.openBuf) {
			clear(d.openBuf[:len(plain)])
		}
		return nil, true, nil
	}
	// The size of the message a PING arrived in is carried down so that the PONG
	// can inherit it. Without that a wide probe would prove only the OUTBOUND
	// direction carries a full-size message, and a path narrowed on the return
	// leg would answer every wide probe from a path that cannot carry the answer.
	res, err = d.handleFramesWithDataAdmission(now, frames, len(msg) >= d.cfg.MaxMessageSize, dataAllowedAtOpen, openedPreRatchet)
	if d.openBuf != nil && len(plain) <= len(d.openBuf) {
		clear(d.openBuf[:len(plain)])
	}
	return res, true, err
}

// holdMax bounds the hold: the honest flight that can precede a PQ_CT chunk
// is at most four datagrams (the Ed25519 frame and three ML-DSA-65 chunks, at
// either plan floor), doubled for network duplication.
const holdMax = 8

// holdEarly keeps a copy of a datagram that did not open while this client's
// PQ ciphertext is outstanding, and reports whether it did. Off-path noise can
// fill the hold; a full hold refuses the new arrival (counted HoldRefused) and
// never evicts, so an injector can at worst return the connect to a
// supersession. A held datagram moves nothing but the hold, and nothing is
// ever sent on its account. Caller must hold d.mu.
func (d *Driver) holdEarly(msg []byte) bool {
	if d.role != core.RoleInitiator || d.state != StateInitiating || d.sess == nil || d.pqEph == nil {
		return false
	}
	if len(msg) > d.cfg.MaxMessageSize {
		return false
	}
	if len(d.hold) >= holdMax {
		d.stats.HoldRefused++
		return false
	}
	d.hold = append(d.hold, append([]byte(nil), msg...))
	return true
}

// drainHold retries each held datagram once, in arrival order, through the
// ordinary open path and its receive window, once the PQ ratchet has
// installed the key an early epoch-1 datagram needs. It runs only after the
// frame handler of the datagram that carried the ratchet has returned, never
// from inside onPQCT: OpenInto reuses d.openBuf, whose bytes that handler is
// still parsing until then. One that opens is an ordinary authenticated
// message; one that does not is counted Unopenable once. The hold is empty
// afterwards whatever the outcome. Caller must hold d.mu.
func (d *Driver) drainHold(now time.Time, res [][]byte) ([][]byte, error) {
	if len(d.hold) == 0 || d.pqEph != nil || d.sess == nil || !d.sess.PQRatcheted() {
		return res, nil
	}
	held := d.hold
	d.hold = nil
	var err error
	for i, m := range held {
		if err == nil && !d.state.Terminal() && d.sess != nil {
			var more [][]byte
			var opened bool
			more, opened, err = d.openAndHandle(now, m, true)
			res = append(res, more...)
			if opened {
				d.stats.HoldOpened++
			}
		} else {
			d.stats.Unopenable++
		}
		clear(m)
		held[i] = nil
	}
	return res, err
}

// dropHold discards every held datagram unopened. Each is counted Unopenable
// once, as it would have been on arrival, and its bytes are wiped. Caller
// must hold d.mu.
func (d *Driver) dropHold() {
	for i, m := range d.hold {
		clear(m)
		d.hold[i] = nil
		d.stats.Unopenable++
	}
	d.hold = nil
}

// --- handshake --------------------------------------------------------------

func (d *Driver) deliverHandshake(now time.Time, msg []byte) error {
	if d.ini != nil {
		sess, payload, err := d.ini.ReadResponse(msg)
		if err != nil {
			d.stats.Unopenable++
			return nil
		}
		// BEFORE d.sess is set, so a refusal terminates without a session
		// rather than opening one it intends to tear down. See
		// refusePathMTUMismatch. A message that authenticated correctly also
		// ends the session when WriteResponse fails locally (below): counting
		// that as Unopenable would tell the operator a credential fault while
		// the initiation opened.
		if mismatch := d.refusePathMTUMismatch(payload); mismatch != nil {
			d.failed = mismatch
			d.terminate()
			return mismatch
		}
		d.sess = sess
		d.ini.Wipe()
		d.ini = nil
		d.replied = true
		d.reached = max(d.reached, 1)
		// A response answers the pre-session ladder: the Karn backoff and the
		// draw window start again from the bottom (CT-1 Amendment 3, Q1).
		d.preFires, d.drawIdx = 0, 0
		if !d.hsSentAt.IsZero() {
			d.hsRTT = now.Sub(d.hsSentAt)
			d.stats.HandshakeRTT = d.hsRTT
		}
		// The first authenticated handshake installs a session. It reaches here,
		// not the transport-open path that advances genSeq, so advance it here
		// too: a reclaim snapshot taken while this driver was still a half-open
		// (seq 0, no session) must not commit against the now-authenticated
		// session. See RetireIfQuiet.
		d.genSeq++
		if err := d.onHandshakeComplete(now); err != nil {
			// A local fault after the response authenticated, the same
			// shape as the path-MTU refusal above: latch and terminate so
			// the session is not left Initiating with Err() nil.
			d.failed = err
			d.terminate()
			return err
		}
		return nil
	}
	hs, err := d.resp.ReadInitiation(msg)
	if err != nil {
		d.stats.Unopenable++
		return nil
	}
	defer hs.Wipe()
	if len(d.peerStatic) > 0 && !bytes.Equal(d.peerStatic, hs.InitiatorStatic()) {
		d.stats.Unopenable++
		return nil
	}
	// The responder's half of instance #3: it states the planning path MTU it
	// sized itself at AND the plan floor baked into MaxMessageSize. A PathMTU-
	// only notice cannot see two ends that agree on PathMTU and disagree on
	// the migration plan (shipping: gateway -plan udp vs a udp,tcp,tls client).
	// EncodePathMTUFloorNotice returns nil when Config.PathMTU is zero, so a
	// caller that does not participate still sends the nil payload every
	// caller in this tree used to send.
	respMsg, sess, err := hs.WriteResponse(EncodePathMTUFloorNotice(d.cfg.PathMTU, d.cfg.MaxMessageSize), core.PadAuto)
	if err != nil {
		// The initiation authenticated. Failing to write the response is a
		// local fault (entropy, padding, a too-long payload), not noise.
		// Counting it as Unopenable would make HandshakeFailure print the
		// credential-mismatch text, and returning nil would leave the gateway
		// silent until the handshake budget expired — indistinguishable from
		// a censor. Terminate and return the cause so the operator sees it
		// on this Deliver, the same shape as a path-MTU mismatch.
		d.failed = err
		d.terminate()
		return err
	}
	d.peerStatic = hs.InitiatorStatic()
	d.sess = sess
	// The first authenticated initiation installs a session on the responder.
	// Advance genSeq so a reclaim snapshot taken while this was a half-open
	// (seq 0, no peer, Unopenable from a prior admission-valid but crypto-
	// invalid datagram) cannot commit a retirement against the authenticated,
	// still-completing handshake. See RetireIfQuiet and admitReinitiation.
	d.genSeq++
	d.hsOut = append(d.hsOut, respMsg)
	if err := d.onHandshakeComplete(now); err != nil {
		// Same rule as the WriteResponse failure above: the initiation
		// authenticated, so a local fault terminates and is surfaced.
		d.failed = err
		d.terminate()
		return err
	}
	return nil
}

// reinitCheckInterval is the minimum time between fresh-reinitiation checks on
// an established responder. It bounds the EXTRA AEAD cost an off-path spray can
// force to a constant per interval regardless of spray rate — the responder
// already pays one AEAD per unopenable datagram in Open, so this only caps the
// additional ReadInitiation — while a genuinely reconnecting client, which
// retransmits its initiation on its own (sub-millisecond to second) Retry
// schedule, always lands inside a later window within a handful of
// retransmissions.
const reinitCheckInterval = time.Millisecond

// A receive stall is unopenable traffic still arriving while nothing has opened
// for stallQuiet: the signature of a gap past the token window, which never
// recovers on its own. During a stall the session probes at spacings drawn from
// stallProbeDraw (a truncated exponential, so a stall has no fixed cadence to
// observe) and counts a probe lost after stallProbeLoss or four measured round
// trips, whichever is longer, so the existing unanswered-and-silent teardown in
// tickEstablished fires in seconds instead of up to MaxLostProbes x Probe.Max.
// Noise alone cannot trigger it: a peer that still answers moves lastOpened and
// ends the stall.
//
// Only unopenable arrivals arm it. A return path that goes silent with nothing
// arriving at all is left to the ordinary ladder, because the fingerprint
// contract (TestSilenceTimerNeverFiresOnAnActiveFlow) forbids probing an active
// flow merely because the peer is quiet.
const (
	stallQuiet     = time.Second
	stallProbeLoss = 1500 * time.Millisecond
)

var stallProbeDraw = Draw{Min: 300 * time.Millisecond, Mean: 400 * time.Millisecond, Max: 500 * time.Millisecond}

func (d *Driver) receiveStalled(now time.Time) bool {
	return d.state == StateEstablished && d.lastUnopenable.After(d.lastOpened) &&
		now.Sub(d.lastOpened) >= stallQuiet
}

// probeLossAfter is how old an outstanding probe must be to count as lost.
func (d *Driver) probeLossAfter(now time.Time) time.Duration {
	if !d.receiveStalled(now) {
		return d.cfg.Probe.Max
	}
	loss := max(stallProbeLoss, 4*d.stats.LastRTT)
	return min(loss, d.cfg.Probe.Max)
}

// admitReinitiation processes a fresh, authenticated handshake-initiation from
// a peer this driver already holds a session with, replacing the old session
// with the new one.
//
// adopted is true only when the new session is in place and the post-handshake
// draws succeeded. authenticated is true when ReadInitiation succeeded, even
// if WriteResponse then failed locally: the caller must not count that as
// Unopenable. err is non-nil only when the old session has already been
// discarded (onHandshakeComplete failed after the swap).
//
// It is the responder's half of the reconnect contract: a client whose carrier
// socket died mid-session re-initialises on its next reconnect round — same
// static keys, fresh ephemeral — and sends a brand-new initiation over its
// fresh socket. That message cannot Open under the old session's keys (the two
// sessions share no keying material), so without this a responder that already
// has an established session would sit silent while a reconnecting client
// retries and fails forever. On a censored network a dead carrier is common
// rather than exotic, so this is the re-establishment path a production client
// actually takes, not a test contrivance.
//
// Only a message that (a) failed to open under the current session AND (b)
// authenticates as a fresh initiation is treated this way, so live traffic and
// noise never reach here. core.Responder.ReadInitiation rejects replays against
// its cache, so an attacker replaying a captured initiation is refused before
// any state is touched and cannot force a rotation of a healthy session.
func (d *Driver) admitReinitiation(now time.Time, msg []byte) (adopted, authenticated bool, err error) {
	if d.role != core.RoleResponder || d.resp == nil {
		return false, false, nil
	}
	if d.state == StateClosing {
		// Once beginClose has run, the recorded cause and reason are final
		// and the queued CLOSE must flush: a fresh initiation arriving first
		// never re-opens the driver. It is not read, so it spends no replay
		// cache entry, and a new driver can admit it (D7, Q6).
		return false, false, nil
	}
	hs, err := d.resp.ReadInitiation(msg)
	if err != nil {
		return false, false, nil
	}
	defer hs.Wipe()
	if len(d.peerStatic) > 0 && !bytes.Equal(d.peerStatic, hs.InitiatorStatic()) {
		return false, false, nil
	}
	respMsg, sess, err := hs.WriteResponse(EncodePathMTUFloorNotice(d.cfg.PathMTU, d.cfg.MaxMessageSize), core.PadAuto)
	if err != nil {
		// The initiation authenticated against this responder. The live
		// session is still the old one: do not terminate it because we
		// could not start the replacement. Returning the error would also
		// be wrong — winn3/driver.Loop.readLoop treats any Deliver error
		// as terminal and stops reading, which would turn a local
		// WriteResponse failure into a one-way tunnel. authenticated=true
		// tells the caller not to count this as Unopenable; that counter
		// means "could not authenticate".
		return false, true, nil
	}
	// The old session is being superseded. The peer abandoned it the moment it
	// re-initialised, so there is nothing left to flush: queued frames, the PQ
	// ratchet, the in-band rekey and every outstanding liveness probe belong to
	// the dead session and must not ride across the cut. The attestation
	// credentials (dualMLSign, dualEDPriv) are the gateway's, not the
	// session's: the replacement generation signs its own transcript with
	// them, and terminate is where they are wiped.
	clear(d.inflight)
	d.ctrl = nil
	// A probe queued and not yet popped went with d.ctrl. Its pending flag
	// must go too, or no probe is ever queued again for the new generation.
	d.pingPending = false
	// Accepted-but-unsent packets are counted, as beginClose and terminate do.
	d.stats.DataFramesDropped += uint64(d.queuedDataLen())
	d.discardQueuedData()
	d.pqEph, d.pqRx = nil, nil
	if d.pqSecret != nil {
		clear(d.pqSecret)
		d.pqSecret = nil
	}
	if d.dualEDSig != nil {
		clear(d.dualEDSig)
		d.dualEDSig = nil
	}
	if d.rekeySecret != nil {
		clear(d.rekeySecret)
		d.rekeySecret = nil
	}
	d.rekeyPriv = nil
	d.rekeyPend = false
	d.rekeyAt, d.rekeyEnd = time.Time{}, time.Time{}
	d.rekeyResendAt = time.Time{}
	d.rekeyConfirmAt = time.Time{}
	d.shape = nil
	d.state = StateInitiating
	d.localReason, d.peerReason = 0, 0
	d.needCarrier = false

	d.peerStatic = hs.InitiatorStatic()
	// A fresh generation begins. Zero curGenAt so this session no longer counts
	// as the previously established one, and move genSeq so a reclaim snapshot
	// taken before this re-initiation cannot commit against the new generation.
	// The new generation is now an authenticated handshake in progress
	// (peerStatic set, curGenAt zero), which the reclaim policy protects.
	d.curGenAt = time.Time{}
	d.genSeq++
	old := d.sess
	d.sess = sess
	if old != nil {
		old.Wipe()
	}
	d.hsOut = append(d.hsOut[:0], respMsg)
	if err := d.onHandshakeComplete(now); err != nil {
		// The old session is already gone. Surface the local failure so
		// the operator is not told this was unauthenticated noise.
		d.failed = err
		d.terminate()
		return false, true, err
	}
	return true, true, nil
}

// refusePathMTUMismatch is the initiator's half of silent-refusal instance #3.
//
// It returns nil — the session proceeds — when the peer sent no PathMTU claim,
// when this end made none, when both PathMTUs agree AND (the peer made no
// plan-floor claim OR the floors agree), or when ApplyNegotiatedPathMTU can
// safely shrink. A 7-byte PathMTU-only notice is the compatibility floor.
//
// Two claims can now refuse: PathMTUs differ, or PathMTUs agree and the
// optional MaxMessageSize suffix differs. The second is the shipping
// udp-only-gateway vs udp,tcp,tls-client pair, which the PathMTU-only notice
// could not see.
//
// When Config.ApplyNegotiatedPathMTU is set and ShrinkToPeerPathMTU reports
// the shrink is safe, this mutates PathMTU and MaxMessageSize to the
// negotiated minimum and returns nil so onHandshakeComplete sizes the shaper
// at the number both ends can carry. The loop must still re-clamp the tun
// device before the gate opens; that pairing is why the loop owns the flag.
//
// The refusal is LOCAL and silent on the wire. Nothing is sent back: the
// initiator has authenticated the response, so it could send a CLOSE, but the
// gateway learns nothing it can act on from one and the protocol's habit of
// answering nothing is worth more than the courtesy. The loudness is aimed at
// the OPERATOR, not the peer — Deliver returns this error, the loop's read side
// exits, and winn3/driver's write side turns StateFailed into ErrSessionFailed
// carrying this text, which cmd/winn-datapath prints as the status document's
// `refusal` field.
func (d *Driver) refusePathMTUMismatch(payload []byte) error {
	peerMTU, ok := DecodePathMTUNotice(payload)
	if !ok || d.cfg.PathMTU == 0 {
		return nil
	}
	// Take the minimum. NegotiatedPathMTU(local, peer) is the only number a
	// session whose two ends BOTH made a claim could carry at: the peer's claim
	// when the peer is the narrow end, this end's claim when this end is. Two
	// ends have both claimed by this point — the peer's notice decoded, so
	// peerMTU > 0, and this end's PathMTU was non-zero or we returned already.
	negotiated, _ := NegotiatedPathMTU(d.cfg.PathMTU, peerMTU)
	d.pathMTUAgreed = negotiated
	// The guarded return, on the number just taken. A session may proceed if
	// BOTH ends are already at that minimum, OR if ApplyNegotiatedPathMTU is
	// set and ShrinkToPeerPathMTU reports the shrink is safe. Any other
	// two-sided difference is refused: the min is in the dead zone, the peer
	// is wider, or the host cannot re-clamp its device MTU.
	if negotiated == d.cfg.PathMTU && negotiated == peerMTU {
		return d.refusePlanFloorMismatch(payload)
	}
	if d.cfg.ApplyNegotiatedPathMTU {
		if newMax, ok := ShrinkToPeerPathMTU(d.cfg.PathMTU, d.cfg.MaxMessageSize, peerMTU); ok {
			d.cfg.PathMTU = negotiated
			d.cfg.MaxMessageSize = newMax
			return nil
		}
	}
	kind := classifyPathMTUMismatch(d.cfg.PathMTU, d.cfg.MaxMessageSize, peerMTU, d.cfg.ApplyNegotiatedPathMTU)
	if kind == pathMTUMismatchNone {
		kind = pathMTUMismatchUnsafe
	}
	return wrap(ErrPathMTUMismatch, pathMTUMismatchFormat(kind),
		peerMTU, d.cfg.PathMTU, d.cfg.MaxMessageSize, negotiated)
}

// refusePlanFloorMismatch is the same-PathMTU half of silent-refusal #3.
//
// PathMTU agreement is not enough: MaxMessageSize is the plan floor, and two
// ends on the same PathMTU with different migration plans have different
// floors. A 7-byte notice (old peer, EncodePathMTUNotice, winn3/gateway.New)
// makes no floor claim and this returns nil — the compatibility path.
func (d *Driver) refusePlanFloorMismatch(payload []byte) error {
	peerFloor, ok := DecodePathMTUFloor(payload)
	if !ok {
		return nil
	}
	if peerFloor == d.cfg.MaxMessageSize {
		return nil
	}
	negotiated := peerFloor
	if d.cfg.MaxMessageSize < peerFloor {
		negotiated = d.cfg.MaxMessageSize
	}
	if d.cfg.ApplyNegotiatedPathMTU && peerFloor < d.cfg.MaxMessageSize {
		if peerFloor >= MessageFloor() && InnerMTU(peerFloor) >= IPv6MinimumLinkMTU {
			d.cfg.MaxMessageSize = peerFloor
			return nil
		}
	}
	kind := classifyPlanFloorMismatch(d.cfg.MaxMessageSize, peerFloor, d.cfg.ApplyNegotiatedPathMTU)
	if kind == pathMTUMismatchNone {
		kind = pathMTUMismatchUnsafe
	}
	return wrap(ErrPathMTUMismatch, planFloorMismatchFormat(kind),
		d.cfg.PathMTU, peerFloor, d.cfg.MaxMessageSize, negotiated)
}

// onHandshakeComplete draws this session's shape and timing and starts the
// post-quantum ratchet. The state stays Initiating: in strict mode the session
// is not usable until the ML-KEM secret is in the chain.
func (d *Driver) onHandshakeComplete(now time.Time) error {
	floor := core.TransportOverhead() + frameHeaderSize
	sh, err := newShaper(d.cfg.Padding, d.cfg.Mimic, d.cfg.Rand, floor, d.cfg.MaxMessageSize, d.cfg.Buckets)
	if err != nil {
		return err
	}
	d.shape = sh

	if d.silence, err = drawTruncExp(d.cfg.Rand, d.cfg.Silence); err != nil {
		return err
	}
	if d.probeEvery, err = drawTruncExp(d.cfg.Rand, d.cfg.Probe); err != nil {
		return err
	}
	d.lastSent = now
	d.lastOpened = now
	d.silentLost = 0
	d.silenceAt = now.Add(d.silence)
	d.probeAt = now.Add(d.probeEvery)
	// The initiator's ladder is one per connect: a response does not
	// replenish it (see tickInitiating). The responder never reads attempt
	// while initiating.
	if d.role == core.RoleResponder {
		d.attempt, d.drawIdx = 0, 0
	}

	if d.role == core.RoleInitiator {
		eph, err := core.GeneratePQEphemeral()
		if err != nil {
			return err
		}
		d.pqEph = eph
		d.queuePQ(core.FramePQEK, eph.EncapsulationKey(), nil)
		return d.armRetry(now)
	}
	d.pqRx = newBlobRx(core.PQEncapsulationKeySize)
	d.phaseAt = now.Add(handshakeBudget(d.cfg.Retry))
	return nil
}

func (d *Driver) queuePQ(t core.FrameType, blob []byte, after func() error) {
	chunks := chunkBlob(t, blob, d.cfg.maxPayload()-frameHeaderSize)
	if after != nil && len(chunks) > 0 {
		chunks[len(chunks)-1].after = after
	}
	d.ctrl = append(d.ctrl, chunks...)
	d.stats.PQChunksSent += uint64(len(chunks))
}

// --- the clock-driven half --------------------------------------------------

func (d *Driver) tick(now time.Time) error {
	switch d.state {
	case StateInitiating:
		return d.tickInitiating(now)
	case StateEstablished:
		return d.tickEstablished(now)
	case StateRekeying:
		if !d.rekeyEnd.IsZero() && !now.Before(d.rekeyEnd) {
			d.beginClose(CloseRekeyFailed, ErrRekeyFailed)
			return nil
		}
		if d.rekeyPend && d.rekeyPriv != nil &&
			!d.rekeyResendAt.IsZero() && !now.Before(d.rekeyResendAt) {
			return d.resendRekeyInit(now)
		}
	}
	return nil
}

// HandshakeFailure is the error a handshake that ran out of budget fails with,
// and it carries the evidence the verdict was reached on.
//
// It exists because of a measured failure to communicate. Before it, a wrong
// gateway static key, a mismatched admission secret, a divergent gateway id and
// a gateway that refused admission all produced exactly the output a censor
// blocking UDP produces — ErrCarrierExhausted, "handshake attempts exhausted on
// this carrier", NeedsCarrierChange() true. Five scenarios, one message,
// measured 2026-08-09. An operator or a user told to try another transport goes
// hunting for a censor while the cause is a typo in a key, and in this product
// those two diagnoses lead to completely different actions.
//
// Stats.Unopenable is the value that separates them and it had no reader
// outside a test. This is its reader. The counters travel with the error, so
// every host that already prints Err() gets them without changing a line, and
// nothing about them reaches the peer: this is a local error, like every other
// error in this package, and no byte on the wire changes because of it.
//
// One honest limit, stated here because a diagnostic that overclaims is worse
// than none. On the CLIENT a credential fault is usually silent: a v3 gateway
// answers nothing it cannot authenticate, which is exactly correct and is not
// negotiable, so the client observes Unopenable == 0 for both a block and a
// refusal. Measured, same day, same five scenarios. The client's message
// therefore says the two are indistinguishable from where it stands rather
// than guessing. On the GATEWAY the discrimination is real: datagrams that
// arrived and could not be opened are the credential fault, and their absence
// is a peer that never spoke.
type HandshakeFailure struct {
	// Base is the sentinel this failure answers to under errors.Is:
	// ErrCarrierExhausted, ErrHandshakeUnauthenticated or ErrPeerUnreachable.
	Base error

	// Initiator distinguishes the two messages, because the two roles can
	// honestly say different things.
	Initiator bool

	// Attempts is how much of the retry budget was spent, Sent how many
	// handshake messages this end put on the carrier, and Unopenable how many
	// messages arrived that could not be authenticated. Every one is read from
	// Stats at the moment of the verdict; none is a constant.
	Attempts   int
	Sent       uint64
	Unopenable uint64
}

func (f *HandshakeFailure) Unwrap() error { return f.Base }

// Error is four sentences, one per role and observation, because the two roles
// can honestly say different things and a message that says more than its role
// can know is the defect this type exists to close.
func (f *HandshakeFailure) Error() string {
	switch {
	case f.Initiator && f.Unopenable > 0:
		return fmt.Sprintf("%s: %d attempts, %d handshake messages sent, "+
			"%d arrived and none of them could be opened. Changing carrier class "+
			"will not help — something is answering. Check the gateway static key, "+
			"the admission secret and the gateway id; a middlebox rewriting the "+
			"payload reads the same way",
			f.Base.Error(), f.Attempts, f.Sent, f.Unopenable)

	case f.Initiator:
		return fmt.Sprintf("%s: %d attempts, %d handshake messages sent, "+
			"nothing arrived at all. A blocked path and a gateway that refused "+
			"these credentials are indistinguishable from here, because a v3 "+
			"gateway answers neither — so check the gateway static key, the "+
			"admission secret and the gateway id before treating this as censorship",
			f.Base.Error(), f.Attempts, f.Sent)

	case f.Unopenable > 0:
		return fmt.Sprintf("%s: waited out one client budget, %d datagrams "+
			"arrived and none of them could be opened, and no session was ever "+
			"established. Something is reaching this gateway and failing to "+
			"authenticate to it: check that its gateway static key, admission "+
			"secret and gateway id match this gateway's. A blocked path would "+
			"have delivered nothing at all, so this is not one",
			f.Base.Error(), f.Unopenable)

	default:
		return fmt.Sprintf("%s: waited out one client budget and nothing arrived "+
			"at all; no peer reached this gateway", f.Base.Error())
	}
}

// handshakeFailure builds the verdict from the counters as they stand.
//
// The choice of sentinel is the whole point and it is made from one measured
// fact: did anything arrive that could not be opened. Nothing arriving is a
// silent path, and a silent path is what a carrier-class change answers.
// Something arriving that will not open is not a carrier problem at all, and
// saying "change transport" to it sends the reader in the wrong direction.
//
// Caller must hold d.mu.
func (d *Driver) handshakeFailure(silent error) *HandshakeFailure {
	f := &HandshakeFailure{
		Base:       silent,
		Initiator:  d.role == core.RoleInitiator,
		Attempts:   d.attempt,
		Sent:       d.stats.HandshakeMessagesSent,
		Unopenable: d.stats.Unopenable,
	}
	if f.Unopenable > 0 {
		f.Base = ErrHandshakeUnauthenticated
	}
	return f
}

func (d *Driver) tickInitiating(now time.Time) error {
	// The client's one deadline for the whole connect, across every phase and
	// every generation. armRetry never schedules a fire past it.
	if d.role == core.RoleInitiator && !d.connectBy.IsZero() && !now.Before(d.connectBy) {
		d.closeConnectExhausted()
		return nil
	}
	if d.phaseAt.IsZero() || now.Before(d.phaseAt) {
		return nil
	}
	// The gateway never retransmits. It waits out one client budget and then
	// drops the half-open session.
	if d.role == core.RoleResponder {
		if d.sess == nil {
			// A gateway that timed out with unopenable messages behind it saw
			// a peer it could not authenticate, which is the operator-facing
			// half of the same fault: on this side the two cases really are
			// distinguishable, so they are distinguished.
			d.beginClose(CloseProtocolError, d.handshakeFailure(ErrPeerUnreachable))
		} else {
			// SILENTLY, with no CLOSE. phaseAt is handshakeBudget, a constant
			// (23.5 s at the defaults), so a CLOSE here is one datagram at a
			// fixed delay after the response. An on-path observer can provoke
			// it without any key by letting a real client's first two packets
			// through and dropping the rest, and it helps no conforming
			// client: the client's own retry budget (15.5 s at the defaults)
			// has ended the attempt before this fires. Measured in L22b: 7 of
			// 7 abandoned handshakes got this datagram 23.50 s later.
			if d.failed == nil {
				d.failed = ErrPQFailed
			}
			d.localReason = ClosePQFailed
			d.terminate()
		}
		return nil
	}

	// One ladder per connect: Retry.Attempts fires in total, across the
	// pre-session retries, the PQ phase, the attestation wait and every
	// generation. Nothing but establish resets attempt. drawIdx advances
	// with it and is reset when a response opens; preFires counts the
	// consecutive unanswered fires of a pre-session phase (see retryFloor).
	d.attempt++
	d.drawIdx++
	if d.attempt >= d.cfg.Retry.Attempts {
		d.closeConnectExhausted()
		return nil
	}

	if d.sess == nil {
		d.preFires++
		d.sinceFresh++
		if d.sinceFresh > d.cfg.Retry.freshAfter() {
			return d.freshInitiation(now)
		}
		msg, err := d.ini.Retransmit()
		if err != nil {
			return err
		}
		d.hsOut = append(d.hsOut, msg)
		return d.armRetry(now)
	}

	// The PQ ciphertext or the attestation is still outstanding one measured
	// RTT plus a draw after the key went out: something in the gateway's
	// flight was lost. The gateway has already ratcheted past anything this
	// generation could resend, so the client abandons the generation and
	// starts a fresh one, which the gateway admits through admitReinitiation.
	if d.pqEph != nil || (d.dualClient && !d.dualDone) {
		return d.supersedeGeneration(now)
	}
	return d.armRetry(now)
}

// closeConnectExhausted ends a connect whose ladder or connectBy ran out, with
// the reason of the phase it ran out in.
func (d *Driver) closeConnectExhausted() {
	switch {
	case d.sess == nil && d.replied:
		// A generation of this connect was answered and then superseded, and
		// the fresh one went unanswered. "Nothing arrived" would be false, and
		// so would a credential verdict built from a stale datagram of the dead
		// generation: close with the furthest phase this connect reached, as
		// the release tree closes the same path, and ask for no carrier change.
		if d.reached >= 2 {
			d.beginClose(CloseDualAuthFailed, ErrDualAuthFailed)
		} else {
			d.beginClose(ClosePQFailed, ErrPQFailed)
		}
	case d.sess == nil:
		f := d.handshakeFailure(ErrCarrierExhausted)
		// The measured failure ErrCarrierExhausted answers is 24 retries
		// into a wholesale UDP block: the carrier CLASS must change, and
		// retrying is not an option this driver offers. That advice is
		// only right for a path that said nothing. When something answered
		// and would not open, a carrier change cannot help and asking for
		// one is what sent operators hunting for a censor.
		d.needCarrier = errors.Is(f.Base, ErrCarrierExhausted)
		d.beginClose(CloseProtocolError, f)
	case d.pqEph != nil:
		d.beginClose(ClosePQFailed, ErrPQFailed)
	default:
		// The ratchet completed and the attestation never verified.
		d.beginClose(CloseDualAuthFailed, ErrDualAuthFailed)
	}
}

// supersedeGeneration abandons this client's current handshake generation
// and starts a fresh one. Everything the dead generation held is wiped here:
// its session (and with it every key, salt and window), the PQ ephemeral and
// any secret, the attestation halves, queued control frames and outstanding
// probes. Queued DATA is kept: none of it was sealed, because data may not
// flow while initiating. Nothing of the old generation is retained, so a late
// datagram from it opens nowhere: before the new response it fails ReadResponse
// against the new initiation, after it it fails OpenInto, and either way it is
// only counted.
func (d *Driver) supersedeGeneration(now time.Time) error {
	if d.sess != nil {
		d.sess.Wipe()
		d.sess = nil
	}
	d.pqEph, d.pqRx = nil, nil
	if d.pqSecret != nil {
		clear(d.pqSecret)
		d.pqSecret = nil
	}
	d.dualMLRx = nil
	if d.dualEDSig != nil {
		clear(d.dualEDSig)
		d.dualEDSig = nil
	}
	if d.dualMLSig != nil {
		clear(d.dualMLSig)
		d.dualMLSig = nil
	}
	d.dropHold()
	d.ctrl = nil
	clear(d.inflight)
	d.pingPending = false
	d.shape = nil
	d.genSeq++
	d.curGenAt = time.Time{}
	d.stats.GenerationsSuperseded++
	return d.freshInitiation(now)
}

func (d *Driver) tickEstablished(now time.Time) error {
	// FIFO of the rekey-confirmation deadline: it fires even if every liveness
	// counter below still reads healthy, because that is exactly the state the
	// F-03 blackhole sits in — the liveness ladders can keep moving on old-epoch
	// traffic (the gateway that never received our ACK keeps speaking the old
	// epoch), while everything this end sends is unopenable there. See
	// rekeyConfirmAt. The CLOSE is sealed under the new epoch and is therefore
	// unopenable to the stuck peer; loudness here is for the LOCAL app layer,
	// which tears the tunnel down visibly and reconnects.
	if !d.rekeyConfirmAt.IsZero() && !now.Before(d.rekeyConfirmAt) {
		d.beginClose(CloseRekeyUnconfirmed, ErrRekeyUnconfirmed)
		return nil
	}
	// Liveness first. Note what is NOT here: a count of unopenable messages.
	//
	// A run of unopenable messages is exactly what a burst loss beyond the token
	// window produces, so it is tempting as a detector. It is also exactly what
	// an off-path attacker produces by injecting garbage at a known 5-tuple, and
	// a detector that cannot tell them apart is a teardown primitive handed to
	// that attacker. The signal used instead is an unanswered PING, in two size
	// classes, read together with whether anything authenticated arrived at all.
	//
	// # Why a probe has a size
	//
	// A probe that is always small answers the wrong question. The network-
	// realism lane narrowed an outer path underneath a live session and measured
	// the result: `established`, gate `carrying`, 200 full-size packets lost,
	// zero send errors, zero path-MTU signals, every small message delivered —
	// because the tun check passes (the inner packet fits the INNER MTU), the
	// write succeeds (a DF path reports nothing), and a PING is small enough to
	// fit. Nothing in three layers moved. For a user under a hostile state that
	// is a tunnel that says it is up while their traffic silently dies.
	//
	// So the default probe is WIDE: sealed to the full message ceiling, which is
	// the size the traffic that matters actually is. A wide probe answered is a
	// strictly stronger liveness statement than a small one answered, and it
	// costs one padded message per probe slot on a tunnel that is ALREADY idle,
	// because probes only fire once inbound has gone quiet.
	//
	// # Why there are two ladders
	//
	//   - lost (either class) is the DEAD-PATH ladder. It runs at exactly the
	//     schedule it always did, so the measured 43.5 s worst case for a burst
	//     loss beyond the token window is unchanged.
	//   - lostWide is the NARROWED-PATH ladder. Once a wide probe is lost the
	//     next probe is narrow, then wide, then narrow: both classes keep
	//     accumulating round-trip evidence, so "large messages do not cross and
	//     small ones do" is a PROOF and a DISPROOF rather than an inference.
	//
	// # Why the comparison is inclusive
	//
	// The boundary instant belongs to the EXPIRY, not to the probe, and the two
	// halves of this pair have to agree about it or the driver deadlocks against
	// its own caller. NextDeadline arms an outstanding probe's wake at
	// `st.at + Probe.Max`; winn3/driver.Loop.waitForWork treats a deadline that is
	// not in the future as "already due; the next Poll consumes it" and returns
	// WITHOUT building a timer. Under a strictly-greater test this Poll does not
	// consume it: the wake fires, nothing expires, NextDeadline recomputes the
	// same instant, and the loop comes straight back. On a real clock that is
	// invisible, because time moves during the spin. On an injected one nothing
	// moves — the only goroutine that can move it is the caller's, and it is
	// inside the loop — so writeLoop spends its maxSpins=4096 budget and exits,
	// after which State() answers "established" and Err() answers nil forever.
	//
	// Inclusive is also the only reading under which Probe.Max is a maximum. It is
	// a Draw ceiling: drawTruncExp clamps into [Min, Max] and validate refuses
	// Max <= Min. The liveness budget is quoted as MaxLostProbes x Probe.Max
	// wherever it appears — dpbridge's carrier budget, netlab's burst-loss bound,
	// and DefaultMaxLostProbes' own "eighty seconds worst case" for 4 x 20 s — and
	// under `>` every one of those is short by a nanosecond per probe.
	//
	// The alternative fix, arming at `st.at + Probe.Max + 1`, agrees with itself
	// just as well and is wrong for that reason: it buys the agreement by making
	// the documented ceiling not the ceiling. It would also make this the one
	// deadline in the package armed at "the deadline plus an epsilon"; every other
	// one here is armed with Add and fired inclusively — silenceAt and probeAt and
	// rekeyAt and rekeyEnd and phaseAt at `!now.Before(...)`, and the probe spacing
	// forty lines below at `now.Sub(lastOpened) >= d.probeEvery`, which is this
	// same expression with the comparison the rest of the file uses.
	lossAfter := d.probeLossAfter(now)
	for tok, st := range d.inflight {
		if now.Sub(st.at) >= lossAfter {
			delete(d.inflight, tok)
			if d.lost == 0 || st.at.Before(d.lostSince) {
				d.lostSince = st.at
			}
			d.lost++
			if !st.at.Before(d.lastOpened) {
				d.silentLost++
			}
			d.stats.ProbesLost++
			if st.wide {
				d.lostWide++
				d.stats.WideProbesLost++
			} else {
				d.stats.NarrowProbesLost++
			}
		}
	}

	// "Has anything authenticated arrived since the probes started failing?" is
	// the one question that separates the three ways a probe budget can expire,
	// and it cannot be forged: only a holder of the session key can move
	// lastOpened.
	//
	// It is also the fix for the off-path spray. The liveness detector was
	// documented as closing the off-path teardown primitive — "noise cannot forge
	// a PONG and cannot suppress one" — and the second clause does not hold. The
	// receive path is bounded, so noise at volume DISPLACES real messages, PONGs
	// included, and the legitimate probe budget then fires on a manufactured
	// outage. Measured: the sprayed end absorbed 28,818 unopenable messages with
	// zero probes lost and stayed established, while the far end spent its full
	// four-probe budget and failed with ErrPeerUnreachable — the honest detector
	// firing on a fabricated fact.
	//
	// The flooded end's OUTBOUND direction is untouched by a spray at its inbox,
	// so its traffic keeps arriving here. Requiring silence as well as unanswered
	// probes therefore refuses the fabricated verdict without weakening the real
	// one: a peer that has genuinely gone sends nothing, so lastOpened freezes and
	// the teardown fires at exactly the schedule it always did. An attacker who
	// wants the teardown must now flood BOTH ends' receive paths, at which point
	// no traffic is crossing in either direction and tearing down is correct.
	//
	// This does NOT reset lost. The counter still means "unanswered round trips",
	// which is what the wide/narrow ladders reason over and what makes the
	// one-way-desynchronised case visible in Stats.
	// silentLost is that question's answer: it counts only probes sent since
	// the last authenticated receive and is reset by any opened message.
	// Comparing lastOpened with lostSince instead let an old unanswered probe,
	// followed by healthy traffic, keep a later total silence from ever
	// tearing down (lostSince remembers the oldest loss).

	if d.lostWide >= d.cfg.MaxLostProbes && d.narrowOKAt.After(d.lostSince) {
		// A full-size round trip has failed to budget while a small one
		// SUCCEEDED, both since the same instant. The path did not go away; it
		// narrowed. Tearing down here would be actively wrong — a re-handshake
		// crosses the same path and lands in the same place, and the plan floor
		// this session was built at is now a lie about what the path carries.
		// The verdict is raised instead, for a policy layer to answer with
		// SetMaxMessageSize or a carrier-class change.
		if !d.narrowed {
			d.narrowed = true
			d.stats.PathNarrowedFor++
		}
	}

	if d.silentLost >= d.cfg.MaxLostProbes {
		// The peer has stopped placing our messages, or has gone. Our OUTBOUND
		// direction may well still work, so the CLOSE is worth sending: it saves
		// the peer from waiting out its own probe budget. If outbound is dead too
		// the CLOSE is simply never received and the peer falls back to its own.
		d.beginClose(CloseDesynchronised, ErrPeerUnreachable)
		return nil
	}

	if !d.rekeyPend && d.rekeyDue(now) {
		return d.startRekey(now)
	}

	silenceDue := !d.silenceAt.IsZero() && !now.Before(d.silenceAt)

	// The probe SLOT always re-arms; the probe only fires when inbound has
	// actually gone quiet. Separating the two matters: if the slot only re-armed
	// on a fire, a healthy busy session would leave probeAt permanently in the
	// past, NextDeadline would return a past time on every call, and the
	// caller's loop would spin instead of waiting.
	probeSlot := !d.probeAt.IsZero() && !now.Before(d.probeAt)
	probeDue := probeSlot && now.Sub(d.lastOpened) >= d.probeEvery

	if silenceDue {
		// Redraw AFTER every fire, from the truncated exponential. This is the
		// property a fixed interval maximally lacks: an observer learns nothing
		// about the next fire from the last one.
		next, err := drawTruncExp(d.cfg.Rand, d.cfg.Silence)
		if err != nil {
			return err
		}
		d.silence = next
		d.silenceAt = now.Add(next)
	}
	if probeSlot {
		next, err := drawTruncExp(d.cfg.Rand, d.cfg.Probe)
		if err != nil {
			return err
		}
		d.probeEvery = next
		d.probeAt = now.Add(next)
	}
	if d.receiveStalled(now) {
		// During a stall only the stall schedule emits probes. The ordinary
		// deadlines above were still consumed and re-armed, so none is left in
		// the past, but none may add a probe between two stall draws.
		if d.pingPending || now.Before(d.nextStallProbe) {
			return nil
		}
		next, err := drawTruncExp(d.cfg.Rand, stallProbeDraw)
		if err != nil {
			return err
		}
		d.nextStallProbe = now.Add(next)
		return d.queueProbe(now, d.nextProbeIsWide())
	}
	if (silenceDue || probeDue) && !d.pingPending {
		return d.queueProbe(now, d.nextProbeIsWide())
	}
	return nil
}

// nextProbeIsWide selects the size class of the next liveness probe.
//
// Healthy: always wide, because the question worth asking is whether the path
// carries the traffic this session actually sends, and a small probe cannot ask
// it. Once the wide ladder starts failing: strict alternation, so the narrow
// class accumulates its own round-trip evidence at the same rate. Without the
// alternation "wide fails" would be a claim with nothing to compare it against,
// and a dead path and a narrowed one would present identically.
func (d *Driver) nextProbeIsWide() bool {
	if d.lostWide == 0 {
		return true
	}
	return !d.lastProbeWide
}

// PathNarrowed reports that this session has proven, by round trip in both size
// classes, that the path carries small messages and does not carry full-size
// ones.
//
// It is not a failure. The session stays established and small traffic keeps
// working, which is precisely why it needs a name: without one the condition is
// invisible at every layer and the user sees a tunnel that reports "up" while
// large transfers stall. A host answers it with SetMaxMessageSize, or by moving
// to a carrier class whose overhead leaves room, and the verdict clears itself
// the moment a wide probe is answered again.
func (d *Driver) PathNarrowed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.narrowed
}

// SetMaxMessageSize narrows or widens the largest message this session may emit.
//
// It is carrier.MessageSizeSink, which winn3/carrier built the migration
// machinery against and which winn3/driver's Loop.Migrate already asserts for
// dynamically. It is also the only thing a host can DO about PathNarrowed: a
// verdict with no lever is a light on a dashboard nobody in Myanmar can see.
//
// The two invariants the sink interface asks for are both held here:
//
//   - the padding shaper is re-clamped, because a top bucket above the new
//     ceiling would round a small packet up past what the carrier can send —
//     which is the black hole one layer in, arriving by way of the fix for it;
//   - a shrink below what an ALREADY-QUEUED frame needs is refused rather than
//     applied, because that frame has nowhere to go and dropping it silently is
//     the same failure again. The caller's remedy is a re-handshake at the
//     smaller size, which carrier.Migrate names RemedyRehandshake.
//
// The wide ladder is reset because "wide" now means a different number: evidence
// gathered about the old ceiling says nothing about the new one.
func (d *Driver) SetMaxMessageSize(n int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.Terminal() {
		return ErrClosed
	}
	if floor := core.TransportOverhead() + frameHeaderSize; n < floor {
		return wrap(ErrConfig, "max message size %d is below the %d-byte floor", n, floor)
	}
	if n > core.MaxTransportPayload {
		return wrap(ErrConfig, "max message size %d exceeds %d", n, core.MaxTransportPayload)
	}
	budget := n - core.TransportOverhead()
	for _, f := range d.ctrl {
		if f.encodedSize() > budget {
			return wrap(ErrConfig,
				"a queued control frame of type %d needs %d bytes and the new %d-byte ceiling leaves %d",
				f.typ, f.encodedSize(), n, budget)
		}
	}
	for _, p := range d.data {
		if frameHeaderSize+len(p) > budget {
			return wrap(ErrConfig,
				"a queued inner packet needs %d bytes and the new %d-byte ceiling leaves %d",
				frameHeaderSize+len(p), n, budget)
		}
	}
	if d.fq != nil {
		var tooBig int
		d.fq.each(func(p []byte) {
			if frameHeaderSize+len(p) > budget && tooBig == 0 {
				tooBig = len(p)
			}
		})
		if tooBig > 0 {
			return wrap(ErrConfig,
				"a queued inner packet needs %d bytes and the new %d-byte ceiling leaves %d",
				frameHeaderSize+tooBig, n, budget)
		}
	}
	d.cfg.MaxMessageSize = n
	if d.shape != nil {
		d.shape.setCeiling(n)
	}
	d.lostWide = 0
	d.narrowed = false
	return nil
}

// rekeyDue reports whether any trigger has fired. The time trigger is a jittered
// draw, never a fixed interval: a fixed rekey interval is the 25.000-second
// metronome again, only slower, and a periodogram does not care about the
// period.
func (d *Driver) rekeyDue(now time.Time) bool {
	// The core's own budgets are consulted as well as this driver's, and they
	// are a floor rather than a duplicate: core.NeedsRekey now fires on EITHER a
	// message count or a byte volume, because 2^28 messages is hundreds of
	// gigabytes of full-MTU packets but only a few of small ones, so a message
	// count alone bounds the wrong quantity. A loose Config must not be able to
	// push a session past what the key schedule is willing to stand behind.
	if d.sess.NeedsRekey() {
		return true
	}
	if d.sess.SendCounter() >= d.cfg.RekeyAfterMessages {
		return true
	}
	if d.epochBytes >= d.cfg.RekeyAfterBytes {
		return true
	}
	return !d.rekeyAt.IsZero() && !now.Before(d.rekeyAt)
}

// --- the nonce contract -----------------------------------------------------
//
// core.Session derives its AEAD nonce as (per-epoch salt || send counter), and
// the counter advances inside Seal under the session's own send mutex. A nonce is
// therefore reused only if some caller gets Seal to run twice at the same
// counter under the same key. No test inside the core can catch that, because it
// is a property of the caller — this driver — and the core lane said so
// explicitly when it handed the contract over. A ChaCha20-Poly1305 nonce reuse is
// catastrophic, so the four paths that could introduce one are named here and
// each is closed by construction rather than by care:
//
//  1. RETRANSMISSION. The driver never re-seals. Poll hands its output to the
//     caller and keeps no copy, and handshake retransmission replays bytes that
//     core.Initiator already produced rather than building new ones. Re-sending
//     bytes is the same nonce with the same plaintext, which is what a
//     retransmission IS and is safe; re-sealing would be a different plaintext
//     under a spent nonce and never happens.
//
//  2. FRAMES SURVIVING A RATCHET. A frame queued before a ratchet and sealed
//     after it is safe because core.installEpoch resets the counter and installs
//     a NEW key and a NEW salt in the same operation. The counter never rewinds
//     under a key it has already been used with.
//
//  3. A SECOND SENDER INTERFACE. There is none. Driver.sess is unexported and no
//     exported method returns it, so the only way to seal is Poll, which holds
//     the driver mutex for its whole body. TestNoExportedPathHandsOutTheSealer
//     pins this by reflection so that adding such an accessor fails a test
//     rather than a review.
//
//  4. A CARRIER SWITCH. The driver holds no carrier, so changing one cannot
//     touch the session. The counter is monotone across a migration, which is
//     exactly what makes a session survive it.
//
// TestNoDemuxTokenIsEverReused checks the consequence rather than the argument:
// the demux token at offset 0 of a transport message is PRF(demux key, counter),
// so two messages sealed at the same (epoch, counter) carry the same token. A
// long adversarial run must produce no repeat at all.

func (d *Driver) queueProbe(now time.Time, wide bool) error {
	tok, err := drawToken(d.cfg.Rand)
	if err != nil {
		return err
	}
	d.ctrl = append(d.ctrl, pingFrame(tok, wide))
	d.inflight[tok] = probeState{at: now, wide: wide}
	d.pingPending = true
	d.lastProbeWide = wide
	d.stats.PingsSent++
	if wide {
		d.stats.WideProbesSent++
	}
	return nil
}

// --- assembly ---------------------------------------------------------------

// assemble builds at most one transport message out of the queued frames.
func (d *Driver) assemble(now time.Time) ([]byte, error) {
	return d.assembleInto(now, nil)
}

// assembleInto builds at most one transport message out of the queued frames,
// sealing directly into dst if non-nil with sufficient capacity.
func (d *Driver) assembleInto(now time.Time, dst []byte) ([]byte, error) {
	if d.sess == nil || d.shape == nil {
		return nil, nil
	}
	budget := d.cfg.maxPayload()
	if cap(d.assembly) < budget {
		d.assembly = make([]byte, 0, budget)
	}
	plain := d.assembly[:0]
	defer func() { clear(d.assembly[:cap(d.assembly)]) }()
	var hooks []func() error
	used := 0
	wide := false

	for len(d.ctrl) > 0 {
		f := d.ctrl[0]
		if used > 0 && f.wide != wide {
			// Never coalesce across the size boundary. A narrow probe packed into
			// a message that some other frame has already made full-size would be
			// black holed by exactly the path it exists to measure, and the
			// detector would then read "small messages do not cross either" — the
			// wrong verdict, reached by the rig's own trap.
			break
		}
		if used+f.encodedSize() > budget {
			if used == 0 {
				// Unreachable by construction: PQ blobs are chunked to fit and
				// every other control frame is a handful of bytes. Returning an
				// error rather than emitting an oversized message means a future
				// frame type that forgets to chunk fails loudly instead of
				// producing packets the carrier silently drops.
				return nil, wrap(ErrProtocol, "control frame type %d needs %d bytes, message payload budget is %d", f.typ, f.encodedSize(), budget)
			}
			break
		}
		next, err := core.AppendFrame(plain, f.typ, f.value)
		if err != nil {
			return nil, err
		}
		plain = next
		used += f.encodedSize()
		wide = f.wide
		if f.after != nil {
			hooks = append(hooks, f.after)
		}
		if f.typ == core.FramePing {
			d.pingPending = false
		}
		d.ctrl = d.ctrl[1:]
	}

	if d.dataMayFlow() {
		for len(d.data) > 0 {
			p := d.data[0]
			if used+frameHeaderSize+len(p) > budget {
				break
			}
			next, err := core.AppendFrame(plain, core.FrameData, p)
			if err != nil {
				return nil, err
			}
			plain = next
			used += frameHeaderSize + len(p)
			d.consumeQueuedData(1)
			d.stats.DataFramesSent++
		}
	}

	if len(plain) == 0 {
		return nil, nil
	}

	minLen := core.TransportOverhead() + len(plain)
	var target int
	var err error
	if wide {
		// The shaper is bypassed rather than asked for a large bucket. target()
		// returns "no padding" for a minLen at or above the ceiling, which for a
		// nine-byte PING would emit a small message and silently turn a wide probe
		// into a narrow one — a detector that quietly measures the wrong thing.
		target = d.cfg.MaxMessageSize
	} else if target, err = d.shape.target(minLen); err != nil {
		return nil, err
	}
	var msg []byte
	if dst != nil {
		msg, err = d.sess.SealInto(dst, plain, target)
		if errors.Is(err, io.ErrShortBuffer) {
			// The frames and packets in plain are already retired from their
			// queues and SealInto consumed no nonce: seal into a fresh buffer
			// rather than lose them (or swallow a CLOSE). PollInto avoids the
			// allocation only when dst has the capacity.
			msg, err = d.sess.Seal(plain, target)
		}
	} else {
		msg, err = d.sess.Seal(plain, target)
	}
	if err != nil {
		if errors.Is(err, core.ErrCounterExhausted) {
			// Nothing further can be sealed, including a CLOSE. This is why the
			// volume rekey trigger sits far below the hard ceiling.
			d.beginClose(CloseCounterExhausted, core.ErrCounterExhausted)
			return nil, nil
		}
		if d.state == StateClosing {
			d.terminate()
			return nil, nil
		}
		return nil, err
	}
	d.noteSent(now, len(msg), len(msg)-minLen)

	// Hooks run only once the message they belong to is built. A ratchet must
	// happen AFTER its last message under the old epoch exists, never before, or
	// the message that carries it becomes unopenable by the peer.
	for _, h := range hooks {
		if err := h(); err != nil {
			d.beginClose(CloseProtocolError, err)
			return msg, nil
		}
	}
	return msg, nil
}

// dataMayFlow is the StrictPQ gate.
func (d *Driver) dataMayFlow() bool {
	switch d.state {
	case StateEstablished:
		return d.rekeyConfirmAt.IsZero()
	case StateInitiating:
		// FastPQ accepts that the first round trip lacks post-quantum forward
		// secrecy, and pays for it again at the ratchet cut: client DATA sent in
		// the half round trip after the gateway emits PQ_CT arrives under epoch
		// 0 at a gateway already on epoch 1 and is lost. Inner TCP recovers.
		//
		// No dual-auth guard is needed here. Config.normalise refuses the
		// FastPQ + DualAuth.Expected combination, so a dual-auth client that
		// reaches Initiating with a session has already committed to waiting
		// for the attestation: its data window is the epoch-1 window
		// onDualAuthML opens, never this epoch-0 one.
		return d.cfg.FastPQ && d.sess != nil
	}
	return false
}

// mayEmitOptional gates everything that is not required right now.
//
// It is false outside Established, and that is the EPOCH CUT RULE. Both ratchets
// in this protocol are hard cuts: core.Session installs one epoch at a time, so
// the instant one end ratchets, everything the other end sends under the old
// epoch is lost. The cut is only safe if neither end emits anything optional
// across it, which is why keepalives, probes, pongs and cover traffic all stop
// during Initiating (the post-quantum ratchet) and Rekeying.
func (d *Driver) mayEmitOptional() bool { return d.state == StateEstablished }

func (d *Driver) noteSent(now time.Time, size, pad int) {
	d.lastSent = now
	d.silenceAt = now.Add(d.silence)
	d.stats.MessagesSent++
	d.stats.BytesSent += uint64(size)
	if pad > 0 {
		d.stats.PadBytesSent += uint64(pad)
	}
	d.epochBytes += uint64(size)
}

// --- inbound frames ---------------------------------------------------------

func (d *Driver) handleFrames(now time.Time, frames []core.Frame, wide bool) ([][]byte, error) {
	return d.handleFramesWithDataAdmission(now, frames, wide, d.dataMayFlow(), false)
}

func (d *Driver) handleFramesWithDataAdmission(now time.Time, frames []core.Frame, wide bool, dataAllowedAtOpen, openedPreRatchet bool) ([][]byte, error) {
	return d.handleFramesInto(now, frames, wide, nil, false, dataAllowedAtOpen, openedPreRatchet)
}

// maxQueuedControlForPong bounds the control queue a PONG may join. A PONG is
// optional, and every authenticated message can carry well over a hundred
// PINGs, so without this a peer outpacing the writer grows d.ctrl without
// limit. An honest peer has at most a couple of probes in flight.
const maxQueuedControlForPong = 32

// borrow is used only with batch-owned plaintext and prevalidated output
// capacity. Scalar callers retain their independently owned packet copies.
// openedPreRatchet is whether the message carrying frames opened before the
// PQ ratchet (under epoch 0); the DUAL_AUTH handlers refuse such frames even
// when an earlier frame of the same message completed the ratchet (D7, Q5).
func (d *Driver) handleFramesInto(now time.Time, frames []core.Frame, wide bool, out [][]byte, borrow bool, dataAllowedAtOpen, openedPreRatchet bool) ([][]byte, error) {
	for _, f := range frames {
		switch f.Type {
		case core.FrameData:
			if !dataAllowedAtOpen || !d.dataMayFlow() {
				d.stats.DataFramesDropped++
				continue
			}
			p := f.Value
			if !borrow {
				p = make([]byte, len(f.Value))
				copy(p, f.Value)
			}
			out = append(out, p)
			d.stats.DataFramesReceived++

		case core.FramePad:
			// Cover. Never delivered upward.

		case core.FramePing:
			if len(f.Value) != pingTokenSize {
				d.beginClose(CloseProtocolError, wrap(ErrProtocol, "ping token is %d bytes, need %d", len(f.Value), pingTokenSize))
				return out, nil
			}
			d.stats.PingsReceived++
			if d.mayEmitOptional() && len(d.ctrl) < maxQueuedControlForPong {
				d.ctrl = append(d.ctrl, pongFrame(f.Value, wide))
			}

		case core.FramePong:
			if err := d.onPong(now, f.Value); err != nil {
				d.beginClose(CloseProtocolError, err)
				return out, nil
			}

		case core.FramePQEK:
			if d.state == StateClosing {
				// Same N-5 rule as PQ_CT below: a closing responder does not
				// encapsulate and queue PQ_CT behind its CLOSE.
				continue
			}
			if err := d.onPQEK(f.Value); err != nil {
				d.beginClose(ClosePQFailed, err)
				return out, nil
			}

		case core.FramePQCT:
			if d.state == StateClosing {
				// Once beginClose has run no handshake-phase handler runs:
				// the recorded failure and reason are final, and nothing
				// arriving before the CLOSE flushes may complete a handshake
				// (CT-1 Amendment 3, N-5).
				continue
			}
			if err := d.onPQCT(f.Value); err != nil {
				d.beginClose(ClosePQFailed, err)
				return out, nil
			}

		case core.FrameDualAuthED:
			if d.state == StateClosing {
				continue
			}
			if err := d.onDualAuthED(f.Value, openedPreRatchet); err != nil {
				d.beginClose(CloseDualAuthFailed, err)
				return out, nil
			}

		case core.FrameDualAuthML:
			if d.state == StateClosing {
				continue
			}
			if err := d.onDualAuthML(f.Value, openedPreRatchet); err != nil {
				d.beginClose(CloseDualAuthFailed, err)
				return out, nil
			}

		case core.FrameRekeyInit:
			if err := d.onRekeyInit(now, f.Value); err != nil {
				d.beginClose(CloseRekeyFailed, err)
				return out, nil
			}

		case core.FrameRekeyAck:
			if err := d.onRekeyAck(f.Value); err != nil {
				d.beginClose(CloseRekeyFailed, err)
				return out, nil
			}

		case core.FrameClose:
			if len(f.Value) != 1 {
				d.beginClose(CloseProtocolError, wrap(ErrProtocol, "close frame is %d bytes, need 1", len(f.Value)))
				return out, nil
			}
			d.peerReason = CloseReason(f.Value[0])
			// No CLOSE is echoed. An echo would either race the peer's own
			// teardown or, if both ends echoed, ping-pong.
			d.terminate()
			return out, nil

		default:
			// A frame type this build does not know. The TLV length keeps the
			// stream aligned, so ignoring it is safe and keeps a mixed-version
			// fleet from fragmenting. It is inside the AEAD, so only a session
			// participant could have put it there.
		}
	}
	return out, nil
}

// onPong resolves outstanding probes UP TO THE SIZE CLASS THAT WAS ANSWERED.
//
// The old rule — one answered probe resolves every outstanding probe — is the
// single line that made a narrowed path invisible: a small PONG cleared a wide
// probe that the path had in fact black holed, so the detector concluded the
// path was fine on evidence about a message the path was never asked to carry.
// A PONG proves what its own round trip proves and nothing wider.
func (d *Driver) onPong(now time.Time, token []byte) error {
	if len(token) != pingTokenSize {
		// Same rule as a malformed PING: the token arrived inside the
		// transport AEAD, so it came from the peer. Swallowing a wrong-length
		// PONG while closing on a wrong-length PING is a parsing differential,
		// and a parsing differential is a fingerprint. A late or duplicated
		// PONG of the right length is still ignored below.
		return wrap(ErrProtocol, "pong token is %d bytes, need %d", len(token), pingTokenSize)
	}
	d.stats.PongsReceived++
	var t [pingTokenSize]byte
	copy(t[:], token)
	st, ok := d.inflight[t]
	if !ok {
		// A late or duplicated PONG. Normal, and not an error.
		return nil
	}
	d.stats.LastRTT = now.Sub(st.at)
	if st.wide {
		// A full-size message made the round trip, so every smaller one can.
		// This is the only event that clears the narrowed verdict, and it clears
		// it on positive evidence rather than on a timeout.
		clear(d.inflight)
		d.lost = 0
		d.lostWide = 0
		d.narrowOKAt = now
		d.lostSince = time.Time{}
		d.narrowed = false
		return nil
	}
	// Only the narrow class is proven. Wide probes stay outstanding, and so does
	// the wide ladder: this PONG is evidence that the path is alive, not evidence
	// that it carries what this session emits.
	for k, v := range d.inflight {
		if !v.wide {
			delete(d.inflight, k)
		}
	}
	d.narrowOKAt = now
	d.lost = d.lostWide
	return nil
}

func (d *Driver) onPQEK(value []byte) error {
	if d.role != core.RoleResponder || d.pqRx == nil {
		return nil
	}
	done, err := d.pqRx.accept(value)
	if err != nil {
		return err
	}
	d.stats.PQChunksReceived++
	if !done {
		return nil
	}
	ct, ss, err := core.PQEncapsulate(d.pqRx.bytes())
	if err != nil {
		return err
	}
	d.pqRx = nil
	d.queuePQ(core.FramePQCT, ct, func() error { return d.completePQ() })
	d.pqSecret = ss
	return nil
}

func (d *Driver) onPQCT(value []byte) error {
	if d.role != core.RoleInitiator || d.pqEph == nil {
		return nil
	}
	if d.pqRx == nil {
		d.pqRx = newBlobRx(core.PQCiphertextSize)
	}
	done, err := d.pqRx.accept(value)
	if err != nil {
		return err
	}
	d.stats.PQChunksReceived++
	if err := d.noteHandshakeProgress(); err != nil {
		return err
	}
	if !done {
		return nil
	}
	ss, err := d.pqEph.Decapsulate(d.pqRx.bytes())
	if err != nil {
		return err
	}
	d.pqRx = nil
	d.pqSecret = ss
	return d.completePQ()
}

// onDualAuthED is the client half of the dual-signature attestation (docs/
// DUAL_SIGNATURE_SPEC.md). It stores the Ed25519 signature; the final
// verification of BOTH signatures happens once both halves are held, here if
// the ML-DSA-65 half completed first, otherwise in onDualAuthML. Fail closed
// at every step.
func (d *Driver) onDualAuthED(value []byte, openedPreRatchet bool) error {
	if !d.dualClient {
		return wrap(ErrProtocol, "dual-auth frame on a session that did not request the attestation")
	}
	if err := d.dualAuthAfterRatchet(openedPreRatchet); err != nil {
		return err
	}
	if d.dualDone {
		return nil
	}
	if d.dualEDSig != nil {
		// The same bytes again is network duplication; different bytes from
		// an authenticated peer are a protocol violation.
		if bytes.Equal(d.dualEDSig, value) {
			return nil
		}
		return wrap(ErrProtocol, "duplicate dual-auth ed25519 frame with a different value")
	}
	if len(value) != dualsign.Ed25519SignatureSize {
		return wrap(ErrProtocol, "dual-auth ed25519 signature has wrong size")
	}
	d.dualEDSig = append([]byte(nil), value...)
	if err := d.noteHandshakeProgress(); err != nil {
		return err
	}
	if d.dualMLSig != nil {
		return d.verifyDualAuth(d.dualMLSig)
	}
	return nil
}

// onDualAuthML reassembles the chunked ML-DSA-65 signature and, once whole,
// verifies both signatures over the session transcript together. Success lifts
// the gate: the session establishes exactly where it would have absent the
// attestation, so the established path and its tests stay singular.
func (d *Driver) onDualAuthML(value []byte, openedPreRatchet bool) error {
	if !d.dualClient {
		return wrap(ErrProtocol, "dual-auth frame on a session that did not request the attestation")
	}
	if err := d.dualAuthAfterRatchet(openedPreRatchet); err != nil {
		return err
	}
	if d.dualDone || d.dualMLSig != nil {
		// A chunk of a half already complete: duplication, harmless.
		return nil
	}
	if d.dualMLRx == nil {
		d.dualMLRx = newBlobRx(dualsign.MLDSA65SignatureSize)
	}
	done, err := d.dualMLRx.accept(value)
	if err != nil {
		return wrap(ErrProtocol, "dual-auth mldsa65 chunk rejected: %v", err)
	}
	if err := d.noteHandshakeProgress(); err != nil {
		return err
	}
	if !done {
		return nil
	}
	mlSig := append([]byte(nil), d.dualMLRx.bytes()...)
	d.dualMLRx = nil
	if d.dualEDSig == nil {
		// UDP does not keep order: the Ed25519 frame was lost or is behind
		// these chunks. Hold the complete half and wait for it; if it never
		// comes, the retry ladder supersedes the generation.
		d.dualMLSig = mlSig
		return nil
	}
	return d.verifyDualAuth(mlSig)
}

// verifyDualAuth verifies both halves over the session transcript together.
// Success lifts the gate: the session establishes exactly where it would have
// absent the attestation, so the established path and its tests stay
// singular. A complete pair that does not verify fails closed; it never
// triggers a new generation.
func (d *Driver) verifyDualAuth(mlSig []byte) error {
	if err := d.dualAuthAfterRatchet(false); err != nil {
		return err
	}
	h := d.sess.TranscriptHash()
	if err := dualsign.VerifyBoth(d.dualEDPub, d.dualMLVeriy, h[:], d.dualEDSig, mlSig); err != nil {
		return wrap(ErrDualAuthFailed, "dual-auth verification failed: %v", err)
	}
	d.dualEDSig = nil
	d.dualMLRx = nil
	d.dualMLSig = nil
	d.dualDone = true
	return d.establish(d.cfg.Clock.Now())
}

// dualAuthAfterRatchet is the client half of the StrictPQ gate for the
// attestation. The gateway seals its attestation under epoch 1, after the PQ
// ratchet, so a DUAL_AUTH frame that opened under epoch 0 can only come from a
// holder of the signing keys acting outside the protocol, and it must never
// establish a session that lacks the ML-KEM secret: it is ErrProtocol, and
// the session closes (CT-1 Amendment 3, N-6). openedPreRatchet is whether
// the frame's MESSAGE opened under epoch 0: a ratchet-completing PQ_CT chunk
// earlier in that same message has already moved the session on by the time
// a later frame is handled, so the session's state alone would admit it (D7,
// Q5). verifyDualAuth, which handles no message, passes false and asserts the
// session's state.
func (d *Driver) dualAuthAfterRatchet(openedPreRatchet bool) error {
	if d.sess == nil || !d.sess.PQRatcheted() || openedPreRatchet {
		return wrap(ErrProtocol, "dual-auth frame before the post-quantum ratchet")
	}
	return nil
}

// completePQ folds the ML-KEM secret in and opens the session for data.
func (d *Driver) completePQ() error {
	if d.pqSecret == nil {
		return wrap(ErrPQFailed, "no shared secret to mix")
	}
	err := d.sess.MixPQ(d.pqSecret)
	clear(d.pqSecret)
	d.pqSecret = nil
	d.pqEph = nil
	if err != nil {
		return err
	}
	d.epochBytes = 0
	now := d.cfg.Clock.Now()
	if d.role == core.RoleResponder &&
		d.sess.InitFlags()&core.HandshakeFlagDualAuth != 0 &&
		d.dualEDPriv != nil && d.dualMLSign != nil {
		h := d.sess.TranscriptHash()
		edSig, err := dualsign.SignEd25519(d.dualEDPriv, h[:])
		if err != nil {
			return err
		}
		mlSig, err := dualsign.SignMLDSA65(d.dualMLSign, h[:])
		if err != nil {
			return err
		}
		d.ctrl = append(d.ctrl, pendingFrame{typ: core.FrameDualAuthED, value: edSig})
		d.ctrl = append(d.ctrl, chunkBlob(core.FrameDualAuthML, mlSig, d.cfg.maxPayload()-frameHeaderSize)...)
	}
	if d.dualClient && !d.dualDone {
		d.reached = 2
		// Strict mode: the tun gate must not open until BOTH signatures over
		// this transcript have verified. Stay Initiating; verifyDualAuth lifts
		// the gate via establish once both hold. The retry ladder keeps
		// running: if the attestation does not arrive by the next fire, the
		// generation is superseded, and when the ladder or connectBy runs out
		// the connect closes with CloseDualAuthFailed.
		d.dualMLRx = newBlobRx(dualsign.MLDSA65SignatureSize)
		return nil
	}
	return d.establish(now)
}

func (d *Driver) establish(now time.Time) error {
	// Only a handshake completing (Initiating) or an in-band rekey completing
	// (Rekeying, completeRekey from onRekeyAck or the REKEY_ACK seal) may
	// establish. A session that has begun to close or has ended never
	// re-establishes: its recorded cause and reason stand, and nothing it
	// receives before the CLOSE flushes can open the data gate (CT-1
	// Amendment 3, N-5).
	if d.state != StateInitiating && d.state != StateRekeying {
		return nil
	}
	d.dropHold()
	d.state = StateEstablished
	if d.establishedAt.IsZero() {
		d.establishedAt = now
	}
	// curGenAt marks THIS generation's establishment. admitReinitiation zeroed
	// it for a fresh session, so this stamps it and a new generation begins
	// (curGenID advances); an in-band rekey leaves it nonzero, so both are
	// preserved. genSeq moves so a reclaim snapshot taken before this
	// establishment cannot commit a retirement against it.
	if d.curGenAt.IsZero() {
		d.curGenAt = now
		d.curGenID++
	}
	d.genSeq++
	d.attempt, d.drawIdx = 0, 0
	d.lost = 0
	// A ratchet is a fresh start for the liveness evidence as well as for the
	// keys: probes queued under the old epoch are unopenable by the peer, so
	// carrying their ladders across the cut would count a ratchet as loss.
	d.lostWide = 0
	d.lostSince = time.Time{}
	d.narrowed = false
	d.phaseAt = time.Time{}
	d.rekeyEnd = time.Time{}
	d.rekeyConfirmAt = time.Time{}
	d.lastOpened = now
	d.silentLost = 0
	d.probeAt = now.Add(d.probeEvery)
	iv, err := drawTruncExp(d.cfg.Rand, d.cfg.RekeyInterval)
	if err != nil {
		return err
	}
	d.rekeyAt = now.Add(iv)
	return nil
}

// --- rekey ------------------------------------------------------------------

// newRekeyEphemeral draws a one-shot X25519 key pair for the in-band ratchet.
//
// It reads exactly 32 bytes and calls NewPrivateKey rather than calling ecdh's
// GenerateKey, mirroring core.GenerateStaticKeyFrom and for the same two
// reasons. GenerateKey routes through internal/randutil.MaybeReadByte, which
// consumes a random EXTRA byte specifically so that callers cannot depend on
// determinism — a good default, and fatal both to a pinned vector and to a test
// that checks the entropy-failure path actually fails. X25519 needs no rejection
// sampling, so reading a fixed 32 bytes loses nothing.
func (d *Driver) newRekeyEphemeral() (*ecdh.PrivateKey, error) {
	var b [core.KeySize]byte
	if _, err := io.ReadFull(d.cfg.Rand, b[:]); err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(b[:])
	clear(b[:])
	return priv, err
}

func (d *Driver) startRekey(now time.Time) error {
	priv, err := d.newRekeyEphemeral()
	if err != nil {
		return err
	}
	d.rekeyPriv = priv
	d.rekeyPend = true
	d.ctrl = append(d.ctrl, pendingFrame{typ: core.FrameRekeyInit, value: priv.PublicKey().Bytes()})
	d.state = StateRekeying
	d.rekeyEnd = now.Add(d.cfg.RekeyTimeout)
	d.rekeyResends = 0
	d.rekeyResendAt, err = d.nextRekeyResend(now)
	return err
}

// Re-send schedule for a REKEY_INIT the peer has not answered: equal jitter
// on a doubling window, so the first resend lands between 375 and 750 ms and
// later ones at most 4 s apart, all inside DefaultRekeyTimeout.
const (
	rekeyResendBase = 750 * time.Millisecond
	rekeyResendCap  = 4 * time.Second
)

// nextRekeyResend draws when the pending REKEY_INIT is next re-sent:
// uniformly in the upper half of the current window, so resends never
// bunch at zero and never fall on a fixed cadence.
func (d *Driver) nextRekeyResend(now time.Time) (time.Time, error) {
	window := rekeyResendBase
	for i := 0; i < d.rekeyResends && window < rekeyResendCap; i++ {
		window *= 2
	}
	if window > rekeyResendCap {
		window = rekeyResendCap
	}
	u, err := unitOpen(d.cfg.Rand)
	if err != nil {
		return time.Time{}, err
	}
	return now.Add(window/2 + time.Duration(u*float64(window/2))), nil
}

// resendRekeyInit re-queues this end's REKEY_INIT, the same ephemeral public
// key, while it waits for the ACK.
//
// Without it, ONE lost REKEY_INIT ends the session: the INIT was queued once,
// tick only watched rekeyEnd, and the data plane stays shut for the whole
// RekeyTimeout before ErrRekeyFailed. Measured on the aicore lab 2026-10-08,
// 3 of 40 heavy uploads died that way with the gateway inbox dropping 11 to
// 13 percent of datagrams.
//
// A resend is a NEW message: sealed at the next counter, so no nonce is
// reused, and padded and timed like any control message. It cannot ratchet
// the responder twice. A responder that already answered is either still in
// StateRekeying with rekeyPend false, which onRekeyInit already ignores, or
// has ratcheted, and an old-epoch message is unopenable there. A responder
// that never saw the first copy answers this one exactly as it would have
// answered the first. The ACK-loss case is not changed: that is F-03's, and a
// resent INIT cannot recover it because the responder has moved epochs.
func (d *Driver) resendRekeyInit(now time.Time) error {
	queued := false
	for _, f := range d.ctrl {
		if f.typ == core.FrameRekeyInit {
			queued = true
			break
		}
	}
	if !queued {
		d.ctrl = append(d.ctrl, pendingFrame{typ: core.FrameRekeyInit, value: d.rekeyPriv.PublicKey().Bytes()})
		d.rekeyResends++
		d.stats.RekeyInitResends++
	}
	next, err := d.nextRekeyResend(now)
	if err != nil {
		return err
	}
	d.rekeyResendAt = next
	return nil
}

// onRekeyInit answers a peer's rekey.
//
// Simultaneous rekey is resolved without a wire field: the INITIATOR role wins
// and the responder yields. Both ends know their role, so the tie-break is free,
// and a tie-break byte on the wire would be one more thing that has to be
// uniform.
func (d *Driver) onRekeyInit(now time.Time, value []byte) error {
	if d.state == StateClosing {
		// A closing driver never answers a rekey. Without this a responder
		// whose own startRekey left rekeyPend set passes the checks below and
		// moves to StateRekeying, and its rekey timeout can then rewrite the
		// recorded close (D7, Q6).
		return nil
	}
	peer, err := ecdh.X25519().NewPublicKey(value)
	if err != nil {
		return wrap(ErrProtocol, "rekey ephemeral rejected: %v", err)
	}
	if d.rekeyPend && d.role == core.RoleInitiator {
		// We win. Ignore theirs; they will yield and answer ours.
		return nil
	}
	if d.state != StateEstablished && !d.rekeyPend {
		return nil
	}

	priv := d.rekeyPriv
	if priv == nil {
		if priv, err = d.newRekeyEphemeral(); err != nil {
			return err
		}
	}
	ss, err := priv.ECDH(peer)
	if err != nil {
		return wrap(ErrProtocol, "rekey key agreement rejected the peer point")
	}
	d.rekeyPriv = nil
	d.rekeyPend = false
	d.rekeyResendAt = time.Time{}
	d.state = StateRekeying
	d.rekeyEnd = now.Add(d.cfg.RekeyTimeout)
	d.rekeySecret = ss
	d.ctrl = append(d.ctrl, pendingFrame{
		typ:   core.FrameRekeyAck,
		value: priv.PublicKey().Bytes(),
		after: func() error {
			err := d.completeRekey(d.rekeySecret)
			// F-03: the ACK just sealed is the peer's ONLY trigger to
			// ratchet, and it can be dropped without either end being told.
			// Every ACK sender can enter that blackhole, regardless of role.
			// Hold its data plane until the ACK receiver's mandatory
			// new-epoch probe arrives. See rekeyConfirmAt and onRekeyAck.
			if err == nil {
				d.rekeyConfirmAt = d.cfg.Clock.Now().Add(d.cfg.RekeyTimeout)
			}
			return err
		},
	})
	return nil
}

func (d *Driver) onRekeyAck(value []byte) error {
	if !d.rekeyPend || d.rekeyPriv == nil {
		return nil
	}
	peer, err := ecdh.X25519().NewPublicKey(value)
	if err != nil {
		return wrap(ErrProtocol, "rekey ephemeral rejected: %v", err)
	}
	ss, err := d.rekeyPriv.ECDH(peer)
	if err != nil {
		return wrap(ErrProtocol, "rekey key agreement rejected the peer point")
	}
	d.rekeySecret = ss
	if err := d.completeRekey(ss); err != nil {
		return err
	}
	// The ACK receiver now holds the new epoch. Send an immediate
	// authenticated probe under it so an idle, healthy peer can clear its
	// ACK-delivery hold; application DATA must never be required to prove
	// convergence.
	return d.queueProbe(d.cfg.Clock.Now(), true)
}

func (d *Driver) completeRekey(secret []byte) error {
	err := d.sess.Rekey(secret)
	clear(secret)
	if d.rekeySecret != nil {
		clear(d.rekeySecret)
		d.rekeySecret = nil
	}
	if err != nil {
		return err
	}
	d.rekeyPriv = nil
	d.rekeyPend = false
	d.rekeyResendAt = time.Time{}
	d.epochBytes = 0
	d.stats.Rekeys++
	clear(d.inflight)
	d.lost = 0
	return d.establish(d.cfg.Clock.Now())
}

// --- teardown ---------------------------------------------------------------

// beginClose queues a best-effort CLOSE and moves to StateClosing, or terminates
// at once when no CLOSE can be sealed.
func (d *Driver) beginClose(reason CloseReason, cause error) {
	if d.state.Terminal() || d.state == StateClosing {
		return
	}
	if cause != nil && d.failed == nil {
		d.failed = cause
	}
	d.localReason = reason
	if d.sess == nil || reason == CloseCounterExhausted {
		d.terminate()
		return
	}
	// In-flight queued data cannot be drained: once the session commits to
	// closing there is no state left that may carry it (dataMayFlow is false in
	// StateClosing), and hold it and the peer that is about to close would never
	// get it. What the carve-out must not do is let accepted-but-unsent packets
	// vanish with no trace -- Enqueue already returned success for them. They are
	// counted into DataFramesDropped, the same counter that records DATA refused
	// because the session was not in a state that may carry them, so a teardown
	// that refused N queued packets is visible to an operator rather than being a
	// silent loss dressed as a clean close.
	d.stats.DataFramesDropped += uint64(d.queuedDataLen())
	d.discardQueuedData()
	d.ctrl = append(d.ctrl, pendingFrame{
		typ:   core.FrameClose,
		value: []byte{byte(reason)},
		after: func() error { d.terminate(); return nil },
	})
	d.state = StateClosing
}

func (d *Driver) terminate() {
	if d.batch != nil {
		d.batch.pool.Close()
		d.batch.wipe()
	}
	if d.failed != nil {
		d.state = StateFailed
	} else {
		d.state = StateClosed
	}
	// The terminate() discard path is reached directly by an observed peer CLOSE
	// and by an immediate close (no session / counter exhausted), so it is the
	// single chokepoint that must account for queued data before discarding it.
	// beginClose counted what it nulled itself; this catches the data that
	// reaches terminate still queued — see TestTeardownCarveOutAccountsQueuedDataWhenPeerCloseArrives.
	d.stats.DataFramesDropped += uint64(d.queuedDataLen())
	d.discardQueuedData()
	d.ctrl = nil
	d.dropHold()
	d.pqEph = nil
	d.pqRx = nil
	if d.pqSecret != nil {
		clear(d.pqSecret)
		d.pqSecret = nil
	}
	// A terminal driver never signs again, so this is where its copies of the
	// gateway's attestation credentials are wiped (D3).
	d.wipeDualCredentials()
	if d.rekeySecret != nil {
		clear(d.rekeySecret)
		d.rekeySecret = nil
	}
	d.rekeyPriv = nil
	if d.openBuf != nil {
		clear(d.openBuf)
		d.openBuf = nil
	}
	clear(d.inflight)
	if d.sess != nil {
		d.sess.Wipe()
	}
	if d.ini != nil {
		d.ini.Wipe()
		d.ini = nil
	}
}

// wipeDualCredentials destroys this driver's ML-DSA-65 signer and zeroes its
// copy of the Ed25519 private key. They are the gateway's long-lived
// attestation credentials, held per driver: a re-initiation keeps them (the
// replacement generation must attest), and only a driver that will never sign
// again wipes them, at terminate or on a failed construction. cfg.DualAuth
// still aliases the caller's slices; those are the host's to wipe at shutdown.
func (d *Driver) wipeDualCredentials() {
	if d.dualMLSign != nil {
		d.dualMLSign.Destroy()
		d.dualMLSign = nil
	}
	clear(d.dualEDPriv)
	d.dualEDPriv = nil
}

// LocalCloseReason reports the reason this end closed with, or zero.
func (d *Driver) LocalCloseReason() CloseReason {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.localReason
}

// ProbeDraw reports the live liveness-probe interval the driver was configured
// with. It is the value a rig must derive its virtual-time budget from, not a
// package constant.
func (d *Driver) ProbeDraw() Draw {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg.Probe
}

// RekeyIntervalDraw reports the live rekey interval.
func (d *Driver) RekeyIntervalDraw() Draw {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg.RekeyInterval
}

// MaxLostProbes reports the live threshold that ends a session.
func (d *Driver) MaxLostProbes() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg.MaxLostProbes
}
