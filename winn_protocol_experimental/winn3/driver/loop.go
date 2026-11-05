package driver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Config is everything one tunnel needs.
//
// Two fields are deliberately NOT here and cannot be supplied: the session's
// MaxMessageSize and the tun's CarrierFloorMessageSize. Both are computed from
// Sizing, because both are the same number and a host that could set either one
// independently could reintroduce the 84-byte black hole.
type Config struct {
	// Session is the session driver's configuration. MaxMessageSize must be
	// zero; the loop pins it. Clock may be nil, in which case it is filled from
	// this Config's Clock so a host configures one clock rather than three.
	Session session.Config

	// Sizing is the migration plan and the floor it implies. Build it with
	// NewSizing. Required.
	Sizing Sizing

	// Carrier is the transport dialled first. Required. Its class must be named
	// in Sizing.Classes, because a carrier outside the plan is a carrier the
	// floor was not computed over.
	Carrier carrier.Conn

	// Tun is the inner-IP layer's configuration, or nil for a session with no
	// inner datapath (a control-plane probe, or a gateway-side session whose
	// inner side is the gateway's own forwarding table).
	//
	// Sink and CarrierFloorMessageSize must be zero: the loop supplies the first
	// (the session driver, through the one-line name adapter) and pins the
	// second.
	Tun *tun.Config

	// Clock is the loop's time source and its wait primitive. Nil means
	// SystemClock.
	Clock Clock

	// Reseq enables the receive resequencer between the carrier and the
	// session's open path (reseq.go). The zero value disables it, which is
	// the previous behaviour exactly. Enable it where measured arrival-order
	// inversions reach inner transport one for one: on the gateway for the
	// uplink (Canada 2026-10-09 measured R 6.9 to 16% against the 0.5% bar).
	Reseq ReseqConfig
}

// Stats is what the loop itself observed. Seam counters (MessagesSent through
// GateChanges) are owned here. Unopenable and PathNarrowedFor are copied from
// the session so a status document that reads only Loop.Stats can still name
// a spray or a narrowed path.
type Stats struct {
	// MessagesSent and MessagesReceived count whole Winn3 messages across the
	// carrier seam.
	MessagesSent     uint64
	MessagesReceived uint64

	// SendFailed counts sealed messages the carrier refused and the loop then
	// discarded: before the session is Established (the session retransmits the
	// handshake on its own schedule) and after a path-MTU refusal (bytes sealed at
	// the old ceiling can never fit). In the Established data phase a refused
	// message is kept and resent verbatim instead (see txPending), because
	// discarding it lets the send counter outrun the peer's token window; a stall
	// longer than carrierStallLimit fails the loop. Re-sealing is never done: it
	// would be a nonce reuse.
	SendFailed uint64

	// SendRefused counts every presentation the carrier refused, including
	// repeated presentations of the same retained bytes. It moves under ordinary
	// backpressure; SendFailed moves only when sealed bytes are abandoned.
	SendRefused uint64

	// RecvFailed counts carrier read errors that were not a carrier swap.
	RecvFailed uint64

	// InnerDelivered counts inner packets handed to the tun layer, and
	// InnerRejected the ones it refused. InnerNoTun counts packets that arrived
	// with no tun configured.
	InnerDelivered uint64
	InnerRejected  uint64
	InnerNoTun     uint64

	// Migrations counts completed carrier swaps.
	Migrations uint64

	// GateChanges counts transitions applied to the tun gate.
	GateChanges uint64

	// Unopenable and PathNarrowedFor are session-layer counters copied here so
	// a status document that reads Loop.Stats cannot report a spray as healthy
	// receive traffic, or a narrowed path as a live tunnel.
	//
	// readLoop increments MessagesReceived for every carrier message whose
	// Deliver did not abort the loop, including noise, scans and replays,
	// which return (nil, nil) and only move session.Stats.Unopenable. Without
	// this copy the published messages_received climbs under an injection
	// while the diagnosis stays local. PathNarrowedFor is the other "looks
	// up while traffic dies" counter: small packets keep RxPackets moving
	// and PromotionReady true after the path has dropped every full-size
	// flow.
	Unopenable      uint64
	PathNarrowedFor uint64

	// RecvBatches and SendBatches count batch-carrier calls that moved at
	// least one message, so MessagesReceived/RecvBatches and
	// MessagesSent/SendBatches are the real batch occupancy at the socket.
	// DataFramesDropped and Rekeys are the session's own: inner packets the
	// session refused or discarded because data could not flow (a rekey or
	// its confirmation hold), and completed in-band ratchets.
	RecvBatches        uint64
	SendBatches        uint64
	DataFramesDropped  uint64
	Rekeys             uint64
	DataQueueHighWater uint64
	// DataQueueDepth is the session's send queue depth at this snapshot.
	DataQueueDepth uint64
	// DataQueueDropped is the session's CoDel drop count at this snapshot
	// (sendqueue_codel.go): head packets shed because their sojourn in the
	// send queue exceeded the target.
	DataQueueDropped uint64
	// DataQueueOverflow is the session's fattest-bucket drops at the send
	// queue cap under session.Driver.SetSendQueueFQ.
	DataQueueOverflow uint64

	// OuterReordered and OuterLost are the session's own: authenticated
	// messages that arrived after a later one, and messages that never
	// arrived. See session.Stats.
	OuterReordered uint64
	OuterLost      uint64
	// OuterReorderDepth splits OuterReordered by displacement
	// (core.ReorderDepth).
	OuterReorderDepth core.ReorderDepth
}

type counters struct {
	messagesSent     atomic.Uint64
	messagesReceived atomic.Uint64
	sendFailed       atomic.Uint64
	sendRefused      atomic.Uint64
	recvFailed       atomic.Uint64
	innerDelivered   atomic.Uint64
	innerRejected    atomic.Uint64
	innerNoTun       atomic.Uint64
	migrations       atomic.Uint64
	gateChanges      atomic.Uint64
	recvBatches      atomic.Uint64
	sendBatches      atomic.Uint64
}

// Loop is one tunnel: one session, one tun layer, and whichever carrier is
// underneath it at the moment.
type Loop struct {
	sess   *session.Driver
	tn     *tun.Tunnel
	clock  Clock
	sizing Sizing
	reseq  resequencer

	wake     chan struct{}
	started  atomic.Bool
	finished atomic.Bool

	mu       sync.Mutex
	sendMu   sync.Mutex
	recvMu   sync.Mutex
	base     context.Context
	car      carrier.Conn
	carCtx   context.Context
	carStop  context.CancelFunc
	carGen   uint64
	openedAt time.Time
	carErr   error

	gateMu sync.Mutex
	down   bool

	closeOnce sync.Once

	writeBuf       []byte
	writeBatchBufs [][]byte
	writeBatchMsgs []carrier.BatchMsg

	// txPending holds messages this loop already SEALED (nonce counter spent)
	// but the carrier refused (a full send buffer / EWOULDBLOCK). They are kept,
	// not discarded, and RETRANSMITTED verbatim before any new message is sealed.
	// Re-sending the identical sealed bytes reuses the same (key, nonce, plaintext)
	// and is safe (see the nonce contract in winn3/session/driver.go); re-sealing
	// would not be. Discarding them instead (the original behaviour) let the
	// send counter race ahead of what the peer received, and a gap larger than the
	// peer's token window (core.DefaultTokenWindow) stranded the peer's receive
	// window permanently: a silent one-way blackhole caught only by liveness.
	// Only the write-loop goroutine touches these.
	txPending [][]byte
	// txPendingGen is the carrier generation txPending was sealed for.
	txPendingGen uint64

	// txStalled records that the last drain could not place everything it had:
	// the write loop then waits for the carrier to drain rather than busy-spinning.
	txStalled bool
	// txStallSince is when the current unbroken stall began; zero when none.
	txStallSince time.Time

	c counters
}

// NewClient builds the initiating half of a tunnel.
func NewClient(cfg Config) (*Loop, error) {
	return newLoop(cfg, session.NewClient)
}

// NewGateway builds the responding half of a tunnel. It emits nothing until an
// initiation is delivered to it.
func NewGateway(cfg Config) (*Loop, error) {
	return newLoop(cfg, session.NewGateway)
}

// NewGatewayFromDriver attaches a gateway handshake that the shared responder
// already authenticated. The caller must use the same sizing and session
// configuration for that handshake and this loop.
func NewGatewayFromDriver(cfg Config, authenticated *session.Driver) (*Loop, error) {
	if authenticated == nil || len(authenticated.PeerStatic()) == 0 ||
		authenticated.State().Terminal() {
		return nil, errWrap(ErrConfig, "gateway handshake is not authenticated")
	}
	if authenticated.MaxMessageSize() != cfg.Sizing.MessageSize {
		return nil, errWrap(ErrSizeMismatch, "authenticated gateway size differs from the carrier plan")
	}
	return newLoop(cfg, func(session.Config) (*session.Driver, error) {
		return authenticated, nil
	})
}

func newLoop(cfg Config, build func(session.Config) (*session.Driver, error)) (*Loop, error) {
	if cfg.Clock == nil {
		cfg.Clock = SystemClock{}
	}
	if cfg.Sizing.MessageSize == 0 {
		return nil, errWrap(ErrConfig, "sizing is not set; build it with NewSizing")
	}
	if cfg.Session.MaxMessageSize != 0 {
		return nil, errWrap(ErrSizeNotPinned,
			"Session.MaxMessageSize is %d; the plan floor for this migration plan is %d",
			cfg.Session.MaxMessageSize, cfg.Sizing.MessageSize)
	}
	if cfg.Session.PathMTU != 0 {
		// Same argument as the line above, one input earlier. The path MTU the
		// two ends compare across the handshake must be the one this Sizing was
		// built from; a host that could set it separately could tell the far
		// end a number it did not size itself at, and the check that closed
		// silent-refusal instance #3 would then be comparing fiction.
		return nil, errWrap(ErrSizeNotPinned,
			"Session.PathMTU is %d; it comes from Sizing, which was built at %d",
			cfg.Session.PathMTU, cfg.Sizing.PathMTU)
	}
	if cfg.Carrier == nil {
		return nil, errWrap(ErrConfig, "no carrier")
	}
	if !cfg.Sizing.Allows(cfg.Carrier.Class()) {
		return nil, errWrap(ErrConfig,
			"the dialled carrier is %s but the migration plan does not name it, so the floor was not computed over it",
			cfg.Carrier.Class())
	}
	if got := cfg.Carrier.MaxMessageSize(); got < cfg.Sizing.MessageSize {
		return nil, errWrap(ErrSizeMismatch,
			"carrier %s carries %d bytes, below the %d-byte plan floor",
			cfg.Carrier.Class(), got, cfg.Sizing.MessageSize)
	}
	if cfg.Reseq.Enabled {
		if _, ok := cfg.Carrier.(carrier.BatchCarrier); !ok {
			return nil, errWrap(ErrConfig,
				"Reseq is enabled but carrier %s is not a batch carrier: the resequencer runs between RecvBatch and DeliverBatch and has no scalar path",
				cfg.Carrier.Class())
		}
	}

	// The one place the size is set. It is set from the floor over every class
	// the session may escalate TO, never from the class it dialled, and never
	// from session.DefaultMaxMessageSize.
	cfg.Session.MaxMessageSize = cfg.Sizing.MessageSize
	// And the input that floor was derived from, which is the number the two
	// ends can compare. A responder states it in the handshake response
	// payload; an initiator either applies the minimum (when the host device
	// can SetMTU, or there is no tun) or refuses a response that names a
	// different one. See winn3/session/pathmtu.go.
	cfg.Session.PathMTU = cfg.Sizing.PathMTU
	canApply := cfg.Tun == nil
	if cfg.Tun != nil {
		_, canApply = cfg.Tun.Device.(tun.MTUSetter)
	}
	cfg.Session.ApplyNegotiatedPathMTU = canApply
	if cfg.Session.Clock == nil {
		cfg.Session.Clock = SessionClock{Clock: cfg.Clock}
	}

	sess, err := build(cfg.Session)
	if err != nil {
		return nil, err
	}

	const batchCapacity = txCarrierBatchSize
	writeBatchBufs := make([][]byte, batchCapacity)
	writeBatchMsgs := make([]carrier.BatchMsg, batchCapacity)
	for i := range writeBatchBufs {
		writeBatchBufs[i] = make([]byte, cfg.Sizing.MessageSize)
		writeBatchMsgs[i] = carrier.BatchMsg{
			Payload: writeBatchBufs[i],
		}
	}

	l := &Loop{
		sess:           sess,
		clock:          cfg.Clock,
		sizing:         cfg.Sizing,
		wake:           make(chan struct{}, 1),
		car:            cfg.Carrier,
		openedAt:       cfg.Clock.Now(),
		writeBuf:       make([]byte, cfg.Sizing.MessageSize),
		writeBatchBufs: writeBatchBufs,
		writeBatchMsgs: writeBatchMsgs,
	}
	l.reseq.configure(cfg.Reseq)

	if cfg.Tun != nil {
		tc := *cfg.Tun
		if tc.Sink != nil {
			return nil, errWrap(ErrConfig, "Tun.Sink must be nil; the loop supplies it")
		}
		if tc.CarrierFloorMessageSize != 0 {
			return nil, errWrap(ErrSizeNotPinned,
				"Tun.CarrierFloorMessageSize is %d; the loop pins it to the %d-byte plan floor",
				tc.CarrierFloorMessageSize, cfg.Sizing.MessageSize)
		}
		if tc.Clock == nil {
			tc.Clock = SessionClock{Clock: cfg.Clock}
		}
		tc.Sink = frameSink{sess: sess, wake: l.signalWake}
		tc = cfg.Sizing.TunConfig(tc)
		tn, err := tun.New(tc)
		if err != nil {
			return nil, err
		}
		if tn.InnerMTU() != cfg.Sizing.InnerMTU {
			// Unreachable: TunConfig set the floor. Kept because the alternative
			// to a loud refusal here is a silent black hole on the first
			// migration, and this is the last place that can see both numbers.
			return nil, errWrap(ErrSizeMismatch,
				"tun inner MTU %d does not match the plan floor's %d",
				tn.InnerMTU(), cfg.Sizing.InnerMTU)
		}
		l.tn = tn
	}
	return l, nil
}

// Session exposes the session driver for status and for the escalation signal.
// It does not expose the sealer: winn3/session holds no exported path to it.
func (l *Loop) Session() *session.Driver { return l.sess }

// Tunnel exposes the inner-IP layer, or nil. A host reads Stats().RxPackets from
// it for the staged-start promotion gate.
//
// The loop OWNS the gate. Do not call Tunnel().SetState or Tunnel().Gate().Set:
// the loop is the single writer, and a second writer can open a gate the loop
// has latched down.
func (l *Loop) Tunnel() *tun.Tunnel { return l.tn }

// SendInner encrypts and transmits one inner IP packet directly, bypassing
// this loop's tun.Tunnel (if any) entirely.
//
// # Why this exists
//
// Config.Tun's doc names "a gateway-side session whose inner side is the
// gateway's own forwarding table" as a real shape and, until this method,
// nothing implemented the second half of it: deliverInner drops every inner
// packet when cfg.Tun is nil (counted as InnerNoTun) because there was
// nothing to hand it to, and winn3/tun cannot be that thing for a real
// multi-peer forwarding gateway even when Tun is set: its own package doc
// states the job is to make an endpoint "structurally incapable of acting as
// a router for anyone else's traffic", by checking every outbound packet's
// SOURCE against the one fixed address this endpoint was assigned. That is
// exactly right for a client, and it is exactly what a gateway that must
// hand an arbitrary internet reply (sourced from whoever the peer's packet
// was addressed to, never from the gateway's own assigned address) back to
// the correct one of many sessions cannot satisfy: no relaxation of
// tun.Config.AcceptTransit reaches the source check, because relaxing it
// would let any packet written to the gateway's shared device be encrypted
// into ANY session's tunnel, which is the cross-peer injection AcceptTransit
// was never meant to open. See cmd/winn3-gateway's forwarding table for the
// caller this method exists for.
//
// # What this method does NOT do
//
// It performs NO address validation of pkt: no martian check, no ownership
// check, none of what winn3/tun's validator does for the direction this
// bypasses. The caller is the authority. By the time a packet reaches here it
// must already have been matched, by the caller's own forwarding table, to
// the ONE session it belongs to. A caller that hands this method a packet it
// has not already attributed correctly has built a cross-peer injection bug,
// not used this method wrong.
//
// # The fail-closed check it DOES do
//
// It refuses unless the session is in the one state tunStateFor maps to
// tun.StateCarrying (StateEstablished), which is the same predicate syncGate
// applies to a tun.Tunnel's gate, and it returns tun.ErrNotCarrying (imported
// already; not a new sentinel) so a caller checking for that error sees one
// consistent signal whether the drop came from a real Gate or from this
// bypass. A caller with no tun.Tunnel has no Gate to ask, so this check IS
// the fail-closed authority for the path it serves: there is no second gate
// hiding downstream that would otherwise let a packet queue across a rekey or
// a teardown.
//
// It also wakes the write loop, exactly as frameSink.SendData does for the
// tun.Tunnel path. Without it a packet handed to Enqueue from outside the
// loop's own goroutines would sit until the session's next scheduled
// deadline (up to the idle keepalive interval), which is the wrong latency
// for what is meant to be an ordinary reply in a live tunnel.
func (l *Loop) SendInner(pkt []byte) error {
	if state := l.sess.DataPlaneState(); state != session.StateEstablished {
		return errWrap(tun.ErrNotCarrying, "session state is %s, not established", state)
	}
	if err := l.sess.Enqueue(pkt); err != nil {
		if errors.Is(err, session.ErrState) {
			return errWrap(tun.ErrNotCarrying, "session stopped carrying before enqueue")
		}
		return err
	}
	l.signalWake()
	return nil
}

// SendInnerBatch encrypts and transmits a batch of inner IP packets directly,
// holding the session lock once and amortizing wake signals.
func (l *Loop) SendInnerBatch(pkts [][]byte) (int, error) {
	if state := l.sess.DataPlaneState(); state != session.StateEstablished {
		return 0, errWrap(tun.ErrNotCarrying, "session state is %s, not established", state)
	}
	n, err := l.sess.EnqueueBatch(pkts)
	if n > 0 {
		l.signalWake()
	}
	if err != nil && errors.Is(err, session.ErrState) {
		return n, errWrap(tun.ErrNotCarrying, "session stopped carrying before enqueue")
	}
	return n, err
}

// HoldsToken reports whether token is recognized by the active session.
func (l *Loop) HoldsToken(token []byte) bool {
	if l.sess == nil {
		return false
	}
	return l.sess.HoldsToken(token)
}

// Authenticates reports whether msg opens under the active session keys.
func (l *Loop) Authenticates(msg []byte) bool {
	if l.sess == nil {
		return false
	}
	return l.sess.Authenticates(msg)
}

// Sizing reports the plan floor this tunnel was built at.
func (l *Loop) Sizing() Sizing { return l.sizing }

// Carrier reports the carrier in use.
func (l *Loop) Carrier() carrier.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.car
}

// CarrierOpenedAt reports when the carrier in use was installed. It is the
// elapsed-time input the escalation policy reasons over, and it is reset by a
// migration because a fresh carrier has not had its budget yet.
func (l *Loop) CarrierOpenedAt() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.openedAt
}

// Observe reports the session's §4.2 carrier-change signal together with the
// carrier's own health. It contains no decision; see driver/dpbridge.
//
// carrier.Observe only reads Conn.fatal(), and only UDP and Stream implement
// that unexported method. The production gateway (cmd/winn3-gateway) and the
// lab pipes wrap a Pipe, which has no fatal(). The loop's own carErr is how
// a dead Pipe, a stream desync, or a run of transient Recv errors is recorded.
// Without overlaying it here, a policy that reads only Observe() (which is
// what this package's own docs tell a host to do) would see a live session
// on a carrier the reader has already given up on, and the tun gate would
// stay open while every Send failed. That is the "looks up while traffic
// dies" class. CarrierErr() still exists for hosts that poll it directly.
func (l *Loop) Observe() carrier.Signal {
	l.mu.Lock()
	c := l.car
	carErr := l.carErr
	l.mu.Unlock()
	sig := carrier.Observe(l.sess, c)
	if sig.CarrierErr == nil {
		sig.CarrierErr = carErr
	}
	return sig
}

// Stats snapshots the loop's own counters.
func (l *Loop) Stats() Stats {
	var unopenable, narrowed, dataDropped, rekeys, queueHigh, queueDepth, queueCulled, queueOverflow, reordered, lost uint64
	var depth core.ReorderDepth
	if l.sess != nil {
		ss := l.sess.Stats()
		unopenable = ss.Unopenable
		narrowed = ss.PathNarrowedFor
		dataDropped = ss.DataFramesDropped
		rekeys = ss.Rekeys
		queueHigh = ss.DataQueueHighWater
		queueDepth = ss.DataQueueDepth
		queueCulled = ss.DataQueueDropped
		queueOverflow = ss.DataQueueOverflow
		reordered = ss.OuterReordered
		lost = ss.OuterLost
		depth = ss.OuterReorderDepth
	}
	return Stats{
		MessagesSent:     l.c.messagesSent.Load(),
		MessagesReceived: l.c.messagesReceived.Load(),
		SendFailed:       l.c.sendFailed.Load(),
		SendRefused:      l.c.sendRefused.Load(),
		RecvFailed:       l.c.recvFailed.Load(),
		InnerDelivered:   l.c.innerDelivered.Load(),
		InnerRejected:    l.c.innerRejected.Load(),
		InnerNoTun:       l.c.innerNoTun.Load(),
		Migrations:       l.c.migrations.Load(),
		GateChanges:      l.c.gateChanges.Load(),
		Unopenable:       unopenable,
		PathNarrowedFor:  narrowed,

		RecvBatches:        l.c.recvBatches.Load(),
		SendBatches:        l.c.sendBatches.Load(),
		DataFramesDropped:  dataDropped,
		Rekeys:             rekeys,
		DataQueueHighWater: queueHigh,
		DataQueueDepth:     queueDepth,
		DataQueueDropped:   queueCulled,
		DataQueueOverflow:  queueOverflow,

		OuterReordered:    reordered,
		OuterLost:         lost,
		OuterReorderDepth: depth,
	}
}

// ProvenFor is how long this tunnel carried authenticated traffic: from the
// moment its session first established to the last message that opened under
// it. Zero until the session establishes. It is what Reconnect reads, through
// ProvenRunner, to tell a round that proved itself from one that only held a
// socket open, so it is measured on the session's own evidence rather than on
// how long Run happened to last.
func (l *Loop) ProvenFor() time.Duration {
	if l.sess == nil {
		return 0
	}
	first, last := l.sess.AuthenticatedSpan()
	if first.IsZero() || last.Before(first) {
		return 0
	}
	return last.Sub(first)
}

// Established reports whether this tunnel's session EVER reached Established,
// whatever it is now. It is the historical fact a supervisor folds in after a
// round ends: a round that established and died at once has a zero ProvenFor
// and is still a round that established.
func (l *Loop) Established() bool {
	if l.sess == nil {
		return false
	}
	first, _ := l.sess.AuthenticatedSpan()
	return !first.IsZero()
}

// PeerCloseReason is the reason the peer gave in an authenticated CLOSE, or
// zero if it sent none.
func (l *Loop) PeerCloseReason() session.CloseReason {
	return l.sess.PeerCloseReason()
}

// --- the loop ----------------------------------------------------------------

// maxDrainPerWake bounds one drain so that a large send queue cannot starve the
// loop from checking context cancellation, MTU updates, or gate state.
const maxDrainPerWake = 8192

// txCarrierBatchSize bounds one outer sendmmsg vector on the transmit path
// only. It is deliberately package-local to the driver: session.MaxBatchSize
// keeps its value of 32, core/batch.go and session/batch.go take zero diff, and
// the Round 35 and Round 38 downlink freeze is provable by
// `git diff --exit-code -- winn3/core/batch.go winn3/session/batch.go`.
const txCarrierBatchSize = 256

// txBatchesPerSend is the number of whole crypto batches accumulated into one
// SendBatch call: 256 / 32 = 8.
const txBatchesPerSend = txCarrierBatchSize / session.MaxBatchSize

// Compile-time guard: txCarrierBatchSize must stay an exact multiple of
// session.MaxBatchSize so the accumulation loop never leaves a partial crypto
// window.
var _ [0]struct{} = [txCarrierBatchSize % session.MaxBatchSize]struct{}{}

// maxSpins bounds consecutive wake-ups that move nothing and wait for nothing.
//
// It is a battery guard, not a correctness one. A future change that leaves a
// deadline permanently in the past would turn this loop into a busy wait on a
// handset, and a VPN that flattens a battery in an hour is a VPN a user under a
// hostile state turns off.
const maxSpins = 4096

// Run drives the tunnel until ctx is cancelled, Close is called, or the session
// terminates. It is the host's goroutine.
//
// On return the tun gate is LATCHED DOWN and Gate.Set has drained, so no packet
// is still on its way to the session or to the host device, including from the
// device pump, which Run starts but does not wait for. The device pump ends when
// the host closes the device; that lifecycle is the host's, which is why
// tun.Device has no Close.
func (l *Loop) Run(ctx context.Context) error {
	if !l.started.CompareAndSwap(false, true) {
		return errWrap(ErrConfig, "Run was called twice on one loop")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	l.mu.Lock()
	l.base = ctx
	l.carCtx, l.carStop = context.WithCancel(ctx)
	l.mu.Unlock()

	var wg sync.WaitGroup
	if l.tn != nil {
		go func() { _ = l.tn.PumpOutbound(ctx) }()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		l.readLoop(ctx)
	}()

	err := l.writeLoop(ctx)
	l.finished.Store(true)
	// Close may have queued a CLOSE after this write loop had already
	// returned (context cancel, then Loop.Close). terminate/Wipe lives on
	// that CLOSE's after-hook and will never run unless someone Polls.
	if l.sess.State() == session.StateClosing {
		l.drainQueuedClose()
	}

	// Order matters. Latch the gate down BEFORE cancelling, so that the drain
	// barrier has run by the time anything else stops: when latchDown returns,
	// no packet anywhere in the tun layer is still on its way.
	l.latchDown()
	cancel()
	l.stopCarrier()
	wg.Wait()
	return err
}

// writeLoop drains, re-applies a negotiated inner MTU, syncs the gate, and waits.
//
// applyNegotiatedMTU runs before syncGate so a shrink that landed in the
// handshake is clamped onto the device while the gate is still closed. That is
// not sufficient on its own: readLoop also calls syncGate, on the goroutine
// that completes the handshake, and would otherwise open the gate at the old
// device MTU. syncGate therefore clamps again immediately before any transition
// to StateCarrying. The write-loop call is the early path (clamp during
// Initiating, after the notice, before Established); the syncGate call is the
// one that cannot be skipped.
//
// It deliberately does NOT latch the gate down on the way out. Every exit from
// this function goes back to Run, which latches once; one call site for the
// property users' safety rests on is auditable, and five is a claim. The
// distinction matters most on the path that is easiest to forget: a cancelled
// context stops the loop while the session is still ESTABLISHED, so nothing in
// the state machine closes the gate and only Run's latch does.
func (l *Loop) writeLoop(ctx context.Context) error {
	defer l.abandonRetained()
	spins := 0
	lastRecv := l.c.messagesReceived.Load()
	for {
		moved, err := l.drain(ctx)
		if err != nil {
			return err
		}
		if err := l.applyNegotiatedMTU(); err != nil {
			return err
		}
		l.syncGate()

		st := l.sess.State()
		if st.Terminal() {
			fmt.Fprintf(os.Stderr, "winn3-debug: [driver.writeLoop] terminal state=%v err=%v\n", st, l.sess.Err())
			if st == session.StateFailed {
				return errWrap(ErrSessionFailed, "%w", l.sess.Err())
			}
			return nil
		}

		// A download is not a busy wait. This loop owns the SEND direction, so on
		// a unidirectional INBOUND transfer it legitimately wakes with nothing to
		// move, over and over, for as long as the transfer lasts. Counting those
		// wakes against the battery budget killed real sessions: MEASURED
		// 2026-08-12, a gateway serving a download recorded sent=2 against
		// recv=7796 and died at 4097 wakes with the transfer still healthy and
		// both ends still Established. It presented as "the tunnel dies after
		// ~4096 packets", and faster transfers died sooner because they produce
		// more empty wakes per second.
		//
		// Receive progress proves the session is alive and doing work, so it
		// clears the budget exactly as sending does. The guard keeps its purpose:
		// a genuine stuck-deadline busy wait moves nothing in EITHER direction
		// and is still caught at the same 4096.
		recv := l.c.messagesReceived.Load()
		if moved > 0 || recv != lastRecv {
			spins = 0
			lastRecv = recv
		} else if spins++; spins > maxSpins {
			return errWrap(ErrConfig, "the write loop woke %d times without moving a message", spins)
		}

		if l.txStalled {
			// The carrier could not accept everything the last drain offered. New
			// sealing is frozen (l.txPending holds the unsent, already-sealed
			// bytes), so the send counter cannot run ahead of the peer while we
			// wait. Back off briefly so the send buffer can drain instead of
			// busy-retrying it. Sealing, and with it the session's timers, stays
			// frozen for at most carrierStallLimit; past that the carrier is
			// treated as failed so the host can rebuild the tunnel.
			if err := l.retentionExpired(); err != nil {
				return err
			}
			if err := l.waitForCarrierDrain(ctx); err != nil {
				return err
			}
			continue
		}

		if l.sess.HasPendingWork() {
			continue
		}

		if err := l.waitForWork(ctx); err != nil {
			return err
		}
	}
}

// carrierDrainBackoff is how long the write loop waits for a full send buffer to
// drain before retrying. It is short so a brief blip costs little latency, and
// bounded so a truly dead carrier is still caught by the spin guard and liveness.
const carrierDrainBackoff = time.Millisecond

// carrierStallLimit bounds how long refused sealed messages may block new
// sealing (and so the session's timers) before the loop gives up. It is one
// absolute budget from the first refusal: partial progress, receive traffic and
// wakes do not extend it.
const carrierStallLimit = 2 * time.Second

// retain records sealed bytes the carrier refused and, on the first refusal of
// a stall, starts the retention budget.
func (l *Loop) retain(b []byte, gen uint64) {
	if len(l.txPending) == 0 {
		l.txStallSince = l.clock.Now()
	}
	l.txPending = append(l.txPending, b)
	l.txPendingGen = gen
	l.txStalled = true
}

// retentionExpired fails the loop once the retention budget is spent. The
// retained bytes are abandoned into SendFailed exactly once.
func (l *Loop) retentionExpired() error {
	if len(l.txPending) == 0 || l.txStallSince.IsZero() {
		return nil
	}
	held := l.clock.Now().Sub(l.txStallSince)
	if held < carrierStallLimit {
		return nil
	}
	l.c.sendFailed.Add(uint64(len(l.txPending)))
	l.txPending = l.txPending[:0]
	l.txStallSince = time.Time{}
	err := errWrap(ErrSessionFailed, "the carrier refused sealed messages for %v", held)
	l.setCarrierErr(err)
	return err
}

// abandonRetained counts whatever is still retained into SendFailed and clears
// it. Every other abandonment path clears txPending first, so nothing is counted
// twice.
func (l *Loop) abandonRetained() {
	if len(l.txPending) > 0 {
		l.c.sendFailed.Add(uint64(len(l.txPending)))
		l.txPending = l.txPending[:0]
	}
	l.txStallSince = time.Time{}
}

// retentionContext bounds a resend of retained bytes by what is left of the
// retention budget, so a carrier that blocks until cancelled cannot hold the
// loop past carrierStallLimit.
func (l *Loop) retentionContext(cctx context.Context) (context.Context, context.CancelFunc) {
	left := carrierStallLimit - l.clock.Now().Sub(l.txStallSince)
	if left < 0 {
		left = 0
	}
	return context.WithTimeout(cctx, left)
}

// waitForCarrierDrain waits out a transient send-buffer stall. Unlike
// waitForWork it does NOT return early on HasPendingWork: the pending work is
// exactly what the carrier just refused, and re-offering it at CPU speed is the
// busy loop this avoids.
func (l *Loop) waitForCarrierDrain(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	t := l.clock.NewTimer(carrierDrainBackoff)
	defer t.Stop()
	// l.wake is deliberately not selected: receive traffic must not turn the
	// backoff into a busy retry of bytes the carrier just refused.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C():
		return nil
	}
}

// drain empties the session's outbox onto the carrier.
//
// A send error is neither a dead session nor, on its own, a dead carrier. The
// measured censorship failure produces no error at all (the socket opens, every
// write succeeds, the reads never return), so a loop that tore down on ENOBUFS
// would fail over for the wrong reason and still not fail over for the right
// one. The message is counted as lost and the loop waits rather than spinning on
// a carrier that is refusing.
func (l *Loop) drain(ctx context.Context) (int, error) {
	l.sendMu.Lock()
	defer l.sendMu.Unlock()

	// Age the send queue first, stalled or not: CoDel's sojourn signal is
	// knowable here, on the dequeue side, and a queue standing behind a
	// refusing carrier must shed while it waits, not only when it moves.
	if l.sess != nil {
		l.sess.CullSendQueue(l.clock.Now())
		// -send-queue-fq: refill the ready window from the flow queues. A
		// no-op unless the host called SetSendQueueFQ.
		l.sess.FillSendWindow()
	}

	moved := 0
	l.txStalled = false
	for i := 0; i < maxDrainPerWake; {
		c, cctx, gen := l.currentCarrier()
		if len(l.txPending) > 0 && gen != l.txPendingGen {
			// The carrier migrated while bytes were retained. They are abandoned
			// rather than moved to another carrier generation; at most one batch
			// (txCarrierBatchSize) is lost, below any peer token window.
			l.c.sendFailed.Add(uint64(len(l.txPending)))
			l.txPending = l.txPending[:0]
			l.txStallSince = time.Time{}
		}
		if batchCarrier, isBatch := c.(carrier.BatchCarrier); isBatch {
			// Retransmit sealed-but-unsent messages from a prior stall, in order,
			// before sealing anything new. This keeps the send counter aligned with
			// what the peer actually receives.
			if len(l.txPending) > 0 {
				if err := l.retentionExpired(); err != nil {
					return moved, err
				}
				rctx, cancel := l.retentionContext(cctx)
				sent, flushErr := l.flushPendingBatch(rctx, batchCarrier)
				cancel()
				moved += sent
				if errors.Is(flushErr, carrier.ErrPathMTUReduced) {
					l.c.sendFailed.Add(uint64(len(l.txPending)))
					l.txPending = l.txPending[:0]
					l.txStallSince = time.Time{}
					l.setCarrierErr(flushErr)
					return moved, flushErr
				}
				if len(l.txPending) > 0 {
					l.txStalled = true
					return moved, nil
				}
				l.txStallSince = time.Time{}
			}
			batchLimit := len(l.writeBatchMsgs)
			if batchLimit > txCarrierBatchSize {
				batchLimit = txCarrierBatchSize
			}
			if remaining := maxDrainPerWake - i; remaining < batchLimit {
				batchLimit = remaining
			}

			count := 0
			var pollErr error
			for count < batchLimit {
				window := batchLimit - count
				if window > session.MaxBatchSize {
					window = session.MaxBatchSize
				}
				l.sess.FillSendWindow()
				got, err := l.sess.PollBatchInto(l.writeBatchBufs[count : count+window])
				l.syncGate()
				count += got
				if err != nil {
					pollErr = err
					break
				}
				if got < window {
					// Short poll means the outbox is drained.
					break
				}
			}
			if count == 0 {
				return moved, pollErr
			}
			for k := 0; k < count; k++ {
				l.writeBatchMsgs[k].Payload = l.writeBatchBufs[k]
				l.writeBatchMsgs[k].N = len(l.writeBatchBufs[k])
			}
			// One presentation. An unsent suffix, whether refused outright or
			// left by a positive short result, is never re-presented here under
			// the unbounded carrier context: it enters retention, which applies
			// the backoff and the budget-bounded context before the next attempt.
			sent, sendErr := batchCarrier.SendBatch(cctx, l.writeBatchMsgs[:count])
			if sent < 0 || sent > count {
				sent, sendErr = 0, io.ErrShortWrite
			}
			if sent > 0 {
				l.c.sendBatches.Add(1)
			}
			l.c.messagesSent.Add(uint64(sent))
			moved += sent
			if count > sent {
				l.c.sendRefused.Add(uint64(count - sent))
				// The carrier refused messages this loop already sealed. In the
				// Established data phase, keep them for verbatim retransmission
				// (their transport nonce is spent, so re-sealing is unsafe but
				// re-sending the same bytes is safe) and stop sealing new ones until
				// they drain. Discarding them here was the defect: the send counter
				// then ran ahead of the peer, and a contiguous gap past the peer's
				// token window stranded its receive window for good. Before
				// Established the handshake owns its own retransmit schedule, so the
				// old drop-and-count behaviour stands there.
				// A path-MTU refusal is permanent for these bytes: they were sealed
				// at the old ceiling and can never fit, so they are counted and
				// dropped. One batch is at most txCarrierBatchSize (256), below the
				// peer's token window, so this gap stays recoverable.
				if l.sess.State() == session.StateEstablished && !errors.Is(sendErr, carrier.ErrPathMTUReduced) {
					for k := sent; k < count; k++ {
						b := make([]byte, l.writeBatchMsgs[k].N)
						copy(b, l.writeBatchBufs[k][:l.writeBatchMsgs[k].N])
						l.retain(b, gen)
					}
				} else {
					l.c.sendFailed.Add(uint64(count - sent))
				}
			}
			if pollErr != nil {
				return moved, pollErr
			}
			if sendErr != nil {
				if errors.Is(sendErr, carrier.ErrPathMTUReduced) {
					l.setCarrierErr(sendErr)
					return moved, sendErr
				}
				if ctx.Err() != nil {
					return moved, ctx.Err()
				}
				return moved, nil
			}
			if len(l.txPending) > 0 {
				// A short result with nil error from a full batch left a retained
				// suffix. Return so writeLoop applies the backoff before the retry;
				// continuing would re-present it at once from the top of this loop.
				return moved, nil
			}
			i += count
			if count < batchLimit {
				return moved, nil
			}
			continue
		}

		// Retransmit any sealed-but-unsent messages before sealing new ones, the
		// same rule as the batch path, so the send counter never runs ahead of the
		// peer.
		for len(l.txPending) > 0 {
			if err := l.retentionExpired(); err != nil {
				return moved, err
			}
			rctx, cancel := l.retentionContext(cctx)
			err := c.Send(rctx, l.txPending[0])
			cancel()
			if err != nil {
				l.c.sendRefused.Add(1)
				if errors.Is(err, carrier.ErrPathMTUReduced) {
					l.c.sendFailed.Add(uint64(len(l.txPending)))
					l.txPending = l.txPending[:0]
					l.txStallSince = time.Time{}
					l.setCarrierErr(err)
					return moved, err
				}
				l.txStalled = true
				if ctx.Err() != nil {
					return moved, ctx.Err()
				}
				return moved, nil
			}
			l.c.messagesSent.Add(1)
			moved++
			l.txPending = l.txPending[1:]
			if len(l.txPending) == 0 {
				l.txStallSince = time.Time{}
			}
		}

		l.sess.FillSendWindow()
		msg, err := l.sess.PollInto(l.writeBuf)
		if err != nil {
			return moved, err
		}
		// Poll may start or complete a rekey. Project that transition onto the
		// physical gate before sending the resulting control message or polling
		// again, rather than leaving the host-facing gate one drain behind.
		l.syncGate()
		if msg == nil {
			return moved, nil
		}
		if err := c.Send(cctx, msg); err != nil {
			// In the Established data phase, keep the refused sealed message for
			// verbatim retransmission rather than discarding it (spent nonce), and
			// stop sealing new ones until it drains. Before Established the handshake
			// retransmit schedule owns replay, so keep the old drop-and-count there.
			l.c.sendRefused.Add(1)
			if l.sess.State() == session.StateEstablished && !errors.Is(err, carrier.ErrPathMTUReduced) {
				b := make([]byte, len(msg))
				copy(b, msg)
				l.retain(b, gen)
			} else {
				l.c.sendFailed.Add(1)
			}
			if errors.Is(err, carrier.ErrPathMTUReduced) {
				l.setCarrierErr(err)
				return moved, err
			}
			if ctx.Err() != nil {
				return moved, ctx.Err()
			}
			return moved, nil
		}
		l.c.messagesSent.Add(1)
		moved++
		i++
	}
	// The queue is deeper than one drain. Come straight back rather than
	// sleeping on a session that has more to say.
	l.signalWake()
	return moved, nil
}

// flushPendingBatch retransmits the sealed-but-unsent messages in l.txPending,
// in order, dropping the prefix the carrier accepts. It returns how many were
// sent and the carrier error that stopped it, and leaves the rest in l.txPending
// for the next attempt. It never seals.
func (l *Loop) flushPendingBatch(cctx context.Context, bc carrier.BatchCarrier) (int, error) {
	msgs := make([]carrier.BatchMsg, len(l.txPending))
	for i, b := range l.txPending {
		msgs[i] = carrier.BatchMsg{Payload: b, N: len(b)}
	}
	// One presentation per attempt: a positive short result leaves the rest for
	// the next attempt, after the backoff, under the same budget.
	sent, sendErr := bc.SendBatch(cctx, msgs)
	if sent < 0 || sent > len(msgs) {
		sent, sendErr = 0, io.ErrShortWrite
	}
	l.c.messagesSent.Add(uint64(sent))
	if sent < len(l.txPending) {
		l.c.sendRefused.Add(uint64(len(l.txPending) - sent))
	}
	if sent == len(l.txPending) {
		l.txPending = l.txPending[:0]
	} else {
		l.txPending = append(l.txPending[:0], l.txPending[sent:]...)
	}
	return sent, sendErr
}

// waitForWork blocks until something happens or the session's next deadline
// arrives. This is the wait the session and tun layers refuse to own.
func (l *Loop) waitForWork(ctx context.Context) error {
	deadline := l.sess.NextDeadline()
	if deadline.IsZero() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-l.wake:
			return nil
		}
	}
	d := deadline.Sub(l.clock.Now())
	if d <= 0 {
		// Already due. Do not build a timer for it; the next Poll consumes it.
		return ctx.Err()
	}
	// A saturated link has work waiting at nearly every wake, and the timer this
	// function would build for it is created, inserted into the runtime timer
	// heap, and removed again without ever firing. MEASURED, Galaxy S26 Ultra
	// 2026-09-17: time.NewTimer under waitForWork was 64k of the 2.5M objects
	// BenchmarkBatchCarrierLoopThroughput allocated, and every one of them also
	// took the timer lock twice. Checking the two channels that are already
	// ready costs two non-blocking receives.
	//
	// Cancellation is checked FIRST and separately. Folding it into the same
	// select as the wake would let a permanently-signalled wake channel starve
	// ctx.Done() for as long as the transfer lasts, which is the shape of a
	// tunnel that ignores its own teardown.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	select {
	case <-l.wake:
		return nil
	default:
	}
	if l.sess.HasPendingWork() {
		return nil
	}
	t := l.clock.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.wake:
		return nil
	case <-t.C():
		return nil
	}
}

// newReceiveBatchStorage provisions every wire buffer before the carrier read.
// Plaintext and packet views are allocated only when a returned slot is used.
func newReceiveBatchStorage(capacity int) ([]carrier.BatchMsg, []session.ReceiveSlot) {
	const batchStorageBudget = 2 * 1024 * 1024
	slots := min(session.MaxBatchSize, max(1, batchStorageBudget/(10*capacity)))
	msgs := make([]carrier.BatchMsg, slots)
	recv := make([]session.ReceiveSlot, slots)
	for i := range msgs {
		msgs[i].Payload = make([]byte, capacity)
	}
	return msgs, recv
}

// prepareReceiveBatchSlots keeps per-slot backing distinct and reusable until
// the carrier ceiling changes. Prepare the whole returned batch before delivery.
func prepareReceiveBatchSlots(msgs []carrier.BatchMsg, recv []session.ReceiveSlot, n, capacity int) {
	for i := 0; i < n; i++ {
		if recv[i].Scratch == nil {
			recv[i].Scratch = make([]byte, capacity)
			recv[i].Packets = make([][]byte, 0, capacity/3)
		}
		recv[i].Message = msgs[i].Payload[:msgs[i].N]
		recv[i].Packets = recv[i].Packets[:0]
	}
}

// deliverReceiveBatch consumes borrowed packet views synchronously. Clear every
// returned slot before reuse, including any suffix left by a terminal error.
// This releases slice references only; it does not erase plaintext storage.
func (l *Loop) deliverReceiveBatch(slots []session.ReceiveSlot) error {
	defer func() {
		for i := range slots {
			clear(slots[i].Packets)
			slots[i].Packets = slots[i].Packets[:0]
		}
	}()
	offset := 0
	for offset < len(slots) {
		done, err := l.sess.DeliverBatch(slots[offset:])
		if err != nil {
			return err
		}
		l.syncGate()
		if done == 0 {
			m := slots[offset].Message
			inner, err := l.sess.Deliver(m)
			if err != nil {
				return err
			}
			l.syncGate()
			l.c.messagesReceived.Add(1)
			for _, p := range inner {
				l.deliverInner(p)
			}
			offset++
			continue
		}
		for i := 0; i < done; i++ {
			slotIdx := offset + i
			l.c.messagesReceived.Add(1)
			for _, p := range slots[slotIdx].Packets {
				l.deliverInner(p)
			}
		}
		offset += done
	}
	return nil
}

// readLoop moves messages off the carrier into the session, and the inner
// packets that come back out into the tun layer.
func (l *Loop) readLoop(ctx context.Context) {
	var scratch []byte
	var batchMsgs []carrier.BatchMsg
	var recvSlots []session.ReceiveSlot
	messageCapacity := 0

	type receiverInto interface {
		RecvInto(context.Context, []byte) ([]byte, error)
	}
	consecutive := 0
	for {
		c, cctx, gen := l.currentCarrier()
		if batchCarrier, ok := c.(carrier.BatchCarrier); ok {
			// Bound batch storage by the current carrier ceiling. Scalar
			// carriers allocate none of these arrays. A jumbo ceiling reduces
			// the slot count instead of multiplying TLV views by 32.
			if capacity := c.MaxMessageSize(); capacity != messageCapacity {
				messageCapacity = capacity
				batchMsgs, recvSlots = newReceiveBatchStorage(capacity)
			}
			// While the resequencer holds messages, cap the receive wait at the
			// hold deadline so the time bound fires even with no arrival. The
			// timer exists only on the hold path; an in-order stream never
			// builds one.
		recvCtx := cctx
		var cancelRecv context.CancelFunc
		if dl := l.reseq.deadline(); !dl.IsZero() {
			wait := dl.Sub(l.clock.Now())
			if wait < 0 {
				wait = 0
			}
			recvCtx, cancelRecv = context.WithTimeout(cctx, wait)
		}
			n, err := batchCarrier.RecvBatch(recvCtx, batchMsgs)
			if cancelRecv != nil {
				cancelRecv()
			}
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if errors.Is(err, context.DeadlineExceeded) && l.reseq.holds() {
					// The hold timer fired with nothing new arriving: release
					// what the time bound has aged out, in counter order.
					consecutive = 0
					if rel := l.reseq.releaseExpired(l.clock.Now()); len(rel) > 0 {
						var derr error
						l.recvMu.Lock()
						if l.carrierGeneration() == gen {
							derr = l.deliverReceiveBatch(rel)
						}
						l.recvMu.Unlock()
						// As on the batch path below: a released message may
						// be a CLOSE, a probe to answer or a terminal error,
						// and only the write loop's Poll acts on it.
						l.signalWake()
						if derr != nil {
							return
						}
					}
					continue
				}
				if l.carrierGeneration() != gen {
					consecutive = 0
					continue
				}
				l.c.recvFailed.Add(1)
				if errors.Is(err, carrier.ErrClosed) || errors.Is(err, carrier.ErrStreamDesync) {
					l.setCarrierErr(err)
					l.signalWake()
					return
				}
				if consecutive++; consecutive > maxRecvErrors {
					l.setCarrierErr(err)
					l.signalWake()
					return
				}
				continue
			}
			consecutive = 0
			if n == 0 {
				continue
			}
			l.c.recvBatches.Add(1)
			l.recvMu.Lock()
			if l.carrierGeneration() != gen {
				l.recvMu.Unlock()
				continue
			}
			prepareReceiveBatchSlots(batchMsgs, recvSlots, n, messageCapacity)
			deliver := recvSlots[:n]
			if l.reseq.enabled {
				deliver = l.reseq.resequence(deliver, l.sess, l.clock.Now())
			}
			err = l.deliverReceiveBatch(deliver)
			l.recvMu.Unlock()
			if err != nil {
				l.signalWake()
				return
			}
			l.signalWake()
			continue
		}

		var msg []byte
		var err error
		if into, ok := c.(receiverInto); ok {
			if scratch == nil {
				scratch = make([]byte, 65535)
			}
			msg, err = into.RecvInto(cctx, scratch)
		} else {
			msg, err = c.Recv(cctx)
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if l.carrierGeneration() != gen {
				// The carrier was replaced underneath this read. Not an error:
				// it is what a migration looks like from here.
				consecutive = 0
				continue
			}
			l.c.recvFailed.Add(1)
			if errors.Is(err, carrier.ErrClosed) || errors.Is(err, carrier.ErrStreamDesync) {
				l.setCarrierErr(err)
				l.signalWake()
				return
			}
			// A transient read error is ordinary on a datagram carrier. A run of
			// them is not, and spinning on one would burn a handset's battery in
			// exactly the conditions the user is already struggling with.
			if consecutive++; consecutive > maxRecvErrors {
				l.setCarrierErr(err)
				l.signalWake()
				return
			}
			continue
		}
		consecutive = 0

		l.recvMu.Lock()
		if l.carrierGeneration() != gen {
			l.recvMu.Unlock()
			continue
		}
		inner, err := l.sess.Deliver(msg)
		l.recvMu.Unlock()
		if err != nil {
			// Terminal. The write loop observes the same state and returns.
			l.signalWake()
			return
		}
		// Apply the state this Deliver may just have reached, HERE, on the
		// goroutine that reached it.
		l.syncGate()
		l.c.messagesReceived.Add(1)
		for _, p := range inner {
			l.deliverInner(p)
		}
		// A delivered message may have changed the state, answered a probe, or
		// left something queued. Poll is the only thing that can tell.
		l.signalWake()
	}
}

// maxRecvErrors is how many consecutive carrier read errors are tolerated
// before the carrier is reported dead.
const maxRecvErrors = 64

func (l *Loop) deliverInner(p []byte) {
	if l.tn == nil {
		l.c.innerNoTun.Add(1)
		return
	}
	if err := l.tn.Inbound(p); err != nil {
		l.c.innerRejected.Add(1)
		return
	}
	l.c.innerDelivered.Add(1)
}

// --- the gate ----------------------------------------------------------------

// Carrying reports whether the tun gate is open for host traffic.
//
// It is the honest answer to "may I write yet", and it exists because the
// obvious answer is wrong. A host that waits for Session().State() to read
// "established" and then writes is racing the gate: the state is reached inside
// Deliver, on the reader, and the gate is applied fractionally later. Measured
// before the reader synced the gate at all, that race cost 64 of 64 packets to
// TxDroppedClosed on a healthy tunnel. Waiting on this instead has no race in
// it, because this IS the gate.
//
// A loop with no tun layer has no physical gate, so the session's projected
// data-plane state is its gate. It reports carrying only while SendInner may
// admit DATA. SendInner still repeats that check under Enqueue's state lock, so
// hosts must check its error rather than treating this accessor as a durable
// reservation. cmd/winn3-gateway does.
func (l *Loop) Carrying() bool {
	if l.sess.DataPlaneState() != session.StateEstablished {
		return false
	}
	if l.tn == nil {
		return true
	}
	return l.tn.Gate().State() == tun.StateCarrying
}

// syncGate applies the session's state to the tun gate.
//
// It is called from the write loop and, for an opening transition, from the read
// loop that observed the state change (see readLoop). What makes more than one
// caller safe is not scheduling, it is l.down: it is set under gateMu, it is
// monotone, and this function returns before computing anything once it is set.
// So a caller holding a stale "established" cannot reopen a gate another
// goroutine has latched down, which is the one direction that must never lose a
// race.
//
// Closing is also allowed from anywhere, through latchDown, for the same reason.
func (l *Loop) syncGate() {
	if l.tn == nil {
		return
	}
	l.gateMu.Lock()
	defer l.gateMu.Unlock()
	if l.down {
		return
	}
	want := tunStateFor(l.sess.DataPlaneState())
	if want == tun.StateDown {
		l.down = true
	}
	if l.tn.Gate().State() == want {
		return
	}
	// Clamp before opening. Opening first is the original black hole: the host
	// generates packets at the old device MTU, the session has already shrunk
	// MaxMessageSize, and full-size flows vanish while both gates report
	// carrying. A clamp failure latches down rather than opening anyway.
	if want == tun.StateCarrying {
		if err := l.clampNegotiatedInnerMTU(); err != nil {
			l.down = true
			l.tn.Gate().Set(tun.StateDown)
			l.c.gateChanges.Add(1)
			return
		}
	}
	l.tn.Gate().Set(want)
	l.c.gateChanges.Add(1)
}

// applyNegotiatedMTU re-clamps the tun to the inner MTU implied by the
// session's current MaxMessageSize, when that size is narrower than the tun
// was built at.
//
// It is the loop half of silent-refusal instance #3's APPLY path. The session
// half (refusePathMTUMismatch + ShrinkToPeerPathMTU) has already mutated
// MaxMessageSize when Config.ApplyNegotiatedPathMTU was set; without this
// clamp the device MTU stays at the pre-handshake value and the host writes
// packets the tunnel can only drop.
//
// A loop with no tun has nothing to clamp: the session shrink is the whole
// apply. A session that did not shrink (agreement, no claim, or a loud
// refusal that left MaxMessageSize untouched) is a no-op because the new
// inner MTU is not strictly below the tun's.
func (l *Loop) applyNegotiatedMTU() error {
	if l.tn == nil {
		return nil
	}
	l.gateMu.Lock()
	defer l.gateMu.Unlock()
	return l.clampNegotiatedInnerMTU()
}

// clampNegotiatedInnerMTU is the body of applyNegotiatedMTU. The caller holds
// gateMu, which is also the lock syncGate uses, so a clamp and an opening
// cannot interleave.
func (l *Loop) clampNegotiatedInnerMTU() error {
	if l.tn == nil {
		return nil
	}
	newInner := session.InnerMTU(l.sess.MaxMessageSize())
	if newInner <= 0 || newInner >= l.tn.InnerMTU() {
		return nil
	}
	if err := l.tn.ClampInnerMTU(newInner); err != nil {
		return errWrap(ErrConfig, "re-applying the negotiated inner MTU %d: %v", newInner, err)
	}
	return nil
}

// latchDown closes the gate and makes the closure permanent.
//
// tun.Gate.Set is a drain barrier: it takes the write lock, so it does not
// return until every packet that had already been admitted has been handed over
// and released. When this returns, nothing in the tun layer is still on its way
// to the session or to the host device, including from the device pump, which
// may still be blocked in the host's ReadPacket.
func (l *Loop) latchDown() {
	if l.tn == nil {
		return
	}
	l.gateMu.Lock()
	defer l.gateMu.Unlock()
	already := l.down
	l.down = true
	if already && l.tn.Gate().State() == tun.StateDown {
		return
	}
	l.tn.Gate().Set(tun.StateDown)
	l.c.gateChanges.Add(1)
}

// --- carrier ownership --------------------------------------------------------

func (l *Loop) currentCarrier() (carrier.Conn, context.Context, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ctx := l.carCtx
	if ctx == nil {
		ctx = context.Background()
	}
	return l.car, ctx, l.carGen
}

func (l *Loop) carrierGeneration() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.carGen
}

func (l *Loop) setCarrierErr(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.carErr == nil {
		l.carErr = err
	}
}

// CarrierErr reports the last fatal error the loop saw from the carrier, if any.
// A dead carrier and a session that wants a different carrier are different
// facts and the policy layer treats them differently.
func (l *Loop) CarrierErr() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.carErr
}

func (l *Loop) stopCarrier() {
	l.mu.Lock()
	stop := l.carStop
	l.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// Migrate moves the live session onto another carrier without a re-handshake.
//
// It performs no policy. The decision to move, and the choice of destination,
// belong to datapath/escalation.go and datapath/failover.go; driver/dpbridge is
// the adapter that puts this loop's evidence into their vocabulary.
//
// It refuses a destination whose class the migration plan does not name, and
// that refusal is the whole point of Sizing. A plan floor is a promise about the
// classes it was computed over and about no others: migrating outside it is
// exactly how a session ends up 84 bytes too wide on a carrier that reports
// itself healthy.
//
// It does NOT close the old carrier. Closing is the caller's, because a caller
// may want to hold a UDP socket open while it probes the replacement.
func (l *Loop) Migrate(to carrier.Conn) (carrier.Migration, error) {
	if to == nil {
		return carrier.Migration{}, errWrap(ErrConfig, "no destination carrier")
	}
	if !l.sizing.Allows(to.Class()) {
		return carrier.Migration{}, errWrap(ErrConfig,
			"the migration plan does not name %s, so the %d-byte floor was not computed over it",
			to.Class(), l.sizing.MessageSize)
	}

	l.mu.Lock()
	from := l.car
	l.mu.Unlock()

	// *session.Driver implements carrier.MessageSizeSink (SetMaxMessageSize).
	// Passing it directly means a future removal of that method fails to
	// compile rather than migrating with a nil sink. A nil sink on a narrowing
	// move is a loud refusal (ErrMigrationWouldBlackHole), not a black hole;
	// the compile pin is so that loud path cannot be lost by accident.
	m, err := carrier.Migrate(l.sess, from, to, l.sizing.MessageSize)
	if err != nil {
		return m, err
	}

	l.mu.Lock()
	old := l.carStop
	base := l.base
	if base == nil {
		base = context.Background()
	}
	l.car = to
	l.carGen++
	l.openedAt = l.clock.Now()
	l.carErr = nil
	l.carCtx, l.carStop = context.WithCancel(base)
	l.mu.Unlock()

	// Unblock the reader's Recv on the old carrier. It observes the generation
	// change and re-arms on the new one.
	if old != nil {
		old()
	}
	l.c.migrations.Add(1)
	l.signalWake()
	return m, nil
}

// MigrateSilentInitiation keeps the write loop from sending the old handshake
// on the new carrier before a fresh initiation has replaced it.
func (l *Loop) MigrateSilentInitiation(to carrier.Conn) (bool, error) {
	l.sendMu.Lock()
	defer l.sendMu.Unlock()
	l.recvMu.Lock()
	defer l.recvMu.Unlock()
	if l.sess.HasAuthenticatedReply() {
		return false, nil
	}
	if _, err := l.Migrate(to); err != nil {
		return false, err
	}
	if err := l.sess.RetryOnNewCarrier(); err != nil {
		return true, err
	}
	return true, nil
}

// --- lifecycle ----------------------------------------------------------------

// Close asks for an orderly teardown: the gate is latched down first so no
// further inner packet can enter, then a CLOSE frame is queued. The CLOSE rides
// an ordinary message, so a dying session looks exactly like a busy one.
//
// It returns as soon as the teardown is requested. Run returns once the CLOSE
// has been handed to the carrier and the session is terminal; a host that wants
// the peer to have been told waits for Run.
//
// If Run has already returned (the kill-switch path that cancels the context
// while the session is still ESTABLISHED), nobody will Poll the CLOSE. In that
// case Close drains it here so Session.Wipe still runs. Leaving keys live
// until GC after a host teardown is the failure TestCloseAfterCancelledRunWipesSessionKeys
// exists to refuse.
//
// Close does NOT close the carrier the loop was given, nor one it was migrated
// onto. The carrier is the caller's, as it is after Migrate: a host that is done
// with a round closes its carrier itself, after Close, so a queued CLOSE can
// still be offered to the peer. A Runner handed to Reconnect that is a bare
// *Loop therefore leaves each finished round's carrier open.
func (l *Loop) Close() error {
	fmt.Fprintf(os.Stderr, "winn3-debug: [Loop.Close] called\n")
	l.closeOnce.Do(func() {
		l.latchDown()
		_ = l.sess.Close()
		if l.finished.Load() {
			l.drainQueuedClose()
		} else {
			l.signalWake()
		}
	})
	return nil
}

// drainQueuedClose Polls the session so a CLOSE queued after the write loop
// has already returned still runs its after-hook (terminate, which calls
// Session.Wipe). The sealed CLOSE is offered to the carrier if it will still
// take it; a cancelled carrier context is not used, because that is the
// usual reason we are here. A send failure does not undo the wipe: Poll has
// already run the hook.
func (l *Loop) drainQueuedClose() {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	for i := 0; i < 8; i++ {
		msg, err := l.sess.PollInto(l.writeBuf)
		if err != nil || msg == nil {
			return
		}
		c, _, _ := l.currentCarrier()
		if c == nil {
			continue
		}
		if err := c.Send(ctx, msg); err != nil {
			l.c.sendFailed.Add(1)
		} else {
			l.c.messagesSent.Add(1)
		}
	}
}

func (l *Loop) signalWake() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}
