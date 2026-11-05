package carrier

import (
	"context"
	"errors"
	"io"
	"math/bits"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

// PipeBufferSlabBytes is the capacity of the small pooled receive buffer.
const PipeBufferSlabBytes = 2048

// pipeItem is one queued inbox entry: the pooled message buffer and the
// moment Deliver admitted it, as the pipe clock's offset from the pipe's
// epoch. The admission time is what Recv and RecvBatch score the inbox
// sojourn from (Stats.InboxSojourn, Stats.InboxSojournMaxUS).
type pipeItem struct {
	bp *[]byte
	at time.Duration
}

// PipeSlotBytes is what one inbox slot costs in the channel's backing array,
// beside the pooled slab it points at. The gateway's memory bill reads it.
const PipeSlotBytes = int(unsafe.Sizeof(pipeItem{}))

// InboxSojournBuckets is the number of buckets in Stats.InboxSojourn.
const InboxSojournBuckets = 12

// inboxSojournUnit is the histogram's unit: bucket i, for i >= 1, counts
// sojourns of 2^i to 2^(i+1)-1 units.
const inboxSojournUnit = 100 * time.Microsecond

// inboxSojournBucket maps one sojourn to its Stats.InboxSojourn bucket:
// under two units (200 us) is bucket 0, 2^i to 2^(i+1)-1 units is bucket
// i, and 2^(InboxSojournBuckets-1) units (204.8 ms) and over is the last
// bucket. A negative sojourn (a clock that stepped back) scores as zero.
func inboxSojournBucket(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	i := bits.Len64(uint64(d/inboxSojournUnit)) - 1
	if i < 0 {
		return 0
	}
	if i >= InboxSojournBuckets {
		return InboxSojournBuckets - 1
	}
	return i
}

// scoreSojourn folds one read's sojourns into the stats under p.mu: the
// histogram by bucket and the longest wait seen, in microseconds.
func (p *Pipe) scoreSojourn(hist *[InboxSojournBuckets]uint64, longest time.Duration, n int) {
	if n == 0 {
		return
	}
	p.mu.Lock()
	for i := range hist {
		p.stats.InboxSojourn[i] += hist[i]
	}
	if us := uint64(max(longest, 0) / time.Microsecond); us > p.stats.InboxSojournMaxUS {
		p.stats.InboxSojournMaxUS = us
	}
	p.mu.Unlock()
}

var pipeBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, PipeBufferSlabBytes)
		return &b
	},
}

func getPipeBuf(size int) *[]byte {
	if size <= PipeBufferSlabBytes {
		bp := pipeBufferPool.Get().(*[]byte)
		*bp = (*bp)[:size]
		return bp
	}
	b := make([]byte, size)
	return &b
}

func recyclePipeBuf(bp *[]byte) {
	clear((*bp)[:cap(*bp)])
	if cap(*bp) == PipeBufferSlabBytes {
		*bp = (*bp)[:PipeBufferSlabBytes]
		pipeBufferPool.Put(bp)
	}
}

// Pipe is a carrier whose transport is a queue rather than a socket.
//
// It exists for two reasons that are the same reason:
//
//   - A gateway serves many sessions over one datagram socket, so the socket
//     cannot belong to a session's carrier. The gateway's demultiplexer reads
//     the socket, decides which session a message belongs to, and calls Deliver
//     on that session's Pipe. The sibling lane building winn3/gateway needs
//     exactly this seam and nothing wider.
//   - It is the only carrier here with a queue between arrival and read, which
//     makes it the only place the arrival-counter property is testable. A
//     sibling lane shipped a bug where a datagram counter moved when the host
//     got round to reading rather than when the datagram arrived; the same
//     mistake on this path would make a live tunnel look blocked or a blocked
//     one look live. TestArrivalCountersMoveOnArrivalNotOnRead sends messages,
//     reads none, and requires the counters to have moved.
//
// A Pipe adds no bytes and has no framing: it is a message queue, so §4.2's
// stream rule does not apply to it and it must never be used as a stand-in for
// a real stream carrier in a test that is supposed to exercise framing.
type Pipe struct {
	class       Class
	out         func(msg []byte) error
	outBatch    func(msgs []BatchMsg) (int, error)
	inbox       chan pipeItem
	pathCeiling int
	clock       Clock
	// epoch anchors pipeItem.at: admission times are stored as offsets from
	// it so a slot carries one int64, not a time.Time.
	epoch time.Time

	closeOnce sync.Once
	done      chan struct{}

	mu         sync.Mutex
	maxMessage int
	closed     bool
	stats      Stats

	// Flow observation state. seq is the configured extractor; the rest are
	// only meaningful when seq != nil and count how the inbound flow behaved.
	seq           func([]byte) uint64
	flowSeen      bool
	flowHigh      uint64
	flowNext      uint64
	flowReordered uint64
	flowLost      uint64
}

// PipeConfig configures a queue-backed carrier.
type PipeConfig struct {
	// Class is what this carrier stands in for. It selects the overhead used to
	// bound SetMaxMessageSize, so a Pipe standing in for a TLS carrier is
	// bounded like one.
	Class Class

	Out func(msg []byte) error

	// OutBatch receives what SendBatch produces. Nil falls back to Out.
	OutBatch func(msgs []BatchMsg) (int, error)

	// Depth bounds the inbox. Zero means DefaultPipeDepth. A full inbox drops
	// the arriving message and counts it, because blocking would backpressure a
	// gateway's demultiplexer, and a demultiplexer that stalls on one slow
	// session stalls every session on that socket.
	Depth int

	// MaxMessageSize is the send ceiling. Zero means MaxMessageSizeFor at
	// PathMTU for Class over IPv6.
	MaxMessageSize int

	// PathMTU is the planning path MTU. Zero means DefaultPathMTU.
	PathMTU int

	// Clock is injected for tests. Nil means the system clock.
	Clock Clock

	// Seq, when non-nil, enables flow observation. It extracts a per-datagram
	// sequence from a delivered message; the Pipe then counts how the inbound
	// flow behaved — how many datagrams arrived out of order and how many it can
	// infer were lost — without ever dropping or re-sorting them.
	//
	// Nil disables flow observation: a Pipe with no extractor is exactly the
	// plain queue it always was, and flow accounting stays at zero.
	Seq func(msg []byte) uint64
}

// DefaultPipeDepth is the default inbox depth: the session's own default send
// queue, so a Pipe cannot be the narrower of the two buffers by accident.
//
// ROUND 40 CORRECTION (2026-09-20): the ratified 256 -> 2048 deepening was
// REVERTED before deploy. Production sessions never use this constant: the
// per-session inbox derives from the token window per ruling D23, and
// inbox_4096_ceiling_test.go pins that derivation. During load the gateway
// counters showed rx_offered == rx_packets in every sample: the 512 inbox
// never dropped, so the 358-445 Mbps ingress plateau is NOT an inbox-depth
// defect.
//
// CORRECTION OF THE CORRECTION (2026-10-10, Canada, tunnel-speed round 2):
// "the 512 inbox never dropped" stopped being true on the iQOO over Wi-Fi.
// Every upload run overflowed the production inbox (5,884 to 27,237
// ErrQueueFull drops per run, 67 to 86% inside the first two seconds, the
// drops 93 to 96% of the phone's retransmits), and the 182 to 263 Mbit/s
// honest uplink was that loss. The production inbox is now
// gatewayTokenWindow/4 = 8192 in cmd/winn3-gateway; THIS constant still
// serves only preflight pipes that carry no traffic, and stays at 256. Do
// not deepen this constant without re-auditing D23 and the token window.
const DefaultPipeDepth = 256

// NewPipe builds a queue-backed carrier.
func NewPipe(cfg PipeConfig) (*Pipe, error) {
	if cfg.Class == ClassUnknown {
		return nil, wrap(ErrConfig, "a pipe must state the class it stands in for")
	}
	pathMTU := cfg.PathMTU
	if pathMTU == 0 {
		pathMTU = DefaultPathMTU
	}
	ceiling := MaxMessageSizeFor(cfg.Class, FamilyIPv6, pathMTU)
	maxMessage := cfg.MaxMessageSize
	if maxMessage == 0 {
		maxMessage = ceiling
	}
	if err := checkSize(maxMessage, ceiling); err != nil {
		return nil, err
	}
	depth := cfg.Depth
	if depth <= 0 {
		depth = DefaultPipeDepth
	}
	clock := cfg.Clock
	if clock == nil {
		clock = SystemClock{}
	}
	return &Pipe{
		class:       cfg.Class,
		out:         cfg.Out,
		outBatch:    cfg.OutBatch,
		inbox:       make(chan pipeItem, depth),
		pathCeiling: ceiling,
		clock:       clock,
		epoch:       clock.Now(),
		done:        make(chan struct{}),
		maxMessage:  maxMessage,
		seq:         cfg.Seq,
	}, nil
}

// NewPipePair builds two pipes wired to each other. Both stand in for class.
func NewPipePair(cfg PipeConfig) (*Pipe, *Pipe, error) {
	a, err := NewPipe(cfg)
	if err != nil {
		return nil, nil, err
	}
	b, err := NewPipe(cfg)
	if err != nil {
		return nil, nil, err
	}
	a.out = b.Deliver
	b.out = a.Deliver
	return a, b, nil
}

// Class reports the transport this carrier stands in for.
func (p *Pipe) Class() Class { return p.class }

// MaxMessageSize is the current send ceiling.
func (p *Pipe) MaxMessageSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxMessage
}

// SetMaxMessageSize narrows or widens the ceiling on a live carrier.
func (p *Pipe) SetMaxMessageSize(n int) error {
	if err := checkSize(n, p.pathCeiling); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	p.maxMessage = n
	return nil
}

// Stats reports what this carrier has seen.
func (p *Pipe) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats
}

// Deliver injects an arriving message. This is the gateway demultiplexer's
// entry point.
//
// The counters move HERE, on arrival, not in Recv. That is the whole point of
// the seam: a policy layer asking "has anything arrived recently" must get an
// answer about the network, not about how promptly this process drained a queue.
func (p *Pipe) Deliver(msg []byte) error {
	return p.DeliverWithRetry(msg, 0)
}

// DeliverWithRetry attempts delivery into the inbox, retrying up to maxRetries
// times when the queue is temporarily full before recording a receive error.
func (p *Pipe) DeliverWithRetry(msg []byte, maxRetries int) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return ErrClosed
	}
	ceiling := p.maxMessage
	p.mu.Unlock()

	if len(msg) == 0 {
		p.mu.Lock()
		p.stats.RecvErrors++
		p.mu.Unlock()
		return ErrMessageEmpty
	}
	if len(msg) > ceiling {
		p.mu.Lock()
		p.stats.RecvErrors++
		p.mu.Unlock()
		return wrap(ErrMessageTooLarge, "%d bytes, ceiling %d", len(msg), ceiling)
	}
	var flowSeq uint64
	observeFlow := p.seq != nil
	if observeFlow {
		flowSeq = p.seq(msg)
	}
	msgLen := len(msg)
	bp := getPipeBuf(msgLen)
	copy(*bp, msg)

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Admission and Close share the lock so no buffer can enter after
		// Close marks the pipe closed and drains its inbox.
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			recyclePipeBuf(bp)
			return ErrClosed
		}
		// One clock read per admission, as before; the same reading stamps
		// the slot so the sojourn is scored from exactly LastDelivered.
		now := p.clock.Now()
		select {
		case p.inbox <- pipeItem{bp: bp, at: now.Sub(p.epoch)}:
			if d := uint64(len(p.inbox)); d > p.stats.InboxHighWater {
				p.stats.InboxHighWater = d
			}
			p.stats.Delivered++
			p.stats.DeliveredBytes += uint64(msgLen)
			p.stats.LastDelivered = now
			if observeFlow {
				p.observe(flowSeq)
			}
			p.mu.Unlock()
			return nil
		default:
			p.mu.Unlock()
			if attempt < maxRetries {
				runtime.Gosched()
				if attempt >= 3 {
					time.Sleep(25 * time.Microsecond)
				}
			}
		}
	}

	recyclePipeBuf(bp)
	p.mu.Lock()
	p.stats.RecvErrors++
	if observeFlow {
		// A dropped datagram still arrived; the flow saw it even though the
		// queue did not keep it.
		p.observe(flowSeq)
	}
	p.mu.Unlock()
	return ErrQueueFull
}

// observe scores one arriving datagram against the inbound flow. It must be
// called with p.mu held, and it implements the whole of the flow-handling
// branch on the arrival path: it counts whether the datagram arrived out of
// order and how many datagrams it can infer were lost, and it never re-sorts
// or drops the datagram itself: that would remove exactly the information a
// reorder-repair layer above this carrier needs.
//
// The model behind Lost is deliberately the codebase's documented
// censor-vs-reorder ambiguity made explicit, not a certainty: an arrival above
// the in-order frontier means the sequences between the frontier and it did not
// precede it. Whether those are truly lost or merely late is not knowable at a
// streaming carrier, exactly as a silent block is not distinguish from a
// dropped path by any local counter. What observation adds is the ability to
// SEE the reordering and the gap instead of being blind to both, so a policy
// layer has the raw shape of the flow to reason over.
func (p *Pipe) observe(s uint64) {
	if !p.flowSeen {
		p.flowSeen = true
		p.flowHigh = s
		p.flowNext = s + 1
		return
	}
	if s >= p.flowNext {
		if s > p.flowHigh {
			p.flowHigh = s
		}
		if gap := s - p.flowNext; gap > 0 {
			p.flowLost += gap
		}
		p.flowNext = s + 1
		return
	}
	// s < flowNext: it sits at or below the in-order frontier, so it arrived
	// after a later-sequence datagram had already advanced past it.
	p.flowReordered++
}

// PipeFlow is what a sequence-aware Pipe has observed about the inbound flow.
// Both counters move on ARRIVAL at Deliver, never on Recv, so a slow reader
// cannot manufacture reordering or loss, any more than it can manufacture a
// delivery.
type PipeFlow struct {
	// Reordered is datagrams that arrived after a later-sequence datagram.
	Reordered uint64
	// Lost is the inferred number of datagrams that never arrived: sequences
	// between the in-order frontier and a later arrival.
	Lost uint64
}

// Flow reports how the inbound flow has behaved, when a sequence extractor was
// configured. With no extractor it reports the zero value, which is the honest
// answer — a plain queue has no way to know a flow reordered or lost anything.
func (p *Pipe) Flow() PipeFlow {
	p.mu.Lock()
	defer p.mu.Unlock()
	return PipeFlow{
		Reordered: p.flowReordered,
		Lost:      p.flowLost,
	}
}

// ErrQueueFull is returned by Pipe.Deliver when the inbox is full.
//
// It is its own sentinel, not a wrap of ErrConfig: a full inbox is
// backpressure, not an invalid configuration. A caller that treats ErrConfig
// as "do not retry" would otherwise drop a live session the first time the
// demultiplexer outran the reader.
var ErrQueueFull = errors.New("winn3/carrier: carrier inbox is full")

// Send hands one message to the configured sink.
func (p *Pipe) Send(ctx context.Context, msg []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(msg) == 0 {
		return ErrMessageEmpty
	}
	p.mu.Lock()
	closed, ceiling, out := p.closed, p.maxMessage, p.out
	p.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if len(msg) > ceiling {
		return wrap(ErrMessageTooLarge, "%d bytes, ceiling %d", len(msg), ceiling)
	}
	if out != nil {
		if err := out(msg); err != nil {
			p.mu.Lock()
			p.stats.SendErrors++
			p.mu.Unlock()
			return err
		}
	}
	p.mu.Lock()
	p.stats.Sent++
	p.stats.SentBytes += uint64(len(msg))
	p.stats.LastSend = p.clock.Now()
	p.mu.Unlock()
	return nil
}

// Recv returns the next queued message.
func (p *Pipe) Recv(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case it := <-p.inbox:
		msg := *it.bp
		res := make([]byte, len(msg))
		copy(res, msg)
		recyclePipeBuf(it.bp)
		var hist [InboxSojournBuckets]uint64
		d := p.clock.Now().Sub(p.epoch) - it.at
		hist[inboxSojournBucket(d)]++
		p.scoreSojourn(&hist, d, 1)
		return res, nil
	case <-p.done:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close releases the queue and unblocks any Recv in progress.
func (p *Pipe) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.closeOnce.Do(func() {
		close(p.done)
		for {
			select {
			case it := <-p.inbox:
				recyclePipeBuf(it.bp)
			default:
				return
			}
		}
	})
	return nil
}

var _ BatchCarrier = (*Pipe)(nil)

// SendBatch hands multiple messages to the configured batch sink or scalar sink.
func (p *Pipe) SendBatch(ctx context.Context, msgs []BatchMsg) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(msgs) == 0 {
		return 0, nil
	}
	for i := range msgs {
		if msgs[i].N < 0 || msgs[i].N > len(msgs[i].Payload) {
			return 0, wrap(ErrConfig, "invalid batch payload length")
		}
	}
	p.mu.Lock()
	closed, outBatch := p.closed, p.outBatch
	p.mu.Unlock()
	if closed {
		return 0, ErrClosed
	}
	if outBatch != nil {
		n, err := outBatch(msgs)
		p.mu.Lock()
		var bytes uint64
		for i := 0; i < n; i++ {
			bytes += uint64(msgs[i].N)
		}
		p.stats.Sent += uint64(n)
		p.stats.SentBytes += bytes
		p.stats.LastSend = p.clock.Now()
		if err != nil {
			p.stats.SendErrors++
		}
		p.mu.Unlock()
		return n, err
	}
	for i := range msgs {
		if err := p.Send(ctx, msgs[i].Payload[:msgs[i].N]); err != nil {
			return i, err
		}
	}
	return len(msgs), nil
}

// RecvBatch returns up to len(msgs) queued messages.
func (p *Pipe) RecvBatch(ctx context.Context, msgs []BatchMsg) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(msgs) == 0 {
		return 0, nil
	}
	p.mu.Lock()
	closed, ceiling := p.closed, p.maxMessage
	p.mu.Unlock()
	if closed {
		return 0, ErrClosed
	}

	var first pipeItem
	select {
	case it := <-p.inbox:
		first = it
	case <-p.done:
		return 0, ErrClosed
	case <-ctx.Done():
		return 0, ctx.Err()
	}

	// One clock read per batch scores every message it takes out: the
	// sojourn is admission (pipeItem.at) to this read.
	now := p.clock.Now().Sub(p.epoch)
	var hist [InboxSojournBuckets]uint64
	var longest time.Duration
	taken := 0
	for i := range msgs {
		var it pipeItem
		if i == 0 {
			it = first
		} else {
			select {
			case m := <-p.inbox:
				it = m
			default:
				p.scoreSojourn(&hist, longest, taken)
				return i, nil
			}
		}
		d := now - it.at
		if d > longest {
			longest = d
		}
		hist[inboxSojournBucket(d)]++
		taken++
		msg := *it.bp
		if len(msg) > ceiling || len(msg) > cap(msgs[i].Payload) {
			msgs[i].Err = io.ErrShortBuffer
			recyclePipeBuf(it.bp)
			p.scoreSojourn(&hist, longest, taken)
			return i, io.ErrShortBuffer
		}
		msgs[i].Payload = msgs[i].Payload[:len(msg)]
		copy(msgs[i].Payload, msg)
		msgs[i].N = len(msg)
		recyclePipeBuf(it.bp)
	}
	p.scoreSojourn(&hist, longest, taken)
	return len(msgs), nil
}
