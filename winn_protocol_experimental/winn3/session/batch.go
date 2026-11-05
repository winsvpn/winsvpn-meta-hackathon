package session

import (
	"errors"
	"io"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

const MaxBatchSize = core.MaxBatchSize

// ReceiveSlot supplies immutable wire input and distinct plaintext storage.
// Scratch capacity must cover len(Message)-DemuxTokenSize-AEADTagSize.
// Packets capacity must be at least len(Message)/3, the maximum TLV count.
// Returned packets borrow Scratch until it is reused. All buffers must be
// disjoint across slots, including duplicated input messages and scratch.
type ReceiveSlot struct {
	Message []byte
	Scratch []byte
	Packets [][]byte
}

type driverBatch struct {
	pool     *core.CryptoPool
	seal     [MaxBatchSize]core.SealSlot
	open     [MaxBatchSize]core.OpenSlot
	assembly [MaxBatchSize][]byte
	counts   [MaxBatchSize]int
	frames   []core.Frame
}

func (d *Driver) batchLocked() *driverBatch {
	if d.batch == nil {
		d.batch = &driverBatch{pool: core.NewCryptoPool()}
	}
	return d.batch
}

func (b *driverBatch) wipe() {
	for i := range b.assembly {
		clear(b.assembly[i])
		b.assembly[i] = nil
	}
	clear(b.seal[:])
	clear(b.open[:])
	clear(b.counts[:])
	clear(b.frames)
	b.frames = nil
}

// PollBatchInto fills an ordered prefix of at most 32 caller output buffers.
// Every slot must have capacity MaxMessageSize; short buffers fail before any
// queue, nonce or accounting mutation. Send the returned prefix in order before
// polling again, including when err is non-nil. Only the prefix is valid output.
// Holding d.mu through each worker join makes control hooks hard epoch barriers.
func (d *Driver) PollBatchInto(slots [][]byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(slots) > MaxBatchSize {
		return 0, core.ErrBatchSize
	}
	if d.state.Terminal() || len(slots) == 0 {
		return 0, nil
	}
	for _, dst := range slots {
		if cap(dst) < d.cfg.MaxMessageSize {
			return 0, io.ErrShortBuffer
		}
	}
	n := 0
	for n < len(slots) && !d.state.Terminal() {
		now := d.cfg.Clock.Now()
		if err := d.tick(now); err != nil {
			return n, err
		}
		if d.state.Terminal() {
			break
		}
		if len(d.hsOut) == 0 && len(d.ctrl) == 0 && d.dataMayFlow() && len(d.data) > 0 && d.shape != nil {
			k, err := d.pollDataBatch(now, slots[n:])
			n += k
			if err != nil {
				return n, err
			}
			if k > 0 {
				continue
			}
		}
		// This path includes every after-hook. Prior parallel work has joined;
		// the hook's message is fully sealed before the hook installs an epoch.
		msg, err := d.pollIntoLocked(slots[n])
		if len(msg) > 0 {
			slots[n] = slots[n][:len(msg)]
			copy(slots[n], msg) // also moves handshake output into caller storage
			n++
		}
		if err != nil {
			return n, err
		}
		if len(msg) == 0 {
			break
		}
	}
	return n, nil
}

// pollDataBatch prepares only ordinary data. Control messages, including their
// after-hooks and padding semantics, remain on the shared scalar assembly path.
func (d *Driver) pollDataBatch(now time.Time, slots [][]byte) (int, error) {
	b := d.batchLocked()
	usedAssembly := 0
	defer func() {
		// Untouched slots were cleared by the call that last filled them.
		for i := range b.assembly[:usedAssembly] {
			clear(b.assembly[i])
		}
		clear(b.seal[:])
		clear(b.counts[:])
	}()
	budget := d.cfg.maxPayload()
	counter, epochSent, epochBytes := d.sess.SendCounter(), d.sess.EpochSentBytes(), d.epochBytes
	n, queued := 0, 0
	var prepareErr error
	for n < len(slots) && queued < len(d.data) {
		// The next Poll must tick before crossing any soft volume boundary.
		// The first message is allowed: tick has already handled the due policy.
		if n > 0 && (counter >= d.cfg.RekeyAfterMessages || counter >= core.RekeyAfterMessages || epochSent >= core.RekeyAfterBytes || epochBytes >= d.cfg.RekeyAfterBytes) {
			break
		}
		if counter >= core.RejectAfterMessages {
			break
		}
		if cap(b.assembly[n]) < budget {
			b.assembly[n] = make([]byte, budget)
		}
		plain := b.assembly[n][:0]
		usedAssembly = n + 1
		k := queued
		for k < len(d.data) && len(plain)+frameHeaderSize+len(d.data[k]) <= budget {
			var err error
			plain, err = core.AppendFrame(plain, core.FrameData, d.data[k])
			if err != nil {
				prepareErr = err
				break
			}
			k++
		}
		if prepareErr != nil || k == queued {
			break
		}
		target, err := d.shape.target(core.TransportOverhead() + len(plain))
		if err != nil {
			prepareErr = err
			break
		}
		b.seal[n] = core.SealSlot{Dst: slots[n], Payload: plain, PadTo: target}
		b.counts[n] = k - queued
		queued = k
		size := uint64(max(target, core.TransportOverhead()+len(plain)))
		counter++
		epochSent += size
		epochBytes += size
		n++
	}
	if n == 0 {
		return 0, prepareErr
	}
	if err := d.sess.SealBatchInto(b.pool, b.seal[:n]); err != nil {
		if errors.Is(err, core.ErrCounterExhausted) {
			d.beginClose(CloseCounterExhausted, err)
			return 0, nil
		}
		return 0, err
	}
	for i := 0; i < n; i++ {
		slots[i] = b.seal[i].Dst
		d.noteSent(now, len(slots[i]), len(slots[i])-core.TransportOverhead()-len(b.seal[i].Payload))
		d.stats.DataFramesSent += uint64(b.counts[i])
	}
	d.consumeQueuedData(queued)
	return n, prepareErr
}

// DeliverBatch returns an ordered prefix of ordinary DATA/PAD messages, stopping
// BEFORE any control message or noise. When the first slot is control, noise or
// a handshake, it processes exactly that slot and returns one. This lets callers
// project the gate after each return without calling back while d.mu is held.
// Unprocessed tickets are canceled without replay commits or byte accounting.
// Packet views in the processed prefix borrow Scratch until the caller reuses it.
// Call again on the unprocessed suffix; after terminal state, discard that suffix.
func (d *Driver) DeliverBatch(slots []ReceiveSlot) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(slots) > MaxBatchSize {
		return 0, core.ErrBatchSize
	}
	if d.state.Terminal() {
		return 0, ErrClosed
	}
	if len(slots) == 0 {
		return 0, nil
	}
	for i := range slots {
		x := &slots[i]
		if cap(x.Scratch) < max(0, len(x.Message)-core.DemuxTokenSize-core.AEADTagSize) || cap(x.Packets) < len(x.Message)/frameHeaderSize {
			return 0, io.ErrShortBuffer
		}
	}
	for i := range slots {
		clear(slots[i].Packets)
		slots[i].Packets = slots[i].Packets[:0]
	}
	b := d.batchLocked()
	defer func() {
		clear(b.open[:])
		clear(b.frames)
		for i := range slots {
			if len(slots[i].Packets) == 0 {
				clear(slots[i].Scratch[:cap(slots[i].Scratch)])
			}
		}
	}()
	// Handshakes may replace sess mid-batch. Tickets are only prepared when a
	// transport session exists, and are retried by CommitOpen after an epoch cut.
	prepared := false
	for i := range slots {
		if d.state.Terminal() {
			return i, nil
		}
		now := d.cfg.Clock.Now()
		x := &slots[i]
		// connectBy binds a batch delivery as it binds Deliver (N-4): the
		// slot is consumed and nothing in it is processed.
		if d.connectExpired(now) {
			d.closeConnectExhausted()
			return i + 1, nil
		}
		if d.sess == nil {
			return i + 1, d.deliverHandshake(now, x.Message)
		}
		if !prepared {
			for j := i; j < len(slots); j++ {
				b.open[j] = core.OpenSlot{Msg: slots[j].Message, Dst: slots[j].Scratch}
			}
			if err := d.sess.SpeculateOpenBatch(b.pool, b.open[i:len(slots)]); err != nil {
				return i, err
			}
			prepared = true
		}
		plain, err := d.sess.PreviewOpen(&b.open[i])
		if err != nil {
			if i > 0 {
				return i, nil
			}
			clear(x.Scratch[:cap(x.Scratch)])
			return 1, d.deliverUnopenable(now, x.Message)
		}
		// Every frame needs at least its header. Size reusable storage from
		// authenticated plaintext instead of reserving the protocol maximum
		// for every session. Keep length zero so clearing follows parsed frames.
		if needed := len(plain) / frameHeaderSize; cap(b.frames) < needed {
			// Geometric growth bounds repeated reallocations for gradually
			// larger messages, while retaining the protocol capacity ceiling.
			capacity := max(needed, min(core.MaxTransportPayload/frameHeaderSize, cap(b.frames)*2))
			b.frames = make([]core.Frame, 0, capacity)
		}
		frames, parseErr := core.ParseFramesInto(b.frames[:0], plain)
		if parseErr != nil {
			// The parser can return nil after filling an earlier prefix. Retain
			// ownership of its backing and clear every slot it could have used.
			clear(b.frames[:len(plain)/frameHeaderSize])
			b.frames = b.frames[:0]
		} else {
			b.frames = frames
		}
		control := parseErr != nil
		for _, f := range frames {
			if f.Type != core.FrameData && f.Type != core.FramePad {
				control = true
				break
			}
		}
		if control && i > 0 {
			return i, nil
		}
		if _, err := d.sess.CommitOpen(&b.open[i]); err != nil {
			return i + 1, d.deliverUnopenable(now, x.Message)
		}
		d.lastOpened = now
		d.lastAuthRecv = now
		d.genSeq++
		d.silentLost = 0
		d.rekeyConfirmAt = time.Time{}
		// Match Deliver: authenticated new-epoch DATA can confirm rekey.
		// Capture admission before handling any frame-driven transition.
		dataAllowedAtOpen := d.dataMayFlow()
		// As in openAndHandle: the DUAL_AUTH gate reads the epoch this
		// message opened under, not the state its own PQ_CT leaves (Q5).
		openedPreRatchet := !d.sess.PQRatcheted()
		d.stats.MessagesReceived++
		d.stats.BytesReceived += uint64(len(x.Message))
		if parseErr != nil {
			d.beginClose(CloseProtocolError, wrap(ErrProtocol, "peer sent an unparseable frame stream: %v", parseErr))
			return i + 1, nil
		}
		x.Packets, err = d.handleFramesInto(now, frames, len(x.Message) >= d.cfg.MaxMessageSize, x.Packets, true, dataAllowedAtOpen, openedPreRatchet)
		clear(b.frames)
		if err != nil {
			return i + 1, err
		}
		// The datagram that carried the ratchet has been handled; anything
		// held ahead of it is retried now, through the scalar open path, and
		// its packets are owned copies (see drainHold).
		if x.Packets, err = d.drainHold(now, x.Packets); err != nil {
			return i + 1, err
		}
		if control {
			return i + 1, nil
		}
	}
	return len(slots), nil
}

// deliverUnopenable is shared with scalar Deliver to preserve reinitiation,
// throttling and silent-noise semantics after speculative failures.
func (d *Driver) deliverUnopenable(now time.Time, msg []byte) error {
	if d.role == core.RoleResponder && d.resp != nil && !now.Before(d.reinitAt) {
		d.reinitAt = now.Add(reinitCheckInterval)
		adopted, authenticated, err := d.admitReinitiation(now, msg)
		if err != nil {
			return err
		}
		if adopted || authenticated {
			return nil
		}
	}
	// A client whose PQ ciphertext is outstanding holds it instead: it may be
	// the gateway's epoch-1 attestation arriving ahead of the PQ_CT (Q5).
	if d.holdEarly(msg) {
		return nil
	}
	d.stats.Unopenable++
	if d.state == StateEstablished {
		d.lastUnopenable = now
	}
	return nil
}
