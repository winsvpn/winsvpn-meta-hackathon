package core

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"sync"
)

// MaxBatchSize bounds both outstanding crypto work and caller slot counts.
const MaxBatchSize = 32

var (
	ErrBatchSize  = errors.New("winn3: batch exceeds 32 slots")
	ErrPoolClosed = errors.New("winn3: crypto worker pool closed")
)

// CryptoPool is a bounded, reusable pool owned by one frame Driver. Calls are
// serialized at the batch boundary, never by workers around individual AEADs.
// Close joins workers; neither Close nor workers acquire session locks.
type CryptoPool struct {
	mu      sync.Mutex
	queue   chan int
	workers sync.WaitGroup
	done    sync.WaitGroup
	jobs    [MaxBatchSize]cryptoJob
	count   int
	closed  bool
}

type cryptoJob struct {
	aead          cipher.AEAD
	nonce         [AEADNonceSize]byte
	dst, src, aad []byte
	plain         []byte
	err           error
	open          bool
}

// NewCryptoPool creates a pool without workers. Parallel batches start at most
// min(GOMAXPROCS, 32) workers and honor later changes by joining and resizing.
func NewCryptoPool() *CryptoPool {
	return new(CryptoPool)
}

func (p *CryptoPool) resizeLocked() {
	n := min(runtime.GOMAXPROCS(0), MaxBatchSize)
	if p.count == n {
		return
	}
	if p.queue != nil {
		close(p.queue)
		p.workers.Wait()
	}
	p.queue = make(chan int, MaxBatchSize)
	p.count = n
	p.workers.Add(n)
	for i := 0; i < n; i++ {
		go p.worker()
	}
}

func (p *CryptoPool) worker() {
	defer p.workers.Done()
	for i := range p.queue {
		p.jobs[i].run()
		p.done.Done()
	}
}

func (j *cryptoJob) run() {
	if j.open {
		j.plain, j.err = j.aead.Open(j.dst[:0], j.nonce[:], j.src, j.aad)
		if j.err != nil {
			j.err = ErrDecrypt
		}
	} else {
		j.aead.Seal(j.dst[:0], j.nonce[:], j.src, j.aad)
	}
	// Drop key references before reporting completion, including on failure.
	j.aead = nil
	clear(j.nonce[:])
	j.dst, j.src, j.aad = nil, nil, nil
}

func (p *CryptoPool) runLocked(n int) {
	if n == 0 {
		return
	}
	if n == 1 {
		p.jobs[0].run()
		return
	}
	p.resizeLocked()
	p.done.Add(n)
	for i := 0; i < n; i++ {
		p.queue <- i
	}
	p.done.Wait()
}

// Close is idempotent and waits for the current bounded batch to finish.
func (p *CryptoPool) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if p.queue != nil {
		close(p.queue)
		p.workers.Wait()
	}
	clear(p.jobs[:])
	p.queue = nil
	p.count = 0
}

// SealSlot describes one message. On success Dst contains the wire message.
// All buffers must be disjoint across slots; Dst must not overlap Payload.
type SealSlot struct {
	Dst     []byte
	Payload []byte
	PadTo   int
}

// SealBatchInto reserves every nonce in slot order under sendMu, then runs raw
// ChaCha20-Poly1305 inline or in parallel. sendMu spans completion, so scalar
// sends, ratchets and wipe cannot interleave. Validation failure consumes no
// nonce or bytes.
func (s *Session) SealBatchInto(p *CryptoPool, slots []SealSlot) error {
	if len(slots) > MaxBatchSize {
		return ErrBatchSize
	}
	if len(slots) == 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrPoolClosed
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.wiped || s.sendAEAD == nil {
		return ErrWiped
	}
	if s.sendCounter >= RejectAfterMessages || uint64(len(slots)) > RejectAfterMessages-s.sendCounter {
		return ErrCounterExhausted
	}
	for i := range slots {
		x := &slots[i]
		if len(x.Payload) > MaxTransportPayload {
			return ErrPayloadTooLarge
		}
		n := TransportOverhead() + len(x.Payload)
		if x.PadTo != 0 && x.PadTo < n {
			return ErrTargetLenTooSmall
		}
		if cap(x.Dst) < max(n, x.PadTo) {
			return io.ErrShortBuffer
		}
	}
	for i := range slots {
		x := &slots[i]
		x.Dst = x.Dst[:max(TransportOverhead()+len(x.Payload), x.PadTo)]
		token := s.sendPRF.token(s.sendCounter)
		copy(x.Dst, token[:])
		plain := x.Dst[DemuxTokenSize : len(x.Dst)-AEADTagSize]
		binary.BigEndian.PutUint16(plain, uint16(len(x.Payload)))
		copy(plain[transportHeaderSize:], x.Payload)
		clear(plain[transportHeaderSize+len(x.Payload):])
		j := &p.jobs[i]
		*j = cryptoJob{aead: s.sendAEAD, dst: plain, src: plain, aad: x.Dst[:DemuxTokenSize]}
		copy(j.nonce[:], s.sendSalt[:])
		binary.BigEndian.PutUint64(j.nonce[nonceSaltSize:], s.sendCounter)
		s.sendCounter++
		s.sentBytes += uint64(len(x.Dst))
		s.epochSentBytes += uint64(len(x.Dst))
	}
	p.runLocked(len(slots))
	clear(p.jobs[:len(slots)])
	return nil
}

// OpenSlot is an opaque speculative ticket plus caller-owned buffers. Msg must
// remain unchanged until CommitOpen completes. Dst must not overlap ANY Msg or
// another slot's Dst, even for duplicate messages. Plaintext is exposed only by
// CommitOpen. A ticket can be committed once and contains no AEAD/key reference.
type OpenSlot struct {
	Msg, Dst []byte
	owner    *Session
	epoch    uint32
	counter  uint64
	plain    []byte
	err      error
	resolved bool
	used     bool
}

// SpeculateOpenBatch performs ordered lookup, then inline or parallel AEAD opens.
// No token is reserved or consumed: a corrupt duplicate cannot starve a genuine
// ticket. recvMu spans completion and all key references are dropped before
// it is released. The owner must commit tickets in original input order.
func (s *Session) SpeculateOpenBatch(p *CryptoPool, slots []OpenSlot) error {
	if len(slots) > MaxBatchSize {
		return ErrBatchSize
	}
	if len(slots) == 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrPoolClosed
	}
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	if s.wiped || s.recvAEAD == nil || s.recvWindow == nil {
		return ErrWiped
	}
	jobs := 0
	var indices [MaxBatchSize]int
	for i := range slots {
		x := &slots[i]
		*x = OpenSlot{Msg: x.Msg, Dst: x.Dst, owner: s, epoch: s.epoch}
		if len(x.Msg) < TransportOverhead() {
			x.err = ErrShortMessage
			continue
		}
		if cap(x.Dst) < len(x.Msg)-DemuxTokenSize-AEADTagSize {
			x.err = io.ErrShortBuffer
			continue
		}
		x.counter, x.resolved = s.recvWindow.lookup(x.Msg[:DemuxTokenSize])
		if !x.resolved {
			x.err = ErrUnauthenticated
			if !s.recvWindow.indexed() {
				x.err = ErrCallerOwnsWindow
			}
			continue
		}
		j := &p.jobs[jobs]
		*j = cryptoJob{aead: s.recvAEAD, dst: x.Dst, src: x.Msg[DemuxTokenSize:], aad: x.Msg[:DemuxTokenSize], open: true}
		copy(j.nonce[:], s.recvSalt[:])
		binary.BigEndian.PutUint64(j.nonce[nonceSaltSize:], x.counter)
		indices[jobs] = i
		jobs++
	}
	p.runLocked(jobs)
	for i := 0; i < jobs; i++ {
		x, j := &slots[indices[i]], &p.jobs[i]
		x.plain, x.err = j.plain, j.err
	}
	clear(p.jobs[:jobs])
	return nil
}

// PreviewOpen resolves an opaque ticket against the current epoch and window,
// without consuming its token. It lets the frame owner identify a control
// boundary before committing it. The returned view is still speculative and
// must never be delivered before CommitOpen succeeds.
func (s *Session) PreviewOpen(x *OpenSlot) ([]byte, error) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	return s.resolveOpenLocked(x)
}

func (s *Session) resolveOpenLocked(x *OpenSlot) ([]byte, error) {
	if x.used {
		return nil, ErrUnauthenticated
	}
	if s.wiped || s.recvAEAD == nil || s.recvWindow == nil {
		return nil, ErrWiped
	}
	if len(x.Msg) < TransportOverhead() {
		return nil, ErrShortMessage
	}
	if cap(x.Dst) < len(x.Msg)-DemuxTokenSize-AEADTagSize {
		return nil, io.ErrShortBuffer
	}
	counter, ok := s.recvWindow.lookup(x.Msg[:DemuxTokenSize])
	if !ok {
		if !s.recvWindow.indexed() {
			return nil, ErrCallerOwnsWindow
		}
		return nil, ErrUnauthenticated
	}
	if x.owner != s || x.epoch != s.epoch || !x.resolved || x.counter != counter {
		copy(s.recvNonce[:], s.recvSalt[:])
		binary.BigEndian.PutUint64(s.recvNonce[nonceSaltSize:], counter)
		x.plain, x.err = s.recvAEAD.Open(x.Dst[:0], s.recvNonce[:], x.Msg[DemuxTokenSize:], x.Msg[:DemuxTokenSize])
		if x.err != nil {
			x.err = ErrDecrypt
		}
		x.owner, x.epoch, x.counter, x.resolved = s, s.epoch, counter, true
	}
	if x.err != nil {
		return nil, x.err
	}
	plain := x.plain
	if len(plain) < transportHeaderSize {
		return nil, ErrDecrypt
	}
	n := int(binary.BigEndian.Uint16(plain))
	if n > len(plain)-transportHeaderSize {
		return nil, ErrDecrypt
	}
	return plain[transportHeaderSize : transportHeaderSize+n : transportHeaderSize+n], nil
}

// CommitOpen authenticates current ownership and replay eligibility, then
// accounts bytes and consumes exactly one token. A new epoch or a token that
// entered the window since speculation is retried with the current AEAD.
func (s *Session) CommitOpen(x *OpenSlot) ([]byte, error) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	plain, err := s.resolveOpenLocked(x)
	x.used = true
	x.owner, x.plain = nil, nil
	if err != nil {
		return nil, err
	}
	s.recvWindow.consumeKnown(x.counter, x.Msg[:DemuxTokenSize])
	s.recvdBytes += uint64(len(x.Msg))
	return plain, nil
}
