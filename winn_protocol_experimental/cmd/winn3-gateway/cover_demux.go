package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"winsvpn.local/winnprotocol/internal/observability"
	"winsvpn.local/winnprotocol/winn3/carrier"
)

// udpConn is the datagram socket the v3 readLoop and session pipes use.
// *net.UDPConn satisfies it. The cover demux's v3 half also satisfies it so
// QUIC cover packets can be split off the same UDP port without a second bind.
type udpConn interface {
	ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	SetReadDeadline(time.Time) error
	Close() error
	LocalAddr() net.Addr
}

// batchWriter is implemented by datagram sockets capable of transmitting batches
// of datagrams in a single system call (such as sendmmsg on Linux).
type batchWriter interface {
	WriteBatchTo(msgs []carrier.BatchMsg, to netip.AddrPort) (int, error)
}

// QUIC long-header versions a cover listener will treat as QUIC rather than
// v3. A high-entropy v3 datagram matching one of these 32-bit values in the
// version field is 3/2^32; that is the false-positive rate of this classifier,
// and it is why the first-byte bits alone are not used.
const (
	quicHeaderFormLong        byte   = 0x80
	quicFixedBit              byte   = 0x40
	quicVersion1              uint32 = 0x00000001
	quicVersion2              uint32 = 0x6b3343cf
	quicVersionNegotiation    uint32 = 0
	quicMaxConnectionIDLength        = 20
	demuxChanDepth                   = 4096

	coverCIDLen      = 8
	coverCIDNonceLen = 4
	coverCIDTagLen   = 4
)

// coverCIDGen generates and validates QUIC connection IDs statelessly using
// AES-NI. Server-issued CIDs carry a 4-byte random nonce and a 4-byte AES tag.
// Short headers bearing a destination CID that matches this tag are recognized
// in constant time without locks, maps, or allocations.
type coverCIDGen struct {
	block cipher.Block
}

func newCoverCIDGen() (*coverCIDGen, error) {
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return &coverCIDGen{block: block}, nil
}

func (g *coverCIDGen) ConnectionIDLen() int { return coverCIDLen }

func (g *coverCIDGen) GenerateConnectionID() (quic.ConnectionID, error) {
	var raw [coverCIDLen]byte
	if _, err := rand.Read(raw[:coverCIDNonceLen]); err != nil {
		return quic.ConnectionID{}, err
	}
	var scratch [2][aes.BlockSize]byte
	tag := g.tag(raw[:coverCIDNonceLen], &scratch)
	copy(raw[coverCIDNonceLen:], tag[:coverCIDTagLen])
	return quic.ConnectionIDFromBytes(raw[:]), nil
}

func (g *coverCIDGen) tag(nonce []byte, scratch *[2][aes.BlockSize]byte) []byte {
	in, out := &scratch[0], &scratch[1]
	*in = [aes.BlockSize]byte{}
	copy(in[:], nonce)
	g.block.Encrypt(out[:], in[:])
	return out[:]
}

func (g *coverCIDGen) matches(pkt []byte, scratch *[2][aes.BlockSize]byte) bool {
	if len(pkt) < 1+coverCIDLen {
		return false
	}
	cid := pkt[1 : 1+coverCIDLen]
	want := g.tag(cid[:coverCIDNonceLen], scratch)
	return subtle.ConstantTimeCompare(
		cid[coverCIDNonceLen:], want[:coverCIDTagLen],
	) == 1
}

// demuxDatagramMin is the default receive-buffer capacity, not a universal
// datagram ceiling and not the larger server readBuffer.
//
// readBuffer is 65535, so every datagram queued on a demux side used to pin a
// 64 KiB pooled buffer. demuxChanDepth is 4096 and there are two sides, so a
// full pair of queues could ask for 512 MiB while the shipped unit file sets
// GOMEMLIMIT=96MiB. Worse in the steady state: at a gigabit, which is 91,041
// packets per second at this plan floor's 1373-byte inner MTU, the pool itself
// churns 91,041 * 65,536 = 5.97 GB/s, and every GC cycle empties sync.Pool and
// turns the next second of that churn back into real allocation. That is a
// self-sustaining collector loop and it is the shape of the measured jitter.
//
// Each split uses max(4096, its configured message ceiling). The default UDP
// plan at path MTU 1450 has a 1402-byte message ceiling and keeps 4096-byte slabs.
// Admitted payload backing is bounded by 2*demuxChanDepth*bufferSize, or 32 MiB
// at the default. Credits include queued, pending and read-copy ownership;
// the receive pump additionally holds at most demuxBatchSize staging buffers.
const demuxDatagramMin = 4096

// demuxSideCount counts the v3 and quic sides constructed by newSplitUDP.
const demuxSideCount = 2

type demuxBufferPool struct {
	size int
	sync.Pool
}

func demuxBufferCapacity(messageSize int) int {
	return max(demuxDatagramMin, messageSize)
}

func newDemuxBufferPool(messageSize int) *demuxBufferPool {
	p := &demuxBufferPool{size: demuxBufferCapacity(messageSize)}
	p.New = func() any {
		b := make([]byte, p.size)
		return &b
	}
	return p
}

// splitUDP is one real UDP socket presented as two PacketConns: v3 datagrams
// and QUIC cover datagrams. The classifier is conservative: only a long header
// with a known QUIC version, or a short header whose DCID verifies against our
// stateless AES-NI cover CID generator, is handed to QUIC. Everything else is
// v3, which stays silent to unauthenticated peers.
type splitUDP struct {
	real  *net.UDPConn
	batch *carrier.RawBatchConn
	done  chan struct{}
	once  sync.Once

	v3   *demuxSide
	quic *demuxSide

	cidGen  *coverCIDGen
	buffers *demuxBufferPool

	// errq drains the socket's error queue and counts send errors; it is the
	// RawBatchConn's own queue when there is one. readFaults counts pump read
	// errors retried rather than treated as fatal (udp_send_errors.go).
	errq       *carrier.SocketErrorQueue
	readFaults atomic.Uint64
	degraded   atomic.Bool

	// readBatch is batch.ReadBatchFrom, or a test's wrapper around it.
	readBatch func([]carrier.BatchMsg) (int, error)
}

type demuxSide struct {
	split    *splitUDP
	incoming chan []demuxDatagram
	wake     chan struct{}
	occupied chan struct{}
	sendMu   sync.Mutex

	recvMu  sync.Mutex
	pending []demuxDatagram

	readDeadlineNano atomic.Int64
}

type demuxDatagram struct {
	b       []byte
	poolBuf *[]byte
	addr    netip.AddrPort
}

func newSplitUDP(real *net.UDPConn, messageSize int) *splitUDP {
	return newSplitUDPWith(real, messageSize, splitTestOptions{})
}

// splitTestOptions are test seams. The zero value is production behaviour.
type splitTestOptions struct {
	// noBatch forces the scalar pump, as on a platform where RawBatchConn is
	// unavailable (for example the 32-bit rejection in NewRawBatchConn).
	noBatch bool
	// wrapBatchRead wraps the batch pump's ReadBatchFrom call.
	wrapBatchRead func(func([]carrier.BatchMsg) (int, error)) func([]carrier.BatchMsg) (int, error)
}

func newSplitUDPWith(real *net.UDPConn, messageSize int, opts splitTestOptions) *splitUDP {
	var batch *carrier.RawBatchConn
	if !opts.noBatch {
		batch, _ = carrier.NewRawBatchConn(real)
	}
	cidGen, err := newCoverCIDGen()
	if err != nil {
		panic(fmt.Sprintf("winn3-gateway: failed to initialize cover CID generator: %v", err))
	}
	errq := batch.ErrorQueue()
	if errq == nil {
		errq, _ = carrier.NewSocketErrorQueue(real)
	}
	s := &splitUDP{
		real:    real,
		batch:   batch,
		done:    make(chan struct{}),
		cidGen:  cidGen,
		buffers: newDemuxBufferPool(messageSize),
		errq:    errq,
	}
	if batch != nil {
		s.readBatch = batch.ReadBatchFrom
		if opts.wrapBatchRead != nil {
			s.readBatch = opts.wrapBatchRead(s.readBatch)
		}
	}
	s.v3 = newDemuxSide(s)
	s.quic = newDemuxSide(s)
	go s.pump()
	return s
}

func newDemuxSide(s *splitUDP) *demuxSide {
	return &demuxSide{
		split:    s,
		incoming: make(chan []demuxDatagram, demuxChanDepth),
		wake:     make(chan struct{}, 1),
		occupied: make(chan struct{}, demuxChanDepth),
	}
}

// enqueue transfers ownership of the currently admissible FIFO prefix without
// waiting for packet credits. Credits count incoming, pending, and read copies.
// Congestion on one side must not stall the shared socket's other consumer.
func (d *demuxSide) enqueue(batch []demuxDatagram) int {
	d.sendMu.Lock()
	defer d.sendMu.Unlock()
	select {
	case <-d.split.done:
		return 0
	default:
	}
	n := 0
reserve:
	for n < len(batch) {
		select {
		case d.occupied <- struct{}{}:
			n++
		default:
			break reserve
		}
	}
	if n == 0 {
		return 0
	}
	select {
	case <-d.split.done:
	default:
		select {
		case d.incoming <- batch[:n]:
			return n
		case <-d.split.done:
		default:
		}
	}
	// Cancellation or an unavailable queue slot leaves ownership with caller.
	for i := 0; i < n; i++ {
		<-d.occupied
	}
	return 0
}

// publish attempts both sides independently and recycles only rejected suffixes.
// A full side drops its unadmitted packets; only cancellation stops the pump.
func (s *splitUDP) publish(v3Batch, quicBatch []demuxDatagram) bool {
	for _, entry := range [...]struct {
		side  *demuxSide
		batch []demuxDatagram
	}{{s.v3, v3Batch}, {s.quic, quicBatch}} {
		n := entry.side.enqueue(entry.batch)
		for i := n; i < len(entry.batch); i++ {
			if entry.batch[i].poolBuf != nil {
				s.buffers.Put(entry.batch[i].poolBuf)
			}
			entry.batch[i] = demuxDatagram{}
		}
	}
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

func (d *demuxSide) release(pkt demuxDatagram) {
	if pkt.poolBuf != nil {
		d.split.buffers.Put(pkt.poolBuf)
	}
	<-d.occupied
}

// discard runs after cancellation. No producer or read copy can still own a
// queue entry while it drains; unaccepted packets remain the producer's job.
func (d *demuxSide) discard() {
	d.sendMu.Lock()
	defer d.sendMu.Unlock()
	d.recvMu.Lock()
	defer d.recvMu.Unlock()
	for _, pkt := range d.pending {
		d.release(pkt)
	}
	d.pending = nil
	for {
		select {
		case batch := <-d.incoming:
			for _, pkt := range batch {
				d.release(pkt)
			}
		default:
			return
		}
	}
}

func (s *splitUDP) stop() {
	s.once.Do(func() {
		close(s.done)
		_ = s.real.SetReadDeadline(time.Now())
		s.v3.discard()
		s.quic.discard()
	})
}

// demuxBatchSize bounds one recvmmsg. Sized to 64 to match core.MaxBatchSize.
const demuxBatchSize = 64

// pump drains the one real socket for every session on this process.
//
// It is the single hardest serialization point in the gateway, so its cost per
// datagram is the one cost nothing downstream can absorb. MEASURED on the
// Canada node, 2026-09-17, during a sustained uplink run against the shipping
// gateway: /proc/net/snmp went from RcvbufErrors 0 to RcvbufErrors 82,318 and
// InErrors 82,318, and the session then failed its liveness probes and tore
// down. The 8 MiB receive buffer was not too small; the reader could not empty
// it, because this loop issued one recvfrom per datagram on a 2.0 GHz Haswell
// behind a single-queue virtio NIC. The send side has been doing 64 datagrams
// per sendmmsg all along.
func (s *splitUDP) pump() {
	if s.batch != nil {
		s.pumpBatch()
		return
	}
	s.pumpScalar()
}

// pumpBatch drains with one recvmmsg per up to demuxBatchSize datagrams. Each
// slot's iovec points straight at the pooled buffer that is then handed to the
// channel, so the syscall saving is not paid back as a copy.
func (s *splitUDP) pumpBatch() {
	bufs := make([]*[]byte, demuxBatchSize)
	msgs := make([]carrier.BatchMsg, demuxBatchSize)
	var scratch [2][aes.BlockSize]byte
	release := func() {
		for i := range bufs {
			if bufs[i] != nil {
				s.buffers.Put(bufs[i])
				bufs[i] = nil
			}
		}
	}
	var faults demuxReadFaults
	for {
		for i := range msgs {
			if bufs[i] == nil {
				bufs[i] = s.buffers.Get().(*[]byte)
			}
			msgs[i].Payload = (*bufs[i])[:s.buffers.size]
		}
		n, err := s.readBatch(msgs)
		if err != nil {
			if s.recoverRead(&faults, err) {
				continue
			}
			release()
			// Unblock v3/QUIC readers. Returning here without closing done
			// parks server.readLoop on demuxSide.recv forever: cover.go closes
			// this socket when the HTTPS/QUIC listener dies, and a gateway
			// that keeps printing posture while carrying nothing is the
			// silent-failure class this product cannot ship. If stop() already
			// ran, done is closed and this is the ordinary shutdown path.
			select {
			case <-s.done:
				return
			default:
			}
			fmt.Fprint(os.Stderr, observability.RedactAddresses(fmt.Sprintf(
				"winn3-gateway: UDP demux read failed: %v\n", err)))
			s.stop()
			return
		}
		s.clearReadFaults(&faults)

		var v3Batch []demuxDatagram
		var quicBatch []demuxDatagram
		for i := 0; i < n; i++ {
			if msgs[i].Err != nil || msgs[i].N == 0 {
				continue
			}
			bp := bufs[i]
			pkt := (*bp)[:msgs[i].N]
			d := demuxDatagram{
				b:       pkt,
				poolBuf: bp,
				addr:    msgs[i].Addr,
			}
			bufs[i] = nil

			if s.routeQUIC(pkt, &scratch) {
				quicBatch = append(quicBatch, d)
			} else {
				v3Batch = append(v3Batch, d)
			}
		}

		if !s.publish(v3Batch, quicBatch) {
			release()
			return
		}
	}
}

// pumpScalar is the per-datagram loop, kept for any platform without recvmmsg.
func (s *splitUDP) pumpScalar() {
	var scratch [2][aes.BlockSize]byte
	var faults demuxReadFaults
	for {
		bp := s.buffers.Get().(*[]byte)
		buf := *bp
		n, _, flags, addr, err := s.real.ReadMsgUDPAddrPort(buf, nil)
		select {
		case <-s.done:
			s.buffers.Put(bp)
			return
		default:
		}
		if demuxPayloadTruncated(flags, err) {
			s.buffers.Put(bp)
			continue
		}
		if err != nil {
			s.buffers.Put(bp)
			if s.recoverRead(&faults, err) {
				continue
			}
			// Unblock v3/QUIC readers. Returning here without closing done
			// parks server.readLoop on demuxSide.recv forever: cover.go closes
			// this socket when the HTTPS/QUIC listener dies, and a gateway
			// that keeps printing posture while carrying nothing is the
			// silent-failure class this product cannot ship. If stop() already
			// ran, done is closed and this is the ordinary shutdown path.
			select {
			case <-s.done:
				return
			default:
			}
			fmt.Fprint(os.Stderr, observability.RedactAddresses(fmt.Sprintf(
				"winn3-gateway: UDP demux read failed: %v\n", err)))
			s.stop()
			return
		}
		s.clearReadFaults(&faults)
		if n == 0 {
			s.buffers.Put(bp)
			continue
		}
		pkt := buf[:n]
		d := demuxDatagram{b: pkt, poolBuf: bp, addr: addr}
		var v3Batch, quicBatch []demuxDatagram
		if s.routeQUIC(pkt, &scratch) {
			quicBatch = []demuxDatagram{d}
		} else {
			v3Batch = []demuxDatagram{d}
		}
		if !s.publish(v3Batch, quicBatch) {
			return
		}
	}
}

func (s *splitUDP) routeQUIC(pkt []byte, scratch *[2][aes.BlockSize]byte) bool {
	if isQUICLongHeader(pkt) {
		return true
	}
	if len(pkt) < 2 || pkt[0]&quicHeaderFormLong != 0 || pkt[0]&quicFixedBit == 0 {
		return false
	}
	return s.cidGen.matches(pkt, scratch)
}

func isQUICLongHeader(pkt []byte) bool {
	if len(pkt) < 5 {
		return false
	}
	if pkt[0]&quicHeaderFormLong == 0 {
		return false
	}
	version := binary.BigEndian.Uint32(pkt[1:5])
	switch version {
	case quicVersion1, quicVersion2, quicVersionNegotiation:
		return true
	default:
		return false
	}
}

func (d *demuxSide) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	d.recvMu.Lock()
	defer d.recvMu.Unlock()
	pkt, err := d.recv()
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	n := copy(b, pkt.b)
	d.release(pkt)
	return n, pkt.addr, nil
}

// WriteToUDPAddrPort is the v3 scalar path. It re-offers a datagram whose send
// consumed a pending socket error about ANOTHER datagram (nothing was sent),
// and otherwise RETURNS the error, including ENOBUFS, so driver.Loop retains
// the sealed bytes and retries them under its own budget. SendScalarRetain
// never drops.
func (d *demuxSide) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return retainScalar(d.split.errq, len(b), func() (int, error) {
		return d.split.real.WriteToUDPAddrPort(b, addr)
	})
}

// retainScalar is the v3 scalar contract: success is reported only for a write
// the kernel accepted in full. Every failure, and any short write, returns a
// non-nil error so driver.Loop retains the sealed bytes; it never returns
// success for unsent bytes.
func retainScalar(q *carrier.SocketErrorQueue, payloadLen int, write func() (int, error)) (int, error) {
	n, err := q.SendScalarRetain(write)
	if err == nil && n != payloadLen {
		return n, io.ErrShortWrite
	}
	return n, err
}

func (d *demuxSide) WriteBatchTo(msgs []carrier.BatchMsg, addr netip.AddrPort) (int, error) {
	if d.split.batch != nil {
		return d.split.batch.WriteBatchTo(msgs, addr)
	}
	for i := range msgs {
		payload := msgs[i].Payload[:msgs[i].N]
		if _, err := d.WriteToUDPAddrPort(payload, addr); err != nil {
			return i, err
		}
	}
	return len(msgs), nil
}

func (d *demuxSide) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := d.ReadFromUDPAddrPort(b)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(addr), nil
}

// WriteTo is the QUIC cover path (quic-go's basicConn.WritePacket). quic-go
// v0.60.0's sendQueue destroys the connection on any write error other than
// EMSGSIZE, so a transient local refusal (an fq ENOBUFS) or a consumed ICMP
// error about another peer must never reach it. SendCoverScalar retries briefly,
// drains, and on exhaustion DROPS the datagram with a success return; quic-go
// resends real data on its own. EMSGSIZE and closure pass through.
func (d *demuxSide) WriteTo(b []byte, addr net.Addr) (int, error) {
	return d.split.errq.SendCoverScalar(len(b), func() (int, error) {
		return d.split.real.WriteTo(b, addr)
	})
}

// recv is called with recvMu held through copying and releasing the packet.
func (d *demuxSide) recv() (demuxDatagram, error) {
	for {
		select {
		case <-d.split.done:
			return demuxDatagram{}, net.ErrClosed
		default:
		}
		deadlineNano := d.readDeadlineNano.Load()
		if deadlineNano != 0 && time.Now().UnixNano() >= deadlineNano {
			return demuxDatagram{}, os.ErrDeadlineExceeded
		}

		if len(d.pending) > 0 {
			pkt := d.pending[0]
			d.pending[0] = demuxDatagram{}
			d.pending = d.pending[1:]
			if len(d.pending) == 0 {
				d.pending = nil
			}
			return pkt, nil
		}

		var timeout <-chan time.Time
		var timer *time.Timer
		if deadlineNano != 0 {
			delay := time.Duration(deadlineNano - time.Now().UnixNano())
			if delay <= 0 {
				return demuxDatagram{}, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(delay)
			timeout = timer.C
		}

		select {
		case batch, ok := <-d.incoming:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				return demuxDatagram{}, net.ErrClosed
			}
			if len(batch) == 0 {
				continue
			}
			pkt := batch[0]
			batch[0] = demuxDatagram{}
			if len(batch) > 1 {
				d.pending = batch[1:]
			}
			return pkt, nil
		case <-timeout:
			return demuxDatagram{}, os.ErrDeadlineExceeded
		case <-d.wake:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-d.split.done:
			if timer != nil {
				timer.Stop()
			}
			return demuxDatagram{}, net.ErrClosed
		}
	}
}

func (d *demuxSide) wakeWaiter() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

func (d *demuxSide) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		d.readDeadlineNano.Store(0)
	} else {
		nano := t.UnixNano()
		if nano == 0 {
			nano = 1
		}
		d.readDeadlineNano.Store(nano)
	}
	d.wakeWaiter()
	return nil
}

func (d *demuxSide) SetWriteDeadline(time.Time) error { return nil }

func (d *demuxSide) SetDeadline(t time.Time) error {
	return d.SetReadDeadline(t)
}

func (d *demuxSide) Close() error {
	d.split.stop()
	return nil
}

func (d *demuxSide) LocalAddr() net.Addr {
	return d.split.real.LocalAddr()
}
