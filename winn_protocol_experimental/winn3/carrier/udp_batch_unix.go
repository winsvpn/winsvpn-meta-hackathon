//go:build linux || android

package carrier

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// kernelBatchConn is the narrow slice of golang.org/x/net this carrier needs.
// ipv4.Message and ipv6.Message are both aliases of socket.Message, so one
// message type serves both address families.
type kernelBatchConn interface {
	ReadBatch([]ipv4.Message, int) (int, error)
	WriteBatch([]ipv4.Message, int) (int, error)
}

type ipv4BatchConn struct{ pc *ipv4.PacketConn }

func (c ipv4BatchConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	return c.pc.ReadBatch(ms, flags)
}

func (c ipv4BatchConn) WriteBatch(ms []ipv4.Message, flags int) (int, error) {
	return c.pc.WriteBatch(ms, flags)
}

type ipv6BatchConn struct{ pc *ipv6.PacketConn }

func (c ipv6BatchConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	return c.pc.ReadBatch(ms, flags)
}

func (c ipv6BatchConn) WriteBatch(ms []ipv4.Message, flags int) (int, error) {
	return c.pc.WriteBatch(ms, flags)
}

const is64Bit = unsafe.Sizeof(uintptr(0)) == 8

type iovec struct {
	base *byte
	len  uint64
}

type msghdr struct {
	name       *byte
	namelen    uint32
	pad_cgo_0  [4]byte
	iov        *iovec
	iovlen     uint64
	control    *byte
	controllen uint64
	flags      int32
	pad_cgo_1  [4]byte
}

type mmsghdr struct {
	hdr       msghdr
	len       uint32
	pad_cgo_0 [4]byte
}

type RawBatchConn struct {
	conn    *net.UDPConn
	rawConn syscall.RawConn
	isConn  bool
	isV4    bool
	mu      sync.Mutex
	hs      []mmsghdr
	iovs    []iovec
	names   [][32]byte

	// One reusable source address per slot, with its own IP backing array.
	// ReadBatch used to publish `&net.UDPAddr{IP: make(net.IP, 4), ...}` for
	// every datagram on an unconnected socket, which is two heap objects per
	// packet: 961,000 of them in a three-second gigabit transfer. The only
	// consumer, recvBatchKernel, turns the address into a netip.AddrPort value
	// before the next ReadBatch can run, so reuse is safe and the copy is
	// already being made.
	addrs   []net.UDPAddr
	addrIPs [][16]byte

	// syscall.RawConn.Read and .Write take a callback, and a closure that
	// captures anything is a heap allocation per call. MEASURED: ReadBatch was
	// 425,995 objects in a three-second gigabit transfer, one per recvmmsg,
	// purely from rebuilding the same callback. These two are built once and
	// read their arguments from the fields below, all of them written under
	// c.mu, which the callers already hold for the whole syscall.
	callN        int
	callFlags    int
	callCount    int
	callAttempts int
	callErrno    syscall.Errno
	readFn    func(uintptr) bool
	writeFn   func(uintptr) bool

	// ReadBatchFrom's state is SEPARATE from everything above, and that is a
	// measured requirement rather than tidiness.
	//
	// rawConn.Read parks the goroutine on the poller until a datagram arrives,
	// so a reader holding the shared c.mu across that call holds it for as long
	// as the link is quiet. The gateway's demux pump is exactly such a reader
	// and the same RawBatchConn carries every session's downlink through
	// WriteBatchTo, so sharing one mutex put the entire transmit path behind
	// the receive wait. MEASURED on the Canada node, 2026-09-17: inner ping RTT
	// went from 45 ms to 2,106 ms and throughput went to zero. These fields and
	// rmu exist so a blocking receive blocks nothing but the next receive.
	rmu        sync.Mutex
	rhs        []mmsghdr
	riovs      []iovec
	rnames     [][32]byte
	rcallN     int
	rcallCount int
	rcallErrno syscall.Errno
	readFromFn func(uintptr) bool

	// errq drains this socket's MSG_ERRQUEUE and counts what WriteBatchTo and
	// ReadBatchFrom absorbed (udp_senderr_linux.go). It has its own lock, taken
	// only with TryLock on these paths, so a drain from the transmit path never
	// waits behind a parked receive or the other way round.
	errq *SocketErrorQueue

	// testRecvErrno, when set by a test, supplies the errno of the next
	// recvmmsg attempt in place of the syscall while it returns non-zero, so
	// the receive helper's retry budget can be exhausted deterministically.
	testRecvErrno func() syscall.Errno
}

type rawBatchConn = RawBatchConn

const txBatchSlots = 256

func NewRawBatchConn(conn *net.UDPConn) (*RawBatchConn, error) {
	if !is64Bit || conn == nil {
		return nil, errors.New("raw batch requires 64-bit architecture")
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	isV4 := true
	if ok && local != nil && local.IP.To4() == nil {
		isV4 = false
	}
	isConn := conn.RemoteAddr() != nil
	c := &RawBatchConn{
		conn:    conn,
		rawConn: rawConn,
		isConn:  isConn,
		isV4:    isV4,
		hs:      make([]mmsghdr, txBatchSlots),
		iovs:    make([]iovec, txBatchSlots),
		names:   make([][32]byte, txBatchSlots),
		addrs:   make([]net.UDPAddr, txBatchSlots),
		addrIPs: make([][16]byte, txBatchSlots),
	}
	c.readFn = func(fd uintptr) bool { return c.runmmsg(fd, unix.SYS_RECVMMSG) }
	c.writeFn = func(fd uintptr) bool { return c.runmmsg(fd, unix.SYS_SENDMMSG) }
	c.rhs = make([]mmsghdr, 32)
	c.riovs = make([]iovec, 32)
	c.rnames = make([][32]byte, 32)
	c.readFromFn = func(fd uintptr) bool { return c.runRecvFrom(fd) }
	c.errq = newSocketErrorQueue(rawConn)
	return c, nil
}

// ErrorQueue is this socket's error-queue drain and send-error counters.
func (c *RawBatchConn) ErrorQueue() *SocketErrorQueue {
	if c == nil {
		return nil
	}
	return c.errq
}

// runRecvFrom is ReadBatchFrom's callback. It is a copy of runmmsg over the
// receive-side vectors so that a parked receive never touches the fields the
// transmit path writes.
//
// A pending socket error is not a receive failure. With IP_RECVERR, an ICMP
// error about any peer sets sk_err, and __skb_recv_udp returns it BEFORE
// looking at the queue (net/ipv4/udp.c), so a datagram from a healthy session
// can sit behind another peer's port-unreachable. MEASURED, Linux 6.8 netns:
// recvmmsg returned ECONNREFUSED with a datagram queued, and the next call
// returned the datagram. The error was consumed by the failed call, so the
// datagram is read again at once, after the error queue is drained.
func (c *RawBatchConn) runRecvFrom(fd uintptr) bool {
	for attempt := 0; ; attempt++ {
		var r1 uintptr
		var errno syscall.Errno
		if h := c.testRecvErrno; h != nil {
			errno = h()
		}
		if errno == 0 {
			r1, _, errno = syscall.Syscall6(
				unix.SYS_RECVMMSG,
				fd,
				uintptr(unsafe.Pointer(&c.rhs[0])),
				uintptr(c.rcallN),
				uintptr(batchRecvFlags),
				0,
				0,
			)
		}
		if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
			return false
		}
		if errno != 0 {
			if attempt < AsyncErrorRetries && isAsyncSocketErrno(errno) {
				c.errq.matchingRetries.Add(1)
				c.errq.drainFD(fd)
				continue
			}
			c.rcallErrno = errno
			return true
		}
		c.rcallCount = int(r1)
		return true
	}
}

// runmmsg is the body both callbacks share. It returns false on EAGAIN so the
// runtime parks the goroutine on the poller and retries, which is the contract
// syscall.RawConn.Read and .Write document.
func (c *RawBatchConn) runmmsg(fd uintptr, trap uintptr) bool {
	r1, _, errno := syscall.Syscall6(
		trap,
		fd,
		uintptr(unsafe.Pointer(&c.hs[0])),
		uintptr(c.callN),
		uintptr(c.callFlags),
		0,
		0,
	)
	if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
		return false
	}
	if trap == unix.SYS_SENDMMSG && errno == syscall.ENOBUFS && c.callAttempts < 8 {
		c.callAttempts++
		return false
	}
	if errno != 0 {
		c.callErrno = errno
		return true
	}
	c.callCount = int(r1)
	return true
}

func newRawBatchConn(conn *net.UDPConn) (*rawBatchConn, error) {
	return NewRawBatchConn(conn)
}

func (c *RawBatchConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	nMsgs := len(ms)
	if nMsgs == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.hs) < nMsgs {
		c.hs = make([]mmsghdr, nMsgs)
		c.iovs = make([]iovec, nMsgs)
		c.names = make([][32]byte, nMsgs)
		c.addrs = make([]net.UDPAddr, nMsgs)
		c.addrIPs = make([][16]byte, nMsgs)
	}
	for i := 0; i < nMsgs; i++ {
		if len(ms[i].Buffers) == 0 || len(ms[i].Buffers[0]) == 0 {
			return 0, errors.New("empty buffer for ReadBatch")
		}
		c.iovs[i].base = &ms[i].Buffers[0][0]
		c.iovs[i].len = uint64(len(ms[i].Buffers[0]))
		c.hs[i].hdr.iov = &c.iovs[i]
		c.hs[i].hdr.iovlen = 1
		c.hs[i].hdr.name = &c.names[i][0]
		c.hs[i].hdr.namelen = 32
		c.hs[i].hdr.control = nil
		c.hs[i].hdr.controllen = 0
		c.hs[i].hdr.flags = 0
		c.hs[i].len = 0
	}
	c.callN, c.callFlags, c.callCount, c.callErrno = nMsgs, flags, 0, 0
	err := c.rawConn.Read(c.readFn)
	count, sysErr := c.callCount, c.callErrno
	if err != nil {
		return 0, err
	}
	if sysErr != 0 {
		return 0, sysErr
	}
	for i := 0; i < count; i++ {
		ms[i].N = int(c.hs[i].len)
		ms[i].Flags = int(c.hs[i].hdr.flags)
		if !c.isConn && c.hs[i].hdr.namelen >= 16 {
			family := binary.NativeEndian.Uint16(c.names[i][0:2])
			if family == unix.AF_INET {
				copy(c.addrIPs[i][:4], c.names[i][4:8])
				c.addrs[i] = net.UDPAddr{
					IP:   c.addrIPs[i][:4],
					Port: int(binary.BigEndian.Uint16(c.names[i][2:4])),
				}
				ms[i].Addr = &c.addrs[i]
			} else if family == unix.AF_INET6 && c.hs[i].hdr.namelen >= 28 {
				copy(c.addrIPs[i][:], c.names[i][8:24])
				c.addrs[i] = net.UDPAddr{
					IP:   c.addrIPs[i][:],
					Port: int(binary.BigEndian.Uint16(c.names[i][2:4])),
				}
				ms[i].Addr = &c.addrs[i]
			}
		} else {
			ms[i].Addr = nil
		}
	}
	return count, nil
}

func (c *RawBatchConn) WriteBatch(ms []ipv4.Message, flags int) (int, error) {
	nMsgs := len(ms)
	if nMsgs == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.hs) < nMsgs {
		c.hs = make([]mmsghdr, nMsgs)
		c.iovs = make([]iovec, nMsgs)
		c.names = make([][32]byte, nMsgs)
	}
	for i := 0; i < nMsgs; i++ {
		if len(ms[i].Buffers) == 0 || len(ms[i].Buffers[0]) == 0 {
			return 0, errors.New("empty buffer for WriteBatch")
		}
		c.iovs[i].base = &ms[i].Buffers[0][0]
		c.iovs[i].len = uint64(len(ms[i].Buffers[0]))
		c.hs[i].hdr.iov = &c.iovs[i]
		c.hs[i].hdr.iovlen = 1
		c.hs[i].hdr.control = nil
		c.hs[i].hdr.controllen = 0
		c.hs[i].hdr.flags = 0
		c.hs[i].len = 0

		if !c.isConn && ms[i].Addr != nil {
			udpAddr, ok := ms[i].Addr.(*net.UDPAddr)
			if ok && udpAddr != nil {
				if ip4 := udpAddr.IP.To4(); ip4 != nil {
					binary.NativeEndian.PutUint16(c.names[i][0:2], unix.AF_INET)
					binary.BigEndian.PutUint16(c.names[i][2:4], uint16(udpAddr.Port))
					copy(c.names[i][4:8], ip4)
					for k := 8; k < 16; k++ {
						c.names[i][k] = 0
					}
					c.hs[i].hdr.name = &c.names[i][0]
					c.hs[i].hdr.namelen = 16
				} else if ip6 := udpAddr.IP.To16(); ip6 != nil {
					binary.NativeEndian.PutUint16(c.names[i][0:2], unix.AF_INET6)
					binary.BigEndian.PutUint16(c.names[i][2:4], uint16(udpAddr.Port))
					binary.NativeEndian.PutUint32(c.names[i][4:8], 0) // flowinfo
					copy(c.names[i][8:24], ip6)
					binary.NativeEndian.PutUint32(c.names[i][24:28], 0) // scope_id
					c.hs[i].hdr.name = &c.names[i][0]
					c.hs[i].hdr.namelen = 28
				}
			}
		} else {
			c.hs[i].hdr.name = nil
			c.hs[i].hdr.namelen = 0
		}
	}
	c.callN, c.callFlags, c.callCount, c.callAttempts, c.callErrno = nMsgs, flags, 0, 0, 0
	err := c.rawConn.Write(c.writeFn)
	count, sysErr := c.callCount, c.callErrno
	if err != nil {
		return count, err
	}
	if sysErr != 0 {
		return count, sysErr
	}
	return count, nil
}

// WriteBatchTo transmits up to len(msgs) datagrams to the specified destination
// address in a single sendmmsg syscall.
func (c *RawBatchConn) WriteBatchTo(msgs []BatchMsg, to netip.AddrPort) (int, error) {
	nMsgs := len(msgs)
	if nMsgs == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.hs) < nMsgs {
		c.hs = make([]mmsghdr, nMsgs)
		c.iovs = make([]iovec, nMsgs)
		c.names = make([][32]byte, nMsgs)
	}

	var name [32]byte
	var namelen uint32
	if to.Addr().Is4() {
		ip4 := to.Addr().As4()
		binary.NativeEndian.PutUint16(name[0:2], unix.AF_INET)
		binary.BigEndian.PutUint16(name[2:4], to.Port())
		copy(name[4:8], ip4[:])
		namelen = 16
	} else if to.Addr().Is6() {
		ip6 := to.Addr().As16()
		binary.NativeEndian.PutUint16(name[0:2], unix.AF_INET6)
		binary.BigEndian.PutUint16(name[2:4], to.Port())
		copy(name[8:24], ip6[:])
		namelen = 28
	}

	for i := 0; i < nMsgs; i++ {
		payload := msgs[i].Payload[:msgs[i].N]
		if len(payload) == 0 {
			return 0, errors.New("empty payload for WriteBatchTo")
		}
		c.iovs[i].base = &payload[0]
		c.iovs[i].len = uint64(len(payload))
		c.hs[i].hdr.iov = &c.iovs[i]
		c.hs[i].hdr.iovlen = 1
		c.hs[i].hdr.control = nil
		c.hs[i].hdr.controllen = 0
		c.hs[i].hdr.flags = 0
		c.hs[i].len = 0
		c.names[i] = name
		c.hs[i].hdr.name = &c.names[i][0]
		c.hs[i].hdr.namelen = namelen
	}

	// SEND-ERROR HANDLING, NEVER A POLLER PARK HELD BEHIND c.mu.
	//
	// c.mu is the transmit lock for EVERY session on this shared socket, so this
	// callback must not block in the poller: a park here stalls every other
	// client's downlink. It therefore returns after ONE pass over sendmmsg and
	// hands any unfinished work back as a short count, which driver.Loop retains
	// and retries under its own bounded, cancellation-aware budget
	// (carrierDrainBackoff within carrierStallLimit), releasing c.mu between
	// tries. Without IP_RECVERR the first fq flow_limit drop is invisible:
	// udp_send_skb turns -ENOBUFS into success and only bumps Udp: SndbufErrors.
	// MEASURED on the Canada node, 2026-09-17 (SndbufErrors 263,060).
	//
	// sendmmsg reports only the count before a failing datagram and discards the
	// error (__sys_sendmmsg, net/socket.c), so a short count is re-presented from
	// the first unsent datagram to learn why it stopped:
	//
	//   - ENOBUFS: the egress qdisc's verdict on that datagram (fq_enqueue ->
	//     NET_XMIT_DROP -> ip_send_skb -> -ENOBUFS). Returned with the accepted
	//     prefix so the caller retains that exact datagram. Counted.
	//   - EAGAIN: the send buffer is full for every session alike. Return the
	//     accepted prefix with NO error and do not park; the caller backs off. A
	//     positive short count is enough for retention, and a zero-progress EAGAIN
	//     returns (0, nil) so the driver's backoff, not a held mutex, does the
	//     waiting.
	//   - a matching (ICMP-class) errno: sock_alloc_send_pskb consumed a pending
	//     sk_err before building the skb, so nothing was sent; re-offer the SAME
	//     datagram up to AsyncErrorRetries, draining the error queue. On
	//     exhaustion the errno is NOT attributed (it may be a synchronous EMSGSIZE
	//     or another peer's consumed ICMP error, indistinguishable by recurrence):
	//     return the accepted prefix with NO error, and let retention carry the
	//     rest. A persistent stall fails the loop generically, never as a peer or
	//     path-MTU verdict.
	//   - any other errno: surfaced, since it is neither transient nor ambiguous.
	var count int
	var sysErr error
	absorbed := 0
	err := c.rawConn.Write(func(fd uintptr) bool {
		for count < nMsgs {
			r1, _, errno := syscall.Syscall6(
				unix.SYS_SENDMMSG,
				fd,
				uintptr(unsafe.Pointer(&c.hs[count])),
				uintptr(nMsgs-count),
				0,
				0,
				0,
			)
			switch {
			case errno == 0 && r1 > 0:
				count += int(r1)
			case errno == 0:
				sysErr = errors.New("sendmmsg accepted no datagram and reported no error")
				return true
			case errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK:
				// Do NOT park: return the prefix and let the caller back off.
				return true
			case errno == syscall.ENOBUFS:
				c.errq.transmitRefused.Add(1)
				sysErr = errno
				return true
			case absorbed < AsyncErrorRetries && isAsyncSocketErrno(errno):
				absorbed++
				c.errq.matchingRetries.Add(1)
				c.errq.drainFD(fd)
			case isAsyncSocketErrno(errno):
				// Retry budget spent. UNATTRIBUTED: return the accepted prefix
				// with no error so the caller retains the rest as backpressure.
				return true
			default:
				sysErr = errno
				return true
			}
		}
		return true
	})
	if err != nil {
		return count, err
	}
	if sysErr != nil {
		return count, sysErr
	}
	return count, nil
}

// batchRecvFlags makes recvmmsg return as soon as the first datagram has been
// copied, carrying whatever else was already queued behind it. Without
// MSG_WAITFORONE, recvmmsg blocks until the whole vector is filled, which would
// convert a quiet link into a stall for the full socket read deadline.
const batchRecvFlags = unix.MSG_WAITFORONE

// batchState caches the wrapped connection and its scratch vectors for the
// carrier's lifetime. Allocating these once is the point: a per-call
// allocation would hand back the syscall saving in GC pressure.
//
// iovecs is the part that was missing. ipv4.Message.Buffers is a [][]byte, and
// writing `Buffers: [][]byte{payload}` builds a ONE-ELEMENT SLICE PER DATAGRAM.
// MEASURED, Galaxy S26 Ultra (SM-S948U1), 2026-09-17, alloc_objects profile of
// BenchmarkWireSpeedUpload: those one-element slices were 5,527,000 of the
// 7,146,000 objects the whole run allocated, 77% of everything, for a
// three-second transfer. Every message slot now owns one reusable
// single-element vector and the loop rewrites element zero.
type batchState struct {
	once     sync.Once
	conn     kernelBatchConn
	mu       sync.Mutex
	messages []ipv4.Message
	scratch  [][]byte
	iovecs   [][][]byte
}

// grow sizes every parallel vector together, so an index valid in one is valid
// in all of them. They are only ever grown, never shrunk.
func (b *batchState) grow(count int) {
	if cap(b.messages) < count {
		b.messages = make([]ipv4.Message, count)
		b.scratch = make([][]byte, count)
		b.iovecs = make([][][]byte, count)
		for i := range b.iovecs {
			b.iovecs[i] = make([][]byte, 1)
		}
	}
	b.messages = b.messages[:count]
	b.scratch = b.scratch[:count]
	b.iovecs = b.iovecs[:count]
}

func (b *batchState) get(conn *net.UDPConn) kernelBatchConn {
	b.once.Do(func() {
		if conn == nil {
			return
		}
		if raw, err := newRawBatchConn(conn); err == nil && raw != nil {
			b.conn = wrapGSOBatchConn(raw, conn)
			return
		}
		local, ok := conn.LocalAddr().(*net.UDPAddr)
		if !ok || local == nil {
			return
		}
		if local.IP.To4() != nil {
			b.conn = ipv4BatchConn{pc: ipv4.NewPacketConn(conn)}
			return
		}
		b.conn = ipv6BatchConn{pc: ipv6.NewPacketConn(conn)}
	})
	return b.conn
}

// vectors returns count reusable messages configured to write directly into
// msgs[i].Payload when capacity permits (zero-copy), falling back to scratch
// buffers if a slot's capacity is below ceiling.
func (b *batchState) vectors(msgs []BatchMsg, ceiling int) []ipv4.Message {
	count := len(msgs)
	b.grow(count)
	for i := 0; i < count; i++ {
		if cap(msgs[i].Payload) >= ceiling {
			b.iovecs[i][0] = msgs[i].Payload[:ceiling]
		} else {
			if cap(b.scratch[i]) < ceiling {
				b.scratch[i] = make([]byte, ceiling)
			}
			b.scratch[i] = b.scratch[i][:ceiling]
			b.iovecs[i][0] = b.scratch[i]
		}
		b.messages[i].Buffers = b.iovecs[i]
		b.messages[i].Addr = nil
		b.messages[i].N = 0
		b.messages[i].NN = 0
		b.messages[i].Flags = 0
	}
	return b.messages
}

// recvBatchKernel performs one recvmmsg and applies exactly the peer filter,
// ceiling check and statistics the per-datagram path applies. It returns
// ok=false when no kernel batch path is available, in which case the caller
// runs the portable loop unchanged.
func (u *UDP) recvBatchKernel(
	ctx context.Context,
	msgs []BatchMsg,
	ceiling int,
) (read int, err error, ok bool) {
	batch := u.recvBatchState.get(u.conn)
	if batch == nil {
		return 0, nil, false
	}
	u.recvBatchState.mu.Lock()
	defer u.recvBatchState.mu.Unlock()
	vectors := u.recvBatchState.vectors(msgs, ceiling)
	count, readErr := batch.ReadBatch(vectors, batchRecvFlags)
	if readErr != nil {
		u.mu.Lock()
		u.stats.RecvErrors++
		u.mu.Unlock()
		if errors.Is(readErr, net.ErrClosed) {
			return 0, ErrClosed, true
		}
		return 0, readErr, true
	}
	u.mu.Lock()
	peer := u.peer
	maxMessage := u.maxMessage
	var want netip.AddrPort
	if peer != nil {
		want = peer.AddrPort()
	}
	isConn := u.conn.RemoteAddr() != nil
	now := u.clock.Now()
	kept := 0
	for i := 0; i < count; i++ {
		n := vectors[i].N
		// The iovec is only ceiling bytes wide, so an oversize datagram comes
		// back with n == ceiling and only MSG_TRUNC says it was cut.
		if vectors[i].Flags&unix.MSG_TRUNC != 0 || n <= 0 || n > maxMessage || n > ceiling {
			u.stats.RecvErrors++
			continue
		}
		from, addrOK := batchSourceAddr(vectors[i].Addr)
		if isConn {
			from = want
			addrOK = true
		}
		if peer != nil {
			if !addrOK ||
				from.Addr().Unmap().WithZone("") != want.Addr().Unmap().WithZone("") ||
				from.Port() != want.Port() {
				u.stats.Foreign++
				continue
			}
		}
		direct := len(msgs[i].Payload) >= ceiling && &vectors[i].Buffers[0][0] == &msgs[i].Payload[0]
		if direct {
			if kept < i {
				copy(msgs[kept].Payload[:n], msgs[i].Payload[:n])
			}
		} else {
			copy(msgs[kept].Payload[:n], vectors[i].Buffers[0][:n])
		}
		msgs[kept].N = n
		msgs[kept].Addr = from
		msgs[kept].Err = nil
		u.stats.Delivered++
		u.stats.DeliveredBytes += uint64(n)
		u.stats.LastDelivered = now
		kept++
	}
	u.mu.Unlock()
	return kept, nil, true
}

// sendBatchKernel performs one sendmmsg. A partial write returns the number of
// datagrams the kernel accepted, matching the documented partial-result
// contract of SendBatch.
func (u *UDP) sendBatchKernel(
	ctx context.Context,
	msgs []BatchMsg,
) (written int, err error, ok bool) {
	batch := u.sendBatchState.get(u.conn)
	if batch == nil {
		return 0, nil, false
	}
	u.mu.Lock()
	closed, maxMessage, peer := u.closed, u.maxMessage, u.peer
	u.mu.Unlock()
	if closed {
		return 0, ErrClosed, true
	}
	var addr net.Addr
	if peer != nil && u.conn.RemoteAddr() == nil {
		addr = peer
	}
	u.sendBatchState.mu.Lock()
	defer u.sendBatchState.mu.Unlock()
	// Same reusable one-element vectors as the receive side. Building
	// `[][]byte{payload}` here was another 415,000 objects in a three-second
	// gigabit upload, on top of the receive side's 5.5 million.
	u.sendBatchState.grow(len(msgs))
	vectors := u.sendBatchState.messages[:len(msgs)]
	for i := range msgs {
		payload := msgs[i].Payload[:msgs[i].N]
		if len(payload) == 0 {
			return 0, ErrMessageEmpty, true
		}
		if len(payload) > maxMessage {
			return 0, wrap(ErrMessageTooLarge, "%d bytes, ceiling %d", len(payload), maxMessage), true
		}
		u.sendBatchState.iovecs[i][0] = payload
		vectors[i].Buffers = u.sendBatchState.iovecs[i]
		vectors[i].Addr = addr
		vectors[i].N = 0
		vectors[i].NN = 0
		vectors[i].Flags = 0
	}
	count, writeErr := batch.WriteBatch(vectors, 0)
	if count < 0 {
		count = 0
	}
	if count > len(msgs) {
		count = len(msgs)
	}
	accepted := uint64(0)
	for i := 0; i < count; i++ {
		accepted += uint64(msgs[i].N)
	}
	u.mu.Lock()
	u.stats.Sent += uint64(count)
	u.stats.SentBytes += accepted
	if count > 0 {
		u.stats.LastSend = u.clock.Now()
	}
	if writeErr != nil {
		u.stats.SendErrors++
	}
	u.mu.Unlock()
	if writeErr != nil {
		if errors.Is(writeErr, net.ErrClosed) {
			return count, ErrClosed, true
		}
		if count < len(msgs) {
			if reduced := u.notePathMTUSendFailure(msgs[count].N, writeErr); reduced != writeErr {
				return count, reduced, true
			}
		}
		return count, writeErr, true
	}
	return count, nil, true
}

// batchSourceAddr converts the address recvmmsg reported. A connected socket
// reports none, which is not an error: the kernel already filtered the peer.
func batchSourceAddr(addr net.Addr) (netip.AddrPort, bool) {
	udp, ok := addr.(*net.UDPAddr)
	if !ok || udp == nil {
		return netip.AddrPort{}, false
	}
	parsed, ok := netip.AddrFromSlice(udp.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(parsed.Unmap().WithZone(udp.Zone), uint16(udp.Port)), true
}

// ReadBatchFrom fills up to len(msgs) slots from one recvmmsg.
//
// It is the receive counterpart of WriteBatchTo and it exists for the same
// reason: a caller that already owns per-slot byte slices should not have to
// know what an ipv4.Message is, nor import x/net, to get the syscall saving.
// Each slot's Payload is used directly as that datagram's iovec, so nothing is
// copied between the kernel and the caller's storage.
//
// A datagram larger than a slot's Payload is NOT silently truncated into it.
// The kernel sets MSG_TRUNC for that slot, this reports ErrMessageTooLarge on
// the slot with N left at zero, and the caller drops it. Handing a truncated
// Winn3 message upward would fail to open and read as a forgery rather than as
// an oversize datagram, which is exactly the confusion the maxRecvDatagram
// comment in udp.go exists to prevent.
//
// MSG_WAITFORONE makes the syscall return as soon as the first datagram has
// been copied, carrying whatever was already queued behind it. Without it
// recvmmsg blocks until the whole vector is full, which turns a quiet link into
// a stall for the socket's whole read deadline.
func (c *RawBatchConn) ReadBatchFrom(msgs []BatchMsg) (int, error) {
	nMsgs := len(msgs)
	if nMsgs == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.rhs) < nMsgs {
		c.rhs = make([]mmsghdr, nMsgs)
		c.riovs = make([]iovec, nMsgs)
		c.rnames = make([][32]byte, nMsgs)
	}
	for i := 0; i < nMsgs; i++ {
		buf := msgs[i].Payload
		if len(buf) == 0 {
			return 0, errors.New("empty buffer for ReadBatchFrom")
		}
		msgs[i].N = 0
		msgs[i].Err = nil
		msgs[i].Addr = netip.AddrPort{}
		c.riovs[i].base = &buf[0]
		c.riovs[i].len = uint64(len(buf))
		c.rhs[i].hdr.iov = &c.riovs[i]
		c.rhs[i].hdr.iovlen = 1
		c.rhs[i].hdr.name = &c.rnames[i][0]
		c.rhs[i].hdr.namelen = 32
		c.rhs[i].hdr.control = nil
		c.rhs[i].hdr.controllen = 0
		c.rhs[i].hdr.flags = 0
		c.rhs[i].len = 0
	}
	c.rcallN, c.rcallCount, c.rcallErrno = nMsgs, 0, 0
	err := c.rawConn.Read(c.readFromFn)
	count, sysErr := c.rcallCount, c.rcallErrno
	if err != nil {
		return 0, err
	}
	if sysErr != 0 {
		return 0, sysErr
	}
	if count > nMsgs {
		count = nMsgs
	}
	for i := 0; i < count; i++ {
		if c.rhs[i].hdr.flags&int32(unix.MSG_TRUNC) != 0 {
			msgs[i].Err = ErrMessageTooLarge
			continue
		}
		n := int(c.rhs[i].len)
		if n < 0 || n > len(msgs[i].Payload) {
			msgs[i].Err = ErrMessageTooLarge
			continue
		}
		msgs[i].N = n
		if c.isConn || c.rhs[i].hdr.namelen < 16 {
			continue
		}
		family := binary.NativeEndian.Uint16(c.rnames[i][0:2])
		port := binary.BigEndian.Uint16(c.rnames[i][2:4])
		if family == unix.AF_INET {
			var ip4 [4]byte
			copy(ip4[:], c.rnames[i][4:8])
			msgs[i].Addr = netip.AddrPortFrom(netip.AddrFrom4(ip4), port)
		} else if family == unix.AF_INET6 && c.rhs[i].hdr.namelen >= 28 {
			var ip16 [16]byte
			copy(ip16[:], c.rnames[i][8:24])
			msgs[i].Addr = netip.AddrPortFrom(netip.AddrFrom16(ip16).Unmap(), port)
		}
	}
	return count, nil
}
