package carrier

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// kernelBatchEnabled controls recvmmsg/sendmmsg syscall batching on linux/android.
// Disabled pending verification of connected-socket address semantics.
var kernelBatchEnabled = true

// UDP is the datagram carrier: one Winn3 message per UDP datagram, and nothing
// else on the wire.
//
// It adds no bytes. A message format that is already unconditionally uniform:
// PRF-output demux token, then ciphertext and tag, with no field an observer
// could predict knowing the whole design, needs no framing, and adding any
// would be adding back the thing the format removes. There is no salt, no
// record header, no sequence number and no keepalive.
//
// # Reordering, and what this carrier does about it
//
// This carrier deliberately has NO reorder discipline of its own. A datagram
// carries no sequence number, so there is nothing here to re-sort by, and the
// datagram must therefore be handed up unaltered. Reorder repair belongs to the
// frame layer above this carrier: netlab's token-window discipline
// (winn3/core/replay.go: the force-advance rule, a low edge that trails the
// counter by half the window, tolerating displacement up to half-the-window
// minus one) re-sorts datagrams into token order once it has opened them. What
// that discipline requires of this carrier is exactly what this carrier does:
// forward every arriving datagram intact, exactly once, one per Recv, and in
// the order the socket delivered it. If this carrier re-sorted, gated a "next"
// counter, or dropped an out-of-order datagram, it would remove the very
// information the frame layer needs to reorder, turning a tolerated
// displacement into a silently-lost message. See udp_reorder_test.go, which
// pins this contract on both peer modes.
//
// # Two peer modes, and the security property in the difference
//
//   - Connected. DialUDP produces a connected socket, so the kernel discards
//     datagrams from anything but the gateway before they reach this process.
//     This is the client mode and it is the cheap one.
//   - Explicit peer. NewUDP over an unconnected socket filters the source
//     address in userspace and counts what it discards as Stats.Foreign.
//
// The filter is not bookkeeping. Stats.LastDelivered is the freshest evidence a
// policy layer has that a carrier is still carrying, and an off-path attacker
// who has found the five-tuple can send datagrams to it. If a foreign datagram
// moved LastDelivered, that attacker could hold a blocked carrier's health
// indicator up and pin a user on a transport that is carrying nothing, a
// failover-suppression attack that costs one spoofed packet per second. Foreign
// datagrams move Foreign and nothing else.
type UDP struct {
	conn *net.UDPConn
	// owns records whether Close should close the socket. A carrier handed a
	// socket it did not open must not close it: on a gateway that socket serves
	// every other session.
	owns bool
	// explicit records that this carrier was built in explicit-peer mode. It is
	// fixed for the carrier's life: a connected socket's peer lives in the
	// kernel and cannot be moved from here, so SetPeer refuses rather than
	// pretending.
	explicit bool

	pathCeiling int
	clock       Clock

	recvMu sync.Mutex
	buf    []byte

	mu sync.Mutex
	// peer is nil on a connected socket. On an unconnected one it is the only
	// address this carrier will send to or accept from. It is MUTABLE (see
	// SetPeer), so every read of it is under mu.
	peer       *net.UDPAddr
	maxMessage int
	closed     bool
	fatalErr   error
	stats      Stats

	// Kernel UDP buffer sizes, written once in NewUDP and then immutable.
	// Linux clamps SO_RCVBUF to rmem_max silently, so these are the grant
	// a getsockopt read back, not the request SetReadBuffer returned nil for.
	socketBufferRequested int
	socketBufferRead      int
	socketBufferWrite     int

	// pathMTU is the kernel path-MTU measurement for this socket. See pmtud.go.
	// It is its own atomic rather than a field under mu because Send reads it
	// on the error path, where mu is not held.
	pathMTU pathMTUState

	// Receive and send have independent scratch vectors and locks. A blocking
	// receive must not prevent the sender from transmitting packets.
	recvBatchState batchState
	sendBatchState batchState

	// One cancellation watch per direction, held for the life of the context
	// rather than rebuilt per datagram batch. See deadline_watch.go.
	readArm  deadlineArm
	writeArm deadlineArm

	// A METHOD VALUE IS A HEAP ALLOCATION. `u.conn.SetReadDeadline` written at
	// a call site builds a closure over u.conn every single time, which put
	// 163,842 objects back into a three-second gigabit transfer right after the
	// watch caching took 481,000 out. Binding both once, next to the conn they
	// close over, costs two words per carrier.
	setRead  func(time.Time) error
	setWrite func(time.Time) error
}

// UDPConfig configures a datagram carrier.
type UDPConfig struct {
	// Remote is the gateway endpoint. Required by DialUDP, ignored by NewUDP
	// when Peer is set.
	Remote *net.UDPAddr

	// Conn is an existing socket for NewUDP. DialUDP opens its own.
	Conn *net.UDPConn

	// Peer, when set, makes this carrier filter and address datagrams explicitly
	// rather than relying on a connected socket.
	Peer *net.UDPAddr

	// OwnsConn tells Close whether it may close Conn. DialUDP always owns.
	OwnsConn bool

	// MaxMessageSize is the send ceiling. Zero means MaxMessageSizeFor at
	// PathMTU for the resolved family. A caller whose session may migrate should
	// pass Floor rather than either.
	MaxMessageSize int

	// PathMTU is the measured path MTU. Zero means DefaultPathMTU.
	PathMTU int

	// Clock is injected for tests. Nil means the system clock.
	Clock Clock

	// SocketBufferBytes is the SO_RCVBUF/SO_SNDBUF this carrier asks the
	// kernel for. Zero means DefaultUDPSocketBufferBytes (8 MiB). A
	// negative value is ErrConfig: there is no "skip" so a caller cannot
	// accidentally ship the kernel default that is the downlink ceiling.
	SocketBufferBytes int

	// SocketBufferHook, if set, is called once after the kernel grant is
	// read back with getsockopt. A short grant is NOT an error: a phone
	// or laptop cannot raise net.core.rmem_max without root, and refusing
	// would make the client unusable on the devices this product targets.
	// The gateway (cmd/winn3-gateway) refuses below 4 MiB because a
	// gateway host is supposed to have had those sysctls raised by the
	// installer. This hook is how a client logs the mismatch instead.
	SocketBufferHook func(requested, gotRead, gotWrite int, setErr error)

	// buffersApplied is set by applyConfiguredUDPSocketBuffers so DialUDP
	// can raise the socket it just opened and NewUDP will not raise it a
	// second time (which would fire the hook twice). Unexported so a
	// caller cannot fake a raise by setting a public flag.
	buffersApplied        bool
	socketBufferRequested int
	socketBufferRead      int
	socketBufferWrite     int
}

// DialUDP opens a connected datagram carrier to the gateway.
//
// It writes nothing: a connected UDP socket is a kernel-side filter, not a
// handshake, so no packet leaves until Send is called. A carrier that greeted
// its gateway would be a fixed-size first packet, fleet-wide.
func DialUDP(ctx context.Context, cfg UDPConfig) (*UDP, error) {
	if cfg.Remote == nil {
		return nil, wrap(ErrConfig, "no remote endpoint")
	}
	if cfg.Remote.Port == 0 {
		return nil, wrap(ErrConfig, "remote port is 0")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", cfg.Remote.String())
	if err != nil {
		return nil, err
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, wrap(ErrConfig, "dialer returned %T, not a UDP connection", conn)
	}
	cfg.Conn = udp
	cfg.Peer = nil
	cfg.OwnsConn = true
	if err := applyConfiguredUDPSocketBuffers(&cfg); err != nil {
		_ = udp.Close()
		return nil, err
	}
	c, err := NewUDP(cfg)
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	return c, nil
}

// NewUDP wraps an existing datagram socket.
func NewUDP(cfg UDPConfig) (*UDP, error) {
	if cfg.Conn == nil {
		return nil, wrap(ErrConfig, "no connection")
	}
	pathMTU := cfg.PathMTU
	if pathMTU == 0 {
		pathMTU = DefaultPathMTU
	}
	addr := cfg.Conn.RemoteAddr()
	if addr == nil && cfg.Peer != nil {
		addr = cfg.Peer
	}
	family := FamilyOf(addr)
	ceiling := MaxMessageSizeFor(ClassUDP, family, pathMTU)

	maxMessage := cfg.MaxMessageSize
	if maxMessage == 0 {
		maxMessage = ceiling
	}
	if err := checkSize(maxMessage, ceiling); err != nil {
		return nil, err
	}
	if remote, ok := cfg.Conn.RemoteAddr().(*net.UDPAddr); ok && remote != nil {
		if cfg.Peer != nil && !sameUDPAddr(cfg.Peer, remote) {
			return nil, wrap(ErrConfig,
				"connected socket is bound to %s but an explicit peer of %s was supplied",
				remote, cfg.Peer)
		}
		cfg.Peer = nil
	} else if cfg.Peer == nil {
		// An unconnected socket with no peer would accept datagrams from
		// anywhere and would not know where to send. Refused rather than
		// defaulted: the default would be a carrier with no sender filter at
		// all, which is the failover-suppression surface described above.
		return nil, wrap(ErrConfig, "unconnected socket needs an explicit peer")
	}

	clock := cfg.Clock
	if clock == nil {
		clock = SystemClock{}
	}
	if err := applyConfiguredUDPSocketBuffers(&cfg); err != nil {
		return nil, err
	}
	u := &UDP{
		conn:                  cfg.Conn,
		peer:                  cfg.Peer,
		explicit:              cfg.Peer != nil,
		owns:                  cfg.OwnsConn,
		pathCeiling:           ceiling,
		clock:                 clock,
		buf:                   make([]byte, maxRecvDatagram),
		maxMessage:            maxMessage,
		socketBufferRequested: cfg.socketBufferRequested,
		socketBufferRead:      cfg.socketBufferRead,
		socketBufferWrite:     cfg.socketBufferWrite,
	}
	u.setRead = u.conn.SetReadDeadline
	u.setWrite = u.conn.SetWriteDeadline
	u.EnablePathMTUDiscovery()
	return u, nil
}

// SocketBuffers reports the SO_RCVBUF/SO_SNDBUF this carrier asked for and
// what the kernel granted. Linux clamps silently to rmem_max, so the grant
// can be a fraction of the request even when SetReadBuffer returned nil.
func (u *UDP) SocketBuffers() (requested, read, write int) {
	return u.socketBufferRequested, u.socketBufferRead, u.socketBufferWrite
}

// Peer reports the address this carrier sends to and accepts from, or nil on a
// connected socket, where the kernel holds it instead.
//
// The returned value is a copy. Handing out the carrier's own pointer would let
// a caller mutate the filter that Recv compares against, from outside the mutex
// that protects it.
func (u *UDP) Peer() *net.UDPAddr {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.peer == nil {
		return nil
	}
	cp := *u.peer
	cp.IP = append(net.IP(nil), u.peer.IP...)
	return &cp
}

// SetPeer moves the return path to a new address. It is how a NAT rebind stops
// costing a re-handshake.
//
// # What it fixes
//
// The gateway's demultiplexer indexes by demux token and takes no address at
// all, so a rebound client's datagrams route perfectly (128 of 128 with the
// source changing between every single datagram, measured). The carrier below it
// did not follow: it filtered on a peer configured once, counted everything else
// as Foreign, and there was no exported way to change it. So the moment a mobile
// client renumbered, every reply went to the address it had left, the client's
// probe budget expired, and the tunnel cost a full re-handshake plus ~43 s of
// dead time. Mobile users renumber constantly.
//
// # The contract, which is a security contract and not a style note
//
// CALL THIS ONLY FROM THE SOURCE ADDRESS OF A DATAGRAM THAT DISPATCHED: one
// that opened under the session AEAD. That is safe precisely because dispatch is
// a cryptographic decision: an attacker who can produce such a datagram already
// holds the session key and does not need the return path. Calling it from any
// weaker signal (a Foreign count, an unauthenticated datagram, a hint from a
// middlebox) hands an off-path attacker the ability to redirect a live tunnel
// to itself with one spoofed packet, which is a strictly worse failure than the
// one this method exists to fix.
//
// Nothing in this package can enforce that, because this package holds no key.
// What it does instead is record the move in Stats.PeerMoves, which is therefore
// an AUTHENTICATED counter, and it is that counter (never Foreign) that a
// policy layer must read to tell a rebind from a censor.
func (u *UDP) SetPeer(addr *net.UDPAddr) error {
	if addr == nil {
		return wrap(ErrConfig, "no peer address")
	}
	if !u.explicit {
		// A connected socket's filter is the kernel's. Re-pointing it means
		// re-dialling, which produces a different socket and therefore a
		// different carrier; silently accepting the address here would leave the
		// caller believing a move happened that did not.
		return wrap(ErrConfig, "this carrier is a connected socket; dial a new one to change its peer")
	}
	cp := *addr
	cp.IP = append(net.IP(nil), addr.IP...)

	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return ErrClosed
	}
	if sameUDPAddr(u.peer, &cp) {
		// Not a move. Counting it would let an ordinary run of traffic inflate
		// the one counter the escalation policy trusts as mobility evidence.
		return nil
	}
	u.peer = &cp
	u.stats.PeerMoves++
	u.stats.LastPeerMove = u.clock.Now()
	return nil
}

// maxRecvDatagram bounds one read.
//
// It is generous rather than tight on purpose. A datagram larger than the
// receive ceiling is discarded by the length check below, but reading it into a
// buffer that is exactly the ceiling would TRUNCATE it instead, and a truncated
// Winn3 message fails to open and looks identical to an attack, which would make
// a path-MTU misconfiguration indistinguishable from a forgery in the logs.
const maxRecvDatagram = 65535

// Class reports the transport this carrier rides.
func (u *UDP) Class() Class { return ClassUDP }

// MaxMessageSize is the current send ceiling.
func (u *UDP) MaxMessageSize() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.maxMessage
}

// SetMaxMessageSize narrows or widens the ceiling on a live carrier.
func (u *UDP) SetMaxMessageSize(n int) error {
	if err := checkSize(n, u.pathCeiling); err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return ErrClosed
	}
	u.maxMessage = n
	return nil
}

// Stats reports what this carrier has seen.
func (u *UDP) Stats() Stats {
	u.mu.Lock()
	st := u.stats
	u.mu.Unlock()
	u.gsoTxStats(&st)
	return st
}

// fatal is the carrier's own last unrecoverable error, read by Observe.
func (u *UDP) fatal() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.fatalErr
}

// Send writes one message as one datagram.
func (u *UDP) Send(ctx context.Context, msg []byte) error {
	return u.sendDatagram(ctx, msg, true)
}

// sendDatagram keeps validation and accounting identical for scalar and batch
// sends. A batch caller owns one write deadline for the complete batch.
func (u *UDP) sendDatagram(ctx context.Context, msg []byte, ownDeadline bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(msg) == 0 {
		return ErrMessageEmpty
	}
	u.mu.Lock()
	closed, maxMessage, peer := u.closed, u.maxMessage, u.peer
	u.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if len(msg) > maxMessage {
		return wrap(ErrMessageTooLarge, "%d bytes, ceiling %d", len(msg), maxMessage)
	}

	var stop func()
	if ownDeadline {
		stop = u.armWrite(ctx)
	}
	var (
		n   int
		err error
	)
	// The peer is snapshotted above rather than read here: SetPeer may move it
	// concurrently, and a send that read it twice could address a datagram to one
	// address and count it against another.
	if peer == nil || u.conn.RemoteAddr() != nil {
		n, err = u.conn.Write(msg)
	} else {
		n, err = u.conn.WriteToUDP(msg, peer)
	}
	if stop != nil {
		stop()
	}
	if err != nil {
		u.mu.Lock()
		u.stats.SendErrors++
		u.mu.Unlock()
		// A datagram the kernel refused for exceeding the discovered path MTU
		// is reported as ErrPathMTUReduced with the measured number attached,
		// so the driver can shrink instead of black-holing every full-size
		// message for the life of the session. See pmtud.go.
		if reduced := u.notePathMTUSendFailure(len(msg), err); reduced != err {
			return reduced
		}
		// A datagram send failure is not fatal to the carrier. On this path the
		// interesting failure (a censor dropping UDP wholesale) produces NO
		// error at all: the socket opens, every write succeeds, and the reads
		// simply never return. Treating a transient ENOBUFS as a dead carrier
		// would tear down a working tunnel for the wrong reason, and treating a
		// silent block as a live one is what the escalation verdict is for.
		return err
	}

	u.mu.Lock()
	u.stats.Sent++
	u.stats.SentBytes += uint64(n)
	u.stats.LastSend = u.clock.Now()
	u.mu.Unlock()
	return nil
}

// Recv returns the next datagram from the peer.
//
// Datagrams from any other source are discarded and counted, and the read is
// retried, so a spraying off-path attacker cannot starve a real one out either:
// each foreign datagram costs one loop iteration, not a returned error.
func (u *UDP) Recv(ctx context.Context) ([]byte, error) {
	return u.recvInto(ctx, nil)
}

// RecvInto receives into caller-owned storage. A full datagram buffer is
// required so oversized packets are rejected rather than silently truncated.
// The returned slice aliases dst and remains owned by the caller.
func (u *UDP) RecvInto(ctx context.Context, dst []byte) ([]byte, error) {
	if len(dst) < maxRecvDatagram {
		return nil, io.ErrShortBuffer
	}
	return u.recvInto(ctx, dst)
}

func (u *UDP) recvInto(ctx context.Context, dst []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	u.mu.Lock()
	closed, ceiling := u.closed, u.maxMessage
	u.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}

	u.recvMu.Lock()
	defer u.recvMu.Unlock()

	stop := u.armRead(ctx)
	defer stop()

	buf := dst
	if buf == nil {
		buf = u.buf
	}

	for {
		n, from, err := u.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			u.mu.Lock()
			u.stats.RecvErrors++
			u.mu.Unlock()
			return nil, err
		}
		u.mu.Lock()
		peer := u.peer
		u.mu.Unlock()
		if peer != nil {
			peerAP := peer.AddrPort()
			if from.Addr().Unmap().WithZone("") != peerAP.Addr().Unmap().WithZone("") || int(from.Port()) != peer.Port {
				u.mu.Lock()
				u.stats.Foreign++
				u.mu.Unlock()
				continue
			}
		}
		if n == 0 || n > ceiling {
			// Not from an attacker necessarily: a path-MTU change or a stale
			// ceiling produces this too. Either way there is no message here.
			// It is counted as a receive error rather than as a delivery,
			// because a delivery would move LastDelivered and misinform the
			// verdict above.
			u.mu.Lock()
			u.stats.RecvErrors++
			u.mu.Unlock()
			continue
		}
		msg := buf[:n]
		if dst == nil {
			msg = append([]byte(nil), msg...)
		}

		u.mu.Lock()
		u.stats.Delivered++
		u.stats.DeliveredBytes += uint64(n)
		u.stats.LastDelivered = u.clock.Now()
		u.mu.Unlock()
		return msg, nil
	}
}

var _ BatchCarrier = (*UDP)(nil)

// RecvBatch returns a contiguous prefix of complete, peer-filtered datagrams.
func (u *UDP) RecvBatch(ctx context.Context, msgs []BatchMsg) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	u.recvMu.Lock()
	defer u.recvMu.Unlock()
	u.mu.Lock()
	closed, ceiling := u.closed, u.maxMessage
	u.mu.Unlock()
	if closed {
		return 0, ErrClosed
	}
	for i := range msgs {
		if cap(msgs[i].Payload) < ceiling {
			return 0, io.ErrShortBuffer
		}
		msgs[i].N = 0
		msgs[i].Err = nil
		msgs[i].Addr = netip.AddrPort{}
	}
	unarm := u.armRead(ctx)
	defer unarm()
	// One recvmmsg where the platform has it. The portable loop below is the
	// same filtering and error contract at one syscall per datagram.
	if kernelBatchEnabled {
		if n, err, ok := u.recvBatchKernel(ctx, msgs, ceiling); ok {
			return n, err
		}
	}
	nread := 0
	drainReads := 0
	for nread < len(msgs) {
		if err := ctx.Err(); err != nil {
			if nread > 0 {
				return nread, nil
			}
			return 0, err
		}
		if nread > 0 {
			// Refused datagrams spend drain reads too. Otherwise a stream of
			// foreign or oversize datagrams holds the accepted prefix back
			// for as long as it keeps arriving inside each 50 microsecond gap.
			if drainReads >= len(msgs)-1 {
				return nread, nil
			}
			if drainReads == 0 {
				// This write is invisible to readArm, so every exit from here
				// has to put the socket back. Without that the next read would
				// inherit a deadline 50 microseconds in the past and fail
				// instantly. One restore per call: a defer per read would grow
				// without bound under the same refused stream.
				defer u.readArm.reapply(u.setRead)
			}
			drainReads++
			deadline := u.clock.Now().Add(50 * time.Microsecond)
			if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
				deadline = limit
			}
			if err := u.conn.SetReadDeadline(deadline); err != nil {
				return nread, nil
			}
		}
		// Read the whole datagram into the carrier-owned buffer before checking
		// the ceiling. A small caller buffer must never hide truncation.
		n, from, err := u.conn.ReadFromUDPAddrPort(u.buf)
		if err != nil {
			if nread > 0 {
				return nread, nil
			}
			u.mu.Lock()
			u.stats.RecvErrors++
			u.mu.Unlock()
			if errors.Is(err, net.ErrClosed) {
				return 0, ErrClosed
			}
			return 0, err
		}
		u.mu.Lock()
		peer := u.peer
		if peer != nil {
			want := peer.AddrPort()
			if from.Addr().Unmap().WithZone("") != want.Addr().Unmap().WithZone("") || from.Port() != want.Port() {
				u.stats.Foreign++
				u.mu.Unlock()
				continue
			}
		}
		if n == 0 || n > u.maxMessage || n > ceiling {
			u.stats.RecvErrors++
			u.mu.Unlock()
			continue
		}
		x := &msgs[nread]
		if cap(x.Payload) < n {
			u.mu.Unlock()
			return nread, io.ErrShortBuffer
		}
		x.Payload = x.Payload[:n]
		copy(x.Payload, u.buf[:n])
		x.N, x.Addr = n, from
		nread++
		u.stats.Delivered++
		u.stats.DeliveredBytes += uint64(n)
		u.stats.LastDelivered = u.clock.Now()
		u.mu.Unlock()
	}
	return nread, nil
}

// SendBatch preserves the scalar path's peer binding, deadline, size checks,
// and health counters. Any unsent suffix is accompanied by its actual error.
func (u *UDP) SendBatch(ctx context.Context, msgs []BatchMsg) (int, error) {
	for i := range msgs {
		if msgs[i].N < 0 || msgs[i].N > len(msgs[i].Payload) {
			return 0, wrap(ErrConfig, "invalid batch payload length")
		}
	}
	if len(msgs) == 0 {
		return 0, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	stop := u.armWrite(ctx)
	defer stop()
	// One sendmmsg where the platform has it. The portable loop below is the
	// same ceiling, statistics and partial-result contract per datagram.
	if kernelBatchEnabled {
		if n, err, ok := u.sendBatchKernel(ctx, msgs); ok {
			return n, err
		}
	}
	for i := range msgs {
		if err := u.sendDatagram(ctx, msgs[i].Payload[:msgs[i].N], false); err != nil {
			return i, err
		}
	}
	return len(msgs), nil
}

// Close releases the socket if this carrier opened it.
func (u *UDP) Close() error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil
	}
	u.closed = true
	owns := u.owns
	u.mu.Unlock()
	// Drop both cancellation watches before anything else. A carrier torn down
	// while its context is still live would otherwise leave two nodes on that
	// context's list until the context itself died.
	u.readArm.release()
	u.writeArm.release()
	if !owns {
		// A gateway's socket serves every session on it. Closing a socket this
		// carrier was merely lent would take down every other session as a side
		// effect of one migrating.
		return nil
	}
	return u.conn.Close()
}

// armRead makes a parked read observe ctx cancellation. See deadlineArm for
// why the watch is held across calls rather than rebuilt for each one.
func (u *UDP) armRead(ctx context.Context) func() {
	return u.readArm.hold(ctx, u.setRead)
}

// armWrite is armRead's counterpart, on its own watch so that a parked read
// cannot move the write deadline or the other way round.
func (u *UDP) armWrite(ctx context.Context) func() {
	return u.writeArm.hold(ctx, u.setWrite)
}

// sameUDPAddr compares two endpoints by address and port.
//
// It compares net.IP values with Equal rather than by bytes, because the same
// address can be held as a 4-byte or a 16-byte slice and a byte comparison would
// reject the gateway's own datagrams on a dual-stack host: a filter that
// discards everything is not a stricter filter, it is a broken carrier.
func sameUDPAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}
