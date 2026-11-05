//go:build linux || android

package carrier

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// SendErrorOptions records which per-family error-reporting options the kernel
// actually accepted on a socket. The two are reported separately because on a
// dual-stack socket the IPv4 option is best effort: udpv6_sendmsg hands a
// v4-mapped destination to udp_sendmsg, whose ENOBUFS check reads the IPv4
// option, but a v6-only socket never takes that path.
type SendErrorOptions struct {
	IPv4 bool
	IPv6 bool
}

// Any reports whether any option was set, i.e. whether the socket reports send
// errors at all.
func (o SendErrorOptions) Any() bool { return o.IPv4 || o.IPv6 }

// EnableSendErrorReporting sets IP_RECVERR, and IPV6_RECVERR as well on an
// AF_INET6 socket, so the kernel reports a transmit-queue refusal for the
// datagram it refuses instead of counting it and claiming success. It returns
// exactly which options the kernel accepted, so a caller can publish truthful
// coverage rather than assume both are on.
//
// A caller that enables this must read through a path that tolerates the
// asynchronous errors it also enables (the demux pump's recoverable-error
// handling) and must drain the error queue after any absorbed error.
func EnableSendErrorReporting(conn *net.UDPConn) (SendErrorOptions, error) {
	if conn == nil {
		return SendErrorOptions{}, wrap(ErrConfig, "send-error reporting: no socket")
	}
	if udpSocketIsIPv6(conn) {
		var opts SendErrorOptions
		if err := udpSetsockoptInt(conn, unix.SOL_IPV6, unix.IPV6_RECVERR, 1); err != nil {
			return opts, err
		}
		opts.IPv6 = true
		// Best effort: a dual-stack socket sends v4-mapped destinations
		// through udp_sendmsg, which reads the IPv4 option. A v6-only socket
		// never does, so a failure here is not fatal and is reported as
		// coverage, not as success.
		if err := udpSetsockoptInt(conn, unix.SOL_IP, unix.IP_RECVERR, 1); err == nil {
			opts.IPv4 = true
		}
		return opts, nil
	}
	if err := udpSetsockoptInt(conn, unix.SOL_IP, unix.IP_RECVERR, 1); err != nil {
		return SendErrorOptions{}, err
	}
	return SendErrorOptions{IPv4: true}, nil
}

// isAsyncSocketErrno reports whether a pending sk_err set from an ICMP or
// ICMPv6 error can carry errno. Those values come from icmp_err_convert
// (net/ipv4/icmp.c), udp_err's TIME_EXCEEDED, PARAMETERPROB and FRAG_NEEDED
// cases (net/ipv4/udp.c), and icmpv6_err_convert (net/ipv6/icmp.c).
//
// Membership here is necessary but NOT sufficient to prove a failure was
// asynchronous: sock_alloc_send_pskb reports a consumed sk_err with these same
// errnos, and a synchronous send can fail with the same errno. So it gates a
// bounded retry of the same datagram, never an attribution.
func isAsyncSocketErrno(e syscall.Errno) bool {
	switch e {
	case unix.ECONNREFUSED, unix.EHOSTDOWN, unix.EHOSTUNREACH, unix.ENETUNREACH,
		unix.ENONET, unix.ENOPROTOOPT, unix.EOPNOTSUPP, unix.EPROTO,
		unix.EMSGSIZE, unix.EACCES:
		return true
	}
	return false
}

// IsAsyncSocketError reports whether err is an errno that a pending socket
// error from an earlier datagram's ICMP result can produce.
func IsAsyncSocketError(err error) bool {
	var e syscall.Errno
	return errors.As(err, &e) && isAsyncSocketErrno(e)
}

// isPermanentSocketErrno reports whether errno means the descriptor itself is
// unusable, as opposed to a transient or peer condition. These, and only these
// plus an explicit close, let the pump conclude the socket is dead.
func isPermanentSocketErrno(e syscall.Errno) bool {
	switch e {
	case unix.EBADF, unix.ENOTSOCK, unix.EPIPE:
		return true
	}
	return false
}

// IsPermanentSocketError reports whether err is a descriptor-level failure that
// justifies tearing the shared socket down.
func IsPermanentSocketError(err error) bool {
	var e syscall.Errno
	return errors.As(err, &e) && isPermanentSocketErrno(e)
}

// SocketErrorQueue drains one socket's MSG_ERRQUEUE and counts what the
// send-error path absorbed. Every method is safe on a nil receiver.
//
// The drain uses golang.org/x/sys/unix.Recvmsg, whose iovec and msghdr layout
// is generated per architecture, so this path is correct on 32-bit as well as
// 64-bit. That matters because NewSocketErrorQueue is used on the scalar
// fallback, where there is no 64-bit-only RawBatchConn to gate it.
//
// OWNERSHIP. At most one goroutine drains at a time. state moves between
// drainIdle, drainRunning and drainRunningPending by compare-and-swap only:
//
//   - A requester CASes idle->running and becomes the owner, or CASes
//     running->pending (or finds pending already set) and returns at once.
//   - The owner gives up ownership ONLY by CAS running->idle. If a requester
//     set pending at any point before that CAS, including after the owner's
//     last empty read, the CAS fails; the owner consumes the flag
//     (pending->running) and runs another round.
//
// So every skipped request is serviced by the owner in place at the time it
// was skipped: publishing the request and releasing ownership cannot pass each
// other. An owner that reaches maxDrainRounds with work still possible keeps
// ownership and hands it to a scheduled continuation goroutine, which drains in
// further bounded attempts until it can release, or until the socket closes.
type SocketErrorQueue struct {
	raw syscall.RawConn

	state   atomic.Int32
	buf     []byte // owner-only
	oob     []byte // owner-only
	handler atomic.Pointer[func(QueuedSocketError)]

	// testBeforeRelease, when set by a test, runs in the owner after a round
	// read the queue empty and before the release CAS: exactly the window in
	// which a lost handoff would happen.
	testBeforeRelease func()
	// testBeforeContinue, when set by a test, runs in a scheduled continuation
	// after its delay and before it touches the descriptor, so a test can close
	// the socket while a continuation is pending.
	testBeforeContinue func()

	matchingRetries atomic.Uint64
	transmitRefused atomic.Uint64
	scalarRefused   atomic.Uint64
	scalarDropped   atomic.Uint64
	drained         atomic.Uint64
	drainedICMP     atomic.Uint64
	drainedLocal    atomic.Uint64
	drainSkipped    atomic.Uint64
	pendingServiced atomic.Uint64
	drainLimitHit   atomic.Uint64
	drainConts      atomic.Uint64
	drainFailures   atomic.Uint64
}

const (
	drainIdle int32 = iota
	drainRunning
	drainRunningPending
)

// continuationDelay spaces scheduled continuation attempts, bounding the CPU a
// backlog or a persistently failing recvmsg can take.
const continuationDelay = time.Millisecond

// NewSocketErrorQueue watches conn's error queue. Use RawBatchConn.ErrorQueue
// instead when the socket already has a RawBatchConn, so both share counters.
func NewSocketErrorQueue(conn *net.UDPConn) (*SocketErrorQueue, error) {
	if conn == nil {
		return nil, wrap(ErrConfig, "error queue: no socket")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	return newSocketErrorQueue(raw), nil
}

func newSocketErrorQueue(raw syscall.RawConn) *SocketErrorQueue {
	return &SocketErrorQueue{
		raw: raw,
		buf: make([]byte, 2048),
		oob: make([]byte, 512),
	}
}

// SetHandler installs fn to receive each drained record. fn runs on whichever
// goroutine owns the drain, so it must not block and must not call back into
// the queue. A record is ADVISORY: ICMP is unauthenticated.
func (q *SocketErrorQueue) SetHandler(fn func(QueuedSocketError)) {
	if q == nil {
		return
	}
	if fn == nil {
		q.handler.Store(nil)
		return
	}
	q.handler.Store(&fn)
}

// Stats returns the queue's counters.
func (q *SocketErrorQueue) Stats() SocketErrorStats {
	if q == nil {
		return SocketErrorStats{}
	}
	return SocketErrorStats{
		MatchingErrorRetries: q.matchingRetries.Load(),
		TransmitRefused:      q.transmitRefused.Load(),
		ScalarRefused:        q.scalarRefused.Load(),
		ScalarDropped:        q.scalarDropped.Load(),
		Drained:              q.drained.Load(),
		DrainedICMP:          q.drainedICMP.Load(),
		DrainedLocal:         q.drainedLocal.Load(),
		DrainSkipped:         q.drainSkipped.Load(),
		DrainPendingServiced: q.pendingServiced.Load(),
		DrainLimitHit:        q.drainLimitHit.Load(),
		DrainContinuations:   q.drainConts.Load(),
		DrainFailures:        q.drainFailures.Load(),
	}
}

// Draining reports whether a drain owner, synchronous or a scheduled
// continuation, currently holds the queue.
func (q *SocketErrorQueue) Draining() bool {
	return q != nil && q.state.Load() != drainIdle
}

// Drain requests a drain of the error queue and returns how many records this
// call read. It never waits for another drainer: if one is running, the request
// is handed to it and Drain returns zero. A RawConn.Control failure other than
// a closed socket counts as a drain failure; a closed socket has nothing left
// to drain.
func (q *SocketErrorQueue) Drain() int {
	if q == nil || q.raw == nil {
		return 0
	}
	n := 0
	if err := q.raw.Control(func(fd uintptr) { n = q.drainFD(fd) }); err != nil && !errors.Is(err, net.ErrClosed) {
		q.drainFailures.Add(1)
	}
	return n
}

// AbsorbAsync decides whether a scalar write that failed with err may re-offer
// the same bytes. It returns true, after draining the error queue, when err is
// one a pending socket error can carry and attempt is below AsyncErrorRetries,
// and counts that retry in MatchingErrorRetries.
func (q *SocketErrorQueue) AbsorbAsync(err error, attempt int) bool {
	if q == nil || attempt >= AsyncErrorRetries || !IsAsyncSocketError(err) {
		return false
	}
	q.matchingRetries.Add(1)
	q.Drain()
	return true
}

// NoteMatchingRetry counts a retry a caller outside this package undertakes
// after a receive failed with err, for example the gateway's receive pump
// reading again after recovering from a read fault. It counts only when err is
// a matching errno; a closure, a cancellation that prevents the retry, or a
// non-matching fault must not be reported here.
func (q *SocketErrorQueue) NoteMatchingRetry(err error) {
	if q != nil && IsAsyncSocketError(err) {
		q.matchingRetries.Add(1)
	}
}

// drainFD requests a drain from a caller already inside a RawConn callback.
func (q *SocketErrorQueue) drainFD(fd uintptr) int {
	if q == nil || !q.acquire() {
		return 0
	}
	n, more := q.drainOwned(fd)
	if more {
		q.scheduleContinuation()
	}
	return n
}

// acquire makes the caller the owner, or records its request with the current
// owner. It returns true only when the caller now owns the queue.
func (q *SocketErrorQueue) acquire() bool {
	for {
		switch q.state.Load() {
		case drainIdle:
			if q.state.CompareAndSwap(drainIdle, drainRunning) {
				return true
			}
		case drainRunning:
			if q.state.CompareAndSwap(drainRunning, drainRunningPending) {
				q.drainSkipped.Add(1)
				return false
			}
		default: // drainRunningPending: the owner will run again anyway.
			q.drainSkipped.Add(1)
			return false
		}
	}
}

// release gives up ownership, or, if a request arrived, consumes it and keeps
// ownership. It returns true when the caller no longer owns the queue.
func (q *SocketErrorQueue) release() bool {
	if q.state.CompareAndSwap(drainRunning, drainIdle) {
		return true
	}
	// Only requesters set pending and only the owner clears it.
	q.state.CompareAndSwap(drainRunningPending, drainRunning)
	q.pendingServiced.Add(1)
	return false
}

// drainOwned runs bounded rounds as the owner. It returns more=true, still
// owning the queue, when maxDrainRounds were used and work may remain (a round
// hit its cap, or a request arrived); the caller must schedule a continuation.
// It returns more=false after releasing ownership.
func (q *SocketErrorQueue) drainOwned(fd uintptr) (total int, more bool) {
	for round := 0; round < maxDrainRounds; round++ {
		n, reason := q.drainRound(fd)
		total += n
		switch reason {
		case drainHitLimit:
			q.drainLimitHit.Add(1)
			continue // more may be queued: keep ownership, read again
		case drainFailed:
			q.drainFailures.Add(1)
		}
		// The round read the queue empty, or failed. Release unless a request
		// arrived; a request makes release fail and this loop run again.
		if hook := q.testBeforeRelease; hook != nil {
			hook()
		}
		if q.release() {
			return total, false
		}
	}
	return total, true
}

// scheduleContinuation hands ownership, which the caller still holds, to a
// goroutine that keeps draining in bounded attempts spaced continuationDelay
// apart. It releases ownership when drainOwned does, or drops it when the
// socket can no longer be used, which is the socket-close case.
func (q *SocketErrorQueue) scheduleContinuation() {
	go func() {
		for {
			time.Sleep(continuationDelay)
			if hook := q.testBeforeContinue; hook != nil {
				hook()
			}
			q.drainConts.Add(1)
			more := false
			if err := q.raw.Control(func(fd uintptr) { _, more = q.drainOwned(fd) }); err != nil {
				if !errors.Is(err, net.ErrClosed) {
					q.drainFailures.Add(1)
				}
				q.state.Store(drainIdle)
				return
			}
			if !more {
				return
			}
		}
	}()
}

type drainReason int

const (
	drainEmpty drainReason = iota
	drainHitLimit
	drainFailed
)

// drainRound reads up to errQueueDrainLimit records with unix.Recvmsg, which is
// architecture-correct, and reports why it stopped. Only the owner calls it.
func (q *SocketErrorQueue) drainRound(fd uintptr) (int, drainReason) {
	n := 0
	for n < errQueueDrainLimit {
		size, oobn, _, from, err := unix.Recvmsg(int(fd), q.buf, q.oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				return n, drainEmpty
			}
			if err == unix.EINTR {
				continue
			}
			return n, drainFailed
		}
		n++
		rec := q.parse(size, oobn, from)
		q.drained.Add(1)
		switch rec.Origin {
		case unix.SO_EE_ORIGIN_ICMP, unix.SO_EE_ORIGIN_ICMP6:
			q.drainedICMP.Add(1)
		case unix.SO_EE_ORIGIN_LOCAL:
			q.drainedLocal.Add(1)
		}
		if h := q.handler.Load(); h != nil {
			(*h)(rec)
		}
	}
	return n, drainHitLimit
}

// parse decodes one record: the original destination from the returned
// Sockaddr and the sock_extended_err from the IP_RECVERR / IPV6_RECVERR control
// message (ip_recv_error, ipv6_recv_error).
func (q *SocketErrorQueue) parse(_ int, oobn int, from unix.Sockaddr) QueuedSocketError {
	var rec QueuedSocketError
	switch sa := from.(type) {
	case *unix.SockaddrInet4:
		rec.Dest = netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(sa.Port))
	case *unix.SockaddrInet6:
		rec.Dest = netip.AddrPortFrom(netip.AddrFrom16(sa.Addr).Unmap(), uint16(sa.Port))
	}
	if oobn > len(q.oob) {
		oobn = len(q.oob)
	}
	msgs, err := unix.ParseSocketControlMessage(q.oob[:oobn])
	if err != nil {
		return rec
	}
	const eeLen = 16 // struct sock_extended_err
	for _, m := range msgs {
		v4 := m.Header.Level == unix.SOL_IP && m.Header.Type == unix.IP_RECVERR
		v6 := m.Header.Level == unix.SOL_IPV6 && m.Header.Type == unix.IPV6_RECVERR
		if (!v4 && !v6) || len(m.Data) < eeLen {
			continue
		}
		rec.Errno = binary.NativeEndian.Uint32(m.Data[0:4])
		rec.Origin, rec.Type, rec.Code = m.Data[4], m.Data[5], m.Data[6]
		rec.Info = binary.NativeEndian.Uint32(m.Data[8:12])
		if off := sockaddrToAddrPort(m.Data[eeLen:]); off.IsValid() {
			rec.Offender = off.Addr()
		}
	}
	return rec
}

func sockaddrToAddrPort(b []byte) netip.AddrPort {
	if len(b) < 16 {
		return netip.AddrPort{}
	}
	port := binary.BigEndian.Uint16(b[2:4])
	switch binary.NativeEndian.Uint16(b[0:2]) {
	case unix.AF_INET:
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[4:8])), port)
	case unix.AF_INET6:
		if len(b) < 28 {
			return netip.AddrPort{}
		}
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[8:24])).Unmap(), port)
	}
	return netip.AddrPort{}
}

// coverScalarRetries and coverScalarBackoff bound the per-datagram wait on the
// QUIC cover path before the datagram is dropped: up to coverScalarRetries+1 = 7
// failed attempts, 6 backoffs of 2 ms, so about 12 ms worst case.
const (
	coverScalarRetries = 6
	coverScalarBackoff = 2 * time.Millisecond
)

// SCALAR ACCOUNTING CONTRACT (both helpers below).
//
//   - ScalarRefused +1 for EVERY attempt the helper handles that failed with
//     ENOBUFS or a matching errno (isAsyncSocketErrno), including the terminal
//     failed attempt.
//   - MatchingErrorRetries +1 for every retry actually undertaken after a
//     matching errno. An ENOBUFS retry is not a matching-error retry.
//   - EMSGSIZE: the cover path EXCLUDES it. It passes straight through to
//     quic-go uncounted and unretried, because quic-go uses it for its own path
//     MTU discovery. The v3 path INCLUDES it: there it is a matching errno and
//     is retried and counted like the others.
//   - Descriptor failures, closure and other errnos pass through uncounted.

// SendCoverScalar runs one QUIC cover-path datagram write. quic-go v0.60.0's
// sendQueue destroys the connection on any write error other than EMSGSIZE, so
// a transient local refusal (ENOBUFS from an fq flow_limit drop) or a consumed
// ICMP error about another peer must NOT reach quic-go. Such errors are retried
// briefly, draining the error queue after a matching errno, and after
// coverScalarRetries+1 failed attempts the datagram is DROPPED with a success
// return (payloadLen, nil); quic-go's own loss recovery resends real data.
func (q *SocketErrorQueue) SendCoverScalar(payloadLen int, write func() (int, error)) (int, error) {
	for attempt := 0; ; attempt++ {
		n, err := write()
		if err == nil ||
			errors.Is(err, unix.EMSGSIZE) ||
			IsPermanentSocketError(err) ||
			errors.Is(err, net.ErrClosed) {
			return n, err
		}
		matching := IsAsyncSocketError(err)
		if !matching && !errors.Is(err, unix.ENOBUFS) {
			// An unexpected errno: pass it through rather than mask it.
			return n, err
		}
		q.noteScalarRefused()
		if matching {
			q.Drain()
		}
		if attempt >= coverScalarRetries {
			q.noteScalarDropped()
			return payloadLen, nil
		}
		if matching && q != nil {
			q.matchingRetries.Add(1)
		}
		time.Sleep(coverScalarBackoff)
	}
}

// SendScalarRetain runs one v3 scalar write. An ENOBUFS is returned at once so
// driver.Loop retains the sealed bytes; a matching errno is retried up to
// AsyncErrorRetries times, draining the queue, and then returned. It NEVER
// returns success for bytes the kernel did not accept: every failure path
// returns a non-nil error.
func (q *SocketErrorQueue) SendScalarRetain(write func() (int, error)) (int, error) {
	for attempt := 0; ; attempt++ {
		n, err := write()
		if err == nil {
			return n, nil
		}
		matching := IsAsyncSocketError(err)
		if matching || errors.Is(err, unix.ENOBUFS) {
			q.noteScalarRefused()
		}
		if !q.AbsorbAsync(err, attempt) {
			return n, err
		}
	}
}

func (q *SocketErrorQueue) noteScalarRefused() {
	if q != nil {
		q.scalarRefused.Add(1)
	}
}

func (q *SocketErrorQueue) noteScalarDropped() {
	if q != nil {
		q.scalarDropped.Add(1)
	}
}
