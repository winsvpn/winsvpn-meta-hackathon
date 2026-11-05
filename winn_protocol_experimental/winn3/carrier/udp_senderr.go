package carrier

import "net/netip"

// Send-error visibility on a shared, unconnected UDP socket.
//
// WHY THIS EXISTS. Without IP_RECVERR, Linux udp_send_skb turns the -ENOBUFS
// that ip_send_skb returns for a qdisc drop into success and only counts it in
// Udp: SndbufErrors (net/ipv4/udp.c). An fq flow_limit drop on the egress qdisc
// is then invisible to the sender, so sealed ciphertext is lost with no refusal
// for the write loop to retain. MEASURED in netns on Linux 6.8, fq flow_limit
// 8: 200 sendto calls all returned success, 177 datagrams never arrived, and
// the qdisc counted flows_plimit 177. With IP_RECVERR the same 177 returned
// ENOBUFS, and every datagram that returned success arrived.
//
// WHAT IT COSTS. IP_RECVERR also turns every ICMP error about ANY peer of the
// socket into a pending socket error (sk_err) plus an error-queue record
// (udp_err in net/ipv4/udp.c). The next send or receive on the socket, for
// whatever peer, consumes sk_err and fails with it. On a gateway that serves
// every session from one socket that is a false refusal charged to an innocent
// session, and a fatal read for the receive pump. Error-queue records are
// charged to the receive buffer (sock_queue_err_skb in net/core/skbuff.c) and
// dequeuing one re-arms sk_err from the next (sock_dequeue_err_skb), so the
// queue must be drained to empty. The carrier therefore:
//
//   - reports a synchronous ENOBUFS for the datagram it names, and nothing else;
//   - retries the SAME datagram a bounded number of times when the errno is one
//     a pending socket error can carry (isAsyncSocketErrno). The only fact this
//     rests on is that sock_alloc_send_pskb checks sock_error(sk) BEFORE it
//     allocates the outgoing skb, so a send that failed at that check sent
//     nothing and re-offering it is safe. Recurrence does NOT prove the errno
//     came from that check: a synchronous EMSGSIZE has the same errno as a
//     consumed ICMP one. So on exhaustion the errno is NOT attributed: the
//     accepted prefix is kept, the remainder is handed back for the caller's
//     own bounded, cancellation-aware retry (driver.Loop retention), and a
//     persistent stall fails that loop generically, never as a peer verdict or
//     a path-MTU verdict;
//   - drains the error queue whenever it absorbs such an error, to empty, so a
//     re-armed sk_err does not resurface on an unrelated later operation.
//
// WHAT STAYS UNATTRIBUTABLE. An error-queue record names the ORIGINAL
// destination of the datagram the ICMP quoted, but ICMP is unauthenticated and
// can be forged by anyone who knows a client's address and port, so a record
// is advisory evidence about that address and never grounds for acting on a
// session. Drops after the qdisc verdict (driver or NIC), NET_XMIT_CN verdicts,
// and on Linux 6.19 and later any skb that __dev_xmit_skb places on a non-empty
// qdisc defer_list (it returns NET_XMIT_SUCCESS without learning the enqueue
// verdict) are still reported as success. IP_RECVERR narrows the invisible
// loss; it does not close it.

// QueuedSocketError is one record read from a socket's error queue.
type QueuedSocketError struct {
	// Dest is the destination of the datagram the error is about, as the
	// kernel recorded it. For a local error (Origin 1) the port is zero.
	Dest netip.AddrPort
	// Errno is the kernel's errno value for the record, such as ECONNREFUSED.
	Errno uint32
	// Origin is SO_EE_ORIGIN_*: 1 local, 2 ICMP, 3 ICMPv6.
	Origin uint8
	Type   uint8
	Code   uint8
	// Info is the ICMP info field; for EMSGSIZE it is the reported MTU.
	Info uint32
	// Offender is the ICMP sender, invalid when the kernel names none.
	Offender netip.Addr
}

// SocketErrorStats counts what the send-error path saw on one socket. Every
// field is an aggregate with no peer identity, because a shared-socket error
// names a datagram's destination and ICMP is forgeable. The doc on each field
// states the exact event it counts and its unit; none of these is a count of
// qdisc drops or of unique datagrams lost.
type SocketErrorStats struct {
	// MatchingErrorRetries counts retries actually undertaken, re-offering the
	// SAME datagram, after a send or receive failed with an errno a pending
	// socket error can carry (isAsyncSocketErrno). Unit: retry attempts, not
	// confirmed asynchronous errors: a synchronous EMSGSIZE that recurs on the
	// batch or v3 scalar path is retried too. An ENOBUFS retry on the cover path
	// is NOT counted here.
	MatchingErrorRetries uint64
	// TransmitRefused counts ENOBUFS results RETURNED to a caller from the
	// batch path RawBatchConn.WriteBatchTo. Unit: returned ENOBUFS results, not
	// qdisc drops (one sendmmsg reports at most one refusal though the qdisc
	// may have dropped more) and not lost datagrams. Scalar writes are counted
	// in ScalarRefused instead.
	TransmitRefused uint64
	// ScalarRefused counts every scalar-path attempt (v3 fallback via
	// SendScalarRetain, QUIC cover via SendCoverScalar) that failed with ENOBUFS
	// or a matching errno and that the helper handled, including the terminal
	// failed attempt. The cover path excludes EMSGSIZE, which it passes
	// straight through to quic-go; the v3 path includes it. Unit: failed
	// attempts.
	ScalarRefused uint64
	// ScalarDropped counts cover-path datagrams dropped after their bounded
	// retry was spent, to keep the QUIC connection alive (quic-go destroys a
	// connection on any non-EMSGSIZE write error). Unit: datagrams dropped.
	ScalarDropped uint64
	// Drained counts error-queue records read; ICMP and Local split it by
	// origin. Unit: records.
	Drained      uint64
	DrainedICMP  uint64
	DrainedLocal uint64
	// DrainSkipped counts drain requests that found another owner draining and
	// returned without draining. Unit: skipped requests. The ownership protocol
	// (SocketErrorQueue) guarantees each is serviced: its request is recorded
	// before the owner can release, so the owner runs at least one more round.
	DrainSkipped uint64
	// DrainPendingServiced counts extra rounds an owner ran because a request
	// arrived while it owned the queue (its release was refused). Unit: rounds.
	DrainPendingServiced uint64
	// DrainLimitHit counts drain rounds that read a full errQueueDrainLimit and
	// so may have left more. Unit: rounds that hit the cap.
	DrainLimitHit uint64
	// DrainContinuations counts scheduled continuation attempts: an owner that
	// used maxDrainRounds with work possibly left keeps ownership and a
	// goroutine continues in further bounded attempts. Unit: attempts.
	DrainContinuations uint64
	// DrainFailures counts drain rounds that ended on a recvmsg error other than
	// the empty-queue EAGAIN, and RawConn.Control errors other than a closed
	// socket. Unit: failures. An empty queue is the ordinary end, not a failure.
	DrainFailures uint64
}

// AsyncErrorRetries bounds how many times one send or receive re-offers the
// same datagram after a matching errno before giving up on that datagram. A
// synchronous error recurs on every attempt and is surfaced (send) or reported
// (receive) after this many cheap syscalls; an asynchronous one is consumed by
// the first.
const AsyncErrorRetries = 4

// errQueueDrainLimit bounds one drain round.
const errQueueDrainLimit = 256

// maxDrainRounds bounds the rounds one drain attempt runs, so a synchronous
// caller (which may be inside the transmit or receive callback) does at most
// maxDrainRounds*errQueueDrainLimit = 4096 reads. Work beyond that is not
// dropped: the owner keeps ownership and schedules a continuation that drains
// in further bounded attempts.
const maxDrainRounds = 16
