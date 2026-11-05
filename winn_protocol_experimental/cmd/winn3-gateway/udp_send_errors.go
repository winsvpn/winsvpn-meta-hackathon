package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"winsvpn.local/winnprotocol/internal/observability"
	"winsvpn.local/winnprotocol/winn3/carrier"
)

// enableUDPSendErrorReporting turns on IP_RECVERR for the shared socket so an
// egress-qdisc refusal (fq flow_limit) reaches the refusing session's write
// loop as ENOBUFS instead of vanishing into Udp: SndbufErrors. See
// winn3/carrier/udp_senderr.go for what it enables and what stays invisible.
//
// It returns the per-family option coverage the kernel actually granted, so
// status can report it truthfully. It is not fatal when unavailable: the
// gateway then runs exactly as before and says so.
func enableUDPSendErrorReporting(conn *net.UDPConn) carrier.SendErrorOptions {
	opts, err := carrier.EnableSendErrorReporting(conn)
	if err == nil {
		fmt.Fprintf(os.Stderr, "winn3-gateway: UDP send-error reporting on (IP_RECVERR ipv4=%v ipv6=%v)\n", opts.IPv4, opts.IPv6)
		return opts
	}
	if !errors.Is(err, errors.ErrUnsupported) {
		fmt.Fprint(os.Stderr, observability.RedactAddresses(fmt.Sprintf(
			"winn3-gateway: UDP send-error reporting unavailable, transmit-queue drops stay invisible to sessions: %v\n", err)))
	}
	return carrier.SendErrorOptions{}
}

// udpSendErrorStatus is the shared socket's send-error evidence. Aggregate
// counters only: no peer address, because an error-queue record names one and
// ICMP is forgeable. Each field's exact event and unit is documented on the
// carrier's SocketErrorStats; the JSON names mirror them.
type udpSendErrorStatus struct {
	// OptionIPv4 / OptionIPv6 report which IP_RECVERR / IPV6_RECVERR options the
	// kernel accepted. On a dual-stack socket the IPv4 option is best effort, so
	// these are reported separately and apart from drain availability below.
	OptionIPv4 bool `json:"option_ipv4"`
	OptionIPv6 bool `json:"option_ipv6"`
	// DrainAvailable is whether an error-queue drain exists for this socket
	// (Linux). It is independent of the options: the block is only published at
	// all when a drain exists.
	DrainAvailable bool `json:"drain_available"`
	// Degraded is set while the receive pump has been retrying read faults past
	// its threshold. It never by itself tears the socket down.
	Degraded bool `json:"degraded"`

	// TransmitRefused: ENOBUFS results returned from the batch path. Not a count
	// of qdisc drops or lost datagrams.
	TransmitRefused uint64 `json:"transmit_refused"`
	// ScalarRefused: failed scalar attempts (v3 fallback and QUIC cover) with
	// ENOBUFS or a matching errno, including each terminal attempt; the cover
	// path excludes the EMSGSIZE it passes through to quic-go. transmit_refused
	// covers only the batch path; scalar coverage lives here.
	ScalarRefused uint64 `json:"scalar_refused"`
	// ScalarDropped: cover datagrams dropped after their bounded retry to keep
	// the QUIC connection alive.
	ScalarDropped uint64 `json:"scalar_dropped"`
	// MatchingErrorRetries: retries undertaken after a matching errno, on every
	// path: batch send, the batch receive helper, both receive pumps (each read
	// the pump undertakes after recovering from a matching-errno fault), and
	// both scalar send paths. Retry attempts, not confirmed cross-peer errors;
	// ENOBUFS retries are not included.
	MatchingErrorRetries uint64 `json:"matching_error_retries"`
	// Error-queue drain accounting.
	ErrorQueueDrained uint64 `json:"error_queue_drained"`
	ErrorQueueICMP    uint64 `json:"error_queue_icmp"`
	ErrorQueueLocal   uint64 `json:"error_queue_local"`
	// DrainSkipped: requests that found another drainer; each is serviced by
	// that owner (DrainPendingServiced counts the extra rounds it ran).
	DrainSkipped         uint64 `json:"drain_skipped"`
	DrainPendingServiced uint64 `json:"drain_pending_serviced"`
	DrainLimitHit        uint64 `json:"drain_limit_hit"`
	DrainContinuations   uint64 `json:"drain_continuations"`
	DrainFailures        uint64 `json:"drain_failures"`
	// DemuxReadFaults: receive-pump errors retried rather than treated as the
	// socket's death.
	DemuxReadFaults uint64 `json:"demux_read_faults"`
}

type udpSendErrorSource interface {
	udpSendErrorQueue() *carrier.SocketErrorQueue
	udpDemuxReadFaults() uint64
	udpDemuxDegraded() bool
}

// buildUDPSendErrorStatus returns the send-error block, or nil when the socket
// has no error-queue drain. On an unsupported platform the queue is nil, so the
// block is omitted entirely (omitempty on a nil pointer), which is the truthful
// answer there rather than a block of zeros claiming a feature that is absent.
func buildUDPSendErrorStatus(conn udpConn, opts carrier.SendErrorOptions) *udpSendErrorStatus {
	src, ok := conn.(udpSendErrorSource)
	if !ok {
		return nil
	}
	q := src.udpSendErrorQueue()
	if q == nil {
		return nil
	}
	st := q.Stats()
	return &udpSendErrorStatus{
		OptionIPv4:           opts.IPv4,
		OptionIPv6:           opts.IPv6,
		DrainAvailable:       true,
		Degraded:             src.udpDemuxDegraded(),
		TransmitRefused:      st.TransmitRefused,
		ScalarRefused:        st.ScalarRefused,
		ScalarDropped:        st.ScalarDropped,
		MatchingErrorRetries: st.MatchingErrorRetries,
		ErrorQueueDrained:    st.Drained,
		ErrorQueueICMP:       st.DrainedICMP,
		ErrorQueueLocal:      st.DrainedLocal,
		DrainSkipped:         st.DrainSkipped,
		DrainPendingServiced: st.DrainPendingServiced,
		DrainLimitHit:        st.DrainLimitHit,
		DrainContinuations:   st.DrainContinuations,
		DrainFailures:        st.DrainFailures,
		DemuxReadFaults:      src.udpDemuxReadFaults(),
	}
}

// Receive-pump fault handling.
//
// With IP_RECVERR a read can fail for reasons that are not the socket's death:
// a pending ICMP error beyond what ReadBatchFrom absorbs, and Go's poller,
// which after an epoll event carrying ONLY EPOLLERR fails every read with "not
// pollable" until the next event (runtime.netpollcheckerr). MEASURED, Linux 6.8
// netns, go1.27: a send-buffer-full socket that received a port-unreachable
// returned "not pollable" 223 times over 267 ms at a 1 ms backoff, then cleared
// by itself when the send buffer drained.
//
// Such recoverable errors must NEVER by themselves declare the shared socket
// dead: doing so would stop every session over one peer's ICMP. Only an actual
// close (net.ErrClosed) or an independently established descriptor-level failure
// (carrier.IsPermanentSocketError) tears the pump down. A recoverable episode
// that runs past demuxDegradedThreshold sets a degraded status flag and keeps
// retrying with a bounded, growing backoff, which caps CPU.
const (
	demuxDegradedThreshold   = 5 * time.Second
	demuxReadFaultBackoffMin = time.Millisecond
	demuxReadFaultBackoffMax = 64 * time.Millisecond
)

// demuxReadFaults is one pump's current episode of consecutive recoverable read
// errors.
type demuxReadFaults struct {
	since   time.Time
	backoff time.Duration
}

// recoverRead handles a pump read error. It returns true when the caller should
// read again (a recoverable error, after a bounded backoff and an error-queue
// drain), and false when the error is closure or a descriptor-level failure
// that must shut the pump down, or when the split is already stopping.
func (s *splitUDP) recoverRead(f *demuxReadFaults, err error) bool {
	if errors.Is(err, net.ErrClosed) || carrier.IsPermanentSocketError(err) {
		return false
	}
	select {
	case <-s.done:
		return false
	default:
	}
	now := time.Now()
	if f.since.IsZero() {
		f.since, f.backoff = now, demuxReadFaultBackoffMin
		fmt.Fprint(os.Stderr, observability.RedactAddresses(fmt.Sprintf(
			"winn3-gateway: UDP demux read fault, recoverable, retrying with backoff: %v\n", err)))
	} else if now.Sub(f.since) >= demuxDegradedThreshold {
		s.degraded.Store(true)
	}
	s.readFaults.Add(1)
	s.errq.Drain()
	t := time.NewTimer(f.backoff)
	defer t.Stop()
	select {
	case <-s.done:
		return false
	case <-t.C:
	}
	if f.backoff < demuxReadFaultBackoffMax {
		f.backoff *= 2
		if f.backoff > demuxReadFaultBackoffMax {
			f.backoff = demuxReadFaultBackoffMax
		}
	}
	// The pump reads again now. A retry after a matching errno counts in
	// MatchingErrorRetries, on both pumps and including the batch pump's retry
	// after ReadBatchFrom spent its own internal budget. readFaults above
	// counts every fault; closure, cancellation (the returns above) and
	// non-matching faults such as "not pollable" add no matching retry.
	s.errq.NoteMatchingRetry(err)
	return true
}

// clearReadFaults ends a fault episode after a good read.
func (s *splitUDP) clearReadFaults(f *demuxReadFaults) {
	*f = demuxReadFaults{}
	s.degraded.Store(false)
}

func (d *demuxSide) udpSendErrorQueue() *carrier.SocketErrorQueue { return d.split.errq }
func (d *demuxSide) udpDemuxReadFaults() uint64                   { return d.split.readFaults.Load() }
func (d *demuxSide) udpDemuxDegraded() bool                       { return d.split.degraded.Load() }
