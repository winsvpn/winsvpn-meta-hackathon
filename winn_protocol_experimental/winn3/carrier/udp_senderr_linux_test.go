//go:build linux || android

package carrier

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIsAsyncSocketErrorClassifiesOnlyICMPResults(t *testing.T) {
	t.Parallel()
	for _, e := range []syscall.Errno{unix.ECONNREFUSED, unix.EHOSTUNREACH, unix.ENETUNREACH,
		unix.EHOSTDOWN, unix.ENONET, unix.ENOPROTOOPT, unix.EOPNOTSUPP, unix.EPROTO, unix.EMSGSIZE, unix.EACCES} {
		if !IsAsyncSocketError(e) || !IsAsyncSocketError(fmt.Errorf("wrapped: %w", e)) {
			t.Errorf("%v is an errno udp_err can store in sk_err", e)
		}
	}
	for _, e := range []error{unix.ENOBUFS, unix.EAGAIN, unix.EBADF, net.ErrClosed, errors.New("x"), nil} {
		if IsAsyncSocketError(e) {
			t.Errorf("%v must not be classified as another datagram's error", e)
		}
	}
}

func TestIsPermanentSocketErrorNamesOnlyDescriptorFailures(t *testing.T) {
	t.Parallel()
	for _, e := range []syscall.Errno{unix.EBADF, unix.ENOTSOCK, unix.EPIPE} {
		if !IsPermanentSocketError(e) || !IsPermanentSocketError(fmt.Errorf("w: %w", e)) {
			t.Errorf("%v is a descriptor-level failure", e)
		}
	}
	for _, e := range []error{unix.ENOBUFS, unix.EAGAIN, unix.ECONNREFUSED, unix.EMSGSIZE, net.ErrClosed, nil} {
		if IsPermanentSocketError(e) {
			t.Errorf("%v must not be treated as a dead descriptor", e)
		}
	}
}

func TestEnableSendErrorReportingReportsPerFamilyCoverage(t *testing.T) {
	t.Parallel()
	get := func(c *net.UDPConn, level, opt int) int {
		t.Helper()
		v, err := udpGetsockoptInt(c, level, opt)
		if err != nil {
			t.Fatalf("getsockopt(%d, %d): %v", level, opt, err)
		}
		return v
	}
	c4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c4.Close()
	opts, err := EnableSendErrorReporting(c4)
	if err != nil || !opts.IPv4 || opts.IPv6 || !opts.Any() {
		t.Fatalf("v4 socket coverage: %+v err=%v", opts, err)
	}
	if get(c4, unix.SOL_IP, unix.IP_RECVERR) != 1 {
		t.Fatal("IP_RECVERR not set on an AF_INET socket")
	}

	c6, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6unspecified})
	if err != nil {
		t.Skipf("no IPv6 socket here: %v", err)
	}
	defer c6.Close()
	opts, err = EnableSendErrorReporting(c6)
	if err != nil || !opts.IPv6 {
		t.Fatalf("v6 socket coverage: %+v err=%v", opts, err)
	}
	if get(c6, unix.SOL_IPV6, unix.IPV6_RECVERR) != 1 {
		t.Fatal("IPV6_RECVERR not set")
	}
	if opts.IPv4 != (get(c6, unix.SOL_IP, unix.IP_RECVERR) == 1) {
		t.Fatal("reported IPv4 coverage disagrees with the socket")
	}
}

// TestAbsorbedErrorsAreDrainedCountedAndAttributedOnlyAdvisorily: the error
// queue ends empty with sk_err clear, the counters move, and the record names
// the peer the ICMP was about, not the peer being served.
func TestAbsorbedErrorsAreDrainedCountedAndAttributedOnlyAdvisorily(t *testing.T) {
	gw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	if _, err := EnableSendErrorReporting(gw); err != nil {
		t.Fatal(err)
	}
	healthy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer healthy.Close()
	raw, err := NewRawBatchConn(gw)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var recs []QueuedSocketError
	raw.ErrorQueue().SetHandler(func(r QueuedSocketError) {
		mu.Lock()
		recs = append(recs, r)
		mu.Unlock()
	})
	closed := closedLoopbackPort(t)
	dest := healthy.LocalAddr().(*net.UDPAddr).AddrPort()

	provokePortUnreachable(t, raw, closed)
	if n, err := raw.WriteBatchTo(seqMsgs(0, 4, 100), dest); n != 4 || err != nil {
		t.Fatalf("WriteBatchTo to the healthy peer: (%d, %v)", n, err)
	}
	st := raw.ErrorQueue().Stats()
	if st.MatchingErrorRetries < 1 || st.Drained < 1 || st.DrainedICMP < 1 || st.TransmitRefused != 0 {
		t.Fatalf("stats after one absorbed port unreachable: %+v", st)
	}
	mu.Lock()
	got := append([]QueuedSocketError(nil), recs...)
	mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("handler saw %d records, want 1: %+v", len(got), got)
	}
	r := got[0]
	if r.Dest != closed || r.Errno != uint32(unix.ECONNREFUSED) || r.Origin != unix.SO_EE_ORIGIN_ICMP ||
		r.Type != 3 || r.Code != 3 || r.Offender != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("record %+v does not name the closed port %v as the ICMP's subject", r, closed)
	}
	if r.Dest == dest {
		t.Fatal("the record blames the peer being served")
	}
	assertQueueClean(t, gw)
}

func TestAbsorbAsyncGate(t *testing.T) {
	t.Parallel()
	gw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	if _, err := EnableSendErrorReporting(gw); err != nil {
		t.Fatal(err)
	}
	q, err := NewSocketErrorQueue(gw)
	if err != nil {
		t.Fatal(err)
	}
	if q.AbsorbAsync(unix.ENOBUFS, 0) {
		t.Fatal("ENOBUFS is the qdisc verdict, not another datagram's error")
	}
	if !q.AbsorbAsync(unix.ECONNREFUSED, 0) {
		t.Fatal("a matching errno below the budget must be absorbed")
	}
	if q.AbsorbAsync(unix.ECONNREFUSED, AsyncErrorRetries) {
		t.Fatal("the retry budget must bound absorption")
	}
}

// helpers shared with the netns send-error tests

func fdOf(t *testing.T, c *net.UDPConn) int {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fd int
	if err := raw.Control(func(f uintptr) { fd = int(f) }); err != nil {
		t.Fatal(err)
	}
	return fd
}

func assertQueueClean(t *testing.T, gw *net.UDPConn) {
	t.Helper()
	rc, _ := gw.SyscallConn()
	var qErr error
	var soErr int
	_ = rc.Control(func(fd uintptr) {
		buf := make([]byte, 64)
		oob := make([]byte, 128)
		_, _, _, _, qErr = unix.Recvmsg(int(fd), buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		soErr, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR)
	})
	if !errors.Is(qErr, unix.EAGAIN) || soErr != 0 {
		t.Fatalf("error queue not empty (%v) or sk_err pending (%d)", qErr, soErr)
	}
}
