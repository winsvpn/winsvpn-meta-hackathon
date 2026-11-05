//go:build linux || android

package carrier

// Real-kernel qdisc and path-MTU tests. They need root and the throwaway
// topology from the lane harness (netns l4g, l4r, l4c; see the harness's
// l4_netns.sh), and run only when WINN3_L4_NETNS=1:
//
//	l4g: l4g0 10.44.1.1  <->  l4r (router)  <->  l4c0 10.44.2.2-6, MTU 1280
//
// Like udp_recverr_shared_socket_linux_test.go they use only the RawBatchConn
// API and a raw IP_RECVERR setsockopt, so they also run against a tree without
// the send-error change. WINN3_L4_RECVERR=0 leaves IP_RECVERR off, which is
// what the gateway shipped with.

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var (
	l4Gateway = netip.MustParseAddr("10.44.1.1")
	l4ClientB = netip.MustParseAddrPort("10.44.2.3:4000")
	l4ClientC = netip.MustParseAddrPort("10.44.2.2:4001")
	l4ClientD = netip.MustParseAddrPort("10.44.2.4:4000")
)

func requireL4Netns(t *testing.T) {
	t.Helper()
	if os.Getenv("WINN3_L4_NETNS") != "1" {
		t.Skip("set WINN3_L4_NETNS=1 and run as root inside the lane harness topology")
	}
	for _, ns := range []string{"l4g", "l4r", "l4c"} {
		if _, err := os.Stat("/run/netns/" + ns); err != nil {
			t.Fatalf("netns %s missing: %v", ns, err)
		}
	}
}

func l4RecvErrWanted() bool { return os.Getenv("WINN3_L4_RECVERR") != "0" }

// l4UDP opens a UDP socket bound to bind inside netns ns. The thread that
// entered ns stays locked and is discarded when its goroutine returns.
func l4UDP(t *testing.T, ns string, bind netip.AddrPort) *net.UDPConn {
	t.Helper()
	type result struct {
		c   *net.UDPConn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		fd, err := unix.Open("/run/netns/"+ns, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			ch <- result{nil, err}
			return
		}
		defer unix.Close(fd)
		if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
			ch <- result{nil, err}
			return
		}
		c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(bind))
		ch <- result{c, err}
	}()
	r := <-ch
	if r.err != nil {
		t.Fatalf("socket in %s at %s: %v", ns, bind, r.err)
	}
	t.Cleanup(func() { _ = r.c.Close() })
	return r.c
}

func l4Sh(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return string(out)
}

func l4Qdisc(t *testing.T, spec ...string) {
	t.Helper()
	l4Sh(t, append([]string{"ip", "netns", "exec", "l4g", "tc", "qdisc", "replace", "dev", "l4g0", "root"}, spec...)...)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", "l4g", "tc", "qdisc", "replace", "dev", "l4g0", "root", "pfifo", "limit", "1000").Run()
	})
}

func l4QdiscStat(t *testing.T, field string) uint64 {
	fs := strings.Fields(l4Sh(t, "ip", "netns", "exec", "l4g", "tc", "-s", "qdisc", "show", "dev", "l4g0"))
	for i := range fs {
		if fs[i] == field && i+1 < len(fs) {
			n, _ := strconv.ParseUint(strings.TrimSuffix(fs[i+1], ","), 10, 64)
			return n
		}
	}
	return 0
}

// collectSeqs drains c on its own goroutine from now on, so the receiver's
// socket buffer is never the thing that drops. The returned function stops
// after c has been quiet for quiet and reports what arrived.
func collectSeqs(c *net.UDPConn, quiet time.Duration) func() map[uint32]int {
	got := map[uint32]int{}
	done := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		stopping := false
		for {
			select {
			case <-stop:
				stopping = true
			default:
			}
			_ = c.SetReadDeadline(time.Now().Add(quiet))
			n, err := c.Read(buf)
			if err != nil {
				if stopping {
					return
				}
				continue
			}
			if n >= 4 {
				got[binary.BigEndian.Uint32(buf)]++
			}
		}
	}()
	return func() map[uint32]int {
		close(stop)
		<-done
		return got
	}
}

func l4GatewaySocket(t *testing.T, recverr bool) (*net.UDPConn, *RawBatchConn) {
	t.Helper()
	gw := l4UDP(t, "l4g", netip.AddrPortFrom(l4Gateway, 0))
	if recverr {
		setRawRecvErr(t, gw)
	}
	raw, err := NewRawBatchConn(gw)
	if err != nil {
		t.Fatal(err)
	}
	return gw, raw
}

// retainAndResend is the driver.Loop Round A contract in miniature: whatever
// the carrier does not accept is kept and re-presented verbatim after
// carrierDrainBackoff, within carrierStallLimit from the first refusal.
func retainAndResend(t *testing.T, raw *RawBatchConn, msgs []BatchMsg, dest netip.AddrPort) (refusals int) {
	t.Helper()
	pending := msgs
	var stallSince time.Time
	for len(pending) > 0 {
		batch := pending
		if len(batch) > 64 {
			batch = batch[:64]
		}
		n, err := raw.WriteBatchTo(batch, dest)
		if n < 0 || n > len(batch) {
			t.Fatalf("WriteBatchTo returned n=%d for %d", n, len(batch))
		}
		pending = pending[n:]
		if n == len(batch) && err == nil {
			stallSince = time.Time{}
			continue
		}
		refusals++
		if stallSince.IsZero() {
			stallSince = time.Now()
		} else if time.Since(stallSince) > 2*time.Second {
			t.Fatalf("carrier refused for over 2s; %d datagrams still pending", len(pending))
		}
		time.Sleep(time.Millisecond)
	}
	return refusals
}

// TestNetnsFqFlowLimitRefusalIsVisibleAndNothingAcceptedIsLost is the defect:
// an fq flow_limit drop must reach the sender as a refusal of the datagram it
// dropped, so retention can resend it, and every datagram the carrier accepted
// must arrive.
func TestNetnsFqFlowLimitRefusalIsVisibleAndNothingAcceptedIsLost(t *testing.T) {
	requireL4Netns(t)
	l4Qdisc(t, "fq", "flow_limit", "8", "maxrate", "8mbit")
	rx := l4UDP(t, "l4c", l4ClientB)
	_, raw := l4GatewaySocket(t, l4RecvErrWanted())
	// Warm ARP on both hops so first-packet resolution is not what is measured.
	if _, err := raw.WriteBatchTo(seqMsgs(999999, 1, 16), l4ClientB); err != nil {
		t.Fatal(err)
	}
	readSeqs(t, rx, 300*time.Millisecond)

	plimit0 := l4QdiscStat(t, "flows_plimit")
	const total = 512
	collect := collectSeqs(rx, 300*time.Millisecond)
	refusals := retainAndResend(t, raw, seqMsgs(0, total, 1000), l4ClientB)
	got := collect()
	drops := l4QdiscStat(t, "flows_plimit") - plimit0
	t.Logf("recverr=%v sent=%d refusals=%d fq_flows_plimit=%d delivered=%d", l4RecvErrWanted(), total, refusals, drops, len(got))
	if drops == 0 {
		t.Fatal("fq never hit flow_limit; the test did not exercise the drop")
	}
	var missing []uint32
	for s := uint32(0); s < total; s++ {
		if got[s] == 0 {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%d of %d datagrams the carrier ACCEPTED never arrived while fq dropped %d at flow_limit: "+
			"the refusal was invisible to the sender (first missing %v)", len(missing), total, drops, missing[:min(8, len(missing))])
	}
	if refusals == 0 {
		t.Fatal("fq dropped datagrams and the carrier reported no refusal")
	}
}

// TestNetnsRefusedFlowDoesNotStallOtherSessions: a client whose fq flow is full
// must not hold the transmit path that every other session shares.
func TestNetnsRefusedFlowDoesNotStallOtherSessions(t *testing.T) {
	requireL4Netns(t)
	if !l4RecvErrWanted() {
		t.Skip("without IP_RECVERR there is no refusal to wait out")
	}
	l4Qdisc(t, "fq", "flow_limit", "8", "maxrate", "8mbit")
	rxC := l4UDP(t, "l4c", l4ClientC)
	rxB := l4UDP(t, "l4c", l4ClientB)
	_, raw := l4GatewaySocket(t, true)
	_, _ = raw.WriteBatchTo(seqMsgs(999999, 1, 16), l4ClientB)
	_, _ = raw.WriteBatchTo(seqMsgs(999999, 1, 16), l4ClientC)
	readSeqs(t, rxB, 300*time.Millisecond)
	readSeqs(t, rxC, 10*time.Millisecond)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var floodLat []time.Duration
	wg.Add(1)
	go func() {
		defer wg.Done()
		flood := seqMsgs(100000, 64, 1000)
		for {
			select {
			case <-stop:
				return
			default:
			}
			start := time.Now()
			_, _ = raw.WriteBatchTo(flood, l4ClientC)
			floodLat = append(floodLat, time.Since(start))
		}
	}()
	// Client B asks for one small datagram every 2 ms: 500 in the second if
	// nothing holds the transmit path.
	const interval = 2 * time.Millisecond
	var lat []time.Duration
	begin := time.Now()
	deadline := begin.Add(time.Second)
	for i := uint32(0); time.Now().Before(deadline); i++ {
		start := time.Now()
		n, err := raw.WriteBatchTo(seqMsgs(i, 1, 200), l4ClientB)
		lat = append(lat, time.Since(start))
		if n != 1 || err != nil {
			t.Fatalf("send to the uncongested client B returned (%d, %v)", n, err)
		}
		time.Sleep(interval)
	}
	close(stop)
	wg.Wait()
	pct := func(d []time.Duration, p int) time.Duration {
		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
		return d[(len(d)-1)*p/100]
	}
	ideal := int(time.Second / interval)
	t.Logf("client B: %d of %d sends in 1s, send latency p50=%v p99=%v max=%v; client C refused-flood calls=%d, each p50=%v p99=%v max=%v",
		len(lat), ideal, pct(lat, 50), pct(lat, 99), pct(lat, 100), len(floodLat), pct(floodLat, 50), pct(floodLat, 99), pct(floodLat, 100))
	if len(lat) < ideal*6/10 {
		t.Fatalf("client B completed %d of %d paced sends while client C's fq flow was full: "+
			"the refused flow is holding the shared transmit path", len(lat), ideal)
	}
}

// TestNetnsSendBufferExhaustionLosesNothing: a full SO_SNDBUF is EAGAIN, not
// ENOBUFS. The carrier may park or return a short count, but it must report no
// error and, with retention, lose nothing. Both trees must pass: this is the
// regression guard for the parking path.
func TestNetnsSendBufferExhaustionLosesNothing(t *testing.T) {
	requireL4Netns(t)
	l4Qdisc(t, "tbf", "rate", "4mbit", "burst", "3000", "limit", "10000000")
	rx := l4UDP(t, "l4c", l4ClientB)
	gw, raw := l4GatewaySocket(t, l4RecvErrWanted())
	if err := gw.SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	_, _ = raw.WriteBatchTo(seqMsgs(999999, 1, 16), l4ClientB)
	readSeqs(t, rx, 300*time.Millisecond)
	collect := collectSeqs(rx, 300*time.Millisecond)
	start := time.Now()
	pending := seqMsgs(0, 64, 1000)
	calls, short := 0, 0
	for len(pending) > 0 {
		n, err := raw.WriteBatchTo(pending, l4ClientB)
		calls++
		if err != nil {
			t.Fatalf("a full send buffer returned an error (%d, %v); it is EAGAIN, not a refusal", n, err)
		}
		if n < len(pending) {
			short++
			time.Sleep(time.Millisecond)
		}
		pending = pending[n:]
	}
	elapsed := time.Since(start)
	got := collect()
	t.Logf("64 datagrams in %d calls (%d short) over %v, delivered %d", calls, short, elapsed, len(got))
	if elapsed < 20*time.Millisecond {
		t.Fatalf("64 KB at 4 Mbit through an 8 KB send buffer took %v; the buffer never filled", elapsed)
	}
	if len(got) != 64 {
		t.Fatalf("delivered %d of 64", len(got))
	}
}

// TestNetnsFragNeededForOneClientIsNotAnotherClientsVerdict: an ICMP
// fragmentation-needed about client D sets EMSGSIZE on the shared socket; it
// must not fail, or be read as a path-MTU verdict for, a send to client B.
func TestNetnsFragNeededForOneClientIsNotAnotherClientsVerdict(t *testing.T) {
	requireL4Netns(t)
	l4Qdisc(t, "pfifo", "limit", "1000")
	l4Sh(t, "ip", "netns", "exec", "l4g", "ip", "route", "flush", "cache")
	rxB := l4UDP(t, "l4c", l4ClientB)
	_ = l4UDP(t, "l4c", l4ClientD)
	_, raw := l4GatewaySocket(t, true)
	_, _ = raw.WriteBatchTo(seqMsgs(999999, 1, 16), l4ClientB)
	readSeqs(t, rxB, 300*time.Millisecond)

	for round := 0; round < 2; round++ {
		// 1400 bytes crosses the router's 1280-byte link with DF set: the
		// router answers ICMP fragmentation-needed, MTU 1280.
		l4Sh(t, "ip", "netns", "exec", "l4g", "ip", "route", "flush", "cache")
		if n, err := raw.WriteBatchTo(seqMsgs(800000, 1, 1400), l4ClientD); n != 1 || err != nil {
			t.Fatalf("round %d: oversize send to D: (%d, %v)", round, n, err)
		}
		time.Sleep(100 * time.Millisecond)
		n, err := raw.WriteBatchTo(seqMsgs(uint32(round*4), 4, 200), l4ClientB)
		if n != 4 || err != nil {
			t.Fatalf("round %d: send to client B returned (%d, %v) after client D's fragmentation-needed; "+
				"that EMSGSIZE is D's path, not B's datagram", round, n, err)
		}
	}
	got := readSeqs(t, rxB, 200*time.Millisecond)
	for s := uint32(0); s < 8; s++ {
		if got[s] != 1 {
			t.Fatalf("client B received datagram %d %d times", s, got[s])
		}
	}
}

// TestNetnsSendBufferFullDoesNotHoldTheTransmitLock is the requirement-3 EAGAIN
// fairness case. A tiny SO_SNDBUF behind a slow tbf makes the shared socket
// return EAGAIN. A zero-progress EAGAIN must NOT park inside rawConn.Write while
// c.mu is held, or one flooding client freezes every other client's transmit
// path. One goroutine floods client C; a second paces client B and its
// WriteBatchTo CALL latency must stay low even though the buffer is full.
// RED on v1 (which returned false on EAGAIN and parked holding c.mu).
func TestNetnsSendBufferFullDoesNotHoldTheTransmitLock(t *testing.T) {
	requireL4Netns(t)
	l4Qdisc(t, "tbf", "rate", "1mbit", "burst", "2000", "limit", "1000000")
	rxC := l4UDP(t, "l4c", l4ClientC)
	rxB := l4UDP(t, "l4c", l4ClientB)
	_ = rxC
	_ = rxB
	gw := l4UDP(t, "l4g", netip.AddrPortFrom(l4Gateway, 0))
	if err := gw.SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	setRawRecvErr(t, gw)
	raw, err := NewRawBatchConn(gw)
	if err != nil {
		t.Fatal(err)
	}
	// Prime the send buffer so it is already full when B measures.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		flood := seqMsgs(100000, 64, 1000)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = raw.WriteBatchTo(flood, l4ClientC)
		}
	}()
	time.Sleep(50 * time.Millisecond)

	var lat []time.Duration
	begin := time.Now()
	for time.Since(begin) < time.Second {
		start := time.Now()
		_, _ = raw.WriteBatchTo(seqMsgs(uint32(len(lat)), 1, 200), l4ClientB)
		lat = append(lat, time.Since(start))
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()

	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p50 := lat[len(lat)/2]
	p99 := lat[(len(lat)-1)*99/100]
	worst := lat[len(lat)-1]
	t.Logf("client B WriteBatchTo call latency over %d calls while the send buffer was full: p50=%v p99=%v max=%v", len(lat), p50, p99, worst)
	if p99 > 2*time.Millisecond {
		t.Fatalf("client B's WriteBatchTo p99 is %v while another client saturates the send buffer: "+
			"a zero-progress EAGAIN is parking in the poller while holding the shared transmit lock", p99)
	}
}

// TestNetnsSynchronousEMSGSIZEStaysUnattributed: a datagram above the path MTU
// fails EMSGSIZE on every attempt (a matching errno). After the retry budget
// the batch path must NOT surface EMSGSIZE (a driver could misread it as a
// path-MTU verdict); it returns the accepted prefix with no error and leaves
// the datagram for retention. Uses a raw IP_RECVERR setsockopt so it also runs
// against v1, where it is RED: v1 returned (0, EMSGSIZE).
func TestNetnsSynchronousEMSGSIZEStaysUnattributed(t *testing.T) {
	requireL4Netns(t)
	l4Qdisc(t, "pfifo", "limit", "1000")
	l4Sh(t, "ip", "netns", "exec", "l4g", "ip", "route", "flush", "cache")
	_ = l4UDP(t, "l4c", l4ClientD)
	gw := l4UDP(t, "l4g", netip.AddrPortFrom(l4Gateway, 0))
	setRawRecvErr(t, gw)
	if err := enableUDPPathMTUDiscovery(gw); err != nil {
		t.Fatal(err)
	}
	raw, err := NewRawBatchConn(gw)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := raw.WriteBatchTo(seqMsgs(1, 1, 1400), l4ClientD); n != 1 || err != nil {
		t.Fatalf("first oversize send: (%d, %v)", n, err)
	}
	time.Sleep(120 * time.Millisecond)
	n, err := raw.WriteBatchTo(seqMsgs(2, 1, 1400), l4ClientD)
	t.Logf("second oversize send=(%d, %v)", n, err)
	if n != 0 || err != nil {
		t.Fatalf("a recurring EMSGSIZE returned (%d, %v); exhaustion must be unattributed, i.e. (0, nil)", n, err)
	}
}
