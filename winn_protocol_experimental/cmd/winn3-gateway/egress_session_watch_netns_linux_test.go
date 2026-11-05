//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"winsvpn.local/winnprotocol/winn3/tun"
)

// Round CM3 Turn 3 (GPT-6 Sol OI-CM3-1) on a real kernel: two namespaces, a
// gateway (l80wg, veth g0 10.81.1.2/24) and a client (l80wc, c0 10.81.1.1/24),
// both 1500. The "narrowing" is `ip route add 10.81.1.1/32 dev g0 mtu 1400`
// in the gateway namespace, after the client is admitted.

const (
	wgNS, wcNS     = "l80wg", "l80wc"
	wgAddr, wcAddr = "10.81.1.2", "10.81.1.1"
)

func gatewayClientNetns(t *testing.T) {
	t.Helper()
	newNetns(t, wgNS)
	newNetns(t, wcNS)
	ipCmd(t, "-n", wgNS, "link", "add", "g0", "type", "veth", "peer", "name", "c0", "netns", wcNS)
	ipCmd(t, "-n", wgNS, "addr", "add", wgAddr+"/24", "dev", "g0")
	ipCmd(t, "-n", wgNS, "link", "set", "g0", "mtu", "1500", "up")
	ipCmd(t, "-n", wcNS, "addr", "add", wcAddr+"/24", "dev", "c0")
	ipCmd(t, "-n", wcNS, "link", "set", "c0", "mtu", "1500", "up")
}

// runInNetns is inNetns for goroutines other than the test's: it reports an
// error instead of failing the test.
func runInNetns(name string, fn func()) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		fd, err := unix.Open("/run/netns/"+name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = unix.Close(fd) }()
		if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
			done <- err
			return
		}
		fn()
		done <- nil
	}()
	return <-done
}

// ipCounters reads the Ip: row of /proc/thread-self/net/snmp in namespace name.
func ipCounters(t *testing.T, name string) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	var err error
	inNetns(t, name, func() {
		var f *os.File
		if f, err = os.Open("/proc/thread-self/net/snmp"); err != nil {
			return
		}
		defer f.Close()
		var header []string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) == 0 || fields[0] != "Ip:" {
				continue
			}
			if header == nil {
				header = fields
				continue
			}
			for i := 1; i < len(fields) && i < len(header); i++ {
				n, _ := strconv.ParseInt(fields[i], 10, 64)
				out[header[i]] = n
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func udpIn(t *testing.T, ns, addr string) *net.UDPConn {
	t.Helper()
	var c *net.UDPConn
	var err error
	inNetns(t, ns, func() { c, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(addr)}) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func ipMTU(t *testing.T, c *net.UDPConn) int {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	if err := raw.Control(func(fd uintptr) { v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU) }); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		return -int(gerr.(syscall.Errno))
	}
	return v
}

// TestEgressNetnsKernelFragmentsAfterARouteNarrows MEASURES what the kernel
// does with the listener's replies once the client's route narrows, instead
// of assuming it (the coordinator's question for Turn 4):
//
//   - an unconnected UDP socket with the default IP_MTU_DISCOVER (what the
//     listener is when -listener-df is off) sends a 1480-byte datagram onto a
//     1400-byte route successfully, and the kernel fragments it locally
//     (Ip FragOKs/FragCreates rise); the send reports nothing;
//   - the same socket with IP_PMTUDISC_DO (-listener-df) gets EMSGSIZE;
//   - IP_MTU on a CONNECTED socket reports the route's MTU (logged before and
//     after the change, with and without a send in between).
//
// On this veth the fragments are reassembled at the client; on Chicago's
// provider path they were lost (Round CM). Either way nothing on the send
// path of the gateway can see the change, which is why the egress watch asks
// the kernel about routes instead.
func TestEgressNetnsKernelFragmentsAfterARouteNarrows(t *testing.T) {
	requireEgressNetns(t)
	gatewayClientNetns(t)
	rx := udpIn(t, wcNS, wcAddr)
	dst := rx.LocalAddr().(*net.UDPAddr)
	tx := udpIn(t, wgNS, wgAddr)
	var connected *net.UDPConn
	var err error
	inNetns(t, wgNS, func() { connected, err = net.DialUDP("udp4", nil, dst) })
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()
	payload := make([]byte, 1452) // 1480-byte IPv4 datagram
	receive := func() int {
		_ = rx.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n, _, err := rx.ReadFromUDP(buf)
		if err != nil {
			return -1
		}
		return n
	}

	mtuBefore := ipMTU(t, connected)
	c0 := ipCounters(t, wgNS)
	if _, err := tx.WriteToUDP(payload, dst); err != nil {
		t.Fatalf("send before the change: %v", err)
	}
	gotBefore := receive()
	c1 := ipCounters(t, wgNS)

	ipCmd(t, "-n", wgNS, "route", "add", wcAddr+"/32", "dev", "g0", "mtu", "1400")
	mtuAfterNoSend := ipMTU(t, connected)
	n, sendErr := tx.WriteToUDP(payload, dst)
	gotAfter := receive()
	c2 := ipCounters(t, wgNS)
	_, _ = connected.Write([]byte("x"))
	_ = receive()
	mtuAfterSend := ipMTU(t, connected)

	// The same send with DF (IP_PMTUDISC_DO), as -listener-df sets it.
	df := udpIn(t, wgNS, wgAddr)
	raw, _ := df.SyscallConn()
	var serr error
	_ = raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
	})
	if serr != nil {
		t.Fatal(serr)
	}
	_, dfErr := df.WriteToUDP(payload, dst)

	t.Logf("before: IP_MTU(connected)=%d; 1480-byte send delivered %d bytes; FragOKs +%d FragCreates +%d",
		mtuBefore, gotBefore, c1["FragOKs"]-c0["FragOKs"], c1["FragCreates"]-c0["FragCreates"])
	t.Logf("after route mtu 1400: IP_MTU(connected) without a send=%d, after a send=%d; unconnected send n=%d err=%v; "+
		"delivered %d bytes (reassembled); FragOKs +%d FragCreates +%d; DF send err=%v",
		mtuAfterNoSend, mtuAfterSend, n, sendErr, gotAfter, c2["FragOKs"]-c1["FragOKs"], c2["FragCreates"]-c1["FragCreates"], dfErr)

	if gotBefore != len(payload) || c1["FragOKs"] != c0["FragOKs"] {
		t.Fatalf("before the change the datagram was not sent whole (delivered %d, FragOKs +%d)", gotBefore, c1["FragOKs"]-c0["FragOKs"])
	}
	if sendErr != nil || n != len(payload) || c2["FragOKs"]-c1["FragOKs"] < 1 || c2["FragCreates"]-c1["FragCreates"] < 2 {
		t.Fatalf("after the change: send (%d, %v), FragOKs +%d FragCreates +%d; want a silent local fragmentation",
			n, sendErr, c2["FragOKs"]-c1["FragOKs"], c2["FragCreates"]-c1["FragCreates"])
	}
	if !errors.Is(dfErr, syscall.EMSGSIZE) {
		t.Fatalf("DF send after the change: %v, want EMSGSIZE", dfErr)
	}
	if mtuBefore != 1500 || mtuAfterSend != 1400 {
		t.Fatalf("IP_MTU(connected) before %d, after a send %d; want 1500 and 1400", mtuBefore, mtuAfterSend)
	}
}

// TestEgressNetnsRouteChangeClosesALiveSession: a real client carries through
// a real gateway session across two namespaces; the route to the client then
// narrows. The egress watch, subscribed in the gateway namespace, sees the
// route notification and closes the session within its one-second bound
// (the backstop is set to a minute, so only the notification can do it). An
// unrelated route change is swept and leaves the session alone.
func TestEgressNetnsRouteChangeClosesALiveSession(t *testing.T) {
	requireEgressNetns(t)
	gatewayClientNetns(t)
	savedInterval := egressRecheckInterval
	egressRecheckInterval = time.Minute
	t.Cleanup(func() { egressRecheckInterval = savedInterval })

	var lookups atomic.Int64
	savedMeasure := measureClientEgress
	measureClientEgress = func(l egressLookup, d netip.AddrPort) egressRoute {
		lookups.Add(1)
		var r egressRoute
		if err := runInNetns(wgNS, func() { r = savedMeasure(l, d) }); err != nil {
			return egressRoute{Dest: d.Addr(), DestPort: d.Port(), Err: err}
		}
		return r
	}
	t.Cleanup(func() { measureClientEgress = savedMeasure })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := udpIn(t, wgNS, wgAddr)
	f := newEgressFixture(t, ctx, conn, func(fn func()) {
		if err := runInNetns(wcNS, fn); err != nil {
			t.Fatal(err)
		}
	})

	var changed <-chan struct{}
	var stopWatch func()
	var werr error
	inNetns(t, wgNS, func() { changed, stopWatch, werr = startRouteWatch() })
	if werr != nil {
		t.Fatal(werr)
	}
	defer stopWatch()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	watchCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); f.srv.runEgressWatch(watchCtx, changed, ticker.C) }()
	defer func() { stop(); <-done }()

	// Unrelated change: swept, nothing closed.
	before := lookups.Load()
	ipCmd(t, "-n", wgNS, "route", "add", "203.0.113.0/24", "dev", "g0", "mtu", "1400")
	waitFor(t, 2*time.Second, "a sweep after an unrelated route change", func() bool { return lookups.Load() > before })
	if f.srv.egressClosed.Load() != 0 || f.sessions() != 1 {
		t.Fatalf("an unrelated route change closed %d sessions", f.srv.egressClosed.Load())
	}

	// The client's own route narrows.
	start := time.Now()
	ipCmd(t, "-n", wgNS, "route", "add", wcAddr+"/32", "dev", "g0", "mtu", "1400")
	waitFor(t, 2*time.Second, "the egress watch to close the session", func() bool { return f.srv.egressClosed.Load() == 1 })
	window := time.Since(start)
	waitFor(t, 10*time.Second, "the session to leave the table", func() bool { return f.sessions() == 0 })
	waitFor(t, 10*time.Second, "the client gate to leave carrying", func() bool {
		return f.cli.loop.Tunnel().Gate().State() != tun.StateCarrying
	})
	if window > time.Second+egressSweepMinGap {
		t.Fatalf("closed %v after the route change, beyond the one-second bound", window)
	}
	t.Logf("route narrowed -> session closed after %v (%d lookups in all); egress_mtu_closed=%d", window,
		lookups.Load(), f.srv.status().EgressMTUClosed)
}
