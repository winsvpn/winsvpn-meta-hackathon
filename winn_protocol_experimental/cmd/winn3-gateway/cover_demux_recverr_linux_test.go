//go:build linux

package main

// The receive pump and the scalar write path on a shared socket with
// IP_RECVERR, on a real kernel. Only newSplitUDP and the demuxSide methods are
// used, and IP_RECVERR is set with a raw setsockopt, so this file also compiles
// against a tree without the send-error change and shows what enabling
// IP_RECVERR alone does to the pump.

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func setRawRecvErrOn(t *testing.T, c *net.UDPConn) {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVERR, 1)
	}); err != nil {
		t.Fatal(err)
	}
	if serr != nil {
		t.Fatalf("IP_RECVERR: %v", serr)
	}
}

func closedLoopbackAddr(t *testing.T) netip.AddrPort {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
	_ = c.Close()
	return ap
}

func splitStopped(s *splitUDP) bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// readFromSplit reads want datagrams from the v3 side within d.
func readFromSplit(t *testing.T, s *splitUDP, want int, d time.Duration) []netip.AddrPort {
	t.Helper()
	_ = s.v3.SetReadDeadline(time.Now().Add(d))
	defer func() { _ = s.v3.SetReadDeadline(time.Time{}) }()
	var from []netip.AddrPort
	buf := make([]byte, 4096)
	for len(from) < want {
		_, addr, err := s.v3.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("after %d of %d datagrams: %v (pump stopped=%v)", len(from), want, err, splitStopped(s))
		}
		from = append(from, addr)
	}
	return from
}

// TestTheDemuxPumpSurvivesAnotherPeersPortUnreachable: one client's closed
// port must not stop the pump that every session's downlink and uplink use,
// nor fail a write to a different client.
func TestTheDemuxPumpSurvivesAnotherPeersPortUnreachable(t *testing.T) {
	real, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer real.Close()
	setRawRecvErrOn(t, real)
	split := newSplitUDP(real, demuxDatagramMin)
	defer split.stop()
	healthy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer healthy.Close()
	gone := closedLoopbackAddr(t)
	gwAddr := real.LocalAddr().(*net.UDPAddr)
	healthyAddr := healthy.LocalAddr().(*net.UDPAddr).AddrPort()

	for round := 0; round < 3; round++ {
		if _, err := split.v3.WriteToUDPAddrPort([]byte("to a client that went away"), gone); err != nil {
			t.Fatalf("round %d: write to the departed client: %v", round, err)
		}
		time.Sleep(50 * time.Millisecond)
		for i := 0; i < 3; i++ {
			if _, err := healthy.WriteToUDP([]byte{byte(round), byte(i), 0, 0, 0, 0, 0, 0}, gwAddr); err != nil {
				t.Fatal(err)
			}
		}
		for _, from := range readFromSplit(t, split, 3, 2*time.Second) {
			if from != healthyAddr {
				t.Fatalf("round %d: datagram attributed to %v, want %v", round, from, healthyAddr)
			}
		}
		if _, err := split.v3.WriteToUDPAddrPort([]byte("to a client that went away"), gone); err != nil {
			t.Fatalf("round %d: second write to the departed client: %v", round, err)
		}
		time.Sleep(50 * time.Millisecond)
		// The pump may have consumed the error first; either way the write to
		// the healthy client is not the departed client's verdict.
		if _, err := split.v3.WriteToUDPAddrPort([]byte("to the healthy client"), healthyAddr); err != nil {
			t.Fatalf("round %d: write to the healthy client failed with another client's error: %v", round, err)
		}
	}
	if splitStopped(split) {
		t.Fatal("the shared pump stopped")
	}
}

// l4Netns helpers for the qdisc-dependent case, run only in the lane harness
// topology (WINN3_L4_NETNS=1, root).
func requireGatewayL4Netns(t *testing.T) {
	t.Helper()
	if os.Getenv("WINN3_L4_NETNS") != "1" {
		t.Skip("set WINN3_L4_NETNS=1 and run as root inside the lane harness topology")
	}
}

func gatewayL4UDP(t *testing.T, ns string, bind netip.AddrPort) *net.UDPConn {
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
		t.Fatalf("socket in %s: %v", ns, r.err)
	}
	t.Cleanup(func() { _ = r.c.Close() })
	return r.c
}

func gatewayL4Sh(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
}

// errorOnlyWakeup drives the shared pump through a port unreachable that lands
// while the send buffer is full. That produces an epoll event carrying only
// EPOLLERR, after which Go's poller fails reads with "not pollable" until the
// next event (runtime.netpollcheckerr). It returns the split, still open, after
// three datagrams from a healthy client were read through it.
func errorOnlyWakeup(t *testing.T) *splitUDP {
	t.Helper()
	requireGatewayL4Netns(t)
	gatewayL4Sh(t, "ip", "netns", "exec", "l4g", "tc", "qdisc", "replace", "dev", "l4g0", "root",
		"tbf", "rate", "40kbit", "burst", "1600", "limit", "1000000")
	gatewayL4Sh(t, "ip", "netns", "exec", "l4c", "tc", "qdisc", "replace", "dev", "l4c0", "root", "netem", "delay", "150ms")
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", "l4g", "tc", "qdisc", "replace", "dev", "l4g0", "root", "pfifo", "limit", "1000").Run()
		_ = exec.Command("ip", "netns", "exec", "l4c", "tc", "qdisc", "del", "dev", "l4c0", "root").Run()
	})
	clientB := netip.MustParseAddrPort("10.44.2.3:4000")
	gone := netip.MustParseAddrPort("10.44.2.2:5000")
	b := gatewayL4UDP(t, "l4c", clientB)
	real := gatewayL4UDP(t, "l4g", netip.MustParseAddrPort("10.44.1.1:0"))
	if err := real.SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	setRawRecvErrOn(t, real)
	split := newSplitUDP(real, demuxDatagramMin)
	t.Cleanup(split.stop)
	time.Sleep(20 * time.Millisecond)

	if _, err := split.v3.WriteToUDPAddrPort(make([]byte, 1000), gone); err != nil {
		t.Fatal(err)
	}
	// Fill the send buffer behind the slow qdisc so the socket is not
	// writable when the ICMP comes back 150 ms later.
	rc, _ := real.SyscallConn()
	eagain := 0
	_ = rc.Write(func(fd uintptr) bool {
		for i := 0; i < 16; i++ {
			if unix.Sendto(int(fd), make([]byte, 1000), unix.MSG_DONTWAIT,
				&unix.SockaddrInet4{Port: int(clientB.Port()), Addr: clientB.Addr().As4()}) == unix.EAGAIN {
				eagain++
			}
		}
		return true
	})
	if eagain == 0 {
		t.Fatal("the send buffer never filled; the error-only wakeup cannot happen")
	}
	time.Sleep(1500 * time.Millisecond)
	gw := net.UDPAddrFromAddrPort(real.LocalAddr().(*net.UDPAddr).AddrPort())
	for i := 0; i < 3; i++ {
		if _, err := b.WriteToUDP([]byte{9, byte(i), 0, 0, 0, 0, 0, 0}, gw); err != nil {
			t.Fatal(err)
		}
	}
	readFromSplit(t, split, 3, 4*time.Second)
	if splitStopped(split) {
		t.Fatal("the shared pump stopped")
	}
	return split
}

func TestNetnsTheDemuxPumpSurvivesAnErrorOnlyWakeup(t *testing.T) {
	errorOnlyWakeup(t)
}
