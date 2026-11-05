package main

import (
	"bytes"
	"context"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func testPair(t *testing.T, ipv6only bool) (int64, int64, string, func()) {
	t.Helper()
	v4a, v4b, v6a, v6b := "192.0.2.1", "192.0.2.2", "", ""
	remote := v4b
	if ipv6only {
		v4a, v4b = "", ""
		v6a, v6b = "2001:db8::1", "2001:db8::2"
		remote = v6b
	}
	a, b := safariNewStack(v4a, v6a, 1280), safariNewStack(v4b, v6b, 1280)
	if a <= 0 || b <= 0 {
		t.Fatalf("create %d %d", a, b)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, pair := range [][2]int64{{a, b}, {b, a}} {
		wg.Add(1)
		go func(p [2]int64) {
			defer wg.Done()
			buf := make([]byte, 1280)
			for ctx.Err() == nil {
				n := safariDequeue(p[0], buf, 100)
				if n > 0 {
					code := safariEnqueue(p[1], buf[:n])
					if code != n && ctx.Err() == nil {
						t.Errorf("inject %d expected %d", code, n)
					}
				}
			}
		}(pair)
	}
	return a, b, remote, func() { cancel(); wg.Wait(); safariCloseStack(a); safariCloseStack(b) }
}
func fullAddress(ip string, port uint16) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	a := netip.MustParseAddr(ip)
	pn := ipv4.ProtocolNumber
	if a.Is6() {
		pn = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.AsSlice()), Port: port}, pn
}
func TestTCPRoundTripAndHalfClose(t *testing.T) {
	for _, six := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[six], func(t *testing.T) {
			a, b, remote, done := testPair(t, six)
			defer done()
			addr, pn := fullAddress(remote, 443)
			listener, e := gonet.ListenTCP(safariGetStack(b).stack, addr, pn)
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			result := make(chan error, 1)
			go func() {
				c, e := listener.Accept()
				if e != nil {
					result <- e
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(4 * time.Second))
				got, e := io.ReadAll(c)
				if e == nil && !bytes.Equal(got, []byte("request")) {
					e = io.ErrUnexpectedEOF
				}
				if e == nil {
					_, e = c.Write([]byte("response"))
				}
				result <- e
			}()
			f := safariDial(a, remote, 443, 3000, false)
			if f <= 0 {
				t.Fatalf("dial %d", f)
			}
			defer safariCloseFlow(f)
			if n := safariWrite(f, []byte("request"), 3000); n != 7 {
				t.Fatalf("write %d", n)
			}
			if n := safariCloseWrite(f); n != 0 {
				t.Fatalf("half close %d", n)
			}
			buf := make([]byte, 200)
			if n := safariRead(f, buf, 3000); n != 8 || string(buf[:n]) != "response" {
				t.Fatalf("read %d", n)
			}
			if n := safariRead(f, buf, 3000); n != 0 {
				t.Fatalf("EOF %d", n)
			}
			if e := <-result; e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestUDPDatagramsAndNoTruncation(t *testing.T) {
	for _, six := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[six], func(t *testing.T) {
			a, b, remote, done := testPair(t, six)
			defer done()
			addr, pn := fullAddress(remote, 53)
			server, e := gonet.DialUDP(safariGetStack(b).stack, &addr, nil, pn)
			if e != nil {
				t.Fatal(e)
			}
			defer server.Close()
			server.SetDeadline(time.Now().Add(4 * time.Second))
			f := safariDial(a, remote, 53, 3000, true)
			if f <= 0 {
				t.Fatalf("dial %d", f)
			}
			defer safariCloseFlow(f)
			for _, payload := range [][]byte{[]byte("dns query"), {}} {
				if n := safariWrite(f, payload, 3000); n != len(payload) {
					t.Fatalf("write %d", n)
				}
				buf := make([]byte, 65535)
				n, peer, e := server.ReadFrom(buf)
				if e != nil {
					t.Fatal(e)
				}
				if !bytes.Equal(buf[:n], payload) {
					t.Fatal("datagram mismatch")
				}
				if _, e = server.WriteTo(buf[:n], peer); e != nil {
					t.Fatal(e)
				}
				if n := safariRead(f, make([]byte, 2), 3000); n != safariTooLarge {
					t.Fatalf("short read %d", n)
				}
				n = safariRead(f, buf, 3000)
				if n != len(payload) || !bytes.Equal(buf[:n], payload) {
					t.Fatalf("echo %d", n)
				}
			}
			if safariCloseWrite(f) != safariArgument {
				t.Fatal("UDP accepted half close")
			}
		})
	}
}
func TestRejectHostDNSAndInvalidFamilies(t *testing.T) {
	h := safariNewStack("192.0.2.1", "", 1280)
	defer safariCloseStack(h)
	for _, host := range []string{"example.invalid", "2001:db8::1", "::ffff:192.0.2.2", "fe80::1%en0"} {
		if got := safariDial(h, host, 443, 100, false); got != safariArgument {
			t.Fatalf("accepted %q: %d", host, got)
		}
	}
	if got := safariEnqueue(h, []byte("GET / HTTP/1.1\r\n")); got != safariArgument {
		t.Fatalf("stream accepted %d", got)
	}
	if got := safariDequeue(h, make([]byte, 20), 10); got != safariTooLarge {
		t.Fatalf("short packet buffer %d", got)
	}
	if got := safariNewStack("", "2001:db8::1", 1000); got != safariArgument {
		t.Fatalf("bad IPv6 MTU %d", got)
	}
}
func TestCloseWakesPacketReadAndDial(t *testing.T) {
	h := safariNewStack("192.0.2.1", "", 1280)
	readDone := make(chan int, 1)
	dialDone := make(chan int64, 1)
	go func() { readDone <- safariDequeue(h, make([]byte, 1280), 10000) }()
	go func() { dialDone <- safariDial(h, "192.0.2.2", 443, 10000, false) }()
	time.Sleep(20 * time.Millisecond)
	safariCloseStack(h)
	select {
	case got := <-readDone:
		if got < 0 && got != safariClosed && got != safariBadHandle {
			t.Fatalf("close read %d", got)
		}
	case <-time.After(time.Second):
		t.Fatal("packet close did not wake")
	}
	select {
	case got := <-dialDone:
		if got >= 0 {
			t.Fatalf("closed dial %d", got)
		}
	case <-time.After(time.Second):
		t.Fatal("dial close did not wake")
	}
	safariCloseStack(h)
}
func TestCloseWakesFlowRead(t *testing.T) {
	h := safariNewStack("192.0.2.1", "", 1280)
	defer safariCloseStack(h)
	f := safariDial(h, "192.0.2.2", 53, 100, true)
	if f <= 0 {
		t.Fatal(f)
	}
	ready := make(chan struct{})
	finished := make(chan int, 1)
	go func() { close(ready); finished <- safariRead(f, make([]byte, 65535), 10000) }()
	<-ready
	time.Sleep(20 * time.Millisecond)
	safariCloseFlow(f)
	select {
	case got := <-finished:
		if got != safariClosed && got != safariBadHandle {
			t.Fatalf("close returned %d", got)
		}
	case <-time.After(time.Second):
		t.Fatal("flow close did not wake")
	}
}
func TestUDPReadTimeout(t *testing.T) {
	h := safariNewStack("192.0.2.1", "", 1280)
	defer safariCloseStack(h)
	f := safariDial(h, "192.0.2.2", 53, 100, true)
	if f <= 0 {
		t.Fatal(f)
	}
	if got := safariRead(f, make([]byte, 65535), 10); got != safariTimeout {
		t.Fatalf("timeout %d", got)
	}
}

var _ net.Conn = (*gonet.TCPConn)(nil)

func TestCloseWakesIdlePacketRead(t *testing.T) {
	h := safariNewStack("192.0.2.1", "", 1280)
	finished := make(chan int, 1)
	go func() { finished <- safariDequeue(h, make([]byte, 1280), 10000) }()
	time.Sleep(20 * time.Millisecond)
	safariCloseStack(h)
	select {
	case got := <-finished:
		if got != safariClosed && got != safariBadHandle {
			t.Fatalf("idle close returned %d", got)
		}
	case <-time.After(time.Second):
		t.Fatal("idle packet read did not wake")
	}
}

func TestConcurrentDialAndShutdown(t *testing.T) {
	for iteration := 0; iteration < 25; iteration++ {
		h := safariNewStack("192.0.2.1", "", 1280)
		s := safariGetStack(h)
		start := make(chan struct{})
		var workers sync.WaitGroup
		for i := 0; i < 16; i++ {
			workers.Add(1)
			go func(datagram bool) {
				defer workers.Done()
				<-start
				f := safariDial(h, "192.0.2.2", 443, 10000, datagram)
				if f > 0 {
					safariCloseFlow(f)
				}
			}(i%2 == 0)
		}
		close(start)
		time.Sleep(time.Millisecond)
		safariCloseStack(h)
		finished := make(chan struct{})
		go func() { workers.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("concurrent dial outlived shutdown")
		}
		if remaining := len(s.stack.RegisteredEndpoints()); remaining != 0 {
			t.Fatalf("shutdown left %d registered endpoints", remaining)
		}
	}
}
