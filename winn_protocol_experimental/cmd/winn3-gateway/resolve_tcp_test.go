package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func dnsTCPFrameMust(t *testing.T, msg []byte) []byte {
	t.Helper()
	framed, err := dnsTCPFrame(msg)
	if err != nil {
		t.Fatalf("dnsTCPFrame: %v", err)
	}
	return framed
}

func startTestResolverTCP(t *testing.T, r *gatewayResolver) net.Addr {
	t.Helper()
	ln, err := listenResolverTCP("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenResolverTCP 127.0.0.1:0: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})
	go r.serveTCP(ctx, ln)
	return ln.Addr()
}

func stubTCPUpstream(t *testing.T, pad int) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stub tcp upstream: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				q, rerr := readDNSTCPFrame(c)
				if rerr != nil {
					return
				}
				reply := make([]byte, len(q), len(q)+pad)
				copy(reply, q)
				reply[2] |= 0x80
				reply = append(reply, make([]byte, pad)...)
				_ = writeDNSTCPFrame(c, reply)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

func stubDualUpstream(t *testing.T, pad int) netip.AddrPort {
	t.Helper()
	tln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dual tcp: %v", err)
	}
	t.Cleanup(func() { _ = tln.Close() })
	port := tln.Addr().(*net.TCPAddr).Port
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatalf("listen dual udp on port %d: %v", port, err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, rerr := pc.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			reply := make([]byte, n, n+pad)
			copy(reply, buf[:n])
			reply[2] |= 0x80
			reply = append(reply, make([]byte, pad)...)
			_, _ = pc.WriteToUDP(reply, from)
		}
	}()
	go func() {
		for {
			c, aerr := tln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				q, rerr := readDNSTCPFrame(c)
				if rerr != nil {
					return
				}
				reply := make([]byte, len(q), len(q)+pad)
				copy(reply, q)
				reply[2] |= 0x80
				reply = append(reply, make([]byte, pad)...)
				_ = writeDNSTCPFrame(c, reply)
			}(c)
		}
	}()
	return tln.Addr().(*net.TCPAddr).AddrPort()
}

func waitTCPAccepted(t *testing.T, r *gatewayResolver, want uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r.Stats().TcpAccepted >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("TcpAccepted = %d, want >= %d", r.Stats().TcpAccepted, want)
}

func waitTokensHeld(t *testing.T, r *gatewayResolver, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r.tokensHeld() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("tokensHeld = %d, want %d", r.tokensHeld(), want)
}

type capturingResolverLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *capturingResolverLog) Printf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintf(&c.buf, format, args...)
}

func (c *capturingResolverLog) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, c.buf.Len())
	copy(out, c.buf.Bytes())
	return out
}

func TestDNSTCPFrameRoundTrip(t *testing.T) {
	msg := dnsQueryBytes(0xabcd)
	framed := dnsTCPFrameMust(t, msg)
	// Independent of the decoder: a little-endian mutant of dnsTCPFrame still
	// round-trips through a matching decoder. The wire prefix must be
	// big-endian length-of-payload, not including itself.
	if got := binary.BigEndian.Uint16(framed[0:2]); got != uint16(len(msg)) {
		t.Fatalf("length prefix = %d, want %d (big-endian, not including the two length bytes)", got, len(msg))
	}
	if le := binary.LittleEndian.Uint16(framed[0:2]); le == uint16(len(msg)) && le != binary.BigEndian.Uint16(framed[0:2]) {
		t.Fatal("length prefix is little-endian")
	}
	if !bytes.Equal(framed[2:], msg) {
		t.Fatal("payload does not match the message")
	}
	got, err := readDNSTCPFrame(bytes.NewReader(framed))
	if err != nil {
		t.Fatalf("readDNSTCPFrame: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("round-trip payload mismatch")
	}
}

func TestDNSTCPFrameRefusesLengthZero(t *testing.T) {
	var hdr [2]byte
	_, err := readDNSTCPFrame(bytes.NewReader(hdr[:]))
	if err == nil {
		t.Fatal("n=0 was accepted as a message")
	}
	if !errors.Is(err, errDNSTCPLengthZero) {
		t.Fatalf("err = %v, want errDNSTCPLengthZero", err)
	}
	if _, err := dnsTCPFrame(nil); !errors.Is(err, errDNSTCPLengthZero) {
		t.Fatalf("dnsTCPFrame(nil) = %v, want errDNSTCPLengthZero", err)
	}
}

func TestDNSTCPFrameRefusesShorterThanDNSHeader(t *testing.T) {
	var framed [2 + 11]byte
	binary.BigEndian.PutUint16(framed[0:2], 11)
	_, err := readDNSTCPFrame(bytes.NewReader(framed[:]))
	if err == nil {
		t.Fatal("n=11 was accepted; a DNS header is 12 bytes")
	}
	if !errors.Is(err, errDNSTCPTooShort) {
		t.Fatalf("err = %v, want errDNSTCPTooShort", err)
	}
}

func TestDNSTCPFrameDoesNotDeliverAPrefixWhenThePeerClosesEarly(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	go func() {
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], 20)
		_, _ = a.Write(hdr[:])
		_, _ = a.Write([]byte{1, 2, 3, 4, 5})
		_ = a.Close()
	}()
	got, err := readDNSTCPFrame(b)
	if err == nil {
		t.Fatalf("read of a truncated body succeeded with %d bytes; must error rather than deliver a prefix", len(got))
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Logf("err = %v (want a short-read error, not a silent prefix)", err)
	}
	if got != nil {
		t.Fatalf("got a %d-byte slice on error; a reader that returns buf[:n] on EOF would pass a weaker test", len(got))
	}
}

func TestDNSTCPFrameRejectsAQueryWithQRSet(t *testing.T) {
	received := make(chan struct{}, 1)
	up, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer func() { _ = up.Close() }()
	go func() {
		c, aerr := up.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = readDNSTCPFrame(c)
		received <- struct{}{}
	}()

	r := newGatewayResolver(mustAddr(t, testGatewayInner), up.Addr().(*net.TCPAddr).AddrPort(), 2*time.Second, 4)
	addr := startTestResolverTCP(t, r)
	c, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	q := dnsQueryBytes(1)
	q[2] |= 0x80
	if err := writeDNSTCPFrame(c, q); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	_, _ = readDNSTCPFrame(c)
	select {
	case <-received:
		t.Fatal("QR=1 query was forwarded upstream")
	case <-time.After(300 * time.Millisecond):
	}
	if r.Stats().TcpAnswered != 0 {
		t.Fatalf("TcpAnswered = %d, want 0", r.Stats().TcpAnswered)
	}
}

func TestDNSTCPResponseDoesNotSetTC(t *testing.T) {
	const pad = 1024
	r := newGatewayResolver(mustAddr(t, testGatewayInner), stubTCPUpstream(t, pad), 2*time.Second, 4)
	addr := startTestResolverTCP(t, r)
	c, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	q := dnsQueryBytes(0x0c0c)
	if err := writeDNSTCPFrame(c, q); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readDNSTCPFrame(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) < dnsHeaderBytes {
		t.Fatalf("answer is %d bytes", len(got))
	}
	if got[2]&0x02 != 0 {
		t.Fatal("TCP answer has TC set; RFC 7766 forbids it, and a writer that does out[2]|=0x02 must fail this test")
	}
	if got[2]&0x80 == 0 {
		t.Fatal("TCP answer does not have QR set")
	}
}

func TestResolverTCPAnswersEndToEndThroughAStubUpstream(t *testing.T) {
	r := newGatewayResolver(mustAddr(t, testGatewayInner), stubTCPUpstream(t, 0), 2*time.Second, 4)
	addr := startTestResolverTCP(t, r)
	c, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	q := dnsQueryBytes(0x1111)
	if err := writeDNSTCPFrame(c, q); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readDNSTCPFrame(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got[0] != q[0] || got[1] != q[1] {
		t.Fatalf("transaction ID %02x%02x, want %02x%02x", got[0], got[1], q[0], q[1])
	}
	if got[2]&0x80 == 0 {
		t.Fatal("QR is not set")
	}
	st := r.Stats()
	if st.TcpAnswered != 1 {
		t.Errorf("TcpAnswered = %d, want 1", st.TcpAnswered)
	}
	if st.Answered != 0 {
		t.Errorf("Answered (UDP) = %d, want 0", st.Answered)
	}
}

func TestResolverTCPForwardsToUpstreamOverTCPNotUDP(t *testing.T) {
	udpOnly := stubUpstream(t, 0)
	r := newGatewayResolver(mustAddr(t, testGatewayInner), udpOnly, 700*time.Millisecond, 4)
	addr := startTestResolverTCP(t, r)
	c, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	q := dnsQueryBytes(0x2222)
	if err := writeDNSTCPFrame(c, q); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readDNSTCPFrame(c)
	if err != nil {
		t.Fatalf("read: %v (want a SERVFAIL from a TCP-to-UDP-only upstream, not a hang)", err)
	}
	if rcode := got[3] & 0x0f; rcode != 2 {
		t.Errorf("RCODE = %d, want 2 (SERVFAIL)", rcode)
	}
	if got[2]&0x02 != 0 {
		t.Error("TC is set on a TCP SERVFAIL")
	}
	st := r.Stats()
	if st.TcpUpstreamFailed != 1 {
		t.Errorf("TcpUpstreamFailed = %d, want 1", st.TcpUpstreamFailed)
	}
	if st.TcpAnswered != 0 {
		t.Errorf("TcpAnswered = %d, want 0", st.TcpAnswered)
	}
	if st.UpstreamFailed != 0 {
		t.Errorf("UpstreamFailed (UDP) = %d, want 0: TCP failures must not fold into the UDP counter", st.UpstreamFailed)
	}
}

func TestResolverTCPSharesInFlightCapsWithUDP(t *testing.T) {
	ours := mustAddr(t, testGatewayInner)
	r := newGatewayResolver(ours, stubUpstream(t, 0), 5*time.Second, dnsDefaultMaxInFlight)
	inner := newFakeInner(1400)
	d := newResolverDevice(inner, r, 1400)
	defer func() { _ = d.Close() }()
	addr := startTestResolverTCP(t, r)

	conns := make([]net.Conn, 0, dnsDefaultMaxInFlightPerClient)
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	for i := 0; i < dnsDefaultMaxInFlightPerClient; i++ {
		c, err := net.Dial("tcp4", addr.String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	waitTCPAccepted(t, r, uint64(dnsDefaultMaxInFlightPerClient))
	waitTokensHeld(t, r, dnsDefaultMaxInFlightPerClient)

	loopback := mustAddr(t, "127.0.0.1")
	pkt := udpPacket(t, loopback, ours, 40000, dnsPort, dnsQueryBytes(1))
	if _, err := d.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket same client: %v", err)
	}
	if got := r.Stats().Refused; got != 1 {
		t.Fatalf("Refused = %d, want 1: UDP from the TCP-holding client must share the per-client cap", got)
	}

	pkt2 := udpPacket(t, mustAddr(t, testClientInner2), ours, 40001, dnsPort, dnsQueryBytes(2))
	if _, err := d.WritePacket(pkt2); err != nil {
		t.Fatalf("WritePacket second client: %v", err)
	}
	_ = readReplyPump(t, d)
	st := r.Stats()
	if st.Answered != 1 {
		t.Errorf("Answered = %d, want 1: a second client must still be served", st.Answered)
	}
	if st.Refused != 1 {
		t.Errorf("Refused = %d, want 1 (only the over-share client)", st.Refused)
	}
}

func TestResolverTCPRefusesOverTheInFlightCeiling(t *testing.T) {
	// Ceiling 2 is below dnsDefaultMaxInFlightPerClient (8). All test
	// connections come from 127.0.0.1, so a process-wide ceiling of 32 would
	// never be reached: the per-client cap would refuse first and
	// TcpRefused+32 would not equal TcpAccepted. Same shape as
	// TestResolverDeviceRefusesOverTheInFlightCeiling.
	const ceiling = 2
	r := newGatewayResolver(mustAddr(t, testGatewayInner), stubTCPUpstream(t, 0), 5*time.Second, ceiling)
	addr := startTestResolverTCP(t, r)
	wantDial := ceiling + 4
	conns := make([]net.Conn, 0, wantDial)
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	for i := 0; i < wantDial; i++ {
		c, err := net.Dial("tcp4", addr.String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	waitTCPAccepted(t, r, uint64(wantDial))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r.Stats().TcpRefused >= 4 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	st := r.Stats()
	if st.TcpRefused < 4 {
		t.Errorf("TcpRefused = %d, want at least 4 with a ceiling of %d and %d accepts",
			st.TcpRefused, ceiling, wantDial)
	}
	if st.TcpRefused+uint64(ceiling) != st.TcpAccepted {
		t.Errorf("TcpRefused (%d) + ceiling (%d) should account for every accept (%d)",
			st.TcpRefused, ceiling, st.TcpAccepted)
	}
}

func TestResolverTCPReleasesTheSlotOnClose(t *testing.T) {
	r := newGatewayResolver(mustAddr(t, testGatewayInner), stubTCPUpstream(t, 0), 5*time.Second, 2)
	addr := startTestResolverTCP(t, r)
	for i := 0; i < 4; i++ {
		c, err := net.Dial("tcp4", addr.String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		q := dnsQueryBytes(uint16(0x3000 + i))
		if err := writeDNSTCPFrame(c, q); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if _, err := readDNSTCPFrame(c); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		_ = c.Close()
		waitTokensHeld(t, r, 0)
	}
	st := r.Stats()
	if st.TcpAnswered != 4 {
		t.Errorf("TcpAnswered = %d, want 4: tokens were not released between connections", st.TcpAnswered)
	}
	if st.TcpRefused != 0 {
		t.Errorf("TcpRefused = %d, want 0: a ceiling of 2 must not refuse 4 sequential connections if tokens are released", st.TcpRefused)
	}
}

func TestResolverTCPTimeoutOnASilentUpstream(t *testing.T) {
	up, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen silent upstream: %v", err)
	}
	defer func() { _ = up.Close() }()
	go func() {
		c, aerr := up.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = c.Close() }()
		time.Sleep(10 * time.Second)
	}()

	r := newGatewayResolver(mustAddr(t, testGatewayInner), up.Addr().(*net.TCPAddr).AddrPort(), 300*time.Millisecond, 4)
	addr := startTestResolverTCP(t, r)
	c, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	start := time.Now()
	if err := writeDNSTCPFrame(c, dnsQueryBytes(0x4040)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readDNSTCPFrame(c)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("client wait %s; want bounded by the 300ms resolver timeout", elapsed)
	}
	if rcode := got[3] & 0x0f; rcode != 2 {
		t.Errorf("RCODE = %d, want 2 (SERVFAIL) after a silent upstream", rcode)
	}
	if r.Stats().TcpUpstreamFailed != 1 {
		t.Errorf("TcpUpstreamFailed = %d, want 1", r.Stats().TcpUpstreamFailed)
	}

	_ = up.Close()
	_, aerr := up.Accept()
	if aerr == nil {
		t.Fatal("Accept on the closed silent upstream succeeded; Close did not unblock")
	}
}

func TestResolverTCPDoesNotLogTheQuery(t *testing.T) {
	capLog := &capturingResolverLog{}
	orig := resolverLog
	resolverLog = capLog
	t.Cleanup(func() { resolverLog = orig })

	r := newGatewayResolver(mustAddr(t, testGatewayInner), stubTCPUpstream(t, 0), 2*time.Second, 4)
	addr := startTestResolverTCP(t, r)
	c, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := writeDNSTCPFrame(c, dnsQueryBytes(0x6565)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := readDNSTCPFrame(c); err != nil {
		t.Fatalf("read: %v", err)
	}
	if logged := capLog.bytes(); len(logged) != 0 {
		t.Fatalf("resolverLog received %q during a query for example.com; per-query logging is forbidden", logged)
	}
}

func TestResolverTCPBindIsTheInnerAddressOnly(t *testing.T) {
	network, address := resolverTCPListenSpec(netip.MustParseAddr("10.64.0.1"), "53")
	if network != "tcp4" {
		t.Fatalf("network = %q, want tcp4 (never tcp, which is IPv6-mapped)", network)
	}
	if address != "10.64.0.1:53" {
		t.Fatalf("address = %q, want 10.64.0.1:53 (never 0.0.0.0:53 or :53)", address)
	}

	ln, err := listenResolverTCP("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 127.0.0.1:0: %v", err)
	}
	defer func() { _ = ln.Close() }()
	ta, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("Addr type %T", ln.Addr())
	}
	if !ta.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("bound %v, want 127.0.0.1", ta.IP)
	}
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.2:%d", ta.Port), 300*time.Millisecond)
	if err == nil {
		_ = c.Close()
		t.Fatal("dial 127.0.0.2 succeeded; a listener bound to 127.0.0.1 must not accept it")
	}
	t.Logf("MEASURED: dial 127.0.0.2:%d failed: %v", ta.Port, err)
}

func TestResolverTCPListenFailureDoesNotFallbackToWildcard(t *testing.T) {
	orig := resolverTCPListen
	t.Cleanup(func() { resolverTCPListen = orig })
	var calls []string
	resolverTCPListen = func(network, address string) (net.Listener, error) {
		calls = append(calls, network+" "+address)
		return nil, syscall.EADDRNOTAVAIL
	}
	_, err := listenResolverTCP("tcp4", "10.64.0.1:53")
	if err == nil {
		t.Fatal("listen succeeded on EADDRNOTAVAIL; must fail closed")
	}
	if !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("err = %v, want the original EADDRNOTAVAIL (a fallback bind would surface EACCES or success)", err)
	}
	if !strings.Contains(err.Error(), "0.0.0.0") {
		t.Fatalf("error %q does not name the wildcard it refused to fall back to", err)
	}
	if len(calls) != 1 || calls[0] != "tcp4 10.64.0.1:53" {
		t.Fatalf("listen calls = %v, want exactly [tcp4 10.64.0.1:53]", calls)
	}
}

func TestResolverTCPBindRejectsWildcardBeforeListen(t *testing.T) {
	orig := resolverTCPListen
	t.Cleanup(func() { resolverTCPListen = orig })
	var calls []string
	resolverTCPListen = func(network, address string) (net.Listener, error) {
		calls = append(calls, network+" "+address)
		return net.Listen(network, address)
	}
	for _, addr := range []string{"0.0.0.0:53", ":53", "0.0.0.0:0"} {
		_, err := listenResolverTCP("tcp4", addr)
		if err == nil {
			t.Errorf("%s: listen succeeded; wildcard must be refused before bind", addr)
		}
	}
	if len(calls) != 0 {
		t.Fatalf("resolverTCPListen was called for a wildcard: %v", calls)
	}
}

func TestResolverTCPNotStartedWithoutForward(t *testing.T) {
	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:1"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := startResolverTCP(ctx, r, false, mustAddr(t, testGatewayInner)); err != nil {
		t.Fatalf("startResolverTCP(forward=false) = %v, want nil", err)
	}
	if r.tcpListener() != nil {
		t.Fatal("started a TCP listener without -forward")
	}
	if r.Stats().TcpAccepted != 0 {
		t.Fatalf("TcpAccepted = %d, want 0", r.Stats().TcpAccepted)
	}
}

func TestResolverTCPStartedWithForward(t *testing.T) {
	origPort := resolverTCPListenPort
	resolverTCPListenPort = "0"
	t.Cleanup(func() { resolverTCPListenPort = origPort })

	r := newGatewayResolver(mustAddr(t, "127.0.0.1"), stubTCPUpstream(t, 0), 2*time.Second, 4)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := startResolverTCP(ctx, r, true, mustAddr(t, "127.0.0.1")); err != nil {
		t.Fatalf("startResolverTCP(forward=true) = %v", err)
	}
	ln := r.tcpListener()
	if ln == nil {
		t.Fatal("startResolverTCP(forward=true) did not publish a listener; a no-op mutant that returns nil without listening must fail here")
	}
	t.Cleanup(func() { _ = ln.Close() })
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial the listener startResolverTCP bound: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := writeDNSTCPFrame(c, dnsQueryBytes(0x5a5a)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readDNSTCPFrame(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got[2]&0x80 == 0 {
		t.Fatal("QR is not set")
	}
	if r.Stats().TcpAnswered != 1 {
		t.Fatalf("TcpAnswered = %d, want 1", r.Stats().TcpAnswered)
	}
}

func TestResolverOversizeUDPThenTCPCarriesTheFullAnswer(t *testing.T) {
	const mtu = 300
	const pad = 1024
	upstream := stubDualUpstream(t, pad)
	// 127.0.0.1 so startResolverTCP can bind without CAP_NET_BIND_SERVICE
	// or a tun address. A mutant that makes startResolverTCP a no-op fails
	// the TCP half; startTestResolverTCP would hide that (it binds itself).
	ours := mustAddr(t, "127.0.0.1")
	r := newGatewayResolver(ours, upstream, 2*time.Second, 4)
	inner := newFakeInner(mtu)
	d := newResolverDevice(inner, r, mtu)
	defer func() { _ = d.Close() }()

	query := dnsQueryBytes(0x0101)
	pkt := udpPacket(t, mustAddr(t, testClientInner), ours, 52000, dnsPort, query)
	if _, err := d.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	reply := readReplyPump(t, d)
	answer := reply[ipv4HeaderMinBytes+udpHeaderBytes:]
	if answer[2]&0x02 == 0 {
		t.Fatal("UDP oversize was not replaced by TC=1")
	}
	st := r.Stats()
	if st.Truncated != 1 {
		t.Errorf("Truncated = %d, want 1", st.Truncated)
	}
	if st.Answered != 0 {
		t.Errorf("Answered = %d, want 0", st.Answered)
	}

	origPort := resolverTCPListenPort
	resolverTCPListenPort = "0"
	t.Cleanup(func() { resolverTCPListenPort = origPort })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := startResolverTCP(ctx, r, true, ours); err != nil {
		t.Fatalf("startResolverTCP: %v", err)
	}
	ln := r.tcpListener()
	if ln == nil {
		t.Fatal("TCP half: startResolverTCP did not listen; a clamp-only mutant that never listens TCP cannot pass this half")
	}
	t.Cleanup(func() { _ = ln.Close() })
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := writeDNSTCPFrame(c, query); err != nil {
		t.Fatalf("write tcp: %v", err)
	}
	got, err := readDNSTCPFrame(c)
	if err != nil {
		t.Fatalf("read tcp: %v", err)
	}
	if got[2]&0x02 != 0 {
		t.Fatal("TCP answer has TC set")
	}
	if len(got) < len(query)+pad {
		t.Fatalf("TCP answer length %d, want the full padded payload (>= %d). A clamp-only mutant that never listens TCP cannot pass this half",
			len(got), len(query)+pad)
	}
	st = r.Stats()
	if st.TcpAnswered != 1 {
		t.Errorf("TcpAnswered = %d, want 1", st.TcpAnswered)
	}
	if st.Answered != 0 {
		t.Errorf("UDP Answered = %d, want still 0", st.Answered)
	}
	if st.Truncated != 1 {
		t.Errorf("Truncated = %d, want still 1", st.Truncated)
	}
}
