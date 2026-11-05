package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/tun"
)

// Helpers. testGatewayInner, testClientInner and mustAddr are the package's
// own, declared in gateway_test.go and forward_test.go; this file reuses them
// rather than introducing a second vocabulary for the same two addresses.

// testInnerNextHop is a router address distinct from both, for the flag
// validation that has to refuse it.
const testInnerNextHop = "10.64.0.254"

// dnsQueryBytes builds a minimal well-formed DNS query for "example.com" A.
func dnsQueryBytes(id uint16) []byte {
	msg := make([]byte, 0, 64)
	var hdr [dnsHeaderBytes]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	hdr[2] = 0x01 // RD
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	msg = append(msg, hdr[:]...)
	for _, label := range []string{"example", "com"} {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00)
	msg = append(msg, 0x00, 0x01) // QTYPE A
	msg = append(msg, 0x00, 0x01) // QCLASS IN
	return msg
}

// udpPacket wraps payload in IPv4+UDP headers with correct checksums.
func udpPacket(t *testing.T, src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	t.Helper()
	total := ipv4HeaderMinBytes + udpHeaderBytes + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = ipProtoUDP
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipv4Checksum(pkt[:ipv4HeaderMinBytes]))
	udp := pkt[ipv4HeaderMinBytes:]
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHeaderBytes+len(payload)))
	copy(udp[udpHeaderBytes:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(src, dst, udp))
	return pkt
}

func testResolver(t *testing.T, upstream netip.AddrPort) *gatewayResolver {
	t.Helper()
	return newGatewayResolver(mustAddr(t, testGatewayInner), upstream, 2*time.Second, 4)
}

func waitResolverStats(t *testing.T, r *gatewayResolver, ready func(resolverStats) bool) resolverStats {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if stats := r.Stats(); ready(stats) {
			return stats
		}
		time.Sleep(5 * time.Millisecond)
	}
	stats := r.Stats()
	t.Fatalf("resolver stats did not settle before timeout: %+v", stats)
	return stats
}

// stubUpstream starts a UDP server that echoes each query back as a response
// with QR set, optionally padded to force the oversize path. It returns the
// address and a cleanup func.
func stubUpstream(t *testing.T, pad int) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen stub upstream: %v", err)
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
			reply[2] |= 0x80 // QR
			reply = append(reply, make([]byte, pad)...)
			_, _ = pc.WriteToUDP(reply, from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// fakeInner is a closableDevice standing in for the reflector or the forward
// device: it records writes and parks its read side until Close.
type fakeInner struct {
	writes [][]byte
	mtu    int
	done   chan struct{}
}

func newFakeInner(mtu int) *fakeInner {
	return &fakeInner{mtu: mtu, done: make(chan struct{})}
}

func (f *fakeInner) WritePacket(pkt []byte) (int, error) {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	f.writes = append(f.writes, cp)
	return len(pkt), nil
}

func (f *fakeInner) ReadPacket([]byte) (int, error) {
	<-f.done
	return 0, errReflectorClosed
}

func (f *fakeInner) MTU() int { return f.mtu }

func (f *fakeInner) Close() error {
	select {
	case <-f.done:
	default:
		close(f.done)
	}
	return nil
}

var _ closableDevice = (*fakeInner)(nil)

// ---------------------------------------------------------------------------
// claim: what the responder takes, and everything it refuses
// ---------------------------------------------------------------------------

func TestResolverClaimsADNSQueryAddressedToTheGatewaysInnerAddress(t *testing.T) {
	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))
	query := dnsQueryBytes(0xbeef)
	pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, testGatewayInner), 34567, dnsPort, query)

	q, ok := r.claim(pkt)
	if !ok {
		t.Fatal("claim refused a well-formed DNS query addressed to -inner-v4")
	}
	if q.client != mustAddr(t, testClientInner) {
		t.Errorf("client = %v, want %v", q.client, testClientInner)
	}
	if q.clientPort != 34567 {
		t.Errorf("clientPort = %d, want 34567", q.clientPort)
	}
	if string(q.payload) != string(query) {
		t.Error("payload does not round-trip the DNS message")
	}
}

func TestResolverClaimCopiesThePayloadOutOfTheCallersBuffer(t *testing.T) {
	// The delivery path reuses its buffer the moment WritePacket returns, and
	// the query outlives the call by a whole upstream round trip.
	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))
	pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, testGatewayInner), 5300, dnsPort, dnsQueryBytes(0x1234))
	q, ok := r.claim(pkt)
	if !ok {
		t.Fatal("claim refused a well-formed query")
	}
	for i := range pkt {
		pkt[i] = 0xff
	}
	if q.payload[0] != 0x12 || q.payload[1] != 0x34 {
		t.Fatal("payload aliases the caller's buffer; scribbling on pkt corrupted the claimed query")
	}
}

func TestResolverRefusesEverythingItMustNotClaim(t *testing.T) {
	gw := mustAddr(t, testGatewayInner)
	client := mustAddr(t, testClientInner)
	query := dnsQueryBytes(1)

	cases := []struct {
		name string
		pkt  func() []byte
	}{
		{"another inner address", func() []byte {
			return udpPacket(t, client, mustAddr(t, "10.64.0.53"), 1000, dnsPort, query)
		}},
		{"a public address", func() []byte {
			return udpPacket(t, client, mustAddr(t, "9.9.9.9"), 1000, dnsPort, query)
		}},
		{"the AdGuard address on awg0", func() []byte {
			return udpPacket(t, client, mustAddr(t, "10.8.1.1"), 1000, dnsPort, query)
		}},
		{"a port that is not 53", func() []byte {
			return udpPacket(t, client, gw, 1000, 5353, query)
		}},
		{"TCP rather than UDP", func() []byte {
			p := udpPacket(t, client, gw, 1000, dnsPort, query)
			p[9] = 6
			return p
		}},
		{"a DNS response rather than a query", func() []byte {
			resp := dnsQueryBytes(1)
			resp[2] |= 0x80
			return udpPacket(t, client, gw, 1000, dnsPort, resp)
		}},
		{"a payload shorter than a DNS header", func() []byte {
			return udpPacket(t, client, gw, 1000, dnsPort, []byte{1, 2, 3})
		}},
		{"a non-initial fragment", func() []byte {
			p := udpPacket(t, client, gw, 1000, dnsPort, query)
			binary.BigEndian.PutUint16(p[6:8], 0x0001)
			return p
		}},
		{"a first fragment with more to follow", func() []byte {
			p := udpPacket(t, client, gw, 1000, dnsPort, query)
			binary.BigEndian.PutUint16(p[6:8], 0x2000)
			return p
		}},
		{"a UDP length field larger than the buffer", func() []byte {
			p := udpPacket(t, client, gw, 1000, dnsPort, query)
			binary.BigEndian.PutUint16(p[ipv4HeaderMinBytes+4:ipv4HeaderMinBytes+6], 4000)
			return p
		}},
		{"a UDP length field shorter than the UDP header", func() []byte {
			p := udpPacket(t, client, gw, 1000, dnsPort, query)
			binary.BigEndian.PutUint16(p[ipv4HeaderMinBytes+4:ipv4HeaderMinBytes+6], 6)
			return p
		}},
		{"a mismatched IPv4 total length field", func() []byte {
			p := udpPacket(t, client, gw, 1000, dnsPort, query)
			binary.BigEndian.PutUint16(p[2:4], 100)
			return p
		}},
		{"a client source port of zero", func() []byte {
			return udpPacket(t, client, gw, 0, dnsPort, query)
		}},
		{"a source equal to our own address", func() []byte {
			return udpPacket(t, gw, gw, 1000, dnsPort, query)
		}},
		{"an IPv6 packet", func() []byte {
			p := udpPacket(t, client, gw, 1000, dnsPort, query)
			p[0] = 0x60
			return p
		}},
		{"a truncated header", func() []byte {
			return udpPacket(t, client, gw, 1000, dnsPort, query)[:12]
		}},
		{"a bad IHL", func() []byte {
			p := udpPacket(t, client, gw, 1000, dnsPort, query)
			p[0] = 0x4f
			return p
		}},
	}

	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := r.claim(tc.pkt()); ok {
				t.Fatalf("claim accepted %s; it must pass through to the wrapped device instead", tc.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The reply packet, which winn3/tun must be willing to carry
// ---------------------------------------------------------------------------

// TestResolverReplyPassesTheTunnelsOutboundRule is the load-bearing test of
// this file. It asserts the exact property that decides WHERE the resolver may
// live: a reply must be sourced from this endpoint's own assignment or
// winn3/tun refuses to carry it. See resolve.go's header.
func TestResolverReplyPassesTheTunnelsOutboundRule(t *testing.T) {
	gw := mustAddr(t, testGatewayInner)
	client := mustAddr(t, testClientInner)
	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))

	reply := r.buildReply(dnsQuery{client: client, clientPort: 40000}, dnsQueryBytes(7))

	src, dst, ok := ipv4SourceDestination(reply)
	if !ok {
		t.Fatal("the reply is not parseable as IPv4")
	}
	if src != gw {
		t.Fatalf("reply source is %v; winn3/tun's outbound rule requires exactly the "+
			"endpoint's own assignment %v, and this is why the resolver cannot live at "+
			"another inner address", src, gw)
	}
	if dst != client {
		t.Fatalf("reply destination is %v, want the asking client %v", dst, client)
	}
	if dst == gw {
		t.Fatal("outbound rule also requires dst != ours")
	}
}

func TestResolverReplyChecksumsVerify(t *testing.T) {
	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))
	client := mustAddr(t, testClientInner)
	payload := dnsQueryBytes(0x4242)
	reply := r.buildReply(dnsQuery{client: client, clientPort: 40000}, payload)

	// A correct IPv4 header sums to zero over itself.
	if got := ipv4Checksum(reply[:ipv4HeaderMinBytes]); got != 0 {
		t.Errorf("IPv4 header checksum does not self-verify: got %#04x, want 0", got)
	}
	// Same for UDP, including the pseudo-header.
	udp := reply[ipv4HeaderMinBytes:]
	if got := udpChecksum(mustAddr(t, testGatewayInner), client, udp); got != 0xffff {
		t.Errorf("UDP checksum does not self-verify: got %#04x, want 0xffff", got)
	}
	if binary.BigEndian.Uint16(udp[0:2]) != dnsPort {
		t.Error("reply source port is not 53")
	}
	if binary.BigEndian.Uint16(udp[2:4]) != 40000 {
		t.Error("reply destination port is not the client's source port")
	}
	if binary.BigEndian.Uint16(udp[4:6]) != uint16(udpHeaderBytes+len(payload)) {
		t.Error("UDP length field is wrong")
	}
	if int(binary.BigEndian.Uint16(reply[2:4])) != len(reply) {
		t.Error("IPv4 total length field does not match the packet")
	}
	if reply[6]&0x40 == 0 {
		t.Error("DF is not set; this responder never fragments")
	}
}

func TestResolverReplyIsAddressedBackToWhoeverAsked(t *testing.T) {
	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))
	for _, who := range []string{"10.64.0.2", "10.64.0.250", "10.64.9.9"} {
		client := mustAddr(t, who)
		reply := r.buildReply(dnsQuery{client: client, clientPort: 1}, dnsQueryBytes(1))
		_, dst, _ := ipv4SourceDestination(reply)
		if dst != client {
			t.Errorf("reply for %s went to %v", who, dst)
		}
	}
}

// ---------------------------------------------------------------------------
// Truncation
// ---------------------------------------------------------------------------

func TestDNSQuestionSectionEnd(t *testing.T) {
	q := dnsQueryBytes(1)
	end, ok := dnsQuestionSectionEnd(q)
	if !ok {
		t.Fatal("refused a well-formed question section")
	}
	if end != len(q) {
		t.Fatalf("end = %d, want %d (the whole query is header + one question)", end, len(q))
	}
}

func TestDNSQuestionSectionEndRefusesWhatItWillNotParse(t *testing.T) {
	cases := map[string][]byte{
		"a compression pointer in the question": func() []byte {
			q := dnsQueryBytes(1)
			q[dnsHeaderBytes] = 0xc0
			return q
		}(),
		"a reserved label length": func() []byte {
			q := dnsQueryBytes(1)
			q[dnsHeaderBytes] = 0x80
			return q
		}(),
		"QDCOUNT of 0": func() []byte {
			q := dnsQueryBytes(1)
			binary.BigEndian.PutUint16(q[4:6], 0)
			return q
		}(),
		"QDCOUNT of 2": func() []byte {
			q := dnsQueryBytes(1)
			binary.BigEndian.PutUint16(q[4:6], 2)
			return q
		}(),
		"a label running past the buffer": func() []byte {
			q := dnsQueryBytes(1)
			q[dnsHeaderBytes] = 0x3f
			return q
		}(),
		"a message shorter than a header": {1, 2, 3},
		"a name with no room for QTYPE/QCLASS": func() []byte {
			q := dnsQueryBytes(1)
			return q[:len(q)-3]
		}(),
	}
	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, ok := dnsQuestionSectionEnd(msg); ok {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

func TestDNSTruncatedAnswerIsAWellFormedTCResponse(t *testing.T) {
	query := dnsQueryBytes(0xabcd)
	query[3] |= 0x10 // CD (checking disabled) set by the client
	out, ok := dnsTruncatedAnswer(query)
	if !ok {
		t.Fatal("could not synthesise a TC=1 answer for a well-formed query")
	}
	if out[0] != 0xab || out[1] != 0xcd {
		t.Error("transaction ID was not preserved")
	}
	if out[2]&0x80 == 0 {
		t.Error("QR is not set; a response must have it")
	}
	if out[2]&0x02 == 0 {
		t.Error("TC is not set; that is the whole point of this message")
	}
	if out[2]&0x01 == 0 {
		t.Error("RD was not preserved from the query")
	}
	if out[3]&0x80 == 0 {
		t.Error("RA is not set")
	}
	if out[3]&0x10 == 0 {
		t.Error("CD was not echoed from the query; a client's policy was silently cleared")
	}
	if binary.BigEndian.Uint16(out[4:6]) != 1 {
		t.Error("QDCOUNT should still be 1")
	}
	for name, off := range map[string]int{"ANCOUNT": 6, "NSCOUNT": 8, "ARCOUNT": 10} {
		if binary.BigEndian.Uint16(out[off:off+2]) != 0 {
			t.Errorf("%s is not zero; a truncated answer carries no records", name)
		}
	}
	if string(out[dnsHeaderBytes:]) != string(query[dnsHeaderBytes:]) {
		t.Error("the question section was not copied back verbatim")
	}
}

func TestDNSTruncatedAnswerRefusesAQueryItCannotParse(t *testing.T) {
	q := dnsQueryBytes(1)
	q[dnsHeaderBytes] = 0xc0
	if _, ok := dnsTruncatedAnswer(q); ok {
		t.Fatal("synthesised an answer from a question section it could not parse")
	}
}

// ---------------------------------------------------------------------------
// The device wrapper
// ---------------------------------------------------------------------------

func TestResolverDevicePassesNonDNSThroughUntouched(t *testing.T) {
	inner := newFakeInner(1400)
	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))
	d := newResolverDevice(inner, r, 1400)
	defer func() { _ = d.Close() }()

	// Ordinary traffic to somewhere on the internet.
	pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, "1.1.1.1"), 1234, 443, []byte("hello"))
	n, err := d.WritePacket(pkt)
	if err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if n != len(pkt) {
		t.Errorf("WritePacket returned %d, want %d", n, len(pkt))
	}
	if len(inner.writes) != 1 {
		t.Fatalf("wrapped device saw %d writes, want 1: non-DNS traffic must pass through", len(inner.writes))
	}
	if string(inner.writes[0]) != string(pkt) {
		t.Error("the packet was modified on the way through")
	}
	if got := r.Stats().Claimed; got != 0 {
		t.Errorf("Claimed = %d, want 0", got)
	}
}

func TestResolverDeviceDoesNotPassAClaimedQueryToTheWrappedDevice(t *testing.T) {
	inner := newFakeInner(1400)
	r := testResolver(t, stubUpstream(t, 0))
	d := newResolverDevice(inner, r, 1400)
	defer func() { _ = d.Close() }()

	pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, testGatewayInner), 1234, dnsPort, dnsQueryBytes(9))
	if _, err := d.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if len(inner.writes) != 0 {
		t.Fatalf("wrapped device saw %d writes; a claimed query must not reach it", len(inner.writes))
	}
	if got := r.Stats().Claimed; got != 1 {
		t.Errorf("Claimed = %d, want 1", got)
	}
}

func TestResolverDeviceAnswersEndToEndThroughAStubUpstream(t *testing.T) {
	inner := newFakeInner(1400)
	r := testResolver(t, stubUpstream(t, 0))
	d := newResolverDevice(inner, r, 1400)
	defer func() { _ = d.Close() }()

	query := dnsQueryBytes(0x7f7f)
	pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, testGatewayInner), 51000, dnsPort, query)
	if _, err := d.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	buf := make([]byte, tun.MaxIPPacket)
	done := make(chan int, 1)
	go func() {
		n, rerr := d.ReadPacket(buf)
		if rerr != nil {
			done <- -1
			return
		}
		done <- n
	}()
	var n int
	select {
	case n = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no reply arrived within 5s")
	}
	if n <= 0 {
		t.Fatal("ReadPacket returned an error rather than the reply")
	}
	reply := buf[:n]

	src, dst, ok := ipv4SourceDestination(reply)
	if !ok {
		t.Fatal("reply is not IPv4")
	}
	if src != mustAddr(t, testGatewayInner) || dst != mustAddr(t, testClientInner) {
		t.Fatalf("reply addresses are %v -> %v, want %v -> %v",
			src, dst, testGatewayInner, testClientInner)
	}
	udp := reply[ipv4HeaderMinBytes:]
	if binary.BigEndian.Uint16(udp[2:4]) != 51000 {
		t.Error("reply did not go back to the client's source port")
	}
	answer := udp[udpHeaderBytes:]
	if answer[0] != 0x7f || answer[1] != 0x7f {
		t.Error("transaction ID does not match the query")
	}
	if answer[2]&0x80 == 0 {
		t.Error("the answer does not have QR set")
	}
	stats := waitResolverStats(t, r, func(stats resolverStats) bool {
		return stats.Answered == 1
	})
	if got := stats.Answered; got != 1 {
		t.Errorf("Answered = %d, want 1", got)
	}
}

func TestResolverDeviceTruncatesAnAnswerThatWouldNotFitTheInnerMTU(t *testing.T) {
	const mtu = 300
	inner := newFakeInner(mtu)
	// Pad the stub's reply well past the MTU budget.
	r := testResolver(t, stubUpstream(t, 1024))
	d := newResolverDevice(inner, r, mtu)
	defer func() { _ = d.Close() }()

	pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, testGatewayInner), 52000, dnsPort, dnsQueryBytes(0x0101))
	if _, err := d.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	buf := make([]byte, tun.MaxIPPacket)
	done := make(chan int, 1)
	go func() {
		n, rerr := d.ReadPacket(buf)
		if rerr != nil {
			done <- -1
			return
		}
		done <- n
	}()
	var n int
	select {
	case n = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no reply arrived within 5s")
	}
	if n <= 0 {
		t.Fatal("ReadPacket returned an error rather than a truncated reply")
	}
	if n > mtu {
		t.Fatalf("emitted a %d-byte packet on a %d-byte MTU", n, mtu)
	}
	answer := buf[ipv4HeaderMinBytes+udpHeaderBytes : n]
	if answer[2]&0x02 == 0 {
		t.Error("the oversize answer was not replaced by a TC=1 response")
	}
	stats := waitResolverStats(t, r, func(stats resolverStats) bool {
		return stats.Truncated == 1
	})
	if got := stats.Truncated; got != 1 {
		t.Errorf("Truncated = %d, want 1", got)
	}
}

// readReplyPump is a helper: it reads one packet off the device with a timeout
// and returns the bytes, or fails the test if none arrives.
func readReplyPump(t *testing.T, d *resolverDevice) []byte {
	t.Helper()
	buf := make([]byte, tun.MaxIPPacket)
	done := make(chan int, 1)
	go func() {
		n, rerr := d.ReadPacket(buf)
		if rerr != nil {
			done <- -1
			return
		}
		done <- n
	}()
	var n int
	select {
	case n = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no reply arrived within 5s")
	}
	if n <= 0 {
		t.Fatal("ReadPacket returned an error rather than a reply")
	}
	return buf[:n]
}

// TestResolverReplyOverTheReadCapTakesTheTruncationPath pins MEDIUM 1: a reply
// larger than dnsUpstreamReadCap must be treated as "does not fit" and answered
// TC=1, never delivered as a silently truncated datagram whose checksum verifies
// over a fragment of the real message. This only bites when the MTU budget is
// LARGE (a jumbo -path-mtu): at ordinary MTUs the budget is below 4096 so the
// oversize check catches it by accident, masking the read-cap defect precisely
// as the reviewer described. A 5000-byte MTU gives a ~4972-byte budget that a
// whole-4096 answer WOULD fit, so only the read-cap guard can force TC here.
func TestResolverReplyOverTheReadCapTakesTheTruncationPath(t *testing.T) {
	const mtu = 5000
	if mtu-ipv4HeaderMinBytes-udpHeaderBytes < dnsUpstreamReadCap {
		t.Fatal("test premise broken: the MTU budget must exceed dnsUpstreamReadCap or the oversize check masks the read-cap guard")
	}
	inner := newFakeInner(mtu)
	// Pad far past dnsUpstreamReadCap (4096): the query is ~38 bytes, +4200
	// makes the reply ~4238, so exchange's Read fills its 4096-byte buffer.
	r := testResolver(t, stubUpstream(t, 4200))
	d := newResolverDevice(inner, r, mtu)
	defer func() { _ = d.Close() }()

	pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, testGatewayInner), 53001, dnsPort, dnsQueryBytes(0xA1))
	if _, err := d.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	reply := readReplyPump(t, d)
	if len(reply) > mtu {
		t.Fatalf("emitted a %d-byte packet on a %d-byte MTU", len(reply), mtu)
	}
	answer := reply[ipv4HeaderMinBytes+udpHeaderBytes:]
	if answer[2]&0x02 == 0 {
		t.Error("an answer that overflows the read cap was not replaced by a TC=1 response")
	}
	if answer[2]&0x80 == 0 {
		t.Error("TC=1 reply does not have QR set")
	}
	st := waitResolverStats(t, r, func(stats resolverStats) bool {
		return stats.Truncated == 1
	})
	if st.Truncated != 1 {
		t.Errorf("Truncated = %d, want 1", st.Truncated)
	}
	if st.UpstreamFailed != 0 {
		t.Errorf("UpstreamFailed = %d, want 0: an oversize answer is truncation, not an upstream failure", st.UpstreamFailed)
	}
	if st.Answered != 0 {
		t.Errorf("Answered = %d, want 0: a truncated answer is not an answer", st.Answered)
	}
}

// ---------------------------------------------------------------------------
// Upstream failure: a synthesised SERVFAIL rather than silence
//
// For a censorship-circumvention product silence is indistinguishable from
// blocking, so an upstream this responder cannot reach must produce a fast,
// diagnosable RCODE=2 instead of a stub timeout under a green "Connected"
// light. The tests below drive each arm of exchange()'s error path.
//
// Every failure mode here is induced on loopback or by a dial that fails
// outright. None of them puts a datagram on the wire: an unroutable public
// address such as TEST-NET-1 does NOT fail locally, it binds the host's own
// address and egresses, which is why none is used here.
// ---------------------------------------------------------------------------

// assertSERVFAIL checks that reply is a well-formed SERVFAIL response to query,
// addressed back to the asking client so the client's stack will accept it.
//
// The TC assertion is the load-bearing one against a careless implementation:
// SERVFAIL must NOT reuse TC=1, because TC sends a stub to TCP/53 and claim()
// takes UDP only, so a TC-flavoured failure would send the client somewhere
// this gateway does not answer.
func assertSERVFAIL(t *testing.T, reply, query []byte, clientPort uint16) {
	t.Helper()
	src, dst, ok := ipv4SourceDestination(reply)
	if !ok {
		t.Fatal("the synthesised failure reply is not parseable as IPv4")
	}
	if src != mustAddr(t, testGatewayInner) || dst != mustAddr(t, testClientInner) {
		t.Fatalf("SERVFAIL addresses are %v -> %v, want %v -> %v",
			src, dst, testGatewayInner, testClientInner)
	}
	if got := ipv4Checksum(reply[:ipv4HeaderMinBytes]); got != 0 {
		t.Errorf("IPv4 header checksum does not self-verify: got %#04x, want 0", got)
	}
	udp := reply[ipv4HeaderMinBytes:]
	if got := udpChecksum(src, dst, udp); got != 0xffff {
		t.Errorf("UDP checksum does not self-verify: got %#04x, want 0xffff", got)
	}
	if binary.BigEndian.Uint16(udp[0:2]) != dnsPort {
		t.Error("SERVFAIL source port is not 53")
	}
	if got := binary.BigEndian.Uint16(udp[2:4]); got != clientPort {
		t.Errorf("SERVFAIL went to port %d, want the client's source port %d", got, clientPort)
	}
	msg := udp[udpHeaderBytes:]
	if len(msg) < dnsHeaderBytes {
		t.Fatalf("SERVFAIL payload is %d bytes, shorter than a DNS header", len(msg))
	}
	if msg[0] != query[0] || msg[1] != query[1] {
		t.Errorf("transaction ID %02x%02x does not echo the query's %02x%02x; a stub discards a mismatched ID",
			msg[0], msg[1], query[0], query[1])
	}
	if msg[2]&0x80 == 0 {
		t.Error("QR is not set; a response must have it")
	}
	if msg[2]&0x02 != 0 {
		t.Error("TC is set on a SERVFAIL; an upstream failure is not a truncation, and TC=1 would " +
			"send the stub to TCP/53, which this gateway does not answer")
	}
	if msg[2]&0x01 != query[2]&0x01 {
		t.Error("RD was not preserved from the query")
	}
	if msg[3]&0x80 == 0 {
		t.Error("RA is not set")
	}
	if msg[3]&0x10 != query[3]&0x10 {
		t.Error("CD was not echoed from the query; the client's checking-disabled policy was silently changed")
	}
	if rcode := msg[3] & 0x0f; rcode != 2 {
		t.Errorf("RCODE = %d, want 2 (SERVFAIL); anything else tells the stub the wrong thing "+
			"about why the name did not resolve", rcode)
	}
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		t.Error("QDCOUNT should still be 1: the question is echoed back")
	}
	for name, off := range map[string]int{"ANCOUNT": 6, "NSCOUNT": 8, "ARCOUNT": 10} {
		if binary.BigEndian.Uint16(msg[off:off+2]) != 0 {
			t.Errorf("%s is not zero; a SERVFAIL carries no records", name)
		}
	}
	if string(msg[dnsHeaderBytes:]) != string(query[dnsHeaderBytes:]) {
		t.Error("the question section was not echoed verbatim")
	}
}

// servfailFixture stands up a resolver device pointed at upstream and writes one
// claimed query into it, returning the resolver, the device and the query bytes.
// The query has CD set so assertSERVFAIL's echo check is actually exercised.
func servfailFixture(t *testing.T, upstream netip.AddrPort, timeout time.Duration, clientPort, id uint16) (*gatewayResolver, *resolverDevice, []byte) {
	t.Helper()
	inner := newFakeInner(1400)
	r := newGatewayResolver(mustAddr(t, testGatewayInner), upstream, timeout, 4)
	d := newResolverDevice(inner, r, 1400)
	t.Cleanup(func() { _ = d.Close() })

	query := dnsQueryBytes(id)
	query[3] |= 0x10 // CD set by the client
	pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, testGatewayInner), clientPort, dnsPort, query)
	if _, err := d.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	return r, d, query
}

// assertFailureCounters pins that a synthesised SERVFAIL does not disturb the
// other counters: the failure is still counted as an upstream failure, and it is
// neither an answer, nor a truncation, nor a refusal.
func assertFailureCounters(t *testing.T, st resolverStats) {
	t.Helper()
	if st.UpstreamFailed != 1 {
		t.Errorf("UpstreamFailed = %d, want 1: answering SERVFAIL must not stop the failure being counted", st.UpstreamFailed)
	}
	if st.Answered != 0 {
		t.Errorf("Answered = %d, want 0: a SERVFAIL is not an answer", st.Answered)
	}
	if st.Truncated != 0 {
		t.Errorf("Truncated = %d, want 0: an upstream failure is not a truncation", st.Truncated)
	}
	if st.Refused != 0 {
		t.Errorf("Refused = %d, want 0: nothing here reached the in-flight cap", st.Refused)
	}
	if st.Dropped != 0 {
		t.Errorf("Dropped = %d, want 0: the SERVFAIL had an empty inbox to queue into", st.Dropped)
	}
}

// TestResolverAnswersSERVFAILWhenTheUpstreamTimesOut drives the deadline arm: a
// socket that accepts the datagram and never replies, which is what a black-holed
// or overloaded upstream looks like from here.
func TestResolverAnswersSERVFAILWhenTheUpstreamTimesOut(t *testing.T) {
	dead, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = dead.Close() }()

	const port = 56001
	r, d, query := servfailFixture(t, dead.LocalAddr().(*net.UDPAddr).AddrPort(), 300*time.Millisecond, port, 0x5151)
	assertSERVFAIL(t, readReplyPump(t, d), query, port)
	assertFailureCounters(t, r.Stats())
}

// TestResolverAnswersSERVFAILWhenTheUpstreamRefuses drives the ECONNREFUSED arm.
// Binding a loopback port and releasing it makes the kernel answer the query
// datagram with ICMP port unreachable, which a connected UDP socket surfaces as
// a read error rather than a timeout.
//
// The resolver timeout is kept short on purpose: on a host that does not deliver
// the ICMP error, this degrades to the deadline arm instead, and the assertion is
// deliberately the same either way -- the client must hear SERVFAIL.
func TestResolverAnswersSERVFAILWhenTheUpstreamRefuses(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closed := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	if cerr := pc.Close(); cerr != nil {
		t.Fatalf("close the stub to free its port: %v", cerr)
	}

	const port = 56002
	r, d, query := servfailFixture(t, closed, 700*time.Millisecond, port, 0x6262)
	assertSERVFAIL(t, readReplyPump(t, d), query, port)
	assertFailureCounters(t, r.Stats())
}

// TestResolverAnswersSERVFAILWhenTheUpstreamCannotBeDialled drives the dial-failure
// arm, the one a network-unreachable upstream takes: net.DialUDP returns before any
// datagram exists, so exchange fails without ever having sent anything.
//
// 0.0.0.0:0 is used because it fails at dial with no egress at all. An unroutable
// public address would NOT exercise this arm -- measured, it binds the host's own
// address, egresses, and times out, which is both the wrong arm and a packet on
// the wire this lane is not permitted to send.
func TestResolverAnswersSERVFAILWhenTheUpstreamCannotBeDialled(t *testing.T) {
	const port = 56003
	r, d, query := servfailFixture(t, netip.MustParseAddrPort("0.0.0.0:0"), 2*time.Second, port, 0x7373)
	assertSERVFAIL(t, readReplyPump(t, d), query, port)
	assertFailureCounters(t, r.Stats())
}

// TestResolverInFlightCapRefusalStaysSilent is the regression guard for the one
// distinction the SERVFAIL change must never collapse.
//
// An in-flight-cap refusal is LOCAL, TRANSIENT overload: the query was never put
// to the upstream, and a stub retry a moment later may genuinely succeed. Turning
// it into SERVFAIL would tell the client to give up on a query that would have
// worked. Only an upstream exchange that actually failed becomes SERVFAIL.
//
// Both arms of the cap are covered, because a later refactor could collapse
// either one: the process-wide semaphore and a single session's own share.
//
// NOTE for anyone reading the evidence: this test passes both BEFORE and AFTER
// the SERVFAIL change, by design -- it guards a behaviour that must not change.
// Only the three tests above were red beforehand.
func TestResolverInFlightCapRefusalStaysSilent(t *testing.T) {
	cases := []struct {
		name        string
		maxInFlight int
		queries     int
		wantRefused uint64
	}{
		{"the process-wide ceiling", 1, 5, 4},
		{"one session's own share", dnsDefaultMaxInFlight, dnsDefaultMaxInFlightPerClient + 2, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := newFakeInner(1400)
			// An upstream that accepts and never answers, with a timeout far
			// longer than the silence window below. That gap is what makes the
			// observation sound: any packet appearing inside the window can only
			// have come from the refusal path, never from an exchange that timed
			// out on its own.
			dead, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = dead.Close() }()
			r := newGatewayResolver(mustAddr(t, testGatewayInner),
				dead.LocalAddr().(*net.UDPAddr).AddrPort(), 5*time.Second, tc.maxInFlight)
			d := newResolverDevice(inner, r, 1400)
			defer func() { _ = d.Close() }()

			for i := 0; i < tc.queries; i++ {
				pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, testGatewayInner),
					uint16(57000+i), dnsPort, dnsQueryBytes(uint16(0x8000+i)))
				if _, werr := d.WritePacket(pkt); werr != nil {
					t.Fatalf("WritePacket: %v", werr)
				}
			}
			if got := r.Stats().Refused; got != tc.wantRefused {
				t.Fatalf("Refused = %d, want %d; the premise of this test needs real refusals to observe",
					got, tc.wantRefused)
			}

			expectNoReplyWithin(t, d, 300*time.Millisecond)

			st := r.Stats()
			if st.UpstreamFailed != 0 {
				t.Errorf("UpstreamFailed = %d, want 0: a cap refusal is local pressure, not an upstream failure", st.UpstreamFailed)
			}
			if st.Answered != 0 || st.Truncated != 0 {
				t.Errorf("Answered = %d and Truncated = %d, want 0 and 0", st.Answered, st.Truncated)
			}
		})
	}
}

// expectNoReplyWithin fails if the device emits anything at all inside window.
func expectNoReplyWithin(t *testing.T, d *resolverDevice, window time.Duration) {
	t.Helper()
	buf := make([]byte, tun.MaxIPPacket)
	got := make(chan int, 1)
	go func() {
		n, rerr := d.ReadPacket(buf)
		if rerr != nil {
			got <- -1
			return
		}
		got <- n
	}()
	select {
	case n := <-got:
		if n <= 0 {
			t.Fatal("ReadPacket errored while proving the refusal path stays silent")
		}
		rcode := -1
		if msg := buf[ipv4HeaderMinBytes+udpHeaderBytes : n]; len(msg) >= dnsHeaderBytes {
			rcode = int(msg[3] & 0x0f)
		}
		t.Fatalf("the in-flight cap emitted a %d-byte reply (RCODE=%d); this path MUST stay silent. "+
			"A cap refusal is transient local overload where a stub retry may succeed, so answering "+
			"SERVFAIL would tell the client to give up on a query that would have worked", n, rcode)
	case <-time.After(window):
	}
}

// TestResolverSemaphoreTokensAreReleasedAfterAnAnswer pins that the in-flight
// semaphore returns its token once an exchange completes. The existing suite
// only exercised exhaustion; without release, repeated queries against an
// answering upstream would accumulate refusals after the first ceiling.
func TestResolverSemaphoreTokensAreReleasedAfterAnAnswer(t *testing.T) {
	stub, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen stub: %v", err)
	}
	defer func() { _ = stub.Close() }()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, rerr := stub.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			reply := append([]byte(nil), buf[:n]...)
			reply[2] |= 0x80
			_, _ = stub.WriteToUDP(reply, from)
		}
	}()

	// A tight ceiling of 2 with an upstream that answers quickly: four
	// sequential queries must all be answered, proving tokens come back.
	r := newGatewayResolver(mustAddr(t, testGatewayInner), stub.LocalAddr().(*net.UDPAddr).AddrPort(), 5*time.Second, 2)
	inner := newFakeInner(1400)
	d := newResolverDevice(inner, r, 1400)
	defer func() { _ = d.Close() }()

	for i := 0; i < 4; i++ {
		pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, testGatewayInner),
			uint16(55000+i), dnsPort, dnsQueryBytes(uint16(0x3000+i)))
		if _, werr := d.WritePacket(pkt); werr != nil {
			t.Fatalf("WritePacket: %v", werr)
		}
		readReplyPump(t, d)
	}
	st := r.Stats()
	if st.Answered != 4 {
		t.Errorf("Answered = %d, want 4: tokens were not released between exchanges", st.Answered)
	}
	if st.Refused != 0 {
		t.Errorf("Refused = %d, want 0: a ceiling of 2 must not refuse 4 sequential queries if tokens are released", st.Refused)
	}
}

func TestResolverDeviceRefusesOverTheInFlightCeiling(t *testing.T) {
	inner := newFakeInner(1400)
	// An upstream that never answers: every query holds its token until the
	// timeout, which is what fills the semaphore.
	dead, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = dead.Close() }()
	r := newGatewayResolver(mustAddr(t, testGatewayInner), dead.LocalAddr().(*net.UDPAddr).AddrPort(), 3*time.Second, 2)
	d := newResolverDevice(inner, r, 1400)
	defer func() { _ = d.Close() }()

	for i := 0; i < 6; i++ {
		pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, testGatewayInner),
			uint16(40000+i), dnsPort, dnsQueryBytes(uint16(i)))
		if _, werr := d.WritePacket(pkt); werr != nil {
			t.Fatalf("WritePacket: %v", werr)
		}
	}
	st := r.Stats()
	if st.Claimed != 6 {
		t.Errorf("Claimed = %d, want 6", st.Claimed)
	}
	if st.Refused < 4 {
		t.Errorf("Refused = %d, want at least 4 with a ceiling of 2 and 6 queries", st.Refused)
	}
	if st.Refused+2 != st.Claimed {
		t.Errorf("Refused (%d) + ceiling (2) should account for every claimed query (%d)",
			st.Refused, st.Claimed)
	}
}

// TestResolverSharesInFlightAcrossSessions caps per-session contribution
// (MEDIUM 2). A wide process-wide ceiling alone lets one authenticated peer
// saturate it and starve every other session. With dnsDefaultMaxInFlight (32)
// and an upstream that never answers, a single client must be refused after
// its per-session share (8) rather than consuming the whole process ceiling.
func TestResolverSharesInFlightAcrossSessions(t *testing.T) {
	inner := newFakeInner(1400)
	dead, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = dead.Close() }()
	r := newGatewayResolver(mustAddr(t, testGatewayInner), dead.LocalAddr().(*net.UDPAddr).AddrPort(), 3*time.Second, dnsDefaultMaxInFlight)
	d := newResolverDevice(inner, r, 1400)
	defer func() { _ = d.Close() }()

	// One client; per-session share is 8, so queries 9 and 10 must be refused
	// even though the process-wide ceiling (32) has room.
	for i := 0; i < 10; i++ {
		pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, testGatewayInner),
			uint16(45000+i), dnsPort, dnsQueryBytes(uint16(i)))
		if _, werr := d.WritePacket(pkt); werr != nil {
			t.Fatalf("WritePacket: %v", werr)
		}
	}
	st := r.Stats()
	if st.Claimed != 10 {
		t.Errorf("Claimed = %d, want 10", st.Claimed)
	}
	if want := 10 - dnsDefaultMaxInFlightPerClient; st.Refused != uint64(want) {
		t.Errorf("Refused = %d, want %d: one session must be capped at its per-session share, not consume the whole process ceiling",
			st.Refused, want)
	}
}

func TestResolverDeviceReadPacketUnblocksOnClose(t *testing.T) {
	inner := newFakeInner(1400)
	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))
	d := newResolverDevice(inner, r, 1400)

	errc := make(chan error, 1)
	go func() {
		_, err := d.ReadPacket(make([]byte, tun.MaxIPPacket))
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errc:
		if err != errResolverDeviceClosed {
			t.Fatalf("ReadPacket returned %v, want errResolverDeviceClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadPacket did not unblock on Close")
	}
}

func TestResolverDeviceCloseClosesTheWrappedDevice(t *testing.T) {
	inner := newFakeInner(1400)
	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))
	d := newResolverDevice(inner, r, 1400)
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-inner.done:
	default:
		t.Fatal("Close did not close the wrapped device; the pump would leak")
	}
	// Close is idempotent, matching every other device backend here.
	if err := d.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestResolverDeviceRelaysTheWrappedDevicesReads(t *testing.T) {
	// The reflector's replies must still reach the tunnel when the resolver
	// is wrapping it.
	reflectorDev := newReflector(1400, mustAddr(t, testGatewayInner))
	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))
	d := newResolverDevice(reflectorDev, r, 1400)
	defer func() { _ = d.Close() }()

	// Not DNS: ordinary traffic the reflector should bounce.
	pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, "1.1.1.1"), 1234, 443, []byte("hi"))
	if _, err := d.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	buf := make([]byte, tun.MaxIPPacket)
	done := make(chan int, 1)
	go func() {
		n, rerr := d.ReadPacket(buf)
		if rerr != nil {
			done <- -1
			return
		}
		done <- n
	}()
	select {
	case n := <-done:
		if n <= 0 {
			t.Fatal("the wrapped reflector's reply did not come through")
		}
		src, dst, _ := ipv4SourceDestination(buf[:n])
		if src != mustAddr(t, testGatewayInner) || dst != mustAddr(t, testClientInner) {
			t.Fatalf("relayed reflection has addresses %v -> %v", src, dst)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the wrapped device's read side was not relayed")
	}
}

func TestResolverDeviceMTUIsTheWrappedDevices(t *testing.T) {
	inner := newFakeInner(1337)
	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))
	d := newResolverDevice(inner, r, 1337)
	defer func() { _ = d.Close() }()
	if d.MTU() != 1337 {
		t.Fatalf("MTU = %d, want 1337; this wrapper adds no encapsulation", d.MTU())
	}
}

// ---------------------------------------------------------------------------
// Flag validation
// ---------------------------------------------------------------------------

func testAssignment(t *testing.T) tun.Assignment {
	t.Helper()
	return tun.Assignment{V4: mustAddr(t, testGatewayInner), RouterV4: mustAddr(t, testInnerNextHop)}
}

func TestValidateResolverModeAcceptsTheRecommendedUpstream(t *testing.T) {
	// AdGuard Home is on the same host as the gateway (both land on the node
	// whose /etc/winsvpn/role is "data") and binds 127.0.0.1 as well as
	// 10.8.1.1, so loopback is reachable without awg0 being up.
	for _, up := range []string{"127.0.0.1:53", "10.8.1.1:53"} {
		opts := serveOptions{resolver: true, resolverUpstream: up, resolverTimeout: dnsDefaultTimeout}
		got, err := validateResolverMode(opts, testAssignment(t))
		if err != nil {
			t.Fatalf("validateResolverMode(%q): %v", up, err)
		}
		if got.String() != up {
			t.Errorf("upstream = %v, want %v", got, up)
		}
	}
}

func TestValidateResolverModeAcceptsResolverOffWithNoInertFlags(t *testing.T) {
	// The validator is now called even when -resolver is off; a clean
	// resolver-off configuration must not be refused.
	for _, opts := range []serveOptions{
		{},
		{forward: true, forwardCIDR: "10.64.0.0/24"},
	} {
		if got, err := validateResolverMode(opts, testAssignment(t)); err != nil {
			t.Fatalf("validateResolverMode(%+v): %v", opts, err)
		} else if got.IsValid() {
			t.Fatalf("validateResolverMode(%+v) with -resolver off returned an upstream %v; want zero",
				opts, got)
		}
	}
}

func TestValidateResolverModeRefusesWhatItMust(t *testing.T) {
	cases := []struct {
		name string
		opts serveOptions
		as   tun.Assignment
	}{
		{"no upstream at all", serveOptions{resolver: true, resolverTimeout: dnsDefaultTimeout}, testAssignment(t)},
		{"a hostname", serveOptions{resolver: true, resolverTimeout: dnsDefaultTimeout, resolverUpstream: "dns.quad9.net:53"}, testAssignment(t)},
		{"an address with no port", serveOptions{resolver: true, resolverTimeout: dnsDefaultTimeout, resolverUpstream: "10.8.1.1"}, testAssignment(t)},
		{"port zero", serveOptions{resolver: true, resolverTimeout: dnsDefaultTimeout, resolverUpstream: "10.8.1.1:0"}, testAssignment(t)},
		{"IPv6", serveOptions{resolver: true, resolverTimeout: dnsDefaultTimeout, resolverUpstream: "[2620:fe::fe]:53"}, testAssignment(t)},
		{"our own inner address", serveOptions{resolver: true, resolverTimeout: dnsDefaultTimeout, resolverUpstream: testGatewayInner + ":53"}, testAssignment(t)},
		{"the inner next hop", serveOptions{resolver: true, resolverTimeout: dnsDefaultTimeout, resolverUpstream: testInnerNextHop + ":53"}, testAssignment(t)},
		{"no inner v4 assigned", serveOptions{resolver: true, resolverTimeout: dnsDefaultTimeout, resolverUpstream: "10.8.1.1:53"}, tun.Assignment{}},
		{"an upstream inside the tunnel's own subnet", serveOptions{
			resolver: true, resolverTimeout: dnsDefaultTimeout, resolverUpstream: "10.64.5.5:53",
			forward: true, forwardCIDR: "10.64.0.0/16",
		}, testAssignment(t)},
		{"resolver-upstream set without -resolver", serveOptions{resolverUpstream: "10.8.1.1:53"}, testAssignment(t)},
		{"resolver-timeout set without -resolver", serveOptions{resolverTimeout: 7 * time.Second}, testAssignment(t)},
		{"a zero resolver-timeout", serveOptions{resolver: true, resolverUpstream: "127.0.0.1:53", resolverTimeout: 0}, testAssignment(t)},
		{"a negative resolver-timeout", serveOptions{resolver: true, resolverUpstream: "127.0.0.1:53", resolverTimeout: -1 * time.Second}, testAssignment(t)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := validateResolverMode(tc.opts, tc.as); err == nil {
				t.Fatalf("validateResolverMode accepted %s", tc.name)
			}
		})
	}
}

// TestResolverDerivationWarningFiresOnAPoolWiderThanA24 pins the trap that the
// hub's /16 default pool and the clients' /24 derivation floor create between
// them. Neither value is wrong on its own and neither script can see the
// other; this warning is the only place in the running system where both are
// visible at once.
func TestResolverDerivationWarningFiresOnAPoolWiderThanA24(t *testing.T) {
	opts := serveOptions{resolver: true, forward: true, forwardCIDR: "10.64.0.0/16"}
	warn := resolverDerivationWarning(opts, testAssignment(t))
	if warn == "" {
		t.Fatal("no warning for a /16 pool with a /24 client-side derivation floor")
	}
	for _, want := range []string{"/24", "10.64.0.0/24", testGatewayInner} {
		if !strings.Contains(warn, want) {
			t.Errorf("warning does not mention %q: %s", want, warn)
		}
	}
}

func TestResolverDerivationWarningIsSilentWhenItCannotApply(t *testing.T) {
	cases := map[string]serveOptions{
		"a /24 pool":          {resolver: true, forward: true, forwardCIDR: "10.64.0.0/24"},
		"a /25 pool":          {resolver: true, forward: true, forwardCIDR: "10.64.0.0/25"},
		"no forward cidr":     {resolver: true},
		"resolver off":        {forward: true, forwardCIDR: "10.64.0.0/16"},
		"an unparseable cidr": {resolver: true, forward: true, forwardCIDR: "not-a-cidr"},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			if warn := resolverDerivationWarning(opts, testAssignment(t)); warn != "" {
				t.Fatalf("warned for %s: %s", name, warn)
			}
		})
	}
}
