package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"testing"
)

// Adversarial cases for the gateway DNS parsers in resolve.go / resolve_tcp.go.
// These pin both refusals and the well-formed inputs that must stay accepted.
// A test that only asserts "valid query works" cannot see a guard disappear.

// dnsQueryWithQNAME builds a QDCOUNT=1 query whose QNAME is the wire encoding
// in qname (length bytes, label bytes, and the terminating 0).
func dnsQueryWithQNAME(id uint16, qname []byte) []byte {
	msg := make([]byte, dnsHeaderBytes, dnsHeaderBytes+len(qname)+4)
	binary.BigEndian.PutUint16(msg[0:2], id)
	msg[2] = 0x01 // RD
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, qname...)
	msg = append(msg, 0x00, 0x01) // QTYPE A
	msg = append(msg, 0x00, 0x01) // QCLASS IN
	return msg
}

// qnameOneByteLabels returns a QNAME of exactly n octets including the
// terminator. n=1 is the root. Odd n is all 1-byte labels; even n uses one
// 2-byte label so the total including the 0 is even.
func qnameOneByteLabels(n int) []byte {
	if n < 1 {
		panic("qnameOneByteLabels: n < 1")
	}
	out := make([]byte, 0, n)
	remain := n - 1 // bytes before terminator
	if remain%2 == 1 {
		out = append(out, 2, 'a', 'b')
		remain -= 3
	}
	for remain > 0 {
		out = append(out, 1, 'a')
		remain -= 2
	}
	out = append(out, 0)
	if len(out) != n {
		panic("qnameOneByteLabels: encoding length mismatch")
	}
	return out
}

func TestDNSParseQuestionSectionAccepts(t *testing.T) {
	root := dnsQueryWithQNAME(1, []byte{0})
	label63 := make([]byte, 1+63+1)
	label63[0] = 63
	for i := 0; i < 63; i++ {
		label63[1+i] = 'a'
	}
	name255 := qnameOneByteLabels(255)

	cases := []struct {
		name string
		msg  []byte
	}{
		{"the stock example.com query", dnsQueryBytes(1)},
		{"the root name", root},
		{"a 63-octet label (RFC maximum)", dnsQueryWithQNAME(1, label63)},
		{"a 255-octet QNAME (RFC 1035 §3.1 maximum)", dnsQueryWithQNAME(1, name255)},
		{"two labels", dnsQueryWithQNAME(1, []byte{1, 'a', 1, 'b', 0})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			end, ok := dnsQuestionSectionEnd(tc.msg)
			if !ok {
				t.Fatalf("refused %s", tc.name)
			}
			if end < dnsHeaderBytes+5 || end > len(tc.msg) {
				t.Fatalf("end=%d outside a plausible question (len=%d)", end, len(tc.msg))
			}
			// QTYPE+QCLASS are the last 4 bytes of the question; the name
			// terminator is immediately before them.
			if tc.msg[end-5] != 0 {
				t.Fatalf("end=%d does not sit just past QTYPE/QCLASS of a terminated name", end)
			}
		})
	}
}

func TestDNSParseQuestionSectionRefuses(t *testing.T) {
	stock := dnsQueryBytes(1)
	pointerSecond := append([]byte(nil), stock...)
	// stock QNAME is [7]example [3]com [0] ...; second length byte is at 12+1+7=20.
	pointerSecond[dnsHeaderBytes+1+7] = 0xc0
	pointerSecond[dnsHeaderBytes+1+7+1] = 0x0c

	pointerLastByte := make([]byte, dnsHeaderBytes+1)
	binary.BigEndian.PutUint16(pointerLastByte[4:6], 1)
	pointerLastByte[dnsHeaderBytes] = 0xc0

	noTerminator := make([]byte, dnsHeaderBytes+1+3)
	binary.BigEndian.PutUint16(noTerminator[4:6], 1)
	noTerminator[dnsHeaderBytes] = 3
	copy(noTerminator[dnsHeaderBytes+1:], []byte("abc"))

	headerOnly := make([]byte, dnsHeaderBytes)
	binary.BigEndian.PutUint16(headerOnly[4:6], 1)

	extended40 := append([]byte(nil), stock...)
	extended40[dnsHeaderBytes] = 0x40

	extended40Second := append([]byte(nil), stock...)
	extended40Second[dnsHeaderBytes+1+7] = 0x40

	cases := []struct {
		name string
		msg  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"header only with QDCOUNT=1", headerOnly},
		{"a message shorter than a header", []byte{1, 2, 3}},
		{"QDCOUNT of 0", func() []byte {
			q := append([]byte(nil), stock...)
			binary.BigEndian.PutUint16(q[4:6], 0)
			return q
		}()},
		{"QDCOUNT of 2", func() []byte {
			q := append([]byte(nil), stock...)
			binary.BigEndian.PutUint16(q[4:6], 2)
			return q
		}()},
		{"QDCOUNT of 65535", func() []byte {
			q := append([]byte(nil), stock...)
			binary.BigEndian.PutUint16(q[4:6], 65535)
			return q
		}()},
		{"a compression pointer as the first length byte", func() []byte {
			q := append([]byte(nil), stock...)
			q[dnsHeaderBytes] = 0xc0
			return q
		}()},
		{"a compression pointer as the second label", pointerSecond},
		{"a compression pointer as the last byte of the message", pointerLastByte},
		{"an extended/BIT-STRING label (0x40) as the first length byte", extended40},
		{"an extended/BIT-STRING label (0x40) as the second label", extended40Second},
		{"a reserved 0x80 label length", func() []byte {
			q := append([]byte(nil), stock...)
			q[dnsHeaderBytes] = 0x80
			return q
		}()},
		{"a label running past the buffer", func() []byte {
			q := append([]byte(nil), stock...)
			q[dnsHeaderBytes] = 0x3f
			return q
		}()},
		{"a name with no terminator", noTerminator},
		{"QTYPE present but QCLASS missing", stock[:len(stock)-2]},
		{"QTYPE truncated to one byte", stock[:len(stock)-3]},
		{"no room for QTYPE/QCLASS", stock[:len(stock)-4]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			end, ok := dnsQuestionSectionEnd(tc.msg)
			if ok {
				t.Fatalf("accepted %s (end=%d len=%d)", tc.name, end, len(tc.msg))
			}
			if end != 0 {
				t.Fatalf("refusal returned end=%d, want 0", end)
			}
		})
	}
}

func TestDNSParseQuestionSectionIgnoresBytesAfterTheQuestion(t *testing.T) {
	q := dnsQueryBytes(1)
	want, ok := dnsQuestionSectionEnd(q)
	if !ok {
		t.Fatal("stock query refused")
	}
	padded := append(append([]byte(nil), q...), 0xde, 0xad, 0xbe, 0xef)
	end, ok := dnsQuestionSectionEnd(padded)
	if !ok {
		t.Fatal("a well-formed question followed by trailing bytes was refused; EDNS queries look like this")
	}
	if end != want {
		t.Fatalf("end=%d, want %d (stop after QCLASS, do not require consuming the whole message)", end, want)
	}
}

func TestDNSParse256OctetNameDoesNotPanicOrOverRead(t *testing.T) {
	// RFC 1035 §3.1 caps a name at 255 octets. This parser does not. Refusing
	// here would make dnsServFailAnswer fail, and emitServFail would Drop —
	// silence, which this product treats as indistinguishable from blocking.
	// This test only forbids a panic and an end that sits outside the buffer.
	msg := dnsQueryWithQNAME(1, qnameOneByteLabels(256))
	end, ok := dnsQuestionSectionEnd(msg)
	if ok {
		if end < 0 || end > len(msg) {
			t.Fatalf("over-read: end=%d len=%d", end, len(msg))
		}
		t.Logf("MEASURED: 256-octet QNAME accepted, end=%d len=%d (RFC cap 255 is not enforced)", end, len(msg))
	} else {
		t.Logf("MEASURED: 256-octet QNAME refused")
	}
}

func TestDNSParseSynthesisedResponseZerosSectionCountsTheQueryLiedAbout(t *testing.T) {
	q := dnsQueryBytes(0xfeed)
	binary.BigEndian.PutUint16(q[6:8], 5)   // ANCOUNT
	binary.BigEndian.PutUint16(q[8:10], 7)  // NSCOUNT
	binary.BigEndian.PutUint16(q[10:12], 9) // ARCOUNT
	out, ok := dnsServFailAnswer(q)
	if !ok {
		t.Fatal("SERVFAIL synthesis refused a well-formed question whose header counts were lies")
	}
	if binary.BigEndian.Uint16(out[4:6]) != 1 {
		t.Fatal("QDCOUNT was not 1")
	}
	for name, off := range map[string]int{"ANCOUNT": 6, "NSCOUNT": 8, "ARCOUNT": 10} {
		if got := binary.BigEndian.Uint16(out[off : off+2]); got != 0 {
			t.Errorf("%s=%d, want 0 (the query's lie must not be copied into a synthesised answer)", name, got)
		}
	}
	if out[3]&0x0f != 2 {
		t.Errorf("RCODE=%d, want 2", out[3]&0x0f)
	}
}

func TestDNSParseClaimIsAnAddressAndQRGateNotAMessageParser(t *testing.T) {
	// claim copies the UDP payload after QR=0 and the address checks. It does
	// not walk QNAME. A pointer or a lying QDCOUNT is still forwarded upstream
	// as opaque bytes; refusing it here would pass the packet to the wrapped
	// device (the two-responders hazard resolve.go documents).
	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))
	cases := []struct {
		name string
		spoil func([]byte)
	}{
		{"a compression pointer in QNAME", func(q []byte) { q[dnsHeaderBytes] = 0xc0 }},
		{"QDCOUNT of 0", func(q []byte) { binary.BigEndian.PutUint16(q[4:6], 0) }},
		{"QDCOUNT of 2", func(q []byte) { binary.BigEndian.PutUint16(q[4:6], 2) }},
		{"ANCOUNT of 5 with no records", func(q []byte) { binary.BigEndian.PutUint16(q[6:8], 5) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query := dnsQueryBytes(0x3333)
			tc.spoil(query)
			pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, testGatewayInner), 34567, dnsPort, query)
			q, ok := r.claim(pkt)
			if !ok {
				t.Fatalf("claim refused %s; that would fall through to the wrapped device instead of the upstream", tc.name)
			}
			if !bytes.Equal(q.payload, query) {
				t.Fatal("claimed payload does not match the spoilt query")
			}
		})
	}
}

func TestDNSParseClaimStripsUDPPadding(t *testing.T) {
	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))
	query := dnsQueryBytes(0x1111)
	pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, testGatewayInner), 34567, dnsPort, query)
	const pad byte = 0xaa
	pkt = append(pkt, pad, pad, pad, pad)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	q, ok := r.claim(pkt)
	if !ok {
		t.Fatal("claim refused a padded datagram whose UDP length field is the real message")
	}
	if !bytes.Equal(q.payload, query) {
		t.Fatalf("payload did not equal the DNS message (got %d bytes, want %d); a mutant that slices udp[8:] instead of udp[8:udpLen] includes the pad",
			len(q.payload), len(query))
	}
}

func TestDNSParseClaimAcceptsIPv4HeaderOptions(t *testing.T) {
	query := dnsQueryBytes(0x2222)
	src := mustAddr(t, testClientInner)
	dst := mustAddr(t, testGatewayInner)
	optLen := 4
	ihl := ipv4HeaderMinBytes + optLen
	total := ihl + udpHeaderBytes + len(query)
	pkt := make([]byte, total)
	pkt[0] = byte(0x40 | (ihl / 4))
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = ipProtoUDP
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	udp := pkt[ihl:]
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], dnsPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHeaderBytes+len(query)))
	copy(udp[udpHeaderBytes:], query)

	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))
	q, ok := r.claim(pkt)
	if !ok {
		t.Fatal("claim refused a well-formed UDP/53 query with IPv4 options (IHL=6); a mutant that hardcodes offset 20 would fail this")
	}
	if !bytes.Equal(q.payload, query) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(q.payload), len(query))
	}
	if q.clientPort != 40000 {
		t.Errorf("clientPort=%d, want 40000", q.clientPort)
	}
}

func TestDNSParseClaimRefusesUDPLengthEqualToTheUDPHeader(t *testing.T) {
	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))
	query := dnsQueryBytes(1)
	pkt := udpPacket(t, mustAddr(t, testClientInner), mustAddr(t, testGatewayInner), 1000, dnsPort, query)
	binary.BigEndian.PutUint16(pkt[ipv4HeaderMinBytes+4:ipv4HeaderMinBytes+6], udpHeaderBytes)
	if _, ok := r.claim(pkt); ok {
		t.Fatal("claim accepted a datagram whose UDP length is header-only (zero DNS payload)")
	}
}

func TestDNSTCPFrameBounds(t *testing.T) {
	t.Run("length 12 is the minimum accepted read", func(t *testing.T) {
		msg := make([]byte, dnsHeaderBytes)
		framed, err := dnsTCPFrame(msg)
		if err != nil {
			t.Fatalf("dnsTCPFrame(12): %v", err)
		}
		got, err := readDNSTCPFrame(bytes.NewReader(framed))
		if err != nil {
			t.Fatalf("readDNSTCPFrame(12): %v", err)
		}
		if len(got) != dnsHeaderBytes {
			t.Fatalf("got %d bytes, want 12", len(got))
		}
	})
	t.Run("length 65535 is accepted and not truncated", func(t *testing.T) {
		msg := make([]byte, dnsTCPMaxMessage)
		framed, err := dnsTCPFrame(msg)
		if err != nil {
			t.Fatalf("dnsTCPFrame(65535): %v", err)
		}
		if binary.BigEndian.Uint16(framed[0:2]) != dnsTCPMaxMessage {
			t.Fatalf("prefix=%d, want 65535", binary.BigEndian.Uint16(framed[0:2]))
		}
		got, err := readDNSTCPFrame(bytes.NewReader(framed))
		if err != nil {
			t.Fatalf("readDNSTCPFrame(65535): %v", err)
		}
		if len(got) != dnsTCPMaxMessage {
			t.Fatalf("got %d bytes, want 65535", len(got))
		}
	})
	t.Run("length 65536 is refused by the encoder", func(t *testing.T) {
		_, err := dnsTCPFrame(make([]byte, dnsTCPMaxMessage+1))
		if !errors.Is(err, errDNSTCPTooLong) {
			t.Fatalf("err=%v, want errDNSTCPTooLong", err)
		}
	})
	t.Run("a little-endian length-12 prefix is not a complete 12-byte message", func(t *testing.T) {
		var framed [2 + dnsHeaderBytes]byte
		framed[0] = byte(dnsHeaderBytes) // LE would encode 12 as {12,0}; BE reads that as 3072
		framed[1] = 0
		got, err := readDNSTCPFrame(bytes.NewReader(framed[:]))
		if err == nil {
			t.Fatalf("accepted a little-endian length prefix as a %d-byte message", len(got))
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			t.Logf("err=%v (short-read is the requirement; exact sentinel is not)", err)
		}
		if got != nil {
			t.Fatalf("got a %d-byte slice on error", len(got))
		}
	})
}

func TestDNSTCPClearTruncationDoesNotPanicOnAShortSlice(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3} {
		msg := make([]byte, n)
		if n >= 3 {
			msg[2] = 0x02
		}
		clearDNSTCPTruncation(msg)
		if n >= 3 && msg[2]&0x02 != 0 {
			t.Fatalf("n=%d: TC was not cleared", n)
		}
	}
}
