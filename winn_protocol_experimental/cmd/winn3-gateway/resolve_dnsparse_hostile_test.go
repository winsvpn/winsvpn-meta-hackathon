package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"
)

// Hostile / malformed inputs for the gateway DNS parsers.
//
// Existing coverage lives in resolve_dnsparse_test.go, resolve_test.go
// (TestDNSQuestionSectionEndRefusesWhatItWillNotParse, claim refusals) and
// resolve_frame_adversarial_test.go. Those tables never put a 0x00, 0xC0,
// 0x40 or 0x80 *inside* a length-prefixed label. A parser that ignores the
// length byte and scans for a terminator 0 would still accept every name in
// those tables, because "example.com" and runs of 'a' contain no NUL. The
// ACCEPT rows below are the ones that make that mutant go red.
//
// This is not a fuzz campaign: every input is a fixed literal.

func dnsParseHeaderQD1(id uint16) []byte {
	msg := make([]byte, dnsHeaderBytes)
	binary.BigEndian.PutUint16(msg[0:2], id)
	msg[2] = 0x01 // RD
	binary.BigEndian.PutUint16(msg[4:6], 1)
	return msg
}

func TestDNSParseHostileQuestionSection(t *testing.T) {
	// QNAME = {3, 'a', 0x00, 'b', 0}: a 3-octet label whose middle octet is
	// NUL, then a real terminator. Correct end is header + 5 + QTYPE + QCLASS.
	nulInside := dnsQueryWithQNAME(1, []byte{3, 'a', 0x00, 'b', 0})
	wantNulEnd := dnsHeaderBytes + 5 + 4 // 21

	ptrInside := dnsQueryWithQNAME(1, []byte{3, 'a', 0xc0, 'b', 0})
	extInside := dnsQueryWithQNAME(1, []byte{3, 'a', 0x40, 'b', 0})
	resInside := dnsQueryWithQNAME(1, []byte{3, 'a', 0x80, 'b', 0})
	ffInside := dnsQueryWithQNAME(1, []byte{3, 'a', 0xff, 'b', 0})

	root := dnsQueryWithQNAME(1, []byte{0})
	wantRootEnd := dnsHeaderBytes + 1 + 4 // 17

	label63 := make([]byte, 1+63+1)
	label63[0] = 63
	for i := 0; i < 63; i++ {
		label63[1+i] = 'a'
	}
	fit63 := dnsQueryWithQNAME(1, label63)
	want63End := dnsHeaderBytes + 1 + 63 + 1 + 4 // 81

	// 0xC0 0x0C (self-referential) is NOT in this table: a follow-pointer
	// mutant would hang the subtest until go test's timeout. The hang is
	// asserted by TestDNSParseSelfReferentialPointerDoesNotHang instead.
	ptrToHeader := dnsParseHeaderQD1(1)
	ptrToHeader = append(ptrToHeader, 0xc0, 0x00, 0x00, 0x01, 0x00, 0x01)

	ptrFFFF := dnsParseHeaderQD1(1)
	ptrFFFF = append(ptrFFFF, 0xff, 0xff, 0x00, 0x01, 0x00, 0x01)

	c1Ptr := dnsParseHeaderQD1(1)
	c1Ptr = append(c1Ptr, 0xc1, 0x0c, 0x00, 0x01, 0x00, 0x01)

	len7f := append(dnsParseHeaderQD1(1), dnsQueryBytes(1)[dnsHeaderBytes:]...)
	len7f[dnsHeaderBytes] = 0x7f

	lenBf := append(dnsParseHeaderQD1(1), dnsQueryBytes(1)[dnsHeaderBytes:]...)
	lenBf[dnsHeaderBytes] = 0xbf

	// Length 1, zero data bytes remaining: over-read if the walker does
	// msg[i+1] without checking.
	len1NoData := dnsParseHeaderQD1(1)
	len1NoData = append(len1NoData, 1)

	// Length 1, one data byte, buffer ends: i == len(msg) after the label,
	// no terminator.
	len1ExactNoTerm := dnsParseHeaderQD1(1)
	len1ExactNoTerm = append(len1ExactNoTerm, 1, 'a')

	// Length 1, data, terminator, only 3 of 4 QTYPE/QCLASS bytes.
	shortClass := dnsQueryWithQNAME(1, []byte{1, 'a', 0})
	shortClass = shortClass[:len(shortClass)-1]

	// High-bit length bytes on a message LONG ENOUGH that treating them as
	// ordinary label lengths would succeed. Existing tests put 0x40/0xC0 on
	// the stock 29-byte query; a mutant that deletes `l&0xc0 != 0` still
	// refuses those because 64/192 octets do not fit — the bounds check
	// hides the missing mask. These rows make that mutant go red.
	asLabel := func(lengthByte byte) []byte {
		n := int(lengthByte)
		qname := make([]byte, 1+n+1)
		qname[0] = lengthByte
		for i := 0; i < n; i++ {
			qname[1+i] = 'x'
		}
		qname[1+n] = 0
		return dnsQueryWithQNAME(1, qname)
	}
	fit40 := asLabel(0x40) // 64-octet "label" plus terminator
	fit80 := asLabel(0x80) // 128
	fitC0 := asLabel(0xc0) // 192; 0xC0 0x78… would also be a pointer if followed
	fit7f := asLabel(0x7f) // 127; RFC max is 63

	// QDCOUNT=1, ANCOUNT=65535, NSCOUNT=65535, ARCOUNT=65535. The question
	// walker must not interpret those counts as a reason to allocate or to
	// keep walking past QCLASS.
	lyingCounts := dnsQueryBytes(1)
	binary.BigEndian.PutUint16(lyingCounts[6:8], 65535)
	binary.BigEndian.PutUint16(lyingCounts[8:10], 65535)
	binary.BigEndian.PutUint16(lyingCounts[10:12], 65535)
	wantStockEnd, stockOK := dnsQuestionSectionEnd(dnsQueryBytes(1))
	if !stockOK {
		t.Fatal("control: stock example.com query was refused")
	}

	type row struct {
		name    string
		msg     []byte
		accept  bool
		wantEnd int // exact end on accept; 0 on refuse
	}
	cases := []row{
		{"NUL octet inside a 3-byte label (not a terminator)", nulInside, true, wantNulEnd},
		{"0xC0 octet inside a 3-byte label (not a pointer)", ptrInside, true, dnsHeaderBytes + 5 + 4},
		{"0x40 octet inside a 3-byte label (not an extended label)", extInside, true, dnsHeaderBytes + 5 + 4},
		{"0x80 octet inside a 3-byte label (not a reserved length)", resInside, true, dnsHeaderBytes + 5 + 4},
		{"0xFF octet inside a 3-byte label", ffInside, true, dnsHeaderBytes + 5 + 4},
		{"minimum message: root name + QTYPE + QCLASS", root, true, wantRootEnd},
		{"63-octet label that fits exactly", fit63, true, want63End},
		{"stock query with AN/NS/ARCOUNT all 65535", lyingCounts, true, wantStockEnd},
		{"compression pointer 0xC0 0x00 into the header", ptrToHeader, false, 0},
		{"0xFF 0xFF pointer-shaped length", ptrFFFF, false, 0},
		{"0xC1 0x0C (pointer with nonzero low bits in the length byte)", c1Ptr, false, 0},
		{"0x7F as a length byte (01xxxxxx, would be a 127-octet label)", len7f, false, 0},
		{"0xBF as a length byte (10xxxxxx)", lenBf, false, 0},
		{"label length 1 with no data byte in the buffer", len1NoData, false, 0},
		{"label consumes the rest of the buffer, no terminator", len1ExactNoTerm, false, 0},
		{"QCLASS truncated by one byte after a well-formed name", shortClass, false, 0},
		{"0x40 length that would fit as a 64-octet label", fit40, false, 0},
		{"0x80 length that would fit as a 128-octet label", fit80, false, 0},
		{"0xC0 length that would fit as a 192-octet label", fitC0, false, 0},
		{"0x7F length that would fit as a 127-octet label", fit7f, false, 0},
		{"nil message", nil, false, 0},
		{"empty message", []byte{}, false, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			end, ok := dnsQuestionSectionEnd(tc.msg)
			if ok != tc.accept {
				t.Fatalf("ok=%v, want %v (end=%d len=%d)", ok, tc.accept, end, len(tc.msg))
			}
			if !tc.accept {
				if end != 0 {
					t.Fatalf("refusal returned end=%d, want 0", end)
				}
				return
			}
			if end != tc.wantEnd {
				t.Fatalf("end=%d, want %d (a scan-for-NUL walker returns a smaller end when a label contains 0x00)", end, tc.wantEnd)
			}
			if end < 0 || end > len(tc.msg) {
				t.Fatalf("over-read: end=%d len=%d", end, len(tc.msg))
			}
		})
	}
}

func TestDNSParseSelfReferentialPointerDoesNotHang(t *testing.T) {
	q := dnsParseHeaderQD1(0x0c0c)
	q = append(q, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01)

	done := make(chan struct{})
	var ok bool
	var end int
	go func() {
		end, ok = dnsQuestionSectionEnd(q)
		close(done)
	}()
	select {
	case <-done:
		if ok {
			t.Fatalf("accepted a self-referential compression pointer (end=%d)", end)
		}
		if end != 0 {
			t.Fatalf("refusal returned end=%d, want 0", end)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dnsQuestionSectionEnd hung on 0xC0 0x0C; a parser that follows compression pointers without a hop limit loops here")
	}
}

func TestDNSParseManyOneOctetLabelsDoesNotPanic(t *testing.T) {
	// 128 labels of one octet plus terminator = 257 octets. RFC 1035 §3.1
	// caps a name at 255; this parser does not. The requirement is: no panic,
	// no end outside the buffer. Silence (a SERVFAIL that cannot be built)
	// is the product failure this cap-not-enforced choice is defending.
	qname := qnameOneByteLabels(257)
	msg := dnsQueryWithQNAME(1, qname)
	end, ok := dnsQuestionSectionEnd(msg)
	if !ok {
		t.Logf("MEASURED: 257-octet QNAME refused")
		return
	}
	if end < 0 || end > len(msg) {
		t.Fatalf("over-read: end=%d len=%d", end, len(msg))
	}
	t.Logf("MEASURED: 257-octet QNAME accepted, end=%d len=%d", end, len(msg))
}

func TestDNSParseOversizeNameStillSynthesisesSERVFAIL(t *testing.T) {
	// A 512-octet QNAME is invalid per RFC 1035. Refusing it in
	// dnsQuestionSectionEnd would make emitServFail Drop — silence, which
	// this product treats as indistinguishable from blocking. Pin that
	// synthesis still succeeds so a future 255-octet cap cannot land
	// without this going red.
	msg := dnsQueryWithQNAME(0x0512, qnameOneByteLabels(512))
	out, ok := dnsServFailAnswer(msg)
	if !ok {
		t.Fatal("SERVFAIL synthesis refused a 512-octet QNAME; emitServFail would Drop (silence)")
	}
	if len(out) != len(msg) {
		t.Fatalf("synthesised %d bytes, want %d (header + the oversize question)", len(out), len(msg))
	}
	if out[3]&0x0f != 2 {
		t.Fatalf("RCODE=%d, want 2", out[3]&0x0f)
	}
	if out[2]&0x80 == 0 {
		t.Fatal("QR is not set")
	}
}

func TestDNSParseSynthesisEchoesNULInsideLabel(t *testing.T) {
	q := dnsQueryWithQNAME(0x4e55, []byte{3, 'a', 0x00, 'b', 0})
	out, ok := dnsServFailAnswer(q)
	if !ok {
		t.Fatal("SERVFAIL synthesis refused a question whose label contains NUL")
	}
	if !bytes.Equal(out[dnsHeaderBytes:], q[dnsHeaderBytes:]) {
		t.Fatal("question section was not echoed verbatim; a scan-for-NUL encoder would cut the label at the inner 0x00")
	}
	if binary.BigEndian.Uint16(out[6:8]) != 0 || binary.BigEndian.Uint16(out[8:10]) != 0 || binary.BigEndian.Uint16(out[10:12]) != 0 {
		t.Fatal("AN/NS/ARCOUNT were not zeroed")
	}
}

func TestDNSParseSynthesisRefusesSelfReferentialPointerWithoutHanging(t *testing.T) {
	q := dnsParseHeaderQD1(1)
	q = append(q, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01)
	done := make(chan struct{})
	var truncOK, failOK bool
	go func() {
		_, truncOK = dnsTruncatedAnswer(q)
		_, failOK = dnsServFailAnswer(q)
		close(done)
	}()
	select {
	case <-done:
		if truncOK || failOK {
			t.Fatalf("synthesised TC=%v SERVFAIL=%v from a self-referential pointer", truncOK, failOK)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("synthesis hung following 0xC0 0x0C")
	}
}

func TestDNSParseClaimHostilePayloads(t *testing.T) {
	r := testResolver(t, netip.MustParseAddrPort("127.0.0.1:53"))
	client := mustAddr(t, testClientInner)
	gw := mustAddr(t, testGatewayInner)

	t.Run("IHL=4 (below the 20-byte minimum) is refused", func(t *testing.T) {
		pkt := udpPacket(t, client, gw, 1000, dnsPort, dnsQueryBytes(1))
		pkt[0] = 0x44 // version 4, IHL 4 → 16 bytes
		if _, ok := r.claim(pkt); ok {
			t.Fatal("claim accepted IHL=4")
		}
	})
	t.Run("IPv4 total-length field of 0 is refused", func(t *testing.T) {
		pkt := udpPacket(t, client, gw, 1000, dnsPort, dnsQueryBytes(1))
		binary.BigEndian.PutUint16(pkt[2:4], 0)
		if _, ok := r.claim(pkt); ok {
			t.Fatal("claim accepted IPv4 total length 0")
		}
	})
	t.Run("IPv4 header only (20 bytes, no UDP) is refused", func(t *testing.T) {
		pkt := udpPacket(t, client, gw, 1000, dnsPort, dnsQueryBytes(1))
		pkt = pkt[:ipv4HeaderMinBytes]
		binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
		if _, ok := r.claim(pkt); ok {
			t.Fatal("claim accepted an IPv4 header with no UDP")
		}
	})
	t.Run("IPv4 total length larger than the buffer is refused", func(t *testing.T) {
		pkt := udpPacket(t, client, gw, 1000, dnsPort, dnsQueryBytes(1))
		binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)+8))
		if _, ok := r.claim(pkt); ok {
			t.Fatal("claim accepted a total-length field larger than the buffer")
		}
	})
	t.Run("OPCODE UPDATE (5) is still claimed; claim is not a message parser", func(t *testing.T) {
		// Byte 2: QR=0, opcode=5 (0x28), RD=1 → 0x29. A mutant that starts
		// refusing non-QUERY opcodes would pass this packet to the wrapped
		// device (the two-responders hazard resolve.go documents).
		q := dnsQueryBytes(0x5555)
		q[2] = 0x29
		pkt := udpPacket(t, client, gw, 34567, dnsPort, q)
		got, ok := r.claim(pkt)
		if !ok {
			t.Fatal("claim refused OPCODE UPDATE; that falls through to the wrapped device")
		}
		if !bytes.Equal(got.payload, q) {
			t.Fatal("claimed payload does not match the UPDATE query")
		}
	})
	t.Run("a QNAME with NUL inside a label is still claimed as opaque bytes", func(t *testing.T) {
		q := dnsQueryWithQNAME(0x4e55, []byte{3, 'a', 0x00, 'b', 0})
		pkt := udpPacket(t, client, gw, 34567, dnsPort, q)
		got, ok := r.claim(pkt)
		if !ok {
			t.Fatal("claim refused a well-formed UDP/53 query whose QNAME contains NUL")
		}
		if !bytes.Equal(got.payload, q) {
			t.Fatal("claimed payload was truncated at the inner NUL")
		}
	})
}

func TestDNSTCPFrameHostilePrefixes(t *testing.T) {
	t.Run("0xFFFF prefix with no body errors and delivers nil", func(t *testing.T) {
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], 65535)
		got, err := readDNSTCPFrame(bytes.NewReader(hdr[:]))
		if err == nil {
			t.Fatalf("accepted a 65535-byte prefix with no body (%d bytes)", len(got))
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			t.Logf("MEASURED: err=%v (short-read is the requirement)", err)
		}
		if got != nil {
			t.Fatalf("error path delivered %d bytes; a reader that returns buf[:n] on EOF would pass a weaker test", len(got))
		}
	})
	t.Run("0xFFFF prefix with 10 body bytes then EOF delivers nil", func(t *testing.T) {
		in := make([]byte, 2+10)
		binary.BigEndian.PutUint16(in[0:2], 65535)
		got, err := readDNSTCPFrame(bytes.NewReader(in))
		if err == nil {
			t.Fatalf("accepted a truncated 65535-byte frame (%d bytes)", len(got))
		}
		if got != nil {
			t.Fatalf("error path delivered %d bytes", len(got))
		}
	})
	t.Run("length 13 (header plus one) is accepted and not truncated", func(t *testing.T) {
		body := make([]byte, 13)
		framed := make([]byte, 2+13)
		binary.BigEndian.PutUint16(framed[0:2], 13)
		copy(framed[2:], body)
		got, err := readDNSTCPFrame(bytes.NewReader(framed))
		if err != nil {
			t.Fatalf("length 13: %v", err)
		}
		if len(got) != 13 {
			t.Fatalf("got %d bytes, want 13", len(got))
		}
	})
}
