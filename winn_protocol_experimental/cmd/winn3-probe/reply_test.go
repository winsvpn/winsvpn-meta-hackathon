package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func testAddrs() (src, dst netip.Addr) {
	return netip.MustParseAddr("10.64.0.2"), netip.MustParseAddr("1.1.1.1")
}

func icmpEchoReplyFrom(req []byte) []byte {
	out := append([]byte(nil), req...)
	copy(out[12:16], req[16:20])
	copy(out[16:20], req[12:16])
	ihl := int(out[0]&0x0f) * 4
	out[ihl] = 0
	out[ihl+2], out[ihl+3] = 0, 0
	binary.BigEndian.PutUint16(out[ihl+2:ihl+4], checksum(out[ihl:]))
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:20]))
	return out
}

func icmpUnreachableFrom(req []byte) []byte {
	out := icmpEchoReplyFrom(req)
	ihl := int(out[0]&0x0f) * 4
	out[ihl] = 3
	out[ihl+2], out[ihl+3] = 0, 0
	binary.BigEndian.PutUint16(out[ihl+2:ihl+4], checksum(out[ihl:]))
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:20]))
	return out
}

func dnsResponseFrom(req []byte) []byte {
	out := append([]byte(nil), req...)
	copy(out[12:16], req[16:20])
	copy(out[16:20], req[12:16])
	ihl := int(out[0]&0x0f) * 4
	// swap UDP ports
	copy(out[ihl:ihl+2], req[ihl+2:ihl+4])
	copy(out[ihl+2:ihl+4], req[ihl:ihl+2])
	flagsOff := ihl + 8 + 2
	flags := binary.BigEndian.Uint16(out[flagsOff : flagsOff+2])
	flags |= 0x8000 // QR
	binary.BigEndian.PutUint16(out[flagsOff:flagsOff+2], flags)
	// recompute UDP checksum
	udp := out[ihl:]
	udp[6], udp[7] = 0, 0
	s4 := [4]byte(out[12:16])
	d4 := [4]byte(out[16:20])
	pseudo := append(append([]byte{}, s4[:]...), d4[:]...)
	pseudo = append(pseudo, 0, 17)
	var lenb [2]byte
	binary.BigEndian.PutUint16(lenb[:], uint16(len(udp)))
	pseudo = append(pseudo, lenb[:]...)
	pseudo = append(pseudo, udp...)
	ck := checksum(pseudo)
	if ck == 0 {
		ck = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], ck)
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:20]))
	return out
}

func TestICMPEchoReplyMatches(t *testing.T) {
	src, dst := testAddrs()
	req := icmpEcho(src, dst, 7, 3, []byte("winn3-forward-proof-20260812"))
	rep := icmpEchoReplyFrom(req)
	if !countAsProbeReply(req, rep, false) {
		t.Fatal("matching ICMP echo reply was not counted")
	}
	if countAsProbeReply(req, req, false) {
		t.Fatal("the echo request itself was counted as a reply")
	}
	if countAsProbeReply(req, icmpUnreachableFrom(req), false) {
		t.Fatal("ICMP destination-unreachable was counted as a pass")
	}
	wrongSeq := icmpEcho(src, dst, 7, 4, []byte("winn3-forward-proof-20260812"))
	if countAsProbeReply(req, icmpEchoReplyFrom(wrongSeq), false) {
		t.Fatal("echo reply with a different seq was counted")
	}
	wrongID := icmpEcho(src, dst, 8, 3, []byte("winn3-forward-proof-20260812"))
	if countAsProbeReply(req, icmpEchoReplyFrom(wrongID), false) {
		t.Fatal("echo reply with a different id was counted")
	}
	unswapped := append([]byte(nil), req...)
	ihl := int(unswapped[0]&0x0f) * 4
	unswapped[ihl] = 0
	if countAsProbeReply(req, unswapped, false) {
		t.Fatal("type-0 packet that did not swap addresses was counted")
	}
}

func TestDNSReplyMatches(t *testing.T) {
	src := netip.MustParseAddr("10.64.0.2")
	dst := netip.MustParseAddr("10.64.0.1")
	req, err := udpDNS(src, dst, dnsUDPSrcPortBase, 53, 99, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	rep := dnsResponseFrom(req)
	if !countAsProbeReply(req, rep, true) {
		t.Fatal("matching DNS response was not counted")
	}
	if countAsProbeReply(req, req, true) {
		t.Fatal("the query itself (QR=0) was counted as a response")
	}
	if countAsProbeReply(req, icmpEchoReplyFrom(icmpEcho(src, dst, 1, 1, []byte("x"))), true) {
		t.Fatal("an ICMP packet was counted as a DNS response")
	}
	other, err := udpDNS(src, dst, dnsUDPSrcPortBase+1, 53, 100, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if countAsProbeReply(req, dnsResponseFrom(other), true) {
		t.Fatal("DNS response for a different txid/port was counted")
	}
}

// A matching reply that carries an error RCODE or the TC bit reached the
// resolver but did not resolve the name; the hub records the DNS proof from
// this verdict, so it must not count.
func TestDNSReplyRejectsErrorAndTruncatedResponses(t *testing.T) {
	src := netip.MustParseAddr("10.64.0.2")
	dst := netip.MustParseAddr("10.64.0.1")
	req, err := udpDNS(src, dst, dnsUDPSrcPortBase, 53, 99, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		set  uint16
		want bool
	}{
		{"NOERROR", 0x0080, true},
		{"FORMERR", 0x0001, false},
		{"SERVFAIL", 0x0002, false},
		{"NXDOMAIN", 0x0003, false},
		{"NOTIMP", 0x0004, false},
		{"REFUSED", 0x0005, false},
		{"truncated", 0x0200, false},
	} {
		rep := dnsResponseFrom(req)
		ihl := int(rep[0]&0x0f) * 4
		flags := binary.BigEndian.Uint16(rep[ihl+10 : ihl+12])
		binary.BigEndian.PutUint16(rep[ihl+10:ihl+12], flags|tc.set)
		if got := countAsProbeReply(req, rep, true); got != tc.want {
			t.Errorf("%s reply counted = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestMatchOutstandingRemovesOnlyTheHit(t *testing.T) {
	src, dst := testAddrs()
	a := icmpEcho(src, dst, 1, 1, []byte("a"))
	b := icmpEcho(src, dst, 1, 2, []byte("b"))
	outstanding := [][]byte{a, b}
	i := matchOutstanding(outstanding, icmpEchoReplyFrom(b), false, netip.Addr{})
	if i != 1 {
		t.Fatalf("match index %d, want 1", i)
	}
	if matchOutstanding(outstanding, icmpUnreachableFrom(a), false, netip.Addr{}) != -1 {
		t.Fatal("unreachable matched an outstanding echo")
	}
}

func TestFinishWithNoMatchPriority(t *testing.T) {
	sessionErr := errors.New("loop died")
	err := finishWithNoMatch(3, false, false, 4, 0, 45*time.Second, sessionErr)
	if err == nil {
		t.Fatal("nil")
	}
	if !strings.Contains(err.Error(), "session ended without a reply") {
		t.Fatalf("session death was not named first: %v", err)
	}
	if !strings.Contains(err.Error(), "not a missing gateway") {
		t.Fatalf("session death still looks like a -forward miss: %v", err)
	}
	if !errors.Is(err, sessionErr) {
		t.Fatalf("wrapped session error is not errors.Is: %v", err)
	}

	err = finishWithNoMatch(2, false, false, 4, 0, 45*time.Second, nil)
	if err == nil {
		t.Fatal("nil unmatched")
	}
	if !strings.Contains(err.Error(), "not a matching ICMP echo reply") {
		t.Fatalf("unmatched packets were not named: %v", err)
	}
	if !strings.Contains(err.Error(), "-forward") {
		t.Fatalf("unmatched path dropped the underlying no-reply cause: %v", err)
	}

	err = finishWithNoMatch(0, false, false, 4, 0, 45*time.Second, nil)
	if err == nil {
		t.Fatal("nil generic")
	}
	if !strings.Contains(err.Error(), "-accept-transit=true") {
		t.Fatalf("generic ICMP no-reply lost the gateway companions: %v", err)
	}
}

func TestUnexpectedSessionEndDoesNotBlameForward(t *testing.T) {
	err := unexpectedSessionEnd(errors.New("maxSpins"))
	if err == nil {
		t.Fatal("nil")
	}
	msg := err.Error()
	for _, w := range []string{"session ended without a reply", "not a missing gateway", "-forward", "-resolver", "maxSpins"} {
		if !strings.Contains(msg, w) {
			t.Errorf("got %q, missing %q", msg, w)
		}
	}
	if strings.Contains(msg, "needs -forward and -accept-transit=true AND") {
		t.Fatalf("session death used the ICMP companion sentence: %q", msg)
	}
}

func TestICMPEchoChecksumsVerify(t *testing.T) {
	src, dst := testAddrs()
	pkt := icmpEcho(src, dst, 7, 1, []byte("winn3-forward-proof-20260812"))
	if got := checksum(pkt[:20]); got != 0 {
		t.Fatalf("IPv4 header checksum verifies to 0x%04x, want 0", got)
	}
	if got := checksum(pkt[20:]); got != 0 {
		t.Fatalf("ICMP checksum verifies to 0x%04x, want 0", got)
	}
}

func TestUDPDNSChecksumsVerify(t *testing.T) {
	src := netip.MustParseAddr("10.64.0.2")
	dst := netip.MustParseAddr("10.64.0.1")
	pkt, err := udpDNS(src, dst, dnsUDPSrcPortBase, 53, 1, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := checksum(pkt[:20]); got != 0 {
		t.Fatalf("IPv4 header checksum verifies to 0x%04x, want 0", got)
	}
	ihl := int(pkt[0]&0x0f) * 4
	udp := pkt[ihl:]
	s4 := [4]byte(pkt[12:16])
	d4 := [4]byte(pkt[16:20])
	pseudo := append(append([]byte{}, s4[:]...), d4[:]...)
	pseudo = append(pseudo, 0, 17)
	var lenb [2]byte
	binary.BigEndian.PutUint16(lenb[:], uint16(len(udp)))
	pseudo = append(pseudo, lenb[:]...)
	pseudo = append(pseudo, udp...)
	if got := checksum(pseudo); got != 0 {
		t.Fatalf("UDP checksum verifies to 0x%04x, want 0", got)
	}
}
