package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
)

func gatewaySwap(pkt []byte, ours netip.Addr) []byte {
	ihl := int(pkt[0]&0x0f) * 4
	reply := append([]byte(nil), pkt...)
	src := [4]byte{}
	copy(src[:], pkt[12:16])
	oa := ours.As4()
	copy(reply[12:16], oa[:])
	copy(reply[16:20], src[:])
	reply[10], reply[11] = 0, 0
	binary.BigEndian.PutUint16(reply[10:12], checksum(reply[:ihl]))
	return reply
}

func TestReflectReplyMatchesGatewaySwap(t *testing.T) {
	src := netip.MustParseAddr("10.64.0.2")
	gw := netip.MustParseAddr("10.64.0.1")
	req := icmpEcho(src, gw, 7, 3, []byte("winn3-canary-reflect-20260818"))
	rep := gatewaySwap(req, gw)
	if !reflectReplyMatches(req, rep, gw) {
		t.Fatal("gateway address-swap was not counted as a reflector reply")
	}
	if countAsProbeReply(req, rep, false) {
		t.Fatal("a reflector swap (ICMP type still 8) was counted as an internet echo reply; that would green a local canary as transit")
	}
	if reflectReplyMatches(req, icmpEchoReplyFrom(req), gw) {
		t.Fatal("a real ICMP echo reply was counted as a reflector swap")
	}
	if reflectReplyMatches(req, req, gw) {
		t.Fatal("the request itself was counted as a reflection")
	}
	otherGW := netip.MustParseAddr("10.64.0.9")
	if reflectReplyMatches(req, gatewaySwap(req, otherGW), gw) {
		t.Fatal("a swap sourced from the wrong gateway inner was counted")
	}
}

func TestMatchOutstandingUsesReflectWhenAddrSet(t *testing.T) {
	src := netip.MustParseAddr("10.64.0.2")
	gw := netip.MustParseAddr("10.64.0.1")
	req := icmpEcho(src, gw, 1, 1, []byte("x"))
	outstanding := [][]byte{req}
	if i := matchOutstanding(outstanding, gatewaySwap(req, gw), false, gw); i != 0 {
		t.Fatalf("reflect match index %d, want 0", i)
	}
	if matchOutstanding(outstanding, icmpEchoReplyFrom(req), false, gw) != -1 {
		t.Fatal("ICMP echo reply matched under reflect mode")
	}
}

func TestCapturingConnRecordsOnlyTheFirstSend(t *testing.T) {
	inner := &stubConn{}
	c := &capturingConn{Conn: inner}
	first := []byte("initiation-transcript")
	second := []byte("later-message")
	if err := c.Send(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := c.Send(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	got := c.First()
	if !bytes.Equal(got, first) {
		t.Fatalf("First()=%q, want the first Send", got)
	}
	got[0] = 'X'
	if c.First()[0] == 'X' {
		t.Fatal("First() returned a live alias of the capture")
	}
}

type stubConn struct {
	carrier.Conn
	sent int
}

func (s *stubConn) Send(context.Context, []byte) error {
	s.sent++
	return nil
}

func TestCanaryRekeyAfterDefaultIsBelowRejectCeiling(t *testing.T) {
	if canaryRekeyAfterDefault == 0 {
		t.Fatal("canaryRekeyAfterDefault is 0; session.Config would fill core.RekeyAfterMessages (1<<28)")
	}
	if canaryRekeyAfterDefault > 1<<20 {
		t.Fatalf("canaryRekeyAfterDefault %d is too high for a loopback canary", canaryRekeyAfterDefault)
	}
}

func TestValidateProbeFlagsFillsCanaryRekeyAfter(t *testing.T) {
	o := validCanary()
	o.rekeyAfter = 16
	parsed, err := validateProbeFlags(o)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.rekeyAfter != 16 {
		t.Fatalf("explicit -rekey-after 16 became %d", parsed.rekeyAfter)
	}
}
