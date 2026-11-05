package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// countAsProbeReply reports whether recv is the expected reply to sent.
// ICMP mode requires an echo reply (type 0) with matching id/seq and
// swapped addresses. DNS mode requires a UDP response (QR=1) with matching
// txid, swapped 4-tuple, and swapped inner addresses, that is complete (TC=0)
// and successful (RCODE=NOERROR): an error or truncated reply proves the
// resolver was reached, not that it resolves names.
//
// The send path used to vary source port and txid and comment that this
// "guarantees" a stale reply cannot be counted. It never inspected the
// receive side, so any inner packet incremented got and printed VERDICT
// success — including ICMP destination-unreachable.
func countAsProbeReply(sent, recv []byte, dnsMode bool) bool {
	if dnsMode {
		return dnsReplyMatches(sent, recv)
	}
	return icmpEchoReplyMatches(sent, recv)
}

func ipv4L4(pkt []byte) (src, dst netip.Addr, proto byte, payload []byte, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, 0, nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return netip.Addr{}, netip.Addr{}, 0, nil, false
	}
	src = netip.AddrFrom4([4]byte(pkt[12:16]))
	dst = netip.AddrFrom4([4]byte(pkt[16:20]))
	return src, dst, pkt[9], pkt[ihl:], true
}

func icmpEchoReplyMatches(sent, recv []byte) bool {
	ssrc, sdst, sproto, sicmp, sok := ipv4L4(sent)
	rsrc, rdst, rproto, ricmp, rok := ipv4L4(recv)
	if !sok || !rok || sproto != 1 || rproto != 1 {
		return false
	}
	if len(sicmp) < 8 || len(ricmp) < 8 {
		return false
	}
	if ricmp[0] != 0 { // echo reply
		return false
	}
	if binary.BigEndian.Uint16(sicmp[4:6]) != binary.BigEndian.Uint16(ricmp[4:6]) {
		return false
	}
	if binary.BigEndian.Uint16(sicmp[6:8]) != binary.BigEndian.Uint16(ricmp[6:8]) {
		return false
	}
	return rsrc == sdst && rdst == ssrc
}

func dnsReplyMatches(sent, recv []byte) bool {
	ssrc, sdst, sproto, sudp, sok := ipv4L4(sent)
	rsrc, rdst, rproto, rudp, rok := ipv4L4(recv)
	if !sok || !rok || sproto != 17 || rproto != 17 {
		return false
	}
	if len(sudp) < 8+12 || len(rudp) < 8+12 {
		return false
	}
	ssport := binary.BigEndian.Uint16(sudp[0:2])
	sdport := binary.BigEndian.Uint16(sudp[2:4])
	rsport := binary.BigEndian.Uint16(rudp[0:2])
	rdport := binary.BigEndian.Uint16(rudp[2:4])
	if rdport != ssport || rsport != sdport {
		return false
	}
	if rsrc != sdst || rdst != ssrc {
		return false
	}
	if binary.BigEndian.Uint16(sudp[8:10]) != binary.BigEndian.Uint16(rudp[8:10]) {
		return false
	}
	rflags := binary.BigEndian.Uint16(rudp[10:12])
	// QR set, TC (0x0200) clear, RCODE (low 4 bits) NOERROR.
	return rflags&0x8000 != 0 && rflags&0x020f == 0
}

// reflectReplyMatches is the local winn3-gateway reflector: src becomes the
// gateway assignment, dst becomes the client's source, L4 bytes are unchanged.
// An ICMP echo reply (type 0) is a different packet and is not counted here.
func reflectReplyMatches(sent, recv []byte, gatewayInner netip.Addr) bool {
	if !gatewayInner.IsValid() || !gatewayInner.Is4() {
		return false
	}
	ssrc, sdst, sproto, spayload, sok := ipv4L4(sent)
	rsrc, rdst, rproto, rpayload, rok := ipv4L4(recv)
	if !sok || !rok || sproto != rproto {
		return false
	}
	if sdst != gatewayInner {
		return false
	}
	if rsrc != gatewayInner || rdst != ssrc {
		return false
	}
	return bytes.Equal(spayload, rpayload)
}

func matchOutstanding(outstanding [][]byte, recv []byte, dnsMode bool, reflectTo netip.Addr) int {
	for i, sent := range outstanding {
		matched := false
		if reflectTo.IsValid() {
			matched = reflectReplyMatches(sent, recv, reflectTo)
		} else {
			matched = countAsProbeReply(sent, recv, dnsMode)
		}
		if matched {
			return i
		}
	}
	return -1
}

func noteReply(recv []byte, outstanding [][]byte, dnsMode bool, reflectTo netip.Addr, got, unmatched int) (int, int, [][]byte) {
	if i := matchOutstanding(outstanding, recv, dnsMode, reflectTo); i >= 0 {
		fmt.Printf("v3probe: RECV  %s\n", describe(recv))
		outstanding = append(outstanding[:i], outstanding[i+1:]...)
		return got + 1, unmatched, outstanding
	}
	fmt.Printf("v3probe: RECV unmatched %s\n", describe(recv))
	return got, unmatched + 1, outstanding
}

func drainReplies(replies <-chan []byte, outstanding [][]byte, dnsMode bool, reflectTo netip.Addr, got, unmatched int) (int, int, [][]byte) {
	for {
		select {
		case r := <-replies:
			got, unmatched, outstanding = noteReply(r, outstanding, dnsMode, reflectTo, got, unmatched)
		default:
			return got, unmatched, outstanding
		}
	}
}

func finishWithNoMatch(unmatched int, dnsMode, reflectMode bool, sent, txDropped int, budget time.Duration, runErr error) error {
	if runErr != nil {
		return unexpectedSessionEnd(runErr)
	}
	if unmatched > 0 {
		return unmatchedNoReplyError(unmatched, dnsMode, reflectMode, sent, txDropped, budget)
	}
	return noReplyError(dnsMode, reflectMode, sent, txDropped, budget)
}
