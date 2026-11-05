package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"syscall"
	"testing"
)

// rtAttrs splits a request's attributes after the rtmsg into type -> value.
func rtAttrs(t *testing.T, b []byte) map[uint16][]byte {
	t.Helper()
	if got := int(binary.NativeEndian.Uint32(b[0:4])); got != len(b) {
		t.Fatalf("nlmsg_len %d, message %d bytes", got, len(b))
	}
	out := map[uint16][]byte{}
	a := b[nlmsgHdrLen+rtMsgLen:]
	for len(a) > 0 {
		l := int(binary.NativeEndian.Uint16(a[0:2]))
		typ := binary.NativeEndian.Uint16(a[2:4])
		if l < rtAttrHdrLen || l > len(a) {
			t.Fatalf("bad attribute length %d", l)
		}
		if _, dup := out[typ]; dup {
			t.Fatalf("attribute %d twice", typ)
		}
		out[typ] = a[rtAttrHdrLen:l]
		a = a[min(nlAlign(l), len(a)):]
	}
	return out
}

func TestEncodeRouteGetRequestAsksForTheListenerFlow(t *testing.T) {
	dst := netip.MustParseAddrPort("1.1.1.1:40000")
	b, err := encodeRouteGetRequest(7, dst, egressLookup{Source: netip.MustParseAddr("203.0.113.7"), Port: 9111, Mark: 0x5})
	if err != nil {
		t.Fatal(err)
	}
	if typ, flags, seq := binary.NativeEndian.Uint16(b[4:6]), binary.NativeEndian.Uint16(b[6:8]), binary.NativeEndian.Uint32(b[8:12]); typ != rtmGetRoute || flags != nlmFRequest || seq != 7 {
		t.Fatalf("header type %d flags %#x seq %d", typ, flags, seq)
	}
	rt := b[nlmsgHdrLen:]
	if rt[0] != afInet || rt[1] != 32 || rt[2] != 32 || binary.NativeEndian.Uint32(rt[8:12]) != rtmFLookupTable {
		t.Fatalf("rtmsg family %d dst_len %d src_len %d flags %#x", rt[0], rt[1], rt[2], binary.NativeEndian.Uint32(rt[8:12]))
	}
	attrs := rtAttrs(t, b)
	if got := attrs[rtaDst]; string(got) != string([]byte{1, 1, 1, 1}) {
		t.Fatalf("RTA_DST %v", got)
	}
	if got := attrs[rtaSrc]; string(got) != string([]byte{203, 0, 113, 7}) {
		t.Fatalf("RTA_SRC %v", got)
	}
	if got := attrs[rtaIPProto]; len(got) != 1 || got[0] != ipprotoUDP {
		t.Fatalf("RTA_IP_PROTO %v", got)
	}
	// 9111 = 0x2397, network byte order.
	if got := attrs[rtaSport]; string(got) != string([]byte{0x23, 0x97}) {
		t.Fatalf("RTA_SPORT %x", got)
	}
	// 40000 = 0x9c40, network byte order: the client's port (Round CM3 Turn 2).
	if got := attrs[rtaDport]; string(got) != string([]byte{0x9c, 0x40}) {
		t.Fatalf("RTA_DPORT %x", got)
	}
	if got := attrs[rtaMark]; len(got) != 4 || binary.NativeEndian.Uint32(got) != 5 {
		t.Fatalf("RTA_MARK %x", got)
	}
	if len(attrs) != 6 {
		t.Fatalf("attributes %v, want exactly dst, src, ipproto, sport, dport, mark (no uid: the kernel supplies the caller's)", attrs)
	}

	// Wildcard listener, port 0, a probe (destination port 0), no mark: no
	// source, no sport, no dport, no mark.
	b, err = encodeRouteGetRequest(1, netip.AddrPortFrom(dst.Addr(), 0), egressLookup{})
	if err != nil {
		t.Fatal(err)
	}
	attrs = rtAttrs(t, b)
	if _, ok := attrs[rtaSrc]; ok || b[nlmsgHdrLen+2] != 0 {
		t.Fatal("a wildcard listener sent a source address")
	}
	if _, ok := attrs[rtaSport]; ok {
		t.Fatal("port 0 sent RTA_SPORT")
	}
	if _, ok := attrs[rtaDport]; ok {
		t.Fatal("a probe (destination port 0) sent RTA_DPORT")
	}
	if _, ok := attrs[rtaMark]; ok {
		t.Fatal("mark 0 sent RTA_MARK")
	}
	if _, ok := attrs[rtaIPProto]; !ok {
		t.Fatal("RTA_IP_PROTO missing")
	}
	if _, err := encodeRouteGetRequest(1, netip.MustParseAddrPort("[2001:db8::1]:1"), egressLookup{}); err == nil {
		t.Fatal("an IPv6 destination was encoded")
	}
}

// nlMsg builds one netlink message of typ with seq around body.
func nlMsg(typ uint16, seq uint32, body []byte) []byte {
	b := make([]byte, nlmsgHdrLen, nlmsgHdrLen+len(body)+4)
	binary.NativeEndian.PutUint16(b[4:6], typ)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	b = append(b, body...)
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func u32(v uint32) []byte { var b [4]byte; binary.NativeEndian.PutUint32(b[:], v); return b[:] }

// newRouteBody is an RTM_NEWROUTE body shaped like the kernel's reply to
// `ip route get 1.1.1.1 ipproto udp sport 9111` through table 100.
func newRouteBody(oif uint32, table uint32, mtu uint32, expires int32) []byte {
	rt := make([]byte, rtMsgLen)
	rt[0], rt[1], rt[4] = afInet, 32, 252 // RT_TABLE_COMPAT in the u8 field, as the kernel sends for tables > 255
	b := appendRtAttr(rt, rtaTable, u32(table))
	b = appendRtAttr(b, rtaDst, []byte{1, 1, 1, 1})
	b = appendRtAttr(b, rtaOIF, u32(oif))
	if mtu > 0 {
		b = appendRtAttr(b, rtaMetrics|0x8000, appendRtAttr(nil, rtaxMTU, u32(mtu)))
	}
	ci := make([]byte, 32)
	binary.NativeEndian.PutUint32(ci[rtaCacheInfoExpiresOffset:], uint32(expires))
	b = appendRtAttr(b, rtaCacheInfo, ci)
	return b
}

func TestParseRouteReply(t *testing.T) {
	r, err := parseRouteReply(nlMsg(rtmNewRoute, 3, newRouteBody(5, 100, 1380, 0)), 3, 0)
	if err != nil || r.OIF != 5 || r.Table != 100 || r.RouteMTU != 1380 || r.Expires != 0 {
		t.Fatalf("got %+v err=%v", r, err)
	}
	r, err = parseRouteReply(nlMsg(rtmNewRoute, 3, newRouteBody(5, 254, 1300, 60000)), 3, 0)
	if err != nil || r.RouteMTU != 1300 || r.Expires != 60000 {
		t.Fatalf("exception reply: %+v %v", r, err)
	}
	r, err = parseRouteReply(nlMsg(rtmNewRoute, 3, newRouteBody(5, 254, 0, 0)), 3, 0)
	if err != nil || r.RouteMTU != 0 {
		t.Fatalf("no metrics: %+v %v", r, err)
	}
	// The kernel's refusal is the errno, a complete answer.
	code := int32(-int32(syscall.ENETUNREACH))
	if _, err = parseRouteReply(nlMsg(nlmsgError, 3, append(u32(uint32(code)), make([]byte, 16)...)), 3, 0); !errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, errNetlinkIncomplete) {
		t.Fatalf("NLMSG_ERROR: err=%v", err)
	}
	// Round CM3 Turn 6: everything that is not one well-formed answer to
	// this request on this socket is INCOMPLETE, never skipped or read as a
	// route. (Turn 5 skipped a message for another sequence number.)
	noOIF := newRouteBody(0, 254, 0, 0)
	good := nlMsg(rtmNewRoute, 3, newRouteBody(5, 254, 1380, 0))
	for name, b := range map[string][]byte{
		"a bare ACK":             nlMsg(nlmsgError, 3, append(u32(0), make([]byte, 16)...)),
		"no RTA_OIF":             nlMsg(rtmNewRoute, 3, noOIF),
		"short header":           good[:10],
		"length too big":         append(append([]byte{}, u32(4096)...), good[4:]...),
		"length too small":       append(append([]byte{}, u32(8)...), good[4:]...),
		"empty datagram":         {},
		"another seq only":       nlMsg(rtmNewRoute, 2, newRouteBody(9, 254, 0, 0)),
		"another seq, then ours": append(nlMsg(rtmNewRoute, 2, newRouteBody(9, 254, 0, 0)), good...),
		"another port id":        nlMsgFull(rtmNewRoute, 0, 3, 99, newRouteBody(5, 254, 1380, 0)),
		"two answers":            append(append([]byte{}, good...), good...),
		"NLMSG_DONE":             nlMsg(nlmsgDone, 3, u32(0)),
		"NLMSG_OVERRUN":          nlMsg(nlmsgOverrun, 3, nil),
		"DUMP_INTR":              nlMsgFull(rtmNewRoute, nlmFDumpIntr, 3, 0, newRouteBody(5, 254, 1380, 0)),
		"positive error code":    nlMsg(nlmsgError, 3, append(u32(5), make([]byte, 16)...)),
		"not AF_INET": func() []byte {
			c := append([]byte{}, good...)
			c[nlmsgHdrLen] = 10
			return c
		}(),
		"attribute overruns": func() []byte {
			c := append([]byte{}, good...)
			binary.NativeEndian.PutUint16(c[nlmsgHdrLen+rtMsgLen:], 200)
			return c
		}(),
		"short RTA_OIF": nlMsg(rtmNewRoute, 3, appendRtAttr(append(make([]byte, 0, 32), afInet, 32, 0, 0, 254, 0, 0, 0, 0, 0, 0, 0), rtaOIF, []byte{5, 0})),
		"trailing attribute bytes": func() []byte {
			body := append(newRouteBody(5, 254, 1380, 0), 1, 0)
			return nlMsg(rtmNewRoute, 3, body)
		}(),
		"short error": nlMsg(nlmsgError, 3, []byte{1}),
	} {
		if _, err := parseRouteReply(b, 3, 0); !errors.Is(err, errNetlinkIncomplete) {
			t.Errorf("%s: err=%v, want errNetlinkIncomplete", name, err)
		}
	}
}

// nlMsgFull builds one netlink message with flags and a port id.
func nlMsgFull(typ, flags uint16, seq, pid uint32, body []byte) []byte {
	b := nlMsg(typ, seq, body)
	binary.NativeEndian.PutUint16(b[6:8], flags)
	binary.NativeEndian.PutUint32(b[12:16], pid)
	return b
}
