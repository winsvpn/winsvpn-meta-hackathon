package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
)

// Round CM3 Turn 5 (GPT-6 Sol OI-CM3-1): "parseSelectorDump treats NLMSG_DONE
// with NLM_F_DUMP_INTR as a successful, potentially empty selector dump."
// Synthetic kernel datagrams for every flag and error case, through the
// parsers and through the request layer with its retries.

const fakePort = 4242

// linkMsg is the kernel's RTM_NEWLINK answer for one device.
func linkMsg(seq, pid uint32, index int32, name string, mtu uint32) []byte {
	h := make([]byte, ifInfomsgLen)
	binary.NativeEndian.PutUint32(h[4:8], uint32(index))
	h = appendRtAttr(h, iflaIfname, append([]byte(name), 0))
	h = appendRtAttr(h, iflaMTU, u32(mtu))
	return nlMsgFull(rtmNewLink, 0, seq, pid, h)
}

// ruleMsgRaw builds an RTM_NEWRULE with the given attributes, in order.
func ruleMsgRaw(seq, pid uint32, tos byte, attrs ...[2]any) []byte {
	h := make([]byte, fibRuleHdrLen)
	h[0], h[3], h[4] = afInet, tos, 254
	for _, a := range attrs {
		h = appendRtAttr(h, a[0].(uint16), a[1].([]byte))
	}
	return nlMsgFull(rtmNewRule, 0, seq, pid, h)
}

func attr(typ uint16, v []byte) [2]any { return [2]any{typ, v} }

func doneMsg(seq, pid uint32, flags uint16, code int32) []byte {
	return nlMsgFull(nlmsgDone, flags, seq, pid, u32(uint32(code)))
}

// The default rule set (local, main, default) with the attributes a 6.8
// kernel sends for them: table, priority, protocol.
func defaultRules(seq, pid uint32) []byte {
	var b []byte
	for _, r := range [][2]uint32{{0, 255}, {32766, 254}, {32767, 253}} {
		b = append(b, ruleMsgRaw(seq, pid, 0, attr(fraTable, u32(r[1])), attr(fraPriority, u32(r[0])),
			attr(fraProtocol, []byte{2}))...)
	}
	return b
}

func TestParseSelectorDumpFailsClosed(t *testing.T) {
	// Control: a clean rule dump, then NLMSG_DONE.
	sel, done, err := parseSelectorDump(append(defaultRules(1, fakePort), doneMsg(1, fakePort, 0, 0)...), 1, fakePort, rtmNewRule)
	if err != nil || !done || len(sel) != 0 {
		t.Fatalf("clean dump: %v done=%t err=%v", sel, done, err)
	}
	// A datagram without NLMSG_DONE: read on.
	if sel, done, err = parseSelectorDump(defaultRules(1, fakePort), 1, fakePort, rtmNewRule); err != nil || done || len(sel) != 0 {
		t.Fatalf("partial datagram: %v done=%t err=%v", sel, done, err)
	}
	fw := ruleMsgRaw(1, fakePort, 0, attr(fraPriority, u32(100)), attr(fraFwmark, u32(1)), attr(fraTable, u32(100)))
	for name, b := range map[string][]byte{
		// Sol's case: the dump was interrupted; DONE carries the flag.
		"DUMP_INTR on NLMSG_DONE":         append(defaultRules(1, fakePort), doneMsg(1, fakePort, nlmFDumpIntr, 0)...),
		"DUMP_INTR on an empty dump":      doneMsg(1, fakePort, nlmFDumpIntr, 0),
		"DUMP_INTR on an object":          append(nlMsgFull(rtmNewRule, nlmFDumpIntr|0x2, 1, fakePort, make([]byte, fibRuleHdrLen)), doneMsg(1, fakePort, 0, 0)...),
		"NLMSG_OVERRUN":                   nlMsgFull(nlmsgOverrun, 0, 1, fakePort, nil),
		"NLMSG_ERROR inside the dump":     append(defaultRules(1, fakePort), nlMsgFull(nlmsgError, 0, 1, fakePort, append(errnoBytes(syscall.EBUSY), make([]byte, 16)...))...),
		"refused dump (EINVAL)":           nlMsgFull(nlmsgError, 0, 1, fakePort, append(errnoBytes(syscall.EINVAL), make([]byte, 16)...)),
		"an ACK inside the dump":          nlMsgFull(nlmsgError, 0, 1, fakePort, append(u32(0), make([]byte, 16)...)),
		"NLMSG_DONE with an error":        doneMsg(1, fakePort, 0, -int32(syscall.EMSGSIZE)),
		"NLMSG_DONE with a short payload": nlMsgFull(nlmsgDone, 0, 1, fakePort, []byte{1, 2}),
		"a message after NLMSG_DONE":      append(doneMsg(1, fakePort, 0, 0), fw...),
		"another sequence number":         append(ruleMsgRaw(9, fakePort, 0, attr(fraTable, u32(254))), doneMsg(1, fakePort, 0, 0)...),
		"NLMSG_DONE of another request":   doneMsg(2, fakePort, 0, 0),
		"another port id":                 append(defaultRules(1, 77), doneMsg(1, 77, 0, 0)...),
		"a route in a rule dump":          routeMsgTosP(1, 0, 254),
		"an IPv6 rule": func() []byte {
			b := ruleMsgRaw(1, fakePort, 0, attr(fraPriority, u32(9)))
			b[nlmsgHdrLen] = 10
			return b
		}(),
		"a NOOP":                   nlMsgFull(1, 0, 1, fakePort, nil),
		"truncated header":         append(defaultRules(1, fakePort), 1, 2, 3),
		"length past the datagram": append(append([]byte{}, u32(4096)...), fw[4:]...),
		"short rule header":        nlMsgFull(rtmNewRule, 0, 1, fakePort, []byte{afInet}),
		// A malformed attribute BEFORE an fwmark attribute: a lenient walk
		// (Turn 5's attrU32 stopped and reported "not found") read this rule
		// as clean.
		"malformed attribute hides fwmark": func() []byte {
			h := make([]byte, fibRuleHdrLen)
			h[0], h[4] = afInet, 100
			h = append(h, 2, 0, byte(fraPriority), 0) // nla_len 2: shorter than its own header
			h = appendRtAttr(h, fraFwmark, u32(1))
			return append(nlMsgFull(rtmNewRule, 0, 1, fakePort, h), doneMsg(1, fakePort, 0, 0)...)
		}(),
		"a u32 attribute of 2 bytes": append(ruleMsgRaw(1, fakePort, 0, attr(fraPriority, []byte{1, 0}), attr(fraFwmark, u32(1))),
			doneMsg(1, fakePort, 0, 0)...),
		"attribute length past the rule": func() []byte {
			c := append([]byte{}, fw...)
			binary.NativeEndian.PutUint16(c[nlmsgHdrLen+fibRuleHdrLen:], 400)
			return c
		}(),
	} {
		sel, done, err := parseSelectorDump(b, 1, fakePort, rtmNewRule)
		if !errors.Is(err, errNetlinkIncomplete) || done || sel != nil {
			t.Errorf("%s: sel=%v done=%t err=%v, want errNetlinkIncomplete", name, sel, done, err)
		}
	}
	// The reason is named (an operator reads it in the refusal).
	for flag, b := range map[string][]byte{
		"NLM_F_DUMP_INTR": doneMsg(1, fakePort, nlmFDumpIntr, 0),
		"NLMSG_OVERRUN":   nlMsgFull(nlmsgOverrun, 0, 1, fakePort, nil),
	} {
		if _, _, err := parseSelectorDump(b, 1, fakePort, rtmNewRule); err == nil || !strings.Contains(err.Error(), flag) {
			t.Errorf("%s: %v does not name it", flag, err)
		}
	}
}

// The rule check is an allowlist (Round CM3 Turn 6): an attribute the kernel
// evaluates identically for the lookup and the reply passes; fwmark, dscp
// (FRA_DSCP, the selector newer kernels send for `ip rule dscp`), tun_id,
// l3mdev and anything unknown make the rule unaccountable.
func TestParseRuleSelectorAllowlist(t *testing.T) {
	accountable := [][2]any{
		attr(fraDst, []byte{45, 0, 0, 0}), attr(fraSrc, []byte{10, 0, 0, 1}), attr(fraIifname, []byte("lo\x00")),
		attr(fraGoto, u32(200)), attr(fraFlow, u32(5)), attr(fraSuppressIfgroup, u32(1)),
		attr(fraSuppressPrefixlen, u32(0)), attr(fraOifname, []byte("eth0\x00")), attr(fraPad, nil),
		attr(fraUIDRange, make([]byte, 8)), attr(fraProtocol, []byte{4}), attr(fraIPProto, []byte{17}),
		attr(fraSportRange, make([]byte, 4)), attr(fraDportRange, make([]byte, 4)),
		attr(fraSportMask, []byte{0xff, 0xff}), attr(fraDportMask, []byte{0xff, 0xff}),
	}
	for _, a := range accountable {
		b := append(ruleMsgRaw(1, fakePort, 0, attr(fraPriority, u32(50)), a, attr(fraTable, u32(100))), doneMsg(1, fakePort, 0, 0)...)
		if sel, done, err := parseSelectorDump(b, 1, fakePort, rtmNewRule); err != nil || !done || len(sel) != 0 {
			t.Errorf("attribute %d: %v err=%v, want accountable", a[0], sel, err)
		}
	}
	for _, tc := range []struct {
		a    [2]any
		want string
	}{
		{attr(fraDSCP, []byte{10}), "rule pref 50 selects on dscp lookup 100"},
		{attr(fraDSCPMask, []byte{0x3f}), "rule pref 50 selects on dscp mask lookup 100"},
		{attr(fraTunID, make([]byte, 8)), "rule pref 50 selects on tun_id lookup 100"},
		{attr(fraL3mdev, []byte{1}), "rule pref 50 selects on l3mdev lookup 100"},
		{attr(26, u32(1)), "rule pref 50 selects on attribute 26 lookup 100"}, // FRA_FLOWLABEL
		{attr(31, u32(1)), "rule pref 50 selects on attribute 31 lookup 100"}, // past __FRA_MAX today
		{attr(fraFwmask, u32(0xff)), "rule pref 50 fwmark 0x0/0xff lookup 100"},
	} {
		b := append(ruleMsgRaw(1, fakePort, 0, attr(fraPriority, u32(50)), tc.a, attr(fraTable, u32(100))), doneMsg(1, fakePort, 0, 0)...)
		sel, done, err := parseSelectorDump(b, 1, fakePort, rtmNewRule)
		if err != nil || !done || len(sel) != 1 || sel[0].String() != tc.want {
			t.Errorf("attribute %d: %v err=%v, want %q", tc.a[0], sel, err, tc.want)
		}
	}
	// A tos rule and an fwmark rule that also carries dscp name both.
	b := append(ruleMsgRaw(1, fakePort, 0x10, attr(fraPriority, u32(7)), attr(fraTable, u32(100))),
		ruleMsgRaw(1, fakePort, 0, attr(fraPriority, u32(8)), attr(fraFwmark, u32(1)), attr(fraDSCP, []byte{1}), attr(fraTable, u32(100)))...)
	sel, _, err := parseSelectorDump(b, 1, fakePort, rtmNewRule)
	if err != nil || len(sel) != 2 || sel[0].String() != "rule pref 7 tos 0x10 lookup 100" ||
		sel[1].String() != "rule pref 8 fwmark 0x1 dscp lookup 100" {
		t.Fatalf("%q err=%v", describeSelectors(sel), err)
	}
}

func TestParseLinkReply(t *testing.T) {
	name, mtu, err := parseLinkReply(linkMsg(2, fakePort, 7, "eth0", 1400), 2, fakePort, 7)
	if err != nil || name != "eth0" || mtu != 1400 {
		t.Fatalf("got %q %d %v", name, mtu, err)
	}
	req := encodeLinkGetRequest(2, 7)
	if binary.NativeEndian.Uint16(req[4:6]) != rtmGetLink || binary.NativeEndian.Uint16(req[6:8]) != nlmFRequest ||
		binary.NativeEndian.Uint32(req[nlmsgHdrLen+4:]) != 7 || int(binary.NativeEndian.Uint32(req[0:4])) != len(req) ||
		!bytes.Equal(req[nlmsgHdrLen:nlmsgHdrLen+4], []byte{0, 0, 0, 0}) || !bytes.Equal(req[nlmsgHdrLen+8:], make([]byte, 8)) {
		t.Fatalf("link request %x", req)
	}
	noMTU := make([]byte, ifInfomsgLen)
	binary.NativeEndian.PutUint32(noMTU[4:8], 7)
	noMTU = appendRtAttr(noMTU, iflaIfname, []byte("eth0\x00"))
	for name, b := range map[string][]byte{
		"another device":           linkMsg(2, fakePort, 8, "eth1", 1500),
		"another sequence":         linkMsg(1, fakePort, 7, "eth0", 1400),
		"another port id":          linkMsg(2, 5, 7, "eth0", 1400),
		"no IFLA_MTU":              nlMsgFull(rtmNewLink, 0, 2, fakePort, noMTU),
		"an MTU below 68":          linkMsg(2, fakePort, 7, "eth0", 0),
		"device gone (ENODEV)":     nlMsgFull(nlmsgError, 0, 2, fakePort, append(errnoBytes(syscall.ENODEV), make([]byte, 16)...)),
		"an ACK":                   nlMsgFull(nlmsgError, 0, 2, fakePort, append(u32(0), make([]byte, 16)...)),
		"DUMP_INTR":                nlMsgFull(rtmNewLink, nlmFDumpIntr, 2, fakePort, linkMsg(2, fakePort, 7, "eth0", 1400)[nlmsgHdrLen:]),
		"a route instead":          nlMsgFull(rtmNewRoute, 0, 2, fakePort, newRouteBody(7, 254, 0, 0)),
		"short ifinfomsg":          nlMsgFull(rtmNewLink, 0, 2, fakePort, []byte{0, 0, 0, 0}),
		"two answers":              append(linkMsg(2, fakePort, 7, "eth0", 1400), linkMsg(2, fakePort, 7, "eth0", 1400)...),
		"truncated IFLA_MTU value": nlMsgFull(rtmNewLink, 0, 2, fakePort, appendRtAttr(append([]byte{}, noMTU...), iflaMTU, []byte{0x78, 5})),
	} {
		if _, _, err := parseLinkReply(b, 2, fakePort, 7); !errors.Is(err, errNetlinkIncomplete) {
			t.Errorf("%s: err=%v, want errNetlinkIncomplete", name, err)
		}
	}
}

// fakeNl is one scripted socket: recv hands out datagrams in order, then
// reports no answer within the bound. slow delays each recv.
type fakeNl struct {
	datagrams [][]byte
	sent      [][]byte
	slow      time.Duration
	closed    bool
}

func (f *fakeNl) port() uint32 { return fakePort }
func (f *fakeNl) close()       { f.closed = true }
func (f *fakeNl) send(req []byte) error {
	f.sent = append(f.sent, append([]byte{}, req...))
	return nil
}
func (f *fakeNl) recv(deadline time.Time) ([]byte, error) {
	if f.slow > 0 {
		time.Sleep(f.slow)
	}
	// The deadline is the caller's to enforce (nlDump checks it between
	// datagrams); this fake only runs out.
	_ = deadline
	if len(f.datagrams) == 0 {
		return nil, incompleteAnswer("no answer within %v", netlinkAnswerBound)
	}
	b := f.datagrams[0]
	f.datagrams = f.datagrams[1:]
	return b, nil
}

// scriptedOpen hands out one fakeNl per attempt.
func scriptedOpen(t *testing.T, attempts ...*fakeNl) (func() (nlTransport, error), *int) {
	n := 0
	return func() (nlTransport, error) {
		if n >= len(attempts) {
			t.Fatalf("attempt %d: the script has %d", n+1, len(attempts))
		}
		f := attempts[n]
		n++
		return f, nil
	}, &n
}

func cleanDump() *fakeNl {
	return &fakeNl{datagrams: [][]byte{
		append(defaultRules(1, fakePort), doneMsg(1, fakePort, 0, 0)...),
		append(routeMsgTosP(2, 0, 254), doneMsg(2, fakePort, 0, 0)...),
	}}
}

func routeMsgTosP(seq uint32, tos byte, table uint32) []byte {
	b := routeMsgTos(seq, tos, table)
	binary.NativeEndian.PutUint32(b[12:16], fakePort)
	return b
}

// Sol's reproduction through the whole dump path: an interrupted dump that
// omitted the fwmark rule is never a clean result. It is asked again on a
// fresh socket; after three incomplete answers the error stands, and every
// discarded answer is counted.
func TestListSelectorsRetriesAnInterruptedDumpThenFailsClosed(t *testing.T) {
	interrupted := func() *fakeNl {
		return &fakeNl{datagrams: [][]byte{append(defaultRules(1, fakePort), doneMsg(1, fakePort, nlmFDumpIntr, 0)...)}}
	}
	before := netlinkIncompleteAnswers.Load()
	open, n := scriptedOpen(t, interrupted(), interrupted(), interrupted())
	sel, err := listSelectorsVia(open)
	if !errors.Is(err, errNetlinkIncomplete) || sel != nil || *n != netlinkAttempts {
		t.Fatalf("three interrupted dumps: %v err=%v attempts=%d, want errNetlinkIncomplete after %d", sel, err, *n, netlinkAttempts)
	}
	if !strings.Contains(err.Error(), "NLM_F_DUMP_INTR") || !strings.Contains(err.Error(), "3 attempts") {
		t.Fatalf("error %q does not say why", err)
	}
	if got := netlinkIncompleteAnswers.Load() - before; got != netlinkAttempts {
		t.Fatalf("counted %d incomplete answers, want %d", got, netlinkAttempts)
	}
	// Interrupted once, then complete: the complete answer is used, and it
	// is the one that shows the fwmark rule.
	withMark := &fakeNl{datagrams: [][]byte{
		append(append(defaultRules(1, fakePort), ruleMsgRaw(1, fakePort, 0, attr(fraPriority, u32(100)),
			attr(fraFwmark, u32(1)), attr(fraTable, u32(100)))...), doneMsg(1, fakePort, 0, 0)...),
		doneMsg(2, fakePort, 0, 0),
	}}
	first := interrupted()
	open, n = scriptedOpen(t, first, withMark)
	sel, err = listSelectorsVia(open)
	if err != nil || len(sel) != 1 || sel[0].Kind != "fwmark rule" || *n != 2 || !first.closed || !withMark.closed {
		t.Fatalf("retry: %v err=%v attempts=%d closed=%t/%t", sel, err, *n, first.closed, withMark.closed)
	}
	// An interruption in the ROUTE dump (after a clean rule dump) also
	// fails the attempt.
	routeIntr := &fakeNl{datagrams: [][]byte{
		append(defaultRules(1, fakePort), doneMsg(1, fakePort, 0, 0)...),
		doneMsg(2, fakePort, nlmFDumpIntr, 0),
	}}
	open, n = scriptedOpen(t, routeIntr, cleanDump())
	if sel, err = listSelectorsVia(open); err != nil || len(sel) != 0 || *n != 2 {
		t.Fatalf("route dump interrupted then clean: %v err=%v attempts=%d", sel, err, *n)
	}
	// Control: one clean attempt.
	open, n = scriptedOpen(t, cleanDump())
	if sel, err = listSelectorsVia(open); err != nil || len(sel) != 0 || *n != 1 {
		t.Fatalf("clean: %v err=%v attempts=%d", sel, err, *n)
	}
}

// A dump that never delivers NLMSG_DONE within netlinkAnswerBound is
// incomplete, even while objects keep arriving.
func TestDumpWithoutDoneWithinTheBoundFailsClosed(t *testing.T) {
	saved := netlinkAnswerBound
	netlinkAnswerBound = 30 * time.Millisecond
	t.Cleanup(func() { netlinkAnswerBound = saved })
	endless := func() *fakeNl {
		f := &fakeNl{slow: 5 * time.Millisecond}
		for range 100 {
			f.datagrams = append(f.datagrams, defaultRules(1, fakePort))
		}
		return f
	}
	open, n := scriptedOpen(t, endless(), endless(), endless())
	start := time.Now()
	sel, err := listSelectorsVia(open)
	if !errors.Is(err, errNetlinkIncomplete) || !strings.Contains(err.Error(), "no NLMSG_DONE within") || sel != nil || *n != 3 {
		t.Fatalf("endless dump: %v err=%v attempts=%d", sel, err, *n)
	}
	if el := time.Since(start); el > 3*(netlinkAnswerBound+50*time.Millisecond) {
		t.Fatalf("three bounded attempts took %v", el)
	}
	// Silence (the socket's own receive timeout) is the same.
	silent := func() *fakeNl { return &fakeNl{} }
	open, _ = scriptedOpen(t, silent(), silent(), silent())
	if _, err = listSelectorsVia(open); !errors.Is(err, errNetlinkIncomplete) {
		t.Fatalf("silent kernel: %v", err)
	}
}

// The per-client and startup question: route, then device. An incomplete
// answer to either is retried and then fails closed; a complete kernel errno
// is returned at once, not retried.
func TestMeasureRouteViaHoldsBothAnswers(t *testing.T) {
	dst := netip.MustParseAddrPort("45.0.1.2:40000")
	route := func(seq uint32, flags uint16, pid uint32) []byte {
		return nlMsgFull(rtmNewRoute, flags, seq, pid, newRouteBody(7, 100, 0, 0))
	}
	good := func() *fakeNl {
		return &fakeNl{datagrams: [][]byte{route(1, 0, fakePort), linkMsg(2, fakePort, 7, "eth0", 1400)}}
	}
	open, n := scriptedOpen(t, good())
	r, err := measureRouteVia(open, egressLookup{Port: 9111}, dst)
	if err != nil || r.Device != "eth0" || r.MTU != 1400 || r.DeviceMTU != 1400 || r.Table != 100 || r.DestPort != 40000 || *n != 1 {
		t.Fatalf("good: %+v err=%v attempts=%d", r, err, *n)
	}
	for name, bad := range map[string]func() *fakeNl{
		"route for another port id": func() *fakeNl {
			return &fakeNl{datagrams: [][]byte{route(1, 0, 1), linkMsg(2, fakePort, 7, "eth0", 1400)}}
		},
		"stale route answer (seq 0)": func() *fakeNl {
			return &fakeNl{datagrams: [][]byte{route(0, 0, fakePort), route(1, 0, fakePort)}}
		},
		"link of another device": func() *fakeNl {
			return &fakeNl{datagrams: [][]byte{route(1, 0, fakePort), linkMsg(2, fakePort, 8, "eth1", 1500)}}
		},
		"no link answer": func() *fakeNl {
			return &fakeNl{datagrams: [][]byte{route(1, 0, fakePort)}}
		},
		"no answer at all": func() *fakeNl { return &fakeNl{} },
	} {
		open, n = scriptedOpen(t, bad(), bad(), bad())
		r, err = measureRouteVia(open, egressLookup{Port: 9111}, dst)
		if !errors.Is(err, errNetlinkIncomplete) || *n != 3 || r.MTU != 0 {
			t.Errorf("%s: %+v err=%v attempts=%d, want errNetlinkIncomplete after 3", name, r, err, *n)
		}
		if lookupSaysNoRoute(err) {
			t.Errorf("%s: an incomplete answer would be served", name)
		}
	}
	unreachable := &fakeNl{datagrams: [][]byte{nlMsgFull(nlmsgError, 0, 1, fakePort, append(errnoBytes(syscall.ENETUNREACH), make([]byte, 16)...))}}
	open, n = scriptedOpen(t, unreachable)
	if _, err = measureRouteVia(open, egressLookup{}, dst); !errors.Is(err, syscall.ENETUNREACH) || *n != 1 || !lookupSaysNoRoute(err) {
		t.Fatalf("a complete ENETUNREACH answer: err=%v attempts=%d", err, *n)
	}
	// The requests: the route question for the listener's flow and the
	// client's port, then the device the ROUTE named.
	f := good()
	open, _ = scriptedOpen(t, f)
	if _, err = measureRouteVia(open, egressLookup{Port: 9111}, dst); err != nil || len(f.sent) != 2 ||
		binary.NativeEndian.Uint16(f.sent[0][4:6]) != rtmGetRoute || binary.NativeEndian.Uint16(f.sent[1][4:6]) != rtmGetLink ||
		binary.NativeEndian.Uint32(f.sent[1][nlmsgHdrLen+4:]) != 7 {
		t.Fatalf("requests %x err=%v", f.sent, err)
	}
	attrs := rtAttrs(t, f.sent[0])
	if !bytes.Equal(attrs[rtaSport], []byte{0x23, 0x97}) || !bytes.Equal(attrs[rtaDport], []byte{0x9c, 0x40}) ||
		!bytes.Equal(attrs[rtaDst], []byte{45, 0, 1, 2}) {
		t.Fatalf("route request attributes %x", attrs)
	}
}

// The guard and startup act on it: incomplete refuses, a complete "no route"
// serves (as before), anything unexplained refuses.
func TestIncompleteAnswersFailClosedAtEveryCaller(t *testing.T) {
	saved := measureClientEgress
	t.Cleanup(func() { measureClientEgress = saved })
	g := &clientEgressGuard{datagram: 1430}
	incomplete := incompleteAnswer("NLM_F_DUMP_INTR (3 attempts)")
	measureClientEgress = func(egressLookup, netip.AddrPort) egressRoute { return egressRoute{Err: incomplete} }
	if _, ok := g.check(netip.MustParseAddrPort("45.0.1.2:40000")); ok {
		t.Fatal("the guard served an incomplete answer")
	}
	// Even one whose own error is a no-route errno (a stale link answer).
	measureClientEgress = func(egressLookup, netip.AddrPort) egressRoute {
		return egressRoute{Err: fmt.Errorf("%w: link 7: %w", errNetlinkIncomplete, syscall.EHOSTUNREACH)}
	}
	if _, ok := g.check(netip.MustParseAddrPort("45.0.1.2:40000")); ok {
		t.Fatal("the guard served an incomplete answer carrying EHOSTUNREACH")
	}
	var logs bytes.Buffer
	err := checkEgressMTU(mustSizing(t, 1450, carrier.ClassUDP), egressLookup{Port: 9111},
		[]egressRoute{{Dest: egressProbeDestinations[0], Device: "eth0", MTU: 1500, DeviceMTU: 1500},
			{Dest: egressProbeDestinations[1], Err: incomplete}}, nil, &logs)
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("startup with one incomplete probe answer: %v", err)
	}
}
