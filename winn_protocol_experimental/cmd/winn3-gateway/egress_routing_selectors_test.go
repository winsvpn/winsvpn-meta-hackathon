package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/tun"
)

// Round CM3 Turn 4 (GPT-6 Sol OI-CM3-1): a netfilter OUTPUT mark (or TOS)
// rewrite plus a policy rule or route selecting on it moves established
// replies to a route no lookup of the gateway's shows. The gateway treats
// any such rule or route as unaccountable.

func installSelectorStub(t *testing.T, sel *atomic.Value) {
	t.Helper()
	saved := detectRoutingSelectors
	detectRoutingSelectors = func() ([]routingSelector, error) {
		v, _ := sel.Load().([]routingSelector)
		return v, nil
	}
	t.Cleanup(func() { detectRoutingSelectors = saved })
}

var fwmarkRule = routingSelector{Kind: "fwmark rule", Priority: 100, Table: 100, Mark: 1, Mask: 0xffffffff, HasMask: true}

func TestCheckRoutingAccountable(t *testing.T) {
	saved := detectRoutingSelectors
	t.Cleanup(func() { detectRoutingSelectors = saved })
	for _, tc := range []struct {
		name   string
		sel    []routingSelector
		err    error
		refuse string
	}{
		{name: "none"},
		{name: "platform", err: errors.ErrUnsupported},
		{name: "fwmark rule", sel: []routingSelector{fwmarkRule}, refuse: "rule pref 100 fwmark 0x1/0xffffffff lookup 100"},
		{name: "not fwmark rule", sel: []routingSelector{{Kind: "fwmark rule", Priority: 5, Table: 51820, Mark: 0xca6c, Invert: true}},
			refuse: "rule pref 5 not fwmark 0xca6c lookup 51820"},
		{name: "tos rule", sel: []routingSelector{{Kind: "tos rule", Priority: 7, Table: 100, Tos: 0x10}}, refuse: "rule pref 7 tos 0x10 lookup 100"},
		{name: "tos route", sel: []routingSelector{{Kind: "tos route", Table: 254, Tos: 0x10}}, refuse: "route in table 254 keyed on tos 0x10"},
		{name: "dump refused", err: fmt.Errorf("kernel dump: %w", syscall.EINVAL), refuse: "cannot list the policy rules"},
		{name: "no netlink", err: fmt.Errorf("%w: rtnetlink socket refused", errFlowNotDescribable), refuse: "cannot list the policy rules"},
		// Round CM3 Turn 6.
		{name: "interrupted dump", err: incompleteAnswer("NLM_F_DUMP_INTR: the dump was interrupted and may be missing objects (3 attempts)"),
			refuse: "NLM_F_DUMP_INTR"},
		{name: "kernel EOPNOTSUPP in the dump", err: fmt.Errorf("%w: kernel dump error %w", errNetlinkIncomplete, syscall.EOPNOTSUPP),
			refuse: "cannot list the policy rules"},
		{name: "kernel ENOSYS", err: syscall.ENOSYS, refuse: "cannot list the policy rules"},
	} {
		detectRoutingSelectors = func() ([]routingSelector, error) { return tc.sel, tc.err }
		var log bytes.Buffer
		err := checkRoutingAccountable(&log)
		if tc.refuse == "" {
			if err != nil {
				t.Fatalf("%s: refused: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.refuse) {
			t.Fatalf("%s: %v, want a refusal naming %q", tc.name, err, tc.refuse)
		}
	}
}

// Through runServe: the refusal happens at startup, before the listener.
func TestRunServeRefusesUnaccountableRouting(t *testing.T) {
	var sel atomic.Value
	sel.Store([]routingSelector{fwmarkRule})
	installSelectorStub(t, &sel)
	opts := operatorValueOptions(t)
	err := runServe(opts, new(bytes.Buffer))
	if err == nil || !strings.Contains(err.Error(), "selects on the packet mark or TOS") {
		t.Fatalf("runServe with an fwmark rule: %v, want the refusal", err)
	}
	sel.Store([]routingSelector(nil))
	if err := runServe(operatorValueOptions(t), new(bytes.Buffer)); err != nil {
		t.Fatalf("control, no selector: %v", err)
	}
}

// While a selector exists: every session is closed and every new client
// refused; when it goes, clients are admitted again.
func TestSweepEgressClosesEverySessionWhileRoutingIsUnaccountable(t *testing.T) {
	stub := &clientEgressStub{}
	installClientEgressStub(t, stub)
	var sel atomic.Value
	sel.Store([]routingSelector(nil))
	installSelectorStub(t, &sel)
	logs := &safeBuffer{}
	savedLog := egressLog
	egressLog = logs
	t.Cleanup(func() { egressLog = savedLog })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newEgressFixture(t, ctx, loopbackConn(t), func(fn func()) { fn() })
	closing := map[*peerSession]struct{}{}

	if n := f.srv.sweepEgress(time.Now(), closing); n != 0 || f.srv.egressUnaccountable.Load() {
		t.Fatalf("no selector: closed %d, unaccountable %t", n, f.srv.egressUnaccountable.Load())
	}
	sel.Store([]routingSelector{fwmarkRule})
	if n := f.srv.sweepEgress(time.Now(), closing); n != 1 || !f.srv.egressUnaccountable.Load() {
		t.Fatalf("fwmark rule: closed %d, unaccountable %t; want 1 and true", n, f.srv.egressUnaccountable.Load())
	}
	out := string(logs.snapshot())
	if !strings.Contains(out, "egress routing UNACCOUNTABLE (rule pref 100 fwmark 0x1/0xffffffff lookup 100)") ||
		!strings.Contains(out, "closing a session: policy routing selects on mark or TOS") || strings.Contains(out, "127.0.0.1") {
		t.Fatalf("log %q", out)
	}
	waitFor(t, 10*time.Second, "the closed session to leave the table", func() bool { return f.sessions() == 0 })
	waitFor(t, 10*time.Second, "the client gate to leave carrying", func() bool {
		return f.cli.loop.Tunnel().Gate().State() != tun.StateCarrying
	})
	st := f.srv.status()
	if !st.EgressRoutingUnaccountable || st.EgressMTUClosed != 1 {
		t.Fatalf("status unaccountable=%t closed=%d", st.EgressRoutingUnaccountable, st.EgressMTUClosed)
	}
	// Round CM3 Turn 6: discarded incomplete answers are in the posture.
	netlinkIncompleteAnswers.Add(7)
	st = f.srv.status()
	js, err := json.Marshal(st)
	if err != nil || st.EgressNetlinkIncomplete < 7 || st.EgressNetlinkIncomplete != netlinkIncompleteAnswers.Load() ||
		!strings.Contains(string(js), fmt.Sprintf(`"egress_netlink_incomplete":%d`, st.EgressNetlinkIncomplete)) {
		t.Fatalf("status egress_netlink_incomplete=%d (counter %d): %s %v", st.EgressNetlinkIncomplete, netlinkIncompleteAnswers.Load(), js, err)
	}
	// A new client is refused while the rule exists, whatever its route.
	refused := f.srv.egressRefused.Load()
	if f.srv.clientEgressFits(netip.MustParseAddrPort("46.0.0.1:40000")) || f.srv.egressRefused.Load() != refused+1 {
		t.Fatal("a new client was admitted while routing was unaccountable")
	}
	// The rule goes: admitted again.
	sel.Store([]routingSelector(nil))
	f.srv.sweepEgress(time.Now(), closing)
	if f.srv.egressUnaccountable.Load() || !f.srv.clientEgressFits(netip.MustParseAddrPort("46.0.0.1:40000")) {
		t.Fatal("clients still refused after the selector went away")
	}
	if !strings.Contains(string(logs.snapshot()), "egress routing accountable again") {
		t.Fatalf("no recovery line: %q", logs.snapshot())
	}
	if f.srv.status().EgressSweepMaxUS == 0 {
		t.Fatal("egress_sweep_max_us was not recorded")
	}
}

// Round CM3 Turn 6: every dump error is unaccountable, whatever it is: a
// refusal, a timeout, an incomplete answer. (Turn 5 kept the previous verdict
// on a timeout, so an incomplete dump could leave "accountable" standing.)
// Another platform is skipped, and a clean dump clears the verdict.
func TestSweepEgressRoutingDumpErrors(t *testing.T) {
	saved := detectRoutingSelectors
	t.Cleanup(func() { detectRoutingSelectors = saved })
	savedLog := egressLog
	logs := new(safeBuffer)
	egressLog = logs
	t.Cleanup(func() { egressLog = savedLog })
	for _, dumpErr := range []error{
		syscall.EAGAIN,
		fmt.Errorf("kernel dump: %w", syscall.EINVAL),
		incompleteAnswer("NLM_F_DUMP_INTR: the dump was interrupted and may be missing objects (3 attempts)"),
		incompleteAnswer("no NLMSG_DONE within 250ms (3 attempts)"),
		// syscall.Errno EOPNOTSUPP matches errors.ErrUnsupported; it is a
		// kernel answer, not another platform.
		fmt.Errorf("%w: kernel dump error %w", errNetlinkIncomplete, syscall.EOPNOTSUPP),
		syscall.EOPNOTSUPP,
		syscall.ENOSYS,
	} {
		s := &server{egressGuard: &clientEgressGuard{datagram: 1430}}
		detectRoutingSelectors = func() ([]routingSelector, error) { return nil, dumpErr }
		s.sweepEgress(time.Now(), map[*peerSession]struct{}{})
		if !s.egressUnaccountable.Load() {
			t.Fatalf("dump error %v left routing accountable", dumpErr)
		}
		if s.clientEgressFits(netip.MustParseAddrPort("45.0.1.2:40000")) {
			t.Fatalf("dump error %v: a new client was admitted", dumpErr)
		}
		detectRoutingSelectors = func() ([]routingSelector, error) { return nil, nil }
		s.sweepEgress(time.Now(), map[*peerSession]struct{}{})
		if s.egressUnaccountable.Load() {
			t.Fatalf("a clean dump after %v did not clear the verdict", dumpErr)
		}
	}
	if !strings.Contains(string(logs.snapshot()), "could not be listed completely") {
		t.Fatalf("log: %q", logs.snapshot())
	}
	s := &server{egressGuard: &clientEgressGuard{datagram: 1430}}
	detectRoutingSelectors = func() ([]routingSelector, error) { return nil, errors.ErrUnsupported }
	s.sweepEgress(time.Now(), map[*peerSession]struct{}{})
	if s.egressUnaccountable.Load() {
		t.Fatal("another platform's ErrUnsupported made routing unaccountable")
	}
}

// ruleMsg builds an RTM_NEWRULE for the dump parser.
func ruleMsg(seq uint32, family, tos byte, flags uint32, attrs map[uint16]uint32) []byte {
	h := make([]byte, fibRuleHdrLen)
	h[0], h[3], h[4] = family, tos, 100
	binary.NativeEndian.PutUint32(h[8:12], flags)
	for _, typ := range []uint16{fraPriority, fraFwmark, fraTable, fraFwmask} {
		if v, ok := attrs[typ]; ok {
			h = appendRtAttr(h, typ, u32(v))
		}
	}
	return nlMsg(rtmNewRule, seq, h)
}

// ruleMsgP is ruleMsg addressed to fakePort.
func ruleMsgP(seq uint32, family, tos byte, flags uint32, attrs map[uint16]uint32) []byte {
	b := ruleMsg(seq, family, tos, flags, attrs)
	binary.NativeEndian.PutUint32(b[12:16], fakePort)
	return b
}

func routeMsgTos(seq uint32, tos byte, table uint32) []byte {
	rt := make([]byte, rtMsgLen)
	rt[0], rt[3], rt[4] = afInet, tos, 254
	return nlMsg(rtmNewRoute, seq, appendRtAttr(rt, rtaTable, u32(table)))
}

func TestParseSelectorDump(t *testing.T) {
	var b []byte
	b = append(b, ruleMsgP(1, afInet, 0, 0, map[uint16]uint32{fraPriority: 0, fraTable: 255})...)                             // local: no
	b = append(b, ruleMsgP(1, afInet, 0, 0, map[uint16]uint32{fraPriority: 100, fraFwmark: 1, fraTable: 100})...)             // fwmark
	b = append(b, ruleMsgP(1, afInet, 0, fibRuleInvert, map[uint16]uint32{fraPriority: 5, fraFwmark: 0, fraFwmask: 0xff})...) // not fwmark 0/0xff
	b = append(b, ruleMsgP(1, afInet, 0x10, 0, map[uint16]uint32{fraPriority: 7, fraTable: 100})...)                          // tos
	sel, done, err := parseSelectorDump(b, 1, fakePort, rtmNewRule)
	if err != nil || done || len(sel) != 3 {
		t.Fatalf("rules: %v done=%t err=%v", sel, done, err)
	}
	if sel[0].String() != "rule pref 100 fwmark 0x1 lookup 100" || sel[1].String() != "rule pref 5 not fwmark 0x0/0xff lookup 100" ||
		sel[2].String() != "rule pref 7 tos 0x10 lookup 100" {
		t.Fatalf("rules: %q | %q | %q", sel[0], sel[1], sel[2])
	}
	r, done, err := parseSelectorDump(append(append(routeMsgTosP(2, 0x10, 100), routeMsgTosP(2, 0, 254)...), doneMsg(2, fakePort, 0, 0)...), 2, fakePort, rtmNewRoute)
	if err != nil || !done || len(r) != 1 || r[0].String() != "route 0.0.0.0/0 in table 100 keyed on tos 0x10" {
		t.Fatalf("routes: %v done=%t err=%v", r, done, err)
	}
	if _, done, err := parseSelectorDump(nlMsgFull(nlmsgError, 0, 3, fakePort, append(errnoBytes(syscall.EINVAL), make([]byte, 16)...)), 3, fakePort, rtmNewRule); done ||
		!errors.Is(err, syscall.EINVAL) || !errors.Is(err, errNetlinkIncomplete) {
		t.Fatalf("error: done=%t err=%v", done, err)
	}
	for _, typ := range []uint16{rtmGetRule, rtmGetRoute} {
		req := encodeDumpRequest(typ, 7)
		if binary.NativeEndian.Uint16(req[4:6]) != typ || binary.NativeEndian.Uint16(req[6:8]) != nlmFRequest|nlmFDump ||
			binary.NativeEndian.Uint32(req[8:12]) != 7 || req[nlmsgHdrLen] != afInet || int(binary.NativeEndian.Uint32(req[0:4])) != len(req) {
			t.Fatalf("dump request %d: %x", typ, req)
		}
		for _, x := range req[nlmsgHdrLen+1:] {
			if x != 0 {
				t.Fatalf("dump request %d header not zeroed: %x", typ, req)
			}
		}
	}
}

func errnoBytes(e syscall.Errno) []byte {
	code := -int32(e)
	return u32(uint32(code))
}
