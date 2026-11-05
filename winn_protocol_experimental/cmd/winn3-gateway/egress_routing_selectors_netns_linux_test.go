//go:build linux

package main

import (
	"context"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Round CM3 Turn 4 (GPT-6 Sol OI-CM3-1) on a real kernel.

// The real rule and route dump finds exactly the selectors that make a reply
// route unaccountable, and not the ones the per-client lookup already
// carries (ipproto, dport, iif lo, oif).
func TestEgressNetnsListsRoutingSelectors(t *testing.T) {
	requireEgressNetns(t)
	const ns = "l80sel"
	policyNetns(t, ns)
	list := func() []routingSelector {
		var sel []routingSelector
		var err error
		inNetns(t, ns, func() { sel, err = listRoutingSelectors() })
		if err != nil {
			t.Fatal(err)
		}
		return sel
	}
	if sel := list(); len(sel) != 0 {
		t.Fatalf("default rules listed as selectors: %v", sel)
	}
	for _, r := range [][]string{
		{"rule", "add", "pref", "200", "ipproto", "udp", "dport", "40000", "lookup", "100"},
		{"rule", "add", "pref", "201", "iif", "lo", "lookup", "100"},
		{"rule", "add", "pref", "202", "oif", "ts1", "lookup", "100"},
		{"rule", "add", "pref", "203", "uidrange", "0-0", "lookup", "100"},
	} {
		ipCmd(t, append([]string{"-n", ns}, r...)...)
	}
	if sel := list(); len(sel) != 0 {
		t.Fatalf("selectors the lookup carries were listed: %v", sel)
	}
	ipCmd(t, "-n", ns, "rule", "add", "pref", "100", "fwmark", "1", "lookup", "100")
	ipCmd(t, "-n", ns, "rule", "add", "pref", "101", "not", "fwmark", "0x2/0xff", "lookup", "100")
	ipCmd(t, "-n", ns, "rule", "add", "pref", "102", "tos", "0x10", "lookup", "100")
	ipCmd(t, "-n", ns, "route", "add", "45.0.0.0/16", "tos", "0x10", "dev", "ts1")
	sel := list()
	got := describeSelectors(sel)
	for _, want := range []string{"rule pref 100 fwmark 0x1", "rule pref 101 not fwmark 0x2/0xff lookup 100",
		"rule pref 102 tos 0x10 lookup 100", "route 45.0.0.0/16 in table 254 keyed on tos 0x10"} {
		if !strings.Contains(got, want) {
			t.Fatalf("selectors %q lack %q", got, want)
		}
	}
	if len(sel) != 4 {
		t.Fatalf("%d selectors, want 4: %q", len(sel), got)
	}
	t.Logf("listed: %s", got)
}

// iif lo and oif rules need no special handling: an output route lookup
// carries iif lo and the unbound listener's oif 0, in the real send and in
// RTM_GETROUTE alike (measured: lane_l80/vm/cm3t5_reroute_premises.txt).
func TestEgressNetnsIifAndOifRulesAreAccounted(t *testing.T) {
	requireEgressNetns(t)
	const ns = "l80iif"
	listener := egressLookup{Port: 9111}
	g := &clientEgressGuard{lookup: listener, datagram: plannedIPv4Datagram(mustSizing(t, 1450, carrier.ClassUDP))}
	client := netip.MustParseAddrPort("46.0.0.1:40000")
	for _, tc := range []struct {
		rule  []string
		serve bool
	}{
		{rule: []string{"iif", "lo"}, serve: false},
		{rule: []string{"oif", "ts1"}, serve: true},
	} {
		policyNetns(t, ns)
		ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.2.1", "dev", "ts2")
		ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.1.1", "dev", "ts1", "table", "100")
		ipCmd(t, append([]string{"-n", ns, "rule", "add", "pref", "100"}, append(tc.rule, "lookup", "100")...)...)
		var r egressRoute
		var ok bool
		inNetns(t, ns, func() { r, ok = g.check(client) })
		dev, fields := ipRouteGet(t, ns, client.Addr(), listener)
		if r.Err != nil || ok != tc.serve || dev != r.Device {
			t.Fatalf("rule %v: %+v served=%t, ip route get %q; want served=%t and the same device",
				tc.rule, r, ok, strings.Join(fields, " "), tc.serve)
		}
		t.Logf("rule %v: via %s mtu %d served=%t (ip route get: dev %s)", tc.rule, r.Device, r.MTU, ok, dev)
	}
}

// Sol's reproduction: a session carries with a 1500 route; table 100 has a
// 1400 route to the client. A mangle OUTPUT MARK rule on the gateway's replies
// alone changes nothing (no fwmark rule selects on it; measured, not routed).
// Adding `ip rule add fwmark 1 lookup 100` (which, with the MARK, moves the
// replies to 1400) is a rule notification: the watch finds the fwmark rule
// and closes the session within its window, and new clients are refused.
func TestEgressNetnsMarkRuleClosesALiveSession(t *testing.T) {
	requireEgressNetns(t)
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skipf("iptables: %v", err)
	}
	gatewayClientNetns(t)
	savedInterval := egressRecheckInterval
	egressRecheckInterval = time.Minute
	t.Cleanup(func() { egressRecheckInterval = savedInterval })

	var lookups, dumps atomic.Int64
	savedMeasure, savedDetect := measureClientEgress, detectRoutingSelectors
	measureClientEgress = func(l egressLookup, d netip.AddrPort) egressRoute {
		lookups.Add(1)
		var r egressRoute
		if err := runInNetns(wgNS, func() { r = savedMeasure(l, d) }); err != nil {
			return egressRoute{Dest: d.Addr(), DestPort: d.Port(), Err: err}
		}
		return r
	}
	detectRoutingSelectors = func() ([]routingSelector, error) {
		dumps.Add(1)
		var sel []routingSelector
		var err error
		if nerr := runInNetns(wgNS, func() { sel, err = listRoutingSelectors() }); nerr != nil {
			return nil, nerr
		}
		return sel, err
	}
	t.Cleanup(func() { measureClientEgress, detectRoutingSelectors = savedMeasure, savedDetect })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := udpIn(t, wgNS, wgAddr)
	port := conn.LocalAddr().(*net.UDPAddr).Port
	f := newEgressFixture(t, ctx, conn, func(fn func()) {
		if err := runInNetns(wcNS, fn); err != nil {
			t.Fatal(err)
		}
	})
	var changed <-chan struct{}
	var stopWatch func()
	var werr error
	inNetns(t, wgNS, func() { changed, stopWatch, werr = startRouteWatch() })
	if werr != nil {
		t.Fatal(werr)
	}
	defer stopWatch()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	watchCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); f.srv.runEgressWatch(watchCtx, changed, ticker.C) }()
	defer func() { stop(); <-done }()

	ipCmd(t, "-n", wgNS, "route", "add", wcAddr+"/32", "dev", "g0", "mtu", "1400", "table", "100")
	// The MARK rule alone: no rtnetlink notification, and nothing to reroute
	// on. An unrelated route change then forces a sweep: nothing closes.
	if out, err := exec.Command("ip", "netns", "exec", wgNS, "iptables", "-t", "mangle", "-A", "OUTPUT",
		"-p", "udp", "--sport", strconv.Itoa(port), "-j", "MARK", "--set-mark", "1").CombinedOutput(); err != nil {
		t.Fatalf("iptables: %v %s", err, out)
	}
	time.Sleep(egressSweepMinGap)
	before := dumps.Load()
	ipCmd(t, "-n", wgNS, "route", "add", "203.0.113.0/24", "dev", "g0")
	waitFor(t, 2*time.Second, "a sweep after an unrelated change", func() bool { return dumps.Load() > before })
	time.Sleep(200 * time.Millisecond)
	if f.srv.egressClosed.Load() != 0 || f.srv.egressUnaccountable.Load() || f.sessions() != 1 {
		t.Fatalf("a MARK rule with no fwmark rule closed %d sessions (unaccountable %t)",
			f.srv.egressClosed.Load(), f.srv.egressUnaccountable.Load())
	}
	if f.cli.loop.Tunnel().Gate().State() != tun.StateCarrying {
		t.Fatal("the client stopped carrying with only a MARK rule in place")
	}

	// The fwmark rule: the MARK now moves the replies to the 1400 route.
	time.Sleep(egressSweepMinGap)
	start := time.Now()
	ipCmd(t, "-n", wgNS, "rule", "add", "pref", "100", "fwmark", "1", "lookup", "100")
	waitFor(t, 3*time.Second, "the watch to close the session", func() bool { return f.srv.egressClosed.Load() == 1 })
	window := time.Since(start)
	if !f.srv.egressUnaccountable.Load() {
		t.Fatal("routing not marked unaccountable")
	}
	waitFor(t, 10*time.Second, "the session to leave the table", func() bool { return f.sessions() == 0 })
	waitFor(t, 10*time.Second, "the client gate to leave carrying", func() bool {
		return f.cli.loop.Tunnel().Gate().State() != tun.StateCarrying
	})
	if f.srv.clientEgressFits(netip.MustParseAddrPort(wcAddr + ":40000")) {
		t.Fatal("a new client was admitted while the fwmark rule exists")
	}
	if window > time.Second+egressSweepMinGap {
		t.Fatalf("closed %v after the fwmark rule, beyond the bound", window)
	}
	t.Logf("fwmark rule -> session closed after %v; lookups %d, rule dumps %d; sweep max %d us",
		window, lookups.Load(), dumps.Load(), f.srv.egressSweepMaxUS.Load())
}
