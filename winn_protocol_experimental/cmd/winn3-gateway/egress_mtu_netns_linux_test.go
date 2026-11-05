//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"winsvpn.local/winnprotocol/winn3/carrier"
)

// Round CM2 retro (GPT-6 Sol OI-CM2-1a, lane L80) on a real kernel: network
// namespaces with policy routing, the measurement run inside them, and each
// answer held equal to what `ip route get` says for the same flow. Needs root
// and iproute2; runs only with WINN3_EGRESS_NETNS=1, and every namespace it
// creates is deleted in cleanup.

func requireEgressNetns(t *testing.T) {
	t.Helper()
	if os.Getenv("WINN3_EGRESS_NETNS") != "1" {
		t.Skip("set WINN3_EGRESS_NETNS=1 and run as root on Linux")
	}
	if os.Geteuid() != 0 {
		t.Fatal("WINN3_EGRESS_NETNS=1 needs root")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Fatalf("iproute2: %v", err)
	}
}

func ipCmd(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// newNetns creates an empty namespace with lo up, deleted in cleanup.
func newNetns(t *testing.T, name string) {
	t.Helper()
	_ = exec.Command("ip", "netns", "del", name).Run()
	ipCmd(t, "netns", "add", name)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
	ipCmd(t, "-n", name, "link", "set", "lo", "up")
}

// policyNetns is one namespace with two dummy uplinks, ts1 (mtu 1400,
// 10.80.1.2/24) and ts2 (mtu 1500, 10.80.2.2/24), and no routes beyond the
// connected ones. Each case adds its own routes and rules.
func policyNetns(t *testing.T, name string) {
	t.Helper()
	newNetns(t, name)
	for _, l := range []struct{ dev, mtu, addr string }{
		{"ts1", "1400", "10.80.1.2/24"},
		{"ts2", "1500", "10.80.2.2/24"},
	} {
		ipCmd(t, "-n", name, "link", "add", l.dev, "type", "dummy")
		ipCmd(t, "-n", name, "link", "set", l.dev, "mtu", l.mtu, "up")
		ipCmd(t, "-n", name, "addr", "add", l.addr, "dev", l.dev)
	}
}

// inNetns runs fn on a locked OS thread that has entered namespace name. The
// thread is never unlocked, so the runtime discards it when fn returns.
func inNetns(t *testing.T, name string, fn func()) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		fd, err := unix.Open("/run/netns/"+name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = unix.Close(fd) }()
		if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
			done <- err
			return
		}
		fn()
		done <- nil
	}()
	if err := <-done; err != nil {
		t.Fatalf("enter netns %s: %v", name, err)
	}
}

func measureInNetns(t *testing.T, name string, lookup egressLookup) []egressRoute {
	t.Helper()
	var routes []egressRoute
	var err error
	inNetns(t, name, func() { routes, err = measureEgressRoute(lookup) })
	if err != nil {
		t.Fatalf("measure in %s: %v", name, err)
	}
	return routes
}

// ipRouteGet is iproute2's answer for the same flow: the dev and, when
// shown, the mtu of the cached route.
func ipRouteGet(t *testing.T, name string, dst netip.Addr, lookup egressLookup) (dev string, fields []string) {
	t.Helper()
	args := []string{"-n", name, "-o", "-4", "route", "get", dst.String()}
	if lookup.Source.IsValid() {
		args = append(args, "from", lookup.Source.String())
	}
	args = append(args, "ipproto", "udp")
	if lookup.Port != 0 {
		args = append(args, "sport", strconv.Itoa(int(lookup.Port)))
	}
	fields = strings.Fields(ipCmd(t, args...))
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			dev = fields[i+1]
		}
	}
	return dev, fields
}

// expectEgress measures in the namespace and requires every destination to
// leave through dev with mtu, agreeing with `ip route get` for the same flow.
func expectEgress(t *testing.T, name string, lookup egressLookup, dev string, mtu int) []egressRoute {
	t.Helper()
	routes := measureInNetns(t, name, lookup)
	if len(routes) != len(egressProbeDestinations) {
		t.Fatalf("%d answers for %d destinations", len(routes), len(egressProbeDestinations))
	}
	for _, r := range routes {
		if r.Err != nil {
			t.Fatalf("%s %s: %v", lookup, r.Dest, r.Err)
		}
		ipDev, fields := ipRouteGet(t, name, r.Dest, lookup)
		if r.Device != dev || r.MTU != mtu || ipDev != r.Device {
			t.Fatalf("%s to %s: measured %s mtu %d, ip route get says dev %s (%s); want %s mtu %d",
				lookup, r.Dest, r.Device, r.MTU, ipDev, strings.Join(fields, " "), dev, mtu)
		}
	}
	t.Logf("%s: %s", lookup, describeEgress(routes))
	return routes
}

func checkUDP(t *testing.T, pathMTU int, lookup egressLookup, routes []egressRoute) error {
	t.Helper()
	return checkEgressMTU(mustSizing(t, pathMTU, carrier.ClassUDP), lookup, routes, nil, new(bytes.Buffer))
}

func TestEgressNetnsFollowsPolicyRouting(t *testing.T) {
	requireEgressNetns(t)
	saved := egressProbeDestinations
	t.Cleanup(func() { egressProbeDestinations = saved })
	egressProbeDestinations = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}
	const ns = "l80egress"
	listener := egressLookup{Port: 9111}
	other := egressLookup{Port: 9112}

	t.Run("main table only", func(t *testing.T) {
		policyNetns(t, ns)
		ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.1.1", "dev", "ts1")
		routes := expectEgress(t, ns, listener, "ts1", 1400)
		if err := checkUDP(t, 1450, listener, routes); err == nil {
			t.Fatal("udp 1450 (1430-byte datagrams) on the 1400 egress served")
		}
		if err := checkUDP(t, 1420, listener, routes); err != nil {
			t.Fatalf("udp 1420 (1400-byte datagrams) on the 1400 egress: %v", err)
		}
	})

	// Sol's counterexample: main default 1400, the listener's UDP policy-routed
	// through 1500. CM2 refused this plan; the lookup serves it.
	t.Run("sport rule to a wider device", func(t *testing.T) {
		policyNetns(t, ns)
		ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.1.1", "dev", "ts1")
		ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.2.1", "dev", "ts2", "table", "100")
		ipCmd(t, "-n", ns, "rule", "add", "pref", "100", "ipproto", "udp", "sport", "9111", "lookup", "100")
		routes := expectEgress(t, ns, listener, "ts2", 1500)
		if routes[0].Table != 100 {
			t.Fatalf("table %d, want 100", routes[0].Table)
		}
		if err := checkUDP(t, 1450, listener, routes); err != nil {
			t.Fatalf("udp 1450 on the policy-routed 1500 egress refused: %v", err)
		}
		// Control: another port is not matched by the rule.
		expectEgress(t, ns, other, "ts1", 1400)
	})

	// The reverse arrangement: CM2 passed it, the lookup refuses.
	t.Run("sport rule to a narrower device", func(t *testing.T) {
		policyNetns(t, ns)
		ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.2.1", "dev", "ts2")
		ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.1.1", "dev", "ts1", "table", "100")
		ipCmd(t, "-n", ns, "rule", "add", "pref", "100", "ipproto", "udp", "sport", "9111", "lookup", "100")
		routes := expectEgress(t, ns, listener, "ts1", 1400)
		if err := checkUDP(t, 1450, listener, routes); err == nil || !strings.Contains(err.Error(), "ts1 with MTU 1400") {
			t.Fatalf("udp 1450 on the policy-routed 1400 egress: %v, want the refusal", err)
		}
		expectEgress(t, ns, other, "ts2", 1500)
	})

	t.Run("source rule", func(t *testing.T) {
		policyNetns(t, ns)
		ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.1.1", "dev", "ts1")
		ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.2.1", "dev", "ts2", "table", "100")
		ipCmd(t, "-n", ns, "rule", "add", "pref", "100", "from", "10.80.2.2", "lookup", "100")
		expectEgress(t, ns, egressLookup{Source: netip.MustParseAddr("10.80.2.2"), Port: 9111}, "ts2", 1500)
		// A wildcard listener's replies get their source after the lookup.
		expectEgress(t, ns, listener, "ts1", 1400)
	})

	// No RTA_UID in the request: the kernel applies the caller's uid (root
	// here, the service user on a node).
	t.Run("uidrange rule", func(t *testing.T) {
		policyNetns(t, ns)
		ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.1.1", "dev", "ts1")
		ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.2.1", "dev", "ts2", "table", "100")
		ipCmd(t, "-n", ns, "rule", "add", "pref", "100", "uidrange", "0-0", "lookup", "100")
		expectEgress(t, ns, listener, "ts2", 1500)
		ipCmd(t, "-n", ns, "rule", "del", "pref", "100")
		ipCmd(t, "-n", ns, "rule", "add", "pref", "100", "uidrange", "1-1", "lookup", "100")
		expectEgress(t, ns, listener, "ts1", 1400)
	})

	t.Run("route mtu metric", func(t *testing.T) {
		policyNetns(t, ns)
		ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.2.1", "dev", "ts2", "mtu", "1380")
		routes := expectEgress(t, ns, listener, "ts2", 1380)
		if routes[0].RouteMTU != 1380 || routes[0].DeviceMTU != 1500 {
			t.Fatalf("%+v", routes[0])
		}
		if err := checkUDP(t, 1450, listener, routes); err == nil {
			t.Fatal("1430-byte datagrams on a route with mtu 1380 served")
		}
	})

	// Sol's OI-CM3-1 reproduction, exactly: a 1500-byte default and a
	// 1400-byte route to a client prefix outside the four probes. The startup
	// check passes (every probe leaves through ts2); the per-client guard, on
	// the real kernel, refuses a client inside the prefix and serves one
	// outside it. The second arrangement is the same prefix through the wide
	// device with a route mtu of 1400.
	t.Run("client prefix narrower than the default", func(t *testing.T) {
		for _, narrowRoute := range [][]string{
			{"route", "add", "45.0.0.0/16", "via", "10.80.1.1", "dev", "ts1"},
			{"route", "add", "45.0.0.0/16", "via", "10.80.2.1", "dev", "ts2", "mtu", "1400"},
		} {
			policyNetns(t, ns)
			ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.2.1", "dev", "ts2")
			ipCmd(t, append([]string{"-n", ns}, narrowRoute...)...)
			routes := expectEgress(t, ns, listener, "ts2", 1500)
			if err := checkUDP(t, 1450, listener, routes); err != nil {
				t.Fatalf("startup check with every probe via the 1500 default: %v", err)
			}
			g := &clientEgressGuard{lookup: listener, datagram: plannedIPv4Datagram(mustSizing(t, 1450, carrier.ClassUDP))}
			inside, outside := netip.MustParseAddrPort("45.0.1.2:40000"), netip.MustParseAddrPort("46.0.0.1:40000")
			var rIn, rOut egressRoute
			var okIn, okOut bool
			inNetns(t, ns, func() {
				rIn, okIn = g.check(inside)
				rOut, okOut = g.check(outside)
			})
			wantDev := narrowRoute[6] // the "dev" argument
			if okIn || rIn.MTU != 1400 || rIn.Device != wantDev {
				t.Fatalf("%v: client %s measured %+v ok=%t, want refused via %s at 1400", narrowRoute, inside, rIn, okIn, wantDev)
			}
			if !okOut || rOut.Device != "ts2" || rOut.MTU != 1500 {
				t.Fatalf("%v: client %s measured %+v ok=%t, want served via ts2 1500", narrowRoute, outside, rOut, okOut)
			}
			if dev, fields := ipRouteGet(t, ns, inside.Addr(), listener); dev != rIn.Device {
				t.Fatalf("ip route get says %q, guard measured %s", strings.Join(fields, " "), rIn.Device)
			}
			t.Logf("%v: startup ok (%s); client %s refused (%s mtu %d); client %s served (%s mtu %d)",
				narrowRoute, describeEgress(routes), inside, rIn.Device, rIn.MTU, outside, rOut.Device, rOut.MTU)
		}
	})

	// Round CM3 Turn 2 (Sol OI-CM3-1), exactly: a `dport 40000` rule sends
	// replies to that client port through a table whose route is on the
	// 1400-byte ts1, while main is 1500 (ts2). The guard carries the client's
	// port (RTA_DPORT), so a client on 40000 is refused and the same address
	// on 40001 is served; `ip route get ... dport` agrees. The same for a
	// sport rule (the listener's port), an ipproto rule (udp narrow; a tcp
	// rule does not touch UDP replies) and an fwmark rule (the listener's
	// mark, 0 here, and a mark set on the lookup).
	t.Run("reply selectors per client", func(t *testing.T) {
		client := netip.MustParseAddrPort("46.0.0.1:40000")
		otherPort := netip.MustParseAddrPort("46.0.0.1:40001")
		for _, tc := range []struct {
			name      string
			rule      []string
			lookup    egressLookup
			refuse    []netip.AddrPort
			serve     []netip.AddrPort
			ipGetArgs func(netip.AddrPort) []string
		}{
			{name: "dport", rule: []string{"ipproto", "udp", "dport", "40000"}, lookup: listener,
				refuse: []netip.AddrPort{client}, serve: []netip.AddrPort{otherPort}},
			{name: "sport", rule: []string{"ipproto", "udp", "sport", "9111"}, lookup: listener,
				refuse: []netip.AddrPort{client, otherPort}},
			{name: "sport other listener", rule: []string{"ipproto", "udp", "sport", "9111"}, lookup: other,
				serve: []netip.AddrPort{client, otherPort}},
			{name: "ipproto udp", rule: []string{"ipproto", "udp"}, lookup: listener,
				refuse: []netip.AddrPort{client, otherPort}},
			{name: "ipproto tcp", rule: []string{"ipproto", "tcp"}, lookup: listener,
				serve: []netip.AddrPort{client, otherPort}},
			{name: "fwmark, listener unmarked", rule: []string{"fwmark", "0x5"}, lookup: listener,
				serve: []netip.AddrPort{client}},
			{name: "fwmark, listener marked", rule: []string{"fwmark", "0x5"},
				lookup: egressLookup{Port: 9111, Mark: 5}, refuse: []netip.AddrPort{client}},
		} {
			policyNetns(t, ns)
			ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.2.1", "dev", "ts2")
			ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.1.1", "dev", "ts1", "table", "100")
			ipCmd(t, append([]string{"-n", ns, "rule", "add", "pref", "100"}, append(tc.rule, "lookup", "100")...)...)
			g := &clientEgressGuard{lookup: tc.lookup, datagram: plannedIPv4Datagram(mustSizing(t, 1450, carrier.ClassUDP))}
			for _, want := range []struct {
				dsts []netip.AddrPort
				ok   bool
			}{{tc.refuse, false}, {tc.serve, true}} {
				for _, dst := range want.dsts {
					var r egressRoute
					var ok bool
					inNetns(t, ns, func() { r, ok = g.check(dst) })
					if r.Err != nil || ok != want.ok {
						t.Fatalf("%s: client %s: %+v served=%t, want served=%t", tc.name, dst, r, ok, want.ok)
					}
					args := []string{"-n", ns, "-o", "-4", "route", "get", dst.Addr().String(), "ipproto", "udp",
						"sport", strconv.Itoa(int(tc.lookup.Port)), "dport", strconv.Itoa(int(dst.Port()))}
					if tc.lookup.Mark != 0 {
						args = append(args, "mark", strconv.Itoa(int(tc.lookup.Mark)))
					}
					fields := strings.Fields(ipCmd(t, args...))
					dev := ""
					for i := 0; i+1 < len(fields); i++ {
						if fields[i] == "dev" {
							dev = fields[i+1]
						}
					}
					if dev != r.Device {
						t.Fatalf("%s: client %s: guard measured %s, ip route get says %q", tc.name, dst, r.Device, strings.Join(fields, " "))
					}
					t.Logf("%s: client %s via %s mtu %d table %d served=%t", tc.name, dst, r.Device, r.MTU, r.Table, ok)
				}
			}
		}
	})

	// Strictness: with NETLINK_GET_STRICT_CHK the kernel refuses a request
	// carrying an attribute a route GET does not accept (EINVAL), and the
	// guard fails closed on it; without strictness the same request is
	// answered as if the attribute were absent. This is what makes a kernel
	// that did not know RTA_DPORT refuse instead of silently measuring a
	// less specific flow.
	t.Run("strict checking refuses an unknown attribute", func(t *testing.T) {
		policyNetns(t, ns)
		ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.2.1", "dev", "ts2")
		dst := netip.MustParseAddrPort("46.0.0.1:40000")
		ask := func(strict bool) error {
			var err error
			inNetns(t, ns, func() {
				saved := setRouteSocketStrict
				if !strict {
					setRouteSocketStrict = func(int) error { return nil }
				}
				defer func() { setRouteSocketStrict = saved }()
				sock, oerr := openRouteSocket()
				if oerr != nil {
					err = oerr
					return
				}
				defer sock.close()
				req, eerr := encodeRouteGetRequest(1, dst, listener)
				if eerr != nil {
					err = eerr
					return
				}
				// RTA_PRIORITY (6) is valid in a route but not in a GET request.
				req = appendRtAttr(req, 6, []byte{1, 0, 0, 0})
				binary.NativeEndian.PutUint32(req[0:4], uint32(len(req)))
				if serr := sock.send(req); serr != nil {
					err = serr
					return
				}
				b, rerr := sock.recv(time.Now().Add(netlinkAnswerBound))
				if rerr != nil {
					err = rerr
					return
				}
				_, err = parseRouteReply(b, 1, sock.port())
			})
			return err
		}
		if err := ask(true); !errors.Is(err, syscall.EINVAL) || lookupSaysNoRoute(err) {
			t.Fatalf("strict: an unknown attribute gave %v, want EINVAL (fail closed)", err)
		}
		if err := ask(false); err != nil {
			t.Fatalf("control, not strict: the same request gave %v, want an answer", err)
		}
		// And the guard, whose socket is strict, answers the real request.
		var r egressRoute
		var ok bool
		inNetns(t, ns, func() {
			r, ok = (&clientEgressGuard{lookup: listener, datagram: 1430}).check(dst)
		})
		if r.Err != nil || !ok || r.Device != "ts2" {
			t.Fatalf("strict guard lookup: %+v ok=%t", r, ok)
		}
	})

	// Nothing routable: every destination is an error, and the check warns.
	t.Run("unreachable", func(t *testing.T) {
		policyNetns(t, ns)
		ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.1.1", "dev", "ts1")
		ipCmd(t, "-n", ns, "route", "add", "unreachable", "default", "table", "100")
		ipCmd(t, "-n", ns, "rule", "add", "pref", "100", "ipproto", "udp", "sport", "9111", "lookup", "100")
		routes := measureInNetns(t, ns, listener)
		if len(routes) != len(egressProbeDestinations) {
			t.Fatalf("%d answers for %d destinations", len(routes), len(egressProbeDestinations))
		}
		for _, r := range routes {
			if !errors.Is(r.Err, syscall.EHOSTUNREACH) && !errors.Is(r.Err, syscall.ENETUNREACH) {
				t.Fatalf("%s: %+v, want an unreachable errno", r.Dest, r)
			}
		}
		var log bytes.Buffer
		if err := checkEgressMTU(mustSizing(t, 1450, carrier.ClassUDP), listener, routes, nil, &log); err != nil ||
			!strings.Contains(log.String(), "egress MTU NOT CHECKED") {
			t.Fatalf("unreachable: err=%v log=%q", err, log.String())
		}
		t.Logf("%s", strings.TrimSpace(log.String()))
	})

	// A source address the host does not own is the kernel's EINVAL.
	t.Run("foreign source", func(t *testing.T) {
		policyNetns(t, ns)
		ipCmd(t, "-n", ns, "route", "add", "default", "via", "10.80.1.1", "dev", "ts1")
		routes := measureInNetns(t, ns, egressLookup{Source: netip.MustParseAddr("192.0.2.9"), Port: 9111})
		if len(routes) != len(egressProbeDestinations) {
			t.Fatalf("%d answers for %d destinations", len(routes), len(egressProbeDestinations))
		}
		for _, r := range routes {
			if r.Err == nil {
				t.Fatalf("%s: a foreign source measured %+v", r.Dest, r)
			}
		}
	})
}

// A cached path MTU learned from an ICMP "fragmentation needed" is reported
// as an exception and does not lower the egress MTU (egressFromReply).
func TestEgressNetnsIgnoresAPMTUException(t *testing.T) {
	requireEgressNetns(t)
	const g, r, c = "l80g", "l80r", "l80c"
	for _, ns := range []string{g, r, c} {
		newNetns(t, ns)
	}
	ipCmd(t, "-n", g, "link", "add", "g0", "type", "veth", "peer", "name", "r0", "netns", r)
	ipCmd(t, "-n", r, "link", "add", "r1", "type", "veth", "peer", "name", "c0", "netns", c)
	ipCmd(t, "-n", g, "addr", "add", "10.81.1.2/24", "dev", "g0")
	ipCmd(t, "-n", g, "link", "set", "g0", "up")
	ipCmd(t, "-n", r, "addr", "add", "10.81.1.1/24", "dev", "r0")
	ipCmd(t, "-n", r, "addr", "add", "10.81.2.1/24", "dev", "r1")
	ipCmd(t, "-n", r, "link", "set", "r0", "up")
	ipCmd(t, "-n", r, "link", "set", "r1", "mtu", "1300", "up")
	ipCmd(t, "-n", c, "addr", "add", "10.81.2.2/24", "dev", "c0")
	ipCmd(t, "-n", c, "link", "set", "c0", "mtu", "1300", "up")
	ipCmd(t, "-n", g, "route", "add", "default", "via", "10.81.1.1")
	ipCmd(t, "-n", c, "route", "add", "default", "via", "10.81.2.1")
	if out, err := exec.Command("ip", "netns", "exec", r, "sysctl", "-qw", "net.ipv4.ip_forward=1").CombinedOutput(); err != nil {
		t.Fatalf("forwarding in %s: %v %s", r, err, out)
	}
	dst := netip.MustParseAddr("10.81.2.2")
	saved := egressProbeDestinations
	t.Cleanup(func() { egressProbeDestinations = saved })
	egressProbeDestinations = []netip.Addr{dst}

	// One DF datagram wider than the router's far side draws the ICMP.
	inNetns(t, g, func() {
		conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 9)))
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		if err := carrier.EnableDontFragment(conn); err != nil {
			t.Error(err)
			return
		}
		_, _ = conn.Write(make([]byte, 1400))
		time.Sleep(300 * time.Millisecond)
	})
	_, fields := ipRouteGet(t, g, dst, egressLookup{})
	line := strings.Join(fields, " ")
	if !strings.Contains(line, "expires") || !strings.Contains(line, "mtu 1300") {
		t.Fatalf("no PMTU exception was created: ip route get says %q", line)
	}
	routes := measureInNetns(t, g, egressLookup{})
	if len(routes) != 1 || routes[0].Err != nil {
		t.Fatalf("%+v", routes)
	}
	got := routes[0]
	if got.Device != "g0" || got.MTU != 1500 || got.PMTUException != 1300 || got.RouteMTU != 0 {
		t.Fatalf("with a 1300 exception on a 1500 device measured %+v (ip route get: %q)", got, line)
	}
	if err := checkUDP(t, 1450, egressLookup{}, routes); err != nil {
		t.Fatalf("a cached path MTU refused: %v", err)
	}
	t.Logf("ip route get: %s; measured: %s", line, describeEgress(routes))
}
