//go:build linux || android

package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"winsvpn.local/winnprotocol/winn3/carrier"
)

// readMTUDiscover reads IP_MTU_DISCOVER back from the kernel.
func readMTUDiscover(t *testing.T, conn *net.UDPConn) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var mode int
	var getErr error
	if err := raw.Control(func(fd uintptr) {
		mode, getErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER)
	}); err != nil {
		t.Fatal(err)
	}
	if getErr != nil {
		t.Fatal(getErr)
	}
	return mode
}

// TestListenerDontFragmentSetsPMTUDiscDo reads the option back from the
// kernel: with -listener-df on, IP_MTU_DISCOVER must be IP_PMTUDISC_DO (2),
// not the default WANT.
func TestListenerDontFragmentSetsPMTUDiscDo(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if before := readMTUDiscover(t, conn); before == syscall.IP_PMTUDISC_DO {
		t.Fatalf("a fresh socket already reads IP_PMTUDISC_DO (%d); the test would be vacuous", before)
	}
	var log bytes.Buffer
	if err := configureListenerDontFragment(conn, true, &log); err != nil {
		t.Fatal(err)
	}
	if got := readMTUDiscover(t, conn); got != syscall.IP_PMTUDISC_DO {
		t.Fatalf("IP_MTU_DISCOVER = %d with the flag on, want IP_PMTUDISC_DO (%d)",
			got, syscall.IP_PMTUDISC_DO)
	}
	if !bytes.Contains(log.Bytes(), []byte("listener DF on")) {
		t.Fatalf("no DF line logged: %q", log.String())
	}
}

// TestListenerDontFragmentFailsClosedOnAClosedSocket: with the flag on, on
// Linux a refused setsockopt is a startup error, never the "not available"
// line.
func TestListenerDontFragmentFailsClosedOnAClosedSocket(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	var log bytes.Buffer
	if err := configureListenerDontFragment(conn, true, &log); err == nil {
		t.Fatalf("DF on a closed socket returned nil (log %q)", log.String())
	}
}

// TestListenerDFOffKeepsTheKernelDefault is Round CM2 (OI-CM2-1a) on the real
// listener runServe opens: with -listener-df off (the default)
// IP_MTU_DISCOVER equals what a fresh socket reads on this kernel, and with
// it on the same readback gives IP_PMTUDISC_DO, so the readback is live. The
// egress refusal still fires with the flag off, before any listener exists.
func TestListenerDFOffKeepsTheKernelDefault(t *testing.T) {
	fresh, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	kernelDefault := readMTUDiscover(t, fresh)
	_ = fresh.Close()
	if kernelDefault == syscall.IP_PMTUDISC_DO {
		t.Fatalf("this kernel's default is already IP_PMTUDISC_DO (%d); the test would be vacuous", kernelDefault)
	}

	savedConfigure, savedMeasure := configureListenerDF, measureEgress
	t.Cleanup(func() { configureListenerDF, measureEgress = savedConfigure, savedMeasure })
	for _, tc := range []struct {
		on   bool
		want int
	}{
		{on: false, want: kernelDefault},
		{on: true, want: syscall.IP_PMTUDISC_DO},
	} {
		opts := operatorValueOptions(t)
		opts.listenerDF = tc.on
		mode, calls := -1, 0
		var log bytes.Buffer
		configureListenerDF = func(c *net.UDPConn, on bool, w io.Writer) error {
			calls++
			err := savedConfigure(c, on, &log)
			mode = readMTUDiscover(t, c)
			return err
		}
		if err := runServe(opts, new(bytes.Buffer)); err != nil {
			t.Fatalf("-listener-df %t: %v", tc.on, err)
		}
		if calls != 1 || mode != tc.want {
			t.Fatalf("-listener-df %t: listener IP_MTU_DISCOVER=%d (configured %d times), want %d",
				tc.on, mode, calls, tc.want)
		}
		if strings.Count(log.String(), "\n") != 1 {
			t.Fatalf("-listener-df %t: DF state logged as %q, want one line", tc.on, log.String())
		}
		t.Logf("-listener-df %t: listener IP_MTU_DISCOVER=%d (kernel default %d); %s",
			tc.on, mode, kernelDefault, strings.TrimSpace(log.String()))
	}

	// Flag off, device one byte narrower than the plan's datagram: refused
	// before the listener exists.
	opts := operatorValueOptions(t)
	calls := 0
	configureListenerDF = func(c *net.UDPConn, on bool, w io.Writer) error {
		calls++
		return savedConfigure(c, on, w)
	}
	measureEgress = func(egressLookup) ([]egressRoute, error) { return oneEgress("eth0", 1479), nil }
	if err := runServe(opts, new(bytes.Buffer)); err == nil || !strings.Contains(err.Error(), "eth0 with MTU 1479") || calls != 0 {
		t.Fatalf("flag off on a 1479-byte device: err=%v, listener configured %d times; want the egress refusal first", err, calls)
	}
}

// TestRtnetlinkConstantsMatchXSys holds the codec's own constants
// (egress_route_netlink.go, portable so its tests run everywhere) equal to
// the kernel ABI values golang.org/x/sys/unix carries.
func TestRtnetlinkConstantsMatchXSys(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"nlmsghdr", nlmsgHdrLen, unix.SizeofNlMsghdr},
		{"rtmsg", rtMsgLen, unix.SizeofRtMsg},
		{"rtattr", rtAttrHdrLen, unix.SizeofRtAttr},
		{"NLMSG_ERROR", nlmsgError, unix.NLMSG_ERROR},
		{"RTM_NEWROUTE", rtmNewRoute, unix.RTM_NEWROUTE},
		{"RTM_GETROUTE", rtmGetRoute, unix.RTM_GETROUTE},
		{"NLM_F_REQUEST", nlmFRequest, unix.NLM_F_REQUEST},
		{"RTM_F_LOOKUP_TABLE", rtmFLookupTable, unix.RTM_F_LOOKUP_TABLE},
		{"AF_INET", afInet, unix.AF_INET},
		{"IPPROTO_UDP", ipprotoUDP, unix.IPPROTO_UDP},
		{"RTA_DST", rtaDst, unix.RTA_DST},
		{"RTA_SRC", rtaSrc, unix.RTA_SRC},
		{"RTA_OIF", rtaOIF, unix.RTA_OIF},
		{"RTA_METRICS", rtaMetrics, unix.RTA_METRICS},
		{"RTA_CACHEINFO", rtaCacheInfo, unix.RTA_CACHEINFO},
		{"RTA_TABLE", rtaTable, unix.RTA_TABLE},
		{"RTA_IP_PROTO", rtaIPProto, unix.RTA_IP_PROTO},
		{"RTA_SPORT", rtaSport, unix.RTA_SPORT},
		{"RTA_DPORT", rtaDport, unix.RTA_DPORT},
		{"RTA_MARK", rtaMark, unix.RTA_MARK},
		{"RTAX_MTU", rtaxMTU, unix.RTAX_MTU},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d here, %d in x/sys/unix", c.name, c.got, c.want)
		}
	}
}

// TestMeasureEgressRouteOnThisHost asks this host's kernel, for a portless
// flow and for the fleet's listener port 9111 (so a policy rule on that port
// shows in the log). A host with no route to any probe destination skips:
// that is the warn path, covered above.
func TestMeasureEgressRouteOnThisHost(t *testing.T) {
	measured := 0
	for _, lookup := range []egressLookup{{}, {Port: 9111}} {
		routes, err := measureEgressRoute(lookup)
		if err != nil {
			t.Fatalf("rtnetlink unavailable: %v", err)
		}
		for _, r := range routes {
			if r.Err != nil {
				t.Logf("%s to %s: %v", lookup, r.Dest, r.Err)
				continue
			}
			measured++
			if r.Device == "" || r.MTU < 576 || r.DeviceMTU < r.MTU {
				t.Fatalf("implausible egress %+v", r)
			}
			t.Logf("%s to %s via %s mtu %d (device %d, route %d, table %d)",
				lookup, r.Dest, r.Device, r.MTU, r.DeviceMTU, r.RouteMTU, r.Table)
		}
	}
	if measured == 0 {
		t.Skip("no route to any probe destination here")
	}
}

// A kernel that cannot enable strict request checking cannot be asked about
// the exact reply flow (it would ignore RTA_DPORT it did not know). Every
// lookup then reports errFlowNotDescribable, the per-client guard fails
// closed, and startup refuses (Round CM3 Turn 2).
func TestNoStrictCheckingFailsClosed(t *testing.T) {
	saved := setRouteSocketStrict
	t.Cleanup(func() { setRouteSocketStrict = saved })
	setRouteSocketStrict = func(int) error { return unix.ENOPROTOOPT }
	if _, err := measureEgressRouteTo(egressLookup{}, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:40000")}); !errors.Is(err, errFlowNotDescribable) {
		t.Fatalf("lookup without strict checking: %v, want errFlowNotDescribable", err)
	}
	savedMeasure := measureClientEgress
	t.Cleanup(func() { measureClientEgress = savedMeasure })
	if r, ok := (&clientEgressGuard{datagram: 1430}).check(netip.MustParseAddrPort("127.0.0.1:40000")); ok {
		t.Fatalf("guard served a client whose flow could not be described: %+v", r)
	}
	if _, err := measureEgressRoute(egressLookup{}); !errors.Is(err, errFlowNotDescribable) {
		t.Fatalf("startup measurement without strict checking: %v", err)
	}
}

// listenerMark reads SO_MARK back from the kernel. Setting a mark needs
// CAP_NET_ADMIN; without it only the unmarked value is checked.
func TestListenerMarkReadsSOMark(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if m, err := listenerMark(conn); err != nil || m != 0 {
		t.Fatalf("fresh socket: mark %d err %v, want 0", m, err)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var setErr error
	if err := raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, 5) }); err != nil {
		t.Fatal(err)
	}
	if setErr != nil {
		t.Skipf("cannot set SO_MARK here (%v); the unmarked read passed", setErr)
	}
	if m, err := listenerMark(conn); err != nil || m != 5 {
		t.Fatalf("marked socket: mark %d err %v, want 5", m, err)
	}
}

// BenchmarkMeasureClientEgress is the cost of one per-client lookup (a fresh
// rtnetlink socket, one RTM_GETROUTE, one interface lookup): what an egress
// sweep spends per live session, and what an admission spends once. Nothing
// runs per packet.
func BenchmarkMeasureClientEgress(b *testing.B) {
	lookup := egressLookup{Source: netip.MustParseAddr("127.0.0.1"), Port: 9111}
	dst := netip.MustParseAddrPort("127.0.0.1:40000")
	for i := 0; i < b.N; i++ {
		if r := measureClientEgress(lookup, dst); r.Err != nil {
			b.Fatal(r.Err)
		}
	}
}

// The rule and route dump and the rtnetlink subscription work on this host,
// as whatever user runs the test (the lane runs it unprivileged and under the
// gateway unit's sandbox properties).
func TestListRoutingSelectorsOnThisHost(t *testing.T) {
	sel, err := listRoutingSelectors()
	if err != nil {
		t.Fatalf("rule/route dump: %v", err)
	}
	t.Logf("uid %d: %d selector(s): %s", os.Getuid(), len(sel), describeSelectors(sel))
}

func TestStartRouteWatchOnThisHost(t *testing.T) {
	_, stop, err := startRouteWatch()
	if err != nil {
		t.Fatalf("route watch as uid %d: %v", os.Getuid(), err)
	}
	stop()
}

// With AF_NETLINK forbidden (RestrictAddressFamilies without it), every
// egress check fails CLOSED instead of reading as "unmeasured". Run only by
// the lane's sandbox harness, which sets WINN3_EXPECT_NO_NETLINK=1.
func TestEgressWithoutNetlinkFailsClosed(t *testing.T) {
	if os.Getenv("WINN3_EXPECT_NO_NETLINK") != "1" {
		t.Skip("run by the sandbox harness without AF_NETLINK")
	}
	routes, err := measureEgressRoute(egressLookup{})
	if !errors.Is(err, errFlowNotDescribable) {
		t.Fatalf("startup lookup without AF_NETLINK: %v %v, want errFlowNotDescribable", routes, err)
	}
	if err := checkEgressMTU(mustSizing(t, 1450, carrier.ClassUDP), egressLookup{}, routes, err, new(bytes.Buffer)); err == nil {
		t.Fatal("startup served without AF_NETLINK")
	}
	if _, err := listRoutingSelectors(); !errors.Is(err, errFlowNotDescribable) {
		t.Fatalf("rule dump without AF_NETLINK: %v", err)
	}
	if r, ok := (&clientEgressGuard{datagram: 1430}).check(netip.MustParseAddrPort("127.0.0.1:40000")); ok {
		t.Fatalf("guard served a client without AF_NETLINK: %+v", r)
	}
}
