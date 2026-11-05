package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
)

// TestMain keeps every runServe test in this package independent of the
// host's NIC: the tests plan at testPathMTU 1500 (1480-byte datagrams), which a
// 1460-byte cloud NIC would refuse. The real measurement has its own tests
// (egress_mtu_linux_test.go), and the wiring tests below swap the stub.
func TestMain(m *testing.M) {
	measureEgress = func(egressLookup) ([]egressRoute, error) {
		return oneEgress("test0", 65535), nil
	}
	// Host independent: the real rule dump has its own tests.
	detectRoutingSelectors = func() ([]routingSelector, error) { return nil, nil }
	os.Exit(m.Run())
}

// oneEgress is a measurement in which the kernel routed the one probed
// destination through dev.
func oneEgress(dev string, mtu int) []egressRoute {
	return []egressRoute{{Dest: netip.MustParseAddr("192.0.2.1"), Device: dev, MTU: mtu, DeviceMTU: mtu}}
}

// The egress refusal is unconditional (Round CM2, OI-CM2-1a): it fires with
// -listener-df off, the default, exactly as with it on.
func TestRunServeRefusesAPlanWiderThanTheEgressDevice(t *testing.T) {
	saved := measureEgress
	t.Cleanup(func() { measureEgress = saved })
	for _, df := range []bool{false, true} {
		opts := operatorValueOptions(t) // udp at testPathMTU: 1452 + 28 = 1480
		opts.listenerDF = df
		measureEgress = func(egressLookup) ([]egressRoute, error) { return oneEgress("eth0", 1479), nil }
		err := runServe(opts, new(bytes.Buffer))
		if err == nil || !strings.Contains(err.Error(), "eth0 with MTU 1479") {
			t.Fatalf("listener DF %t: runServe on a 1479-byte device returned %v, want the egress refusal", df, err)
		}
		// Control: one byte wider and the same options serve, so the refusal
		// above is the egress check and nothing else.
		measureEgress = func(egressLookup) ([]egressRoute, error) { return oneEgress("eth0", 1480), nil }
		if err := runServe(opts, new(bytes.Buffer)); err != nil {
			t.Fatalf("listener DF %t: runServe on a 1480-byte device: %v", df, err)
		}
	}
}

// runServe asks about its own listener's flow: the -listen address and port,
// so a policy rule on either is followed (Round CM2 retro, L80), and the
// wildcard address leaves the source to the kernel as the replies do.
func TestRunServeLooksUpItsOwnListenerFlow(t *testing.T) {
	saved := measureEgress
	t.Cleanup(func() { measureEgress = saved })
	port := freeUDPPort(t)
	loopback := netip.MustParseAddr("127.0.0.1")
	for _, tc := range []struct {
		listen string
		want   egressLookup
	}{
		{listen: "127.0.0.1:0", want: egressLookup{Source: loopback}},
		{listen: fmt.Sprintf("127.0.0.1:%d", port), want: egressLookup{Source: loopback, Port: uint16(port)}},
	} {
		var got []egressLookup
		measureEgress = func(l egressLookup) ([]egressRoute, error) {
			got = append(got, l)
			return oneEgress("eth0", 1500), nil
		}
		opts := operatorValueOptions(t)
		opts.listen = tc.listen
		if err := runServe(opts, new(bytes.Buffer)); err != nil {
			t.Fatalf("-listen %s: %v", tc.listen, err)
		}
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("-listen %s: looked up %+v, want exactly [%+v]", tc.listen, got, tc.want)
		}
	}
}

// The wildcard address leaves the source to the kernel, exactly as the
// listener's replies do; a named address and a port are both carried.
func TestEgressLookupFor(t *testing.T) {
	for _, tc := range []struct {
		addr *net.UDPAddr
		want egressLookup
		text string
	}{
		{addr: &net.UDPAddr{IP: net.IPv4zero, Port: 9111}, want: egressLookup{Port: 9111}, text: "udp from 0.0.0.0:9111"},
		{addr: &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 9111},
			want: egressLookup{Source: netip.MustParseAddr("203.0.113.7"), Port: 9111}, text: "udp from 203.0.113.7:9111"},
		{addr: &net.UDPAddr{IP: net.ParseIP("203.0.113.7").To4()}, want: egressLookup{Source: netip.MustParseAddr("203.0.113.7")}},
		{addr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 9111}, want: egressLookup{Port: 9111}},
		{addr: nil, want: egressLookup{}},
	} {
		got := egressLookupFor(tc.addr)
		if got != tc.want {
			t.Errorf("%v: got %+v, want %+v", tc.addr, got, tc.want)
		}
		if tc.text != "" && got.String() != tc.text {
			t.Errorf("%v: String() = %q, want %q", tc.addr, got.String(), tc.text)
		}
	}
}

// freeUDPPort returns a port nothing listens on at this moment.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return port
}

// With -listener-df on, runServe sets DF on its own listener and a refused
// setsockopt fails startup.
func TestRunServeSetsDFOnItsListenerAndFailsClosed(t *testing.T) {
	saved := enableListenerDF
	t.Cleanup(func() { enableListenerDF = saved })
	opts := operatorValueOptions(t)
	opts.listenerDF = true
	var got *net.UDPConn
	enableListenerDF = func(c *net.UDPConn, w io.Writer) error {
		got = c
		return saved(c, w)
	}
	if err := runServe(opts, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("runServe never set DF on its listener")
	}
	if addr, ok := got.LocalAddr().(*net.UDPAddr); !ok || addr.IP.To4() == nil || addr.Port == 0 {
		t.Fatalf("DF was set on %v, not the bound udp4 listener", got.LocalAddr())
	}
	refused := errors.New("synthetic setsockopt refusal")
	enableListenerDF = func(*net.UDPConn, io.Writer) error { return refused }
	if err := runServe(opts, new(bytes.Buffer)); !errors.Is(err, refused) {
		t.Fatalf("runServe with a refused DF returned %v, want it to fail closed", err)
	}
}

func mustSizing(t *testing.T, pathMTU int, classes ...carrier.Class) driver.Sizing {
	t.Helper()
	s, err := driver.NewSizing(pathMTU, classes...)
	if err != nil {
		t.Fatalf("NewSizing(%d, %v): %v", pathMTU, classes, err)
	}
	return s
}

func TestPlannedIPv4DatagramMatchesRoundCMArithmetic(t *testing.T) {
	// L59 measured these on the wire: plan 1450 udp is message 1402 and a
	// 1430-byte IPv4 datagram; plan 1400 is 1352 and 1380.
	for _, tc := range []struct{ pathMTU, message, datagram int }{
		{1450, 1402, 1430},
		{1400, 1352, 1380},
		{1357, 1309, 1337},
	} {
		s := mustSizing(t, tc.pathMTU, carrier.ClassUDP)
		if s.MessageSize != tc.message || plannedIPv4Datagram(s) != tc.datagram {
			t.Fatalf("path %d: message %d datagram %d, want %d and %d",
				tc.pathMTU, s.MessageSize, plannedIPv4Datagram(s), tc.message, tc.datagram)
		}
	}
}

var chicagoLookup = egressLookup{Port: 9111}

func TestCheckEgressMTURefusesChicago(t *testing.T) {
	var log bytes.Buffer
	err := checkEgressMTU(mustSizing(t, 1450, carrier.ClassUDP), chicagoLookup, oneEgress("eth0", 1400), nil, &log)
	if err == nil {
		t.Fatal("plan 1450 on a 1400-byte NIC was accepted; that is us-chicago1's silent fragmentation")
	}
	// "at most 1420": a udp plan's IPv4 datagram is path MTU - 20, so 1420
	// is the widest path MTU whose datagram (1400) fits a 1400-byte device.
	for _, want := range []string{"-path-mtu 1450", "1430-byte", "eth0 with MTU 1400", "at most 1420", "floor 1357",
		"udp from 0.0.0.0:9111"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
	if log.Len() != 0 {
		t.Errorf("a refusal also logged %q", log.String())
	}
}

func TestCheckEgressMTUBoundaries(t *testing.T) {
	udp := mustSizing(t, 1400, carrier.ClassUDP) // datagram 1380
	full := mustSizing(t, 1450, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS)
	tests := []struct {
		name   string
		sizing driver.Sizing
		mtu    int
		refuse bool
	}{
		{name: "chicago after OI-CM-1", sizing: udp, mtu: 1400},
		{name: "datagram equals device", sizing: udp, mtu: 1380},
		{name: "one byte narrower", sizing: udp, mtu: 1379, refuse: true},
		{name: "fleet 1500", sizing: mustSizing(t, 1450, carrier.ClassUDP), mtu: 1500},
		{name: "gcp 1460", sizing: mustSizing(t, 1450, carrier.ClassUDP), mtu: 1460},
		{name: "device below plan floor", sizing: udp, mtu: 1300, refuse: true},
		// The binary holds the physical rule only: a full plan's datagram that
		// fits is served even when the device is below that plan's floor. The
		// planning rule is the installer's (check_gateway_egress_mtu).
		// A full plan's message is sized for TLS over IPv6, so its UDP
		// datagram is narrower than the path MTU by 112 - 28 = 84 bytes.
		{name: "full plan datagram 1366 on 1366", sizing: full, mtu: 1366},
		{name: "full plan on 1365", sizing: full, mtu: 1365, refuse: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var log bytes.Buffer
			err := checkEgressMTU(tc.sizing, chicagoLookup, oneEgress("ens3", tc.mtu), nil, &log)
			if tc.refuse != (err != nil) {
				t.Fatalf("mtu %d datagram %d: err=%v, want refuse=%t",
					tc.mtu, plannedIPv4Datagram(tc.sizing), err, tc.refuse)
			}
			if !tc.refuse && !strings.Contains(log.String(), "egress MTU ok") {
				t.Fatalf("accepted without the ok line: %q", log.String())
			}
		})
	}
}

func TestCheckEgressMTUBelowFloorAdvice(t *testing.T) {
	err := checkEgressMTU(mustSizing(t, 1400, carrier.ClassUDP), chicagoLookup, oneEgress("eth0", 1300), nil, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "No path MTU this plan accepts (floor 1357)") {
		t.Fatalf("a device below the plan floor got %v, want the lower-floor advice", err)
	}
}

func TestCheckEgressMTUUnmeasuredWarnsAndContinues(t *testing.T) {
	s := mustSizing(t, 1450, carrier.ClassUDP)
	dst := netip.MustParseAddr("192.0.2.1")
	for _, tc := range []struct {
		name   string
		routes []egressRoute
		err    error
		want   string
	}{
		{name: "no route to any destination", routes: []egressRoute{{Dest: dst, Err: syscall.ENETUNREACH}},
			want: "WARNING: egress MTU NOT CHECKED"},
		{name: "netlink unavailable", err: errors.New("rtnetlink socket: permission denied"), want: "WARNING: egress MTU NOT CHECKED"},
		{name: "device reports zero", routes: []egressRoute{{Dest: dst, Device: "eth0"}}, want: "WARNING: egress MTU NOT CHECKED"},
		{name: "nothing probed", want: "WARNING: egress MTU NOT CHECKED"},
		{name: "platform", err: errors.ErrUnsupported, want: "not available on this platform"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log bytes.Buffer
			if err := checkEgressMTU(s, chicagoLookup, tc.routes, tc.err, &log); err != nil {
				t.Fatalf("an unmeasured route refused: %v", err)
			}
			if !strings.Contains(log.String(), tc.want) || !strings.Contains(log.String(), "1430") {
				t.Fatalf("log %q lacks %q and the datagram size", log.String(), tc.want)
			}
		})
	}
}

// spyListenerDF wraps configureListenerDF and enableListenerDF for one test.
// It records the state runServe asked for, whether DF was attempted, and the
// log configureListenerDF wrote.
type listenerDFSpy struct {
	configured int
	on         bool
	enabled    int
	log        bytes.Buffer
}

func spyListenerDF(t *testing.T) *listenerDFSpy {
	t.Helper()
	savedConfigure, savedEnable := configureListenerDF, enableListenerDF
	t.Cleanup(func() { configureListenerDF, enableListenerDF = savedConfigure, savedEnable })
	spy := &listenerDFSpy{}
	enableListenerDF = func(c *net.UDPConn, w io.Writer) error {
		spy.enabled++
		return savedEnable(c, w)
	}
	configureListenerDF = func(c *net.UDPConn, on bool, w io.Writer) error {
		spy.configured++
		spy.on = on
		return savedConfigure(c, on, &spy.log)
	}
	return spy
}

func TestResolveListenerDF(t *testing.T) {
	for _, tc := range []struct {
		flag    bool
		env     string
		want    bool
		wantErr bool
	}{
		{flag: false, env: "", want: false},
		{flag: false, env: "0", want: false},
		{flag: false, env: "1", want: true},
		{flag: true, env: "", want: true},
		{flag: true, env: "0", want: true}, // the flag is set; env is read only at the default
		{flag: true, env: "1", want: true},
		{flag: false, env: "true", wantErr: true},
		{flag: false, env: "yes", wantErr: true},
		{flag: false, env: "01", wantErr: true},
		{flag: false, env: " 1", wantErr: true},
		{flag: true, env: "on", wantErr: true}, // refused whatever the flag says
	} {
		got, err := resolveListenerDF(tc.flag, tc.env)
		if tc.wantErr {
			if err == nil || !strings.Contains(err.Error(), "WINN3_GATEWAY_LISTENER_DF") {
				t.Errorf("flag %t env %q: got (%t, %v), want a refusal naming the variable", tc.flag, tc.env, got, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("flag %t env %q: got (%t, %v), want %t", tc.flag, tc.env, got, err, tc.want)
		}
	}
}

// Off by default: runServe asks for DF off, never attempts it, and logs one
// line saying so (Round CM2, OI-CM2-1a).
func TestRunServeLeavesListenerDFOffByDefault(t *testing.T) {
	spy := spyListenerDF(t)
	opts := operatorValueOptions(t)
	if err := runServe(opts, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	if spy.configured != 1 || spy.on || spy.enabled != 0 {
		t.Fatalf("default run: configured %d times, on=%t, DF attempted %d times; want once, off, never",
			spy.configured, spy.on, spy.enabled)
	}
	if got := spy.log.String(); strings.Count(got, "\n") != 1 || !strings.Contains(got, "listener DF off") {
		t.Fatalf("default run logged %q, want exactly one DF-off line", got)
	}
}

func TestRunServeListenerDFFromTheEnvironment(t *testing.T) {
	for _, tc := range []struct {
		env    string
		on     bool
		refuse bool
	}{
		{env: "0", on: false},
		{env: "1", on: true},
		{env: "true", refuse: true},
	} {
		t.Run(tc.env, func(t *testing.T) {
			spy := spyListenerDF(t)
			opts := operatorValueOptions(t)
			t.Setenv("WINN3_GATEWAY_LISTENER_DF", tc.env)
			err := runServe(opts, new(bytes.Buffer))
			if tc.refuse {
				if err == nil || !strings.Contains(err.Error(), "WINN3_GATEWAY_LISTENER_DF") || spy.configured != 0 {
					t.Fatalf("env %q: err=%v configured=%d, want a refusal before the listener exists",
						tc.env, err, spy.configured)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if spy.configured != 1 || spy.on != tc.on || (spy.enabled == 1) != tc.on {
				t.Fatalf("env %q: configured %d on=%t DF attempted %d, want on=%t",
					tc.env, spy.configured, spy.on, spy.enabled, tc.on)
			}
		})
	}
}

// The flag reaches runServe through run's own parser.
func TestRunParsesTheListenerDFFlag(t *testing.T) {
	for _, withFlag := range []bool{false, true} {
		spy := spyListenerDF(t)
		o := operatorValueOptions(t)
		args := []string{"-mode", "serve",
			"-listen", o.listen, "-static", o.staticPath, "-admission", o.admission,
			"-gateway-id", o.gatewayID, "-inner-v4", o.innerV4, "-router-v4", o.routerV4,
			"-plan", o.plan, "-path-mtu", fmt.Sprint(o.pathMTU), "-max-sessions", fmt.Sprint(o.maxSessions),
			"-for", o.runFor.String(),
			"-cert", o.certPath, "-key", o.keyPath, "-cover-cert", o.coverCertPath,
			"-cover-key", o.coverKeyPath, "-ech-keys", o.echKeysPath}
		if withFlag {
			args = append(args, "-listener-df")
		}
		if err := run(args, new(bytes.Buffer)); err != nil {
			t.Fatalf("-listener-df %t: %v", withFlag, err)
		}
		if spy.configured != 1 || spy.on != withFlag {
			t.Fatalf("-listener-df %t: configured %d times with on=%t", withFlag, spy.configured, spy.on)
		}
	}
}

func TestConfigureListenerDontFragmentLogsOneLine(t *testing.T) {
	saved := enableListenerDF
	t.Cleanup(func() { enableListenerDF = saved })
	calls := 0
	enableListenerDF = func(*net.UDPConn, io.Writer) error { calls++; return nil }
	var log bytes.Buffer
	if err := configureListenerDontFragment(nil, false, &log); err != nil || calls != 0 {
		t.Fatalf("off: err=%v DF attempted %d times", err, calls)
	}
	if strings.Count(log.String(), "\n") != 1 || !strings.Contains(log.String(), "listener DF off") {
		t.Fatalf("off logged %q", log.String())
	}
	if err := configureListenerDontFragment(nil, true, new(bytes.Buffer)); err != nil || calls != 1 {
		t.Fatalf("on: err=%v DF attempted %d times, want once", err, calls)
	}
}

// Sol's counterexample to CM2 (OI-CM2-1a), at the level of the comparison:
// the main table's default leaves through a 1400-byte device, a policy rule
// sends the listener's UDP through a 1500-byte one. The comparison takes what
// the lookup for the listener's flow returned, so a udp plan at 1450
// (1430-byte datagrams) serves. The reverse arrangement refuses. The netns
// test in egress_mtu_linux_test.go shows the kernel lookup returns these.
func TestCheckEgressMTUFollowsThePolicyRoutedEgress(t *testing.T) {
	udp1450 := mustSizing(t, 1450, carrier.ClassUDP)
	var log bytes.Buffer
	if err := checkEgressMTU(udp1450, chicagoLookup, oneEgress("ens4", 1500), nil, &log); err != nil {
		t.Fatalf("policy-routed 1500-byte egress refused: %v", err)
	}
	if !strings.Contains(log.String(), "egress MTU ok: widest IPv4 datagram 1430 <= ens4 mtu 1500") {
		t.Fatalf("log %q", log.String())
	}
	if err := checkEgressMTU(udp1450, chicagoLookup, oneEgress("ens3", 1400), nil, new(bytes.Buffer)); err == nil ||
		!strings.Contains(err.Error(), "ens3 with MTU 1400") {
		t.Fatalf("policy-routed 1400-byte egress: %v, want the refusal", err)
	}
}

// A route's own mtu metric below the device is what the kernel applies.
func TestCheckEgressMTUHonoursTheRouteMTUMetric(t *testing.T) {
	r := egressFromReply(netip.MustParseAddr("192.0.2.1"), routeReply{OIF: 2, Table: 100, RouteMTU: 1380}, "ens4", 1500)
	if r.MTU != 1380 || r.RouteMTU != 1380 || r.DeviceMTU != 1500 || r.PMTUException != 0 {
		t.Fatalf("route mtu 1380 on a 1500 device: %+v", r)
	}
	if err := checkEgressMTU(mustSizing(t, 1450, carrier.ClassUDP), chicagoLookup, []egressRoute{r}, nil, new(bytes.Buffer)); err == nil ||
		!strings.Contains(err.Error(), "ens4 with MTU 1380") {
		t.Fatalf("1430-byte datagrams on a route with mtu 1380: %v, want the refusal", err)
	}
	// A route mtu above the device does not raise it.
	if r := egressFromReply(netip.Addr{}, routeReply{OIF: 2, RouteMTU: 9000}, "ens4", 1500); r.MTU != 1500 {
		t.Fatalf("route mtu 9000 on a 1500 device gave %+v", r)
	}
}

// A cached path MTU to one destination (the reply carries an expiry) is the
// path beyond this host. It is recorded and logged, never compared.
func TestCheckEgressMTUIgnoresAPMTUException(t *testing.T) {
	r := egressFromReply(netip.MustParseAddr("192.0.2.1"), routeReply{OIF: 2, RouteMTU: 1300, Expires: 59000}, "ens3", 1500)
	if r.MTU != 1500 || r.PMTUException != 1300 || r.RouteMTU != 0 {
		t.Fatalf("PMTU exception 1300 on a 1500 device: %+v", r)
	}
	var log bytes.Buffer
	if err := checkEgressMTU(mustSizing(t, 1450, carrier.ClassUDP), chicagoLookup, []egressRoute{r}, nil, &log); err != nil {
		t.Fatalf("a cached path MTU refused startup: %v", err)
	}
	if !strings.Contains(log.String(), "cached path mtu 1300") {
		t.Fatalf("log %q does not record the exception", log.String())
	}
}

// Destinations that disagree warn and serve; all of them too narrow refuses;
// a failed lookup for some destinations does not stop a measured refusal.
func TestCheckEgressMTUAcrossDestinations(t *testing.T) {
	udp1450 := mustSizing(t, 1450, carrier.ClassUDP) // 1430-byte datagrams
	d := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	wide := egressRoute{Dest: d("192.0.2.1"), Device: "ens4", MTU: 1500, DeviceMTU: 1500}
	narrow := egressRoute{Dest: d("192.0.2.2"), Device: "wg1", MTU: 1420, DeviceMTU: 1420}
	narrow2 := egressRoute{Dest: d("192.0.2.3"), Device: "eth0", MTU: 1400, DeviceMTU: 1400}
	failed := egressRoute{Dest: d("192.0.2.4"), Err: syscall.ENETUNREACH}

	var log bytes.Buffer
	if err := checkEgressMTU(udp1450, chicagoLookup, []egressRoute{wide, narrow}, nil, &log); err != nil {
		t.Fatalf("disagreeing destinations refused: %v", err)
	}
	for _, want := range []string{"WARNING: egress MTU AMBIGUOUS", "192.0.2.1 via ens4 mtu 1500", "192.0.2.2 via wg1 mtu 1420", "through wg1 (mtu 1420)"} {
		if !strings.Contains(log.String(), want) {
			t.Fatalf("log %q lacks %q", log.String(), want)
		}
	}
	err := checkEgressMTU(udp1450, chicagoLookup, []egressRoute{narrow, failed, narrow2}, nil, new(bytes.Buffer))
	if err == nil || !strings.Contains(err.Error(), "wg1 with MTU 1420 at the widest") {
		t.Fatalf("every measured destination too narrow: %v, want the refusal naming the widest", err)
	}
	log.Reset()
	if err := checkEgressMTU(udp1450, chicagoLookup, []egressRoute{failed, wide}, nil, &log); err != nil ||
		!strings.Contains(log.String(), "egress lookup failed for some destinations (192.0.2.4: "+syscall.ENETUNREACH.Error()) ||
		!strings.Contains(log.String(), "egress MTU ok") {
		t.Fatalf("one failed and one wide destination: err=%v log=%q", err, log.String())
	}
}

// A flow the kernel cannot be asked about refuses startup: the per-client
// guard would refuse every client on the same condition (Round CM3 Turn 2).
func TestCheckEgressMTURefusesWhenTheFlowCannotBeDescribed(t *testing.T) {
	err := checkEgressMTU(mustSizing(t, 1450, carrier.ClassUDP), chicagoLookup, nil,
		fmt.Errorf("%w: NETLINK_GET_STRICT_CHK: %v", errFlowNotDescribable, syscall.ENOPROTOOPT), new(bytes.Buffer))
	if err == nil || !strings.Contains(err.Error(), "would refuse every client") {
		t.Fatalf("startup with an undescribable flow: %v, want the refusal", err)
	}
}
