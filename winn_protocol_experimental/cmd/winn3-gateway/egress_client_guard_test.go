package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Round CM3 (GPT-6 Sol OI-CM3-1): a 1500-byte default route and a 1400-byte
// route to one client prefix outside the four startup probes. The startup
// check passes (the probes all leave through the 1500 device); the per-client
// guard must refuse a client in that prefix and serve one outside it. The
// netns test in egress_mtu_netns_linux_test.go runs the same arrangement
// against a real kernel.

// clientEgressStub stands in for the kernel's per-client answer. It records
// every lookup and answers narrow for addresses in narrowPrefix, for the
// destination port narrowPort (a `dport` rule), or for every address while
// allNarrow is set.
type clientEgressStub struct {
	narrowPrefix netip.Prefix
	narrowPort   uint16
	allNarrow    atomic.Bool
	mu           sync.Mutex
	asked        []netip.AddrPort
	lookups      []egressLookup
}

func (s *clientEgressStub) measure(lookup egressLookup, dst netip.AddrPort) egressRoute {
	s.mu.Lock()
	s.asked = append(s.asked, dst)
	s.lookups = append(s.lookups, lookup)
	s.mu.Unlock()
	if s.allNarrow.Load() || (s.narrowPrefix.IsValid() && s.narrowPrefix.Contains(dst.Addr())) ||
		(s.narrowPort != 0 && dst.Port() == s.narrowPort) {
		return egressRoute{Dest: dst.Addr(), DestPort: dst.Port(), Device: "ts1", MTU: 1400, DeviceMTU: 1400, Table: 254}
	}
	return egressRoute{Dest: dst.Addr(), DestPort: dst.Port(), Device: "ts2", MTU: 1500, DeviceMTU: 1500, Table: 254}
}

func (s *clientEgressStub) record() ([]netip.AddrPort, []egressLookup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]netip.AddrPort(nil), s.asked...), append([]egressLookup(nil), s.lookups...)
}

// installClientEgressStub swaps measureClientEgress for the test. Register
// it BEFORE anything that runs a read loop, so the restore runs after that
// loop has stopped (t.Cleanup is last in, first out).
func installClientEgressStub(t *testing.T, stub *clientEgressStub) {
	t.Helper()
	saved := measureClientEgress
	measureClientEgress = stub.measure
	t.Cleanup(func() { measureClientEgress = saved })
}

func TestClientEgressGuardRefusesOnlyTheNarrowPrefix(t *testing.T) {
	stub := &clientEgressStub{narrowPrefix: netip.MustParsePrefix("45.0.0.0/16")}
	installClientEgressStub(t, stub)
	udp1450 := mustSizing(t, 1450, carrier.ClassUDP) // 1430-byte datagrams
	lookup := egressLookup{Port: 9111}
	g := &clientEgressGuard{lookup: lookup, datagram: plannedIPv4Datagram(udp1450)}

	// The startup check sees only the probes, which route through ts2 1500.
	var probes []egressRoute
	for _, d := range egressProbeDestinations {
		probes = append(probes, stub.measure(lookup, netip.AddrPortFrom(d, 0)))
	}
	var log bytes.Buffer
	if err := checkEgressMTU(udp1450, lookup, probes, nil, &log); err != nil {
		t.Fatalf("startup check with every probe via the 1500 default: %v", err)
	}

	if r, ok := g.check(netip.MustParseAddrPort("45.0.1.2:40000")); ok || r.Device != "ts1" || r.MTU != 1400 {
		t.Fatalf("client 45.0.1.2 behind the 1400 route: route %+v ok=%t, want refused", r, ok)
	}
	if r, ok := g.check(netip.MustParseAddrPort("46.0.0.1:40000")); !ok || r.Device != "ts2" {
		t.Fatalf("client 46.0.0.1 via the 1500 default: route %+v ok=%t, want served", r, ok)
	}
	// A v4-mapped address is asked about as plain IPv4, port kept.
	if _, ok := g.check(netip.MustParseAddrPort("[::ffff:45.0.1.2]:40001")); ok {
		t.Fatal("the v4-mapped form of a narrow client was served")
	}
	asked, lookups := stub.record()
	want := []netip.AddrPort{netip.MustParseAddrPort("45.0.1.2:40000"), netip.MustParseAddrPort("46.0.0.1:40000"),
		netip.MustParseAddrPort("45.0.1.2:40001")}
	if len(asked) < len(probes)+3 {
		t.Fatalf("asked %v", asked)
	}
	for i, w := range want {
		if got := asked[len(probes)+i]; got != w || !got.Addr().Is4() {
			t.Fatalf("guard lookup %d asked about %s, want the client itself (%s)", i, got, w)
		}
		if lookups[len(probes)+i] != lookup {
			t.Fatalf("guard lookup %d used flow %+v, want the listener's %+v", i, lookups[len(probes)+i], lookup)
		}
	}

	// The boundary: a 1400-byte datagram fits a 1400-byte route.
	if _, ok := (&clientEgressGuard{lookup: lookup, datagram: 1400}).check(netip.MustParseAddrPort("45.0.1.2:40000")); !ok {
		t.Fatal("a datagram equal to the route MTU was refused")
	}
}

// Round CM3 Turn 2 (Sol): a `dport` rule. The client's own port is in the
// lookup, so a client on the narrow-routed port is refused and the same
// address on another port is served.
func TestClientEgressGuardAsksWithTheClientPort(t *testing.T) {
	stub := &clientEgressStub{narrowPort: 40000}
	installClientEgressStub(t, stub)
	g := &clientEgressGuard{lookup: egressLookup{Port: 9111}, datagram: 1430}
	if r, ok := g.check(netip.MustParseAddrPort("46.0.0.1:40000")); ok || r.DestPort != 40000 {
		t.Fatalf("client port 40000 behind a dport rule to 1400: %+v ok=%t, want refused", r, ok)
	}
	if _, ok := g.check(netip.MustParseAddrPort("46.0.0.1:40001")); !ok {
		t.Fatal("the same client on port 40001 was refused")
	}
}

// A complete "no route" answer (unreachable, prohibit) never refuses, as at
// startup: such a reply cannot leave fragmented. A lookup the kernel REFUSED
// fails closed: the flow could not be described. Round CM3 Turn 6: so does an
// incomplete answer, a host netlink error (a timeout, which used to be
// served) and a device MTU that is not a number.
func TestClientEgressGuardServesAnUnmeasuredRoute(t *testing.T) {
	saved := measureClientEgress
	t.Cleanup(func() { measureClientEgress = saved })
	g := &clientEgressGuard{datagram: 1430}
	for _, tc := range []struct {
		r     egressRoute
		serve bool
	}{
		{r: egressRoute{Err: syscall.ENETUNREACH}, serve: true},
		{r: egressRoute{Err: syscall.EHOSTUNREACH}, serve: true},
		{r: egressRoute{Err: syscall.EACCES}, serve: true},
		{r: egressRoute{Err: errors.ErrUnsupported}, serve: true},
		{r: egressRoute{Err: errors.New("rtnetlink receive: resource temporarily unavailable")}, serve: false},
		{r: egressRoute{Err: incompleteAnswer("no answer within 250ms (3 attempts)")}, serve: false},
		{r: egressRoute{Err: fmt.Errorf("%w: link 7: %w", errNetlinkIncomplete, syscall.ENODEV)}, serve: false},
		{r: egressRoute{Device: "eth0", MTU: 0}, serve: false},
		{r: egressRoute{Err: fmt.Errorf("kernel route lookup: %w", syscall.EINVAL)}, serve: false},
		{r: egressRoute{Err: fmt.Errorf("kernel route lookup: %w", syscall.EOPNOTSUPP)}, serve: false},
		{r: egressRoute{Err: fmt.Errorf("%w: NETLINK_GET_STRICT_CHK: %v", errFlowNotDescribable, syscall.ENOPROTOOPT)}, serve: false},
	} {
		measureClientEgress = func(egressLookup, netip.AddrPort) egressRoute { return tc.r }
		if _, ok := g.check(netip.MustParseAddrPort("45.0.1.2:40000")); ok != tc.serve {
			t.Fatalf("route %+v: served=%t, want %t", tc.r, ok, tc.serve)
		}
	}
	var nilServer server
	if !nilServer.clientEgressFits(netip.MustParseAddrPort("45.0.1.2:1")) {
		t.Fatal("a server with no guard refused a client")
	}
}

// udpAttemptCarries runs one UDP client against endpoint and reports whether
// it reached carrying within the window.
func udpAttemptCarries(t *testing.T, endpoint, dir string, window time.Duration) bool {
	t.Helper()
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := net.ResolveUDPAddr("udp4", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	car, err := carrier.DialUDP(t.Context(), carrier.UDPConfig{
		Remote: remote, MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := newCarrierClientForTest(t, t.Context(), dir, sizing, car)
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if client.loop.Tunnel().Gate().State() == tun.StateCarrying {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// Through runServe itself: the guard is installed, asks about the client's
// own address with the listener's flow, and a narrow answer refuses the
// session before anything is built, counted in egress_mtu_refused and not in
// session_build_failures. Control: a wide answer carries.
func TestRunServeRefusesAClientWhoseRouteIsTooNarrow(t *testing.T) {
	for _, narrow := range []bool{true, false} {
		stub := &clientEgressStub{}
		stub.allNarrow.Store(narrow)
		installClientEgressStub(t, stub)
		opts := ingressOptions(t, 5*time.Second)
		g := startIngressGateway(t, opts)
		carried := udpAttemptCarries(t, g.endpoint, g.dir, 3*time.Second)
		st := g.stopped(t)
		asked, lookups := stub.record()
		if len(asked) == 0 {
			t.Fatalf("narrow=%t: runServe never asked about the client's route", narrow)
		}
		_, portText, _ := net.SplitHostPort(g.endpoint)
		port, err := strconv.Atoi(portText)
		if err != nil {
			t.Fatal(err)
		}
		for i, a := range asked {
			if a.Addr() != netip.MustParseAddr("127.0.0.1") || a.Port() == 0 || int(a.Port()) == port ||
				lookups[i].Source != netip.MustParseAddr("127.0.0.1") || int(lookups[i].Port) != port {
				t.Fatalf("narrow=%t: lookup %d asked about %s with flow %+v, want 127.0.0.1 from the listener %s",
					narrow, i, a, lookups[i], g.endpoint)
			}
		}
		if narrow {
			if carried {
				t.Fatal("a client whose replies route through a 1400-byte device carried with a 1438-byte plan")
			}
			if st.EgressMTURefused == 0 || st.Admitted != 0 || st.Built != 0 || st.BuildFailures != 0 {
				t.Fatalf("narrow: egress_mtu_refused=%d admitted=%d built=%d build_failures=%d; want >0, 0, 0, 0",
					st.EgressMTURefused, st.Admitted, st.Built, st.BuildFailures)
			}
			continue
		}
		if !carried || st.EgressMTURefused != 0 || st.Admitted != 1 {
			t.Fatalf("control: carried=%t egress_mtu_refused=%d admitted=%d, want true, 0, 1",
				carried, st.EgressMTURefused, st.Admitted)
		}
	}
}

func lineWith(text, needle string) string {
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, needle) {
			return l
		}
	}
	return ""
}

// The refusal is counted, and its bounded log line names the device and MTU
// but never the client's address.
func TestClientEgressRefusalLogNamesNoAddress(t *testing.T) {
	stub := &clientEgressStub{narrowPrefix: netip.MustParsePrefix("45.0.0.0/16")}
	installClientEgressStub(t, stub)
	s := &server{egressGuard: &clientEgressGuard{lookup: egressLookup{Port: 9111}, datagram: 1430}}
	var fits []bool
	out := captureEgressLog(t, func() {
		for i := 0; i < maxRefusalLogs+5; i++ {
			fits = append(fits, s.clientEgressFits(netip.MustParseAddrPort("45.0.1.2:40000")))
		}
		fits = append(fits, s.clientEgressFits(netip.MustParseAddrPort("46.0.0.1:40000")))
	})
	for i, ok := range fits[:len(fits)-1] {
		if ok {
			t.Fatalf("attempt %d from the narrow prefix was served", i)
		}
	}
	if !fits[len(fits)-1] {
		t.Fatal("a client via the wide default was refused")
	}
	if got := s.egressRefused.Load(); got != uint64(maxRefusalLogs+5) {
		t.Fatalf("egress_mtu_refused = %d, want %d", got, maxRefusalLogs+5)
	}
	line := lineWith(out, "refused a client whose replies")
	if !strings.Contains(line, "through ts1 (mtu 1400, route mtu 0, table 254): the plan's 1430-byte") {
		t.Fatalf("refusal line %q", line)
	}
	if strings.Contains(out, "45.0.1.2") || strings.Contains(out, "40000") {
		t.Fatalf("the refusal log names the client:\n%s", out)
	}
	if n := strings.Count(out, "refused a client whose replies"); n != maxRefusalLogs {
		t.Fatalf("%d refusal lines, want the bound %d", n, maxRefusalLogs)
	}
	if !strings.Contains(out, "further egress refusals will not be logged") {
		t.Fatalf("no end-of-log line:\n%s", out)
	}
}

// A lookup the kernel refused is counted and logged as such, still without
// the address.
func TestClientEgressFailClosedLogNamesNoAddress(t *testing.T) {
	saved := measureClientEgress
	t.Cleanup(func() { measureClientEgress = saved })
	measureClientEgress = func(_ egressLookup, dst netip.AddrPort) egressRoute {
		return egressRoute{Dest: dst.Addr(), DestPort: dst.Port(), Err: fmt.Errorf("kernel route lookup: %w", syscall.EINVAL)}
	}
	s := &server{egressGuard: &clientEgressGuard{lookup: egressLookup{Port: 9111}, datagram: 1430}}
	var ok bool
	out := captureEgressLog(t, func() { ok = s.clientEgressFits(netip.MustParseAddrPort("45.0.1.2:40000")) })
	if ok || s.egressRefused.Load() != 1 {
		t.Fatalf("a refused lookup: served=%t refused=%d, want refused and counted", ok, s.egressRefused.Load())
	}
	if line := lineWith(out, "refused a client"); !strings.Contains(line, "the kernel refused or did not completely answer the route lookup") ||
		strings.Contains(out, "45.0.1.2") || strings.Contains(out, "40000") {
		t.Fatalf("fail-closed log %q (full: %q)", line, out)
	}
}

// Under -demux=token a live session that moves to an address whose replies
// route through a narrow device is not rebound: the old binding stays, the
// datagram is dropped, and the refusal is counted.
func TestTokenDemuxRebindToANarrowRouteIsRefused(t *testing.T) {
	stub := &clientEgressStub{}
	installClientEgressStub(t, stub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	sessionCfg, err := buildSessionConfig(serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	})
	if err != nil {
		t.Fatal(err)
	}
	assign, err := parseAssignment(testGatewayInner, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer conn.Close()
	srv := &server{
		conn: conn, sizing: sizing, sessionCfg: sessionCfg, assign: assign,
		maxSessions: 8, demux: "token",
		peers:       make(map[netip.AddrPort]*peerSession),
		egressGuard: &clientEgressGuard{datagram: plannedIPv4Datagram(sizing)},
	}
	readDone := make(chan error, 1)
	go func() { readDone <- srv.readLoop(ctx) }()
	defer func() {
		_ = conn.SetReadDeadline(time.Now())
		<-readDone
		srv.closeAll()
	}()

	gwAddr := conn.LocalAddr().(*net.UDPAddr)
	cli := startTestClient(t, ctx, testClientOpts{
		dir: dir, gwAddr: gwAddr,
		gatewayPublic: readTestKey(t, filepath.Join(dir, "static.pub")),
		admission:     readTestSecret(t, filepath.Join(dir, "admission.key")),
		sizing:        sizing, inner: testClientInner,
	})
	waitFor(t, 40*time.Second, "the client gate to carry", func() bool {
		return cli.loop.Tunnel().Gate().State() == tun.StateCarrying
	})
	pre := []byte("token-demux pre-move round trip")
	cli.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, pre))
	if back := cli.dev.take(t, 40*time.Second); !bytes.Equal(back[20:], pre) {
		t.Fatalf("pre-rebind round trip payload is %q", back[20:])
	}
	oldAddr := func() netip.AddrPort {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		for a := range srv.peers {
			return a
		}
		return netip.AddrPort{}
	}()

	rebound, err := net.DialUDP("udp4", nil, gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rebound.Close() })
	ap := rebound.LocalAddr().(*net.UDPAddr).AddrPort()
	if srv.known(ap) {
		t.Skip("kernel reused the live client's source port")
	}
	newCar, err := carrier.NewUDP(carrier.UDPConfig{
		Conn: rebound, OwnsConn: true, MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	// From here every address's replies route through a narrow device.
	stub.allNarrow.Store(true)
	if _, err := cli.loop.Migrate(newCar); err != nil {
		t.Fatalf("client Loop.Migrate: %v", err)
	}
	post := []byte("token-demux post-rebind round trip to a narrow route")
	cli.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, post))
	waitFor(t, 10*time.Second, "the rebind to be refused", func() bool {
		return srv.status().EgressMTURefused >= 1
	})
	if srv.known(ap) {
		t.Fatal("the session was rebound to an address whose replies route through a narrow device")
	}
	if !srv.known(oldAddr) {
		t.Fatalf("the old binding %s was dropped", oldAddr)
	}
	if st := srv.status(); st.Sessions != 1 || st.Strangers != 0 {
		t.Fatalf("sessions=%d strangers=%d after the refused rebind, want 1 and 0", st.Sessions, st.Strangers)
	}
}

// captureEgressLog runs fn with egressLog redirected and returns what was written.
func captureEgressLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf safeBuffer
	saved := egressLog
	egressLog = &buf
	defer func() { egressLog = saved }()
	fn()
	return string(buf.snapshot())
}
