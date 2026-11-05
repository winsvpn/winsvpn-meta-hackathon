package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Silent-refusal instance #9: the lab rig resolved its assignment and built its
// session AFTER listenAndLearnPeer had already bound the socket and blocked in
// MSG_PEEK, and after openConfiguredTun had already created and addressed a
// kernel interface on the host.
//
// These tests assert the ORDER, not just the rules. The rules were never in
// doubt — winn3/tun and winn3/core state them loudly and correctly. What was
// wrong was that they fired at first-datagram time, which for a responder that
// nobody dials is never.
//
// Two things they deliberately do NOT do:
//
//   - They never call runGateway with a configuration that could get past the
//     preflight. On a Linux host with CAP_NET_ADMIN that would open a real
//     device and then park in MSG_PEEK until the test timeout. The
//     over-fire control below exercises the same gates directly instead.
//   - They assert nothing about what a peer can observe. The rig must still
//     answer an unauthenticated datagram with silence; the loudness added here
//     is toward the OPERATOR, at startup, before anything binds.

// preflightPhrases are the fragments only the startup gates emit. An error
// carrying one of these proves runGateway returned before openConfiguredTun,
// on every platform, without this test having to name the device error.
var preflightPhrases = []string{
	"cannot build a session",
	"cannot carry traffic",
	"-inner-v4",
	"-router-v4",
	"-tun-addr",
}

func refusedBeforeAnythingOpened(err error) bool {
	if err == nil {
		return false
	}
	for _, phrase := range preflightPhrases {
		if strings.Contains(err.Error(), phrase) {
			return true
		}
	}
	return false
}

// operatorFiles writes a static key and an admission secret that are BOTH
// valid, so that any refusal a test sees comes from the value under test.
func operatorFiles(t *testing.T) (staticPath, admissionPath string) {
	t.Helper()
	dir := t.TempDir()
	static, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	staticPath = filepath.Join(dir, "static.key")
	if err := os.WriteFile(staticPath, static.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	admissionPath = filepath.Join(dir, "admission.key")
	if err := os.WriteFile(admissionPath, []byte(strings.Repeat("a", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	return staticPath, admissionPath
}

// goodOptions is a rig configuration that can genuinely carry traffic. Every
// case below is this, with exactly one field spoiled.
func goodOptions(t *testing.T) gatewayOptions {
	t.Helper()
	staticPath, admissionPath := operatorFiles(t)
	return gatewayOptions{
		listen:     "127.0.0.1:0",
		staticPath: staticPath,
		admission:  admissionPath,
		gatewayID:  "gw.example",
		innerV4:    "10.99.3.2",
		routerV4:   "10.99.3.1",
		tunName:    "winn3lab0",
		tunAddr:    "10.99.3.2",
		tunRoutes:  []string{"10.99.3.1/32"},
	}
}

func devNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// TestRunGatewayRefusesAnUnusableConfigurationBeforeItOpensADeviceOrBindsASocket
// is the whole finding.
//
// Every case here used to reach openConfiguredTun, create a kernel interface,
// bind a UDP socket, print "listening" and then block — surfacing the refusal
// only if and when a client happened to connect. The assertion is on the error's
// CONTENT precisely because the error's content is what proves how far the
// function got: a device or socket error would name /dev/net/tun or Linux, and
// no case below may produce one.
func TestRunGatewayRefusesAnUnusableConfigurationBeforeItOpensADeviceOrBindsASocket(t *testing.T) {
	cases := []struct {
		name   string
		spoil  func(*gatewayOptions)
		expect string
	}{
		{
			// The pair that started this. Rejected by winn3/tun/tun.go:169.
			name:   "router equal to the assigned address",
			spoil:  func(o *gatewayOptions) { o.routerV4 = o.innerV4 },
			expect: "router address equals the assigned address",
		},
		{
			// -inner-v4's default is "" and parseAssignment always caught it —
			// but only after the socket was bound.
			name:   "inner address unset",
			spoil:  func(o *gatewayOptions) { o.innerV4 = "" },
			expect: "-inner-v4 is empty",
		},
		{
			name:   "inner address unparseable",
			spoil:  func(o *gatewayOptions) { o.innerV4 = "10.99.3.999" },
			expect: "-inner-v4",
		},
		{
			name:   "router address unparseable",
			spoil:  func(o *gatewayOptions) { o.routerV4 = "not-an-address" },
			expect: "-router-v4",
		},
		{
			// The flag name promises IPv4 and the parser does not enforce it.
			// netip.ParseAddr is happy; tun.Assignment.validate is not.
			name:   "inner address is an IPv6 literal in an IPv4 flag",
			spoil:  func(o *gatewayOptions) { o.innerV4, o.tunAddr = "2001:db8::2", "2001:db8::2" },
			expect: "not a 4-byte address",
		},
		{
			name:   "router address is an IPv6 literal in an IPv4 flag",
			spoil:  func(o *gatewayOptions) { o.routerV4 = "2001:db8::1" },
			expect: "not a 4-byte address",
		},
		{
			name:   "inner address is IPv4-mapped IPv6",
			spoil:  func(o *gatewayOptions) { o.innerV4, o.tunAddr = "::ffff:10.99.3.2", "::ffff:10.99.3.2" },
			expect: "not a 4-byte address",
		},
		{
			name:   "inner address is loopback",
			spoil:  func(o *gatewayOptions) { o.innerV4, o.tunAddr = "127.0.0.1", "127.0.0.1" },
			expect: "unusable",
		},
		{
			name:   "inner address is unspecified",
			spoil:  func(o *gatewayOptions) { o.innerV4, o.tunAddr = "0.0.0.0", "0.0.0.0" },
			expect: "unusable",
		},
		{
			name:   "inner address is multicast",
			spoil:  func(o *gatewayOptions) { o.innerV4, o.tunAddr = "224.0.0.9", "224.0.0.9" },
			expect: "unusable",
		},
		{
			name:   "inner address is in the reserved high block",
			spoil:  func(o *gatewayOptions) { o.innerV4, o.tunAddr = "255.255.255.255", "255.255.255.255" },
			expect: "unusable",
		},
		{
			name:   "router address is link-local",
			spoil:  func(o *gatewayOptions) { o.routerV4 = "169.254.1.1" },
			expect: "router address is unusable",
		},
		{
			// -gateway-id's default is "" too, and core refuses an empty one
			// (winn3/core/params.go:350). A rig started without it bound a
			// socket and could never have admitted anybody.
			name:   "gateway id unset",
			spoil:  func(o *gatewayOptions) { o.gatewayID = "" },
			expect: "gateway id is empty",
		},
		{
			name:   "gateway id longer than 255 bytes",
			spoil:  func(o *gatewayOptions) { o.gatewayID = strings.Repeat("g", 256) },
			expect: "more than 255",
		},
		{
			// core's admission floor is 32 bytes. An empty or truncated
			// admission file is an operator error, not a peer's.
			name: "admission secret below the 32-byte floor",
			spoil: func(o *gatewayOptions) {
				o.admission = writeTempFile(t, "short.key", "tooshort")
			},
			expect: "admission key",
		},
		{
			name: "admission file is empty",
			spoil: func(o *gatewayOptions) {
				o.admission = writeTempFile(t, "empty.key", "")
			},
			expect: "admission key",
		},
		{
			// winn3/tun never sees -tun-addr, so no rule in that package can
			// catch this. The kernel would source from one address and the
			// tunnel would refuse anything that is not the other.
			name:   "interface address is not the assigned address",
			spoil:  func(o *gatewayOptions) { o.tunAddr = "10.99.3.7" },
			expect: "is not -inner-v4",
		},
		{
			name:   "interface address unparseable",
			spoil:  func(o *gatewayOptions) { o.tunAddr = "10.99.3.7/32" },
			expect: "-tun-addr",
		},
		{
			// parseAssignment currently assigns no inner IPv6, so any
			// -tun-addr6 value is a source the kernel would originate and
			// winn3/tun would refuse as ErrFamilyOff.
			name:   "tun-addr6 set while this gateway assigns no inner IPv6",
			spoil:  func(o *gatewayOptions) { o.tunAddr6 = "2001:db8::2" },
			expect: "-tun-addr6",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := goodOptions(t)
			tc.spoil(&opts)
			err := runGateway(opts, devNull(t))
			if err == nil {
				t.Fatalf("runGateway accepted a configuration that can never carry traffic; "+
					"it would have bound %s and waited in silence", opts.listen)
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Fatalf("refused, but not for the stated reason.\n got: %v\nwant substring: %q",
					err, tc.expect)
			}
			if !refusedBeforeAnythingOpened(err) {
				t.Fatalf("the refusal does not look like a startup refusal, so it may have "+
					"come from the device or the socket rather than from a gate that runs "+
					"before either exists: %v", err)
			}
		})
	}
}

func writeTempFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestEveryLegitimateConfigurationStillPassesEveryStartupGate is the over-fire
// control, and it is the reason the table above is worth anything.
//
// A gate that refuses everything would be strictly worse than the defect it
// closes: the rig would stop starting at all and the operator would have no way
// to tell a real refusal from a broken one. Each case here is a configuration
// that can genuinely carry traffic and must reach the point where the only thing
// left to fail is the host itself.
//
// It calls the startup gates directly rather than runGateway, because on a Linux
// host with CAP_NET_ADMIN a configuration that passes them opens a real device
// and then blocks in MSG_PEEK forever.
func TestEveryLegitimateConfigurationStillPassesEveryStartupGate(t *testing.T) {
	cases := []struct {
		name   string
		adjust func(*gatewayOptions)
	}{
		{"the reference rig", func(*gatewayOptions) {}},
		{"no router address at all, which is optional",
			func(o *gatewayOptions) { o.routerV4 = "" }},
		{"a router address in a different private block",
			func(o *gatewayOptions) { o.routerV4 = "172.16.0.1" }},
		{"a 100.64/10 CGNAT assignment",
			func(o *gatewayOptions) { o.innerV4, o.tunAddr, o.routerV4 = "100.64.0.2", "100.64.0.2", "100.64.0.1" }},
		{"a public-range assignment, which this layer does not police",
			func(o *gatewayOptions) {
				o.innerV4, o.tunAddr, o.routerV4 = "198.51.100.2", "198.51.100.2", "198.51.100.1"
			}},
		{"no host routes, which is a posture and not an error",
			func(o *gatewayOptions) { o.tunRoutes = nil }},
		{"several host routes",
			func(o *gatewayOptions) { o.tunRoutes = []string{"10.99.3.1/32", "10.99.3.5/32"} }},
		{"a one-byte gateway id",
			func(o *gatewayOptions) { o.gatewayID = "g" }},
		{"a 255-byte gateway id, which is the boundary",
			func(o *gatewayOptions) { o.gatewayID = strings.Repeat("g", 255) }},
		{"an admission secret exactly at the 32-byte floor",
			func(o *gatewayOptions) { o.admission = writeTempFile(t, "floor.key", strings.Repeat("k", 32)) }},
		{"an admission secret with a trailing newline, as keygen writes it",
			func(o *gatewayOptions) { o.admission = writeTempFile(t, "nl.key", strings.Repeat("k", 64)+"\n") }},
		{"an unset -tun-addr, which configureInterface refuses later and loudly",
			func(o *gatewayOptions) { o.tunAddr = "" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := goodOptions(t)
			tc.adjust(&opts)

			sizing, err := driver.NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
			if err != nil {
				t.Fatal(err)
			}
			assign, err := parseAssignment(opts.innerV4, opts.routerV4)
			if err != nil {
				t.Fatalf("parseAssignment refused a usable configuration: %v", err)
			}
			sessionConfig, err := buildGatewaySession(opts)
			if err != nil {
				t.Fatalf("buildGatewaySession refused a usable configuration: %v", err)
			}
			if err := checkTunAddrMatchesAssignment(opts.tunAddr, assign); err != nil {
				t.Fatalf("the interface-address gate refused a usable configuration: %v", err)
			}
			if err := preflightSession(sizing, sessionConfig, assign); err != nil {
				t.Fatalf("the preflight refused a configuration that can carry traffic, which "+
					"is worse than the defect it closes: %v", err)
			}
		})
	}
}

// TestThePreflightDelegatesToTheRealConstructorsInsteadOfRestatingTheirRules.
//
// The value of the dry run is that a rule added to winn3/tun or winn3/core is
// enforced at the rig's startup on the day it is added, without this file being
// touched. That property is only real if the preflight actually calls those
// constructors, so this asserts on a rule that exists ONLY inside them and is
// nowhere restated in main.go: the wrong-family assignment.
//
// If somebody later replaces preflightSession with a hand-written checklist,
// this test is what notices.
func TestThePreflightDelegatesToTheRealConstructorsInsteadOfRestatingTheirRules(t *testing.T) {
	staticPath, admissionPath := operatorFiles(t)
	sessionConfig, err := buildGatewaySession(gatewayOptions{
		staticPath: staticPath, admission: admissionPath, gatewayID: "gw.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	sizing, err := driver.NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}

	// Built by hand rather than through parseAssignment, so the only thing that
	// can reject it is tun.New.
	assign, err := parseAssignment("2001:db8::2", "")
	if err != nil {
		t.Fatalf("parseAssignment rejected an IPv6 literal in -inner-v4; if that is now a "+
			"parser rule, this test needs a different witness: %v", err)
	}
	err = preflightSession(sizing, sessionConfig, assign)
	if err == nil {
		t.Fatal("the preflight accepted an IPv6 address in the IPv4 assignment; " +
			"it is no longer running winn3/tun's own validation")
	}
	if !errors.Is(err, tun.ErrConfig) {
		t.Fatalf("the refusal did not come from winn3/tun, so the preflight is restating "+
			"rules rather than delegating to them: %v", err)
	}
}

// TestParseAssignmentDoesNotEnforceTheFamilyItsFlagNamesPromise records what
// parseAssignment actually does, as opposed to what its flag names suggest.
//
// This is deliberately an assertion that the parser is PERMISSIVE. It is not a
// defect on its own — the family rule is winn3/tun's and it is correctly
// enforced there — but the rig's safety now depends on the preflight being the
// thing that runs it. Tightening parseAssignment without noticing that would
// leave TestThePreflightDelegates... without a witness, and this test says so
// where somebody will read it.
func TestParseAssignmentDoesNotEnforceTheFamilyItsFlagNamesPromise(t *testing.T) {
	assign, err := parseAssignment("2001:db8::2", "2001:db8::1")
	if err != nil {
		t.Skipf("parseAssignment now enforces the family itself: %v", err)
	}
	if assign.V4.Is4() {
		t.Fatalf("expected the IPv6 literal to land in V4 unchanged, got %v", assign.V4)
	}
}

// TestThePreflightDeviceReportsTheSameMTUTheRealInterfaceWillHave.
//
// tun.New refuses a device MTU above the inner MTU and below the IPv4 floor, so
// a preflight device that reported some convenient number would be answering a
// question the real start never asks — and the rig would pass its own dry run
// and then fail at first datagram, which is the defect this file closes wearing
// a different hat.
func TestThePreflightDeviceReportsTheSameMTUTheRealInterfaceWillHave(t *testing.T) {
	sizing, err := driver.NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	// openConfiguredTun is called with sizing.InnerMTU and labTun.MTU returns
	// exactly what it was given, so this is the number the real device reports.
	if got := (preflightDevice{mtu: sizing.InnerMTU}).MTU(); got != sizing.InnerMTU {
		t.Fatalf("preflight device MTU %d, real device MTU %d", got, sizing.InnerMTU)
	}
}

// TestThePreflightDeviceCarriesNoPackets. The dry run must open nothing and
// move nothing; both packet methods exist only to satisfy tun.Device.
func TestThePreflightDeviceCarriesNoPackets(t *testing.T) {
	d := preflightDevice{mtu: 1400}
	if _, err := d.ReadPacket(make([]byte, 64)); !errors.Is(err, errPreflightIO) {
		t.Fatalf("ReadPacket returned %v", err)
	}
	if _, err := d.WritePacket(make([]byte, 64)); !errors.Is(err, errPreflightIO) {
		t.Fatalf("WritePacket returned %v", err)
	}
}

// TestTunfdExecRefusesAChildDescriptorItCannotProduceBeforeItOpensADevice.
//
// The same ordering fault in the rig's other mode. runTunFDExec checked
// -child-fd at tun_linux.go:204, after openTunDevice had created the interface
// and configureInterface had addressed it and brought it up — so the operator
// got the refusal only once the host had already been changed. The check is a
// fact about Go's ExtraFiles, decidable from the flag alone.
//
// This drives run(), not runTunFDExec, so it exercises the argument parsing an
// operator actually types.
func TestTunfdExecRefusesAChildDescriptorItCannotProduceBeforeItOpensADevice(t *testing.T) {
	err := run([]string{
		"-mode", "tunfd-exec", "-tun", "winn3lab0", "-tun-addr", "10.99.3.2",
		"-mtu", "1203", "-child-fd", "4", "/bin/true",
	}, devNull(t))
	if err == nil {
		t.Fatal("tunfd-exec accepted -child-fd 4")
	}
	if !strings.Contains(err.Error(), "-child-fd 4") {
		t.Fatalf("refused for some other reason, which may mean it reached the device "+
			"first: %v", err)
	}
}

// TestTunfdExecStillAcceptsTheOnlyDescriptorItCanProduce is the matching
// over-fire control: -child-fd 3 must get past the flag gate and fail only on
// the host, never on the flag.
func TestTunfdExecStillAcceptsTheOnlyDescriptorItCanProduce(t *testing.T) {
	err := run([]string{
		"-mode", "tunfd-exec", "-tun", "winn3lab0", "-tun-addr", "10.99.3.2",
		"-mtu", "1203", "-child-fd", "3", "/bin/true",
	}, devNull(t))
	if err != nil && strings.Contains(err.Error(), "-child-fd") {
		t.Fatalf("the flag gate refused the one descriptor Go can produce: %v", err)
	}
}

// TestTunfdExecRefusesTheOtherHostlessFlagsBeforeItOpensADevice covers the
// rest of tunfdExecFlagError: missing command, missing MTU, missing tun name,
// missing address. Each used to be reachable only after openTunDevice on Linux.
func TestTunfdExecRefusesTheOtherHostlessFlagsBeforeItOpensADevice(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		expect string
	}{
		{
			name: "no command",
			args: []string{
				"-mode", "tunfd-exec", "-tun", "winn3lab0", "-tun-addr", "10.99.3.2",
				"-mtu", "1203", "-child-fd", "3",
			},
			expect: "tunfd-exec needs a command",
		},
		{
			name: "mtu unset",
			args: []string{
				"-mode", "tunfd-exec", "-tun", "winn3lab0", "-tun-addr", "10.99.3.2",
				"-child-fd", "3", "/bin/true",
			},
			expect: "tunfd-exec needs -mtu",
		},
		{
			name: "tun name unset",
			args: []string{
				"-mode", "tunfd-exec", "-tun-addr", "10.99.3.2",
				"-mtu", "1203", "-child-fd", "3", "/bin/true",
			},
			expect: "tunfd-exec needs -tun",
		},
		{
			name: "tun address unset",
			args: []string{
				"-mode", "tunfd-exec", "-tun", "winn3lab0",
				"-mtu", "1203", "-child-fd", "3", "/bin/true",
			},
			expect: "tunfd-exec needs -tun-addr",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := run(tc.args, devNull(t))
			if err == nil {
				t.Fatal("tunfd-exec accepted a configuration that cannot produce a descriptor")
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Fatalf("refused for some other reason, which may mean it reached the device first: %v", err)
			}
			if strings.Contains(err.Error(), "/dev/net/tun") || strings.Contains(err.Error(), "Linux only") {
				t.Fatalf("the refusal names the device or the platform, so the flag gate did not fire first: %v", err)
			}
		})
	}
}

// TestKeygenAndGatewayRefusePositionalArguments. An extra token used to be
// dropped on the floor: flag.FlagSet parks it in Args() and neither mode read
// it. Under this threat model an operator who thought they passed a peer or a
// path and were ignored is looking at a silent misconfiguration.
func TestKeygenAndGatewayRefusePositionalArguments(t *testing.T) {
	dir := t.TempDir()
	err := run([]string{"-mode", "keygen", "-out", dir, "surprise"}, devNull(t))
	if err == nil {
		t.Fatal("keygen accepted a positional argument")
	}
	if !strings.Contains(err.Error(), "positional") {
		t.Fatalf("keygen refused for some other reason: %v", err)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("keygen wrote %d files before refusing leftover args; the check ran too late", len(entries))
	}

	err = run([]string{
		"-mode", "gateway", "-listen", "127.0.0.1:0", "-tun", "winn3lab0", "surprise",
	}, devNull(t))
	if err == nil {
		t.Fatal("gateway accepted a positional argument")
	}
	if !strings.Contains(err.Error(), "positional") {
		t.Fatalf("gateway refused for some other reason: %v", err)
	}
}

// TestGatewayNewUDPWiresASocketBufferHook. carrier.NewUDP requests 8 MiB and
// does not refuse a short grant; the library does not log. A caller that
// omits SocketBufferHook makes a clamped SO_RCVBUF look like a slow path.
func TestGatewayNewUDPWiresASocketBufferHook(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if !strings.Contains(src, "SocketBufferHook:") {
		t.Fatal("runGateway's NewUDP has no SocketBufferHook; a short kernel grant would be silent")
	}
	if !strings.Contains(src, "FormatUDPSocketBufferGrant") {
		t.Fatal("the hook does not print FormatUDPSocketBufferGrant")
	}
}

// TestThePreflightBuildsARealSessionAndClosesIt guards the other direction: a
// preflight that returned nil without constructing anything would pass every
// test above by doing nothing at all.
func TestThePreflightBuildsARealSessionAndClosesIt(t *testing.T) {
	staticPath, admissionPath := operatorFiles(t)
	sessionConfig, err := buildGatewaySession(gatewayOptions{
		staticPath: staticPath, admission: admissionPath, gatewayID: "gw.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	sizing, err := driver.NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	assign, err := parseAssignment("10.99.3.2", "10.99.3.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := preflightSession(sizing, sessionConfig, assign); err != nil {
		t.Fatal(err)
	}

	// The same configuration, with the session half made impossible in a way
	// only session/core can see. If the preflight were a no-op this would pass.
	var noAccept session.Config = sessionConfig
	noAccept.Accept = nil
	if err := preflightSession(sizing, noAccept, assign); err == nil {
		t.Fatal("the preflight accepted a responder with no Accept, so it is not building " +
			"a session driver at all")
	}
}
