package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// The tests in this file are ordered by what they are evidence FOR, because the
// distinction has been got wrong in this project before: a unit test of the
// reflector is evidence about an address swap, and only TestServerCarriesRealClients
// is evidence that a client can reach this gateway.

const (
	testClientInner  = "10.64.0.2"
	testClientInner2 = "10.64.0.3"
	testGatewayInner = "10.64.0.1"
	testGatewayID    = "wins-test-gateway"
	testPathMTU      = 1500
)

// --- the reflector ------------------------------------------------------------

// TestReflectorSwapsAddressesAndSourcesFromTheAssignment is the address rule in
// reflect.go stated as a test.
//
// The assertion that matters is the SOURCE. A reflector that mirrored the
// arriving header would put the client's own address in the source of the
// reply, and winn3/tun/ip.go's outbound rule (src MUST be ours) would refuse to
// carry it — silently, as TxDroppedInvalid. The tunnel would look established
// and nothing would ever come back.
func TestReflectorSwapsAddressesAndSourcesFromTheAssignment(t *testing.T) {
	ours := netip.MustParseAddr(testGatewayInner)
	r := newReflector(1423, ours)
	defer r.Close()

	payload := []byte("reflector payload")
	in := testIPv4(t, testClientInner, testGatewayInner, payload)
	n, err := r.WritePacket(in)
	if err != nil {
		t.Fatalf("WritePacket returned %v", err)
	}
	if n != len(in) {
		t.Fatalf("WritePacket reported %d of %d bytes; tun.deliver reads a short "+
			"write as a device failure for a packet the device accepted", n, len(in))
	}

	buf := make([]byte, 65535)
	got, err := r.ReadPacket(buf)
	if err != nil {
		t.Fatalf("ReadPacket returned %v", err)
	}
	reply := buf[:got]

	if src := net.IP(reply[12:16]).String(); src != testGatewayInner {
		t.Fatalf("reply source is %s, want the gateway assignment %s: "+
			"winn3/tun/ip.go refuses an outbound packet whose source is not ours",
			src, testGatewayInner)
	}
	if dst := net.IP(reply[16:20]).String(); dst != testClientInner {
		t.Fatalf("reply destination is %s, want %s", dst, testClientInner)
	}
	if !bytes.Equal(reply[20:], payload) {
		t.Fatalf("reply payload is %q, want %q", reply[20:], payload)
	}
	if sum := verifyChecksum(reply[:20]); sum != 0 {
		t.Fatalf("reply header checksum does not verify: residual %#04x. A stale "+
			"checksum over rewritten addresses is dropped by every real stack", sum)
	}
	if r.Reflected() != 1 {
		t.Fatalf("Reflected is %d, want 1", r.Reflected())
	}
}

// TestReflectorSourcesFromTheAssignmentEvenForForeignDestinations covers the
// case a naive mirror gets wrong: a client addressing something this gateway
// does not own. The reply must STILL be sourced from the assignment, or the
// outbound rule refuses it.
func TestReflectorSourcesFromTheAssignmentEvenForForeignDestinations(t *testing.T) {
	ours := netip.MustParseAddr(testGatewayInner)
	r := newReflector(1423, ours)
	defer r.Close()

	in := testIPv4(t, testClientInner, "8.8.8.8", []byte("to somewhere else"))
	if _, err := r.WritePacket(in); err != nil {
		t.Fatalf("WritePacket returned %v", err)
	}
	buf := make([]byte, 65535)
	n, err := r.ReadPacket(buf)
	if err != nil {
		t.Fatalf("ReadPacket returned %v", err)
	}
	if src := net.IP(buf[12:16]).String(); src != testGatewayInner {
		t.Fatalf("reply source is %s, want %s even though the client addressed 8.8.8.8",
			src, testGatewayInner)
	}
	if dst := net.IP(buf[16:20]).String(); dst != testClientInner {
		t.Fatalf("reply destination is %s, want %s", dst, testClientInner)
	}
	_ = n
}

// TestReflectorIgnoresWhatItCannotAnswer requires the reflector to take the
// bytes and produce nothing, rather than to fail. A device that errors here
// makes tun.deliver count a device write failure for a packet the host accepted.
func TestReflectorIgnoresWhatItCannotAnswer(t *testing.T) {
	r := newReflector(1423, netip.MustParseAddr(testGatewayInner))
	defer r.Close()

	cases := map[string][]byte{
		"short":          {0x45, 0, 0},
		"not IPv4":       append([]byte{0x60}, make([]byte, 39)...),
		"impossible IHL": append([]byte{0x40}, make([]byte, 19)...),
		// Version 6 with a low nibble that WOULD be a legal IPv4 IHL (5 -> 20
		// bytes). Without this case the version check is untested: 0x60 has a
		// low nibble of zero, so the length check refuses it whether the
		// version is examined or not, and a reflector that answered IPv6 as
		// though it were IPv4 would pass.
		"IPv6 with a plausible IHL": append([]byte{0x65}, make([]byte, 39)...),
	}
	for name, pkt := range cases {
		t.Run(name, func(t *testing.T) {
			n, err := r.WritePacket(pkt)
			if err != nil {
				t.Fatalf("WritePacket returned %v; the device accepted the bytes", err)
			}
			if n != len(pkt) {
				t.Fatalf("WritePacket reported %d of %d bytes", n, len(pkt))
			}
		})
	}
	if r.Reflected() != 0 {
		t.Fatalf("Reflected is %d, want 0", r.Reflected())
	}
	if r.Ignored() != uint64(len(cases)) {
		t.Fatalf("Ignored is %d, want %d", r.Ignored(), len(cases))
	}
}

// TestReflectorCloseUnblocksAParkedRead is the tun.Device lifecycle: the HOST
// closes the device and that is what releases the pump.
func TestReflectorCloseUnblocksAParkedRead(t *testing.T) {
	r := newReflector(1423, netip.MustParseAddr(testGatewayInner))
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		_, err := r.ReadPacket(buf)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = r.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a parked ReadPacket returned no error after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock a parked ReadPacket")
	}
}

// --- configuration ------------------------------------------------------------

// TestAdmissionSecretIsOpaqueBytes pins the decision that cost a debugging
// cycle: keygen writes the secret hex-encoded and BOTH ends must use the file's
// bytes, not the decoded value. cmd/winn-datapath (winn3_run.go:372) and
// cmd/winn3-labrig (main.go:384) both do exactly this. Decoding on one end only
// produces a different admission tag and a gateway that is silent, which is
// indistinguishable from a gateway that is not there.
func TestAdmissionSecretIsOpaqueBytes(t *testing.T) {
	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "admission.key"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := buildSessionConfig(serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.TrimRight(raw, "\r\n")
	got := cfg.Core.Gateway.AdmissionKeys[0]
	if !bytes.Equal(got, want) {
		t.Fatalf("admission key is %d bytes %q, want the file's %d bytes %q: "+
			"the secret is opaque and must be byte-identical on both ends",
			len(got), got, len(want), want)
	}
	if len(got) != 64 {
		t.Fatalf("admission key is %d bytes; keygen writes 64 hex characters and "+
			"a 32-byte value here means this end decoded what the other end did not",
			len(got))
	}
}

func TestAdmissionSecretRefusesDecodedOrNoncanonicalKeygenMaterial(t *testing.T) {
	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	admissionPath := filepath.Join(dir, "admission.key")
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"hex decoded to 32 bytes", bytes.Repeat([]byte{0x5a}, 32)},
		{"uppercase hex", bytes.Repeat([]byte("A"), 64)},
		{"non-hex ASCII", bytes.Repeat([]byte("z"), 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(admissionPath, tc.body, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := buildSessionConfig(serveOptions{
				staticPath: filepath.Join(dir, "static.key"),
				admission:  admissionPath,
				gatewayID:  testGatewayID,
			})
			if err == nil || !strings.Contains(err.Error(), "-admission") {
				t.Fatalf("buildSessionConfig error = %v, want named -admission refusal", err)
			}
		})
	}
}

// TestGatewayIDIsRawBytes pins the encoding this binary uses, which is the
// majority convention in the tree and NOT what cdatapath does. See the report:
// cdatapath/winn_datapath_winn3.go:639 base64-decodes the same field.
func TestGatewayIDIsRawBytes(t *testing.T) {
	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	cfg, err := buildSessionConfig(serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(cfg.Core.Gateway.GatewayID); got != testGatewayID {
		t.Fatalf("GatewayID is %q, want the raw operator string %q", got, testGatewayID)
	}
}

// TestBuildSessionConfigRefusesAnEmptyGatewayID: without it a captured
// initiation replays at any gateway sharing the admission key.
func TestBuildSessionConfigRefusesAnEmptyGatewayID(t *testing.T) {
	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	_, err := buildSessionConfig(serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  "   ",
	})
	if err == nil {
		t.Fatal("an empty gateway-id was accepted")
	}
	if !strings.Contains(err.Error(), "gateway-id") {
		t.Fatalf("error does not name the field: %v", err)
	}
}

// TestBuildSessionConfigRefusesANonAbsoluteReplayJournal pins the
// WINN3_REPLAY_JOURNAL wiring: a relative path would be created inside this
// process's working directory, wherever that is at startup, so the binary
// refuses it while still accepting an absolute one.
func TestBuildSessionConfigRefusesANonAbsoluteReplayJournal(t *testing.T) {
	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	opts := serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	}
	for _, rel := range []string{
		"replay.journal",
		"./replay.journal",
		"../replay.journal",
		"state/replay.journal",
	} {
		t.Setenv("WINN3_REPLAY_JOURNAL", rel)
		_, err := buildSessionConfig(opts)
		if err == nil || !strings.Contains(err.Error(), "absolute") {
			t.Fatalf("relative journal %q was not refused as non-absolute: %v", rel, err)
		}
		if !strings.Contains(err.Error(), rel) {
			t.Fatalf("the refusal does not name the offending path %q: %v", rel, err)
		}
	}
	t.Setenv("WINN3_REPLAY_JOURNAL", filepath.Join(dir, "replay.journal"))
	if _, err := buildSessionConfig(opts); err != nil {
		t.Fatalf("an absolute journal path was refused: %v", err)
	}
}

func TestParsePlan(t *testing.T) {
	got, err := parsePlan("udp,tcp,tls")
	if err != nil {
		t.Fatal(err)
	}
	want := []carrier.Class{carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d is %v, want %v", i, got[i], want[i])
		}
	}
	if _, err := parsePlan("udp,quic"); err == nil {
		t.Fatal("an unknown class was accepted")
	}
	if _, err := parsePlan(" , "); err == nil {
		t.Fatal("an empty plan was accepted")
	}
}

func TestParseAssignmentRejectsARouterEqualToTheAddress(t *testing.T) {
	if _, err := parseAssignment("", "", "", ""); err == nil {
		t.Fatal("an empty inner address was accepted")
	}
	if _, err := parseAssignment("not-an-address", "", "", ""); err == nil {
		t.Fatal("a malformed inner address was accepted")
	}
	got, err := parseAssignment(testGatewayInner, testClientInner, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.V4.String() != testGatewayInner || got.RouterV4.String() != testClientInner {
		t.Fatalf("parsed %v / %v", got.V4, got.RouterV4)
	}

	// The case this test is NAMED for, which until 2026-08-09 it did not
	// actually exercise. A name that claims coverage the body does not have is
	// worse than no test: this one sat directly above the defect it purports to
	// cover while a lane lost a debugging cycle to it in the field.
	err = mustRefuse(t,
		"-inner-v4 "+testGatewayInner+" -router-v4 "+testGatewayInner+
			" (the router equals the gateway's own inner address)",
		func() error {
			_, err := parseAssignment(testGatewayInner, testGatewayInner, "", "")
			return err
		})
	// The operator typed two flags and a value. All three must be in the
	// message, or they are back to bisecting a config file against a gateway
	// that answers nothing.
	for _, needle := range []string{"-router-v4", "-inner-v4", testGatewayInner} {
		if !strings.Contains(err.Error(), needle) {
			t.Errorf("the refusal does not name %q, so an operator cannot tell which two "+
				"flags collided or on what value:\n  %v", needle, err)
		}
	}
}

// TestParseAssignmentAcceptsAnInnerIPv6Assignment pins the 2026-08-11 addition
// of -inner-v6 / -router-v6. Before they existed an inner IPv6 packet arriving
// at this gateway failed familyAllowed and was counted as RxDropFamilyOff —
// which is exactly how the first standalone iOS carry showed rx_offered 50 /
// rx_packets 0 / rx_dropped_invalid 50 once the full-tunnel route set routed
// IPv6 into a tunnel whose far end had no IPv6 assignment.
func TestParseAssignmentAcceptsAnInnerIPv6Assignment(t *testing.T) {
	got, err := parseAssignment("", "", "2001:db8::1", "2001:db8::2")
	if err != nil {
		t.Fatal(err)
	}
	if got.V4.IsValid() {
		t.Fatalf("no -inner-v4 was given but V4 parsed as %v", got.V4)
	}
	if !got.V6.IsValid() || got.V6.String() != "2001:db8::1" {
		t.Fatalf("inner IPv6 parsed as %v, want 2001:db8::1", got.V6)
	}
	if !got.RouterV6.IsValid() || got.RouterV6.String() != "2001:db8::2" {
		t.Fatalf("router IPv6 parsed as %v, want 2001:db8::2", got.RouterV6)
	}

	// Both families together, as the iOS fix uses: inner-v4 plus inner-v6.
	got2, err := parseAssignment("10.64.0.1", "10.64.0.2", "2001:db8::1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !got2.V4.IsValid() || !got2.V6.IsValid() {
		t.Fatalf("expected both families assigned, got V4=%v V6=%v", got2.V4, got2.V6)
	}

	// A router equal to the assigned address must be refused, mirroring the
	// IPv4 rule — otherwise the preflight would catch it later, out of the
	// operator's hands.
	mustRefuse(t,
		"-inner-v6 2001:db8::1 -router-v6 2001:db8::1 (the router equals the gateway's own inner IPv6 address)",
		func() error {
			_, err := parseAssignment("", "", "2001:db8::1", "2001:db8::1")
			return err
		})
}

// `what` is the configuration in the operator's own vocabulary — the flags and
// the values — and it is not decoration. When a startup check is removed, this
// is the line that goes red, and a red line reading only "the configuration was
// accepted" sends the next reader back to the source to find out which
// configuration. Naming the flags here is what makes the failure diagnostic on
// its own.
func mustRefuse(t *testing.T, what string, fn func() error) error {
	t.Helper()
	err := fn()
	if err == nil {
		t.Fatalf("ACCEPTED a configuration that cannot carry traffic: %s.\n"+
			"It must be refused at STARTUP. Accepted, this gateway binds its socket, "+
			"prints \"listening\", and then answers every handshake with silence — no "+
			"log line, no counter, no error, on either end. That is silent-refusal "+
			"instance #8, and under this threat model it is indistinguishable from a "+
			"censor.", what)
	}
	return err
}

// orUnset renders an omitted flag as the word an operator would use, so a
// failure message never reads `-router-v4 ""`.
func orUnset(v string) string {
	if strings.TrimSpace(v) == "" {
		return "(unset)"
	}
	return v
}

// --- silent-refusal instance #8, and the family it belongs to -------------------

// TestAGatewayThatCannotCarryTrafficRefusesToStart is the regression for silent
// refusal #8.
//
// The field symptom: a gateway started with -router-v4 equal to -inner-v4 bound
// its socket, printed "listening", and then refused every handshake while
// logging NOTHING on either end. Measured on 2026-08-09 with the real binaries
// over real UDP: the gateway's own status document showed datagrams=5 with
// admitted=0, sessions_built=0, stranger_datagrams=0 and refused_datagrams=0 —
// every counter that could have named a problem read zero — while the client
// reported only "handshake attempts exhausted on this carrier". Under this
// threat model that is indistinguishable from a censor, which is why this class
// of defect is tracked separately from ordinary configuration bugs.
//
// The mechanism was NOT silence in the routing path. tun.New rejects the
// collision correctly (tun.go:169); the rejection was simply deferred to first
// datagram, where readLoop discarded it. So the test is: runServe must REFUSE,
// before it binds anything.
//
// The table is the whole family, not just the pair that prompted it, because
// "an operator-supplied configuration that is accepted and then produces
// silence" is the class and the pair is one member. Every row below was
// confirmed silent against the pre-fix binary.
func TestAGatewayThatCannotCarryTrafficRefusesToStart(t *testing.T) {
	base := func(t *testing.T) serveOptions {
		t.Helper()
		dir := t.TempDir()
		if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
			t.Fatal(err)
		}
		t.Setenv("WINN3_GATEWAY_REPLAY_JOURNAL", "1")
		t.Setenv("WINN3_REPLAY_JOURNAL", writeEmptyReplayJournal(t, dir))
		return serveOptions{
			listen:      "127.0.0.1:0",
			staticPath:  filepath.Join(dir, "static.key"),
			admission:   filepath.Join(dir, "admission.key"),
			gatewayID:   testGatewayID,
			innerV4:     testGatewayInner,
			plan:        "udp",
			pathMTU:     testPathMTU,
			maxSessions: 8,
			runFor:      time.Second,
		}
	}

	// wants is a substring the refusal must contain, so that the message is
	// actionable and not merely non-empty.
	for _, tc := range []struct {
		name   string
		mutate func(*serveOptions)
		wants  []string
	}{
		{
			name:   "the router equals the inner address",
			mutate: func(o *serveOptions) { o.routerV4 = testGatewayInner },
			wants:  []string{"-router-v4", "-inner-v4", testGatewayInner},
		},
		{
			name:   "the router is a loopback address",
			mutate: func(o *serveOptions) { o.routerV4 = "127.0.0.1" },
			wants:  []string{"-router-v4"},
		},
		{
			name:   "the router is multicast",
			mutate: func(o *serveOptions) { o.routerV4 = "224.0.0.1" },
			wants:  []string{"-router-v4"},
		},
		{
			// -router-v4 names the family in the flag itself, and netip parses
			// a v6 literal happily, so this reaches tun as an assignment whose
			// v4 router is not a 4-byte address.
			name:   "the router is an IPv6 literal",
			mutate: func(o *serveOptions) { o.routerV4 = "fd00::1" },
			wants:  []string{"-router-v4"},
		},
		{
			name:   "the inner address is loopback",
			mutate: func(o *serveOptions) { o.innerV4 = "127.0.0.1" },
			wants:  []string{"-inner-v4"},
		},
		{
			name:   "the inner address is unspecified",
			mutate: func(o *serveOptions) { o.innerV4 = "0.0.0.0" },
			wants:  []string{"-inner-v4"},
		},
		{
			name:   "the inner address is multicast",
			mutate: func(o *serveOptions) { o.innerV4 = "224.0.0.1" },
			wants:  []string{"-inner-v4"},
		},
		{
			name:   "the inner address is link-local",
			mutate: func(o *serveOptions) { o.innerV4 = "169.254.1.1" },
			wants:  []string{"-inner-v4"},
		},
		{
			name:   "the inner address is an IPv6 literal",
			mutate: func(o *serveOptions) { o.innerV4 = "fd00::1" },
			wants:  []string{"-inner-v4"},
		},
		{
			name:   "the inner address is IPv4-mapped IPv6",
			mutate: func(o *serveOptions) { o.innerV4 = "::ffff:10.64.0.1" },
			wants:  []string{"-inner-v4"},
		},
		{
			// sessionFor's ceiling test is `len(peers) >= maxSessions`, so zero
			// is reached before the first client arrives.
			name:   "the session ceiling is zero",
			mutate: func(o *serveOptions) { o.maxSessions = 0 },
			wants:  []string{"-max-sessions"},
		},
		{
			name:   "the session ceiling is negative",
			mutate: func(o *serveOptions) { o.maxSessions = -1 },
			wants:  []string{"-max-sessions"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := base(t)
			tc.mutate(&opts)
			err := mustRefuse(t,
				fmt.Sprintf("-inner-v4 %s -router-v4 %s -max-sessions %d -path-mtu %d "+
					"-plan %s (%s)",
					opts.innerV4, orUnset(opts.routerV4), opts.maxSessions,
					opts.pathMTU, opts.plan, tc.name),
				func() error { return runServe(opts, new(bytes.Buffer)) })
			for _, needle := range tc.wants {
				if !strings.Contains(err.Error(), needle) {
					t.Errorf("the refusal does not name %q; an operator reading it cannot "+
						"tell which flag to change:\n  %v", needle, err)
				}
			}
		})
	}
}

// TestAValidConfigurationIsNotRefused is the over-fire control, and it is not
// optional.
//
// A startup check that refuses a working gateway is a WORSE outage than the one
// being fixed: the silent gateway fails for whoever misconfigured it, and an
// over-eager validator fails for everyone. Every row here must start, serve, and
// stop cleanly.
func TestAValidConfigurationIsNotRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*serveOptions)
	}{
		{"the router is omitted entirely", func(o *serveOptions) { o.routerV4 = "" }},
		{"the router is the client's address", func(o *serveOptions) { o.routerV4 = testClientInner }},
		{"the router is whitespace, meaning unset", func(o *serveOptions) { o.routerV4 = "   " }},
		{"a wider migration plan", func(o *serveOptions) { o.plan = "udp,tcp,tls" }},
		{"a ceiling of exactly one", func(o *serveOptions) { o.maxSessions = 1 }},
		{"the default path MTU", func(o *serveOptions) { o.pathMTU = carrier.DefaultPathMTU }},
		{"a different inner subnet", func(o *serveOptions) {
			o.innerV4, o.routerV4 = "172.16.9.9", "172.16.9.1"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := operatorValueOptions(t)
			tc.mutate(&opts)
			if err := runServe(opts, new(bytes.Buffer)); err != nil {
				t.Fatalf("a legitimate configuration was refused, which is a worse outage "+
					"than the silence this check exists to prevent: %v", err)
			}
		})
	}
}

// TestTheStatusDocumentNamesASessionThatCouldNotBeBuilt covers what preflight
// cannot: a fault that only appears once traffic is flowing.
//
// The ceiling is the live example. Before this counter existed, a gateway
// refusing every client at its ceiling and a gateway nobody was reaching
// produced the same status document, and the difference is the whole diagnosis.
func TestTheStatusDocumentNamesASessionThatCouldNotBeBuilt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// Two real clients, a ceiling of one: the second can never be built while
	// the first is live. Real clients, because since the admission screen a
	// datagram that fails the admission tag never reaches the ceiling at all,
	// and a live session is never reclaimed to make room.
	r := newReclaimRig(t, 1, nil)
	srv := r.srv
	r.serve(t, ctx)
	first := startTestClient(t, ctx, r.opts)
	waitFor(t, 20*time.Second, "the first client to carry", func() bool { return carrying(first) })
	_ = startTestClient(t, ctx, r.opts)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if srv.status().BuildFailures > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	st := srv.status()
	t.Fatalf("the second peer was refused and session_build_failures is still %d; the "+
		"status document cannot distinguish a gateway refusing everyone from a gateway "+
		"nobody is reaching (sessions=%d admitted=%d datagrams=%d)",
		st.BuildFailures, st.Sessions, st.Admitted, st.Datagrams)
}

// --- the thing this binary exists for -----------------------------------------

// TestServerCarriesRealClients is the ONLY test here that is evidence a client
// can reach this gateway.
//
// It binds a real datagram socket, dials it from real client carriers in the
// same process, and requires of EACH client: a completed handshake, an inner
// packet delivered to the gateway, that packet reflected back, and the
// promotion predicate satisfied — Gate.State() == StateCarrying AND
// Stats().RxPackets > 0, the same conjunction winn3PromotionReady applies.
//
// Two clients, not one, because a gateway that serves exactly one client is a
// rig and this is the difference between this binary and cmd/winn3-labrig.
func TestServerCarriesRealClients(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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
		conn:        conn,
		sizing:      sizing,
		sessionCfg:  sessionCfg,
		assign:      assign,
		maxSessions: 8,
		peers:       make(map[netip.AddrPort]*peerSession),
	}
	readDone := make(chan error, 1)
	go func() { readDone <- srv.readLoop(ctx) }()
	defer func() {
		_ = conn.SetReadDeadline(time.Now())
		<-readDone
		srv.closeAll()
	}()

	gwAddr := conn.LocalAddr().(*net.UDPAddr)
	gatewayPublic := readTestKey(t, filepath.Join(dir, "static.pub"))
	admission := readTestSecret(t, filepath.Join(dir, "admission.key"))

	clients := []struct {
		name  string
		inner string
	}{
		{"first", testClientInner},
		{"second", testClientInner2},
	}
	// startTestClient registers Cleanup on its *testing.T. Calling it from
	// the parent — not from inside t.Run — keeps both clients alive until
	// after the census. Nested t.Run cleanup used to Close the first client
	// before the second was counted, so Sessions dropped to 1 even though
	// both subtests had just promoted. That mismatch is independent of cover
	// (reproduced with main.go.bak_20260812_v3_cover_listener_impl and cover
	// sources stubbed). The census claim is simultaneous occupancy.
	type running struct {
		name, inner string
		cli         *testClient
	}
	var live []running
	for _, c := range clients {
		cli := startTestClient(t, ctx, testClientOpts{
			dir: dir, gwAddr: gwAddr, gatewayPublic: gatewayPublic,
			admission: admission, sizing: sizing, inner: c.inner,
		})
		live = append(live, running{name: c.name, inner: c.inner, cli: cli})
	}
	for _, c := range live {
		c := c
		t.Run(c.name, func(t *testing.T) {
			cli := c.cli

			waitFor(t, 40*time.Second, "the client gate to carry", func() bool {
				return cli.loop.Tunnel().Gate().State() == tun.StateCarrying
			})

			payload := []byte("winn3 gateway round trip " + c.name)
			cli.dev.offer(t, testIPv4(t, c.inner, testGatewayInner, payload))

			back := cli.dev.take(t, 40*time.Second)
			if src := net.IP(back[12:16]).String(); src != testGatewayInner {
				t.Fatalf("reflected packet source is %s, want %s", src, testGatewayInner)
			}
			if dst := net.IP(back[16:20]).String(); dst != c.inner {
				t.Fatalf("reflected packet destination is %s, want %s", dst, c.inner)
			}
			if !bytes.Equal(back[20:], payload) {
				t.Fatalf("reflected payload is %q, want %q", back[20:], payload)
			}

			waitFor(t, 20*time.Second, "the promotion predicate to fire", func() bool {
				return cli.loop.Tunnel().Gate().State() == tun.StateCarrying &&
					cli.loop.Tunnel().Stats().RxPackets > 0
			})
			st := cli.loop.Tunnel().Stats()
			if st.RxPackets == 0 {
				t.Fatal("RxPackets is zero with a carrying gate: the gate opened over " +
					"an empty tunnel, which is the state this predicate exists to catch")
			}
			if st.RxDroppedInvalid != 0 {
				t.Fatalf("the client rejected %d inbound packets as invalid", st.RxDroppedInvalid)
			}
			if st.TxDroppedInvalid != 0 {
				t.Fatalf("the client refused to carry %d outbound packets", st.TxDroppedInvalid)
			}
		})
	}

	if got := srv.status().Sessions; got != len(clients) {
		t.Fatalf("the gateway holds %d sessions, want %d: one socket must carry many", got, len(clients))
	}
	if got := srv.status().Promoted; got != len(clients) {
		t.Fatalf("%d gateway-side sessions satisfy the promotion predicate, want %d",
			got, len(clients))
	}
	// One session per PEER, constructed once. A demultiplexer that fails to
	// reuse a peer's session still shows a correct census — it builds a fresh
	// session per datagram and discards all but one — so the census cannot
	// detect the fault and this counter is what does.
	if got := srv.status().Built; got != uint64(len(clients)) {
		t.Fatalf("the gateway constructed %d sessions for %d peers: a peer's "+
			"session is being rebuilt per datagram rather than reused",
			got, len(clients))
	}
}

// TestCloseAllDeliversCloseNormalToTheClient is the production SIGTERM path.
//
// server.serve on ctx.Done joins readLoop then calls closeAll. closeAll is
// peerSession.close. Loop.Close documents that Run returns once CLOSE has
// been handed to the carrier; TestCancellingRunLatchesTheGateDown documents
// that cancelling Run's ctx first does NOT emit CLOSE and leaves the session
// Established. The client probe budget is DefaultMaxLostProbes ×
// DefaultProbeMax (4 × 20s). A teardown that only latches the local gate
// therefore looks like a censor for up to eighty seconds.
//
// This test calls closeAll the way serve does and requires the client to
// observe CloseNormal well inside that budget. A cancel-then-Close close()
// leaves the client Established and this wait times out. The 15s ceiling is
// the teeth: it cannot be satisfied by the probe-timeout path.
func TestCloseAllDeliversCloseNormalToTheClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
		conn:        conn,
		sizing:      sizing,
		sessionCfg:  sessionCfg,
		assign:      assign,
		maxSessions: 8,
		peers:       make(map[netip.AddrPort]*peerSession),
	}
	readDone := make(chan error, 1)
	go func() { readDone <- srv.readLoop(ctx) }()
	var joinReader sync.Once
	joinReaderFn := func() {
		joinReader.Do(func() {
			_ = conn.SetReadDeadline(time.Now())
			select {
			case <-readDone:
			case <-time.After(5 * time.Second):
			}
		})
	}
	defer joinReaderFn()

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
	payload := []byte("winn3 gateway close-all round trip")
	cli.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, payload))
	_ = cli.dev.take(t, 40*time.Second)

	srv.mu.Lock()
	if len(srv.peers) != 1 {
		n := len(srv.peers)
		srv.mu.Unlock()
		t.Fatalf("gateway holds %d sessions before closeAll, want 1", n)
	}
	var gwLoop *driver.Loop
	for _, ps := range srv.peers {
		gwLoop = ps.loop
	}
	srv.mu.Unlock()
	if gwLoop == nil {
		t.Fatal("no gateway loop to observe after closeAll")
	}

	// Production order in server.serve: stop the socket reader, then closeAll.
	joinReaderFn()

	started := time.Now()
	srv.closeAll()

	waitFor(t, 15*time.Second, "the client to observe CloseNormal from closeAll (not the 80s probe budget)", func() bool {
		return cli.loop.Session().PeerCloseReason() == session.CloseNormal
	})
	elapsed := time.Since(started)
	if elapsed >= 20*time.Second {
		t.Fatalf("client saw CloseNormal after %s; that is inside the probe budget, not a CLOSE frame", elapsed)
	}
	if got := cli.loop.Session().State(); !got.Terminal() {
		t.Fatalf("client session is %s after observing CloseNormal, want terminal", got)
	}
	if got := gwLoop.Session().LocalCloseReason(); got != session.CloseNormal {
		t.Fatalf("gateway LocalCloseReason is %s, want CloseNormal", got)
	}
	if got := gwLoop.Session().State(); !got.Terminal() {
		t.Fatalf("gateway session is %s after closeAll, want terminal (CLOSE Polled, not left in StateClosing)", got)
	}
}

// TestServerRefusesBeyondTheSessionCeilingInSilence: a full gateway emits
// nothing, exactly as winn3/gateway's refusal paths do. A refused client must
// see what a probe sees.
func TestServerRefusesBeyondTheSessionCeilingInSilence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A FULLY configured server, deliberately. Against a half-built one every
	// session fails for its own reasons and the test passes whatever the
	// ceiling does — which is exactly what an off-by-one in the comparison
	// would exploit.
	srv, _ := newTestServer(t, 1)

	if _, err := srv.sessionFor(ctx, netip.MustParseAddrPort("127.0.0.1:1")); err != nil {
		t.Fatalf("the first session, which is within the ceiling, was refused: %v", err)
	}
	if got := len(srv.peers); got != 1 {
		t.Fatalf("the table holds %d sessions after one admission, want 1", got)
	}
	if _, err := srv.sessionFor(ctx, netip.MustParseAddrPort("127.0.0.1:2")); err == nil {
		t.Fatal("a session past the ceiling was admitted")
	}
	if got := len(srv.peers); got != 1 {
		t.Fatalf("the table holds %d sessions, want 1", got)
	}
	srv.closeAll()
}

// TestAFinishedSessionFreesItsCeilingSlot is the eviction half of
// -max-sessions: a session whose Loop.Run has returned must not keep its
// demux slot. Without releasePeer the ceiling fills with corpses and every
// later client is refused in silence — the same threat-model failure as a
// block.
func TestAFinishedSessionFreesItsCeilingSlot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, _ := newTestServer(t, 1)
	t.Cleanup(func() { srv.closeAll() })

	first := netip.MustParseAddrPort("127.0.0.1:1")
	second := netip.MustParseAddrPort("127.0.0.1:2")
	ps, err := srv.sessionFor(ctx, first)
	if err != nil {
		t.Fatalf("the first session, which is within the ceiling, was refused: %v", err)
	}
	if _, err := srv.sessionFor(ctx, second); err == nil {
		t.Fatal("a second peer was admitted while the first still occupied the only slot")
	}

	ps.stop()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		n := len(srv.peers)
		srv.mu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv.mu.Lock()
	n := len(srv.peers)
	srv.mu.Unlock()
	if n != 0 {
		t.Fatalf("after Loop.Run returned the demux still holds %d sessions; a dead session is occupying the ceiling", n)
	}

	if _, err := srv.sessionFor(ctx, second); err != nil {
		t.Fatalf("a new peer was refused after the occupying session finished: %v", err)
	}
}

// TestSessionCeilingDoesNotTouchTheForwardTable: refusing a peer at the
// ceiling must not learn, forget, or collide. The forwarding table is not
// the session ceiling and a refused datagram never reaches WritePacket.
func TestSessionCeilingDoesNotTouchTheForwardTable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, _ := newTestServer(t, 1)
	t.Cleanup(func() { srv.closeAll() })

	tbl := newForwardTable()
	held := fakeLoop()
	inner := mustAddr(t, "10.64.0.2")
	tbl.learn(inner, held)
	srv.table = tbl

	if _, err := srv.sessionFor(ctx, netip.MustParseAddrPort("127.0.0.1:1")); err != nil {
		t.Fatalf("the first session was refused: %v", err)
	}
	if _, err := srv.sessionFor(ctx, netip.MustParseAddrPort("127.0.0.1:2")); err == nil {
		t.Fatal("a session past the ceiling was admitted")
	}

	got, ok := tbl.lookup(inner)
	if !ok || got != held {
		t.Fatalf("the ceiling refuse mutated the forwarding table: got=%v ok=%v", got, ok)
	}
	if stats := tbl.Stats(); stats.Size != 1 || stats.Learned != 1 || stats.Forgotten != 0 || stats.Collisions != 0 {
		t.Fatalf("ceiling refuse mutated table stats: %+v", stats)
	}
}

// TestReleasePeerDoesNotEvictANewerSessionAtTheSameAddrPort is forget's
// pointer guard at the demux layer: an old Run returning late must not
// delete a mapping a reconnect already installed for the same UDP address.
func TestReleasePeerDoesNotEvictANewerSessionAtTheSameAddrPort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, _ := newTestServer(t, 2)
	t.Cleanup(func() { srv.closeAll() })

	from := netip.MustParseAddrPort("127.0.0.1:9")
	old, err := srv.sessionFor(ctx, from)
	if err != nil {
		t.Fatalf("old session: %v", err)
	}

	// A reconnect from the SAME AddrPort reuses old (sessionFor's first
	// branch). To install a newer occupant we have to put it in the map
	// ourselves — the race releasePeer exists to lose correctly.
	newer, err := srv.newSession(ctx, from)
	if err != nil {
		t.Fatalf("newer session: %v", err)
	}
	srv.mu.Lock()
	srv.peers[from] = newer
	srv.mu.Unlock()

	srv.releasePeer(from, old)

	srv.mu.Lock()
	got := srv.peers[from]
	srv.mu.Unlock()
	if got != newer {
		t.Fatal("old session's releasePeer evicted the newer occupant of the same AddrPort")
	}
	// old is no longer in the map, so closeAll will not see it. Stop it
	// here or its Run goroutine outlives the test.
	old.close()
}

// newTestServer builds a server with real key material, real sizing and a real
// socket. maxSessions is the only knob a caller varies.
func newTestServer(t *testing.T, maxSessions int) (*server, *net.UDPAddr) {
	t.Helper()
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
	t.Cleanup(func() { _ = conn.Close() })
	return &server{
		conn:        conn,
		sizing:      sizing,
		sessionCfg:  sessionCfg,
		assign:      assign,
		maxSessions: maxSessions,
		peers:       make(map[netip.AddrPort]*peerSession),
	}, conn.LocalAddr().(*net.UDPAddr)
}

// TestAStrangerCannotBuyStateWithJunk is the length pre-filter.
//
// Address demultiplexing makes the FIRST datagram from an address allocate a
// session, a pipe, a device and two goroutines. A datagram that could not be an
// initiation must therefore be refused BEFORE any of that, or one junk byte per
// spoofed source address fills the session table. This is a mitigation and not
// the fix — see the package doc — but an unmitigated version of it is a trivial
// remote resource exhaustion.
func TestAStrangerCannotBuyStateWithJunk(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, gwAddr := newTestServer(t, 8)
	readDone := make(chan error, 1)
	go func() { readDone <- srv.readLoop(ctx) }()
	defer func() {
		_ = srv.conn.SetReadDeadline(time.Now())
		<-readDone
		srv.closeAll()
	}()

	junk := make([]byte, core.MaxHandshakeMessage+1)
	peer, err := net.DialUDP("udp4", nil, gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if _, err := peer.Write(junk); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 10*time.Second, "the gateway to see the datagram", func() bool {
		return srv.status().Datagrams > 0
	})
	// Give any erroneous session construction time to happen before asserting
	// that it did not.
	time.Sleep(300 * time.Millisecond)

	st := srv.status()
	if st.Strangers == 0 {
		t.Fatal("the oversize datagram was not counted as a stranger")
	}
	if st.Sessions != 0 {
		t.Fatalf("a datagram too large to be an initiation bought %d sessions", st.Sessions)
	}
	if st.Built != 0 {
		t.Fatalf("a datagram too large to be an initiation constructed %d sessions", st.Built)
	}
}

func TestCouldBeInitiation(t *testing.T) {
	if couldBeInitiation(0) {
		t.Fatal("a zero-length datagram was treated as a possible initiation")
	}
	if !couldBeInitiation(1) {
		t.Fatal("a one-byte datagram was refused on length")
	}
	if !couldBeInitiation(core.MaxHandshakeMessage) {
		t.Fatalf("a %d-byte datagram was refused; that is exactly the ceiling",
			core.MaxHandshakeMessage)
	}
	if couldBeInitiation(core.MaxHandshakeMessage + 1) {
		t.Fatal("a datagram past the handshake ceiling was accepted on length")
	}
}

// --- harness ------------------------------------------------------------------

type testClientOpts struct {
	dir           string
	gwAddr        *net.UDPAddr
	gatewayPublic []byte
	admission     []byte
	sizing        driver.Sizing
	inner         string
}

type testClient struct {
	loop *driver.Loop
	dev  *testDevice
	car  *carrier.UDP
}

func startTestClient(t *testing.T, ctx context.Context, o testClientOpts) *testClient {
	t.Helper()
	staticBytes, err := readKeyFile(filepath.Join(o.dir, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	staticKey, err := core.NewStaticKey(staticBytes)
	if err != nil {
		t.Fatal(err)
	}
	gatewayStatic, err := core.NewPublicKey(o.gatewayPublic)
	if err != nil {
		t.Fatal(err)
	}
	car, err := carrier.DialUDP(ctx, carrier.UDPConfig{
		Remote:         o.gwAddr,
		MaxMessageSize: o.sizing.MessageSize,
		PathMTU:        o.sizing.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	dev := newTestDevice(o.sizing.InnerMTU)
	tunCfg := tun.Config{
		Assign: tun.Assignment{V4: netip.MustParseAddr(o.inner)},
		Device: dev,
		Clock:  driver.SessionClock{Clock: driver.SystemClock{}},
	}
	loop, err := driver.NewClient(driver.Config{
		Session: session.Config{
			Core: core.Config{
				Gateway: core.GatewayParams{
					AdmissionKeys: [][]byte{o.admission},
					GatewayID:     []byte(testGatewayID),
				},
			},
			Static:        staticKey,
			GatewayStatic: gatewayStatic,
			Padding:       core.PadBucket,
		},
		Sizing:  o.sizing,
		Carrier: car,
		Tun:     &tunCfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = loop.Run(runCtx) }()
	t.Cleanup(func() {
		cancel()
		_ = loop.Close()
		_ = dev.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	return &testClient{loop: loop, dev: dev, car: car}
}

// testDevice stands in for the platform tun interface on the CLIENT side.
type testDevice struct {
	mtu       int
	in        chan []byte
	out       chan []byte
	closeOnce sync.Once
	closed    chan struct{}
}

func newTestDevice(mtu int) *testDevice {
	return &testDevice{
		mtu:    mtu,
		in:     make(chan []byte, 32),
		out:    make(chan []byte, 32),
		closed: make(chan struct{}),
	}
}

func (d *testDevice) ReadPacket(buf []byte) (int, error) {
	select {
	case p := <-d.in:
		return copy(buf, p), nil
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

func (d *testDevice) WritePacket(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	select {
	case d.out <- cp:
		return len(p), nil
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

func (d *testDevice) MTU() int { return d.mtu }

func (d *testDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

func (d *testDevice) offer(t *testing.T, pkt []byte) {
	t.Helper()
	select {
	case d.in <- pkt:
	case <-time.After(10 * time.Second):
		t.Fatal("the device would not accept an outbound packet")
	}
}

func (d *testDevice) take(t *testing.T, within time.Duration) []byte {
	t.Helper()
	select {
	case p := <-d.out:
		return p
	case <-time.After(within):
		t.Fatal("no packet was delivered to the device")
		return nil
	}
}

func waitFor(t *testing.T, budget time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func readTestKey(t *testing.T, path string) []byte {
	t.Helper()
	b, err := readKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readTestSecret(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimRight(raw, "\r\n")
}

func testIPv4(t *testing.T, src, dst string, payload []byte) []byte {
	t.Helper()
	total := 20 + len(payload)
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	binary.BigEndian.PutUint16(b[4:6], 0x1234)
	b[8] = 64
	b[9] = 17
	copy(b[12:16], net.ParseIP(src).To4())
	copy(b[16:20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(b[10:12], ipv4Checksum(b[:20]))
	copy(b[20:], payload)
	return b
}

// verifyChecksum returns zero if and only if a complete header verifies.
func verifyChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
