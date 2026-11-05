package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
)

// Silent-refusal sweep, 2026-08-09: two instances of the same shape in this
// binary's v3 desktop mode.
//
// The shape: a value IS validated somewhere real, but later than the operator
// is standing there, and the rejection meets a path whose job is silence.
//
//  1. -winn3-print-sizing is the documented pre-start hook and it returned the
//     plan floor without ever constructing a session, so the inner assignment —
//     checked ONLY by tun.New, several constructors further in — was never
//     looked at. A host asked "can I start this?", was told a number, set its
//     interface MTU to it, and then started an engine that refused the same
//     profile with one line on a stderr the Windows supervisor drains and
//     discards.
//  2. -transport and -control reached no code at all in this mode: run()
//     returns into runWinn3 before the transport switch, and
//     winn3RefuseMixedModes did not name them. Not honoured, not refused, no
//     message.
//
// Nothing here changes what a PEER can observe. The loudness is toward the
// operator, at startup, before the socket exists.

// realKeyProfile is validProfile() with key paths that actually exist, because
// the preflight reads them and the shared fixture points at /nonexistent.
func realKeyProfile(t *testing.T) map[string]any {
	t.Helper()
	dir := t.TempDir()

	ours, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, body []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	document := validProfile()
	document["keys"] = map[string]any{
		"static_path":         write("static.key", ours.Bytes()),
		"gateway_static_path": write("gateway.pub", theirs.Public()),
		"admission_path":      write("admission.key", []byte(strings.Repeat("a", 64))),
	}
	return document
}

// preflightOf runs exactly what the -winn3-print-sizing branch runs.
func preflightOf(t *testing.T, document map[string]any) error {
	t.Helper()
	profile, err := loadWinn3Profile(writeProfile(t, document))
	if err != nil {
		return err
	}
	classes, err := profile.classes()
	if err != nil {
		return err
	}
	pathMTU := profile.PathMTU
	if pathMTU == 0 {
		pathMTU = carrier.DefaultPathMTU
	}
	sizing, err := driver.NewSizing(pathMTU, classes...)
	if err != nil {
		return err
	}
	return winn3PreflightSession(profile, sizing)
}

// TestPrintSizingRefusesAProfileTheRealStartWouldRefuse.
//
// Every case here used to pass the pre-start hook and produce a plan floor,
// which the Windows supervisor's STEP 3 reads as permission to create the
// Wintun adapter — after which the real engine died on a stderr line that
// supervisor throws away, and the operator was told the datapath "stopped
// before it carried anything". That sentence describes a peer; the cause was a
// typo in a profile.
func TestPrintSizingRefusesAProfileTheRealStartWouldRefuse(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		expect string
	}{
		{
			// Silent-refusal instance #8, in this binary. Refused by
			// winn3/tun/tun.go:169 and by nothing in winn3_profile.go.
			name: "router equal to the assigned address",
			mutate: func(d map[string]any) {
				d["inner"] = map[string]any{"v4": "10.64.0.2", "router_v4": "10.64.0.2"}
			},
			expect: "router address equals the assigned address",
		},
		{
			name: "the assignment carries no address at all",
			mutate: func(d map[string]any) {
				d["inner"] = map[string]any{}
			},
			expect: "neither an IPv4 nor an IPv6 address",
		},
		{
			name: "a loopback inner address",
			mutate: func(d map[string]any) {
				d["inner"] = map[string]any{"v4": "127.0.0.1", "router_v4": "10.64.0.1"}
			},
			expect: "unusable",
		},
		{
			name: "an unspecified inner address",
			mutate: func(d map[string]any) {
				d["inner"] = map[string]any{"v4": "0.0.0.0", "router_v4": "10.64.0.1"}
			},
			expect: "unusable",
		},
		{
			name: "a multicast router address",
			mutate: func(d map[string]any) {
				d["inner"] = map[string]any{"v4": "10.64.0.2", "router_v4": "224.0.0.9"}
			},
			expect: "router address is unusable",
		},
		{
			// assignmentAddrs tests want4 != addr.Is4(), and Is4() is false for
			// a 4-in-6 literal, so this lands in the V6 slot and is refused
			// only by Assignment.validate — after the dial, before this change.
			name: "an IPv4-mapped literal in inner.v6",
			mutate: func(d map[string]any) {
				d["inner"] = map[string]any{
					"v4": "10.64.0.2", "router_v4": "10.64.0.1", "v6": "::ffff:10.64.0.9"}
			},
			expect: "not a native 16-byte address",
		},
		{
			// Kept in the table although the profile LOADER catches this one
			// before the preflight runs, because the table's claim is "refused
			// with nothing created", not "refused by the preflight". Measured,
			// not assumed: the first draft expected core's wording
			// ("gateway id is empty", winn3/core/params.go:350) and got the
			// loader's instead.
			name:   "an empty gateway id, which the loader already refuses",
			mutate: func(d map[string]any) { d["gateway_id"] = "  " },
			expect: "gateway_id is empty",
		},
		{
			// The profile loader does NOT check that key paths exist —
			// validProfile() points at /nonexistent and loads fine. Only
			// winn3BuildSession opens them, and before this change that
			// happened after the dial. Added because mutation D04 (make
			// winn3BuildSession's error a nil return) SURVIVED the first table:
			// every other case reached the failure through the constructors
			// instead, so nothing proved the key files were read at all.
			name: "a key file that does not exist",
			mutate: func(d map[string]any) {
				keys, _ := d["keys"].(map[string]any)
				keys["static_path"] = filepath.Join(t.TempDir(), "absent.key")
			},
			expect: "static_path",
		},
		{
			name: "an admission file that does not exist",
			mutate: func(d map[string]any) {
				keys, _ := d["keys"].(map[string]any)
				keys["admission_path"] = filepath.Join(t.TempDir(), "absent.key")
			},
			expect: "admission_path",
		},
		{
			name: "a static key of the wrong length",
			mutate: func(d map[string]any) {
				keys, _ := d["keys"].(map[string]any)
				path := filepath.Join(t.TempDir(), "short.key")
				if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
					t.Fatal(err)
				}
				keys["static_path"] = path
			},
			expect: "static_path",
		},
		{
			name: "an admission secret below the 32-byte floor",
			mutate: func(d map[string]any) {
				keys, _ := d["keys"].(map[string]any)
				path := filepath.Join(t.TempDir(), "short.key")
				if err := os.WriteFile(path, []byte("tooshort"), 0o600); err != nil {
					t.Fatal(err)
				}
				keys["admission_path"] = path
			},
			expect: "admission key",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document := realKeyProfile(t)
			tc.mutate(document)
			err := preflightOf(t, document)
			if err == nil {
				t.Fatal("the pre-start hook approved a profile that can never carry " +
					"traffic; a host would now configure an interface to the plan " +
					"floor it printed")
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Fatalf("refused, but not for the stated reason.\n got: %v\nwant substring: %q",
					err, tc.expect)
			}
		})
	}
}

// TestPrintSizingStillApprovesEveryProfileThatCanCarryTraffic is the over-fire
// control.
//
// A pre-start hook that refuses everything is strictly worse than one that
// checks nothing: the host stops starting at all and cannot tell a real refusal
// from a broken probe. Each case is a profile that genuinely works.
func TestPrintSizingStillApprovesEveryProfileThatCanCarryTraffic(t *testing.T) {
	cases := []struct {
		name   string
		adjust func(map[string]any)
	}{
		{"the reference profile", func(map[string]any) {}},
		{"no router address, which is optional", func(d map[string]any) {
			d["inner"] = map[string]any{"v4": "10.64.0.2"}
		}},
		{"a gateway role rather than a client", func(d map[string]any) {
			d["role"] = winn3RoleGateway
			// keys.gateway_static_path is the CLIENT's field and the loader
			// refuses it on a gateway, so a role flip has to drop it.
			keys, _ := d["keys"].(map[string]any)
			delete(keys, "gateway_static_path")
		}},
		{"a udp-only plan", func(d map[string]any) {
			d["plan"] = []string{"udp"}
		}},
		{"the default path MTU rather than an explicit one", func(d map[string]any) {
			delete(d, "path_mtu")
		}},
		{"a 1500-byte path MTU", func(d map[string]any) {
			d["path_mtu"] = 1500
		}},
		{"a tunfd device, whose real MTU only the host can know", func(d map[string]any) {
			d["device"] = map[string]any{"kind": winn3DeviceTunFD, "name": "winn0"}
		}},
		{"an admission secret exactly at the 32-byte floor", func(d map[string]any) {
			keys, _ := d["keys"].(map[string]any)
			path := filepath.Join(t.TempDir(), "floor.key")
			if err := os.WriteFile(path, []byte(strings.Repeat("k", 32)), 0o600); err != nil {
				t.Fatal(err)
			}
			keys["admission_path"] = path
		}},
		{"an admission secret with a trailing newline", func(d map[string]any) {
			keys, _ := d["keys"].(map[string]any)
			path := filepath.Join(t.TempDir(), "nl.key")
			if err := os.WriteFile(path, []byte(strings.Repeat("k", 64)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			keys["admission_path"] = path
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document := realKeyProfile(t)
			tc.adjust(document)
			if err := preflightOf(t, document); err != nil {
				t.Fatalf("the pre-start hook refused a profile that can carry traffic, "+
					"which is worse than the defect it closes: %v", err)
			}
		})
	}
}

// TestThePreflightOpensNoSocketAndAdoptsNoDescriptor.
//
// The whole value of running the hook is that it can be run with nothing yet
// created. If the dry run reached winn3BuildDevice it would bind the loopback
// seam port — and for device kind tunfd it would adopt winn3AdoptedTunFD, which
// at pre-start time is -1.
func TestThePreflightOpensNoSocketAndAdoptsNoDescriptor(t *testing.T) {
	if winn3AdoptedTunFD != -1 {
		t.Skipf("another test left winn3AdoptedTunFD at %d", winn3AdoptedTunFD)
	}
	document := realKeyProfile(t)
	document["device"] = map[string]any{"kind": winn3DeviceTunFD, "name": "winn0"}
	if err := preflightOf(t, document); err != nil {
		t.Fatalf("the preflight tried to touch the host device: %v", err)
	}

	// The loopback kind names a fixed host_port. If the preflight bound it, a
	// second preflight in the same process would collide.
	loopback := realKeyProfile(t)
	for i := 0; i < 3; i++ {
		if err := preflightOf(t, loopback); err != nil {
			t.Fatalf("preflight %d refused a profile the first one accepted, which "+
				"means it is holding a socket: %v", i, err)
		}
	}
}

// TestThePreflightDeviceCarriesNoPackets. Both packet methods exist only to
// satisfy tun.Device; reaching either means the dry run was wired into a
// running loop.
func TestThePreflightDeviceCarriesNoPackets(t *testing.T) {
	d := winn3PreflightDevice{mtu: 1203}
	if _, err := d.ReadPacket(make([]byte, 64)); err != errWinn3PreflightIO {
		t.Fatalf("ReadPacket returned %v", err)
	}
	if _, err := d.WritePacket(make([]byte, 64)); err != errWinn3PreflightIO {
		t.Fatalf("WritePacket returned %v", err)
	}
	if d.MTU() != 1203 {
		t.Fatalf("MTU is %d", d.MTU())
	}
}

// TestTheDesktopV3ModeRefusesTheFrameTransportFlagsItCannotHonour.
//
// run() returns into runWinn3 before the transport switch, so -transport and
// -control used to reach no code in this mode. -transport unix -control PATH
// alongside -winn3-profile left the host blocking on accept() forever while the
// engine wrote status documents to a stdout nobody read: both halves silent,
// which is the one outcome this protocol must never be mistaken for.
func TestTheDesktopV3ModeRefusesTheFrameTransportFlagsItCannotHonour(t *testing.T) {
	v3 := winn3Options{profile: "/tmp/winn3.json", tunFD: -1}
	cases := []struct {
		name   string
		opts   options
		expect string
	}{
		{"a unix transport", options{udpFD: -1, transport: "unix"}, "-transport"},
		{"an unknown transport", options{udpFD: -1, transport: "carrier-pigeon"}, "-transport"},
		{"a control socket", options{udpFD: -1, control: "@winn"}, "-control"},
		{"both together", options{udpFD: -1, transport: "unix", control: "/run/winn.sock"},
			"-transport"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := winn3RefuseMixedModes(tc.opts, v3)
			if err == nil {
				t.Fatal("accepted a flag this mode silently ignores")
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Fatalf("refused without naming the flag: %v", err)
			}
		})
	}
}

// TestTheDesktopV3ModeStillAcceptsTheTransportDefaults is the matching
// over-fire control, and it is not hypothetical: the first draft of the refusal
// above tested `transport != "stdio"` and broke
// TestTheTwoProtocolsCannotBeMixed, whose clean-configuration case builds
// options{} with the zero value rather than the flag default.
func TestTheDesktopV3ModeStillAcceptsTheTransportDefaults(t *testing.T) {
	v3 := winn3Options{profile: "/tmp/winn3.json", tunFD: -1}
	for _, transport := range []string{"", "stdio"} {
		if err := winn3RefuseMixedModes(
			options{udpFD: -1, transport: transport}, v3); err != nil {
			t.Fatalf("a clean v3 configuration with -transport %q was refused: %v",
				transport, err)
		}
	}
}

// TestTheFrameModeStillHonoursTheFlagsTheDesktopModeRefuses guards the boundary
// the refusal must not cross: -winn3 (frame mode) genuinely serves over a unix
// socket, and nothing added here may touch it.
func TestTheFrameModeStillHonoursTheFlagsTheDesktopModeRefuses(t *testing.T) {
	frame := winn3Options{frame: true, keys: "/tmp/k.json", tunFD: -1}
	if err := winn3RefuseMixedModes(
		options{udpFD: -1, transport: "unix", control: "/run/winn.sock"}, frame); err != nil {
		t.Fatalf("the frame mode was refused a transport it implements: %v", err)
	}
}

// TestPreflightErrorsNameTheFieldTheOperatorWouldEdit.
//
// The failure this closes was not that no error existed; it was that the error
// the operator finally saw said "the datapath stopped before it carried
// anything". A refusal that does not name inner.v4 or inner.router_v4 sends
// somebody back to reading packet captures.
func TestPreflightErrorsNameTheFieldTheOperatorWouldEdit(t *testing.T) {
	document := realKeyProfile(t)
	document["inner"] = map[string]any{"v4": "10.64.0.2", "router_v4": "10.64.0.2"}
	err := preflightOf(t, document)
	if err == nil {
		t.Fatal("accepted router == inner")
	}
	for _, want := range []string{"inner.v4", "inner.router_v4", "10.64.0.2"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not mention %q, so it does not tell the "+
				"operator what to edit: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "stopped before it carried anything") {
		t.Fatal("the refusal is still phrased as a liveness failure")
	}
}

// TestThePrintSizingFlagActuallyRunsThePreflightAndPrintsNothingWhenItRefuses.
//
// This is the test the table above did NOT provide, and the mutation harness
// said so: every case there calls winn3PreflightSession directly, so deleting
// the call from the -winn3-print-sizing branch SURVIVED the whole table
// (mutation D01). A suite that proves a function works while nothing proves it
// is reached is precisely the failure this sweep exists to find.
//
// Both halves matter. The hook must refuse, AND it must not print a plan floor
// on the way out — a host that reads a sizing document treats it as permission.
func TestThePrintSizingFlagActuallyRunsThePreflightAndPrintsNothingWhenItRefuses(t *testing.T) {
	document := realKeyProfile(t)
	document["inner"] = map[string]any{"v4": "10.64.0.2", "router_v4": "10.64.0.2"}

	var out bytes.Buffer
	err := runWinn3(context.Background(), winn3Options{
		profile: writeProfile(t, document), tunFD: -1, printSizing: true,
	}, &out)
	if err == nil {
		t.Fatal("-winn3-print-sizing approved a profile whose router equals its " +
			"assigned address; the real start refuses it")
	}
	if !strings.Contains(err.Error(), "router address equals the assigned address") {
		t.Fatalf("refused for some other reason: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("the hook printed a plan floor for a profile that can never carry "+
			"traffic, which a host reads as permission to configure an interface: %s",
			out.String())
	}
}

// TestPrintSizingStillPrintsSizing. The hook's output contract is unchanged: a
// profile that passes must still produce exactly one status document on stdout
// and nothing else, because a host parses it to set an interface MTU.
//
// Driven through runWinn3 rather than around it, for the same reason as above.
func TestPrintSizingStillPrintsSizing(t *testing.T) {
	var out bytes.Buffer
	err := runWinn3(context.Background(), winn3Options{
		profile: writeProfile(t, realKeyProfile(t)), tunFD: -1, printSizing: true,
	}, &out)
	if err != nil {
		t.Fatalf("the hook refused a profile that can carry traffic: %v", err)
	}
	lines := strings.Count(strings.TrimRight(out.String(), "\n"), "\n") + 1
	if lines != 1 {
		t.Fatalf("the hook wrote %d lines to stdout, not 1:\n%s", lines, out.String())
	}
	if !strings.Contains(out.String(), `"event":"sizing"`) {
		t.Fatalf("the status document is not a sizing document: %s", out.String())
	}
}
