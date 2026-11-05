package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/conform"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
)

// The cross-host conformance adapter for the DESKTOP AND ANDROID CLIENT.
//
// This binary has TWO configuration entry points and they reach the same
// core.GatewayParams by different code:
//
//	-winn3-profile   the desktop document (Linux, Windows): winn3Profile,
//	                 winn3BuildSession, profile.classes()
//	-winn3-keys      the frame-mode document (Android): winn3Keys.sessionConfig,
//	                 decodeWinn3Create, winn3CreateClasses
//
// Two entry points into one engine is exactly the shape that produced defect 1
// — five call sites, four agreeing — so both are driven here and BOTH are
// compared against the reference AND against each other. A suite that checked
// only one of them would have proved the tree consistent while the other half
// diverged.

// --- fixtures ----------------------------------------------------------------

// winn3ConformanceKeyFiles writes the reference operator's material to disk.
//
// Through real files, verbatim, because "what is the admission secret" is a
// question about how the FILE is read: keygen writes hex text with a trailing
// newline, and the rule is trim \r\n and stop.
func winn3ConformanceKeyFiles(t *testing.T, op conform.Operator) (dir, staticPath, gwPubPath, admissionPath string) {
	t.Helper()
	dir = t.TempDir()

	clientStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	gatewayStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	staticPath = filepath.Join(dir, "client.key")
	gwPubPath = filepath.Join(dir, "static.pub")
	admissionPath = filepath.Join(dir, "admission.key")

	write := func(path string, body []byte) {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(staticPath, clientStatic.Bytes())
	write(gwPubPath, gatewayStatic.Public())
	write(admissionPath, []byte(op.AdmissionFile))
	return dir, staticPath, gwPubPath, admissionPath
}

// winn3ConformanceProfileDerivation drives the DESKTOP entry point.
func winn3ConformanceProfileDerivation(t *testing.T, op conform.Operator) conform.Derivation {
	t.Helper()
	dir, staticPath, gwPubPath, admissionPath := winn3ConformanceKeyFiles(t, op)

	profile := winn3Profile{
		Version:   winn3ProfileVersion,
		Role:      winn3RoleClient,
		Plan:      append([]string(nil), op.CarrierClasses...),
		PathMTU:   op.PathMTU,
		GatewayID: op.GatewayID,
		Carrier: winn3CarrierSpec{
			Class:    "udp",
			Endpoint: "127.0.0.1:51833",
		},
		Inner: winn3InnerSpec{V4: "10.64.0.2", RouterV4: "10.64.0.1"},
		Keys: winn3KeySpec{
			StaticPath:        staticPath,
			GatewayStaticPath: gwPubPath,
			AdmissionPath:     admissionPath,
		},
		Device:               winn3DeviceSpec{Kind: "loopback-udp", HostPort: 9},
		AllowOwnSocket:       true,
		OuterSocketExclusion: "conformance: no route is installed by this test",
	}
	// Written and re-read through loadWinn3Profile rather than used directly,
	// so the decoder — DisallowUnknownFields, the validator, the defaults — is
	// part of what is under test. A struct built in memory skips the half of
	// this entry point most likely to drift.
	path := filepath.Join(dir, "profile.json")
	body, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadWinn3Profile(path)
	if err != nil {
		t.Fatalf("loadWinn3Profile refused the reference operator configuration: %v", err)
	}

	cfg, _, err := winn3BuildSession(loaded)
	if err != nil {
		t.Fatalf("winn3BuildSession refused the reference operator configuration: %v", err)
	}
	classes, err := loaded.classes()
	if err != nil {
		t.Fatal(err)
	}
	pathMTU := loaded.PathMTU
	if pathMTU == 0 {
		pathMTU = carrier.DefaultPathMTU
	}
	sizing, err := driver.NewSizing(pathMTU, classes...)
	if err != nil {
		t.Fatal(err)
	}
	return conform.FromCore(
		"cmd/winn-datapath -winn3-profile (winn3_run.go:winn3BuildSession) [Linux, Windows]",
		cfg.Core.Gateway, sizing, loaded.Plan)
}

// winn3ConformanceFrameDerivation drives the FRAME-MODE entry point — the one
// Android uses, and the one WinnV3EngineConfig.toJson writes for.
func winn3ConformanceFrameDerivation(t *testing.T, op conform.Operator) conform.Derivation {
	t.Helper()
	dir, staticPath, gwPubPath, admissionPath := winn3ConformanceKeyFiles(t, op)

	keys := winn3Keys{
		Version:           winn3KeysVersion,
		Role:              winn3RoleClient,
		GatewayID:         op.GatewayID,
		StaticPath:        staticPath,
		GatewayStaticPath: gwPubPath,
		AdmissionPath:     admissionPath,
	}
	path := filepath.Join(dir, "keys.json")
	body, err := json.Marshal(keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadWinn3Keys(path)
	if err != nil {
		t.Fatalf("loadWinn3Keys refused the reference operator configuration: %v", err)
	}
	cfg, _, err := loaded.sessionConfig()
	if err != nil {
		t.Fatalf("winn3Keys.sessionConfig refused the reference operator configuration: %v", err)
	}

	// The sizing half comes from the CREATE DOCUMENT, because in frame mode
	// that is where path_mtu and the plan live — WinnV3EngineConfig.toJson
	// writes exactly this shape.
	row, err := conform.Floor(op.CarrierClasses, op.PathMTU)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := decodeWinn3Create(
		winn3ConformanceCreateJSON(t, op, row.InnerMTU), false, true)
	if err != nil {
		t.Fatalf("decodeWinn3Create refused the reference operator configuration: %v", err)
	}
	return conform.FromCore(
		"cmd/winn-datapath -winn3-keys + Create frame (winn3_keys.go + winn3_create.go) [Android]",
		cfg.Core.Gateway, plan.sizing, plan.doc.CarrierClasses)
}

// winn3ConformanceCreateJSON builds the Create payload EXACTLY as
// WinnV3EngineConfig.toJson does — same field names, same shapes, same order —
// so that a change to either side that the other did not make shows up here
// rather than as a start failure on a handset.
func winn3ConformanceCreateJSON(t *testing.T, op conform.Operator, innerMTU int) []byte {
	t.Helper()
	classes := make([]string, 0, len(op.CarrierClasses))
	for _, c := range op.CarrierClasses {
		classes = append(classes, fmt.Sprintf("%q", c))
	}
	return []byte(fmt.Sprintf(
		`{"payload":"ip-packet","gateway_endpoint":"127.0.0.1:51833",`+
			`"inner_address":"10.64.0.2","inner_next_hop":"10.64.0.1",`+
			`"inner_mtu":%d,"path_mtu":%d,"carrier_classes":[%s],`+
			`"session_id":"conformance","allow_own_socket":true,"owns_tun":false}`,
		innerMTU, op.PathMTU, strings.Join(classes, ",")))
}

// --- tier A -------------------------------------------------------------------

// TestDesktopProfileConformsToTheCrossHostSuite.
func TestDesktopProfileConformsToTheCrossHostSuite(t *testing.T) {
	op := conform.Reference()
	want, err := conform.Expected(op)
	if err != nil {
		t.Fatal(err)
	}
	want.MustMatch(t, winn3ConformanceProfileDerivation(t, op))
}

// TestFrameModeConformsToTheCrossHostSuite.
func TestFrameModeConformsToTheCrossHostSuite(t *testing.T) {
	op := conform.Reference()
	want, err := conform.Expected(op)
	if err != nil {
		t.Fatal(err)
	}
	want.MustMatch(t, winn3ConformanceFrameDerivation(t, op))
}

// TestThisBinarysTwoEntryPointsAgreeWithEachOther.
//
// Two documents that must always agree are two documents that eventually will
// not — this binary says so itself, in winn3_keys.go, about why the key
// document is not the profile. This is the test that makes the observation
// enforceable: both documents describe the same gateway and must reach the same
// core.GatewayParams.
func TestThisBinarysTwoEntryPointsAgreeWithEachOther(t *testing.T) {
	op := conform.Reference()
	profile := winn3ConformanceProfileDerivation(t, op)
	frame := winn3ConformanceFrameDerivation(t, op)
	profile.MustMatch(t, frame)
}

// TestBothEntryPointsAreAdmittedByAGatewayBuiltFromTheReference.
func TestBothEntryPointsAreAdmittedByAGatewayBuiltFromTheReference(t *testing.T) {
	op := conform.Reference()
	gateway, err := conform.Expected(op)
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []conform.Derivation{
		winn3ConformanceProfileDerivation(t, op),
		winn3ConformanceFrameDerivation(t, op),
	} {
		if err := conform.AdmissionRoundTrip(client, gateway); err != nil {
			t.Error(err)
		}
	}
}

// --- the encoding rules, as negative controls ---------------------------------

// TestNeitherEntryPointDecodesTheGatewayID.
func TestNeitherEntryPointDecodesTheGatewayID(t *testing.T) {
	op := conform.Reference()
	for _, d := range []conform.Derivation{
		winn3ConformanceProfileDerivation(t, op),
		winn3ConformanceFrameDerivation(t, op),
	} {
		if string(d.GatewayID) != op.GatewayID {
			t.Errorf("%s derived gateway_id %q (%x) from the operator string %q; %q "+
				"base64-decodes to six bytes and that is what defect 1 was",
				d.Host, d.GatewayID, d.GatewayID, op.GatewayID, op.GatewayID)
		}
	}
}

// TestNeitherEntryPointDecodesTheAdmissionSecret.
func TestNeitherEntryPointDecodesTheAdmissionSecret(t *testing.T) {
	op := conform.Reference()
	for _, d := range []conform.Derivation{
		winn3ConformanceProfileDerivation(t, op),
		winn3ConformanceFrameDerivation(t, op),
	} {
		if string(d.AdmissionKey) != string(op.AdmissionSecret()) {
			t.Errorf("%s keyed with %d bytes (%q…); the admission file's 64 hex characters ARE "+
				"the secret and hex-decoding them produces a tag the gateway cannot verify",
				d.Host, len(d.AdmissionKey), first16(d.AdmissionKey))
		}
	}
}

// --- the plan floor, at the seam that refuses a wrong one ----------------------

// TestTheCreateSeamRefusesTheDialledCarrierMTUAcrossTheWholeMatrix is defect 2,
// generalised.
//
// TestTheFloorIsTheOnlyAcceptableInnerMTU already pins one path MTU. This walks
// every path MTU in the conformance matrix and asserts, for each, that the
// floor is accepted and the DIALLED UDP-over-IPv4 number is refused — because
// the dialled number is what a host computes when it sizes to the carrier it
// opened, and that is the mistake, not an arbitrary wrong integer.
//
// SPLIT IN TWO 2026-08-10. Three of the matrix's six path MTUs — 1280, 1360 and
// 1400 — are now inside the inner-IPv6 dead zone over the reference plan, and
// driver.NewSizing refuses them before the seam ever compares inner_mtu against
// anything. Those rows are not skipped, which would quietly shrink the matrix
// the day somebody widened the zone: they assert the refusal instead, and
// driver.NewSizing itself is the oracle for which branch a row is in, so the
// two can never disagree about where the boundary is.
func TestTheCreateSeamRefusesTheDialledCarrierMTUAcrossTheWholeMatrix(t *testing.T) {
	for _, pathMTU := range conform.MatrixPathMTUs() {
		if pathMTU < 600 {
			// Below the IPv4 floor the tunnel is refused for a different reason
			// and the refusal under test would not be the one that fired.
			continue
		}
		op := conform.Reference()
		op.PathMTU = pathMTU
		row, err := conform.Floor(op.CarrierClasses, pathMTU)
		if err != nil {
			t.Fatal(err)
		}

		classes, err := winn3CreateClasses(op.CarrierClasses)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := driver.NewSizing(pathMTU, classes...); errors.Is(
			err, driver.ErrPathMTUDeadZone) {
			// The dead zone. The plan floor here is an inner MTU below RFC
			// 8200's 1280, so the session would resolve, carry and never
			// promote; the seam must refuse it rather than hand back a tunnel
			// whose only defect is invisible until an IPv6 flow is tried.
			_, seamErr := decodeWinn3Create(
				winn3ConformanceCreateJSON(t, op, row.InnerMTU), false, true)
			if !errors.Is(seamErr, driver.ErrPathMTUDeadZone) {
				t.Errorf("path_mtu %d: driver.NewSizing calls this the inner-IPv6 dead zone "+
					"and the create seam does not agree — it answered %v. The seam is the "+
					"last thing between this path MTU and a handset that can never promote.",
					pathMTU, seamErr)
			}
			continue
		}

		if _, err := decodeWinn3Create(
			winn3ConformanceCreateJSON(t, op, row.InnerMTU), false, true); err != nil {
			t.Errorf("path_mtu %d: the create seam refused the PLAN FLOOR inner MTU %d: %v",
				pathMTU, row.InnerMTU, err)
		}
		if row.DialledUDPv4InnerMTU == row.InnerMTU {
			continue // no gap at this path MTU; nothing to refuse
		}
		_, err = decodeWinn3Create(
			winn3ConformanceCreateJSON(t, op, row.DialledUDPv4InnerMTU), false, true)
		if err == nil {
			t.Errorf("path_mtu %d: the create seam ACCEPTED inner_mtu %d, which is the dialled "+
				"UDP-over-IPv4 number. The plan floor is %d — a %d-byte gap that black-holes "+
				"every full-size flow at the first migration while the tunnel reads up. That "+
				"is defect 2 and this seam is the last thing standing between it and a handset.",
				pathMTU, row.DialledUDPv4InnerMTU, row.InnerMTU, row.Gap)
		}
	}
}

// TestCreateRefusesAPlanWithoutUDP is TIER B.
//
// Every shipping host now refuses a plan without udp because udp is the only
// carrier this entry point can dial. This regression test keeps the command
// boundary fail-closed while the shared floor arithmetic remains usable for
// conformance calculations over arbitrary carrier sets.
func TestCreateRefusesAPlanWithoutUDP(t *testing.T) {
	op := conform.Reference()
	op.CarrierClasses = []string{"tcp", "tls"}
	_, err := winn3CreateClasses(op.CarrierClasses)
	if err == nil {
		t.Fatal("cmd/winn-datapath accepted a plan without udp even though this entry point " +
			"cannot dial any of the requested carriers")
	}
	if !strings.Contains(err.Error(), "udp") {
		t.Errorf("the refusal does not name udp: %v", err)
	}
	// Shared sizing remains deliberately independent of a platform's dial
	// capabilities so the conformance matrix can compare arbitrary plans.
	if _, err := conform.Floor(op.CarrierClasses, op.PathMTU); err != nil {
		t.Errorf("the conformance matrix cannot size [tcp tls]: %v", err)
	}
}

func first16(b []byte) string {
	if len(b) > 16 {
		return string(b[:16])
	}
	return string(b)
}
