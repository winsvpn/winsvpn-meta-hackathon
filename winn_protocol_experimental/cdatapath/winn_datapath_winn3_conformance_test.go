//go:build darwin

// winn_datapath_winn3_conformance_test.go — the cross-host conformance adapter
// for the C ABI, which is the APPLE host's only way in.
//
// This entry point is where defect 1 lived: it base64-decoded gateway_id while
// the four other call sites in the tree used the operator string's raw bytes,
// so Apple was the one platform that computed a different admission tag from
// the same operator value — and a v3 gateway answers nothing it cannot
// authenticate. The fix is in place; what was missing is a test that fails if
// anybody puts it back, on this entry point or on any of the other four.
//
// Nothing here opens a socket to anything real. Every create that reaches the
// network layer adopts a loopback descriptor pointed at a second socket in this
// same process.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"winsvpn.local/winnprotocol/winn3/conform"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// winn3ConformanceDocument is the reference operator configuration as a create
// document for THIS entry point.
//
// Two fields are encoded and the asymmetry is the whole point:
//
//   - gateway_id is the RAW operator string. It is an authenticated tag input
//     that is never transmitted, and every other host derives []byte(operator).
//   - admission_key is base64, because it is a secret whose bytes are arbitrary
//     and a JSON string cannot carry them any other way.
//
// admission_key is base64 OF THE ADMISSION FILE'S BYTES — the 64 hex characters
// keygen wrote — and NOT of the 32 bytes they encode. That is the trap this
// adapter exists to hold: the gateway keys with the file's bytes, so a control
// plane that base64s the decoded secret hands Apple a 32-byte key against a
// 64-byte gateway and the gateway answers nothing.
func winn3ConformanceDocument(t *testing.T, op conform.Operator) map[string]any {
	t.Helper()
	priv, gw := testKeys(t)
	doc := map[string]any{
		"contract":         winn3Contract,
		"payload":          winn3Payload,
		"carrier":          winn3Carrier,
		"gateway_endpoint": "127.0.0.1:51820",
		"static_private":   priv,
		"gateway_static":   gw,
		"gateway_id":       op.GatewayID,
		"admission_key":    base64.StdEncoding.EncodeToString(op.AdmissionSecret()),
		"inner_v4":         "10.64.0.2",
		"inner_router_v4":  "10.64.0.1",
		"carrier_classes":  op.CarrierClasses,
		"session_id":       "conformance",
	}
	if op.PathMTU != 0 {
		doc["path_mtu"] = op.PathMTU
	}
	return doc
}

// winn3ConformanceDerivation drives the REAL create path — decodeWinn3Config,
// carrierClasses, the path-MTU default, driver.NewSizing and admissionProfile,
// in openWinn3's own order — and reports what this host derived.
//
// The sizing is read off a tunnel that really opened, via Loop.Sizing(), rather
// than recomputed here: a test that recomputed it would agree with itself while
// the engine ran on something else.
func winn3ConformanceDerivation(t *testing.T, op conform.Operator) conform.Derivation {
	t.Helper()
	doc := winn3ConformanceDocument(t, op)

	cfg, err := decodeWinn3Config(encode(t, doc))
	if err != nil {
		t.Fatalf("decodeWinn3Config refused the reference operator configuration: %v", err)
	}
	admission, err := admissionProfile(cfg)
	if err != nil {
		t.Fatalf("admissionProfile refused the reference operator configuration: %v", err)
	}

	fd, peer, loopFile := loopbackPair(t)
	defer peer.Close()
	defer loopFile.Close()
	tunnel, err := openWinn3(encode(t, doc), fd)
	if err != nil {
		t.Fatalf("openWinn3 refused the reference operator configuration: %v", err)
	}
	defer tunnel.close()
	sizing := tunnel.loop.Sizing()

	classNames := make([]string, 0, len(sizing.Classes))
	for _, c := range sizing.Classes {
		classNames = append(classNames, c.String())
	}
	return conform.FromCore(
		"cdatapath/winn_datapath_winn3.go:openWinn3 (the C ABI) [iOS, macOS]",
		admission.Gateway, sizing, classNames)
}

// --- tier A -------------------------------------------------------------------

// TestCABIConformsToTheCrossHostSuite.
func TestCABIConformsToTheCrossHostSuite(t *testing.T) {
	op := conform.Reference()
	want, err := conform.Expected(op)
	if err != nil {
		t.Fatal(err)
	}
	want.MustMatch(t, winn3ConformanceDerivation(t, op))
}

// TestAGatewayBuiltFromTheReferenceAdmitsThisEntryPoint is the property in the
// currency the field failure was denominated in.
//
// The negative control for this test is not hypothetical: it is what shipped.
// A client whose gateway_id was six decoded bytes against a gateway holding
// eight raw ones produced session_states:["initiating"], messages_received:5,
// messages_sent:0 and refused_datagrams:0 — a gateway receiving every packet,
// authenticating none, and reporting no refusal because an unauthenticated
// datagram is not refused, it is ignored.
func TestAGatewayBuiltFromTheReferenceAdmitsThisEntryPoint(t *testing.T) {
	op := conform.Reference()
	gateway, err := conform.Expected(op)
	if err != nil {
		t.Fatal(err)
	}
	if err := conform.AdmissionRoundTrip(winn3ConformanceDerivation(t, op), gateway); err != nil {
		t.Fatal(err)
	}
}

// TestTheAdmissionKeyIsTheFilesBytesNotTheDecodedSecret.
//
// The one encoding question this entry point genuinely has that the others do
// not: admission_key crosses as base64 because the file cannot. What it must
// carry is the FILE'S BYTES.
//
// keygen writes 64 hex characters. Every file-reading consumer — the gateway,
// both cmd/winn-datapath entry points, the labrig — keys with those characters.
// A control plane that base64-encodes the DECODED 32 bytes instead produces a
// document that parses, a key that is the right shape, a session that starts,
// and a gateway that never answers. There is nothing on the wire to catch it,
// and this is the only place it can be caught at all.
func TestTheAdmissionKeyIsTheFilesBytesNotTheDecodedSecret(t *testing.T) {
	op := conform.Reference()
	got := winn3ConformanceDerivation(t, op)

	if string(got.AdmissionKey) != string(op.AdmissionSecret()) {
		t.Fatalf("this entry point keyed with %d bytes; the admission FILE holds %d and those "+
			"are what the gateway keys with", len(got.AdmissionKey), len(op.AdmissionSecret()))
	}

	// The negative control: base64 of the DECODED secret is the natural mistake
	// for a control plane to make, and it must not be admitted by a gateway
	// built from the file.
	gateway, err := conform.Expected(op)
	if err != nil {
		t.Fatal(err)
	}
	wrong := got
	wrong.Host = "a control plane that base64-encoded the DECODED admission secret"
	decoded, err := hex.DecodeString(string(op.AdmissionSecret()))
	if err != nil {
		t.Fatal(err)
	}
	wrong.AdmissionKey = decoded
	if err := conform.AdmissionRoundTrip(wrong, gateway); err == nil {
		t.Fatal("a client keyed with the DECODED admission secret was admitted by a gateway " +
			"keyed with the file's bytes. If that is now true, the two encodings have been " +
			"unified somewhere and this test should say so; until then it is the trap that " +
			"makes an Apple session start, report up, and be ignored forever.")
	}
}

// TestGatewayIDIsStillTakenVerbatimAcrossTheConformanceFixture is defect 1's
// regression pin at the entry point that had it.
func TestGatewayIDIsStillTakenVerbatimAcrossTheConformanceFixture(t *testing.T) {
	op := conform.Reference()
	got := winn3ConformanceDerivation(t, op)
	if string(got.GatewayID) != op.GatewayID {
		t.Fatalf("gateway_id was derived as %q (%x) from the operator string %q. This entry "+
			"point base64-decoded it until 2026-08-09; %q decodes CLEANLY to six bytes, which "+
			"is why the defect was silent.", got.GatewayID, got.GatewayID, op.GatewayID, op.GatewayID)
	}
	decoded, err := base64.StdEncoding.DecodeString(op.GatewayID)
	if err != nil {
		t.Fatal("the conformance fixture's gateway id no longer decodes as base64, so it no " +
			"longer reproduces the defect")
	}
	if string(got.GatewayID) == string(decoded) {
		t.Fatal("the raw and decoded gateway ids are equal, so this test proves nothing")
	}
}

// --- plan admission regression pins -------------------------------------------

func TestAnEmptyPlanIsRefused(t *testing.T) {
	if _, err := carrierClasses(nil); err == nil {
		t.Fatal("carrierClasses(nil) accepted an omitted migration plan")
	}
}

// TestThePlanMustContainUDPDivergenceIsStillExactlyWhatItSays.
//
// cmd/winn-datapath refuses a plan without udp because udp is the only class it
// can dial. This entry point accepts [tcp,tls] and sizes it. Apple cannot dial
// tcp or tls either — carrier.NewUDP is the only carrier openWinn3 builds — so
// the plan is accepted and then not dialable, which is the same asymmetry one
// platform along.
func TestAPlanWithoutUDPIsRefused(t *testing.T) {
	if _, err := carrierClasses([]string{"tcp", "tls"}); err == nil {
		t.Fatal("carrierClasses accepted a plan this UDP-only entry point cannot dial")
	}
}

// --- the path-MTU default -------------------------------------------------------

// TestTheOmittedPathMTUDefaultsToTheSameNumberEveryOtherHostDefaultsTo is
// defect 3's only mitigation: nothing negotiates the path MTU, so the defaults
// agreeing is the entire reason two ends that were both left alone still talk.
func TestTheOmittedPathMTUDefaultsToTheSameNumberEveryOtherHostDefaultsTo(t *testing.T) {
	op := conform.Reference()
	op.PathMTU = 0
	got := winn3ConformanceDerivation(t, op)
	if got.PathMTU != conform.DefaultPathMTU {
		t.Fatalf("an omitted path_mtu resolved to %d here; cmd/winn3-gateway and "+
			"cmd/winn-datapath's profile both default to %d. Nothing in v3 negotiates this "+
			"number, so two ends that were both left alone must land on the same one or the "+
			"session establishes and then stalls on the first full-size flow.",
			got.PathMTU, conform.DefaultPathMTU)
	}
	// INVERTED 2026-08-10. This asserted tun.IPv6MinLinkMTU == conform.DefaultPathMTU,
	// because this entry point defaulted through the first while the gateway
	// defaulted through the second, and the two being the same number was the
	// only thing keeping them in agreement. That equality is what let the fleet
	// default sit at 1280 — RFC 8200's INNER link floor used as an OUTER
	// planning MTU, which over any real plan yields an inner MTU below 1280 and
	// a session that resolves, carries and can never promote. Both halves were
	// fixed together: the constant moved to 1450 and this seam now resolves
	// through carrier.DefaultPathMTU like every other entry point, so the check
	// that has teeth is the opposite one.
	if conform.DefaultPathMTU == tun.IPv6MinLinkMTU {
		t.Fatalf("the fleet default is back on RFC 8200's link floor (%d). That number is a "+
			"floor for the INNER interface, and as an OUTER path MTU it puts every default "+
			"session in the inner-IPv6 dead zone driver.NewSizing exists to refuse.",
			tun.IPv6MinLinkMTU)
	}

	want, err := conform.Floor(op.CarrierClasses, conform.DefaultPathMTU)
	if err != nil {
		t.Fatal(err)
	}
	if got.MessageSize != want.MessageSize || got.InnerMTU != want.InnerMTU {
		t.Fatalf("at the default path MTU this host plans %d/%d; the reference is %d/%d",
			got.MessageSize, got.InnerMTU, want.MessageSize, want.InnerMTU)
	}
}
