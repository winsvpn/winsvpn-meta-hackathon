package conform

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/bits"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// These are the suite's own tests: they check that the REFERENCE is right,
// because a reference nobody checked is just a fourth opinion. The host
// adapters live in the host packages and assert against this one.

// --- the three defects, as reference facts ---------------------------------

// TestTheReferenceGatewayIDDecodesCleanlyAsBase64 is the whole reason defect 1
// survived to production, pinned so nobody "tidies" the fixture into a name
// that would have failed loudly.
func TestTheReferenceGatewayIDDecodesCleanlyAsBase64(t *testing.T) {
	op := Reference()
	raw, err := base64.StdEncoding.DecodeString(op.GatewayID)
	if err != nil {
		t.Fatalf("the reference gateway id %q no longer decodes as base64, so this fixture no "+
			"longer reproduces defect 1: a name that fails base64 decoding makes the wrong "+
			"encoding LOUD, and the defect's whole difficulty was that ordinary names are "+
			"silent. Pick another name from the base64 alphabet.", op.GatewayID)
	}
	if bytes.Equal(raw, op.GatewayIDBytes()) {
		t.Fatal("the reference gateway id decodes to itself, so a host that base64-decoded it " +
			"would agree by accident and this fixture would prove nothing")
	}
	if len(raw) != 6 || len(op.GatewayIDBytes()) != 8 {
		t.Fatalf("expected the 8-byte name %q to decode to 6 bytes; got %d and %d",
			op.GatewayID, len(op.GatewayIDBytes()), len(raw))
	}
}

// TestTheReferenceAdmissionSecretIsHexTextAndIsNotDecoded pins the rule that
// cost a debugging cycle: keygen writes hex, every consumer keys with the
// file's bytes.
func TestTheReferenceAdmissionSecretIsHexTextAndIsNotDecoded(t *testing.T) {
	op := Reference()
	secret := op.AdmissionSecret()
	if len(secret) != 64 {
		t.Fatalf("the admission secret is %d bytes; keygen writes 64 hex characters and every "+
			"consumer keys with those characters, not with the 32 bytes they encode", len(secret))
	}
	if bytes.ContainsAny(secret, "\r\n") {
		t.Fatal("the trailing newline was not trimmed")
	}
	decoded, err := hex.DecodeString(string(secret))
	if err != nil {
		t.Fatal("the reference secret is not valid hex, so this fixture no longer reproduces " +
			"the hex-decode trap: the trap only exists because decoding SUCCEEDS")
	}
	if len(decoded) != 32 || bytes.Equal(decoded, secret) {
		t.Fatalf("the reference secret hex-decodes to %d bytes; it must decode cleanly to a "+
			"DIFFERENT value, or a host that decoded it would agree by accident", len(decoded))
	}
}

// TestTheReferencePlanFloorIsTheNumberDefectTwoGotWrong.
func TestTheReferencePlanFloorIsTheNumberDefectTwoGotWrong(t *testing.T) {
	got, err := Expected(Reference())
	if err != nil {
		t.Fatal(err)
	}
	if got.InnerMTU != 1359 {
		t.Fatalf("the plan floor inner MTU over [udp tcp tls] at a 1500-byte path is %d; the "+
			"plan floor is 1359 and WinnV3EngineConfig shipped 1443", got.InnerMTU)
	}
	if got.MessageSize != 1388 {
		t.Fatalf("the plan floor message size is %d, want 1388", got.MessageSize)
	}
	dialled := tun.InnerMTUForPath(1500, tun.UDPOverIPv4Overhead)
	if dialled != 1443 {
		t.Fatalf("InnerMTUForPath(1500, 28) is %d, want 1443", dialled)
	}
	if dialled-got.InnerMTU != 84 {
		t.Fatalf("the black hole is %d bytes wide; defect 2 was 84 (1443 dialled udp/v4 minus "+
			"1359 plan floor, which is TLS over IPv6's 112-byte overhead minus UDP over IPv4's 28)",
			dialled-got.InnerMTU)
	}
}

// TestTheGatewayAndClientPathMTUMustBeConfiguredIdentically is defect 3.
//
// It does not assert that the two agree — nothing makes them agree, which is
// the defect. It asserts the SIZE OF THE DAMAGE when they do not, so that the
// day somebody adds negotiation this test tells them what they fixed.
func TestTheGatewayAndClientPathMTUMustBeConfiguredIdentically(t *testing.T) {
	plan := []string{"udp"}
	gatewaySide, err := Floor(plan, DefaultPathMTU) // the gateway's -path-mtu default (1450 since 2026-08-10)
	if err != nil {
		t.Fatal(err)
	}
	clientSide, err := Floor(plan, 1500) // a client that measured its path
	if err != nil {
		t.Fatal(err)
	}
	if gatewaySide.MessageSize == clientSide.MessageSize {
		t.Fatal("a gateway on its default and a 1500-byte client now plan the same message size. " +
			"Either the arithmetic changed or somebody made the two ends reconcile. Note " +
			"what does NOT satisfy this: the refusal shipped on 2026-08-09 carries the " +
			"responder's path MTU across the handshake and ends the session when the two " +
			"differ, which makes the mismatch loud without making the numbers agree — the " +
			"path-mtu-not-negotiated row stays open for the take-the-minimum half. Delete " +
			"that row only when the client actually adopts the smaller of the two.")
	}
	// RESTATED 2026-08-10 with the fleet default raise. It was 1232 (gateway at
	// 1280) against 1452; the gateway default moved to 1450 and the damage
	// SHRANK to 50 bytes, which is the point of the raise and not a reason to
	// delete the row — an operator can still configure the two ends apart, and
	// the notice now makes that loud rather than silent.
	if gatewaySide.MessageSize != 1402 || clientSide.MessageSize != 1452 {
		t.Fatalf("the documented mismatch is 1402 (gateway at %d) against 1452 (client at "+
			"1500); this build gives %d against %d",
			DefaultPathMTU, gatewaySide.MessageSize, clientSide.MessageSize)
	}
}

// --- the four entry points, one constant -------------------------------------

// TestEveryEntryPointDefaultsThroughTheOneConstant.
//
// REPLACES TestTheTwoDefaultsAreTheSameNumber, 2026-08-10, and it is a STRONGER
// test rather than a relaxed one.
//
// The old test asserted carrier.DefaultPathMTU == tun.IPv6MinLinkMTU, because
// the tree reached "no path MTU was given" through BOTH names: cmd/winn3-gateway
// and cmd/winn-datapath's profile through the first, cmd/winn-datapath's create
// document and cdatapath through the second. The two were equal at 1280 and the
// equality was doing real work by accident.
//
// That equality is now FALSE ON PURPOSE. The fleet default is 1450 and
// tun.IPv6MinLinkMTU is still 1280, because it is RFC 8200's floor and has
// nothing to do with what a host should plan at. Asserting they are equal would
// now forbid the raise.
//
// What actually had to hold — and what nearly did not — is that all four entry
// points resolve through ONE constant. Raising carrier.DefaultPathMTU alone
// would have moved two of them and left Apple's route and the create document
// planning at 1280 against gateways planning at 1450: a path-MTU mismatch on
// every default session, on one platform, which is defect 3 arriving by default
// rather than by configuration. So this reads the four sources.
func TestEveryEntryPointDefaultsThroughTheOneConstant(t *testing.T) {
	if DefaultPathMTU != carrier.DefaultPathMTU {
		t.Fatalf("conform.DefaultPathMTU is %d, want %d", DefaultPathMTU, carrier.DefaultPathMTU)
	}
	// The default must not itself be inside the dead zone it exists to keep
	// hosts out of. This is the assertion that makes the raise load-bearing
	// rather than cosmetic.
	if _, err := driver.NewSizing(DefaultPathMTU, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS); err != nil {
		t.Fatalf("the fleet default %d is not a path the shipping plan can be built at: %v",
			DefaultPathMTU, err)
	}

	root := engineRoot(t)
	for _, entry := range []struct{ file, why string }{
		{"cmd/winn3-gateway/main.go", "the gateway's -path-mtu flag default"},
		{"cmd/winn-datapath/winn3_run.go", "the client profile's default"},
		{"cmd/winn-datapath/winn3_create.go", "the create document's default — Windows and the shells"},
		{"cdatapath/winn_datapath_winn3.go", "the C shared-library seam — Apple's route into the engine"},
	} {
		raw, err := os.ReadFile(filepath.Join(root, entry.file)) //nolint:gosec // our own tree
		if err != nil {
			t.Errorf("%s could not be read: %v", entry.file, err)
			continue
		}
		body := string(raw)
		if !strings.Contains(body, "carrier.DefaultPathMTU") {
			t.Errorf("%s (%s) does not mention carrier.DefaultPathMTU.\n"+
				"  Every entry point that resolves a missing path_mtu must resolve it "+
				"through that one constant. A second name for the default is how the "+
				"fleet default gets raised on three hosts and not on the fourth.",
				entry.file, entry.why)
		}
		if strings.Contains(body, "pathMTU = tun.IPv6MinLinkMTU") {
			t.Errorf("%s (%s) still defaults a missing path_mtu to tun.IPv6MinLinkMTU.\n"+
				"  That is RFC 8200's minimum link MTU, not a planning path MTU, and it is "+
				"no longer equal to the fleet default. A host defaulting through it plans "+
				"at 1280 while the rest of the fleet plans at %d.",
				entry.file, entry.why, carrier.DefaultPathMTU)
		}
	}
}

// --- the reference agrees with the engine ------------------------------------

// TestTheReferenceFloorIsCarrierFloor proves this package computes nothing of
// its own: every matrix row must equal carrier.Floor called directly.
func TestTheReferenceFloorIsCarrierFloor(t *testing.T) {
	rows, err := Matrix()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(MatrixPlans())*len(MatrixPathMTUs()) {
		t.Fatalf("matrix is %d rows, want %d", len(rows), len(MatrixPlans())*len(MatrixPathMTUs()))
	}
	for _, row := range rows {
		classes, err := Classes(row.Classes)
		if err != nil {
			t.Fatal(err)
		}
		want := carrier.Floor(row.PathMTU, classes...)
		if row.MessageSize != want {
			t.Errorf("%v at %d: matrix says message size %d, carrier.Floor says %d",
				row.Classes, row.PathMTU, row.MessageSize, want)
		}
		if row.InnerMTU != session.InnerMTU(want) {
			t.Errorf("%v at %d: matrix says inner MTU %d, session.InnerMTU says %d",
				row.Classes, row.PathMTU, row.InnerMTU, session.InnerMTU(want))
		}
	}
}

// TestTheLowerClampIsExercised proves the 130-byte row is doing work: at that
// path MTU a TLS/IPv6 carrier's 112-byte overhead leaves less than
// session.MessageFloor(), so MaxMessageSizeForPath's floor clamp fires — while
// the udp/v4 cell in the same row is still unclamped.
//
// The clamp never fires on a real link, which is exactly why a hand-written
// mirror of this arithmetic is likely to omit it, and why the suite has to
// exercise it deliberately rather than wait for a path to.
func TestTheLowerClampIsExercised(t *testing.T) {
	row, err := Floor([]string{"udp", "tcp", "tls"}, 130)
	if err != nil {
		t.Fatal(err)
	}
	if row.MessageSize != session.MessageFloor() {
		t.Fatalf("at a 130-byte path the udp+tcp+tls floor is %d; the clamp is %d and this row "+
			"exists to exercise it. If the arithmetic changed so the clamp no longer fires, "+
			"pick a smaller path MTU rather than deleting the row",
			row.MessageSize, session.MessageFloor())
	}
	if row.InnerMTU != 0 {
		t.Fatalf("a clamped message size implies a zero inner MTU; got %d", row.InnerMTU)
	}
	// The same row must NOT be clamped for a udp/v4 carrier, or the row is only
	// testing "everything clamps" and would pass against a mirror that clamps
	// unconditionally.
	unclamped := carrier.MaxMessageSizeFor(carrier.ClassUDP, carrier.FamilyIPv4, 130)
	if unclamped <= session.MessageFloor() {
		t.Fatalf("udp over IPv4 at a 130-byte path is also clamped (%d); pick a path MTU where "+
			"one cell clamps and another does not", unclamped)
	}
}

// TestOverheadsAreCarrierOverheads pins the six numbers WinnV3Sizing mirrors.
func TestOverheadsAreCarrierOverheads(t *testing.T) {
	want := map[string]int{
		"udp/v4": 20 + 8,
		"udp/v6": 40 + 8,
		"tcp/v4": 20 + (20 + 12) + (2 + 16),
		"tcp/v6": 40 + (20 + 12) + (2 + 16),
		"tls/v4": 20 + (20 + 12) + (5 + 1 + 16) + (2 + 16),
		"tls/v6": 40 + (20 + 12) + (5 + 1 + 16) + (2 + 16),
	}
	got := Overheads()
	if len(got) != len(want) {
		t.Fatalf("Overheads returned %d rows, want %d. A silently dropped class shrinks "+
			"the vector file, and a host that also omitted that class would then agree.",
			len(got), len(want))
	}
	seen := map[string]bool{}
	for _, row := range got {
		family := "v6"
		if row.IPv4 {
			family = "v4"
		}
		key := row.Class + "/" + family
		if row.Overhead != want[key] {
			t.Errorf("%s overhead is %d, want %d", key, row.Overhead, want[key])
		}
		seen[key] = true
	}
	for key := range want {
		if !seen[key] {
			t.Errorf("Overheads omitted %s — a host that also omitted it would agree", key)
		}
	}
	if last := got[len(got)-1].Overhead; last != 112 {
		t.Errorf("tls over IPv6 is %d, want 112 — the number the 84-byte gap is made of", last)
	}
}

// --- the demux token ---------------------------------------------------------

// TestTheDocumentedDemuxTokenIsTheOneOnTheWire drives DemuxTokenFromDoc — which
// is written from winn3/core/index.go's published construction — against the
// bytes a REAL session really seals.
//
// This is the one place the suite implements something twice on purpose. A host
// building a session index has nothing but that doc comment to work from, so a
// change to core's private derivation that left the comment behind would be
// discovered by whoever wrote the next index, in the field.
func TestTheDocumentedDemuxTokenIsTheOneOnTheWire(t *testing.T) {
	client, gateway := establish(t)

	key, epoch := gateway.RecvDemuxKey()
	if epoch != 0 {
		t.Fatalf("a fresh session is epoch %d, want 0", epoch)
	}
	if bytes.Equal(key[:], make([]byte, len(key))) {
		t.Fatal("the receive demux key is all zeroes")
	}

	for counter := uint64(0); counter < 4; counter++ {
		msg, err := client.Seal([]byte("winn3 conformance demux probe"), 0)
		if err != nil {
			t.Fatal(err)
		}
		want := DemuxTokenFromDoc(key[:], counter)
		if !bytes.Equal(msg[:core.DemuxTokenSize], want) {
			t.Fatalf("message %d carries demux token %x, but the construction published at "+
				"winn3/core/index.go:47 — HMAC-SHA256(key, \"winn3 demux v1\" || be64(counter))[:8] "+
				"— names %x.\n"+
				"A host building a session index has only that doc comment to work from. If "+
				"core's derivation changed, the comment has to change with it in the SAME "+
				"commit, or the next index built from it drops every packet.",
				counter, msg[:core.DemuxTokenSize], want)
		}
		if _, err := gateway.Open(msg); err != nil {
			t.Fatalf("the gateway could not open message %d: %v", counter, err)
		}
	}
}

// --- the admission round trip -------------------------------------------------

// TestAdmissionRoundTripAcceptsAgreement is the positive control.
func TestAdmissionRoundTripAcceptsAgreement(t *testing.T) {
	ref, err := Expected(Reference())
	if err != nil {
		t.Fatal(err)
	}
	if err := AdmissionRoundTrip(ref, ref); err != nil {
		t.Fatalf("two hosts with identical admission inputs could not complete an admission: %v", err)
	}
}

// TestAdmissionRoundTripCatchesTheGatewayIDDefect is the NEGATIVE CONTROL, and
// it is the test that says this suite has teeth.
//
// It reproduces defect 1 exactly: the gateway holds the operator string's raw
// bytes and the client base64-decodes it first. Nothing about that produces an
// error anywhere except here.
func TestAdmissionRoundTripCatchesTheGatewayIDDefect(t *testing.T) {
	op := Reference()
	gateway, err := Expected(op)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(op.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	client := gateway
	client.Host = "a host that base64-decodes gateway_id (defect 1)"
	client.GatewayID = decoded

	err = AdmissionRoundTrip(client, gateway)
	if err == nil {
		t.Fatal("a client that base64-decoded gateway_id completed an admission against a " +
			"gateway that did not. This suite would not have caught defect 1.")
	}
	if !strings.Contains(err.Error(), "THE GATEWAY WOULD NOT HAVE ANSWERED") {
		t.Fatalf("the refusal does not name the consequence: %v", err)
	}
	if ms := Compare(client, gateway); len(ms) == 0 {
		t.Fatal("Compare found no divergence between a raw and a base64-decoded gateway id")
	}
}

// TestAdmissionRoundTripCatchesTheHexDecodedSecret is the second negative
// control: the admission secret decoded on one end only.
func TestAdmissionRoundTripCatchesTheHexDecodedSecret(t *testing.T) {
	op := Reference()
	gateway, err := Expected(op)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := hex.DecodeString(string(op.AdmissionSecret()))
	if err != nil {
		t.Fatal(err)
	}
	client := gateway
	client.Host = "a host that hex-decodes the admission secret"
	client.AdmissionKey = decoded

	if err := AdmissionRoundTrip(client, gateway); err == nil {
		t.Fatal("a client that hex-decoded the admission secret completed an admission against " +
			"a gateway that keyed with the file's bytes")
	}
	ms := Compare(client, gateway)
	if len(ms) == 0 {
		t.Fatal("Compare found no divergence")
	}
	if !strings.Contains(Explain(client, gateway, ms), "opaque bytes") {
		t.Error("the failure message does not state that the secret is opaque bytes")
	}
}

// TestAdmissionRoundTripCatchesATagSizeDifference: a message sealed for a
// 32-byte-tag gateway must not verify at a 16-byte-tag gateway sharing the key,
// because one tag would otherwise be a prefix of the other.
func TestAdmissionRoundTripCatchesATagSizeDifference(t *testing.T) {
	gateway, err := Expected(Reference())
	if err != nil {
		t.Fatal(err)
	}
	client := gateway
	client.Host = "a host configured with a 16-byte admission tag"
	client.TagSize = core.MinTagSize

	if err := AdmissionRoundTrip(client, gateway); err == nil {
		t.Fatal("a 16-byte-tag client was admitted by a 32-byte-tag gateway")
	}
}

// --- the failure message ------------------------------------------------------

// TestTheFailureMessageNamesBothValuesAndTheConsequence.
//
// A conformance suite that says "hosts disagree" has moved the debugging cost,
// not removed it. The message has to carry both renderings and the field
// symptom, because the reader is usually looking at a bug report that says
// "it does not connect in Yangon".
func TestTheFailureMessageNamesBothValuesAndTheConsequence(t *testing.T) {
	a, err := Expected(Reference())
	if err != nil {
		t.Fatal(err)
	}
	b := a
	b.Host = "the other host"
	b.GatewayID = []byte("different")
	b.InnerMTU = 1443

	msg := Explain(a, b, Compare(a, b))
	for _, want := range []string{
		hex.EncodeToString(a.GatewayID),
		hex.EncodeToString(b.GatewayID),
		"1359", "1443",
		"CONSEQUENCE (admission)",
		"CONSEQUENCE (sizing)",
		"never transmitted",
		"reads",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the failure message does not contain %q:\n%s", want, msg)
		}
	}
}

// --- tier B -------------------------------------------------------------------

// TestEveryKnownDivergenceIsFullyStated. A row with no consequence is a row
// nobody thought about.
func TestEveryKnownDivergenceIsFullyStated(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range KnownDivergences() {
		if seen[d.ID] {
			t.Errorf("duplicate divergence id %q", d.ID)
		}
		seen[d.ID] = true
		for name, value := range map[string]string{
			"id": d.ID, "a": d.A, "b": d.B,
			"behaviour": d.Behaviour, "consequence": d.Consequence, "fix": d.Fix,
		} {
			if strings.TrimSpace(value) == "" {
				t.Errorf("divergence %q has an empty %s", d.ID, name)
			}
		}
	}
	if len(KnownDivergences()) != 1 {
		t.Errorf("KnownDivergences has %d rows, want 1. Adding a row is a decision, not a "+
			"maintenance step: state the consequence and the fix, then update this count. "+
			"REMOVING one is also a decision: the row that left on 2026-08-09 was "+
			"operator-value-whitespace-normalisation, closed by the gateway refusing edge "+
			"whitespace at the flag, and it became a pin rather than simply vanishing.",
			len(KnownDivergences()))
	}
}

// --- what the control plane serves --------------------------------------------
//
// The hub is a host, and it is the one whose mistakes are fleet-wide. These four
// tests hold the `the-control-plane-serves-no-key-bearing-field` pin.

// servedReference is the section a control plane emits for the reference
// operator. The two per-device values are the shape the hub allocates and mints:
// an inner address from the gateway's own space (NOT the AmneziaWG pool) and a
// second X25519 identity (NOT client_private_key).
func servedReference() map[string]string {
	return ServedWinnSection(
		Reference(),
		"lab-alpha",
		"lab-alpha",
		"10.10.0.9",
		"10.10.0.1",
		"10.10.0.1",
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x53}, 32)),
	)
}

// TestTheServedSectionCarriesEveryFieldAStandaloneStartNeeds.
//
// The defect this pins was an ABSENCE, which is the hardest kind to notice: the
// hub served a well-formed `[winn]` section that simply had none of the key
// material in it, and every engine in the tree was working. So the assertion is
// on the field set itself rather than on any value.
func TestTheServedSectionCarriesEveryFieldAStandaloneStartNeeds(t *testing.T) {
	section := servedReference()
	for _, key := range ServedWinnSectionRequiredKeys {
		if strings.TrimSpace(section[key]) == "" {
			t.Errorf("the served [winn] section carries no %q. A standalone start is "+
				"refused by name without it (WinsTunnelConfig.winn3StartRefusalReason), "+
				"and before 2026-08-09 SIX of these were missing at once — which is why "+
				"four wired platforms could not be driven by a real server config.", key)
		}
	}
	if section["carrier"] != "winn3" {
		t.Errorf("served carrier = %q, want winn3: the value must be refused nowhere, and "+
			"it was refused at BOTH supported-carrier lists until 2026-08-09",
			section["carrier"])
	}
	// The relay's parameters must NOT be here. There is no AmneziaWG engine in a
	// standalone session, and a section carrying h1..h4 is the shape that
	// selects the AmneziaWG loopback seam — the silent downgrade the carrier
	// gate exists to prevent.
	for _, key := range []string{"h1", "h2", "h3", "h4", "s1", "s2", "s3", "s4", "max_datagram"} {
		if _, present := section[key]; present {
			t.Errorf("the served standalone section carries %q, which describes a component "+
				"a standalone session does not contain", key)
		}
	}
}

// TestTheServedGatewayIDIsBase64OverTheOperatorText.
//
// Defect 1 reached through the control plane. `gateway_id` is an authenticated
// input to the admission tag and is NEVER TRANSMITTED, so nothing on the wire
// catches a disagreement: the gateway computes a different tag, drops the
// datagram, and — being a v3 gateway — answers nothing at all.
//
// The rule is exactly one decode, at the descriptor boundary in the host. The
// hub therefore ships the descriptor's base64 VERBATIM, and what it decodes to
// must be the operator's own name byte for byte.
func TestTheServedGatewayIDIsBase64OverTheOperatorText(t *testing.T) {
	o := Reference()
	section := servedReference()

	decoded, err := base64.StdEncoding.DecodeString(section["gateway_id"])
	if err != nil {
		t.Fatalf("served gateway_id is not base64: %v", err)
	}
	if !bytes.Equal(decoded, o.GatewayIDBytes()) {
		t.Fatalf("served gateway_id decodes to %q, want the operator name %q",
			decoded, o.GatewayID)
	}
	// The negative control, and it is the real one: `winsgw01` is eight
	// characters of the base64 alphabet, so serving the operator name RAW —
	// the obvious "simplification" — produces a value that decodes cleanly to
	// something else entirely, and the gateway simply never replies.
	if section["gateway_id"] == o.GatewayID {
		t.Fatal("the served gateway_id is the operator name unencoded. The host " +
			"base64-decodes this field at the descriptor boundary, so it would key with " +
			"the decode of an operator name that happens to be valid base64 — which is " +
			"defect 1 exactly, and nothing anywhere would report it.")
	}
	if wrong, err := base64.StdEncoding.DecodeString(o.GatewayID); err == nil {
		if bytes.Equal(wrong, o.GatewayIDBytes()) {
			t.Fatal("the reference operator name no longer demonstrates the trap")
		}
	}
}

// TestTheServedAdmissionKeyIsTheFileBytesNotTheDecodedSecret.
//
// Defect 4 (opaque admission secret) reached through the control plane, and it is the one that is WORSE
// than a refusal: a wrong-length admission key still passes the gateway's size
// pre-filter, a session is BUILT, and then the gateway goes completely silent.
// A host watching for "did the gateway see me" sees yes.
func TestTheServedAdmissionKeyIsTheFileBytesNotTheDecodedSecret(t *testing.T) {
	o := Reference()
	section := servedReference()

	decoded, err := base64.StdEncoding.DecodeString(section["admission_key"])
	if err != nil {
		t.Fatalf("served admission_key is not base64: %v", err)
	}
	if !bytes.Equal(decoded, o.AdmissionSecret()) {
		t.Fatalf("served admission_key carries %d bytes, want the key file's %d",
			len(decoded), len(o.AdmissionSecret()))
	}
	if len(decoded) != 64 {
		t.Fatalf("served admission_key decodes to %d bytes; keygen writes 64 ASCII hex "+
			"characters and every consumer keys with those, not with the 32 they encode",
			len(decoded))
	}
	// The negative control: base64 of the HEX-DECODED bytes. It is 32 bytes,
	// looks entirely plausible in a config, and is the exact defect.
	raw, err := hex.DecodeString(strings.TrimSpace(string(o.AdmissionSecret())))
	if err != nil {
		t.Fatalf("the reference admission file is not hex text: %v", err)
	}
	if section["admission_key"] == base64.StdEncoding.EncodeToString(raw) {
		t.Fatal("the served admission_key is base64 of the DECODED secret. The gateway " +
			"would admit the datagram, build a session, and never answer again.")
	}
	// And the trailing newline the real file carries is gone, because the rule
	// is trim \r\n and stop.
	if bytes.HasSuffix(decoded, []byte("\n")) || bytes.HasSuffix(decoded, []byte("\r")) {
		t.Fatal("the served admission_key kept the key file's trailing newline")
	}
}

// TestTheServedSectionConformsToTheCrossHostSuite.
//
// The whole point of the package, applied to the hub: a served config must
// derive BYTE-IDENTICAL admission-tag inputs and an IDENTICAL plan floor to
// every engine in the tree. This is the same MustMatch every other host runs.
func TestTheServedSectionConformsToTheCrossHostSuite(t *testing.T) {
	expected, err := Expected(Reference())
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromServedSection(
		"server/wins_control_plane_setup_ONETOUCH.sh + lib/winn_protocol_dispatch.dart"+
			":_winn3StandaloneStart",
		servedReference(),
	)
	if err != nil {
		t.Fatal(err)
	}
	got.MustMatch(t, expected)

	// A round trip against a gateway derived from the SAME operator values.
	// Compare alone proves the two structs agree; this proves a tag one seals
	// is one the other admits, which is the property users experience.
	if err := AdmissionRoundTrip(got, expected); err != nil {
		t.Fatalf("a session started from a served config would not be admitted: %v", err)
	}
}

// TestFromServedSectionConformsByRefusingAnUnknownCarrierClass is the NEEDLE
// for the served boundary's refusal of a carrier class the plan cannot express,
// with its negative control.
//
// ===========================================================================
// WHY THIS IS A NEEDLE, AND WHICH FAILURE IT HOLDS SHUT
// ===========================================================================
//
// The hub is the most dangerous host in the suite: it derives inputs for EVERY
// DEVICE AT ONCE, over the network, so one mistake there strands the fleet
// silently. Every other host derives its plan from a document an operator can
// inspect; the hub derives it for everyone, and Classes / ClassNamed /
// driver.NewSizing are the only thing that stop a served `carrier_classes`
// naming a carrier the plan cannot speak.
//
// A host that normalised an unknown class instead of refusing it would repeat
// the former empty-plan defect, where cdatapath substituted a silent {"udp"}.
// That would make this one host plan a floor nobody
// else plans, which is the silent-refusal family arriving through the hub. The
// production path already refuses: this test pins that the refusal survives to
// the served-document boundary a real host consumes, in BOTH directions.
//
//   - NEEDLE: a served section naming an unknown class must be REFUSED, and the
//     refusal must name the class.
//   - NEGATIVE CONTROL: the same-shaped sections that MUST be accepted — the
//     reference plan, and a plan carrying operator whitespace — are accepted. A
//     refusal sharp enough to catch one unknown class must not refuse the plan
//     the rest of the suite is built on, or this needle is a fixture that
//     over-refuses.
//
// Deliberate-break proof (ran with `go test -overlay`): overlay ClassNamed to
// fail OPEN — make every unknown name resolve to UDP — and the NEEDLE goes red,
// because the unknown-class section is accepted and a floor is derived; overlay
// it fail-CLOSED — make every name resolve to ClassUnknown — and the NEGATIVE
// CONTROL goes red. Either direction, a sibling that blunts the refusal turns
// this test red, which is the point of a suite that lives in the same module as
// the code it guards.
func TestFromServedSectionConformsByRefusingAnUnknownCarrierClass(t *testing.T) {
	// NEEDLE. The reference section with one carrier class swapped for a name
	// no plan can express. Operator whitespace is placed around every entry so
	// the needle and the whitespace negative control differ ONLY in the class
	// name that is invalid — nothing else moves, which is what makes the needle
	// pointed.
	unknown := servedReference()
	unknown["carrier_classes"] = " udp , tcp , icmp "

	got, err := FromServedSection(
		"a served section that names a carrier class the plan cannot express",
		unknown)
	if err == nil {
		t.Fatalf("a served section naming %q was NOT refused; it derived path_mtu=%d "+
			"classes=%v message_size=%d.\n"+
			"  This host cannot build a session for that class. If it instead silently "+
			"derived a conservative floor instead, every device it served would plan "+
			"differently from every engine in the tree and none of them would say why, "+
			"which is the silent-refusal family arriving through the hub.",
			"icmp", got.PathMTU, stringifyClasses(got.Classes), got.MessageSize)
	}
	if !strings.Contains(err.Error(), "icmp") {
		t.Errorf("the refusal does not name the offending class %q (%v); a message that "+
			"says only \"bad plan\" makes the operator hunt for the entry, which is where "+
			"the debugging cost of every silent refusal lives.", "icmp", err)
	}

	// NEGATIVE CONTROL 1 — the reference plan must still be accepted.
	if _, err := FromServedSection("the reference served section", servedReference()); err != nil {
		t.Fatalf("the reference served section was refused: %v. A refusal sharp enough "+
			"to catch one unknown class must not refuse the plan the whole suite is "+
			"built on, or this needle is really a fixture that over-refuses.", err)
	}

	// NEGATIVE CONTROL 2 — the operator-whitespace shape must be accepted. The
	// whitespace is placed EXACTLY as in the needle (around every entry, not
	// just the bad one), so the needle's refusal is provably about the class
	// name and not about the spaces — the two sections are byte-identical apart
	// from the single invalid class.
	whitespace := servedReference()
	whitespace["carrier_classes"] = " udp , tcp , tls "
	if _, err := FromServedSection("the reference plan with operator whitespace", whitespace); err != nil {
		t.Fatalf("the reference plan with operator whitespace was refused: %v. Edge "+
			"whitespace is tolerated here by design (each class is trimmed), so refusing "+
			"it would be an over-broad needle reading the whitespace as the defect.", err)
	}
}

// stringifyClasses renders a Derivation's resolved class list for a failure
// message, falling back to the raw names if the resolution is empty.
func stringifyClasses(classes []string) string {
	if len(classes) == 0 {
		return "<empty>"
	}
	return strings.Join(classes, ",")
}

// TestAServedSectionThatOmitsTheMigrationPlanIsCaught keeps the served control
// plane aligned with every shipping create path: an omitted migration plan is
// refused instead of silently becoming a UDP-only plan.
func TestAServedSectionThatOmitsTheMigrationPlanIsCaught(t *testing.T) {
	section := servedReference()
	delete(section, "carrier_classes")

	// The REFERENCE derivation refuses, exactly as driver.NewSizing and
	// cmd/winn-datapath's winn3CreateClasses do. That refusal is the correct
	// behaviour shared by driver.NewSizing and both shipping create paths.
	if _, err := FromServedSection("served config with no plan", section); err == nil {
		t.Fatal("a served config naming no carrier_classes was accepted instead of " +
			"failing closed at the control-plane boundary")
	}

	// And the cost of the substitution, stated as a number rather than argued
	// about: a udp-only plan gives a floor 84 bytes wider than udp+tcp+tls at a
	// 1500 path. A client sized that way carries small packets perfectly and
	// black-holes every full-size flow the moment the session migrates, while
	// both ends report "up".
	udpOnly := servedReference()
	udpOnly["carrier_classes"] = "udp"
	narrow, err := FromServedSection("served config with a udp-only plan", udpOnly)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := Expected(Reference())
	if err != nil {
		t.Fatal(err)
	}
	ms := Compare(narrow, expected)
	if len(ms) == 0 {
		t.Fatal("a udp-only plan produced the same floor as udp,tcp,tls; the reference " +
			"operator no longer demonstrates defect 2's gap")
	}
	if narrow.InnerMTU <= expected.InnerMTU {
		t.Fatalf("a udp-only served plan gave inner MTU %d, not WIDER than the "+
			"udp,tcp,tls floor of %d — the direction of the defect has changed and this "+
			"test is no longer measuring it", narrow.InnerMTU, expected.InnerMTU)
	}
	t.Logf("omitting the migration plan and defaulting to udp costs %d bytes of inner "+
		"MTU overshoot (%d vs %d): %s",
		narrow.InnerMTU-expected.InnerMTU, narrow.InnerMTU, expected.InnerMTU,
		Explain(narrow, expected, ms))
}

// TestTheServedFixtureIsTheOneEveryHostParses is what makes this a CROSS-HOST
// check rather than a Go one.
//
// ===========================================================================
// WHY A GREP AND NOT A CLEVERER MECHANISM
// ===========================================================================
//
// The suite's other host adapters compare DERIVATIONS: a host runs its own
// arithmetic and reports numbers. That found every encoding and sizing defect
// and could not have found the one that cost this project four platforms,
// because that one lives BEFORE the arithmetic. Android looked for
// `v3_gateway_id` in lowercase hex, Windows for a `[winn3]` section of file
// paths, and Linux had no `[winn]` reader for v3 at all. None of those hosts
// would have reached the point of computing a number, so a report-and-compare
// harness would have shown three platforms silently absent.
//
// What is needed is the DOCUMENT, byte for byte, driven through each host's own
// parser. C++ and Kotlin cannot import this package, so the fixture is a string
// literal in each host's own test — and this test greps for it. A fixture that
// drifted from the contract would otherwise make each host's test a test of
// itself: parsing a document nobody serves, and passing.
//
// The C++ tests build and RUN on the development host, so those two really do
// parse this text with the shipping parser on every run.
func TestTheServedFixtureIsTheOneEveryHostParses(t *testing.T) {
	fixture := ServedWinnSectionINI(servedReference())

	// Each host's test carries the fixture as a literal, so the comparison is on
	// the LINES rather than on the whole blob: a C++ string literal is wrapped
	// across source lines and a Kotlin one is indented. Every line has to be
	// present, in the file, verbatim.
	hosts := map[string]string{
		"windows/runner/winn3_supervisor_test.cc":                           "c++, runs on the dev host",
		"linux/runner/linux_winn3_host_test.cc":                             "c++, runs on the dev host",
		"android/app/src/test/kotlin/org/winsvpn/app/WinnV3AdoptionTest.kt": "kotlin",
	}
	root := repoRoot(t)
	for path, language := range hosts {
		raw, err := os.ReadFile(filepath.Join(root, path)) //nolint:gosec // our own tree
		if err != nil {
			t.Errorf("%s (%s) could not be read: %v. A host whose fixture cannot be "+
				"checked is a host this suite does not cover, and a green run that skipped "+
				"a platform looks exactly like one that covered it.", path, language, err)
			continue
		}
		body := string(raw)
		for _, line := range strings.Split(strings.TrimSpace(fixture), "\n") {
			// The two long base64 values are split across source lines in C++.
			// Check the KEY and the first 24 characters of the value, which is
			// far more than enough to catch a re-encoding and short enough to
			// survive a line wrap.
			probe := line
			if len(probe) > 40 {
				probe = probe[:40]
			}
			if !strings.Contains(body, probe) {
				t.Errorf("%s (%s) does not carry the served fixture line %q.\n"+
					"  Its parser is therefore being fed a document the control plane does "+
					"not emit, so that host's test proves nothing about a real server config.\n"+
					"  The contract is conform.ServedWinnSectionINI; regenerate the literal "+
					"from it rather than editing it by hand.", path, language, probe)
				break
			}
		}
	}
}

// --- the promoted posture -----------------------------------------------------
//
// ===========================================================================
// WHY THESE ARE GREPS AND NOT DERIVATIONS
// ===========================================================================
//
// Same reason TestTheServedFixtureIsTheOneEveryHostParses is a grep. The defect
// these hold shut is not an arithmetic one and no report-and-compare harness
// could have found it: a host promoting to a posture that captures nothing
// computes every number on the way there correctly. What was missing was a
// REFUSAL, and a refusal that is not there produces no number to compare.
//
// So the guards are named in conform.go, once, and each host's own file is read
// and searched for them. If somebody deletes a guard, this fails and says what
// it was for.

// requireGuards reads each named file and insists on every needle.
func requireGuards(t *testing.T, guards []PostureGuard) {
	t.Helper()
	root := repoRoot(t)
	for _, guard := range guards {
		raw, err := os.ReadFile(filepath.Join(root, guard.File)) //nolint:gosec // our own tree
		if err != nil {
			t.Errorf("%s could not be read: %v. A guard whose file cannot be checked is a "+
				"guard this suite does not cover, and a green run that skipped one looks "+
				"exactly like a run that checked it.", guard.File, err)
			continue
		}
		if !strings.Contains(string(raw), guard.Needle) {
			t.Errorf("%s no longer contains %q.\n  What it was for: %s",
				guard.File, guard.Needle, guard.Why)
		}
	}
}

// TestNoDesktopHostPromotesToAPostureThatCapturesNothing holds the route half of
// `a-promotion-that-captured-nothing-reported-success`.
func TestNoDesktopHostPromotesToAPostureThatCapturesNothing(t *testing.T) {
	requireGuards(t, StandaloneCaptureGuards)
}

// TestEnforceRoutesKeepsTheOuterSocketCarveOut holds the APPLE route half of the
// same refusal. On Apple the promoted /0 wins over the physical interface only
// because enforceRoutes is on (ruled), and the engine's own outer socket is then
// safe only because its /32 stays in NEIPv4Settings.excludedRoutes. A posture
// half of that — enforceRoutes with the /32 carve-out dropped from excludedRoutes
// — lets the promoted /0 capture the transport it dials on. No live tunnel is
// needed to hold this shut: it is asserted on the routing posture the hosts
// ship, the same way the desktop route half is.
func TestEnforceRoutesKeepsTheOuterSocketCarveOut(t *testing.T) {
	requireGuards(t, StandaloneEnforceRoutesGuards)
}

// TestNoDesktopHostPromotesWithoutMovingNameResolution holds the resolver half,
// which is the half a served config makes reachable.
//
// The `[winn]` contract has no `dns` key, so a desktop session started from one
// would widen its ROUTES onto the tunnel and leave NAME RESOLUTION pointed at
// whatever the network handed out. The /1 pair does not capture that resolver:
// the physical link's own connected prefix is more specific than /1.
func TestNoDesktopHostPromotesWithoutMovingNameResolution(t *testing.T) {
	requireGuards(t, StandaloneResolverGuards)

	// And the assertion that used to permit it must be GONE, not merely joined
	// by a better one. A suite carrying both would be green either way.
	//
	// COMMENTS ARE STRIPPED FIRST, and that is not a convenience. The C++ test
	// keeps the old assertion quoted in a comment on purpose — a defect that is
	// only described in a commit message is a defect the next reader re-argues
	// from scratch — and a guard that could not tell the record apart from the
	// code would force the record to be deleted to make the guard pass. A guard
	// looks at what executes.
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "linux/runner/winn3_posture_test.cc")) //nolint:gosec // our own tree
	if err != nil {
		t.Fatalf("linux/runner/winn3_posture_test.cc could not be read: %v", err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	// The CODE SHAPE that permitted it: a bare `Check(BuildPromotedPosture(none`
	// with no negation. The replacement is `Check(!BuildPromotedPosture(none`.
	const permissive = "Check(BuildPromotedPosture(none"
	if strings.Contains(code.String(), permissive) {
		t.Errorf("linux/runner/winn3_posture_test.cc still EXECUTES `%s…`, which asserts "+
			"that a promotion installing no resolver succeeds.\n"+
			"  That assertion WAS the defect: it pinned shut a promotion that widens the "+
			"routes onto the tunnel and leaves every DNS query going out the physical "+
			"interface in the clear, to the resolver the censor operates. A test that pins "+
			"a defect is worse than no test, because it makes the defect look considered.",
			permissive)
	}
}

// TestNoMobileHostPromotesWithAResolverItCannotJustify holds the half of the
// same row that ships to users.
//
// ===========================================================================
// WHY THIS IS A SECOND TEST AND NOT MORE NEEDLES IN THE FIRST ONE
// ===========================================================================
//
// The desktop and mobile failures are different defects wearing one name, and
// folding them together would let either be fixed while the other stayed
// broken and the suite stayed green.
//
//   - DESKTOP failed by OMISSION. A served `[winn3]` section names no resolver,
//     `dns_servers` is empty, and BuildPromotedPosture refuses. Fail-closed.
//   - MOBILE failed by COMMISSION. Both hosts reached for the resolver they had
//     — the AmneziaWG `[Interface] DNS` line — and installed it. On Apple that
//     line is filled by lib/main.dart with the PUBLIC Quad9 literals; on
//     Android it was defaulted to `10.8.1.1`, an address in the v1 inner space
//     that the winn/3 tun layer drops.
//
// The second is the worse one, and it is the one a served config makes
// reachable on the two platforms with users behind them.
//
// The needles also assert something no behavioural test on those platforms can:
// two of the Apple ones were MUTATION-TESTED on 2026-08-09 and SURVIVED being
// deleted, because the shipping builder cannot reach an input that would
// distinguish them. A grep is the only thing that can hold a line whose value
// is entirely in the edit that has not happened yet.
func TestNoMobileHostPromotesWithAResolverItCannotJustify(t *testing.T) {
	requireGuards(t, StandaloneMobileResolverGuards)

	// AND THE PREDICATE IS DERIVED, NOT TRANSPORTED. This is the clause the
	// whole row turns on, and it is checked as BYTES rather than as intent:
	// neither mobile host may read a resolver or an inner-ness claim out of the
	// document it is handed, because that document is unsigned hub output.
	//
	// It is a grep for the KEY NAMES over each host's own source, which is
	// stronger than checking the fixture: a fixture that never carries the key
	// proves nothing about a host that would happily read one if it appeared.
	root := repoRoot(t)
	mobile := map[string]string{
		"apple/WinsTunnelCore/WinsWinn3SessionStart.swift":                 "swift",
		"android/app/src/main/kotlin/org/winsvpn/app/WinnV3SessionPlan.kt": "kotlin",
		"android/app/src/main/kotlin/org/winsvpn/app/WinnV3Posture.kt":     "kotlin",
	}
	// The spellings a host would use to READ one of the forbidden keys out of
	// the served section. Quoted, because every one of these hosts looks a key
	// up by a string literal.
	forbidden := []string{
		`"dns_are_inner"`, `"dns_servers"`, `"resolvers"`,
	}
	for path, language := range mobile {
		raw, err := os.ReadFile(filepath.Join(root, path)) //nolint:gosec // our own tree
		if err != nil {
			t.Errorf("%s (%s) could not be read: %v. A host whose source cannot be checked "+
				"is a host this suite does not cover.", path, language, err)
			continue
		}
		body := string(raw)
		for _, key := range forbidden {
			if strings.Contains(body, key) {
				t.Errorf("%s (%s) reads %s out of the document it is handed.\n"+
					"  The served [winn] section is UNSIGNED hub output and the resolver "+
					"address decides where every name lookup in the session goes. A "+
					"transported boolean asserting \"this resolver is inside the tunnel\" is "+
					"unverifiable by the host receiving it -- it is the leak wearing a flag "+
					"rather than a defence against one.\n"+
					"  The predicate must be DERIVED from the two inner facts the "+
					"ML-DSA-65-signed descriptor carries, inner_v4 and inner_router_v4. If a "+
					"resolver field belongs only on the signed format-v3 DESCRIPTOR and "+
					"must remain absent from unsigned served output.", path, language, key)
			}
		}
	}

	// THE DETECTOR MUST BE ABLE TO FIRE. A forbidden-key check that cannot
	// detect a forbidden key is the same false comfort as a green run that
	// skipped a platform, so it is exercised against a file that legitimately
	// carries one: windows/runner/winn3_supervisor.h reads `dns_are_inner` out
	// of a LOCAL `[winn3]` file, which is allowed for exactly the reason it is
	// forbidden above -- somebody holding that machine wrote it, and it never
	// crosses the wire. The supervisor gates it on `!served` for that reason.
	supervisor, err := os.ReadFile( //nolint:gosec // our own tree
		filepath.Join(root, "windows/runner/winn3_supervisor.h"))
	if err != nil {
		t.Fatalf("windows/runner/winn3_supervisor.h could not be read: %v", err)
	}
	if !strings.Contains(string(supervisor), `"dns_are_inner"`) {
		t.Error("the forbidden-key detector cannot be shown to work: the one file known to " +
			"read dns_are_inner from a LOCAL section no longer contains the spelling this " +
			"test greps for, so a mobile host that grew the key would not be caught either")
	}
	if !strings.Contains(string(supervisor), `!served && key == "dns_are_inner"`) {
		t.Error("windows/runner/winn3_supervisor.h no longer gates dns_are_inner on !served.\n" +
			"  A SERVED section that could carry it would put an unverifiable claim about " +
			"where a resolver lives into unsigned hub output, which is the thing every host " +
			"in this row derives instead of accepting.")
	}

	// Neither may name the inner next hop as the resolver UNLESS THE SIGNED
	// DESCRIPTOR SAYS A RESOLVER ANSWERS THERE. Absent that signed fact the
	// address is documented as carrying PMTU signals only and the gateway behind
	// it answers no queries, so naming it is not a fix for the leak -- it is
	// total name-resolution failure wearing the fix's clothes, and it would look
	// green on every check above.
	//
	// AMENDED 2026-08-12, and the Android needle below CHANGED as part of that
	// amendment rather than being quietly dropped. The clause narrowed from "is
	// the next hop" to "is the next hop AND the descriptor names no resolver
	// there"; the Kotlin string had to re-wrap to fit inside the new `if`, which
	// broke the old needle's contiguous substring and failed this test. That
	// failure was the guard working exactly as intended -- it is the reason a
	// human is reading this paragraph -- so the needle is re-pinned to text that
	// still exists, and a SECOND needle is added below it pinning the half that
	// actually matters. Re-pinning the refusal text alone would have been the
	// weakening move: the refusal text survives every mutation that widens the
	// gate, because a gate that never fires still contains its own message.
	for _, guard := range []PostureGuard{
		{
			File:   "apple/WinsTunnelCore/WinsWinn3SessionStart.swift",
			Needle: "is [winn] inner_router_v4, which is documented as the inner next hop for PMTU signals only",
			Why:    "Apple refuses the PMTU-only next hop as a resolver, by name.",
		},
		{
			File:   "android/app/src/main/kotlin/org/winsvpn/app/WinnV3Posture.kt",
			Needle: "is the inner next hop, which is documented as carrying PMTU",
			Why:    "Android refuses the same address for the same reason.",
		},
		{
			File:   "apple/WinsTunnelCore/WinsWinn3SessionStart.swift",
			Needle: "The signed descriptor does not name a resolver there",
			Why: "the refusal SAYS WHY it still applies. An operator who has stood a " +
				"resolver up and re-signed reads this and learns their descriptor is not " +
				"carrying the field, rather than re-reading a sentence about PMTU that " +
				"stopped being the whole story.",
		},
		{
			File:   "android/app/src/main/kotlin/org/winsvpn/app/WinnV3Posture.kt",
			Needle: "The signed descriptor does not name a",
			Why:    "the same diagnostic on Android, wrapped across two Kotlin string parts.",
		},
	} {
		requireGuards(t, []PostureGuard{guard})
	}

	// AND THE NARROWING IS CONDITIONAL ON A SIGNED FACT ON BOTH HOSTS.
	//
	// Held separately from the message needles above because the two fail in
	// opposite directions and folding them would hide that. A message needle
	// catches the clause being DELETED; this catches the clause being WIDENED --
	// the `if advertised...` condition removed so the next hop is accepted as a
	// resolver on every configuration, signed fact or not. That mutation leaves
	// every string above intact and every other needle in this file matching,
	// and it is the one that ships a green promotion pointing at an address
	// where nothing is listening.
	requireGuards(t, StandaloneResolverStagingGuards)
}

// TestAStandalonePromotedRouteSetIsDerivedAndKeepsTheNextHop holds
// `promotion-discarded-the-bootstraps-only-route` AND states the decision: a
// standalone session's routes are DERIVED, so the served contract must never
// grow a key for them.
func TestAStandalonePromotedRouteSetIsDerivedAndKeepsTheNextHop(t *testing.T) {
	// The contract, as bytes. Nothing route-shaped or resolver-shaped may appear
	// in the document a host is actually handed.
	fixture := ServedWinnSectionINI(servedReference())
	for _, key := range ServedWinnSectionCarriesNoPostureKey {
		if strings.Contains(fixture, "\n"+key+" =") {
			t.Errorf("the served [winn] document now carries a %q key.\n"+
				"  Routes are DERIVED — the promoted posture takes the default route "+
				"unconditionally, so a served route key could only ever ADD capture while "+
				"handing the decision that moves a user's traffic to unsigned hub output.\n"+
				"  A RESOLVER belongs in the ML-DSA-65-signed descriptor, beside "+
				"inner_router_v4, for the same reason inverted: it decides where every name "+
				"lookup goes and the section is not signed.\n"+
				"  The signed format-v3 descriptor is the canonical resolver source; "+
				"unsigned served output must not override it.", key)
		}
	}
	for _, key := range ServedWinnSectionCarriesNoPostureKey {
		for _, ordered := range ServedWinnSectionKeyOrder {
			if ordered == key {
				t.Errorf("ServedWinnSectionKeyOrder names %q, so a caller could emit it and "+
					"every host would parse it", key)
			}
		}
	}

	// The one address a standalone promoted route set IS derived from is already
	// in the contract and is required, so the derivation can never be handed
	// nothing.
	section := servedReference()
	if strings.TrimSpace(section["inner_router_v4"]) == "" {
		t.Fatal("the served section carries no inner_router_v4, which is the ONLY address a " +
			"standalone promoted route set is derived from")
	}
	required := false
	for _, key := range ServedWinnSectionRequiredKeys {
		if key == "inner_router_v4" {
			required = true
		}
	}
	if !required {
		t.Error("inner_router_v4 is not in ServedWinnSectionRequiredKeys. It is the inner " +
			"next hop, the one route a bootstrap posture installs, and the route the " +
			"promoted posture keeps — a session that starts without it promotes to the /1 " +
			"pair and nothing else.")
	}

	// And the host-side fix: a union rather than an assignment.
	requireGuards(t, StandaloneRouteDerivationGuards)
}

// TestTheLinuxServedParserHasACaller holds the second row's re-characterisation.
//
// The ORDER is checked, not just the presence: the v3 branch has to come before
// the winn/1 predicate, exactly as windows_tunnel_backend.cpp branches on
// ConfigSelectsWinn3 before reaching ParseWinn3Section. Two parsers that can
// both claim one document is how a standalone session silently becomes a relay.
func TestTheLinuxServedParserHasACaller(t *testing.T) {
	requireGuards(t, StandaloneLinuxCallerGuards)

	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "linux/runner/linux_tunnel_backend.cc")) //nolint:gosec // our own tree
	if err != nil {
		t.Fatalf("linux/runner/linux_tunnel_backend.cc could not be read: %v", err)
	}
	body := string(raw)
	const branch = "if (winsvpn::winn3host::LinuxConfigSelectsWinn3(raw_config)) {"
	const relay = "winsvpn::winn::LinuxConfigSelectsWinnProtocol(raw_config)"
	at, relayAt := strings.Index(body, branch), strings.Index(body, relay)
	if at < 0 {
		t.Fatalf("linux_tunnel_backend.cc no longer branches on LinuxConfigSelectsWinn3")
	}
	if relayAt < 0 {
		t.Fatalf("linux_tunnel_backend.cc no longer consults the winn/1 predicate at all, " +
			"which is a bigger change than this test was written for")
	}
	if at > relayAt {
		t.Errorf("the standalone v3 branch (offset %d) comes AFTER the winn/1 predicate "+
			"(offset %d).\n"+
			"  A served `carrier = winn3` document would then be claimed by the AmneziaWG "+
			"relay parser first. It fails closed there, but it fails in the relay's words "+
			"about a protocol it was not asked to speak — and the whole point of the branch "+
			"is that the two parsers can never both claim one document.", at, relayAt)
	}
}

// repoRoot walks up from this package to the repository root — the directory
// holding both `winn_protocol_experimental` and the host trees.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir := engineRoot(t)
	return filepath.Dir(dir)
}

// TestEveryHostDefaultsAMissingPathMTUToTheSameNumber holds the Android
// path-MTU pin.
//
// A served `[winn]` section carries `path_mtu` only when an operator set one,
// so "no path_mtu" is the case that actually happens rather than an edge. Two
// hosts defaulting differently is defect 3 arriving by DEFAULT rather than by
// configuration, and it lands in the WIDE mismatch regime — where the session
// never carries at all.
func TestEveryHostDefaultsAMissingPathMTUToTheSameNumber(t *testing.T) {
	section := servedReference()
	delete(section, "path_mtu")
	got, err := FromServedSection("a served section naming no path_mtu", section)
	if err != nil {
		t.Fatal(err)
	}
	if got.PathMTU != DefaultPathMTU {
		t.Fatalf("a served section with no path_mtu resolved to %d, want %d",
			got.PathMTU, DefaultPathMTU)
	}

	// The number the Kotlin host must agree on, stated here so a change to
	// either side fails rather than drifts.
	//
	// RESTATED 2026-08-10. It was 1139, the floor at the old 1280 default, and
	// 1139 is below RFC 8200's 1280 — which is the whole reason the default
	// moved: at that floor no host could put inner IPv6 on the interface, so
	// every default session sat in the dead zone. At 1450 the floor is 1309 and
	// inner IPv6 becomes possible with 29 bytes to spare.
	//
	// windows/runner/winn3_supervisor.h's kShippingFloorInnerMTU states the
	// same number and moved with it.
	if got.InnerMTU != 1309 {
		t.Fatalf("the plan floor at the default path MTU is %d, want 1309 — the number "+
			"windows/runner's kShippingFloorInnerMTU also states", got.InnerMTU)
	}
	if got.InnerMTU < tun.IPv6MinLinkMTU {
		t.Fatalf("the plan floor at the FLEET DEFAULT is %d, below RFC 8200's %d. A host on "+
			"the default cannot put inner IPv6 on its interface — ipv6_add_dev() returns "+
			"-EINVAL — so it resolves, bootstraps, carries and can never promote. That is "+
			"the dead zone, and defaulting into it is what 2026-08-10 fixed.",
			got.InnerMTU, tun.IPv6MinLinkMTU)
	}
	wide, err := FromServedSection("a host defaulting to 1500", servedReference())
	if err != nil {
		t.Fatal(err)
	}
	if wide.InnerMTU-got.InnerMTU != 50 {
		t.Fatalf("the gap between a 1500-byte and a %d-byte plan is %d bytes, not the 50 the "+
			"fleet default concedes. It was 220 while the default was 1280; if the "+
			"arithmetic changed again, restate the pin's symptom with the new number "+
			"rather than deleting it",
			DefaultPathMTU, wide.InnerMTU-got.InnerMTU)
	}
}

// TestTheFleetDefaultFloorCarriesAFullSizeInnerUnfragmented is the path-MTU
// floor needle for the 2026-08-10 fleet default raise to 1450.
//
// ===========================================================================
// WHAT "WITHOUT FRAGMENTATION" MEANS HERE
// ===========================================================================
//
// The whole reason the fleet default moved 1280 -> 1450 was that the OLD floor
// (1139) sat BELOW RFC 8200's 1280, so no host on the default could place inner
// IPv6 on its interface and every default session ended in the dead zone: it
// resolved, bootstrapped, carried, and could never promote, while both ends
// reported `carrying` — defect #3's exact symptom, innocent until the raise.
//
// The raise is only SAFE if the new floor still keeps a full-size inner packet
// unfragmented on the path: a max-size Winn3 message, wrapped in the widest
// carrier overhead the plan may migrate to, must still fit within
// DefaultPathMTU. If it did not, raising the default would convert #3's
// cannot-promote blocker into a cannot-connect one — the WIDE mismatch regime
// that black-holes full-size flows at the first migration while the tunnel
// reads up at both ends. This needle is what makes that regression loud.
func TestTheFleetDefaultFloorCarriesAFullSizeInnerUnfragmented(t *testing.T) {
	// The premise the whole needle sits on. If the fleet default moves again,
	// this fails with the new number in the message and the floor's other
	// symptoms must be restated rather than silently re-pinned.
	if DefaultPathMTU != 1450 {
		t.Fatalf("this needle's premise is gone: the fleet default is %d, not 1450. The "+
			"test exists to pin the 1450 path-MTU floor; if the default moved again "+
			"deliberately, restate the floor's symptom with the new number rather than "+
			"deleting the needle.", DefaultPathMTU)
	}

	// The reference plan (udp+tcp+tls) at the FLEET DEFAULT. This is the floor
	// the whole fleet resolves to when nobody overrides path_mtu, so it is the
	// one that has to be provably unfragmented.
	row, err := Floor(Reference().CarrierClasses, DefaultPathMTU)
	if err != nil {
		t.Fatal(err)
	}
	if row.MessageSize <= session.MessageFloor() || row.InnerMTU <= 0 {
		t.Fatalf("the %d-byte fleet-default floor is clamped or empty (message %d, inner %d); "+
			"\"without fragmentation\" is meaningless for a plan that cannot carry a full "+
			"packet. The 130-byte row is the one that may clamp; the FLEET DEFAULT may not.",
			DefaultPathMTU, row.MessageSize, row.InnerMTU)
	}

	// A full-size inner packet — the whole corridor up to inner MTU — must fit
	// the path wrapped in EVERY carrier the reference plan may migrate to, or it
	// is fragmented on the wire. Fragmentation is the thing a v3 tunnel must
	// never do: a fragmented Winn3 message is a distinctive fingerprint and
	// fragments are widely dropped. If the floor drifted such that any
	// reachable carrier overshoots the path, this goes red naming the class.
	classes, err := Classes(Reference().CarrierClasses)
	if err != nil {
		t.Fatal(err)
	}
	for _, class := range classes {
		for _, family := range []carrier.Family{carrier.FamilyIPv4, carrier.FamilyIPv6} {
			if outer := carrier.Overhead(class, family) + row.MessageSize; outer > DefaultPathMTU {
				t.Errorf("a full-size inner over %v/%v is %d bytes, %d past the %d-byte path "+
					"— it would be fragmented or dropped while the tunnel reports carrying. "+
					"Raising the default to 1450 was only safe while the floor still fits.",
					class, family, outer, outer-DefaultPathMTU, DefaultPathMTU)
			}
		}
	}

	// And the dead-zone clause, which is why the number had to be 1450 at all:
	// the floor must clear RFC 8200's 1280 so a default session can place inner
	// IPv6. A default whose floor cannot carry inner IPv6 is back in the
	// cannot-promote dead zone #3 sat in before 2026-08-10.
	if row.InnerMTU < tun.IPv6MinLinkMTU {
		t.Fatalf("the fleet-default floor inner MTU %d sits below RFC 8200's %d; a session "+
			"on the default cannot promote, which is exactly the dead zone the raise to "+
			"%d was supposed to leave.", row.InnerMTU, tun.IPv6MinLinkMTU, DefaultPathMTU)
	}
	if !row.InnerIPv6 {
		t.Fatalf("the fleet-default floor is not InnerIPv6; the machine cannot install the " +
			"inner address it would need to carry.")
	}
}

// --- the regression pins ------------------------------------------------------

// TestEveryPinNamesATestThatExists is what stops the pin table becoming
// decoration.
//
// A pin claims a fixed defect is held closed by named tests. If one of those
// tests is renamed or deleted, the claim silently becomes false and the defect
// can return with the table still cheerfully asserting it cannot. So the claim
// is CHECKED: every name in HeldBy must be a real func in a real _test.go under
// the engine tree.
//
// It is the same discipline the suite applies to the hosts. A comment saying
// two things agree is worth less than a test that fails when they do not, and a
// table saying four defects are pinned is worth less than a test that fails
// when a pin's test is gone.
func TestEveryPinNamesATestThatExists(t *testing.T) {
	root := engineRoot(t)
	bodies := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable directory is not this test's business
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), "_test.go") ||
			strings.HasPrefix(d.Name(), "._") {
			return nil
		}
		raw, readErr := os.ReadFile(path) //nolint:gosec // walking our own tree
		if readErr != nil {
			return nil
		}
		for _, m := range testFuncRe.FindAllStringSubmatch(string(raw), -1) {
			bodies[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bodies) == 0 {
		t.Fatal("found no test functions at all; this check would pass vacuously")
	}

	for _, pin := range RegressionPins() {
		if len(pin.HeldBy) == 0 {
			t.Errorf("pin %q names no test. A pin nothing holds is a comment.", pin.ID)
		}
		for _, name := range pin.HeldBy {
			if !bodies[name] {
				t.Errorf("pin %q claims to be held by %s, and no such test exists in the "+
					"engine tree. Either the test was renamed — in which case update the pin — "+
					"or it was deleted, in which case the defect this pin describes can come "+
					"back and nothing will notice.\n  defect:  %s\n  symptom: %s",
					pin.ID, name, pin.Defect, pin.Symptom)
			}
		}
	}
}

var testFuncRe = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]*)\(`)

// engineRoot walks up from this package to winn_protocol_experimental.
func engineRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the engine module root from the conform package")
	return ""
}

// TestEveryPinIsFullyStated. A pin with no symptom is a pin nobody can
// recognise from a bug report, which is the only situation one gets read in.
func TestEveryPinIsFullyStated(t *testing.T) {
	seen := map[string]bool{}
	for _, pin := range RegressionPins() {
		if seen[pin.ID] {
			t.Errorf("duplicate pin id %q", pin.ID)
		}
		seen[pin.ID] = true
		for name, value := range map[string]string{
			"id": pin.ID, "defect": pin.Defect, "symptom": pin.Symptom, "fixed_on": pin.FixedOn,
		} {
			if strings.TrimSpace(value) == "" {
				t.Errorf("pin %q has an empty %s", pin.ID, name)
			}
		}
	}
	if len(RegressionPins()) != 17 {
		t.Errorf("RegressionPins has %d rows, want 17 (gateway_id encoding, the plan-floor "+
			"inner MTU, admission-secret opacity, the gateway honouring its own -path-mtu, "+
			"the served config's key names, the control plane serving no key-bearing field, "+
			"the Android path-MTU default, a promotion that captured nothing reporting "+
			"success, promotion discarding the bootstrap's only route, the gate-state "+
			"vocabulary crossing the host boundary by convention, configuration validated "+
			"later than the operator was standing there, a preflight that restates rules "+
			"instead of running them, operator-value whitespace refused at the flag, a "+
			"path-MTU mismatch that established and then black-holed in silence, the "+
			"path-MTU notice's seven-byte on-wire record, the promotion predicate reading "+
			"RxPackets rather than RxOffered, and an unauthenticated datagram getting no "+
			"byte back). Adding a row is a decision: state the symptom as it appeared "+
			"from OUTSIDE, name the tests that hold it, then update this count.",
			len(RegressionPins()))
	}
}

// TestPinsAndDivergencesAreDisjoint.
//
// The two tables mean opposite things — a pin is fixed and its return fails the
// build, a divergence is unfixed and is measured debt — so an id in both is a
// contradiction about whether something is broken right now.
func TestPinsAndDivergencesAreDisjoint(t *testing.T) {
	pins := map[string]bool{}
	for _, p := range RegressionPins() {
		pins[p.ID] = true
	}
	for _, d := range KnownDivergences() {
		if pins[d.ID] {
			t.Errorf("%q is both a regression pin (fixed, must not return) and a known "+
				"divergence (unfixed, tracked). It cannot be both.", d.ID)
		}
	}
}

// --- the vector file ----------------------------------------------------------

// TestTheVectorFileCarriesTheWrongAnswersBesideTheRightOnes.
func TestTheVectorFileCarriesTheWrongAnswersBesideTheRightOnes(t *testing.T) {
	v, err := BuildVectors(Reference())
	if err != nil {
		t.Fatal(err)
	}
	if v.Admission.GatewayIDHex == v.Admission.GatewayIDBase64Decoded {
		t.Fatal("the vector file's right and wrong gateway id are the same value")
	}
	if v.Admission.AdmissionKeyHex == v.Admission.AdmissionIfHexDecoded {
		t.Fatal("the vector file's right and wrong admission key are the same value")
	}
	if v.Constants.Overhead != 29 {
		t.Fatalf("tun.Overhead() is %d, want 29 — the constant WinnV3Sizing.OVERHEAD mirrors",
			v.Constants.Overhead)
	}
	if len(v.Floors) == 0 || len(v.Overheads) != 6 || len(v.Demux) != 4 {
		t.Fatalf("vectors are incomplete: %d floors, %d overheads, %d demux",
			len(v.Floors), len(v.Overheads), len(v.Demux))
	}
	b, err := v.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(b, []byte("\n")) {
		t.Error("the vector file does not end in a newline")
	}
}

// --- helpers ------------------------------------------------------------------

// establish drives a real handshake to a pair of live sessions using only
// exported core API.
func establish(t *testing.T) (client, gateway *core.Session) {
	t.Helper()
	op := Reference()
	cfg := core.Config{Gateway: core.GatewayParams{
		AdmissionKeys: [][]byte{op.AdmissionSecret()},
		GatewayID:     op.GatewayIDBytes(),
	}}

	gwStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	gwPublic, err := core.NewPublicKey(gwStatic.Public())
	if err != nil {
		t.Fatal(err)
	}
	cliStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}

	initiator, err := core.NewInitiator(cfg, cliStatic, gwPublic)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := core.NewResponder(cfg, gwStatic, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}

	initiation, err := initiator.WriteInitiation(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	handshake, err := responder.ReadInitiation(initiation)
	if err != nil {
		t.Fatal(err)
	}
	response, gwSession, err := handshake.WriteResponse(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	cliSession, _, err := initiator.ReadResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	return cliSession, gwSession
}

// Recorder is a Reporter that collects failures, so the negative controls can
// assert MustMatch really fails rather than trusting Compare.
type Recorder struct{ Failures []string }

func (r *Recorder) Helper() {}
func (r *Recorder) Errorf(format string, args ...any) {
	r.Failures = append(r.Failures, fmt.Sprintf(format, args...))
}

// TestMustMatchActuallyFails: the check the whole suite is built on.
func TestMustMatchActuallyFails(t *testing.T) {
	a, err := Expected(Reference())
	if err != nil {
		t.Fatal(err)
	}
	var rec Recorder
	a.MustMatch(&rec, a)
	if len(rec.Failures) != 0 {
		t.Fatalf("MustMatch failed on two identical derivations: %v", rec.Failures)
	}
	b := a
	b.InnerMTU = 1443
	a.MustMatch(&rec, b)
	if len(rec.Failures) != 1 {
		t.Fatalf("MustMatch reported %d failures on a 1443-vs-1359 inner MTU, want 1", len(rec.Failures))
	}
}

// --- the gate-state vocabulary ------------------------------------------------

// TestTheGateStateVocabularyIsTheSameOnEveryHost holds the seventh
// silent-refusal defect shut, in BOTH directions.
//
// ===========================================================================
// WHY BOTH DIRECTIONS, AND WHY A NEEDLE LIST ALONE IS HALF A GUARD
// ===========================================================================
//
// The needles in [GateStateVocabularyGuards] are built from the names
// winn3/tun emits, so a rename in gate.go rewrites them and every host still
// carrying the old spelling fails. That is the Go→host direction and it is the
// one that matters most, because one edit in one Go file silently disarms four
// platforms at once.
//
// It is not sufficient. A needle asks "does this file contain this text", and
// a host that swapped its literal for a DIFFERENT valid name — `rekeying`, say
// — still contains the word `carrying` in the comment above it. So the value
// each host actually ASSIGNS is extracted from its own source and compared. A
// host edit fails too, and it fails naming the host.
//
// Neither half is a behavioural test and neither can be. `gate_state` crosses
// a process boundary between a Go engine and a Kotlin, Swift or C++ host; no
// `go test` can execute the other side, and every host test that exists feeds
// its own literal into its own parser — which is exactly how five call sites
// came to agree with themselves and with nothing else. Reading the hosts'
// source is what the `[winn]` key-name contract does for the same reason, and
// this is that mechanism pointed at this seam.
func TestTheGateStateVocabularyIsTheSameOnEveryHost(t *testing.T) {
	// The suite must not be able to pass by having nothing to check.
	vocab := GateStateVocabulary()
	if len(vocab) != 6 {
		t.Fatalf("winn3/tun declares %d states, want 6. If that was deliberate, every host "+
			"below needs the new name and this number needs updating — in that order.",
			len(vocab))
	}
	carrying := GateStateCarryingName()
	if carrying == "" || carrying == GateStateUnknownName() {
		t.Fatalf("the carrying name is %q, which cannot be right", carrying)
	}
	names := map[string]bool{}
	carriers := 0
	for _, entry := range vocab {
		if entry.Name == "" {
			t.Fatalf("State(%d) has no name", entry.Ordinal)
		}
		if names[entry.Name] {
			t.Fatalf("two states are named %q, so a host cannot parse it unambiguously",
				entry.Name)
		}
		names[entry.Name] = true
		if entry.MayCarry {
			carriers++
			if entry.Name != carrying {
				t.Fatalf("State(%d) %q carries but is not GateStateCarryingName() %q",
					entry.Ordinal, entry.Name, carrying)
			}
		}
	}
	if carriers != 1 {
		t.Fatalf("%d states carry, want exactly 1. Every host implements \"carrying\" as "+
			"equality against ONE name; a second carrying state would make all four of them "+
			"wrong at once and none of them would report it.", carriers)
	}
	if len(GateStateHostVocabularies) == 0 {
		t.Fatal("no host vocabularies are listed, so this test would pass vacuously")
	}

	// DIRECTION 1 — Go is the source of truth, and each host is required to
	// carry what Go emits.
	requireGuards(t, GateStateVocabularyGuards())

	// DIRECTION 2 — the value each host ASSIGNS is extracted and compared.
	root := repoRoot(t)
	for _, host := range GateStateHostVocabularies {
		raw, err := os.ReadFile(filepath.Join(root, host.File)) //nolint:gosec // our own tree
		if err != nil {
			t.Errorf("%s (%s) could not be read: %v.\n  A host whose vocabulary cannot be "+
				"checked is a host this contract does not cover, and a green run that skipped "+
				"a platform looks exactly like one that covered it.",
				host.File, host.Language, err)
			continue
		}
		body := string(raw)
		block, ok := spanBetween(body, host.DeclPrefix, host.DeclSuffix)
		if !ok {
			t.Errorf("%s (%s) no longer declares its gate-state vocabulary where this "+
				"contract looks for it (between %q and %q).\n"+
				"  What this host's copy is for: %s\n"+
				"  If the declaration moved, move GateStateHostVocabularies with it. Deleting "+
				"the row instead would leave the platform unchecked while the suite stayed "+
				"green.",
				host.File, host.Language, host.DeclPrefix, host.DeclSuffix, host.Why)
			continue
		}

		if !host.Full {
			// A single-name host. The extracted literal must BE the Go name.
			if block != carrying {
				t.Errorf("%s (%s) compares gate_state against %q; winn3/tun emits %q.\n"+
					"  MISMATCH. This host will never see the name the engine publishes, so "+
					"mayCarry() is false forever and the session holds the bootstrap posture "+
					"while handshaking, rekeying and moving bytes exactly as designed. Nothing "+
					"logs it, and a v3 gateway answers no unauthenticated datagram, so from "+
					"the user's side it is the censor.\n"+
					"  What this host's copy is for: %s\n"+
					"  winn3/tun.State.String() is the source of truth. Change it there and "+
					"every host here, or change nothing.",
					host.File, host.Language, block, carrying, host.Why)
			}
			continue
		}

		// A full-vocabulary host. Every wire name it declares must be one Go
		// emits, and every name Go emits must be one it declares.
		caseRe := regexp.MustCompile(host.CasePattern)
		declared := map[string]string{} // wire name -> host's own case name
		byCase := map[string]string{}   // host case name -> wire name
		for _, m := range caseRe.FindAllStringSubmatch(block, -1) {
			if prior, dup := declared[m[2]]; dup {
				t.Errorf("%s (%s) declares the wire name %q twice, as %s and %s",
					host.File, host.Language, m[2], prior, m[1])
			}
			declared[m[2]] = m[1]
			byCase[m[1]] = m[2]
		}
		if len(declared) == 0 {
			t.Errorf("%s (%s): the vocabulary block matched but no cases were extracted "+
				"from it, so this check would pass vacuously. Pattern: %s",
				host.File, host.Language, host.CasePattern)
			continue
		}
		var missing, extra []string
		for _, entry := range vocab {
			if _, ok := declared[entry.Name]; !ok {
				missing = append(missing, entry.Name)
			}
		}
		for name := range declared {
			if !names[name] {
				extra = append(extra, name)
			}
		}
		sort.Strings(missing)
		sort.Strings(extra)
		if len(missing) > 0 {
			t.Errorf("%s (%s) does not declare the gate_state name(s) %v that winn3/tun "+
				"emits.\n"+
				"  MISMATCH. fromWire returns null for a name the enum does not carry, and "+
				"null is not carrying — so a session that reaches one of these states is a "+
				"session this host will never promote.\n"+
				"  What this host's copy is for: %s",
				host.File, host.Language, missing, host.Why)
		}
		if len(extra) > 0 {
			t.Errorf("%s (%s) declares the gate_state name(s) %v, which winn3/tun does NOT "+
				"emit.\n"+
				"  Either the host is holding a stale spelling — in which case the state it "+
				"stands for is unreachable and the host silently never promotes — or a state "+
				"was added on the host side that Go does not have, which is a vocabulary this "+
				"seam has two versions of.\n"+
				"  winn3/tun.State.String() is the source of truth.",
				host.File, host.Language, extra)
		}

		// And the case this host treats as carrying must map to the Go
		// carrying name. A host can hold every name correctly and still gate on
		// the wrong one.
		clauseRe := regexp.MustCompile(host.CarryingClausePattern)
		clause := clauseRe.FindStringSubmatch(block)
		if clause == nil {
			// The clause lives outside the enum's case block on Kotlin, so look
			// at the whole file before giving up.
			clause = clauseRe.FindStringSubmatch(body)
		}
		if clause == nil {
			t.Errorf("%s (%s): no clause matching %s says which case carries, so nothing "+
				"here checks that this host gates on the right one",
				host.File, host.Language, host.CarryingClausePattern)
			continue
		}
		if got := byCase[clause[1]]; got != carrying {
			t.Errorf("%s (%s) treats %s as the carrying state, whose wire name is %q; "+
				"winn3/tun carries on %q.\n"+
				"  MISMATCH. This host would promote on the wrong state, or on none.",
				host.File, host.Language, clause[1], got, carrying)
		}

		// AND ITS PARSE MUST NOT DEFAULT.
		//
		// This is the clause a needle could not hold, and mutation testing on
		// 2026-08-09 is how that was found: the needle
		// `return entries.firstOrNull { it.wire == t }` is a PREFIX of the
		// fail-open version `… ?: CARRYING`, so appending an elvis left the
		// grep perfectly green while turning the one host that parses the whole
		// vocabulary into a host that promotes on any name at all — including a
		// name Go renamed out from under it, which is the exact defect this
		// contract exists to stop.
		//
		// So the parse function's BODY is read and any defaulting operator in
		// it is refused. `?: null` would be harmless and is still refused: a
		// parser with no default cannot acquire a bad one by edit.
		if host.ParseFunc != "" {
			parse, found := kotlinFunctionBody(body, host.ParseFunc)
			if !found {
				t.Errorf("%s (%s) no longer declares %q, so nothing here checks that an "+
					"unrecognised gate_state fails closed", host.File, host.Language,
					host.ParseFunc)
			} else if strings.Contains(parse, "?:") {
				t.Errorf("%s (%s): %s DEFAULTS — its body contains an elvis operator.\n"+
					"  %s\n"+
					"  A defaulting parse is the shape that fails OPEN. `?: %s` would promote "+
					"the tunnel on a name nothing recognised, which is what a rename on the Go "+
					"side looks like from here. The parse must return null and the caller must "+
					"read null as not carrying.\n"+
					"  body:\n%s",
					host.File, host.Language, host.ParseFunc, host.Why,
					strings.ToUpper(carrying), parse)
			}
		}
	}

	// The generated artifact carries the same vocabulary, so a non-Go harness
	// reading `winn3-conformance -emit` gets it from the code that defines it.
	doc := GateStateVocabularyDocument()
	for _, entry := range vocab {
		if !strings.Contains(doc, "\t"+entry.Name+"\t") {
			t.Errorf("the emitted vocabulary document does not name %q", entry.Name)
		}
	}
	if !strings.Contains(doc, "\t"+carrying+"\tcarries\n") {
		t.Errorf("the emitted vocabulary document does not mark %q as the carrying name",
			carrying)
	}
	if !strings.Contains(doc, "\t"+GateStateUnknownName()+"\tsentinel-never-a-state\n") {
		t.Errorf("the emitted vocabulary document does not mark %q as the sentinel",
			GateStateUnknownName())
	}
	vectors, err := BuildVectors(Reference())
	if err != nil {
		t.Fatal(err)
	}
	if vectors.GateStateCarry != carrying || len(vectors.GateStates) != len(vocab) ||
		vectors.GateStateDocument != doc {
		t.Errorf("the emitted vectors do not carry the gate-state vocabulary: carry=%q "+
			"states=%d", vectors.GateStateCarry, len(vectors.GateStates))
	}
}

func TestDevicecheckRefusesAmbientAndroidConformanceSources(t *testing.T) {
	const generatedPrefix = "android/devicecheck/app/src/main/kotlin/org/winsvpn/app/"
	for _, host := range GateStateHostVocabularies {
		if strings.HasPrefix(filepath.ToSlash(host.File), generatedPrefix) {
			t.Fatalf("generated devicecheck source is a gate-state authority: %s", host.File)
		}
	}
	for _, guard := range GateStateVocabularyGuards() {
		if strings.HasPrefix(filepath.ToSlash(guard.File), generatedPrefix) {
			t.Fatalf("generated devicecheck source is a gate-state guard: %s", guard.File)
		}
	}
	for _, decl := range InnerBlockMaskDeclarations {
		if strings.HasPrefix(filepath.ToSlash(decl.File), generatedPrefix) {
			t.Fatalf("generated devicecheck source is a block-mask authority: %s", decl.File)
		}
	}

	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "android/devicecheck/build_devicecheck.sh"))
	if err != nil {
		t.Fatalf("devicecheck generator could not be read: %v", err)
	}
	script := string(raw)
	for _, needle := range []string{
		`SOURCE_AUTHORITY_ROOT="/Library/WinsVPN/ReleaseAndroidSource/devicecheck-v3"`,
		`SOURCE_CUSTODY_CONTRACT="winsvpn-devicecheck-source-custody-v2"`,
		`SOURCE_CONSUMER_STATUS="unintegrated"`,
		`"${RELEASE_PYTHON}" -I -S /dev/fd/11 gate`,
		"OWNER-BLOCKED: immutable compiler-input handoff is not implemented",
	} {
		if !strings.Contains(script, needle) {
			t.Errorf("devicecheck generator no longer enforces authenticated source custody: missing %q", needle)
		}
	}
	for _, forbidden := range []string{
		`cp "${SRC}/WinnV3Bridge.kt"`,
		`cp "${SRC}/${name}" "${DST}/${name}"`,
		`SOURCE_CONSUMER_STATUS="integrated"`,
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("devicecheck generator regained an ambient or falsely integrated source path: %q", forbidden)
		}
	}
}

// TestTheGateStateExtractorCanActuallyFail is the control for the test above.
//
// A cross-host check that cannot detect a divergence is the same false comfort
// as a green run that skipped a platform, and this suite has been bitten by
// exactly that shape before — see the forbidden-key detector's own control in
// TestNoMobileHostPromotesWithAResolverItCannotJustify. So the extractor is
// run against synthetic sources that carry a WRONG vocabulary, and it must say
// so.
func TestTheGateStateExtractorCanActuallyFail(t *testing.T) {
	// A single-name host whose literal drifted. Note the comment still says
	// `carrying`, which is why `strings.Contains` over the file is not enough
	// and the value has to be extracted.
	const driftedSwift = `
  /// The only value of winn3_gate_state that carries. It is
  /// winn3/tun.StateCarrying.String() — "carrying".
  static let carryingState = "conveying"
`
	got, ok := spanBetween(driftedSwift, "static let carryingState = \"", "\"")
	if !ok {
		t.Fatal("the extractor could not find a declaration it is pointed straight at, so a " +
			"real host's drift would be reported as a missing declaration rather than as a " +
			"mismatch")
	}
	if got != "conveying" {
		t.Fatalf("the extractor read %q from a source that assigns \"conveying\"", got)
	}
	if got == GateStateCarryingName() {
		t.Fatal("the extractor returned the Go name for a source that does not contain it, " +
			"which means the comparison above can never fail")
	}
	if strings.Contains(driftedSwift, GateStateCarryingName()) != true {
		t.Fatal("this fixture was supposed to keep the word `carrying` in a COMMENT, so it " +
			"demonstrates why a Contains check would have passed it")
	}

	// A full-vocabulary host that lost a name and gained one Go does not emit.
	const driftedKotlin = `internal enum class WinnV3GateState(val wire: String) {
    DOWN("down"),
    EPOCH0("epoch0"),
    HANDSHAKING("handshaking"),
    REKEYING("rekeying"),
    CONVEYING("conveying"),
    CLOSED("closed"),
    ;
    fun mayCarry(): Boolean = this == CONVEYING
`
	block, ok := spanBetween(driftedKotlin,
		"internal enum class WinnV3GateState(val wire: String) {", "\n    ;")
	if !ok {
		t.Fatal("the Kotlin vocabulary block could not be extracted from a source shaped " +
			"exactly like the real one")
	}
	caseRe := regexp.MustCompile(`([A-Z][A-Z0-9_]*)\("([^"]*)"\)`)
	found := map[string]bool{}
	for _, m := range caseRe.FindAllStringSubmatch(block, -1) {
		found[m[2]] = true
	}
	if len(found) != 6 {
		t.Fatalf("extracted %d cases from the drifted enum, want 6", len(found))
	}
	if found[GateStateCarryingName()] {
		t.Fatalf("the drifted fixture still declares %q, so it does not demonstrate a "+
			"detectable divergence", GateStateCarryingName())
	}
	if !found["conveying"] {
		t.Fatal("the extractor did not see the drifted name, so an added host-side name " +
			"would go unreported")
	}

	// And the REAL hosts must not look like the drifted fixtures — i.e. the
	// check above is green because the tree agrees, not because it is blind.
	root := repoRoot(t)
	for _, host := range GateStateHostVocabularies {
		raw, err := os.ReadFile(filepath.Join(root, host.File)) //nolint:gosec // our own tree
		if err != nil {
			t.Errorf("%s could not be read: %v", host.File, err)
			continue
		}
		if _, ok := spanBetween(string(raw), host.DeclPrefix, host.DeclSuffix); !ok {
			t.Errorf("%s: the extractor finds no declaration, so its agreement with Go is "+
				"unproven rather than true", host.File)
		}
	}
}

// TestNoOtherHostFileHoldsAGateStateLiteral. The contract covers the call sites
// it knows about; a SIXTH copy appearing somewhere else would be outside it and
// the suite would stay green.
//
// So the host trees are swept for the carrying name spelled as a quoted
// literal, and every occurrence must be in a file this contract names. Test
// sources are exempt: a host test SHOULD carry the literal, because that is how
// it exercises its own parser.
func TestNoOtherHostFileHoldsAGateStateLiteral(t *testing.T) {
	root := repoRoot(t)
	quoted := `"` + GateStateCarryingName() + `"`

	// An OCCURRENCE COUNT, not a file allow-list.
	//
	// The allow-list this replaced exempted a whole file because the contract
	// named it once. Mutation testing on 2026-08-09 added a second, unpinned
	// literal to linux_winn3_host.cc — a file the contract already covered for
	// its use of the shared constant — and the sweep SURVIVED it. A file is
	// covered for the occurrences the contract accounts for and no more.
	//
	// "Accounted for" is computed from the needles themselves, so it maintains
	// itself: a guard that stops containing the literal stops paying for one.
	accounted := map[string]int{}
	for _, guard := range GateStateVocabularyGuards() {
		accounted[filepath.Clean(guard.File)] += strings.Count(guard.Needle, quoted)
	}

	trees := []string{
		"android/app/src/main",
		"android/devicecheck/app/src/main/kotlin/org/winsvpn/devicecheck",
		"windows/runner", "linux/runner",
		"apple/WinsTunnelCore", "apple/EngineWrappers",
		"winn_protocol_experimental/cdatapath",
	}
	scanned := 0
	for _, tree := range trees {
		base := filepath.Join(root, tree)
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil //nolint:nilerr // an unreadable directory is not this test's business
			}
			name := d.Name()
			if d.IsDir() {
				if name == "build" || name == ".build" || name == ".gradle" {
					return filepath.SkipDir
				}
				return nil
			}
			// AppleDouble sidecars and every .bak_* snapshot are not code.
			if strings.HasPrefix(name, "._") || strings.Contains(name, ".bak") {
				return nil
			}
			switch filepath.Ext(name) {
			case ".kt", ".swift", ".h", ".cc", ".cpp", ".m", ".mm":
			default:
				return nil
			}
			if strings.Contains(name, "Test") || strings.Contains(name, "_test.") {
				return nil
			}
			raw, readErr := os.ReadFile(path) //nolint:gosec // walking our own tree
			if readErr != nil {
				return nil
			}
			scanned++
			found := strings.Count(string(raw), quoted)
			if found == 0 {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			clean := filepath.Clean(rel)
			if found <= accounted[clean] {
				return nil
			}
			t.Errorf("%s holds %d occurrence(s) of the gate-state literal %s; this contract "+
				"accounts for %d.\n"+
				"  The unaccounted one is a hand-copied spelling of a string winn3/tun owns, "+
				"outside the contract that keeps the others honest. A rename in gate.go would "+
				"leave it stale, whatever compares against it would never match, and the thing "+
				"it gates would silently stop happening — with no test in any language going "+
				"red.\n"+
				"  Either consume the constant the platform already has — Linux does this via "+
				"winsvpn::winn3::kCarryingGate, which is why linux_winn3_host.cc holds no "+
				"literal at all — or add a needle to GateStateVocabularyGuards() built from "+
				"GateStateCarryingName(), so the new site goes red with everything else.",
				rel, found, quoted, accounted[clean])
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned == 0 {
		t.Fatal("no host sources were scanned, so this sweep would pass vacuously")
	}
}

// kotlinFunctionBody returns the lines of the function opened by decl, up to
// the first line whose trimmed content is exactly "}".
//
// Deliberately indentation-INDEPENDENT. A span keyed on "\n        }" would
// break the moment a sibling lane reindented the file, and a check that breaks
// on formatting is a check somebody deletes.
func kotlinFunctionBody(body, decl string) (string, bool) {
	at := strings.Index(body, decl)
	if at < 0 {
		return "", false
	}
	var out []string
	for _, line := range strings.Split(body[at:], "\n") {
		if strings.TrimSpace(line) == "}" {
			return strings.Join(out, "\n"), true
		}
		out = append(out, line)
	}
	return "", false
}

// spanBetween returns the text between the first occurrence of prefix and the
// next occurrence of suffix after it.
func spanBetween(body, prefix, suffix string) (string, bool) {
	at := strings.Index(body, prefix)
	if at < 0 {
		return "", false
	}
	rest := body[at+len(prefix):]
	end := strings.Index(rest, suffix)
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

// --- the inner-resolver /24 block mask ----------------------------------------

// innerMaskLiteralRe matches ONE integer literal as C++, Swift or Kotlin spell
// it: hex with an optional `_` group separator in any case, or plain decimal.
// Type suffixes (`u`, `L`, `UL`) sit outside the match and are ignored — they
// are the language's business, not the number's.
//
// NOTE THE ABSENCE OF A TRAILING \b, which is not an oversight. It was there
// first, and mutation testing on 2026-08-12 caught it: a suffixed DECIMAL like
// `4294967040u` has no word boundary between its last digit and its suffix, so
// the pattern matched nothing at all and the extractor reported "0 literals" —
// a red run, but for the wrong reason, blaming a missing declaration for a
// legal respelling of the right number. A leading \b is enough to keep the
// digits of an identifier (`uint32_t`, `UInt32`) from being read as a literal.
var innerMaskLiteralRe = regexp.MustCompile(`0[xX][0-9A-Fa-f_]+|\b\d[\d_]*`)

// parseInnerMaskLiteral turns one literal into its value.
//
// ===========================================================================
// WHY THIS NORMALISES INSTEAD OF PINNING A SPELLING
// ===========================================================================
//
// A DELIBERATE MISS, and it is worth being explicit about which way it cuts.
// `0xFFFFFF00`, `0xffffff00`, `0xFFFF_FF00`, `0xFFFFFF00L` and `4294967040` all
// parse to the same number here and all pass. This contract is about the /24
// floor, not about typography: the three families already spell it three
// different ways because three languages have three conventions, and a fourth
// convention arriving is not a defect. A check that went red when a lane
// lowercased a hex digit would be a check somebody switches off, and the file
// it lives in has already been through that once (see the 2026-08-12 amendment
// on the Android resolver needle).
//
// What it buys is strictly more than a literal grep would: a mutation is caught
// by its VALUE however it is written, where a grep for `0xFFFFFF00` is blind to
// `0xffffff00` arriving next to a changed number, and blind to a comment that
// carries the string the declaration no longer does.
//
// The one form it gives up on is a COMPUTED mask — `~0xFFu`, `0xFFFFFFFFu << 8`.
// That fails LOUDLY rather than silently, because the literal count stops
// matching, and the failure says to restate the literal or teach this parser.
// Deleting the row is the one response that is not available.
func parseInnerMaskLiteral(text string) (uint32, error) {
	clean := strings.ReplaceAll(text, "_", "")
	base, digits := 10, clean
	if len(clean) > 2 && (clean[:2] == "0x" || clean[:2] == "0X") {
		base, digits = 16, clean[2:]
	}
	value, err := strconv.ParseUint(digits, base, 32)
	if err != nil {
		return 0, fmt.Errorf("%q is not a 32-bit integer literal this contract can read "+
			"(hex or decimal, `_` separators and type suffixes allowed): %w", text, err)
	}
	return uint32(value), nil
}

// extractInnerBlockMask reads ONE family's mask out of a source body.
//
// It refuses rather than guesses, in every way a source can stop being
// readable, because each of those ways is a real defect wearing an
// unreadability costume:
//
//   - the declaration MISSING — the family stopped deriving, or moved, and a
//     contract that shrugged would leave a platform uncovered while staying
//     green, which is the failure mode this whole package exists to name;
//   - the declaration occurring TWICE — a second copy inside one file, which an
//     extractor that took the first match would read straight past;
//   - the wrong NUMBER of literals — `(a & MASK) == b` drops the mask from one
//     operand, leaves a perfectly correct literal in the file, and turns a
//     block comparison into an equality that admits exactly one address;
//   - the two literals DISAGREEING — the half-mutation's other shape, where
//     each operand is masked to a different block and no single value exists to
//     compare with anybody.
func extractInnerBlockMask(decl InnerBlockMaskDeclaration, body string) (uint32, string, error) {
	if n := strings.Count(body, decl.Decl); n != 1 {
		return 0, "", fmt.Errorf("%q occurs %d times, want exactly 1", decl.Decl, n)
	}
	span, ok := spanBetween(body, decl.Decl, decl.Terminator)
	if !ok {
		return 0, "", fmt.Errorf("the declaration %q is not terminated by %q, so there is "+
			"nothing to read", decl.Decl, decl.Terminator)
	}
	raw := innerMaskLiteralRe.FindAllString(span, -1)
	if len(raw) != decl.Literals {
		return 0, "", fmt.Errorf("the declaration holds %d integer literal(s) %q, want exactly "+
			"%d. Span: %q", len(raw), raw, decl.Literals, span)
	}
	var first uint32
	for i, text := range raw {
		value, err := parseInnerMaskLiteral(text)
		if err != nil {
			return 0, "", err
		}
		if i == 0 {
			first = value
			continue
		}
		if value != first {
			return 0, "", fmt.Errorf("the declaration masks its operands with DIFFERENT values, "+
				"%s (0x%08X) and %s (0x%08X). One address can then be inside the block by one "+
				"operand's reckoning and outside it by the other's, which is not a floor at all",
				raw[0], first, text, value)
		}
	}
	return first, strings.Join(raw, " "), nil
}

// TestTheInnerResolverBlockMaskIsTheSameInEveryClientFamily is the cross-family
// pin on the /24 inner-resolver floor.
//
// ===========================================================================
// WHAT IT HOLDS THAT NOTHING ELSE COULD
// ===========================================================================
//
// Three client families decide "is this resolver INSIDE my tunnel" by masking
// the candidate and their own signed inner assignment to a block and comparing.
// The block is a /24 in all three and it is hard-coded in all three, because the
// descriptor carries the assignment as a bare address with no prefix. They share
// no code: C++ names the constant, Swift and Kotlin inline it twice each.
//
// Until this test, nothing made them agree. linux/runner/winn3_posture_test.cc
// pinned the C++ side on 2026-08-12 and said in its own comment that it could
// do no better, because a C++ program cannot read a .swift or a .kt file. So
// the divergence this catches is the one where ONE family's floor moves — say
// to a /16 for a hub whose pool spilled past its first /24 — and the other two
// stay. Both platforms then read the SAME signed descriptor and give DIFFERENT
// answers about the same resolver, and the one that widened accepts a resolver
// sitting in another tenant's block. Nothing logs a disagreement, because
// neither platform can see the other.
//
// It is not a behavioural test and cannot be. The seam is three source files in
// three languages that no single process ever loads.
func TestTheInnerResolverBlockMaskIsTheSameInEveryClientFamily(t *testing.T) {
	// The contract must not be able to pass by covering nothing, and "all three
	// families" is checked rather than assumed. A table that lost its Swift row
	// would still agree with itself.
	covered := map[string]bool{}
	for _, decl := range InnerBlockMaskDeclarations {
		switch filepath.Ext(decl.File) {
		case ".h", ".cc", ".cpp":
			covered["c++"] = true
		case ".swift":
			covered["swift"] = true
		case ".kt":
			covered["kotlin"] = true
		}
	}
	for _, family := range []string{"c++", "swift", "kotlin"} {
		if !covered[family] {
			t.Fatalf("InnerBlockMaskDeclarations names no %s declaration. A family missing from "+
				"the table is a family this contract does not cover, and a green run that "+
				"skipped one looks exactly like a run that checked it.", family)
		}
	}

	// THE REFERENCE MUST BE A MASK, AND MUST NOT HAVE BEEN WIDENED.
	//
	// SameInnerBlock is a REFUSAL predicate, so the two directions are not
	// symmetric. Narrowing over-refuses — the operator's own resolver stops
	// being derivable, which is loud and safe. WIDENING accepts addresses
	// outside the signed inner block, which is the leak. So the reference is
	// checked to be a contiguous prefix mask no wider than a /24: the obvious
	// way to make a future red run green is to widen this constant until both
	// sides agree, and that is weakening the gate rather than fixing the drift.
	if inverted := ^InnerResolverBlockMask; inverted&(inverted+1) != 0 {
		t.Fatalf("InnerResolverBlockMask 0x%08X is not a contiguous prefix mask, so it does not "+
			"describe a block at all", InnerResolverBlockMask)
	}
	if got := bits.OnesCount32(InnerResolverBlockMask); got != InnerResolverBlockPrefixLen {
		t.Fatalf("InnerResolverBlockMask 0x%08X is a /%d, but InnerResolverBlockPrefixLen says "+
			"/%d. The gateway states this constant as a prefix length and the clients state it "+
			"as a mask; the two spellings of one number have drifted inside this file.",
			InnerResolverBlockMask, got, InnerResolverBlockPrefixLen)
	}
	if InnerResolverBlockPrefixLen < 24 {
		t.Fatalf("InnerResolverBlockPrefixLen is /%d, WIDER than the /24 floor every client "+
			"family derives against.\n"+
			"  Widening is the unsafe direction: a wider block calls more candidates \"inside "+
			"my tunnel\", so a resolver in another tenant's /24 off the same signed descriptor "+
			"is accepted. Narrowing only ever over-refuses.\n"+
			"  If a red run was made green by widening this, that is the gate being weakened "+
			"rather than the drift being fixed.", InnerResolverBlockPrefixLen)
	}

	// WHAT EACH FAMILY ACTUALLY DECLARES, EXTRACTED.
	root := repoRoot(t)
	values := map[string]uint32{}
	raws := map[string]string{}
	languages := map[string]string{}
	for _, decl := range InnerBlockMaskDeclarations {
		raw, err := os.ReadFile(filepath.Join(root, decl.File)) //nolint:gosec // our own tree
		if err != nil {
			t.Errorf("%s (%s) could not be read: %v.\n  A family whose declaration cannot be "+
				"checked is a family this contract does not cover.", decl.File, decl.Language, err)
			continue
		}
		value, text, err := extractInnerBlockMask(decl, string(raw))
		if err != nil {
			t.Errorf("%s (%s): the /24 floor is no longer where this contract looks for it.\n"+
				"  %v\n"+
				"  What this declaration is for: %s\n"+
				"  If it moved or was respelled, move InnerBlockMaskDeclarations with it — "+
				"deleting the row would leave the family unchecked while the suite stayed green, "+
				"and this contract exists because that is precisely what nothing noticed before.",
				decl.File, decl.Language, err, decl.Why)
			continue
		}
		values[decl.File] = value
		raws[decl.File] = text
		languages[decl.File] = decl.Language
	}
	if len(values) == 0 {
		t.Fatal("no declaration could be extracted from any family, so the comparison below " +
			"would pass vacuously")
	}

	var moved, agreed []string
	for file, value := range values {
		if value == InnerResolverBlockMask {
			agreed = append(agreed, file)
			continue
		}
		moved = append(moved, file)
	}
	sort.Strings(moved)
	sort.Strings(agreed)

	switch {
	case len(moved) == 0:
		// Every family agrees with the reference and therefore with each other.

	case len(moved) == len(values):
		// EVERY family moved together. That is a deliberate prefix change, not a
		// drift, and it fails anyway — the same way the fleet-default path-MTU
		// needle fails when its premise moves. A constant this contract states
		// rather than derives has to be re-stated by a person, or it is a rubber
		// stamp that re-points itself to whatever the tree happens to say.
		t.Errorf("EVERY client family now declares 0x%08X (was 0x%08X, a /%d).\n"+
			"  They still agree with each other, so this is a deliberate prefix change rather "+
			"than a drift — and it is exactly the change that has to be written down. Restate "+
			"InnerResolverBlockMask and InnerResolverBlockPrefixLen here, and check the "+
			"consequence the gateway's resolverDerivationWarning describes: the hub allocates "+
			"inner addresses out of WINN3_INNER_POOL_CIDR, and a floor NARROWER than that pool "+
			"strands every client the pool allocates outside the first block, with a refusal "+
			"that says nothing about allocation order because nothing on the client knows "+
			"about allocation order.\n"+
			"  Widening instead of narrowing is the direction that leaks; see the safe-direction "+
			"check above.",
			values[moved[0]], InnerResolverBlockMask, InnerResolverBlockPrefixLen)

	default:
		// THE DIVERGENCE. One or more families moved and the others did not.
		for _, file := range moved {
			t.Errorf("%s (%s) masks the inner block with %s (0x%08X); %v declare(s) 0x%08X.\n"+
				"  DIVERGENCE, and it is invisible from either side. These families share no "+
				"code and no process — a C++ program cannot read a .swift or a .kt file — so "+
				"both platforms read the SAME ML-DSA-65-signed descriptor and give DIFFERENT "+
				"answers about the SAME resolver, and neither can see the other's answer.\n"+
				"  The wider floor is the one that leaks: it calls a resolver in another "+
				"tenant's block \"inside my tunnel\" and installs it. The narrower one refuses "+
				"a resolver the operator legitimately stood up, and says nothing about why the "+
				"other platform accepted it.\n"+
				"  What this declaration is for: %s\n"+
				"  Move all of them or none of them.",
				file, languages[file], raws[file], values[file], agreed, InnerResolverBlockMask,
				func() string {
					for _, decl := range InnerBlockMaskDeclarations {
						if decl.File == file {
							return decl.Why
						}
					}
					return "(no row)"
				}())
		}
	}

	// AND THE PROSE, which extraction cannot see. Four files state this number
	// without declaring it, and a number that moves in five declarations while
	// staying in four explanations is how the next author writes a sixth copy
	// correctly-according-to-the-docs and is wrong.
	requireGuards(t, InnerBlockMaskGuards())
}

// TestTheInnerBlockMaskExtractorCanActuallyFail is the control for the test
// above.
//
// A cross-family check that cannot detect a divergence is the same false
// comfort as a green run that skipped a platform, and this suite has been bitten
// by exactly that shape twice — see the forbidden-key detector's own control in
// TestNoMobileHostPromotesWithAResolverItCannotJustify, and
// TestTheGateStateExtractorCanActuallyFail. So the extractor is run against
// synthetic sources carrying each mutation it is supposed to catch, and it must
// say so.
func TestTheInnerBlockMaskExtractorCanActuallyFail(t *testing.T) {
	cpp := InnerBlockMaskDeclaration{
		Language: "c++", Decl: "inline constexpr uint32_t kInnerBlockMask =",
		Terminator: ";", Literals: 1,
	}
	swift := InnerBlockMaskDeclaration{
		Language: "swift", Decl: "static func sameInnerBlock(_ a: UInt32, _ b: UInt32) -> Bool {",
		Terminator: "}", Literals: 2,
	}
	kotlin := InnerBlockMaskDeclaration{
		Language: "kotlin", Decl: "fun sameInnerBlock(a: Long, b: Long): Boolean =",
		Terminator: "\n", Literals: 2,
	}

	// ===========================================================================
	// 1. THE MUTATION A grep COULD NOT HAVE CAUGHT
	// ===========================================================================
	//
	// This is not a hypothetical fixture. The shipping header states the number
	// in prose twice, in every family's spelling, in the paragraph directly
	// above the declaration — so a strings.Contains needle stays green while the
	// declaration says something else entirely. That fact is what decided this
	// contract's mechanism.
	const driftedCpp = `
// because the mobile clients derive against a hard 0xFFFFFF00 floor; desktop
// kInnerBlockMask is the /24 floor, and it is the same constant Apple spells
// ` + "`0xFFFF_FF00`" + ` and Android spells ` + "`0xFFFFFF00L`" + `. It is named rather than
inline constexpr uint32_t kInnerBlockMask = 0xFFFF0000u;
`
	got, _, err := extractInnerBlockMask(cpp, driftedCpp)
	if err != nil {
		t.Fatalf("the extractor could not read a declaration it is pointed straight at (%v), so "+
			"a real family's drift would be reported as a missing declaration rather than as a "+
			"mismatch", err)
	}
	if got != 0xFFFF0000 {
		t.Fatalf("the extractor read 0x%08X from a source that assigns 0xFFFF0000", got)
	}
	if got == InnerResolverBlockMask {
		t.Fatal("the extractor returned the reference value for a source that does not declare " +
			"it, which means the comparison in the test above can never fail")
	}
	if !strings.Contains(driftedCpp, "0xFFFFFF00") {
		t.Fatal("this fixture was supposed to keep the reference spelling in a COMMENT, so it " +
			"demonstrates why a Contains check would have passed a mutated declaration")
	}
	// And the SHIPPING header really is shaped that way — the fixture is a copy
	// of a real hazard, not an invented one. If the prose above the declaration
	// were ever tidied away this control would be arguing from a file that no
	// longer exists, which is worth knowing.
	root := repoRoot(t)
	header, err := os.ReadFile(filepath.Join(root, "windows/runner/winn3_posture.h")) //nolint:gosec // our own tree
	if err != nil {
		t.Fatalf("windows/runner/winn3_posture.h could not be read: %v", err)
	}
	if before, _, ok := strings.Cut(string(header),
		"inline constexpr uint32_t kInnerBlockMask ="); !ok || !strings.Contains(before, "0xFFFFFF00") {
		t.Error("windows/runner/winn3_posture.h no longer states the mask in prose ABOVE its " +
			"declaration. That prose is why this contract extracts the value instead of grepping " +
			"for it; if it is gone, the reasoning in InnerBlockMaskDeclarations' comment should " +
			"be restated rather than left citing a file that stopped demonstrating it.")
	}

	// ===========================================================================
	// 2. THE HALF-MUTATION — one operand loses its mask
	// ===========================================================================
	//
	// Every literal in the file is still correct. What changed is that a block
	// comparison became an equality, so the only "same block" address is the
	// assignment itself and the operator's own resolver is refused. The literal
	// COUNT is the only thing that sees this.
	const halfMaskedSwift = `
  static func sameInnerBlock(_ a: UInt32, _ b: UInt32) -> Bool {
    (a & 0xFFFF_FF00) == b
  }
`
	if _, _, err := extractInnerBlockMask(swift, halfMaskedSwift); err == nil {
		t.Error("the extractor accepted a body that masks only ONE operand. `(a & MASK) == b` " +
			"leaves a correct literal in the file and turns the block test into an equality, so " +
			"nothing but the literal count can notice it")
	}

	// ===========================================================================
	// 3. TWO OPERANDS, TWO DIFFERENT BLOCKS
	// ===========================================================================
	const splitKotlin = `
    fun sameInnerBlock(a: Long, b: Long): Boolean = (a and 0xFFFFFF00L) == (b and 0xFFFF0000L)
`
	if _, _, err := extractInnerBlockMask(kotlin, splitKotlin); err == nil {
		t.Error("the extractor accepted a declaration whose two operands are masked to " +
			"DIFFERENT blocks, so one address could be inside by one reckoning and outside by " +
			"the other")
	}

	// ===========================================================================
	// 4. A SECOND DECLARATION IN THE SAME FILE
	// ===========================================================================
	//
	// The defect this whole contract is about, arriving inside one family. An
	// extractor that took the first match would read past it and report
	// agreement.
	const twiceKotlin = `
    fun sameInnerBlock(a: Long, b: Long): Boolean = (a and 0xFFFFFF00L) == (b and 0xFFFFFF00L)
    fun sameInnerBlock(a: Long, b: Long): Boolean = (a and 0xFFFF0000L) == (b and 0xFFFF0000L)
`
	if _, _, err := extractInnerBlockMask(kotlin, twiceKotlin); err == nil {
		t.Error("the extractor accepted a file carrying TWO declarations of the same predicate, " +
			"and would have reported the first one's value as the family's answer")
	}

	// ===========================================================================
	// 5. A COMPUTED MASK FAILS LOUDLY RATHER THAN SILENTLY
	// ===========================================================================
	//
	// The one form the normaliser gives up on. It must be a red run with a
	// message, never a quiet pass.
	const computedCpp = `
inline constexpr uint32_t kInnerBlockMask = 0xFFFFFFFFu << 8;
`
	if _, _, err := extractInnerBlockMask(cpp, computedCpp); err == nil {
		t.Error("a COMPUTED mask was accepted. This parser reads literals; an expression it " +
			"cannot evaluate has to fail so somebody restates the literal or teaches the parser, " +
			"rather than passing on a number nobody checked")
	}

	// ===========================================================================
	// 6. THE SPELLINGS THAT MUST STILL PASS
	// ===========================================================================
	//
	// The deliberate miss, asserted so it stays deliberate. These are all the
	// same number and this contract is about the number.
	//
	// The SUFFIXED DECIMAL in this list is here because it was the one that got
	// away. Mutation testing on 2026-08-12 respelled the C++ declaration as
	// `4294967040u` and the extractor reported zero literals — the fixture below
	// had only ever tried the bare `4294967040`, where the terminating `;`
	// supplied the word boundary the pattern was wrongly relying on. A control
	// that only tests the easy spellings is a control that certifies a bug.
	for _, spelling := range []string{
		"0xFFFFFF00u", "0xffffff00", "0xFFFF_FF00", "0xFFFFFF00L", "0xffffff00UL",
		"4294967040", "4294967040u",
	} {
		value, _, err := extractInnerBlockMask(cpp,
			"inline constexpr uint32_t kInnerBlockMask = "+spelling+";")
		if err != nil {
			t.Errorf("the spelling %s was refused (%v). A family respelling the SAME number is "+
				"not a defect, and a check that goes red on typography is a check somebody "+
				"switches off", spelling, err)
			continue
		}
		if value != InnerResolverBlockMask {
			t.Errorf("the spelling %s parsed to 0x%08X, not the reference 0x%08X",
				spelling, value, InnerResolverBlockMask)
		}
	}

	// ===========================================================================
	// 7. AND THE REAL FAMILIES MUST STILL BE READABLE
	// ===========================================================================
	//
	// i.e. the test above is green because the tree agrees, not because it is
	// blind.
	for _, decl := range InnerBlockMaskDeclarations {
		raw, err := os.ReadFile(filepath.Join(root, decl.File)) //nolint:gosec // our own tree
		if err != nil {
			t.Errorf("%s could not be read: %v", decl.File, err)
			continue
		}
		if _, _, err := extractInnerBlockMask(decl, string(raw)); err != nil {
			t.Errorf("%s: the extractor finds no readable declaration (%v), so this family's "+
				"agreement with the others is UNPROVEN rather than true", decl.File, err)
		}
	}
}

// --- the host report round-trip ----------------------------------------------
//
// report.go is the CROSS-HOST half of this suite. A NON-GO host cannot import
// Go, so it runs its own real derivation code and emits the answer as a JSON
// HostReport; report.go then parses that document (ParseHostReport) and
// compares it to the reference vectors (VerifyReport). The whole design is
// conditional on that machinery being honest: a host that cannot be parsed, or
// whose wrong answer elides a mismatch, would make the conformance run green
// while the platform silently disagrees with the wire.
//
// TestReportProducesAValidConformanceReport is the suite's OWN check on that
// machinery. It feeds report.go a sample winn/3 configuration — the reference
// operator (carrier =  udp+tcp+tls) with the carrier/stealth fields a real
// winn/3 carrier document requires — derives the report object a host would
// emit for it, round-trips it through report.go, and asserts the object is
// valid AND that malformed or wrong reports are refused. Named Test* so
// `-run Report` actually executes it; a bare `ReportTest` would match nothing
// and report "no tests to run" with a zero exit — a green that asserts nothing.
func TestReportProducesAValidConformanceReport(t *testing.T) {
	op := Reference()
	v, err := BuildVectors(op)
	if err != nil {
		t.Fatal(err)
	}

	// The reference plan's own floor is the one correct answer the sample
	// config's carrier (udp+tcp+tls) admits. If the matrix no longer carries a
	// row for it, there is no correct report to build and this test must say so
	// rather than quietly agree by accident.
	ref, ok := referenceRow(v)
	if !ok || ref.MessageSize == 0 {
		t.Fatal("the conformance matrix has no floor for the reference carrier plan; " +
			"a correct host report cannot be derived without one")
	}

	// This is exactly what a host harness emits: every field filled from the
	// reference vectors it was handed.
	correct := HostReport{
		Host:                      "sample-winn3-host",
		Language:                  "go-test",
		GatewayIDHex:              v.Admission.GatewayIDHex,
		AdmissionKeyHex:           v.Admission.AdmissionKeyHex,
		TagSize:                   v.Admission.TagSize,
		PathMTU:                   v.Operator.PathMTU,
		CarrierClasses:            append([]string(nil), v.Operator.CarrierClasses...),
		MessageSize:               ref.MessageSize,
		InnerMTU:                  ref.InnerMTU,
		InnerIPv6:                 ref.InnerIPv6,
		TransportObservedBothWays: true,
		Floors:                    v.Floors,
		Overheads:                 v.Overheads,
	}

	raw, err := json.Marshal(correct)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseHostReport(raw)
	if err != nil {
		t.Fatalf("a correct report must parse into a valid conformance report object: %v", err)
	}

	// The report object must round-trip the field this configuration is named
	// by — its carrier. A report whose carrier does not match the sample plan
	// is not a report about the winn/3 config this suite serves.
	if strings.Join(parsed.CarrierClasses, "+") != strings.Join(op.CarrierClasses, "+") {
		t.Fatalf("the parsed report carries plan %v, want the reference carrier plan %v",
			parsed.CarrierClasses, v.Operator.CarrierClasses)
	}

	// A report holding the reference numbers must verify clean: zero mismatches
	// is what makes a host "conformant".
	if ms := VerifyReport(v, parsed); len(ms) != 0 {
		t.Fatalf("the reference report must verify clean against its own vectors; got %d "+
			"mismatch(es):\n%s", len(ms), ExplainReport(v, parsed, ms))
	}

	// The carrier/stealth REQUIRED FIELDS exist at the winn/3 carrier document
	// the engines consume, independent of any host. The sample configuration is
	// not fully a winn/3 config until its emission names protocol_version,
	// carrier and stealth — the same three keys TestConfigEmitWinn3CarrierINI
	// pins — so this report is a report about a real winn/3 carrier, not about a
	// bare number table.
	requiresCarrierStealth := func(doc string, required ...string) {
		t.Helper()
		for _, line := range required {
			if !strings.Contains(doc, line+"\n") {
				t.Errorf("required winn/3 carrier field %q is missing from the sample emission:\n%s",
					line, doc)
			}
		}
	}
	requiresCarrierStealth(
		renderWinn3SampleProduct(t),
		"protocol_version=winn/3",
		"carrier=udp",
		"stealth=true",
	)

	// ---- the negative controls: a report we cannot trust to fail is a report ----
	// ---- we cannot trust to pass                                              ----

	// A host that narrowed the carrier must not verify clean: VerifyReport must
	// name the disagreement, or a platform shipping the wrong plan floors
	// reports green.
	badCarrier := correct
	badCarrier.CarrierClasses = []string{"udp"}
	rawBad, err := json.Marshal(badCarrier)
	if err != nil {
		t.Fatal(err)
	}
	parsedBad, err := ParseHostReport(rawBad)
	if err != nil {
		t.Fatalf("a report with a wrong-but-parseable carrier must parse (so that "+
			"VerifyReport can then reject it), got: %v", err)
	}
	if ms := VerifyReport(v, parsedBad); len(ms) == 0 {
		t.Fatal("a report that narrowed the reference carrier must not verify clean; " +
			"VerifyReport returned no mismatch")
	}

	// A report that claims to observe transport in only one direction must
	// not verify clean: the promotion predicate gates on RxPackets (inbound),
	// and a document that carries the inbound counter without the outbound one
	// leaves a host unable to tell "data went in and came back" from "inbound
	// only". VerifyReport must name the omission.
	oneDirection := correct
	oneDirection.TransportObservedBothWays = false
	rawOne, err := json.Marshal(oneDirection)
	if err != nil {
		t.Fatal(err)
	}
	parsedOne, err := ParseHostReport(rawOne)
	if err != nil {
		t.Fatalf("a report with transport_observed_both_ways=false must parse: %v", err)
	}
	if ms := VerifyReport(v, parsedOne); len(ms) == 0 {
		t.Fatal("a report that observes transport in only one direction must not verify " +
			"clean; VerifyReport returned no mismatch for transport_observed_both_ways")
	}

	// Any report object must still fail REQUIRED-field checks even when correct,
	// so a correct report cannot be an empty shell. This asserts the negative of
	// the positive above: proof is inverted, not assumed.
	if ms := VerifyReport(v, HostReport{}); len(ms) == 0 {
		t.Fatal("an empty HostReport must fail verification; VerifyReport returned no mismatch")
	}

	// ParseHostReport must refuse a misspelled key. A harness that emits a field
	// nobody compares would otherwise report a value nobody checked, which is the
	// silent-success failure ParseHostReport's DisallowUnknownFields exists to
	// remove.
	unknown := []byte(`{"host":"h","language":"go","carrier_classes":["udp"],"not_a_real_field":1}`)
	if _, err := ParseHostReport(unknown); err == nil {
		t.Fatal("ParseHostReport accepted a JSON document carrying an unknown field; " +
			"a misspelled key must be refused, not silently ignored")
	}

	// And a report that names no host is not a report about any platform.
	if _, err := ParseHostReport([]byte(`{"language":"go"}`)); err == nil {
		t.Fatal("a report that names no host must be refused")
	}
}

// renderWinn3SampleProduct emits a sample `[winn/3]` carrier document for the
// test, deriving it from a real session Config rather than pasting a constant
// (a constant emission is what TestConfigEmitWinn3CarrierINI is written to
// catch).
func renderWinn3SampleProduct(t *testing.T) string {
	t.Helper()
	static, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &session.Config{
		Static:         static,
		MaxMessageSize: 1168,
		Padding:        core.PadBucket,
	}
	return cfg.EmitWinn3INI(session.CarrierUDP, true)
}

// --- pins added 2026-08-11 (ds_conformpins) ------------------------------

// TestThePathMTUNoticeWireRecordIsSevenExactBytes pins the ON-WIRE record of
// the path-MTU notice, the responder's half of silent-refusal instance #3.
//
// The refusal half is pinned by TestAPathMTUMismatchRefusesTheSessionLoudly
// and its family; this pins the RECORD itself. That distinction is the whole
// point: the register is written and read by the SAME package
// (winn3/session/pathmtu.go's EncodePathMTUNotice and DecodePathMTUNotice), so
// a sibling that flips the byte order from BigEndian to LittleEndian in BOTH
// halves stays green forever — encode-then-decode round trips cannot see a
// self-consistent change. Only the conform suite, which holds the responder's
// EXACT bytes, can make a wire change a decision.
func TestThePathMTUNoticeWireRecordIsSevenExactBytes(t *testing.T) {
	// 1500 decimal = 0x05DC, so the exact seven bytes are
	//   'W' '3' 'P' 'M'  0x01  0x05  0xDC
	//   magic             ver   mtu big-endian
	got := session.EncodePathMTUNotice(1500)
	want := []byte{'W', '3', 'P', 'M', 0x01, 0x05, 0xDC}
	if len(got) != len(want) {
		t.Fatalf("EncodePathMTUNotice(1500) is %d bytes (% x), want %d", len(got), got, len(want))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodePathMTUNotice(1500) = % x, want % x. The wire record is not the "+
			"seven exact big-endian bytes the cross-implementation contract depends on; "+
			"a byte-order flip in both halves of pathmtu.go passes every round-trip test "+
			"and this one exists to catch exactly that.", got, want)
	}

	// The decoder must read back the same record and only that record.
	if mtu, ok := session.DecodePathMTUNotice(got); !ok || mtu != 1500 {
		t.Fatalf("DecodePathMTUNotice(record) = (%d, %v), want (1500, true)", mtu, ok)
	}

	// A foreign magic must read as "no claim", never as a wrong MTU — a later
	// hint in the shared payload is not a path-MTU notice.
	if _, ok := session.DecodePathMTUNotice([]byte{'W', '3', 'Q', 'X', 0x01, 0x05, 0xDC}); ok {
		t.Fatal("a payload with a foreign magic was read as a path-MTU notice")
	}

	// An unknown version fails towards "no claim" (pre-notice behaviour), never
	// towards a false refusal.
	if _, ok := session.DecodePathMTUNotice([]byte{'W', '3', 'P', 'M', 0x02, 0x05, 0xDC}); ok {
		t.Fatal("a payload with an unknown version was read as a path-MTU notice")
	}

	// A claim nobody can act on is worse than no claim.
	if enc := session.EncodePathMTUNotice(0); enc != nil {
		t.Fatalf("EncodePathMTUNotice(0) = % x, want nil (no claim)", enc)
	}
	if enc := session.EncodePathMTUNotice(-1); enc != nil {
		t.Fatalf("EncodePathMTUNotice(-1) = % x, want nil (no claim)", enc)
	}
}

// TestThePromotionGateCountsRxPacketsNeverRxOffered pins the ONE place the
// promotion gate is decided, and which counter feeds it.
//
// The predicate is Gate.State() == StateCarrying && RxPackets > 0 — RxPackets,
// NEVER RxOffered. RxPackets counts an inner packet VALIDATED and DELIVERED to
// the host device (PROVEN); RxOffered counts an arrival with nothing validated.
// It is computed once, next to the counters, in
// cmd/winn-datapath/winn3_status.go, so two hosts in two languages cannot each
// re-derive it and drift. The guard holds both the predicate body and the call
// site, so a sibling cannot widen the body to rxOffered OR feed the correct
// predicate the wrong counter without the suite noticing. The behavioural proof
// that the two counters differ is driven apart by
// TestPromotionIsGatedOnDeliveriesAndNotOnArrivals in the engine package.
func TestThePromotionGateCountsRxPacketsNeverRxOffered(t *testing.T) {
	requireGuards(t, PromotionPredicateGuards)
}

// TestAnUnauthenticatedDatagramGetsNoByteBack pins the runtime half of the v3
// silence convention: a gateway never answers a datagram it could not
// authenticate. Only a fresh initiation that authenticates under the gateway's
// admission key ever emits a byte.
//
// The behavioural teeth live in winn3/gateway/silence_test.go and
// winn3/session/credentialfault_test.go (named in the pin's HeldBy); this test
// is the conform-level seam that holds the refusal path's structure here.
func TestAnUnauthenticatedDatagramGetsNoByteBack(t *testing.T) {
	requireGuards(t, RefusalSilenceGuards)
}

// TestTheGatewayStmtsThePathMTUNoticeItPlannedAt pins the path-MTU notice being
// STATED in the handshake response — the refusal half of silent-refusal #3 and
// the half that carries the 1450 fleet default onto the wire.
//
// Before 2026-08-10 the responder passed nil to WriteResponse, so a gateway
// planning at one number and claiming another was undetectable: the client had
// no path-MTU to mismatch against, the session established, and full-size flows
// black-holed while both ends reported carrying. This needle pins the call to
// g.notice — which New pre-computes from the path MTU it was constructed with
// — so a sibling that reverts to nil reopens the defect.
func TestTheGatewayStmtsThePathMTUNoticeItPlannedAt(t *testing.T) {
	requireGuards(t, RefusalSilenceGuards)
}

// TestTheRefusalPathIsCountedAndStaysSilent pins the capacity refusal counter
// and its silent return as the structural twin of the unauth counter already
// held. A full table, a broken binder, and a rejected registration all must
// look identical to a probe: one counter incremented, one empty Result returned
// with no Reply.
func TestTheRefusalPathIsCountedAndStaysSilent(t *testing.T) {
	requireGuards(t, RefusalSilenceGuards)
}

// TestTheFleetDefaultPathMTUIsTheConstantTheGatewayFlagsUse pins the literal
// 1450 as the fleet default AND the gateway's -path-mtu flag resolving through
// that constant rather than a hard-coded number.
//
// The value moved from 1280 to 1450 on 2026-08-10 and the constant is the ONE
// name all four entry points resolve through — but nothing pinned the literal
// itself. A silent edit to the constant (e.g. back to 1280) would reshape every
// plan floor on the fleet at once and pass every existing test, because each
// test compares against carrier.DefaultPathMTU and that constant would have moved
// too. This needle asks "is the value still 1450" in the source file that
// defines it.
func TestTheFleetDefaultPathMTUIsTheConstantTheGatewayFlagsUse(t *testing.T) {
	requireGuards(t, FleetDefaultPathMTUGate)
}

// TestTheStatusDocumentObservesTransportInBothDirections pins the status
// document publishing TX packets alongside RX packets, so the promotion gate's
// inbound-only view is complemented by the outbound side a host must see.
//
// The predicate is gate==carrying && RxPackets>0 — RxPackets, never RxOffered.
// That is correct and this needle does not touch it. What it adds is the claim
// that the SAME document which carries RxPackets also carries TxPackets: a host
// reasoning over a status document that lost the tx counter would have no way
// to tell "inbound and the reply came back" from "inbound only, nothing left".
// Both counters are pinned here so the document carries transport evidence in
// both directions.
func TestTheStatusDocumentObservesTransportInBothDirections(t *testing.T) {
	requireGuards(t, PromotionPredicateGuards)
}

// --- fail-closed needles added 2026-08-12 (pkg_winn3_conform) --------------
//
// These hold shut error paths that previously failed OPEN or degraded
// silently: encoding/base64.DecodeString("") succeeds, Overheads() used to
// skip a class on error, compareOverheads ignored extra host rows, and
// not_derived on floors/overheads skipped even when the host sent data.

func referenceHostReport(t *testing.T, v Vectors) HostReport {
	t.Helper()
	ref, ok := referenceRow(v)
	if !ok || ref.MessageSize == 0 {
		t.Fatal("the conformance matrix has no floor for the reference carrier plan")
	}
	return HostReport{
		Host:                      "sample-winn3-host",
		Language:                  "go-test",
		GatewayIDHex:              v.Admission.GatewayIDHex,
		AdmissionKeyHex:           v.Admission.AdmissionKeyHex,
		TagSize:                   v.Admission.TagSize,
		PathMTU:                   v.Operator.PathMTU,
		CarrierClasses:            append([]string(nil), v.Operator.CarrierClasses...),
		MessageSize:               ref.MessageSize,
		InnerMTU:                  ref.InnerMTU,
		InnerIPv6:                 ref.InnerIPv6,
		TransportObservedBothWays: true,
		Floors:                    v.Floors,
		Overheads:                 v.Overheads,
	}
}

// TestFromServedSectionRefusesAMissingGatewayID is the needle for the empty
// base64 hole: DecodeString("") returns (empty, nil), so a served section
// that omitted gateway_id used to derive a session with empty admission-tag
// inputs instead of refusing. Two such hosts would then agree with each other.
func TestFromServedSectionRefusesAMissingGatewayID(t *testing.T) {
	section := servedReference()
	delete(section, "gateway_id")
	got, err := FromServedSection("served config with no gateway_id", section)
	if err == nil {
		t.Fatalf("a served section with no gateway_id derived host=%q gateway_id=%q. "+
			"encoding/base64.DecodeString(\"\") succeeds with empty bytes, so without this "+
			"refusal two hosts that both omitted the key would MustMatch each other on "+
			"empty admission-tag inputs. Apple refuses the same absence by name "+
			"(WinsTunnelConfig.winn3StartRefusalReason).",
			got.Host, got.GatewayID)
	}
	if !strings.Contains(err.Error(), "gateway_id") {
		t.Errorf("the refusal does not name gateway_id (%v)", err)
	}
	if _, err := FromServedSection("the reference served section", servedReference()); err != nil {
		t.Fatalf("the reference served section was refused: %v", err)
	}
}

// TestFromServedSectionRefusesAMissingAdmissionKey is the same hole on the
// other admission-tag input. A wrong-length key is worse than a refusal
// (defect 4): a session is built and then the gateway goes silent.
func TestFromServedSectionRefusesAMissingAdmissionKey(t *testing.T) {
	section := servedReference()
	delete(section, "admission_key")
	got, err := FromServedSection("served config with no admission_key", section)
	if err == nil {
		t.Fatalf("a served section with no admission_key derived host=%q admission=%d bytes. "+
			"That is an empty key, not a refusal.",
			got.Host, len(got.AdmissionKey))
	}
	if !strings.Contains(err.Error(), "admission_key") {
		t.Errorf("the refusal does not name admission_key (%v)", err)
	}
}

func TestFromServedSectionRefusesInvalidBase64AndNonNumericPathMTU(t *testing.T) {
	badID := servedReference()
	badID["gateway_id"] = "!!!not-base64!!!"
	if _, err := FromServedSection("served gateway_id that is not base64", badID); err == nil {
		t.Fatal("a served gateway_id that is not base64 was accepted")
	}
	badKey := servedReference()
	badKey["admission_key"] = "!!!not-base64!!!"
	if _, err := FromServedSection("served admission_key that is not base64", badKey); err == nil {
		t.Fatal("a served admission_key that is not base64 was accepted")
	}
	badMTU := servedReference()
	badMTU["path_mtu"] = "fourteen-hundred"
	if _, err := FromServedSection("served path_mtu that is not a number", badMTU); err == nil {
		t.Fatal("a served path_mtu that is not a number was accepted")
	}
	if _, err := FromServedSection("the reference served section", servedReference()); err != nil {
		t.Fatalf("the reference served section was refused: %v", err)
	}
}

func TestClassNamedRefusesAnUnknownClass(t *testing.T) {
	if _, err := ClassNamed("icmp"); err == nil {
		t.Fatal("ClassNamed accepted icmp; an unknown class must be refused, not charged as a floor")
	} else if !strings.Contains(err.Error(), "icmp") {
		t.Errorf("the refusal does not name the offending class (%v)", err)
	}
	for _, name := range []string{"udp", "tcp", "tls", " UDP ", "TCP"} {
		if _, err := ClassNamed(name); err != nil {
			t.Errorf("ClassNamed(%q) refused the documented class: %v", name, err)
		}
	}
}

func TestExpectedRefusesAnEmptyPlan(t *testing.T) {
	op := Reference()
	op.CarrierClasses = nil
	if _, err := Expected(op); err == nil {
		t.Fatal("Expected accepted an empty migration plan; Classes must refuse it")
	}
	if _, err := Expected(Reference()); err != nil {
		t.Fatalf("the reference operator was refused: %v", err)
	}
}

func TestVerifyReportFlagsAnExtraOverheadTheHostInvented(t *testing.T) {
	v, err := BuildVectors(Reference())
	if err != nil {
		t.Fatal(err)
	}
	correct := referenceHostReport(t, v)
	if ms := VerifyReport(v, correct); len(ms) != 0 {
		t.Fatalf("CONTROL: the reference report must verify clean; got %d mismatch(es):\n%s",
			len(ms), ExplainReport(v, correct, ms))
	}
	extra := correct
	extra.Overheads = append(append([]OverheadRow(nil), correct.Overheads...), OverheadRow{
		Class: "icmp", IPv4: true, Overhead: 28,
	})
	ms := VerifyReport(v, extra)
	found := false
	for _, m := range ms {
		if strings.Contains(m.Field, "icmp") {
			found = true
			if !strings.Contains(m.B, "does not know") {
				t.Errorf("extra overhead mismatch does not say the suite does not know the row: %+v", m)
			}
		}
	}
	if !found {
		t.Fatalf("a host that invented an icmp overhead was not flagged; mismatches: %v", ms)
	}
}

func TestVerifyReportFlagsFloorsDeclaredNotDerivedButPopulated(t *testing.T) {
	v, err := BuildVectors(Reference())
	if err != nil {
		t.Fatal(err)
	}
	correct := referenceHostReport(t, v)
	covered := correct
	covered.NotDerived = []string{"floors"}
	ms := VerifyReport(v, covered)
	found := false
	for _, m := range ms {
		if strings.Contains(m.Field, "floors (declared not_derived)") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a host that declared floors not_derived and then sent %d rows was not flagged; mismatches: %v",
			len(covered.Floors), ms)
	}
	okSkip := correct
	okSkip.Floors = nil
	okSkip.NotDerived = []string{"floors"}
	for _, m := range VerifyReport(v, okSkip) {
		if strings.Contains(m.Field, "floors (declared not_derived)") {
			t.Fatalf("declaring floors not_derived with no rows must be excused; got %v", m)
		}
	}
}

func TestVerifyReportFlagsOverheadsDeclaredNotDerivedButPopulated(t *testing.T) {
	v, err := BuildVectors(Reference())
	if err != nil {
		t.Fatal(err)
	}
	correct := referenceHostReport(t, v)
	covered := correct
	covered.NotDerived = []string{"overheads"}
	ms := VerifyReport(v, covered)
	found := false
	for _, m := range ms {
		if strings.Contains(m.Field, "overheads (declared not_derived)") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a host that declared overheads not_derived and then sent %d rows was not flagged; mismatches: %v",
			len(covered.Overheads), ms)
	}
}

func TestParseHostReportRefusesTrailingJSON(t *testing.T) {
	v, err := BuildVectors(Reference())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(referenceHostReport(t, v))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseHostReport(raw); err != nil {
		t.Fatalf("CONTROL: a correct report must parse: %v", err)
	}
	trailing := append(append([]byte{}, raw...), []byte(`{"host":"second"}`)...)
	if _, err := ParseHostReport(trailing); err == nil {
		t.Fatal("ParseHostReport accepted trailing JSON after the object; a second host would be silently ignored")
	}
	padded := append(append([]byte{}, raw...), '\n', ' ')
	if _, err := ParseHostReport(padded); err != nil {
		t.Fatalf("trailing whitespace after a correct report must still parse: %v", err)
	}
}

func TestATransportOnlyMismatchDoesNotClaimASizingConsequence(t *testing.T) {
	v, err := BuildVectors(Reference())
	if err != nil {
		t.Fatal(err)
	}
	ms := []Mismatch{{
		Field: "transport_observed_both_ways",
		A:     "true",
		B:     "false",
	}}
	msg := ExplainReport(v, HostReport{Host: "h", Language: "go"}, ms)
	if strings.Contains(msg, "CONSEQUENCE (sizing)") {
		t.Fatal("a transport-only mismatch claimed a sizing consequence")
	}
	if strings.Contains(msg, "CONSEQUENCE (admission)") {
		t.Fatal("a transport-only mismatch claimed an admission consequence")
	}
	if !strings.Contains(msg, "CONSEQUENCE (transport observation)") {
		t.Fatalf("a transport-only mismatch did not name the transport consequence:\n%s", msg)
	}
}

func TestDecodeHexRefusesNonHex(t *testing.T) {
	if _, err := DecodeHex("zz"); err == nil {
		t.Fatal("DecodeHex accepted non-hex")
	}
	got, err := DecodeHex("6f")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != 0x6f {
		t.Fatalf("DecodeHex(\"6f\") = %x, want 6f", got)
	}
}
