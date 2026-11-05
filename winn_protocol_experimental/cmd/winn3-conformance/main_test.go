package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/conform"
	"winsvpn.local/winnprotocol/winn3/driver"
)

// These tests cover the cmd/winn3-conformance DRIVER: the flag surface, the
// emit/verify plumbing, and exit-code discipline. They mirror the intent of the
// control-plane hub suites (server/test_winn3_descriptor_hub.py and
// server/test_winn3_pathmtu_hub.py) from the cross-host side: the reference a
// non-Go host must reproduce is the same operator configuration the hub refuses
// to ship twisted. A host that would make the hub refuse a descriptor must fail
// the conformance comparison here, so the two suites cannot silently disagree.

// --- exit codes and the nothing-done discipline ---------------------------

func TestExitCodeForDistinguishesUnprovenFromFailure(t *testing.T) {
	if got := exitCodeFor(unproven("nothing was checked")); got != 2 {
		t.Fatalf("unprovenError must exit 2, got %d: a run that checked nothing and a run that "+
			"passed are not the same fact and must not read the same in a pipeline", got)
	}
	if got := exitCodeFor(wrongAnswerErr{}); got != 1 {
		t.Fatalf("a concrete disagreement must exit 1, got %d", got)
	}
	// exitCodeFor is only ever reached with a non-nil error in main; its contract
	// is: unproven = 2, anything else = 1. Success (nil) exits 0 by falling
	// through main, so it is not a branch of this function and is not asserted.
}

// wrongAnswerErr is a non-unproven error, standing in for a host disagreement.
type wrongAnswerErr struct{}

func (wrongAnswerErr) Error() string { return "a host disagreed" }

func TestRunWithNothingToDoIsUnproven(t *testing.T) {
	var out strings.Builder
	err := run(nil, &out)
	if err == nil {
		t.Fatal("run with no flags returned nil; it must refuse to report success for a run " +
			"that checked nothing")
	}
	if _, ok := err.(unprovenError); !ok {
		t.Fatalf("expected an unprovenError (exit 2), got %T: %v", err, err)
	}
}

func TestSplitPathsCommaAndSpace(t *testing.T) {
	got := splitPaths(" a ,, b ,c ")
	exp := []string{"a", "b", "c"}
	if len(got) != len(exp) {
		t.Fatalf("splitPaths(%q) = %v, want %v", " a ,, b ,c ", got, exp)
	}
	for i := range exp {
		if got[i] != exp[i] {
			t.Fatalf("splitPaths(%q)[%d] = %q, want %q", " a ,, b ,c ", i, got[i], exp[i])
		}
	}
}

func TestHexStringLowerCase(t *testing.T) {
	if got := hexString("a\xffZ"); got != "61ff5a" {
		t.Fatalf("hexString = %q, want %q", got, "61ff5a")
	}
}

// --- emit ----------------------------------------------------------------

func TestEmitVectorsToStdoutWritesTheReference(t *testing.T) {
	var out strings.Builder
	if err := run([]string{"-emit", "-"}, &out); err != nil {
		t.Fatalf("emit to stdout failed: %v", err)
	}
	body := out.String()
	for _, needle := range []string{`"generator"`, `"gateway_id_hex"`, `"plan_floors"`,
		`"regression_pins"`, `"known_divergences"`} {
		if !strings.Contains(body, needle) {
			t.Fatalf("emitted vectors lack %s", needle)
		}
	}
}

func TestEmitTaskListCarriesInputsOnly(t *testing.T) {
	// Mirrors test_winn3_descriptor_hub's "no secret in an error body" and the
	// task-list contract in emitTaskList: a non-Go host harness reads INPUTS
	// ONLY, so the only thing it can do is run its host's real derivation. A
	// task list that leaked an expected answer would let a harness echo it.
	v, err := conform.BuildVectors(conform.Reference())
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := emitTaskList(v, "-", &out); err != nil {
		t.Fatalf("emitTaskList failed: %v", err)
	}
	body := out.String()
	for _, line := range []string{"operator_gateway_id_hex ", "operator_admission_file_hex ",
		"operator_path_mtu 1500", "operator_classes udp,tcp,tls", "floor ", "overhead "} {
		if !strings.Contains(body, line) {
			t.Fatalf("task list lacks %q:\n%s", line, body)
		}
	}
	// The two WRONG-ANSWER derivations are the flaw this suite exists to catch;
	// handing them to a harness as if they were inputs defeats the comparison.
	if strings.Contains(body, v.Admission.GatewayIDBase64Decoded) {
		t.Fatal("the task list leaks the base64-decoded gateway id; a host could echo it")
	}
	if strings.Contains(body, v.Admission.AdmissionIfHexDecoded) {
		t.Fatal("the task list leaks the hex-decoded admission secret; a host could echo it")
	}
	// The plan-floor answer is a derived number, never an input line.
	if strings.Contains(body, "inner_mtu") || strings.Contains(body, "message_size") {
		t.Fatalf("the task list leaks a derived plan-floor answer:\n%s", body)
	}
}

func TestLoadVectorsStrictRejectsUnknownFields(t *testing.T) {
	v, err := conform.BuildVectors(conform.Reference())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := v.JSON()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "vec.json")
	if err := os.WriteFile(good, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadVectors(good)
	if err != nil {
		t.Fatalf("a vector file this suite generated must load: %v", err)
	}
	if reloaded.Admission.GatewayIDHex != v.Admission.GatewayIDHex {
		t.Fatalf("round-tripped gateway_id_hex changed: %q != %q",
			reloaded.Admission.GatewayIDHex, v.Admission.GatewayIDHex)
	}

	sneaky := strings.Replace(string(raw), `"generator"`, `"generatorr"`, 1)
	bad := filepath.Join(dir, "sneaky.json")
	if err := os.WriteFile(bad, []byte(sneaky), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVectors(bad); err == nil {
		t.Fatal("a vector file with an unknown field loaded cleanly; a misspelled key decodes " +
			"to a zero value and is compared against silently, which is the class of silent " +
			"success this suite exists to remove")
	}
}

// --- descriptor intent (mirrors server/test_winn3_descriptor_hub.py) -------

// helper: a host report that agrees with the vectors on everything except the
// fields a caller replaces, declaring the sizing/floors out of scope so the
// comparison is focused on the field under test.
//
// transport_observed_both_ways is declared out of scope for the same reason the
// sizing fields are, and it is declared rather than answered on purpose: this
// fixture is an admission-tag report, it carries no traffic and has no engine,
// so claiming true would be inventing an agreement about something it never
// observed. NotDerived exists precisely so "did not derive it" cannot be
// confused with "reported false" — see HostReport.NotDerived. VerifyReport
// still flags this fixture if it ever declares the field AND reports a value.
func focusedReport(t *testing.T, v conform.Vectors, gwIDHex, keyHex string) conform.HostReport {
	t.Helper()
	return conform.HostReport{
		Host:            "test-host",
		Language:        "go",
		GatewayIDHex:    gwIDHex,
		AdmissionKeyHex: keyHex,
		TagSize:         v.Admission.TagSize,
		NotDerived: []string{
			"path_mtu", "carrier_classes", "message_size", "inner_mtu", "inner_ipv6",
			"floors", "overheads", "transport_observed_both_ways",
		},
	}
}

func mismatches(t *testing.T, v conform.Vectors, r conform.HostReport) []conform.Mismatch {
	t.Helper()
	return conform.VerifyReport(v, r)
}

func TestVerifyReportAgreesOnACorrectHost(t *testing.T) {
	v, err := conform.BuildVectors(conform.Reference())
	if err != nil {
		t.Fatal(err)
	}
	r := focusedReport(t, v, v.Admission.GatewayIDHex, v.Admission.AdmissionKeyHex)
	if ms := mismatches(t, v, r); len(ms) != 0 {
		t.Fatalf("a host that derives the reference exactly must agree, got %d mismatches: %v",
			len(ms), ms)
	}
}

func TestVerifyReportFlagsABase64DecodedGatewayID(t *testing.T) {
	// Mirrors test_winn3_descriptor_hub: a host that base64-decodes gateway_id
	// does not error — it silently derives six different bytes (defect 1). The
	// wrong-answer value is published next to the right one, so the suite can
	// both report it and name it.
	v, err := conform.BuildVectors(conform.Reference())
	if err != nil {
		t.Fatal(err)
	}
	if v.Admission.GatewayIDBase64Decoded == v.Admission.GatewayIDHex {
		t.Fatal("the fixture's wrong answer must differ from the right one, or a decoding host " +
			"would agree by accident and this test would prove nothing")
	}
	r := focusedReport(t, v, v.Admission.GatewayIDBase64Decoded, v.Admission.AdmissionKeyHex)
	ms := mismatches(t, v, r)
	found := false
	for _, m := range ms {
		if strings.HasPrefix(m.Field, "gateway_id_hex") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a base64-decoded gateway id was not flagged on gateway_id_hex: %v", ms)
	}
	explained := conform.ExplainReport(v, r, ms)
	if !strings.Contains(explained, "base64-DECODED gateway id") {
		t.Fatalf("expected the defect-1 hint in the explanation:\n%s", explained)
	}
}

func TestVerifyReportFlagsAHexDecodedAdmissionSecret(t *testing.T) {
	// Mirrors test_winn3_descriptor_hub: keygen writes hex TEXT and every
	// consumer keys with the file's bytes; hex-decoding it keys 32 bytes
	// against the other end's 64 and the gateway answers nothing.
	v, err := conform.BuildVectors(conform.Reference())
	if err != nil {
		t.Fatal(err)
	}
	r := focusedReport(t, v, v.Admission.GatewayIDHex, v.Admission.AdmissionIfHexDecoded)
	ms := mismatches(t, v, r)
	found := false
	for _, m := range ms {
		if strings.HasPrefix(m.Field, "admission_key_hex") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a hex-decoded admission secret was not flagged on admission_key_hex: %v", ms)
	}
	explained := conform.ExplainReport(v, r, ms)
	if !strings.Contains(explained, "hex-DECODED admission secret") {
		t.Fatalf("expected the hex-decode hint in the explanation:\n%s", explained)
	}
}

func TestAdmissionSecretIsTheFilesBytesTrimmedNotDecoded(t *testing.T) {
	// The reference admission file carries a trailing newline; the secret is the
	// bytes with only CR/LF trimmed and NOTHING ELSE — never a hex decode.
	op := conform.Reference()
	sec := op.AdmissionSecret()
	if len(sec) != 64 {
		t.Fatalf("the admission secret is %d bytes, want the file's 64 ASCII hex chars as bytes",
			len(sec))
	}
	v, err := conform.BuildVectors(op)
	if err != nil {
		t.Fatal(err)
	}
	if v.Admission.AdmissionKeyLen != 64 {
		t.Fatalf("the published admission key length is %d, want 64 (the file's bytes)",
			v.Admission.AdmissionKeyLen)
	}
	// The published "if hex-decoded" value must be the trap: it differs from
	// the correct key so a decoding host is caught, not silently agreed with.
	if v.Admission.AdmissionIfHexDecoded == v.Admission.AdmissionKeyHex {
		t.Fatal("hex-decoding the admission secret must produce something OTHER than the key, " +
			"or a decoding host would agree by accident")
	}
}

func TestReferenceOperatorPreservesEdgeWhitespaceAndCatchesATrimmingHost(t *testing.T) {
	// Mirrors test_winn3_descriptor_hub's refusal of edge whitespace in operator
	// values (trap 3): a trailing/leading space keys different bytes on two
	// hosts and neither end can ever discover it. The hub refuses to be the
	// thing that ships the space; this side asserts the suite PRESERVES it so a
	// host that silently trims fails the comparison rather than agreeing.
	op := conform.Reference()
	op.GatewayID = "winsgw01 " // a trailing space, the exact asymmetry trap
	gwBytes := op.GatewayIDBytes()
	if len(gwBytes) != 9 {
		t.Fatalf("a trailing-space gateway id must be 9 bytes, got %d", len(gwBytes))
	}
	v, err := conform.BuildVectors(op)
	if err != nil {
		t.Fatal(err)
	}
	wantHex := hexString(op.GatewayID)
	if v.Admission.GatewayIDHex != wantHex {
		t.Fatalf("the suite did not publish the whitespace-bearing gateway id verbatim: "+
			"%q != %q", v.Admission.GatewayIDHex, wantHex)
	}
	trimmed := conform.HostReport{
		Host:            "trimming-host",
		Language:        "go",
		GatewayIDHex:    hexString(strings.TrimSpace(op.GatewayID)),
		AdmissionKeyHex: v.Admission.AdmissionKeyHex,
		TagSize:         v.Admission.TagSize,
		NotDerived: []string{
			"path_mtu", "carrier_classes", "message_size", "inner_mtu", "inner_ipv6",
			"floors", "overheads", "transport_observed_both_ways",
		},
	}
	ms := conform.VerifyReport(v, trimmed)
	found := false
	for _, m := range ms {
		if strings.HasPrefix(m.Field, "gateway_id_hex") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a host that trimmed the edge whitespace was not flagged on gateway_id_hex: %v", ms)
	}
}

// --- path-MTU intent (mirrors server/test_winn3_pathmtu_hub.py) ------------

func TestFleetDefaultPathMTUIs1450(t *testing.T) {
	// Mirrors test_winn3_pathmtu_hub::test_plan_constants_do_not_drift: the
	// fleet default, raised from 1280 2026-08-10, must agree with the default
	// the conformance suite plans at when a host supplies no path MTU.
	if carrier.DefaultPathMTU != 1450 {
		t.Fatalf("carrier.DefaultPathMTU = %d, want 1450", carrier.DefaultPathMTU)
	}
	if conform.DefaultPathMTU != carrier.DefaultPathMTU {
		t.Fatalf("conform.DefaultPathMTU (%d) drifted from carrier.DefaultPathMTU (%d)",
			conform.DefaultPathMTU, carrier.DefaultPathMTU)
	}
}

func TestReferencePathMTUIsNotTheFleetDefault(t *testing.T) {
	// The reference operator chose 1500 rather than the default on purpose: a
	// host that quietly substitutes its own default would otherwise agree by
	// accident, hiding the migrate-to-default bug.
	if conform.Reference().PathMTU == carrier.DefaultPathMTU {
		t.Fatal("the reference path MTU equals the default, so a host that silently used its " +
			"default would agree with the reference by accident and the suite would not see it")
	}
}

func TestWidestPlanDeadZoneCrossesAt1421(t *testing.T) {
	// Mirrors test_winn3_pathmtu_hub::test_full_plan_dead_zone_is_1421 and the
	// driver's refusal: 1280..1420 for [udp tcp tls] carries inner IPv6 below
	// the 1280 floor and must not be served; 1421 is exactly the edge.
	for _, mtu := range []int{1280, 1400, 1420} {
		if _, err := driver.NewSizing(mtu, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS); err == nil {
			t.Fatalf("NewSizing accepted [udp tcp tls] at path MTU %d, inside the dead zone", mtu)
		}
		row, err := conform.Floor([]string{"udp", "tcp", "tls"}, mtu)
		if err != nil {
			t.Fatal(err)
		}
		if row.InnerIPv6 {
			t.Fatalf("plan floor at %d claims inner IPv6 (%d) but the dead zone must not", mtu, row.InnerMTU)
		}
	}
	if _, err := driver.NewSizing(1421, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS); err != nil {
		t.Fatalf("NewSizing refused the exact dead-zone edge 1421: %v", err)
	}
	row, err := conform.Floor([]string{"udp", "tcp", "tls"}, 1421)
	if err != nil {
		t.Fatal(err)
	}
	if !row.InnerIPv6 || row.InnerMTU != 1280 {
		t.Fatalf("[udp tcp tls] at 1421 must carry inner IPv6 exactly at the 1280 floor, got "+
			"ipv6=%t inner=%d", row.InnerIPv6, row.InnerMTU)
	}
}

func TestUDPOnlyPlanCrossesAt1357(t *testing.T) {
	// The same threshold is PLAN-AWARE (driver/doc, mirroring
	// test_winn3_pathmtu_hub::test_udp_only_plan_crosses_at_1357): a udp-only
	// plan carries inner IPv6 at 1357, so a flat 1421 floor would over-refuse it.
	if _, err := driver.NewSizing(1356, carrier.ClassUDP); err == nil {
		t.Fatal("NewSizing accepted a udp-only plan at 1356, inside its dead zone")
	}
	if _, err := driver.NewSizing(1357, carrier.ClassUDP); err != nil {
		t.Fatalf("NewSizing refused the udp-only edge 1357: %v", err)
	}
	row, err := conform.Floor([]string{"udp"}, 1357)
	if err != nil {
		t.Fatal(err)
	}
	if !row.InnerIPv6 || row.InnerMTU != 1280 {
		t.Fatalf("udp-only at 1357 must carry inner IPv6 at the 1280 floor, got ipv6=%t inner=%d",
			row.InnerIPv6, row.InnerMTU)
	}
}

func TestMatrixPublishesDeadZoneRowsAsNotCarryingIPv6(t *testing.T) {
	// The whole-matrix comparison is what catches a host whose floor diverges
	// at a path it has not met yet. Rows in the dead zone must be published as
	// inner_ipv6=false so a host that claims to carry IPv6 there is flagged.
	v, err := conform.BuildVectors(conform.Reference())
	if err != nil {
		t.Fatal(err)
	}
	var dead, wide bool
	for _, row := range v.Floors {
		switch {
		case strings.Join(row.Classes, "+") == "udp+tcp+tls" && row.PathMTU == 1280:
			if row.InnerIPv6 {
				t.Fatalf("the [udp tcp tls]@1280 row claims inner IPv6 (%d)", row.InnerMTU)
			}
			dead = true
		case strings.Join(row.Classes, "+") == "udp+tcp+tls" && row.PathMTU == 1500:
			if !row.InnerIPv6 {
				t.Fatalf("the [udp tcp tls]@1500 row must carry inner IPv6, got inner=%d", row.InnerMTU)
			}
			wide = true
		}
	}
	if !dead || !wide {
		t.Fatalf("matrix missing expected rows: dead=%v wide=%v", dead, wide)
	}
}

// --- the verify plumbing end to end ----------------------------------------

func writeVectorsFile(t *testing.T) (dir, path string) {
	t.Helper()
	v, err := conform.BuildVectors(conform.Reference())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := v.JSON()
	if err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	path = filepath.Join(dir, "vec.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

func TestVerifyRunWithADivergingHostFails(t *testing.T) {
	dir, vpath := writeVectorsFile(t)
	report := filepath.Join(dir, "report.json")
	if err := os.WriteFile(report, []byte(
		`{"host":"diverging","language":"go","gateway_id_hex":"c229ec830d35","admission_key_hex":"x","tag_size":32,"not_derived":["path_mtu","carrier_classes","message_size","inner_mtu","inner_ipv6","floors","overheads"]}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	err := run([]string{"-vectors", vpath, "-verify", report}, &out)
	if err == nil {
		t.Fatal("verify run with a diverging host returned nil; the build must fail")
	}
	if _, ok := err.(unprovenError); ok {
		t.Fatalf("a diverging host must be exit 1, not exit 2 (%v)", err)
	}
	if !strings.Contains(err.Error(), "diverge") {
		t.Fatalf("the failure must say a host diverges: %v", err)
	}
}

func TestVerifyRunWithAnUnreadableReportIsUnproven(t *testing.T) {
	dir, vpath := writeVectorsFile(t)
	report := filepath.Join(dir, "missing.json")
	var out strings.Builder
	err := run([]string{"-vectors", vpath, "-verify", report}, &out)
	if err == nil {
		t.Fatal("a verify run whose report could not be read returned nil")
	}
	if _, ok := err.(unprovenError); !ok {
		t.Fatalf("a run that never reached a host must be unproven (exit 2), got %T: %v", err, err)
	}
}
