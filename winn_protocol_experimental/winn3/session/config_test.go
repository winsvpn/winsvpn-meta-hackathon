package session

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

// TestConfigEmitWinn3CarrierINI emits a full `[winn/3]` carrier INI and asserts
// the three keys the winn/3 carrier contract requires — protocol_version,
// carrier, stealth — are present, and that the emission is DERIVED from the
// session config rather than a constant that would pass for any input.
//
// The derivation check is the part with teeth: the doc must move when the
// config it is a function of moves. A constant emitter would survive the
// presence assertions and die here, which is exactly the survivor shape the
// mutation catalogue warns about (a positive fact with nothing asserting the
// negative).
func TestConfigEmitWinn3CarrierINI(t *testing.T) {
	cfg := sessEmitTestConfig(t, 1168)

	doc := cfg.EmitWinn3INI(CarrierUDP, true)

	if !strings.HasPrefix(doc, "[winn/3]\n") {
		t.Fatalf("emission does not open a [winn/3] section:\n%s", doc)
	}

	// The winn3ProtocolVersion constant is the single spelling the emitter
	// uses. Assert it against the wire contract here so a silent drift of the
	// constant is a failure in its own right, not just a divergence the
	// presence check would not see because both sides moved together.
	if winn3ProtocolVersion != "winn/3" {
		t.Errorf("winn3ProtocolVersion drifted from the wire contract: %q", winn3ProtocolVersion)
	}

	// The protocol_version line is pinned to the WIRE CONTRACT literal, not to
	// the winn3ProtocolVersion constant. A test that wrote
	// "protocol_version="+winn3ProtocolVersion would move with the constant and
	// survive a mutation that changed it to "winn/3x" — the exact survivor shape
	// the mutation catalogue warns about (a bound test that moves with the very
	// thing it is supposed to pin). The constant is checked separately below so
	// a drift of either the constant or the emitter is caught.
	var required = []string{
		"protocol_version=winn/3",
		"carrier=" + CarrierUDP,
		"stealth=true",
	}
	for _, line := range required {
		if !strings.Contains(doc, line+"\n") {
			t.Errorf("required winn/3 carrier key line %q is missing from:\n%s", line, doc)
		}
	}

	// The negative control: re-emit from a different config and different
	// carrier. If the document does not change, the emitter is a constant and
	// nothing above means anything.
	cfg2 := sessEmitTestConfig(t, 1420)
	doc2 := cfg2.EmitWinn3INI(CarrierTLS, false)

	if want := "carrier=" + CarrierTLS + "\n"; !strings.Contains(doc2, want) {
		t.Errorf("re-emitting with carrier=%s did not emit %q:\n%s", CarrierTLS, strings.TrimSpace(want), doc2)
	}
	if !strings.Contains(doc2, "stealth=false\n") {
		t.Errorf("re-emitting with stealth=false did not emit stealth=false:\n%s", doc2)
	}
	if want := "max_message_size=" + strconv.Itoa(1420) + "\n"; !strings.Contains(doc2, want) {
		t.Errorf("re-emitting with a 1420 message size did not emit %q:\n%s", strings.TrimSpace(want), doc2)
	}
	if want := "inner_mtu=" + strconv.Itoa(InnerMTU(1420)) + "\n"; !strings.Contains(doc2, want) {
		t.Errorf("inner_mtu is not derived from the message size (want %q):\n%s", strings.TrimSpace(want), doc2)
	}
}

// TestConfigEmissionKeyOrderParityWithDartDispatch pins the key ORDER of the
// `[winn/3]` carrier document this package emits and asserts it stays in parity
// with the key order lib/winn_protocol_dispatch.dart emits for its `[winn]`
// section.
//
// Why order is load-bearing and not cosmetic: the session `[winn/3]` document
// is one of the inputs the four platform hosts turn into Create payloads, and
// those four JSON documents are diffed byte for byte in review
// (WINN_PROTOCOL_PLATFORM_PLAN.md, "the four platforms' Create payloads can be
// diffed in review"). A host that emits its keys in a different order than its
// siblings still parses and still works — and the diff of the four Create
// payloads grows a spurious line for every reordered key, so the next reviewer
// cannot tell a real platform divergence from the noise. Pinning the order is
// what keeps that diff readable.
//
// The parity direction matters. The Dart writer is the shipped authority — the
// `[winn]` section it emits is what actually reaches a device — so this test
// reads the Dart SOURCE as text (Go cannot import Dart) and asserts the Go
// document matches it on the keys they share, rather than asserting the Dart
// writer against a Go constant that could drift with it. The order is checked
// against literal key lists, never derived from the emitter, so a reorder on
// either side is a failure rather than a self-consistent change.
//
// The one key the two documents share today is `carrier`, and its position is
// the parity claim: BOTH documents place it second, immediately after the key
// that selects the protocol (`enabled` on the Dart side, `protocol_version`
// here). That positional contract is what a reorder of either writer breaks,
// and it is asserted directly rather than as a shared-subsequence that a single
// shared key would satisfy vacuously.
func TestConfigEmissionKeyOrderParityWithDartDispatch(t *testing.T) {
	doc := sessEmitTestConfig(t, 1168).EmitWinn3INI(CarrierUDP, true)
	sessionKeys := emissionKeys(t, doc)

	// (1) The Go side, pinned to literals. A reorder of EmitWinn3INI — putting
	// `stealth` before `protocol_version`, say — is a failure here and only
	// here; nothing else in this package compares the document to itself.
	wantSessionKeys := []string{
		"protocol_version", "carrier", "stealth", "max_message_size", "inner_mtu",
	}
	if !stringSlicesEqual(sessionKeys, wantSessionKeys) {
		t.Errorf("EmitWinn3INI key order = %v, want the pinned order %v\n%s",
			sessionKeys, wantSessionKeys, doc)
	}

	// (2) The Dart side, read from source. The standalone `[winn]` section is
	// the winn/3 carrier document the Dart writer emits; it is the document a
	// device is actually handed, so it is the reference for parity.
	dartSection, dartSource := dartStandaloneWinnSectionKeys(t)
	if len(dartSection) == 0 {
		t.Fatalf("could not extract a standalone [winn] section key order from %s", dartSource)
	}

	// (3) Parity on the shared key. `carrier` must be present in BOTH documents
	// and must occupy the same position in both: the second key, immediately
	// after the protocol-selecting lead. Asserting position 1 (0-based) rather
	// than just "both contain carrier" is what gives the parity claim teeth for
	// a single shared key.
	if dartCarrierAt := indexOf(dartSection, "carrier"); dartCarrierAt != 1 {
		t.Errorf("lib/winn_protocol_dispatch.dart emits `carrier` at position %d in its "+
			"[winn] section (keys %v); a reorder of the Dart writer breaks the "+
			"byte-diffability of the four Create payloads", dartCarrierAt, dartSection)
	}
	if sessionCarrierAt := indexOf(sessionKeys, "carrier"); sessionCarrierAt != 1 {
		t.Errorf("EmitWinn3INI emits `carrier` at position %d (keys %v); parity with the "+
			"Dart writer requires `carrier` second in both documents",
			sessionCarrierAt, sessionKeys)
	}

	// (4) The general invariant, for when the two documents grow more shared
	// keys: the relative order of the keys the session document shares with the
	// Dart writer must be identical in both. Today that is the single `carrier`
	// key; the subsequence check is written so adding a shared key cannot make
	// the assertion silently vacuous.
	shared := intersectStrings(sessionKeys, dartSection)
	if len(shared) == 0 {
		t.Fatal("the session [winn/3] document and the Dart [winn] section share no " +
			"keys; the parity test has nothing to compare")
	}
	if got, want := restrictTo(sessionKeys, shared), restrictTo(dartSection, shared); !stringSlicesEqual(got, want) {
		t.Errorf("shared-key relative order differs: session [winn/3] emits %v, Dart "+
			"[winn] emits %v. The four Create payloads cannot be diffed byte for byte "+
			"if the two writers disagree about ordering", got, want)
	}
}

// TestConfigDefaultsSurviveEmissionRoundTrip is the zero-defaults guard. Its
// premise is the one the `config.go.bak_20260809_zerodefaults` history documents:
// a Config left at its zero value is exactly the state that must NOT silently
// normalise into an unsafe MTU or an unroutable inner size. The test builds the
// worst case — a caller that sets nothing but a static key — normalises it,
// emits the `[winn/3]` carrier document, and then READS the two sizing numbers
// back out of the emitted document as a host-profile consumer would (a genuine
// write-then-read round trip). Every value must survive with a sane, positive,
// self-consistent magnitude: a zero `max_message_size` or a zero-or-negative,
// over-large `inner_mtu` is the exact silent black hole this guard exists to
// refuse.
//
// The negative control matters as much as the positive one. `EmitWinn3INI`
// normalises its own copy before emitting, so a regression that stops
// `normalise` from applying the default MaxMessageSize would be HIDDEN by the
// round trip through the document alone. That is why the test also asserts the
// normalised Config's own field directly, and why the whole body must go red —
// not just one line — when a default is dropped.
func TestConfigDefaultsSurviveEmissionRoundTrip(t *testing.T) {
	cfg := sessEmitTestConfig(t, 0)
	if err := cfg.normalise(); err != nil {
		t.Fatalf("normalise refused the default config: %v", err)
	}

	// Round trip: write the carrier document, then parse the sizing numbers back
	// out of it. This is the write-then-read the guard is about.
	doc := cfg.EmitWinn3INI(CarrierUDP, true)
	gotMsg := winn3INIValue(t, doc, "max_message_size")
	gotInner := winn3INIValue(t, doc, "inner_mtu")

	// (1) The sane default must survive with its magnitude, never a silent zero.
	if cfg.MaxMessageSize != DefaultMaxMessageSize {
		t.Errorf("normalise left MaxMessageSize=%d, want the safe default %d (a zero or drifted default is the unsafe-MTU regression)",
			cfg.MaxMessageSize, DefaultMaxMessageSize)
	}
	if gotMsg != DefaultMaxMessageSize {
		t.Errorf("emitted max_message_size=%d after a default-normalise, want %d (a silent zero here is the unsafe-MTU regression)",
			gotMsg, DefaultMaxMessageSize)
	}
	if gotMsg <= 0 {
		t.Errorf("emitted max_message_size=%d is not positive; the tunnel cannot size itself", gotMsg)
	}

	// (2) The route value must be positive, leave room for the transport and
	// frame headers below its own message ceiling, and match the package's own
	// derivation from exactly that message size. A zero, negative or over-large
	// inner MTU routes nothing and black-holes every packet.
	if want := InnerMTU(gotMsg); gotInner != want {
		t.Errorf("emitted inner_mtu=%d does not match InnerMTU(%d)=%d; the emitted route is not derived from the emitted message",
			gotInner, gotMsg, want)
	}
	if gotInner <= 0 {
		t.Errorf("emitted inner_mtu=%d is not a usable route size (a zero or negative inner MTU black-holes every packet)", gotInner)
	}
	if gotInner >= gotMsg {
		t.Errorf("emitted inner_mtu=%d must leave room for the transport and frame headers below max_message_size=%d", gotInner, gotMsg)
	}
}

// TestConfigEmitParseRoundTrip is the emit/parse round trip: emit a `[winn/3]`
// carrier section from a Config, parse it back with ParseWinn3INI, and require
// that every field the emitter wrote survives. Then emit again from what the
// parse recovered and require a byte-identical document, so the round trip is
// closed on both directions rather than a one-way presence check.
//
// The teeth are in the strictness of the parse half. A serializer that stops
// writing one of the five keys makes ParseWinn3INI report a missing-key error,
// so the round trip fails loudly instead of silently passing a field that was
// dropped on the wire — the "positive fact with nothing asserting the negative"
// survivor shape from the mutation catalogue. And because ParseWinn3INI insists
// inner_mtu is the exact derivation of max_message_size, a document that drifts
// from the Config's own derivation is refused rather than returned.
//
// Two unrelated config/carrier/stealth combinations are exercised so the round
// trip is not a constant that would pass for any input.
func TestConfigEmitParseRoundTrip(t *testing.T) {
	for _, c := range []struct {
		max     int
		carrier string
		stealth bool
	}{
		{1168, CarrierUDP, true},
		{1420, CarrierTLS, false},
	} {
		cfg := sessEmitTestConfig(t, c.max)
		if err := cfg.normalise(); err != nil {
			t.Fatalf("normalise refused the config: %v", err)
		}
		doc := cfg.EmitWinn3INI(c.carrier, c.stealth)

		sec, err := ParseWinn3INI(doc)
		if err != nil {
			t.Fatalf("ParseWinn3INI rejected the document emitted from a Config (carrier=%s, stealth=%t, max=%d): %v\n%s",
				c.carrier, c.stealth, c.max, err, doc)
		}

		if sec.ProtocolVersion != winn3ProtocolVersion {
			t.Errorf("carrier=%s: parsed protocol_version=%q, want %q", c.carrier, sec.ProtocolVersion, winn3ProtocolVersion)
		}
		if sec.Carrier != c.carrier {
			t.Errorf("max=%d: parsed carrier=%q, want %q", c.max, sec.Carrier, c.carrier)
		}
		if sec.Stealth != c.stealth {
			t.Errorf("carrier=%s: parsed stealth=%t, want %t", c.carrier, sec.Stealth, c.stealth)
		}
		if sec.MaxMessageSize != c.max {
			t.Errorf("carrier=%s: parsed max_message_size=%d, want %d (a dropped or drifted size fails the round trip)",
				c.carrier, sec.MaxMessageSize, c.max)
		}
		if want := InnerMTU(c.max); sec.InnerMTU != want {
			t.Errorf("carrier=%s: parsed inner_mtu=%d, want the derivation %d (inner_mtu dropped by the emitter)",
				c.carrier, sec.InnerMTU, want)
		}

		// Close the round trip in the other direction: rebuild a Config from the
		// recovered section and re-emit. A byte-identical document proves the
		// parse recovered everything the serializer wrote.
		cfg2 := sessEmitTestConfig(t, sec.MaxMessageSize)
		if err := cfg2.normalise(); err != nil {
			t.Fatalf("normalise refused the reconstructed config: %v", err)
		}
		if doc2 := cfg2.EmitWinn3INI(sec.Carrier, sec.Stealth); doc2 != doc {
			t.Errorf("emit(parse(emit(cfg))) differs from the original document; the round trip is not lossless.\n"+
				"--- original\n%s\n--- re-emitted from the parse\n%s", doc, doc2)
		}
	}
}

// winn3INIValue parses the integer of one `key=value` line back out of an
// INI-style document. It exists to make the emission round trip a genuine
// write-then-read rather than an assertion against the very variables the
// emitter wrote. A missing or malformed line is a fatal error.
func winn3INIValue(t *testing.T, doc, key string) int {
	t.Helper()
	for _, line := range strings.Split(doc, "\n") {
		if !strings.HasPrefix(line, key+"=") {
			continue
		}
		v, err := strconv.Atoi(strings.TrimSpace(line[len(key)+1:]))
		if err != nil {
			t.Fatalf("line %q for key %q is not an integer: %v", line, key, err)
		}
		return v
	}
	t.Fatalf("key %q not found in document:\n%s", key, doc)
	return 0
}

// emissionKeys parses the ordered `key=value` (or `key = value`) lines out of an
// INI-style document, ignoring the section header. Order is document order.
func emissionKeys(t *testing.T, doc string) []string {
	t.Helper()
	var out []string
	lineRe := regexp.MustCompile(`^([A-Za-z0-9_]+)\s*=`)
	for _, line := range strings.Split(doc, "\n") {
		m := lineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, m[1])
	}
	return out
}

// dartStandaloneWinnSectionKeys reads lib/winn_protocol_dispatch.dart from the
// tree and returns the ordered key list of the STANDALONE `[winn]` section it
// emits, plus the path it was read from.
//
// The standalone branch is the `final lines = <String>[...]` block that carries
// the winn/3 served-section keys — `carrier = $kWinnCarrierWinn3`, `inner_v4`,
// `gateway_static`, `admission_key` — so it is the document a winn/3 session is
// actually handed. The relay branch is skipped: it describes the AmneziaWG
// relay, not the standalone carrier this package's `[winn/3]` document
// describes.
func dartStandaloneWinnSectionKeys(t *testing.T) ([]string, string) {
	t.Helper()
	path := dartDispatchPath(t)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	// Every `final lines = <String>[` ... `];` block in the file, in order.
	var blocks [][]string
	for {
		open := strings.Index(string(src), "final lines = <String>[")
		if open < 0 {
			break
		}
		src = src[open:]
		close := strings.Index(string(src), "];")
		if close < 0 {
			break
		}
		block := string(src[len("final lines = <String>["):close])
		src = src[close:]
		blocks = append(blocks, parseDartIniKeys(block))
	}
	if len(blocks) == 0 {
		t.Fatalf("no `final lines = <String>[...]` block found in %s", path)
	}

	// The standalone branch is the one carrying the winn/3 served-section keys
	// (`inner_v4`, `gateway_static`, `admission_key`). It is identified by these
	// CARDINAL markers, never by the position of `carrier` — coupling branch
	// detection to the very ordering this test asserts would let a reorder of
	// the first keys evade the parity check by breaking detection instead.
	for _, b := range blocks {
		if indexOf(b, "inner_v4") >= 0 && indexOf(b, "admission_key") >= 0 {
			return b, path
		}
	}
	t.Fatalf("no standalone [winn] section (carrying inner_v4 and admission_key) found in %s", path)
	return nil, path
}

// parseDartIniKeys extracts the ordered key names from one `'key = ...'` list
// literal body.
func parseDartIniKeys(body string) []string {
	var out []string
	re := regexp.MustCompile(`'([A-Za-z0-9_]+) = `)
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

// dartDispatchPath returns the path of lib/winn_protocol_dispatch.dart relative
// to the module, resolved from this package's own directory (go test runs each
// package with the working directory set to that package's source directory).
//
// WINS_SESS_CONFIG_DART overrides the path so a mutation control can point the
// test at a private copy of the Dart writer without touching the shared tree.
func dartDispatchPath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("WINS_SESS_CONFIG_DART"); p != "" {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("WINS_SESS_CONFIG_DART=%s does not exist: %v", p, err)
		}
		return p
	}
	candidates := []string{
		filepath.Join("..", "..", "..", "lib", "winn_protocol_dispatch.dart"),
		filepath.Join("..", "..", "..", "..", "source", "wins_vpn", "lib", "winn_protocol_dispatch.dart"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Fatalf("lib/winn_protocol_dispatch.dart not found from %s (tried %v)",
		candidates[0], candidates)
	return ""
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func indexOf(s []string, v string) int {
	for i, e := range s {
		if e == v {
			return i
		}
	}
	return -1
}

func intersectStrings(a, b []string) []string {
	var out []string
	for _, e := range a {
		if indexOf(b, e) >= 0 {
			out = append(out, e)
		}
	}
	return out
}

func restrictTo(s, keep []string) []string {
	var out []string
	for _, e := range s {
		if indexOf(keep, e) >= 0 {
			out = append(out, e)
		}
	}
	return out
}

// sessEmitTestConfig builds a valid client Config at the given MaxMessageSize.
func sessEmitTestConfig(t *testing.T, maxMessageSize int) *Config {
	t.Helper()
	static, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	return &Config{
		Static:         static,
		MaxMessageSize: maxMessageSize,
		Padding:        core.PadBucket,
	}
}
