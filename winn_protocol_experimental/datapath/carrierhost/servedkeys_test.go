package carrierhost

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// profileJSONTags returns every json tag on Profile, which is the schema every
// key list in this repository ultimately answers to.
func profileJSONTags(t *testing.T) map[string]bool {
	t.Helper()
	tags := map[string]bool{}
	structType := reflect.TypeOf(Profile{})
	for index := 0; index < structType.NumField(); index++ {
		tag := structType.Field(index).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		tags[strings.Split(tag, ",")[0]] = true
	}
	return tags
}

// The point of ServedProfileKeys is that a platform host can trust it. A key
// that is not a real field of Profile would be emitted into the [winn] section,
// forwarded into the profile document, and then rejected by the engine's
// DisallowUnknownFields decoder at startup — the failure would surface on a
// user's device, not here.
func TestServedProfileKeysAreRealSchemaFields(t *testing.T) {
	tags := profileJSONTags(t)
	for _, key := range ServedProfileKeys {
		if !tags[key] {
			t.Errorf(
				"served key %q is not a json tag on Profile; the engine "+
					"decodes with DisallowUnknownFields, so serving it would "+
					"be a hard parse failure on the device", key)
		}
	}
	for _, key := range RequiredServedProfileKeys {
		if !tags[key] {
			t.Errorf("required served key %q is not a json tag on Profile", key)
		}
	}
	for _, key := range DeviceLocalProfileKeys {
		if !tags[key] {
			t.Errorf("device-local key %q is not a json tag on Profile", key)
		}
	}
}

// Every spa_* field in the schema is accounted for, deliberately, one way or
// the other. This is the test that would have caught the original defect: the
// fields existed in Profile and no list mentioned them at all, so nothing
// anywhere was wrong and the capability was still unreachable.
func TestEverySPASchemaFieldIsClassified(t *testing.T) {
	served := map[string]bool{}
	for _, key := range SPAServedProfileKeys {
		served[key] = true
	}
	deviceLocal := map[string]bool{}
	for _, key := range DeviceLocalProfileKeys {
		deviceLocal[key] = true
	}

	var unclassified []string
	for tag := range profileJSONTags(t) {
		if !strings.HasPrefix(tag, "spa_") {
			continue
		}
		if !served[tag] && !deviceLocal[tag] {
			unclassified = append(unclassified, tag)
		}
	}
	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Fatalf(
			"Profile has spa_ field(s) %v that are neither served nor "+
				"device-local. An unclassified field is invisible to every "+
				"platform host, which is exactly how SPA came to be "+
				"unreachable from all four of them at once. Add each one to "+
				"SPAServedProfileKeys or DeviceLocalProfileKeys and "+
				"regenerate.", unclassified)
	}
}

// spa_key_path names a file on the device. Serving it would let whoever
// answered the config request choose which file the engine opens, which is a
// different and much worse thing than choosing a transport parameter.
func TestSPAKeyPathIsNeverServed(t *testing.T) {
	if !profileJSONTags(t)["spa_key_path"] {
		t.Fatal("spa_key_path is no longer a field of Profile; this test and " +
			"DeviceLocalProfileKeys both need updating")
	}
	for _, key := range ServedProfileKeys {
		if key == "spa_key_path" {
			t.Fatal(
				"spa_key_path is in ServedProfileKeys. It names a FILE ON THE " +
					"DEVICE holding a credential; a control plane must never " +
					"be able to choose it.")
		}
	}
}

func TestServedAndDeviceLocalKeysAreDisjoint(t *testing.T) {
	served := map[string]bool{}
	for _, key := range ServedProfileKeys {
		if served[key] {
			t.Errorf("served key %q is listed twice", key)
		}
		served[key] = true
	}
	for _, key := range DeviceLocalProfileKeys {
		if served[key] {
			t.Errorf("%q is both served and device-local", key)
		}
	}
	for _, key := range RequiredServedProfileKeys {
		if !served[key] {
			t.Errorf("required key %q is not in ServedProfileKeys", key)
		}
	}
	for _, key := range SPAServedProfileKeys {
		if !served[key] {
			t.Errorf("SPA key %q is not in ServedProfileKeys", key)
		}
	}
}

// No spa_* key may be required. This is the entire backward-compatibility
// argument for adding these fields: a served config that names none of them
// describes exactly the session it described before the fields existed, so a
// client gaining the capability cannot change what any existing config does.
func TestNoSPAKeyIsRequired(t *testing.T) {
	for _, required := range RequiredServedProfileKeys {
		if strings.HasPrefix(required, "spa_") {
			t.Errorf(
				"%q is required. Requiring an spa_ key would make every "+
					"existing served config incomplete the moment a client "+
					"understood SPA.", required)
		}
	}
}

// requireRepositoryRoot reports whether a repository root that will not resolve
// has to be a FAILURE rather than a skip.
//
// The skip below is legitimate in exactly one situation: this module copied or
// vendored out of the repository layout, where the four generated platform files
// are genuinely not on disk to be compared against. It is illegitimate
// everywhere else, because a skipped test reports the package as `ok` — a skip
// that reads as a pass is the same defect class this project keeps finding, and
// the drift guard is the one test whose whole value is that it cannot be
// bypassed.
//
// CI and GITHUB_ACTIONS are set by .github/workflows/test-and-validate.yml and
// by GitHub itself. WINN_REQUIRE_REPO_ROOT lets any other runner demand the same
// strictness without having to claim to be CI.
func requireRepositoryRoot() bool {
	for _, name := range []string{"CI", "GITHUB_ACTIONS", "WINN_REQUIRE_REPO_ROOT"} {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" || value == "0" || strings.EqualFold(value, "false") {
			continue
		}
		return true
	}
	return false
}

// The drift guard. One ordinary `go test ./...` run checks all four platform
// hosts, which is why the generator does not have to be wired into the Gradle,
// Xcode, Flutter and CMake builds separately.
//
// "Cannot be skipped by a build system" is not the same claim as "some build
// system runs it", and until 2026-08-05 only the first was true: no workflow ran
// `go test` at all. The Go job in .github/workflows/test-and-validate.yml is
// what makes this guard enforced rather than remembered.
func TestGeneratedPlatformKeyFilesAreCurrent(t *testing.T) {
	root, err := ResolveRepositoryRoot("")
	if err != nil {
		if requireRepositoryRoot() {
			t.Fatalf(
				"repository root not resolvable from %s: %v\n"+
					"  This runner set CI/GITHUB_ACTIONS/WINN_REQUIRE_REPO_ROOT, so "+
					"the drift guard MUST run.\n"+
					"  Skipping here would report the package as ok while checking "+
					"none of the four generated platform files.\n"+
					"  Run the suite from inside a full checkout (the root is the "+
					"directory holding both winn_protocol_experimental/go.mod and "+
					"pubspec.yaml).",
				t.Name(), err)
		}
		t.Skipf("repository root not resolvable from %s: %v "+
			"(set WINN_REQUIRE_REPO_ROOT=1 to make this a failure)",
			t.Name(), err)
	}
	for _, file := range GeneratedPlatformKeyFiles() {
		path := filepath.Join(root, file.Path)
		got, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: %v\n  regenerate with: cd winn_protocol_experimental "+
				"&& go run ./cmd/winn-carrier-keys", file.Path, err)
			continue
		}
		if string(got) != file.Content {
			t.Errorf(
				"%s is STALE.\n"+
					"  It is generated from datapath/carrierhost/servedkeys.go "+
					"and has drifted from it.\n"+
					"  Regenerate with: cd winn_protocol_experimental && "+
					"go run ./cmd/winn-carrier-keys\n"+
					"  Do not edit the generated file by hand: the next "+
					"regeneration silently discards the edit.",
				file.Path)
		}
	}
}

// TestWindowsJoinsTheKeySchemeIfItEverGainsACarrier is the recorded debt for
// the FIFTH hand-typed key allowlist, made enforceable instead of remembered.
//
// windows/runner/windows_winn_engine.cpp has its own `kKnownKeys` (13 entries,
// unknown key = hard refusal) and it is outside this generation scheme. That is
// NOT a live defect today and it is deliberately left alone:
//
//   - It is not the same KIND of list. This scheme's authority is
//     carrierhost.Profile's json tags, and TestServedProfileKeysAreRealSchemaFields
//     proves the served list really matches that schema. Windows' kKnownKeys is
//     the `[winn]`-SECTION HOST VOCABULARY -- enabled, endpoint, session_id,
//     max_datagram, carrier, h1..h4, s1..s4 -- and those names are not
//     datapath.Config's json tags (which are gateway_endpoint, awg_header_types,
//     ...) nor anything else declared in Go. There is no authority to generate
//     them FROM. Inventing one that merely restates what the C++ already says
//     would produce a generator with nothing checking it against a schema, which
//     is the half of this design that carries the value.
//   - The four host halves genuinely differ, on purpose. Dart names
//     gateway_endpoint where Linux, Windows and Kotlin name endpoint; Dart omits
//     h1..h4 because `obfuscation` is their single source of truth; Kotlin's
//     RESERVED_KEYS omits h1..h4 and s1..s4 because it reads them elsewhere.
//     One generated list would either flatten those decisions or need per-platform
//     variants, at which point the generator is a config file, not an authority.
//   - Folding the generated carrier keys into Windows TODAY would change
//     behaviour in the one direction that must not change. Windows currently
//     REFUSES a direct-awg section that also carries masque_template or spa_*;
//     unioning the generated list in would make it silently accept and ignore
//     them, converting a loud refusal into a silent drop on the platform
//     kWinnHostCapabilities records as `absent`.
//
// THE TRIGGER. The debt goes live the day Windows gains carrier support: at that
// moment Windows starts building a carrierhost.Profile document, the authority
// DOES apply to it, and a hand-typed list would drift exactly as the other four
// did. This test fires at precisely that moment rather than leaving it to a
// handoff paragraph somebody has to remember to re-read.
func TestWindowsJoinsTheKeySchemeIfItEverGainsACarrier(t *testing.T) {
	root, err := ResolveRepositoryRoot("")
	if err != nil {
		if requireRepositoryRoot() {
			t.Fatalf("repository root not resolvable: %v", err)
		}
		t.Skipf("repository root not resolvable: %v "+
			"(set WINN_REQUIRE_REPO_ROOT=1 to make this a failure)", err)
	}
	const relative = "windows/runner/windows_winn_engine.cpp"
	source, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		t.Fatalf("%s: %v", relative, err)
	}
	text := string(source)

	// If the anchors are gone the file was restructured and this guard has lost
	// track of it. Say so loudly: a guard that quietly stops matching is the
	// same "reads as a pass" defect as a skip.
	if !strings.Contains(text, "kKnownKeys") {
		t.Fatalf(
			"%s no longer declares kKnownKeys, so this guard can no longer tell "+
				"whether the Windows host has joined the generated-key scheme. "+
				"Re-anchor this test on whatever replaced it.", relative)
	}

	// Windows has joined the scheme. Nothing left to warn about.
	if strings.Contains(text, "kServedCarrierProfileKeys") {
		return
	}

	// The narrow carrier gate: everything but direct-awg is refused before the
	// key sweep is ever reached, which is what makes the hand-typed list inert.
	const narrowGate = "if (carrier != kCarrierDirectAwg) {"
	if !strings.Contains(text, narrowGate) {
		t.Fatalf(
			"%s no longer refuses every carrier but direct-awg, and its key "+
				"allowlist is still hand-typed.\n"+
				"  Windows now parses a carrier profile, so carrierhost.Profile "+
				"IS its authority and a hand-typed list will drift from it "+
				"exactly as the other four did.\n"+
				"  Fix: include the generated linux/runner/linux_winn_carrier_profile_keys.h "+
				"(or a Windows equivalent emitted by cmd/winn-carrier-keys) and "+
				"union kServedCarrierProfileKeys into the sweep, the way "+
				"linux/runner/linux_winn_host.cc does.\n"+
				"  Add the new file to GeneratedPlatformKeyFiles() so "+
				"TestGeneratedPlatformKeyFilesAreCurrent covers it too.",
			relative)
	}
}

// A profile carrying every served key, including all five SPA ones, really does
// parse. Proves the served list describes a document the engine accepts rather
// than a list that merely looks right.
func TestAProfileUsingEverySPAServedKeyParses(t *testing.T) {
	document := `{
  "profile": "` + ProfileVersion + `",
  "carrier": "` + CarrierHTTP3 + `",
  "masque_template": "https://c.example/.well-known/masque/udp/{target_host}/{target_port}/",
  "public_target": "198.51.100.20:51820",
  "server_name": "gateway.example",
  "suite": "x25519-mlkem768",
  "controller_id": "controller-1",
  "controller_pins_path": "/dev/null",
  "root_ca_path": "/dev/null",
  "ech_config_list_path": "/dev/null",
  "authorization_mode": "identity",
  "device_id": "device-1",
  "device_pq_algorithm": "mldsa65",
  "device_seed_path": "/dev/null",
  "client_cert_path": "/dev/null",
  "client_key_path": "/dev/null",
  "session_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "sequence_epoch": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "manifest_digest": "` + strings.Repeat("a", 64) + `",
  "max_inner_datagram": 1400,
  "privacy_profile": "high-risk",
  "spa_mode": "` + SPAModeRequired + `",
  "spa_key_path": "/dev/null",
  "spa_target": "198.51.100.20:9111",
  "spa_packet_size": 256,
  "spa_bucket_window_seconds": 10,
  "spa_max_skew_seconds": 60
}`
	profile, err := ParseProfile([]byte(document))
	if err != nil {
		t.Fatalf("a document using every served key must parse: %v", err)
	}
	if profile.SPAMode != SPAModeRequired {
		t.Errorf("spa_mode = %q, want %q", profile.SPAMode, SPAModeRequired)
	}
	if profile.SPATarget != "198.51.100.20:9111" {
		t.Errorf("spa_target = %q", profile.SPATarget)
	}
	if profile.SPAPacketSize != 256 {
		t.Errorf("spa_packet_size = %d", profile.SPAPacketSize)
	}
	if profile.SPABucketWindowSeconds != 10 || profile.SPAMaxSkewSeconds != 60 {
		t.Errorf("freshness policy = %d/%d",
			profile.SPABucketWindowSeconds, profile.SPAMaxSkewSeconds)
	}
}
