package carrier

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

// carveFixtureSeed is TEST-ONLY material. It is the exact seed the checked-in
// conformance fixture under ../conform/testdata was carved from. It is never a
// real deployment secret: anyone who holds it can re-derive the private halves
// of the fixture's identities, which is exactly the point of a reproducible
// test vector and exactly why it must never be reused off the bench. It is the
// seed-digest, not the seed itself, that appears in the committed fixture.
var carveFixtureSeed = mustDecodeSeed("98037684190bcdeb1a72e276f3d914ea893f0722f6156529186aa1246dfbe13f")

// carveFixtureRoles are the roles carved into the committed conformance
// fixture: two gateways and two clients across two named hosts, so the fixture
// exercises both sides of a real pair.
var carveFixtureRoles = []string{
	"gateway.wins-sea-01",
	"client.wins-sea-01",
	"gateway.wins-sea-02",
	"client.wins-sea-02",
}

func mustDecodeSeed(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	if len(b) != core.KeySize {
		panic("fixture seed is not 32 bytes")
	}
	return b
}

// TestCarveIsDeterministic: the same seed and roles must produce byte-identical
// JSON, so a fixture is reproducible and a committed copy can be diffed.
func TestCarveIsDeterministic(t *testing.T) {
	a, err := Carve(carveFixtureSeed, carveFixtureRoles)
	if err != nil {
		t.Fatalf("first carve: %v", err)
	}
	b, err := Carve(carveFixtureSeed, carveFixtureRoles)
	if err != nil {
		t.Fatalf("second carve: %v", err)
	}
	ja, _ := MarshalBundle(a)
	jb, _ := MarshalBundle(b)
	if !bytes.Equal(ja, jb) {
		t.Fatal("carve of the same seed and roles is not byte-stable")
	}
}

// TestCarveDistinguishesRoles: two roles must not fall back to the same key —
// a repeated identity across roles would be a silent configuration collision.
func TestCarveDistinguishesRoles(t *testing.T) {
	b, err := Carve(carveFixtureSeed, carveFixtureRoles)
	if err != nil {
		t.Fatalf("carve: %v", err)
	}
	seen := map[string]bool{}
	for _, k := range b.Keys {
		if seen[k.PublicKeyHex] {
			t.Fatalf("role %q shares a key with an earlier role", k.Role)
		}
		seen[k.PublicKeyHex] = true
	}
}

// TestCarveDistinguishesSeeds: two seeds must not produce a shared private
// identity (a single shared public key would imply a shared handshake key).
func TestCarveDistinguishesSeeds(t *testing.T) {
	otherSeed := make([]byte, core.KeySize)
	for i := range otherSeed {
		otherSeed[i] = 0xff
	}
	a, err := Carve(carveFixtureSeed, carveFixtureRoles)
	if err != nil {
		t.Fatalf("carve A: %v", err)
	}
	b, err := Carve(otherSeed, carveFixtureRoles)
	if err != nil {
		t.Fatalf("carve B: %v", err)
	}
	if a.Keys[0].PublicKeyHex == b.Keys[0].PublicKeyHex {
		t.Fatal("two different seeds produced an identical gateway public key")
	}
}

// TestCarvedPublicKeysAreValid: every public half must decode as a real,
// well-formed X25519 point — the same way the engine validates a peer key.
func TestCarvedPublicKeysAreValid(t *testing.T) {
	b, err := Carve(carveFixtureSeed, carveFixtureRoles)
	if err != nil {
		t.Fatalf("carve: %v", err)
	}
	for _, k := range b.Keys {
		raw, err := hex.DecodeString(k.PublicKeyHex)
		if err != nil {
			t.Fatalf("role %q public key is not hex: %v", k.Role, err)
		}
		if len(raw) != core.KeySize {
			t.Fatalf("role %q public key is %d bytes, want %d", k.Role, len(raw), core.KeySize)
		}
		if _, err := core.NewPublicKey(raw); err != nil {
			t.Fatalf("role %q public key is rejected by the engine: %v", k.Role, err)
		}
	}
}

// TestCarveBundleLetsNoPrivateMaterialThrough is the negative half of the
// fixture guarantee. The bundle is PUBLIC-ONLY by construction; this test
// proves that by re-deriving every private scalar and the seed and asserting
// none of them — as raw bytes or as hex — appears anywhere in the serialized
// bundle. A carve that started to leak a private half fails here.
func TestCarveBundleLetsNoPrivateMaterialThrough(t *testing.T) {
	seed := carveFixtureSeed
	bundle, err := Carve(seed, carveFixtureRoles)
	if err != nil {
		t.Fatalf("carve: %v", err)
	}
	raw, err := MarshalBundle(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	blob := string(raw)

	seedHex := hex.EncodeToString(seed)
	if strings.Contains(blob, seedHex) {
		t.Fatal("serialized bundle contains the raw seed hex")
	}
	if bytes.Contains(raw, seed) {
		t.Fatal("serialized bundle contains the raw seed bytes")
	}

	// Re-derive each private scalar with the same derivation the package uses,
	// and assert neither its bytes nor its hex reach the blob.
	prk, err := hkdf.Extract(sha256.New, seed, []byte(CarveDomain))
	if err != nil {
		t.Fatalf("hkdf extract: %v", err)
	}
	for _, role := range carveFixtureRoles {
		scalar, err := hkdf.Expand(sha256.New, prk, role, core.KeySize)
		if err != nil {
			t.Fatalf("hkdf expand %q: %v", role, err)
		}
		if strings.Contains(blob, hex.EncodeToString(scalar)) {
			t.Fatalf("serialized bundle contains the private scalar hex for role %q", role)
		}
		if bytes.Contains(raw, scalar) {
			t.Fatalf("serialized bundle contains the raw private scalar for role %q", role)
		}
	}
}

// TestCarveRejectsABadRequest: the configuration guard must fail closed for an
// empty role set, a duplicate, a blank, an unsafe label, and a short seed.
func TestCarveRejectsABadRequest(t *testing.T) {
	cases := []struct {
		name  string
		seed  []byte
		roles []string
	}{
		{"no roles", carveFixtureSeed, nil},
		{"blank role", carveFixtureSeed, []string{""}},
		{"unsafe role", carveFixtureSeed, []string{"gateway/../etc"}},
		{"role with whitespace", carveFixtureSeed, []string{"gateway one"}},
		{"duplicate role", carveFixtureSeed, []string{"a", "a"}},
		{"short seed", make([]byte, core.KeySize-1), carveFixtureRoles},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Carve(tc.seed, tc.roles); err == nil {
				t.Fatal("carve accepted an invalid request")
			}
		})
	}
}

// TestCarveFromReaderUsesEverySeedByte pins the reader path to exactly
// core.KeySize bytes so a caller-controlled reader is reproducible.
func TestCarveFromReaderUsesEverySeedByte(t *testing.T) {
	r := bytes.NewReader(carveFixtureSeed)
	b, err := CarveFromReader(r, []string{"client.wins-sea-01"})
	if err != nil {
		t.Fatalf("carve from reader: %v", err)
	}
	if got, want := len(b.Keys), 1; got != want {
		t.Fatalf("got %d keys, want %d", got, want)
	}
	if b.Derivation.SeedFingerprint != fingerprint([]byte(CarveDomain), carveFixtureSeed) {
		t.Fatal("reader-carved bundle does not bind to the consumed seed")
	}
}

// TestCommittedCarveFixtureMatchesDerivation is the drift guard that keeps the
// checked-in conformance fixture honest. It re-carves from the authoritative
// test seed and roles and requires the committed file under
// ../conform/testdata to be byte-identical. A change to the derivation, the
// seed or the roles that is not also reflected in the fixture makes this test
// fail — the same contract carrierhost.TestGeneratedPlatformKeyFilesAreCurrent
// gives the platform key lists.
func TestCommittedCarveFixtureMatchesDerivation(t *testing.T) {
	want, err := Carve(carveFixtureSeed, carveFixtureRoles)
	if err != nil {
		t.Fatalf("carve: %v", err)
	}
	wantRaw, err := MarshalBundle(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	path := filepath.Join("..", "conform", "testdata", "winn3_carrier_keybundle.json")
	gotRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed fixture %s: %v", path, err)
	}
	if !bytes.Equal(gotRaw, wantRaw) {
		t.Fatalf("committed fixture %s is stale; regenerate with\n"+
			"  cd winn_protocol_experimental && ./winn-carrier-keys -carve "+
			"winn3/conform/testdata -carve-seed <fixture seed> -carve-roles %s",
			path, strings.Join(carveFixtureRoles, ","))
	}
}

// TestCommittedCarveFixtureIsDecodableJSON guards against a hand-edited file
// that is byte-equal to nothing and not even valid JSON: the drift test
// compares bytes, this one confirms the committed file is a well-formed
// public-only bundle with the expected shape.
func TestCommittedCarveFixtureIsDecodableJSON(t *testing.T) {
	path := filepath.Join("..", "conform", "testdata", "winn3_carrier_keybundle.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed fixture: %v", err)
	}
	var b CarveBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("committed fixture is not valid JSON: %v", err)
	}
	if b.Format != CarveVersion {
		t.Fatalf("committed fixture format %q, want %q", b.Format, CarveVersion)
	}
	if len(b.Keys) != len(carveFixtureRoles) {
		t.Fatalf("committed fixture has %d keys, want %d", len(b.Keys), len(carveFixtureRoles))
	}
	for _, k := range b.Keys {
		if k.Role == "" || k.PublicKeyHex == "" || k.Fingerprint == "" {
			t.Fatalf("committed fixture has an empty field in key %+v", k)
		}
	}
}

// TestFingerprintIsHexOfHashBytesNotHexPrefix.
//
// The old comment said "first 16 bytes of hex(sha256(m))", which is 16 hex
// characters. The code is hex(sum[:16]) — 32 hex characters. A "fix" that
// matched the comment would shorten every public-key fingerprint and break
// every committed fixture that records one.
func TestFingerprintIsHexOfHashBytesNotHexPrefix(t *testing.T) {
	t.Parallel()
	b, err := Carve(carveFixtureSeed, DefaultCarveRoles)
	if err != nil {
		t.Fatalf("carve: %v", err)
	}
	if len(b.Derivation.SeedFingerprint) != 64 {
		t.Fatalf("seed fingerprint is %d hex chars, want 64 (full sha256)", len(b.Derivation.SeedFingerprint))
	}
	for _, k := range b.Keys {
		if len(k.Fingerprint) != 32 {
			t.Fatalf("role %q fingerprint is %d hex chars, want 32 (hex of 16 hash bytes)", k.Role, len(k.Fingerprint))
		}
	}
}
