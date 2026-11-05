package carrier

// Carve is the derivation behind the winn-carrier-keys CLI: a single seed
// carves a standalone set of winn3 carrier identity key pairs.
//
// What "carve" means here, and why it exists
//
// A carrier identity in winn3 is an X25519 static key (core.StaticKey): the
// same classical proof-of-possession key that the handshake in
// winn3/core/keys.go describes. Four hosts, four languages and a conformance
// rig all need the same set of these identities, and none of them can link a
// shared constant. Carve derives every identity in a bundle from one 32-byte
// seed through HKDF-SHA256 with per-role domain separation, so a whole fleet
// of carrier key pairs is one seed away instead of N individually managed
// files — the same discipline TEST_VECTORS.md already applies to the v2 PSKs.
//
// The private half is never exposed by this package. Derivation happens in
// memory for the caller that owns the seed; the Bundle a carve produces is
// PUBLIC-ONLY — X25519 public keys and fingerprints, plus a digest of the
// seed, never the seed itself and never a private scalar. A committed
// conformance fixture can therefore be checked in without becoming a secret,
// and a producer that holds the seed can re-derive the private halves offline
// without any of them ever touching a log, a print, or a file.
//
// This file is deliberately additive. It changes no existing carrier
// behaviour and adds one error sentinel only.

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"winsvpn.local/winnprotocol/winn3/core"
)

// CarveDomain is the fixed HKDF salts/info domain. It is the one string that
// separates a carved key from any other HKDF use in this tree; change it and
// every previously carved public key changes.
const CarveDomain = "winsvpn.winn3.carrier-keybundle"

// CarveVersion identifies the bundle serialization. Bump on any incompatible
// change to the JSON layout.
const CarveVersion = "winn3.carrier-keybundle.v1"

// CarveKDF is the advertised derivation, for readers of a fixture.
const CarveKDF = "HKDF-SHA256-X25519"

// CarvedKey is one derived carrier identity. It carries its public half and a
// fingerprint of it, and deliberately nothing else: there is no private field
// in this struct, so a JSON marshal of a Bundle cannot leak one.
type CarvedKey struct {
	Role         string `json:"role"`
	PublicKeyHex string `json:"public_key_hex"`
	Fingerprint  string `json:"public_key_fingerprint"`
}

// CarveDerivation records how a bundle was derived. SeedFingerprint is
// sha256(CarveDomain || seed), a digest that binds the bundle to its seed
// without exposing the seed — and therefore without exposing the private
// halves it would derive.
type CarveDerivation struct {
	KDF             string `json:"kdf"`
	Domain          string `json:"domain"`
	SeedFingerprint string `json:"seed_fingerprint"`
}

// CarveBundle is the public-only, standalone bundle. Keys is sorted by role so
// a marshal is byte-stable for the same inputs.
type CarveBundle struct {
	Format     string          `json:"format"`
	Derivation CarveDerivation `json:"derivation"`
	Keys       []CarvedKey     `json:"keys"`
}

// ErrCarveConfig is returned for an invalid carve request — a missing or
// repeated role, or a role label that could not be used safely as a file
// component. Refusing a label at carve time instead of accepting a plausible
// one is the same choice the rest of this package makes for a malformed
// stream: an error now, not silent confusion later.
var ErrCarveConfig = fmt.Errorf("winn3/carrier: invalid carve configuration")

// DefaultCarveRoles are the identities a bare carve emits: one gateway and one
// client per named host, mirroring the fleet's wins-sea-01 naming.
var DefaultCarveRoles = []string{
	"gateway.wins-sea-01",
	"client.wins-sea-01",
}

// ValidateCarveRoles returns an error if roles cannot be carved: empty, a
// blank label, a duplicate, or a label that is unsafe as a file component.
func ValidateCarveRoles(roles []string) error {
	if len(roles) == 0 {
		return wrap(ErrCarveConfig, "no roles to carve")
	}
	seen := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		if r == "" {
			return wrap(ErrCarveConfig, "a role label is empty")
		}
		if strings.TrimSpace(r) != r || strings.ContainsAny(r, " \t\r\n/\\") {
			return wrap(ErrCarveConfig, "role %q is not a safe label", r)
		}
		if _, ok := seen[r]; ok {
			return wrap(ErrCarveConfig, "role %q is repeated", r)
		}
		seen[r] = struct{}{}
	}
	return nil
}

// Carve derives one X25519 carrier identity key pair per role from seed.
//
// seed must be exactly core.KeySize bytes. The returned Bundle contains public
// halves and fingerprints only. The private scalars are derived transiently
// and dropped; there is no accessor that returns them. To reproduce the same
// public keys, pass the same seed — derive is deterministic by construction of
// the KDF.
func Carve(seed []byte, roles []string) (*CarveBundle, error) {
	if err := ValidateCarveRoles(roles); err != nil {
		return nil, err
	}
	if len(seed) != core.KeySize {
		return nil, wrap(ErrCarveConfig,
			"seed is %d bytes, need %d", len(seed), core.KeySize)
	}

	b := &CarveBundle{
		Format: CarveVersion,
		Derivation: CarveDerivation{
			KDF:             CarveKDF,
			Domain:          CarveDomain,
			SeedFingerprint: fingerprint([]byte(CarveDomain), seed),
		},
	}

	prk, err := hkdf.Extract(sha256.New, seed, []byte(CarveDomain))
	if err != nil {
		return nil, wrap(ErrCarveConfig, "hkdf extract: %v", err)
	}

	for _, role := range roles {
		scalar, err := hkdf.Expand(sha256.New, prk, role, core.KeySize)
		if err != nil {
			return nil, wrap(ErrCarveConfig, "hkdf expand %q: %v", role, err)
		}
		sk, err := core.NewStaticKey(scalar)
		if err != nil {
			return nil, wrap(ErrCarveConfig, "role %q did not yield a valid key: %v", role, err)
		}
		pub := sk.Public()
		if _, err := core.NewPublicKey(pub); err != nil {
			return nil, wrap(ErrCarveConfig, "role %q produced an invalid public key: %v", role, err)
		}
		b.Keys = append(b.Keys, CarvedKey{
			Role:         role,
			PublicKeyHex: hex.EncodeToString(pub),
			Fingerprint:  fingerprint(nil, pub),
		})
	}

	sort.Slice(b.Keys, func(i, j int) bool { return b.Keys[i].Role < b.Keys[j].Role })
	return b, nil
}

// CarveFromReader draws a seed of exactly core.KeySize bytes from r and carves
// the given roles from it. It is the non-command entry point so that a caller
// controlling the reader (e.g. a pinned reader under a test) can reproduce a
// carve without a private key ever crossing a boundary.
func CarveFromReader(r io.Reader, roles []string) (*CarveBundle, error) {
	if err := ValidateCarveRoles(roles); err != nil {
		return nil, err
	}
	seed := make([]byte, core.KeySize)
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, wrap(ErrCarveConfig, "could not read a %d-byte seed: %v", core.KeySize, err)
	}
	return Carve(seed, roles)
}

// MarshalBundle renders the public-only bundle as stable JSON. It is the exact
// bytes the CLI writes and a test asserts the committed fixture matches.
func MarshalBundle(b *CarveBundle) ([]byte, error) {
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// RolePublicKey returns the public-key hex for a role, or "" if absent.
func (b *CarveBundle) RolePublicKey(role string) string {
	for _, k := range b.Keys {
		if k.Role == role {
			return k.PublicKeyHex
		}
	}
	return ""
}

// fingerprint is hex(sha256(prefix||m)) when prefix is non-empty (64 hex
// chars: a seed digest binds the domain), or hex of the first 16 bytes of
// sha256(m) when prefix is empty (32 hex chars: a public-key fingerprint).
// That is hex(sum[:16]), not the first 16 characters of the hex string.
func fingerprint(prefix, m []byte) string {
	h := sha256.New()
	if len(prefix) > 0 {
		h.Write(prefix)
	}
	h.Write(m)
	sum := h.Sum(nil)
	if len(prefix) > 0 {
		return hex.EncodeToString(sum)
	}
	return hex.EncodeToString(sum[:16])
}

// randomSeed draws core.KeySize random bytes. It is unused by
// cmd/winn-carrier-keys, which draws the seed itself in carveSeedBytes; it
// never prints the seed.
func randomSeed() ([]byte, error) {
	seed := make([]byte, core.KeySize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, err
	}
	return seed, nil
}
