//go:build darwin

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/winn3/dualsign"
)

func testWinn3DualAuthPublics(t *testing.T, seedByte byte) ([]byte, []byte) {
	t.Helper()
	edPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
	edPublic := append([]byte(nil), edPrivate.Public().(ed25519.PublicKey)...)
	mlSigner, err := pqauth.NewSigner(pqauth.MLDSA65, bytes.Repeat([]byte{seedByte + 1}, dualsign.MLDSA65SeedSize))
	if err != nil {
		t.Fatalf("build ML-DSA-65 signer: %v", err)
	}
	t.Cleanup(mlSigner.Destroy)
	mlPublic := append([]byte(nil), mlSigner.PublicBytes()...)
	return edPublic, mlPublic
}

func TestWinn3DualAuthPairBindsExactPublicKeysIntoTheCreatedSession(t *testing.T) {
	edPublic, mlPublic := testWinn3DualAuthPublics(t, 0x21)
	doc := baseConfig(t)
	doc["auth_ed25519"] = base64.StdEncoding.EncodeToString(edPublic)
	doc["auth_mldsa65"] = base64.StdEncoding.EncodeToString(mlPublic)

	cfg, err := decodeWinn3Config(encode(t, doc))
	if err != nil {
		t.Fatalf("decode exact dual-auth pair: %v", err)
	}
	if !cfg.dualAuth.Expected {
		t.Fatal("the exact pair did not set session.DualAuth.Expected")
	}
	if !bytes.Equal(cfg.dualAuth.Ed25519Public, edPublic) {
		t.Fatal("the session config did not retain the exact Ed25519 public key bytes")
	}
	if !bytes.Equal(cfg.dualAuth.MLDSA65Public, mlPublic) {
		t.Fatal("the session config did not retain the exact ML-DSA-65 public key bytes")
	}

	fd, peer, loopFile := loopbackPair(t)
	defer peer.Close()
	defer loopFile.Close()
	tunnel, err := openWinn3(encode(t, doc), fd)
	if err != nil {
		t.Fatalf("the live C create path did not bind the exact pair: %v", err)
	}
	defer tunnel.close()
	if tunnel.loop.Session().DualAuthVerified() {
		t.Fatal("a newly created client reported dual-auth verified before any gateway attestation")
	}
}

func TestWinn3DualAuthAbsentPairPreservesTheLegacyCreateShape(t *testing.T) {
	cfg, err := decodeWinn3Config(encode(t, baseConfig(t)))
	if err != nil {
		t.Fatalf("decode legacy create document: %v", err)
	}
	if cfg.dualAuth.Expected || len(cfg.dualAuth.Ed25519Public) != 0 || len(cfg.dualAuth.MLDSA65Public) != 0 {
		t.Fatal("a legacy document acquired stale dual-auth material")
	}
}

func TestWinn3DualAuthExplicitEmptyPairCannotSelectLegacyMode(t *testing.T) {
	doc := baseConfig(t)
	doc["auth_ed25519"] = ""
	doc["auth_mldsa65"] = ""
	_, err := openWinn3(encode(t, doc), -1)
	if err == nil || !strings.Contains(err.Error(), "auth_ed25519") {
		t.Fatalf("an explicitly empty pair selected legacy mode: %v", err)
	}
	if strings.Contains(err.Error(), "allow_own_socket") {
		t.Fatalf("empty dual-auth validation ran after the socket rule: %v", err)
	}
}

func TestWinn3DualAuthHalfProvisionedAndWrongLengthRefuseBeforeTheSocketRule(t *testing.T) {
	edPublic, mlPublic := testWinn3DualAuthPublics(t, 0x31)
	edB64 := base64.StdEncoding.EncodeToString(edPublic)
	mlB64 := base64.StdEncoding.EncodeToString(mlPublic)

	rows := []struct {
		name  string
		ed    string
		ml    string
		field string
	}{
		{name: "missing Ed25519 half", ml: mlB64, field: "auth_ed25519"},
		{name: "missing ML-DSA-65 half", ed: edB64, field: "auth_mldsa65"},
		{name: "Ed25519 31 bytes", ed: base64.StdEncoding.EncodeToString(edPublic[:31]), ml: mlB64, field: "auth_ed25519"},
		{name: "Ed25519 33 bytes", ed: base64.StdEncoding.EncodeToString(append(edPublic, 0)), ml: mlB64, field: "auth_ed25519"},
		{name: "ML-DSA-65 1951 bytes", ed: edB64, ml: base64.StdEncoding.EncodeToString(mlPublic[:1951]), field: "auth_mldsa65"},
		{name: "ML-DSA-65 1953 bytes", ed: edB64, ml: base64.StdEncoding.EncodeToString(append(mlPublic, 0)), field: "auth_mldsa65"},
		{name: "Ed25519 invalid base64", ed: "not base64!", ml: mlB64, field: "auth_ed25519"},
		{name: "ML-DSA-65 invalid base64", ed: edB64, ml: "not base64!", field: "auth_mldsa65"},
		{name: "Ed25519 non-canonical base64", ed: edB64 + "\n", ml: mlB64, field: "auth_ed25519"},
		{name: "ML-DSA-65 non-canonical base64", ed: edB64, ml: mlB64 + "\n", field: "auth_mldsa65"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			doc := baseConfig(t)
			if row.ed != "" {
				doc["auth_ed25519"] = row.ed
			}
			if row.ml != "" {
				doc["auth_mldsa65"] = row.ml
			}
			_, err := openWinn3(encode(t, doc), -1)
			if err == nil {
				t.Fatal("invalid dual-auth material reached create")
			}
			if !strings.Contains(err.Error(), row.field) {
				t.Fatalf("refusal %q does not name %s", err, row.field)
			}
			if strings.Contains(err.Error(), "allow_own_socket") {
				t.Fatalf("dual-auth validation ran after the socket rule: %v", err)
			}
		})
	}
}

func TestWinn3DualAuthASecondDecodeCannotReuseStaleMaterial(t *testing.T) {
	edPublic, mlPublic := testWinn3DualAuthPublics(t, 0x41)
	dual := baseConfig(t)
	dual["auth_ed25519"] = base64.StdEncoding.EncodeToString(edPublic)
	dual["auth_mldsa65"] = base64.StdEncoding.EncodeToString(mlPublic)
	first, err := decodeWinn3Config(encode(t, dual))
	if err != nil || !first.dualAuth.Expected {
		t.Fatalf("first dual-auth decode failed: expected=%t err=%v", first.dualAuth.Expected, err)
	}
	replacementEd, replacementML := testWinn3DualAuthPublics(t, 0x43)
	replacement := baseConfig(t)
	replacement["auth_ed25519"] = base64.StdEncoding.EncodeToString(replacementEd)
	replacement["auth_mldsa65"] = base64.StdEncoding.EncodeToString(replacementML)
	second, err := decodeWinn3Config(encode(t, replacement))
	if err != nil {
		t.Fatalf("replacement dual-auth decode failed: %v", err)
	}
	if !bytes.Equal(second.dualAuth.Ed25519Public, replacementEd) ||
		!bytes.Equal(second.dualAuth.MLDSA65Public, replacementML) {
		t.Fatal("a fresh create reused the predecessor session's dual-auth pair")
	}
	legacy, err := decodeWinn3Config(encode(t, baseConfig(t)))
	if err != nil {
		t.Fatalf("second legacy decode failed: %v", err)
	}
	if legacy.dualAuth.Expected || len(legacy.dualAuth.Ed25519Public) != 0 || len(legacy.dualAuth.MLDSA65Public) != 0 {
		t.Fatal("a later legacy decode reused stale dual-auth material")
	}
}

func TestWinn3DualAuthDuplicateReplacementIsRefusedWithoutChangingLegacyDuplicateSemantics(t *testing.T) {
	edPublic, mlPublic := testWinn3DualAuthPublics(t, 0x51)
	doc := baseConfig(t)
	doc["auth_ed25519"] = base64.StdEncoding.EncodeToString(edPublic)
	doc["auth_mldsa65"] = base64.StdEncoding.EncodeToString(mlPublic)
	encoded := string(encode(t, doc))
	rows := []struct {
		field string
		value string
	}{
		{
			field: "auth_ed25519",
			value: base64.StdEncoding.EncodeToString(bytes.Repeat(
				[]byte{0xEE}, dualsign.Ed25519PublicKeySize)),
		},
		{
			field: "auth_mldsa65",
			value: base64.StdEncoding.EncodeToString(bytes.Repeat(
				[]byte{0xEF}, dualsign.MLDSA65PublicKeySize)),
		},
	}
	for _, row := range rows {
		for _, value := range []string{row.value, doc[row.field].(string)} {
			replaced := strings.TrimSuffix(encoded, "}") +
				`,"` + row.field + `":"` + value + `"}`
			if _, err := decodeWinn3Config([]byte(replaced)); err == nil ||
				!strings.Contains(err.Error(), row.field) ||
				!strings.Contains(err.Error(), "duplicated") {
				t.Fatalf("duplicate %s was not refused by name: %v", row.field, err)
			}
		}
	}
	caseVariant := strings.TrimSuffix(encoded, "}") +
		`,"AUTH_ED25519":"` + doc["auth_ed25519"].(string) + `"}`
	if _, err := decodeWinn3Config([]byte(caseVariant)); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "auth_ed25519") {
		t.Fatalf("case-variant replacement was not refused: %v", err)
	}

	// Existing create fields retain encoding/json's pinned last-key-wins
	// compatibility. Only the newly introduced attestation pair is hardened
	// against duplicate replacement.
	legacyDuplicate := `{"contract":"wrong","contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"winn3"}`
	if _, err := decodeWinn3Config([]byte(legacyDuplicate)); err != nil {
		t.Fatalf("legacy duplicate-field compatibility changed: %v", err)
	}
}
