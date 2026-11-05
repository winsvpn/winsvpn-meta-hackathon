package echconfig_test

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

const rotationPublicName = "cdn.cover-origin.net"

func TestRotateKeepsOldKeySecondAndSendsOnlyTheNewOneAsRetry(t *testing.T) {
	oldList, oldFile, err := echconfig.Generate(rotationPublicName, 9)
	if err != nil {
		t.Fatal(err)
	}
	newList, rotated, err := echconfig.Rotate(oldFile, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rotated.Keys) != 2 {
		t.Fatalf("rotated file has %d entries, want 2", len(rotated.Keys))
	}
	if !rotated.Keys[0].SendAsRetry || rotated.Keys[1].SendAsRetry {
		t.Fatalf("send_as_retry = [%t %t], want [true false]",
			rotated.Keys[0].SendAsRetry, rotated.Keys[1].SendAsRetry)
	}
	if rotated.Keys[1].Config != oldFile.Keys[0].Config ||
		rotated.Keys[1].PrivateKey != oldFile.Keys[0].PrivateKey {
		t.Fatal("the existing key did not survive byte-for-byte as entry 2")
	}
	entries, err := echconfig.Describe(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].PublicName != rotationPublicName || entries[1].PublicName != rotationPublicName {
		t.Fatalf("public names %q/%q, want the existing one inherited", entries[0].PublicName, entries[1].PublicName)
	}
	if entries[0].ConfigID == entries[1].ConfigID {
		t.Fatalf("new key reused config ID %d", entries[0].ConfigID)
	}
	if entries[0].PublicKeySHA256 == entries[1].PublicKeySHA256 {
		t.Fatal("new key equals the old key")
	}
	retry, err := echconfig.RetryConfigList(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retry, newList) {
		t.Fatal("retry config list is not exactly the new key's config list")
	}
	if bytes.Equal(newList, oldList) {
		t.Fatal("new config list equals the old one")
	}
}

// The property the whole overlap exists for: a peer that cached the OLD shared
// config and a peer holding the NEW per-node config are both accepted by a
// server loaded with the rotated file.
func TestRotatedServerAcceptsHoldersOfEitherConfig(t *testing.T) {
	oldList, oldFile, err := echconfig.Generate(rotationPublicName, 9)
	if err != nil {
		t.Fatal(err)
	}
	newList, rotated, err := echconfig.Rotate(oldFile, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	paths := rotationPKI(t)
	server := rotationServer(t, paths, rotated)
	for name, list := range map[string][]byte{"old": oldList, "new": newList} {
		clientState, serverState, clientErr, serverErr := handshake(t, rotationClient(t, paths, list), server)
		if clientErr != nil || serverErr != nil {
			t.Fatalf("%s config: client=%v server=%v", name, clientErr, serverErr)
		}
		if !clientState.ECHAccepted || !serverState.ECHAccepted {
			t.Fatalf("%s config: ECH not accepted", name)
		}
	}
	// Anti-vacuity: a server holding only the OLD key must not accept the new
	// config, or the two-entry file proves nothing.
	oldOnly := rotationServer(t, paths, oldFile)
	_, _, clientErr, serverErr := handshake(t, rotationClient(t, paths, newList), oldOnly)
	if clientErr == nil && serverErr == nil {
		t.Fatal("old-only server accepted the new config")
	}
}

func TestRotateRefusesAnOverlapAlreadyInProgress(t *testing.T) {
	_, oldFile, err := echconfig.Generate(rotationPublicName, 9)
	if err != nil {
		t.Fatal(err)
	}
	_, rotated, err := echconfig.Rotate(oldFile, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := echconfig.Rotate(rotated, "", 0); err == nil ||
		!strings.Contains(err.Error(), "overlap is already in progress") {
		t.Fatalf("second rotation err = %v, want overlap refusal", err)
	}
}

func TestRotateRefusesTheExistingConfigID(t *testing.T) {
	_, oldFile, err := echconfig.Generate(rotationPublicName, 9)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := echconfig.Rotate(oldFile, "", 9); err == nil {
		t.Fatal("rotation reused the existing config ID")
	}
	for range 64 {
		_, rotated, err := echconfig.Rotate(oldFile, "", 0)
		if err != nil {
			t.Fatal(err)
		}
		entries, err := echconfig.Describe(rotated)
		if err != nil {
			t.Fatal(err)
		}
		if entries[0].ConfigID == 9 || entries[0].ConfigID == 0 {
			t.Fatalf("random config ID %d collides or is zero", entries[0].ConfigID)
		}
	}
}

func TestDescribeCarriesNoPrivateKeyMaterial(t *testing.T) {
	_, oldFile, err := echconfig.Generate(rotationPublicName, 9)
	if err != nil {
		t.Fatal(err)
	}
	_, rotated, err := echconfig.Rotate(oldFile, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := echconfig.Describe(rotated)
	if err != nil {
		t.Fatal(err)
	}
	rendered := fmt.Sprintf("%+v %#v", entries, entries)
	for _, entry := range rotated.Keys {
		raw, err := base64.StdEncoding.DecodeString(entry.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		for _, form := range []string{entry.PrivateKey, hex.EncodeToString(raw)} {
			if strings.Contains(strings.ToLower(rendered), strings.ToLower(form)) {
				t.Fatal("Describe output contains a private key")
			}
		}
	}
}

func TestLoadKeyFileRoundTripsAndRefusesGroupReadable(t *testing.T) {
	_, oldFile, err := echconfig.Generate(rotationPublicName, 9)
	if err != nil {
		t.Fatal(err)
	}
	data, err := echconfig.EncodeKeyFile(oldFile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ech-keys.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := echconfig.LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Keys[0] != oldFile.Keys[0] {
		t.Fatal("LoadKeyFile did not round-trip")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := echconfig.LoadKeyFile(path); err == nil {
		t.Fatal("LoadKeyFile accepted a group-readable key file")
	}
}

func rotationServer(t *testing.T, paths pki.Paths, file echconfig.KeyFile) *tls.Config {
	t.Helper()
	keys, err := echconfig.TLSKeys(file)
	if err != nil {
		t.Fatal(err)
	}
	suite, err := tlsconfig.ParseSuite("x25519-mlkem768")
	if err != nil {
		t.Fatal(err)
	}
	config, err := tlsconfig.ServerForALPN(paths.ServerCert, paths.ServerKey, paths.CACert, suite, "h2")
	if err != nil {
		t.Fatal(err)
	}
	if err := echconfig.ConfigureServer(config, keys, true); err != nil {
		t.Fatal(err)
	}
	return config
}

func rotationClient(t *testing.T, paths pki.Paths, list []byte) *tls.Config {
	t.Helper()
	suite, err := tlsconfig.ParseSuite("x25519-mlkem768")
	if err != nil {
		t.Fatal(err)
	}
	config, err := tlsconfig.ClientForALPN(
		paths.DeviceCert, paths.DeviceKey, paths.CACert, "localhost", suite, "h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := echconfig.ConfigureClient(config, list, true); err != nil {
		t.Fatal(err)
	}
	return config
}

func rotationPKI(t *testing.T) pki.Paths {
	t.Helper()
	paths, err := pki.GenerateLab(
		filepath.Join(t.TempDir(), "pki"), "localhost", "ech-device-1", time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return paths
}
