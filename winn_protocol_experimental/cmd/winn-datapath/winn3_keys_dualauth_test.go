package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/winn3/dualsign"
	"winsvpn.local/winnprotocol/winn3/session"
)

func writeHexKey(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(hex.EncodeToString(raw)+"\n"), mode); err != nil {
		t.Fatal(err)
	}
}

func stagedDualAuth(t *testing.T, dir string) (edPath, mlPath string, edPub, mlPub []byte) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := pqauth.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	mlPub = append([]byte(nil), signer.PublicBytes()...)
	signer.Destroy()
	edPath = filepath.Join(dir, "auth_ed25519.pub")
	mlPath = filepath.Join(dir, "auth_mldsa65.pub")
	writeHexKey(t, edPath, pub, 0o600)
	writeHexKey(t, mlPath, mlPub, 0o600)
	return edPath, mlPath, append([]byte(nil), pub...), mlPub
}

func TestFrameModeSessionConfigIngestsStagedDualAuth(t *testing.T) {
	dir := t.TempDir()
	document := validKeys(t, dir)
	edPath, mlPath, edPub, mlPub := stagedDualAuth(t, dir)
	document["dual_auth_ed25519_pub_path"] = edPath
	document["dual_auth_mldsa65_pub_path"] = mlPath
	keys, err := loadWinn3Keys(writeKeys(t, dir, document))
	if err != nil {
		t.Fatalf("dual-auth key document was refused: %v", err)
	}
	cfg, _, err := keys.sessionConfig()
	if err != nil {
		t.Fatalf("sessionConfig did not ingest staged dual-auth keys: %v", err)
	}
	if err := requireLiveDualAuth(keys, cfg); err != nil {
		t.Fatalf("CreateAck gate refused live dual-auth: %v", err)
	}
	if !cfg.DualAuth.Expected {
		t.Fatal("session.Config.DualAuth.Expected was not set")
	}
	if !bytes.Equal(cfg.DualAuth.Ed25519Public, edPub) {
		t.Fatal("ingested Ed25519 public key does not match the staged file")
	}
	if !bytes.Equal(cfg.DualAuth.MLDSA65Public, mlPub) {
		t.Fatal("ingested ML-DSA public key does not match the staged file")
	}
	if len(cfg.DualAuth.Ed25519Public) != dualsign.Ed25519PublicKeySize ||
		len(cfg.DualAuth.MLDSA65Public) != dualsign.MLDSA65PublicKeySize {
		t.Fatalf("ingested dual-auth sizes %d/%d",
			len(cfg.DualAuth.Ed25519Public), len(cfg.DualAuth.MLDSA65Public))
	}
}

func TestFrameModeCreateAckGateRefusesMissingDualAuthIngest(t *testing.T) {
	dir := t.TempDir()
	document := validKeys(t, dir)
	edPath, mlPath, _, _ := stagedDualAuth(t, dir)
	keys, err := loadWinn3Keys(writeKeys(t, dir, document))
	if err != nil {
		t.Fatal(err)
	}
	keys.DualAuthEd25519PubPath = edPath
	keys.DualAuthMLDSA65PubPath = mlPath
	if err := requireLiveDualAuth(keys, session.Config{}); err == nil {
		t.Fatal("CreateAck was allowed without ingesting staged dual-auth keys")
	} else if !strings.Contains(err.Error(), "not ingested") {
		t.Fatalf("refusal does not name the missing ingest: %v", err)
	}
}

func TestPrivateKeyReadsRefuseSymlinksAndGroupAccess(t *testing.T) {
	dir := t.TempDir()
	document := validKeys(t, dir)
	keys, err := loadWinn3Keys(writeKeys(t, dir, document))
	if err != nil {
		t.Fatal(err)
	}

	world := filepath.Join(dir, "world-admission.key")
	if err := os.WriteFile(world, []byte("lab-admission-secret-padded-to-32-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	keys.AdmissionPath = world
	if _, _, err := keys.sessionConfig(); err == nil {
		t.Fatal("a group/other-readable admission file was accepted")
	} else if !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("world-readable refusal does not name permissions: %v", err)
	}

	target := filepath.Join(dir, "real-static.key")
	if err := os.WriteFile(target, bytes.Repeat([]byte{0x11}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "static.link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	keys, err = loadWinn3Keys(writeKeys(t, dir, validKeys(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	keys.StaticPath = link
	if _, _, err := keys.sessionConfig(); err == nil {
		t.Fatal("a symlink static key was accepted")
	} else if !strings.Contains(err.Error(), "regular file") &&
		!strings.Contains(err.Error(), "symbolic") {
		t.Fatalf("symlink refusal is unrecognisable: %v", err)
	}
}

func TestDesktopAndFrameDualAuthHelpersShareTheSameIngest(t *testing.T) {
	dir := t.TempDir()
	edPath, mlPath, edPub, mlPub := stagedDualAuth(t, dir)
	var cfg session.Config
	if err := applyDualAuthPublics(&cfg, edPath, mlPath); err != nil {
		t.Fatal(err)
	}
	if !cfg.DualAuth.Expected || !bytes.Equal(cfg.DualAuth.Ed25519Public, edPub) ||
		!bytes.Equal(cfg.DualAuth.MLDSA65Public, mlPub) {
		t.Fatal("applyDualAuthPublics did not load the staged public keys")
	}
	if err := applyDualAuthPublics(&session.Config{}, edPath, ""); err == nil {
		t.Fatal("a split dual-auth pair was accepted")
	}
}
