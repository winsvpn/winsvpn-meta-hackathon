package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/winn3/dualsign"
)

// deriveKeygenDir runs keygen into a fresh directory and returns it.
func deriveKeygenDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	return dir
}

func deriveArgs(staticPath, edPath, mlPath, out string) []string {
	args := []string{"-mode", "derive-public"}
	for _, kv := range [][2]string{
		{"-static", staticPath},
		{"-dual-auth-ed-key", edPath},
		{"-dual-auth-ml-seed", mlPath},
		{"-out", out},
	} {
		if kv[1] != "" {
			args = append(args, kv[0], kv[1])
		}
	}
	return args
}

func deriveReadHex(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := hex.DecodeString(string(raw))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return decoded
}

func deriveWrite(t *testing.T, path string, body []byte) string {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The data-plane installer compares these files with keygen's .pub outputs and
// installs them as the node's public halves, so they must be keygen's files
// byte for byte: same names, same lowercase hex, no newline, nothing else.
func TestDerivePublicMatchesKeygen(t *testing.T) {
	src := deriveKeygenDir(t)
	out := filepath.Join(t.TempDir(), "derived")
	var stdout bytes.Buffer
	err := run(deriveArgs(
		filepath.Join(src, "static.key"),
		filepath.Join(src, "auth_ed25519.seed"),
		filepath.Join(src, "auth_mldsa65.seed"),
		out), &stdout)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if got, want := strings.Join(names, ","), "auth_ed25519.pub,auth_mldsa65.pub,static.pub"; got != want {
		t.Fatalf("derive-public wrote %s, want exactly %s", got, want)
	}
	sizes := map[string]int{"static.pub": 64, "auth_ed25519.pub": 64, "auth_mldsa65.pub": 3904}
	for _, name := range derivedPublicFiles {
		got, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s differs from keygen's", name)
		}
		if len(got) != sizes[name] {
			t.Fatalf("%s is %d bytes, want %d", name, len(got), sizes[name])
		}
		if runtime.GOOS != "windows" {
			info, err := os.Stat(filepath.Join(out, name))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("%s has mode %04o, want 0600 as keygen writes", name, info.Mode().Perm())
			}
		}
	}
	staticPub, _ := os.ReadFile(filepath.Join(src, "static.pub"))
	if !strings.Contains(stdout.String(), `"event":"derive-public"`) ||
		!strings.Contains(stdout.String(), `"gateway_public":"`+string(staticPub)+`"`) {
		t.Fatalf("stdout %q does not name the event and the gateway public key", stdout.String())
	}

	// -static is read as -mode serve reads it, so a raw 32-byte key derives
	// the same half as keygen's hex.
	raw := deriveWrite(t, filepath.Join(t.TempDir(), "static.raw"), deriveReadHex(t, filepath.Join(src, "static.key")))
	rawOut := filepath.Join(t.TempDir(), "raw")
	if err := runDerivePublic(raw, filepath.Join(src, "auth_ed25519.seed"),
		filepath.Join(src, "auth_mldsa65.seed"), rawOut, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(rawOut, "static.pub")); !bytes.Equal(got, staticPub) {
		t.Fatalf("raw static key derived %q, want %q", got, staticPub)
	}
}

// Each half is checked against its secret by a path other than the one that
// derived it: X25519 through crypto/ecdh, and both dual-auth halves by
// verifying a signature their secrets made.
func TestDerivePublicHalvesBelongToTheSecrets(t *testing.T) {
	src := deriveKeygenDir(t)
	out := t.TempDir()
	if err := runDerivePublic(filepath.Join(src, "static.key"), filepath.Join(src, "auth_ed25519.seed"),
		filepath.Join(src, "auth_mldsa65.seed"), out, io.Discard); err != nil {
		t.Fatal(err)
	}

	x, err := ecdh.X25519().NewPrivateKey(deriveReadHex(t, filepath.Join(src, "static.key")))
	if err != nil {
		t.Fatal(err)
	}
	if got := deriveReadHex(t, filepath.Join(out, "static.pub")); !bytes.Equal(got, x.PublicKey().Bytes()) {
		t.Fatal("static.pub is not the X25519 public key of static.key")
	}

	hash := sha256.Sum256([]byte("winn3-gateway derive-public"))
	edSig, err := dualsign.SignEd25519(ed25519.PrivateKey(deriveReadHex(t, filepath.Join(src, "auth_ed25519.seed"))), hash[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := dualsign.VerifyEd25519(deriveReadHex(t, filepath.Join(out, "auth_ed25519.pub")), hash[:], edSig); err != nil {
		t.Fatalf("auth_ed25519.pub does not verify its seed's signature: %v", err)
	}

	signer, err := pqauth.NewSigner(pqauth.MLDSA65, deriveReadHex(t, filepath.Join(src, "auth_mldsa65.seed")))
	if err != nil {
		t.Fatal(err)
	}
	mlSig, err := dualsign.SignMLDSA65(signer, hash[:])
	signer.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := pqauth.NewVerifier(pqauth.MLDSA65, deriveReadHex(t, filepath.Join(out, "auth_mldsa65.pub")))
	if err != nil {
		t.Fatal(err)
	}
	if err := dualsign.VerifyMLDSA65(verifier, hash[:], mlSig); err != nil {
		t.Fatalf("auth_mldsa65.pub does not verify its seed's signature: %v", err)
	}
}

// Every refusal happens before -out is created, so a refused run leaves
// nothing behind for an installer to mistake for derived halves.
func TestDerivePublicRefusesBeforeWriting(t *testing.T) {
	src := deriveKeygenDir(t)
	static := filepath.Join(src, "static.key")
	ed := filepath.Join(src, "auth_ed25519.seed")
	ml := filepath.Join(src, "auth_mldsa65.seed")
	bad := t.TempDir()

	edPriv := deriveReadHex(t, ed)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	mixed := append(append([]byte(nil), edPriv[:ed25519.SeedSize]...), other[ed25519.SeedSize:]...)
	mismatchedEd := deriveWrite(t, filepath.Join(bad, "ed.mixed"), []byte(hex.EncodeToString(mixed)))
	seedOnlyEd := deriveWrite(t, filepath.Join(bad, "ed.seed32"), []byte(hex.EncodeToString(edPriv[:ed25519.SeedSize])))
	shortML := deriveWrite(t, filepath.Join(bad, "ml.short"), []byte(strings.Repeat("ab", 31)))
	nonHexML := deriveWrite(t, filepath.Join(bad, "ml.nonhex"), []byte(strings.Repeat("zz", 32)))
	link := filepath.Join(bad, "static.link")
	if err := os.Symlink(static, link); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name               string
		static, ed, ml, to string
		want               string
	}{
		{"no -out", static, ed, ml, "-", "derive-public needs -out"},
		{"no -static", "", ed, ml, "", "derive-public needs -static, -dual-auth-ed-key and -dual-auth-ml-seed"},
		{"no -dual-auth-ed-key", static, "", ml, "", "derive-public needs -static, -dual-auth-ed-key and -dual-auth-ml-seed"},
		{"no -dual-auth-ml-seed", static, ed, "", "", "derive-public needs -static, -dual-auth-ed-key and -dual-auth-ml-seed"},
		{"missing static file", filepath.Join(bad, "absent"), ed, ml, "", "-static:"},
		{"static is a symlink", link, ed, ml, "", "not a regular file"},
		{"ed key is a bare seed", static, seedOnlyEd, ml, "", "-dual-auth-ed-key must hold 64 bytes hex"},
		{"ed key public half from another seed", static, mismatchedEd, ml, "", "not derived from the seed"},
		{"ml seed too short", static, ed, shortML, "", "-dual-auth-ml-seed must hold 32 bytes hex"},
		{"ml seed not hex", static, ed, nonHexML, "", "-dual-auth-ml-seed must hold 32 bytes hex"},
	}
	if runtime.GOOS != "windows" {
		open := deriveWrite(t, filepath.Join(bad, "static.0644"), []byte(hex.EncodeToString(deriveReadHex(t, static))))
		if err := os.Chmod(open, 0o644); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, struct {
			name               string
			static, ed, ml, to string
			want               string
		}{"static readable by others", open, ed, ml, "", "want no group/other access"})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "derived")
			to := out
			if tc.to == "-" {
				to = ""
			}
			err := run(deriveArgs(tc.static, tc.ed, tc.ml, to), io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
			if _, statErr := os.Lstat(out); !os.IsNotExist(statErr) {
				t.Fatalf("-out %s exists after a refused run (stat err %v)", out, statErr)
			}
		})
	}
}

// O_EXCL, as keygen: a half already present is never replaced.
func TestDerivePublicRefusesToOverwrite(t *testing.T) {
	src := deriveKeygenDir(t)
	out := t.TempDir()
	existing := deriveWrite(t, filepath.Join(out, "static.pub"), []byte("keep"))
	err := runDerivePublic(filepath.Join(src, "static.key"), filepath.Join(src, "auth_ed25519.seed"),
		filepath.Join(src, "auth_mldsa65.seed"), out, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite existing key file static.pub") {
		t.Fatalf("err = %v, want an overwrite refusal", err)
	}
	if got, _ := os.ReadFile(existing); string(got) != "keep" {
		t.Fatalf("existing static.pub became %q", got)
	}
}

// CLAUDE-S1-T1-1 (Round S1 review, Turn 1): every name is checked before the
// first write, so a half that exists only for a later name still leaves no
// partial set; Turn 1 wrote static.pub and auth_ed25519.pub first.
func TestDerivePublicRefusesBeforeAnyWriteWhenALaterHalfExists(t *testing.T) {
	src := deriveKeygenDir(t)
	out := t.TempDir()
	existing := deriveWrite(t, filepath.Join(out, "auth_mldsa65.pub"), []byte("keep"))
	err := runDerivePublic(filepath.Join(src, "static.key"), filepath.Join(src, "auth_ed25519.seed"),
		filepath.Join(src, "auth_mldsa65.seed"), out, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite existing key file auth_mldsa65.pub") {
		t.Fatalf("err = %v, want an overwrite refusal naming auth_mldsa65.pub", err)
	}
	for _, name := range []string{"static.pub", "auth_ed25519.pub"} {
		if _, statErr := os.Lstat(filepath.Join(out, name)); !os.IsNotExist(statErr) {
			t.Fatalf("%s exists after a refused run (stat err %v): a partial set was left behind", name, statErr)
		}
	}
	if got, _ := os.ReadFile(existing); string(got) != "keep" {
		t.Fatalf("existing auth_mldsa65.pub became %q", got)
	}
}

func TestUnknownModeNamesDerivePublic(t *testing.T) {
	err := run([]string{"-mode", "nope"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "use keygen, derive-public, serve, resources or features") {
		t.Fatalf("err = %v", err)
	}
}

func TestFeaturesModeNamesPeerRegistryTier(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"-mode", "features"}, &buf); err != nil {
		t.Fatalf("features mode failed: %v", err)
	}
	features := map[string]bool{}
	for _, line := range strings.Split(buf.String(), "\n") {
		if line != "" {
			features[line] = true
		}
	}
	if !features["peer-registry-tier"] {
		t.Fatalf("features output lacks peer-registry-tier: %q", buf.String())
	}
}
