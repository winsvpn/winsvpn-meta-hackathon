package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/echconfig"
)

// runCLI runs the command's run() with argv, returning stdout. The flag set is
// process-global, so each call installs a fresh one.
func runCLI(t *testing.T, argv ...string) (string, error) {
	t.Helper()
	oldArgs, oldFlags, oldStdout := os.Args, flag.CommandLine, os.Stdout
	defer func() { os.Args, flag.CommandLine, os.Stdout = oldArgs, oldFlags, oldStdout }()
	os.Args = append([]string{"winn-ech-keygen"}, argv...)
	flag.CommandLine = flag.NewFlagSet("winn-ech-keygen", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	done := make(chan []byte)
	go func() {
		data, _ := io.ReadAll(reader)
		done <- data
	}()
	runErr := run()
	_ = writer.Close()
	return string(<-done), runErr
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func privateForms(t *testing.T, file echconfig.KeyFile) []string {
	t.Helper()
	var forms []string
	for _, entry := range file.Keys {
		raw, err := base64.StdEncoding.DecodeString(entry.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		forms = append(forms, entry.PrivateKey, hex.EncodeToString(raw))
	}
	return forms
}

func TestAddToWritesTwoEntriesAndNeverPrintsAPrivateKey(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	for _, dir := range []string{first, second} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := runCLI(t, "-public-name", "cdn.cover-origin.net", "-out", first); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(first, "ech-server-keys.json")
	before, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}

	out, err := runCLI(t, "-add-to", existing, "-out", second)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("-add-to modified the existing key file")
	}
	rotated, err := echconfig.LoadKeyFile(filepath.Join(second, "ech-server-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rotated.Keys) != 2 || !rotated.Keys[0].SendAsRetry || rotated.Keys[1].SendAsRetry {
		t.Fatalf("rotated file shape wrong: %d entries", len(rotated.Keys))
	}
	info, err := os.Stat(filepath.Join(second, "ech-server-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %04o, want 0600", info.Mode().Perm())
	}

	described, err := runCLI(t, "-describe", filepath.Join(second, "ech-server-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(described, "entries 2") ||
		!strings.Contains(described, "send_as_retry=true") ||
		!strings.Contains(described, "send_as_retry=false") {
		t.Fatalf("describe output missing fields:\n%s", described)
	}
	list, err := os.ReadFile(filepath.Join(second, "ech-config-list.bin"))
	if err != nil {
		t.Fatal(err)
	}
	listDigest := sha256Hex(list)
	if !strings.Contains(out, "ech_config_list_sha256 "+listDigest) ||
		!strings.Contains(described, "retry_config_list_sha256 "+listDigest) {
		t.Fatal("printed config-list digest does not match ech-config-list.bin")
	}
	for _, form := range privateForms(t, rotated) {
		for name, text := range map[string]string{"-add-to": out, "-describe": described} {
			if strings.Contains(strings.ToLower(text), strings.ToLower(form)) {
				t.Fatalf("%s stdout contains a private key", name)
			}
		}
	}

	// A second rotation of the two-entry file is refused, and writes nothing.
	third := filepath.Join(root, "third")
	if err := os.Mkdir(third, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := runCLI(t, "-add-to", filepath.Join(second, "ech-server-keys.json"), "-out", third); err == nil {
		t.Fatal("rotating a two-entry file was accepted")
	}
	if entries, _ := os.ReadDir(third); len(entries) != 0 {
		t.Fatalf("refused rotation left %d files behind", len(entries))
	}
}

func TestAddToRefusesToOverwriteItsSource(t *testing.T) {
	dir := t.TempDir()
	if _, err := runCLI(t, "-public-name", "cdn.cover-origin.net", "-out", dir); err != nil {
		t.Fatal(err)
	}
	if _, err := runCLI(t, "-add-to", filepath.Join(dir, "ech-server-keys.json"), "-out", dir); err == nil ||
		!strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("err = %v, want overwrite refusal", err)
	}
}

func TestDescribeTakesNoOtherFlag(t *testing.T) {
	if _, err := runCLI(t, "-describe", "x", "-out", t.TempDir()); err == nil {
		t.Fatal("-describe accepted -out")
	}
}
