package awg

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testPeerKey = "nNOe1VBs+qdVjQGHgems9Xd3SO6gsrVl7+DM8y/EZAQ="

func TestFileApplierWritesPrivateCanonicalPSK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.psk")
	psk := bytes.Repeat([]byte{0x5a}, 32)
	applier := FileApplier{Path: path}
	if err := applier.Apply(context.Background(), testPeerKey, psk); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	expected := base64.StdEncoding.EncodeToString(psk) + "\n"
	if string(data) != expected {
		t.Fatalf("PSK file = %q, want %q", data, expected)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("permissions = %04o, want 0600", info.Mode().Perm())
		}
	}
}

func TestFileApplierReadsUniqueCurrentPSKCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.psk")
	expected := bytes.Repeat([]byte{0x71}, 32)
	applier := FileApplier{Path: path}
	if err := applier.Apply(
		context.Background(), testPeerKey, expected,
	); err != nil {
		t.Fatal(err)
	}
	first, err := applier.ReadCurrentPSK(
		context.Background(), testPeerKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := applier.ReadCurrentPSK(
		context.Background(), testPeerKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, expected) ||
		!bytes.Equal(second, expected) ||
		(len(first) != 0 && &first[0] == &second[0]) {
		t.Fatal("file applier did not return unique current PSK copies")
	}
	clear(first)
	if !bytes.Equal(second, expected) {
		t.Fatal("clearing one PSK copy changed another")
	}
	clear(second)
}

func TestCommandApplierUsesExpectedAWGContractAndCleansSecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-specific")
	}
	directory := t.TempDir()
	argsPath := filepath.Join(directory, "args")
	copiedPSKPath := filepath.Join(directory, "copied-psk")
	scriptPath := filepath.Join(directory, "fake-awg")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > " + shellQuote(argsPath) + "\n" +
		"cp \"$6\" " + shellQuote(copiedPSKPath) + "\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	psk := bytes.Repeat([]byte{0x2a}, 32)
	applier := CommandApplier{Binary: scriptPath, Interface: "awg0", TempDir: directory}
	if err := applier.Apply(context.Background(), testPeerKey, psk); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(args)), "\n")
	if len(lines) != 6 ||
		lines[0] != "set" ||
		lines[1] != "awg0" ||
		lines[2] != "peer" ||
		lines[3] != testPeerKey ||
		lines[4] != "preshared-key" {
		t.Fatalf("unexpected AWG arguments: %q", lines)
	}
	if _, err := os.Stat(lines[5]); !os.IsNotExist(err) {
		t.Fatalf("temporary PSK still exists: %v", err)
	}
	copied, err := os.ReadFile(copiedPSKPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(copied) != base64.StdEncoding.EncodeToString(psk)+"\n" {
		t.Fatal("AWG command received the wrong PSK")
	}
}

func TestCommandApplierReadsOnlyRequestedCurrentPSK(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-specific")
	}
	directory := t.TempDir()
	scriptPath := filepath.Join(directory, "fake-awg")
	expected := bytes.Repeat([]byte{0x37}, 32)
	otherPeer := "U2jiOUixcKvYR+zRKfsp2ol7P4vY7PWtxokjAsVLiV8="
	script := "#!/bin/sh\n" +
		"if [ \"$1\" != show ] || [ \"$3\" != preshared-keys ]; then exit 7; fi\n" +
		"printf '%s\\t%s\\n' " + shellQuote(otherPeer) + " " +
		shellQuote(base64.StdEncoding.EncodeToString(
			bytes.Repeat([]byte{0x19}, 32),
		)) + "\n" +
		"printf '%s\\t%s\\n' " + shellQuote(testPeerKey) + " " +
		shellQuote(base64.StdEncoding.EncodeToString(expected)) + "\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	applier := CommandApplier{
		Binary: scriptPath, Interface: "awg0",
	}
	actual, err := applier.ReadCurrentPSK(
		context.Background(), testPeerKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("command applier returned the wrong current PSK")
	}
	clear(actual)
}

func TestFileApplierApplyRejectsNon32BytePSK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.psk")
	applier := FileApplier{Path: path}
	for _, psk := range [][]byte{nil, {}, bytes.Repeat([]byte{0x5a}, 31), bytes.Repeat([]byte{0x5a}, 33)} {
		err := applier.Apply(context.Background(), testPeerKey, psk)
		if err == nil || !strings.Contains(err.Error(), "exactly 32 bytes") {
			t.Fatalf("len=%d err=%v", len(psk), err)
		}
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("Apply wrote a PSK file after rejecting len=%d: %v", len(psk), statErr)
		}
	}
}

func TestFileApplierApplyRejectsAllZeroPSK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.psk")
	applier := FileApplier{Path: path}
	err := applier.Apply(context.Background(), testPeerKey, make([]byte, 32))
	if err == nil || !strings.Contains(err.Error(), "all zero") {
		t.Fatalf("all-zero Apply err=%v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("Apply wrote a PSK file after rejecting all-zero: %v", statErr)
	}
}

func TestCommandApplierApplyRejectsAllZeroPSK(t *testing.T) {
	err := CommandApplier{Binary: "/no/such/awg", Interface: "awg0"}.Apply(
		context.Background(), testPeerKey, make([]byte, 32),
	)
	if err == nil || !strings.Contains(err.Error(), "all zero") {
		t.Fatalf("all-zero Apply err=%v", err)
	}
}

func TestFileApplierApplyRejectsInvalidPeerPublicKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.psk")
	psk := bytes.Repeat([]byte{0x5a}, 32)
	err := FileApplier{Path: path}.Apply(context.Background(), "not-a-peer-key", psk)
	if err == nil {
		t.Fatal("Apply accepted an invalid peer public key")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("Apply wrote a PSK file after rejecting the peer key: %v", statErr)
	}
}

func TestCommandApplierApplyRejectsRelativeBinaryAndInvalidInterface(t *testing.T) {
	psk := bytes.Repeat([]byte{0x2a}, 32)
	relative := CommandApplier{Binary: "awg", Interface: "awg0"}
	err := relative.Apply(context.Background(), testPeerKey, psk)
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("relative binary err=%v", err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("executable fixture is Unix-specific")
	}
	scriptPath := filepath.Join(t.TempDir(), "fake-awg")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	invalid := CommandApplier{Binary: scriptPath, Interface: "awg 0"}
	err = invalid.Apply(context.Background(), testPeerKey, psk)
	if err == nil || !strings.Contains(err.Error(), "invalid AWG interface name") {
		t.Fatalf("invalid interface err=%v", err)
	}
}

func TestFileApplierReadCurrentPSKRejectsCancelledContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.psk")
	applier := FileApplier{Path: path}
	psk := bytes.Repeat([]byte{0x71}, 32)
	if err := applier.Apply(context.Background(), testPeerKey, psk); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := applier.ReadCurrentPSK(ctx, testPeerKey)
	if err == nil {
		clear(got)
		t.Fatal("ReadCurrentPSK succeeded on a cancelled context")
	}
}

func TestFileApplierReadCurrentPSKRejectsInvalidAndAllZeroFile(t *testing.T) {
	directory := t.TempDir()
	valid := bytes.Repeat([]byte{0x5a}, 32)
	invalidPath := filepath.Join(directory, "invalid.psk")
	invalidApplier := FileApplier{Path: invalidPath}
	if err := invalidApplier.Apply(context.Background(), testPeerKey, valid); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invalidPath, []byte("not-base64\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := invalidApplier.ReadCurrentPSK(context.Background(), testPeerKey)
	if err == nil || !strings.Contains(err.Error(), "encoding is invalid") {
		t.Fatalf("invalid encoding err=%v", err)
	}
	zeroPath := filepath.Join(directory, "zero.psk")
	zeroApplier := FileApplier{Path: zeroPath}
	if err := zeroApplier.Apply(context.Background(), testPeerKey, valid); err != nil {
		t.Fatal(err)
	}
	zero := []byte(base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	if err := os.WriteFile(zeroPath, zero, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = zeroApplier.ReadCurrentPSK(context.Background(), testPeerKey)
	if err == nil || !strings.Contains(err.Error(), "applied PSK is invalid") {
		t.Fatalf("all-zero file err=%v", err)
	}
}

func TestCommandApplierReadCurrentPSKDuplicateAndMissingPeer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-specific")
	}
	encoded := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x37}, 32))
	directory := t.TempDir()
	dupPath := filepath.Join(directory, "dup-awg")
	dupScript := "#!/bin/sh\n" +
		"printf '%s\\t%s\\n' " + shellQuote(testPeerKey) + " " + shellQuote(encoded) + "\n" +
		"printf '%s\\t%s\\n' " + shellQuote(testPeerKey) + " " + shellQuote(encoded) + "\n"
	if err := os.WriteFile(dupPath, []byte(dupScript), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := CommandApplier{Binary: dupPath, Interface: "awg0"}.ReadCurrentPSK(
		context.Background(), testPeerKey,
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate peer PSKs") {
		t.Fatalf("duplicate peer err=%v", err)
	}
	missingPath := filepath.Join(directory, "missing-awg")
	missingScript := "#!/bin/sh\nprintf '%s\\t%s\\n' " +
		shellQuote("U2jiOUixcKvYR+zRKfsp2ol7P4vY7PWtxokjAsVLiV8=") + " " +
		shellQuote(encoded) + "\n"
	if err := os.WriteFile(missingPath, []byte(missingScript), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err = CommandApplier{Binary: missingPath, Interface: "awg0"}.ReadCurrentPSK(
		context.Background(), testPeerKey,
	)
	if err == nil || !strings.Contains(err.Error(), "did not report the requested peer PSK") {
		t.Fatalf("missing peer err=%v", err)
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
