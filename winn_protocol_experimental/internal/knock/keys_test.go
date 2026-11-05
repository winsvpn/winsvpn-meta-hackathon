package knock

import (
	"os"
	"path/filepath"
	"testing"
)

// testHexKey1/2 are fixture data for these tests only - deterministic,
// obviously-synthetic 32-byte (64 hex char) patterns, never real
// credentials.
const testHexKey1 = "0101010101010101010101010101010101010101010101010101010101010101"
const testHexKey2 = "0202020202020202020202020202020202020202020202020202020202020202"

func writeTempKeysFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spa-keys")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestLoadKeysFromFileParsesMultipleKeysInOrder(t *testing.T) {
	path := writeTempKeysFile(t, "# most current first\n"+testHexKey1+"\n\n"+testHexKey2+"\n")
	keys, err := LoadKeysFromFile(path)
	if err != nil {
		t.Fatalf("LoadKeysFromFile: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("len(keys) = %d, want 2", len(keys))
	}
	if len(keys[0]) != 32 || len(keys[1]) != 32 {
		t.Fatalf("decoded key lengths = %d, %d, want 32 bytes each", len(keys[0]), len(keys[1]))
	}
	if keys[0][0] != 0x01 || keys[1][0] != 0x02 {
		t.Fatalf("keys decoded out of order: keys[0][0]=%x keys[1][0]=%x", keys[0][0], keys[1][0])
	}
}

func TestLoadKeysFromFileRejectsGroupOrWorldReadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spa-keys")
	if err := os.WriteFile(path, []byte(testHexKey1+"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadKeysFromFile(path); err == nil {
		t.Fatal("LoadKeysFromFile accepted a group/world-readable SPA key file")
	}
}

func TestLoadKeysFromFileRejectsMissingFile(t *testing.T) {
	if _, err := LoadKeysFromFile(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("LoadKeysFromFile accepted a nonexistent path")
	}
}

func TestLoadKeysFromFileRejectsEmptyFile(t *testing.T) {
	path := writeTempKeysFile(t, "\n\n# only a comment\n")
	if _, err := LoadKeysFromFile(path); err == nil {
		t.Fatal("LoadKeysFromFile accepted a file with no key lines")
	}
}

func TestLoadKeysFromFileRejectsInvalidHex(t *testing.T) {
	path := writeTempKeysFile(t, "this is not hex\n")
	if _, err := LoadKeysFromFile(path); err == nil {
		t.Fatal("LoadKeysFromFile accepted a non-hex line")
	}
}

// TestLoadKeysFromFileRoundTripsIntoNewGate proves the loader's output is
// actually usable by NewGate, not merely well-typed - the two were written
// together but exercised separately until this test.
func TestLoadKeysFromFileRoundTripsIntoNewGate(t *testing.T) {
	path := writeTempKeysFile(t, testHexKey1+"\n")
	keys, err := LoadKeysFromFile(path)
	if err != nil {
		t.Fatalf("LoadKeysFromFile: %v", err)
	}
	if _, err := NewGate(keys, 256, GateConfig{}); err != nil {
		t.Fatalf("NewGate rejected keys loaded from file: %v", err)
	}
}
