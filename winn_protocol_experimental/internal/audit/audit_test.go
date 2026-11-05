package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/securefile"
)

func TestAuditOpenRejectsSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privilege varies on Windows")
	}
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "audit.key")
	target := filepath.Join(directory, "target.jsonl")
	link := filepath.Join(directory, "audit.jsonl")
	if err := securefile.AtomicWrite(keyPath, bytes.Repeat([]byte{0x71}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, keyPath); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("audit symlink error = %v", err)
	}
}

func TestAuditChainReopensAndHidesDeviceIdentity(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "audit.key")
	logPath := filepath.Join(directory, "audit.jsonl")
	if err := securefile.AtomicWrite(keyPath, bytes.Repeat([]byte{0x81}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Open(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Record("request_rejected", "sensitive-device-name", "request-1", "bad request"); err != nil {
		t.Fatal(err)
	}
	if err := first.Record("rekey_committed", "sensitive-device-name", "request-2", "generation=1"); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("sensitive-device-name")) {
		t.Fatal("audit log exposed the raw device identity")
	}
	second, err := Open(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Record("rekey_committed", "other-device", "request-3", "generation=2"); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Verify(logPath, keyPath); err != nil {
		t.Fatal(err)
	}
}

func TestAuditTamperingFailsClosed(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "audit.key")
	logPath := filepath.Join(directory, "audit.jsonl")
	if err := securefile.AtomicWrite(keyPath, bytes.Repeat([]byte{0x92}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	log, err := Open(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Record("rekey_committed", "device-1", "request-1", "generation=1"); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(encoded), "generation=1", "generation=9", 1)
	if err := os.WriteFile(logPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(logPath, keyPath); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("tampered audit verification error = %v", err)
	}
}

func TestAuditWriteFailureMarksSinkUnhealthy(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "audit.key")
	logPath := filepath.Join(directory, "audit.jsonl")
	if err := securefile.AtomicWrite(keyPath, bytes.Repeat([]byte{0xa3}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	log, err := Open(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := log.Record("event", "", "", ""); err == nil {
		t.Fatal("write to closed audit file unexpectedly succeeded")
	}
	if log.Healthy() {
		t.Fatal("audit sink remained healthy after a write failure")
	}
}
