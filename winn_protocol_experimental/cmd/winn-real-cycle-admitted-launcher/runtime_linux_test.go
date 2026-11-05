//go:build linux

package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSealedAdapterSurvivesOriginalPathMutation(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "adapter-source")
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(
		sourcePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o500,
	)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(writer, hash), source); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	expected := fmt.Sprintf("%x", hash.Sum(nil))
	sealed, err := sealExactAdapter(sourcePath, expected)
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close()

	if err := os.Chmod(sourcePath, 0o700); err != nil {
		t.Fatal(err)
	}
	mutator, err := os.OpenFile(sourcePath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mutator.WriteAt([]byte{0}, 0); err != nil {
		t.Fatal(err)
	}
	if err := mutator.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := sealed.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySealedAdapter(sealed, info.Size(), expected); err != nil {
		t.Fatalf("sealed descriptor followed source mutation: %v", err)
	}
	if _, err := sealed.WriteAt([]byte{0}, 0); err == nil {
		t.Fatal("sealed descriptor accepted write")
	}
	if err := sealed.Truncate(info.Size() - 1); err == nil {
		t.Fatal("sealed descriptor accepted shrink")
	}
	if err := sealed.Truncate(info.Size() + 1); err == nil {
		t.Fatal("sealed descriptor accepted grow")
	}
	if err := sealed.Chmod(0o400); err == nil {
		t.Fatal("sealed descriptor accepted chmod")
	}
}

func TestVerifySealedAdapterRejectsMissingSeals(t *testing.T) {
	fd, err := unix.MemfdCreate(
		"missing-seals",
		unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC|unix.MFD_EXEC,
	)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "missing-seals")
	defer file.Close()
	data := []byte("adapter")
	if _, err := file.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	if err := verifySealedAdapter(
		file, int64(len(data)), fmt.Sprintf("%x", hash[:]),
	); err == nil {
		t.Fatal("missing seals unexpectedly accepted")
	}
}

func TestProductionRuntimeRefusesNonemptyStateDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(directory, "orphan"), []byte("pending"), 0o400,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := newProductionRuntime(
		directory, "/does/not/matter", "bad", 0,
	); err == nil {
		t.Fatal("nonempty state directory unexpectedly accepted")
	}
}

func TestProductionRuntimePublishesWithoutReplacement(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(t.TempDir(), "adapter-source")
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(
		sourcePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o500,
	)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(writer, hash), source); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	runtimeBoundary, err := newProductionRuntime(
		directory,
		sourcePath,
		fmt.Sprintf("%x", hash.Sum(nil)),
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	runtime := runtimeBoundary.(*productionRuntime)
	data := []byte("{\"binding\":true}\n")
	published, err := runtime.PublishExclusive(bindingFileName, data)
	if err != nil {
		t.Fatal(err)
	}
	offset, err := published.Seek(0, io.SeekCurrent)
	if err != nil || offset != 0 {
		t.Fatalf("publication descriptor offset=%d err=%v", offset, err)
	}
	replayed, err := io.ReadAll(published)
	if err != nil || string(replayed) != string(data) {
		t.Fatalf("publication replay mismatch: %q %v", replayed, err)
	}
	if err := published.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.PublishExclusive(bindingFileName, data); err == nil {
		t.Fatal("replacement publication unexpectedly succeeded")
	}
	info, err := os.Stat(filepath.Join(directory, bindingFileName))
	if err != nil || info.Mode().Perm() != 0o400 ||
		descriptorNlink(info) != 1 {
		t.Fatalf("published identity is unsafe: info=%v err=%v", info, err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}
