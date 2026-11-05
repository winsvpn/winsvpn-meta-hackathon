package securefile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type failingDirectorySyncFile struct {
	syncErr  error
	closeErr error
}

func (f failingDirectorySyncFile) Sync() error  { return f.syncErr }
func (f failingDirectorySyncFile) Close() error { return f.closeErr }

func TestAtomicWriteRejectsWritableParentWithoutChangingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission test")
	}
	directory := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(filepath.Join(directory, "secret"), []byte("secret"), 0o600); err == nil {
		t.Fatal("write into group/other-writable parent was accepted")
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o777 {
		t.Fatalf("parent permissions were changed to %04o", info.Mode().Perm())
	}
}

func TestReadersRejectSymlinksAndWritablePublicData(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink and POSIX permission test")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(link); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("private symlink error = %v", err)
	}
	if _, err := ReadPublicIntegrity(link, 1024); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("public symlink error = %v", err)
	}
	if err := os.Chmod(target, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublicIntegrity(target, 1024); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("writable public-data error = %v", err)
	}
}

func TestLimitedReadRejectsOversizeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateLimited(path, 4); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize read error = %v", err)
	}
}

func TestDirectorySyncPropagatesOpenSyncAndCloseErrors(t *testing.T) {
	sentinel := errors.New("sentinel")
	if err := syncDirectoryWith("unused", func(string) (directorySyncFile, error) {
		return nil, sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("open error = %v", err)
	}
	if err := syncDirectoryWith("unused", func(string) (directorySyncFile, error) {
		return failingDirectorySyncFile{syncErr: sentinel}, nil
	}); !errors.Is(err, sentinel) {
		t.Fatalf("sync error = %v", err)
	}
	if err := syncDirectoryWith("unused", func(string) (directorySyncFile, error) {
		return failingDirectorySyncFile{closeErr: sentinel}, nil
	}); !errors.Is(err, sentinel) {
		t.Fatalf("close error = %v", err)
	}
}

func TestRootedDirectorySyncUsesTheRequestedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory fsync is not used on Windows")
	}
	directory := t.TempDir()
	if err := syncDirectory(directory); err != nil {
		t.Fatalf("sync rooted directory: %v", err)
	}
	file := filepath.Join(directory, "not-a-directory")
	if err := os.WriteFile(file, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syncDirectory(file); err == nil {
		t.Fatal("regular file accepted as a directory")
	}
}

func TestOpenFileWithinParentCreatesOnlyTheFinalComponent(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "lock")
	file, err := OpenFileWithinParent(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("opened mode = %v, want regular", info.Mode())
	}
}
