//go:build unix

package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type identityTestInfo struct{ sys any }

func (identityTestInfo) Name() string       { return "identity-test" }
func (identityTestInfo) Size() int64        { return 0 }
func (identityTestInfo) Mode() os.FileMode  { return 0o600 }
func (identityTestInfo) ModTime() time.Time { return time.Time{} }
func (identityTestInfo) IsDir() bool        { return false }
func (i identityTestInfo) Sys() any         { return i.sys }

func TestIdentityFromInfoRejectsNegativeDarwinDevice(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin dev_t is the signed platform case")
	}
	stat := &syscall.Stat_t{}
	reflect.ValueOf(stat).Elem().FieldByName("Dev").SetInt(-1)
	if _, err := identityFromInfo(identityTestInfo{sys: stat}); err == nil {
		t.Fatal("negative Darwin device identity was accepted")
	}
}

func TestGatherProvenanceRefusesDescriptorXattrQuarantine(t *testing.T) {
	attribute := "user.winn.quarantine"
	if runtime.GOOS == "darwin" {
		attribute = "com.apple.quarantine"
	}
	for _, target := range []string{"root", "regular-file", "directory"} {
		t.Run(target, func(t *testing.T) {
			cfg := provenanceConfig(t)
			path := cfg.SnapshotRoot
			switch target {
			case "regular-file":
				path = filepath.Join(cfg.SnapshotRoot, "go.mod")
			case "directory":
				path = filepath.Join(cfg.SnapshotRoot, "scripts")
			}
			if err := unix.Setxattr(path, attribute, []byte("quarantined"), 0); err != nil {
				if errors.Is(err, unix.ENOTSUP) ||
					errors.Is(err, unix.EOPNOTSUPP) {
					t.Skipf("test filesystem has no xattr support: %v", err)
				}
				t.Fatalf("set %s on %s: %v", attribute, path, err)
			}
			_, err := gatherProvenance(cfg)
			if !errors.Is(err, errQuarantined) {
				t.Fatalf(
					"descriptor-bound quarantine attribute on %s produced %v",
					target, err,
				)
			}
		})
	}
}

func TestGatherProvenanceRefusesSnapshotPathReplacement(t *testing.T) {
	cfg := provenanceConfig(t)
	originalProbe := mountProber
	t.Cleanup(func() { mountProber = originalProbe })

	held := cfg.SnapshotRoot + ".held"
	mountProber = func(file *os.File) (mountFacts, error) {
		facts, err := probeMountDescriptor(file)
		if err != nil {
			return mountFacts{}, err
		}
		if err := os.Rename(cfg.SnapshotRoot, held); err != nil {
			return mountFacts{}, err
		}
		if err := os.Mkdir(cfg.SnapshotRoot, 0o700); err != nil {
			return mountFacts{}, err
		}
		if err := os.WriteFile(
			filepath.Join(cfg.SnapshotRoot, "replacement"),
			[]byte("different snapshot\n"), 0o600,
		); err != nil {
			return mountFacts{}, err
		}
		return facts, nil
	}

	_, err := gatherProvenance(cfg)
	if err == nil {
		t.Fatal("a same-UID pathname replacement was accepted")
	}
	if !strings.Contains(err.Error(), "changed device/inode identity") {
		t.Fatalf(
			"replacement refusal was %v, want stable-directory identity failure",
			err,
		)
	}
}

func TestDescriptorXattrUnsupportedFailsClosed(t *testing.T) {
	file, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()

	_, err = listDescriptorXattrs(
		file,
		func(int, []byte) (int, error) {
			return 0, unix.ENOTSUP
		},
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported descriptor xattrs produced %v", err)
	}
}
