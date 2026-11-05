//go:build darwin

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	expectedManifestSHA  = "246223ff3223d8f6988db59f899053c2dd9ab4af33489ca87e341cc78f3f2b9d"
	expectedManifestSize = 4793
	expectedProdSHA      = "971fafaba3a7bc59b2a072d219d9decfe5e953e4ffb1d44a5146b15205892f99"
	expectedAllSHA       = "9baaaf0a0ff79ea5d7765fbbc53220f535bae20f60b2cd4d4f5b990d1fb667af"
	e7MainSHA            = "7ea84df5cf5f314851dfed356ff1d817bdb4748aab20690d164552e090ea2299"
	e7MainSize           = int64(21337)
	e8MainSHA            = "7e6294d45d07e789a1a3c43a753f0c4aa75d62e935110d28d8b8fae8a5c87883"
	mainPath             = "cmd/winn-phase1-soak-controller/main.go"
	nodeDir              = "cmd/winn-local-sealed-node"
	ackText              = "I UNDERSTAND THIS MUTATES THE SELECTED CANONICAL ROOT"
	schema               = "winn-e8-r7-guarded-promoter-ledger/2"
)

var equalPaths = map[string]bool{
	"cmd/winn-phase1-soak-controller/e8_full_linux_test.go":        true,
	"cmd/winn-phase1-soak-controller/e8_rehearsal_grant.go":        true,
	"cmd/winn-phase1-soak-controller/e8_rehearsal_types.go":        true,
	"cmd/winn-phase1-soak-controller/e8_rehearsal_unsupported.go":  true,
	"cmd/winn-phase1-soak-controller/e8_transaction_linux.go":      true,
	"cmd/winn-phase1-soak-controller/e8_transaction_linux_test.go": true,
}

var absentPaths = map[string]bool{
	"cmd/winn-phase1-soak-controller/e8_e2_fixture_linux_test.go": true,
	"cmd/winn-phase1-soak-controller/e8_publish_linux_test.go":    true,
	"cmd/winn-phase1-soak-controller/e8_rehearsal.go":             true,
	"cmd/winn-phase1-soak-controller/e8_rehearsal_grant_test.go":  true,
	"cmd/winn-phase1-soak-controller/e8_rehearsal_linux.go":       true,
	"cmd/winn-phase1-soak-controller/e8_rehearsal_linux_test.go":  true,
	"internal/realcycle/localrehearsal.go":                        true,
	"internal/realcycle/localrehearsal_test.go":                   true,
	"cmd/winn-local-sealed-node/main_linux.go":                    true,
	"cmd/winn-local-sealed-node/main_unsupported.go":              true,
	"cmd/winn-local-sealed-node/sandbox_linux.go":                 true,
	"cmd/winn-local-sealed-node/main_linux_test.go":               true,
}

type row struct {
	SHA  string `json:"sha256"`
	Size int64  `json:"size"`
	Path string `json:"path"`
}

type identity struct {
	Dev  uint64 `json:"dev"`
	Ino  uint64 `json:"ino"`
	Type uint32 `json:"type"`
	Mode uint32 `json:"mode"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	Size int64  `json:"size"`
	SHA  string `json:"sha256,omitempty"`
}

func identityOf(st *unix.Stat_t, sha string) identity {
	return identity{
		Dev: uint64(st.Dev), Ino: st.Ino, Type: uint32(st.Mode & unix.S_IFMT),
		Mode: uint32(st.Mode & 07777), UID: st.Uid, GID: st.Gid, Size: st.Size, SHA: sha,
	}
}

func sameObject(a, b identity) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Type == b.Type
}

func sameFull(a, b identity) bool {
	return sameObject(a, b) && a.Mode == b.Mode && a.UID == b.UID &&
		a.GID == b.GID && a.Size == b.Size && a.SHA == b.SHA
}

func sameDir(a, b identity) bool {
	return sameObject(a, b) && a.Type == unix.S_IFDIR && b.Type == unix.S_IFDIR &&
		a.Mode == b.Mode && a.UID == b.UID && a.GID == b.GID
}

func safeRel(p string) bool {
	return p != "" && p != "." && filepath.IsLocal(filepath.FromSlash(p)) &&
		filepath.ToSlash(filepath.Clean(filepath.FromSlash(p))) == p &&
		!strings.ContainsRune(p, '\x00')
}

func sumBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func splitRel(p string) (string, string, error) {
	if !safeRel(p) {
		return "", "", fmt.Errorf("unsafe relative path %q", p)
	}
	dir, leaf := filepath.Split(filepath.FromSlash(p))
	dir = strings.TrimSuffix(filepath.ToSlash(dir), "/")
	if dir == "." {
		dir = ""
	}
	if leaf == "" || leaf == "." || leaf == ".." {
		return "", "", fmt.Errorf("invalid leaf in %q", p)
	}
	return dir, leaf, nil
}

type config struct {
	Candidate string
	Canonical string
	Manifest  string
	Receipt   string
	Execute   bool
	Ack       string
	TestMode  bool
	FaultAt   int
}
