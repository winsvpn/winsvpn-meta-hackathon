package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func helperSource(t *testing.T) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	src, err := os.ReadFile(filepath.Join(filepath.Dir(file), "gcloud_immutable_helper.go"))
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func openHeldDir(t *testing.T, path string) *os.File {
	t.Helper()
	fd, err := syscall.Open(path, dirOpenFlags(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return os.NewFile(uintptr(fd), path)
}

func fixturePolicy() sealPolicy {
	return sealPolicy{
		UID:        uint32(os.Getuid()),
		GID:        uint32(os.Getgid()),
		ApplyFlags: false,
	}
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for rel, body := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func writeSymlink(t *testing.T, root, rel, target string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func digestOrMismatch(t *testing.T, root *os.File, policy sealPolicy) string {
	t.Helper()
	got, err := inspectTree(root, strings.Repeat("0", 64), policy)
	if !errors.Is(err, errHashMismatch) {
		t.Fatalf("got err %v hash %q", err, got)
	}
	if len(got) != 64 {
		t.Fatalf("digest %q", got)
	}
	return got
}

func TestParseRuntimeRootUnsafePath(t *testing.T) {
	hex := strings.Repeat("a", 64)
	valid := "/var/lib/winsvpn/gcloud-runtime-v1/" + hex
	if got, err := parseRuntimeRoot(valid); err != nil || got != hex {
		t.Fatalf("valid path: got %q err %v", got, err)
	}
	unsafe := []string{
		"",
		"var/lib/winsvpn/gcloud-runtime-v1/" + hex,
		"./var/lib/winsvpn/gcloud-runtime-v1/" + hex,
		"/var/lib/winsvpn/gcloud-runtime-v1/" + strings.Repeat("A", 64),
		"/var/lib/winsvpn/gcloud-runtime-v1/" + strings.Repeat("a", 63),
		"/var/lib/winsvpn/gcloud-runtime-v1/" + strings.Repeat("a", 65),
		"/var/lib/winsvpn/gcloud-runtime-v1/" + hex + "/",
		"/var/lib/winsvpn/gcloud-runtime-v1/" + hex + "/extra",
		"/var/lib/winsvpn/gcloud-runtime-v1/../gcloud-runtime-v1/" + hex,
		"/var/lib/winsvpn//gcloud-runtime-v1/" + hex,
		"/var/lib/winsvpn/gcloud-runtime-v2/" + hex,
		"/tmp/" + hex,
		"/var/lib/winsvpn/gcloud-runtime-v1/" + hex + "\x00",
		"/var/lib/winsvpn/gcloud-runtime-v1/" + hex + "/..",
		"/" + strings.Repeat("a", 64),
	}
	for _, path := range unsafe {
		if _, err := parseRuntimeRoot(path); !errors.Is(err, errUnsafePath) {
			t.Errorf("path %q: got %v", path, err)
		}
	}
}

func TestRunRejectsUnsafePathBeforeRootOrLinux(t *testing.T) {
	err := run([]string{"/tmp/not-a-runtime-root"})
	if !errors.Is(err, errUnsafePath) {
		t.Fatalf("got %v", err)
	}
	err = run(nil)
	if !errors.Is(err, errUsage) {
		t.Fatalf("got %v", err)
	}
	err = run([]string{"a", "b"})
	if !errors.Is(err, errUsage) {
		t.Fatalf("got %v", err)
	}
}

func TestRunRequiresEuidZero(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("euid 0; refusal is not observable")
	}
	path := "/var/lib/winsvpn/gcloud-runtime-v1/" + strings.Repeat("b", 64)
	err := run([]string{path})
	if !errors.Is(err, errNeedRoot) {
		t.Fatalf("got %v", err)
	}
}

func TestRequiresLinux(t *testing.T) {
	err := requireLinux()
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if !errors.Is(err, errLinuxOnly) {
		t.Fatalf("got %v", err)
	}
}

func TestOpenChildRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	root := openHeldDir(t, dir)
	defer root.Close()
	_, err := openChild(root, "link")
	if !errors.Is(err, errSymlink) {
		t.Fatalf("got %v", err)
	}
}

func TestSafeRelativeSymlinkAccepted(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "hello", "sub/b.txt": "world"})
	writeSymlink(t, dir, "link", "a.txt")
	writeSymlink(t, dir, "sub/rel", "../a.txt")
	writeSymlink(t, dir, "sub/dot", ".")
	root := openHeldDir(t, dir)
	defer root.Close()
	policy := fixturePolicy()
	got := digestOrMismatch(t, root, policy)
	again, err := inspectTree(root, got, policy)
	if err != nil {
		t.Fatal(err)
	}
	if again != got {
		t.Fatalf("digest drifted %q vs %q", again, got)
	}
}

func TestUnsafeSymlinkTargetsRejected(t *testing.T) {
	cases := []struct {
		name   string
		rel    string
		target string
	}{
		{"absolute", "link", "/tmp/escape"},
		{"escape", "link", "../outside"},
		{"nested-escape", "sub/link", "../../outside"},
		{"backslash", "link", "a\\b"},
		{"drive", "link", "C:windows"},
		{"oversize", "link", strings.Repeat("a", maxPathBytes+1)},
		{"depth", "link", strings.Repeat("x/", maxDepth) + "y"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateSymlinkTarget(tc.rel, tc.target); !errors.Is(err, errSymlink) {
				t.Fatalf("validator: got %v", err)
			}
			dir := t.TempDir()
			writeTree(t, dir, map[string]string{"sub/keep.txt": "x"})
			if err := os.Symlink(tc.target, filepath.Join(dir, filepath.FromSlash(tc.rel))); err != nil {
				t.Skipf("host rejected symlink create: %v", err)
			}
			root := openHeldDir(t, dir)
			defer root.Close()
			_, err := inspectTree(root, strings.Repeat("0", 64), fixturePolicy())
			if !errors.Is(err, errSymlink) {
				t.Fatalf("inspect: got %v", err)
			}
		})
	}
	if err := validateSymlinkTarget("link", ""); !errors.Is(err, errSymlink) {
		t.Fatalf("empty: got %v", err)
	}
	if err := validateSymlinkTarget("link", "a\x00b"); !errors.Is(err, errSymlink) {
		t.Fatalf("nul: got %v", err)
	}
	dir := t.TempDir()
	if err := os.Symlink("", filepath.Join(dir, "empty")); err == nil {
		root := openHeldDir(t, dir)
		defer root.Close()
		if _, err := inspectTree(root, strings.Repeat("0", 64), fixturePolicy()); !errors.Is(err, errSymlink) {
			t.Fatalf("empty inspect: got %v", err)
		}
	}
}

func TestSymlinkMutationRejected(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "x", "sub/b.txt": "y"})
	writeSymlink(t, dir, "link", "a.txt")
	root := openHeldDir(t, dir)
	defer root.Close()
	policy := fixturePolicy()
	policy.AfterList = func(rel string) {
		if rel != "sub" {
			return
		}
		link := filepath.Join(dir, "link")
		if err := os.Remove(link); err != nil {
			t.Errorf("remove link: %v", err)
			return
		}
		if err := os.Symlink("missing", link); err != nil {
			t.Errorf("replace link: %v", err)
		}
	}
	_, err := inspectTree(root, strings.Repeat("0", 64), policy)
	if !errors.Is(err, errMutation) {
		t.Fatalf("got %v", err)
	}
}

func TestHardlinkedRegularFileRejected(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "same"})
	if err := os.Link(filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")); err != nil {
		t.Fatal(err)
	}
	root := openHeldDir(t, dir)
	defer root.Close()
	_, err := inspectTree(root, strings.Repeat("0", 64), fixturePolicy())
	if !errors.Is(err, errHardlink) {
		t.Fatalf("got %v", err)
	}
}

func TestWrongOwnerRejected(t *testing.T) {
	policy := fixturePolicy()
	policy.UID++
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "x"})
	root := openHeldDir(t, dir)
	defer root.Close()
	_, err := inspectTree(root, strings.Repeat("0", 64), policy)
	if !errors.Is(err, errOwner) {
		t.Fatalf("got %v", err)
	}
}

func TestWrongGroupRejected(t *testing.T) {
	policy := fixturePolicy()
	policy.GID ^= 1
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "x"})
	root := openHeldDir(t, dir)
	defer root.Close()
	_, err := inspectTree(root, strings.Repeat("0", 64), policy)
	if !errors.Is(err, errOwner) {
		t.Fatalf("got %v", err)
	}
}

func TestGroupWorldWritableRejected(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "x"})
	if err := os.Chmod(filepath.Join(dir, "a.txt"), 0o666); err != nil {
		t.Fatal(err)
	}
	root := openHeldDir(t, dir)
	defer root.Close()
	_, err := inspectTree(root, strings.Repeat("0", 64), fixturePolicy())
	if !errors.Is(err, errMode) {
		t.Fatalf("file: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "a.txt"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o775); err != nil {
		t.Fatal(err)
	}
	_, err = inspectTree(root, strings.Repeat("0", 64), fixturePolicy())
	if !errors.Is(err, errMode) {
		t.Fatalf("dir: %v", err)
	}
}

func TestSpecialFileRejected(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "x"})
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	root := openHeldDir(t, dir)
	defer root.Close()
	_, err := inspectTree(root, strings.Repeat("0", 64), fixturePolicy())
	if !errors.Is(err, errSpecial) {
		t.Fatalf("got %v", err)
	}
}

func TestWrongDeviceRejected(t *testing.T) {
	id := fileID{dev: 1, ino: 2, nlink: 1, uid: 0, gid: 0, mode: syscall.S_IFREG | 0o644, size: 1}
	if err := inspectID(id, 1, sealPolicy{UID: 0, GID: 0}, 'f'); err != nil {
		t.Fatal(err)
	}
	if err := inspectID(id, 2, sealPolicy{UID: 0, GID: 0}, 'f'); !errors.Is(err, errDevice) {
		t.Fatalf("got %v", err)
	}
}

func TestPathTraversalNamesRejected(t *testing.T) {
	for _, name := range []string{"", ".", "..", "a/b", "a\\b", "a\x00b"} {
		if err := validateChildName(name); !errors.Is(err, errTraversal) {
			t.Errorf("name %q: got %v", name, err)
		}
	}
	if err := validateChildName("gcloud"); err != nil {
		t.Fatal(err)
	}
}

func TestMutationDuringTraversalRejected(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "x", "sub/b.txt": "y"})
	root := openHeldDir(t, dir)
	defer root.Close()
	policy := fixturePolicy()
	policy.AfterList = func(rel string) {
		if rel == "." {
			if err := os.WriteFile(filepath.Join(dir, "sneak"), []byte("z"), 0o644); err != nil {
				t.Errorf("mutate: %v", err)
			}
		}
	}
	_, err := inspectTree(root, strings.Repeat("0", 64), policy)
	if !errors.Is(err, errMutation) {
		t.Fatalf("got %v", err)
	}
}

func TestInventoryHashMismatch(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "hello", "sub/b.txt": "world"})
	root := openHeldDir(t, dir)
	defer root.Close()
	policy := fixturePolicy()
	got := digestOrMismatch(t, root, policy)
	again, err := inspectTree(root, got, policy)
	if err != nil {
		t.Fatal(err)
	}
	if again != got {
		t.Fatalf("digest drifted %q vs %q", again, got)
	}
	policy.ApplyFlags = true
	_, err = inspectTree(root, strings.Repeat("f", 64), policy)
	if !errors.Is(err, errHashMismatch) {
		t.Fatalf("mismatch with ApplyFlags: %v", err)
	}
}

func TestInventoryBindsContentNotModeOrDirectories(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "hello"})
	root := openHeldDir(t, dir)
	defer root.Close()
	policy := fixturePolicy()
	first := digestOrMismatch(t, root, policy)
	if err := os.Chmod(filepath.Join(dir, "a.txt"), 0o755); err != nil {
		t.Fatal(err)
	}
	modeDigest := digestOrMismatch(t, root, policy)
	if modeDigest != first {
		t.Fatal("mode bound into digest")
	}
	if err := os.Mkdir(filepath.Join(dir, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	dirDigest := digestOrMismatch(t, root, policy)
	if dirDigest != first {
		t.Fatal("empty directory bound into digest")
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("HELLO"), 0o644); err != nil {
		t.Fatal(err)
	}
	root.Close()
	root = openHeldDir(t, dir)
	defer root.Close()
	second := digestOrMismatch(t, root, policy)
	if first == second {
		t.Fatal("content change did not bind a new digest")
	}
}

func TestOnlyRootCustodyReceiptExcludedFromDigest(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "hello", "sub/b.txt": "world"})
	root := openHeldDir(t, dir)
	defer root.Close()
	policy := fixturePolicy()
	without := digestOrMismatch(t, root, policy)
	writeTree(t, dir, map[string]string{receiptName: `{"receipt":true}`})
	withReceipt := digestOrMismatch(t, root, policy)
	if without != withReceipt {
		t.Fatalf("receipt bound into digest: %q vs %q", without, withReceipt)
	}
	writeTree(t, dir, map[string]string{"extra.txt": "new"})
	withExtra := digestOrMismatch(t, root, policy)
	if withExtra == without {
		t.Fatal("regular file was excluded like a receipt")
	}
	writeTree(t, dir, map[string]string{"sub/" + receiptName: "nested"})
	_, err := inspectTree(root, strings.Repeat("0", 64), policy)
	if !errors.Is(err, errNestedReceipt) {
		t.Fatalf("nested receipt: got %v", err)
	}
}

func TestAggregateTreeBytesBounded(t *testing.T) {
	if maxFileBytes != 512*1024*1024 || maxTreeBytes != int64(3*1024*1024*1024) {
		t.Fatalf("limit drift: file=%d tree=%d", maxFileBytes, maxTreeBytes)
	}
	acc := &walkAcc{}
	for i := int64(0); i < maxTreeBytes/int64(maxFileBytes); i++ {
		if err := acc.accountRegular(maxFileBytes); err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
	}
	if acc.totalBytes != maxTreeBytes {
		t.Fatalf("got %d want %d", acc.totalBytes, maxTreeBytes)
	}
	if err := acc.accountRegular(1); !errors.Is(err, errTooLarge) {
		t.Fatalf("aggregate overflow: got %v", err)
	}
	if err := (&walkAcc{}).accountRegular(-1); !errors.Is(err, errTooLarge) {
		t.Fatalf("negative size: got %v", err)
	}
	if err := (&walkAcc{}).accountRegular(maxFileBytes + 1); !errors.Is(err, errTooLarge) {
		t.Fatalf("single-file overflow: got %v", err)
	}
}

func TestAncestorCustodyRequiresRootOwnedNonWritableDirectory(t *testing.T) {
	good := fileID{uid: 0, gid: 0, mode: syscall.S_IFDIR | 0o755}
	if err := inspectAncestorID(good); err != nil {
		t.Fatal(err)
	}
	nonRoot := good
	nonRoot.uid = 501
	if err := inspectAncestorID(nonRoot); !errors.Is(err, errOwner) {
		t.Fatalf("non-root owner: got %v", err)
	}
	wrongGroup := good
	wrongGroup.gid = 123
	if err := inspectAncestorID(wrongGroup); !errors.Is(err, errOwner) {
		t.Fatalf("non-root group: got %v", err)
	}
	writable := good
	writable.mode = syscall.S_IFDIR | 0o775
	if err := inspectAncestorID(writable); !errors.Is(err, errMode) {
		t.Fatalf("writable ancestor: got %v", err)
	}
	for _, special := range []uint32{0o1000, 0o2000, 0o4000} {
		specialMode := good
		specialMode.mode |= special
		if err := inspectAncestorID(specialMode); !errors.Is(err, errMode) {
			t.Fatalf("special ancestor mode %04o: got %v", special, err)
		}
	}
	regular := good
	regular.mode = syscall.S_IFREG | 0o644
	if err := inspectAncestorID(regular); !errors.Is(err, errNotDir) {
		t.Fatalf("non-directory ancestor: got %v", err)
	}
}

func TestInventoryMatchesProductionContract(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"a.txt":     "hello",
		"sub/b.txt": "world",
		receiptName: "not-in-digest",
	})
	writeSymlink(t, dir, "link", "a.txt")
	writeSymlink(t, dir, "sub/rel", "../a.txt")
	if err := os.Mkdir(filepath.Join(dir, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	root := openHeldDir(t, dir)
	defer root.Close()
	got := digestOrMismatch(t, root, fixturePolicy())
	want := independentInstallTreeSHA256(t, dir)
	if got != want {
		t.Fatalf("helper %q != production contract %q", got, want)
	}
	const pinned = "9e100fe271366b1ec7d4ca7c154833171fb0d3e924e5b13851c6c97a43da0c4a"
	if got != pinned {
		t.Fatalf("helper %q != pinned production digest %s", got, pinned)
	}
	if python, ok := pythonInstallTreeSHA256(t, dir); ok && python != got {
		t.Fatalf("helper %q != python install_tree_sha256 %q", got, python)
	}
	hello := sha256.Sum256([]byte("hello"))
	world := sha256.Sum256([]byte("world"))
	link := sha256.Sum256([]byte("a.txt"))
	rel := sha256.Sum256([]byte("../a.txt"))
	manual := productionFormatDigest([]prodEntry{
		{kind: 'F', rel: "a.txt", payloadLen: int64(len("hello")), sum: hello},
		{kind: 'L', rel: "link", payloadLen: int64(len("a.txt")), sum: link},
		{kind: 'F', rel: "sub/b.txt", payloadLen: int64(len("world")), sum: world},
		{kind: 'L', rel: "sub/rel", payloadLen: int64(len("../a.txt")), sum: rel},
	})
	if got != manual {
		t.Fatalf("helper %q != manual F/L contract %q", got, manual)
	}
}

func TestNoSetFlagsOnSymlink(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "x", "sub/b.txt": "y", receiptName: "receipt"})
	writeSymlink(t, dir, "link", "a.txt")
	writeSymlink(t, dir, "sub/rel", "../a.txt")
	root := openHeldDir(t, dir)
	defer root.Close()
	policy := fixturePolicy()
	got := digestOrMismatch(t, root, policy)
	sealed := map[string]byte{}
	policy.ApplyFlags = true
	policy.SetFlags = func(kind byte, rel string) error {
		if kind == 'l' || kind == 'L' {
			t.Fatalf("SETFLAGS on symlink %q", rel)
		}
		if _, exists := sealed[rel]; exists {
			t.Fatalf("duplicate SETFLAGS %q", rel)
		}
		sealed[rel] = kind
		return nil
	}
	if _, err := inspectTree(root, got, policy); err != nil {
		t.Fatal(err)
	}
	if _, ok := sealed["link"]; ok {
		t.Fatal("SETFLAGS recorded for symlink link")
	}
	if _, ok := sealed["sub/rel"]; ok {
		t.Fatal("SETFLAGS recorded for symlink sub/rel")
	}
	for _, name := range []string{".", "a.txt", "sub", "sub/b.txt", receiptName} {
		if _, ok := sealed[name]; !ok {
			t.Fatalf("missing SETFLAGS on %q; got %v", name, sealed)
		}
	}
	src := helperSource(t)
	if !bytes.Contains(src, []byte("child.kind == 'l'")) {
		t.Fatal("seal walk does not branch on symlink kind")
	}
	if !bytes.Contains(src, []byte("if kind == 'l'")) {
		t.Fatal("missing SETFLAGS refusal for symlink inodes")
	}
}

func TestOptionalOfficialArchiveInventory(t *testing.T) {
	archive := optionalOfficialGcloudArchive(t)
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	var inventory []string
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeSymlink {
			continue
		}
		member := path.Clean(header.Name)
		if member == "google-cloud-sdk" {
			continue
		}
		rel := member
		if strings.HasPrefix(member, "google-cloud-sdk/") {
			rel = strings.TrimPrefix(member, "google-cloud-sdk/")
		}
		if err := validateSymlinkTarget(rel, header.Linkname); err != nil {
			t.Errorf("official symlink %q -> %q: %v", rel, header.Linkname, err)
			continue
		}
		inventory = append(inventory, rel+"\x00"+header.Linkname+"\n")
	}
	sort.Strings(inventory)
	inventorySHA256 := sha256.Sum256([]byte(strings.Join(inventory, "")))
	if len(inventory) != 1052 {
		t.Fatalf("official 582.0.0 safe symlink count drifted: %d", len(inventory))
	}
	if got := hex.EncodeToString(inventorySHA256[:]); got != "1b3d1c431376926985b21aa50e67297174c2ec1e49583d1ab4afd76cd8fd4cdf" {
		t.Fatalf("official 582.0.0 safe symlink inventory drifted: %s", got)
	}
	t.Logf("accepted exact official 582.0.0 symlink inventory: %d", len(inventory))
}

func TestProductionPolicyIsRootAndSetsFlags(t *testing.T) {
	p := productionPolicy()
	if p.UID != 0 || p.GID != 0 || !p.ApplyFlags {
		t.Fatalf("%+v", p)
	}
}

func TestRealSetflagsSkippedUnlessRootLinuxFixture(t *testing.T) {
	enabled := os.Getenv("WINSVPN_GCLOUD_IMMUTABLE_HELPER_LINUX_ROOT") == "1"
	if !enabled {
		dir := t.TempDir()
		writeTree(t, dir, map[string]string{"a.txt": "x"})
		root := openHeldDir(t, dir)
		defer root.Close()
		got := digestOrMismatch(t, root, fixturePolicy())
		_, err := inspectTree(root, got, fixturePolicy())
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("WINSVPN_GCLOUD_IMMUTABLE_HELPER_LINUX_ROOT requires linux euid 0")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "x", "sub/b.txt": "y"})
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, 0, 0)
	}); err != nil {
		t.Fatal(err)
	}
	root := openHeldDir(t, dir)
	defer root.Close()
	policy := sealPolicy{UID: 0, GID: 0, ApplyFlags: false}
	got, err := inspectTree(root, strings.Repeat("0", 64), policy)
	if !errors.Is(err, errHashMismatch) {
		t.Fatal(err)
	}
	policy.ApplyFlags = true
	if _, err := inspectTree(root, got, policy); err != nil {
		if errors.Is(err, syscall.ENOTTY) || errors.Is(err, syscall.EOPNOTSUPP) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
}

func TestSourceHasNoUnsealNoSubprocessNoNetwork(t *testing.T) {
	src := helperSource(t)
	forbidden := []string{
		"unseal",
		"Unseal",
		"os/exec",
		"\"net\"",
		"net/http",
		"os.Remove",
		"os.RemoveAll",
		"syscall.Unlink",
		"syscall.Rmdir",
		"syscall.Rename",
		"os.Rename",
		"io.Copy",
		"exec.Command",
		"StartProcess",
		"ForkExec",
		"SYS_EXECVE",
		"import \"C\"",
		"os.Chdir",
		"http.",
		"Dial",
		"Listen",
	}
	for _, item := range forbidden {
		if bytes.Contains(src, []byte(item)) {
			t.Errorf("forbidden surface %q", item)
		}
	}
	if bytes.Contains(src, []byte("&^ fsImmutableFL")) || bytes.Contains(src, []byte("&^= fsImmutableFL")) {
		t.Fatal("source clears FS_IMMUTABLE_FL")
	}
	if !bytes.Contains(src, []byte("O_NOFOLLOW")) {
		t.Fatal("missing no-follow opens")
	}
	if !bytes.Contains(src, []byte("openAt")) {
		t.Fatal("missing retained-descriptor child opens")
	}
	if !bytes.Contains(src, []byte("fstatAt")) || !bytes.Contains(src, []byte("linuxAtSymlinkNofollow")) {
		t.Fatal("missing no-follow child stat")
	}
	if !bytes.Contains(src, []byte("readlinkAt")) {
		t.Fatal("missing no-follow readlink")
	}
	if !bytes.Contains(src, []byte("inspectAncestorID(id)")) {
		t.Fatal("fixed runtime-root walk does not enforce ancestor custody")
	}
	if !bytes.Contains(src, []byte("acc.accountRegular(cid.size)")) {
		t.Fatal("tree walk does not enforce the aggregate payload limit")
	}
	if !bytes.Contains(src, []byte(receiptName)) {
		t.Fatal("missing custody receipt exclusion")
	}
	if !bytes.Contains(src, []byte("fsIocSetflags")) {
		t.Fatal("missing SETFLAGS")
	}
	if bytes.Count(src, []byte("applyImmutableBottomUp")) < 2 {
		t.Fatal("bottom-up SETFLAGS is missing")
	}
}

func TestStaticHelperSurface(t *testing.T) {
	src := helperSource(t)
	if !bytes.Contains(src, []byte("package main")) {
		t.Fatal("helper is not package main")
	}
	if bytes.Contains(src, []byte("golang.org/x/")) {
		t.Fatal("helper must stay on the Go standard library")
	}
	if bytes.Contains(src, []byte("cgo")) && bytes.Contains(src, []byte("import \"C\"")) {
		t.Fatal("cgo is forbidden")
	}
	imports := []string{
		"crypto/sha256",
		"crypto/subtle",
		"encoding/hex",
		"errors",
		"fmt",
		"io",
		"os",
		"path",
		"reflect",
		"regexp",
		"runtime",
		"sort",
		"strconv",
		"strings",
		"syscall",
		"unsafe",
	}
	for _, name := range imports {
		if !bytes.Contains(src, []byte("\t\""+name+"\"")) && !bytes.Contains(src, []byte("\""+name+"\"")) {
			t.Errorf("expected import %s", name)
		}
	}
}

func TestInspectIDRejectsWritableAndHardlink(t *testing.T) {
	base := fileID{dev: 7, ino: 3, nlink: 1, uid: 0, gid: 0, mode: syscall.S_IFREG | 0o644}
	if err := inspectID(base, 7, sealPolicy{UID: 0, GID: 0}, 'f'); err != nil {
		t.Fatal(err)
	}
	hard := base
	hard.nlink = 2
	if err := inspectID(hard, 7, sealPolicy{UID: 0, GID: 0}, 'f'); !errors.Is(err, errHardlink) {
		t.Fatalf("got %v", err)
	}
	writable := base
	writable.mode = syscall.S_IFREG | 0o664
	if err := inspectID(writable, 7, sealPolicy{UID: 0, GID: 0}, 'f'); !errors.Is(err, errMode) {
		t.Fatalf("got %v", err)
	}
	world := base
	world.mode = syscall.S_IFREG | 0o646
	if err := inspectID(world, 7, sealPolicy{UID: 0, GID: 0}, 'f'); !errors.Is(err, errMode) {
		t.Fatalf("got %v", err)
	}
	link := fileID{dev: 7, ino: 9, nlink: 1, uid: 0, gid: 0, mode: syscall.S_IFLNK | 0o777, size: 5}
	if err := inspectID(link, 7, sealPolicy{UID: 0, GID: 0}, 'l'); err != nil {
		t.Fatalf("symlink mode: %v", err)
	}
	for _, item := range []struct {
		kind byte
		id   fileID
	}{
		{kind: 'd', id: fileID{dev: 7, ino: 10, nlink: 1, uid: 0, gid: 1, mode: syscall.S_IFDIR | 0o755}},
		{kind: 'f', id: fileID{dev: 7, ino: 11, nlink: 1, uid: 0, gid: 1, mode: syscall.S_IFREG | 0o644}},
		{kind: 'l', id: fileID{dev: 7, ino: 12, nlink: 1, uid: 0, gid: 1, mode: syscall.S_IFLNK | 0o777}},
	} {
		if err := inspectID(item.id, 7, sealPolicy{UID: 0, GID: 0}, item.kind); !errors.Is(err, errOwner) {
			t.Fatalf("kind=%c wrong gid: %v", item.kind, err)
		}
	}
}

func TestProductionPolicyRequiresExactSealedModes(t *testing.T) {
	policy := productionPolicy()
	if !policy.RequireExactModes {
		t.Fatal("production helper must require exact sealed modes")
	}
	for _, item := range []struct {
		name string
		kind byte
		mode uint32
	}{
		{name: "directory", kind: 'd', mode: syscall.S_IFDIR | sealedDirectoryMode},
		{name: "data", kind: 'f', mode: syscall.S_IFREG | sealedDataMode},
		{name: "executable", kind: 'f', mode: syscall.S_IFREG | sealedExecutableMode},
		{name: "symlink", kind: 'l', mode: syscall.S_IFLNK | sealedSymlinkMode},
	} {
		t.Run(item.name, func(t *testing.T) {
			id := fileID{dev: 7, ino: 3, nlink: 1, uid: 0, gid: 0, mode: item.mode}
			if err := inspectID(id, 7, policy, item.kind); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, mode := range []uint32{0o400, 0o500, 0o600, 0o700, 0o644, 0o755} {
		for _, kind := range []byte{'d', 'f'} {
			id := fileID{dev: 7, ino: 3, nlink: 1, uid: 0, gid: 0, mode: mode}
			if kind == 'd' {
				id.mode |= syscall.S_IFDIR
			} else {
				id.mode |= syscall.S_IFREG
			}
			if err := inspectID(id, 7, policy, kind); !errors.Is(err, errMode) {
				t.Fatalf("kind=%c mode=%04o: %v", kind, mode, err)
			}
		}
	}
	for _, item := range []struct {
		kind byte
		mode uint32
	}{
		{kind: 'd', mode: syscall.S_IFDIR | sealedDirectoryMode},
		{kind: 'f', mode: syscall.S_IFREG | sealedDataMode},
		{kind: 'f', mode: syscall.S_IFREG | sealedExecutableMode},
		{kind: 'l', mode: syscall.S_IFLNK | sealedSymlinkMode},
	} {
		for _, special := range []uint32{0o1000, 0o2000, 0o4000, 0o7000} {
			id := fileID{dev: 7, ino: 3, nlink: 1, uid: 0, gid: 0, mode: item.mode | special}
			if err := inspectID(id, 7, policy, item.kind); !errors.Is(err, errMode) {
				t.Fatalf("kind=%c special=%04o: %v", item.kind, special, err)
			}
		}
	}
}

type prodEntry struct {
	kind       byte
	rel        string
	payloadLen int64
	sum        [32]byte
}

func productionFormatDigest(entries []prodEntry) string {
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	h := sha256.New()
	for _, e := range entries {
		_, _ = h.Write([]byte{e.kind, 0})
		_, _ = h.Write([]byte(e.rel))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(strconv.FormatInt(e.payloadLen, 10)))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(e.sum[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func independentInstallTreeSHA256(t *testing.T, root string) string {
	t.Helper()
	type rec struct {
		rel     string
		kind    byte
		payload []byte
	}
	var recs []rec
	err := filepath.WalkDir(root, func(current string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if current == root {
			return nil
		}
		rel, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.Name() == receiptName {
			if filepath.Dir(rel) != "." {
				return errNestedReceipt
			}
			return nil
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(current)
			if err != nil {
				return err
			}
			recs = append(recs, rec{rel: rel, kind: 'L', payload: []byte(target)})
		case info.IsDir():
			return nil
		case info.Mode().IsRegular():
			data, err := os.ReadFile(current)
			if err != nil {
				return err
			}
			recs = append(recs, rec{rel: rel, kind: 'F', payload: data})
		default:
			return errSpecial
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].rel < recs[j].rel })
	h := sha256.New()
	for _, r := range recs {
		sum := sha256.Sum256(r.payload)
		_, _ = h.Write([]byte{r.kind, 0})
		_, _ = h.Write([]byte(r.rel))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(strconv.FormatInt(int64(len(r.payload)), 10)))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(sum[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func pythonInstallTreeSHA256(t *testing.T, root string) (string, bool) {
	t.Helper()
	script := `
import hashlib, os, stat, sys
from pathlib import Path
RECEIPT_NAME = ".winsvpn-gcloud-custody-v1.json"
root = Path(sys.argv[1]).resolve(strict=True)
digest = hashlib.sha256()
entries = []
for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
    base = Path(directory)
    dirnames.sort()
    filenames.sort()
    entries.extend(base / name for name in dirnames if (base / name).is_symlink())
    for name in filenames:
        if name == RECEIPT_NAME:
            if base != root:
                raise SystemExit("nested custody receipt")
            continue
        entries.append(base / name)
for path in sorted(entries, key=lambda item: item.relative_to(root).as_posix().encode("utf-8")):
    relative = path.relative_to(root).as_posix()
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        payload = os.readlink(path).encode("utf-8")
        kind = b"L"
    elif stat.S_ISREG(info.st_mode):
        payload = path.read_bytes()
        kind = b"F"
    else:
        raise SystemExit("unsupported")
    digest.update(kind + b"\x00" + relative.encode("utf-8") + b"\x00")
    digest.update(str(len(payload)).encode("ascii") + b"\x00" + hashlib.sha256(payload).digest())
sys.stdout.write(digest.hexdigest())
`
	cmd := exec.Command("/usr/bin/python3", "-c", script, root)
	out, err := cmd.Output()
	if err != nil {
		t.Logf("python install_tree_sha256 unavailable: %v", err)
		return "", false
	}
	got := strings.TrimSpace(string(out))
	if len(got) != 64 {
		t.Fatalf("python digest %q", got)
	}
	return got, true
}

func optionalOfficialGcloudArchive(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("WINSVPN_GCLOUD_CLI_LINUX_ARCHIVE"); p != "" {
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() {
			t.Fatalf("WINSVPN_GCLOUD_CLI_LINUX_ARCHIVE is not a regular file")
		}
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("optional official archive not present")
	}
	candidate := filepath.Join(home, "Downloads", "google-cloud-cli-582.0.0-linux-x86_64.tar.gz")
	st, err := os.Lstat(candidate)
	if err != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		t.Skip("optional official Google Cloud CLI 582.0.0 linux x86_64 archive not present")
	}
	return candidate
}
