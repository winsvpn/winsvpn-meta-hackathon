// Linux-only fixed-function sealer for an already prepared Google Cloud CLI
// runtime tree at /var/lib/winsvpn/gcloud-runtime-v1/<64-lowercase-hex>.
// The helper sets FS_IMMUTABLE_FL on held descriptors and never clears flags.
package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	fsImmutableFL = 0x00000010
	// linux amd64: _IOR('f', 1, long) / _IOW('f', 2, long)
	fsIocGetflags = 0x80086601
	fsIocSetflags = 0x40086602
	// linux amd64: SYS_OPENAT / SYS_NEWFSTATAT / SYS_READLINKAT / AT_SYMLINK_NOFOLLOW
	linuxSysOpenat         = 257
	linuxSysNewfstatat     = 262
	linuxSysReadlinkat     = 267
	linuxAtSymlinkNofollow = 0x100
	maxDepth               = 32
	maxEntries             = 200000
	maxFileBytes           = 512 * 1024 * 1024
	maxTreeBytes           = int64(3 * 1024 * 1024 * 1024)
	maxPathBytes           = 1024
	receiptName            = ".winsvpn-gcloud-custody-v1.json"
	sealedDataMode         = uint32(0o444)
	sealedExecutableMode   = uint32(0o555)
	sealedDirectoryMode    = uint32(0o555)
	sealedSymlinkMode      = uint32(0o777)
)

var (
	runtimeRootPattern = regexp.MustCompile(`^/var/lib/winsvpn/gcloud-runtime-v1/([0-9a-f]{64})$`)

	errUsage         = errors.New("exactly one absolute runtime-root argument is required")
	errUnsafePath    = errors.New("runtime-root path is unsafe")
	errNeedRoot      = errors.New("euid 0 is required")
	errLinuxOnly     = errors.New("linux/amd64-only")
	errSymlink       = errors.New("symlink rejected")
	errHardlink      = errors.New("hard-linked regular file rejected")
	errOwner         = errors.New("unexpected uid or gid rejected")
	errMode          = errors.New("unsafe or unexpected mode rejected")
	errSpecial       = errors.New("special file rejected")
	errTraversal     = errors.New("path traversal rejected")
	errDevice        = errors.New("mount/device change rejected")
	errMutation      = errors.New("entry changed during traversal")
	errHashMismatch  = errors.New("inventory hash mismatch")
	errNotImmutable  = errors.New("FS_IMMUTABLE_FL missing after seal")
	errNotDir        = errors.New("runtime-root must be a directory")
	errClearFlags    = errors.New("refusing to clear filesystem flags")
	errTooLarge      = errors.New("tree exceeds size or entry limit")
	errNestedReceipt = errors.New("nested Google Cloud CLI custody receipt is forbidden")
)

type sealPolicy struct {
	UID               uint32
	GID               uint32
	ApplyFlags        bool
	RequireExactModes bool
	AfterList         func(rel string)
	SetFlags          func(kind byte, rel string) error
}

type fileID struct {
	dev, ino, nlink uint64
	uid, gid        uint32
	mode            uint32
	size            int64
	mtime           int64
	ctime           int64
}

type node struct {
	name     string
	kind     byte
	id       fileID
	content  [32]byte
	target   string
	children []*node
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "gcloud-immutable-helper: %s\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	expected, err := parseRuntimeRoot(args[0])
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errNeedRoot
	}
	if err := requireLinux(); err != nil {
		return err
	}
	root, err := openRuntimeRoot(args[0])
	if err != nil {
		return err
	}
	defer root.Close()
	_, err = inspectTree(root, expected, productionPolicy())
	return err
}

func productionPolicy() sealPolicy {
	return sealPolicy{UID: 0, GID: 0, ApplyFlags: true, RequireExactModes: true}
}

func requireLinux() error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errLinuxOnly
	}
	return nil
}

func parseRuntimeRoot(abs string) (string, error) {
	if abs == "" || abs != path.Clean(abs) || !path.IsAbs(abs) {
		return "", errUnsafePath
	}
	match := runtimeRootPattern.FindStringSubmatch(abs)
	if match == nil {
		return "", errUnsafePath
	}
	return match[1], nil
}

func openRuntimeRoot(abs string) (*os.File, error) {
	expected, err := parseRuntimeRoot(abs)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open("/", dirOpenFlags(), 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	for _, name := range []string{"var", "lib", "winsvpn", "gcloud-runtime-v1", expected} {
		next, err := openChildDir(current, name)
		_ = current.Close()
		if err != nil {
			return nil, err
		}
		id, err := idFromFile(next)
		if err != nil {
			_ = next.Close()
			return nil, err
		}
		if err := inspectAncestorID(id); err != nil {
			_ = next.Close()
			return nil, err
		}
		current = next
	}
	return current, nil
}

func dirOpenFlags() int {
	return syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
}

func fileOpenFlags() int {
	return syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
}

func validateChildName(name string) error {
	if name == "" || name == "." || name == ".." {
		return errTraversal
	}
	for _, r := range name {
		if r == '/' || r == 0 || r == '\\' {
			return errTraversal
		}
	}
	return nil
}

func openChildDir(dir *os.File, name string) (*os.File, error) {
	return openatHeld(dir, name, dirOpenFlags())
}

func openChild(dir *os.File, name string) (*os.File, error) {
	return openatHeld(dir, name, fileOpenFlags())
}

func openatHeld(dir *os.File, name string, flags int) (*os.File, error) {
	if err := validateChildName(name); err != nil {
		return nil, err
	}
	full := path.Join(dir.Name(), name)
	fd, err := openAt(int(dir.Fd()), name, full, flags)
	runtime.KeepAlive(dir)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: %s", errSymlink, name)
		}
		if errors.Is(err, syscall.ENOENT) {
			return nil, errMutation
		}
		if errors.Is(err, syscall.ENOTDIR) {
			return nil, errNotDir
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), full), nil
}

func openAt(dirfd int, name, full string, flags int) (int, error) {
	if runtime.GOOS == "linux" {
		p, err := syscall.BytePtrFromString(name)
		if err != nil {
			return 0, err
		}
		r1, _, errno := syscall.Syscall6(linuxSysOpenat, uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(flags), 0, 0, 0)
		runtime.KeepAlive(p)
		if errno != 0 {
			return 0, errno
		}
		return int(r1), nil
	}
	return syscall.Open(full, flags, 0)
}

func inspectTree(root *os.File, expected string, policy sealPolicy) (string, error) {
	rootID, err := idFromFile(root)
	if err != nil {
		return "", err
	}
	kind, err := fileKind(rootID.mode)
	if err != nil {
		return "", err
	}
	if kind != 'd' {
		return "", errNotDir
	}
	if err := inspectID(rootID, rootID.dev, policy, kind); err != nil {
		return "", err
	}
	tree := &node{name: ".", kind: 'd', id: rootID}
	acc := &walkAcc{rootDev: rootID.dev, policy: policy, entries: 1}
	if err := walkDir(root, tree, acc, 0); err != nil {
		return "", err
	}
	got := digestTree(tree)
	if len(expected) != 64 || len(got) != 64 || subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		return got, errHashMismatch
	}
	if !policy.ApplyFlags {
		return got, nil
	}
	if policy.SetFlags == nil {
		if err := requireLinux(); err != nil {
			return got, err
		}
	}
	if err := applyImmutableBottomUp(root, tree, policy); err != nil {
		return got, err
	}
	return got, nil
}

type walkAcc struct {
	rootDev    uint64
	policy     sealPolicy
	entries    int
	totalBytes int64
}

func (acc *walkAcc) accountRegular(size int64) error {
	if size < 0 || size > maxFileBytes || acc.totalBytes > maxTreeBytes-size {
		return errTooLarge
	}
	acc.totalBytes += size
	return nil
}

func walkDir(dir *os.File, n *node, acc *walkAcc, depth int) error {
	if depth > maxDepth {
		return errTraversal
	}
	before, err := idFromFile(dir)
	if err != nil {
		return err
	}
	if !before.sameDir(n.id) {
		return errMutation
	}
	names, err := listNames(dir)
	if err != nil {
		return err
	}
	if acc.policy.AfterList != nil {
		acc.policy.AfterList(n.name)
	}
	again, err := listNames(dir)
	if err != nil {
		return err
	}
	if !equalStrings(names, again) {
		return errMutation
	}
	mid, err := idFromFile(dir)
	if err != nil {
		return err
	}
	if !mid.sameDir(n.id) {
		return errMutation
	}
	if acc.entries+len(names) > maxEntries {
		return errTooLarge
	}
	for _, name := range names {
		childPath := name
		if n.name != "." {
			childPath = n.name + "/" + name
		}
		if name == receiptName && n.name != "." {
			return fmt.Errorf("%w: %s", errNestedReceipt, childPath)
		}
		if len(childPath) > maxPathBytes {
			return errTraversal
		}
		listed, ckind, err := inspectChildAt(dir, name, acc.rootDev, acc.policy)
		if err != nil {
			return fmt.Errorf("%w: %s", err, childPath)
		}
		if ckind == 'l' {
			cn, err := inspectSymlink(dir, name, childPath, listed, acc)
			if err != nil {
				return err
			}
			acc.entries++
			n.children = append(n.children, cn)
			continue
		}
		child, err := openChild(dir, name)
		if err != nil {
			return err
		}
		cid, err := idFromFile(child)
		if err != nil {
			_ = child.Close()
			return err
		}
		openedKind, err := fileKind(cid.mode)
		if err != nil {
			_ = child.Close()
			return fmt.Errorf("%w: %s", err, childPath)
		}
		if openedKind != ckind || cid.dev != listed.dev || cid.ino != listed.ino || cid.nlink != listed.nlink || cid.uid != listed.uid || cid.gid != listed.gid || cid.mode != listed.mode {
			_ = child.Close()
			return errMutation
		}
		if err := inspectID(cid, acc.rootDev, acc.policy, ckind); err != nil {
			_ = child.Close()
			return fmt.Errorf("%w: %s", err, childPath)
		}
		cn := &node{name: childPath, kind: ckind, id: cid}
		acc.entries++
		if ckind == 'd' {
			if err := walkDir(child, cn, acc, depth+1); err != nil {
				_ = child.Close()
				return err
			}
		} else {
			if err := acc.accountRegular(cid.size); err != nil {
				_ = child.Close()
				return fmt.Errorf("%w: %s", err, childPath)
			}
			sum, err := hashRegular(child, cid)
			if err != nil {
				_ = child.Close()
				return err
			}
			cn.content = sum
		}
		if err := child.Close(); err != nil {
			return err
		}
		n.children = append(n.children, cn)
	}
	if err := revalidateSymlinkChildren(dir, n, acc.rootDev); err != nil {
		return err
	}
	finalNames, err := listNames(dir)
	if err != nil {
		return err
	}
	if !equalStrings(names, finalNames) {
		return errMutation
	}
	after, err := idFromFile(dir)
	if err != nil {
		return err
	}
	if !after.sameDir(n.id) {
		return errMutation
	}
	return nil
}

func inspectSymlink(dir *os.File, name, childPath string, listed fileID, acc *walkAcc) (*node, error) {
	target, err := readlinkAt(dir, name)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, childPath)
	}
	if err := validateSymlinkTarget(childPath, target); err != nil {
		return nil, fmt.Errorf("%w: %s", err, childPath)
	}
	again, kind, err := inspectChildAt(dir, name, acc.rootDev, acc.policy)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, childPath)
	}
	target2, err := readlinkAt(dir, name)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, childPath)
	}
	if kind != 'l' || !again.sameSymlink(listed) || target2 != target {
		return nil, errMutation
	}
	sum := sha256.Sum256([]byte(target))
	return &node{name: childPath, kind: 'l', id: again, content: sum, target: target}, nil
}

func applyImmutableBottomUp(dir *os.File, n *node, policy sealPolicy) error {
	id, err := idFromFile(dir)
	if err != nil {
		return err
	}
	if !id.sameDir(n.id) {
		return errMutation
	}
	names, err := listNames(dir)
	if err != nil {
		return err
	}
	if len(names) != len(n.children) {
		return errMutation
	}
	for i, child := range n.children {
		want := path.Base(child.name)
		if names[i] != want {
			return errMutation
		}
		listed, ckind, err := inspectChildAt(dir, names[i], n.id.dev, sealPolicy{UID: child.id.uid, GID: child.id.gid})
		if err != nil {
			return err
		}
		if ckind != child.kind || listed.dev != child.id.dev || listed.ino != child.id.ino {
			return errMutation
		}
		if child.kind == 'l' {
			if err := revalidateSymlink(dir, child, n.id.dev); err != nil {
				return err
			}
			continue
		}
		held, err := openChild(dir, names[i])
		if err != nil {
			return err
		}
		cid, err := idFromFile(held)
		if err != nil {
			_ = held.Close()
			return err
		}
		if child.kind == 'd' {
			if !cid.sameDir(child.id) {
				_ = held.Close()
				return errMutation
			}
			if err := applyImmutableBottomUp(held, child, policy); err != nil {
				_ = held.Close()
				return err
			}
		} else {
			if !cid.sameFile(child.id) {
				_ = held.Close()
				return errMutation
			}
			if err := applyFlags(held, 'f', child.name, policy); err != nil {
				_ = held.Close()
				return err
			}
		}
		if err := held.Close(); err != nil {
			return err
		}
	}
	if err := revalidateSymlinkChildren(dir, n, n.id.dev); err != nil {
		return err
	}
	if err := applyFlags(dir, 'd', n.name, policy); err != nil {
		return err
	}
	if err := revalidateSymlinkChildren(dir, n, n.id.dev); err != nil {
		return err
	}
	return nil
}

func applyFlags(f *os.File, kind byte, rel string, policy sealPolicy) error {
	if kind == 'l' {
		return errSymlink
	}
	if policy.SetFlags != nil {
		return policy.SetFlags(kind, rel)
	}
	if err := setImmutable(int(f.Fd())); err != nil {
		runtime.KeepAlive(f)
		return err
	}
	runtime.KeepAlive(f)
	return nil
}

func revalidateSymlinkChildren(dir *os.File, n *node, rootDev uint64) error {
	for _, child := range n.children {
		if child.kind != 'l' {
			continue
		}
		if err := revalidateSymlink(dir, child, rootDev); err != nil {
			return err
		}
	}
	return nil
}

func revalidateSymlink(dir *os.File, child *node, rootDev uint64) error {
	name := path.Base(child.name)
	listed, kind, err := inspectChildAt(dir, name, rootDev, sealPolicy{UID: child.id.uid, GID: child.id.gid})
	if err != nil {
		return err
	}
	if kind != 'l' || !listed.sameSymlink(child.id) {
		return errMutation
	}
	target, err := readlinkAt(dir, name)
	if err != nil {
		return err
	}
	if target != child.target {
		return errMutation
	}
	if err := validateSymlinkTarget(child.name, target); err != nil {
		return err
	}
	return nil
}

func inspectChildAt(dir *os.File, name string, rootDev uint64, policy sealPolicy) (fileID, byte, error) {
	if err := validateChildName(name); err != nil {
		return fileID{}, 0, err
	}
	st, err := fstatAt(dir, name)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return fileID{}, 0, errMutation
		}
		return fileID{}, 0, err
	}
	id := fileID{
		dev:   uint64(st.Dev),
		ino:   uint64(st.Ino),
		nlink: uint64(st.Nlink),
		uid:   st.Uid,
		gid:   st.Gid,
		mode:  uint32(st.Mode),
		size:  st.Size,
	}
	id.mtime, id.ctime, err = statTimes(st)
	if err != nil {
		return fileID{}, 0, err
	}
	kind, err := fileKind(id.mode)
	if err != nil {
		return fileID{}, 0, err
	}
	if err := inspectID(id, rootDev, policy, kind); err != nil {
		return fileID{}, 0, err
	}
	return id, kind, nil
}

func fstatAt(dir *os.File, name string) (syscall.Stat_t, error) {
	var st syscall.Stat_t
	if runtime.GOOS == "linux" {
		p, err := syscall.BytePtrFromString(name)
		if err != nil {
			return st, err
		}
		_, _, errno := syscall.Syscall6(
			linuxSysNewfstatat,
			uintptr(dir.Fd()),
			uintptr(unsafe.Pointer(p)),
			uintptr(unsafe.Pointer(&st)),
			linuxAtSymlinkNofollow,
			0,
			0,
		)
		runtime.KeepAlive(dir)
		runtime.KeepAlive(p)
		if errno != 0 {
			return st, errno
		}
		return st, nil
	}
	if err := syscall.Lstat(path.Join(dir.Name(), name), &st); err != nil {
		return st, err
	}
	return st, nil
}

func readlinkAt(dir *os.File, name string) (string, error) {
	if err := validateChildName(name); err != nil {
		return "", err
	}
	buf := make([]byte, maxPathBytes+1)
	var n int
	if runtime.GOOS == "linux" {
		p, err := syscall.BytePtrFromString(name)
		if err != nil {
			return "", err
		}
		r1, _, errno := syscall.Syscall6(
			linuxSysReadlinkat,
			uintptr(dir.Fd()),
			uintptr(unsafe.Pointer(p)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			0,
			0,
		)
		runtime.KeepAlive(dir)
		runtime.KeepAlive(p)
		runtime.KeepAlive(buf)
		if errno != 0 {
			if errno == syscall.ENOENT || errno == syscall.EINVAL {
				return "", errMutation
			}
			if errno == syscall.ELOOP {
				return "", errSymlink
			}
			return "", errno
		}
		n = int(r1)
	} else {
		var err error
		n, err = syscall.Readlink(path.Join(dir.Name(), name), buf)
		if err != nil {
			if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EINVAL) {
				return "", errMutation
			}
			return "", err
		}
	}
	if n <= 0 || n > maxPathBytes || n >= len(buf) {
		return "", errSymlink
	}
	for _, c := range buf[:n] {
		if c == 0 {
			return "", errSymlink
		}
	}
	return string(buf[:n]), nil
}

func validateSymlinkTarget(rel, target string) error {
	if target == "" || len(target) > maxPathBytes {
		return errSymlink
	}
	if target[0] == '/' {
		return errSymlink
	}
	for i := 0; i < len(target); i++ {
		if target[i] == 0 || target[i] == '\\' {
			return errSymlink
		}
	}
	if len(target) >= 2 && target[1] == ':' {
		a := target[0]
		if (a >= 'A' && a <= 'Z') || (a >= 'a' && a <= 'z') {
			return errSymlink
		}
	}
	var resolved []string
	if dir := path.Dir(rel); dir != "." {
		resolved = strings.Split(dir, "/")
	}
	for _, part := range strings.Split(target, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(resolved) == 0 {
				return errSymlink
			}
			resolved = resolved[:len(resolved)-1]
			continue
		}
		resolved = append(resolved, part)
		if len(resolved) > maxDepth {
			return errSymlink
		}
	}
	return nil
}

func inspectID(id fileID, rootDev uint64, policy sealPolicy, kind byte) error {
	if id.dev != rootDev {
		return errDevice
	}
	if id.uid != policy.UID || id.gid != policy.GID {
		return fmt.Errorf(
			"%w: uid=%d gid=%d expected_uid=%d expected_gid=%d",
			errOwner,
			id.uid,
			id.gid,
			policy.UID,
			policy.GID,
		)
	}
	if id.mode&0o7000 != 0 || (kind != 'l' && id.mode&0o022 != 0) {
		return errMode
	}
	if policy.RequireExactModes {
		permissions := id.mode & 0o7777
		if (kind == 'd' && permissions != sealedDirectoryMode) ||
			(kind == 'f' && permissions != sealedDataMode && permissions != sealedExecutableMode) ||
			(kind == 'l' && permissions != sealedSymlinkMode) {
			return errMode
		}
	}
	if kind == 'f' && id.nlink != 1 {
		return errHardlink
	}
	return nil
}

func inspectAncestorID(id fileID) error {
	kind, err := fileKind(id.mode)
	if err != nil {
		return err
	}
	if kind != 'd' {
		return errNotDir
	}
	if id.uid != 0 || id.gid != 0 {
		return errOwner
	}
	if id.mode&0o7022 != 0 {
		return errMode
	}
	return nil
}

func fileKind(mode uint32) (byte, error) {
	switch mode & syscall.S_IFMT {
	case syscall.S_IFREG:
		return 'f', nil
	case syscall.S_IFDIR:
		return 'd', nil
	case syscall.S_IFLNK:
		return 'l', nil
	default:
		return 0, errSpecial
	}
}

func idFromFile(f *os.File) (fileID, error) {
	info, err := f.Stat()
	if err != nil {
		return fileID{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return fileID{}, errors.New("stat type is unsupported")
	}
	mtime, ctime, err := statTimes(*st)
	if err != nil {
		return fileID{}, err
	}
	return fileID{
		dev:   uint64(st.Dev),
		ino:   uint64(st.Ino),
		nlink: uint64(st.Nlink),
		uid:   st.Uid,
		gid:   st.Gid,
		mode:  uint32(st.Mode),
		size:  st.Size,
		mtime: mtime,
		ctime: ctime,
	}, nil
}

func statTimes(st syscall.Stat_t) (int64, int64, error) {
	value := reflect.ValueOf(st)
	read := func(names ...string) (int64, error) {
		for _, name := range names {
			field := value.FieldByName(name)
			if !field.IsValid() {
				continue
			}
			sec := field.FieldByName("Sec")
			nsec := field.FieldByName("Nsec")
			if !sec.IsValid() || !nsec.IsValid() || !sec.CanInt() || !nsec.CanInt() {
				return 0, errors.New("stat timestamp is unsupported")
			}
			return sec.Int()*1_000_000_000 + nsec.Int(), nil
		}
		return 0, errors.New("stat timestamp is unavailable")
	}
	mtime, err := read("Mtim", "Mtimespec")
	if err != nil {
		return 0, 0, err
	}
	ctime, err := read("Ctim", "Ctimespec")
	if err != nil {
		return 0, 0, err
	}
	return mtime, ctime, nil
}

func (a fileID) sameDir(b fileID) bool {
	return a.dev == b.dev && a.ino == b.ino && a.nlink == b.nlink && a.uid == b.uid && a.gid == b.gid && a.mode == b.mode && a.ctime == b.ctime
}

func (a fileID) sameFile(b fileID) bool {
	return a.sameDir(b) && a.size == b.size && a.mtime == b.mtime
}

func (a fileID) sameSymlink(b fileID) bool {
	return a.sameDir(b) && a.size == b.size && a.mtime == b.mtime
}

func hashRegular(f *os.File, id fileID) ([32]byte, error) {
	var zero [32]byte
	if id.size < 0 || id.size > maxFileBytes {
		return zero, errTooLarge
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return zero, err
	}
	sum := sha256.New()
	var total int64
	buf := make([]byte, 64*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > maxFileBytes {
				return zero, errTooLarge
			}
			_, _ = sum.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return zero, err
		}
	}
	again, err := idFromFile(f)
	if err != nil {
		return zero, err
	}
	if !again.sameFile(id) || total != id.size {
		return zero, errMutation
	}
	var out [32]byte
	copy(out[:], sum.Sum(nil))
	return out, nil
}

func digestTree(root *node) string {
	var nodes []*node
	collectDigestEntries(root, &nodes)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].name < nodes[j].name })
	h := sha256.New()
	for _, n := range nodes {
		kind, size, ok := digestPayload(n)
		if !ok {
			continue
		}
		_, _ = h.Write([]byte{kind, 0})
		_, _ = h.Write([]byte(n.name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(strconv.FormatInt(size, 10)))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(n.content[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func digestPayload(n *node) (byte, int64, bool) {
	switch n.kind {
	case 'f':
		return 'F', n.id.size, true
	case 'l':
		return 'L', int64(len(n.target)), true
	default:
		return 0, 0, false
	}
}

func collectDigestEntries(n *node, dst *[]*node) {
	if (n.kind == 'f' || n.kind == 'l') && n.name != "." && n.name != receiptName {
		*dst = append(*dst, n)
	}
	for _, child := range n.children {
		collectDigestEntries(child, dst)
	}
}

func listNames(f *os.File) ([]string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	fd := int(f.Fd())
	var names []string
	buf := make([]byte, 8192)
	for {
		n, err := syscall.ReadDirent(fd, buf)
		runtime.KeepAlive(f)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			break
		}
		_, _, names = syscall.ParseDirent(buf[:n], -1, names)
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if err := validateChildName(name); err != nil {
			return nil, err
		}
		if _, ok := seen[name]; ok {
			return nil, errMutation
		}
		seen[name] = struct{}{}
	}
	sort.Strings(names)
	return names, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func setImmutable(fd int) error {
	var flags int64
	if err := ioctlFlags(fd, fsIocGetflags, &flags); err != nil {
		return err
	}
	next := flags | fsImmutableFL
	if next&fsImmutableFL == 0 {
		return errNotImmutable
	}
	if flags&^next != 0 {
		return errClearFlags
	}
	if next != flags {
		if err := ioctlFlags(fd, fsIocSetflags, &next); err != nil {
			return err
		}
		if next&fsImmutableFL == 0 {
			return errClearFlags
		}
	}
	var got int64
	if err := ioctlFlags(fd, fsIocGetflags, &got); err != nil {
		return err
	}
	if got&fsImmutableFL == 0 {
		return errNotImmutable
	}
	if flags&^got != 0 {
		return errClearFlags
	}
	if err := syscall.Fsync(fd); err != nil {
		return err
	}
	return nil
}

func ioctlFlags(fd int, req uintptr, flags *int64) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(flags)))
	if errno != 0 {
		return errno
	}
	return nil
}
