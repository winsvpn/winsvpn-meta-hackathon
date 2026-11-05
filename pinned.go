//go:build darwin

package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type pinnedDir struct {
	label   string
	fd      int
	id      identity
	owned   []int
	anchors []dirAnchor
}

type leafRef struct {
	dir  *pinnedDir
	name string
	id   identity
}

type dirAnchor struct {
	parent int
	leaf   string
	fd     int
	id     identity
}

func (d *pinnedDir) close() {
	if d != nil {
		for i := len(d.owned) - 1; i >= 0; i-- {
			_ = unix.Close(d.owned[i])
		}
		d.owned = nil
		d.fd = -1
	}
}

func cleanAbs(p string) (string, error) {
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return "", fmt.Errorf("path must be an already-clean absolute path: %q", p)
	}
	return p, nil
}

// openPinnedAbsolute resolves every component from a retained "/" descriptor.
// It rejects symlinks at every component and pins the final identity. Strings
// are used only as audit labels after this one descriptor-relative resolution.
func openPinnedAbsolute(path string) (*pinnedDir, []identity, error) {
	path, err := cleanAbs(path)
	if err != nil {
		return nil, nil, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	owned := []int{fd}
	var chain []identity
	var anchors []dirAnchor
	add := func(x int) error {
		var st unix.Stat_t
		if err := unix.Fstat(x, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return errors.New("resolved component is not a directory")
		}
		chain = append(chain, identityOf(&st, ""))
		return nil
	}
	if err := add(fd); err != nil {
		unix.Close(fd)
		return nil, nil, err
	}
	for _, c := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if c == "" {
			continue
		}
		next, e := unix.Openat(fd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			for _, x := range owned {
				unix.Close(x)
			}
			return nil, nil, fmt.Errorf("openat component %q of %q: %w", c, path, e)
		}
		parent := fd
		fd = next
		owned = append(owned, fd)
		if err := add(fd); err != nil {
			for _, x := range owned {
				unix.Close(x)
			}
			return nil, nil, err
		}
		anchors = append(anchors, dirAnchor{parent: parent, leaf: c, fd: fd, id: chain[len(chain)-1]})
	}
	return &pinnedDir{label: path, fd: fd, id: chain[len(chain)-1], owned: owned, anchors: anchors}, chain, nil
}

func (d *pinnedDir) openDir(rel string) (*pinnedDir, error) {
	if rel == "" {
		dup, err := unix.Dup(d.fd)
		if err != nil {
			return nil, err
		}
		return &pinnedDir{label: d.label, fd: dup, id: d.id, owned: []int{dup}}, nil
	}
	if !safeRel(rel) {
		return nil, fmt.Errorf("unsafe directory relative path %q", rel)
	}
	fd := d.fd
	var owned []int
	var anchors []dirAnchor
	label := d.label
	for _, c := range strings.Split(filepath.ToSlash(rel), "/") {
		next, e := unix.Openat(fd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			for _, x := range owned {
				unix.Close(x)
			}
			return nil, fmt.Errorf("openat %s/%s: %w", label, c, e)
		}
		parent := fd
		fd = next
		owned = append(owned, fd)
		label = filepath.Join(label, c)
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			for _, x := range owned {
				unix.Close(x)
			}
			return nil, err
		}
		anchors = append(anchors, dirAnchor{parent: parent, leaf: c, fd: fd, id: identityOf(&st, "")})
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &pinnedDir{label: label, fd: fd, id: identityOf(&st, ""), owned: owned, anchors: anchors}, nil
}

func (d *pinnedDir) recheck() error {
	var st unix.Stat_t
	if err := unix.Fstat(d.fd, &st); err != nil {
		return err
	}
	got := identityOf(&st, "")
	if !sameDir(got, d.id) {
		return fmt.Errorf("pinned directory identity/owner/mode drift: %s", d.label)
	}
	for _, a := range d.anchors {
		var fst, ent unix.Stat_t
		if err := unix.Fstat(a.fd, &fst); err != nil {
			return err
		}
		if err := unix.Fstatat(a.parent, a.leaf, &ent, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("expected ancestor name no longer resolves: %s: %w", a.leaf, err)
		}
		fid, eid := identityOf(&fst, ""), identityOf(&ent, "")
		if !sameDir(fid, a.id) || !sameDir(eid, a.id) {
			return fmt.Errorf("ancestor rename/substitution/metadata drift: %s", a.leaf)
		}
	}
	return nil
}

func (d *pinnedDir) statLeaf(name string) (identity, error) {
	if strings.Contains(name, "/") || name == "" || name == "." || name == ".." {
		return identity{}, errors.New("invalid leaf")
	}
	var st unix.Stat_t
	if err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return identity{}, err
	}
	return identityOf(&st, ""), nil
}

func (d *pinnedDir) openLeaf(name string, flags int, mode uint32) (int, error) {
	if strings.Contains(name, "/") || name == "" || name == "." || name == ".." {
		return -1, errors.New("invalid leaf")
	}
	return unix.Openat(d.fd, name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
}

func hashFD(fd int, limit int64) (string, int64, error) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return "", 0, err
	}
	f := os.NewFile(uintptr(dup), "retained-descriptor")
	defer f.Close()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return "", n, err
	}
	if n > limit {
		return "", n, errors.New("descriptor exceeds bounded read")
	}
	return fmt.Sprintf("%x", h.Sum(nil)), n, nil
}

func verifyLeaf(d *pinnedDir, name string, r row, requireOneLink bool) (identity, error) {
	fd, err := d.openLeaf(name, unix.O_RDONLY, 0)
	if err != nil {
		return identity{}, err
	}
	defer unix.Close(fd)
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return identity{}, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0644 {
		return identity{}, fmt.Errorf("want regular 0644, got type/mode %#o", before.Mode)
	}
	if requireOneLink && before.Nlink != 1 {
		return identity{}, fmt.Errorf("nlink=%d, want 1", before.Nlink)
	}
	sha, n, err := hashFD(fd, r.Size)
	if err != nil {
		return identity{}, err
	}
	if err := unix.Fstat(fd, &after); err != nil {
		return identity{}, err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size ||
		before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid {
		return identity{}, errors.New("descriptor mutated while hashing")
	}
	if n != r.Size || sha != r.SHA {
		return identity{}, fmt.Errorf("tuple size=%d sha=%s, want %d %s", n, sha, r.Size, r.SHA)
	}
	entry, err := d.statLeaf(name)
	if err != nil {
		return identity{}, err
	}
	got := identityOf(&after, sha)
	if !sameObject(got, entry) {
		return identity{}, errors.New("descriptor/entry identity mismatch")
	}
	return got, nil
}

func lsofEmptyBracketed(d *pinnedDir, name string, want identity) error {
	return lsofEmptySet([]leafRef{{dir: d, name: name, id: want}})
}

func lsofEmptySet(refs []leafRef) error {
	args := []string{"-F", "pfn", "--"}
	for _, r := range refs {
		if err := r.dir.recheck(); err != nil {
			return fmt.Errorf("lsof ancestor pre-bracket drift: %w", err)
		}
		before, err := r.dir.statLeaf(r.name)
		if err != nil || !sameObject(before, r.id) {
			return errors.New("lsof pre-bracket identity drift")
		}
		args = append(args, filepath.Join(r.dir.label, r.name))
	}
	out, err := exec.Command("/usr/sbin/lsof", args...).CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 {
			return fmt.Errorf("lsof: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	if len(out) != 0 {
		return fmt.Errorf("lsof reports open descriptor(s): %s", strings.TrimSpace(string(out)))
	}
	for _, r := range refs {
		if err := r.dir.recheck(); err != nil {
			return fmt.Errorf("lsof ancestor post-bracket drift: %w", err)
		}
		after, err := r.dir.statLeaf(r.name)
		if err != nil || !sameObject(after, r.id) {
			return errors.New("lsof post-bracket identity drift")
		}
	}
	return nil
}

func chainsOverlapAtOrBelow(receiptChain, protectedChain []identity) bool {
	if len(protectedChain) == 0 {
		return false
	}
	protectedRoot := protectedChain[len(protectedChain)-1]
	for _, ancestor := range receiptChain {
		if sameObject(ancestor, protectedRoot) {
			return true
		}
	}
	if len(receiptChain) < len(protectedChain) {
		return false
	}
	for i := range protectedChain {
		if !sameObject(receiptChain[i], protectedChain[i]) {
			return false
		}
	}
	return true
}

func requireSameFilesystem(root, child *pinnedDir) error {
	if root == nil || child == nil || root.id.Dev != child.id.Dev {
		return errors.New("cross-filesystem directory refused")
	}
	return nil
}
