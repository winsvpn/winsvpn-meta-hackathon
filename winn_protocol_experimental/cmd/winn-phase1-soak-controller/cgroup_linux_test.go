//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxCycleCgroupAtomicConfigurationAccountingAndCleanupEvidence(
	t *testing.T,
) {
	containment, procRoot := newLinuxContainmentFixture(
		t, "cpu memory pids\n", "memory pids\n", true,
	)
	command := exec.Command("/bin/true")
	if err := containment.Configure(command); err != nil {
		t.Fatal(err)
	}
	if command.SysProcAttr == nil || !command.SysProcAttr.UseCgroupFD ||
		command.SysProcAttr.CgroupFD != int(containment.directory.Fd()) {
		t.Fatal("command was not configured for clone-into-cgroup")
	}

	writeFixtureFile(t, containment.path, "cgroup.procs", "201\n202\n")
	writeCgroupProcFixture(t, procRoot, 201, 2, 3, 1024)
	writeCgroupProcFixture(t, procRoot, 202, 4, 5, 2048)
	writeFixtureFile(t, containment.path, "memory.peak", "4194304\n")
	writeFixtureFile(t, containment.path, "pids.peak", "9\n")
	threads, files, rss, supported, err := containment.Sample(procRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !supported || threads != 9 || files != 8 || rss != 4<<20 {
		t.Fatalf(
			"sample supported=%t threads=%d files=%d rss=%d",
			supported, threads, files, rss,
		)
	}

	writeFixtureFile(t, containment.path, "cgroup.kill", "")
	if err := containment.KillAll(); err != nil {
		t.Fatal(err)
	}
	if got := readFixtureFile(t, containment.path, "cgroup.kill"); got != "1\n" {
		t.Fatalf("cgroup.kill contains %q", got)
	}
	finalEvents := "populated 0\nfrozen 0\n"
	writeFixtureFile(t, containment.path, "cgroup.events", finalEvents)
	wantInode := containment.childInode
	evidence, err := containment.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Schema != linuxCgroupV2CleanupSchema ||
		evidence.ChildCgroupInode != wantInode ||
		evidence.FinalCgroupEvents != finalEvents ||
		!evidence.ChildRemoved {
		t.Fatalf("unexpected cleanup evidence: %+v", evidence)
	}
	if _, err := os.Lstat(containment.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("child cgroup was not removed: %v", err)
	}
	if second, err := containment.Finish(); err == nil ||
		second != (CycleContainmentCleanup{}) {
		t.Fatalf("second cleanup returned evidence=%+v err=%v", second, err)
	}
}

func TestLinuxCycleCgroupPopulatedOneKillsThenRecordsZero(t *testing.T) {
	containment, _ := newLinuxContainmentFixture(
		t, "memory pids\n", "memory pids\n", true,
	)
	writeFixtureFile(t, containment.path, "cgroup.kill", "")
	reads := [][]byte{
		[]byte("populated 1\nfrozen 0\n"),
		[]byte("populated 0\nfrozen 0\n"),
	}
	containment.readEvents = func() ([]byte, error) {
		if len(reads) == 0 {
			t.Fatal("unexpected extra cgroup.events read")
		}
		raw := reads[0]
		reads = reads[1:]
		return raw, nil
	}
	killObserved := false
	oldUnlink := cgroupUnlinkat
	cgroupUnlinkat = func(parentFD int, name string, flags int) error {
		if got := readFixtureFile(
			t, containment.path, "cgroup.kill",
		); got == "1\n" {
			killObserved = true
		}
		return oldUnlink(parentFD, name, flags)
	}
	t.Cleanup(func() { cgroupUnlinkat = oldUnlink })
	evidence, err := containment.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if evidence.FinalCgroupEvents != "populated 0\nfrozen 0\n" ||
		!evidence.ChildRemoved {
		t.Fatalf("wrong terminal evidence: %+v", evidence)
	}
	if !killObserved {
		t.Fatal("populated cgroup reached removal without a cgroup.kill write")
	}
	if got := readRemovedFixtureSibling(
		t, containment.path, "cgroup.kill",
	); got != "" {
		// The whole child is intentionally gone. This helper returning empty
		// proves the test did not accidentally inspect a replacement path.
		t.Fatalf("removed child unexpectedly remained readable: %q", got)
	}
}

func TestRemovedCgroupLinkCountMatchesRegularAndCgroupfsSemantics(t *testing.T) {
	for _, count := range []uint64{0, 2} {
		if !validRemovedCgroupLinkCount(count) {
			t.Errorf("valid post-removal link count %d was refused", count)
		}
	}
	for _, count := range []uint64{1, 3, 4, ^uint64(0)} {
		if validRemovedCgroupLinkCount(count) {
			t.Errorf("invalid post-removal link count %d was accepted", count)
		}
	}
}

func TestParseCgroupEventsRejectsMalformedInputs(t *testing.T) {
	oversized := append(
		[]byte("populated 0\n"),
		make([]byte, maximumCgroupControlBytes)...,
	)
	cases := map[string][]byte{
		"empty":        {},
		"missing":      []byte("frozen 0\n"),
		"duplicate":    []byte("populated 0\npopulated 0\n"),
		"invalid":      []byte("populated 2\n"),
		"malformed":    []byte("populated  0\n"),
		"unterminated": []byte("populated 0"),
		"oversized":    oversized,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCgroupEvents(raw); err == nil {
				t.Fatalf("accepted malformed cgroup.events %q", raw)
			}
		})
	}
	if populated, err := parseCgroupEvents(
		[]byte("populated 0\nfrozen 0\n"),
	); err != nil || populated {
		t.Fatalf("canonical populated=0 was refused: %t %v", populated, err)
	}
}

func TestLinuxCycleCgroupRemovalFailureReturnsNoPartialEvidence(t *testing.T) {
	containment, _ := newLinuxContainmentFixture(
		t, "memory pids\n", "memory pids\n", true,
	)
	writeFixtureFile(t, containment.path, "cgroup.events", "populated 0\n")
	old := cgroupUnlinkat
	cgroupUnlinkat = func(int, string, int) error {
		return unix.EPERM
	}
	t.Cleanup(func() { cgroupUnlinkat = old })
	evidence, err := containment.Finish()
	if err == nil || evidence != (CycleContainmentCleanup{}) {
		t.Fatalf("removal failure returned evidence=%+v err=%v", evidence, err)
	}
	if _, err := os.Lstat(containment.path); err != nil {
		t.Fatalf("failed removal did not preserve the named child: %v", err)
	}
}

func TestLinuxCycleCgroupReappearanceFailsClosed(t *testing.T) {
	containment, _ := newLinuxContainmentFixture(
		t, "memory pids\n", "memory pids\n", true,
	)
	writeFixtureFile(t, containment.path, "cgroup.events", "populated 0\n")
	old := cgroupUnlinkat
	cgroupUnlinkat = func(parentFD int, name string, flags int) error {
		if err := old(parentFD, name, flags); err != nil {
			return err
		}
		return unix.Mkdirat(parentFD, name, 0o700)
	}
	t.Cleanup(func() { cgroupUnlinkat = old })
	evidence, err := containment.Finish()
	if err == nil || !strings.Contains(err.Error(), "reappeared") ||
		evidence != (CycleContainmentCleanup{}) {
		t.Fatalf("reappearance returned evidence=%+v err=%v", evidence, err)
	}
}

func TestLinuxCycleCgroupFinalWindowSwapReturnsNoEvidence(t *testing.T) {
	containment, _ := newLinuxContainmentFixture(
		t, "memory pids\n", "memory pids\n", true,
	)
	writeFixtureFile(t, containment.path, "cgroup.events", "populated 0\n")
	alternate := containment.path + ".alternate"
	old := cgroupUnlinkat
	cgroupUnlinkat = func(parentFD int, name string, flags int) error {
		if err := os.Rename(containment.path, alternate); err != nil {
			return err
		}
		if err := os.Mkdir(containment.path, 0o700); err != nil {
			return err
		}
		return old(parentFD, name, flags)
	}
	t.Cleanup(func() { cgroupUnlinkat = old })
	evidence, err := containment.Finish()
	if err == nil || !strings.Contains(err.Error(), "remains linked") ||
		evidence != (CycleContainmentCleanup{}) {
		t.Fatalf("final-window swap returned evidence=%+v err=%v", evidence, err)
	}
	if _, err := os.Stat(alternate); err != nil {
		t.Fatalf("original held inode did not survive at alternate name: %v", err)
	}
	if _, err := os.Lstat(containment.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement name was not removed: %v", err)
	}
}

func TestLinuxCycleCgroupPathSwapCannotRedirectCleanup(t *testing.T) {
	containment, _ := newLinuxContainmentFixture(
		t, "memory pids\n", "memory pids\n", true,
	)
	heldPath := containment.path + ".held"
	if err := os.Rename(containment.path, heldPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(containment.path, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, heldPath, "cgroup.events", "populated 0\n")
	writeFixtureFile(t, containment.path, "cgroup.events", "populated 0\n")
	evidence, err := containment.Finish()
	if err == nil || !strings.Contains(err.Error(), "changed identity") ||
		evidence != (CycleContainmentCleanup{}) {
		t.Fatalf("path swap returned evidence=%+v err=%v", evidence, err)
	}
	if _, err := os.Stat(heldPath); err != nil {
		t.Fatalf("held cgroup was modified: %v", err)
	}
	if _, err := os.Stat(containment.path); err != nil {
		t.Fatalf("replacement cgroup was modified: %v", err)
	}
}

func TestDelegatedCgroupParentRejectsSymlinkRedirectionAndWrongFilesystem(
	t *testing.T,
) {
	oldFstatfs := cgroupFstatfs
	cgroupFstatfs = func(_ int, facts *unix.Statfs_t) error {
		facts.Type = unix.CGROUP2_SUPER_MAGIC
		return nil
	}
	t.Cleanup(func() { cgroupFstatfs = oldFstatfs })

	rootBase := t.TempDir()
	realRoot := filepath.Join(rootBase, "real")
	if err := os.MkdirAll(filepath.Join(realRoot, "delegated", "unit"), 0o700); err != nil {
		t.Fatal(err)
	}
	rootLink := filepath.Join(rootBase, "root-link")
	if err := os.Symlink(realRoot, rootLink); err != nil {
		t.Fatal(err)
	}
	if fd, err := openDelegatedCgroupParent(rootLink, "/delegated/unit"); err == nil {
		_ = unix.Close(fd)
		t.Fatal("configured cgroup-root symlink was accepted")
	}

	intermediateRoot := filepath.Join(rootBase, "intermediate-root")
	realDelegated := filepath.Join(intermediateRoot, "real-delegated")
	if err := os.MkdirAll(filepath.Join(realDelegated, "unit"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDelegated, filepath.Join(intermediateRoot, "delegated")); err != nil {
		t.Fatal(err)
	}
	if fd, err := openDelegatedCgroupParent(
		intermediateRoot, "/delegated/unit",
	); err == nil {
		_ = unix.Close(fd)
		t.Fatal("intermediate delegated-path symlink was accepted")
	}

	cgroupFstatfs = func(_ int, facts *unix.Statfs_t) error {
		facts.Type = unix.TMPFS_MAGIC
		return nil
	}
	if fd, err := openDelegatedCgroupParent(realRoot, "/delegated/unit"); err == nil {
		_ = unix.Close(fd)
		t.Fatal("wrong filesystem was accepted as cgroup v2")
	} else if !strings.Contains(err.Error(), "not on cgroup-v2") {
		t.Fatalf("wrong-filesystem rejection was not diagnostic: %v", err)
	}
}

func TestCurrentCgroupPathRejectsTraversal(t *testing.T) {
	for _, path := range []string{"/delegated/../unit", "/delegated//unit", "/delegated/./unit"} {
		if _, err := relativeCgroupComponents(path); err == nil {
			t.Fatalf("unsafe current cgroup path %q was accepted", path)
		}
	}
}

func TestDelegatedControllerRequirements(t *testing.T) {
	t.Run("populated delegated parent", func(t *testing.T) {
		old := cgroupWriteSubtreeControl
		cgroupWriteSubtreeControl = func(int) error {
			t.Fatal("controller enablement was attempted on a populated parent")
			return nil
		}
		t.Cleanup(func() { cgroupWriteSubtreeControl = old })
		_, _, err := prepareControllerFixtureWithParentHook(
			t, "memory pids\n", "", true, func(parent string) {
				writeFixtureFile(t, parent, "cgroup.procs", "123\n")
			},
		)
		if err == nil || !strings.Contains(err.Error(), "contains processes") {
			t.Fatalf("populated delegated parent was accepted: %v", err)
		}
	})
	t.Run("absent controller", func(t *testing.T) {
		_, _, err := prepareControllerFixture(
			t, "cpu pids\n", "pids\n", true,
		)
		if err == nil || !strings.Contains(err.Error(), "memory controller") {
			t.Fatalf("absent memory controller was accepted: %v", err)
		}
	})
	t.Run("malformed controller list", func(t *testing.T) {
		_, _, err := prepareControllerFixture(
			t, "memory  pids\n", "memory pids\n", true,
		)
		if err == nil || !strings.Contains(err.Error(), "canonically") {
			t.Fatalf("malformed controller list was accepted: %v", err)
		}
	})
	t.Run("duplicate controller", func(t *testing.T) {
		_, _, err := prepareControllerFixture(
			t, "memory pids memory\n", "memory pids\n", true,
		)
		if err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("duplicate controller was accepted: %v", err)
		}
	})
	t.Run("unterminated controller list", func(t *testing.T) {
		_, _, err := prepareControllerFixture(
			t, "memory pids", "memory pids\n", true,
		)
		if err == nil || !strings.Contains(err.Error(), "unterminated") {
			t.Fatalf("unterminated controller list was accepted: %v", err)
		}
	})
	t.Run("write denied", func(t *testing.T) {
		old := cgroupWriteSubtreeControl
		cgroupWriteSubtreeControl = func(int) error { return unix.EPERM }
		t.Cleanup(func() { cgroupWriteSubtreeControl = old })
		_, _, err := prepareControllerFixture(
			t, "memory pids\n", "", true,
		)
		if err == nil || !strings.Contains(err.Error(), "enable delegated") {
			t.Fatalf("controller write denial was accepted: %v", err)
		}
	})
	t.Run("verification mismatch", func(t *testing.T) {
		old := cgroupWriteSubtreeControl
		cgroupWriteSubtreeControl = func(int) error { return nil }
		t.Cleanup(func() { cgroupWriteSubtreeControl = old })
		_, _, err := prepareControllerFixture(
			t, "memory pids\n", "", true,
		)
		if err == nil || !strings.Contains(err.Error(), "did not enable") {
			t.Fatalf("controller verification mismatch was accepted: %v", err)
		}
	})
	t.Run("enable and verify", func(t *testing.T) {
		var subtreePath string
		old := cgroupWriteSubtreeControl
		cgroupWriteSubtreeControl = func(parentFD int) error {
			return os.WriteFile(subtreePath, []byte("memory pids\n"), 0o600)
		}
		t.Cleanup(func() { cgroupWriteSubtreeControl = old })
		containment, parent, err := prepareControllerFixtureWithParentHook(
			t, "memory pids\n", "", true,
			func(path string) { subtreePath = filepath.Join(path, "cgroup.subtree_control") },
		)
		if err != nil {
			t.Fatal(err)
		}
		if containment == nil || parent == "" {
			t.Fatal("enabled controller fixture did not create containment")
		}
		writeFixtureFile(t, containment.path, "cgroup.events", "populated 0\n")
		if _, err := containment.Finish(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("already enabled", func(t *testing.T) {
		containment, _, err := prepareControllerFixture(
			t, "cpu memory pids\n", "memory pids\n", true,
		)
		if err != nil {
			t.Fatal(err)
		}
		writeFixtureFile(t, containment.path, "cgroup.events", "populated 0\n")
		if _, err := containment.Finish(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDelegatedParentCgroupRequiresExactControllerSubgroup(t *testing.T) {
	for _, test := range []struct {
		current string
		want    string
		ok      bool
	}{
		{"/system.slice/winn.service/controller", "/system.slice/winn.service", true},
		{"/delegated/unit/controller", "/delegated/unit", true},
		{"/delegated/unit", "", false},
		{"/delegated/unit/controller-other", "", false},
		{"/controller", "", false},
		{"/", "", false},
	} {
		got, err := delegatedParentCgroup(test.current)
		if test.ok {
			if err != nil {
				t.Errorf("delegatedParentCgroup(%q): %v", test.current, err)
			} else if got != test.want {
				t.Errorf(
					"delegatedParentCgroup(%q) = %q, want %q",
					test.current, got, test.want,
				)
			}
		} else if err == nil {
			t.Errorf(
				"delegatedParentCgroup(%q) = %q; unsafe topology accepted",
				test.current, got,
			)
		}
	}
}

func TestLinuxCycleCgroupRequiresChildPeakFiles(t *testing.T) {
	_, _, err := prepareControllerFixture(
		t, "memory pids\n", "memory pids\n", false,
	)
	if err == nil ||
		(!strings.Contains(err.Error(), "memory.peak") &&
			!strings.Contains(err.Error(), "pids.peak")) {
		t.Fatalf("missing child peak files were accepted: %v", err)
	}
}

func TestNoopContainmentUsesClosedNonApplicableShape(t *testing.T) {
	evidence, err := (noopCycleContainment{}).Finish()
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Schema != nonApplicableCleanupSchema ||
		evidence.ChildCgroupInode != 0 ||
		evidence.FinalCgroupEvents != "" ||
		evidence.ChildRemoved {
		t.Fatalf("non-applicable evidence is not closed: %+v", evidence)
	}
}

func TestLinuxCycleCgroupFailClosedWithoutUnifiedMembership(t *testing.T) {
	if _, err := prepareCycleContainment(
		t.TempDir(), filepath.Join(t.TempDir(), "missing-proc"), 1, true,
	); err == nil || !strings.Contains(err.Error(), "current cgroup membership") {
		t.Fatalf("missing unified membership was accepted: %v", err)
	}
}

func newLinuxContainmentFixture(
	t *testing.T,
	controllers, subtree string,
	createPeakFiles bool,
) (*linuxCycleCgroup, string) {
	t.Helper()
	containment, procRoot, err := prepareControllerFixture(
		t, controllers, subtree, createPeakFiles,
	)
	if err != nil {
		t.Fatal(err)
	}
	return containment, procRoot
}

func prepareControllerFixture(
	t *testing.T,
	controllers, subtree string,
	createPeakFiles bool,
) (*linuxCycleCgroup, string, error) {
	t.Helper()
	return prepareControllerFixtureWithParentHook(
		t, controllers, subtree, createPeakFiles, nil,
	)
}

func prepareControllerFixtureWithParentHook(
	t *testing.T,
	controllers, subtree string,
	createPeakFiles bool,
	parentHook func(string),
) (*linuxCycleCgroup, string, error) {
	t.Helper()
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	cgroupRoot := filepath.Join(root, "cgroup")
	current := "/delegated/unit/" + controllerDelegationSubgroup
	if err := os.MkdirAll(filepath.Join(procRoot, "self"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(procRoot, "self", "cgroup"),
		[]byte("0::"+current+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(cgroupRoot, "delegated", "unit")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, parent, "cgroup.controllers", controllers)
	writeFixtureFile(t, parent, "cgroup.subtree_control", subtree)
	writeFixtureFile(t, parent, "cgroup.procs", "")
	if parentHook != nil {
		parentHook(parent)
	}
	oldUnlink := cgroupUnlinkat
	cgroupUnlinkat = func(parentFD int, name string, flags int) error {
		if flags == unix.AT_REMOVEDIR {
			childPath := filepath.Join(parent, name)
			entries, err := os.ReadDir(childPath)
			if err == nil {
				for _, entry := range entries {
					if err := os.Remove(filepath.Join(childPath, entry.Name())); err != nil {
						return err
					}
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		return oldUnlink(parentFD, name, flags)
	}
	t.Cleanup(func() { cgroupUnlinkat = oldUnlink })
	oldFstatfs := cgroupFstatfs
	cgroupFstatfs = func(_ int, facts *unix.Statfs_t) error {
		facts.Type = unix.CGROUP2_SUPER_MAGIC
		return nil
	}
	t.Cleanup(func() { cgroupFstatfs = oldFstatfs })
	oldMkdir := cgroupMkdirat
	cgroupMkdirat = func(parentFD int, name string, mode uint32) error {
		if err := oldMkdir(parentFD, name, mode); err != nil {
			return err
		}
		if !createPeakFiles {
			return nil
		}
		childFD, err := unix.Openat(
			parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0,
		)
		if err != nil {
			return err
		}
		defer unix.Close(childFD)
		for _, peak := range []string{"memory.peak", "pids.peak"} {
			fd, err := unix.Openat(
				childFD, peak,
				unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC,
				0o600,
			)
			if err != nil {
				return err
			}
			if _, err := unix.Write(fd, []byte("0\n")); err != nil {
				_ = unix.Close(fd)
				return err
			}
			if err := unix.Close(fd); err != nil {
				return err
			}
		}
		return nil
	}
	t.Cleanup(func() { cgroupMkdirat = oldMkdir })
	result, err := prepareCycleContainment(cgroupRoot, procRoot, 7, true)
	if err != nil {
		return nil, procRoot, err
	}
	return result.(*linuxCycleCgroup), procRoot, nil
}

func writeFixtureFile(t *testing.T, directory, name, value string) {
	t.Helper()
	if err := os.WriteFile(
		filepath.Join(directory, name), []byte(value), 0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func readFixtureFile(t *testing.T, directory, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(directory, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func readRemovedFixtureSibling(t *testing.T, directory, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(directory, name))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func writeCgroupProcFixture(
	t *testing.T,
	procRoot string,
	pid, threads, files int,
	rss int64,
) {
	t.Helper()
	root := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(filepath.Join(root, "fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < files; index++ {
		writeFixtureFile(t, filepath.Join(root, "fd"), strconv.Itoa(index), "")
	}
	status := "Tgid:\t" + strconv.Itoa(pid) + "\n" +
		"Threads:\t" + strconv.Itoa(threads) + "\n" +
		"VmRSS:\t" + strconv.FormatInt(rss/1024, 10) + " kB\n"
	writeFixtureFile(t, root, "status", status)
}
