//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	maximumCgroupControlBytes  = 4 << 10
	maximumCgroupProcsBytes    = 1 << 20
	maximumCgroupParentEntries = 4096
)

type linuxCycleCgroup struct {
	path            string
	parentDirectory *os.File
	name            string
	directory       *os.File
	childDevice     uint64
	childInode      uint64
	finished        bool

	// Test-only deterministic event sequencing. Nil uses the held descriptor.
	readEvents func() ([]byte, error)
}

var (
	cgroupMkdirat             = unix.Mkdirat
	cgroupUnlinkat            = unix.Unlinkat
	cgroupFstatat             = unix.Fstatat
	cgroupFstatfs             = unix.Fstatfs
	cgroupWriteSubtreeControl = func(parentFD int) error {
		file, err := openCgroupFileAt(parentFD, "cgroup.subtree_control", os.O_WRONLY)
		if err != nil {
			return err
		}
		if err := writeAllOperation(file, []byte("+memory +pids\n")); err != nil {
			_ = file.Close()
			return err
		}
		return file.Close()
	}
)

func prepareCycleContainment(
	cgroupRoot, procRoot string, sequence int64, required bool,
) (cycleContainment, error) {
	if !required {
		return noopCycleContainment{}, nil
	}
	current, err := currentCgroupV2(procRoot)
	if err != nil {
		return nil, err
	}
	delegatedParent, err := delegatedParentCgroup(current)
	if err != nil {
		return nil, err
	}
	parentPath := filepath.Join(
		cgroupRoot, strings.TrimPrefix(delegatedParent, "/"),
	)
	parentFD, err := openDelegatedCgroupParent(cgroupRoot, delegatedParent)
	if err != nil {
		return nil, fmt.Errorf("open delegated cgroup parent %s: %w", parentPath, err)
	}
	// #nosec G115 -- unix.Open returned a nonnegative live descriptor.
	parent := os.NewFile(uintptr(parentFD), parentPath)
	closeParent := func(cause error) (cycleContainment, error) {
		return nil, errors.Join(cause, parent.Close())
	}
	if err := ensureDelegatedControllers(parentFD); err != nil {
		return closeParent(err)
	}

	name := fmt.Sprintf("winn-cycle-%d-%d", os.Getpid(), sequence)
	path := filepath.Join(parentPath, name)
	if err := cgroupMkdirat(parentFD, name, 0o700); err != nil {
		return closeParent(fmt.Errorf(
			"create per-cycle cgroup %s (systemd unit must use Delegate=yes): %w",
			path, err,
		))
	}
	removeCreated := func(cause error) (cycleContainment, error) {
		removeErr := cgroupUnlinkat(parentFD, name, unix.AT_REMOVEDIR)
		return closeParent(errors.Join(cause, removeErr))
	}
	childFD, err := unix.Openat(
		parentFD, name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return removeCreated(fmt.Errorf("open per-cycle cgroup: %w", err))
	}
	// #nosec G115 -- unix.Openat returned a nonnegative live descriptor.
	child := os.NewFile(uintptr(childFD), path)
	var childStat unix.Stat_t
	if err := unix.Fstat(childFD, &childStat); err != nil {
		_ = child.Close()
		return removeCreated(fmt.Errorf("stat per-cycle cgroup descriptor: %w", err))
	}
	var namedStat unix.Stat_t
	if err := cgroupFstatat(
		parentFD, name, &namedStat, unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		_ = child.Close()
		return removeCreated(fmt.Errorf("stat named per-cycle cgroup: %w", err))
	}
	if !sameCgroupObject(childStat, namedStat) {
		_ = child.Close()
		return removeCreated(errors.New(
			"per-cycle cgroup changed identity while acquiring descriptor custody",
		))
	}
	if err := requireCgroup2Filesystem(childFD, "per-cycle cgroup"); err != nil {
		_ = child.Close()
		return removeCreated(err)
	}
	containment := &linuxCycleCgroup{
		path:            path,
		parentDirectory: parent,
		name:            name,
		directory:       child,
		childDevice:     uint64(childStat.Dev),
		childInode:      childStat.Ino,
	}
	if err := containment.requirePeakFiles(); err != nil {
		_ = child.Close()
		return removeCreated(err)
	}
	return containment, nil
}

func delegatedParentCgroup(current string) (string, error) {
	components, err := relativeCgroupComponents(current)
	if err != nil {
		return "", fmt.Errorf("validate current cgroup path: %w", err)
	}
	if len(components) < 2 ||
		components[len(components)-1] != controllerDelegationSubgroup {
		return "", fmt.Errorf(
			"controller must run in exact delegated subgroup %q, got %q",
			controllerDelegationSubgroup, current,
		)
	}
	return "/" + strings.Join(components[:len(components)-1], "/"), nil
}

func ensureDelegatedControllers(parentFD int) error {
	processes, err := readCgroupFileAt(
		parentFD, "cgroup.procs", maximumCgroupProcsBytes,
	)
	if err != nil {
		return fmt.Errorf("read delegated parent processes: %w", err)
	}
	if len(processes) != 0 {
		return errors.New(
			"delegated cgroup parent contains processes; refusing the " +
				"cgroup-v2 no-internal-process violation",
		)
	}
	available, err := readControllerSet(parentFD, "cgroup.controllers", false)
	if err != nil {
		return fmt.Errorf("read delegated cgroup controllers: %w", err)
	}
	for _, required := range []string{"memory", "pids"} {
		if !available[required] {
			return fmt.Errorf(
				"delegated cgroup parent does not offer required %s controller",
				required,
			)
		}
	}
	enabled, err := readControllerSet(parentFD, "cgroup.subtree_control", true)
	if err != nil {
		return fmt.Errorf("read delegated subtree controllers: %w", err)
	}
	if !enabled["memory"] || !enabled["pids"] {
		if err := cgroupWriteSubtreeControl(parentFD); err != nil {
			return fmt.Errorf(
				"enable delegated memory and pids controllers: %w", err,
			)
		}
		enabled, err = readControllerSet(
			parentFD, "cgroup.subtree_control", true,
		)
		if err != nil {
			return fmt.Errorf("verify delegated subtree controllers: %w", err)
		}
	}
	if !enabled["memory"] || !enabled["pids"] {
		return errors.New(
			"delegated subtree did not enable both memory and pids controllers",
		)
	}
	return nil
}

func readControllerSet(
	directoryFD int, name string, allowEmpty bool,
) (map[string]bool, error) {
	raw, err := readCgroupFileAt(
		directoryFD, name, maximumCgroupControlBytes,
	)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		if allowEmpty {
			return map[string]bool{}, nil
		}
		return nil, errors.New("controller list is empty")
	}
	if raw[len(raw)-1] != '\n' || !utf8.Valid(raw) {
		return nil, errors.New("controller list is malformed or unterminated")
	}
	fields := strings.Fields(string(raw))
	if string(raw) != strings.Join(fields, " ")+"\n" {
		return nil, errors.New("controller list is not canonically formatted")
	}
	result := make(map[string]bool)
	for _, field := range fields {
		if strings.Trim(field, "abcdefghijklmnopqrstuvwxyz0123456789_.-") != "" {
			return nil, fmt.Errorf("invalid controller name %q", field)
		}
		if result[field] {
			return nil, fmt.Errorf("duplicate controller %q", field)
		}
		result[field] = true
	}
	if len(result) == 0 && !allowEmpty {
		return nil, errors.New("controller list is empty")
	}
	return result, nil
}

func currentCgroupV2(procRoot string) (string, error) {
	// #nosec G304 -- procRoot is fixed controller configuration and the
	// remaining components are constant; the file is read-only and bounded.
	file, err := os.Open(filepath.Join(procRoot, "self", "cgroup"))
	if err != nil {
		return "", fmt.Errorf("open current cgroup membership: %w", err)
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(io.LimitReader(file, 1<<20))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "0::/") || line == "0::/" {
			path := strings.TrimPrefix(line, "0::")
			if _, err := relativeCgroupComponents(path); err != nil {
				return "", fmt.Errorf("invalid current cgroup-v2 path: %w", err)
			}
			return path, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read current cgroup membership: %w", err)
	}
	return "", errors.New("unified cgroup-v2 membership was not found")
}

func absoluteDirectoryComponents(path string) ([]string, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("path is not absolute")
	}
	if path == "/" {
		return nil, nil
	}
	if strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return nil, errors.New("path is not canonical")
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, errors.New("path contains a forbidden component")
		}
	}
	return components, nil
}

func relativeCgroupComponents(path string) ([]string, error) {
	components, err := absoluteDirectoryComponents(path)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(path) != path {
		return nil, errors.New("cgroup path is not canonical")
	}
	return components, nil
}

func openAbsoluteDirectoryNoSymlinks(path string) (int, error) {
	components, err := absoluteDirectoryComponents(path)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Open(
		"/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		return -1, fmt.Errorf("open filesystem root: %w", err)
	}
	for _, component := range components {
		next, openErr := unix.Openat(
			fd, component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		closeErr := unix.Close(fd)
		if openErr != nil {
			return -1, errors.Join(
				fmt.Errorf("open directory component %q: %w", component, openErr),
				closeErr,
			)
		}
		if closeErr != nil {
			_ = unix.Close(next)
			return -1, fmt.Errorf(
				"close directory before component %q: %w", component, closeErr,
			)
		}
		fd = next
	}
	return fd, nil
}

func openDelegatedCgroupParent(cgroupRoot, current string) (int, error) {
	components, err := relativeCgroupComponents(current)
	if err != nil {
		return -1, fmt.Errorf("validate current cgroup path: %w", err)
	}
	fd, err := openAbsoluteDirectoryNoSymlinks(cgroupRoot)
	if err != nil {
		return -1, fmt.Errorf("open configured cgroup root: %w", err)
	}
	if err := requireCgroup2Filesystem(fd, "configured cgroup root"); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	for _, component := range components {
		next, openErr := unix.Openat(
			fd, component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		closeErr := unix.Close(fd)
		if openErr != nil {
			return -1, errors.Join(
				fmt.Errorf("open delegated component %q: %w", component, openErr),
				closeErr,
			)
		}
		if closeErr != nil {
			_ = unix.Close(next)
			return -1, fmt.Errorf(
				"close delegated component parent for %q: %w",
				component, closeErr,
			)
		}
		fd = next
		if err := requireCgroup2Filesystem(fd, "delegated cgroup component"); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
	}
	return fd, nil
}

func requireCgroup2Filesystem(fd int, label string) error {
	var facts unix.Statfs_t
	if err := cgroupFstatfs(fd, &facts); err != nil {
		return fmt.Errorf("stat filesystem for %s: %w", label, err)
	}
	if facts.Type != unix.CGROUP2_SUPER_MAGIC {
		return fmt.Errorf(
			"%s is not on cgroup-v2 filesystem (type %#x)",
			label, facts.Type,
		)
	}
	return nil
}

func (c *linuxCycleCgroup) Configure(command *exec.Cmd) error {
	if c == nil || c.directory == nil || c.finished {
		return errors.New("per-cycle cgroup descriptor is unavailable")
	}
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{}
	}
	command.SysProcAttr.UseCgroupFD = true
	// #nosec G115 -- os.File owns a live Linux kernel descriptor represented
	// by int in SysProcAttr.CgroupFD.
	command.SysProcAttr.CgroupFD = int(c.directory.Fd())
	return nil
}

func (c *linuxCycleCgroup) Sample(
	procRoot string,
) (threads, openFiles, rssBytes int64, supported bool, err error) {
	pids, err := c.pids()
	if err != nil {
		return 0, 0, 0, false, err
	}
	for _, pid := range pids {
		memberThreads, memberFiles, memberRSS := procSample(procRoot, pid)
		threads = saturatingAdd(threads, memberThreads)
		openFiles = saturatingAdd(openFiles, memberFiles)
		rssBytes = saturatingAdd(rssBytes, memberRSS)
	}
	pidsPeak, err := c.readCgroupInt("pids.peak")
	if err != nil {
		return 0, 0, 0, false, fmt.Errorf("read required pids.peak: %w", err)
	}
	memoryPeak, err := c.readCgroupInt("memory.peak")
	if err != nil {
		return 0, 0, 0, false, fmt.Errorf("read required memory.peak: %w", err)
	}
	if pidsPeak > threads {
		threads = pidsPeak
	}
	if memoryPeak > rssBytes {
		rssBytes = memoryPeak
	}
	return threads, openFiles, rssBytes, true, nil
}

func (c *linuxCycleCgroup) TerminateAll() error {
	pids, err := c.pids()
	if err != nil {
		return err
	}
	var findings []error
	for _, pid := range pids {
		fd, err := unix.PidfdOpen(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			findings = append(findings,
				fmt.Errorf("open pidfd for cgroup pid %d: %w", pid, err))
			continue
		}
		signalErr := unix.PidfdSendSignal(fd, syscall.SIGTERM, nil, 0)
		closeErr := unix.Close(fd)
		if signalErr != nil && !errors.Is(signalErr, syscall.ESRCH) {
			findings = append(findings,
				fmt.Errorf("SIGTERM cgroup pid %d by pidfd: %w", pid, signalErr))
		}
		if closeErr != nil {
			findings = append(findings,
				fmt.Errorf("close pidfd for cgroup pid %d: %w", pid, closeErr))
		}
	}
	return errors.Join(findings...)
}

func (c *linuxCycleCgroup) pids() ([]int, error) {
	if c == nil || c.directory == nil || c.finished {
		return nil, errors.New("per-cycle cgroup descriptor is unavailable")
	}
	// #nosec G115 -- os.File owns a live Linux kernel descriptor represented
	// by int in the openat-family APIs.
	raw, err := readCgroupFileAt(
		int(c.directory.Fd()), "cgroup.procs", maximumCgroupProcsBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("read per-cycle cgroup.procs: %w", err)
	}
	var result []int
	for _, field := range strings.Fields(string(raw)) {
		pid, err := strconv.Atoi(field)
		if err != nil || pid <= 1 {
			return nil, fmt.Errorf("invalid pid %q in cgroup.procs", field)
		}
		result = append(result, pid)
	}
	return result, nil
}

func (c *linuxCycleCgroup) readCgroupInt(name string) (int64, error) {
	// #nosec G115 -- os.File owns a live Linux kernel descriptor represented
	// by int in the openat-family APIs.
	raw, err := readCgroupFileAt(
		int(c.directory.Fd()), name, maximumCgroupControlBytes,
	)
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(string(raw))
	if value == "max" {
		return 0, errors.New("cgroup metric is unbounded")
	}
	number, err := strconv.ParseInt(value, 10, 64)
	if err != nil || number < 0 {
		return 0, fmt.Errorf("invalid cgroup metric %q", value)
	}
	return number, nil
}

func (c *linuxCycleCgroup) requirePeakFiles() error {
	if _, err := c.readCgroupInt("memory.peak"); err != nil {
		return fmt.Errorf("required child memory.peak is unavailable: %w", err)
	}
	if _, err := c.readCgroupInt("pids.peak"); err != nil {
		return fmt.Errorf("required child pids.peak is unavailable: %w", err)
	}
	return nil
}

func (c *linuxCycleCgroup) KillAll() error {
	if c == nil || c.directory == nil {
		return errors.New("per-cycle cgroup descriptor is unavailable")
	}
	// #nosec G115 -- os.File owns a live Linux kernel descriptor represented
	// by int in the openat-family APIs.
	file, err := openCgroupFileAt(
		int(c.directory.Fd()), "cgroup.kill", os.O_WRONLY,
	)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		return errors.New("cgroup.kill is unavailable; refusing partial cleanup")
	}
	if err != nil {
		return fmt.Errorf("open cgroup.kill: %w", err)
	}
	if err := writeAllOperation(file, []byte("1\n")); err != nil {
		_ = file.Close()
		return fmt.Errorf("write cgroup.kill: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close cgroup.kill: %w", err)
	}
	return nil
}

func (c *linuxCycleCgroup) eventBytes() ([]byte, error) {
	if c.readEvents != nil {
		return c.readEvents()
	}
	// #nosec G115 -- os.File owns a live Linux kernel descriptor represented
	// by int in the openat-family APIs.
	return readCgroupFileAt(
		int(c.directory.Fd()), "cgroup.events", maximumCgroupControlBytes,
	)
}

func parseCgroupEvents(raw []byte) (bool, error) {
	if len(raw) == 0 {
		return false, errors.New("cgroup.events is empty")
	}
	if len(raw) > maximumCgroupControlBytes {
		return false, errors.New("cgroup.events exceeds the 4 KiB bound")
	}
	if raw[len(raw)-1] != '\n' || !utf8.Valid(raw) {
		return false, errors.New("cgroup.events is malformed or unterminated")
	}
	found := 0
	populated := false
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || line != fields[0]+" "+fields[1] {
			return false, fmt.Errorf("malformed cgroup.events line %q", line)
		}
		if fields[0] != "populated" {
			continue
		}
		found++
		switch fields[1] {
		case "0":
			populated = false
		case "1":
			populated = true
		default:
			return false, fmt.Errorf("invalid populated value %q", fields[1])
		}
	}
	if found != 1 {
		return false, fmt.Errorf(
			"cgroup.events contains %d populated lines, expected exactly one",
			found,
		)
	}
	return populated, nil
}

func (c *linuxCycleCgroup) verifyNamedIdentity() error {
	if c.parentDirectory == nil || c.directory == nil {
		return errors.New("cgroup descriptor custody is unavailable")
	}
	var held unix.Stat_t
	// #nosec G115 -- os.File owns a live Linux kernel descriptor represented
	// by int in Fstat.
	if err := unix.Fstat(int(c.directory.Fd()), &held); err != nil {
		return fmt.Errorf("stat held child cgroup: %w", err)
	}
	var named unix.Stat_t
	// #nosec G115 -- os.File owns a live Linux kernel descriptor represented
	// by int in the fstatat-family APIs.
	if err := cgroupFstatat(
		int(c.parentDirectory.Fd()), c.name, &named, unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fmt.Errorf("stat named child cgroup: %w", err)
	}
	if !sameCgroupObject(held, named) ||
		uint64(held.Dev) != c.childDevice ||
		held.Ino != c.childInode {
		return errors.New("per-cycle cgroup changed identity during its lifecycle")
	}
	return nil
}

func sameCgroupObject(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev &&
		left.Ino == right.Ino &&
		left.Mode&unix.S_IFMT == unix.S_IFDIR &&
		right.Mode&unix.S_IFMT == unix.S_IFDIR
}

func (c *linuxCycleCgroup) Finish() (CycleContainmentCleanup, error) {
	if c == nil {
		return CycleContainmentCleanup{}, errors.New(
			"per-cycle cgroup containment is unavailable",
		)
	}
	if c.finished {
		return CycleContainmentCleanup{}, errors.New(
			"per-cycle cgroup cleanup was already attempted",
		)
	}
	c.finished = true
	fail := func(cause error) (CycleContainmentCleanup, error) {
		var closeErrors []error
		if c.directory != nil {
			closeErrors = append(closeErrors, c.directory.Close())
			c.directory = nil
		}
		if c.parentDirectory != nil {
			closeErrors = append(closeErrors, c.parentDirectory.Close())
			c.parentDirectory = nil
		}
		return CycleContainmentCleanup{}, errors.Join(
			cause, errors.Join(closeErrors...),
		)
	}
	if err := c.verifyNamedIdentity(); err != nil {
		return fail(err)
	}
	raw, err := c.eventBytes()
	if err != nil {
		return fail(fmt.Errorf("read cgroup.events: %w", err))
	}
	populated, err := parseCgroupEvents(raw)
	if err != nil {
		return fail(err)
	}
	if populated {
		if err := c.KillAll(); err != nil {
			return fail(err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for populated {
			if time.Now().After(deadline) {
				return fail(errors.New(
					"per-cycle cgroup did not reach populated=0 after cgroup.kill",
				))
			}
			time.Sleep(10 * time.Millisecond)
			raw, err = c.eventBytes()
			if err != nil {
				return fail(fmt.Errorf("read cgroup.events: %w", err))
			}
			populated, err = parseCgroupEvents(raw)
			if err != nil {
				return fail(err)
			}
		}
	}
	if err := c.verifyNamedIdentity(); err != nil {
		return fail(err)
	}
	evidence := CycleContainmentCleanup{
		Schema:            linuxCgroupV2CleanupSchema,
		ChildCgroupInode:  c.childInode,
		FinalCgroupEvents: string(raw),
		ChildRemoved:      true,
	}
	// #nosec G115 -- os.File owns a live Linux kernel descriptor represented
	// by int in the unlinkat-family APIs.
	parentFD := int(c.parentDirectory.Fd())
	if err := cgroupUnlinkat(parentFD, c.name, unix.AT_REMOVEDIR); err != nil {
		return fail(fmt.Errorf("remove empty per-cycle cgroup: %w", err))
	}
	var unlinked unix.Stat_t
	// #nosec G115 -- os.File owns a live Linux kernel descriptor represented
	// by int in Fstat.
	if err := unix.Fstat(int(c.directory.Fd()), &unlinked); err != nil {
		return fail(fmt.Errorf("stat held child after removal: %w", err))
	}
	if uint64(unlinked.Dev) != c.childDevice ||
		unlinked.Ino != c.childInode ||
		unlinked.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fail(errors.New(
			"held child changed identity while verifying removal",
		))
	}
	// cgroupfs is kernfs-backed: unlike a regular ext4 directory, an open
	// descriptor can continue to report the synthetic directory link count
	// of 2 after rmdir. The descriptor's unchanged device/inode/type plus the
	// parent-relative ENOENT check below are the removal proof. Accept only
	// the two kernel-observed terminal shapes; any other count is anomalous.
	if !validRemovedCgroupLinkCount(uint64(unlinked.Nlink)) {
		return fail(fmt.Errorf(
			"held child has invalid post-removal link count %d",
			unlinked.Nlink,
		))
	}
	if err := c.verifyHeldInodeAbsentFromParent(unlinked); err != nil {
		return fail(err)
	}
	var after unix.Stat_t
	err = cgroupFstatat(
		parentFD, c.name, &after, unix.AT_SYMLINK_NOFOLLOW,
	)
	if !errors.Is(err, unix.ENOENT) {
		if err == nil {
			return fail(errors.New(
				"per-cycle cgroup name reappeared after removal",
			))
		}
		return fail(fmt.Errorf("verify per-cycle cgroup removal: %w", err))
	}
	if err := c.directory.Close(); err != nil {
		c.directory = nil
		return fail(fmt.Errorf("close unlinked child cgroup descriptor: %w", err))
	}
	c.directory = nil
	if err := c.parentDirectory.Close(); err != nil {
		c.parentDirectory = nil
		return CycleContainmentCleanup{}, fmt.Errorf(
			"close delegated parent cgroup descriptor: %w", err,
		)
	}
	c.parentDirectory = nil
	return evidence, nil
}

func validRemovedCgroupLinkCount(count uint64) bool {
	return count == 0 || count == 2
}

func (c *linuxCycleCgroup) verifyHeldInodeAbsentFromParent(
	held unix.Stat_t,
) error {
	if c.parentDirectory == nil {
		return errors.New("delegated parent cgroup descriptor is unavailable")
	}
	duplicateFD, err := unix.FcntlInt(
		uintptr(c.parentDirectory.Fd()), unix.F_DUPFD_CLOEXEC, 0,
	)
	if err != nil {
		return fmt.Errorf("duplicate delegated parent for removal census: %w", err)
	}
	// #nosec G115 -- unix.FcntlInt returned a nonnegative live descriptor.
	parent := os.NewFile(uintptr(duplicateFD), c.parentDirectory.Name())
	if parent == nil {
		_ = unix.Close(duplicateFD)
		return errors.New("wrap delegated parent removal-census descriptor")
	}
	defer func() { _ = parent.Close() }()

	entries, err := parent.ReadDir(maximumCgroupParentEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read delegated parent removal census: %w", err)
	}
	if len(entries) > maximumCgroupParentEntries {
		return fmt.Errorf(
			"delegated parent removal census exceeds %d entries",
			maximumCgroupParentEntries,
		)
	}
	for _, entry := range entries {
		var candidate unix.Stat_t
		// #nosec G115 -- os.File owns a live Linux kernel descriptor
		// represented by int in the fstatat-family APIs.
		if err := cgroupFstatat(
			int(c.parentDirectory.Fd()), entry.Name(), &candidate,
			unix.AT_SYMLINK_NOFOLLOW,
		); err != nil {
			return fmt.Errorf(
				"stat delegated parent census entry %q: %w",
				entry.Name(), err,
			)
		}
		if candidate.Dev == held.Dev &&
			candidate.Ino == held.Ino &&
			candidate.Mode&unix.S_IFMT == unix.S_IFDIR {
			return fmt.Errorf(
				"held child remains linked under sibling name %q after removal",
				entry.Name(),
			)
		}
	}
	return nil
}

func openCgroupFileAt(
	directoryFD int, name string, flags int,
) (*os.File, error) {
	fd, err := unix.Openat(
		directoryFD, name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		return nil, err
	}
	// #nosec G115 -- unix.Openat returned a nonnegative live descriptor.
	return os.NewFile(uintptr(fd), name), nil
}

func readCgroupFileAt(
	directoryFD int, name string, maximum int64,
) ([]byte, error) {
	file, err := openCgroupFileAt(directoryFD, name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(raw)) > maximum {
		return nil, fmt.Errorf("%s exceeds the %d-byte bound", name, maximum)
	}
	return raw, nil
}

type noopCycleContainment struct{}

func (noopCycleContainment) Configure(*exec.Cmd) error { return nil }
func (noopCycleContainment) Sample(string) (
	int64, int64, int64, bool, error,
) {
	return 0, 0, 0, false, nil
}
func (noopCycleContainment) TerminateAll() error { return nil }
func (noopCycleContainment) KillAll() error      { return nil }
func (noopCycleContainment) Finish() (CycleContainmentCleanup, error) {
	return nonApplicableContainmentCleanup(), nil
}
