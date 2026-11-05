//go:build linux && winn_incomplete_e8

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func installLocalOnlySandbox() error {
	runtime.LockOSThread()
	androidInitialSeccompFilters := -1
	var androidStatusFile *os.File
	if runtime.GOOS == "android" {
		// Android application UIDs enter with every capability set, including
		// the bounding set, already empty. PR_CAPBSET_DROP requires
		// CAP_SETPCAP and returns EPERM even though there is nothing to drop.
		if err := verifyNoProcessCapabilities(); err != nil {
			return fmt.Errorf(
				"verify Android capability confinement: %w", err,
			)
		}
		var err error
		androidStatusFile, err = os.Open("/proc/self/status")
		if err != nil {
			return fmt.Errorf("open Android status before seccomp: %w", err)
		}
		defer androidStatusFile.Close()
		androidInitialSeccompFilters, err =
			processStatusIntegerFromFile(
				androidStatusFile, "Seccomp_filters:",
			)
		if err != nil || androidInitialSeccompFilters < 1 {
			return errors.New(
				"read initial Android seccomp filter count",
			)
		}
	} else {
		for capability := uintptr(0); capability <= 63; capability++ {
			if _, _, errno := syscall.AllThreadsSyscall6(
				unix.SYS_PRCTL, unix.PR_CAPBSET_DROP,
				capability, 0, 0, 0, 0,
			); errno != 0 && errno != unix.EINVAL {
				return fmt.Errorf(
					"drop capability bounding bit %d: %w",
					capability, errno,
				)
			}
		}
		if _, _, errno := syscall.AllThreadsSyscall6(
			unix.SYS_PRCTL, unix.PR_CAP_AMBIENT,
			unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0,
		); errno != 0 && errno != unix.EINVAL {
			return fmt.Errorf("clear ambient capabilities: %w", errno)
		}
		header := unix.CapUserHeader{
			Version: unix.LINUX_CAPABILITY_VERSION_3,
			Pid:     0,
		}
		capabilities := [2]unix.CapUserData{}
		if _, _, errno := syscall.AllThreadsSyscall(
			unix.SYS_CAPSET,
			// #nosec G103 -- capset requires pointers to fixed Linux UAPI
			// structures retained for this synchronous syscall.
			uintptr(unsafe.Pointer(&header)),
			// #nosec G103 -- see the capset UAPI lifetime proof above.
			uintptr(unsafe.Pointer(&capabilities[0])),
			0,
		); errno != 0 {
			return fmt.Errorf("clear effective capabilities: %w", errno)
		}
	}
	if _, _, errno := syscall.AllThreadsSyscall6(
		unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0,
	); errno != 0 {
		return fmt.Errorf("set no-new-privileges: %w", errno)
	}
	if runtime.GOOS == "android" {
		if err := verifyNoProcessCapabilities(); err != nil {
			return fmt.Errorf(
				"reverify Android capability confinement: %w", err,
			)
		}
		if value, err := processStatusIntegerFromFile(
			androidStatusFile, "NoNewPrivs:",
		); err != nil || value != 1 {
			return errors.New("Android no-new-privileges was not applied")
		}
	}
	expectedArch := uint32(0)
	switch runtime.GOARCH {
	case "arm64":
		expectedArch = unix.AUDIT_ARCH_AARCH64
	case "amd64":
		expectedArch = unix.AUDIT_ARCH_X86_64
	default:
		return errors.New("unsupported E8 seccomp architecture")
	}
	filters := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: expectedArch},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
	}
	// This is deliberately an allowlist. The worker has already parsed and
	// retained all capabilities it needs; every pathname, network, credential,
	// process-creation, pidfd, namespace, mount and mutation syscall therefore
	// falls through to EPERM, including future syscalls unknown to this binary.
	allowed := []uint32{
		unix.SYS_READ, unix.SYS_WRITE, unix.SYS_CLOSE, unix.SYS_FSTAT,
		unix.SYS_LSEEK, unix.SYS_MMAP, unix.SYS_MPROTECT, unix.SYS_MUNMAP,
		unix.SYS_BRK, unix.SYS_RT_SIGACTION, unix.SYS_RT_SIGPROCMASK,
		unix.SYS_RT_SIGRETURN, unix.SYS_IOCTL, unix.SYS_PREAD64,
		unix.SYS_WRITEV, unix.SYS_SCHED_YIELD, unix.SYS_MREMAP,
		unix.SYS_MADVISE, unix.SYS_NANOSLEEP, unix.SYS_GETPID,
		unix.SYS_GETPPID,
		unix.SYS_EXIT, unix.SYS_EXIT_GROUP, unix.SYS_FCNTL,
		unix.SYS_SIGALTSTACK, unix.SYS_GETTID, unix.SYS_FUTEX,
		unix.SYS_SCHED_GETAFFINITY, unix.SYS_CLOCK_GETTIME,
		unix.SYS_EPOLL_PWAIT, unix.SYS_EPOLL_CTL,
		unix.SYS_TGKILL, unix.SYS_EVENTFD2, unix.SYS_EPOLL_CREATE1,
		unix.SYS_PRLIMIT64, unix.SYS_GETRANDOM, unix.SYS_RSEQ,
		unix.SYS_RESTART_SYSCALL, unix.SYS_RECVMSG,
	}
	for _, syscallNumber := range allowed {
		filters = append(filters,
			unix.SockFilter{
				Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
				Jt:   0,
				Jf:   1,
				K:    syscallNumber,
			},
			unix.SockFilter{
				Code: unix.BPF_RET | unix.BPF_K,
				K:    unix.SECCOMP_RET_ALLOW,
			},
		)
	}
	filters = append(filters, unix.SockFilter{
		Code: unix.BPF_RET | unix.BPF_K,
		K:    unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM),
	})
	program := unix.SockFprog{
		// #nosec G115 -- this local allowlist is far below uint16 capacity.
		Len:    uint16(len(filters)),
		Filter: &filters[0],
	}
	_, _, errno := unix.Syscall6(
		unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC,
		// #nosec G103 -- seccomp requires a pointer to the fixed Linux UAPI
		// sock_fprog retained for this synchronous syscall.
		uintptr(unsafe.Pointer(&program)),
		0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("install seccomp allowlist: %w", errno)
	}
	if runtime.GOOS == "android" {
		filters, err := processStatusIntegerFromFile(
			androidStatusFile, "Seccomp_filters:",
		)
		if err != nil {
			return fmt.Errorf(
				"read Android seccomp filter count after install: %w",
				err,
			)
		}
		if filters != androidInitialSeccompFilters+1 {
			return fmt.Errorf(
				"Android seccomp filter count did not increment exactly: "+
					"before=%d after=%d",
				androidInitialSeccompFilters, filters,
			)
		}
		if value, err := processStatusIntegerFromFile(
			androidStatusFile, "NoNewPrivs:",
		); err != nil || value != 1 {
			return errors.New(
				"Android no-new-privileges changed after seccomp",
			)
		}
	}
	if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0); err != unix.EPERM {
		if err == nil {
			_ = unix.Close(fd)
		}
		return errors.New("E8 seccomp network denial self-test failed")
	}
	if fd, err := unix.Openat(
		unix.AT_FDCWD, "/etc/passwd", unix.O_RDONLY|unix.O_CLOEXEC, 0,
	); err != unix.EPERM {
		if err == nil {
			_ = unix.Close(fd)
		}
		return errors.New("E8 seccomp filesystem denial self-test failed")
	}
	if _, _, errno := unix.Syscall6(
		unix.SYS_UTIMENSAT, ^uintptr(99), 0, 0, 0, 0, 0,
	); errno != unix.EPERM {
		return errors.New("E8 seccomp mutation denial self-test failed")
	}
	return nil
}

func processStatusIntegerFromFile(file *os.File, name string) (int, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return 0, err
	}
	return parseProcessStatusInteger(data, name)
}

func verifyNoProcessCapabilities() error {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	required := map[string]bool{
		"CapInh:": false,
		"CapPrm:": false,
		"CapEff:": false,
		"CapBnd:": false,
		"CapAmb:": false,
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if _, ok := required[fields[0]]; !ok {
			continue
		}
		if fields[1] == "" || strings.Trim(fields[1], "0") != "" {
			return fmt.Errorf("%s is not zero", fields[0])
		}
		required[fields[0]] = true
	}
	for name, found := range required {
		if !found {
			return fmt.Errorf("%s is missing", name)
		}
	}
	return nil
}

func processStatusInteger(name string) (int, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	return parseProcessStatusInteger(data, name)
}

func parseProcessStatusInteger(data []byte, name string) (int, error) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == name {
			value, parseErr := strconv.Atoi(fields[1])
			if parseErr != nil || value < 0 {
				return 0, errors.New("process status integer is invalid")
			}
			return value, nil
		}
	}
	return 0, fmt.Errorf("%s is missing", name)
}
