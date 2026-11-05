//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const maxAdapterBytes = 128 << 20

type productionRuntime struct {
	parentFD int
	adapter  *os.File
	timeout  time.Duration
}

func newProductionRuntime(
	stateDirectory, adapterPath, adapterSHA256 string,
	timeout time.Duration,
) (durableRuntime, error) {
	parentFD, err := unix.Open(
		stateDirectory,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open state directory: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(parentFD, &stat); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Mode&0o7777 != 0o700 ||
		// #nosec G115 -- POSIX effective user identifiers are nonnegative
		// uid_t values and Stat_t.Uid is the platform's native uid_t.
		stat.Uid != uint32(os.Geteuid()) {
		_ = unix.Close(parentFD)
		return nil, errors.New(
			"state directory must be retained, owned, and mode 0700",
		)
	}
	if err := requireEmptyDirectory(parentFD); err != nil {
		_ = unix.Close(parentFD)
		return nil, err
	}
	adapter, err := sealExactAdapter(adapterPath, adapterSHA256)
	if err != nil {
		_ = unix.Close(parentFD)
		return nil, err
	}
	return &productionRuntime{
		parentFD: parentFD,
		adapter:  adapter,
		timeout:  timeout,
	}, nil
}

func (runtime *productionRuntime) Close() error {
	var adapterErr error
	if runtime.adapter != nil {
		adapterErr = runtime.adapter.Close()
		runtime.adapter = nil
	}
	if runtime.parentFD < 0 {
		return adapterErr
	}
	err := unix.Close(runtime.parentFD)
	runtime.parentFD = -1
	return errors.Join(adapterErr, err)
}

func (runtime *productionRuntime) PublishExclusive(
	name string,
	data []byte,
) (*os.File, error) {
	if name != bindingFileName && name != intentFileName &&
		name != resultFileName {
		return nil, errors.New("publication name is not allowlisted")
	}
	if len(data) == 0 || len(data) > maxResultBytes {
		return nil, errors.New("publication bytes are empty or oversized")
	}
	tempName := "." + name + ".pending"
	tempFD, err := unix.Openat(
		runtime.parentFD,
		tempName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|
			unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o400,
	)
	if err != nil {
		return nil, fmt.Errorf("create exclusive publication temp: %w", err)
	}
	tempOpen := true
	defer func() {
		if tempOpen {
			_ = unix.Close(tempFD)
		}
	}()
	for remaining := data; len(remaining) > 0; {
		written, writeErr := unix.Write(tempFD, remaining)
		if writeErr != nil {
			return nil, fmt.Errorf("write publication temp: %w", writeErr)
		}
		if written <= 0 {
			return nil, errors.New("publication write made no progress")
		}
		remaining = remaining[written:]
	}
	if err := unix.Fsync(tempFD); err != nil {
		return nil, fmt.Errorf("fsync publication temp: %w", err)
	}
	if err := unix.Close(tempFD); err != nil {
		return nil, fmt.Errorf("close publication temp: %w", err)
	}
	tempOpen = false
	if err := unix.Renameat2(
		runtime.parentFD, tempName,
		runtime.parentFD, name,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return nil, fmt.Errorf("rename publication without replacement: %w", err)
	}
	if err := unix.Fsync(runtime.parentFD); err != nil {
		return nil, fmt.Errorf("fsync publication parent: %w", err)
	}
	finalFD, err := unix.Openat(
		runtime.parentFD,
		name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("reopen publication: %w", err)
	}
	// #nosec G115 -- unix.Openat returned a nonnegative live descriptor.
	final := os.NewFile(uintptr(finalFD), name)
	if final == nil {
		_ = unix.Close(finalFD)
		return nil, errors.New("wrap publication descriptor")
	}
	info, err := final.Stat()
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o400 ||
		info.Size() != int64(len(data)) ||
		descriptorNlink(info) != 1 ||
		// #nosec G115 -- POSIX effective user identifiers are nonnegative.
		descriptorUID(info) != uint64(os.Geteuid()) {
		_ = final.Close()
		return nil, errors.New("reopened publication identity is unsafe")
	}
	replayed := make([]byte, len(data))
	if _, err := ioReadFull(final, replayed); err != nil ||
		!bytes.Equal(replayed, data) {
		_ = final.Close()
		return nil, errors.New("reopened publication bytes differ")
	}
	if _, err := final.Seek(0, 0); err != nil {
		_ = final.Close()
		return nil, errors.New("rewind publication descriptor")
	}
	return final, nil
}

func (runtime *productionRuntime) SpawnPreflight(
	binding, intent *os.File,
	environment []string,
) ([]byte, error) {
	if runtime.adapter == nil {
		return nil, errors.New("sealed adapter descriptor is unavailable")
	}
	contextWithDeadline, cancel := context.WithTimeout(
		context.Background(), runtime.timeout,
	)
	defer cancel()
	command := exec.CommandContext(contextWithDeadline, "/proc/self/fd/3")
	command.Args[0] = "winn-real-cycle-admitted-adapter"
	command.Env = environment
	command.ExtraFiles = []*os.File{runtime.adapter, binding, intent}
	var stdout, stderr boundedCapture
	stdout.maximum = maxResultBytes
	stderr.maximum = maxResultBytes
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf(
			"adapter exited unsuccessfully: %w stderr=%q",
			err, stderr.Bytes(),
		)
	}
	if contextWithDeadline.Err() != nil {
		return nil, errors.New("adapter exceeded deadline")
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("adapter output exceeded bound")
	}
	return stdout.Bytes(), nil
}

func requireEmptyDirectory(parentFD int) error {
	duplicate, err := unix.Dup(parentFD)
	if err != nil {
		return fmt.Errorf("duplicate state directory census descriptor: %w", err)
	}
	// #nosec G115 -- unix.Dup returned a nonnegative live descriptor.
	directory := os.NewFile(uintptr(duplicate), "e3-state-census")
	if directory == nil {
		_ = unix.Close(duplicate)
		return errors.New("wrap state directory census descriptor")
	}
	names, readErr := directory.Readdirnames(1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(
			fmt.Errorf("read state directory census: %w", readErr),
			closeErr,
		)
	}
	if closeErr != nil {
		return closeErr
	}
	if len(names) != 0 {
		return errors.New(
			"state directory is nonempty; automatic resume and orphan reuse are forbidden",
		)
	}
	return nil
}

func sealExactAdapter(
	sourcePath, expectedSHA256 string,
) (*os.File, error) {
	sourceFD, err := unix.Open(
		sourcePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		return nil, fmt.Errorf("open adapter source: %w", err)
	}
	// #nosec G115 -- unix.Open returned a nonnegative live descriptor.
	source := os.NewFile(uintptr(sourceFD), "adapter-source")
	if source == nil {
		_ = unix.Close(sourceFD)
		return nil, errors.New("wrap adapter source descriptor")
	}
	sourceInfo, err := source.Stat()
	if err != nil || !sourceInfo.Mode().IsRegular() ||
		sourceInfo.Mode().Perm() != 0o500 ||
		sourceInfo.Size() <= 0 || sourceInfo.Size() > maxAdapterBytes ||
		descriptorNlink(sourceInfo) != 1 ||
		// #nosec G115 -- POSIX effective user identifiers are nonnegative.
		descriptorUID(sourceInfo) != uint64(os.Geteuid()) {
		_ = source.Close()
		return nil, errors.New("adapter source identity is unsafe")
	}
	sealedFD, err := unix.MemfdCreate(
		"winn-e3-admitted-adapter",
		unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC|unix.MFD_EXEC,
	)
	if err != nil {
		_ = source.Close()
		return nil, fmt.Errorf("create sealed adapter memfd: %w", err)
	}
	// #nosec G115 -- unix.MemfdCreate returned a nonnegative live descriptor.
	sealed := os.NewFile(uintptr(sealedFD), "sealed-adapter-memfd")
	if sealed == nil {
		_ = unix.Close(sealedFD)
		_ = source.Close()
		return nil, errors.New("wrap sealed adapter memfd")
	}
	hash := sha256.New()
	copied, copyErr := ioCopy(
		ioMultiWriter(sealed, hash),
		ioLimitReader(source, maxAdapterBytes+1),
	)
	afterSource, statErr := source.Stat()
	sourceCloseErr := source.Close()
	if copyErr != nil || statErr != nil || sourceCloseErr != nil ||
		copied != sourceInfo.Size() ||
		!os.SameFile(sourceInfo, afterSource) ||
		sourceInfo.Mode() != afterSource.Mode() ||
		sourceInfo.Size() != afterSource.Size() ||
		!sourceInfo.ModTime().Equal(afterSource.ModTime()) ||
		fmt.Sprintf("%x", hash.Sum(nil)) != expectedSHA256 {
		_ = sealed.Close()
		return nil, errors.New("adapter source copy or digest is unstable")
	}
	if err := sealed.Sync(); err != nil {
		_ = sealed.Close()
		return nil, fmt.Errorf("fsync adapter memfd bytes: %w", err)
	}
	if err := sealed.Chmod(0o500); err != nil {
		_ = sealed.Close()
		return nil, fmt.Errorf("seal adapter mode: %w", err)
	}
	const requiredSeals = unix.F_SEAL_WRITE |
		unix.F_SEAL_SHRINK |
		unix.F_SEAL_GROW |
		unix.F_SEAL_EXEC |
		unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(
		sealed.Fd(), unix.F_ADD_SEALS, requiredSeals,
	); err != nil {
		_ = sealed.Close()
		return nil, fmt.Errorf("apply adapter memfd seals: %w", err)
	}
	actualSeals, err := unix.FcntlInt(
		sealed.Fd(), unix.F_GET_SEALS, 0,
	)
	if err != nil || actualSeals&requiredSeals != requiredSeals {
		_ = sealed.Close()
		return nil, errors.New("adapter memfd seal replay mismatch")
	}
	if _, err := sealed.Seek(0, 0); err != nil {
		_ = sealed.Close()
		return nil, errors.New("rewind sealed adapter before replay")
	}
	if err := verifySealedAdapter(
		sealed, sourceInfo.Size(), expectedSHA256,
	); err != nil {
		_ = sealed.Close()
		return nil, err
	}
	return sealed, nil
}

func verifySealedAdapter(
	file *os.File,
	expectedSize int64,
	expectedSHA256 string,
) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o500 ||
		info.Size() != expectedSize ||
		descriptorNlink(info) != 0 ||
		// #nosec G115 -- POSIX effective user identifiers are nonnegative.
		descriptorUID(info) != uint64(os.Geteuid()) {
		return errors.New("sealed adapter identity is unsafe")
	}
	const requiredSeals = unix.F_SEAL_WRITE |
		unix.F_SEAL_SHRINK |
		unix.F_SEAL_GROW |
		unix.F_SEAL_EXEC |
		unix.F_SEAL_SEAL
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&requiredSeals != requiredSeals {
		return errors.New("sealed adapter seals are incomplete")
	}
	hash := sha256.New()
	copied, err := ioCopy(hash, file)
	after, statErr := file.Stat()
	if err != nil || statErr != nil || copied != info.Size() ||
		!os.SameFile(info, after) ||
		info.Mode() != after.Mode() || info.Size() != after.Size() ||
		!info.ModTime().Equal(after.ModTime()) ||
		fmt.Sprintf("%x", hash.Sum(nil)) != expectedSHA256 {
		return errors.New("sealed adapter replay mismatch")
	}
	if _, err := file.Seek(0, 0); err != nil {
		return errors.New("rewind sealed adapter descriptor")
	}
	return nil
}

type boundedCapture struct {
	mutex    sync.Mutex
	buffer   bytes.Buffer
	maximum  int
	overflow bool
}

func (capture *boundedCapture) Write(data []byte) (int, error) {
	capture.mutex.Lock()
	defer capture.mutex.Unlock()
	remaining := capture.maximum - capture.buffer.Len()
	if remaining > 0 {
		chunk := data
		if len(chunk) > remaining {
			chunk = chunk[:remaining]
		}
		_, _ = capture.buffer.Write(chunk)
	}
	if len(data) > remaining {
		capture.overflow = true
	}
	return len(data), nil
}

func (capture *boundedCapture) Bytes() []byte {
	capture.mutex.Lock()
	defer capture.mutex.Unlock()
	return bytes.Clone(capture.buffer.Bytes())
}
