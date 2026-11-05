//go:build linux && winn_incomplete_e8

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"winsvpn.local/winnprotocol/internal/realcycle"
)

const (
	workerFD               = uintptr(3)
	contractFD             = uintptr(4)
	channelFD              = uintptr(5)
	maxLocalRehearsalBytes = 64 << 10
	preparedIdentitySchema = "winn-e8-retained-worker-identity/v1"
)

type preparedIdentity struct {
	Schema                    string `json:"schema"`
	ProcessID                 uint64 `json:"process_id"`
	ProcessStartTicks         uint64 `json:"process_start_ticks"`
	WorkerSHA256              string `json:"worker_sha256"`
	WorkerBuildID             string `json:"worker_build_id,omitempty"`
	AndroidPackageName        string `json:"android_package_name,omitempty"`
	AndroidPackageVersionCode uint64 `json:"android_package_version_code,omitempty"`
	AndroidSigningCertSHA256  string `json:"android_signing_cert_sha256,omitempty"`
}

// These values are empty for the sealed-memfd Linux build. The Android APK
// packaging task must set all four with -ldflags -X. Because they are embedded
// in the executable, the E2/E5 ExecutableSHA256 commits to the exact build
// identity that is emitted from the already-running retained worker.
var (
	androidPackageName       string
	androidPackageVersion    string
	androidSigningCertSHA256 string
	androidWorkerBuildID     string
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run() error {
	unix.CloseOnExec(int(channelFD))
	channelFlags, err := unix.FcntlInt(channelFD, unix.F_GETFD, 0)
	if err != nil || channelFlags&unix.FD_CLOEXEC == 0 {
		return errors.New("capability channel CLOEXEC was not applied")
	}
	worker := os.NewFile(workerFD, "sealed-local-node-worker")
	contractFile := os.NewFile(contractFD, "sealed-local-node-contract")
	channel := os.NewFile(channelFD, "local-node-capability-channel")
	if worker == nil || contractFile == nil || channel == nil {
		return errors.New("inherited descriptors 3, 4, and 5 are required")
	}
	defer worker.Close()
	defer contractFile.Close()
	defer channel.Close()
	startTicks, err := currentProcessStartTicks()
	if err != nil {
		return err
	}
	if err := verifyInitialDescriptors(); err != nil {
		return err
	}
	if err := unix.SetsockoptInt(
		int(channelFD), unix.SOL_SOCKET, unix.SO_PASSCRED, 1,
	); err != nil {
		return err
	}
	workerDigest, err := executingWorkerDigest(worker)
	if err != nil {
		return err
	}
	androidIdentity, err := preparedAndroidBuildIdentity()
	if err != nil {
		return err
	}
	if err := installLocalOnlySandbox(); err != nil {
		return fmt.Errorf("install E8 local-only sandbox: %w", err)
	}
	preparedBytes, err := json.Marshal(preparedIdentity{
		Schema: preparedIdentitySchema,
		// #nosec G115 -- Linux Getpid returns a positive pid_t.
		ProcessID: uint64(os.Getpid()), ProcessStartTicks: startTicks,
		WorkerSHA256:              workerDigest,
		WorkerBuildID:             androidIdentity.WorkerBuildID,
		AndroidPackageName:        androidIdentity.AndroidPackageName,
		AndroidPackageVersionCode: androidIdentity.AndroidPackageVersionCode,
		AndroidSigningCertSHA256:  androidIdentity.AndroidSigningCertSHA256,
	})
	if err != nil {
		return err
	}
	if _, err := channel.Write(preparedBytes); err != nil {
		return fmt.Errorf("send prepared worker identity: %w", err)
	}
	expectSealedContractCapability := runtime.GOOS == "android"
	if expectSealedContractCapability {
		// Descriptor 4 is an inherited read-only placeholder until the
		// authenticated supervisor has finalized and sealed the real memfd.
		if err := unix.Close(int(contractFD)); err != nil {
			return fmt.Errorf("close Android contract placeholder: %w", err)
		}
	}
	signal, supervisorPeer, receivedContractFD, err :=
		receiveCredentialedPacketWithDescriptor(
			int(channelFD), expectSealedContractCapability,
		)
	// #nosec G115 -- Getppid and SCM_CREDENTIALS share Linux pid_t.
	if err != nil || supervisorPeer.Pid != int32(os.Getppid()) ||
		string(signal) != "contract-ready" {
		if receivedContractFD >= 0 {
			_ = unix.Close(receivedContractFD)
		}
		return errors.New("read contract-ready from authenticated supervisor")
	}
	if expectSealedContractCapability {
		if receivedContractFD != int(contractFD) {
			_ = unix.Close(receivedContractFD)
			return errors.New(
				"sealed Android contract did not occupy descriptor 4",
			)
		}
		if _, err := unix.FcntlInt(
			contractFD, unix.F_SETFD, unix.FD_CLOEXEC,
		); err != nil {
			return fmt.Errorf("secure Android contract descriptor: %w", err)
		}
	} else if receivedContractFD >= 0 {
		_ = unix.Close(receivedContractFD)
		return errors.New("Linux contract-ready carried an unexpected descriptor")
	}
	const requiredSeals = unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK |
		unix.F_SEAL_GROW | unix.F_SEAL_SEAL
	seals, err := unix.FcntlInt(contractFD, unix.F_GET_SEALS, 0)
	contractInfo, statErr := contractFile.Stat()
	contractAccess, accessErr := unix.FcntlInt(
		contractFD, unix.F_GETFL, 0,
	)
	expectedContractAccess := unix.O_RDONLY
	modeIsExact := contractInfo != nil &&
		contractInfo.Mode().Perm() == 0o400
	if runtime.GOOS == "android" {
		expectedContractAccess = unix.O_RDWR
		// Android SELinux rejects fchmod on anonymous memfds. The descriptor is
		// delivered only after all immutable seals are installed, so its mode
		// metadata is not relied on for write prevention.
		modeIsExact = contractInfo != nil
	}
	if err != nil || statErr != nil || seals != requiredSeals ||
		accessErr != nil ||
		contractAccess&unix.O_ACCMODE != expectedContractAccess ||
		!modeIsExact ||
		contractInfo.Size() <= 0 ||
		contractInfo.Size() > maxLocalRehearsalBytes {
		return errors.New("deferred contract was not sealed exactly")
	}
	contractBytes, err := readExactContractAt(
		contractFile, contractInfo.Size(), maxLocalRehearsalBytes,
	)
	if err != nil {
		return fmt.Errorf(
			"contract descriptor is unreadable or oversized: %w", err,
		)
	}
	contract, err := parseLocalRehearsalContract(contractBytes)
	if err != nil {
		return err
	}
	if contract.WorkerSHA256 != workerDigest {
		return errors.New("executing worker digest differs from sealed contract")
	}
	ready, readyBytes, err := encodeLocalRehearsalFrame(
		realcycle.LocalRehearsalNodeFrame{
			State: "ready", ContractDigest: contract.ObjectDigest,
			Role: contract.Role, NodeID: contract.NodeID,
			// #nosec G115 -- Linux Getpid returns a positive pid_t.
			ProcessID: uint64(os.Getpid()), ProcessStart: startTicks,
		},
	)
	if err != nil {
		return err
	}
	if _, err := channel.Write(readyBytes); err != nil {
		return fmt.Errorf("send ready frame: %w", err)
	}
	input, peer, err := receiveCredentialedPacket(int(channelFD))
	if err != nil || peer.Pid != supervisorPeer.Pid {
		return errors.New("read start frame from authenticated supervisor")
	}
	start, err := parseLocalRehearsalFrame(input)
	if err != nil {
		return err
	}
	if start.State != "start" ||
		start.ContractDigest != contract.ObjectDigest ||
		start.Role != contract.Role || start.NodeID != contract.NodeID ||
		start.ProcessID != ready.ProcessID ||
		start.ProcessStart != ready.ProcessStart {
		return errors.New("start frame does not bind contract")
	}
	operationInput, operationOutput, operationDigest, err :=
		realcycle.LocalRehearsalOperationEvidence(
			// #nosec G115 -- Linux Getpid returns a positive pid_t.
			contract, start.StartToken, uint64(os.Getpid()), startTicks,
		)
	if err != nil {
		return err
	}
	if err := worker.Close(); err != nil {
		return fmt.Errorf("close worker descriptor: %w", err)
	}
	if err := contractFile.Close(); err != nil {
		return fmt.Errorf("close contract descriptor: %w", err)
	}
	if !descriptorClosed(int(workerFD)) || !descriptorClosed(int(contractFD)) {
		return errors.New("worker or contract descriptor remained open")
	}
	_, terminalBytes, err := encodeLocalRehearsalFrame(
		realcycle.LocalRehearsalNodeFrame{
			State: "terminal-success", ContractDigest: contract.ObjectDigest,
			Role: contract.Role, NodeID: contract.NodeID,
			ProcessID: ready.ProcessID, ProcessStart: ready.ProcessStart,
			StartToken:     start.StartToken,
			OperationKind:  "sealed-local-service-self-check",
			OperationInput: operationInput, OperationOutput: operationOutput,
			OperationDigest: operationDigest,
		},
	)
	if err != nil {
		return err
	}
	if _, err := channel.Write(terminalBytes); err != nil {
		return fmt.Errorf("send terminal frame: %w", err)
	}
	if err := channel.Close(); err != nil {
		return fmt.Errorf("close capability channel: %w", err)
	}
	return nil
}

func readExactContractAt(
	file *os.File,
	size int64,
	maxBytes int64,
) ([]byte, error) {
	if file == nil || size <= 0 || size > maxBytes {
		return nil, errors.New("contract descriptor size is invalid")
	}
	data := make([]byte, int(size))
	count, err := file.ReadAt(data, 0)
	if err != nil || count != len(data) {
		return nil, errors.New("contract descriptor is short")
	}
	var extra [1]byte
	count, err = file.ReadAt(extra[:], size)
	if count != 0 || !errors.Is(err, io.EOF) {
		return nil, errors.New("contract descriptor exceeds declared size")
	}
	return data, nil
}

func preparedAndroidBuildIdentity() (preparedIdentity, error) {
	if runtime.GOOS != "android" {
		if androidPackageName != "" || androidPackageVersion != "" ||
			androidSigningCertSHA256 != "" || androidWorkerBuildID != "" {
			return preparedIdentity{}, errors.New(
				"non-Android worker contains Android package identity",
			)
		}
		return preparedIdentity{}, nil
	}
	versionCode, err := strconv.ParseUint(androidPackageVersion, 10, 64)
	if err != nil || versionCode == 0 ||
		!validAndroidPackageName(androidPackageName) ||
		!validLowerHexDigest(androidSigningCertSHA256) ||
		!validLowerHexDigest(androidWorkerBuildID) {
		return preparedIdentity{}, errors.New(
			"android worker build identity is missing or malformed",
		)
	}
	return preparedIdentity{
		WorkerBuildID:             androidWorkerBuildID,
		AndroidPackageName:        androidPackageName,
		AndroidPackageVersionCode: versionCode,
		AndroidSigningCertSHA256:  androidSigningCertSHA256,
	}, nil
}

func validLowerHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validAndroidPackageName(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" ||
			(part[0] < 'A' || part[0] > 'Z') &&
				(part[0] < 'a' || part[0] > 'z') {
			return false
		}
		for _, character := range part[1:] {
			if (character < 'A' || character > 'Z') &&
				(character < 'a' || character > 'z') &&
				(character < '0' || character > '9') &&
				character != '_' {
				return false
			}
		}
	}
	return true
}

func receiveCredentialedPacket(fd int) ([]byte, *unix.Ucred, error) {
	data, credential, receivedFD, err :=
		receiveCredentialedPacketWithDescriptor(fd, false)
	if receivedFD >= 0 {
		_ = unix.Close(receivedFD)
	}
	return data, credential, err
}

func receiveCredentialedPacketWithDescriptor(
	fd int,
	requireDescriptor bool,
) ([]byte, *unix.Ucred, int, error) {
	data := make([]byte, maxLocalRehearsalBytes+1)
	control := make(
		[]byte,
		unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(4),
	)
	count, controlCount, receiveFlags, _, err := unix.Recvmsg(
		fd, data, control, unix.MSG_CMSG_CLOEXEC,
	)
	if err != nil || count == 0 || count > maxLocalRehearsalBytes ||
		receiveFlags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
		return nil, nil, -1,
			errors.New("credentialed packet is unreadable")
	}
	messages, err := unix.ParseSocketControlMessage(control[:controlCount])
	if err != nil {
		return nil, nil, -1,
			errors.New("credentialed packet control data is invalid")
	}
	var credential *unix.Ucred
	receivedFD := -1
	for index := range messages {
		message := &messages[index]
		switch {
		case message.Header.Level == unix.SOL_SOCKET &&
			message.Header.Type == unix.SCM_CREDENTIALS:
			if credential != nil {
				return nil, nil, receivedFD,
					errors.New("credentialed packet repeats credentials")
			}
			credential, err = unix.ParseUnixCredentials(message)
		case message.Header.Level == unix.SOL_SOCKET &&
			message.Header.Type == unix.SCM_RIGHTS:
			rights, rightsErr := unix.ParseUnixRights(message)
			if rightsErr != nil || len(rights) != 1 || receivedFD >= 0 {
				for _, right := range rights {
					_ = unix.Close(right)
				}
				return nil, nil, receivedFD,
					errors.New("credentialed packet rights are invalid")
			}
			receivedFD = rights[0]
		default:
			err = errors.New("credentialed packet control type is invalid")
		}
		if err != nil {
			if receivedFD >= 0 {
				_ = unix.Close(receivedFD)
			}
			return nil, nil, -1, err
		}
	}
	if credential == nil ||
		(requireDescriptor && receivedFD < 0) ||
		(!requireDescriptor && receivedFD >= 0) {
		if receivedFD >= 0 {
			_ = unix.Close(receivedFD)
		}
		return nil, nil, -1,
			errors.New("credentialed packet control data is invalid")
	}
	return data[:count], credential, receivedFD, nil
}

func decodeStrictLocal(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("local rehearsal object has trailing data")
	}
	return nil
}

func parseLocalRehearsalContract(
	data []byte,
) (realcycle.LocalRehearsalNodeContract, error) {
	if len(data) == 0 || len(data) > maxLocalRehearsalBytes {
		return realcycle.LocalRehearsalNodeContract{},
			errors.New("local rehearsal contract exceeds bound")
	}
	var value realcycle.LocalRehearsalNodeContract
	if err := decodeStrictLocal(data, &value); err != nil {
		return realcycle.LocalRehearsalNodeContract{}, err
	}
	if err := realcycle.ValidateLocalRehearsalContract(value); err != nil {
		return realcycle.LocalRehearsalNodeContract{}, err
	}
	return value, nil
}

func parseLocalRehearsalFrame(
	data []byte,
) (realcycle.LocalRehearsalNodeFrame, error) {
	if len(data) == 0 || len(data) > maxLocalRehearsalBytes {
		return realcycle.LocalRehearsalNodeFrame{},
			errors.New("local rehearsal frame exceeds bound")
	}
	var value realcycle.LocalRehearsalNodeFrame
	if err := decodeStrictLocal(data, &value); err != nil {
		return realcycle.LocalRehearsalNodeFrame{}, err
	}
	if err := realcycle.ValidateLocalRehearsalFrame(value); err != nil {
		return realcycle.LocalRehearsalNodeFrame{}, err
	}
	return value, nil
}

func encodeLocalRehearsalFrame(
	value realcycle.LocalRehearsalNodeFrame,
) (realcycle.LocalRehearsalNodeFrame, []byte, error) {
	if err := realcycle.ValidateLocalRehearsalFrame(value); err != nil {
		return realcycle.LocalRehearsalNodeFrame{}, nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 ||
		len(encoded) > maxLocalRehearsalBytes {
		return realcycle.LocalRehearsalNodeFrame{}, nil,
			errors.New("local rehearsal frame encoding exceeds bound")
	}
	return value, encoded, nil
}

func descriptorClosed(fd int) bool {
	// #nosec G115 -- callers pass only fixed nonnegative descriptor numbers.
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return err == unix.EBADF
}

func verifyInitialDescriptors() error {
	type descriptorExpectation struct {
		kind   uint32
		access int
	}
	workerAccess := unix.O_RDWR
	if runtime.GOOS == "android" {
		workerAccess = unix.O_RDONLY
	}
	expected := map[int]descriptorExpectation{
		0: {unix.S_IFCHR, unix.O_RDONLY},
		1: {unix.S_IFCHR, unix.O_WRONLY},
		2: {unix.S_IFIFO, unix.O_WRONLY},
		3: {unix.S_IFREG, workerAccess},
		4: {unix.S_IFREG, unix.O_RDONLY},
		5: {unix.S_IFSOCK, unix.O_RDWR},
	}
	for fd, want := range expected {
		var stat unix.Stat_t
		// #nosec G115 -- the map contains fixed nonnegative descriptors.
		flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err := unix.Fstat(fd, &stat); err != nil ||
			flagErr != nil || stat.Mode&unix.S_IFMT != want.kind ||
			flags&unix.O_ACCMODE != want.access {
			return fmt.Errorf("descriptor %d has unexpected type", fd)
		}
	}
	var cgroupInfo unix.Stat_t
	cgroupStatErr := unix.Stat("/sys/fs/cgroup/cpu.max", &cgroupInfo)
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(entries) > 64 {
		return errors.New("descriptor census is unavailable or oversized")
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd <= 5 {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			continue // The directory-reading descriptor closed after ReadDir.
		}
		target, err := os.Readlink("/proc/self/fd/" + entry.Name())
		var stat unix.Stat_t
		statErr := unix.Fstat(fd, &stat)
		access, accessErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		runtimeInternal := target == "anon_inode:[eventpoll]" ||
			target == "anon_inode:[eventfd]"
		cgroupReadOnly := target == "/sys/fs/cgroup/cpu.max" &&
			cgroupStatErr == nil && statErr == nil &&
			stat.Dev == cgroupInfo.Dev && stat.Ino == cgroupInfo.Ino &&
			accessErr == nil && access&unix.O_ACCMODE == unix.O_RDONLY
		if err != nil || flags&unix.FD_CLOEXEC == 0 ||
			(!runtimeInternal && !cgroupReadOnly) {
			return fmt.Errorf("unexpected inherited descriptor %d (%q)", fd, target)
		}
	}
	return nil
}

func executingWorkerDigest(file *os.File) (string, error) {
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 {
		return "", errors.New("worker descriptor identity is invalid")
	}
	executed, err := os.Stat("/proc/self/exe")
	if err != nil || !os.SameFile(before, executed) {
		return "", errors.New("descriptor 3 is not executing worker")
	}
	if before.Size() > 128<<20 {
		return "", errors.New("executing worker is oversized")
	}
	data := make([]byte, int(before.Size()))
	if _, err := file.ReadAt(data, 0); err != nil {
		return "", errors.New("read executing worker descriptor")
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash[:]), nil
}

func currentProcessStartTicks() (uint64, error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}
	closeIndex := strings.LastIndexByte(string(data), ')')
	if closeIndex < 0 || closeIndex+2 >= len(data) {
		return 0, errors.New("invalid /proc/self/stat")
	}
	fields := strings.Fields(string(data[closeIndex+2:]))
	// fields starts at Linux stat field 3 (state), so starttime field 22 is 19.
	if len(fields) <= 19 {
		return 0, errors.New("short /proc/self/stat")
	}
	value, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || value == 0 {
		return 0, errors.New("invalid process start ticks")
	}
	return value, nil
}
