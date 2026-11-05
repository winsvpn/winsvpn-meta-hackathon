//go:build linux && winn_incomplete_e8

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"winsvpn.local/winnprotocol/internal/realcycle"
)

const e8LocalRehearsalMaxBytes = 64 << 10

const e8PreparedIdentitySchema = "winn-e8-retained-worker-identity/v1"

type e8PreparedIdentity struct {
	Schema                    string `json:"schema"`
	ProcessID                 uint64 `json:"process_id"`
	ProcessStartTicks         uint64 `json:"process_start_ticks"`
	WorkerSHA256              string `json:"worker_sha256"`
	WorkerBuildID             string `json:"worker_build_id,omitempty"`
	AndroidPackageName        string `json:"android_package_name,omitempty"`
	AndroidPackageVersionCode uint64 `json:"android_package_version_code,omitempty"`
	AndroidSigningCertSHA256  string `json:"android_signing_cert_sha256,omitempty"`
}

type e8Child struct {
	command             *exec.Cmd
	channel             net.Conn
	contract            realcycle.LocalRehearsalNodeContract
	ready               realcycle.LocalRehearsalNodeFrame
	start               realcycle.LocalRehearsalNodeFrame
	terminal            realcycle.LocalRehearsalNodeFrame
	stderr              *boundedBuffer
	sandboxThreadCount  uint64
	sandboxStatusDigest string
	pidfd               *os.File
	processStart        uint64
	contractWriter      *os.File
	contractCapability  *os.File
	channelCapability   *os.File
	descriptorCount     uint64
	descriptorDigest    string
}

type e8PreparedWorkerSet struct {
	children       []*e8Child
	identities     [e5PlanNodeCount]e8PreparedIdentity
	worker         *os.File
	workerPath     string
	workerSHA      string
	workerAccess   int
	androidPackage *e8AndroidPackageBinding
	consumed       bool
}

var (
	writeE8ReceiptOperation  = writeAll
	syncE8ReceiptOperation   = func(file *os.File) error { return file.Sync() }
	closeE8ReceiptOperation  = func(file *os.File) error { return file.Close() }
	renameE8ReceiptOperation = func(directory *secureDirectory) error {
		return unix.Renameat2(
			int(directory.file.Fd()), "."+e8ReceiptFile+".pending",
			int(directory.file.Fd()), e8ReceiptFile, unix.RENAME_NOREPLACE,
		)
	}
	syncE8DirectoryOperation = func(directory *secureDirectory) error {
		return directory.file.Sync()
	}
	killE8PidfdOperation = func(file *os.File) error {
		return unix.PidfdSendSignal(int(file.Fd()), unix.SIGKILL, nil, 0)
	}
	waitE8ChildOperation = func(command *exec.Cmd) error {
		return command.Wait()
	}
)

type e8PublicationError struct {
	Stage                string
	FinalReceiptMayExist bool
	DirectorySynced      bool
	ReceiptAuthenticated bool
}

func (err *e8PublicationError) Error() string {
	return "E8 receipt publication is indeterminate at " + err.Stage
}

func prepareLocalFourNode(
	ctx context.Context,
	workerPath, workerSHA string,
) (prepared *e8PreparedWorkerSet, returnErr error) {
	if runtime.GOOS == "android" {
		return nil, errors.New(
			"E8 Android requires a PackageManager-bound packaged worker",
		)
	}
	if !digestPattern.MatchString(workerSHA) {
		return nil, errors.New("E8 prepared worker SHA-256 is malformed")
	}
	worker, err := sealE8Worker(workerPath, workerSHA)
	if err != nil {
		return nil, fmt.Errorf("seal E8 prepared worker: %w", err)
	}
	return prepareLocalFourNodeWithWorker(
		ctx, workerPath, workerSHA, worker, unix.O_RDWR, nil,
	)
}

func prepareLocalFourNodeWithWorker(
	ctx context.Context,
	workerPath, workerSHA string,
	worker *os.File,
	workerAccess int,
	androidPackage *e8AndroidPackageBinding,
) (prepared *e8PreparedWorkerSet, returnErr error) {
	if !digestPattern.MatchString(workerSHA) || worker == nil ||
		(workerAccess != unix.O_RDONLY && workerAccess != unix.O_RDWR) {
		if worker != nil {
			_ = worker.Close()
		}
		return nil, errors.New("E8 prepared worker source is invalid")
	}
	if androidPackage != nil {
		if workerAccess != unix.O_RDONLY ||
			androidPackage.WorkerSHA256 != workerSHA ||
			validateE8AndroidPackageBinding(*androidPackage) != nil {
			_ = worker.Close()
			return nil, errors.New(
				"E8 Android prepared worker package binding is invalid",
			)
		}
		bindingCopy := *androidPackage
		androidPackage = &bindingCopy
	}
	prepared = &e8PreparedWorkerSet{
		children: make([]*e8Child, 0, e5PlanNodeCount),
		worker:   worker, workerPath: workerPath, workerSHA: workerSHA,
		workerAccess: workerAccess, androidPackage: androidPackage,
	}
	ok := false
	defer func() {
		if !ok {
			returnErr = errors.Join(returnErr, prepared.Close())
			prepared = nil
		}
	}()
	for index := range e5PlanNodeCount {
		writer, reader, err := newE8DeferredContract(
			fmt.Sprintf("winn-e8-deferred-contract-%d", index),
		)
		if err != nil {
			return nil, err
		}
		if runtime.GOOS == "android" {
			if reader != nil {
				return nil, errors.Join(
					errors.New("unexpected Android deferred contract reader"),
					writer.Close(), reader.Close(),
				)
			}
			placeholderFD, err := unix.FcntlInt(
				worker.Fd(), unix.F_DUPFD_CLOEXEC, 0,
			)
			if err != nil {
				return nil, errors.Join(err, writer.Close())
			}
			// #nosec G115 -- F_DUPFD_CLOEXEC returned a nonnegative descriptor.
			reader = os.NewFile(
				uintptr(placeholderFD), "e8-android-contract-placeholder",
			)
			if reader == nil {
				_ = unix.Close(placeholderFD)
				return nil, errors.Join(
					errors.New("wrap E8 Android contract placeholder"),
					writer.Close(),
				)
			}
		}
		pair, err := unix.Socketpair(
			unix.AF_UNIX,
			unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC,
			0,
		)
		if err != nil {
			return nil, errors.Join(err, writer.Close(), reader.Close())
		}
		// #nosec G115 -- Socketpair returned nonnegative live descriptors.
		parentFile := os.NewFile(uintptr(pair[0]), "e8-prepared-parent-channel")
		// #nosec G115 -- Socketpair returned nonnegative live descriptors.
		childFile := os.NewFile(uintptr(pair[1]), "e8-prepared-child-channel")
		parentConn, err := net.FileConn(parentFile)
		parentCloseErr := parentFile.Close()
		if err != nil || parentCloseErr != nil {
			return nil, errors.Join(
				err, parentCloseErr, writer.Close(), reader.Close(),
				childFile.Close(),
			)
		}
		command := exec.CommandContext(ctx, "/proc/self/fd/3")
		command.Args[0] = "winn-local-sealed-node"
		command.Env = []string{}
		command.ExtraFiles = []*os.File{worker, reader, childFile}
		command.SysProcAttr = &unix.SysProcAttr{Setpgid: true}
		stderr := newBoundedBuffer(64 << 10)
		command.Stderr = stderr
		if err := enableE8Passcred(parentConn); err != nil {
			return nil, errors.Join(
				err, parentConn.Close(), writer.Close(), reader.Close(),
				childFile.Close(),
			)
		}
		if err := command.Start(); err != nil {
			return nil, errors.Join(
				err, parentConn.Close(), writer.Close(), reader.Close(),
				childFile.Close(),
			)
		}
		pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
		if err != nil {
			_ = syscallKillGroup(command.Process.Pid)
			_ = command.Wait()
			return nil, errors.Join(
				err, parentConn.Close(), writer.Close(), reader.Close(),
				childFile.Close(),
			)
		}
		processStart, err := linuxProcessStartTicks(command.Process.Pid)
		if err != nil {
			_ = unix.Close(pidfd)
			_ = syscallKillGroup(command.Process.Pid)
			_ = command.Wait()
			return nil, errors.Join(
				err, parentConn.Close(), writer.Close(), reader.Close(),
				childFile.Close(),
			)
		}
		// #nosec G115 -- PidfdOpen returned a nonnegative live descriptor.
		pidfdFile := os.NewFile(uintptr(pidfd), "e8-prepared-child-pidfd")
		if pidfdFile == nil {
			_ = unix.Close(pidfd)
			_ = syscallKillGroup(command.Process.Pid)
			_ = command.Wait()
			return nil, errors.Join(
				errors.New("wrap E8 prepared child pidfd"),
				parentConn.Close(), writer.Close(), reader.Close(),
				childFile.Close(),
			)
		}
		child := &e8Child{
			command: command, channel: parentConn, stderr: stderr,
			pidfd: pidfdFile, processStart: processStart,
			contractWriter: writer, contractCapability: reader,
			channelCapability: childFile,
		}
		prepared.children = append(prepared.children, child)
	}
	for index, child := range prepared.children {
		_ = child.channel.SetReadDeadline(time.Now().Add(30 * time.Second))
		data, peer, err := readE8CredentialedPacket(child.channel)
		if err != nil {
			return nil, fmt.Errorf(
				"read E8 prepared identity: %w (stderr=%q)",
				err, string(child.stderr.Bytes()),
			)
		}
		var identity e8PreparedIdentity
		if err := decodeStrictObject(data, &identity); err != nil {
			return nil, err
		}
		if err := validateE8PreparedIdentity(
			identity, child, peer, workerSHA, androidPackage,
		); err != nil {
			return nil, errors.New(
				"E8 prepared identity is not kernel/executable bound",
			)
		}
		currentStart, err := linuxProcessStartTicks(child.command.Process.Pid)
		if err != nil || currentStart != identity.ProcessStartTicks {
			return nil, errors.New("E8 prepared process identity changed")
		}
		prepared.identities[index] = identity
	}
	ok = true
	return prepared, nil
}

func validateE8PreparedIdentity(
	identity e8PreparedIdentity,
	child *e8Child,
	peer *unix.Ucred,
	workerSHA string,
	androidPackage *e8AndroidPackageBinding,
) error {
	if child == nil || child.command == nil || child.command.Process == nil ||
		child.command.Process.Pid <= 0 || peer == nil ||
		identity.Schema != e8PreparedIdentitySchema ||
		identity.ProcessID == 0 || identity.ProcessStartTicks == 0 ||
		identity.WorkerSHA256 != workerSHA ||
		// #nosec G115 -- the child PID was proven positive.
		identity.ProcessID != uint64(child.command.Process.Pid) ||
		identity.ProcessStartTicks != child.processStart ||
		// #nosec G115 -- SCM_CREDENTIALS and os.Process use Linux pid_t.
		peer.Pid != int32(child.command.Process.Pid) {
		return errors.New("E8 prepared identity kernel binding mismatch")
	}
	if androidPackage == nil {
		if identity.WorkerBuildID != "" ||
			identity.AndroidPackageName != "" ||
			identity.AndroidPackageVersionCode != 0 ||
			identity.AndroidSigningCertSHA256 != "" {
			return errors.New("E8 non-Android worker claimed package identity")
		}
		return nil
	}
	if identity.WorkerBuildID != androidPackage.WorkerBuildID ||
		identity.AndroidPackageName != androidPackage.PackageName ||
		identity.AndroidPackageVersionCode != androidPackage.VersionCode ||
		identity.AndroidSigningCertSHA256 !=
			androidPackage.SigningCertificateSHA256 {
		return errors.New("E8 Android worker build/package identity mismatch")
	}
	return nil
}

func (prepared *e8PreparedWorkerSet) Close() error {
	if prepared == nil {
		return nil
	}
	err := cleanupE8Children(prepared.children)
	prepared.children = nil
	if prepared.worker != nil {
		err = errors.Join(err, prepared.worker.Close())
		prepared.worker = nil
	}
	return err
}

func validateE8PreparedPlan(
	plan e5FourNodePlan,
	prepared *e8PreparedWorkerSet,
	workerPath, workerSHA string,
) error {
	if prepared == nil || prepared.consumed ||
		len(prepared.children) != e5PlanNodeCount ||
		prepared.worker == nil ||
		(prepared.workerAccess != unix.O_RDONLY &&
			prepared.workerAccess != unix.O_RDWR) ||
		prepared.workerPath != workerPath || prepared.workerSHA != workerSHA {
		return errors.New("E8 retained pre-E5 worker capability is unavailable")
	}
	retainedDigest, err := digestE8RetainedWorker(prepared.worker)
	if err != nil || retainedDigest != workerSHA {
		return errors.New("E8 retained pre-E5 worker digest changed")
	}
	if prepared.androidPackage != nil {
		reopened, err := openE8AndroidPackagedWorker(
			*prepared.androidPackage, true,
		)
		if err != nil {
			return errors.New("E8 Android package custody changed before E5")
		}
		retainedInfo, retainedErr := prepared.worker.Stat()
		reopenedInfo, reopenedErr := reopened.Stat()
		closeErr := reopened.Close()
		if retainedErr != nil || reopenedErr != nil || closeErr != nil ||
			!os.SameFile(retainedInfo, reopenedInfo) {
			return errors.New(
				"E8 Android packaged worker identity changed before E5",
			)
		}
	} else if prepared.workerAccess != unix.O_RDWR {
		return errors.New("E8 non-Android retained worker access is invalid")
	}
	seenPID := map[uint64]bool{}
	for index, node := range plan.Nodes {
		identity := prepared.identities[index]
		if identity.Schema != e8PreparedIdentitySchema ||
			identity.ProcessID == 0 || identity.ProcessStartTicks == 0 ||
			identity.WorkerSHA256 != workerSHA ||
			node.ProcessID != identity.ProcessID ||
			node.ProcessStartTicks != identity.ProcessStartTicks ||
			node.ExecutableSHA256 != identity.WorkerSHA256 ||
			seenPID[identity.ProcessID] {
			return fmt.Errorf(
				"E8 E5 node %d does not bind its retained pre-E5 worker", index,
			)
		}
		seenPID[identity.ProcessID] = true
		child := prepared.children[index]
		if child.command == nil || child.command.Process == nil ||
			child.command.Process.Pid <= 0 {
			return errors.New("E8 retained pre-E5 worker process is unavailable")
		}
		// #nosec G115 -- the retained child PID was proven positive.
		if uint64(child.command.Process.Pid) != node.ProcessID ||
			child.processStart != node.ProcessStartTicks {
			return errors.New("E8 retained worker handle/E5 identity mismatch")
		}
		currentStart, err := linuxProcessStartTicks(child.command.Process.Pid)
		if err != nil || currentStart != node.ProcessStartTicks {
			return errors.New("E8 retained E5 worker identity is no longer live")
		}
	}
	return nil
}

func digestE8RetainedWorker(file *os.File) (string, error) {
	if file == nil {
		return "", errors.New("E8 retained worker is missing")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() ||
		info.Size() <= 0 || info.Size() > 128<<20 {
		return "", errors.New("E8 retained worker identity is invalid")
	}
	data := make([]byte, int(info.Size()))
	if _, err := file.ReadAt(data, 0); err != nil {
		return "", errors.New("read E8 retained worker")
	}
	return admittedRawSHA(data), nil
}

func runLocalFourNode(
	ctx context.Context,
	plan e5FourNodePlan,
	e6 e6VerificationReceipt,
	e7 e7VerificationReceipt,
	grant e8GrantResult,
	e6SHA, e7SHA, workerPath, workerSHA string,
	nodeNonces [4]string,
	prepared *e8PreparedWorkerSet,
) (evidence [4]e8NodeEvidence, returnErr error) {
	seenNodeNonces := map[string]bool{}
	for _, nonce := range nodeNonces {
		if !noncePattern.MatchString(nonce) || seenNodeNonces[nonce] {
			return evidence, errors.New("E8 durable node nonce catalog is invalid")
		}
		seenNodeNonces[nonce] = true
	}
	if err := validateE8PreparedPlan(
		plan, prepared, workerPath, workerSHA,
	); err != nil {
		return evidence, err
	}
	worker := prepared.worker
	deadline := 30 * time.Second
	if grant.MaxRehearsalSeconds > 30 {
		return evidence, errors.New("E8 rehearsal duration exceeds 30 seconds")
	}
	if grant.MaxRehearsalSeconds > 0 {
		// #nosec G115 -- the protocol bound above proves this is <= 30.
		deadline = time.Duration(grant.MaxRehearsalSeconds) * time.Second
	}
	select {
	case <-ctx.Done():
		return evidence, ctx.Err()
	default:
	}
	children := prepared.children
	androidPackageBindingDigest := ""
	if prepared.androidPackage != nil {
		androidPackageBindingDigest = prepared.androidPackage.ObjectDigest
	}
	ok := false
	defer func() {
		if !ok {
			returnErr = errors.Join(returnErr, prepared.Close())
		}
	}()
	for index, node := range plan.Nodes {
		nonce := nodeNonces[index]
		contract, contractBytes, err :=
			encodeE8LocalRehearsalContract(
				realcycle.LocalRehearsalNodeContract{
					RunID: plan.RunID, CycleID: plan.CycleID,
					AttemptID: plan.AttemptID, TopologyID: plan.TopologyID,
					Role: node.Role, NodeID: node.NodeID, ServiceID: node.ServiceID,
					PlanSHA256:            e6.PlanSHA256,
					PlanObjectDigest:      e6.PlanObjectDigest,
					E6ReceiptSHA256:       e6SHA,
					E6ReceiptObjectDigest: e6.ObjectDigest,
					E7ReceiptSHA256:       e7SHA,
					E7ReceiptObjectDigest: e7.ObjectDigest,
					RehearsalGrantDigest:  grant.CollectionDigest,
					WorkerSHA256:          workerSHA, RehearsalNonce: nonce,
				},
			)
		if err != nil {
			return evidence, err
		}
		child := children[index]
		if child.contractWriter == nil {
			return evidence, errors.New("E8 deferred contract writer is missing")
		}
		if err := finalizeE8DeferredContract(
			child.contractWriter, contractBytes,
		); err != nil {
			return evidence, err
		}
		if runtime.GOOS != "android" {
			child.contractWriter = nil
		}
		child.contract = contract
	}
	prepared.consumed = true
	for _, child := range children {
		_ = child.channel.SetWriteDeadline(time.Now().Add(deadline))
		if runtime.GOOS == "android" {
			if child.contractWriter == nil ||
				child.contractCapability == nil {
				return evidence, errors.New(
					"E8 Android sealed contract handoff is missing",
				)
			}
			if err := sendE8SealedContractReady(
				child.channel, child.contractWriter,
			); err != nil {
				return evidence, err
			}
			if err := child.contractCapability.Close(); err != nil {
				return evidence, err
			}
			child.contractCapability = child.contractWriter
			child.contractWriter = nil
		} else if _, err := child.channel.Write(
			[]byte("contract-ready"),
		); err != nil {
			return evidence, err
		}
	}
	for _, child := range children {
		_ = child.channel.SetReadDeadline(time.Now().Add(deadline))
		data, peer, err := readE8CredentialedPacket(child.channel)
		if err != nil {
			return evidence, fmt.Errorf(
				"%w (child stderr=%q)",
				err, string(child.stderr.Bytes()),
			)
		}
		child.ready, err = parseE8LocalRehearsalFrame(data)
		if child.command.Process.Pid <= 0 {
			return evidence, errors.New("E8 child has an invalid kernel PID")
		}
		if err != nil || child.ready.State != "ready" ||
			child.ready.ContractDigest != child.contract.ObjectDigest ||
			// #nosec G115 -- the child PID was just proven positive.
			child.ready.ProcessID != uint64(child.command.Process.Pid) ||
			// #nosec G115 -- SCM_CREDENTIALS and os.Process use Linux pid_t.
			peer.Pid != int32(child.command.Process.Pid) {
			return evidence, errors.New("E8 ready frame is not kernel-bound")
		}
		startTicks, err := linuxProcessStartTicks(child.command.Process.Pid)
		if err != nil || startTicks != child.ready.ProcessStart {
			return evidence, errors.New("E8 ready process start identity mismatch")
		}
		count, digest, err := verifyE8SandboxStatus(child.command.Process.Pid)
		if err != nil {
			return evidence, err
		}
		child.sandboxThreadCount = count
		child.sandboxStatusDigest = digest
		count, digest, err = verifyE8ChildDescriptorCensus(
			child.command.Process.Pid, worker,
			child.contractCapability, child.channelCapability,
			prepared.workerAccess,
		)
		if err != nil {
			return evidence, err
		}
		child.descriptorCount = count
		child.descriptorDigest = digest
		if err := child.contractCapability.Close(); err != nil {
			return evidence, err
		}
		child.contractCapability = nil
		if err := child.channelCapability.Close(); err != nil {
			return evidence, err
		}
		child.channelCapability = nil
	}
	for _, child := range children {
		token, err := e8RandomHex(16)
		if err != nil {
			return evidence, err
		}
		var data []byte
		child.start, data, err = encodeE8LocalRehearsalFrame(
			realcycle.LocalRehearsalNodeFrame{
				State: "start", ContractDigest: child.contract.ObjectDigest,
				Role: child.contract.Role, NodeID: child.contract.NodeID,
				ProcessID:    child.ready.ProcessID,
				ProcessStart: child.ready.ProcessStart,
				StartToken:   token,
			},
		)
		if err != nil {
			return evidence, err
		}
		_ = child.channel.SetWriteDeadline(time.Now().Add(deadline))
		if _, err := child.channel.Write(data); err != nil {
			return evidence, err
		}
	}
	for index, child := range children {
		_ = child.channel.SetReadDeadline(time.Now().Add(deadline))
		data, peer, err := readE8CredentialedPacket(child.channel)
		if err != nil {
			return evidence, err
		}
		child.terminal, err = parseE8LocalRehearsalFrame(data)
		expectedInput, expectedOutput, expectedOperation, operationErr :=
			realcycle.LocalRehearsalOperationEvidence(
				child.contract, child.start.StartToken,
				child.ready.ProcessID, child.ready.ProcessStart,
			)
		if err != nil || operationErr != nil ||
			child.terminal.State != "terminal-success" ||
			child.terminal.ContractDigest != child.contract.ObjectDigest ||
			child.terminal.ProcessID != child.ready.ProcessID ||
			child.terminal.ProcessStart != child.ready.ProcessStart ||
			child.terminal.StartToken != child.start.StartToken ||
			child.terminal.OperationKind != "sealed-local-service-self-check" ||
			child.terminal.OperationInput != expectedInput ||
			child.terminal.OperationOutput != expectedOutput ||
			child.terminal.OperationDigest != expectedOperation ||
			// #nosec G115 -- SCM_CREDENTIALS and os.Process use Linux pid_t.
			peer.Pid != int32(child.command.Process.Pid) {
			return evidence, errors.New("E8 terminal frame cross-binding mismatch")
		}
		if err := requireE8ChannelEOF(child.channel); err != nil {
			return evidence, err
		}
		if err := waitE8ChildOperation(child.command); err != nil {
			return evidence, fmt.Errorf("E8 child %d failed: %w", index, err)
		}
		child.command.Process = nil
		if child.pidfd == nil {
			return evidence, errors.New("E8 child lost retained pidfd")
		}
		if err := unix.PidfdSendSignal(
			// #nosec G115 -- os.File owns a live Linux pidfd.
			int(child.pidfd.Fd()), 0, nil, 0,
		); err != unix.ESRCH {
			return evidence, errors.New("E8 child pidfd remained live after reap")
		}
		if err := child.pidfd.Close(); err != nil {
			return evidence, err
		}
		child.pidfd = nil
		if err := child.channel.Close(); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			return evidence, err
		}
		child.channel = nil
		evidence[index] = e8NodeEvidence{
			Contract: child.contract, Ready: child.ready,
			Start: child.start, Terminal: child.terminal, ExitCode: 0,
			ChannelEOFObserved: true, ZeroSurvivorsObserved: true,
			SandboxThreadCount:  child.sandboxThreadCount,
			SandboxStatusDigest: child.sandboxStatusDigest,
			PidfdRetained:       true, PidfdReaped: true,
			LifecyclePolicyDigest:       e8LifecyclePolicyDigest(),
			DescriptorCount:             child.descriptorCount,
			DescriptorCensusDigest:      child.descriptorDigest,
			AndroidPackageBindingDigest: androidPackageBindingDigest,
		}
	}
	if err := prepared.Close(); err != nil {
		return evidence, err
	}
	ok = true
	return evidence, nil
}

func cleanupE8Children(children []*e8Child) error {
	var cleanupErr error
	for _, child := range children {
		if child.channel != nil {
			err := child.channel.Close()
			if err != nil && !errors.Is(err, net.ErrClosed) {
				cleanupErr = errors.Join(cleanupErr, err)
			}
			child.channel = nil
		}
		if child.command.Process != nil {
			currentStart, err := linuxProcessStartTicks(
				child.command.Process.Pid,
			)
			if err == nil && currentStart == child.processStart {
				if child.pidfd == nil {
					cleanupErr = errors.Join(
						cleanupErr, errors.New("E8 cleanup lacks pidfd"),
					)
				} else if err := killE8PidfdOperation(child.pidfd); err != nil &&
					err != unix.ESRCH {
					cleanupErr = errors.Join(cleanupErr, err)
				}
				if err := syscallKillGroup(child.command.Process.Pid); err != nil &&
					err != unix.ESRCH {
					cleanupErr = errors.Join(cleanupErr, err)
				}
			} else if err == nil || !errors.Is(err, os.ErrNotExist) {
				cleanupErr = errors.Join(
					cleanupErr,
					errors.New("E8 cleanup process start identity changed"),
				)
			}
			if err := waitE8ChildOperation(child.command); err != nil {
				if _, ok := err.(*exec.ExitError); !ok {
					cleanupErr = errors.Join(cleanupErr, err)
				}
			}
			child.command.Process = nil
		}
		if child.pidfd != nil {
			cleanupErr = errors.Join(cleanupErr, child.pidfd.Close())
			child.pidfd = nil
		}
		if child.contractWriter != nil {
			cleanupErr = errors.Join(cleanupErr, child.contractWriter.Close())
			child.contractWriter = nil
		}
		if child.contractCapability != nil {
			cleanupErr = errors.Join(
				cleanupErr, child.contractCapability.Close(),
			)
			child.contractCapability = nil
		}
		if child.channelCapability != nil {
			cleanupErr = errors.Join(
				cleanupErr, child.channelCapability.Close(),
			)
			child.channelCapability = nil
		}
	}
	return cleanupErr
}

func verifyE8ChildDescriptorCensus(
	pid int, worker, contract, channel *os.File,
	workerAccess int,
) (uint64, string, error) {
	if worker == nil || contract == nil || channel == nil {
		return 0, "", errors.New("E8 descriptor source capabilities are missing")
	}
	if workerAccess != unix.O_RDONLY && workerAccess != unix.O_RDWR {
		return 0, "", errors.New("E8 worker descriptor access is invalid")
	}
	root := "/proc/" + strconv.Itoa(pid) + "/fd"
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) < 6 || len(entries) > 64 {
		return 0, "", errors.New("E8 child descriptor census is unavailable")
	}
	type expectedDescriptor struct {
		file   *os.File
		access int
	}
	contractAccess := unix.O_RDONLY
	if runtime.GOOS == "android" {
		// Android receives the memfd only after F_SEAL_WRITE and the complete
		// immutable seal set are installed.
		contractAccess = unix.O_RDWR
	}
	expected := map[int]expectedDescriptor{
		3: {file: worker, access: workerAccess},
		4: {file: contract, access: contractAccess},
		5: {file: channel, access: unix.O_RDWR},
	}
	rows := make([]string, 0, len(entries))
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd < 0 {
			return 0, "", errors.New("E8 child descriptor number is invalid")
		}
		info, err := os.Stat(root + "/" + entry.Name())
		if err != nil {
			return 0, "", err
		}
		identity, err := identityFromInfo(info)
		if err != nil {
			return 0, "", err
		}
		fdInfo, err := os.ReadFile(
			"/proc/" + strconv.Itoa(pid) + "/fdinfo/" + entry.Name(),
		)
		if err != nil {
			return 0, "", err
		}
		var flags uint64
		foundFlags := false
		for _, line := range strings.Split(string(fdInfo), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "flags:" {
				flags, err = strconv.ParseUint(fields[1], 8, 64)
				foundFlags = err == nil
			}
		}
		if !foundFlags {
			return 0, "", errors.New("E8 child fdinfo lacks flags")
		}
		target, err := os.Readlink(root + "/" + entry.Name())
		if err != nil {
			return 0, "", err
		}
		if source, ok := expected[fd]; ok {
			sourceInfo, err := source.file.Stat()
			if err != nil || !os.SameFile(info, sourceInfo) ||
				int(flags)&unix.O_ACCMODE != source.access {
				return 0, "", fmt.Errorf(
					"E8 child descriptor %d does not bind retained source", fd,
				)
			}
		} else if fd > 5 {
			runtimeTarget := target == "anon_inode:[eventpoll]" ||
				target == "anon_inode:[eventfd]" ||
				target == "/sys/fs/cgroup/cpu.max"
			if !runtimeTarget || int(flags)&unix.O_CLOEXEC == 0 {
				return 0, "", fmt.Errorf(
					"E8 child inherited unapproved descriptor %d (%q)", fd, target,
				)
			}
		}
		rows = append(rows, fmt.Sprintf(
			"fd=%d;dev=%d;ino=%d;mode=%o;flags=%o;target=%s",
			fd, identity.device, identity.inode, info.Mode(), flags, target,
		))
	}
	sort.Strings(rows)
	digest, err := admittedDigest("winn-e8-r3-child-fd-census/v1", rows)
	return uint64(len(rows)), digest, err
}

func sealE8Worker(path, expectedSHA string) (*os.File, error) {
	source, digest, err := openAndDigestPinnedFile(path)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || info.Mode().Perm() != 0o500 || digest != expectedSHA {
		return nil, errors.New("E8 worker source identity or digest mismatch")
	}
	if err := verifyE8StaticELF(source); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(source, 128<<20))
	if err != nil || int64(len(data)) != info.Size() {
		return nil, errors.New("E8 worker source replay mismatch")
	}
	fd, err := unix.MemfdCreate(
		"winn-e8-local-node-worker",
		unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC|unix.MFD_EXEC,
	)
	if err != nil {
		return nil, err
	}
	// #nosec G115 -- MemfdCreate returned a nonnegative live descriptor.
	file := os.NewFile(uintptr(fd), "sealed-e8-worker")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap E8 worker memfd")
	}
	if err := writeAll(file, data); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if err := file.Chmod(0o500); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK |
		unix.F_SEAL_GROW | unix.F_SEAL_EXEC | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func enableE8Passcred(conn net.Conn) error {
	raw, ok := conn.(syscall.Conn)
	if !ok {
		return errors.New("E8 channel lacks raw connection")
	}
	var result error
	control, err := raw.SyscallConn()
	if err != nil {
		return err
	}
	if err := control.Control(func(fd uintptr) {
		// #nosec G115 -- syscall.Conn retains a live descriptor for Control.
		result = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
	}); err != nil {
		return err
	}
	return result
}

func readE8CredentialedPacket(conn net.Conn) ([]byte, *unix.Ucred, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, nil, errors.New("E8 channel is not a Unix connection")
	}
	data := make([]byte, e8LocalRehearsalMaxBytes+1)
	control := make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	count, controlCount, _, _, err := unixConn.ReadMsgUnix(data, control)
	if err != nil || count == 0 || count > e8LocalRehearsalMaxBytes {
		return nil, nil, errors.New("E8 capability frame is unreadable or oversized")
	}
	messages, err := unix.ParseSocketControlMessage(control[:controlCount])
	if err != nil || len(messages) != 1 {
		return nil, nil, errors.New("E8 capability frame lacks exact credentials")
	}
	credential, err := unix.ParseUnixCredentials(&messages[0])
	if err != nil {
		return nil, nil, err
	}
	return data[:count], credential, nil
}

func encodeE8LocalRehearsalContract(
	value realcycle.LocalRehearsalNodeContract,
) (realcycle.LocalRehearsalNodeContract, []byte, error) {
	digest, err := realcycle.LocalRehearsalContractObjectDigest(value)
	if err != nil {
		return realcycle.LocalRehearsalNodeContract{}, nil, err
	}
	value.ObjectDigest = digest
	if err := realcycle.ValidateLocalRehearsalContract(value); err != nil {
		return realcycle.LocalRehearsalNodeContract{}, nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 ||
		len(encoded) > e8LocalRehearsalMaxBytes {
		return realcycle.LocalRehearsalNodeContract{}, nil,
			errors.New("E8 local rehearsal contract encoding exceeds bound")
	}
	return value, encoded, nil
}

func encodeE8LocalRehearsalFrame(
	value realcycle.LocalRehearsalNodeFrame,
) (realcycle.LocalRehearsalNodeFrame, []byte, error) {
	if err := realcycle.ValidateLocalRehearsalFrame(value); err != nil {
		return realcycle.LocalRehearsalNodeFrame{}, nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 ||
		len(encoded) > e8LocalRehearsalMaxBytes {
		return realcycle.LocalRehearsalNodeFrame{}, nil,
			errors.New("E8 local rehearsal frame encoding exceeds bound")
	}
	return value, encoded, nil
}

func parseE8LocalRehearsalFrame(
	data []byte,
) (realcycle.LocalRehearsalNodeFrame, error) {
	if len(data) == 0 || len(data) > e8LocalRehearsalMaxBytes {
		return realcycle.LocalRehearsalNodeFrame{},
			errors.New("E8 local rehearsal frame exceeds bound")
	}
	var value realcycle.LocalRehearsalNodeFrame
	if err := decodeStrictObject(data, &value); err != nil {
		return realcycle.LocalRehearsalNodeFrame{}, err
	}
	if err := realcycle.ValidateLocalRehearsalFrame(value); err != nil {
		return realcycle.LocalRehearsalNodeFrame{}, err
	}
	return value, nil
}

func e8RandomHex(bytesCount int) (string, error) {
	data := make([]byte, bytesCount)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", data), nil
}

func newE8DeferredContract(name string) (*os.File, *os.File, error) {
	fd, err := unix.MemfdCreate(
		name, unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC,
	)
	if err != nil {
		return nil, nil, err
	}
	// #nosec G115 -- MemfdCreate returned a nonnegative live descriptor.
	writer := os.NewFile(uintptr(fd), name+"-writer")
	if writer == nil {
		_ = unix.Close(fd)
		return nil, nil, errors.New("wrap E8 deferred contract writer")
	}
	// Android SELinux denies both fchmod and reopening anonymous memfds through
	// /proc/self/fd. The Android child therefore receives this descriptor only
	// after the full seal set is installed, over its authenticated capability
	// channel. Linux retains the independently reopened O_RDONLY handoff.
	if runtime.GOOS == "android" {
		return writer, nil, nil
	}
	if err := writer.Chmod(0o400); err != nil {
		return nil, nil, errors.Join(err, writer.Close())
	}
	readerFD, err := unix.Open(
		"/proc/self/fd/"+strconv.Itoa(fd),
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, nil, errors.Join(
			fmt.Errorf("open E8 deferred contract read-only capability: %w", err),
			writer.Close(),
		)
	}
	// #nosec G115 -- unix.Open returned a nonnegative live descriptor.
	reader := os.NewFile(uintptr(readerFD), name+"-reader")
	if reader == nil {
		_ = unix.Close(readerFD)
		return nil, nil, errors.Join(
			errors.New("wrap E8 deferred contract reader"), writer.Close(),
		)
	}
	writerInfo, writerErr := writer.Stat()
	readerInfo, readerErr := reader.Stat()
	if writerErr != nil || readerErr != nil ||
		!os.SameFile(writerInfo, readerInfo) {
		return nil, nil, errors.Join(
			errors.New("E8 deferred contract descriptors differ"),
			writerErr, readerErr, writer.Close(), reader.Close(),
		)
	}
	return writer, reader, nil
}

func finalizeE8DeferredContract(writer *os.File, data []byte) error {
	if writer == nil || len(data) == 0 || len(data) > e8LocalRehearsalMaxBytes {
		return errors.New("E8 deferred contract payload is invalid")
	}
	if err := writeAll(writer, data); err != nil {
		return errors.Join(err, writer.Close())
	}
	if err := writer.Sync(); err != nil {
		return errors.Join(err, writer.Close())
	}
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK |
		unix.F_SEAL_GROW | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(
		writer.Fd(), unix.F_ADD_SEALS, seals,
	); err != nil {
		return errors.Join(err, writer.Close())
	}
	if err := verifyE8DeferredContractImmutable(writer, seals, data); err != nil {
		return errors.Join(err, writer.Close())
	}
	if runtime.GOOS == "android" {
		return nil
	}
	return writer.Close()
}

func verifyE8DeferredContractImmutable(
	writer *os.File,
	expectedSeals int,
	expectedData []byte,
) error {
	actualSeals, err := unix.FcntlInt(
		writer.Fd(), unix.F_GET_SEALS, 0,
	)
	if err != nil || actualSeals != expectedSeals {
		return errors.New("E8 deferred contract seal set is not exact")
	}
	info, err := writer.Stat()
	if err != nil || !info.Mode().IsRegular() ||
		info.Size() != int64(len(expectedData)) {
		return errors.New("sealed E8 contract size is not exact")
	}
	replayed := make([]byte, len(expectedData))
	if count, err := writer.ReadAt(replayed, 0); err != nil ||
		count != len(replayed) || !bytes.Equal(replayed, expectedData) {
		return errors.New("sealed E8 contract bytes differ")
	}
	var extra [1]byte
	if count, err := writer.ReadAt(extra[:], int64(len(expectedData))); count != 0 || !errors.Is(err, io.EOF) {
		return errors.New("sealed E8 contract exceeds expected size")
	}
	if _, err := writer.Write([]byte{0}); !errors.Is(err, unix.EPERM) {
		return errors.New("sealed E8 contract accepted write")
	}
	if _, err := writer.WriteAt([]byte{0}, 0); !errors.Is(err, unix.EPERM) {
		return errors.New("sealed E8 contract accepted pwrite")
	}
	if err := writer.Truncate(0); !errors.Is(err, unix.EPERM) {
		return errors.New("sealed E8 contract accepted ftruncate")
	}
	mapping, err := unix.Mmap(
		int(writer.Fd()), 0, 1,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED,
	)
	if err == nil {
		_ = unix.Munmap(mapping)
		return errors.New("sealed E8 contract accepted writable mmap")
	}
	if !errors.Is(err, unix.EPERM) {
		return fmt.Errorf(
			"sealed E8 contract writable mmap returned unexpected error: %w",
			err,
		)
	}
	return nil
}

func sendE8SealedContractReady(conn net.Conn, contract *os.File) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok || contract == nil {
		return errors.New("E8 Android contract channel is invalid")
	}
	control := unix.UnixRights(int(contract.Fd()))
	count, controlCount, err := unixConn.WriteMsgUnix(
		[]byte("contract-ready"), control, nil,
	)
	if err != nil || count != len("contract-ready") ||
		controlCount != len(control) {
		return errors.Join(
			errors.New("send sealed E8 Android contract capability"), err,
		)
	}
	return nil
}

func linuxProcessStartTicks(pid int) (uint64, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	closeIndex := strings.LastIndexByte(string(data), ')')
	if closeIndex < 0 {
		return 0, errors.New("invalid process stat")
	}
	fields := strings.Fields(string(data[closeIndex+2:]))
	if len(fields) <= 19 {
		return 0, errors.New("short process stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func syscallKillGroup(pid int) error {
	return unix.Kill(-pid, unix.SIGKILL)
}

func verifyE8SandboxStatus(pid int) (uint64, string, error) {
	taskRoot := "/proc/" + strconv.Itoa(pid) + "/task"
	root, err := os.OpenRoot(taskRoot)
	if err != nil {
		return 0, "", err
	}
	defer root.Close()
	entries, err := os.ReadDir(taskRoot)
	if err != nil {
		return 0, "", err
	}
	if len(entries) == 0 || len(entries) > 64 {
		return 0, "", errors.New("E8 sandbox thread census is empty or oversized")
	}
	required := map[string]string{
		"NoNewPrivs:": "1", "Seccomp:": "2",
		"CapInh:": "0000000000000000",
		"CapPrm:": "0000000000000000",
		"CapEff:": "0000000000000000",
		"CapBnd:": "0000000000000000",
		"CapAmb:": "0000000000000000",
	}
	rows := make([]string, 0, len(entries))
	for _, entry := range entries {
		tid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || tid <= 0 {
			return 0, "", errors.New("E8 sandbox thread identity is invalid")
		}
		status, openErr := root.Open(entry.Name() + "/status")
		if openErr != nil {
			return 0, "", openErr
		}
		data, readErr := io.ReadAll(
			io.LimitReader(status, e8LocalRehearsalMaxBytes+1),
		)
		closeErr := status.Close()
		if readErr != nil || closeErr != nil ||
			len(data) > e8LocalRehearsalMaxBytes {
			if readErr != nil {
				return 0, "", readErr
			}
			if closeErr != nil {
				return 0, "", closeErr
			}
			return 0, "", errors.New("E8 sandbox status exceeds bound")
		}
		if len(data) == 0 {
			return 0, "", errors.New("E8 sandbox status is empty")
		}
		found := map[string]string{}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				if _, ok := required[fields[0]]; ok {
					found[fields[0]] = fields[1]
				}
			}
		}
		for key, expected := range required {
			if found[key] != expected {
				return 0, "", fmt.Errorf(
					"E8 child thread %d kernel sandbox status has %s=%q",
					tid, key, found[key],
				)
			}
		}
		rows = append(rows, fmt.Sprintf(
			"tid=%d;nonewprivs=1;seccomp=2;capinh=0;capprm=0;capeff=0;capbnd=0;capamb=0",
			tid,
		))
	}
	sort.Strings(rows)
	digest, err := admittedDigest("winn-e8-r3-sandbox-thread-census/v1", rows)
	return uint64(len(rows)), digest, err
}

func requireE8ChannelEOF(conn net.Conn) error {
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	count, err := conn.Read(one[:])
	if count != 0 || !errors.Is(err, io.EOF) {
		return errors.New("E8 parent did not observe capability-channel EOF")
	}
	return nil
}

func publishE8Receipt(
	directory *secureDirectory, data []byte, expected e8Receipt,
) error {
	if len(data) == 0 || len(data) > e8ReceiptMaxBytes {
		return errors.New("E8 publication bytes are invalid")
	}
	pending := "." + e8ReceiptFile + ".pending"
	if _, err := directory.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	entries, err := directory.ReadDir()
	if err != nil || len(entries) > 1 {
		return errors.New("E8 publication root has an invalid artifact census")
	}
	existing := ""
	if len(entries) == 1 {
		existing = entries[0].Name()
		if entries[0].IsDir() ||
			(existing != pending && existing != e8ReceiptFile) {
			return errors.New("E8 publication root contains an unknown artifact")
		}
	}
	cleanupPending := func() {
		// #nosec G115 -- secureDirectory owns a live Linux descriptor.
		_ = unix.Unlinkat(int(directory.file.Fd()), pending, 0)
	}
	authenticate := func(name string) error {
		file, err := openAdmittedPrivateFileMode(
			directory, name, os.O_RDONLY, 0, 0o400,
		)
		if err != nil {
			return err
		}
		defer file.Close()
		replayed, err := io.ReadAll(io.LimitReader(file, e8ReceiptMaxBytes+1))
		if err != nil || !bytes.Equal(replayed, data) {
			return errors.New("E8 recovery artifact bytes differ")
		}
		var value e8Receipt
		if err := decodeStrictObject(replayed, &value); err != nil ||
			validateE8Receipt(value) != nil || value != expected {
			return errors.New("E8 recovery artifact is unauthenticated")
		}
		return nil
	}
	if existing == e8ReceiptFile {
		if err := authenticate(e8ReceiptFile); err != nil {
			return err
		}
		if err := syncE8DirectoryOperation(directory); err != nil {
			return &e8PublicationError{
				Stage:                "recovered-final-directory-fsync",
				FinalReceiptMayExist: true, ReceiptAuthenticated: true,
			}
		}
		return nil
	}
	if existing == pending {
		if err := authenticate(pending); err != nil {
			return err
		}
	} else {
		file, err := openAdmittedPrivateFileMode(
			directory, pending,
			os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400, 0o400,
		)
		if err != nil {
			return err
		}
		if err := writeE8ReceiptOperation(file, data); err != nil {
			_ = file.Close()
			cleanupPending()
			return err
		}
		if err := syncE8ReceiptOperation(file); err != nil {
			_ = file.Close()
			cleanupPending()
			return err
		}
		if err := closeE8ReceiptOperation(file); err != nil {
			cleanupPending()
			return err
		}
	}
	if err := renameE8ReceiptOperation(directory); err != nil {
		return err
	}
	if err := syncE8DirectoryOperation(directory); err != nil {
		return &e8PublicationError{
			Stage: "parent-directory-fsync", FinalReceiptMayExist: true,
		}
	}
	if err := authenticate(e8ReceiptFile); err != nil {
		return &e8PublicationError{
			Stage: "durable-readback-authentication", FinalReceiptMayExist: true,
			DirectorySynced: true,
		}
	}
	return nil
}
