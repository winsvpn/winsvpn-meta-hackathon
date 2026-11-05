//go:build linux && winn_incomplete_e8

package main

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func testE8GrantResult() e8GrantResult {
	return e8GrantResult{
		Grant:             e8RehearsalGrant{RehearsalNonce: strings.Repeat("a", 32)},
		GrantObjectDigest: strings.Repeat("b", 64),
		CollectionDigest:  strings.Repeat("c", 64),
	}
}

func TestE8OneShotTransactionRecoversAndRejectsAnotherOutput(t *testing.T) {
	grantRoot := privateTestDirectory(t)
	outputRoot := privateTestDirectory(t)
	output, err := openAdmittedPrivateDirectory(outputRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	grant := testE8GrantResult()
	transaction, err := openE8Transaction(grantRoot, grant, output)
	if err != nil || transaction.phase() != "reserved" {
		t.Fatalf("reserve E8 grant: phase=%q err=%v", transaction.phase(), err)
	}
	if err := transaction.Close(); err != nil {
		t.Fatal(err)
	}
	transaction, err = openE8Transaction(grantRoot, grant, output)
	if err != nil || transaction.phase() != "reserved" {
		t.Fatalf("replay E8 reservation: phase=%q err=%v", transaction.phase(), err)
	}
	e3 := strings.Repeat("d", 64)
	receipt := strings.Repeat("e", 64)
	if err := transaction.recordE3(e3); err != nil {
		t.Fatal(err)
	}
	if err := transaction.recordChildren(e3); err != nil {
		t.Fatal(err)
	}
	if err := transaction.commit(e3, receipt); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Close(); err != nil {
		t.Fatal(err)
	}
	transaction, err = openE8Transaction(grantRoot, grant, output)
	if err != nil || transaction.phase() != "receipt-committed" {
		t.Fatalf("replay committed E8 transaction: %v", err)
	}
	_ = transaction.Close()

	otherRoot := privateTestDirectory(t)
	other, err := openAdmittedPrivateDirectory(otherRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if transaction, err := openE8Transaction(grantRoot, grant, other); err == nil {
		_ = transaction.Close()
		t.Fatal("one-shot E8 grant was replayed against another output inode")
	}
}

func TestE8ImmutableTransactionRepairsEveryTornRecord(t *testing.T) {
	phases := []string{"reserved", "e3-durable", "children-complete", "receipt-committed"}
	for target := range phases {
		t.Run(phases[target], func(t *testing.T) {
			grantRoot := privateTestDirectory(t)
			output, err := openAdmittedPrivateDirectory(privateTestDirectory(t))
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			grant := testE8GrantResult()
			e3, receipt := strings.Repeat("d", 64), strings.Repeat("e", 64)
			var transaction *e8Transaction
			if target > 0 {
				transaction, err = openE8Transaction(grantRoot, grant, output)
				if err != nil {
					t.Fatal(err)
				}
				if target > 1 {
					if err := transaction.recordE3(e3); err != nil {
						t.Fatal(err)
					}
				}
				if target > 2 {
					if err := transaction.recordChildren(e3); err != nil {
						t.Fatal(err)
					}
				}
			}
			oldWrite := writeAllOperation
			writeAllOperation = func(writer io.Writer, data []byte) error {
				_, _ = writer.Write(data[:len(data)/2])
				return errors.New("injected short immutable record")
			}
			if target == 0 {
				transaction, err = openE8Transaction(grantRoot, grant, output)
			} else if target == 1 {
				err = transaction.recordE3(e3)
			} else if target == 2 {
				err = transaction.recordChildren(e3)
			} else {
				err = transaction.commit(e3, receipt)
			}
			writeAllOperation = oldWrite
			if err == nil {
				t.Fatal("short immutable record was accepted")
			}
			if transaction != nil {
				_ = transaction.Close()
			}
			transaction, err = openE8Transaction(grantRoot, grant, output)
			if err != nil {
				t.Fatal(err)
			}
			wantPrior := ""
			if target > 0 {
				wantPrior = phases[target-1]
			}
			if target == 0 {
				wantPrior = "reserved"
			}
			if transaction.phase() != wantPrior {
				t.Fatalf("repair phase=%q want=%q", transaction.phase(), wantPrior)
			}
			_ = transaction.Close()
		})
	}
}

func TestPublishE8ReceiptRecoversPendingAndCommittedFiles(t *testing.T) {
	value, encoded := testEncodedE8Receipt(t)
	root := privateTestDirectory(t)
	pending := filepath.Join(root, "."+e8ReceiptFile+".pending")
	if err := os.WriteFile(pending, encoded, 0o400); err != nil {
		t.Fatal(err)
	}
	directory, err := openAdmittedPrivateDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := publishE8Receipt(directory, encoded, value); err != nil {
		t.Fatalf("recover pending E8 receipt: %v", err)
	}
	if _, err := os.Lstat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending E8 receipt survived recovery: %v", err)
	}
	if err := publishE8Receipt(directory, encoded, value); err != nil {
		t.Fatalf("idempotent committed E8 receipt replay: %v", err)
	}
}

func TestCleanupE8ChildrenReportsKillAndWaitFailuresAfterReap(t *testing.T) {
	command := exec.Command("sleep", "30")
	command.SysProcAttr = &unix.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	start, err := linuxProcessStartTicks(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	child := &e8Child{
		command: command, channel: left,
		pidfd:        os.NewFile(uintptr(pidfd), "test-e8-pidfd"),
		processStart: start,
	}
	oldKill := killE8PidfdOperation
	oldWait := waitE8ChildOperation
	killFailure := errors.New("injected pidfd kill evidence failure")
	waitFailure := errors.New("injected wait evidence failure")
	killE8PidfdOperation = func(file *os.File) error {
		realErr := unix.PidfdSendSignal(int(file.Fd()), unix.SIGKILL, nil, 0)
		return errors.Join(realErr, killFailure)
	}
	waitE8ChildOperation = func(command *exec.Cmd) error {
		return errors.Join(command.Wait(), waitFailure)
	}
	defer func() {
		killE8PidfdOperation = oldKill
		waitE8ChildOperation = oldWait
	}()
	err = cleanupE8Children([]*e8Child{child})
	if !errors.Is(err, killFailure) || !errors.Is(err, waitFailure) {
		t.Fatalf("cleanup suppressed lifecycle failures: %v", err)
	}
	if child.command.Process != nil || child.pidfd != nil || child.channel != nil {
		t.Fatal("cleanup retained process, pidfd, or channel capability")
	}
}

func TestRequireE8ChannelEOFRejectsLingeringCapabilityData(t *testing.T) {
	pair, err := unix.Socketpair(
		unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	leftFile := os.NewFile(uintptr(pair[0]), "e8-test-left")
	rightFile := os.NewFile(uintptr(pair[1]), "e8-test-right")
	left, err := net.FileConn(leftFile)
	_ = leftFile.Close()
	if err != nil {
		_ = rightFile.Close()
		t.Fatal(err)
	}
	right, err := net.FileConn(rightFile)
	_ = rightFile.Close()
	if err != nil {
		_ = left.Close()
		t.Fatal(err)
	}
	defer left.Close()
	defer right.Close()
	if _, err := right.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := requireE8ChannelEOF(left); err == nil {
		t.Fatal("E8 accepted lingering capability-channel data as EOF")
	}
}
