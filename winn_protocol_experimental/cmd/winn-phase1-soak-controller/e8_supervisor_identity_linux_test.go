//go:build linux && winn_incomplete_e8

package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Supervisor identity and durable nonce ledger behaviour. These exercise the
// two implementer notes that are observable without the Linux rehearsal
// runtime: retained-descriptor identity binding with io.Closer ownership, and
// crash-persistent single-use nonce consumption.

func e8TestRunningSupervisor(t *testing.T) (string, string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	held, digest, err := openAndDigestPinnedFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	return executable, digest
}

func TestE8SupervisorIdentityAdmitsRunningImage(t *testing.T) {
	executable, digest := e8TestRunningSupervisor(t)
	identity, err := verifyE8SupervisorIdentity(e6VerificationReceipt{
		SupervisorExecutablePath:   executable,
		SupervisorExecutableSHA256: digest,
	})
	if err != nil {
		t.Fatalf("running supervisor image was rejected: %v", err)
	}
	if identity == nil {
		t.Fatal("running supervisor image produced no identity")
	}
	defer func() {
		if err := identity.Close(); err != nil {
			t.Fatalf("close returned %v", err)
		}
	}()
	if !digestPattern.MatchString(identity.ObjectDigest) {
		t.Fatalf("identity digest is malformed: %q", identity.ObjectDigest)
	}
	if identity.SHA256 != digest || identity.Path != executable {
		t.Fatalf("identity did not bind the declared executable: %+v", identity)
	}
	if identity.Device == 0 || identity.Inode == 0 ||
		identity.Size <= 0 || identity.Mode&0o111 == 0 {
		t.Fatalf("identity measurement is incomplete: %+v", identity)
	}
	expected, err := e8SupervisorIdentityDigest(identity)
	if err != nil || expected != identity.ObjectDigest {
		t.Fatalf("identity digest does not re-derive: %q %v", expected, err)
	}
}

// TestE8SupervisorIdentityRejectsSameBytesAtDifferentInodeLocal mirrors the
// Linux-only acceptance test so the inode-substitution boundary is exercised
// wherever the subsystem compiles.
func TestE8SupervisorIdentityRejectsSameBytesAtDifferentInodeLocal(t *testing.T) {
	executable, digest := e8TestRunningSupervisor(t)
	data, err := os.ReadFile(executable) // #nosec G304 -- test reads its own binary.
	if err != nil {
		t.Fatal(err)
	}
	root := privateTestDirectory(t)
	copyPath := filepath.Join(root, "same-bytes-different-inode")
	if err := os.WriteFile(copyPath, data, 0o500); err != nil {
		t.Fatal(err)
	}
	identity, err := verifyE8SupervisorIdentity(e6VerificationReceipt{
		SupervisorExecutablePath:   copyPath,
		SupervisorExecutableSHA256: digest,
	})
	if err == nil {
		if identity != nil {
			_ = identity.Close()
		}
		t.Fatal("E8 accepted mutable-path equivalence without inode equality")
	}
	if identity != nil {
		t.Fatal("rejected verification still returned an identity")
	}
	if !strings.Contains(err.Error(), "not the running supervisor image") {
		t.Fatalf("unexpected rejection reason: %v", err)
	}
}

func TestE8SupervisorIdentityRejectsReplacedExecutablePath(t *testing.T) {
	executable, digest := e8TestRunningSupervisor(t)
	data, err := os.ReadFile(executable) // #nosec G304 -- test reads its own binary.
	if err != nil {
		t.Fatal(err)
	}
	backup := executable + ".executing-image"
	replacement := executable + ".replacement"
	if err := os.WriteFile(replacement, data, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(executable, backup); err != nil {
		_ = os.Remove(replacement)
		t.Fatal(err)
	}
	if err := os.Rename(replacement, executable); err != nil {
		_ = os.Rename(backup, executable)
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(executable); err != nil {
			t.Errorf("remove replacement executable: %v", err)
			return
		}
		if err := os.Rename(backup, executable); err != nil {
			t.Errorf("restore executing image path: %v", err)
		}
	}()

	identity, err := verifyE8SupervisorIdentity(e6VerificationReceipt{
		SupervisorExecutablePath:   executable,
		SupervisorExecutableSHA256: digest,
	})
	if err == nil {
		if identity != nil {
			_ = identity.Close()
		}
		t.Fatal("E8 admitted pathname replacement as the running image")
	}
	if identity != nil {
		t.Fatal("replaced-path rejection returned retained identity")
	}
	if !strings.Contains(err.Error(), "not the running supervisor image") {
		t.Fatalf("unexpected pathname-replacement rejection: %v", err)
	}
}

func TestE8SupervisorIdentityRejectsMalformedDeclarations(t *testing.T) {
	_, digest := e8TestRunningSupervisor(t)
	cases := []struct {
		name    string
		receipt e6VerificationReceipt
	}{
		{"relative path", e6VerificationReceipt{
			SupervisorExecutablePath:   "relative/supervisor",
			SupervisorExecutableSHA256: digest,
		}},
		{"empty path", e6VerificationReceipt{
			SupervisorExecutableSHA256: digest,
		}},
		{"uncleaned path", e6VerificationReceipt{
			SupervisorExecutablePath:   "/tmp/../tmp/supervisor",
			SupervisorExecutableSHA256: digest,
		}},
		{"malformed digest", e6VerificationReceipt{
			SupervisorExecutablePath:   "/usr/bin/true",
			SupervisorExecutableSHA256: "not-a-digest",
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			identity, err := verifyE8SupervisorIdentity(testCase.receipt)
			if err == nil {
				if identity != nil {
					_ = identity.Close()
				}
				t.Fatal("malformed declaration was admitted")
			}
			if identity != nil {
				t.Fatal("rejected verification retained an identity")
			}
		})
	}
}

func TestE8SupervisorIdentityCloseIsNilSafeAndIdempotent(t *testing.T) {
	var absent *e8SupervisorIdentity
	if err := absent.Close(); err != nil {
		t.Fatalf("nil identity close returned %v", err)
	}
	executable, digest := e8TestRunningSupervisor(t)
	identity, err := verifyE8SupervisorIdentity(e6VerificationReceipt{
		SupervisorExecutablePath:   executable,
		SupervisorExecutableSHA256: digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Close(); err != nil {
		t.Fatalf("first close returned %v", err)
	}
	if err := identity.Close(); err != nil {
		t.Fatalf("second close returned %v", err)
	}
}

func e8TestGrant() e8GrantResult {
	return e8GrantResult{
		GrantObjectDigest: strings.Repeat("a", 64),
		CollectionDigest:  strings.Repeat("b", 64),
	}
}

func TestE8NonceLedgerIsSingleUseAndCrashPersistent(t *testing.T) {
	root := privateTestDirectory(t)
	directory := openTestSecureDirectory(t, root)
	defer func() { _ = directory.Close() }()
	grant := e8TestGrant()
	nonce := strings.Repeat("c", 32)

	ledger, err := openE8NonceLedger(directory, grant)
	if err != nil {
		t.Fatal(err)
	}
	consumed, err := ledger.Consumed(nonce)
	if err != nil || consumed {
		t.Fatalf("fresh nonce reported consumed=%v err=%v", consumed, err)
	}
	if err := ledger.Consume(nonce); err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	consumed, err = ledger.Consumed(nonce)
	if err != nil || !consumed {
		t.Fatalf("consumed nonce reported consumed=%v err=%v", consumed, err)
	}
	if err := ledger.Consume(nonce); err == nil {
		t.Fatal("replayed nonce was admitted")
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening the ledger models a restart after a crash: the consumption
	// record must still forbid replay.
	reopened, err := openE8NonceLedger(directory, grant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	consumed, err = reopened.Consumed(nonce)
	if err != nil || !consumed {
		t.Fatalf("consumption did not survive reopen: %v %v", consumed, err)
	}
	if err := reopened.Consume(nonce); err == nil {
		t.Fatal("replay was admitted after reopen")
	}
}

func TestE8NonceLedgerScopesByGrantAndRejectsMalformedNonces(t *testing.T) {
	root := privateTestDirectory(t)
	directory := openTestSecureDirectory(t, root)
	defer func() { _ = directory.Close() }()
	nonce := strings.Repeat("d", 32)

	first := e8TestGrant()
	ledger, err := openE8NonceLedger(directory, first)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Consume(nonce); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	second := e8TestGrant()
	second.CollectionDigest = strings.Repeat("e", 64)
	other, err := openE8NonceLedger(directory, second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	consumed, err := other.Consumed(nonce)
	if err != nil || consumed {
		t.Fatalf("nonce leaked across grant scopes: %v %v", consumed, err)
	}

	for _, malformed := range []string{
		"", "short", strings.Repeat("z", 32), strings.Repeat("a", 64),
	} {
		if err := other.Consume(malformed); err == nil {
			t.Fatalf("malformed nonce %q was consumed", malformed)
		}
	}
	if _, err := openE8NonceLedger(directory, e8GrantResult{}); err == nil {
		t.Fatal("ledger opened for a malformed grant identity")
	}
}

func TestE8NonceLedgerRunCatalogRecoversExactBindingAndRejectsCopy(
	t *testing.T,
) {
	root := privateTestDirectory(t)
	directory := openTestSecureDirectory(t, root)
	defer func() { _ = directory.Close() }()
	grant := e8TestGrant()
	grant.Grant.RehearsalNonce = strings.Repeat("f", 32)
	binding := e8NonceLedgerBinding{
		GrantRootDevice: 11,
		GrantRootInode:  12,
		OutputDevice:    13,
		OutputInode:     14,
	}
	ledger, err := openE8NonceLedger(directory, grant)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ledger.ReserveRun(grant.Grant.RehearsalNonce, binding)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := ledger.ReserveRun(grant.Grant.RehearsalNonce, binding)
	if err != nil || recovered != first {
		t.Fatalf("exact nonce catalog recovery failed: %v %v", recovered, err)
	}
	copiedRoot := binding
	copiedRoot.GrantRootInode++
	if _, err := ledger.ReserveRun(
		grant.Grant.RehearsalNonce,
		copiedRoot,
	); err == nil {
		t.Fatal("copied grant root replay recovered the nonce catalog")
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestE8NonceLedgerTornClaimPermanentlyFailsClosed(t *testing.T) {
	root := privateTestDirectory(t)
	directory := openTestSecureDirectory(t, root)
	defer func() { _ = directory.Close() }()
	grant := e8TestGrant()
	grant.Grant.RehearsalNonce = strings.Repeat("1", 32)
	binding := e8NonceLedgerBinding{
		GrantRootDevice: 21,
		GrantRootInode:  22,
		OutputDevice:    23,
		OutputInode:     24,
	}
	ledger, err := openE8NonceLedger(directory, grant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ledger.Close() }()
	oldWrite := e8NonceLedgerWriteOperation
	e8NonceLedgerWriteOperation = func(writer io.Writer, data []byte) error {
		_, _ = writer.Write(data[:len(data)/2])
		return io.ErrShortWrite
	}
	_, firstErr := ledger.ReserveRun(grant.Grant.RehearsalNonce, binding)
	e8NonceLedgerWriteOperation = oldWrite
	if !errors.Is(firstErr, io.ErrShortWrite) &&
		(firstErr == nil || !strings.Contains(firstErr.Error(), "not writable")) {
		t.Fatalf("torn claim injection did not fail: %v", firstErr)
	}
	if _, err := ledger.ReserveRun(
		grant.Grant.RehearsalNonce,
		binding,
	); err == nil || !strings.Contains(err.Error(), "torn prior claim") {
		t.Fatalf("torn nonce claim was reusable: %v", err)
	}
}

func exerciseE8NonceDurability(
	rootPath string,
	grant e8GrantResult,
	binding e8NonceLedgerBinding,
) (nonces [4]string, returnErr error) {
	parent, err := openSecureDirectory(filepath.Dir(rootPath))
	if err != nil {
		return nonces, err
	}
	defer func() { returnErr = errors.Join(returnErr, parent.Close()) }()
	root, err := openE8DurableDirectory(
		parent, filepath.Base(rootPath), "controller-root",
	)
	if err != nil {
		return nonces, err
	}
	defer func() { returnErr = errors.Join(returnErr, root.Close()) }()
	ledger, err := openE8NonceLedger(root, grant)
	if err != nil {
		return nonces, err
	}
	defer func() { returnErr = errors.Join(returnErr, ledger.Close()) }()
	return ledger.ReserveRun(grant.Grant.RehearsalNonce, binding)
}

func e8NonceDurabilityTestInputs() (
	e8GrantResult,
	e8NonceLedgerBinding,
) {
	grant := e8TestGrant()
	grant.Grant.RehearsalNonce = strings.Repeat("2", 32)
	return grant, e8NonceLedgerBinding{
		GrantRootDevice: 31,
		GrantRootInode:  32,
		OutputDevice:    33,
		OutputInode:     34,
	}
}

func TestE8NonceLedgerFaultsAtEveryNamespaceAndClaimBoundary(t *testing.T) {
	stages := []string{
		"controller-root-mkdir",
		"controller-root-directory-sync",
		"controller-root-parent-sync",
		"ledger-base-mkdir",
		"ledger-base-directory-sync",
		"ledger-base-parent-sync",
		"grant-scope-mkdir",
		"grant-scope-directory-sync",
		"grant-scope-parent-sync",
		"claim-name-created",
		"claim-name-directory-sync",
		"claim-payload-written",
		"claim-file-sync",
		"claim-file-close",
		"claim-final-directory-sync",
	}
	oldBoundary := e8NonceDurabilityBoundaryOperation
	defer func() { e8NonceDurabilityBoundaryOperation = oldBoundary }()
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			rootPath := filepath.Join(t.TempDir(), "controller-nonce-root")
			grant, binding := e8NonceDurabilityTestInputs()
			hit := false
			e8NonceDurabilityBoundaryOperation = func(actual string) error {
				if actual == stage && !hit {
					hit = true
					return errors.New("injected nonce durability fault")
				}
				return nil
			}
			if _, err := exerciseE8NonceDurability(
				rootPath, grant, binding,
			); err == nil || !hit {
				t.Fatalf("stage %q was not faulted: %v", stage, err)
			}
			e8NonceDurabilityBoundaryOperation = oldBoundary
			first, firstErr := exerciseE8NonceDurability(
				rootPath, grant, binding,
			)
			if firstErr != nil {
				if !strings.Contains(firstErr.Error(), "torn prior claim") {
					t.Fatalf("restart was neither recovery nor fail-closed: %v", firstErr)
				}
				return
			}
			second, err := exerciseE8NonceDurability(
				rootPath, grant, binding,
			)
			if err != nil || first != second {
				t.Fatalf("restart minted a different nonce catalog: %v %v", err, second)
			}
		})
	}
}

func TestE8NonceLedgerSubprocessSIGKILLHelper(t *testing.T) {
	if os.Getenv("WINN_E8_NONCE_SIGKILL_HELPER") != "1" {
		return
	}
	rootPath := os.Getenv("WINN_E8_NONCE_SIGKILL_ROOT")
	stage := os.Getenv("WINN_E8_NONCE_SIGKILL_STAGE")
	if rootPath == "" || stage == "" {
		t.Fatal("hard-stop helper environment is incomplete")
	}
	grant, binding := e8NonceDurabilityTestInputs()
	e8NonceDurabilityBoundaryOperation = func(actual string) error {
		if actual == stage {
			if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
				return err
			}
			select {}
		}
		return nil
	}
	if _, err := exerciseE8NonceDurability(rootPath, grant, binding); err != nil {
		t.Fatal(err)
	}
	t.Fatal("hard-stop helper reached normal return")
}

func TestE8NonceLedgerRecoversAfterRealSubprocessSIGKILL(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "controller-nonce-root")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(
		executable,
		"-test.run=^TestE8NonceLedgerSubprocessSIGKILLHelper$",
	)
	command.Env = append(
		os.Environ(),
		"WINN_E8_NONCE_SIGKILL_HELPER=1",
		"WINN_E8_NONCE_SIGKILL_ROOT="+rootPath,
		"WINN_E8_NONCE_SIGKILL_STAGE=claim-file-sync",
	)
	err = command.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) ||
		exitErr.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("helper was not stopped by SIGKILL: %v", err)
	}
	grant, binding := e8NonceDurabilityTestInputs()
	first, err := exerciseE8NonceDurability(rootPath, grant, binding)
	if err != nil {
		t.Fatalf("recover after SIGKILL: %v", err)
	}
	second, err := exerciseE8NonceDurability(rootPath, grant, binding)
	if err != nil || first != second {
		t.Fatalf("SIGKILL recovery was not idempotent: %v %v", err, second)
	}
}
