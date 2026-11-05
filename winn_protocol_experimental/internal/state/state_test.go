package state

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const testPeer = "nNOe1VBs+qdVjQGHgems9Xd3SO6gsrVl7+DM8y/EZAQ="

func TestOpenRejectsSymlinkStateLock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privilege varies on Windows")
	}
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "state.key")
	statePath := filepath.Join(directory, "controller.state")
	lockTarget := filepath.Join(directory, "lock-target")
	if err := securefile.AtomicWrite(keyPath, bytes.Repeat([]byte{0x31}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockTarget, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(lockTarget, statePath+".lock"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(statePath, keyPath, time.Hour, "controller-1", testSigner(t)); err == nil ||
		!strings.Contains(err.Error(), "regular file") {
		t.Fatalf("state lock symlink error = %v", err)
	}
}

func TestPrepareCommitReopenAndIdempotency(t *testing.T) {
	store, statePath, keyPath := newTestStore(t)
	request := testRequest(t, "request-one", 0)
	prepared, err := store.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Idempotent || prepared.Committed {
		t.Fatal("new preparation reported incorrect state")
	}

	encrypted, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte(prepared.Response.PresharedKey)) ||
		bytes.Contains(encrypted, []byte(request.DeviceID)) {
		t.Fatal("encrypted state exposes plaintext protocol state")
	}
	if err := store.Commit(context.Background(), request.RequestID); err != nil {
		t.Fatal(err)
	}
	clear(prepared.PSK)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(statePath, keyPath, time.Hour, "controller-1", testSigner(t))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	retry, err := reopened.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(retry.PSK)
	if !retry.Idempotent || !retry.Committed {
		t.Fatal("exact retry did not return the committed response")
	}
	if retry.Response.Generation != 1 {
		t.Fatalf("generation = %d, want 1", retry.Response.Generation)
	}
}

func TestPendingReplayAndGenerationGuards(t *testing.T) {
	store, _, _ := newTestStore(t)
	first := testRequest(t, "request-one", 0)
	prepared, err := store.Prepare(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(prepared.PSK)

	second := testRequest(t, "request-two", 0)
	if _, err := store.Prepare(context.Background(), second); !errors.Is(err, ErrRotationPending) {
		t.Fatalf("second pending rotation error = %v", err)
	}
	changed := first
	changed.Nonce = token(7)
	if _, err := store.Prepare(context.Background(), changed); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("request ID content replay error = %v", err)
	}
	if err := store.Commit(context.Background(), first.RequestID); err != nil {
		t.Fatal(err)
	}
	stale := testRequest(t, "request-three", 0)
	if _, err := store.Prepare(context.Background(), stale); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("stale generation error = %v", err)
	}
}

func TestRevokedDeviceCannotPrepare(t *testing.T) {
	store, _, _ := newTestStore(t)
	if err := store.Revoke(context.Background(), "device-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Prepare(context.Background(), testRequest(t, "request-one", 0)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked device error = %v", err)
	}
}

func TestWrongStateKeyFailsAuthentication(t *testing.T) {
	store, statePath, _ := newTestStore(t)
	prepared, err := store.Prepare(context.Background(), testRequest(t, "request-one", 0))
	if err != nil {
		t.Fatal(err)
	}
	clear(prepared.PSK)
	wrongKeyPath := filepath.Join(t.TempDir(), "wrong.key")
	if err := securefile.AtomicWrite(wrongKeyPath, bytes.Repeat([]byte{0x99}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(statePath, wrongKeyPath, time.Hour, "controller-1", testSigner(t)); err == nil {
		t.Fatal("encrypted state opened with the wrong key")
	}
}

func TestExclusiveLockPreventsSplitBrainAndReleasesOnClose(t *testing.T) {
	store, statePath, keyPath := newTestStore(t)
	if _, err := Open(statePath, keyPath, time.Hour, "controller-1", testSigner(t)); err == nil {
		t.Fatal("second file-state owner acquired an exclusive lock")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(statePath, keyPath, time.Hour, "controller-1", testSigner(t))
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAdministrativeOpenDoesNotRequireResponseSigningSeed(t *testing.T) {
	store, statePath, keyPath := newTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	admin, err := OpenAdministrative(statePath, keyPath, time.Hour, "controller-1")
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Prepare(context.Background(), testRequest(t, "request-one", 0)); err == nil {
		t.Fatal("administrative state prepared a signed rotation without a signer")
	}
}

func TestFailedPreparePersistenceRollsBackMemory(t *testing.T) {
	store, statePath, _ := newTestStore(t)
	request := testRequest(t, "request-one", 0)
	blocker := statePath + ".not-a-directory"
	if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	store.path = filepath.Join(blocker, "impossible")
	if _, err := store.Prepare(context.Background(), request); err == nil {
		t.Fatal("prepare unexpectedly persisted to an impossible path")
	}
	store.path = statePath
	prepared, err := store.Prepare(context.Background(), request)
	if err != nil {
		t.Fatalf("failed prepare poisoned in-memory state: %v", err)
	}
	defer clear(prepared.PSK)
	if prepared.Idempotent {
		t.Fatal("failed prepare was retained in memory")
	}
}

func TestFailedCommitPersistenceRollsBackMemory(t *testing.T) {
	store, statePath, _ := newTestStore(t)
	request := testRequest(t, "request-one", 0)
	prepared, err := store.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(prepared.PSK)
	blocker := statePath + ".not-a-directory"
	if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	store.path = filepath.Join(blocker, "impossible")
	if err := store.Commit(context.Background(), request.RequestID); err == nil {
		t.Fatal("commit unexpectedly persisted to an impossible path")
	}
	store.path = statePath
	retry, err := store.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(retry.PSK)
	if retry.Committed {
		t.Fatal("failed commit was retained in memory")
	}
	if err := store.Commit(context.Background(), request.RequestID); err != nil {
		t.Fatal(err)
	}
}

func TestAbortPendingRequiresExactBindingAndAllowsRecovery(t *testing.T) {
	store, _, _ := newTestStore(t)
	first := testRequest(t, "request-one", 0)
	prepared, err := store.Prepare(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(prepared.PSK)
	if err := store.AbortPending(context.Background(), first.DeviceID, first.PeerPublicKey, token(9)); err == nil {
		t.Fatal("abort accepted the wrong pending request ID")
	}
	if err := store.AbortPending(context.Background(), first.DeviceID, first.PeerPublicKey, first.RequestID); err != nil {
		t.Fatal(err)
	}
	second := testRequest(t, "request-two", 0)
	recovered, err := store.Prepare(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(recovered.PSK)
	if recovered.Response.Generation != 1 {
		t.Fatalf("recovered generation = %d, want 1", recovered.Response.Generation)
	}
}

func TestFileTunnelTransactionReconcilesAndSerializes(t *testing.T) {
	store, statePath, _ := newTestStore(t)
	request := testRequest(t, "transaction-one", 0)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	transaction, err := store.BeginTunnelTransaction(
		ctx, request.DeviceID, request.PeerPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := transaction.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(prepared.PSK)
	realPath := store.path
	store.path = filepath.Join(statePath, "impossible")
	if err := transaction.Commit(ctx, request.RequestID); err == nil {
		t.Fatal("commit unexpectedly succeeded through an impossible path")
	}
	store.path = realPath
	first, err := transaction.ReconcileCommitOutcome(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Disposition != CommitUncommitted ||
		!bytes.Equal(first.PSK, prepared.PSK) {
		t.Fatalf("uncommitted snapshot = %+v", first)
	}
	clear(first.PSK)
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer waitCancel()
	if _, err := store.BeginTunnelTransaction(
		waitCtx, request.DeviceID, request.PeerPublicKey,
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("same-tunnel contender error = %v", err)
	}
	second, err := transaction.ReconcileCommitOutcome(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(second.PSK)
	if second.Disposition != CommitUncommitted ||
		!bytes.Equal(second.PSK, prepared.PSK) {
		t.Fatalf("second uncommitted snapshot = %+v", second)
	}
	if err := transaction.Release(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestFileReconcileRejectsAuthenticatedSwapBackABA(t *testing.T) {
	store, statePath, _ := newTestStore(t)
	request := testRequest(t, "transaction-aba", 0)
	transaction, err := store.BeginTunnelTransaction(
		context.Background(), request.DeviceID, request.PeerPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := transaction.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(prepared.PSK)

	directory := filepath.Dir(statePath)
	originalA := filepath.Join(directory, "original-a.state")
	replacementB := filepath.Join(directory, "replacement-b.state")
	current, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacementB, current, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(current)
	if err := os.Rename(statePath, originalA); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacementB, statePath); err != nil {
		t.Fatal(err)
	}

	realPath := store.path
	blocker := filepath.Join(directory, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	store.path = filepath.Join(blocker, "state")
	if err := transaction.Commit(context.Background(), request.RequestID); err == nil {
		t.Fatal("commit unexpectedly succeeded")
	}
	store.path = realPath

	swappedB := filepath.Join(directory, "observed-b.state")
	store.reconcileHook = func() {
		store.reconcileHook = nil
		if err := os.Rename(statePath, swappedB); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(originalA, statePath); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := transaction.ReconcileCommitOutcome(context.Background(), request)
	clear(snapshot.PSK)
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("authenticated B-read/A-restore error = %v", err)
	}
	if err := transaction.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestFileTransactionRejectsRepeatedPrepareCommitAndReconcile(t *testing.T) {
	store, _, _ := newTestStore(t)
	request := testRequest(t, "transaction-repeat", 0)
	transaction, err := store.BeginTunnelTransaction(
		context.Background(), request.DeviceID, request.PeerPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := transaction.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	clear(prepared.PSK)
	if _, err := transaction.Prepare(context.Background(), request); err == nil {
		t.Fatal("repeated Prepare was accepted")
	}
	if err := transaction.Commit(context.Background(), request.RequestID); err == nil {
		t.Fatal("Commit after invalid repeated Prepare was accepted")
	}
	if _, err := transaction.ReconcileCommitOutcome(context.Background(), request); err == nil {
		t.Fatal("Reconcile after invalid transition was accepted")
	}
	if err := transaction.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestFileTunnelReleaseFailurePoisonsEntry(t *testing.T) {
	store, _, _ := newTestStore(t)
	request := testRequest(t, "transaction-release", 0)
	transaction, err := store.BeginTunnelTransaction(
		context.Background(), request.DeviceID, request.PeerPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := transaction.Release(cancelled); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("cancelled release error = %v", err)
	}
	if _, err := store.BeginTunnelTransaction(
		context.Background(), request.DeviceID, request.PeerPublicKey,
	); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("poisoned entry acquisition error = %v", err)
	}
}

func TestFileReleaseRemovalFailureRetainsPoisonedEntry(t *testing.T) {
	store, _, _ := newTestStore(t)
	request := testRequest(t, "release-removal", 0)
	transaction, err := store.BeginTunnelTransaction(
		context.Background(), request.DeviceID, request.PeerPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	store.releaseVerify = func(*fileTunnelLease) error {
		return errors.New("injected registry verification failure")
	}
	if err := transaction.Release(context.Background()); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("release error = %v", err)
	}
	store.releaseVerify = nil
	if _, err := store.BeginTunnelTransaction(
		context.Background(), request.DeviceID, request.PeerPublicKey,
	); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("poisoned registry acquisition error = %v", err)
	}
}

func TestFileReleaseWaiterWakesAndFailsBeforePrepare(t *testing.T) {
	store, _, _ := newTestStore(t)
	request := testRequest(t, "release-waiter", 0)
	transaction, err := store.BeginTunnelTransaction(
		context.Background(), request.DeviceID, request.PeerPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := store.BeginTunnelTransaction(
			context.Background(), request.DeviceID, request.PeerPublicKey,
		)
		result <- err
	}()
	store.releaseVerify = func(*fileTunnelLease) error {
		return errors.New("injected registry verification failure")
	}
	if err := transaction.Release(context.Background()); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrReconciliationRequired) {
			t.Fatalf("waiter error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter did not wake boundedly")
	}
}

func TestStaleOrDoubleReleaseCannotDeleteCurrentEntry(t *testing.T) {
	store, _, _ := newTestStore(t)
	request := testRequest(t, "release-stale", 0)
	transaction, err := store.BeginTunnelTransaction(
		context.Background(), request.DeviceID, request.PeerPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Release(context.Background()); err == nil {
		t.Fatal("double release succeeded")
	}
	current, err := store.BeginTunnelTransaction(
		context.Background(), request.DeviceID, request.PeerPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Release(context.Background()); err == nil {
		t.Fatal("stale release deleted or affected current ownership")
	}
	if err := current.Lease().Validate(context.Background()); err != nil {
		t.Fatalf("current lease was damaged by stale release: %v", err)
	}
	if err := current.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func newTestStore(t *testing.T) (*Store, string, string) {
	t.Helper()
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "state.key")
	if err := securefile.AtomicWrite(keyPath, bytes.Repeat([]byte{0x42}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(directory, "controller.state")
	store, err := Open(statePath, keyPath, time.Hour, "controller-1", testSigner(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, statePath, keyPath
}

func testRequest(t *testing.T, id string, generation uint64) protocol.RekeyRequest {
	t.Helper()
	request := protocol.RekeyRequest{
		Version:           protocol.Version,
		Suite:             protocol.DefaultSuite,
		ControllerID:      "controller-1",
		DeviceID:          "device-1",
		PeerPublicKey:     testPeer,
		RequestID:         tokenForString(id),
		Nonce:             token(2),
		CurrentGeneration: generation,
		Capabilities:      protocol.RequiredCapabilities(protocol.DefaultSuite),
	}
	if err := pqauth.SignRequest(&request, testSigner(t)); err != nil {
		t.Fatal(err)
	}
	return request
}

func testSigner(t *testing.T) *pqauth.Signer {
	t.Helper()
	signer, err := pqauth.NewSigner(protocol.RequiredAuthAlgorithm(protocol.DefaultSuite), bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func token(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func tokenForString(value string) string {
	data := make([]byte, 32)
	copy(data, []byte(value))
	return base64.RawURLEncoding.EncodeToString(data)
}
