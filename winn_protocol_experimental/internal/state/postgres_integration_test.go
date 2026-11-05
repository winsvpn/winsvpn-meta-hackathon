package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const postgresTestController = "controller-pg-integration"

func TestPostgresGenerationConversionsAreBoundsChecked(t *testing.T) {
	if _, err := generationFromDatabase(-1); err == nil {
		t.Fatal("negative PostgreSQL generation was accepted")
	}
	maximum, err := generationFromDatabase(int64(protocol.MaxGeneration))
	if err != nil || maximum != protocol.MaxGeneration {
		t.Fatalf("maximum PostgreSQL generation conversion = %d, %v", maximum, err)
	}
	databaseMaximum, err := generationToDatabase(protocol.MaxGeneration)
	if err != nil || databaseMaximum != int64(protocol.MaxGeneration) {
		t.Fatalf("maximum protocol generation conversion = %d, %v", databaseMaximum, err)
	}
	if _, err := generationToDatabase(protocol.MaxGeneration + 1); err == nil {
		t.Fatal("generation above PostgreSQL bigint range was accepted")
	}
}

func TestPostgresStoreTransactionsEncryptionAndCrossInstanceState(t *testing.T) {
	dsn := os.Getenv("WINN_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("WINN_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "state.key")
	if err := securefile.AtomicWrite(keyPath, bytes.Repeat([]byte{0x51}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t)
	first := openPostgresTest(t, ctx, dsn, keyPath, postgresTestController, signer)
	cleanPostgresController(t, ctx, first, postgresTestController)
	defer func() {
		cleanPostgresController(t, context.Background(), first, postgresTestController)
		first.Close()
	}()

	request := postgresRequest(t, signer, postgresTestController, "device-pg-1", "request-pg-one", 0)
	prepared, err := first.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(prepared.PSK)
	var encrypted []byte
	if err := first.pool.QueryRow(
		ctx,
		`SELECT response_envelope FROM winn_requests WHERE controller_id=$1 AND request_id=$2`,
		postgresTestController,
		request.RequestID,
	).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte(prepared.Response.PresharedKey)) ||
		bytes.Contains(encrypted, prepared.PSK) {
		t.Fatal("PostgreSQL response envelope exposes the PSK")
	}

	second := openPostgresTest(t, ctx, dsn, keyPath, postgresTestController, signer)
	defer second.Close()
	retry, err := second.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(retry.PSK)
	if !retry.Idempotent || retry.Committed || !bytes.Equal(prepared.PSK, retry.PSK) {
		t.Fatal("second controller instance did not observe the exact pending response")
	}
	if err := second.Commit(ctx, request.RequestID); err != nil {
		t.Fatal(err)
	}
	committed, err := first.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(committed.PSK)
	if !committed.Idempotent || !committed.Committed {
		t.Fatal("committed response was not visible across controller instances")
	}
	snapshot, err := first.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Peers) != 1 || snapshot.Peers[0].Generation != 1 {
		t.Fatalf("unexpected PostgreSQL snapshot: %+v", snapshot)
	}

	wrongKeyPath := filepath.Join(directory, "wrong-state.key")
	if err := securefile.AtomicWrite(wrongKeyPath, bytes.Repeat([]byte{0x72}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongKeyStore := openPostgresTest(t, ctx, dsn, wrongKeyPath, postgresTestController, signer)
	if _, err := wrongKeyStore.Prepare(ctx, request); err == nil ||
		!strings.Contains(err.Error(), "authentication failed") {
		wrongKeyStore.Close()
		t.Fatalf("wrong at-rest key error = %v", err)
	}
	wrongKeyStore.Close()

	if err := second.Revoke(ctx, request.DeviceID); err != nil {
		t.Fatal(err)
	}
	next := postgresRequest(t, signer, postgresTestController, request.DeviceID, "request-pg-two", 1)
	if _, err := first.Prepare(ctx, next); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked device error = %v", err)
	}
}

func TestPostgresStoreSerializesCompetingRotations(t *testing.T) {
	dsn := os.Getenv("WINN_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("WINN_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	keyPath := filepath.Join(t.TempDir(), "state.key")
	if err := securefile.AtomicWrite(keyPath, bytes.Repeat([]byte{0x63}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t)
	controllerID := "controller-pg-race"
	store := openPostgresTest(t, ctx, dsn, keyPath, controllerID, signer)
	cleanPostgresController(t, ctx, store, controllerID)
	defer func() {
		cleanPostgresController(t, context.Background(), store, controllerID)
		store.Close()
	}()

	requests := []protocol.RekeyRequest{
		postgresRequest(t, signer, controllerID, "device-race-1", "request-race-one", 0),
		postgresRequest(t, signer, controllerID, "device-race-1", "request-race-two", 0),
	}
	type result struct {
		prepared Prepared
		err      error
	}
	results := make(chan result, len(requests))
	var group sync.WaitGroup
	for _, request := range requests {
		request := request
		group.Add(1)
		go func() {
			defer group.Done()
			prepared, err := store.Prepare(ctx, request)
			results <- result{prepared: prepared, err: err}
		}()
	}
	group.Wait()
	close(results)
	successes := 0
	pending := 0
	successfulRequestID := ""
	for outcome := range results {
		if outcome.err == nil {
			successes++
			successfulRequestID = outcome.prepared.Response.RequestID
			clear(outcome.prepared.PSK)
			continue
		}
		if errors.Is(outcome.err, ErrRotationPending) {
			pending++
			continue
		}
		t.Fatalf("unexpected competing rotation error: %v", outcome.err)
	}
	if successes != 1 || pending != 1 {
		t.Fatalf("competing outcomes successes=%d pending=%d", successes, pending)
	}
	if err := store.AbortPending(ctx, "device-race-1", testPeer, successfulRequestID); err != nil {
		t.Fatal(err)
	}
	for _, request := range requests {
		if request.RequestID == successfulRequestID {
			continue
		}
		recovered, err := store.Prepare(ctx, request)
		if err != nil {
			t.Fatalf("rotation did not recover after exact abort: %v", err)
		}
		clear(recovered.PSK)
	}
}

func TestPostgresTunnelTransactionMaxConnectionsOne(t *testing.T) {
	dsn := os.Getenv("WINN_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("WINN_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	keyPath := filepath.Join(t.TempDir(), "state.key")
	if err := securefile.AtomicWrite(keyPath, bytes.Repeat([]byte{0x64}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t)
	controllerID := "controller-pg-held-one"
	store := openPostgresTestWithLimit(t, ctx, dsn, keyPath, controllerID, signer, 1)
	cleanPostgresController(t, ctx, store, controllerID)
	defer store.Close()
	request := postgresRequest(t, signer, controllerID, "device-held-one", "held-one", 0)
	transaction, err := store.BeginTunnelTransaction(ctx, request.DeviceID, request.PeerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := transaction.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(prepared.PSK)
	if acquired := store.pool.Stat().AcquiredConns(); acquired != 1 {
		t.Fatalf("acquired connections = %d, want exactly retained one", acquired)
	}
	if err := transaction.Commit(ctx, request.RequestID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := transaction.ReconcileCommitOutcome(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	clear(snapshot.PSK)
	if snapshot.Disposition != CommitCommitted {
		t.Fatalf("reconciled disposition = %v", snapshot.Disposition)
	}
	if acquired := store.pool.Stat().AcquiredConns(); acquired != 1 {
		t.Fatalf("held operations checked out another connection: %d", acquired)
	}
	if err := transaction.Release(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresNTransactionsUseExactlyNConnections(t *testing.T) {
	dsn := os.Getenv("WINN_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("WINN_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	keyPath := filepath.Join(t.TempDir(), "state.key")
	if err := securefile.AtomicWrite(keyPath, bytes.Repeat([]byte{0x65}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t)
	controllerID := "controller-pg-held-n"
	store := openPostgresTestWithLimit(t, ctx, dsn, keyPath, controllerID, signer, 2)
	cleanPostgresController(t, ctx, store, controllerID)
	defer store.Close()
	requests := []protocol.RekeyRequest{
		postgresRequest(t, signer, controllerID, "device-held-a", "held-a", 0),
		postgresRequest(t, signer, controllerID, "device-held-b", "held-b", 0),
	}
	var transactions []TunnelTransaction
	for _, request := range requests {
		transaction, err := store.BeginTunnelTransaction(ctx, request.DeviceID, request.PeerPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		transactions = append(transactions, transaction)
	}
	if acquired := store.pool.Stat().AcquiredConns(); acquired != 2 {
		t.Fatalf("acquired connections = %d, want N=2", acquired)
	}
	for index, transaction := range transactions {
		prepared, err := transaction.Prepare(ctx, requests[index])
		if err != nil {
			t.Fatal(err)
		}
		clear(prepared.PSK)
	}
	extraCtx, extraCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer extraCancel()
	if _, err := store.BeginTunnelTransaction(
		extraCtx, "device-held-c", testPeer,
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("N+1 acquisition error = %v", err)
	}
	for _, transaction := range transactions {
		if err := transaction.Release(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPostgresNPlusOneAcquisitionCancelsBoundedly(t *testing.T) {
	dsn, store, signer, ctx := newHeldPostgresTest(t, "n-plus-one", 1)
	_ = dsn
	request := postgresRequest(t, signer, store.controllerID, "device-n1-a", "n1-a", 0)
	transaction, err := store.BeginTunnelTransaction(ctx, request.DeviceID, request.PeerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := store.BeginTunnelTransaction(
		waitCtx, "device-n1-b", testPeer,
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("N+1 acquisition error = %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("N+1 cancellation was not bounded")
	}
	if err := transaction.Release(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresSameTunnelWaiterDoesNotBlockOwnerProgress(t *testing.T) {
	_, store, signer, ctx := newHeldPostgresTest(t, "same-waiter", 1)
	request := postgresRequest(t, signer, store.controllerID, "device-waiter", "wait-owner", 0)
	owner, err := store.BeginTunnelTransaction(ctx, request.DeviceID, request.PeerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	waiterResult := make(chan TunnelTransaction, 1)
	waiterErrors := make(chan error, 1)
	go func() {
		waiter, err := store.BeginTunnelTransaction(ctx, request.DeviceID, request.PeerPublicKey)
		if err != nil {
			waiterErrors <- err
			return
		}
		waiterResult <- waiter
	}()
	prepared, err := owner.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	clear(prepared.PSK)
	if err := owner.Release(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case waiter := <-waiterResult:
		if err := waiter.Release(ctx); err != nil {
			t.Fatal(err)
		}
	case err := <-waiterErrors:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("same-tunnel waiter blocked owner progress")
	}
}

func TestPostgresPrepareCommitReconcileUseHeldBackendPID(t *testing.T) {
	_, store, signer, ctx := newHeldPostgresTest(t, "held-pid", 1)
	request := postgresRequest(t, signer, store.controllerID, "device-held-pid", "held-pid", 0)
	generic, err := store.BeginTunnelTransaction(ctx, request.DeviceID, request.PeerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	transaction := generic.(*postgresTunnelTransaction)
	pid := transaction.lease.backendPID
	prepared, err := transaction.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	clear(prepared.PSK)
	if transaction.lease.conn.Conn().PgConn().PID() != pid {
		t.Fatal("Prepare drifted backend PID")
	}
	if err := transaction.Commit(ctx, request.RequestID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := transaction.ReconcileCommitOutcome(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	clear(snapshot.PSK)
	if transaction.lease.conn.Conn().PgConn().PID() != pid {
		t.Fatal("Commit/reconcile drifted backend PID")
	}
	if err := transaction.Release(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresNoSecondPoolCheckoutWhileLeaseHeld(t *testing.T) {
	_, store, signer, ctx := newHeldPostgresTest(t, "no-second", 1)
	request := postgresRequest(t, signer, store.controllerID, "device-no-second", "no-second", 0)
	transaction, err := store.BeginTunnelTransaction(ctx, request.DeviceID, request.PeerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := transaction.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	clear(prepared.PSK)
	if err := transaction.Commit(ctx, request.RequestID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := transaction.ReconcileCommitOutcome(ctx, request)
	clear(snapshot.PSK)
	if err != nil {
		t.Fatal(err)
	}
	if acquired := store.pool.Stat().AcquiredConns(); acquired != 1 {
		t.Fatalf("additional checkout observed: %d", acquired)
	}
	if err := transaction.Release(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresCanonicalNestedLockOrder(t *testing.T) {
	_, store, signer, ctx := newHeldPostgresTest(t, "nested-order", 1)
	request := postgresRequest(t, signer, store.controllerID, "device-order", "nested-order", 0)
	generic, err := store.BeginTunnelTransaction(ctx, request.DeviceID, request.PeerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	transaction := generic.(*postgresTunnelTransaction)
	prepared, err := transaction.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	clear(prepared.PSK)
	var sessionLocks, transactionLocks int
	if err := transaction.lease.conn.QueryRow(
		ctx,
		`SELECT count(*) FILTER (WHERE objsubid=2),
		        count(*) FILTER (WHERE objsubid=1)
		   FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory'`,
	).Scan(&sessionLocks, &transactionLocks); err != nil {
		t.Fatal(err)
	}
	if sessionLocks != 1 || transactionLocks != 0 {
		t.Fatalf("post-Prepare lock census session=%d transaction=%d", sessionLocks, transactionLocks)
	}
	if err := transaction.Release(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresHeldSessionLossIsIndeterminate(t *testing.T) {
	_, store, signer, ctx := newHeldPostgresTest(t, "session-loss", 1)
	request := postgresRequest(t, signer, store.controllerID, "device-loss", "session-loss", 0)
	generic, err := store.BeginTunnelTransaction(ctx, request.DeviceID, request.PeerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	transaction := generic.(*postgresTunnelTransaction)
	if err := transaction.lease.conn.Conn().Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Prepare(ctx, request); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("lost-session Prepare error = %v", err)
	}
	_ = transaction.Release(ctx)
}

func TestPostgresTransactionRejectsRepeatedPrepareAndRequestRebinding(t *testing.T) {
	_, store, signer, ctx := newHeldPostgresTest(t, "repeat-binding", 1)
	request := postgresRequest(t, signer, store.controllerID, "device-repeat", "repeat-one", 0)
	transaction, err := store.BeginTunnelTransaction(ctx, request.DeviceID, request.PeerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := transaction.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	clear(prepared.PSK)
	rebound := postgresRequest(t, signer, store.controllerID, request.DeviceID, "repeat-two", 0)
	if _, err := transaction.Prepare(ctx, rebound); err == nil {
		t.Fatal("sequential Prepare rebound a retained transaction")
	}
	if err := transaction.Commit(ctx, request.RequestID); err == nil {
		t.Fatal("Commit after invalid rebinding was accepted")
	}
	if err := transaction.Release(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresUnlockTrueAbsenceQueryErrorHijacksSession(t *testing.T) {
	_, store, signer, ctx := newHeldPostgresTest(t, "absence-error", 1)
	request := postgresRequest(t, signer, store.controllerID, "device-absence", "absence-error", 0)
	generic, err := store.BeginTunnelTransaction(ctx, request.DeviceID, request.PeerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	transaction := generic.(*postgresTunnelTransaction)
	store.releaseHooks.absent = func(context.Context, *pgxpool.Conn, [2]int32) (bool, error) {
		return false, errors.New("injected absence query error")
	}
	if err := transaction.Release(ctx); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("release error = %v", err)
	}
	receipt := store.quarantine[transaction.lease.digest]
	if receipt.FailureClass != "absence_error" || !receipt.CloseAttempted {
		t.Fatalf("quarantine receipt = %+v", receipt)
	}
}

func TestPostgresUnlockFalseHijacksSession(t *testing.T) {
	_, store, signer, ctx := newHeldPostgresTest(t, "unlock-false", 1)
	request := postgresRequest(t, signer, store.controllerID, "device-unlock", "unlock-false", 0)
	generic, err := store.BeginTunnelTransaction(ctx, request.DeviceID, request.PeerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	transaction := generic.(*postgresTunnelTransaction)
	store.releaseHooks.unlock = func(context.Context, *pgxpool.Conn, [2]int32) (bool, error) {
		return false, nil
	}
	if err := transaction.Release(ctx); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("release error = %v", err)
	}
	if receipt := store.quarantine[transaction.lease.digest]; receipt.FailureClass != "unlock_false" {
		t.Fatalf("quarantine receipt = %+v", receipt)
	}
}

func TestPostgresPoisonedSessionNeverReturnsToPool(t *testing.T) {
	_, store, signer, ctx := newHeldPostgresTest(t, "never-pool", 2)
	request := postgresRequest(t, signer, store.controllerID, "device-never-pool", "never-pool", 0)
	generic, err := store.BeginTunnelTransaction(ctx, request.DeviceID, request.PeerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	transaction := generic.(*postgresTunnelTransaction)
	oldPID := transaction.lease.backendPID
	store.releaseHooks.unlock = func(context.Context, *pgxpool.Conn, [2]int32) (bool, error) {
		return false, nil
	}
	_ = transaction.Release(ctx)
	replacement, err := store.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Release()
	if replacement.Conn().PgConn().PID() == oldPID {
		t.Fatal("poisoned physical session returned to pool")
	}
}

func TestPostgresCloseFailureRemainsLatched(t *testing.T) {
	_, store, signer, ctx := newHeldPostgresTest(t, "close-failure", 1)
	request := postgresRequest(t, signer, store.controllerID, "device-close-failure", "close-failure", 0)
	generic, err := store.BeginTunnelTransaction(ctx, request.DeviceID, request.PeerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	transaction := generic.(*postgresTunnelTransaction)
	store.releaseHooks.unlock = func(context.Context, *pgxpool.Conn, [2]int32) (bool, error) {
		return false, nil
	}
	realClose := store.releaseHooks.close
	store.releaseHooks.close = func(ctx context.Context, conn *pgx.Conn) error {
		_ = realClose(ctx, conn)
		return errors.New("injected close receipt failure")
	}
	if err := transaction.Release(ctx); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("release error = %v", err)
	}
	receipt := store.quarantine[transaction.lease.digest]
	if receipt.CloseConfirmed || !receipt.CloseAttempted {
		t.Fatalf("close failure receipt = %+v", receipt)
	}
	if _, err := store.BeginTunnelTransaction(
		ctx, request.DeviceID, request.PeerPublicKey,
	); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("close-failure latch acquisition error = %v", err)
	}
}

func TestPostgresCloseWaitsBoundedlyThenDisposesActiveSession(t *testing.T) {
	_, store, signer, ctx := newHeldPostgresTest(t, "bounded-close", 1)
	request := postgresRequest(t, signer, store.controllerID, "device-bounded-close", "bounded-close", 0)
	generic, err := store.BeginTunnelTransaction(ctx, request.DeviceID, request.PeerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	transaction := generic.(*postgresTunnelTransaction)
	started := time.Now()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if elapsed < 200*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("bounded Close duration = %s", elapsed)
	}
	receipt := store.quarantine[transaction.lease.digest]
	if receipt.FailureClass != "bounded_shutdown_disposal" ||
		!receipt.CloseAttempted || !receipt.CloseConfirmed {
		t.Fatalf("bounded shutdown receipt = %+v", receipt)
	}
}

func newHeldPostgresTest(
	t *testing.T,
	suffix string,
	maxConnections int,
) (string, *PostgresStore, *pqauth.Signer, context.Context) {
	t.Helper()
	dsn := os.Getenv("WINN_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("WINN_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	keyPath := filepath.Join(t.TempDir(), "state.key")
	if err := securefile.AtomicWrite(keyPath, bytes.Repeat([]byte{0x66}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t)
	controllerID := "controller-pg-" + suffix
	store := openPostgresTestWithLimit(
		t, ctx, dsn, keyPath, controllerID, signer, maxConnections,
	)
	cleanPostgresController(t, ctx, store, controllerID)
	t.Cleanup(func() { _ = store.Close() })
	return dsn, store, signer, ctx
}

func TestPostgresDSNRequiresVerifiedTLSExceptLoopbackTestMode(t *testing.T) {
	if err := validatePostgresDSN("postgres://user@db.example/winn?sslmode=require", false); err == nil {
		t.Fatal("unverified remote PostgreSQL TLS was accepted")
	}
	if err := validatePostgresDSN("postgres://user@db.example/winn?sslmode=verify-full", false); err != nil {
		t.Fatal(err)
	}
	if err := validatePostgresDSN("postgres://user@127.0.0.1/winn?sslmode=disable", true); err != nil {
		t.Fatal(err)
	}
	if err := validatePostgresDSN("postgres://user@db.example/winn?sslmode=disable", true); err == nil {
		t.Fatal("test-only insecure mode escaped loopback")
	}
}

func TestPostgresRedemptionsSurviveRestartAndSerializeInstances(
	t *testing.T,
) {
	dsn := os.Getenv("WINN_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("WINN_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second,
	)
	defer cancel()
	firstToken := redemptionTokenID(t.Name(), time.Now().UnixNano(), 1)
	raceToken := redemptionTokenID(t.Name(), time.Now().UnixNano(), 2)
	expiresAt := time.Now().UTC().Add(time.Hour)

	first := openPostgresRedemptionTest(t, ctx, dsn)
	if !privacytoken.IsDurableRedemptionStore(first) {
		t.Fatal("PostgreSQL redemption store is not marked durable")
	}
	if err := first.Redeem(ctx, firstToken, expiresAt); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second := openPostgresRedemptionTest(t, ctx, dsn)
	defer second.Close()
	if err := second.Redeem(
		ctx, firstToken, expiresAt,
	); !errors.Is(err, privacytoken.ErrAlreadyRedeemed) {
		t.Fatalf("restarted store redemption error = %v", err)
	}
	third := openPostgresRedemptionTest(t, ctx, dsn)
	defer third.Close()
	defer func() {
		_, _ = second.pool.Exec(
			context.Background(),
			`DELETE FROM winn_privacy_token_redemptions
			  WHERE token_id = ANY($1)`,
			[]string{firstToken, raceToken},
		)
	}()

	results := make(chan error, 2)
	var group sync.WaitGroup
	for _, store := range []*PostgresRedemptionStore{second, third} {
		store := store
		group.Add(1)
		go func() {
			defer group.Done()
			results <- store.Redeem(ctx, raceToken, expiresAt)
		}()
	}
	group.Wait()
	close(results)
	successes := 0
	replays := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, privacytoken.ErrAlreadyRedeemed):
			replays++
		default:
			t.Fatalf("concurrent redemption error = %v", err)
		}
	}
	if successes != 1 || replays != 1 {
		t.Fatalf(
			"concurrent redemption outcomes success=%d replay=%d",
			successes, replays,
		)
	}
}

func openPostgresRedemptionTest(
	t *testing.T,
	ctx context.Context,
	dsn string,
) *PostgresRedemptionStore {
	t.Helper()
	store, err := OpenPostgresRedemptions(
		ctx,
		PostgresRedemptionOptions{
			DSN:                   dsn,
			MaxConnections:        4,
			AllowInsecureLoopback: true,
			AutoMigrate:           true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func redemptionTokenID(name string, nonce int64, index int) string {
	digest := sha256.Sum256(
		[]byte(fmt.Sprintf("%s|%d|%d", name, nonce, index)),
	)
	return hex.EncodeToString(digest[:])
}

func openPostgresTest(
	t *testing.T,
	ctx context.Context,
	dsn string,
	keyPath string,
	controllerID string,
	signer *pqauth.Signer,
) *PostgresStore {
	return openPostgresTestWithLimit(
		t, ctx, dsn, keyPath, controllerID, signer, 8,
	)
}

func openPostgresTestWithLimit(
	t *testing.T,
	ctx context.Context,
	dsn string,
	keyPath string,
	controllerID string,
	signer *pqauth.Signer,
	maxConnections int,
) *PostgresStore {
	t.Helper()
	store, err := OpenPostgres(ctx, PostgresOptions{
		DSN:                   dsn,
		StateKeyPath:          keyPath,
		TTL:                   time.Hour,
		ControllerID:          controllerID,
		Signer:                signer,
		MaxConnections:        maxConnections,
		AllowInsecureLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func cleanPostgresController(t *testing.T, ctx context.Context, store *PostgresStore, controllerID string) {
	t.Helper()
	if store.closed.Load() {
		return
	}
	for _, table := range []string{"winn_requests", "winn_peers", "winn_revoked_devices"} {
		if _, err := store.pool.Exec(ctx, "DELETE FROM "+table+" WHERE controller_id=$1", controllerID); err != nil {
			t.Errorf("clean %s: %v", table, err)
		}
	}
}

func postgresRequest(
	t *testing.T,
	signer *pqauth.Signer,
	controllerID string,
	deviceID string,
	requestID string,
	generation uint64,
) protocol.RekeyRequest {
	t.Helper()
	request := protocol.RekeyRequest{
		Version:           protocol.Version,
		Suite:             protocol.DefaultSuite,
		ControllerID:      controllerID,
		DeviceID:          deviceID,
		PeerPublicKey:     testPeer,
		RequestID:         tokenForString(requestID),
		Nonce:             tokenForString(requestID + "-nonce"),
		CurrentGeneration: generation,
		Capabilities:      protocol.RequiredCapabilities(protocol.DefaultSuite),
	}
	if err := pqauth.SignRequest(&request, signer); err != nil {
		t.Fatal(err)
	}
	return request
}
