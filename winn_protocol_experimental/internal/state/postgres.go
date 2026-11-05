package state

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	postgresSchemaVersion = 1
	postgresResponseAD    = "winn-postgres-response/v1"
)

type PostgresOptions struct {
	DSN                   string
	StateKeyPath          string
	TTL                   time.Duration
	ControllerID          string
	Signer                *pqauth.Signer
	MaxConnections        int
	AllowInsecureLoopback bool
	AutoMigrate           bool
	AdministrativeOnly    bool
}

type PostgresStore struct {
	pool         *pgxpool.Pool
	key          [32]byte
	ttl          time.Duration
	controllerID string
	signer       *pqauth.Signer
	verifier     *pqauth.Verifier
	random       io.Reader
	now          func() time.Time
	closed       atomic.Bool
	leaseMu      sync.Mutex
	leases       map[[32]byte]*postgresTunnelLease
	releaseHooks postgresReleaseHooks
	quarantine   map[[32]byte]postgresQuarantineReceipt
}

type postgresReleaseHooks struct {
	unlock func(context.Context, *pgxpool.Conn, [2]int32) (bool, error)
	absent func(context.Context, *pgxpool.Conn, [2]int32) (bool, error)
	close  func(context.Context, *pgx.Conn) error
}

type postgresQuarantineReceipt struct {
	BackendPID     uint32
	FailureClass   string
	CloseAttempted bool
	CloseConfirmed bool
	RecordedAtUTC  time.Time
}

type txBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type postgresTunnelLease struct {
	store      *PostgresStore
	conn       *pgxpool.Conn
	digest     [32]byte
	token      [32]byte
	backendPID uint32
	keys       [2]int32
	state      uint8
}

type postgresTunnelTransaction struct {
	lease         *postgresTunnelLease
	request       *protocol.RekeyRequest
	requestDigest [32]byte
	phase         uint8
	reconciles    uint8
	busy          atomic.Bool
}

func OpenPostgres(ctx context.Context, options PostgresOptions) (*PostgresStore, error) {
	if options.TTL < minimumKeyTTL || options.TTL > protocol.MaxKeyLifetime {
		return nil, fmt.Errorf("key TTL must be between %s and %s", minimumKeyTTL, protocol.MaxKeyLifetime)
	}
	if !protocol.ValidDeviceID(options.ControllerID) {
		return nil, errors.New("invalid controller ID")
	}
	if options.Signer == nil && !options.AdministrativeOnly {
		return nil, errors.New("controller PQ response signer is required")
	}
	if options.MaxConnections < 1 || options.MaxConnections > 1024 {
		return nil, errors.New("PostgreSQL maximum connections must be between 1 and 1024")
	}
	if err := validatePostgresDSN(options.DSN, options.AllowInsecureLoopback); err != nil {
		return nil, err
	}
	keyData, err := securefile.ReadPrivateLimited(options.StateKeyPath, 1024)
	if err != nil {
		return nil, fmt.Errorf("read state key: %w", err)
	}
	defer clear(keyData)
	if len(keyData) != 32 {
		return nil, fmt.Errorf("state key length is %d, want 32", len(keyData))
	}
	var verifier *pqauth.Verifier
	if options.Signer != nil {
		publicKey := options.Signer.PublicBytes()
		verifier, err = pqauth.NewVerifier(options.Signer.Algorithm(), publicKey)
		clear(publicKey)
		if err != nil {
			return nil, fmt.Errorf("build controller response verifier: %w", err)
		}
	}
	poolConfig, err := pgxpool.ParseConfig(options.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL DSN: %w", err)
	}
	// #nosec G115 -- MaxConnections was bounded to 1..1024 above.
	poolConfig.MaxConns = int32(options.MaxConnections)
	poolConfig.MinConns = 1
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL pool: %w", err)
	}
	store := &PostgresStore{
		pool:         pool,
		ttl:          options.TTL,
		controllerID: options.ControllerID,
		signer:       options.Signer,
		verifier:     verifier,
		random:       rand.Reader,
		now:          time.Now,
		leases:       make(map[[32]byte]*postgresTunnelLease),
		quarantine:   make(map[[32]byte]postgresQuarantineReceipt),
	}
	store.releaseHooks = postgresReleaseHooks{
		unlock: func(ctx context.Context, conn *pgxpool.Conn, keys [2]int32) (bool, error) {
			var unlocked bool
			err := conn.QueryRow(
				ctx, `SELECT pg_advisory_unlock($1,$2)`, keys[0], keys[1],
			).Scan(&unlocked)
			return unlocked, err
		},
		absent: func(ctx context.Context, conn *pgxpool.Conn, keys [2]int32) (bool, error) {
			var count int
			err := conn.QueryRow(
				ctx,
				`SELECT count(*) FROM pg_locks
				  WHERE pid=pg_backend_pid() AND locktype='advisory'
				    AND classid=($1::integer::bigint & 4294967295)
				    AND objid=($2::integer::bigint & 4294967295)
				    AND objsubid=2 AND granted`,
				keys[0], keys[1],
			).Scan(&count)
			return count == 0, err
		},
		close: func(ctx context.Context, conn *pgx.Conn) error {
			return conn.Close(ctx)
		},
	}
	copy(store.key[:], keyData)
	if err := pool.Ping(ctx); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("ping PostgreSQL: %w", err)
	}
	if options.AutoMigrate {
		err = store.migrate(ctx)
	} else {
		err = store.verifySchema(ctx)
	}
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func postgresLeaseKeys(digest [32]byte) [2]int32 {
	return [2]int32{
		int32(digest[0])<<24 | int32(digest[1])<<16 | int32(digest[2])<<8 | int32(digest[3]),
		int32(digest[4])<<24 | int32(digest[5])<<16 | int32(digest[6])<<8 | int32(digest[7]),
	}
}

func (s *PostgresStore) BeginTunnelTransaction(
	ctx context.Context,
	deviceID string,
	peerPublicKey string,
) (TunnelTransaction, error) {
	if ctx == nil {
		return nil, errors.New("tunnel transaction context is required")
	}
	if s.closed.Load() {
		return nil, errors.New("PostgreSQL controller state is closed")
	}
	if !protocol.ValidDeviceID(deviceID) {
		return nil, errors.New("invalid device ID")
	}
	if err := protocol.ValidatePeerPublicKey(peerPublicKey); err != nil {
		return nil, err
	}
	digest := tunnelDigest(s.controllerID, deviceID, peerPublicKey)
	keys := postgresLeaseKeys(digest)
	for {
		if cause := context.Cause(ctx); cause != nil {
			return nil, cause
		}
		s.leaseMu.Lock()
		current := s.leases[digest]
		if current == nil {
			lease := &postgresTunnelLease{
				store: s, digest: digest, keys: keys, state: 4,
			}
			s.leases[digest] = lease
			s.leaseMu.Unlock()
			conn, err := s.pool.Acquire(ctx)
			if err != nil {
				s.leaseMu.Lock()
				if s.leases[digest] == lease {
					delete(s.leases, digest)
				}
				s.leaseMu.Unlock()
				return nil, err
			}
			lease.conn = conn
			lease.backendPID = conn.Conn().PgConn().PID()
			if _, err := io.ReadFull(rand.Reader, lease.token[:]); err != nil {
				conn.Release()
				s.leaseMu.Lock()
				delete(s.leases, digest)
				s.leaseMu.Unlock()
				return nil, err
			}
			for {
				var acquired bool
				err = conn.QueryRow(
					ctx,
					`SELECT pg_try_advisory_lock($1,$2)`,
					keys[0], keys[1],
				).Scan(&acquired)
				if err != nil {
					conn.Release()
					s.leaseMu.Lock()
					delete(s.leases, digest)
					s.leaseMu.Unlock()
					return nil, err
				}
				if acquired {
					break
				}
				timer := time.NewTimer(5 * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					conn.Release()
					s.leaseMu.Lock()
					delete(s.leases, digest)
					s.leaseMu.Unlock()
					return nil, context.Cause(ctx)
				case <-timer.C:
				}
			}
			s.leaseMu.Lock()
			lease.state = 1
			s.leaseMu.Unlock()
			if err := lease.Validate(ctx); err != nil {
				_ = (&postgresTunnelTransaction{lease: lease}).Release(context.Background())
				return nil, err
			}
			return &postgresTunnelTransaction{lease: lease}, nil
		}
		if current.state == 2 {
			s.leaseMu.Unlock()
			return nil, ErrReconciliationRequired
		}
		s.leaseMu.Unlock()
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, context.Cause(ctx)
		case <-timer.C:
		}
	}
}

func (l *postgresTunnelLease) Validate(ctx context.Context) error {
	if ctx == nil || context.Cause(ctx) != nil {
		if ctx == nil {
			return errors.New("lease context is required")
		}
		return context.Cause(ctx)
	}
	l.store.leaseMu.Lock()
	validLocal := l.state == 1 && l.store.leases[l.digest] == l &&
		l.conn != nil && l.conn.Conn().PgConn().PID() == l.backendPID
	l.store.leaseMu.Unlock()
	if !validLocal {
		return ErrReconciliationRequired
	}
	var count int
	err := l.conn.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM pg_locks
		  WHERE pid=pg_backend_pid()
		    AND locktype='advisory'
		    AND classid=($1::integer::bigint & 4294967295)
		    AND objid=($2::integer::bigint & 4294967295)
		    AND objsubid=2 AND granted`,
		l.keys[0], l.keys[1],
	).Scan(&count)
	if err != nil || count != 1 {
		return ErrReconciliationRequired
	}
	return nil
}

func (t *postgresTunnelTransaction) Lease() TunnelLease { return t.lease }

func (t *postgresTunnelTransaction) enter(ctx context.Context) error {
	if !t.busy.CompareAndSwap(false, true) {
		return errors.New("concurrent tunnel transaction use")
	}
	if err := t.lease.Validate(ctx); err != nil {
		t.busy.Store(false)
		return err
	}
	return nil
}

func (t *postgresTunnelTransaction) leave() { t.busy.Store(false) }

func (t *postgresTunnelTransaction) Prepare(
	ctx context.Context,
	req protocol.RekeyRequest,
) (Prepared, error) {
	if err := t.enter(ctx); err != nil {
		return Prepared{}, err
	}
	defer t.leave()
	if t.phase != tunnelPhaseNew || t.request != nil {
		t.phase = tunnelPhaseInvalid
		return Prepared{}, errors.New("repeated or invalid tunnel Prepare transition")
	}
	if tunnelDigest(req.ControllerID, req.DeviceID, req.PeerPublicKey) != t.lease.digest {
		t.phase = tunnelPhaseInvalid
		return Prepared{}, errors.New("request is not bound to tunnel transaction")
	}
	digest, err := protocol.RequestDigest(req)
	if err != nil {
		t.phase = tunnelPhaseInvalid
		return Prepared{}, err
	}
	t.phase = tunnelPhasePrepareAttempted
	prepared, err := t.lease.store.prepareOnceWith(
		ctx, t.lease.conn.Conn(), req, hex.EncodeToString(digest[:]),
	)
	if validateErr := t.lease.Validate(ctx); validateErr != nil {
		clear(prepared.PSK)
		return Prepared{}, validateErr
	}
	if err != nil {
		return prepared, err
	}
	copyReq := req
	t.request = &copyReq
	t.requestDigest = digest
	t.phase = tunnelPhasePrepared
	return prepared, nil
}

func (t *postgresTunnelTransaction) Commit(ctx context.Context, requestID string) error {
	if err := t.enter(ctx); err != nil {
		return err
	}
	defer t.leave()
	if t.phase != tunnelPhasePrepared || t.request == nil ||
		t.request.RequestID != requestID {
		t.phase = tunnelPhaseInvalid
		return errors.New("commit request is not bound to tunnel transaction")
	}
	t.phase = tunnelPhaseCommitAttempted
	err := t.lease.store.commitOnceWith(ctx, t.lease.conn.Conn(), requestID)
	if validateErr := t.lease.Validate(ctx); validateErr != nil {
		return validateErr
	}
	return err
}

func (t *postgresTunnelTransaction) ReconcileCommitOutcome(
	ctx context.Context,
	req protocol.RekeyRequest,
) (result CommitSnapshot, resultErr error) {
	if err := t.enter(ctx); err != nil {
		return CommitSnapshot{}, err
	}
	defer t.leave()
	digest, digestErr := protocol.RequestDigest(req)
	if t.phase != tunnelPhaseCommitAttempted || t.reconciles >= 2 ||
		digestErr != nil || t.request == nil ||
		t.request.RequestID != req.RequestID || digest != t.requestDigest {
		t.phase = tunnelPhaseInvalid
		return CommitSnapshot{}, errors.New("reconciliation request is not bound to transaction")
	}
	t.reconciles++
	transaction, err := t.lease.conn.Conn().BeginTx(
		ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadOnly},
	)
	if err != nil {
		if validateErr := t.lease.Validate(ctx); validateErr != nil {
			return CommitSnapshot{}, validateErr
		}
		return CommitSnapshot{}, err
	}
	defer func() {
		_ = transaction.Rollback(ctx)
		if validateErr := t.lease.Validate(ctx); validateErr != nil {
			clear(result.PSK)
			result = CommitSnapshot{}
			resultErr = validateErr
		}
	}()
	if err := advisoryLock(ctx, transaction, t.lease.store.controllerID, "request", req.RequestID); err != nil {
		return CommitSnapshot{}, err
	}
	if err := advisoryLock(ctx, transaction, t.lease.store.controllerID, "peer", req.DeviceID, req.PeerPublicKey); err != nil {
		return CommitSnapshot{}, err
	}
	var storedDevice, storedDigest string
	var envelope []byte
	var committed bool
	if err := transaction.QueryRow(
		ctx,
		`SELECT device_id,digest,response_envelope,committed
		   FROM winn_requests WHERE controller_id=$1 AND request_id=$2`,
		t.lease.store.controllerID, req.RequestID,
	).Scan(&storedDevice, &storedDigest, &envelope, &committed); err != nil {
		return CommitSnapshot{}, err
	}
	if storedDevice != req.DeviceID ||
		storedDigest != hex.EncodeToString(digest[:]) {
		return CommitSnapshot{}, errors.New("PostgreSQL request binding mismatch")
	}
	response, psk, err := t.lease.store.openResponse(req.RequestID, envelope)
	if err != nil {
		return CommitSnapshot{}, err
	}
	var generation int64
	var keyID string
	var pending *string
	if err := transaction.QueryRow(
		ctx,
		`SELECT generation,key_id,pending_request_id FROM winn_peers
		  WHERE controller_id=$1 AND device_id=$2 AND peer_public_key=$3`,
		t.lease.store.controllerID, req.DeviceID, req.PeerPublicKey,
	).Scan(&generation, &keyID, &pending); err != nil {
		clear(psk)
		return CommitSnapshot{}, err
	}
	current, err := generationFromDatabase(generation)
	if err != nil {
		clear(psk)
		return CommitSnapshot{}, err
	}
	disposition := CommitIndeterminate
	if committed && pending == nil && current == response.Generation && keyID == response.KeyID {
		disposition = CommitCommitted
	} else if !committed && pending != nil && *pending == req.RequestID &&
		current == req.CurrentGeneration {
		disposition = CommitUncommitted
	} else {
		clear(psk)
		return CommitSnapshot{}, errors.New("PostgreSQL outcome is indeterminate")
	}
	if err := transaction.Commit(ctx); err != nil {
		clear(psk)
		return CommitSnapshot{}, err
	}
	snapshotBytes, _ := json.Marshal(struct {
		Response   protocol.RekeyResponse
		Committed  bool
		Generation uint64
		KeyID      string
		Pending    *string
	}{response, committed, current, keyID, pending})
	hash := sha256.Sum256(snapshotBytes)
	clear(snapshotBytes)
	return CommitSnapshot{
		Disposition: disposition, Response: response, PSK: psk,
		RequestDigest: digest, SnapshotHash: hash,
	}, nil
}

func (t *postgresTunnelTransaction) Release(ctx context.Context) error {
	if !t.busy.CompareAndSwap(false, true) {
		return errors.New("concurrent tunnel transaction use")
	}
	defer t.busy.Store(false)
	if t.phase == tunnelPhaseReleased || t.phase == tunnelPhasePoisoned {
		return errors.New("repeated tunnel release")
	}
	l := t.lease
	s := l.store
	releaseOK := false
	failureClass := "release_context_or_validation"
	if ctx != nil && context.Cause(ctx) == nil && l.conn != nil &&
		l.Validate(ctx) == nil {
		unlocked, err := s.releaseHooks.unlock(ctx, l.conn, l.keys)
		if err != nil {
			failureClass = "unlock_error"
		} else if !unlocked {
			failureClass = "unlock_false"
		} else {
			absent, absentErr := s.releaseHooks.absent(ctx, l.conn, l.keys)
			if absentErr != nil {
				failureClass = "absence_error"
			} else if !absent {
				failureClass = "lock_still_present"
			} else {
				releaseOK = true
			}
		}
	}
	s.leaseMu.Lock()
	if releaseOK && l.state == 1 && s.leases[l.digest] == l {
		delete(s.leases, l.digest)
		l.state = 3
		t.phase = tunnelPhaseReleased
		clear(l.token[:])
		conn := l.conn
		l.conn = nil
		s.leaseMu.Unlock()
		conn.Release()
		return nil
	}
	l.state = 2
	t.phase = tunnelPhasePoisoned
	s.leases[l.digest] = l
	s.quarantine[l.digest] = postgresQuarantineReceipt{
		BackendPID:    l.backendPID,
		FailureClass:  failureClass,
		RecordedAtUTC: time.Now().UTC(),
	}
	conn := l.conn
	l.conn = nil
	s.leaseMu.Unlock()
	var closeErr error
	if conn != nil {
		physical := conn.Hijack()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr = s.releaseHooks.close(cleanupCtx, physical)
		cancel()
		s.leaseMu.Lock()
		receipt := s.quarantine[l.digest]
		receipt.CloseAttempted = true
		receipt.CloseConfirmed = closeErr == nil
		s.quarantine[l.digest] = receipt
		s.leaseMu.Unlock()
	}
	return errors.Join(ErrReconciliationRequired, closeErr)
}

func (s *PostgresStore) Prepare(ctx context.Context, request protocol.RekeyRequest) (Prepared, error) {
	if s.closed.Load() {
		return Prepared{}, errors.New("PostgreSQL controller state is closed")
	}
	if s.signer == nil {
		return Prepared{}, errors.New("administrative PostgreSQL state cannot prepare rotations")
	}
	if err := protocol.ValidateRequest(request); err != nil {
		return Prepared{}, fmt.Errorf("invalid rekey request: %w", err)
	}
	if request.ControllerID != s.controllerID {
		return Prepared{}, errors.New("request is for a different controller")
	}
	if request.AuthAlgorithm != s.signer.Algorithm() {
		return Prepared{}, errors.New("request suite requires a different controller PQ signer")
	}
	if request.CurrentGeneration >= protocol.MaxGeneration {
		return Prepared{}, errors.New("generation exhausted")
	}
	digest, err := protocol.RequestDigest(request)
	if err != nil {
		return Prepared{}, err
	}
	digestHex := hex.EncodeToString(digest[:])
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		prepared, err := s.prepareOnce(ctx, request, digestHex)
		if !retryablePostgres(err) {
			return prepared, err
		}
		lastErr = err
	}
	return Prepared{}, fmt.Errorf("PostgreSQL transaction retry limit reached: %w", lastErr)
}

func (s *PostgresStore) prepareOnce(
	ctx context.Context,
	request protocol.RekeyRequest,
	digestHex string,
) (Prepared, error) {
	return s.prepareOnceWith(ctx, s.pool, request, digestHex)
}

func (s *PostgresStore) prepareOnceWith(
	ctx context.Context,
	beginner txBeginner,
	request protocol.RekeyRequest,
	digestHex string,
) (Prepared, error) {
	transaction, err := beginner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Prepared{}, err
	}
	defer transaction.Rollback(ctx)
	if err := advisoryLock(ctx, transaction, s.controllerID, "request", request.RequestID); err != nil {
		return Prepared{}, err
	}
	var revoked bool
	err = transaction.QueryRow(
		ctx,
		`SELECT revoked FROM winn_revoked_devices WHERE controller_id=$1 AND device_id=$2`,
		s.controllerID,
		request.DeviceID,
	).Scan(&revoked)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Prepared{}, err
	}
	if revoked {
		return Prepared{}, ErrRevoked
	}

	var existingDevice string
	var existingDigest string
	var existingEnvelope []byte
	var existingCommitted bool
	err = transaction.QueryRow(
		ctx,
		`SELECT device_id, digest, response_envelope, committed
		   FROM winn_requests
		  WHERE controller_id=$1 AND request_id=$2
		  FOR UPDATE`,
		s.controllerID,
		request.RequestID,
	).Scan(&existingDevice, &existingDigest, &existingEnvelope, &existingCommitted)
	if err == nil {
		if existingDevice != request.DeviceID || existingDigest != digestHex {
			return Prepared{}, ErrReplayConflict
		}
		response, psk, err := s.openResponse(request.RequestID, existingEnvelope)
		if err != nil {
			return Prepared{}, fmt.Errorf("stored response is corrupt: %w", err)
		}
		if err := transaction.Commit(ctx); err != nil {
			clear(psk)
			return Prepared{}, err
		}
		return Prepared{
			Response:   response,
			PSK:        psk,
			Idempotent: true,
			Committed:  existingCommitted,
		}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Prepared{}, err
	}

	if err := advisoryLock(ctx, transaction, s.controllerID, "peer", request.DeviceID, request.PeerPublicKey); err != nil {
		return Prepared{}, err
	}
	var currentGeneration int64
	var pendingRequest *string
	err = transaction.QueryRow(
		ctx,
		`SELECT generation, pending_request_id
		   FROM winn_peers
		  WHERE controller_id=$1 AND device_id=$2 AND peer_public_key=$3
		  FOR UPDATE`,
		s.controllerID,
		request.DeviceID,
		request.PeerPublicKey,
	).Scan(&currentGeneration, &pendingRequest)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Prepared{}, err
	}
	if pendingRequest != nil && *pendingRequest != "" {
		return Prepared{}, &PendingError{RequestID: *pendingRequest}
	}
	storedGeneration, err := generationFromDatabase(currentGeneration)
	if err != nil {
		return Prepared{}, err
	}
	if request.CurrentGeneration != storedGeneration {
		return Prepared{}, &GenerationError{Current: storedGeneration}
	}

	psk := make([]byte, 32)
	if _, err := io.ReadFull(s.random, psk); err != nil {
		return Prepared{}, fmt.Errorf("generate AWG PSK: %w", err)
	}
	var nonzero byte
	for _, value := range psk {
		nonzero |= value
	}
	if nonzero == 0 {
		clear(psk)
		return Prepared{}, errors.New("random source returned an invalid all-zero PSK")
	}
	now := s.now().UTC()
	generation := request.CurrentGeneration + 1
	response := protocol.RekeyResponse{
		Version:       protocol.Version,
		Suite:         request.Suite,
		ControllerID:  s.controllerID,
		DeviceID:      request.DeviceID,
		PeerPublicKey: request.PeerPublicKey,
		RequestID:     request.RequestID,
		Nonce:         request.Nonce,
		Generation:    generation,
		KeyID:         protocol.KeyID(s.controllerID, request.Suite, request.DeviceID, request.PeerPublicKey, generation, psk),
		PresharedKey:  base64.StdEncoding.EncodeToString(psk),
		IssuedAt:      now.Format(time.RFC3339Nano),
		ExpiresAt:     now.Add(s.ttl).Format(time.RFC3339Nano),
		Capabilities:  protocol.RequiredCapabilities(request.Suite),
	}
	if err := pqauth.SignResponse(&response, s.signer); err != nil {
		clear(psk)
		return Prepared{}, fmt.Errorf("sign response with controller ML-DSA key: %w", err)
	}
	envelope, err := s.sealResponse(request.RequestID, response)
	if err != nil {
		clear(psk)
		return Prepared{}, err
	}
	_, err = transaction.Exec(
		ctx,
		`INSERT INTO winn_requests
			(controller_id, request_id, device_id, peer_public_key, digest, response_envelope, created_at, committed)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,false)`,
		s.controllerID,
		request.RequestID,
		request.DeviceID,
		request.PeerPublicKey,
		digestHex,
		envelope,
		now,
	)
	if err != nil {
		clear(psk)
		return Prepared{}, err
	}
	_, err = transaction.Exec(
		ctx,
		`INSERT INTO winn_peers
			(controller_id, device_id, peer_public_key, suite, generation, key_id, issued_at, expires_at, pending_request_id)
		 VALUES ($1,$2,$3,'',0,'',NULL,NULL,$4)
		 ON CONFLICT (controller_id, device_id, peer_public_key)
		 DO UPDATE SET pending_request_id=EXCLUDED.pending_request_id`,
		s.controllerID,
		request.DeviceID,
		request.PeerPublicKey,
		request.RequestID,
	)
	if err != nil {
		clear(psk)
		return Prepared{}, err
	}
	_, err = transaction.Exec(
		ctx,
		`DELETE FROM winn_requests
		  WHERE (controller_id, request_id) IN (
			SELECT controller_id, request_id
			  FROM winn_requests
			 WHERE committed=true AND created_at < $1
			 LIMIT 1000
		  )`,
		now.Add(-requestRetention),
	)
	if err != nil {
		clear(psk)
		return Prepared{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		clear(psk)
		return Prepared{}, err
	}
	return Prepared{Response: response, PSK: psk}, nil
}

func (s *PostgresStore) Commit(ctx context.Context, requestID string) error {
	if s.closed.Load() {
		return errors.New("PostgreSQL controller state is closed")
	}
	if s.signer == nil {
		return errors.New("administrative PostgreSQL state cannot commit rotations")
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		err := s.commitOnce(ctx, requestID)
		if !retryablePostgres(err) {
			return err
		}
		lastErr = err
	}
	return fmt.Errorf("PostgreSQL transaction retry limit reached: %w", lastErr)
}

func (s *PostgresStore) commitOnce(ctx context.Context, requestID string) error {
	return s.commitOnceWith(ctx, s.pool, requestID)
}

func (s *PostgresStore) commitOnceWith(
	ctx context.Context,
	beginner txBeginner,
	requestID string,
) error {
	transaction, err := beginner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer transaction.Rollback(ctx)
	if err := advisoryLock(ctx, transaction, s.controllerID, "request", requestID); err != nil {
		return err
	}
	var envelope []byte
	var committed bool
	err = transaction.QueryRow(
		ctx,
		`SELECT response_envelope, committed
		   FROM winn_requests
		  WHERE controller_id=$1 AND request_id=$2
		  FOR UPDATE`,
		s.controllerID,
		requestID,
	).Scan(&envelope, &committed)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("unknown request ID")
	}
	if err != nil {
		return err
	}
	if committed {
		return transaction.Commit(ctx)
	}
	response, psk, err := s.openResponse(requestID, envelope)
	clear(psk)
	if err != nil {
		return fmt.Errorf("stored response is corrupt: %w", err)
	}
	if err := advisoryLock(ctx, transaction, s.controllerID, "peer", response.DeviceID, response.PeerPublicKey); err != nil {
		return err
	}
	databaseGeneration, err := generationToDatabase(response.Generation)
	if err != nil {
		return err
	}
	commandTag, err := transaction.Exec(
		ctx,
		`UPDATE winn_peers
		    SET suite=$1, generation=$2, key_id=$3, issued_at=$4, expires_at=$5, pending_request_id=NULL
		  WHERE controller_id=$6 AND device_id=$7 AND peer_public_key=$8 AND pending_request_id=$9`,
		response.Suite,
		databaseGeneration,
		response.KeyID,
		response.IssuedAt,
		response.ExpiresAt,
		s.controllerID,
		response.DeviceID,
		response.PeerPublicKey,
		requestID,
	)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() != 1 {
		return errors.New("pending request binding mismatch")
	}
	_, err = transaction.Exec(
		ctx,
		`UPDATE winn_requests SET committed=true WHERE controller_id=$1 AND request_id=$2`,
		s.controllerID,
		requestID,
	)
	if err != nil {
		return err
	}
	return transaction.Commit(ctx)
}

func (s *PostgresStore) Revoke(ctx context.Context, deviceID string) error {
	if s.closed.Load() {
		return errors.New("PostgreSQL controller state is closed")
	}
	if !protocol.ValidDeviceID(deviceID) {
		return errors.New("invalid device ID")
	}
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer transaction.Rollback(ctx)
	_, err = transaction.Exec(
		ctx,
		`INSERT INTO winn_revoked_devices (controller_id, device_id, revoked, updated_at)
		 VALUES ($1,$2,true,$3)
		 ON CONFLICT (controller_id, device_id)
		 DO UPDATE SET revoked=true, updated_at=EXCLUDED.updated_at`,
		s.controllerID,
		deviceID,
		s.now().UTC(),
	)
	if err != nil {
		return err
	}
	return transaction.Commit(ctx)
}

func (s *PostgresStore) AbortPending(
	ctx context.Context,
	deviceID string,
	peerPublicKey string,
	requestID string,
) error {
	if s.closed.Load() {
		return errors.New("PostgreSQL controller state is closed")
	}
	if !protocol.ValidDeviceID(deviceID) {
		return errors.New("invalid device ID")
	}
	if err := protocol.ValidatePeerPublicKey(peerPublicKey); err != nil {
		return err
	}
	if requestID == "" {
		return errors.New("request ID is required")
	}
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer transaction.Rollback(ctx)
	if err := advisoryLock(ctx, transaction, s.controllerID, "request", requestID); err != nil {
		return err
	}
	if err := advisoryLock(ctx, transaction, s.controllerID, "peer", deviceID, peerPublicKey); err != nil {
		return err
	}
	var pendingRequest *string
	err = transaction.QueryRow(
		ctx,
		`SELECT pending_request_id
		   FROM winn_peers
		  WHERE controller_id=$1 AND device_id=$2 AND peer_public_key=$3
		  FOR UPDATE`,
		s.controllerID,
		deviceID,
		peerPublicKey,
	).Scan(&pendingRequest)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("peer has no pending rotation")
		}
		return err
	}
	if pendingRequest == nil || *pendingRequest == "" {
		return errors.New("peer has no pending rotation")
	}
	if *pendingRequest != requestID {
		return errors.New("pending request binding mismatch")
	}
	commandTag, err := transaction.Exec(
		ctx,
		`DELETE FROM winn_requests
		  WHERE controller_id=$1 AND request_id=$2 AND device_id=$3 AND peer_public_key=$4 AND committed=false`,
		s.controllerID,
		requestID,
		deviceID,
		peerPublicKey,
	)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() != 1 {
		return errors.New("pending request record is missing or already committed")
	}
	_, err = transaction.Exec(
		ctx,
		`UPDATE winn_peers SET pending_request_id=NULL
		  WHERE controller_id=$1 AND device_id=$2 AND peer_public_key=$3 AND pending_request_id=$4`,
		s.controllerID,
		deviceID,
		peerPublicKey,
		requestID,
	)
	if err != nil {
		return err
	}
	return transaction.Commit(ctx)
}

func (s *PostgresStore) Snapshot(ctx context.Context) (Snapshot, error) {
	if s.closed.Load() {
		return Snapshot{}, errors.New("PostgreSQL controller state is closed")
	}
	rows, err := s.pool.Query(
		ctx,
		`SELECT device_id, peer_public_key, suite, generation, key_id, expires_at, pending_request_id
		   FROM winn_peers
		  WHERE controller_id=$1
		  ORDER BY device_id, peer_public_key`,
		s.controllerID,
	)
	if err != nil {
		return Snapshot{}, err
	}
	defer rows.Close()
	result := Snapshot{}
	for rows.Next() {
		var peer PeerSnapshot
		var generation int64
		var expiresAt *time.Time
		var pending *string
		if err := rows.Scan(
			&peer.DeviceID,
			&peer.PeerPublicKey,
			&peer.Suite,
			&generation,
			&peer.KeyID,
			&expiresAt,
			&pending,
		); err != nil {
			return Snapshot{}, err
		}
		peer.Generation, err = generationFromDatabase(generation)
		if err != nil {
			return Snapshot{}, err
		}
		if expiresAt != nil {
			peer.ExpiresAt = expiresAt.UTC().Format(time.RFC3339Nano)
		}
		if pending != nil {
			peer.PendingRequest = *pending
		}
		result.Peers = append(result.Peers, peer)
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, err
	}
	revokedRows, err := s.pool.Query(
		ctx,
		`SELECT device_id
		   FROM winn_revoked_devices
		  WHERE controller_id=$1 AND revoked=true
		  ORDER BY device_id`,
		s.controllerID,
	)
	if err != nil {
		return Snapshot{}, err
	}
	defer revokedRows.Close()
	for revokedRows.Next() {
		var deviceID string
		if err := revokedRows.Scan(&deviceID); err != nil {
			return Snapshot{}, err
		}
		result.RevokedDevices = append(result.RevokedDevices, deviceID)
	}
	return result, revokedRows.Err()
}

func (s *PostgresStore) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	deadline := time.Now().Add(250 * time.Millisecond)
	for {
		s.leaseMu.Lock()
		active := false
		for _, lease := range s.leases {
			if lease.state == 1 && lease.conn != nil {
				active = true
				break
			}
		}
		s.leaseMu.Unlock()
		if !active || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.leaseMu.Lock()
	type quarantinedConnection struct {
		digest [32]byte
		conn   *pgx.Conn
	}
	var physical []quarantinedConnection
	for digest, lease := range s.leases {
		lease.state = 2
		if lease.conn != nil {
			physical = append(physical, quarantinedConnection{
				digest: digest,
				conn:   lease.conn.Hijack(),
			})
			lease.conn = nil
			s.quarantine[digest] = postgresQuarantineReceipt{
				BackendPID:    lease.backendPID,
				FailureClass:  "bounded_shutdown_disposal",
				RecordedAtUTC: time.Now().UTC(),
			}
		}
	}
	s.leaseMu.Unlock()
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	var closeErrors []error
	for _, item := range physical {
		closeErr := s.releaseHooks.close(cleanupCtx, item.conn)
		if closeErr != nil {
			closeErrors = append(closeErrors, closeErr)
		}
		s.leaseMu.Lock()
		receipt := s.quarantine[item.digest]
		receipt.CloseAttempted = true
		receipt.CloseConfirmed = closeErr == nil
		s.quarantine[item.digest] = receipt
		s.leaseMu.Unlock()
	}
	cancel()
	s.pool.Close()
	clear(s.key[:])
	return errors.Join(closeErrors...)
}

func (s *PostgresStore) migrate(ctx context.Context) error {
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin PostgreSQL schema migration: %w", err)
	}
	defer transaction.Rollback(ctx)
	if _, err := transaction.Exec(ctx, `SELECT pg_advisory_xact_lock(7829892146624602157)`); err != nil {
		return fmt.Errorf("lock PostgreSQL schema migration: %w", err)
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS winn_schema (
			singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
			version integer NOT NULL
		)`,
		`INSERT INTO winn_schema (singleton, version) VALUES (true, 1)
		 ON CONFLICT (singleton) DO NOTHING`,
		`CREATE TABLE IF NOT EXISTS winn_revoked_devices (
			controller_id text NOT NULL,
			device_id text NOT NULL,
			revoked boolean NOT NULL,
			updated_at timestamptz NOT NULL,
			PRIMARY KEY (controller_id, device_id)
		)`,
		`CREATE TABLE IF NOT EXISTS winn_peers (
			controller_id text NOT NULL,
			device_id text NOT NULL,
			peer_public_key text NOT NULL,
			suite text NOT NULL,
			generation bigint NOT NULL CHECK (generation >= 0),
			key_id text NOT NULL,
			issued_at timestamptz,
			expires_at timestamptz,
			pending_request_id text,
			PRIMARY KEY (controller_id, device_id, peer_public_key)
		)`,
		`CREATE TABLE IF NOT EXISTS winn_requests (
			controller_id text NOT NULL,
			request_id text NOT NULL,
			device_id text NOT NULL,
			peer_public_key text NOT NULL,
			digest text NOT NULL CHECK (length(digest) = 64),
			response_envelope bytea NOT NULL,
			created_at timestamptz NOT NULL,
			committed boolean NOT NULL DEFAULT false,
			PRIMARY KEY (controller_id, request_id)
		)`,
		`CREATE INDEX IF NOT EXISTS winn_requests_retention_idx
		 ON winn_requests (created_at) WHERE committed=true`,
		`CREATE TABLE IF NOT EXISTS winn_privacy_token_redemptions (
			token_id text PRIMARY KEY CHECK (length(token_id) = 64),
			expires_at timestamptz NOT NULL,
			redeemed_at timestamptz NOT NULL,
			CHECK (expires_at > redeemed_at)
		)`,
		`CREATE INDEX IF NOT EXISTS winn_privacy_token_redemptions_expiry_idx
		 ON winn_privacy_token_redemptions (expires_at)`,
	}
	for _, statement := range statements {
		if _, err := transaction.Exec(ctx, statement); err != nil {
			return fmt.Errorf("apply PostgreSQL schema migration: %w", err)
		}
	}
	var version int
	if err := transaction.QueryRow(ctx, `SELECT version FROM winn_schema WHERE singleton=true`).Scan(&version); err != nil {
		return fmt.Errorf("read PostgreSQL schema version: %w", err)
	}
	if version != postgresSchemaVersion {
		return fmt.Errorf("unsupported PostgreSQL schema version %d", version)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit PostgreSQL schema migration: %w", err)
	}
	return nil
}

func (s *PostgresStore) verifySchema(ctx context.Context) error {
	var version int
	if err := s.pool.QueryRow(ctx, `SELECT version FROM winn_schema WHERE singleton=true`).Scan(&version); err != nil {
		return fmt.Errorf("verify PostgreSQL schema (apply schema/postgres_v1.sql first): %w", err)
	}
	if version != postgresSchemaVersion {
		return fmt.Errorf("unsupported PostgreSQL schema version %d", version)
	}
	return nil
}

func (s *PostgresStore) sealResponse(requestID string, response protocol.RekeyResponse) ([]byte, error) {
	plaintext, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	aead, err := s.responseAEAD()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(s.random, nonce); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nonce, nonce, plaintext, s.responseAD(requestID))
	return sealed, nil
}

func (s *PostgresStore) openResponse(requestID string, envelope []byte) (protocol.RekeyResponse, []byte, error) {
	var response protocol.RekeyResponse
	aead, err := s.responseAEAD()
	if err != nil {
		return response, nil, err
	}
	if len(envelope) < aead.NonceSize()+aead.Overhead() {
		return response, nil, errors.New("encrypted response is too short")
	}
	nonce := envelope[:aead.NonceSize()]
	plaintext, err := aead.Open(nil, nonce, envelope[aead.NonceSize():], s.responseAD(requestID))
	if err != nil {
		return response, nil, errors.New("decrypt stored response: authentication failed")
	}
	defer clear(plaintext)
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return response, nil, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return response, nil, err
	}
	if response.ControllerID != s.controllerID || response.RequestID != requestID {
		return response, nil, errors.New("stored response binding mismatch")
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, response.IssuedAt)
	if err != nil {
		return response, nil, errors.New("stored response has invalid issued_at")
	}
	if response.Generation == 0 {
		return response, nil, errors.New("stored response has invalid generation")
	}
	binding := protocol.RekeyRequest{
		Suite:             response.Suite,
		ControllerID:      response.ControllerID,
		DeviceID:          response.DeviceID,
		PeerPublicKey:     response.PeerPublicKey,
		RequestID:         response.RequestID,
		Nonce:             response.Nonce,
		CurrentGeneration: response.Generation - 1,
	}
	psk, err := protocol.ValidateResponse(binding, response, issuedAt)
	if err != nil {
		return response, nil, err
	}
	if err := pqauth.VerifyResponse(response, s.verifier); err != nil {
		clear(psk)
		return response, nil, err
	}
	return response, psk, nil
}

func (s *PostgresStore) responseAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *PostgresStore) responseAD(requestID string) []byte {
	return []byte(postgresResponseAD + "\x00" + s.controllerID + "\x00" + requestID)
}

func advisoryLock(ctx context.Context, transaction pgx.Tx, values ...string) error {
	key := strings.Join(values, "\x1f")
	_, err := transaction.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key)
	return err
}

func retryablePostgres(err error) bool {
	if err == nil {
		return false
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		return false
	}
	return postgresError.Code == "40001" || postgresError.Code == "40P01"
}

func generationFromDatabase(value int64) (uint64, error) {
	if value < 0 {
		return 0, errors.New("PostgreSQL contains a negative peer generation")
	}
	// #nosec G115 -- the negative range was rejected immediately above.
	return uint64(value), nil
}

func generationToDatabase(value uint64) (int64, error) {
	if value > protocol.MaxGeneration {
		return 0, errors.New("peer generation exceeds the PostgreSQL bigint range")
	}
	// #nosec G115 -- MaxGeneration is exactly the signed bigint maximum.
	return int64(value), nil
}

func validatePostgresDSN(dsn string, allowInsecureLoopback bool) error {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return fmt.Errorf("parse PostgreSQL DSN: %w", err)
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return errors.New("PostgreSQL DSN must be a postgres:// or postgresql:// URL")
	}
	if parsed.User == nil || parsed.User.Username() == "" {
		return errors.New("PostgreSQL DSN must include a database user")
	}
	host := parsed.Hostname()
	if host == "" {
		return errors.New("PostgreSQL DSN must include a host")
	}
	if parsed.Query().Get("sslmode") == "verify-full" {
		return nil
	}
	ip := net.ParseIP(host)
	if allowInsecureLoopback && ip != nil && ip.IsLoopback() {
		return nil
	}
	return errors.New(`PostgreSQL DSN must use sslmode=verify-full (insecure mode is test-only and restricted to loopback)`)
}
