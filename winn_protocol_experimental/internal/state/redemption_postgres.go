package state

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"winsvpn.local/winnprotocol/internal/privacytoken"
)

const maximumRedemptionLifetime = 7 * 24 * time.Hour

type PostgresRedemptionOptions struct {
	DSN                   string
	MaxConnections        int
	AllowInsecureLoopback bool
	AutoMigrate           bool
}

// PostgresRedemptionStore is a cluster-wide atomic single-use token ledger.
// Every carrier instance sharing the database observes the same unique token
// ID constraint, including across process restarts.
type PostgresRedemptionStore struct {
	pool   *pgxpool.Pool
	now    func() time.Time
	closed atomic.Bool
}

func OpenPostgresRedemptions(
	ctx context.Context,
	options PostgresRedemptionOptions,
) (*PostgresRedemptionStore, error) {
	if ctx == nil {
		return nil, errors.New(
			"PostgreSQL redemption startup context is required",
		)
	}
	if options.MaxConnections < 1 || options.MaxConnections > 1024 {
		return nil, errors.New(
			"PostgreSQL redemption connections must be between 1 and 1024",
		)
	}
	if err := validatePostgresDSN(
		options.DSN, options.AllowInsecureLoopback,
	); err != nil {
		return nil, err
	}
	poolConfig, err := pgxpool.ParseConfig(options.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL redemption DSN: %w", err)
	}
	// #nosec G115 -- MaxConnections is bounded above.
	poolConfig.MaxConns = int32(options.MaxConnections)
	poolConfig.MinConns = 1
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL redemption pool: %w", err)
	}
	store := &PostgresRedemptionStore{pool: pool, now: time.Now}
	if err := pool.Ping(ctx); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("ping PostgreSQL redemption store: %w", err)
	}
	if options.AutoMigrate {
		err = store.migrate(ctx)
		if err == nil {
			err = store.verifySchema(ctx)
		}
	} else {
		err = store.verifySchema(ctx)
	}
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func (store *PostgresRedemptionStore) Redeem(
	ctx context.Context,
	tokenID string,
	expiresAt time.Time,
) error {
	if store == nil || store.closed.Load() {
		return errors.New("PostgreSQL redemption store is closed")
	}
	if ctx == nil {
		return errors.New("privacy token redemption context is required")
	}
	if !validRedemptionTokenID(tokenID) {
		return errors.New("privacy token redemption ID is invalid")
	}
	now := store.now().UTC()
	expiresAt = expiresAt.UTC()
	if !expiresAt.After(now) ||
		expiresAt.Sub(now) > maximumRedemptionLifetime {
		return errors.New("privacy token redemption expiry is invalid")
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		err := store.redeemOnce(ctx, tokenID, expiresAt, now)
		if !retryablePostgres(err) {
			return err
		}
		lastErr = err
	}
	return fmt.Errorf(
		"PostgreSQL redemption retry limit reached: %w", lastErr,
	)
}

func (store *PostgresRedemptionStore) redeemOnce(
	ctx context.Context,
	tokenID string,
	expiresAt time.Time,
	now time.Time,
) error {
	transaction, err := store.pool.BeginTx(
		ctx, pgx.TxOptions{IsoLevel: pgx.Serializable},
	)
	if err != nil {
		return err
	}
	defer transaction.Rollback(ctx)
	tag, err := transaction.Exec(
		ctx,
		`INSERT INTO winn_privacy_token_redemptions
			(token_id, expires_at, redeemed_at)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (token_id) DO NOTHING`,
		tokenID, expiresAt, now,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return privacytoken.ErrAlreadyRedeemed
	}
	if err := transaction.Commit(ctx); err != nil {
		return err
	}
	return nil
}

func (store *PostgresRedemptionStore) Durable() bool {
	return true
}

func (store *PostgresRedemptionStore) Close() error {
	if store == nil || store.closed.Swap(true) {
		return nil
	}
	store.pool.Close()
	return nil
}

func (store *PostgresRedemptionStore) migrate(
	ctx context.Context,
) error {
	transaction, err := store.pool.BeginTx(
		ctx, pgx.TxOptions{IsoLevel: pgx.Serializable},
	)
	if err != nil {
		return fmt.Errorf(
			"begin PostgreSQL redemption migration: %w", err,
		)
	}
	defer transaction.Rollback(ctx)
	if _, err := transaction.Exec(
		ctx, `SELECT pg_advisory_xact_lock(7829892146624602157)`,
	); err != nil {
		return fmt.Errorf("lock PostgreSQL redemption migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS winn_privacy_token_redemptions (
			token_id text PRIMARY KEY CHECK (length(token_id) = 64),
			expires_at timestamptz NOT NULL,
			redeemed_at timestamptz NOT NULL,
			CHECK (expires_at > redeemed_at)
		)`); err != nil {
		return fmt.Errorf("apply PostgreSQL redemption migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		CREATE INDEX IF NOT EXISTS winn_privacy_token_redemptions_expiry_idx
		ON winn_privacy_token_redemptions (expires_at)`); err != nil {
		return fmt.Errorf(
			"apply PostgreSQL redemption retention index: %w", err,
		)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf(
			"commit PostgreSQL redemption migration: %w", err,
		)
	}
	return nil
}

func (store *PostgresRedemptionStore) verifySchema(
	ctx context.Context,
) error {
	var version int
	if err := store.pool.QueryRow(
		ctx, `SELECT version FROM winn_schema WHERE singleton=true`,
	).Scan(&version); err != nil {
		return fmt.Errorf(
			"verify PostgreSQL redemption schema version: %w", err,
		)
	}
	if version != postgresSchemaVersion {
		return fmt.Errorf(
			"unsupported PostgreSQL redemption schema version %d", version,
		)
	}
	var tableName *string
	if err := store.pool.QueryRow(
		ctx,
		`SELECT to_regclass('public.winn_privacy_token_redemptions')::text`,
	).Scan(&tableName); err != nil {
		return fmt.Errorf("verify PostgreSQL redemption schema: %w", err)
	}
	if tableName == nil || *tableName == "" {
		return errors.New(
			"verify PostgreSQL redemption schema (apply schema/postgres_v1.sql first): table is missing",
		)
	}
	var primaryTokenID bool
	if err := store.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			  FROM pg_constraint constraint_record
			  JOIN pg_class table_record
			    ON table_record.oid = constraint_record.conrelid
			  JOIN pg_namespace namespace_record
			    ON namespace_record.oid = table_record.relnamespace
			 WHERE namespace_record.nspname = 'public'
			   AND table_record.relname =
			       'winn_privacy_token_redemptions'
			   AND constraint_record.contype = 'p'
			   AND pg_get_constraintdef(constraint_record.oid) =
			       'PRIMARY KEY (token_id)'
		)`).Scan(&primaryTokenID); err != nil {
		return fmt.Errorf(
			"verify PostgreSQL redemption uniqueness: %w", err,
		)
	}
	if !primaryTokenID {
		return errors.New(
			"PostgreSQL redemption schema lacks the token_id primary key",
		)
	}
	return nil
}

func validRedemptionTokenID(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
