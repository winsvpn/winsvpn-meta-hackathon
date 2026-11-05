package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/audit"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/revocation"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/state"
)

func main() {
	var statePath string
	var stateKeyPath string
	var auditLogPath string
	var auditKeyPath string
	var postgresDSNFile string
	var postgresMaxConnections int
	var postgresInsecureLoopback bool
	var action string
	var deviceID string
	var peerPublicKey string
	var requestID string
	var ttl time.Duration
	var controllerID string
	var labMode bool
	var controllerSeedPath string
	var controllerAlgorithm string
	var revocationOut string
	var revocationSequence uint64
	var revocationValidity time.Duration
	flag.StringVar(&statePath, "state", "", "encrypted controller state path")
	flag.StringVar(&stateKeyPath, "state-key", "", "32-byte controller state key path")
	flag.StringVar(&auditLogPath, "audit-log", "", "tamper-evident JSONL audit log path")
	flag.StringVar(&auditKeyPath, "audit-key", "", "32-byte HMAC audit key path")
	flag.StringVar(&postgresDSNFile, "postgres-dsn-file", "", "private file containing a PostgreSQL URL (alternative to -state)")
	flag.IntVar(&postgresMaxConnections, "postgres-max-connections", 4, "PostgreSQL connection pool ceiling")
	flag.BoolVar(&postgresInsecureLoopback, "postgres-insecure-loopback", false, "allow test-only non-TLS PostgreSQL on a numeric loopback address")
	flag.StringVar(&action, "action", "snapshot", "snapshot, revoke, abort-pending, or revocation-list")
	flag.StringVar(&controllerSeedPath, "controller-pq-seed", "", "controller ML-DSA seed that signs the revocation list")
	flag.StringVar(&controllerAlgorithm, "controller-pq-algorithm", pqauth.MLDSA87, "controller ML-DSA algorithm")
	flag.StringVar(&revocationOut, "revocation-out", "", "output path for the signed device revocation list")
	flag.Uint64Var(&revocationSequence, "revocation-sequence", 0, "revocation list sequence; 0 reads the existing -revocation-out and increments")
	flag.DurationVar(&revocationValidity, "revocation-validity", 24*time.Hour, "revocation list validity window")
	flag.StringVar(&deviceID, "device-id", "", "device to revoke")
	flag.StringVar(&peerPublicKey, "peer-public-key", "", "peer key for abort-pending")
	flag.StringVar(&requestID, "request-id", "", "exact pending request ID for abort-pending")
	flag.DurationVar(&ttl, "key-ttl", 24*time.Hour, "state key TTL setting")
	flag.StringVar(&controllerID, "controller-id", "winn-controller-1", "controller audience identifier")
	flag.BoolVar(&labMode, "lab-mode", false, "enable explicitly non-production settings")
	flag.Parse()
	if stateKeyPath == "" || auditLogPath == "" || auditKeyPath == "" {
		exitError("-state-key, -audit-log, and -audit-key are required")
	}
	if (statePath == "") == (postgresDSNFile == "") {
		exitError("choose exactly one state backend: -state or -postgres-dsn-file")
	}
	if postgresMaxConnections < 1 || postgresMaxConnections > 1024 {
		exitError("-postgres-max-connections must be between 1 and 1024")
	}
	if postgresInsecureLoopback && !labMode {
		exitError("-postgres-insecure-loopback requires -lab-mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var store state.AdministrativeController
	var err error
	if postgresDSNFile != "" {
		dsnData, readErr := securefile.ReadPrivateLimited(postgresDSNFile, 64<<10)
		if readErr != nil {
			exitError("read PostgreSQL DSN: " + readErr.Error())
		}
		dsn := strings.TrimSpace(string(dsnData))
		clear(dsnData)
		store, err = state.OpenPostgres(ctx, state.PostgresOptions{
			DSN:                   dsn,
			StateKeyPath:          stateKeyPath,
			TTL:                   ttl,
			ControllerID:          controllerID,
			MaxConnections:        postgresMaxConnections,
			AllowInsecureLoopback: postgresInsecureLoopback,
			AdministrativeOnly:    true,
		})
	} else {
		store, err = state.OpenAdministrative(statePath, stateKeyPath, ttl, controllerID)
	}
	if err != nil {
		exitError(err.Error())
	}
	defer store.Close()
	auditLog, err := audit.Open(auditLogPath, auditKeyPath)
	if err != nil {
		exitError(err.Error())
	}
	defer auditLog.Close()
	switch action {
	case "snapshot":
		snapshot, err := store.Snapshot(ctx)
		if err != nil {
			exitError(err.Error())
		}
		encoded, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			exitError(err.Error())
		}
		if err := auditLog.Record("admin_snapshot", "", "", "controller state snapshot read"); err != nil {
			exitError(err.Error())
		}
		fmt.Println(string(encoded))
	case "revoke":
		if deviceID == "" {
			exitError("-device-id is required for revoke")
		}
		if err := store.Revoke(ctx, deviceID); err != nil {
			exitError(err.Error())
		}
		if err := auditLog.Record("device_revoked", deviceID, "", "administrator revoked device"); err != nil {
			exitError(err.Error())
		}
		fmt.Printf("{\"status\":\"revoked\",\"device_id\":%q}\n", deviceID)
	case "abort-pending":
		if deviceID == "" || peerPublicKey == "" || requestID == "" {
			exitError("-device-id, -peer-public-key, and -request-id are required for abort-pending")
		}
		if err := store.AbortPending(ctx, deviceID, peerPublicKey, requestID); err != nil {
			exitError(err.Error())
		}
		if err := auditLog.Record("pending_rotation_aborted", deviceID, requestID, "administrator cleared exact pending rotation"); err != nil {
			exitError(err.Error())
		}
		fmt.Printf("{\"status\":\"pending_aborted\",\"device_id\":%q,\"request_id\":%q}\n", deviceID, requestID)
	case "revocation-list":
		if controllerSeedPath == "" || revocationOut == "" {
			exitError("-controller-pq-seed and -revocation-out are required for revocation-list")
		}
		// KnownGoodAt is taken before the snapshot read, not after, so the
		// list can only ever understate how current it is. A device revoked
		// while this command runs lands in the next list rather than being
		// silently attributed to this one.
		knownGoodAt := time.Now().UTC()
		snapshot, err := store.Snapshot(ctx)
		if err != nil {
			exitError(err.Error())
		}
		sequence := revocationSequence
		if sequence == 0 {
			sequence, err = nextRevocationSequence(revocationOut)
			if err != nil {
				exitError(err.Error())
			}
		}
		list, err := revocation.Build(
			controllerID, sequence, knownGoodAt, revocationValidity,
			snapshot.RevokedDevices,
		)
		if err != nil {
			exitError(err.Error())
		}
		signer, err := pqauth.LoadSigner(controllerAlgorithm, controllerSeedPath)
		if err != nil {
			exitError(err.Error())
		}
		defer signer.Destroy()
		if err := revocation.Sign(&list, signer); err != nil {
			exitError(err.Error())
		}
		encoded, err := revocation.Encode(list)
		if err != nil {
			exitError(err.Error())
		}
		// 0o644: the list is a public trust input, not a secret. It is
		// authenticated by signature, so confidentiality of the file buys
		// nothing, and carriers must be able to read it.
		if err := securefile.AtomicWrite(revocationOut, encoded, 0o644); err != nil {
			exitError(err.Error())
		}
		if err := auditLog.Record(
			"revocation_list_published", "", "",
			fmt.Sprintf(
				"sequence=%d devices=%d validity=%s",
				list.Sequence, len(list.RevokedHashes), revocationValidity,
			),
		); err != nil {
			exitError(err.Error())
		}
		// Device identifiers are not printed. The list itself carries only
		// salted hashes, and echoing the plaintext roster to a terminal or a
		// CI log would undo that.
		fmt.Printf(
			"{\"status\":\"published\",\"sequence\":%d,\"revoked_devices\":%d,\"known_good_at\":%q,\"not_after\":%q,\"path\":%q}\n",
			list.Sequence, len(list.RevokedHashes), list.KnownGoodAt,
			list.NotAfter, revocationOut,
		)
	default:
		exitError("-action must be snapshot, revoke, abort-pending, or revocation-list")
	}
}

// nextRevocationSequence advances the monotone counter from whatever is
// already published, so an operator cannot accidentally reissue a lower
// sequence and have every carrier reject the new list as a rollback.
func nextRevocationSequence(path string) (uint64, error) {
	previous, err := revocation.Load(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read existing revocation list: %w", err)
	}
	if previous.Sequence == ^uint64(0) {
		return 0, errors.New("revocation list sequence would overflow")
	}
	return previous.Sequence + 1, nil
}

func exitError(message string) {
	fmt.Fprintln(os.Stderr, "winn-admin:", message)
	os.Exit(1)
}
