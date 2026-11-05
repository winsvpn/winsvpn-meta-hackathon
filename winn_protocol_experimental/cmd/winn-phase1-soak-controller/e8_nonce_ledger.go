//go:build winn_incomplete_e8

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// Durable single-use rehearsal-nonce ledger.
//
// The in-receipt seenNonces map in validateE8Receipt only proves that the four
// node contracts of one receipt carry distinct nonces. It cannot prove that a
// nonce was never consumed by an earlier run under the same grant, and it does
// not survive a crash. This ledger closes that gap.
//
// Consumption is recorded by an exclusive create of a per-nonce entry inside a
// grant-scoped directory. Exclusive create is atomic, so the durable record of
// a consumed nonce can never be torn into a reusable state:
//
//   - if the entry does not exist, the nonce has not been consumed;
//   - if the entry exists, the nonce is consumed and can never be replayed,
//     regardless of whether the payload was fully written before a crash.
//
// A crash between the exclusive create and the directory sync therefore
// resolves conservatively: either the entry is absent (never consumed) or it is
// present (treated as consumed). There is no state in which a previously
// consumed nonce becomes available again, which is the fail-closed direction.
//
// The entry payload is written and fsynced before the directory is fsynced,
// mirroring the E8 transaction event idiom in e8_transaction_linux.go.
const (
	e8NonceLedgerDirectory = ".local-rehearsal-nonce-ledger"
	e8NonceLedgerSchema    = "winn-local-sealed-rehearsal-nonce-consumption/v1"
	e8NonceLedgerDomain    = "winn-realcycle-e8-rehearsal-nonce-consumption/v1"
	e8NonceLedgerMaxBytes  = 4 << 10
)

// e8NonceLedgerEntry is the durable record of one consumed nonce. Field order
// is the canonical encoding order and must not be reordered.
type e8NonceLedgerEntry struct {
	Schema                string    `json:"schema"`
	GrantObjectDigest     string    `json:"grant_object_digest"`
	GrantCollectionDigest string    `json:"grant_collection_digest"`
	RehearsalNonce        string    `json:"rehearsal_nonce"`
	GrantRootDevice       uint64    `json:"grant_root_device"`
	GrantRootInode        uint64    `json:"grant_root_inode"`
	OutputDevice          uint64    `json:"output_device"`
	OutputInode           uint64    `json:"output_inode"`
	NodeNonces            [4]string `json:"node_nonces"`
	Consumed              bool      `json:"consumed"`
	ObjectDigest          string    `json:"object_digest"`
}

type e8NonceLedgerBinding struct {
	GrantRootDevice uint64
	GrantRootInode  uint64
	OutputDevice    uint64
	OutputInode     uint64
}

// e8NonceLedger is a grant-scoped, crash-persistent single-use nonce store.
type e8NonceLedger struct {
	directory             *secureDirectory
	grantObjectDigest     string
	grantCollectionDigest string
}

var e8NonceDurabilityBoundaryOperation = func(string) error { return nil }

func openE8DurableDirectory(
	parent *secureDirectory,
	name, stage string,
) (*secureDirectory, error) {
	if parent == nil || parent.file == nil {
		return nil, errors.New("E8 nonce durable parent is missing")
	}
	if err := parent.Mkdir(name, 0o700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	} else {
		if err := e8NonceDurabilityBoundaryOperation(
			stage + "-mkdir",
		); err != nil {
			return nil, err
		}
	}
	child, err := parent.OpenDirectory(name)
	if err != nil {
		return nil, err
	}
	fail := func(stageErr error) (*secureDirectory, error) {
		return nil, errors.Join(stageErr, child.Close())
	}
	info, err := child.file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fail(errors.New(
			"E8 nonce directory identity or mode is invalid",
		))
	}
	if err := child.VerifyPath(); err != nil {
		return fail(err)
	}
	// Sync the new inode before its parent name, then sync the parent entry.
	// Repeating both syncs for an existing directory makes restart after a
	// process death at any earlier boundary converge to the same durable
	// namespace.
	if err := child.Sync(); err != nil {
		return fail(err)
	}
	if err := e8NonceDurabilityBoundaryOperation(
		stage + "-directory-sync",
	); err != nil {
		return fail(err)
	}
	if err := parent.Sync(); err != nil {
		return fail(err)
	}
	if err := e8NonceDurabilityBoundaryOperation(
		stage + "-parent-sync",
	); err != nil {
		return fail(err)
	}
	if err := parent.VerifyPath(); err != nil {
		return fail(err)
	}
	if err := child.VerifyPath(); err != nil {
		return fail(err)
	}
	return child, nil
}

// openE8NonceLedger opens, creating if absent, the grant-scoped ledger
// directory beneath the supplied evidence root. Two different grants never
// share a scope, so a nonce consumed under one grant cannot mask a nonce under
// another.
func openE8NonceLedger(
	root *secureDirectory, grant e8GrantResult,
) (*e8NonceLedger, error) {
	if root == nil {
		return nil, errors.New("E8 nonce ledger root is missing")
	}
	if !digestPattern.MatchString(grant.CollectionDigest) ||
		!digestPattern.MatchString(grant.GrantObjectDigest) {
		return nil, errors.New("E8 nonce ledger grant identity is malformed")
	}
	base, err := openE8DurableDirectory(
		root, e8NonceLedgerDirectory, "ledger-base",
	)
	if err != nil {
		return nil, err
	}
	scope, err := openE8DurableDirectory(
		base, grant.CollectionDigest, "grant-scope",
	)
	if err != nil {
		_ = base.Close()
		return nil, err
	}
	if err := base.Close(); err != nil {
		_ = scope.Close()
		return nil, err
	}
	return &e8NonceLedger{
		directory:             scope,
		grantObjectDigest:     grant.GrantObjectDigest,
		grantCollectionDigest: grant.CollectionDigest,
	}, nil
}

func e8NonceLedgerEntryName(nonce string) (string, error) {
	if !noncePattern.MatchString(nonce) {
		return "", errors.New("E8 rehearsal nonce is malformed")
	}
	return nonce + ".json", nil
}

// Consumed reports whether the nonce was already consumed under this grant.
// Any existing entry counts as consumed, including a partially written one.
func (ledger *e8NonceLedger) Consumed(nonce string) (bool, error) {
	if ledger == nil || ledger.directory == nil {
		return false, errors.New("E8 nonce ledger is closed")
	}
	name, err := e8NonceLedgerEntryName(nonce)
	if err != nil {
		return false, err
	}
	file, err := ledger.directory.Open(name, os.O_RDONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if err := file.Close(); err != nil {
		return true, err
	}
	return true, nil
}

// Consume durably records a single use of the nonce under this grant. It
// returns an error when the nonce was already consumed, which is terminal
// replay evidence.
func (ledger *e8NonceLedger) Consume(nonce string) error {
	return ledger.consume(nonce, e8NonceLedgerBinding{}, false)
}

// Reserve durably consumes a nonce for one exact retained grant-root and
// output-root identity. A complete matching claim is idempotent recovery for
// that same transaction. A copied grant root, another output, or any torn
// claim fails closed as replay.
func (ledger *e8NonceLedger) Reserve(
	nonce string,
	binding e8NonceLedgerBinding,
) error {
	if binding.GrantRootDevice == 0 || binding.GrantRootInode == 0 ||
		binding.OutputDevice == 0 || binding.OutputInode == 0 {
		return errors.New("E8 nonce reservation binding is incomplete")
	}
	return ledger.consume(nonce, binding, true)
}

// ReserveRun consumes the grant nonce and durably catalogs the four CSPRNG
// node nonces before any child can start. Exact recovery returns the original
// catalog; copied grants and torn claims fail closed.
func (ledger *e8NonceLedger) ReserveRun(
	nonce string,
	binding e8NonceLedgerBinding,
) ([4]string, error) {
	var absent [4]string
	if ledger == nil || ledger.directory == nil {
		return absent, errors.New("E8 nonce ledger is closed")
	}
	if binding.GrantRootDevice == 0 || binding.GrantRootInode == 0 ||
		binding.OutputDevice == 0 || binding.OutputInode == 0 {
		return absent, errors.New("E8 nonce reservation binding is incomplete")
	}
	name, err := e8NonceLedgerEntryName(nonce)
	if err != nil {
		return absent, err
	}
	entry := ledger.entry(nonce, binding)
	seen := map[string]bool{}
	for index := range entry.NodeNonces {
		raw := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, raw); err != nil {
			return absent, err
		}
		entry.NodeNonces[index] = hex.EncodeToString(raw)
		if seen[entry.NodeNonces[index]] {
			return absent, errors.New("E8 node nonce generator repeated output")
		}
		seen[entry.NodeNonces[index]] = true
	}
	encoded, err := encodeE8NonceLedgerEntry(entry)
	if err != nil {
		return absent, err
	}
	file, err := openAdmittedPrivateFile(
		ledger.directory, name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
	)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ledger.recoverRun(name, entry)
		}
		return absent, err
	}
	if err := e8NonceDurabilityBoundaryOperation(
		"claim-name-created",
	); err != nil {
		return absent, errors.Join(err, file.Close())
	}
	if err := ledger.persistClaim(file, encoded); err != nil {
		return absent, err
	}
	return entry.NodeNonces, nil
}

func (ledger *e8NonceLedger) consume(
	nonce string,
	binding e8NonceLedgerBinding,
	allowExactRecovery bool,
) error {
	if ledger == nil || ledger.directory == nil {
		return errors.New("E8 nonce ledger is closed")
	}
	name, err := e8NonceLedgerEntryName(nonce)
	if err != nil {
		return err
	}
	entry := ledger.entry(nonce, binding)
	encoded, err := encodeE8NonceLedgerEntry(entry)
	if err != nil {
		return err
	}
	file, err := openAdmittedPrivateFile(
		ledger.directory, name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
	)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			if allowExactRecovery {
				return ledger.recoverExact(name, entry)
			}
			return errors.New("E8 rehearsal nonce was already consumed")
		}
		return err
	}
	if err := e8NonceDurabilityBoundaryOperation(
		"claim-name-created",
	); err != nil {
		return errors.Join(err, file.Close())
	}
	return ledger.persistClaim(file, encoded)
}

var e8NonceLedgerWriteOperation = writeAll

func (ledger *e8NonceLedger) entry(
	nonce string,
	binding e8NonceLedgerBinding,
) e8NonceLedgerEntry {
	return e8NonceLedgerEntry{
		Schema:                e8NonceLedgerSchema,
		GrantObjectDigest:     ledger.grantObjectDigest,
		GrantCollectionDigest: ledger.grantCollectionDigest,
		RehearsalNonce:        nonce,
		GrantRootDevice:       binding.GrantRootDevice,
		GrantRootInode:        binding.GrantRootInode,
		OutputDevice:          binding.OutputDevice,
		OutputInode:           binding.OutputInode,
		Consumed:              true,
	}
}

func encodeE8NonceLedgerEntry(entry e8NonceLedgerEntry) ([]byte, error) {
	entry.ObjectDigest = ""
	digest, err := admittedDigest(e8NonceLedgerDomain, entry)
	if err != nil {
		return nil, err
	}
	entry.ObjectDigest = digest
	encoded, err := json.Marshal(entry)
	if err != nil || len(encoded) > e8NonceLedgerMaxBytes {
		return nil, errors.New("E8 nonce ledger entry exceeds bound")
	}
	return encoded, nil
}

func (ledger *e8NonceLedger) persistClaim(
	file *os.File,
	encoded []byte,
) error {
	// Persist the exclusive name before its payload. A crash from this point
	// onward can leave a complete claim or a permanent torn tombstone, but
	// never an absent reusable nonce.
	if err := ledger.directory.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := e8NonceDurabilityBoundaryOperation(
		"claim-name-directory-sync",
	); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := e8NonceLedgerWriteOperation(file, encoded); err != nil {
		return errors.Join(
			fmt.Errorf("E8 nonce ledger entry is not writable: %w", err),
			file.Close(),
		)
	}
	if err := e8NonceDurabilityBoundaryOperation(
		"claim-payload-written",
	); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := e8NonceDurabilityBoundaryOperation(
		"claim-file-sync",
	); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := e8NonceDurabilityBoundaryOperation(
		"claim-file-close",
	); err != nil {
		return err
	}
	if err := ledger.directory.Sync(); err != nil {
		return err
	}
	return e8NonceDurabilityBoundaryOperation("claim-final-directory-sync")
}

func (ledger *e8NonceLedger) recoverExact(
	name string,
	expected e8NonceLedgerEntry,
) error {
	file, err := ledger.directory.Open(name, os.O_RDONLY, 0o600)
	if err != nil {
		return errors.New("E8 rehearsal nonce has an unreadable prior claim")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, e8NonceLedgerMaxBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 ||
		len(data) > e8NonceLedgerMaxBytes {
		return errors.New("E8 rehearsal nonce has a torn prior claim")
	}
	var actual e8NonceLedgerEntry
	if err := decodeStrictObject(data, &actual); err != nil {
		return errors.New("E8 rehearsal nonce has a torn prior claim")
	}
	digest := actual.ObjectDigest
	actual.ObjectDigest = ""
	expectedDigest, err := admittedDigest(e8NonceLedgerDomain, actual)
	actual.ObjectDigest = digest
	if err != nil || digest != expectedDigest || actual != expected {
		return errors.New("E8 rehearsal nonce was already consumed")
	}
	return nil
}

func (ledger *e8NonceLedger) recoverRun(
	name string,
	expected e8NonceLedgerEntry,
) ([4]string, error) {
	var absent [4]string
	file, err := ledger.directory.Open(name, os.O_RDONLY, 0o600)
	if err != nil {
		return absent, errors.New(
			"E8 rehearsal nonce has an unreadable prior claim",
		)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, e8NonceLedgerMaxBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 ||
		len(data) > e8NonceLedgerMaxBytes {
		return absent, errors.New("E8 rehearsal nonce has a torn prior claim")
	}
	var actual e8NonceLedgerEntry
	if err := decodeStrictObject(data, &actual); err != nil {
		return absent, errors.New("E8 rehearsal nonce has a torn prior claim")
	}
	digest := actual.ObjectDigest
	actual.ObjectDigest = ""
	derived, err := admittedDigest(e8NonceLedgerDomain, actual)
	actual.ObjectDigest = digest
	if err != nil || digest != derived {
		return absent, errors.New("E8 rehearsal nonce has a torn prior claim")
	}
	expected.NodeNonces = actual.NodeNonces
	expected.ObjectDigest = actual.ObjectDigest
	seen := map[string]bool{}
	for _, nodeNonce := range actual.NodeNonces {
		if !noncePattern.MatchString(nodeNonce) || seen[nodeNonce] {
			return absent, errors.New(
				"E8 rehearsal nonce has an invalid node catalog",
			)
		}
		seen[nodeNonce] = true
	}
	if actual != expected {
		return absent, errors.New("E8 rehearsal nonce was already consumed")
	}
	return actual.NodeNonces, nil
}

// Close releases the retained grant-scoped directory.
func (ledger *e8NonceLedger) Close() error {
	if ledger == nil || ledger.directory == nil {
		return nil
	}
	directory := ledger.directory
	ledger.directory = nil
	return directory.Close()
}
