// The provider-side append-only anchor ledger. POSIX only.
//
// This file is the reason the boundary in rejection.go exists: Append holds an
// exclusive flock(2) for the whole read-verify-append sequence, and every ledger
// file is opened with O_NOFOLLOW|O_CLOEXEC. Both are load-bearing — the lock is
// what makes the monotonic chain safe against a concurrent second request for
// the same ordinal, and O_NOFOLLOW is what stops a planted symbolic link from
// redirecting the append. Neither has a portable equivalent, and neither is
// emulated on a platform that lacks it.
//
// A host without these primitives therefore does not get a Ledger at all. That
// makes cmd/winn-phase1-anchor-server a POSIX-only binary, which it always was
// in fact; the build constraint states it rather than discovering it at link
// time.

//go:build unix

package phase1anchor

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Ledger durably appends one signed, monotonic receipt chain per matrix.
type Ledger struct {
	Directory  string
	ProviderID string
	PrivateKey ed25519.PrivateKey
	Now        func() time.Time
}

type ledgerRecord struct {
	Request Request `json:"request"`
	Receipt Receipt `json:"receipt"`
}

func reject(err error) error {
	return RejectionError{Err: err}
}

func (ledger Ledger) Append(request Request) (Receipt, error) {
	if err := request.Validate(); err != nil {
		return Receipt{}, reject(err)
	}
	if !safeID.MatchString(ledger.ProviderID) ||
		len(ledger.PrivateKey) != ed25519.PrivateKeySize {
		return Receipt{}, errors.New("ledger signer configuration is invalid")
	}
	if err := secureDirectory(ledger.Directory); err != nil {
		return Receipt{}, err
	}
	lockPath := filepath.Join(ledger.Directory, request.MatrixID+".lock")
	// #nosec G304 -- Directory is an administrator-configured private
	// directory and MatrixID is restricted to a slash-free safe identifier.
	lock, err := openLedgerFile(
		lockPath, unix.O_CREAT|unix.O_RDWR, 0o600,
	)
	if err != nil {
		return Receipt{}, err
	}
	defer lock.Close()
	lockDescriptor := lock.Fd()
	if lockDescriptor > uintptr(^uint(0)>>1) {
		return Receipt{}, errors.New("ledger lock descriptor is out of range")
	}
	// #nosec G115 -- the uintptr value is bounded above by max int.
	lockFD := int(lockDescriptor)
	if err := unix.Flock(lockFD, unix.LOCK_EX); err != nil {
		return Receipt{}, err
	}
	defer func() {
		_ = unix.Flock(lockFD, unix.LOCK_UN)
	}()

	logPath := filepath.Join(ledger.Directory, request.MatrixID+".jsonl")
	records, err := ledger.readAndVerify(logPath, request)
	if err != nil {
		return Receipt{}, reject(err)
	}
	if len(records) > 0 &&
		!sameMatrixIdentity(records[0].Request, request) {
		return Receipt{}, reject(errors.New(
			"request changes the frozen provider-ledger identity",
		))
	}
	requestDigest, err := request.Digest()
	if err != nil {
		return Receipt{}, err
	}
	// The append state machine, in the order it decides:
	//
	//  1. slot already recorded -- an exact retry replays the stored receipt,
	//     any other request for that slot is a permanent conflict;
	//  2. chain already terminal -- a sealed chain admits no new record;
	//  3. slot not contiguous -- a sequence gap is a permanent rejection;
	//  4. otherwise sign the new record and durably append it.
	//
	// Step 1 must stay ahead of step 2. A sealed matrix still has to replay
	// every receipt it already holds, the terminal seal included, so a
	// provider that lost a response can retry the identical request and get
	// the identical receipt. Only a *new* record is barred after the seal.
	if request.Ordinal < len(records) {
		existing := records[request.Ordinal]
		if existing.Receipt.RequestDigest != requestDigest {
			return Receipt{}, reject(errors.New(
				"occupied provider sequence conflicts with request",
			))
		}
		return existing.Receipt, nil
	}
	// Defence in depth, and deliberately not the guard doing the work today.
	// Appends after a seal are actually rejected by the occupied-slot branch
	// above: a sealed chain holds ExpectedBatchCount+2 records, Validate
	// bounds Ordinal to {0}, [1,ExpectedBatchCount] and {ExpectedBatchCount+1},
	// and sameMatrixIdentity freezes ExpectedBatchCount to the genesis record,
	// so every ordinal a caller can express is below len(records) and already
	// occupied. This condition is therefore unreachable as the package stands.
	// It is kept because that unreachability is an emergent property of
	// ordinal arithmetic that lives in another file: widening the ordinal
	// bounds, adding a request kind, or letting ExpectedBatchCount drift would
	// silently reopen a terminal chain for appends. With this check the seal
	// invariant survives such a change as an explicit rejection rather than
	// becoming a silent extension of sealed evidence.
	if isTerminalChain(records, request.ExpectedBatchCount) {
		return Receipt{}, reject(errors.New("provider ledger is already sealed"))
	}
	if request.Ordinal != len(records) {
		return Receipt{}, reject(fmt.Errorf(
			"provider sequence gap: got %d want %d",
			request.Ordinal, len(records),
		))
	}
	previous := zeroDigest
	if len(records) > 0 {
		previous, err = records[len(records)-1].Receipt.Digest()
		if err != nil {
			return Receipt{}, err
		}
	}
	now := time.Now
	if ledger.Now != nil {
		now = ledger.Now
	}
	receipt, err := NewReceipt(
		request,
		ledger.ProviderID,
		previous,
		now().UTC().Format(time.RFC3339Nano),
		ledger.PrivateKey,
	)
	if err != nil {
		return Receipt{}, err
	}
	// Canonical form, stated once for third-party implementations. The
	// canonical value of a ledger record -- and of every signature and digest
	// preimage in this package -- is the compact encoding/json encoding of the
	// fixed struct, with NO trailing LF. The sealed file form is that exact
	// value plus one LF. That LF is framing only: it terminates the JSONL line
	// and is never part of any signed or hashed input, so an implementation
	// that hashes or signs the newline computes a different value from this
	// one. readAndVerify pins both halves of the rule on the way back in.
	line, err := json.Marshal(ledgerRecord{
		Request: request,
		Receipt: receipt,
	})
	if err != nil {
		return Receipt{}, err
	}
	// #nosec G304 -- logPath is scoped to the validated private directory
	// and a slash-free MatrixID.
	file, err := openLedgerFile(
		logPath, unix.O_CREAT|unix.O_WRONLY|unix.O_APPEND, 0o600,
	)
	if err != nil {
		return Receipt{}, err
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		return Receipt{}, errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return Receipt{}, errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return Receipt{}, err
	}
	directory, err := os.Open(ledger.Directory)
	if err != nil {
		return Receipt{}, err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return Receipt{}, errors.Join(syncErr, closeErr)
	}
	return receipt, nil
}

func (ledger Ledger) readAndVerify(
	path string,
	request Request,
) ([]ledgerRecord, error) {
	// #nosec G304 -- path is built from the validated private directory and
	// a slash-free MatrixID.
	file, err := openLedgerFile(path, unix.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > 64<<20 {
		return nil, errors.New("provider ledger exceeds 64 MiB")
	}
	reader := bufio.NewReader(io.LimitReader(file, 64<<20))
	var records []ledgerRecord
	previous := zeroDigest
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			if line[len(line)-1] != '\n' {
				return nil, errors.New("provider ledger has ambiguous tail")
			}
			var record ledgerRecord
			if err := decodeStrict(line, &record); err != nil {
				return nil, fmt.Errorf("provider ledger receipt: %w", err)
			}
			if err := pinCanonicalRecord(line, record); err != nil {
				return nil, err
			}
			if record.Request.Ordinal != len(records) ||
				(len(records) == 0 &&
					record.Request.Kind != KindGenesis) ||
				(len(records) > 0 &&
					!sameMatrixIdentity(
						records[0].Request, record.Request,
					)) {
				return nil, errors.New(
					"provider ledger request sequence is invalid",
				)
			}
			if err := record.Receipt.Verify(
				record.Request,
				ledger.ProviderID,
				ledger.PrivateKey.Public().(ed25519.PublicKey),
				previous,
			); err != nil {
				return nil, err
			}
			records = append(records, record)
			previous, err = record.Receipt.Digest()
			if err != nil {
				return nil, err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	return records, nil
}

func openLedgerFile(path string, flags int, mode uint32) (*os.File, error) {
	// #nosec G304 -- path is built from the administrator-owned private
	// ledger directory and a slash-free validated matrix identifier.
	descriptor, err := unix.Open(
		path, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode,
	)
	if err != nil {
		return nil, err
	}
	// #nosec G115 -- unix.Open returned a nonnegative live descriptor.
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("cannot wrap provider ledger descriptor")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, errors.Join(
			errors.New("provider ledger file is not private and regular"),
			err,
			file.Close(),
		)
	}
	return file, nil
}

// isTerminalChain reports whether a verified chain already ends in its seal
// record, the terminal state after which no further record may be appended.
// readAndVerify pins every record's ordinal to its index and Receipt.Verify
// pins ProviderSequence to that ordinal, so the last record's sequence is
// always len(records)-1 and this asks exactly one question: is the seal slot,
// ExpectedBatchCount+1, filled? Callers must pass the batch count from a
// request whose matrix identity has already been matched against records[0],
// which is what freezes ExpectedBatchCount for the life of the chain.
func isTerminalChain(records []ledgerRecord, expectedBatchCount int) bool {
	return len(records) > 0 &&
		records[len(records)-1].Receipt.ProviderSequence ==
			expectedBatchCount+1
}

func sameMatrixIdentity(left Request, right Request) bool {
	return left.MatrixID == right.MatrixID &&
		left.SourceDigest == right.SourceDigest &&
		left.AutoArtifactDigest == right.AutoArtifactDigest &&
		left.ProfileDigest == right.ProfileDigest &&
		left.ScheduleDigest == right.ScheduleDigest &&
		left.ExpectedBatchCount == right.ExpectedBatchCount
}

func secureDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return errors.New("ledger directory must be a private real directory")
	}
	return nil
}

// pinCanonicalRecord requires a sealed JSONL line to be exactly the canonical
// encoding of the record it decoded to, plus the one terminating LF. Strict
// decoding alone pins the parsed value, not the bytes: encoding/json keeps the
// last of duplicate object keys and ignores insignificant whitespace, so many
// distinct lines decode to one record and hash to one digest. Two auditors
// running different JSON parsers could then read different provider or request
// values out of the same ledger line while every signature, digest and chain
// link still verified. This is the byte pin the sealed anchor slot files
// already carry, applied to provider recovery and audit state.
func pinCanonicalRecord(line []byte, record ledgerRecord) error {
	canonical, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if !bytes.Equal(line, append(canonical, '\n')) {
		return errors.New(
			"provider ledger record bytes are not the canonical encoding",
		)
	}
	return nil
}
