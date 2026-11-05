// Package transparency implements a compact append-only receipt log for Winn
// gateway manifests. It is a deployment-local realization of the SCITT
// transparency-service properties: signed receipts, an append-only hash chain,
// and externally retainable checkpoints.
package transparency

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	Format       = "winn-transparency-receipt/v1"
	MaxLogSize   = 64 << 20
	MaxLineSize  = 64 << 10
	MaxClockSkew = 5 * time.Minute
)

type Receipt struct {
	Format                string `json:"format"`
	Sequence              uint64 `json:"sequence"`
	Timestamp             string `json:"timestamp"`
	ManifestDigest        string `json:"manifest_digest"`
	PreviousReceiptDigest string `json:"previous_receipt_digest,omitempty"`
	AuthAlgorithm         string `json:"auth_algorithm"`
	AuthKeyID             string `json:"auth_key_id"`
	AuthSignature         string `json:"auth_signature"`
}

type Checkpoint struct {
	Size          uint64 `json:"size"`
	ReceiptDigest string `json:"receipt_digest"`
}

func NewReceipt(sequence uint64, manifestDigest, previousDigest string, signer *pqauth.Signer, now time.Time) (Receipt, error) {
	if signer == nil {
		return Receipt{}, errors.New("transparency signer is required")
	}
	receipt := Receipt{
		Format:                Format,
		Sequence:              sequence,
		Timestamp:             now.UTC().Format(time.RFC3339Nano),
		ManifestDigest:        manifestDigest,
		PreviousReceiptDigest: previousDigest,
		AuthAlgorithm:         signer.Algorithm(),
		AuthKeyID:             signer.KeyID(),
	}
	if err := validateReceipt(receipt, false); err != nil {
		return Receipt{}, err
	}
	message, err := unsignedCanonical(receipt)
	if err != nil {
		return Receipt{}, err
	}
	signature, err := pqauth.SignDomainMessage(
		pqauth.TransparencySignatureDomain, message, signer,
	)
	if err != nil {
		return Receipt{}, err
	}
	defer clear(signature)
	receipt.AuthSignature = base64.StdEncoding.EncodeToString(signature)
	return receipt, nil
}

func VerifyReceipt(receipt Receipt, pins *pqauth.VerifierSet) error {
	if pins == nil {
		return errors.New("transparency verifier pins are required")
	}
	if err := validateReceipt(receipt, true); err != nil {
		return err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(receipt.AuthSignature)
	if err != nil || len(signature) == 0 {
		return errors.New("invalid transparency receipt signature encoding")
	}
	defer clear(signature)
	verifier, err := pins.Verifier(receipt.AuthAlgorithm, receipt.AuthKeyID)
	if err != nil {
		return err
	}
	message, err := unsignedCanonical(receipt)
	if err != nil {
		return err
	}
	return pqauth.VerifyDomainMessage(
		pqauth.TransparencySignatureDomain, message, signature, verifier,
	)
}

func Digest(receipt Receipt) (string, error) {
	if receipt.AuthSignature == "" {
		return "", errors.New("cannot digest an unsigned receipt")
	}
	encoded, err := canonical(receipt)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// Append atomically appends one verified-chain receipt. The short-lived
// O_EXCL lock deliberately fails closed after a writer crash; an operator must
// reconcile the log before removing a stale lock.
func Append(path, manifestDigest string, signer *pqauth.Signer, pins *pqauth.VerifierSet, now time.Time) (Receipt, Checkpoint, error) {
	if !validDigest(manifestDigest) {
		return Receipt{}, Checkpoint{}, errors.New("invalid manifest digest")
	}
	if pins == nil {
		return Receipt{}, Checkpoint{},
			errors.New("transparency verifier pins are required")
	}
	release, err := acquireLock(path + ".lock")
	if err != nil {
		return Receipt{}, Checkpoint{}, err
	}
	defer release()
	receipts, checkpoint, err := ReadAndVerify(path, pins)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Receipt{}, Checkpoint{}, err
	}
	sequence := uint64(len(receipts)) + 1
	receipt, err := NewReceipt(sequence, manifestDigest, checkpoint.ReceiptDigest, signer, now)
	if err != nil {
		return Receipt{}, Checkpoint{}, err
	}
	if err := VerifyReceipt(receipt, pins); err != nil {
		return Receipt{}, Checkpoint{},
			fmt.Errorf("verify new transparency receipt: %w", err)
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return Receipt{}, Checkpoint{}, err
	}
	var existing []byte
	if len(receipts) > 0 {
		existing, err = securefile.ReadPublicIntegrity(path, MaxLogSize)
		if err != nil {
			return Receipt{}, Checkpoint{}, err
		}
		defer clear(existing)
	}
	if len(existing)+len(encoded)+1 > MaxLogSize {
		return Receipt{}, Checkpoint{}, errors.New("transparency log exceeds size limit")
	}
	next := make([]byte, 0, len(existing)+len(encoded)+1)
	next = append(next, existing...)
	next = append(next, encoded...)
	next = append(next, '\n')
	defer clear(next)
	if err := securefile.AtomicWrite(path, next, 0o644); err != nil {
		return Receipt{}, Checkpoint{}, err
	}
	digest, err := Digest(receipt)
	if err != nil {
		return Receipt{}, Checkpoint{}, err
	}
	return receipt, Checkpoint{Size: sequence, ReceiptDigest: digest}, nil
}

func ReadAndVerify(path string, pins *pqauth.VerifierSet) ([]Receipt, Checkpoint, error) {
	data, err := securefile.ReadPublicIntegrity(path, MaxLogSize)
	if err != nil {
		return nil, Checkpoint{}, err
	}
	defer clear(data)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), MaxLineSize)
	var receipts []Receipt
	var previous string
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			return nil, Checkpoint{}, errors.New("transparency log contains an empty record")
		}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		var receipt Receipt
		if err := decoder.Decode(&receipt); err != nil {
			return nil, Checkpoint{}, err
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return nil, Checkpoint{}, errors.New("transparency receipt contains extra JSON")
		}
		if receipt.Sequence != uint64(len(receipts))+1 ||
			receipt.PreviousReceiptDigest != previous {
			return nil, Checkpoint{}, errors.New("transparency receipt chain is discontinuous")
		}
		if err := VerifyReceipt(receipt, pins); err != nil {
			return nil, Checkpoint{}, fmt.Errorf("receipt %d: %w", receipt.Sequence, err)
		}
		previous, err = Digest(receipt)
		if err != nil {
			return nil, Checkpoint{}, err
		}
		receipts = append(receipts, receipt)
	}
	if err := scanner.Err(); err != nil {
		return nil, Checkpoint{}, err
	}
	return receipts, Checkpoint{Size: uint64(len(receipts)), ReceiptDigest: previous}, nil
}

// VerifyInclusion verifies the entire append-only chain and requires the
// selected manifest digest to appear in it. When expected is non-nil, it also
// pins the externally retained checkpoint to detect rollback or truncation.
func VerifyInclusion(path, manifestDigest string, pins *pqauth.VerifierSet, expected *Checkpoint) (Checkpoint, error) {
	return verifyInclusion(path, manifestDigest, pins, expected, false)
}

// VerifyInclusionExtension requires the selected manifest receipt to occur
// strictly after expected and requires the verified log head to grow. This is
// used for a manifest sequence advance so a receipt already covered by the
// caller's rollback pin cannot be replayed as a new checkpoint extension.
func VerifyInclusionExtension(
	path string,
	manifestDigest string,
	pins *pqauth.VerifierSet,
	expected Checkpoint,
) (Checkpoint, error) {
	return verifyInclusion(
		path, manifestDigest, pins, &expected, true,
	)
}

func verifyInclusion(
	path string,
	manifestDigest string,
	pins *pqauth.VerifierSet,
	expected *Checkpoint,
	requireExtension bool,
) (Checkpoint, error) {
	if !validDigest(manifestDigest) {
		return Checkpoint{}, errors.New("invalid manifest inclusion digest")
	}
	receipts, checkpoint, err := ReadAndVerify(path, pins)
	if err != nil {
		return Checkpoint{}, err
	}
	if expected != nil {
		if expected.Size == 0 ||
			expected.Size > checkpoint.Size ||
			!validDigest(expected.ReceiptDigest) {
			return Checkpoint{}, errors.New(
				"transparency checkpoint is not an available prefix",
			)
		}
		pinnedDigest, digestErr := Digest(receipts[expected.Size-1])
		if digestErr != nil || pinnedDigest != expected.ReceiptDigest {
			return Checkpoint{}, errors.New(
				"transparency checkpoint prefix mismatch",
			)
		}
		if requireExtension && checkpoint.Size <= expected.Size {
			return Checkpoint{}, errors.New(
				"transparency checkpoint did not extend",
			)
		}
	}
	for index, receipt := range receipts {
		if receipt.ManifestDigest == manifestDigest {
			if requireExtension &&
				uint64(index+1) <= expected.Size {
				continue
			}
			return checkpoint, nil
		}
	}
	if requireExtension {
		return Checkpoint{}, errors.New(
			"gateway manifest receipt does not extend the transparency checkpoint",
		)
	}
	return Checkpoint{}, errors.New("gateway manifest is absent from the transparency log")
}

func unsignedCanonical(receipt Receipt) ([]byte, error) {
	receipt.AuthSignature = ""
	return canonical(receipt)
}

func canonical(receipt Receipt) ([]byte, error) {
	return json.Marshal(receipt)
}

func validateReceipt(receipt Receipt, requireSignature bool) error {
	if receipt.Format != Format || receipt.Sequence == 0 ||
		!validDigest(receipt.ManifestDigest) {
		return errors.New("invalid transparency receipt")
	}
	if receipt.Sequence == 1 {
		if receipt.PreviousReceiptDigest != "" {
			return errors.New("first transparency receipt has a predecessor")
		}
	} else if !validDigest(receipt.PreviousReceiptDigest) {
		return errors.New("transparency receipt predecessor is invalid")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, receipt.Timestamp)
	if err != nil || timestamp.Location() != time.UTC {
		return errors.New("transparency receipt timestamp must be RFC3339Nano UTC")
	}
	if receipt.AuthAlgorithm != pqauth.MLDSA65 && receipt.AuthAlgorithm != pqauth.MLDSA87 {
		return errors.New("invalid transparency authentication algorithm")
	}
	if !validDigest(receipt.AuthKeyID) {
		return errors.New("invalid transparency authentication key ID")
	}
	if requireSignature && receipt.AuthSignature == "" {
		return errors.New("transparency signature is required")
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func acquireLock(path string) (func(), error) {
	if err := securefile.EnsurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	// #nosec G304 -- path is an explicit administrator-configured log path.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("acquire transparency log lock: %w", err)
	}
	return func() {
		_ = file.Close()
		_ = os.Remove(path)
	}, nil
}
