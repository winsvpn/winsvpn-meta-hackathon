// Package phase1anchor defines the signed, monotonic, two-provider archive
// receipts used to pin every formal Phase 1 evidence batch off-host.
package phase1anchor

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	RequestSchema = "winn-phase1-archive-pin/v1"
	ReceiptSchema = "winn-phase1-archive-receipt/v1"

	KindGenesis = "genesis"
	KindBatch   = "batch"
	KindSeal    = "seal"

	requestDomain     = "winn-phase1-archive-pin/v1"
	idempotencyDomain = "winn-phase1-pin-idempotency/v1"
	receiptDomain     = "winn-phase1-archive-receipt/v1"
)

var safeID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// Request is serialized as canonical JSON by encoding/json over this fixed
// struct. Unknown fields are rejected at every trust boundary.
type Request struct {
	Schema             string `json:"schema"`
	Kind               string `json:"kind"`
	MatrixID           string `json:"matrix_id"`
	SourceDigest       string `json:"source_digest"`
	AutoArtifactDigest string `json:"auto_artifact_digest"`
	ProfileDigest      string `json:"profile_digest"`
	ScheduleDigest     string `json:"schedule_digest"`
	ExpectedBatchCount int    `json:"expected_batch_count"`
	Ordinal            int    `json:"ordinal"`

	BatchKey               string `json:"batch_key,omitempty"`
	ScheduleRowDigest      string `json:"schedule_row_digest,omitempty"`
	Profile                string `json:"profile,omitempty"`
	Readiness              string `json:"readiness,omitempty"`
	AttemptCount           int    `json:"attempt_count,omitempty"`
	ArchiveDigest          string `json:"archive_sha256,omitempty"`
	EvidenceManifestDigest string `json:"evidence_manifest_sha256,omitempty"`
	AttemptLogDigest       string `json:"attempt_log_sha256,omitempty"`
	AttemptAnchorDigest    string `json:"attempt_anchor_sha256,omitempty"`

	AggregateDigest string `json:"aggregate_sha256,omitempty"`
}

// Receipt is the durable provider response. Signature authenticates every
// field except Signature itself using a domain-separated canonical encoding.
type Receipt struct {
	Schema                string `json:"schema"`
	ProviderID            string `json:"provider_id"`
	ProviderKeyID         string `json:"provider_key_id"`
	ProviderSequence      int    `json:"provider_sequence"`
	PreviousReceiptDigest string `json:"previous_receipt_sha256"`
	IdempotencyKey        string `json:"idempotency_key"`
	RequestDigest         string `json:"request_sha256"`
	ReceivedAtUTC         string `json:"received_at_utc"`
	MatrixID              string `json:"matrix_id"`
	Signature             string `json:"signature_ed25519"`
}

type unsignedReceipt struct {
	Schema                string `json:"schema"`
	ProviderID            string `json:"provider_id"`
	ProviderKeyID         string `json:"provider_key_id"`
	ProviderSequence      int    `json:"provider_sequence"`
	PreviousReceiptDigest string `json:"previous_receipt_sha256"`
	IdempotencyKey        string `json:"idempotency_key"`
	RequestDigest         string `json:"request_sha256"`
	ReceivedAtUTC         string `json:"received_at_utc"`
	MatrixID              string `json:"matrix_id"`
}

func (request Request) Validate() error {
	if request.Schema != RequestSchema ||
		!safeID.MatchString(request.MatrixID) ||
		!digest(request.SourceDigest) ||
		!digest(request.AutoArtifactDigest) ||
		!digest(request.ProfileDigest) ||
		!digest(request.ScheduleDigest) ||
		request.ExpectedBatchCount < 1 ||
		request.ExpectedBatchCount > 100_000 {
		return errors.New("archive-pin request has invalid matrix identity")
	}
	emptyBatch := request.BatchKey == "" &&
		request.ScheduleRowDigest == "" &&
		request.Profile == "" &&
		request.Readiness == "" &&
		request.AttemptCount == 0 &&
		request.ArchiveDigest == "" &&
		request.EvidenceManifestDigest == "" &&
		request.AttemptLogDigest == "" &&
		request.AttemptAnchorDigest == ""
	switch request.Kind {
	case KindGenesis:
		if request.Ordinal != 0 || !emptyBatch ||
			request.AggregateDigest != "" {
			return errors.New("genesis request has batch or seal fields")
		}
	case KindBatch:
		if request.Ordinal < 1 ||
			request.Ordinal > request.ExpectedBatchCount ||
			!safeID.MatchString(request.BatchKey) ||
			!digest(request.ScheduleRowDigest) ||
			!safeID.MatchString(request.Profile) ||
			(request.Readiness != "warm" &&
				request.Readiness != "cold") ||
			request.AttemptCount != 100 ||
			!digest(request.ArchiveDigest) ||
			!digest(request.EvidenceManifestDigest) ||
			!digest(request.AttemptLogDigest) ||
			!digest(request.AttemptAnchorDigest) ||
			request.AggregateDigest != "" {
			return errors.New("batch request is incomplete or inconsistent")
		}
	case KindSeal:
		if request.Ordinal != request.ExpectedBatchCount+1 ||
			!emptyBatch || !digest(request.AggregateDigest) {
			return errors.New("seal request is incomplete or inconsistent")
		}
	default:
		return errors.New("archive-pin request kind is invalid")
	}
	return nil
}

func (request Request) Canonical() ([]byte, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(request)
}

func DecodeRequest(reader io.Reader) (Request, error) {
	data, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
	if err != nil {
		return Request{}, err
	}
	if len(data) > 64<<10 {
		return Request{}, errors.New("archive-pin request exceeds 64 KiB")
	}
	var request Request
	if err := decodeStrict(data, &request); err != nil {
		return Request{}, err
	}
	if err := request.Validate(); err != nil {
		return Request{}, err
	}
	return request, nil
}

func DecodeReceipt(reader io.Reader) (Receipt, error) {
	data, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
	if err != nil {
		return Receipt{}, err
	}
	if len(data) > 64<<10 {
		return Receipt{}, errors.New("archive receipt exceeds 64 KiB")
	}
	var receipt Receipt
	if err := decodeStrict(data, &receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func (request Request) Digest() (string, error) {
	canonical, err := request.Canonical()
	if err != nil {
		return "", err
	}
	return domainDigest(requestDomain, canonical), nil
}

func (request Request) IdempotencyKey() (string, error) {
	if err := request.Validate(); err != nil {
		return "", err
	}
	material := fmt.Sprintf("%s\x00%s\x00%016x",
		// #nosec G115 -- Validate bounds Ordinal to [0,100001].
		idempotencyDomain, request.MatrixID, uint64(request.Ordinal),
	)
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:]), nil
}

func PublicKeyID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:])
}

func NewReceipt(
	request Request,
	providerID string,
	previousDigest string,
	receivedAtUTC string,
	private ed25519.PrivateKey,
) (Receipt, error) {
	if !safeID.MatchString(providerID) ||
		!canonicalTimestamp(receivedAtUTC) ||
		len(private) != ed25519.PrivateKeySize {
		return Receipt{}, errors.New("receipt signer configuration is invalid")
	}
	// The ordinal-aware rule, enforced by the type rather than by whoever
	// happens to be calling it.
	//
	// A plain canonical-digest check here would accept ZeroDigest at any
	// position, so a non-genesis receipt could be signed with the genesis
	// predecessor and the chain would fork at that link while every individual
	// signature stayed valid. Pushing that check out to callers means the
	// invariant holds only for the callers someone remembered to audit; putting
	// it here means a direct package caller cannot violate it at all.
	if !ValidPreviousDigest(previousDigest, request.Ordinal) {
		if request.Ordinal == 0 {
			return Receipt{}, fmt.Errorf(
				"genesis receipt previous digest is %q, want the canonical "+
					"zero digest", previousDigest,
			)
		}
		return Receipt{}, fmt.Errorf(
			"receipt previous digest %q is not valid at ordinal %d; the zero "+
				"digest belongs only to genesis",
			previousDigest, request.Ordinal,
		)
	}
	requestDigest, err := request.Digest()
	if err != nil {
		return Receipt{}, err
	}
	idempotencyKey, err := request.IdempotencyKey()
	if err != nil {
		return Receipt{}, err
	}
	unsigned := unsignedReceipt{
		Schema:                ReceiptSchema,
		ProviderID:            providerID,
		ProviderKeyID:         PublicKeyID(private.Public().(ed25519.PublicKey)),
		ProviderSequence:      request.Ordinal,
		PreviousReceiptDigest: previousDigest,
		IdempotencyKey:        idempotencyKey,
		RequestDigest:         requestDigest,
		ReceivedAtUTC:         receivedAtUTC,
		MatrixID:              request.MatrixID,
	}
	message, err := receiptMessage(unsigned)
	if err != nil {
		return Receipt{}, err
	}
	signature := ed25519.Sign(private, message)
	return Receipt{
		Schema:                unsigned.Schema,
		ProviderID:            unsigned.ProviderID,
		ProviderKeyID:         unsigned.ProviderKeyID,
		ProviderSequence:      unsigned.ProviderSequence,
		PreviousReceiptDigest: unsigned.PreviousReceiptDigest,
		IdempotencyKey:        unsigned.IdempotencyKey,
		RequestDigest:         unsigned.RequestDigest,
		ReceivedAtUTC:         unsigned.ReceivedAtUTC,
		MatrixID:              unsigned.MatrixID,
		Signature:             base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func (receipt Receipt) Verify(
	request Request,
	expectedProvider string,
	public ed25519.PublicKey,
	previousDigest string,
) error {
	requestDigest, err := request.Digest()
	if err != nil {
		return err
	}
	idempotencyKey, err := request.IdempotencyKey()
	if err != nil {
		return err
	}
	if receipt.Schema != ReceiptSchema ||
		receipt.ProviderID != expectedProvider ||
		receipt.ProviderKeyID != PublicKeyID(public) ||
		receipt.ProviderSequence != request.Ordinal ||
		receipt.PreviousReceiptDigest != previousDigest ||
		receipt.IdempotencyKey != idempotencyKey ||
		receipt.RequestDigest != requestDigest ||
		receipt.MatrixID != request.MatrixID {
		return errors.New("receipt metadata does not match its pinned request")
	}
	if !canonicalTimestamp(receipt.ReceivedAtUTC) {
		return errors.New("receipt timestamp is not canonical UTC RFC3339Nano")
	}
	// The same ordinal-aware rule on the verifying side, applied to BOTH the
	// caller's expectation and the receipt's own stored value.
	//
	// The equality check above only proves the two agree; it does not prove
	// either is legal at this position. Two agreeing wrong values — a
	// non-genesis receipt sealed and expected with the zero digest — would pass
	// every other check here, including the signature, because the receipt was
	// genuinely signed over exactly those bytes. This is additive: the equality
	// and signature checks still stand.
	if !ValidPreviousDigest(previousDigest, request.Ordinal) {
		return fmt.Errorf(
			"the expected previous digest %q is not valid at ordinal %d",
			previousDigest, request.Ordinal,
		)
	}
	if !ValidPreviousDigest(receipt.PreviousReceiptDigest, request.Ordinal) {
		return fmt.Errorf(
			"the receipt's previous digest %q is not valid at ordinal %d; the "+
				"zero digest belongs only to genesis",
			receipt.PreviousReceiptDigest, request.Ordinal,
		)
	}
	signature, err := base64.StdEncoding.DecodeString(receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("receipt signature encoding is invalid")
	}
	unsigned := unsignedReceipt{
		Schema:                receipt.Schema,
		ProviderID:            receipt.ProviderID,
		ProviderKeyID:         receipt.ProviderKeyID,
		ProviderSequence:      receipt.ProviderSequence,
		PreviousReceiptDigest: receipt.PreviousReceiptDigest,
		IdempotencyKey:        receipt.IdempotencyKey,
		RequestDigest:         receipt.RequestDigest,
		ReceivedAtUTC:         receipt.ReceivedAtUTC,
		MatrixID:              receipt.MatrixID,
	}
	message, err := receiptMessage(unsigned)
	if err != nil {
		return err
	}
	if !ed25519.Verify(public, message, signature) {
		return errors.New("receipt signature verification failed")
	}
	return nil
}

// Canonical returns the single encoding a receipt is permitted to have on
// disk. Digest hashes a re-marshal of the parsed struct, so on its own it
// cannot pin the sealed file's bytes: encoding/json accepts duplicate object
// keys (last wins) and ignores insignificant whitespace, so several distinct
// byte sequences can parse to the same receipt and produce the same digest.
// Callers that verify sealed evidence must compare the file bytes against
// Canonical (plus the trailing newline the writer emits) so two auditors using
// different JSON parsers cannot read different values out of one sealed file.
func (receipt Receipt) Canonical() ([]byte, error) {
	if receipt.Schema != ReceiptSchema {
		return nil, errors.New("receipt schema is invalid")
	}
	return json.Marshal(receipt)
}

func (receipt Receipt) Digest() (string, error) {
	canonical, err := receipt.Canonical()
	if err != nil {
		return "", err
	}
	return domainDigest(receiptDomain, canonical), nil
}

// receiptMessage builds the Ed25519 signing preimage. The canonical value it
// signs is the compact encoding/json encoding of the fixed unsigned struct
// with NO trailing LF; the LF a sealed file or JSONL line carries is framing
// only and must never enter this preimage.
func receiptMessage(receipt unsignedReceipt) ([]byte, error) {
	canonical, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return domainMessage(receiptDomain, canonical), nil
}

func domainDigest(domain string, canonical []byte) string {
	sum := sha256.Sum256(domainMessage(domain, canonical))
	return hex.EncodeToString(sum[:])
}

func domainMessage(domain string, canonical []byte) []byte {
	result := make([]byte, 0, len(domain)+1+len(canonical))
	result = append(result, domain...)
	result = append(result, 0)
	result = append(result, canonical...)
	return result
}

// ZeroDigest is the canonical "no predecessor" previous-receipt digest: the
// genesis anchor's previous digest, and the only value permitted there.
//
// It exists as ONE exported symbol because it was previously four independent
// 64-zero literals — in this package's ledger, in the formal verifier, in the
// pin client's expectations, and (wrongly) as an empty string in the
// controller. Four copies of a constant agree only by the coincidence of having
// been copied correctly, and the controller's copy was not: it passed "", which
// this package's own validator rejects, so a real run would have contacted two
// external providers and failed mid-chain on an irreversible anchor sequence.
//
// A shared constant makes that class of divergence impossible to reintroduce
// by omission.
const ZeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"

// ValidDigest reports whether value is a canonical lowercase 64-character hex
// SHA-256 digest.
//
// Canonical means exactly that: uppercase hex, short values, and the empty
// string are all rejected. Every previous-receipt digest in the chain must
// satisfy this, and the genesis link must additionally equal ZeroDigest.
func ValidDigest(value string) bool {
	return digest(value)
}

// ValidPreviousDigest reports whether value is acceptable as a previous-receipt
// digest for an anchor at the given ordinal.
//
// Ordinal 0 is the genesis link, where the only acceptable value is ZeroDigest;
// every later link must carry a canonical digest of the receipt before it. This
// is the single place that rule is expressed, so a caller cannot accidentally
// accept an empty predecessor at genesis or a zero predecessor halfway down the
// chain.
func ValidPreviousDigest(value string, ordinal int) bool {
	if ordinal == 0 {
		return value == ZeroDigest
	}
	return digest(value) && value != ZeroDigest
}

func digest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, current := range value {
		if (current < '0' || current > '9') &&
			(current < 'a' || current > 'f') {
			return false
		}
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func canonicalTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil &&
		strings.HasSuffix(value, "Z") &&
		parsed.UTC().Format(time.RFC3339Nano) == value
}
