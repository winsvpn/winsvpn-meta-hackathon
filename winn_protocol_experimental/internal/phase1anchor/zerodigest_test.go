// Canonical previous-receipt digests.
//
// These exist because the constant had four independent copies and one of them
// was wrong. The controller passed "" as the genesis predecessor; this package
// rejects it. Nothing caught that, because nothing tested the boundary between
// the two — so a real run would have contacted two external providers and
// failed on their side, mid-chain, on a sequence that cannot be retracted.
package phase1anchor

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestZeroDigestIsCanonical(t *testing.T) {
	if len(ZeroDigest) != 64 {
		t.Fatalf("ZeroDigest is %d characters, want 64", len(ZeroDigest))
	}
	if ZeroDigest != strings.Repeat("0", 64) {
		t.Fatalf("ZeroDigest is %q", ZeroDigest)
	}
	if !ValidDigest(ZeroDigest) {
		t.Fatal("the canonical zero digest is not a valid digest")
	}
	// The ledger's own constant must be the exported one, not a copy.
	if zeroDigest != ZeroDigest {
		t.Fatal("the ledger keeps a separate zero-digest constant")
	}
}

func TestValidDigestRejectsNonCanonicalForms(t *testing.T) {
	for name, value := range map[string]string{
		"empty":       "",
		"short":       strings.Repeat("0", 63),
		"long":        strings.Repeat("0", 65),
		"uppercase":   strings.ToUpper(strings.Repeat("ab", 32)),
		"non_hex":     strings.Repeat("g", 64),
		"whitespace":  " " + strings.Repeat("0", 63),
		"zero_prefix": strings.Repeat("0", 32),
	} {
		t.Run(name, func(t *testing.T) {
			if ValidDigest(value) {
				t.Fatalf("%q was accepted as a canonical digest", value)
			}
		})
	}
	if !ValidDigest(strings.Repeat("ab", 32)) {
		t.Fatal("a canonical lowercase digest was refused")
	}
}

// TestValidPreviousDigestSeparatesGenesisFromTheChain pins the one rule that
// distinguishes the two positions: genesis carries exactly the zero digest, and
// no later link may.
func TestValidPreviousDigestSeparatesGenesisFromTheChain(t *testing.T) {
	real := strings.Repeat("ab", 32)

	if !ValidPreviousDigest(ZeroDigest, 0) {
		t.Fatal("the canonical zero digest was refused at genesis")
	}
	if ValidPreviousDigest("", 0) {
		t.Fatal(
			"the empty string was accepted as a genesis predecessor; this is " +
				"exactly the value the controller was passing",
		)
	}
	if ValidPreviousDigest(real, 0) {
		t.Fatal("a real receipt digest was accepted as a genesis predecessor")
	}
	if !ValidPreviousDigest(real, 1) {
		t.Fatal("a canonical digest was refused mid-chain")
	}
	if ValidPreviousDigest(ZeroDigest, 1) {
		t.Fatal("the zero digest was accepted mid-chain")
	}
	if ValidPreviousDigest("", 1) {
		t.Fatal("the empty string was accepted mid-chain")
	}
}

// TestNewReceiptRefusesAnEmptyPredecessorBeforeSigning proves the refusal
// happens locally, at construction, rather than after a wasted provider round
// trip.
func TestNewReceiptRefusesAnEmptyPredecessorBeforeSigning(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{
		Schema:             RequestSchema,
		Kind:               KindGenesis,
		MatrixID:           "phase1-auto-v1",
		SourceDigest:       strings.Repeat("1", 64),
		AutoArtifactDigest: strings.Repeat("2", 64),
		ProfileDigest:      strings.Repeat("3", 64),
		ScheduleDigest:     strings.Repeat("4", 64),
		ExpectedBatchCount: 1,
		Ordinal:            0,
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("the fixture request must be valid: %v", err)
	}
	stamp := "2026-07-26T00:00:00Z"

	if _, err := NewReceipt(
		request, "provider-one", "", stamp, private,
	); err == nil {
		t.Fatal(
			"a receipt was signed over an empty predecessor; the controller's " +
				"genesis call would have been accepted",
		)
	}
	if _, err := NewReceipt(
		request, "provider-one", ZeroDigest, stamp, private,
	); err != nil {
		t.Fatalf("the canonical genesis predecessor was refused: %v", err)
	}
}

// TestReceiptVerifyRejectsAnEmptyPredecessor covers the verifying side of the
// same boundary.
func TestReceiptVerifyRejectsAnEmptyPredecessor(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{
		Schema:             RequestSchema,
		Kind:               KindGenesis,
		MatrixID:           "phase1-auto-v1",
		SourceDigest:       strings.Repeat("1", 64),
		AutoArtifactDigest: strings.Repeat("2", 64),
		ProfileDigest:      strings.Repeat("3", 64),
		ScheduleDigest:     strings.Repeat("4", 64),
		ExpectedBatchCount: 1,
		Ordinal:            0,
	}
	receipt, err := NewReceipt(
		request, "provider-one", ZeroDigest,
		"2026-07-26T00:00:00Z", private,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.Verify(
		request, "provider-one", public, ZeroDigest,
	); err != nil {
		t.Fatalf("a genuine genesis receipt was refused: %v", err)
	}
	if err := receipt.Verify(
		request, "provider-one", public, "",
	); err == nil {
		t.Fatal(
			"verification accepted an empty expected predecessor, so a caller " +
				"passing \"\" would appear to succeed",
		)
	}
}

// TestNewReceiptRefusesZeroDigestOffGenesis and its Verify counterpart are the
// defense-in-depth half of the ordinal rule.
//
// Fixing the controller and the pin CLI protects the two call sites that were
// audited. It does nothing for any other caller of this package, now or later.
// The invariant has to be impossible to violate through the core types
// themselves, or it is only a convention that happens to hold today.
func TestNewReceiptRefusesZeroDigestOffGenesis(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	stamp := "2026-07-26T00:00:00Z"
	real := strings.Repeat("ab", 32)

	batch := chainFixtureRequest(KindBatch, 4)
	if _, err := NewReceipt(
		batch, "provider-one", ZeroDigest, stamp, private,
	); err == nil {
		t.Fatal(
			"a non-genesis receipt was signed with the genesis predecessor; " +
				"the chain would fork at that link with a valid signature on it",
		)
	}
	if _, err := NewReceipt(
		batch, "provider-one", real, stamp, private,
	); err != nil {
		t.Fatalf("a canonical mid-chain predecessor was refused: %v", err)
	}

	genesis := chainFixtureRequest(KindGenesis, 0)
	if _, err := NewReceipt(
		genesis, "provider-one", real, stamp, private,
	); err == nil {
		t.Fatal("a genesis receipt was signed with a real predecessor digest")
	}
	if _, err := NewReceipt(
		genesis, "provider-one", ZeroDigest, stamp, private,
	); err != nil {
		t.Fatalf("the canonical genesis predecessor was refused: %v", err)
	}
}

// TestVerifyRefusesZeroDigestOffGenesis covers the verifying side, including
// the case both sides agree on the wrong value.
func TestVerifyRefusesZeroDigestOffGenesis(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	batch := chainFixtureRequest(KindBatch, 4)

	// A receipt genuinely signed over the zero digest at ordinal 4. NewReceipt
	// refuses to build one now, so it is constructed directly — which is
	// exactly what a pre-fix producer, or a hostile one, would have on disk.
	forged := forgeReceiptWithPredecessor(t, batch, ZeroDigest, private)
	if err := forged.Verify(
		batch, "provider-one", public, ZeroDigest,
	); err == nil {
		t.Fatal(
			"a non-genesis receipt carrying the genesis predecessor verified; " +
				"both sides agreed on a value that is illegal at this position, " +
				"and the signature over it is genuine",
		)
	}

	// And the caller's expectation alone is checked too.
	honest := forgeReceiptWithPredecessor(
		t, batch, strings.Repeat("ab", 32), private)
	if err := honest.Verify(
		batch, "provider-one", public, ZeroDigest,
	); err == nil {
		t.Fatal("verification accepted an illegal expected predecessor")
	}
	if err := honest.Verify(
		batch, "provider-one", public, strings.Repeat("ab", 32),
	); err != nil {
		t.Fatalf("a legal mid-chain receipt was refused: %v", err)
	}
}

func chainFixtureRequest(kind string, ordinal int) Request {
	request := Request{
		Schema:             RequestSchema,
		Kind:               kind,
		MatrixID:           "phase1-auto-v1",
		SourceDigest:       strings.Repeat("1", 64),
		AutoArtifactDigest: strings.Repeat("2", 64),
		ProfileDigest:      strings.Repeat("3", 64),
		ScheduleDigest:     strings.Repeat("4", 64),
		ExpectedBatchCount: 8,
		Ordinal:            ordinal,
	}
	if kind == KindBatch {
		request.BatchKey = "b0004-edge-warm"
		request.ScheduleRowDigest = strings.Repeat("5", 64)
		request.Profile = "baseline"
		request.Readiness = "warm"
		request.AttemptCount = 100
		request.ArchiveDigest = strings.Repeat("6", 64)
		request.EvidenceManifestDigest = strings.Repeat("7", 64)
		request.AttemptLogDigest = strings.Repeat("8", 64)
		request.AttemptAnchorDigest = strings.Repeat("9", 64)
	}
	return request
}

// forgeReceiptWithPredecessor builds and signs a receipt directly, bypassing
// NewReceipt's guard, so the verifying side can be tested against inputs a
// well-behaved signer will no longer produce.
func forgeReceiptWithPredecessor(
	t *testing.T,
	request Request,
	previousDigest string,
	private ed25519.PrivateKey,
) Receipt {
	t.Helper()
	requestDigest, err := request.Digest()
	if err != nil {
		t.Fatal(err)
	}
	idempotencyKey, err := request.IdempotencyKey()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := unsignedReceipt{
		Schema:                ReceiptSchema,
		ProviderID:            "provider-one",
		ProviderKeyID:         PublicKeyID(private.Public().(ed25519.PublicKey)),
		ProviderSequence:      request.Ordinal,
		PreviousReceiptDigest: previousDigest,
		IdempotencyKey:        idempotencyKey,
		RequestDigest:         requestDigest,
		ReceivedAtUTC:         "2026-07-26T00:00:00Z",
		MatrixID:              request.MatrixID,
	}
	message, err := receiptMessage(unsigned)
	if err != nil {
		t.Fatal(err)
	}
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
		Signature: base64.StdEncoding.EncodeToString(
			ed25519.Sign(private, message),
		),
	}
}
