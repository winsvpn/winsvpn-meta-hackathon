// Ledger tamper suite. POSIX only, for the same reason as ledger.go.

//go:build unix

package phase1anchor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const tamperTimestamp = "2026-07-25T00:00:00Z"

// secondPrivateKey is the independent second-provider signer. It must never
// equal testPrivateKey so that cross-provider substitution is a real forgery.
func secondPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(
		[]byte("fedcba9876543210fedcba9876543210"),
	)
}

func mustReceipt(
	t *testing.T,
	request Request,
	providerID string,
	previous string,
	receivedAt string,
	private ed25519.PrivateKey,
) Receipt {
	t.Helper()
	receipt, err := NewReceipt(
		request, providerID, previous, receivedAt, private,
	)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

// tamperPredecessor is a real mid-chain predecessor digest.
//
// These fixtures used the zero digest at ordinal 1, which the package now
// refuses: the zero digest is the genesis link and nothing else. Using it
// off-genesis made every fixture here an example of the very state the chain
// rule forbids.
const tamperPredecessor = "abababababababababababababababab" +
	"abababababababababababababababab"

func flipSignatureByte(t *testing.T, receipt *Receipt) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(receipt.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		t.Fatalf("fixture signature is unusable: %v", err)
	}
	raw[0] ^= 0x01
	receipt.Signature = base64.StdEncoding.EncodeToString(raw)
}

func TestReceiptVerifyRejectsEveryTamperedField(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *Receipt)
		want   string
	}{
		{
			"schema",
			func(_ *testing.T, r *Receipt) { r.Schema = RequestSchema },
			"metadata",
		},
		{
			"provider_identity",
			func(_ *testing.T, r *Receipt) { r.ProviderID = "provider-two" },
			"metadata",
		},
		{
			"provider_key_id",
			func(_ *testing.T, r *Receipt) {
				r.ProviderKeyID = strings.Repeat("f", 64)
			},
			"metadata",
		},
		{
			"replayed_at_later_sequence",
			func(_ *testing.T, r *Receipt) { r.ProviderSequence = 2 },
			"metadata",
		},
		{
			"broken_previous_receipt_link",
			func(_ *testing.T, r *Receipt) {
				r.PreviousReceiptDigest = strings.Repeat("c", 64)
			},
			"metadata",
		},
		{
			"idempotency_key",
			func(_ *testing.T, r *Receipt) {
				r.IdempotencyKey = strings.Repeat("d", 64)
			},
			"metadata",
		},
		{
			"request_digest",
			func(_ *testing.T, r *Receipt) {
				r.RequestDigest = strings.Repeat("e", 64)
			},
			"metadata",
		},
		{
			"non_canonical_timestamp",
			func(_ *testing.T, r *Receipt) {
				r.ReceivedAtUTC = "2026-07-25T00:00:00+00:00"
			},
			"canonical UTC",
		},
		{
			// received_at_utc is the only receipt field no metadata
			// comparison pins, so this case proves the Ed25519 signature
			// itself covers it.
			"canonical_but_forged_timestamp",
			func(_ *testing.T, r *Receipt) {
				r.ReceivedAtUTC = "2026-07-25T00:00:01Z"
			},
			"signature verification failed",
		},
		{
			"flipped_signature_byte",
			func(t *testing.T, r *Receipt) { flipSignatureByte(t, r) },
			"signature verification failed",
		},
		{
			"signature_is_not_base64",
			func(_ *testing.T, r *Receipt) { r.Signature = "!!not base64!!" },
			"signature encoding",
		},
		{
			"signature_is_truncated",
			func(t *testing.T, r *Receipt) {
				t.Helper()
				raw, err := base64.StdEncoding.DecodeString(r.Signature)
				if err != nil {
					t.Fatal(err)
				}
				r.Signature = base64.StdEncoding.EncodeToString(raw[:32])
			},
			"signature encoding",
		},
		{
			"signature_is_absent",
			func(_ *testing.T, r *Receipt) { r.Signature = "" },
			"signature encoding",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := testRequest(KindBatch, 1)
			private := testPrivateKey()
			public := private.Public().(ed25519.PublicKey)
			receipt := mustReceipt(
				t, request, "provider-one", tamperPredecessor,
				tamperTimestamp, private,
			)
			if err := receipt.Verify(
				request, "provider-one", public, tamperPredecessor,
			); err != nil {
				t.Fatalf("untampered fixture failed: %v", err)
			}
			test.mutate(t, &receipt)
			err := receipt.Verify(
				request, "provider-one", public, tamperPredecessor,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf(
					"tampered receipt error = %v, want %q",
					err, test.want,
				)
			}
		})
	}
}

func TestReceiptVerifyRejectsForeignAndSwappedProviderKeys(t *testing.T) {
	request := testRequest(KindBatch, 1)
	first := testPrivateKey()
	second := secondPrivateKey()
	firstPublic := first.Public().(ed25519.PublicKey)
	secondPublic := second.Public().(ed25519.PublicKey)
	if PublicKeyID(firstPublic) == PublicKeyID(secondPublic) {
		t.Fatal("the two test providers share one signing key")
	}
	foreign := mustReceipt(
		t, request, "provider-one", tamperPredecessor, tamperTimestamp, second,
	)
	if err := foreign.Verify(
		request, "provider-one", firstPublic, tamperPredecessor,
	); err == nil {
		t.Fatal("a receipt signed by a foreign key verified")
	}
	forged := foreign
	forged.ProviderKeyID = PublicKeyID(firstPublic)
	if err := forged.Verify(
		request, "provider-one", firstPublic, tamperPredecessor,
	); err == nil ||
		!strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("forged provider key id error = %v", err)
	}
	genuine := mustReceipt(
		t, request, "provider-one", tamperPredecessor, tamperTimestamp, first,
	)
	if err := genuine.Verify(
		request, "provider-two", firstPublic, tamperPredecessor,
	); err == nil {
		t.Fatal("a receipt verified under the wrong provider identity")
	}
	if err := genuine.Verify(
		request, "provider-one", secondPublic, tamperPredecessor,
	); err == nil {
		t.Fatal("a receipt verified against the other provider trust root")
	}
}

func TestReceiptVerifyRejectsSwappedDualProviderSlots(t *testing.T) {
	request := testRequest(KindGenesis, 0)
	first := testPrivateKey()
	second := secondPrivateKey()
	firstPublic := first.Public().(ed25519.PublicKey)
	secondPublic := second.Public().(ed25519.PublicKey)
	one := mustReceipt(
		t, request, "provider-one", zeroDigest, tamperTimestamp, first,
	)
	two := mustReceipt(
		t, request, "provider-two", zeroDigest, tamperTimestamp, second,
	)
	if err := one.Verify(
		request, "provider-one", firstPublic, zeroDigest,
	); err != nil {
		t.Fatal(err)
	}
	if err := two.Verify(
		request, "provider-two", secondPublic, zeroDigest,
	); err != nil {
		t.Fatal(err)
	}
	if err := two.Verify(
		request, "provider-one", firstPublic, zeroDigest,
	); err == nil {
		t.Fatal("the second provider receipt verified in the first slot")
	}
	if err := one.Verify(
		request, "provider-two", secondPublic, zeroDigest,
	); err == nil {
		t.Fatal("the first provider receipt verified in the second slot")
	}
	oneDigest, err := one.Digest()
	if err != nil {
		t.Fatal(err)
	}
	twoDigest, err := two.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if oneDigest == twoDigest {
		t.Fatal("both provider chains share one receipt digest")
	}
}

func TestReceiptSignatureIsBoundToItsDomainTag(t *testing.T) {
	request := testRequest(KindBatch, 1)
	private := testPrivateKey()
	public := private.Public().(ed25519.PublicKey)
	genuine := mustReceipt(
		t, request, "provider-one", tamperPredecessor, tamperTimestamp, private,
	)
	canonical, err := json.Marshal(unsignedReceipt{
		Schema:                genuine.Schema,
		ProviderID:            genuine.ProviderID,
		ProviderKeyID:         genuine.ProviderKeyID,
		ProviderSequence:      genuine.ProviderSequence,
		PreviousReceiptDigest: genuine.PreviousReceiptDigest,
		IdempotencyKey:        genuine.IdempotencyKey,
		RequestDigest:         genuine.RequestDigest,
		ReceivedAtUTC:         genuine.ReceivedAtUTC,
		MatrixID:              genuine.MatrixID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := genuine.Verify(
		request, "provider-one", public, tamperPredecessor,
	); err != nil {
		t.Fatalf("the domain-separated fixture failed: %v", err)
	}
	digest := sha256.Sum256(domainMessage(receiptDomain, canonical))
	for _, test := range []struct {
		name    string
		message []byte
	}{
		{"no_domain_tag", canonical},
		{"request_domain_tag", domainMessage(requestDomain, canonical)},
		{
			"idempotency_domain_tag",
			domainMessage(idempotencyDomain, canonical),
		},
		{
			"domain_without_nul_separator",
			append([]byte(receiptDomain), canonical...),
		},
		{
			"domain_with_space_separator",
			append([]byte(receiptDomain+" "), canonical...),
		},
		{"digest_instead_of_message", digest[:]},
	} {
		t.Run(test.name, func(t *testing.T) {
			forged := genuine
			forged.Signature = base64.StdEncoding.EncodeToString(
				ed25519.Sign(private, test.message),
			)
			if err := forged.Verify(
				request, "provider-one", public, tamperPredecessor,
			); err == nil {
				t.Fatal("a signature over another preimage verified")
			}
		})
	}
}

func TestDomainDigestSeparatesRequestAndReceiptPreimages(t *testing.T) {
	canonical := []byte(`{"schema":"shared"}`)
	if domainDigest(requestDomain, canonical) ==
		domainDigest(receiptDomain, canonical) {
		t.Fatal("request and receipt digests collide on shared bytes")
	}
	if domainDigest(receiptDomain, canonical) ==
		domainDigest(idempotencyDomain, canonical) {
		t.Fatal("receipt and idempotency digests collide on shared bytes")
	}
	message := domainMessage(receiptDomain, canonical)
	if !bytes.Equal(message[:len(receiptDomain)], []byte(receiptDomain)) ||
		message[len(receiptDomain)] != 0 ||
		!bytes.Equal(message[len(receiptDomain)+1:], canonical) {
		t.Fatalf("domain message layout changed: %q", message)
	}
}

func TestReceiptRejectsSignatureOverDifferentCanonicalBytes(t *testing.T) {
	request := testRequest(KindBatch, 1)
	private := testPrivateKey()
	public := private.Public().(ed25519.PublicKey)
	target := mustReceipt(
		t, request, "provider-one", tamperPredecessor, tamperTimestamp, private,
	)
	sibling := mustReceipt(
		t, request, "provider-one", tamperPredecessor,
		"2026-07-25T00:00:02Z", private,
	)
	transplanted := target
	transplanted.Signature = sibling.Signature
	if err := transplanted.Verify(
		request, "provider-one", public, tamperPredecessor,
	); err == nil ||
		!strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("transplanted signature error = %v", err)
	}
	canonical, err := request.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	crossType := target
	crossType.Signature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(private, domainMessage(requestDomain, canonical)),
	)
	if err := crossType.Verify(
		request, "provider-one", public, tamperPredecessor,
	); err == nil {
		t.Fatal("a request signature was accepted as a receipt signature")
	}
	neighbour := testRequest(KindBatch, 2)
	neighbour.BatchKey = "edge--cold--b001"
	neighbour.Readiness = "cold"
	replayed := mustReceipt(
		t, neighbour, "provider-one", tamperPredecessor, tamperTimestamp, private,
	)
	if err := replayed.Verify(
		request, "provider-one", public, tamperPredecessor,
	); err == nil {
		t.Fatal("a receipt for another ordinal verified against this request")
	}
}

func TestDecodeReceiptRejectsInjectedTruncatedAndExtendedFiles(t *testing.T) {
	receipt := mustReceipt(
		t, testRequest(KindGenesis, 0), "provider-one", zeroDigest,
		tamperTimestamp, testPrivateKey(),
	)
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	// The anchor server writes exactly one canonical line plus a newline.
	if _, err := DecodeReceipt(
		bytes.NewReader(append(append([]byte{}, encoded...), '\n')),
	); err != nil {
		t.Fatalf("the canonical receipt line was rejected: %v", err)
	}
	injected := strings.Replace(
		string(encoded),
		`{"schema":`,
		`{"anchor_override":"trusted","schema":`,
		1,
	)
	if injected == string(encoded) {
		t.Fatal("unknown-field injection fixture did not apply")
	}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"unknown_field_injection", []byte(injected)},
		{"truncated_file", encoded[:len(encoded)/2]},
		{"extended_with_second_receipt", append(
			append(append([]byte{}, encoded...), '\n'), encoded...,
		)},
		{"extended_with_trailing_garbage", append(
			append([]byte{}, encoded...), []byte("\nANCHOR_OK\n")...,
		)},
		{"empty_file", nil},
		{"oversize_file", append(
			bytes.Repeat([]byte(" "), 64<<10), encoded...,
		)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeReceipt(
				bytes.NewReader(test.data),
			); err == nil {
				t.Fatal("a malformed receipt file decoded")
			}
		})
	}
}

func TestDecodeRequestRejectsInjectedTruncatedAndExtendedFiles(t *testing.T) {
	request := testRequest(KindBatch, 1)
	encoded, err := request.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRequest(
		bytes.NewReader(append(append([]byte{}, encoded...), '\n')),
	); err != nil {
		t.Fatalf("the canonical request line was rejected: %v", err)
	}
	injected := strings.Replace(
		string(encoded),
		`{"schema":`,
		`{"expected_batch_count_override":9,"schema":`,
		1,
	)
	if injected == string(encoded) {
		t.Fatal("unknown-field injection fixture did not apply")
	}
	swappedKind := strings.Replace(
		string(encoded), `"kind":"batch"`, `"kind":"seal"`, 1,
	)
	if swappedKind == string(encoded) {
		t.Fatal("kind-swap fixture did not apply")
	}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"unknown_field_injection", []byte(injected)},
		{"kind_swapped_to_seal", []byte(swappedKind)},
		{"truncated_file", encoded[:len(encoded)/2]},
		{"extended_with_second_request", append(
			append(append([]byte{}, encoded...), '\n'), encoded...,
		)},
		{"empty_file", nil},
		{"oversize_file", append(
			bytes.Repeat([]byte(" "), 64<<10), encoded...,
		)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeRequest(
				bytes.NewReader(test.data),
			); err == nil {
				t.Fatal("a malformed request file decoded")
			}
		})
	}
}

func newTamperLedger(t *testing.T) (string, Ledger) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory, Ledger{
		Directory:  directory,
		ProviderID: "provider-one",
		PrivateKey: testPrivateKey(),
		Now: func() time.Time {
			return time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
		},
	}
}

func sealedChain() []Request {
	batchTwo := testRequest(KindBatch, 2)
	batchTwo.BatchKey = "edge--cold--b001"
	batchTwo.Readiness = "cold"
	return []Request{
		testRequest(KindGenesis, 0),
		testRequest(KindBatch, 1),
		batchTwo,
		testRequest(KindSeal, 3),
	}
}

func readLedgerLines(t *testing.T, path string) [][]byte {
	t.Helper()
	// #nosec G304 -- path is the disposable per-test temporary ledger.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := bytes.TrimSuffix(data, []byte("\n"))
	if len(trimmed) == 0 {
		return nil
	}
	return bytes.Split(trimmed, []byte("\n"))
}

func writeLedgerLines(t *testing.T, path string, lines [][]byte) {
	t.Helper()
	var buffer bytes.Buffer
	for _, line := range lines {
		buffer.Write(line)
		buffer.WriteByte('\n')
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLedgerRejectsTamperedReceiptLines(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *ledgerRecord)
	}{
		{
			"receipt_timestamp",
			func(_ *testing.T, r *ledgerRecord) {
				r.Receipt.ReceivedAtUTC = "2026-07-25T00:00:09Z"
			},
		},
		{
			"receipt_sequence",
			func(_ *testing.T, r *ledgerRecord) {
				r.Receipt.ProviderSequence = 7
			},
		},
		{
			"receipt_previous_digest",
			func(_ *testing.T, r *ledgerRecord) {
				r.Receipt.PreviousReceiptDigest = tamperPredecessor
			},
		},
		{
			"receipt_provider_identity",
			func(_ *testing.T, r *ledgerRecord) {
				r.Receipt.ProviderID = "provider-two"
			},
		},
		{
			"receipt_signature_byte",
			func(t *testing.T, r *ledgerRecord) {
				flipSignatureByte(t, &r.Receipt)
			},
		},
		{
			"request_archive_digest",
			func(_ *testing.T, r *ledgerRecord) {
				r.Request.ArchiveDigest = strings.Repeat("b", 64)
			},
		},
		{
			"request_ordinal",
			func(_ *testing.T, r *ledgerRecord) { r.Request.Ordinal = 2 },
		},
		{
			"request_expected_batch_count",
			func(_ *testing.T, r *ledgerRecord) {
				r.Request.ExpectedBatchCount = 3
			},
		},
		{
			"receipt_resigned_by_a_foreign_provider",
			func(t *testing.T, r *ledgerRecord) {
				r.Receipt = mustReceipt(
					t,
					r.Request,
					r.Receipt.ProviderID,
					r.Receipt.PreviousReceiptDigest,
					r.Receipt.ReceivedAtUTC,
					secondPrivateKey(),
				)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory, ledger := newTamperLedger(t)
			chain := sealedChain()
			for _, request := range chain[:2] {
				if _, err := ledger.Append(request); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(
				directory, chain[0].MatrixID+".jsonl",
			)
			lines := readLedgerLines(t, path)
			if len(lines) != 2 {
				t.Fatalf("fixture has %d records, want 2", len(lines))
			}
			var record ledgerRecord
			if err := json.Unmarshal(lines[1], &record); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, &record)
			rewritten, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			lines[1] = rewritten
			writeLedgerLines(t, path, lines)
			_, err = ledger.Append(chain[2])
			if err == nil {
				t.Fatal("a tampered provider ledger line was accepted")
			}
			if !IsRejection(err) {
				t.Fatalf("tamper is retryable rather than permanent: %v", err)
			}
		})
	}
}

func TestLedgerRejectsStructurallyRewrittenChains(t *testing.T) {
	for _, test := range []struct {
		name    string
		rewrite func(*testing.T, [][]byte) [][]byte
	}{
		{
			"duplicated_record",
			func(_ *testing.T, lines [][]byte) [][]byte {
				return append(lines, lines[1])
			},
		},
		{
			"dropped_record",
			func(_ *testing.T, lines [][]byte) [][]byte {
				return [][]byte{lines[0], lines[2]}
			},
		},
		{
			"reordered_records",
			func(_ *testing.T, lines [][]byte) [][]byte {
				return [][]byte{lines[0], lines[2], lines[1]}
			},
		},
		{
			"replayed_genesis_at_the_tail",
			func(_ *testing.T, lines [][]byte) [][]byte {
				return append(lines, lines[0])
			},
		},
		{
			"empty_record",
			func(_ *testing.T, lines [][]byte) [][]byte {
				return append(lines, []byte("{}"))
			},
		},
		{
			"unknown_field_in_record",
			func(_ *testing.T, lines [][]byte) [][]byte {
				injected := strings.Replace(
					string(lines[2]),
					`{"request":`,
					`{"trusted":true,"request":`,
					1,
				)
				return [][]byte{lines[0], lines[1], []byte(injected)}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory, ledger := newTamperLedger(t)
			chain := sealedChain()
			for _, request := range chain[:3] {
				if _, err := ledger.Append(request); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(
				directory, chain[0].MatrixID+".jsonl",
			)
			lines := readLedgerLines(t, path)
			if len(lines) != 3 {
				t.Fatalf("fixture has %d records, want 3", len(lines))
			}
			writeLedgerLines(t, path, test.rewrite(t, lines))
			if _, err := ledger.Append(chain[3]); err == nil {
				t.Fatal("a rewritten provider ledger chain was accepted")
			}
		})
	}
}

func TestSealedLedgerAdmitsNoFurtherReceipts(t *testing.T) {
	directory, ledger := newTamperLedger(t)
	chain := sealedChain()
	for _, request := range chain {
		if _, err := ledger.Append(request); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(directory, chain[0].MatrixID+".jsonl")
	sealed := len(readLedgerLines(t, path))
	if sealed != len(chain) {
		t.Fatalf("sealed ledger has %d records, want %d", sealed, len(chain))
	}
	// A sealed ledger exposes no reachable free ordinal: Validate bounds
	// every kind to [0, ExpectedBatchCount+1], and all of those are taken.
	beyond := testRequest(KindBatch, 4)
	if err := beyond.Validate(); err == nil {
		t.Fatal("a batch past the frozen batch count validated")
	}
	secondSeal := testRequest(KindSeal, 4)
	if err := secondSeal.Validate(); err == nil {
		t.Fatal("a second terminal seal validated")
	}
	replay, err := ledger.Append(chain[3])
	if err != nil {
		t.Fatalf("the exact terminal seal stopped being idempotent: %v", err)
	}
	if replay.ProviderSequence != 3 {
		t.Fatalf("seal replay sequence = %d, want 3", replay.ProviderSequence)
	}
	rewrittenSeal := chain[3]
	rewrittenSeal.AggregateDigest = strings.Repeat("b", 64)
	_, err = ledger.Append(rewrittenSeal)
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("post-seal aggregate rewrite error = %v", err)
	}
	if !IsRejection(err) {
		t.Fatal("post-seal rewrite must be a permanent rejection")
	}
	rewrittenBatch := chain[1]
	rewrittenBatch.ArchiveDigest = strings.Repeat("c", 64)
	_, err = ledger.Append(rewrittenBatch)
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("post-seal batch rewrite error = %v", err)
	}
	if !IsRejection(err) {
		t.Fatal("post-seal batch rewrite must be a permanent rejection")
	}
	if got := len(readLedgerLines(t, path)); got != sealed {
		t.Fatalf("the sealed ledger grew to %d records", got)
	}
}

// terminate returns the sealed file form of one record: its canonical bytes
// plus the single framing LF, and nothing else.
func terminate(line []byte) []byte {
	return append(append([]byte{}, line...), '\n')
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// canonicalLedgerFixture seals a genesis record and one batch record into a
// fresh temporary ledger and hands back the two genuine lines, stripped of
// their LF terminators.
func canonicalLedgerFixture(t *testing.T) (Ledger, string, [][]byte) {
	t.Helper()
	directory, ledger := newTamperLedger(t)
	chain := sealedChain()
	for _, request := range chain[:2] {
		if _, err := ledger.Append(request); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(directory, chain[0].MatrixID+".jsonl")
	lines := readLedgerLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("fixture has %d records, want 2", len(lines))
	}
	return ledger, path, lines
}

// writeLedgerBytes replaces the ledger with exactly these bytes. Unlike
// writeLedgerLines it adds no terminator, so a test can control the framing.
func writeLedgerBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

// ledgerFile joins the genuine first record to the exact bytes a test wants
// the second record and its terminator to occupy.
func ledgerFile(first []byte, second []byte) []byte {
	var buffer bytes.Buffer
	buffer.Write(first)
	buffer.WriteByte('\n')
	buffer.Write(second)
	return buffer.Bytes()
}

// TestLedgerRecordsRoundTripByteExactly proves the byte pin is satisfiable by
// every record kind the ledger can hold. If any field marshalled back
// differently from the way it was written, sealed ledgers could never satisfy
// the pin and the check would have to be abandoned rather than tightened.
func TestLedgerRecordsRoundTripByteExactly(t *testing.T) {
	directory, ledger := newTamperLedger(t)
	chain := sealedChain()
	for _, request := range chain {
		if _, err := ledger.Append(request); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(directory, chain[0].MatrixID+".jsonl")
	lines := readLedgerLines(t, path)
	if len(lines) != len(chain) {
		t.Fatalf("sealed ledger has %d records, want %d", len(lines), len(chain))
	}
	for index, line := range lines {
		var record ledgerRecord
		if err := decodeStrict(terminate(line), &record); err != nil {
			t.Fatalf("record %d (%s): %v", index, chain[index].Kind, err)
		}
		if err := pinCanonicalRecord(terminate(line), record); err != nil {
			t.Fatalf(
				"record %d (%s) is not byte-exact: %v",
				index, chain[index].Kind, err,
			)
		}
	}
}

func TestLedgerRejectsNonCanonicalRecordBytes(t *testing.T) {
	// Regression guard first. The genuine record, written back byte for byte
	// with its single LF, must keep verifying, so every rejection below is
	// attributable to its own mutation rather than to this harness. This is
	// also the property the existing sealed evidence depends on.
	ledger, path, lines := canonicalLedgerFixture(t)
	writeLedgerBytes(t, path, ledgerFile(lines[0], terminate(lines[1])))
	if _, err := ledger.Append(sealedChain()[2]); err != nil {
		t.Fatalf("the canonical sealed record stopped verifying: %v", err)
	}

	for _, test := range []struct {
		name string
		// rewrite returns the exact bytes replacing the second record and its
		// terminator. Every case must still decode to the identical record.
		rewrite func(*testing.T, []byte, ledgerRecord) []byte
	}{
		{
			// The first "request" carries a forged archive digest and the
			// second carries the genuine one. encoding/json keeps the last
			// value, so this line verifies and digests exactly like the sealed
			// record while a first-wins parser reads the forged digest.
			"duplicate_top_level_request_key",
			func(t *testing.T, _ []byte, record ledgerRecord) []byte {
				forged := record.Request
				forged.ArchiveDigest = strings.Repeat("b", 64)
				return terminate([]byte(fmt.Sprintf(
					`{"request":%s,"request":%s,"receipt":%s}`,
					mustMarshal(t, forged),
					mustMarshal(t, record.Request),
					mustMarshal(t, record.Receipt),
				)))
			},
		},
		{
			// A repeated key needs no differing value to be dangerous: it is
			// already a second byte sequence for one signed record.
			"duplicate_top_level_receipt_key",
			func(t *testing.T, _ []byte, record ledgerRecord) []byte {
				return terminate([]byte(fmt.Sprintf(
					`{"request":%s,"receipt":%s,"receipt":%s}`,
					mustMarshal(t, record.Request),
					mustMarshal(t, record.Receipt),
					mustMarshal(t, record.Receipt),
				)))
			},
		},
		{
			// Nested duplicates are the harder case: the outer object is
			// well formed and only the embedded request is ambiguous.
			"duplicate_nested_key_in_request",
			func(_ *testing.T, line []byte, record ledgerRecord) []byte {
				return terminate([]byte(strings.Replace(
					string(line),
					fmt.Sprintf(
						`"archive_sha256":%q`,
						record.Request.ArchiveDigest,
					),
					fmt.Sprintf(
						`"archive_sha256":%q,"archive_sha256":%q`,
						strings.Repeat("b", 64),
						record.Request.ArchiveDigest,
					),
					1,
				)))
			},
		},
		{
			"duplicate_nested_key_in_receipt",
			func(_ *testing.T, line []byte, record ledgerRecord) []byte {
				return terminate([]byte(strings.Replace(
					string(line),
					fmt.Sprintf(
						`"provider_id":%q`, record.Receipt.ProviderID,
					),
					fmt.Sprintf(
						`"provider_id":%q,"provider_id":%q`,
						"provider-two", record.Receipt.ProviderID,
					),
					1,
				)))
			},
		},
		{
			"insignificant_whitespace_inside_the_object",
			func(_ *testing.T, line []byte, _ ledgerRecord) []byte {
				return terminate([]byte(strings.Replace(
					string(line), `{"request":`, `{ "request" : `, 1,
				)))
			},
		},
		{
			"insignificant_whitespace_around_the_object",
			func(_ *testing.T, line []byte, _ ledgerRecord) []byte {
				return terminate(append(
					append([]byte("\t"), line...), ' ',
				))
			},
		},
		{
			// Caught by the ambiguous-tail guard: a record with no terminator
			// cannot be distinguished from a torn write.
			"missing_trailing_newline",
			func(_ *testing.T, line []byte, _ ledgerRecord) []byte {
				return append([]byte{}, line...)
			},
		},
		{
			// CR is JSON whitespace, so the line still decodes and the tail
			// still ends in LF. Only the byte pin rejects it.
			"crlf_line_ending",
			func(_ *testing.T, line []byte, _ ledgerRecord) []byte {
				return terminate(append(
					append([]byte{}, line...), '\r',
				))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ledger, path, lines := canonicalLedgerFixture(t)
			var record ledgerRecord
			if err := json.Unmarshal(lines[1], &record); err != nil {
				t.Fatal(err)
			}
			rewritten := test.rewrite(t, lines[1], record)
			if bytes.Equal(rewritten, terminate(lines[1])) {
				t.Fatal("the non-canonical fixture did not apply")
			}
			// Every fixture must remain one record that Go decodes to the
			// identical value. That is what makes it dangerous: signature,
			// digest and chain checks all still pass on it, so a rejection
			// here can only come from the byte pin or the framing guard.
			var probe ledgerRecord
			if err := json.Unmarshal(
				bytes.TrimRight(rewritten, "\r\n"), &probe,
			); err != nil {
				t.Fatalf("the fixture stopped being one record: %v", err)
			}
			if probe != record {
				t.Fatal("the fixture altered the record, not only its bytes")
			}
			writeLedgerBytes(t, path, ledgerFile(lines[0], rewritten))
			_, err := ledger.Append(sealedChain()[2])
			if err == nil {
				t.Fatal("a non-canonical provider ledger line was accepted")
			}
			if !IsRejection(err) {
				t.Fatalf(
					"non-canonical bytes are retryable, not permanent: %v",
					err,
				)
			}
		})
	}
}

func TestLedgerRejectsRecordsAppendedAfterTheTerminalSeal(t *testing.T) {
	directory, ledger := newTamperLedger(t)
	chain := sealedChain()
	for _, request := range chain {
		if _, err := ledger.Append(request); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(directory, chain[0].MatrixID+".jsonl")
	lines := readLedgerLines(t, path)
	var sealRecord ledgerRecord
	if err := json.Unmarshal(lines[3], &sealRecord); err != nil {
		t.Fatal(err)
	}
	// No valid request can occupy ordinal 4, so a post-seal append has to be
	// hand-written straight into the signed log.
	forged := ledgerRecord{
		Request: testRequest(KindBatch, 1),
		Receipt: sealRecord.Receipt,
	}
	forged.Request.Ordinal = 4
	forged.Receipt.ProviderSequence = 4
	line, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	writeLedgerLines(t, path, append(lines, line))
	_, err = ledger.Append(chain[3])
	if err == nil {
		t.Fatal("a record appended after the terminal seal was accepted")
	}
	if !IsRejection(err) {
		t.Fatalf("post-seal append is retryable rather than permanent: %v", err)
	}
}
