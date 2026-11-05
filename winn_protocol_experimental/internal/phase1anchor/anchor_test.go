// Exercises the POSIX provider ledger, so it is constrained to the same
// platforms as ledger.go rather than failing to compile elsewhere.

//go:build unix

package phase1anchor

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testRequest(kind string, ordinal int) Request {
	request := Request{
		Schema: RequestSchema, Kind: kind,
		MatrixID:           "matrix-one",
		SourceDigest:       strings.Repeat("1", 64),
		AutoArtifactDigest: strings.Repeat("2", 64),
		ProfileDigest:      strings.Repeat("3", 64),
		ScheduleDigest:     strings.Repeat("4", 64),
		ExpectedBatchCount: 2,
		Ordinal:            ordinal,
	}
	if kind == KindBatch {
		request.BatchKey = "edge--warm--b001"
		request.ScheduleRowDigest = strings.Repeat("5", 64)
		request.Profile = "edge"
		request.Readiness = "warm"
		request.AttemptCount = 100
		request.ArchiveDigest = strings.Repeat("6", 64)
		request.EvidenceManifestDigest = strings.Repeat("7", 64)
		request.AttemptLogDigest = strings.Repeat("8", 64)
		request.AttemptAnchorDigest = strings.Repeat("9", 64)
	}
	if kind == KindSeal {
		request.AggregateDigest = strings.Repeat("a", 64)
	}
	return request
}

func testPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(
		[]byte("0123456789abcdef0123456789abcdef"),
	)
}

func TestReceiptBindsRequestAndPreviousReceipt(t *testing.T) {
	request := testRequest(KindGenesis, 0)
	private := testPrivateKey()
	receipt, err := NewReceipt(
		request,
		"provider-one",
		zeroDigest,
		"2026-07-25T00:00:00Z",
		private,
	)
	if err != nil {
		t.Fatal(err)
	}
	public := private.Public().(ed25519.PublicKey)
	if err := receipt.Verify(
		request, "provider-one", public, zeroDigest,
	); err != nil {
		t.Fatal(err)
	}
	receipt.RequestDigest = strings.Repeat("f", 64)
	if err := receipt.Verify(
		request, "provider-one", public, zeroDigest,
	); err == nil {
		t.Fatal("tampered receipt verified")
	}
}

func TestReceiptAndRequestRequireCanonicalEncodings(t *testing.T) {
	request := testRequest(KindGenesis, 0)
	request.SourceDigest = strings.Repeat("A", 64)
	if err := request.Validate(); err == nil {
		t.Fatal("uppercase source digest was accepted")
	}
	request = testRequest(KindGenesis, 0)
	private := testPrivateKey()
	_, err := NewReceipt(
		request,
		"provider-one",
		zeroDigest,
		"2026-07-25T00:00:00+00:00",
		private,
	)
	if err == nil {
		t.Fatal("non-canonical receipt timestamp was signed")
	}
}

func TestLedgerIsMonotonicIdempotentAndFailClosed(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	private := testPrivateKey()
	ledger := Ledger{
		Directory: directory, ProviderID: "provider-one",
		PrivateKey: private,
		Now: func() time.Time {
			return time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
		},
	}
	genesis := testRequest(KindGenesis, 0)
	first, err := ledger.Append(genesis)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := ledger.Append(genesis)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, _ := first.Digest()
	retryDigest, _ := retry.Digest()
	if firstDigest != retryDigest {
		t.Fatal("identical retry returned another receipt")
	}
	skipped := testRequest(KindBatch, 2)
	if _, err := ledger.Append(skipped); err == nil ||
		!strings.Contains(err.Error(), "gap") {
		t.Fatalf("sequence skip error=%v", err)
	}
	batchOne := testRequest(KindBatch, 1)
	receiptOne, err := ledger.Append(batchOne)
	if err != nil {
		t.Fatal(err)
	}
	conflict := batchOne
	conflict.ArchiveDigest = strings.Repeat("b", 64)
	if _, err := ledger.Append(conflict); err == nil ||
		!strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("conflicting retry error=%v", err)
	}
	batchTwo := testRequest(KindBatch, 2)
	batchTwo.BatchKey = "edge--cold--b001"
	batchTwo.Readiness = "cold"
	if _, err := ledger.Append(batchTwo); err != nil {
		t.Fatal(err)
	}
	seal := testRequest(KindSeal, 3)
	sealed, err := ledger.Append(seal)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := receiptOne.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if sealed.ProviderSequence != 3 || previous == zeroDigest {
		t.Fatalf("seal=%#v prior=%s", sealed, previous)
	}
	if _, err := ledger.Append(batchTwo); err != nil {
		t.Fatalf("exact pre-seal retry must remain idempotent: %v", err)
	}
}

// sameReceipt fails unless two receipts are the identical signed object.
// Comparing digests rather than fields means a retry that changed any signed
// field, including the timestamp, cannot pass as idempotent.
func sameReceipt(t *testing.T, got Receipt, want Receipt) {
	t.Helper()
	gotDigest, err := got.Digest()
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := want.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != wantDigest {
		t.Fatalf(
			"receipt digest = %s, want %s (sequence %d, want %d)",
			gotDigest, wantDigest,
			got.ProviderSequence, want.ProviderSequence,
		)
	}
}

// TestLedgerAppendStateMachine pins the behaviours of the ordered append state
// machine -- occupied slot, terminal chain, contiguity -- without asserting on
// any error wording, so the wording stays free to change while the accept and
// reject decisions and their RejectionError classification do not.
func TestLedgerAppendStateMachine(t *testing.T) {
	directory, ledger := newTamperLedger(t)
	chain := sealedChain()
	recorded := make([]Receipt, 0, len(chain))
	for _, request := range chain {
		receipt, err := ledger.Append(request)
		if err != nil {
			t.Fatal(err)
		}
		recorded = append(recorded, receipt)
	}
	path := filepath.Join(directory, chain[0].MatrixID+".jsonl")
	sealed := len(readLedgerLines(t, path))
	if sealed != len(chain) {
		t.Fatalf("sealed ledger holds %d records, want %d", sealed, len(chain))
	}

	// 1. The terminal seal itself stays idempotent. A provider that sealed the
	// matrix but lost the response must be able to retry and be told the same
	// thing, not that the ledger is closed to it.
	t.Run("exact_seal_retry", func(t *testing.T) {
		replay, err := ledger.Append(chain[len(chain)-1])
		if err != nil {
			t.Fatalf("the exact terminal seal stopped replaying: %v", err)
		}
		sameReceipt(t, replay, recorded[len(recorded)-1])
	})

	// 2. Sealing does not retire the history. Every slot recorded before the
	// seal must still replay its own receipt, which is why the occupied-slot
	// branch has to be decided before the terminal-state check.
	t.Run("exact_historical_slot_retry_after_seal", func(t *testing.T) {
		for index, request := range chain[:len(chain)-1] {
			replay, err := ledger.Append(request)
			if err != nil {
				t.Fatalf("slot %d stopped replaying after the seal: %v",
					index, err)
			}
			sameReceipt(t, replay, recorded[index])
		}
	})

	// 3. A retry that keeps an occupied ordinal but changes any signed field
	// is a permanent rejection, never a rewrite and never a retryable fault.
	t.Run("conflicting_retry", func(t *testing.T) {
		rewrittenBatch := chain[1]
		rewrittenBatch.ArchiveDigest = strings.Repeat("b", 64)
		rewrittenSeal := chain[len(chain)-1]
		rewrittenSeal.AggregateDigest = strings.Repeat("b", 64)
		for name, request := range map[string]Request{
			"batch": rewrittenBatch,
			"seal":  rewrittenSeal,
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := ledger.Append(request); err == nil {
					t.Fatal("a conflicting retry was accepted")
				} else if !IsRejection(err) {
					t.Fatalf("conflict is retryable, not permanent: %v", err)
				}
			})
		}
	})

	// 4. A non-contiguous ordinal on a live chain is a permanent rejection and
	// leaves the chain untouched. This needs its own unsealed ledger: on a
	// sealed chain no expressible ordinal is past the end.
	t.Run("sequence_gap", func(t *testing.T) {
		gapDirectory, gapLedger := newTamperLedger(t)
		genesis := chain[0]
		if _, err := gapLedger.Append(genesis); err != nil {
			t.Fatal(err)
		}
		gapPath := filepath.Join(gapDirectory, genesis.MatrixID+".jsonl")
		if _, err := gapLedger.Append(testRequest(KindBatch, 2)); err == nil {
			t.Fatal("a skipped provider sequence was accepted")
		} else if !IsRejection(err) {
			t.Fatalf("sequence gap is retryable, not permanent: %v", err)
		}
		if got := len(readLedgerLines(t, gapPath)); got != 1 {
			t.Fatalf("a rejected gap left %d records, want 1", got)
		}
	})

	// 5. The seal is terminal: no request can add a record to a sealed chain.
	// Ordinals past the seal never validate, and every ordinal that does
	// validate is already occupied, so each one either replays exactly or is
	// rejected. Either way the record count never moves.
	t.Run("no_new_record_after_seal", func(t *testing.T) {
		batchCount := chain[0].ExpectedBatchCount
		// Nothing past the seal slot is even expressible: those ordinals fail
		// validation before the ledger is opened.
		for _, ordinal := range []int{batchCount + 2, batchCount + 3} {
			if err := testRequest(KindBatch, ordinal).Validate(); err == nil {
				t.Fatalf("a batch at ordinal %d past the seal validated",
					ordinal)
			}
			if err := testRequest(KindSeal, ordinal).Validate(); err == nil {
				t.Fatalf("a second seal at ordinal %d validated", ordinal)
			}
		}
		// Every ordinal that does validate is already occupied, so a request
		// carrying new content for one is rejected rather than recorded. At
		// ordinal 0 the only fields a genesis may vary are the frozen matrix
		// identity, so that one is refused by the identity guard; the rest are
		// refused as occupied-slot conflicts. All are permanent.
		for ordinal := 0; ordinal <= batchCount+1; ordinal++ {
			kind := KindBatch
			switch ordinal {
			case 0:
				kind = KindGenesis
			case batchCount + 1:
				kind = KindSeal
			}
			novel := testRequest(kind, ordinal)
			switch kind {
			case KindGenesis:
				novel.SourceDigest = strings.Repeat("e", 64)
			case KindBatch:
				novel.ArchiveDigest = strings.Repeat("e", 64)
			case KindSeal:
				novel.AggregateDigest = strings.Repeat("e", 64)
			}
			if err := novel.Validate(); err != nil {
				t.Fatalf("fixture for ordinal %d is invalid: %v", ordinal, err)
			}
			if _, err := ledger.Append(novel); err == nil {
				t.Fatalf("a new %s record at ordinal %d was accepted",
					kind, ordinal)
			} else if !IsRejection(err) {
				t.Fatalf("post-seal %s at ordinal %d is retryable: %v",
					kind, ordinal, err)
			}
		}
		if got := len(readLedgerLines(t, path)); got != sealed {
			t.Fatalf("the sealed ledger grew to %d records, want %d",
				got, sealed)
		}
	})
}

func TestLedgerRejectsAmbiguousOrTamperedTail(t *testing.T) {
	for _, tail := range []string{
		`{"incomplete":`,
		"{\"request\":{},\"receipt\":{}}\n",
	} {
		t.Run(tail[:2], func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			ledger := Ledger{
				Directory: directory, ProviderID: "provider-one",
				PrivateKey: testPrivateKey(),
			}
			genesis := testRequest(KindGenesis, 0)
			if _, err := ledger.Append(genesis); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(
				directory, genesis.MatrixID+".jsonl",
			)
			file, err := os.OpenFile(
				path, os.O_WRONLY|os.O_APPEND, 0o600,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString(tail); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := ledger.Append(
				testRequest(KindBatch, 1),
			); err == nil {
				t.Fatal("corrupt provider ledger tail was accepted")
			}
		})
	}
}

func TestLedgerRejectsSymlinksAndOversizeFiles(t *testing.T) {
	for _, target := range []string{"matrix-one.lock", "matrix-one.jsonl"} {
		t.Run(target, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(
				outside, filepath.Join(directory, target),
			); err != nil {
				t.Fatal(err)
			}
			ledger := Ledger{
				Directory:  directory,
				ProviderID: "provider-one",
				PrivateKey: testPrivateKey(),
			}
			if _, err := ledger.Append(
				testRequest(KindGenesis, 0),
			); err == nil {
				t.Fatal("symlinked provider ledger file was accepted")
			}
		})
	}

	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "matrix-one.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate((64 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	ledger := Ledger{
		Directory:  directory,
		ProviderID: "provider-one",
		PrivateKey: testPrivateKey(),
	}
	if _, err := ledger.Append(
		testRequest(KindGenesis, 0),
	); err == nil || !strings.Contains(err.Error(), "64 MiB") {
		t.Fatalf("oversize provider ledger error=%v", err)
	}
}
