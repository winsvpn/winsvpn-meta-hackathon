package transparency

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
)

func TestAppendVerifyAndDetectTampering(t *testing.T) {
	signer, pins := transparencyTestKeys(t)
	path := filepath.Join(t.TempDir(), "manifest-transparency.jsonl")
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	firstDigest := digestText("1")
	_, checkpoint, err := Append(path, firstDigest, signer, pins, now)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Size != 1 || checkpoint.ReceiptDigest == "" {
		t.Fatalf("checkpoint = %#v", checkpoint)
	}
	_, checkpoint, err = Append(path, digestText("2"), signer, pins, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	receipts, verified, err := ReadAndVerify(path, pins)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 2 || verified != checkpoint {
		t.Fatalf("verified checkpoint = %#v, want %#v", verified, checkpoint)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for index := range data {
		if data[index] == '2' {
			data[index] = '3'
			break
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadAndVerify(path, pins); err == nil {
		t.Fatal("tampered transparency log verified")
	}
}

func TestAppendRefusesConcurrentOrStaleWriterLock(t *testing.T) {
	signer, pins := transparencyTestKeys(t)
	path := filepath.Join(t.TempDir(), "log.jsonl")
	if err := os.WriteFile(path+".lock", []byte("held"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Append(path, digestText("x"), signer, pins, time.Now().UTC()); err == nil {
		t.Fatal("append succeeded despite writer lock")
	}

	live := filepath.Join(t.TempDir(), "live.jsonl")
	started := make(chan struct{})
	firstErr := make(chan error, 1)
	go func() {
		close(started)
		_, _, err := Append(live, digestText("c"), signer, pins, time.Now().UTC())
		firstErr <- err
	}()
	<-started
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(live + ".lock"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first append never created lock file")
		}
		time.Sleep(100 * time.Microsecond)
	}
	if _, _, err := Append(live, digestText("d"), signer, pins, time.Now().UTC()); err == nil {
		t.Fatal("append succeeded while another writer held the lock")
	}
	if err := <-firstErr; err != nil {
		t.Fatalf("first append: %v", err)
	}
}

func TestAppendRejectsNilOrUnpinnedSignerBeforePersistence(t *testing.T) {
	signer, pins := transparencyTestKeys(t)
	path := filepath.Join(t.TempDir(), "log.jsonl")
	if _, _, err := Append(
		path, digestText("n"), signer, nil, time.Now().UTC(),
	); err == nil {
		t.Fatal("append accepted nil verifier pins")
	}
	otherSeed := make([]byte, 32)
	for index := range otherSeed {
		otherSeed[index] = byte(index + 71)
	}
	other, err := pqauth.NewSigner(pqauth.MLDSA65, otherSeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Append(
		path, digestText("u"), other, pins, time.Now().UTC(),
	); err == nil {
		t.Fatal("append accepted an unpinned receipt signer")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected append persisted a log: %v", err)
	}
}

func TestVerifyInclusionExtensionRequiresNewReceipt(t *testing.T) {
	signer, pins := transparencyTestKeys(t)
	path := filepath.Join(t.TempDir(), "log.jsonl")
	now := time.Now().UTC()
	first := digestText("a")
	second := digestText("b")
	third := digestText("c")
	if _, _, err := Append(path, first, signer, pins, now); err != nil {
		t.Fatal(err)
	}
	if _, head, err := Append(
		path, second, signer, pins, now.Add(time.Minute),
	); err != nil {
		t.Fatal(err)
	} else if _, err := VerifyInclusionExtension(
		path, second, pins, head,
	); err == nil {
		t.Fatal("receipt inside retained checkpoint counted as extension")
	}
	if _, _, err := Append(
		path, third, signer, pins, now.Add(2*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	receipts, _, err := ReadAndVerify(path, pins)
	if err != nil {
		t.Fatal(err)
	}
	expectedDigest, err := Digest(receipts[1])
	if err != nil {
		t.Fatal(err)
	}
	extended, err := VerifyInclusionExtension(
		path, third, pins, Checkpoint{
			Size:          2,
			ReceiptDigest: expectedDigest,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if extended.Size != 3 {
		t.Fatalf("extended checkpoint size = %d", extended.Size)
	}
}

func TestAppendRejectsUppercaseManifestDigest(t *testing.T) {
	signer, pins := transparencyTestKeys(t)
	path := filepath.Join(t.TempDir(), "log.jsonl")
	upper := strings.ToUpper(digestText("u"))
	if _, _, err := Append(path, upper, signer, pins, time.Now().UTC()); err == nil {
		t.Fatal("append accepted uppercase hex manifest digest")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected uppercase digest persisted a log: %v", err)
	}
}

func TestVerifyInclusionFindsLoggedDigestAndRejectsAbsent(t *testing.T) {
	signer, pins := transparencyTestKeys(t)
	path := filepath.Join(t.TempDir(), "log.jsonl")
	present := digestText("p")
	absent := digestText("q")
	_, checkpoint, err := Append(path, present, signer, pins, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > MaxLineSize {
		t.Fatalf("single receipt log size %d exceeds MaxLineSize %d", info.Size(), MaxLineSize)
	}
	t.Logf("single-receipt log bytes=%d MaxLineSize=%d MaxLogSize=%d", info.Size(), MaxLineSize, MaxLogSize)
	got, err := VerifyInclusion(path, present, pins, &checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if got != checkpoint {
		t.Fatalf("inclusion checkpoint = %#v, want %#v", got, checkpoint)
	}
	if _, err := VerifyInclusion(path, absent, pins, nil); err == nil {
		t.Fatal("absent manifest digest verified as included")
	}
}

func transparencyTestKeys(t *testing.T) (*pqauth.Signer, *pqauth.VerifierSet) {
	t.Helper()
	seed := make([]byte, 32)
	for index := range seed {
		seed[index] = byte(31 - index)
	}
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := signer.PublicBytes()
	verifier, err := pqauth.NewVerifier(signer.Algorithm(), publicKey)
	clear(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := pqauth.NewVerifierSet(verifier)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pins
}

func digestText(text string) string {
	const digits = "0123456789abcdef"
	result := make([]byte, 64)
	for index := range result {
		result[index] = digits[(int(text[0])+index)%len(digits)]
	}
	return string(result)
}
