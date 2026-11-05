package revocation

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/securefile"
)

var testNow = time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)

const testController = "winn-controller-1"

func testKeys(t *testing.T) (*pqauth.Signer, *pqauth.VerifierSet) {
	t.Helper()
	seed := make([]byte, 32)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	signer, err := pqauth.NewSigner(pqauth.MLDSA87, seed)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := pqauth.NewVerifier(pqauth.MLDSA87, signer.PublicBytes())
	if err != nil {
		t.Fatal(err)
	}
	pins, err := pqauth.NewVerifierSet(verifier)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pins
}

func signedList(t *testing.T, signer *pqauth.Signer, sequence uint64, devices []string) List {
	t.Helper()
	list, err := Build(testController, sequence, testNow, 24*time.Hour, devices)
	if err != nil {
		t.Fatal(err)
	}
	if err := Sign(&list, signer); err != nil {
		t.Fatal(err)
	}
	return list
}

func writeList(t *testing.T, path string, list List) {
	t.Helper()
	encoded, err := Encode(list)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.AtomicWrite(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSignedListVerifies(t *testing.T) {
	signer, pins := testKeys(t)
	list := signedList(t, signer, 1, []string{"device-1", "device-2"})
	if err := Verify(list, testController, pins, testNow); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFailsClosedOnTamperedDocument(t *testing.T) {
	signer, pins := testKeys(t)
	tests := []struct {
		name   string
		mutate func(*List)
	}{
		{"removed hash", func(l *List) { l.RevokedHashes = nil }},
		{"added hash", func(l *List) {
			l.RevokedHashes = append(
				l.RevokedHashes, strings.Repeat("a", 64),
			)
		}},
		{"changed salt", func(l *List) {
			l.Salt = "nNOe1VBs+qdVjQGHgems9Xd3SO6gsrVl7+DM8y/EZAQ="
		}},
		{"changed sequence", func(l *List) { l.Sequence = 99 }},
		{"changed controller", func(l *List) { l.ControllerID = "other" }},
		{"extended window", func(l *List) {
			l.NotAfter = testNow.Add(72 * time.Hour).Format(time.RFC3339Nano)
		}},
		{"moved known good instant", func(l *List) {
			l.KnownGoodAt = testNow.Add(-time.Hour).Format(time.RFC3339Nano)
		}},
		{"changed key id", func(l *List) { l.AuthKeyID = strings.Repeat("b", 64) }},
		{"stripped signature", func(l *List) { l.AuthSignature = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			list := signedList(t, signer, 1, []string{"device-1", "device-2"})
			test.mutate(&list)
			if err := Verify(list, testController, pins, testNow); err == nil {
				t.Fatal("tampered revocation list verified")
			}
		})
	}
}

func TestVerifyRejectsUnpinnedSigner(t *testing.T) {
	signer, _ := testKeys(t)
	otherSeed := make([]byte, 32)
	for index := range otherSeed {
		otherSeed[index] = byte(200 - index)
	}
	otherSigner, err := pqauth.NewSigner(pqauth.MLDSA87, otherSeed)
	if err != nil {
		t.Fatal(err)
	}
	otherVerifier, err := pqauth.NewVerifier(
		pqauth.MLDSA87, otherSigner.PublicBytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	otherPins, err := pqauth.NewVerifierSet(otherVerifier)
	if err != nil {
		t.Fatal(err)
	}
	list := signedList(t, signer, 1, []string{"device-1"})
	if err := Verify(list, testController, otherPins, testNow); err == nil {
		t.Fatal("list signed by an unpinned controller verified")
	}
}

func TestVerifyRejectsControllerMismatch(t *testing.T) {
	signer, pins := testKeys(t)
	list := signedList(t, signer, 1, []string{"device-1"})
	if err := Verify(list, "a-different-controller", pins, testNow); err == nil {
		t.Fatal("list from another controller verified")
	}
}

// A revocation list signed under a different Winn domain must not verify as a
// revocation list. This is the cross-artifact replay check.
func TestVerifyRejectsForeignSignatureDomain(t *testing.T) {
	signer, pins := testKeys(t)
	list := signedList(t, signer, 1, []string{"device-1"})
	message, err := unsignedCanonical(list)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := pqauth.SignDomainMessage(
		pqauth.ManifestV2SignatureDomain, message, signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	list.AuthSignature = base64.StdEncoding.EncodeToString(foreign)
	if err := Verify(list, testController, pins, testNow); err == nil {
		t.Fatal("manifest-domain signature accepted as a revocation list")
	}
}

func TestLoadVerifiedRejectsRollbackAndEquivocation(t *testing.T) {
	signer, pins := testKeys(t)
	directory := t.TempDir()
	listPath := filepath.Join(directory, "revocation-list.json")
	statePath := filepath.Join(directory, "revocation-state.json")

	first := signedList(t, signer, 2, []string{"device-1"})
	writeList(t, listPath, first)
	_, state, err := LoadVerified(listPath, statePath, testController, pins, testNow)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeTrustState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.AtomicWrite(statePath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	// Advancing is accepted.
	writeList(t, listPath, signedList(t, signer, 3, []string{"device-1", "device-2"}))
	if _, _, err := LoadVerified(
		listPath, statePath, testController, pins, testNow,
	); err != nil {
		t.Fatalf("advancing sequence rejected: %v", err)
	}

	// Rolling back to a smaller revoked set is not. This is the property that
	// stops an adversary holding the distribution channel from shrinking the
	// revoked set; the worst they can do is stop it growing.
	writeList(t, listPath, signedList(t, signer, 1, nil))
	_, _, err = LoadVerified(listPath, statePath, testController, pins, testNow)
	if err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("sequence rollback = %v, want a rollback rejection", err)
	}

	// Same sequence, different content is equivocation.
	writeList(t, listPath, signedList(t, signer, 2, nil))
	_, _, err = LoadVerified(listPath, statePath, testController, pins, testNow)
	if err == nil || !strings.Contains(err.Error(), "equivocated") {
		t.Fatalf("sequence equivocation = %v, want an equivocation rejection", err)
	}
}

// The core of the freshness tradeoff. A stale list keeps enforcing the
// revocations it names and keeps serving everyone it does not, so an adversary
// who blocks distribution cannot convert that into an outage.
func TestStaleListKeepsEnforcingAndKeepsServing(t *testing.T) {
	signer, _ := testKeys(t)
	list := signedList(t, signer, 1, []string{"device-1"})
	checker, err := NewChecker(list, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	checker.SetNow(func() time.Time { return testNow.Add(90 * 24 * time.Hour) })

	status := checker.Status()
	if !status.Stale {
		t.Fatal("a 90-day-old list is not reported stale")
	}
	if status.DenyingAll {
		t.Fatal("soft-fail configuration is denying all devices")
	}
	if !checker.RevokedDevice("device-1") {
		t.Fatal("stale list stopped enforcing a revocation it names")
	}
	if checker.RevokedDevice("device-2") {
		t.Fatal("stale list denied a device it does not name")
	}
}

// The opt-in hard posture. Turning it on really does deny everyone once the
// list ages out, which is why it is not the default.
func TestRequireFreshDeniesEveryoneWhenStale(t *testing.T) {
	signer, _ := testKeys(t)
	list := signedList(t, signer, 1, []string{"device-1"})
	checker, err := NewChecker(list, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}

	// Fresh: only the named device is denied.
	checker.SetNow(func() time.Time { return testNow.Add(time.Minute) })
	if checker.RevokedDevice("device-2") {
		t.Fatal("fresh require-fresh checker denied an unrevoked device")
	}

	// Stale: everyone is denied.
	checker.SetNow(func() time.Time { return testNow.Add(48 * time.Hour) })
	if !checker.RevokedDevice("device-2") {
		t.Fatal("require-fresh did not deny an unrevoked device once stale")
	}
	if status := checker.Status(); !status.DenyingAll {
		t.Fatal("Status did not report the deny-all posture")
	}
}

// An expired list is still loadable and still enforced. Refusing to load it
// would discard true revocations and enforce nothing in their place.
func TestExpiredListStillLoadsAndEnforces(t *testing.T) {
	signer, pins := testKeys(t)
	directory := t.TempDir()
	listPath := filepath.Join(directory, "revocation-list.json")
	writeList(t, listPath, signedList(t, signer, 1, []string{"device-1"}))

	wellAfterExpiry := testNow.Add(30 * 24 * time.Hour)
	list, _, err := LoadVerified(listPath, "", testController, pins, wellAfterExpiry)
	if err != nil {
		t.Fatalf("expired list refused to load: %v", err)
	}
	checker, err := NewChecker(list, DefaultMaxAge, false)
	if err != nil {
		t.Fatal(err)
	}
	checker.SetNow(func() time.Time { return wellAfterExpiry })
	if !checker.RevokedDevice("device-1") {
		t.Fatal("expired list stopped enforcing its revocations")
	}
	if status := checker.Status(); !status.Expired || !status.Stale {
		t.Fatalf("Status = %#v, want expired and stale", status)
	}
}

// A list dated in the future is rejected: unlike an old list, it is not a
// safe under-approximation of anything.
func TestFutureListIsRejected(t *testing.T) {
	signer, pins := testKeys(t)
	list := signedList(t, signer, 1, []string{"device-1"})
	if err := Verify(
		list, testController, pins, testNow.Add(-24*time.Hour),
	); err == nil {
		t.Fatal("list from the future verified")
	}
}

// Per-list salts mean two captured lists cannot be diffed to learn who was
// revoked in between.
func TestSaltsDifferAcrossLists(t *testing.T) {
	signer, _ := testKeys(t)
	first := signedList(t, signer, 1, []string{"device-1"})
	second := signedList(t, signer, 2, []string{"device-1"})
	if first.Salt == second.Salt {
		t.Fatal("two lists reused the same salt")
	}
	if first.RevokedHashes[0] == second.RevokedHashes[0] {
		t.Fatal("the same device hashed identically across two lists")
	}
}

func TestDeviceHashIsStableForOneSalt(t *testing.T) {
	signer, _ := testKeys(t)
	list := signedList(t, signer, 1, []string{"device-1"})
	checker, err := NewChecker(list, DefaultMaxAge, false)
	if err != nil {
		t.Fatal(err)
	}
	checker.SetNow(func() time.Time { return testNow })
	for range 3 {
		if !checker.RevokedDevice("device-1") {
			t.Fatal("device hash lookup is not stable")
		}
	}
}

func TestBuildRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name     string
		build    func() (List, error)
		contains string
	}{
		{"zero sequence", func() (List, error) {
			return Build(testController, 0, testNow, time.Hour, nil)
		}, "sequence"},
		{"empty controller", func() (List, error) {
			return Build("", 1, testNow, time.Hour, nil)
		}, "controller"},
		{"validity too long", func() (List, error) {
			return Build(testController, 1, testNow, 30*24*time.Hour, nil)
		}, "validity"},
		{"invalid device id", func() (List, error) {
			return Build(testController, 1, testNow, time.Hour, []string{"bad id!"})
		}, "invalid revoked device"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.build()
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error = %v, want one containing %q", err, test.contains)
			}
		})
	}
}

func TestBuildDeduplicatesAndOrders(t *testing.T) {
	list, err := Build(
		testController, 1, testNow, time.Hour,
		[]string{"device-3", "device-1", "device-2", "device-1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.RevokedHashes) != 3 {
		t.Fatalf("hash count = %d, want 3", len(list.RevokedHashes))
	}
	for index := 1; index < len(list.RevokedHashes); index++ {
		if list.RevokedHashes[index-1] >= list.RevokedHashes[index] {
			t.Fatal("hashes are not strictly ordered")
		}
	}
}

func TestInstallRejectsMalformedList(t *testing.T) {
	signer, _ := testKeys(t)
	list := signedList(t, signer, 1, []string{"device-1"})
	checker, err := NewChecker(list, DefaultMaxAge, false)
	if err != nil {
		t.Fatal(err)
	}
	broken := list
	broken.RevokedHashes = []string{"not-a-hash"}
	if err := checker.Install(broken); err == nil {
		t.Fatal("malformed list installed")
	}
	// The previously installed list must survive a rejected install.
	checker.SetNow(func() time.Time { return testNow })
	if !checker.RevokedDevice("device-1") {
		t.Fatal("a rejected install discarded the working list")
	}
}

// Refresh is what bounds the propagation delay for a revocation. Without it
// a revoked device keeps data-plane access until every carrier is restarted.
func TestRefreshPicksUpANewlyPublishedRevocation(t *testing.T) {
	signer, pins := testKeys(t)
	directory := t.TempDir()
	listPath := filepath.Join(directory, "revocation-list.json")
	statePath := filepath.Join(directory, "state.json")
	source := Source{
		ListPath:     listPath,
		StatePath:    statePath,
		ControllerID: testController,
		Pins:         pins,
	}

	writeList(t, listPath, signedList(t, signer, 1, nil))
	initial, _, err := LoadVerified(listPath, statePath, testController, pins, testNow)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := NewChecker(initial, DefaultMaxAge, false)
	if err != nil {
		t.Fatal(err)
	}
	checker.SetNow(func() time.Time { return testNow })
	if checker.RevokedDevice("device-1") {
		t.Fatal("device revoked before it was published")
	}

	// The operator publishes a new list naming the device.
	writeList(t, listPath, signedList(t, signer, 2, []string{"device-1"}))
	changed, err := checker.Refresh(source, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("Refresh did not report the new list")
	}
	if !checker.RevokedDevice("device-1") {
		t.Fatal("refreshed checker does not enforce the new revocation")
	}

	// Re-reading the same sequence is a no-op rather than a reinstall.
	changed, err = checker.Refresh(source, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("Refresh reinstalled an unchanged list")
	}
}

// A failed refresh must never widen access. This is the soft-fail promise in
// its most load-bearing form: if it were wrong, blocking distribution would
// un-revoke devices rather than merely delay new revocations.
func TestFailedRefreshKeepsEnforcingThePreviousList(t *testing.T) {
	signer, pins := testKeys(t)
	directory := t.TempDir()
	listPath := filepath.Join(directory, "revocation-list.json")
	statePath := filepath.Join(directory, "state.json")
	source := Source{
		ListPath:     listPath,
		StatePath:    statePath,
		ControllerID: testController,
		Pins:         pins,
	}

	writeList(t, listPath, signedList(t, signer, 5, []string{"device-1"}))
	initial, state, err := LoadVerified(listPath, statePath, testController, pins, testNow)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeTrustState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.AtomicWrite(statePath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	checker, err := NewChecker(initial, DefaultMaxAge, false)
	if err != nil {
		t.Fatal(err)
	}
	checker.SetNow(func() time.Time { return testNow })

	failures := []struct {
		name  string
		write func()
	}{
		{"forged signature", func() {
			forged := signedList(t, signer, 6, nil)
			forged.RevokedHashes = []string{strings.Repeat("c", 64)}
			writeList(t, listPath, forged)
		}},
		{"rollback to an emptier list", func() {
			writeList(t, listPath, signedList(t, signer, 2, nil))
		}},
		{"missing file", func() {
			if err := securefile.AtomicWrite(
				listPath, []byte("{}\n"), 0o644,
			); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, failure := range failures {
		t.Run(failure.name, func(t *testing.T) {
			failure.write()
			if _, err := checker.Refresh(source, testNow); err == nil {
				t.Fatal("invalid list was accepted")
			}
			if !checker.RevokedDevice("device-1") {
				t.Fatal("a failed refresh stopped enforcing the previous list")
			}
		})
	}
}

func TestTrustStateRoundTrip(t *testing.T) {
	signer, pins := testKeys(t)
	directory := t.TempDir()
	listPath := filepath.Join(directory, "revocation-list.json")
	statePath := filepath.Join(directory, "state.json")
	writeList(t, listPath, signedList(t, signer, 7, []string{"device-1"}))
	_, state, err := LoadVerified(listPath, statePath, testController, pins, testNow)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeTrustState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.AtomicWrite(statePath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTrustState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != state {
		t.Fatalf("trust state round trip = %#v, want %#v", loaded, state)
	}
}

// Without a retained state file LoadVerified has no rollback pin, so the
// running checker's own installed list must be the pin. An older, validly
// signed list (expired lists still load) must not replace a newer one, and a
// different list at the same sequence must be reported, not ignored.
func TestRefreshWithoutStateFileRejectsRollbackAndEquivocation(t *testing.T) {
	signer, pins := testKeys(t)
	listPath := filepath.Join(t.TempDir(), "revocation-list.json")
	source := Source{
		ListPath:     listPath,
		ControllerID: testController,
		Pins:         pins,
	}

	writeList(t, listPath, signedList(t, signer, 5, []string{"device-1"}))
	initial, _, err := LoadVerified(listPath, "", testController, pins, testNow)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := NewChecker(initial, DefaultMaxAge, false)
	if err != nil {
		t.Fatal(err)
	}
	checker.SetNow(func() time.Time { return testNow })

	writeList(t, listPath, signedList(t, signer, 2, nil))
	if _, err := checker.Refresh(source, testNow); err == nil ||
		!strings.Contains(err.Error(), "rollback") {
		t.Fatalf("stateless rollback refresh = %v, want rollback refusal", err)
	}
	if !checker.RevokedDevice("device-1") {
		t.Fatal("stateless rollback un-revoked device-1")
	}

	writeList(t, listPath, signedList(t, signer, 5, nil))
	if _, err := checker.Refresh(source, testNow); err == nil ||
		!strings.Contains(err.Error(), "equivocated") {
		t.Fatalf("stateless equivocation refresh = %v, want equivocation refusal", err)
	}
	if !checker.RevokedDevice("device-1") {
		t.Fatal("stateless equivocation un-revoked device-1")
	}
	if got := checker.Status().Sequence; got != 5 {
		t.Fatalf("installed sequence = %d, want 5", got)
	}

	// Forward progress still installs.
	writeList(t, listPath, signedList(t, signer, 6, []string{"device-1", "device-2"}))
	changed, err := checker.Refresh(source, testNow)
	if err != nil || !changed {
		t.Fatalf("forward refresh = %t, %v; want installed", changed, err)
	}
	if !checker.RevokedDevice("device-2") {
		t.Fatal("forward refresh did not enforce device-2")
	}
}

// Install is the pin for every caller, not only Refresh.
func TestInstallRefusesRollbackEquivocationAndForeignController(t *testing.T) {
	signer, _ := testKeys(t)
	current := signedList(t, signer, 3, []string{"device-1"})
	checker, err := NewChecker(current, DefaultMaxAge, false)
	if err != nil {
		t.Fatal(err)
	}
	checker.SetNow(func() time.Time { return testNow })
	if err := checker.Install(signedList(t, signer, 2, nil)); err == nil {
		t.Fatal("Install accepted a lower sequence")
	}
	if err := checker.Install(signedList(t, signer, 3, nil)); err == nil {
		t.Fatal("Install accepted a different list at the same sequence")
	}
	if err := checker.Install(current); err != nil {
		t.Fatalf("re-installing the identical list: %v", err)
	}
	foreign, err := Build("another-controller", 4, testNow, 24*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Sign(&foreign, signer); err != nil {
		t.Fatal(err)
	}
	if err := checker.Install(foreign); err == nil {
		t.Fatal("Install accepted a list from a different controller")
	}
	if !checker.RevokedDevice("device-1") {
		t.Fatal("a refused Install changed the enforced list")
	}
}
