package state

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/securefile"
)

func TestCredentialVaultReserveConsumeRestartAndReplay(
	t *testing.T,
) {
	fixture := newCredentialVaultFixture(t, 12)
	bundles := fixture.imports
	reservation, err := fixture.vault.BeginReservation(
		context.Background(), fixture.request("candidate-a"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if reservation.UnusedCredentials != 10 ||
		len(reservation.ClassInventories) != 1 {
		t.Fatalf("reservation inventory = %#v", reservation)
	}
	if err := fixture.vault.CommitReservation(
		context.Background(), reservation.ID,
	); err != nil {
		t.Fatal(err)
	}
	taken, err := fixture.vault.TakeCredential(
		context.Background(), reservation.ID, "candidate-a",
	)
	if err != nil {
		t.Fatal(err)
	}
	if taken.TokenID == "" || taken.Pseudonym == "" ||
		taken.Signer == nil {
		t.Fatalf("taken credential = %#v", taken)
	}
	message := []byte("destroyable credential signer")
	signature, err := pqauth.SignDomainMessage(
		pqauth.CarrierSignatureDomain, message, taken.Signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	clear(signature)
	taken.Signer.Destroy()
	if !taken.Signer.Destroyed() {
		t.Fatal("taken credential signer did not report destruction")
	}
	if _, err := pqauth.SignDomainMessage(
		pqauth.CarrierSignatureDomain, message, taken.Signer,
	); err == nil {
		t.Fatal("destroyed credential signer remained callable")
	}
	fixture.vault.mu.Lock()
	consumed := fixture.vault.state.Credentials[taken.TokenID]
	fixture.vault.mu.Unlock()
	if consumed.Status != credentialConsumed ||
		len(consumed.AuthSeed) != 0 ||
		consumed.Token != (privacytoken.Token{}) {
		t.Fatal("consumed credential retained vault secret material")
	}

	crashCredentialVault(t, fixture.vault)
	reopened := fixture.reopen(t)
	defer reopened.Close()
	if len(reopened.state.Reservations) != 0 {
		t.Fatal("restart did not reconcile active reservation")
	}
	available := availableCredentialIDs(reopened.state)
	if len(available[credentialClassID(fixture.class)]) != 11 {
		t.Fatalf(
			"restart available credentials = %d; want 11",
			len(available[credentialClassID(fixture.class)]),
		)
	}
	var replay CredentialImport
	for _, current := range bundles {
		verified, err := privacytoken.Verify(
			current.Bundle.PublicToken(),
			&fixture.issuer.PublicKey,
			fixture.class.TokenKeyID,
		)
		if err != nil {
			t.Fatal(err)
		}
		if verified.TokenID == taken.TokenID {
			replay = current
			break
		}
	}
	if replay.Bundle.Format == "" {
		t.Fatal("failed to locate consumed credential fixture")
	}
	if err := reopened.Add(
		context.Background(), []CredentialImport{replay},
	); err == nil {
		t.Fatal("durably consumed token was imported for replay")
	}
	assertPrivateVaultModes(t, fixture.path)
}

func TestCredentialVaultReconcilesCrashBeforeCommit(
	t *testing.T,
) {
	fixture := newCredentialVaultFixture(t, 12)
	reservation, err := fixture.vault.BeginReservation(
		context.Background(), fixture.request("candidate-a"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if reservation.ID == "" {
		t.Fatal("prepared reservation ID is empty")
	}
	crashCredentialVault(t, fixture.vault)
	reopened := fixture.reopen(t)
	defer reopened.Close()
	replacement, err := reopened.BeginReservation(
		context.Background(), fixture.request("candidate-b"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.UnusedCredentials != 10 {
		t.Fatalf(
			"post-crash unused inventory = %d; want 10",
			replacement.UnusedCredentials,
		)
	}
}

func TestCredentialVaultConcurrentExactReservations(
	t *testing.T,
) {
	const reservations = 8
	fixture := newCredentialVaultFixture(t, 24)
	defer fixture.vault.Close()
	results := make(chan CredentialReservation, reservations)
	failures := make(chan error, reservations)
	var group sync.WaitGroup
	group.Add(reservations)
	for index := range reservations {
		go func(current int) {
			defer group.Done()
			request := fixture.request(
				"candidate-" + string(rune('a'+current)),
			)
			reservation, err := fixture.vault.BeginReservation(
				context.Background(), request,
			)
			if err == nil {
				err = fixture.vault.CommitReservation(
					context.Background(), reservation.ID,
				)
			}
			if err != nil {
				failures <- err
				return
			}
			results <- reservation
		}(index)
	}
	group.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	seen := make(map[string]struct{}, reservations)
	var committed []CredentialReservation
	for reservation := range results {
		if _, duplicate := seen[reservation.ID]; duplicate {
			t.Fatal("concurrent reservations reused an ID")
		}
		seen[reservation.ID] = struct{}{}
		committed = append(committed, reservation)
	}
	if len(committed) != reservations {
		t.Fatalf(
			"committed reservations = %d; want %d",
			len(committed), reservations,
		)
	}
	fixture.vault.mu.Lock()
	reserved := 0
	for _, credential := range fixture.vault.state.Credentials {
		if credential.Status == credentialReserved {
			reserved++
		}
	}
	fixture.vault.mu.Unlock()
	if reserved != reservations*2 {
		t.Fatalf(
			"reserved credentials = %d; want %d",
			reserved, reservations*2,
		)
	}
	for _, reservation := range committed {
		if err := fixture.vault.ReleaseReservation(
			context.Background(), reservation.ID,
		); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCredentialVaultAtomicallyReservesMultipleClasses(
	t *testing.T,
) {
	fixture := newCredentialVaultFixture(t, 12)
	defer fixture.vault.Close()
	secondClass := fixture.class
	secondClass.Scope = "carrier-anonymous-secondary"
	secondClass.IssuerDomain = "issuer-independent-secondary"
	secondImports := issueCredentialVaultImports(
		t, fixture.issuer, secondClass, 10,
	)
	if err := fixture.vault.Add(
		context.Background(), secondImports,
	); err != nil {
		t.Fatal(err)
	}
	request := fixture.request("candidate-primary")
	request.Requirements = append(
		request.Requirements,
		CredentialRequirement{
			CandidateID: "candidate-secondary",
			NodeID:      "gateway-vault-secondary",
			Class:       secondClass,
			Count:       2,
		},
	)
	reservation, err := fixture.vault.BeginReservation(
		context.Background(), request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if reservation.UnusedCredentials != 8 ||
		len(reservation.ClassInventories) != 2 ||
		len(reservation.Candidates) != 2 {
		t.Fatalf("multi-class reservation = %#v", reservation)
	}
	if err := fixture.vault.CommitReservation(
		context.Background(), reservation.ID,
	); err != nil {
		t.Fatal(err)
	}
	first, err := fixture.vault.TakeCredential(
		context.Background(),
		reservation.ID,
		"candidate-primary",
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.vault.TakeCredential(
		context.Background(),
		reservation.ID,
		"candidate-secondary",
	)
	if err != nil {
		first.Signer.Destroy()
		t.Fatal(err)
	}
	first.Signer.Destroy()
	second.Signer.Destroy()
	if first.TokenID == second.TokenID {
		t.Fatal("multi-class reservation reused a token ID")
	}
}

func TestCredentialVaultExpiryAndRollbackSafeWriteFailure(
	t *testing.T,
) {
	fixture := newCredentialVaultFixture(t, 12)
	defer fixture.vault.Close()
	request := fixture.request("candidate-a")
	reservation, err := fixture.vault.BeginReservation(
		context.Background(), request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.vault.CommitReservation(
		context.Background(), reservation.ID,
	); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Set(request.ExpiresAt)
	if _, err := fixture.vault.TakeCredential(
		context.Background(), reservation.ID, "candidate-a",
	); !errors.Is(err, ErrCredentialReservation) {
		t.Fatalf("expired reservation take error = %v", err)
	}
	if err := fixture.vault.ReleaseReservation(
		context.Background(), reservation.ID,
	); err != nil {
		t.Fatal(err)
	}

	fixture.clock.Set(fixture.now.Add(61 * time.Minute))
	fixture.vault.mu.Lock()
	revision := fixture.vault.state.Revision
	fixture.vault.random = errorReader{}
	fixture.vault.mu.Unlock()
	retryRequest := fixture.request("candidate-b")
	retryRequest.ExpiresAt = fixture.now.Add(90 * time.Minute)
	if _, err := fixture.vault.BeginReservation(
		context.Background(), retryRequest,
	); err == nil {
		t.Fatal("injected persistence failure unexpectedly reserved")
	}
	fixture.vault.mu.Lock()
	if fixture.vault.state.Revision != revision ||
		len(fixture.vault.state.Reservations) != 0 {
		fixture.vault.mu.Unlock()
		t.Fatal("failed persistence changed in-memory vault state")
	}
	fixture.vault.random = bytes.NewReader(
		bytes.Repeat([]byte{0x5a}, 4096),
	)
	fixture.vault.mu.Unlock()
	if _, err := fixture.vault.BeginReservation(
		context.Background(), retryRequest,
	); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialVaultRejectsTruncationTamperAndLegacyPlaintext(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "truncated",
			mutate: func(data []byte) []byte {
				return data[:len(data)/2]
			},
		},
		{
			name: "tampered",
			mutate: func(data []byte) []byte {
				result := bytes.Clone(data)
				result[len(result)/2] ^= 0x01
				return result
			},
		},
		{
			name: "legacy plaintext",
			mutate: func(_ []byte) []byte {
				return []byte(
					`{"version":1,"credentials":[]}` + "\n",
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCredentialVaultFixture(t, 2)
			if err := fixture.vault.Close(); err != nil {
				t.Fatal(err)
			}
			encoded, err := os.ReadFile(fixture.path)
			if err != nil {
				t.Fatal(err)
			}
			mutated := test.mutate(encoded)
			if err := os.WriteFile(
				fixture.path, mutated, 0o600,
			); err != nil {
				t.Fatal(err)
			}
			if opened, err := OpenCredentialVault(
				fixture.config(),
			); err == nil {
				_ = opened.Close()
				t.Fatal("corrupt or legacy vault was accepted")
			}
		})
	}
}

func TestCredentialVaultCrossProcessLock(t *testing.T) {
	if os.Getenv("WINN_CREDENTIAL_LOCK_HELPER") == "1" {
		vault, err := OpenCredentialVault(CredentialVaultConfig{
			Path:    os.Getenv("WINN_CREDENTIAL_VAULT_PATH"),
			KeyPath: os.Getenv("WINN_CREDENTIAL_KEY_PATH"),
		})
		if err == nil {
			_ = vault.Close()
			os.Exit(7)
		}
		os.Exit(0)
	}
	fixture := newCredentialVaultFixture(t, 1)
	defer fixture.vault.Close()
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestCredentialVaultCrossProcessLock$",
	)
	command.Env = append(
		os.Environ(),
		"WINN_CREDENTIAL_LOCK_HELPER=1",
		"WINN_CREDENTIAL_VAULT_PATH="+fixture.path,
		"WINN_CREDENTIAL_KEY_PATH="+fixture.keyPath,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf(
			"cross-process lock helper failed: %v: %s",
			err, output,
		)
	}
}

type credentialVaultFixture struct {
	now     time.Time
	clock   *credentialVaultTestClock
	path    string
	keyPath string
	issuer  *rsa.PrivateKey
	class   CredentialClassBinding
	imports []CredentialImport
	vault   *CredentialVault
}

func newCredentialVaultFixture(
	t testing.TB,
	count int,
) *credentialVaultFixture {
	t.Helper()
	now := time.Date(
		2026, time.July, 24, 14, 0, 0, 0, time.UTC,
	)
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "vault.key")
	if err := securefile.AtomicWrite(
		keyPath, bytes.Repeat([]byte{0x33}, 32), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	issuer := credentialVaultIssuer(t)
	keyID, err := privacytoken.IssuerKeyID(&issuer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&issuer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	class := CredentialClassBinding{
		TokenKeyID:      keyID,
		Scope:           "carrier-anonymous",
		IssuerDomain:    "issuer-independent",
		IssuerPublicKey: base64.StdEncoding.EncodeToString(publicDER),
		NotBefore: now.Add(-time.Minute).Format(
			time.RFC3339Nano,
		),
		NotAfter: now.Add(2 * time.Hour).Format(
			time.RFC3339Nano,
		),
	}
	clear(publicDER)
	imports := issueCredentialVaultImports(t, issuer, class, count)
	clock := &credentialVaultTestClock{current: now}
	fixture := &credentialVaultFixture{
		now:     now,
		clock:   clock,
		path:    filepath.Join(directory, "credentials.vault"),
		keyPath: keyPath,
		issuer:  issuer,
		class:   class,
		imports: imports,
	}
	vault, err := OpenCredentialVault(fixture.config())
	if err != nil {
		t.Fatal(err)
	}
	fixture.vault = vault
	if err := vault.Add(context.Background(), imports); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *credentialVaultFixture) config() CredentialVaultConfig {
	return CredentialVaultConfig{
		Path:           fixture.path,
		KeyPath:        fixture.keyPath,
		MaxCredentials: 64,
		Now:            fixture.clock.Now,
	}
}

func (fixture *credentialVaultFixture) reopen(
	t testing.TB,
) *CredentialVault {
	t.Helper()
	vault, err := OpenCredentialVault(fixture.config())
	if err != nil {
		t.Fatal(err)
	}
	return vault
}

func (fixture *credentialVaultFixture) request(
	candidateID string,
) CredentialReservationRequest {
	return CredentialReservationRequest{
		Profile:                  "auto-vault",
		ControllerID:             "controller-vault",
		ManifestDigest:           strings.Repeat("a", 64),
		ManifestSequence:         11,
		ExpiresAt:                fixture.clock.Now().Add(time.Hour),
		MinimumUnusedCredentials: 8,
		Requirements: []CredentialRequirement{{
			CandidateID: candidateID,
			NodeID:      "gateway-vault",
			Class:       fixture.class,
			Count:       2,
		}},
	}
}

func issueCredentialVaultImports(
	t testing.TB,
	issuer *rsa.PrivateKey,
	class CredentialClassBinding,
	count int,
) []CredentialImport {
	t.Helper()
	result := make([]CredentialImport, count)
	for index := range count {
		request, state, err := privacytoken.BeginIssue(
			&issuer.PublicKey, pqauth.MLDSA65,
		)
		if err != nil {
			t.Fatal(err)
		}
		response, err := privacytoken.BlindSign(request, issuer)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := state.Finalize(response)
		if err != nil {
			t.Fatal(err)
		}
		result[index] = CredentialImport{
			Class: class, Bundle: bundle,
		}
	}
	return result
}

var (
	credentialVaultIssuerOnce sync.Once
	credentialVaultIssuerKey  *rsa.PrivateKey
	credentialVaultIssuerErr  error
)

func credentialVaultIssuer(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	credentialVaultIssuerOnce.Do(func() {
		credentialVaultIssuerKey,
			credentialVaultIssuerErr =
			privacytoken.GenerateIssuerKey(3072)
	})
	if credentialVaultIssuerErr != nil {
		t.Fatal(credentialVaultIssuerErr)
	}
	return credentialVaultIssuerKey
}

func crashCredentialVault(
	t testing.TB,
	vault *CredentialVault,
) {
	t.Helper()
	vault.mu.Lock()
	if vault.lock == nil {
		vault.mu.Unlock()
		t.Fatal("credential vault has no process lock")
	}
	if err := vault.lock.release(); err != nil {
		vault.mu.Unlock()
		t.Fatal(err)
	}
	vault.lock = nil
	clearCredentialVaultSecrets(&vault.state)
	clear(vault.key[:])
	vault.closed = true
	vault.mu.Unlock()
}

func assertPrivateVaultModes(t testing.TB, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	for _, current := range []string{path, path + ".lock"} {
		info, err := os.Stat(current)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf(
				"%s mode = %04o; want 0600",
				current, info.Mode().Perm(),
			)
		}
	}
}

type credentialVaultTestClock struct {
	mu      sync.Mutex
	current time.Time
}

func (clock *credentialVaultTestClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.current
}

func (clock *credentialVaultTestClock) Set(current time.Time) {
	clock.mu.Lock()
	clock.current = current
	clock.mu.Unlock()
}

type errorReader struct{}

func (errorReader) Read(_ []byte) (int, error) {
	return 0, errors.New("injected credential vault random failure")
}
