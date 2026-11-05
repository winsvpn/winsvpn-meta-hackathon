package preparation

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/state"
)

func TestEncryptedCredentialVaultAdapterPersistsAndDestroysSigners(
	t *testing.T,
) {
	fixture := newEncryptedCredentialAdapterFixture(t, 12)
	lease, err := fixture.pool.AcquireAnonymousCredentialInventory(
		context.Background(), fixture.request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if lease.UnusedCredentials != 12-MinimumReservedCredentialsPerH3 ||
		len(lease.ClassInventories) != 1 {
		t.Fatalf("encrypted inventory lease = %#v", lease)
	}
	requirement := fixture.request.Requirements[0]
	sublease, err := lease.Credentials.AcquireAnonymousCredentials(
		context.Background(),
		credentialSubleaseRequest(requirement, lease.ExpiresAt),
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := sublease.Source.NextAnonymousCredential()
	if err != nil {
		t.Fatal(err)
	}
	if credential.Resource == nil || credential.Signer == nil ||
		credential.Signer.Destroyed() {
		t.Fatal("vault credential did not own a live signer resource")
	}
	if _, err := privacytoken.Verify(
		credential.Token,
		&fixture.issuer.PublicKey,
		requirement.TokenKeyID,
	); err != nil {
		t.Fatal(err)
	}
	signer := credential.Signer
	credential.Destroy()
	if !signer.Destroyed() {
		t.Fatal("explicit credential cleanup did not destroy signer")
	}
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sublease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.vault.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := state.OpenCredentialVault(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	adapter, err := NewEncryptedAnonymousCredentialVault(reopened)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewProductionAnonymousCredentialPool(
		ProductionAnonymousCredentialPoolConfig{
			Vault: adapter,
			Now:   func() time.Time { return fixture.now },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := pool.AcquireAnonymousCredentialInventory(
		context.Background(), fixture.request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.UnusedCredentials !=
		11-MinimumReservedCredentialsPerH3 {
		t.Fatalf(
			"post-restart unused credentials = %d; want %d",
			replacement.UnusedCredentials,
			11-MinimumReservedCredentialsPerH3,
		)
	}
	if err := replacement.Resource.Close(
		context.Background(),
	); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptedCredentialVaultAdapterRetirementDestroysLeakedSigner(
	t *testing.T,
) {
	fixture := newEncryptedCredentialAdapterFixture(t, 12)
	defer fixture.vault.Close()
	lease, err := fixture.pool.AcquireAnonymousCredentialInventory(
		context.Background(), fixture.request,
	)
	if err != nil {
		t.Fatal(err)
	}
	requirement := fixture.request.Requirements[0]
	sublease, err := lease.Credentials.AcquireAnonymousCredentials(
		context.Background(),
		credentialSubleaseRequest(requirement, lease.ExpiresAt),
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := sublease.Source.NextAnonymousCredential()
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if credential.Signer.Destroyed() {
		t.Fatal("root close revoked an active scoped credential")
	}
	if err := sublease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !credential.Signer.Destroyed() {
		t.Fatal("candidate retirement did not destroy leaked signer")
	}
}

type encryptedCredentialAdapterFixture struct {
	now     time.Time
	issuer  *rsa.PrivateKey
	request AnonymousCredentialPoolRequest
	config  state.CredentialVaultConfig
	vault   *state.CredentialVault
	pool    *ProductionAnonymousCredentialPool
}

func newEncryptedCredentialAdapterFixture(
	t testing.TB,
	count int,
) *encryptedCredentialAdapterFixture {
	t.Helper()
	now := productionNow()
	issuer := productionCredentialIssuer(t)
	keyID, err := privacytoken.IssuerKeyID(&issuer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&issuer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	requirement := AnonymousCredentialRequirement{
		CandidateID:     "h3-encrypted-vault",
		NodeID:          "gateway-encrypted-vault",
		TokenKeyID:      keyID,
		CredentialScope: "carrier-anonymous",
		IssuerDomain:    "issuer-independent",
		IssuerPublicKey: base64.StdEncoding.EncodeToString(
			publicDER,
		),
		NotBefore: now.Add(-time.Minute).Format(
			time.RFC3339Nano,
		),
		NotAfter: now.Add(2 * time.Hour).Format(
			time.RFC3339Nano,
		),
		Count: MinimumReservedCredentialsPerH3,
	}
	clear(publicDER)
	request := AnonymousCredentialPoolRequest{
		Profile:                  "auto-encrypted-vault",
		ControllerID:             "controller-encrypted-vault",
		ManifestDigest:           strings.Repeat("c", 64),
		ManifestSequence:         13,
		ExpiresAt:                now.Add(time.Hour),
		MinimumUnusedCredentials: Phase1MinimumUnusedCredentials,
		Requirements: []AnonymousCredentialRequirement{
			requirement,
		},
	}
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "vault.key")
	if err := securefile.AtomicWrite(
		keyPath, bytes.Repeat([]byte{0x4d}, 32), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	config := state.CredentialVaultConfig{
		Path:           filepath.Join(directory, "credentials.vault"),
		KeyPath:        keyPath,
		MaxCredentials: 64,
		Now:            func() time.Time { return now },
	}
	vault, err := state.OpenCredentialVault(config)
	if err != nil {
		t.Fatal(err)
	}
	class := state.CredentialClassBinding{
		TokenKeyID:      requirement.TokenKeyID,
		Scope:           requirement.CredentialScope,
		IssuerDomain:    requirement.IssuerDomain,
		IssuerPublicKey: requirement.IssuerPublicKey,
		NotBefore:       requirement.NotBefore,
		NotAfter:        requirement.NotAfter,
	}
	imports := make([]state.CredentialImport, count)
	for index := range count {
		issueRequest, clientState, err := privacytoken.BeginIssue(
			&issuer.PublicKey, pqauth.MLDSA65,
		)
		if err != nil {
			t.Fatal(err)
		}
		response, err := privacytoken.BlindSign(issueRequest, issuer)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := clientState.Finalize(response)
		if err != nil {
			t.Fatal(err)
		}
		imports[index] = state.CredentialImport{
			Class: class, Bundle: bundle,
		}
	}
	if err := vault.Add(context.Background(), imports); err != nil {
		t.Fatal(err)
	}
	adapter, err := NewEncryptedAnonymousCredentialVault(vault)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewProductionAnonymousCredentialPool(
		ProductionAnonymousCredentialPoolConfig{
			Vault: adapter,
			Now:   func() time.Time { return now },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return &encryptedCredentialAdapterFixture{
		now:     now,
		issuer:  issuer,
		request: request,
		config:  config,
		vault:   vault,
		pool:    pool,
	}
}
