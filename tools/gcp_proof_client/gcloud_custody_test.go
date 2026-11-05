package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	testAccount      = "proof@winsproof123.iam.gserviceaccount.com"
	testOtherAccount = "other@winsproof123.iam.gserviceaccount.com"
	testProject      = "winsproof123"
	testPrivateKey   = "TEST_GCLOUD_FAKE_PRIVATE_KEY_MATERIAL"
)

func testGcloudIdentity(t *testing.T) gcloudIdentityInput {
	t.Helper()
	return writeTestCredential(t, 0400, testAccount, testProject, gcloudServiceAccountKind)
}

func writeTestCredential(t *testing.T, mode os.FileMode, account, project, kind string) gcloudIdentityInput {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "credential.json")
	var payload any
	if kind == gcloudWorkloadIdentityKind {
		subjectToken := filepath.Join(dir, "subject-token")
		if err := os.WriteFile(subjectToken, []byte("fixture-signed-subject-token\n"), 0400); err != nil {
			t.Fatal(err)
		}
		payload = map[string]any{
			"type":               "external_account",
			"audience":           "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/pool/providers/prov",
			"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
			"token_url":          "https://sts.googleapis.com/v1/token",
			"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" +
				account + ":generateAccessToken",
			"credential_source": map[string]any{"file": subjectToken},
		}
	} else {
		payload = map[string]any{
			"type":           "service_account",
			"project_id":     project,
			"private_key_id": "fixture",
			"private_key":    "-----BEGIN PRIVATE KEY-----\n" + testPrivateKey + "\n-----END PRIVATE KEY-----\n",
			"client_email":   account,
			"client_id":      "1234567890",
			"auth_uri":       "https://accounts.google.com/o/oauth2/auth",
			"token_uri":      "https://oauth2.googleapis.com/token",
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return gcloudIdentityInput{
		kind: kind, path: path, expectedAccount: testAccount, expectedProject: testProject,
	}
}

func assertNoSecret(t *testing.T, text string) {
	t.Helper()
	for _, secret := range []string{testPrivateKey, testAccount, testOtherAccount, "attacker-sentinel"} {
		if strings.Contains(text, secret) {
			t.Fatalf("report retained identity or key material")
		}
	}
}

func packedTarGz(t *testing.T, members []tarFixtureMember) []byte {
	t.Helper()
	return makeGcloudArchive(t, members)
}

func TestArchiveBombLimitsFailBeforeExtraction(t *testing.T) {
	t.Run("outer", func(t *testing.T) {
		old := maxGcloudArchiveOuter
		maxGcloudArchiveOuter = 8
		t.Cleanup(func() { maxGcloudArchiveOuter = old })
		archive := packedTarGz(t, []tarFixtureMember{
			{name: "google-cloud-sdk/bin/gcloud", typeflag: tar.TypeReg, mode: 0755, body: "x"},
		})
		if _, err := extractOfficialGcloudArchive(archive, "google-cloud-cli.tar.gz", filepath.Join(t.TempDir(), "outer")); err == nil {
			t.Fatal("outer size bomb was accepted")
		} else if !strings.Contains(err.Error(), "outer size") {
			t.Fatalf("wrong refusal: %v", err)
		}
	})
	t.Run("count", func(t *testing.T) {
		old := maxGcloudArchiveEntries
		maxGcloudArchiveEntries = 2
		t.Cleanup(func() { maxGcloudArchiveEntries = old })
		archive := packedTarGz(t, []tarFixtureMember{
			{name: "google-cloud-sdk/a", typeflag: tar.TypeReg, mode: 0644, body: "1"},
			{name: "google-cloud-sdk/b", typeflag: tar.TypeReg, mode: 0644, body: "2"},
			{name: "google-cloud-sdk/c", typeflag: tar.TypeReg, mode: 0644, body: "3"},
			{name: "google-cloud-sdk/d", typeflag: tar.TypeReg, mode: 0644, body: "4"},
		})
		if _, err := extractOfficialGcloudArchive(archive, "google-cloud-cli.tar.gz", filepath.Join(t.TempDir(), "count")); err == nil {
			t.Fatal("member-count bomb was accepted")
		} else if !strings.Contains(err.Error(), "too many members") {
			t.Fatalf("wrong refusal: %v", err)
		}
	})
	t.Run("member", func(t *testing.T) {
		old := maxGcloudArchiveMember
		maxGcloudArchiveMember = 4
		t.Cleanup(func() { maxGcloudArchiveMember = old })
		archive := packedTarGz(t, []tarFixtureMember{
			{name: "google-cloud-sdk/big.bin", typeflag: tar.TypeReg, mode: 0644, body: "abcdefghij"},
		})
		if _, err := extractOfficialGcloudArchive(archive, "google-cloud-cli.tar.gz", filepath.Join(t.TempDir(), "member")); err == nil {
			t.Fatal("member-size bomb was accepted")
		} else if !strings.Contains(err.Error(), "member size") {
			t.Fatalf("wrong refusal: %v", err)
		}
	})
	t.Run("aggregate", func(t *testing.T) {
		old := maxGcloudArchiveBytes
		maxGcloudArchiveBytes = 6
		t.Cleanup(func() { maxGcloudArchiveBytes = old })
		archive := packedTarGz(t, []tarFixtureMember{
			{name: "google-cloud-sdk/one.bin", typeflag: tar.TypeReg, mode: 0644, body: "abcd"},
			{name: "google-cloud-sdk/two.bin", typeflag: tar.TypeReg, mode: 0644, body: "efgh"},
		})
		if _, err := extractOfficialGcloudArchive(archive, "google-cloud-cli.tar.gz", filepath.Join(t.TempDir(), "aggregate")); err == nil {
			t.Fatal("aggregate bomb was accepted")
		} else if !strings.Contains(err.Error(), "aggregate") {
			t.Fatalf("wrong refusal: %v", err)
		}
	})
	t.Run("depth", func(t *testing.T) {
		old := maxGcloudArchiveDepth
		maxGcloudArchiveDepth = 3
		t.Cleanup(func() { maxGcloudArchiveDepth = old })
		archive := packedTarGz(t, []tarFixtureMember{
			{name: "google-cloud-sdk/a/b/c/d", typeflag: tar.TypeReg, mode: 0644, body: "x"},
		})
		if _, err := extractOfficialGcloudArchive(archive, "google-cloud-cli.tar.gz", filepath.Join(t.TempDir(), "depth")); err == nil {
			t.Fatal("depth bomb was accepted")
		} else if !strings.Contains(err.Error(), "depth") {
			t.Fatalf("wrong refusal: %v", err)
		}
	})
	t.Run("ratio", func(t *testing.T) {
		old := maxGcloudArchiveRatio
		maxGcloudArchiveRatio = 2
		t.Cleanup(func() { maxGcloudArchiveRatio = old })
		zeros := bytes.Repeat([]byte{0}, 256*1024)
		archive := packedTarGz(t, []tarFixtureMember{
			{name: "google-cloud-sdk/zeros.bin", typeflag: tar.TypeReg, mode: 0644, body: string(zeros)},
		})
		if _, err := extractOfficialGcloudArchive(archive, "google-cloud-cli.tar.gz", filepath.Join(t.TempDir(), "ratio")); err == nil {
			t.Fatal("compression-ratio bomb was accepted")
		} else if !strings.Contains(err.Error(), "ratio") && !strings.Contains(err.Error(), "expanded size") {
			t.Fatalf("wrong refusal: %v", err)
		}
	})
}

func TestCredentialUnsafeModeWrongIdentityAndAmbientEnv(t *testing.T) {
	t.Run("unsafe mode", func(t *testing.T) {
		input := writeTestCredential(t, 0644, testAccount, testProject, gcloudServiceAccountKind)
		_, err := authenticateGcloudCredential(input)
		if err == nil {
			t.Fatal("unsafe-mode credential was accepted")
		}
		if !strings.Contains(err.Error(), "immutable mode 0400") {
			t.Fatalf("wrong refusal: %v", err)
		}
		assertNoSecret(t, err.Error())
	})
	t.Run("wrong identity", func(t *testing.T) {
		input := writeTestCredential(t, 0400, testOtherAccount, testProject, gcloudServiceAccountKind)
		_, err := authenticateGcloudCredential(input)
		if err == nil {
			t.Fatal("wrong identity was accepted")
		}
		if !strings.Contains(err.Error(), "does not match the bound identity") {
			t.Fatalf("wrong refusal: %v", err)
		}
		assertNoSecret(t, err.Error())
	})
	t.Run("workload identity", func(t *testing.T) {
		input := writeTestCredential(t, 0400, testAccount, testProject, gcloudWorkloadIdentityKind)
		bound, err := authenticateGcloudCredential(input)
		if err != nil {
			t.Fatal(err)
		}
		if bound.kind != gcloudWorkloadIdentityKind || bound.expectedProject != testProject {
			t.Fatal("workload identity was not bound")
		}
	})
	t.Run("wrong project", func(t *testing.T) {
		input := writeTestCredential(t, 0400, testAccount, "otherproof123", gcloudServiceAccountKind)
		_, err := authenticateGcloudCredential(input)
		if err == nil {
			t.Fatal("wrong project was accepted")
		}
		if !strings.Contains(err.Error(), "does not match the bound identity") {
			t.Fatalf("wrong refusal: %v", err)
		}
		assertNoSecret(t, err.Error())
	})
	t.Run("ambient env omitted", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/attacker-sentinel.json")
		t.Setenv("PYTHONPATH", "/tmp/attacker-sentinel")
		t.Setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "/tmp/attacker-sentinel.json")
		env, err := isolatedGcloudEnv("/tmp/home", "/tmp/config", "/tmp/tmp", "/tmp/config/bound_credential.json", testProject)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(env, "\n")
		if strings.Contains(joined, "GOOGLE_APPLICATION_CREDENTIALS=") ||
			strings.Contains(joined, "PYTHONPATH=") ||
			strings.Contains(joined, "attacker-sentinel") {
			t.Fatal("isolated environment inherited ambient credentials")
		}
		if !strings.Contains(joined, "CLOUDSDK_CONFIG=/tmp/config") ||
			!strings.Contains(joined, "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=/tmp/config/bound_credential.json") {
			t.Fatal("isolated environment lost the bound credential")
		}
	})
}

func writeCredentialPayload(t *testing.T, kind string, payload any) gcloudIdentityInput {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential.json")
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	return gcloudIdentityInput{
		kind: kind, path: path, expectedAccount: testAccount, expectedProject: testProject,
	}
}

func TestExactServiceAccountAndWIFSemantics(t *testing.T) {
	t.Run("bare private key", func(t *testing.T) {
		input := writeCredentialPayload(t, gcloudServiceAccountKind, map[string]any{
			"type": "service_account", "project_id": testProject, "private_key_id": "fixture",
			"private_key": testPrivateKey, "client_email": testAccount, "client_id": "1234567890",
			"auth_uri": saAuthURI, "token_uri": saTokenURI,
		})
		_, err := authenticateGcloudCredential(input)
		if err == nil {
			t.Fatal("bare private key was accepted")
		}
		if !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("wrong refusal: %v", err)
		}
		assertNoSecret(t, err.Error())
	})
	t.Run("wrong auth uri", func(t *testing.T) {
		input := writeCredentialPayload(t, gcloudServiceAccountKind, map[string]any{
			"type": "service_account", "project_id": testProject, "private_key_id": "fixture",
			"private_key":  "-----BEGIN PRIVATE KEY-----\n" + testPrivateKey + "\n-----END PRIVATE KEY-----\n",
			"client_email": testAccount, "client_id": "1234567890",
			"auth_uri": "https://example.invalid/auth", "token_uri": saTokenURI,
		})
		_, err := authenticateGcloudCredential(input)
		if err == nil {
			t.Fatal("wrong auth uri was accepted")
		}
		assertNoSecret(t, err.Error())
	})
	t.Run("missing sa key", func(t *testing.T) {
		input := writeCredentialPayload(t, gcloudServiceAccountKind, map[string]any{
			"type": "service_account", "project_id": testProject, "private_key_id": "fixture",
			"private_key":  "-----BEGIN PRIVATE KEY-----\n" + testPrivateKey + "\n-----END PRIVATE KEY-----\n",
			"client_email": testAccount, "client_id": "1234567890",
			"token_uri": saTokenURI,
		})
		_, err := authenticateGcloudCredential(input)
		if err == nil {
			t.Fatal("incomplete service-account keys were accepted")
		}
		if !strings.Contains(err.Error(), "keys are not exact") {
			t.Fatalf("wrong refusal: %v", err)
		}
		assertNoSecret(t, err.Error())
	})
	t.Run("wrong wif token url", func(t *testing.T) {
		input := writeCredentialPayload(t, gcloudWorkloadIdentityKind, map[string]any{
			"type":               "external_account",
			"audience":           "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/pool/providers/prov",
			"subject_token_type": wifSubjectTokenType,
			"token_url":          "https://example.invalid/token",
			"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" +
				testAccount + ":generateAccessToken",
			"credential_source": map[string]any{"file": "/var/run/service-account/token"},
		})
		_, err := authenticateGcloudCredential(input)
		if err == nil {
			t.Fatal("wrong WIF token URL was accepted")
		}
		assertNoSecret(t, err.Error())
	})
	t.Run("relative wif source", func(t *testing.T) {
		input := writeCredentialPayload(t, gcloudWorkloadIdentityKind, map[string]any{
			"type":               "external_account",
			"audience":           "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/pool/providers/prov",
			"subject_token_type": wifSubjectTokenType,
			"token_url":          wifTokenURL,
			"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" +
				testAccount + ":generateAccessToken",
			"credential_source": map[string]any{"file": "relative-token"},
		})
		_, err := authenticateGcloudCredential(input)
		if err == nil {
			t.Fatal("relative WIF credential source was accepted")
		}
		assertNoSecret(t, err.Error())
	})
	t.Run("regional wif audience", func(t *testing.T) {
		input := writeCredentialPayload(t, gcloudWorkloadIdentityKind, map[string]any{
			"type":               "external_account",
			"audience":           "//iam.googleapis.com/projects/123456789/locations/us-central1/workloadIdentityPools/pool/providers/prov",
			"subject_token_type": wifSubjectTokenType,
			"token_url":          wifTokenURL,
			"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" +
				testAccount + ":generateAccessToken",
			"credential_source": map[string]any{"file": "/var/run/service-account/token"},
		})
		_, err := authenticateGcloudCredential(input)
		if err == nil {
			t.Fatal("regional WIF audience was accepted")
		}
		assertNoSecret(t, err.Error())
	})
}

func TestWIFSubjectTokenIsDescriptorSnapshottedAndCredentialIsRewritten(t *testing.T) {
	input := writeTestCredential(t, 0400, testAccount, testProject, gcloudWorkloadIdentityKind)
	bound, err := authenticateGcloudCredential(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(bound.subjectToken) != "fixture-signed-subject-token\n" {
		t.Fatal("authenticated WIF subject token bytes were not retained")
	}
	var parsed workloadIdentityCredential
	if err := strictDecode(bound.data, &parsed); err != nil {
		t.Fatal(err)
	}
	var source map[string]string
	if err := strictDecode(parsed.CredentialSource, &source); err != nil {
		t.Fatal(err)
	}
	original := source["file"]
	if err := os.Rename(original, original+".held"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(original, []byte("attacker-subject-token\n"), 0400); err != nil {
		t.Fatal(err)
	}
	rewritten, err := runtimeGcloudCredential(bound, "/proc/self/fd/6")
	if err != nil {
		t.Fatal(err)
	}
	if err := strictDecode(rewritten, &parsed); err != nil {
		t.Fatal(err)
	}
	if err := strictDecode(parsed.CredentialSource, &source); err != nil {
		t.Fatal(err)
	}
	if source["file"] != "/proc/self/fd/6" || bytes.Contains(rewritten, []byte(original)) {
		t.Fatal("runtime WIF credential still references the replaceable subject-token pathname")
	}
	if string(bound.subjectToken) != "fixture-signed-subject-token\n" {
		t.Fatal("pathname replacement changed descriptor-snapshotted subject token bytes")
	}
}

func TestWIFSubjectTokenRejectsMutableModeAndExtraLink(t *testing.T) {
	input := writeTestCredential(t, 0400, testAccount, testProject, gcloudWorkloadIdentityKind)
	credentialData, err := os.ReadFile(input.path)
	if err != nil {
		t.Fatal(err)
	}
	var parsed workloadIdentityCredential
	if err := strictDecode(credentialData, &parsed); err != nil {
		t.Fatal(err)
	}
	var source map[string]string
	if err := strictDecode(parsed.CredentialSource, &source); err != nil {
		t.Fatal(err)
	}
	subjectPath := source["file"]
	if err := os.Chmod(subjectPath, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticateGcloudCredential(input); err == nil || !strings.Contains(err.Error(), "descriptor-authenticated mode 0400") {
		t.Fatalf("mutable subject-token mode was not refused: %v", err)
	}
	if err := os.Chmod(subjectPath, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(subjectPath, subjectPath+".extra-link"); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticateGcloudCredential(input); err == nil || !strings.Contains(err.Error(), "descriptor-authenticated mode 0400") {
		t.Fatalf("multiply linked subject token was not refused: %v", err)
	}
}

func mutateGcloudReceipt(t *testing.T, fixture gcloudCustodyFixture, mutate func(map[string]any)) {
	t.Helper()
	data, err := os.ReadFile(fixture.receipt)
	if err != nil {
		t.Fatal(err)
	}
	var receipt map[string]any
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	mutate(receipt)
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.receipt, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.receipt, encoded, 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.receipt, 0444); err != nil {
		t.Fatal(err)
	}
}

func newVerifiedGcloudFixtureGuard(t *testing.T) (gcloudCustodyFixture, *verifiedGcloud) {
	t.Helper()
	fixture := newGcloudCustodyFixture(t)
	guard, err := verifyGcloudCustodyWithPinAndAuthority(
		fixture.executable, fixture.pin, fixture.authority, fixture.issuance, fixture.authorityOwner,
	)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, guard
}

func overwriteTestOwnerCustodyFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
}

func replaceTestOwnerCustodyFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusiveFile(path, data, 0400); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyUnchangedRevalidatesFixedOwnerAuthorization(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		_, guard := newVerifiedGcloudFixtureGuard(t)
		var issuance gcloudOwnerIssuanceDocument
		if err := strictDecode(guard.ownerAuthorization.issuance.data, &issuance); err != nil {
			t.Fatal(err)
		}
		var authorization gcloudReceiptAuthorizationDocument
		if err := strictDecode(issuance.Receipt, &authorization); err != nil {
			t.Fatal(err)
		}
		expires, err := time.Parse("2006-01-02T15:04:05Z", authorization.ExpiresUTC)
		if err != nil {
			t.Fatal(err)
		}
		if err := guard.verifyUnchangedAt(expires); err == nil ||
			(!strings.Contains(err.Error(), "stale") && !strings.Contains(err.Error(), "expired")) {
			t.Fatalf("expired owner authorization was accepted: %v", err)
		}
	})

	for _, tc := range []struct {
		name string
		file func(*verifiedGcloud) gcloudAuthorityFileCustody
	}{
		{name: "authority byte drift", file: func(guard *verifiedGcloud) gcloudAuthorityFileCustody {
			return guard.ownerAuthorization.authority
		}},
		{name: "issuance byte drift", file: func(guard *verifiedGcloud) gcloudAuthorityFileCustody {
			return guard.ownerAuthorization.issuance
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, guard := newVerifiedGcloudFixtureGuard(t)
			custody := tc.file(guard)
			hostile := append([]byte(nil), custody.data...)
			hostile[len(hostile)-1] ^= 1
			overwriteTestOwnerCustodyFile(t, custody.configuredPath, hostile)
			if err := guard.verifyUnchanged(); err == nil || !strings.Contains(err.Error(), "custody changed") {
				t.Fatalf("owner authorization byte drift was accepted: %v", err)
			}
		})
	}

	t.Run("valid same-release issuance rotation", func(t *testing.T) {
		fixture, guard := newVerifiedGcloudFixtureGuard(t)
		receiptData, err := os.ReadFile(fixture.receipt)
		if err != nil {
			t.Fatal(err)
		}
		var rotated gcloudReceipt
		if err := strictDecode(receiptData, &rotated); err != nil {
			t.Fatal(err)
		}
		rotated.IssuanceID = strings.Repeat("b", 32)
		signTestGcloudReceipt(t, &rotated, fixture.privateKey)
		writeTestGcloudIssuance(t, fixture.issuance, rotated)
		if err := guard.verifyUnchanged(); err == nil || !strings.Contains(err.Error(), "issuance custody changed") {
			t.Fatalf("owner issuance rotation was accepted: %v", err)
		}
	})

	for _, tc := range []struct {
		name      string
		authority bool
	}{
		{name: "authority path drift", authority: true},
		{name: "issuance path drift", authority: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newGcloudCustodyFixture(t)
			target := fixture.issuance
			if tc.authority {
				target = fixture.authority
			}
			link := filepath.Join(t.TempDir(), "fixed-owner-custody.json")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			authorityPath, issuancePath := fixture.authority, fixture.issuance
			if tc.authority {
				authorityPath = link
			} else {
				issuancePath = link
			}
			guard, err := verifyGcloudCustodyWithPinAndAuthority(
				fixture.executable, fixture.pin, authorityPath, issuancePath, fixture.authorityOwner,
			)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			replacement := filepath.Join(t.TempDir(), "replacement-owner-custody.json")
			if err := writeExclusiveFile(replacement, data, 0400); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(replacement, link); err != nil {
				t.Fatal(err)
			}
			if err := guard.verifyUnchanged(); err == nil || !strings.Contains(err.Error(), "custody changed") {
				t.Fatalf("owner authorization path drift was accepted: %v", err)
			}
		})
	}
}

func TestVerifyUnchangedRechecksSignatureOwnerAndReleaseAfterSnapshotMatch(t *testing.T) {
	t.Run("signature", func(t *testing.T) {
		_, guard := newVerifiedGcloudFixtureGuard(t)
		var issuance map[string]any
		if err := json.Unmarshal(guard.ownerAuthorization.issuance.data, &issuance); err != nil {
			t.Fatal(err)
		}
		issuance["signature"] = strings.Repeat("0", 128)
		encoded, err := json.Marshal(issuance)
		if err != nil {
			t.Fatal(err)
		}
		replaceTestOwnerCustodyFile(t, guard.ownerAuthorization.issuance.configuredPath, encoded)
		guard.ownerAuthorization.issuance, err = stableExternalAuthorityFile(
			guard.ownerAuthorization.issuance.configuredPath, guard.ownerAuthorization.authorityOwner,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := guard.verifyUnchanged(); err == nil || !strings.Contains(err.Error(), "signature") {
			t.Fatalf("forged owner issuance survived full revalidation: %v", err)
		}
	})

	t.Run("owner binding", func(t *testing.T) {
		_, guard := newVerifiedGcloudFixtureGuard(t)
		var authority map[string]any
		if err := json.Unmarshal(guard.ownerAuthorization.authority.data, &authority); err != nil {
			t.Fatal(err)
		}
		authority["owner_uid"] = uint64(guard.ownerAuthorization.authorityOwner) + 1
		encoded, err := json.Marshal(authority)
		if err != nil {
			t.Fatal(err)
		}
		replaceTestOwnerCustodyFile(t, guard.ownerAuthorization.authority.configuredPath, encoded)
		guard.ownerAuthorization.authority, err = stableExternalAuthorityFile(
			guard.ownerAuthorization.authority.configuredPath, guard.ownerAuthorization.authorityOwner,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := guard.verifyUnchanged(); err == nil || !strings.Contains(err.Error(), "owner authority is invalid") {
			t.Fatalf("wrong owner binding survived full revalidation: %v", err)
		}
	})

	t.Run("same release", func(t *testing.T) {
		fixture, guard := newVerifiedGcloudFixtureGuard(t)
		receiptData, err := os.ReadFile(fixture.receipt)
		if err != nil {
			t.Fatal(err)
		}
		var differentRelease gcloudReceipt
		if err := strictDecode(receiptData, &differentRelease); err != nil {
			t.Fatal(err)
		}
		differentRelease.Version = "999.0.0"
		differentRelease.IssuanceID = strings.Repeat("c", 32)
		signTestGcloudReceipt(t, &differentRelease, fixture.privateKey)
		writeTestGcloudIssuance(t, fixture.issuance, differentRelease)
		guard.ownerAuthorization.issuance, err = stableExternalAuthorityFile(
			guard.ownerAuthorization.issuance.configuredPath, guard.ownerAuthorization.authorityOwner,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := guard.verifyUnchanged(); err == nil || !strings.Contains(err.Error(), "does not authorize") {
			t.Fatalf("fresh issuance for another release survived full revalidation: %v", err)
		}
	})
}

type ownerCustodyMutationRunner struct {
	mutate func()
	calls  int
}

func (*ownerCustodyMutationRunner) run(context.Context, []string) (commandResult, error) {
	return commandResult{}, errors.New("pathname execution is forbidden")
}

func (r *ownerCustodyMutationRunner) runFromCustody(context.Context, *os.File, *os.File, *os.File, *os.File, string, []string, []string) (commandResult, error) {
	r.calls++
	r.mutate()
	return commandResult{}, nil
}

func TestRunRevalidatesOwnerAuthorizationAfterCommand(t *testing.T) {
	fixture, guard := newVerifiedGcloudFixtureGuard(t)
	if err := guard.bindIdentity(testGcloudIdentity(t)); err != nil {
		t.Fatal(err)
	}
	receiptData, err := os.ReadFile(fixture.receipt)
	if err != nil {
		t.Fatal(err)
	}
	var rotated gcloudReceipt
	if err := strictDecode(receiptData, &rotated); err != nil {
		t.Fatal(err)
	}
	rotated.IssuanceID = strings.Repeat("d", 32)
	signTestGcloudReceipt(t, &rotated, fixture.privateKey)
	runner := &ownerCustodyMutationRunner{mutate: func() {
		writeTestGcloudIssuance(t, fixture.issuance, rotated)
	}}
	if _, err := guard.run(context.Background(), runner, []string{"version"}); err == nil ||
		!strings.Contains(err.Error(), "issuance custody changed") {
		t.Fatalf("owner issuance rotation during a command was accepted: %v", err)
	}
	if runner.calls != 1 {
		t.Fatalf("custody runner call count = %d, want 1", runner.calls)
	}
}

func TestOwnerAuthorizationRevalidationImmediatelyBracketsCommands(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("custody test source path is unavailable")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "gcloud_custody.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, method := range []struct {
		name, start, end string
	}{
		{
			name:  "production sealed runtime",
			start: "func (g *verifiedGcloud) runFromProductionSealedRuntime",
			end:   "\nfunc (g *verifiedGcloud) run(",
		},
		{
			name:  "private snapshot runtime",
			start: "func (g *verifiedGcloud) run(",
		},
	} {
		start := strings.Index(text, method.start)
		if start < 0 {
			t.Fatalf("%s command method is missing", method.name)
		}
		body := text[start:]
		if method.end != "" {
			end := strings.Index(body, method.end)
			if end < 0 {
				t.Fatalf("%s command method boundary is missing", method.name)
			}
			body = body[:end]
		}
		commandCall := strings.Index(body, "secureRunner.runFromCustody(")
		if commandCall < 0 {
			t.Fatalf("%s descriptor command call is missing", method.name)
		}
		commandBuild := strings.LastIndex(body[:commandCall], "command :=")
		precheck := strings.LastIndex(body[:commandCall], "g.verifyUnchanged()")
		postcheck := strings.Index(body[commandCall:], "g.verifyUnchanged()")
		if commandBuild < 0 || precheck < commandBuild || postcheck < 0 {
			t.Fatalf("%s descriptor command is not immediately bracketed by full custody revalidation", method.name)
		}
	}
}

func TestProductionSealedModesAreExactAndNonrootReadable(t *testing.T) {
	root := t.TempDir()
	dataPath := filepath.Join(root, "data")
	executablePath := filepath.Join(root, "executable")
	t.Cleanup(func() {
		_ = os.Chmod(root, 0700)
		_ = os.Chmod(dataPath, 0600)
		_ = os.Chmod(executablePath, 0700)
	})
	if err := os.WriteFile(dataPath, []byte("data"), 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dataPath, 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executablePath, []byte("exec"), 0555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(executablePath, 0555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0555); err != nil {
		t.Fatal(err)
	}
	for _, pathName := range []string{root, dataPath, executablePath} {
		info, err := os.Lstat(pathName)
		if err != nil || !gcloudSealedRuntimeModeAllowed(info) {
			t.Fatalf("accepted sealed mode was refused for %s: %v", pathName, err)
		}
	}
	for _, hostile := range []struct {
		path string
		mode os.FileMode
	}{
		{dataPath, 0400}, {dataPath, 0644}, {executablePath, 0500}, {executablePath, 0755}, {root, 0500}, {root, 0755},
	} {
		if err := os.Chmod(hostile.path, hostile.mode); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(hostile.path)
		if err != nil {
			t.Fatal(err)
		}
		if gcloudSealedRuntimeModeAllowed(info) {
			t.Fatalf("hostile sealed mode %04o was accepted for %s", hostile.mode, hostile.path)
		}
		if hostile.path == root {
			_ = os.Chmod(root, 0555)
		} else if hostile.path == dataPath {
			_ = os.Chmod(dataPath, 0444)
		} else {
			_ = os.Chmod(executablePath, 0555)
		}
	}
}

func TestProductionReceiptSchemaAndSignatureFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "missing issued_utc", mutate: func(receipt map[string]any) { delete(receipt, "issued_utc") }},
		{name: "missing issuance_id", mutate: func(receipt map[string]any) { delete(receipt, "issuance_id") }},
		{name: "unknown field", mutate: func(receipt map[string]any) { receipt["unknown"] = true }},
		{name: "signature mutation", mutate: func(receipt map[string]any) { receipt["issuance_signature"] = strings.Repeat("0", 128) }},
		{name: "signed field mutation", mutate: func(receipt map[string]any) { receipt["archive_sha256"] = strings.Repeat("e", 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newGcloudCustodyFixture(t)
			mutateGcloudReceipt(t, fixture, tc.mutate)
			if _, err := verifyGcloudCustodyWithPinAndAuthority(
				fixture.executable, fixture.pin, fixture.authority, fixture.issuance, fixture.authorityOwner,
			); err == nil {
				t.Fatal("hostile production receipt mutation was accepted")
			}
		})
	}
}

func TestProductionAuthorityCustodyAndReceiptReplayAreBound(t *testing.T) {
	fixture := newGcloudCustodyFixture(t)
	if _, err := verifyGcloudCustodyWithPin(fixture.executable, fixture.pin); err == nil {
		t.Fatal("production verifier accepted a test-configured same-UID authority")
	}
	if err := os.Chmod(fixture.authority, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyGcloudCustodyWithPinAndAuthority(
		fixture.executable, fixture.pin, fixture.authority, fixture.issuance, fixture.authorityOwner,
	); err == nil {
		t.Fatal("mutable owner authority was accepted")
	}
	if err := os.Chmod(fixture.authority, 0400); err != nil {
		t.Fatal(err)
	}
	replayedRoot := filepath.Join(filepath.Dir(fixture.root), "replayed-google-cloud-sdk")
	if err := os.Rename(fixture.root, replayedRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyGcloudCustodyWithPinAndAuthority(
		filepath.Join(replayedRoot, "bin", "gcloud"), fixture.pin, fixture.authority, fixture.issuance, fixture.authorityOwner,
	); err == nil || !strings.Contains(err.Error(), "install root") {
		t.Fatalf("receipt replay at another root was not refused: %v", err)
	}
}

func TestDurableReceiptRequiresFreshMatchingExternalIssuance(t *testing.T) {
	fixture := newGcloudCustodyFixture(t)
	receiptData, err := os.ReadFile(fixture.receipt)
	if err != nil {
		t.Fatal(err)
	}
	var durable gcloudReceipt
	if err := strictDecode(receiptData, &durable); err != nil {
		t.Fatal(err)
	}
	issued := time.Now().UTC().Truncate(time.Second).Add(-12 * time.Hour)
	durable.IssuedUTC = issued.Format("2006-01-02T15:04:05Z")
	durable.ExpiresUTC = issued.Add(time.Hour).Format("2006-01-02T15:04:05Z")
	durable.IssuanceID = strings.Repeat("e", 32)
	signTestGcloudReceipt(t, &durable, fixture.privateKey)
	writeTestDurableGcloudReceipt(t, fixture.receipt, durable)
	if _, err := verifyGcloudCustodyWithPinAndAuthority(
		fixture.executable, fixture.pin, fixture.authority, fixture.issuance, fixture.authorityOwner,
	); err != nil {
		t.Fatalf("expired durable receipt was not refreshed by the matching external issuance: %v", err)
	}

	staleFresh := durable
	writeTestGcloudIssuance(t, fixture.issuance, staleFresh)
	if _, err := verifyGcloudCustodyWithPinAndAuthority(
		fixture.executable, fixture.pin, fixture.authority, fixture.issuance, fixture.authorityOwner,
	); err == nil || !strings.Contains(err.Error(), "fresh") {
		t.Fatalf("stale external issuance was accepted: %v", err)
	}

	fresh := durable
	now := time.Now().UTC().Truncate(time.Second)
	fresh.IssuedUTC = now.Format("2006-01-02T15:04:05Z")
	fresh.ExpiresUTC = now.Add(time.Hour).Format("2006-01-02T15:04:05Z")
	fresh.IssuanceID = strings.Repeat("f", 32)
	fresh.InstallTreeSHA256 = strings.Repeat("9", 64)
	signTestGcloudReceipt(t, &fresh, fixture.privateKey)
	writeTestGcloudIssuance(t, fixture.issuance, fresh)
	if _, err := verifyGcloudCustodyWithPinAndAuthority(
		fixture.executable, fixture.pin, fixture.authority, fixture.issuance, fixture.authorityOwner,
	); err == nil || !strings.Contains(err.Error(), "does not authorize") {
		t.Fatalf("fresh issuance for a different tree was accepted: %v", err)
	}
}

func TestMissingIdentityIsOwnerBlocker(t *testing.T) {
	fixture := newGcloudCustodyFixture(t)
	guard, err := verifyGcloudCustodyWithPinAndAuthority(fixture.executable, fixture.pin, fixture.authority, fixture.issuance, fixture.authorityOwner)
	if err != nil {
		t.Fatal(err)
	}
	_, err = guard.run(context.Background(), subprocessRunner{}, []string{"version"})
	if err == nil || !strings.Contains(err.Error(), "owner blocker") {
		t.Fatalf("missing identity was not an owner blocker: %v", err)
	}
	assertNoSecret(t, err.Error())
}

func TestSnapshotMatchesExtractedTreeAndCleansUp(t *testing.T) {
	fixture := newGcloudCustodyFixture(t)
	extracted, err := extractOfficialGcloudArchive(fixture.archiveData, fixture.pin.archiveName, filepath.Join(t.TempDir(), "archive"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(t.TempDir(), "runtime")
	if err := snapshotGcloudRuntime(extracted, snapshot); err != nil {
		t.Fatal(err)
	}
	extractedTree, err := gcloudTreeSHA256(extracted)
	if err != nil {
		t.Fatal(err)
	}
	snapshotTree, err := gcloudTreeSHA256(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if extractedTree != snapshotTree {
		t.Fatal("descriptor snapshot tree does not match the extracted archive")
	}
	root, err := os.OpenRoot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	held, err := gcloudTreeSHA256FromRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if held != snapshotTree {
		t.Fatal("descriptor-walked tree hash does not match the snapshot")
	}

	before, err := filepath.Glob(filepath.Join(os.TempDir(), "winsvpn-gcloud-runtime-*"))
	if err != nil {
		t.Fatal(err)
	}
	_, runErr := func() (commandResult, error) {
		guard, err := verifyGcloudCustodyWithPinAndAuthority(fixture.executable, fixture.pin, fixture.authority, fixture.issuance, fixture.authorityOwner)
		if err != nil {
			return commandResult{}, err
		}
		if err := guard.bindIdentity(testGcloudIdentity(t)); err != nil {
			return commandResult{}, err
		}
		return guard.run(context.Background(), subprocessRunner{}, []string{"version"})
	}()
	if runErr != nil && strings.Contains(runErr.Error(), "owner blocker") {
		t.Fatal(runErr)
	}
	after, err := filepath.Glob(filepath.Join(os.TempDir(), "winsvpn-gcloud-runtime-*"))
	if err != nil {
		t.Fatal(err)
	}
	beforePaths := make(map[string]struct{}, len(before))
	for _, pathName := range before {
		beforePaths[pathName] = struct{}{}
	}
	for _, pathName := range after {
		if _, existed := beforePaths[pathName]; !existed {
			t.Fatalf("runtime scratch leaked: %s", pathName)
		}
	}
}

func TestNestedReceiptNameIsNeverHashBlind(t *testing.T) {
	fixture := newGcloudCustodyFixture(t)
	nestedDirectory := filepath.Join(fixture.root, "nested")
	if err := os.Mkdir(nestedDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nestedDirectory, gcloudReceiptName), []byte("hostile\n"), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := gcloudTreeSHA256(fixture.root); err == nil {
		t.Fatalf("path tree hash accepted a nested receipt name: %v", err)
	}
	root, err := os.OpenRoot(fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := gcloudTreeSHA256FromRoot(root); err == nil {
		t.Fatalf("descriptor tree hash accepted a nested receipt name: %v", err)
	}
}

func TestGzipFramingStillRejectsConcatenatedBombs(t *testing.T) {
	var raw bytes.Buffer
	encoder := gzip.NewWriter(&raw)
	if _, err := encoder.Write([]byte("not-a-tar")); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := extractOfficialGcloudArchive(raw.Bytes(), "google-cloud-cli.tar.gz", filepath.Join(t.TempDir(), "bad")); err == nil {
		t.Fatal("invalid gzip/tar payload was accepted")
	}
}

type childPathnameSwapRunner struct {
	maliciousExecutions int
}

func (*childPathnameSwapRunner) run(context.Context, []string) (commandResult, error) {
	return commandResult{}, errors.New("pathname execution is forbidden")
}

func (*childPathnameSwapRunner) runFromDescriptor(context.Context, *os.File, []string, []string) (commandResult, error) {
	return commandResult{}, errors.New("execution used a directory child pathname instead of the held executable descriptor")
}

func (r *childPathnameSwapRunner) runFromCustody(ctx context.Context, executable, root, credential, subjectToken *os.File, workingDirectory string, argv []string, env []string) (commandResult, error) {
	visibleRoot := filepath.Clean(workingDirectory)
	binDir := filepath.Join(visibleRoot, "bin")
	visible := filepath.Join(binDir, "gcloud")
	backup := visible + ".reviewed"
	_ = os.Chmod(visibleRoot, 0700)
	_ = os.Chmod(binDir, 0700)
	if err := os.Rename(visible, backup); err != nil {
		return commandResult{}, err
	}
	if err := os.WriteFile(visible, []byte("#!/bin/sh\nprintf 'MALICIOUS\\n'\n"), 0700); err != nil {
		_ = os.Rename(backup, visible)
		return commandResult{}, err
	}
	result, runErr := (subprocessRunner{}).runFromCustody(ctx, executable, root, credential, subjectToken, workingDirectory, argv, env)
	r.maliciousExecutions += bytes.Count(result.stdout, []byte("MALICIOUS"))
	_ = os.Remove(visible)
	restoreErr := os.Rename(backup, visible)
	if runErr != nil {
		return commandResult{}, runErr
	}
	if restoreErr != nil {
		return commandResult{}, restoreErr
	}
	return result, nil
}

func TestHeldExecutableIgnoresSameUIDChildPathnameSwap(t *testing.T) {
	fixture := newGcloudCustodyFixture(t)
	guard, err := verifyGcloudCustodyWithPinAndAuthority(fixture.executable, fixture.pin, fixture.authority, fixture.issuance, fixture.authorityOwner)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.bindIdentity(testGcloudIdentity(t)); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "linux" {
		_, err := guard.run(context.Background(), subprocessRunner{}, []string{"probe"})
		if err == nil || !strings.Contains(err.Error(), "Linux") {
			t.Fatalf("non-linux descriptor execution was not fail-closed: %v", err)
		}
		return
	}
	runner := &childPathnameSwapRunner{}
	for attempt := 0; attempt < 25; attempt++ {
		result, err := guard.run(context.Background(), runner, []string{"probe"})
		if err != nil {
			t.Fatal(err)
		}
		if string(result.stdout) != "REVIEWED\n" || result.exitCode != 0 {
			t.Fatalf("held executable did not run reviewed bytes after pathname swap: %#v", result)
		}
		if bytes.Contains(result.stdout, []byte("MALICIOUS")) {
			t.Fatal("same-UID child pathname swap was executed")
		}
	}
	if runner.maliciousExecutions != 0 {
		t.Fatalf("substituted child pathname executed %d times", runner.maliciousExecutions)
	}
}

func TestCleanupOverwriteUsesHeldDescriptorAfterPathnameSwap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential.json")
	secret := bytes.Repeat([]byte{'S'}, 32)
	if err := os.WriteFile(path, secret, 0600); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim.json")
	sentinel := bytes.Repeat([]byte{'V'}, 32)
	if err := os.WriteFile(victim, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "victim-alias.json")
	if err := os.Link(victim, alias); err != nil {
		t.Fatal(err)
	}
	held, err := openNoFollow(path, syscall.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	hidden := path + ".original"
	if err := os.Rename(path, hidden); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(victim, path); err != nil {
		t.Fatal(err)
	}
	overwriteHeld(held, int64(len(secret)))
	_ = os.Remove(path)
	original, err := os.ReadFile(hidden)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(original, []byte{'S'}) {
		t.Fatal("held original inode was not overwritten")
	}
	live, err := os.ReadFile(alias)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(live, sentinel) {
		t.Fatalf("swapped victim pathname was overwritten: %q", live)
	}
}

func TestGcloudCustodySourceBindsHeldExecutableNotChildPathname(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("custody source path is unavailable")
	}
	src, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "gcloud_custody.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if regexp.MustCompile(`/proc/self/fd/[^"\s]*/bin/gcloud`).MatchString(text) {
		t.Fatal("execution still uses a mutable /proc/self/fd/N/bin/gcloud child pathname")
	}
	if strings.Contains(text, "os.Lstat(path)") && strings.Contains(text, "os.OpenFile(path, os.O_WRONLY") {
		t.Fatal("cleanup still reopens a previously inspected pathname before overwrite")
	}
}

func TestHeldExecutionChdirDoesNotDependOnChildFDShuffle(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("custody source path is unavailable")
	}
	src, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "gcloud_custody.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if strings.Contains(text, "cmd.Dir = procSelfFd(4)") {
		t.Fatal("Cmd.Dir still resolves the future child root fd before ExtraFiles renumbering")
	}
	for _, required := range []string{
		"func heldRootWorkingDirectory",
		"!os.SameFile(rootInfo, visibleWorkingDirectory)",
		"cmd.Dir = workingDirectory",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("held execution working-directory binding is missing %q", required)
		}
	}
}

func TestProductionRuntimeRootIsExactAndTreeBound(t *testing.T) {
	tree := strings.Repeat("a", 64)
	expected := filepath.Join(gcloudProductionRuntimeRoot, tree)
	if err := validateProductionGcloudRoot(expected, tree); err != nil {
		t.Fatalf("exact production runtime root was refused: %v", err)
	}
	for _, hostile := range []string{
		gcloudProductionRuntimeRoot,
		expected + string(filepath.Separator),
		filepath.Join(gcloudProductionRuntimeRoot, strings.Repeat("b", 64)),
		filepath.Join(os.TempDir(), tree),
		"var/lib/winsvpn/gcloud-runtime-v1/" + tree,
	} {
		if err := validateProductionGcloudRoot(hostile, tree); err == nil {
			t.Fatalf("unsafe production runtime root was accepted: %q", hostile)
		}
	}
	for _, hostileTree := range []string{"", strings.Repeat("0", 64), strings.Repeat("A", 64), "../" + tree} {
		if _, err := expectedProductionGcloudRoot(hostileTree); err == nil {
			t.Fatalf("unsafe production tree identity was accepted: %q", hostileTree)
		}
	}
}

func TestLinuxEffectiveCapabilityParserFailsClosed(t *testing.T) {
	capImmutable := uint64(1) << linuxCapImmutable
	parsed, err := parseLinuxCapEff([]byte("Name:\twinsproof\nCapEff:\t0000000000000200\n"))
	if err != nil || parsed != capImmutable {
		t.Fatalf("CAP_LINUX_IMMUTABLE was not parsed exactly: value=%x err=%v", parsed, err)
	}
	for _, hostile := range [][]byte{
		nil,
		[]byte("Name:\twinsproof\n"),
		[]byte("CapEff:\t0\nCapEff:\t0\n"),
		[]byte("CapEff:\tnot-hex\n"),
		[]byte("CapEff:\t00000000000000000\n"),
		[]byte("CapEff:\t0\x00\n"),
	} {
		if _, err := parseLinuxCapEff(hostile); err == nil {
			t.Fatalf("hostile Linux capability status was accepted: %q", hostile)
		}
	}
}

func TestSealedRuntimeEnvironmentUsesOnlyHeldDescriptors(t *testing.T) {
	env, err := isolatedGcloudSealedEnv("/tmp/home", "/tmp/config", "/tmp/state", testProject)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	for _, required := range []string{
		"CLOUDSDK_ROOT_DIR=/proc/self/fd/4",
		"CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=/proc/self/fd/5",
		"CLOUDSDK_PYTHON=/proc/self/fd/4/" + gcloudBundledPythonRelative,
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("sealed runtime environment is missing %q", required)
		}
	}
	if strings.Contains(joined, "bound_credential.json") || strings.Contains(joined, gcloudProductionRuntimeRoot) {
		t.Fatal("sealed runtime environment exposes a mutable credential or root pathname")
	}
}

func TestProductionRunNeverBuildsAMutableSDKSnapshot(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("custody source path is unavailable")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "gcloud_custody.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	start := strings.Index(text, "func (g *verifiedGcloud) runFromProductionSealedRuntime")
	end := strings.Index(text[start:], "\nfunc (g *verifiedGcloud) run(")
	if start < 0 || end < 0 {
		t.Fatal("production sealed runtime boundary is missing")
	}
	body := text[start : start+end]
	for _, forbidden := range []string{"extractOfficialGcloudArchive", "snapshotGcloudRuntime", "freezePrivateRuntime", "os.RemoveAll(g.root)"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("production sealed runtime still uses mutable runtime operation %q", forbidden)
		}
	}
	for _, required := range []string{"verifyProductionSealedRuntime", "gcloudTreeSHA256FromRoot", "runFromCustody", "stableOpenFile"} {
		if !strings.Contains(body, required) {
			t.Fatalf("production sealed runtime is missing %q", required)
		}
	}
}
