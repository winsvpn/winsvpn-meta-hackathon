package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func provisionerSource(t *testing.T) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	src, err := os.ReadFile(filepath.Join(filepath.Dir(file), "gcloud_runtime_provisioner.go"))
	if err != nil {
		t.Fatal(err)
	}
	return src
}

type tarMember struct {
	name, body, link string
	typeflag         byte
	mode             int64
}

func packedTarGz(t *testing.T, members []tarMember) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, member := range members {
		header := &tar.Header{
			Name:     member.name,
			Linkname: member.link,
			Mode:     member.mode,
			Typeflag: member.typeflag,
			Size:     int64(len(member.body)),
		}
		if member.typeflag == tar.TypeDir || member.typeflag == tar.TypeSymlink || member.typeflag == tar.TypeLink ||
			member.typeflag == tar.TypeFifo || member.typeflag == tar.TypeChar {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := tarWriter.Write([]byte(member.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func reviewedSDKMembers() []tarMember {
	return []tarMember{
		{name: "google-cloud-sdk/", typeflag: tar.TypeDir, mode: 0755},
		{name: "google-cloud-sdk/bin/", typeflag: tar.TypeDir, mode: 0755},
		{
			name: "google-cloud-sdk/bin/gcloud", typeflag: tar.TypeReg, mode: 0755,
			body: "#!/bin/sh\nprintf 'REVIEWED\\n'\n",
		},
		{name: "google-cloud-sdk/component.txt", typeflag: tar.TypeReg, mode: 0644, body: "reviewed\n"},
	}
}

func writeFileMode(t *testing.T, pathName string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(pathName, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pathName, mode); err != nil {
		t.Fatal(err)
	}
}

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x11}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signReceipt(t *testing.T, auth receiptAuth, key ed25519.PrivateKey) string {
	t.Helper()
	message, err := receiptSignatureMessage(auth)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(ed25519.Sign(key, message))
}

func writeAuthority(t *testing.T, pathName string, pub ed25519.PublicKey, owner uint32) {
	t.Helper()
	doc := ownerAuthorityDoc{
		Contract: ownerAuthority, SchemaVersion: 1, Algorithm: ownerAlgorithm,
		KeyID: sha256Hex(pub), PublicKey: hex.EncodeToString(pub), OwnerUID: owner,
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(pathName); err == nil {
		if err := os.Chmod(pathName, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeFileMode(t, pathName, encoded, 0400)
}

func writeIssuance(t *testing.T, pathName string, auth receiptAuth, signature string) {
	t.Helper()
	issuance := map[string]any{
		"contract": ownerIssuance, "schema_version": 1, "issuer": ownerIssuer,
		"algorithm": ownerAlgorithm, "key_id": auth.AuthorityKeyID,
		"receipt": receiptAuthMap(auth), "signature": signature,
	}
	encoded, err := json.Marshal(issuance)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(pathName); err == nil {
		if err := os.Chmod(pathName, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeFileMode(t, pathName, encoded, 0400)
}

func freshAuth(t *testing.T, pin reviewedPin, tree, rootSHA, keyID string) receiptAuth {
	t.Helper()
	issued := time.Now().UTC().Truncate(time.Second)
	return receiptAuth{
		SchemaVersion: 1, Contract: receiptContract,
		Version: pin.version, Platform: pin.platform,
		ArchiveName: pin.archiveName, ArchiveSHA256: pin.archiveSHA256,
		InstallTreeSHA256: tree, ExecutablePath: executableRel,
		InstallRootSHA256: rootSHA,
		IssuedUTC:         issued.Format("2006-01-02T15:04:05Z"),
		ExpiresUTC:        issued.Add(time.Hour).Format("2006-01-02T15:04:05Z"),
		IssuanceID:        strings.Repeat("a", 32), AuthorityKeyID: keyID,
		ControllerSHA256: strings.Repeat("b", 64), ManifestSHA256: strings.Repeat("c", 64),
		TrustAnchorSHA256: strings.Repeat("d", 64),
	}
}

func stubHelper(t *testing.T, dir string) (string, string) {
	t.Helper()
	pathName := filepath.Join(dir, "winsvpn-gcloud-immutable-helper")
	body := []byte("#!/bin/sh\nexit 0\n")
	writeFileMode(t, pathName, body, 0555)
	return pathName, sha256Hex(body)
}

func testConfig(t *testing.T) (provisionConfig, string) {
	t.Helper()
	base := t.TempDir()
	runtimePrefix := filepath.Join(base, "gcloud-runtime-v1")
	if err := os.Mkdir(runtimePrefix, 0700); err != nil {
		t.Fatal(err)
	}
	helper, helperSHA := stubHelper(t, base)
	pin := compiledReviewedPin()
	t.Cleanup(func() {
		_ = filepath.Walk(base, func(pathName string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil
			}
			if info.IsDir() {
				_ = os.Chmod(pathName, 0700)
			} else if info.Mode()&os.ModeSymlink == 0 {
				_ = os.Chmod(pathName, 0600)
			}
			return nil
		})
	})
	return provisionConfig{
		Pin:           pin,
		AuthorityPath: filepath.Join(base, "authority.json"),
		IssuancePath:  filepath.Join(base, "issuance.json"),
		StagingParent: base,
		RuntimePrefix: runtimePrefix,
		HelperPath:    helper,
		HelperSHA256:  helperSHA,
		ExpectedUID:   uint32(os.Getuid()),
		ExpectedGID:   uint32(os.Getgid()),
	}, base
}

func preparedArchive(t *testing.T, cfg *provisionConfig, base string, members []tarMember) (string, receiptAuth, string, ed25519.PrivateKey) {
	t.Helper()
	archiveData := packedTarGz(t, members)
	cfg.Pin.archiveSHA256 = sha256Hex(archiveData)
	archivePath := filepath.Join(base, cfg.Pin.archiveName)
	writeFileMode(t, archivePath, archiveData, 0600)
	calc := filepath.Join(t.TempDir(), "calc")
	sdk, err := extractOfficialArchive(archiveData, cfg.Pin.archiveName, calc)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(filepath.Join(sdk, custodyArchiveName), archiveData, 0444); err != nil {
		t.Fatal(err)
	}
	tree, err := installTreeSHA256(sdk)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(cfg.RuntimePrefix, tree)
	rootSHA := sha256Hex([]byte(dest))
	pub, priv := testKeys(t)
	auth := freshAuth(t, cfg.Pin, tree, rootSHA, sha256Hex(pub))
	signature := signReceipt(t, auth, priv)
	writeAuthority(t, cfg.AuthorityPath, pub, cfg.ExpectedUID)
	writeIssuance(t, cfg.IssuancePath, auth, signature)
	return archivePath, auth, signature, priv
}

func TestRunRejectsUsageAndUnsafePathBeforeRoot(t *testing.T) {
	if err := run(nil); !errors.Is(err, errUsage) {
		t.Fatalf("nil args: %v", err)
	}
	if err := run([]string{"a", "b"}); !errors.Is(err, errUsage) {
		t.Fatalf("extra args: %v", err)
	}
	if err := run([]string{"google-cloud-cli-582.0.0-linux-x86_64.tar.gz"}); !errors.Is(err, errUnsafePath) {
		t.Fatalf("relative: %v", err)
	}
	if err := run([]string{"/tmp/wrong-name.tar.gz"}); !errors.Is(err, errArchiveName) {
		t.Fatalf("name: %v", err)
	}
}

func TestRunRequiresEuidZero(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("euid 0; non-root refusal is not observable")
	}
	err := run([]string{"/tmp/google-cloud-cli-582.0.0-linux-x86_64.tar.gz"})
	if !errors.Is(err, errNeedRoot) {
		t.Fatalf("got %v", err)
	}
}

func TestProvisionRequiresEffectiveCustodyIdentity(t *testing.T) {
	cfg, _ := testConfig(t)
	archivePath := filepath.Join(t.TempDir(), cfg.Pin.archiveName)
	for _, mutate := range []func(*provisionConfig){
		func(value *provisionConfig) { value.ExpectedUID ^= 1 },
		func(value *provisionConfig) { value.ExpectedGID ^= 1 },
	} {
		wrong := cfg
		mutate(&wrong)
		if err := provision(archivePath, wrong); !errors.Is(err, errOwner) {
			t.Fatalf("wrong effective custody identity: %v", err)
		}
	}
}

func TestRequiresLinux(t *testing.T) {
	err := requireLinux()
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if !errors.Is(err, errLinuxOnly) {
		t.Fatalf("got %v", err)
	}
}

func TestDuplicateJSONKeysRejected(t *testing.T) {
	err := rejectDuplicateKeys([]byte(`{"contract":"a","contract":"b"}`))
	if !errors.Is(err, errDuplicateJSON) {
		t.Fatalf("got %v", err)
	}
	nested := []byte(`{"contract":"x","receipt":{"version":"1","version":"2"}}`)
	if err := rejectDuplicateKeys(nested); !errors.Is(err, errDuplicateJSON) {
		t.Fatalf("nested: %v", err)
	}
}

func TestWrongKeyAndSignatureRejected(t *testing.T) {
	cfg, _ := testConfig(t)
	pub, priv := testKeys(t)
	auth := freshAuth(t, cfg.Pin, strings.Repeat("1", 64), strings.Repeat("2", 64), sha256Hex(pub))
	signature := signReceipt(t, auth, priv)
	writeAuthority(t, cfg.AuthorityPath, pub, cfg.ExpectedUID)
	writeIssuance(t, cfg.IssuancePath, auth, strings.Repeat("f", 128))
	if _, _, err := loadVerifiedIssuance(cfg); !errors.Is(err, errTrust) {
		t.Fatalf("wrong signature: %v", err)
	}
	writeIssuance(t, cfg.IssuancePath, auth, signature)
	otherPub, _, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x33}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	writeAuthority(t, cfg.AuthorityPath, otherPub, cfg.ExpectedUID)
	if _, _, err := loadVerifiedIssuance(cfg); !errors.Is(err, errTrust) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestStaleIssuanceRejected(t *testing.T) {
	cfg, _ := testConfig(t)
	pub, priv := testKeys(t)
	auth := freshAuth(t, cfg.Pin, strings.Repeat("1", 64), strings.Repeat("2", 64), sha256Hex(pub))
	auth.IssuedUTC = "2025-12-31T23:00:00Z"
	auth.ExpiresUTC = "2026-01-01T00:00:00Z"
	writeAuthority(t, cfg.AuthorityPath, pub, cfg.ExpectedUID)
	writeIssuance(t, cfg.IssuancePath, auth, signReceipt(t, auth, priv))
	if _, _, err := loadVerifiedIssuance(cfg); !errors.Is(err, errStale) {
		t.Fatalf("year 2025: %v", err)
	}
	auth = freshAuth(t, cfg.Pin, strings.Repeat("1", 64), strings.Repeat("2", 64), sha256Hex(pub))
	auth.IssuedUTC = "2026-01-01T00:00:00Z"
	auth.ExpiresUTC = "2026-01-01T00:30:00Z"
	writeIssuance(t, cfg.IssuancePath, auth, signReceipt(t, auth, priv))
	if _, _, err := loadVerifiedIssuance(cfg); !errors.Is(err, errStale) {
		t.Fatalf("expired: %v", err)
	}
}

func TestExactSchemaRejectedOnMissingKey(t *testing.T) {
	cfg, _ := testConfig(t)
	writeFileMode(t, cfg.AuthorityPath, []byte(`{"contract":"winsvpn-gcloud-owner-authority-v1"}`), 0400)
	if _, _, err := loadVerifiedIssuance(cfg); !errors.Is(err, errSchema) && !errors.Is(err, errTrust) {
		t.Fatalf("got %v", err)
	}
}

func TestHappyPathProvisionsWithoutClaimingImmutable(t *testing.T) {
	cfg, base := testConfig(t)
	cfg.InvokeHelper = true
	archivePath, auth, _, _ := preparedArchive(t, &cfg, base, reviewedSDKMembers())
	if err := provision(archivePath, cfg); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(cfg.RuntimePrefix, auth.InstallTreeSHA256)
	tree, err := installTreeSHA256(dest)
	if err != nil {
		t.Fatal(err)
	}
	if tree != auth.InstallTreeSHA256 {
		t.Fatalf("tree %s != %s", tree, auth.InstallTreeSHA256)
	}
	receipt, err := os.ReadFile(filepath.Join(dest, receiptName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(receipt, []byte{'\n'}) {
		t.Fatal("durable receipt must end with newline")
	}
	info, err := os.Lstat(filepath.Join(dest, custodyArchiveName))
	if err != nil || info.Mode().Perm() != 0444 {
		t.Fatalf("archive mode %v", info)
	}
	receiptInfo, err := os.Lstat(filepath.Join(dest, receiptName))
	if err != nil || receiptInfo.Mode().Perm() != 0444 {
		t.Fatalf("receipt mode %v", receiptInfo)
	}
	rootInfo, err := os.Lstat(dest)
	if err != nil || rootInfo.Mode().Perm() != 0555 {
		t.Fatalf("root mode %v", rootInfo)
	}
	executableInfo, err := os.Lstat(filepath.Join(dest, "bin", "gcloud"))
	if err != nil || executableInfo.Mode().Perm() != 0555 {
		t.Fatalf("executable mode %v", executableInfo)
	}
	dataInfo, err := os.Lstat(filepath.Join(dest, "component.txt"))
	if err != nil || dataInfo.Mode().Perm() != 0444 {
		t.Fatalf("data mode %v", dataInfo)
	}
	stage := filepath.Join(cfg.StagingParent, stagingDirPrefix+auth.InstallTreeSHA256)
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("successful provision left staging path: %v", err)
	}
	if cfg.RequireImmutable {
		t.Fatal("macOS tests must not require Linux immutable success")
	}
	if err := provision(archivePath, cfg); err != nil {
		t.Fatalf("idempotent revalidate: %v", err)
	}
}

func TestArchiveHashTreeAndRootDriftRejected(t *testing.T) {
	t.Run("archive", func(t *testing.T) {
		cfg, base := testConfig(t)
		archivePath, _, _, _ := preparedArchive(t, &cfg, base, reviewedSDKMembers())
		cfg.Pin.archiveSHA256 = strings.Repeat("e", 64)
		if err := provision(archivePath, cfg); err == nil {
			t.Fatal("archive hash drift accepted")
		}
	})
	t.Run("tree", func(t *testing.T) {
		cfg, base := testConfig(t)
		archivePath, auth, _, priv := preparedArchive(t, &cfg, base, reviewedSDKMembers())
		auth.InstallTreeSHA256 = strings.Repeat("f", 64)
		auth.InstallRootSHA256 = sha256Hex([]byte(filepath.Join(cfg.RuntimePrefix, auth.InstallTreeSHA256)))
		writeIssuance(t, cfg.IssuancePath, auth, signReceipt(t, auth, priv))
		if err := provision(archivePath, cfg); !errors.Is(err, errTree) {
			t.Fatalf("tree drift: %v", err)
		}
		stage := filepath.Join(cfg.StagingParent, stagingDirPrefix+auth.InstallTreeSHA256)
		if _, err := os.Lstat(stage); !os.IsNotExist(err) {
			t.Fatalf("failed candidate left stale staging: %v", err)
		}
	})
	t.Run("root", func(t *testing.T) {
		cfg, base := testConfig(t)
		archivePath, auth, _, priv := preparedArchive(t, &cfg, base, reviewedSDKMembers())
		auth.InstallRootSHA256 = strings.Repeat("a", 64)
		writeIssuance(t, cfg.IssuancePath, auth, signReceipt(t, auth, priv))
		if err := provision(archivePath, cfg); !errors.Is(err, errRootHash) {
			t.Fatalf("root drift: %v", err)
		}
	})
}

func TestTraversalRejected(t *testing.T) {
	for _, name := range []string{
		"../google-cloud-sdk/bin/gcloud",
		"/tmp/google-cloud-sdk/bin/gcloud",
		"google-cloud-sdk/../../etc/passwd",
		"google-cloud-sdk/./bin/gcloud",
		"C:google-cloud-sdk/bin/gcloud",
	} {
		archive := packedTarGz(t, []tarMember{
			{name: name, typeflag: tar.TypeReg, mode: 0644, body: "x"},
		})
		if _, err := extractOfficialArchive(archive, "x.tar.gz", filepath.Join(t.TempDir(), "x")); !errors.Is(err, errTraversal) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestHardlinkRejected(t *testing.T) {
	archive := packedTarGz(t, []tarMember{
		{name: "google-cloud-sdk/a", typeflag: tar.TypeReg, mode: 0644, body: "x"},
		{name: "google-cloud-sdk/b", typeflag: tar.TypeLink, link: "google-cloud-sdk/a", mode: 0644},
	})
	if _, err := extractOfficialArchive(archive, "x.tar.gz", filepath.Join(t.TempDir(), "hl")); !errors.Is(err, errSpecial) {
		t.Fatalf("archive hardlink: %v", err)
	}
	cfg, base := testConfig(t)
	archivePath, _, _, _ := preparedArchive(t, &cfg, base, reviewedSDKMembers())
	linked := archivePath + ".link"
	if err := os.Link(archivePath, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := bindOfficialArchive(archivePath, cfg.Pin.archiveSHA256, cfg.ExpectedUID, cfg.ExpectedGID); !errors.Is(err, errHardlink) {
		t.Fatalf("nlink archive: %v", err)
	}
}

func TestUnsafeSymlinkRejectedAndSafeRelativeAccepted(t *testing.T) {
	unsafe := packedTarGz(t, append(reviewedSDKMembers(), tarMember{
		name: "google-cloud-sdk/escape", typeflag: tar.TypeSymlink, link: "../../etc/passwd", mode: 0777,
	}))
	if _, err := extractOfficialArchive(unsafe, "x.tar.gz", filepath.Join(t.TempDir(), "bad")); !errors.Is(err, errSymlink) {
		t.Fatalf("unsafe: %v", err)
	}
	abs := packedTarGz(t, append(reviewedSDKMembers(), tarMember{
		name: "google-cloud-sdk/abs", typeflag: tar.TypeSymlink, link: "/tmp/x", mode: 0777,
	}))
	if _, err := extractOfficialArchive(abs, "x.tar.gz", filepath.Join(t.TempDir(), "abs")); !errors.Is(err, errSymlink) {
		t.Fatalf("absolute: %v", err)
	}
	safe := packedTarGz(t, append(reviewedSDKMembers(), tarMember{
		name: "google-cloud-sdk/link", typeflag: tar.TypeSymlink, link: "component.txt", mode: 0777,
	}))
	sdk, err := extractOfficialArchive(safe, "x.tar.gz", filepath.Join(t.TempDir(), "ok"))
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(filepath.Join(sdk, "link"))
	if err != nil || target != "component.txt" {
		t.Fatalf("safe symlink %q %v", target, err)
	}
}

func TestDuplicateMembersRejected(t *testing.T) {
	archive := packedTarGz(t, []tarMember{
		{name: "google-cloud-sdk/a.txt", typeflag: tar.TypeReg, mode: 0644, body: "1"},
		{name: "google-cloud-sdk/a.txt", typeflag: tar.TypeReg, mode: 0644, body: "2"},
	})
	if _, err := extractOfficialArchive(archive, "x.tar.gz", filepath.Join(t.TempDir(), "dup")); !errors.Is(err, errDuplicateMember) {
		t.Fatalf("got %v", err)
	}
}

func TestExpandedLimitsRejected(t *testing.T) {
	t.Run("outer", func(t *testing.T) {
		old := maxArchiveOuter
		maxArchiveOuter = 8
		t.Cleanup(func() { maxArchiveOuter = old })
		archive := packedTarGz(t, reviewedSDKMembers())
		if _, err := extractOfficialArchive(archive, "x.tar.gz", filepath.Join(t.TempDir(), "outer")); !errors.Is(err, errTooLarge) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("count", func(t *testing.T) {
		old := maxArchiveEntries
		maxArchiveEntries = 2
		t.Cleanup(func() { maxArchiveEntries = old })
		archive := packedTarGz(t, reviewedSDKMembers())
		if _, err := extractOfficialArchive(archive, "x.tar.gz", filepath.Join(t.TempDir(), "count")); !errors.Is(err, errTooLarge) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("member", func(t *testing.T) {
		old := maxArchiveMember
		maxArchiveMember = 4
		t.Cleanup(func() { maxArchiveMember = old })
		archive := packedTarGz(t, []tarMember{
			{name: "google-cloud-sdk/big.bin", typeflag: tar.TypeReg, mode: 0644, body: "abcdefghij"},
		})
		if _, err := extractOfficialArchive(archive, "x.tar.gz", filepath.Join(t.TempDir(), "member")); !errors.Is(err, errTooLarge) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("aggregate", func(t *testing.T) {
		old := maxArchiveBytes
		maxArchiveBytes = 6
		t.Cleanup(func() { maxArchiveBytes = old })
		archive := packedTarGz(t, []tarMember{
			{name: "google-cloud-sdk/one.bin", typeflag: tar.TypeReg, mode: 0644, body: "abcd"},
			{name: "google-cloud-sdk/two.bin", typeflag: tar.TypeReg, mode: 0644, body: "efgh"},
		})
		if _, err := extractOfficialArchive(archive, "x.tar.gz", filepath.Join(t.TempDir(), "agg")); !errors.Is(err, errTooLarge) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("depth", func(t *testing.T) {
		old := maxArchiveDepth
		maxArchiveDepth = 2
		t.Cleanup(func() { maxArchiveDepth = old })
		archive := packedTarGz(t, []tarMember{
			{name: "google-cloud-sdk/a/b/c.txt", typeflag: tar.TypeReg, mode: 0644, body: "x"},
		})
		if _, err := extractOfficialArchive(archive, "x.tar.gz", filepath.Join(t.TempDir(), "depth")); !errors.Is(err, errTooLarge) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestNativeSizeLimitsAndInstallTreeBoundary(t *testing.T) {
	if maxArchiveOuter != int64(512*1024*1024) || maxArchiveMember != int64(512*1024*1024) ||
		maxArchiveBytes != int64(3*1024*1024*1024) {
		t.Fatalf("limit drift: outer=%d member=%d expanded/tree=%d", maxArchiveOuter, maxArchiveMember, maxArchiveBytes)
	}
	old := maxArchiveBytes
	maxArchiveBytes = 6
	t.Cleanup(func() { maxArchiveBytes = old })
	root := t.TempDir()
	writeFileMode(t, filepath.Join(root, "a"), []byte("abc"), 0600)
	writeFileMode(t, filepath.Join(root, "b"), []byte("def"), 0600)
	if _, err := installTreeSHA256(root); err != nil {
		t.Fatalf("exact tree boundary rejected: %v", err)
	}
	writeFileMode(t, filepath.Join(root, custodyArchiveName), []byte("x"), 0600)
	if _, err := installTreeSHA256(root); !errors.Is(err, errTooLarge) {
		t.Fatalf("retained archive over tree boundary: %v", err)
	}
	exact := &countingReader{r: bytes.NewReader(nil), n: maxArchiveBytes, compressed: 1}
	if n, err := exact.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("exact expanded boundary did not reach EOF: n=%d err=%v", n, err)
	}
	over := &countingReader{r: bytes.NewReader([]byte{'x'}), n: maxArchiveBytes, compressed: 1}
	if n, err := over.Read(make([]byte, 1)); n != 0 || !errors.Is(err, errTooLarge) {
		t.Fatalf("expanded boundary overflow accepted: n=%d err=%v", n, err)
	}
}

func TestExactUnixModesRejectPrivilegeBits(t *testing.T) {
	for _, expected := range []os.FileMode{sealedDataMode, sealedExecutableMode, sealedDirectoryMode, stageLockMode} {
		if !exactUnixMode(expected, expected) {
			t.Fatalf("exact mode %v rejected", expected)
		}
		for _, special := range []os.FileMode{os.ModeSetuid, os.ModeSetgid, os.ModeSticky} {
			if exactUnixMode(expected|special, expected) {
				t.Fatalf("mode %v accepted special bit %v", expected, special)
			}
		}
	}
}

func TestNestedReceiptRejected(t *testing.T) {
	archive := packedTarGz(t, append(reviewedSDKMembers(), tarMember{
		name: "google-cloud-sdk/sub/" + receiptName, typeflag: tar.TypeReg, mode: 0644, body: "{}",
	}))
	if _, err := extractOfficialArchive(archive, "x.tar.gz", filepath.Join(t.TempDir(), "nested")); !errors.Is(err, errNestedReceipt) {
		t.Fatalf("got %v", err)
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	writeFileMode(t, filepath.Join(dir, "a.txt"), []byte("x"), 0600)
	writeFileMode(t, filepath.Join(dir, "sub", receiptName), []byte("{}"), 0400)
	if _, err := installTreeSHA256(dir); !errors.Is(err, errNestedReceipt) {
		t.Fatalf("hash nested: %v", err)
	}
}

func TestExistingDestinationSubstitutionRejected(t *testing.T) {
	cfg, base := testConfig(t)
	archivePath, auth, _, _ := preparedArchive(t, &cfg, base, reviewedSDKMembers())
	if err := provision(archivePath, cfg); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(cfg.RuntimePrefix, auth.InstallTreeSHA256)
	victim := filepath.Join(dest, "component.txt")
	if err := os.Chmod(dest, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("substituted\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dest, 0555); err != nil {
		t.Fatal(err)
	}
	if err := provision(archivePath, cfg); !errors.Is(err, errIdempotentFail) {
		t.Fatalf("got %v", err)
	}
	got, err := os.ReadFile(victim)
	if err != nil || string(got) != "substituted\n" {
		t.Fatalf("destination was overwritten: %q %v", got, err)
	}
}

func TestExistingDestinationFastPathRejectsWrongGIDAndSpecialMode(t *testing.T) {
	cfg, base := testConfig(t)
	archivePath, auth, signature, _ := preparedArchive(t, &cfg, base, reviewedSDKMembers())
	if err := provision(archivePath, cfg); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(cfg.RuntimePrefix, auth.InstallTreeSHA256)
	wrongGID := cfg
	wrongGID.ExpectedGID ^= 1
	if err := revalidateRoot(dest, auth, signature, wrongGID, true); !errors.Is(err, errOwner) {
		t.Fatalf("wrong root gid reached immutable fast path: %v", err)
	}
	if err := os.Chmod(dest, sealedDirectoryMode|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dest)
	if err != nil || !hasSpecialModeBits(info.Mode()) {
		t.Fatalf("hostile sticky mode was not installed: %v %v", info, err)
	}
	if err := revalidateRoot(dest, auth, signature, cfg, true); !errors.Is(err, errMode) {
		t.Fatalf("special root mode reached immutable fast path: %v", err)
	}
}

func TestAuthorityAndHelperRequireExactGID(t *testing.T) {
	cfg, base := testConfig(t)
	_, _, _, _ = preparedArchive(t, &cfg, base, reviewedSDKMembers())
	wrongGID := cfg
	wrongGID.ExpectedGID ^= 1
	if _, _, err := loadVerifiedIssuance(wrongGID); !errors.Is(err, errTrust) {
		t.Fatalf("authority wrong gid: %v", err)
	}
	if err := verifyHelper(wrongGID); !errors.Is(err, errHelper) {
		t.Fatalf("helper wrong gid: %v", err)
	}
}

func TestHelperHashAndPathSubstitutionRejected(t *testing.T) {
	cfg, base := testConfig(t)
	archivePath, _, _, _ := preparedArchive(t, &cfg, base, reviewedSDKMembers())
	cfg.HelperSHA256 = strings.Repeat("a", 64)
	cfg.InvokeHelper = true
	if err := provision(archivePath, cfg); !errors.Is(err, errHelper) {
		t.Fatalf("hash: %v", err)
	}
	cfg, base = testConfig(t)
	archivePath, _, _, _ = preparedArchive(t, &cfg, base, reviewedSDKMembers())
	realHelper := cfg.HelperPath
	link := filepath.Join(base, "helper-link")
	if err := os.Symlink(realHelper, link); err != nil {
		t.Fatal(err)
	}
	cfg.HelperPath = link
	cfg.InvokeHelper = true
	if err := provision(archivePath, cfg); !errors.Is(err, errHelper) && !errors.Is(err, errHelperPath) {
		t.Fatalf("path symlink: %v", err)
	}
}

func TestHelperWritableAncestorRejected(t *testing.T) {
	cfg, base := testConfig(t)
	cfg.CheckHelperAncestry = true
	if err := os.Chmod(base, 0777); err != nil {
		t.Fatal(err)
	}
	if err := verifyHelper(cfg); !errors.Is(err, errHelperPath) {
		t.Fatalf("writable helper ancestor was accepted: %v", err)
	}
}

func TestTreeScopedStagingSupportsSequentialCandidates(t *testing.T) {
	cfg, base := testConfig(t)
	firstArchive, firstAuth, _, _ := preparedArchive(t, &cfg, base, reviewedSDKMembers())
	if err := provision(firstArchive, cfg); err != nil {
		t.Fatal(err)
	}
	secondMembers := append(reviewedSDKMembers(), tarMember{
		name: "google-cloud-sdk/second.txt", typeflag: tar.TypeReg, mode: 0644, body: "second\n",
	})
	secondArchive, secondAuth, _, _ := preparedArchive(t, &cfg, base, secondMembers)
	if firstAuth.InstallTreeSHA256 == secondAuth.InstallTreeSHA256 {
		t.Fatal("distinct candidates produced the same tree identity")
	}
	if err := provision(secondArchive, cfg); err != nil {
		t.Fatal(err)
	}
	for _, auth := range []receiptAuth{firstAuth, secondAuth} {
		dest := filepath.Join(cfg.RuntimePrefix, auth.InstallTreeSHA256)
		if info, err := os.Lstat(dest); err != nil || !info.IsDir() || info.Mode().Perm() != 0555 {
			t.Fatalf("candidate %s missing or wrong mode: %v %v", auth.InstallTreeSHA256, info, err)
		}
		stage := filepath.Join(cfg.StagingParent, stagingDirPrefix+auth.InstallTreeSHA256)
		if _, err := os.Lstat(stage); !os.IsNotExist(err) {
			t.Fatalf("candidate %s left staging path: %v", auth.InstallTreeSHA256, err)
		}
	}
}

func TestExactStalePrivateStageIsReclaimedBeforeRetry(t *testing.T) {
	cfg, base := testConfig(t)
	archivePath, auth, _, _ := preparedArchive(t, &cfg, base, reviewedSDKMembers())
	stage := filepath.Join(cfg.StagingParent, stagingDirPrefix+auth.InstallTreeSHA256)
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(stage, "partial"), 0700); err != nil {
		t.Fatal(err)
	}
	writeFileMode(t, filepath.Join(stage, "partial", "member"), []byte("partial"), 0600)
	if err := os.Symlink("member", filepath.Join(stage, "partial", "link")); err != nil {
		t.Fatal(err)
	}
	if err := provision(archivePath, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("stale stage survived successful retry: %v", err)
	}
}

func TestSameTreeLockPreservesConcurrentActiveStageAndThenRecovers(t *testing.T) {
	cfg, base := testConfig(t)
	archivePath, auth, _, _ := preparedArchive(t, &cfg, base, reviewedSDKMembers())
	stage := filepath.Join(cfg.StagingParent, stagingDirPrefix+auth.InstallTreeSHA256)
	lock, err := acquireStageLock(stage, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if lock.file != nil {
			_ = lock.Close()
		}
	})
	if err := os.Mkdir(stage, privateStageMode); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(stage, "active-run-marker")
	writeFileMode(t, marker, []byte("active"), 0600)
	stageBefore, err := os.Lstat(stage)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- provision(archivePath, cfg)
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errStageActive) {
			t.Fatalf("same-tree contender: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("same-tree contender did not fail closed")
	}
	stageAfter, err := os.Lstat(stage)
	if err != nil || !os.SameFile(stageBefore, stageAfter) {
		t.Fatalf("active stage identity changed: before=%v after=%v err=%v", stageBefore, stageAfter, err)
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "active" {
		t.Fatalf("active stage marker changed: %q %v", data, err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := provision(archivePath, cfg); err != nil {
		t.Fatalf("crash-recovery retry: %v", err)
	}
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("recovered stage survived: %v", err)
	}
	lockInfo, err := os.Lstat(stage + stagingLockSuffix)
	if err != nil || !lockInfo.Mode().IsRegular() || !exactUnixMode(lockInfo.Mode(), stageLockMode) {
		t.Fatalf("retained lock is unsafe: %v %v", lockInfo, err)
	}
}

func TestStageCleanupRequiresHeldMatchingLock(t *testing.T) {
	cfg, _ := testConfig(t)
	stage := filepath.Join(cfg.StagingParent, stagingDirPrefix+strings.Repeat("1", 64))
	if err := os.Mkdir(stage, privateStageMode); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(stage, "preserve")
	writeFileMode(t, marker, []byte("preserve"), 0600)
	if err := cleanupPrivateStageIfPresent(stage, cfg, nil); !errors.Is(err, errStageLock) {
		t.Fatalf("unlocked cleanup: %v", err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "preserve" {
		t.Fatalf("unlocked cleanup changed stage: %q %v", data, err)
	}
}

func TestRestrictiveLockAndStageCrashRemnantsRecover(t *testing.T) {
	cfg, base := testConfig(t)
	archivePath, auth, _, _ := preparedArchive(t, &cfg, base, reviewedSDKMembers())
	stage := filepath.Join(cfg.StagingParent, stagingDirPrefix+auth.InstallTreeSHA256)
	lockPath := stage + stagingLockSuffix
	writeFileMode(t, lockPath, nil, 0400)
	lock, err := acquireStageLock(stage, cfg)
	if err != nil {
		t.Fatalf("restrictive retained lock did not recover: %v", err)
	}
	lockInfo, err := os.Lstat(lockPath)
	if err != nil || !exactUnixMode(lockInfo.Mode(), stageLockMode) {
		_ = lock.Close()
		t.Fatalf("retained lock was not normalized exactly: %v %v", lockInfo, err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stage, privateStageMode); err != nil {
		t.Fatal(err)
	}
	writeFileMode(t, filepath.Join(stage, "crash-marker"), []byte("crash"), 0400)
	if err := os.Chmod(stage, 0500); err != nil {
		t.Fatal(err)
	}
	if err := provision(archivePath, cfg); err != nil {
		t.Fatalf("restrictive stale stage did not recover: %v", err)
	}
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("recovered restrictive stage survived: %v", err)
	}
}

func TestStageLockRejectsHostileFilesystemEntries(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		cfg, base := testConfig(t)
		stage := filepath.Join(cfg.StagingParent, stagingDirPrefix+strings.Repeat("2", 64))
		target := filepath.Join(base, "lock-target")
		writeFileMode(t, target, nil, stageLockMode)
		if err := os.Symlink(target, stage+stagingLockSuffix); err != nil {
			t.Fatal(err)
		}
		if lock, err := acquireStageLock(stage, cfg); !errors.Is(err, errStageLock) || lock != nil {
			t.Fatalf("symlink lock: lock=%v err=%v", lock, err)
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		cfg, base := testConfig(t)
		stage := filepath.Join(cfg.StagingParent, stagingDirPrefix+strings.Repeat("3", 64))
		target := filepath.Join(base, "hard-lock-target")
		writeFileMode(t, target, nil, stageLockMode)
		if err := os.Link(target, stage+stagingLockSuffix); err != nil {
			t.Fatal(err)
		}
		if lock, err := acquireStageLock(stage, cfg); !errors.Is(err, errStageLock) || lock != nil {
			t.Fatalf("hardlink lock: lock=%v err=%v", lock, err)
		}
	})
	t.Run("special-mode", func(t *testing.T) {
		cfg, _ := testConfig(t)
		stage := filepath.Join(cfg.StagingParent, stagingDirPrefix+strings.Repeat("4", 64))
		lockPath := stage + stagingLockSuffix
		writeFileMode(t, lockPath, nil, stageLockMode|os.ModeSticky)
		info, err := os.Lstat(lockPath)
		if err != nil || !hasSpecialModeBits(info.Mode()) {
			t.Fatalf("hostile lock mode was not installed: %v %v", info, err)
		}
		if lock, err := acquireStageLock(stage, cfg); !errors.Is(err, errStageLock) || lock != nil {
			t.Fatalf("special-mode lock: lock=%v err=%v", lock, err)
		}
	})
}

func TestUnsafeStalePrivateStageIsPreservedAndRejected(t *testing.T) {
	cfg, base := testConfig(t)
	archivePath, auth, _, _ := preparedArchive(t, &cfg, base, reviewedSDKMembers())
	stage := filepath.Join(cfg.StagingParent, stagingDirPrefix+auth.InstallTreeSHA256)
	if err := os.Mkdir(stage, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stage, 0755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(stage, "owner-marker")
	writeFileMode(t, marker, []byte("preserve"), 0600)
	if err := provision(archivePath, cfg); err == nil {
		t.Fatal("unsafe stale stage was accepted")
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "preserve" {
		t.Fatalf("unsafe stale stage was modified: %q %v", data, err)
	}
}

func TestPublishedUnsealedDestinationRetriesHelperInsteadOfWedging(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("this recovery test uses the non-Linux immutable refusal as its deterministic crash seam")
	}
	cfg, base := testConfig(t)
	invocations := filepath.Join(base, "helper-invocations")
	helperBody := []byte("#!/bin/sh\nprintf 'invoked\\n' >> '" + invocations + "'\nexit 0\n")
	if err := os.Chmod(cfg.HelperPath, 0700); err != nil {
		t.Fatal(err)
	}
	writeFileMode(t, cfg.HelperPath, helperBody, 0555)
	cfg.HelperSHA256 = sha256Hex(helperBody)
	cfg.InvokeHelper = true
	cfg.RequireImmutable = true
	archivePath, auth, _, _ := preparedArchive(t, &cfg, base, reviewedSDKMembers())
	if err := provision(archivePath, cfg); !errors.Is(err, errLinuxOnly) {
		t.Fatalf("first publish should stop only at immutable verification: %v", err)
	}
	dest := filepath.Join(cfg.RuntimePrefix, auth.InstallTreeSHA256)
	if info, err := os.Lstat(dest); err != nil || !info.IsDir() {
		t.Fatalf("published recovery candidate missing: %v %v", info, err)
	}
	if err := provision(archivePath, cfg); !errors.Is(err, errLinuxOnly) {
		t.Fatalf("retry should re-run the helper and stop at immutable verification: %v", err)
	}
	data, err := os.ReadFile(invocations)
	if err != nil || string(data) != "invoked\ninvoked\n" {
		t.Fatalf("helper was not retried exactly: %q %v", data, err)
	}
}

func TestProductionNormalizationSetsRootModeBeforePublication(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(pathName string, info os.FileInfo, err error) error {
			if err == nil && info != nil {
				if info.IsDir() {
					_ = os.Chmod(pathName, 0700)
				} else if info.Mode()&os.ModeSymlink == 0 {
					_ = os.Chmod(pathName, 0600)
				}
			}
			return nil
		})
	})
	writeFileMode(t, filepath.Join(root, "data"), []byte("x"), 0600)
	cfg := provisionConfig{
		RequireLinux: true,
		ExpectedUID:  uint32(os.Getuid()),
		ExpectedGID:  uint32(os.Getgid()),
	}
	if err := normalizeTree(root, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode().Perm() != sealedDirectoryMode {
		t.Fatalf("production root mode is not sealed before rename: %v %v", info, err)
	}
}

func TestProductionHelperPathIsFixed(t *testing.T) {
	cfg := productionConfig()
	if cfg.HelperPath != helperPath || helperPath != "/usr/local/libexec/winsvpn-gcloud-immutable-helper" {
		t.Fatalf("%q", cfg.HelperPath)
	}
	if cfg.AuthorityPath != ownerAuthorityPath || cfg.IssuancePath != ownerIssuancePath {
		t.Fatal("authority paths drifted")
	}
	if cfg.RuntimePrefix != productionRuntimeRoot {
		t.Fatal("runtime prefix drifted")
	}
}

func TestMalformedELFProgramHeaderOffsetRejected(t *testing.T) {
	data := make([]byte, 64)
	copy(data[:4], []byte{0x7f, 'E', 'L', 'F'})
	data[4] = 2
	data[5] = 1
	binary.LittleEndian.PutUint16(data[16:18], 2)
	binary.LittleEndian.PutUint16(data[18:20], 62)
	binary.LittleEndian.PutUint64(data[32:40], ^uint64(0))
	binary.LittleEndian.PutUint16(data[54:56], 56)
	binary.LittleEndian.PutUint16(data[56:58], 1)
	if linuxELF64Amd64Static(data) {
		t.Fatal("overflowing ELF program-header offset was accepted")
	}
}

func TestInstallTreeFormatMatchesController(t *testing.T) {
	dir := t.TempDir()
	writeFileMode(t, filepath.Join(dir, "a.txt"), []byte("hello"), 0644)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	writeFileMode(t, filepath.Join(dir, "sub", "b.txt"), []byte("world"), 0644)
	writeFileMode(t, filepath.Join(dir, receiptName), []byte("not-in-digest"), 0400)
	if err := os.Symlink("a.txt", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../a.txt", filepath.Join(dir, "sub", "rel")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "empty"), 0755); err != nil {
		t.Fatal(err)
	}
	got, err := installTreeSHA256(dir)
	if err != nil {
		t.Fatal(err)
	}
	const pinned = "9e100fe271366b1ec7d4ca7c154833171fb0d3e924e5b13851c6c97a43da0c4a"
	if got != pinned {
		t.Fatalf("got %s want %s", got, pinned)
	}
}

func TestCompiledPinMatchesReviewedRelease(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	tools := filepath.Dir(file)
	pin := compiledReviewedPin()
	generated, err := os.ReadFile(filepath.Join(tools, "gcp_proof_client", "gcloud_pin_generated.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{pin.version, pin.platform, pin.archiveName, pin.archiveSHA256} {
		if !bytes.Contains(generated, []byte(want)) {
			t.Fatalf("generated pin missing %s", want)
		}
	}
}

func TestReviewedOfficialArchiveExtractsAndNormalizes(t *testing.T) {
	archivePath := os.Getenv("WINSVPN_GCLOUD_REVIEWED_ARCHIVE")
	if archivePath == "" {
		t.Skip("WINSVPN_GCLOUD_REVIEWED_ARCHIVE is not set")
	}
	scratch := t.TempDir()
	caseProbe := filepath.Join(scratch, "winsvpn-case-probe-A")
	if err := os.WriteFile(caseProbe, []byte("case-sensitive-probe"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(scratch, "winsvpn-case-probe-a")); err == nil {
		t.Skip("reviewed Google SDK archive requires a case-sensitive extraction filesystem; run this test on Linux or a case-sensitive macOS volume")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	pin := compiledReviewedPin()
	if err := validateArchiveArg(archivePath, pin.archiveName); err != nil {
		t.Fatal(err)
	}
	archiveData, err := bindOfficialArchive(archivePath, pin.archiveSHA256, uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	sdk, err := extractOfficialArchive(archiveData, pin.archiveName, filepath.Join(scratch, "archive"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(filepath.Join(sdk, custodyArchiveName), archiveData, sealedDataMode); err != nil {
		t.Fatal(err)
	}
	treeBefore, err := installTreeSHA256(sdk)
	if err != nil {
		t.Fatal(err)
	}
	cfg := provisionConfig{ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid())}
	if err := normalizeTree(sdk, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sdk, sealedDirectoryMode); err != nil {
		t.Fatal(err)
	}
	treeAfter, err := installTreeSHA256(sdk)
	if err != nil || treeAfter != treeBefore {
		t.Fatalf("normalization changed reviewed tree: before=%s after=%s err=%v", treeBefore, treeAfter, err)
	}
	if err := requireExecutable(sdk, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
	bundledPython := filepath.Join(sdk, "platform", "bundledpythonunix", "bin", "python3.14")
	pythonInfo, err := os.Lstat(bundledPython)
	if err != nil || !pythonInfo.Mode().IsRegular() || pythonInfo.Mode().Perm() != sealedExecutableMode {
		t.Fatalf("reviewed bundled Python is missing or has the wrong mode: %v %v", pythonInfo, err)
	}
	var symlinks []string
	err = filepath.WalkDir(sdk, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(current)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(sdk, current)
			if err != nil {
				return err
			}
			symlinks = append(symlinks, filepath.ToSlash(rel)+"\x00"+target+"\n")
			return nil
		}
		if !sealedPublicModeAllowed(info) {
			return fmt.Errorf("reviewed runtime mode is not exact for %s: %04o", current, info.Mode().Perm())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(symlinks)
	if len(symlinks) != 1052 {
		t.Fatalf("official 582.0.0 safe symlink count drifted: %d", len(symlinks))
	}
	if got := sha256Hex([]byte(strings.Join(symlinks, ""))); got != "1b3d1c431376926985b21aa50e67297174c2ec1e49583d1ab4afd76cd8fd4cdf" {
		t.Fatalf("official 582.0.0 safe symlink inventory drifted: %s", got)
	}
	t.Logf("reviewed archive tree=%s symlinks=%d bytes=%d", treeAfter, len(symlinks), len(archiveData))
}

func TestOwnerSignedSourceHashesDoNotCreateCompiledTrustCycle(t *testing.T) {
	pin := compiledReviewedPin()
	auth := freshAuth(t, pin, strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64))
	auth.ControllerSHA256 = strings.Repeat("4", 64)
	auth.ManifestSHA256 = strings.Repeat("5", 64)
	auth.TrustAnchorSHA256 = strings.Repeat("6", 64)
	if err := requirePinMatch(auth, pin); err != nil {
		t.Fatalf("signed release-source hashes were incorrectly compiled into the provisioner: %v", err)
	}
	if err := validateReceiptAuth(auth, false); err != nil {
		t.Fatalf("valid signed release-source hashes were refused: %v", err)
	}
	auth.TrustAnchorSHA256 = strings.Repeat("0", 64)
	if err := validateReceiptAuth(auth, false); err == nil {
		t.Fatal("zero signed trust-anchor hash was accepted")
	}
}

func TestLinuxRootImmutableSkippedUnlessOptIn(t *testing.T) {
	enabled := os.Getenv("WINSVPN_GCLOUD_RUNTIME_PROVISIONER_LINUX_ROOT") == "1"
	if !enabled {
		if runtime.GOOS == "linux" && os.Geteuid() == 0 {
			t.Log("opt-in unset; not claiming Linux immutable success")
		}
		return
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("WINSVPN_GCLOUD_RUNTIME_PROVISIONER_LINUX_ROOT requires linux euid 0")
	}
	dir := t.TempDir()
	writeFileMode(t, filepath.Join(dir, "a.txt"), []byte("x"), 0444)
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := linuxFileImmutable(dir, info)
	if err != nil {
		t.Logf("immutable ioctl unavailable on this filesystem: %v", err)
		return
	}
	if ok {
		t.Fatal("temp directory unexpectedly immutable without the helper")
	}
}

func TestStaticForbiddenSurfaces(t *testing.T) {
	src := provisionerSource(t)
	forbidden := []string{
		"unseal",
		"Unseal",
		"\"net\"",
		"net/http",
		"os.RemoveAll",
		"os.Chdir",
		"import \"C\"",
		"golang.org/x/",
		"StartProcess",
		"ForkExec",
		"SYS_EXECVE",
		"http.",
		"Dial",
		"Listen",
	}
	for _, item := range forbidden {
		if bytes.Contains(src, []byte(item)) {
			t.Errorf("forbidden surface %q", item)
		}
	}
	if bytes.Count(src, []byte("exec.Command")) != 1 {
		t.Fatal("must invoke exactly one helper subprocess")
	}
	if !bytes.Contains(src, []byte("os/exec")) {
		t.Fatal("helper invoke requires os/exec")
	}
	if !bytes.Contains(src, []byte(receiptName)) || !bytes.Contains(src, []byte(custodyArchiveName)) {
		t.Fatal("missing custody names")
	}
	if !bytes.Contains(src, []byte("winsvpn-gcloud-owner-receipt-v1")) {
		t.Fatal("missing signature domain")
	}
	if !bytes.Contains(src, []byte(helperPath)) {
		t.Fatal("missing fixed helper path")
	}
	if !bytes.Contains(src, []byte("crypto/ed25519")) {
		t.Fatal("must use standard-library Ed25519")
	}
	if bytes.Contains(src, []byte("&^ fsImmutableFL")) || bytes.Contains(src, []byte("&^= linuxFSImmutable")) {
		t.Fatal("source clears immutable flags")
	}
}

func TestProductionConfigIsRootLinuxOnly(t *testing.T) {
	cfg := productionConfig()
	if !cfg.RequireRoot || !cfg.RequireLinux || !cfg.ApplyChown || !cfg.InvokeHelper || !cfg.RequireImmutable ||
		!cfg.CheckAuthorityAncestry || !cfg.CheckHelperAncestry || !cfg.CheckProvisionAncestry ||
		!cfg.ExecHelperByFD {
		t.Fatalf("%+v", cfg)
	}
	if cfg.ExpectedUID != 0 || cfg.ExpectedGID != 0 {
		t.Fatal("production must be root-owned")
	}
	if path.Base(cfg.Pin.archiveName) != cfg.Pin.archiveName {
		t.Fatal("archive name must be a basename")
	}
}
