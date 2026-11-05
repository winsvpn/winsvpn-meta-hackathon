// Linux amd64 root provisioner for the reviewed Google Cloud CLI runtime.
// It extracts one official archive under owner issuance, publishes an
// exclusive sealed tree, and invokes only the independently built helper.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	receiptName             = ".winsvpn-gcloud-custody-v1.json"
	custodyArchiveName      = ".winsvpn-gcloud-official-archive"
	receiptContract         = "winsvpn-gcloud-install-custody-v1"
	ownerAuthorityPath      = "/var/lib/winsvpn/gcloud-owner-authority-v1.json"
	ownerIssuancePath       = "/var/lib/winsvpn/gcloud-owner-issuance.json"
	ownerAuthority          = "winsvpn-gcloud-owner-authority-v1"
	ownerIssuance           = "winsvpn-gcloud-owner-issuance-v1"
	ownerIssuer             = "winsvpn-owner"
	ownerAlgorithm          = "ed25519"
	ownerSignatureDomain    = "winsvpn-gcloud-owner-receipt-v1\n"
	productionRuntimeRoot   = "/var/lib/winsvpn/gcloud-runtime-v1"
	productionStagingParent = "/var/lib/winsvpn"
	stagingDirPrefix        = "gcloud-runtime-stage-v1."
	stagingLockSuffix       = ".lock"
	helperPath              = "/usr/local/libexec/winsvpn-gcloud-immutable-helper"
	executableRel           = "bin/gcloud"
	linuxFSIOCGetFlags      = uintptr(0x80086601)
	linuxFSImmutable        = int32(0x00000010)
	linuxSysRenameat2       = 316
	linuxRenameNoreplace    = 1
	linuxATFdcwd            = ^uintptr(99)
	sealedDataMode          = os.FileMode(0444)
	sealedExecutableMode    = os.FileMode(0555)
	sealedDirectoryMode     = os.FileMode(0555)
	privateStageMode        = os.FileMode(0700)
	stageLockMode           = os.FileMode(0600)
)

var (
	maxArchiveOuter   = int64(512 * 1024 * 1024)
	maxArchiveMember  = int64(512 * 1024 * 1024)
	maxArchiveEntries = 200000
	maxArchiveRatio   = int64(100)
	maxArchiveBytes   = int64(3 * 1024 * 1024 * 1024)
	maxArchiveDepth   = 32
	maxPathBytes      = 1024
	maxAuthorityBytes = int64(64 * 1024)
	maxReceiptAge     = 6 * time.Hour
	maxClockSkew      = 5 * time.Minute
)

var (
	shaPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	issuanceIDPat = regexp.MustCompile(`^[0-9a-f]{32}$`)
	utcSecondsPat = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	ed25519PubPat = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ed25519SigPat = regexp.MustCompile(`^[0-9a-f]{128}$`)
	zeroSHA       = strings.Repeat("0", 64)
)

var compiledHelperSHA256 string

var (
	errUsage           = errors.New("exactly one absolute official archive path is required")
	errUnsafePath      = errors.New("archive path is unsafe")
	errNeedRoot        = errors.New("euid 0 is required")
	errLinuxOnly       = errors.New("linux/amd64-only")
	errArchiveName     = errors.New("archive filename does not match the reviewed pin")
	errArchiveHash     = errors.New("archive hash does not match the reviewed pin")
	errArchiveType     = errors.New("Google Cloud CLI archive type is unsupported")
	errDestExists      = errors.New("existing destination does not revalidate byte for byte")
	errHelper          = errors.New("immutable helper is not the compiled static helper")
	errTree            = errors.New("install tree hash does not match the signed issuance")
	errRootHash        = errors.New("install root hash does not match the signed issuance")
	errTrust           = errors.New("owner-blocked: Google Cloud CLI owner authority is invalid")
	errStale           = errors.New("Google Cloud CLI owner issuance is stale, expired, or invalid")
	errSchema          = errors.New("Google Cloud CLI owner document schema is invalid")
	errDuplicateJSON   = errors.New("duplicate JSON key is forbidden")
	errNestedReceipt   = errors.New("nested Google Cloud CLI custody receipt is forbidden")
	errHardlink        = errors.New("hard-linked regular file rejected")
	errSymlink         = errors.New("unsafe symlink rejected")
	errTraversal       = errors.New("path traversal rejected")
	errDuplicateMember = errors.New("official archive contains duplicate members")
	errTooLarge        = errors.New("official archive exceeds a size, ratio, depth, or entry limit")
	errSpecial         = errors.New("official archive contains an unsafe member")
	errOwner           = errors.New("unexpected uid or gid rejected")
	errMode            = errors.New("unsafe or unexpected mode rejected")
	errDevice          = errors.New("staging and destination must share one filesystem")
	errImmutable       = errors.New("FS_IMMUTABLE_FL missing after seal")
	errNotDir          = errors.New("runtime root must be a directory")
	errIdempotentFail  = errors.New("existing destination substitution is forbidden")
	errHelperPath      = errors.New("helper path substitution is forbidden")
	errStageActive     = errors.New("same-tree provisioning is already active")
	errStageLock       = errors.New("same-tree provisioning lock is unsafe")
)

type reviewedPin struct {
	version, platform, archiveName, archiveSHA256 string
}

type provisionConfig struct {
	Pin                    reviewedPin
	AuthorityPath          string
	IssuancePath           string
	StagingParent          string
	RuntimePrefix          string
	HelperPath             string
	HelperSHA256           string
	RequireRoot            bool
	RequireLinux           bool
	ApplyChown             bool
	InvokeHelper           bool
	RequireImmutable       bool
	ExpectedUID            uint32
	ExpectedGID            uint32
	CheckAuthorityAncestry bool
	CheckHelperAncestry    bool
	CheckProvisionAncestry bool
	RequireHelperELF       bool
	ExecHelperByFD         bool
}

type receiptAuth struct {
	SchemaVersion     int    `json:"schema_version"`
	Contract          string `json:"contract"`
	Version           string `json:"version"`
	Platform          string `json:"platform"`
	ArchiveName       string `json:"archive_name"`
	ArchiveSHA256     string `json:"archive_sha256"`
	InstallTreeSHA256 string `json:"install_tree_sha256"`
	ExecutablePath    string `json:"executable_path"`
	InstallRootSHA256 string `json:"install_root_sha256"`
	IssuedUTC         string `json:"issued_utc"`
	ExpiresUTC        string `json:"expires_utc"`
	IssuanceID        string `json:"issuance_id"`
	AuthorityKeyID    string `json:"authority_key_id"`
	ControllerSHA256  string `json:"controller_sha256"`
	ManifestSHA256    string `json:"manifest_sha256"`
	TrustAnchorSHA256 string `json:"trust_anchor_sha256"`
}

type durableReceipt struct {
	receiptAuth
	IssuanceSignature string `json:"issuance_signature"`
}

type ownerAuthorityDoc struct {
	Contract      string `json:"contract"`
	SchemaVersion int    `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	PublicKey     string `json:"public_key"`
	OwnerUID      uint32 `json:"owner_uid"`
}

type ownerIssuanceDoc struct {
	Contract      string          `json:"contract"`
	SchemaVersion int             `json:"schema_version"`
	Issuer        string          `json:"issuer"`
	Algorithm     string          `json:"algorithm"`
	KeyID         string          `json:"key_id"`
	Receipt       json.RawMessage `json:"receipt"`
	Signature     string          `json:"signature"`
}

type countingReader struct {
	r          io.Reader
	n          int64
	compressed int64
}

type stageLock struct {
	file      *os.File
	stageRoot string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "gcloud-runtime-provisioner: %s\n", err)
		os.Exit(1)
	}
}

func compiledReviewedPin() reviewedPin {
	return reviewedPin{
		version:       "582.0.0",
		platform:      "linux_amd64",
		archiveName:   "google-cloud-cli-582.0.0-linux-x86_64.tar.gz",
		archiveSHA256: "e917ca3a21bc9d5ae13759d11a581a6a948a5170f257f2640a25e7c44cf6a8a5",
	}
}

func productionConfig() provisionConfig {
	return provisionConfig{
		Pin:                    compiledReviewedPin(),
		AuthorityPath:          ownerAuthorityPath,
		IssuancePath:           ownerIssuancePath,
		StagingParent:          productionStagingParent,
		RuntimePrefix:          productionRuntimeRoot,
		HelperPath:             helperPath,
		HelperSHA256:           compiledHelperSHA256,
		RequireRoot:            true,
		RequireLinux:           true,
		ApplyChown:             true,
		InvokeHelper:           true,
		RequireImmutable:       true,
		ExpectedUID:            0,
		ExpectedGID:            0,
		CheckAuthorityAncestry: true,
		CheckHelperAncestry:    true,
		CheckProvisionAncestry: true,
		RequireHelperELF:       true,
		ExecHelperByFD:         true,
	}
}

func run(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	if err := validateArchiveArg(args[0], compiledReviewedPin().archiveName); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errNeedRoot
	}
	if err := requireLinux(); err != nil {
		return err
	}
	return provision(args[0], productionConfig())
}

func requireLinux() error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errLinuxOnly
	}
	return nil
}

func validateArchiveArg(archivePath, wantName string) error {
	if archivePath == "" || !path.IsAbs(archivePath) || path.Clean(archivePath) != archivePath {
		return errUnsafePath
	}
	if strings.ContainsRune(archivePath, 0) || strings.Contains(archivePath, "\\") {
		return errUnsafePath
	}
	if path.Base(archivePath) != wantName {
		return errArchiveName
	}
	return nil
}

func provision(archivePath string, cfg provisionConfig) (resultErr error) {
	if cfg.RequireRoot && os.Geteuid() != 0 {
		return errNeedRoot
	}
	if cfg.RequireLinux {
		if err := requireLinux(); err != nil {
			return err
		}
	}
	if uint32(os.Geteuid()) != cfg.ExpectedUID || uint32(os.Getegid()) != cfg.ExpectedGID {
		return errOwner
	}
	if err := validateArchiveArg(archivePath, cfg.Pin.archiveName); err != nil {
		return err
	}
	if !shaPattern.MatchString(cfg.Pin.archiveSHA256) || cfg.Pin.archiveSHA256 == zeroSHA ||
		cfg.Pin.version == "" || cfg.Pin.platform != "linux_amd64" ||
		!strings.HasSuffix(cfg.Pin.archiveName, ".tar.gz") {
		return errArchiveHash
	}
	auth, signature, err := loadVerifiedIssuance(cfg)
	if err != nil {
		return err
	}
	if err := requirePinMatch(auth, cfg.Pin); err != nil {
		return err
	}
	dest, err := expectedDestination(cfg.RuntimePrefix, auth.InstallTreeSHA256)
	if err != nil {
		return err
	}
	if sha256Hex([]byte(dest)) != auth.InstallRootSHA256 {
		return errRootHash
	}
	stageRoot := filepath.Join(cfg.StagingParent, stagingDirPrefix+auth.InstallTreeSHA256)
	if err := requireSameFilesystem(cfg.StagingParent, cfg.RuntimePrefix); err != nil {
		return err
	}
	if cfg.CheckProvisionAncestry {
		if err := verifyProvisionParents(cfg); err != nil {
			return err
		}
	}
	lock, err := acquireStageLock(stageRoot, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil && resultErr == nil {
			resultErr = fmt.Errorf("same-tree provisioning lock close failed: %w", closeErr)
		}
	}()
	if exists, err := pathExists(dest); err != nil {
		return err
	} else if exists {
		if err := revalidateRoot(dest, auth, signature, cfg, true); err == nil {
			return cleanupPrivateStageIfPresent(stageRoot, cfg, lock)
		}
		recovery := cfg
		recovery.RequireImmutable = false
		if err := revalidateRoot(dest, auth, signature, recovery, true); err != nil {
			return err
		}
		if err := invokeHelper(dest, cfg); err != nil {
			return err
		}
		if err := revalidateRoot(dest, auth, signature, cfg, true); err != nil {
			return err
		}
		return cleanupPrivateStageIfPresent(stageRoot, cfg, lock)
	}
	archiveData, err := bindOfficialArchive(archivePath, cfg.Pin.archiveSHA256, cfg.ExpectedUID, cfg.ExpectedGID)
	if err != nil {
		return err
	}
	if err := cleanupPrivateStageIfPresent(stageRoot, cfg, lock); err != nil {
		return err
	}
	if err := os.Mkdir(stageRoot, privateStageMode); err != nil {
		return fmt.Errorf("private staging is not exclusive: %w", err)
	}
	stageCreated := true
	defer func() {
		if resultErr == nil || !stageCreated {
			return
		}
		if cleanupErr := cleanupPrivateStageIfPresent(stageRoot, cfg, lock); cleanupErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("private staging cleanup failed: %w", cleanupErr))
		}
	}()
	if cfg.ApplyChown {
		if err := os.Chown(stageRoot, int(cfg.ExpectedUID), int(cfg.ExpectedGID)); err != nil {
			return err
		}
	}
	if err := chmodAndSync(stageRoot, privateStageMode, cfg.ExpectedUID, cfg.ExpectedGID); err != nil {
		return err
	}
	if err := validatePrivateStageRoot(stageRoot, cfg); err != nil {
		return err
	}
	if err := syncDirectory(cfg.StagingParent); err != nil {
		return err
	}
	unpack := filepath.Join(stageRoot, "unpack")
	sdk, err := extractOfficialArchive(archiveData, cfg.Pin.archiveName, unpack)
	if err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(sdk, custodyArchiveName), archiveData, sealedDataMode); err != nil {
		return err
	}
	tree, err := installTreeSHA256(sdk)
	if err != nil {
		return err
	}
	if !sameSHA(tree, auth.InstallTreeSHA256) {
		return errTree
	}
	durable, err := canonicalJSON(durableReceiptMap(auth, signature), true)
	if err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(sdk, receiptName), durable, sealedDataMode); err != nil {
		return err
	}
	if err := normalizeTree(sdk, cfg); err != nil {
		return err
	}
	if err := syncTreeDirectories(sdk); err != nil {
		return err
	}
	again, err := installTreeSHA256(sdk)
	if err != nil || !sameSHA(again, auth.InstallTreeSHA256) {
		return errTree
	}
	if err := requireExecutable(sdk, cfg.ExpectedUID, cfg.ExpectedGID); err != nil {
		return err
	}
	if err := renameNoReplace(sdk, dest); err != nil {
		return err
	}
	if err := chmodAndSync(dest, sealedDirectoryMode, cfg.ExpectedUID, cfg.ExpectedGID); err != nil {
		return err
	}
	if err := syncDirectory(dest); err != nil {
		return err
	}
	if err := syncDirectory(cfg.RuntimePrefix); err != nil {
		return err
	}
	if err := os.Remove(unpack); err != nil {
		return fmt.Errorf("published runtime left a non-empty unpack directory: %w", err)
	}
	if err := os.Remove(stageRoot); err != nil {
		return fmt.Errorf("published runtime left a non-empty staging directory: %w", err)
	}
	stageCreated = false
	if err := syncDirectory(cfg.StagingParent); err != nil {
		return err
	}
	if err := invokeHelper(dest, cfg); err != nil {
		return err
	}
	return revalidateRoot(dest, auth, signature, cfg, false)
}

func requirePinMatch(auth receiptAuth, pin reviewedPin) error {
	if auth.SchemaVersion != 1 || auth.Contract != receiptContract ||
		auth.Version != pin.version || auth.Platform != pin.platform ||
		auth.ArchiveName != pin.archiveName || auth.ArchiveSHA256 != pin.archiveSHA256 ||
		auth.ExecutablePath != executableRel {
		return errTrust
	}
	return nil
}

func expectedDestination(prefix, treeSHA string) (string, error) {
	if !shaPattern.MatchString(treeSHA) || treeSHA == zeroSHA {
		return "", errTree
	}
	if prefix == "" || !filepath.IsAbs(prefix) || filepath.Clean(prefix) != prefix {
		return "", errUnsafePath
	}
	dest := filepath.Join(prefix, treeSHA)
	if filepath.Clean(dest) != dest || !filepath.IsAbs(dest) {
		return "", errUnsafePath
	}
	return dest, nil
}

func loadVerifiedIssuance(cfg provisionConfig) (receiptAuth, string, error) {
	authorityData, err := bindExternalAuthority(cfg.AuthorityPath, cfg.ExpectedUID, cfg.ExpectedGID, cfg.CheckAuthorityAncestry)
	if err != nil {
		return receiptAuth{}, "", err
	}
	if _, err := decodeExactObject(authorityData, []string{
		"contract", "schema_version", "algorithm", "key_id", "public_key", "owner_uid",
	}); err != nil {
		return receiptAuth{}, "", errSchema
	}
	var authority ownerAuthorityDoc
	if err := strictDecode(authorityData, &authority); err != nil ||
		authority.SchemaVersion != 1 || authority.Contract != ownerAuthority ||
		authority.Algorithm != ownerAlgorithm || authority.OwnerUID != cfg.ExpectedUID ||
		!shaPattern.MatchString(authority.KeyID) || !ed25519PubPat.MatchString(authority.PublicKey) {
		return receiptAuth{}, "", errTrust
	}
	publicKey, err := hex.DecodeString(authority.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || sha256Hex(publicKey) != authority.KeyID {
		return receiptAuth{}, "", errTrust
	}
	issuanceData, err := bindExternalAuthority(cfg.IssuancePath, cfg.ExpectedUID, cfg.ExpectedGID, cfg.CheckAuthorityAncestry)
	if err != nil {
		return receiptAuth{}, "", err
	}
	if _, err := decodeExactObject(issuanceData, []string{
		"contract", "schema_version", "issuer", "algorithm", "key_id", "receipt", "signature",
	}); err != nil {
		return receiptAuth{}, "", errSchema
	}
	var issuance ownerIssuanceDoc
	if err := strictDecode(issuanceData, &issuance); err != nil ||
		issuance.SchemaVersion != 1 || issuance.Contract != ownerIssuance ||
		issuance.Issuer != ownerIssuer || issuance.Algorithm != ownerAlgorithm ||
		issuance.KeyID != authority.KeyID || !ed25519SigPat.MatchString(issuance.Signature) {
		return receiptAuth{}, "", errTrust
	}
	if _, err := decodeExactObject(issuance.Receipt, []string{
		"schema_version", "contract", "version", "platform", "archive_name", "archive_sha256",
		"install_tree_sha256", "executable_path", "install_root_sha256", "issued_utc", "expires_utc",
		"issuance_id", "authority_key_id", "controller_sha256", "manifest_sha256", "trust_anchor_sha256",
	}); err != nil {
		return receiptAuth{}, "", errSchema
	}
	var auth receiptAuth
	if err := strictDecode(issuance.Receipt, &auth); err != nil {
		return receiptAuth{}, "", errSchema
	}
	if err := validateReceiptAuth(auth, true); err != nil {
		return receiptAuth{}, "", err
	}
	if auth.AuthorityKeyID != authority.KeyID {
		return receiptAuth{}, "", errTrust
	}
	message, err := receiptSignatureMessage(auth)
	if err != nil {
		return receiptAuth{}, "", err
	}
	signature, err := hex.DecodeString(issuance.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		return receiptAuth{}, "", errTrust
	}
	return auth, issuance.Signature, nil
}

func validateReceiptAuth(auth receiptAuth, requireFresh bool) error {
	if auth.SchemaVersion != 1 || auth.Contract != receiptContract {
		return errSchema
	}
	if !shaPattern.MatchString(auth.InstallTreeSHA256) || auth.InstallTreeSHA256 == zeroSHA ||
		!shaPattern.MatchString(auth.InstallRootSHA256) ||
		!shaPattern.MatchString(auth.ArchiveSHA256) || auth.ArchiveSHA256 == zeroSHA ||
		!shaPattern.MatchString(auth.AuthorityKeyID) ||
		!shaPattern.MatchString(auth.ControllerSHA256) || auth.ControllerSHA256 == zeroSHA ||
		!shaPattern.MatchString(auth.ManifestSHA256) || auth.ManifestSHA256 == zeroSHA ||
		!shaPattern.MatchString(auth.TrustAnchorSHA256) || auth.TrustAnchorSHA256 == zeroSHA ||
		!issuanceIDPat.MatchString(auth.IssuanceID) || auth.ExecutablePath != executableRel {
		return errSchema
	}
	if !utcSecondsPat.MatchString(auth.IssuedUTC) || !utcSecondsPat.MatchString(auth.ExpiresUTC) {
		return errStale
	}
	issued, issuedErr := time.Parse("2006-01-02T15:04:05Z", auth.IssuedUTC)
	expires, expiresErr := time.Parse("2006-01-02T15:04:05Z", auth.ExpiresUTC)
	if issuedErr != nil || expiresErr != nil || issued.Year() < 2026 ||
		!expires.After(issued) || expires.Sub(issued) > maxReceiptAge {
		return errStale
	}
	if requireFresh {
		now := time.Now().UTC()
		if expires.Before(now.Add(-maxClockSkew)) ||
			issued.After(now.Add(maxClockSkew)) || now.Sub(issued) > maxReceiptAge {
			return errStale
		}
	}
	return nil
}

func receiptAuthMap(auth receiptAuth) map[string]any {
	return map[string]any{
		"schema_version": auth.SchemaVersion, "contract": auth.Contract,
		"version": auth.Version, "platform": auth.Platform,
		"archive_name": auth.ArchiveName, "archive_sha256": auth.ArchiveSHA256,
		"install_tree_sha256": auth.InstallTreeSHA256, "executable_path": auth.ExecutablePath,
		"install_root_sha256": auth.InstallRootSHA256, "issued_utc": auth.IssuedUTC,
		"expires_utc": auth.ExpiresUTC, "issuance_id": auth.IssuanceID,
		"authority_key_id": auth.AuthorityKeyID, "controller_sha256": auth.ControllerSHA256,
		"manifest_sha256": auth.ManifestSHA256, "trust_anchor_sha256": auth.TrustAnchorSHA256,
	}
}

func durableReceiptMap(auth receiptAuth, signature string) map[string]any {
	value := receiptAuthMap(auth)
	value["issuance_signature"] = signature
	return value
}

func receiptSignatureMessage(auth receiptAuth) ([]byte, error) {
	canonical, err := canonicalJSON(receiptAuthMap(auth), false)
	if err != nil {
		return nil, err
	}
	return append([]byte(ownerSignatureDomain), canonical...), nil
}

func canonicalJSON(value any, newline bool) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	encoded := buffer.Bytes()
	if !newline {
		encoded = bytes.TrimSuffix(encoded, []byte{'\n'})
	}
	return encoded, nil
}

func bindExternalAuthority(pathName string, expectedUID, expectedGID uint32, checkAncestry bool) ([]byte, error) {
	if pathName == "" || !filepath.IsAbs(pathName) || filepath.Clean(pathName) != pathName {
		return nil, errTrust
	}
	info, err := os.Lstat(pathName)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errTrust
	}
	links, err := fileLinkCount(info)
	if err != nil || links != 1 {
		return nil, errTrust
	}
	owner, ownerErr := fileOwner(info)
	gid, gidErr := fileGID(info)
	if ownerErr != nil || gidErr != nil || owner != expectedUID || gid != expectedGID ||
		!nonWritableUnixMode(info.Mode()) {
		return nil, errTrust
	}
	if info.Size() <= 0 || info.Size() > maxAuthorityBytes {
		return nil, errTrust
	}
	if checkAncestry {
		for directory := filepath.Dir(pathName); ; directory = filepath.Dir(directory) {
			ancestor, statErr := os.Lstat(directory)
			if statErr != nil || !ancestor.IsDir() || ancestor.Mode()&os.ModeSymlink != 0 || ancestor.Mode().Perm()&0022 != 0 {
				return nil, errTrust
			}
			ancestorOwner, ownerErr := fileOwner(ancestor)
			ancestorGID, gidErr := fileGID(ancestor)
			if ownerErr != nil || gidErr != nil ||
				!trustedOwnerGroup(ancestorOwner, ancestorGID, expectedUID, expectedGID) ||
				!nonWritableUnixMode(ancestor.Mode()) {
				return nil, errTrust
			}
			parent := filepath.Dir(directory)
			if parent == directory {
				break
			}
		}
	}
	data, identity, err := stableFile(pathName)
	if err != nil || identity.uid != expectedUID || identity.gid != expectedGID ||
		!nonWritableUnixMode(identity.mode) ||
		len(data) == 0 || int64(len(data)) > maxAuthorityBytes {
		return nil, errTrust
	}
	return data, nil
}

type stableIdentity struct {
	mode os.FileMode
	uid  uint32
	gid  uint32
	size int64
}

func stableFile(pathName string) ([]byte, stableIdentity, error) {
	data, identity, file, err := openStableFile(pathName)
	if err != nil {
		return nil, stableIdentity{}, err
	}
	if err := file.Close(); err != nil {
		return nil, stableIdentity{}, errors.New("custody file changed while read")
	}
	return data, identity, nil
}

func openStableFile(pathName string) ([]byte, stableIdentity, *os.File, error) {
	before, err := os.Lstat(pathName)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, stableIdentity{}, nil, errors.New("custody file is not a regular file")
	}
	beforeLinks, err := fileLinkCount(before)
	if err != nil || beforeLinks != 1 {
		return nil, stableIdentity{}, nil, errHardlink
	}
	fd, err := syscall.Open(pathName, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, stableIdentity{}, nil, err
	}
	file := os.NewFile(uintptr(fd), pathName)
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, stableIdentity{}, nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxArchiveOuter+1))
	finished, statErr := file.Stat()
	after, afterErr := os.Lstat(pathName)
	if readErr != nil || statErr != nil || afterErr != nil {
		_ = file.Close()
		return nil, stableIdentity{}, nil, errors.New("custody file changed while read")
	}
	openedLinks, _ := fileLinkCount(opened)
	finishedLinks, _ := fileLinkCount(finished)
	afterLinks, _ := fileLinkCount(after)
	beforeOwner, beforeOwnerErr := fileOwner(before)
	openedOwner, openedOwnerErr := fileOwner(opened)
	finishedOwner, finishedOwnerErr := fileOwner(finished)
	afterOwner, afterOwnerErr := fileOwner(after)
	beforeGID, beforeGIDErr := fileGID(before)
	openedGID, openedGIDErr := fileGID(opened)
	finishedGID, finishedGIDErr := fileGID(finished)
	afterGID, afterGIDErr := fileGID(after)
	if openedLinks != 1 || finishedLinks != 1 || afterLinks != 1 ||
		beforeOwnerErr != nil || openedOwnerErr != nil || finishedOwnerErr != nil || afterOwnerErr != nil ||
		beforeGIDErr != nil || openedGIDErr != nil || finishedGIDErr != nil || afterGIDErr != nil ||
		beforeOwner != openedOwner || openedOwner != finishedOwner || finishedOwner != afterOwner ||
		beforeGID != openedGID || openedGID != finishedGID || finishedGID != afterGID ||
		before.Mode() != opened.Mode() || opened.Mode() != finished.Mode() || finished.Mode() != after.Mode() ||
		!os.SameFile(before, opened) || !os.SameFile(opened, finished) || !os.SameFile(finished, after) ||
		before.Size() != opened.Size() || opened.Size() != finished.Size() || finished.Size() != after.Size() {
		_ = file.Close()
		return nil, stableIdentity{}, nil, errors.New("custody file changed while read")
	}
	if int64(len(data)) != before.Size() {
		_ = file.Close()
		return nil, stableIdentity{}, nil, errors.New("custody file changed while read")
	}
	return data, stableIdentity{mode: finished.Mode(), uid: finishedOwner, gid: finishedGID, size: finished.Size()}, file, nil
}

func bindOfficialArchive(pathName, expectedSHA string, expectedUID, expectedGID uint32) ([]byte, error) {
	info, err := os.Lstat(pathName)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("official archive must be a regular single-link file")
	}
	links, err := fileLinkCount(info)
	if err != nil || links != 1 {
		return nil, errHardlink
	}
	owner, ownerErr := fileOwner(info)
	gid, gidErr := fileGID(info)
	if ownerErr != nil || gidErr != nil || owner != expectedUID || gid != expectedGID ||
		info.Mode().Perm()&0022 != 0 || hasSpecialModeBits(info.Mode()) {
		return nil, errOwner
	}
	if info.Size() < 22 || info.Size() > maxArchiveOuter {
		return nil, errTooLarge
	}
	data, identity, err := stableFile(pathName)
	if err != nil {
		return errWrap(err, "official archive")
	}
	if identity.uid != expectedUID || identity.gid != expectedGID ||
		identity.mode.Perm()&0022 != 0 || hasSpecialModeBits(identity.mode) {
		return nil, errOwner
	}
	if identity.size < 22 || identity.size > maxArchiveOuter || int64(len(data)) != identity.size {
		return nil, errTooLarge
	}
	got := sha256Hex(data)
	if !sameSHA(got, expectedSHA) {
		return nil, errArchiveHash
	}
	return data, nil
}

func errWrap(err error, label string) ([]byte, error) {
	if errors.Is(err, errHardlink) {
		return nil, err
	}
	return nil, fmt.Errorf("%s: %w", label, err)
}

func (c *countingReader) Read(p []byte) (int, error) {
	remainingAgg := maxArchiveBytes - c.n
	remainingRatio := c.compressed*maxArchiveRatio - c.n
	remaining := remainingAgg
	if remainingRatio < remaining {
		remaining = remainingRatio
	}
	if remaining <= 0 {
		var probe [1]byte
		n, err := c.r.Read(probe[:])
		c.n += int64(n)
		if n > 0 || err == nil {
			return 0, errTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > remaining+1 {
		p = p[:remaining+1]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > maxArchiveBytes || c.compressed <= 0 || c.n > c.compressed*maxArchiveRatio {
		return 0, errTooLarge
	}
	return n, err
}

func extractOfficialArchive(archiveData []byte, archiveName, output string) (string, error) {
	if !strings.HasSuffix(archiveName, ".tar.gz") {
		return "", errArchiveType
	}
	if int64(len(archiveData)) < 22 || int64(len(archiveData)) > maxArchiveOuter {
		return "", errTooLarge
	}
	if err := os.Mkdir(output, 0700); err != nil {
		return "", err
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(archiveData))
	if err != nil {
		return "", errors.New("official archive is not valid gzip")
	}
	gzipReader.Multistream(false)
	defer gzipReader.Close()
	tarReader := tar.NewReader(&countingReader{r: gzipReader, compressed: int64(len(archiveData))})
	seen := make(map[string]struct{})
	var totalBytes int64
	for entries := 0; ; entries++ {
		if entries >= maxArchiveEntries {
			return "", errTooLarge
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, errTooLarge) {
				return "", err
			}
			return "", errors.New("official archive is invalid")
		}
		member, err := safeArchivePath(header.Name)
		if err != nil {
			return "", err
		}
		if path.Base(member) == receiptName || path.Base(member) == custodyArchiveName {
			return "", errNestedReceipt
		}
		if _, duplicate := seen[member]; duplicate {
			return "", errDuplicateMember
		}
		seen[member] = struct{}{}
		if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
			if header.Size < 0 || header.Size > maxArchiveMember {
				return "", errTooLarge
			}
			totalBytes += header.Size
			if totalBytes < 0 || totalBytes > maxArchiveBytes {
				return "", errTooLarge
			}
		}
		relativeParent := path.Dir(member)
		if err := ensureSafeDirectories(output, relativeParent); err != nil {
			return "", err
		}
		destination := filepath.Join(output, filepath.FromSlash(member))
		switch header.Typeflag {
		case tar.TypeDir:
			info, statErr := os.Lstat(destination)
			if os.IsNotExist(statErr) {
				if err := os.Mkdir(destination, 0700); err != nil {
					return "", err
				}
			} else if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return "", errors.New("official archive directory collides with another entry")
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := writeTarRegular(tarReader, destination, header.Size, header.Mode&0111 != 0); err != nil {
				return "", err
			}
		case tar.TypeSymlink:
			if err := safeSymlinkTarget(member, header.Linkname); err != nil {
				return "", err
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				return "", errors.New("official archive symlink collides with another entry")
			}
			if err := os.Symlink(header.Linkname, destination); err != nil {
				return "", err
			}
		case tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo, tar.TypeCont, tar.TypeXHeader, tar.TypeGNUSparse:
			return "", errSpecial
		default:
			return "", errSpecial
		}
	}
	root := filepath.Join(output, "google-cloud-sdk")
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("official archive lacks the canonical SDK root")
	}
	return root, nil
}

func safeArchivePath(name string) (string, error) {
	if name == "" || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") ||
		strings.ContainsRune(name, 0) ||
		(len(name) >= 2 && name[1] == ':' && ((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z'))) {
		return "", errTraversal
	}
	normalized := strings.TrimSuffix(name, "/")
	if len(normalized) > maxPathBytes {
		return "", errTooLarge
	}
	clean := path.Clean(normalized)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") ||
		clean != normalized ||
		(clean != "google-cloud-sdk" && !strings.HasPrefix(clean, "google-cloud-sdk/")) {
		return "", errTraversal
	}
	for _, part := range strings.Split(clean, "/") {
		if part == "" || part == "." || part == ".." {
			return "", errTraversal
		}
	}
	depth := 1 + strings.Count(clean, "/")
	if depth > maxArchiveDepth {
		return "", errTooLarge
	}
	return clean, nil
}

func safeSymlinkTarget(member, target string) error {
	if target == "" || len(target) > maxPathBytes || strings.Contains(target, "\\") ||
		strings.HasPrefix(target, "/") || strings.ContainsRune(target, 0) ||
		(len(target) >= 2 && target[1] == ':' && ((target[0] >= 'A' && target[0] <= 'Z') || (target[0] >= 'a' && target[0] <= 'z'))) {
		return errSymlink
	}
	resolved := []string{}
	if dir := path.Dir(member); dir != "." {
		resolved = strings.Split(dir, "/")
	}
	for _, part := range strings.Split(target, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(resolved) == 0 {
				return errSymlink
			}
			resolved = resolved[:len(resolved)-1]
			continue
		}
		resolved = append(resolved, part)
		if len(resolved) > maxArchiveDepth {
			return errSymlink
		}
	}
	if len(resolved) == 0 || resolved[0] != "google-cloud-sdk" {
		return errSymlink
	}
	return nil
}

func ensureSafeDirectories(root, relativeDirectory string) error {
	if relativeDirectory == "." || relativeDirectory == "" {
		return nil
	}
	current := root
	for _, component := range strings.Split(relativeDirectory, "/") {
		if component == "" || component == "." || component == ".." {
			return errTraversal
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0700); err != nil {
				return err
			}
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("official archive traverses a non-directory parent")
		}
	}
	return nil
}

func writeTarRegular(reader io.Reader, destination string, size int64, executable bool) error {
	if size < 0 || size > maxArchiveMember {
		return errTooLarge
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	written, copyErr := io.CopyN(file, reader, size)
	mode := os.FileMode(0600)
	if executable {
		mode = 0700
	}
	chmodErr := file.Chmod(mode)
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil && errors.Is(copyErr, errTooLarge) {
		return copyErr
	}
	if copyErr != nil || written != size || chmodErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("official archive member could not be extracted exactly")
	}
	return nil
}

func installTreeSHA256(root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errNotDir
	}
	type rec struct {
		rel  string
		kind byte
		size int64
		sum  [32]byte
	}
	var recs []rec
	treeEntries := 1
	var treeBytes int64
	err = filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == root {
			return nil
		}
		rel, relErr := filepath.Rel(root, current)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		treeEntries++
		if treeEntries > maxArchiveEntries {
			return errTooLarge
		}
		listed, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if listed.Mode().IsRegular() {
			if listed.Size() < 0 || listed.Size() > maxArchiveOuter || treeBytes > maxArchiveBytes-listed.Size() {
				return errTooLarge
			}
			treeBytes += listed.Size()
		}
		if entry.Name() == receiptName {
			if filepath.Dir(rel) != "." {
				return errNestedReceipt
			}
			return nil
		}
		switch {
		case listed.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(current)
			if err != nil {
				return err
			}
			if err := safeRuntimeSymlink(rel, target); err != nil {
				return err
			}
			payload := []byte(target)
			recs = append(recs, rec{
				rel: rel, kind: 'L', size: int64(len(payload)), sum: sha256.Sum256(payload),
			})
		case listed.IsDir():
			return nil
		case listed.Mode().IsRegular():
			links, err := fileLinkCount(listed)
			if err != nil || links != 1 {
				return errHardlink
			}
			data, _, err := stableFile(current)
			if err != nil {
				return err
			}
			recs = append(recs, rec{
				rel: rel, kind: 'F', size: int64(len(data)), sum: sha256.Sum256(data),
			})
		default:
			return errSpecial
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].rel < recs[j].rel })
	tree := sha256.New()
	for _, item := range recs {
		_, _ = tree.Write([]byte{item.kind, 0})
		_, _ = tree.Write([]byte(item.rel))
		_, _ = tree.Write([]byte{0})
		_, _ = tree.Write([]byte(strconv.FormatInt(item.size, 10)))
		_, _ = tree.Write([]byte{0})
		_, _ = tree.Write(item.sum[:])
	}
	return hex.EncodeToString(tree.Sum(nil)), nil
}

func safeRuntimeSymlink(rel, target string) error {
	if target == "" || len(target) > maxPathBytes || strings.HasPrefix(target, "/") ||
		strings.Contains(target, "\\") || strings.ContainsRune(target, 0) {
		return errSymlink
	}
	resolved := []string{}
	if dir := path.Dir(rel); dir != "." {
		resolved = strings.Split(dir, "/")
	}
	for _, part := range strings.Split(target, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(resolved) == 0 {
				return errSymlink
			}
			resolved = resolved[:len(resolved)-1]
			continue
		}
		resolved = append(resolved, part)
		if len(resolved) > maxArchiveDepth {
			return errSymlink
		}
	}
	return nil
}

func normalizeTree(root string, cfg provisionConfig) error {
	var directories []string
	err := filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if cfg.ApplyChown {
			if err := os.Lchown(current, int(cfg.ExpectedUID), int(cfg.ExpectedGID)); err != nil {
				return err
			}
			info, err = os.Lstat(current)
			if err != nil {
				return err
			}
		}
		owner, ownerErr := fileOwner(info)
		gid, gidErr := fileGID(info)
		if ownerErr != nil || gidErr != nil || owner != cfg.ExpectedUID || gid != cfg.ExpectedGID {
			return errOwner
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if hasSpecialModeBits(info.Mode()) || (runtime.GOOS == "linux" && info.Mode().Perm() != 0777) {
				return errMode
			}
			return nil
		}
		if info.IsDir() {
			directories = append(directories, current)
			return nil
		}
		if !info.Mode().IsRegular() {
			return errSpecial
		}
		links, err := fileLinkCount(info)
		if err != nil || links != 1 {
			return errHardlink
		}
		mode := sealedDataMode
		if info.Mode().Perm()&0111 != 0 && entry.Name() != receiptName && entry.Name() != custodyArchiveName {
			mode = sealedExecutableMode
		}
		if entry.Name() == receiptName || entry.Name() == custodyArchiveName {
			mode = sealedDataMode
		}
		return chmodAndSync(current, mode, cfg.ExpectedUID, cfg.ExpectedGID)
	})
	if err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		mode := sealedDirectoryMode
		if directories[index] == root && !cfg.RequireLinux {
			// macOS refuses the test-host rename of a non-writable source root.
			// Production is Linux-only and enters publication already at 0555.
			mode = 0700
		}
		if err := chmodAndSync(directories[index], mode, cfg.ExpectedUID, cfg.ExpectedGID); err != nil {
			return err
		}
	}
	return nil
}

func chmodAndSync(pathName string, mode os.FileMode, expectedUID, expectedGID uint32) error {
	info, err := os.Lstat(pathName)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		return errSpecial
	}
	owner, ownerErr := fileOwner(info)
	gid, gidErr := fileGID(info)
	if ownerErr != nil || gidErr != nil || owner != expectedUID || gid != expectedGID {
		return errOwner
	}
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	if info.IsDir() {
		flags |= syscall.O_DIRECTORY
	}
	fd, err := syscall.Open(pathName, flags, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), pathName)
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return errSpecial
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	finished, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	finishedOwner, ownerErr := fileOwner(finished)
	finishedGID, gidErr := fileGID(finished)
	if ownerErr != nil || gidErr != nil || finishedOwner != expectedUID || finishedGID != expectedGID ||
		!exactUnixMode(finished.Mode(), mode) {
		_ = file.Close()
		return errMode
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func requireExecutable(root string, expectedUID, expectedGID uint32) error {
	executable := filepath.Join(root, filepath.FromSlash(executableRel))
	info, err := os.Lstat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("installed SDK lacks the canonical gcloud executable")
	}
	links, err := fileLinkCount(info)
	if err != nil || links != 1 {
		return errHardlink
	}
	owner, ownerErr := fileOwner(info)
	gid, gidErr := fileGID(info)
	if ownerErr != nil || gidErr != nil || owner != expectedUID || gid != expectedGID ||
		!exactUnixMode(info.Mode(), sealedExecutableMode) {
		return errors.New("installed SDK lacks the canonical gcloud executable")
	}
	return nil
}

func syncDirectory(pathName string) error {
	directory, err := os.Open(pathName)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("custody directory could not be synchronized")
	}
	return nil
}

func syncTreeDirectories(root string) error {
	var directories []string
	if err := filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			directories = append(directories, current)
		}
		return nil
	}); err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := syncDirectory(directories[index]); err != nil {
			return err
		}
	}
	return nil
}

func writeExclusive(pathName string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(pathName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(data)
	chmodErr := file.Chmod(mode)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(data) || chmodErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("exclusive custody write was incomplete")
	}
	return nil
}

func renameNoReplace(oldpath, newpath string) error {
	if _, err := os.Lstat(newpath); err == nil {
		return errDestExists
	} else if !os.IsNotExist(err) {
		return err
	}
	if runtime.GOOS == "linux" {
		oldPtr, err := syscall.BytePtrFromString(oldpath)
		if err != nil {
			return err
		}
		newPtr, err := syscall.BytePtrFromString(newpath)
		if err != nil {
			return err
		}
		_, _, errno := syscall.Syscall6(
			linuxSysRenameat2,
			linuxATFdcwd,
			uintptr(unsafe.Pointer(oldPtr)),
			linuxATFdcwd,
			uintptr(unsafe.Pointer(newPtr)),
			linuxRenameNoreplace,
			0,
		)
		runtime.KeepAlive(oldPtr)
		runtime.KeepAlive(newPtr)
		if errno != 0 {
			if errno == syscall.EEXIST {
				return errDestExists
			}
			return errno
		}
		return nil
	}
	return os.Rename(oldpath, newpath)
}

func invokeHelper(dest string, cfg provisionConfig) error {
	if !cfg.InvokeHelper {
		return nil
	}
	helper, err := openVerifiedHelper(cfg)
	if err != nil {
		return err
	}
	defer helper.Close()
	commandPath := cfg.HelperPath
	var extraFiles []*os.File
	if cfg.ExecHelperByFD {
		if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
			return errLinuxOnly
		}
		commandPath = "/proc/self/fd/3"
		extraFiles = []*os.File{helper}
	}
	cmd := exec.Command(commandPath, dest)
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stdin = nil
	cmd.ExtraFiles = extraFiles
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("immutable helper failed: %w", err)
	}
	return nil
}

func verifyHelper(cfg provisionConfig) error {
	helper, err := openVerifiedHelper(cfg)
	if err != nil {
		return err
	}
	return helper.Close()
}

func openVerifiedHelper(cfg provisionConfig) (*os.File, error) {
	if cfg.HelperPath == "" || !filepath.IsAbs(cfg.HelperPath) || filepath.Clean(cfg.HelperPath) != cfg.HelperPath {
		return nil, errHelperPath
	}
	if strings.Contains(cfg.HelperPath, "\\") {
		return nil, errHelperPath
	}
	if cfg.CheckHelperAncestry {
		if err := verifyTrustedDirectoryAncestry(filepath.Dir(cfg.HelperPath), cfg.ExpectedUID, cfg.ExpectedGID, false); err != nil {
			return nil, errHelperPath
		}
	}
	info, err := os.Lstat(cfg.HelperPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errHelper
	}
	links, err := fileLinkCount(info)
	if err != nil || links != 1 {
		return nil, errHelper
	}
	owner, err := fileOwner(info)
	gid, gidErr := fileGID(info)
	if err != nil || gidErr != nil || owner != cfg.ExpectedUID || gid != cfg.ExpectedGID {
		return nil, errHelper
	}
	if !exactUnixMode(info.Mode(), sealedExecutableMode) {
		return nil, errHelper
	}
	data, identity, helper, err := openStableFile(cfg.HelperPath)
	if err != nil || identity.uid != cfg.ExpectedUID || identity.gid != cfg.ExpectedGID ||
		!exactUnixMode(identity.mode, sealedExecutableMode) {
		if helper != nil {
			_ = helper.Close()
		}
		return nil, errHelper
	}
	got := sha256Hex(data)
	if !shaPattern.MatchString(cfg.HelperSHA256) || cfg.HelperSHA256 == zeroSHA || !sameSHA(got, cfg.HelperSHA256) {
		_ = helper.Close()
		return nil, errHelper
	}
	if cfg.RequireHelperELF && !linuxELF64Amd64Static(data) {
		_ = helper.Close()
		return nil, errHelper
	}
	return helper, nil
}

func linuxELF64Amd64Static(data []byte) bool {
	if len(data) < 64 {
		return false
	}
	if data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return false
	}
	if data[4] != 2 || data[5] != 1 {
		return false
	}
	kind := binary.LittleEndian.Uint16(data[16:18])
	if kind != 2 && kind != 3 {
		return false
	}
	if binary.LittleEndian.Uint16(data[18:20]) != 62 {
		return false
	}
	phoff := binary.LittleEndian.Uint64(data[32:40])
	phentsize := binary.LittleEndian.Uint16(data[54:56])
	phnum := binary.LittleEndian.Uint16(data[56:58])
	if phentsize < 56 || phnum == 0 || phnum > 128 {
		return false
	}
	tableBytes := uint64(phentsize) * uint64(phnum)
	if phoff > uint64(len(data)) || tableBytes > uint64(len(data))-phoff {
		return false
	}
	for i := 0; i < int(phnum); i++ {
		off := int(phoff + uint64(i)*uint64(phentsize))
		if binary.LittleEndian.Uint32(data[off:off+4]) == 3 {
			return false
		}
	}
	return true
}

func revalidateRoot(root string, auth receiptAuth, signature string, cfg provisionConfig, existing bool) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errNotDir
	}
	owner, ownerErr := fileOwner(info)
	gid, gidErr := fileGID(info)
	if ownerErr != nil || gidErr != nil || owner != cfg.ExpectedUID || gid != cfg.ExpectedGID {
		return errOwner
	}
	if !exactUnixMode(info.Mode(), sealedDirectoryMode) {
		return errMode
	}
	if err := verifySealedTreeMetadata(root, cfg.ExpectedUID, cfg.ExpectedGID); err != nil {
		return err
	}
	tree, err := installTreeSHA256(root)
	if err != nil || !sameSHA(tree, auth.InstallTreeSHA256) {
		if existing {
			return errIdempotentFail
		}
		return errTree
	}
	if sha256Hex([]byte(root)) != auth.InstallRootSHA256 {
		return errRootHash
	}
	receiptPath := filepath.Join(root, receiptName)
	receiptData, receiptID, err := stableFile(receiptPath)
	if err != nil || receiptID.uid != cfg.ExpectedUID || receiptID.gid != cfg.ExpectedGID ||
		!exactUnixMode(receiptID.mode, sealedDataMode) {
		return errors.New("Google Cloud CLI custody receipt must be immutable mode 0444")
	}
	want, err := canonicalJSON(durableReceiptMap(auth, signature), true)
	if err != nil || !bytes.Equal(receiptData, want) {
		return errors.New("durable custody receipt does not match the verified issuance")
	}
	archivePath := filepath.Join(root, custodyArchiveName)
	archiveData, archiveID, err := stableFile(archivePath)
	if err != nil || archiveID.uid != cfg.ExpectedUID || archiveID.gid != cfg.ExpectedGID ||
		!exactUnixMode(archiveID.mode, sealedDataMode) {
		return errors.New("Google Cloud CLI retained official archive must be immutable mode 0444")
	}
	if !sameSHA(sha256Hex(archiveData), auth.ArchiveSHA256) {
		return errArchiveHash
	}
	if err := requireExecutable(root, cfg.ExpectedUID, cfg.ExpectedGID); err != nil {
		return err
	}
	if cfg.RequireImmutable {
		if runtime.GOOS != "linux" {
			return errLinuxOnly
		}
		if err := verifyLinuxImmutableTree(root, cfg.ExpectedUID, cfg.ExpectedGID); err != nil {
			return err
		}
	}
	return nil
}

func verifyLinuxImmutableTree(root string, expectedUID, expectedGID uint32) error {
	if err := verifySealedTreeMetadata(root, expectedUID, expectedGID); err != nil {
		return err
	}
	return filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errImmutable
		}
		info, err := os.Lstat(current)
		if err != nil {
			return errImmutable
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		ok, err := linuxFileImmutable(current, info)
		if err != nil || !ok {
			return errImmutable
		}
		return nil
	})
}

func verifySealedTreeMetadata(root string, expectedUID, expectedGID uint32) error {
	return filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		owner, ownerErr := fileOwner(info)
		gid, gidErr := fileGID(info)
		if ownerErr != nil || gidErr != nil || owner != expectedUID || gid != expectedGID {
			return errOwner
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if hasSpecialModeBits(info.Mode()) || (runtime.GOOS == "linux" && info.Mode().Perm() != 0777) {
				return errMode
			}
			return nil
		}
		if !sealedPublicModeAllowed(info) {
			return errMode
		}
		return nil
	})
}

func sealedPublicModeAllowed(info os.FileInfo) bool {
	if info.IsDir() {
		return exactUnixMode(info.Mode(), sealedDirectoryMode)
	}
	if info.Mode().IsRegular() {
		return exactUnixMode(info.Mode(), sealedDataMode) || exactUnixMode(info.Mode(), sealedExecutableMode)
	}
	return false
}

func verifyTrustedDirectoryAncestry(start string, expectedUID, expectedGID uint32, requirePublicTraverse bool) error {
	if start == "" || !filepath.IsAbs(start) || filepath.Clean(start) != start {
		return errUnsafePath
	}
	for current := start; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !nonWritableUnixMode(info.Mode()) {
			return errOwner
		}
		owner, ownerErr := fileOwner(info)
		gid, gidErr := fileGID(info)
		if ownerErr != nil || gidErr != nil || !trustedOwnerGroup(owner, gid, expectedUID, expectedGID) {
			return errOwner
		}
		if requirePublicTraverse && info.Mode().Perm()&0005 != 0005 {
			return errMode
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

func verifyProvisionParents(cfg provisionConfig) error {
	for _, directory := range []string{cfg.StagingParent, cfg.RuntimePrefix} {
		if err := verifyTrustedDirectoryAncestry(directory, cfg.ExpectedUID, cfg.ExpectedGID, true); err != nil {
			return err
		}
	}
	return nil
}

func linuxFileImmutable(pathName string, info os.FileInfo) (bool, error) {
	if info.Mode()&os.ModeSymlink != 0 {
		return false, errSymlink
	}
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	if info.IsDir() {
		flags |= syscall.O_DIRECTORY
	}
	fd, err := syscall.Open(pathName, flags, 0)
	if err != nil {
		return false, err
	}
	defer syscall.Close(fd)
	var attrs int32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), linuxFSIOCGetFlags, uintptr(unsafe.Pointer(&attrs)))
	if errno != 0 {
		return false, errno
	}
	return attrs&linuxFSImmutable != 0, nil
}

func requireSameFilesystem(a, b string) error {
	var sa, sb syscall.Stat_t
	if err := syscall.Lstat(a, &sa); err != nil {
		return err
	}
	if err := syscall.Lstat(b, &sb); err != nil {
		return err
	}
	if sa.Dev != sb.Dev {
		return errDevice
	}
	return nil
}

func (lock *stageLock) Close() error {
	if lock == nil || lock.file == nil {
		return errStageLock
	}
	err := lock.file.Close()
	lock.file = nil
	return err
}

func acquireStageLock(stageRoot string, cfg provisionConfig) (*stageLock, error) {
	if cfg.StagingParent == "" || !filepath.IsAbs(cfg.StagingParent) || filepath.Clean(cfg.StagingParent) != cfg.StagingParent ||
		filepath.Dir(stageRoot) != cfg.StagingParent {
		return nil, errStageLock
	}
	treeSHA := strings.TrimPrefix(filepath.Base(stageRoot), stagingDirPrefix)
	if !shaPattern.MatchString(treeSHA) || treeSHA == zeroSHA ||
		filepath.Base(stageRoot) != stagingDirPrefix+treeSHA {
		return nil, errStageLock
	}
	lockPath := stageRoot + stagingLockSuffix
	baseFlags := syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	fd, err := syscall.Open(lockPath, baseFlags|syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL, uint32(stageLockMode.Perm()))
	created := err == nil
	if errors.Is(err, syscall.EEXIST) {
		fd, err = syscall.Open(lockPath, baseFlags|syscall.O_RDONLY, 0)
		if errors.Is(err, syscall.EACCES) {
			fd, err = syscall.Open(lockPath, baseFlags|syscall.O_WRONLY, 0)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errStageLock, err)
	}
	file := os.NewFile(uintptr(fd), lockPath)
	lock := &stageLock{file: file, stageRoot: stageRoot}
	fail := func(cause error) (*stageLock, error) {
		_ = lock.Close()
		return nil, cause
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return fail(errStageActive)
		}
		return fail(fmt.Errorf("%w: %v", errStageLock, err))
	}
	if created {
		if cfg.ApplyChown {
			if err := file.Chown(int(cfg.ExpectedUID), int(cfg.ExpectedGID)); err != nil {
				return fail(fmt.Errorf("%w: %v", errStageLock, err))
			}
		}
	}
	held, err := stageLockIdentity(lock, cfg)
	if err != nil || hasSpecialModeBits(held.Mode()) || held.Mode().Perm()&^stageLockMode.Perm() != 0 {
		return fail(errStageLock)
	}
	needsSync := created
	if !exactUnixMode(held.Mode(), stageLockMode) {
		if err := file.Chmod(stageLockMode); err != nil {
			return fail(fmt.Errorf("%w: %v", errStageLock, err))
		}
		needsSync = true
	}
	if needsSync {
		if err := file.Sync(); err != nil {
			return fail(fmt.Errorf("%w: %v", errStageLock, err))
		}
		if err := syncDirectory(cfg.StagingParent); err != nil {
			return fail(fmt.Errorf("%w: %v", errStageLock, err))
		}
	}
	if err := validateStageLock(lock, cfg); err != nil {
		return fail(err)
	}
	return lock, nil
}

func validateStageLock(lock *stageLock, cfg provisionConfig) error {
	held, err := stageLockIdentity(lock, cfg)
	if err != nil || !exactUnixMode(held.Mode(), stageLockMode) {
		return errStageLock
	}
	return nil
}

func stageLockIdentity(lock *stageLock, cfg provisionConfig) (os.FileInfo, error) {
	if lock == nil || lock.file == nil || lock.stageRoot == "" ||
		lock.file.Name() != lock.stageRoot+stagingLockSuffix {
		return nil, errStageLock
	}
	held, err := lock.file.Stat()
	if err != nil || !held.Mode().IsRegular() {
		return nil, errStageLock
	}
	listed, err := os.Lstat(lock.file.Name())
	if err != nil || !listed.Mode().IsRegular() || listed.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(held, listed) || held.Mode() != listed.Mode() {
		return nil, errStageLock
	}
	links, linksErr := fileLinkCount(held)
	owner, ownerErr := fileOwner(held)
	gid, gidErr := fileGID(held)
	device, deviceErr := fileDevice(held)
	parent, parentErr := os.Lstat(cfg.StagingParent)
	var parentDevice uint64
	var parentDeviceErr error
	if parentErr == nil {
		parentDevice, parentDeviceErr = fileDevice(parent)
	}
	if linksErr != nil || ownerErr != nil || gidErr != nil || deviceErr != nil ||
		parentErr != nil || parentDeviceErr != nil || links != 1 || owner != cfg.ExpectedUID ||
		gid != cfg.ExpectedGID || device != parentDevice {
		return nil, errStageLock
	}
	return held, nil
}

func validatePrivateStageRoot(stageRoot string, cfg provisionConfig) error {
	info, err := os.Lstat(stageRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		!exactUnixMode(info.Mode(), privateStageMode) {
		return errors.New("private staging root has an unsafe shape")
	}
	owner, ownerErr := fileOwner(info)
	gid, gidErr := fileGID(info)
	if ownerErr != nil || gidErr != nil || owner != cfg.ExpectedUID || gid != cfg.ExpectedGID {
		return errors.New("private staging root has unsafe custody")
	}
	return requireSameFilesystem(cfg.StagingParent, stageRoot)
}

func cleanupPrivateStageIfPresent(stageRoot string, cfg provisionConfig, lock *stageLock) error {
	if err := validateStageLock(lock, cfg); err != nil || lock.stageRoot != stageRoot {
		return errStageLock
	}
	exists, err := pathExists(stageRoot)
	if err != nil || !exists {
		return err
	}
	rootInfo, err := os.Lstat(stageRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 ||
		hasSpecialModeBits(rootInfo.Mode()) || rootInfo.Mode().Perm()&^privateStageMode.Perm() != 0 {
		return errors.New("stale private staging root has an unsafe shape")
	}
	rootOwner, ownerErr := fileOwner(rootInfo)
	rootGID, gidErr := fileGID(rootInfo)
	rootDevice, deviceErr := fileDevice(rootInfo)
	if ownerErr != nil || gidErr != nil || deviceErr != nil ||
		rootOwner != cfg.ExpectedUID || rootGID != cfg.ExpectedGID {
		return errors.New("stale private staging root has unsafe custody")
	}
	if err := requireSameFilesystem(cfg.StagingParent, stageRoot); err != nil {
		return err
	}
	if !exactUnixMode(rootInfo.Mode(), privateStageMode) {
		if err := os.Chmod(stageRoot, privateStageMode); err != nil {
			return err
		}
		normalized, err := os.Lstat(stageRoot)
		if err != nil || !os.SameFile(rootInfo, normalized) || !normalized.IsDir() ||
			normalized.Mode()&os.ModeSymlink != 0 || !exactUnixMode(normalized.Mode(), privateStageMode) {
			return errors.New("stale private staging root could not be normalized safely")
		}
		normalizedOwner, ownerErr := fileOwner(normalized)
		normalizedGID, gidErr := fileGID(normalized)
		normalizedDevice, deviceErr := fileDevice(normalized)
		if ownerErr != nil || gidErr != nil || deviceErr != nil ||
			normalizedOwner != cfg.ExpectedUID || normalizedGID != cfg.ExpectedGID || normalizedDevice != rootDevice {
			return errors.New("stale private staging root changed during normalization")
		}
		if err := syncDirectory(stageRoot); err != nil {
			return err
		}
		if err := syncDirectory(cfg.StagingParent); err != nil {
			return err
		}
		rootInfo = normalized
	}
	var entries []string
	err = filepath.WalkDir(stageRoot, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		owner, ownerErr := fileOwner(info)
		gid, gidErr := fileGID(info)
		device, deviceErr := fileDevice(info)
		if ownerErr != nil || gidErr != nil || deviceErr != nil || owner != cfg.ExpectedUID ||
			gid != cfg.ExpectedGID || device != rootDevice {
			return errors.New("stale private staging entry has unsafe custody")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if hasSpecialModeBits(info.Mode()) {
				return errMode
			}
		} else {
			if !info.IsDir() && !info.Mode().IsRegular() {
				return errSpecial
			}
			if !nonWritableUnixMode(info.Mode()) {
				return errMode
			}
			if info.Mode().IsRegular() {
				links, err := fileLinkCount(info)
				if err != nil || links != 1 {
					return errHardlink
				}
			}
		}
		entries = append(entries, current)
		return nil
	})
	if err != nil {
		return err
	}
	if err := validateStageLock(lock, cfg); err != nil {
		return err
	}
	for index := len(entries) - 1; index >= 0; index-- {
		if err := os.Remove(entries[index]); err != nil {
			return err
		}
	}
	return syncDirectory(cfg.StagingParent)
}

func pathExists(pathName string) (bool, error) {
	_, err := os.Lstat(pathName)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sameSHA(got, want string) bool {
	if len(got) != 64 || len(want) != 64 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func hasSpecialModeBits(mode os.FileMode) bool {
	return mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0
}

func exactUnixMode(mode, expected os.FileMode) bool {
	return mode.Perm() == expected.Perm() && !hasSpecialModeBits(mode)
}

func nonWritableUnixMode(mode os.FileMode) bool {
	return mode.Perm()&0022 == 0 && !hasSpecialModeBits(mode)
}

func trustedOwnerGroup(uid, gid, expectedUID, expectedGID uint32) bool {
	return (uid == expectedUID && gid == expectedGID) || (uid == 0 && gid == 0)
}

func fileLinkCount(info os.FileInfo) (uint64, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, errors.New("stat type is unsupported")
	}
	return uint64(st.Nlink), nil
}

func fileOwner(info os.FileInfo) (uint32, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, errors.New("stat type is unsupported")
	}
	return st.Uid, nil
}

func fileGID(info os.FileInfo) (uint32, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, errors.New("stat type is unsupported")
	}
	return st.Gid, nil
}

func fileDevice(info os.FileInfo) (uint64, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, errors.New("stat type is unsupported")
	}
	return uint64(st.Dev), nil
}

func strictDecode(data []byte, target any) error {
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are forbidden")
		}
		return err
	}
	return nil
}

func decodeExactObject(data []byte, expected []string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := strictDecode(data, &fields); err != nil {
		return nil, err
	}
	if len(fields) != len(expected) {
		return nil, errSchema
	}
	for _, key := range expected {
		if _, found := fields[key]; !found {
			return nil, errSchema
		}
	}
	return fields, nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, isDelim := token.(json.Delim)
		if !isDelim {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if _, found := seen[key]; found {
					return fmt.Errorf("%w: %q", errDuplicateJSON, key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errors.New("JSON object is not closed")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errors.New("JSON array is not closed")
			}
		default:
			return errors.New("unexpected JSON closing delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are forbidden")
		}
		return err
	}
	return nil
}
