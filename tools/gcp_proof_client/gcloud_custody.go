package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	pathpkg "path"
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

var (
	maxGcloudArchiveOuter   = int64(2 * 1024 * 1024 * 1024)
	maxGcloudArchiveMember  = int64(512 * 1024 * 1024)
	maxGcloudArchiveEntries = 200000
	maxGcloudArchiveRatio   = int64(100)
	maxGcloudArchiveBytes   = int64(4 * 1024 * 1024 * 1024)
	maxGcloudArchiveDepth   = 32
	maxGcloudPathBytes      = 1024
	maxGcloudCredential     = 256 * 1024
	maxGcloudSubjectToken   = 256 * 1024
	maxGcloudAuthority      = 64 * 1024
	maxGcloudCommandOutput  = 4 * 1024 * 1024
)

var (
	gcloudAccountPattern  = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,64}$`)
	wifEmailPattern       = regexp.MustCompile(`^https://iamcredentials\.googleapis\.com/v1/projects/-/serviceAccounts/([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,64}):generateAccessToken$`)
	wifAudiencePattern    = regexp.MustCompile(`^//iam\.googleapis\.com/projects/[0-9]{1,20}/locations/global/workloadIdentityPools/[A-Za-z0-9-]{1,64}/providers/[A-Za-z0-9-]{1,64}$`)
	saPrivateKeyPattern   = regexp.MustCompile(`^-----BEGIN (?:RSA )?PRIVATE KEY-----\n[A-Za-z0-9+/=_\n]+\n-----END (?:RSA )?PRIVATE KEY-----\n?$`)
	saPrivateKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	saClientIDPattern     = regexp.MustCompile(`^[0-9]{6,32}$`)
	gcloudIssuancePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	gcloudUTCSeconds      = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

const (
	gcloudServiceAccountKind    = "service_account"
	gcloudWorkloadIdentityKind  = "workload_identity"
	wifTokenURL                 = "https://sts.googleapis.com/v1/token"
	wifSubjectTokenType         = "urn:ietf:params:oauth:token-type:jwt"
	saAuthURI                   = "https://accounts.google.com/o/oauth2/auth"
	saTokenURI                  = "https://oauth2.googleapis.com/token"
	gcloudOwnerAuthorityPath    = "/var/lib/winsvpn/gcloud-owner-authority-v1.json"
	gcloudOwnerIssuancePath     = "/var/lib/winsvpn/gcloud-owner-issuance.json"
	gcloudOwnerAuthority        = "winsvpn-gcloud-owner-authority-v1"
	gcloudOwnerIssuance         = "winsvpn-gcloud-owner-issuance-v1"
	gcloudOwnerIssuer           = "winsvpn-owner"
	gcloudOwnerAlgorithm        = "ed25519"
	gcloudOwnerSignatureDomain  = "winsvpn-gcloud-owner-receipt-v1\n"
	gcloudProductionRuntimeRoot = "/var/lib/winsvpn/gcloud-runtime-v1"
	gcloudBundledPythonRelative = "platform/bundledpythonunix/bin/python3.14"
	linuxCapImmutable           = uint(9)
	linuxFSIOCGetFlags          = uintptr(0x80086601)
	linuxFSImmutable            = int32(0x00000010)
)

var (
	saCredentialKeys  = []string{"type", "project_id", "private_key_id", "private_key", "client_email", "client_id", "auth_uri", "token_uri"}
	wifCredentialKeys = []string{"type", "audience", "subject_token_type", "token_url", "service_account_impersonation_url", "credential_source"}
)

type gcloudReviewPin struct {
	version, platform, archiveName, archiveSHA256 string
}

func compiledGcloudReviewPin() gcloudReviewPin {
	return gcloudReviewPin{
		version:       reviewedGcloudVersion,
		platform:      reviewedGcloudPlatform,
		archiveName:   reviewedGcloudArchiveName,
		archiveSHA256: reviewedGcloudArchiveSHA256,
	}
}

type gcloudReceipt struct {
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
	IssuanceSignature string `json:"issuance_signature"`
}

type gcloudReceiptAuthorizationDocument struct {
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

type gcloudOwnerIssuanceDocument struct {
	Contract      string          `json:"contract"`
	SchemaVersion int             `json:"schema_version"`
	Issuer        string          `json:"issuer"`
	Algorithm     string          `json:"algorithm"`
	KeyID         string          `json:"key_id"`
	Receipt       json.RawMessage `json:"receipt"`
	Signature     string          `json:"signature"`
}

type gcloudOwnerAuthorityDocument struct {
	Contract      string `json:"contract"`
	SchemaVersion int    `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	PublicKey     string `json:"public_key"`
	OwnerUID      uint32 `json:"owner_uid"`
}

type stableFileIdentity struct {
	info os.FileInfo
	mode os.FileMode
	uid  uint32
}

type gcloudAuthorityFileCustody struct {
	configuredPath, canonicalPath string
	data                          []byte
	identity                      stableFileIdentity
}

type gcloudOwnerAuthorizationCustody struct {
	authority, issuance gcloudAuthorityFileCustody
	freshAuthorization  []byte
	authorityOwner      uint32
}

type gcloudIdentityInput struct {
	kind, path, expectedAccount, expectedProject string
}

type boundGcloudIdentity struct {
	kind, expectedAccount, expectedProject string
	data                                   []byte
	subjectToken                           []byte
}

type serviceAccountCredential struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	ClientID     string `json:"client_id"`
	AuthURI      string `json:"auth_uri"`
	TokenURI     string `json:"token_uri"`
}

type workloadIdentityCredential struct {
	Type                           string          `json:"type"`
	Audience                       string          `json:"audience"`
	SubjectTokenType               string          `json:"subject_token_type"`
	TokenURL                       string          `json:"token_url"`
	ServiceAccountImpersonationURL string          `json:"service_account_impersonation_url"`
	CredentialSource               json.RawMessage `json:"credential_source"`
}

type verifiedGcloud struct {
	executable, root, receiptPath, archivePath   string
	receiptSHA256, treeSHA256, runtimeTreeSHA256 string
	executableSHA256, archiveSHA256              string
	executableIdentity, receiptIdentity          stableFileIdentity
	archiveIdentity                              stableFileIdentity
	archiveData                                  []byte
	pin                                          gcloudReviewPin
	ownerAuthorization                           gcloudOwnerAuthorizationCustody
	identity                                     *boundGcloudIdentity
	productionSealed                             bool
}

type descriptorCommandRunner interface {
	runFromDescriptor(context.Context, *os.File, []string, []string) (commandResult, error)
}

type heldExecutableRunner interface {
	runFromHeldExecutable(context.Context, *os.File, *os.File, []string, []string) (commandResult, error)
}

type custodyDescriptorRunner interface {
	runFromCustody(context.Context, *os.File, *os.File, *os.File, *os.File, string, []string, []string) (commandResult, error)
}

type boundedBuffer struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.exceeded || b.buf.Len()+len(p) > b.limit {
		b.exceeded = true
		return 0, errors.New("Google Cloud CLI command output exceeds the bound")
	}
	return b.buf.Write(p)
}

func (b *boundedBuffer) bytes() []byte {
	return append([]byte(nil), b.buf.Bytes()...)
}

func procSelfFd(fd int) string {
	return "/proc/self/fd/" + strconv.Itoa(fd)
}

type countingReader struct {
	r          io.Reader
	n          int64
	compressed int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	remainingAgg := maxGcloudArchiveBytes - c.n
	remainingRatio := c.compressed*maxGcloudArchiveRatio - c.n
	remaining := remainingAgg
	if remainingRatio < remaining {
		remaining = remainingRatio
	}
	if remaining <= 0 {
		return 0, errors.New("official archive compression ratio or expanded size exceeds the limit")
	}
	if int64(len(p)) > remaining+1 {
		p = p[:remaining+1]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > maxGcloudArchiveBytes {
		return 0, errors.New("official archive expanded size exceeds the aggregate limit")
	}
	if c.compressed <= 0 || c.n > c.compressed*maxGcloudArchiveRatio {
		return 0, errors.New("official archive compression ratio exceeds the limit")
	}
	return n, err
}

func (subprocessRunner) runFromDescriptor(ctx context.Context, root *os.File, argv []string, env []string) (commandResult, error) {
	executable, err := openGcloudFromHeldRoot(root)
	if err != nil {
		return commandResult{}, err
	}
	defer executable.Close()
	workingDirectory, err := heldRootWorkingDirectory(root)
	if err != nil {
		return commandResult{}, err
	}
	return runHeldDescriptors(ctx, executable, root, nil, nil, workingDirectory, argv, env)
}

func (subprocessRunner) runFromHeldExecutable(ctx context.Context, executable, root *os.File, argv []string, env []string) (commandResult, error) {
	workingDirectory, err := heldRootWorkingDirectory(root)
	if err != nil {
		return commandResult{}, err
	}
	return runHeldDescriptors(ctx, executable, root, nil, nil, workingDirectory, argv, env)
}

func (subprocessRunner) runFromCustody(ctx context.Context, executable, root, credential, subjectToken *os.File, workingDirectory string, argv []string, env []string) (commandResult, error) {
	return runHeldDescriptors(ctx, executable, root, credential, subjectToken, workingDirectory, argv, env)
}

func heldRootWorkingDirectory(root *os.File) (string, error) {
	if root == nil {
		return "", errors.New("descriptor-bound Google Cloud CLI execution requires a held root descriptor")
	}
	workingDirectory := filepath.Clean(root.Name())
	if !filepath.IsAbs(workingDirectory) || root.Name() != workingDirectory {
		return "", errors.New("descriptor-bound Google Cloud CLI working directory is invalid")
	}
	visible, err := os.Lstat(workingDirectory)
	if err != nil || visible.Mode()&os.ModeSymlink != 0 || !visible.IsDir() {
		return "", errors.New("descriptor-bound Google Cloud CLI working directory is invalid")
	}
	held, err := root.Stat()
	if err != nil || !held.IsDir() || !os.SameFile(visible, held) {
		return "", errors.New("descriptor-bound Google Cloud CLI working directory does not match the held root")
	}
	return workingDirectory, nil
}

func openGcloudFromHeldRoot(root *os.File) (*os.File, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("descriptor-bound Google Cloud CLI execution requires Linux")
	}
	if root == nil {
		return nil, errors.New("private Google Cloud CLI root descriptor could not be held")
	}
	info, err := root.Stat()
	if err != nil || !info.IsDir() {
		return nil, errors.New("private Google Cloud CLI root descriptor is not a directory")
	}
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		return nil, errors.New("descriptor-bound Google Cloud CLI execution requires procfs")
	}
	bin, err := os.Open(procSelfFd(int(root.Fd())) + "/bin")
	runtime.KeepAlive(root)
	if err != nil {
		return nil, errors.New("private Google Cloud CLI executable descriptor could not be held")
	}
	defer bin.Close()
	binInfo, err := bin.Stat()
	if err != nil || !binInfo.IsDir() {
		return nil, errors.New("private Google Cloud CLI executable descriptor could not be held")
	}
	file, err := os.Open(procSelfFd(int(bin.Fd())) + "/gcloud")
	runtime.KeepAlive(bin)
	if err != nil {
		return nil, errors.New("private Google Cloud CLI executable descriptor could not be held")
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("private Google Cloud CLI executable descriptor could not be held")
	}
	return file, nil
}

func runHeldDescriptors(ctx context.Context, executable, root, credential, subjectToken *os.File, workingDirectory string, argv []string, env []string) (commandResult, error) {
	if runtime.GOOS != "linux" {
		return commandResult{}, errors.New("descriptor-bound Google Cloud CLI execution requires Linux")
	}
	if executable == nil || root == nil || credential == nil {
		return commandResult{}, errors.New("descriptor-bound Google Cloud CLI execution requires held executable and root descriptors")
	}
	if len(argv) == 0 {
		return commandResult{}, errors.New("empty command argv")
	}
	if env == nil {
		return commandResult{}, errors.New("Google Cloud CLI execution requires an isolated environment")
	}
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		return commandResult{}, errors.New("descriptor-bound Google Cloud CLI execution requires procfs")
	}
	execInfo, err := executable.Stat()
	if err != nil || !execInfo.Mode().IsRegular() {
		return commandResult{}, errors.New("held Google Cloud CLI executable descriptor is not a regular file")
	}
	links, err := fileLinkCount(execInfo)
	if err != nil || links != 1 {
		return commandResult{}, errors.New("Google Cloud CLI custody file must have exactly one link")
	}
	if _, err := fileOwner(execInfo); err != nil {
		return commandResult{}, err
	}
	rootInfo, err := root.Stat()
	if err != nil || !rootInfo.IsDir() {
		return commandResult{}, errors.New("held Google Cloud CLI root descriptor is not a directory")
	}
	visibleWorkingDirectory, err := os.Lstat(workingDirectory)
	if err != nil || visibleWorkingDirectory.Mode()&os.ModeSymlink != 0 || !visibleWorkingDirectory.IsDir() ||
		!filepath.IsAbs(workingDirectory) || filepath.Clean(workingDirectory) != workingDirectory ||
		!os.SameFile(rootInfo, visibleWorkingDirectory) {
		return commandResult{}, errors.New("descriptor-bound Google Cloud CLI working directory does not match the held root")
	}
	commandPath := procSelfFd(3)
	cmd := exec.CommandContext(ctx, commandPath, argv[1:]...)
	cmd.Args[0] = commandPath
	cmd.ExtraFiles = []*os.File{executable, root, credential}
	if subjectToken != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, subjectToken)
	}
	cmd.Env = append([]string{}, env...)
	// Go resolves Cmd.Dir before ExtraFiles are renumbered to child fds 3+.
	// Use the already verified immutable literal root for chdir while retaining
	// descriptor-only executable, SDK, and credential access after exec.
	cmd.Dir = workingDirectory
	cmd.Stdin = nil
	stdout := &boundedBuffer{limit: maxGcloudCommandOutput}
	stderr := &boundedBuffer{limit: maxGcloudCommandOutput}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	if stdout.exceeded || stderr.exceeded {
		return commandResult{}, errors.New("Google Cloud CLI command output exceeds the bound")
	}
	if err == nil {
		return commandResult{stdout: stdout.bytes(), exitCode: 0}, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return commandResult{
			stdout:   stdout.bytes(),
			stderr:   stderr.bytes(),
			exitCode: exitErr.ExitCode(),
		}, nil
	}
	return commandResult{}, err
}

func fileLinkCount(info os.FileInfo) (uint64, error) {
	if info == nil {
		return 0, errors.New("Google Cloud CLI custody file link count is unavailable")
	}
	value, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("Google Cloud CLI custody file link count is unavailable")
	}
	return uint64(value.Nlink), nil
}

func fileOwner(info os.FileInfo) (uint32, error) {
	if info == nil {
		return 0, errors.New("Google Cloud CLI custody file owner is unavailable")
	}
	value, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("Google Cloud CLI custody file owner is unavailable")
	}
	return value.Uid, nil
}

func sameStableFile(left, right stableFileIdentity) bool {
	if left.info == nil || right.info == nil || !os.SameFile(left.info, right.info) {
		return false
	}
	return left.info.Size() == right.info.Size() &&
		left.info.ModTime() == right.info.ModTime() &&
		left.mode == right.mode &&
		left.uid == right.uid
}

func stableFile(path string) ([]byte, stableFileIdentity, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, stableFileIdentity{}, errors.New("Google Cloud CLI custody file is not a regular file")
	}
	links, err := fileLinkCount(before)
	if err != nil || links != 1 {
		return nil, stableFileIdentity{}, errors.New("Google Cloud CLI custody file must have exactly one link")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, stableFileIdentity{}, errors.New("Google Cloud CLI custody file is unreadable")
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, stableFileIdentity{}, errors.New("Google Cloud CLI custody file identity is unreadable")
	}
	data, readErr := io.ReadAll(file)
	finished, statErr := file.Stat()
	closeErr := file.Close()
	after, pathErr := os.Lstat(path)
	beforeLinks, beforeLinkErr := fileLinkCount(before)
	openedLinks, openedLinkErr := fileLinkCount(opened)
	finishedLinks, finishedLinkErr := fileLinkCount(finished)
	afterLinks, afterLinkErr := fileLinkCount(after)
	beforeOwner, beforeOwnerErr := fileOwner(before)
	openedOwner, openedOwnerErr := fileOwner(opened)
	finishedOwner, finishedOwnerErr := fileOwner(finished)
	afterOwner, afterOwnerErr := fileOwner(after)
	if readErr != nil || statErr != nil || closeErr != nil || pathErr != nil ||
		beforeLinkErr != nil || openedLinkErr != nil || finishedLinkErr != nil || afterLinkErr != nil ||
		beforeOwnerErr != nil || openedOwnerErr != nil || finishedOwnerErr != nil || afterOwnerErr != nil ||
		beforeLinks != 1 || openedLinks != 1 || finishedLinks != 1 || afterLinks != 1 ||
		beforeOwner != openedOwner || openedOwner != finishedOwner || finishedOwner != afterOwner ||
		!os.SameFile(before, opened) || !os.SameFile(opened, finished) || !os.SameFile(finished, after) ||
		before.Size() != opened.Size() || opened.Size() != finished.Size() || finished.Size() != after.Size() ||
		before.ModTime() != opened.ModTime() || opened.ModTime() != finished.ModTime() || finished.ModTime() != after.ModTime() ||
		before.Mode() != opened.Mode() || opened.Mode() != finished.Mode() || finished.Mode() != after.Mode() {
		return nil, stableFileIdentity{}, errors.New("Google Cloud CLI custody file changed while read")
	}
	return data, stableFileIdentity{info: finished, mode: finished.Mode(), uid: finishedOwner}, nil
}

func stableExternalAuthorityFile(path string, expectedOwner uint32) (gcloudAuthorityFileCustody, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return gcloudAuthorityFileCustody{}, errors.New("owner-blocked: Google Cloud CLI owner authority is unavailable")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(resolved) {
		return gcloudAuthorityFileCustody{}, errors.New("owner-blocked: Google Cloud CLI owner authority is unavailable")
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return gcloudAuthorityFileCustody{}, errors.New("owner-blocked: Google Cloud CLI owner authority is unavailable")
	}
	for directory := filepath.Dir(resolved); ; directory = filepath.Dir(directory) {
		info, statErr := os.Lstat(directory)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return gcloudAuthorityFileCustody{}, errors.New("owner-blocked: Google Cloud CLI owner authority ancestry is not custodied")
		}
		owner, ownerErr := fileOwner(info)
		if ownerErr != nil || (owner != 0 && owner != expectedOwner) {
			return gcloudAuthorityFileCustody{}, errors.New("owner-blocked: Google Cloud CLI owner authority ancestry is not custodied")
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
	}
	data, identity, err := stableFile(resolved)
	if err != nil || identity.uid != expectedOwner || identity.mode.Perm()&0222 != 0 || len(data) == 0 || len(data) > maxGcloudAuthority {
		return gcloudAuthorityFileCustody{}, errors.New("owner-blocked: Google Cloud CLI owner authority is not custodied")
	}
	return gcloudAuthorityFileCustody{
		configuredPath: path,
		canonicalPath:  resolved,
		data:           append([]byte(nil), data...),
		identity:       identity,
	}, nil
}

func sameGcloudAuthorityFileCustody(current, fixed gcloudAuthorityFileCustody) bool {
	return current.configuredPath == fixed.configuredPath &&
		current.canonicalPath == fixed.canonicalPath &&
		sameStableFile(current.identity, fixed.identity) &&
		bytes.Equal(current.data, fixed.data)
}

func gcloudReceiptAuthorization(receipt gcloudReceipt) map[string]any {
	return map[string]any{
		"schema_version": receipt.SchemaVersion, "contract": receipt.Contract,
		"version": receipt.Version, "platform": receipt.Platform,
		"archive_name": receipt.ArchiveName, "archive_sha256": receipt.ArchiveSHA256,
		"install_tree_sha256": receipt.InstallTreeSHA256, "executable_path": receipt.ExecutablePath,
		"install_root_sha256": receipt.InstallRootSHA256, "issued_utc": receipt.IssuedUTC,
		"expires_utc": receipt.ExpiresUTC, "issuance_id": receipt.IssuanceID,
		"authority_key_id": receipt.AuthorityKeyID, "controller_sha256": receipt.ControllerSHA256,
		"manifest_sha256": receipt.ManifestSHA256, "trust_anchor_sha256": receipt.TrustAnchorSHA256,
	}
}

func (document gcloudReceiptAuthorizationDocument) signedReceipt(signature string) gcloudReceipt {
	return gcloudReceipt{
		SchemaVersion: document.SchemaVersion, Contract: document.Contract,
		Version: document.Version, Platform: document.Platform,
		ArchiveName: document.ArchiveName, ArchiveSHA256: document.ArchiveSHA256,
		InstallTreeSHA256: document.InstallTreeSHA256, ExecutablePath: document.ExecutablePath,
		InstallRootSHA256: document.InstallRootSHA256, IssuedUTC: document.IssuedUTC,
		ExpiresUTC: document.ExpiresUTC, IssuanceID: document.IssuanceID,
		AuthorityKeyID: document.AuthorityKeyID, ControllerSHA256: document.ControllerSHA256,
		ManifestSHA256: document.ManifestSHA256, TrustAnchorSHA256: document.TrustAnchorSHA256,
		IssuanceSignature: signature,
	}
}

func gcloudReceiptSignatureMessage(receipt gcloudReceipt) ([]byte, error) {
	canonical, err := canonicalJSON(gcloudReceiptAuthorization(receipt), false)
	if err != nil {
		return nil, errors.New("Google Cloud CLI custody receipt authorization is invalid")
	}
	return append([]byte(gcloudOwnerSignatureDomain), canonical...), nil
}

func validateGcloudReceiptWindow(receipt gcloudReceipt, requireFresh bool, now time.Time) error {
	if !gcloudUTCSeconds.MatchString(receipt.IssuedUTC) || !gcloudUTCSeconds.MatchString(receipt.ExpiresUTC) {
		return errors.New("Google Cloud CLI custody receipt timestamp is invalid")
	}
	issued, issuedErr := time.Parse("2006-01-02T15:04:05Z", receipt.IssuedUTC)
	expires, expiresErr := time.Parse("2006-01-02T15:04:05Z", receipt.ExpiresUTC)
	now = now.UTC()
	if issuedErr != nil || expiresErr != nil || issued.Year() < 2026 ||
		!expires.After(issued) || expires.Sub(issued) > 6*time.Hour {
		return errors.New("Google Cloud CLI custody receipt issuance is stale, expired, or invalid")
	}
	if requireFresh && (!expires.After(now) ||
		issued.After(now.Add(5*time.Minute)) || now.Sub(issued) > 6*time.Hour) {
		return errors.New("Google Cloud CLI custody receipt issuance is stale, expired, or invalid")
	}
	return nil
}

func verifyGcloudReceiptAuthority(receipt gcloudReceipt, root string, authorityCustody gcloudAuthorityFileCustody, expectedOwner uint32, requireFresh bool, now time.Time) error {
	if err := validateGcloudReceiptWindow(receipt, requireFresh, now); err != nil {
		return err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return errors.New("Google Cloud CLI custody install root is unreadable")
	}
	resolvedRoot, err = filepath.Abs(resolvedRoot)
	if err != nil || receipt.InstallRootSHA256 != sha256Hex([]byte(resolvedRoot)) {
		return errors.New("Google Cloud CLI custody receipt install root is invalid")
	}
	if !gcloudIssuancePattern.MatchString(receipt.IssuanceID) ||
		!shaPattern.MatchString(receipt.AuthorityKeyID) ||
		!shaPattern.MatchString(receipt.ControllerSHA256) || receipt.ControllerSHA256 == strings.Repeat("0", 64) ||
		!shaPattern.MatchString(receipt.ManifestSHA256) || receipt.ManifestSHA256 == strings.Repeat("0", 64) ||
		!shaPattern.MatchString(receipt.TrustAnchorSHA256) || receipt.TrustAnchorSHA256 == strings.Repeat("0", 64) {
		return errors.New("Google Cloud CLI custody receipt issuance fields are invalid")
	}
	if authorityCustody.identity.info == nil || authorityCustody.identity.uid != expectedOwner ||
		authorityCustody.identity.mode.Perm()&0222 != 0 || len(authorityCustody.data) == 0 || len(authorityCustody.data) > maxGcloudAuthority {
		return errors.New("owner-blocked: Google Cloud CLI owner authority is not custodied")
	}
	if _, err := decodeExactObject(authorityCustody.data, []string{"contract", "schema_version", "algorithm", "key_id", "public_key", "owner_uid"}, nil); err != nil {
		return errors.New("owner-blocked: Google Cloud CLI owner authority schema is invalid")
	}
	var authority gcloudOwnerAuthorityDocument
	if err := strictDecode(authorityCustody.data, &authority); err != nil || authority.SchemaVersion != 1 ||
		authority.Contract != gcloudOwnerAuthority || authority.Algorithm != gcloudOwnerAlgorithm ||
		authority.OwnerUID != expectedOwner || !shaPattern.MatchString(authority.KeyID) {
		return errors.New("owner-blocked: Google Cloud CLI owner authority is invalid")
	}
	publicKey, keyErr := hex.DecodeString(authority.PublicKey)
	signature, signatureErr := hex.DecodeString(receipt.IssuanceSignature)
	message, messageErr := gcloudReceiptSignatureMessage(receipt)
	if keyErr != nil || signatureErr != nil || messageErr != nil || len(publicKey) != ed25519.PublicKeySize ||
		len(signature) != ed25519.SignatureSize || authority.KeyID != sha256Hex(publicKey) ||
		receipt.AuthorityKeyID != authority.KeyID || !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		return errors.New("owner-blocked: Google Cloud CLI custody receipt signature is invalid")
	}
	return nil
}

func sameDurableGcloudAuthorization(durable, fresh gcloudReceipt) bool {
	left := gcloudReceiptAuthorization(durable)
	right := gcloudReceiptAuthorization(fresh)
	for _, key := range []string{"issued_utc", "expires_utc", "issuance_id"} {
		delete(left, key)
		delete(right, key)
	}
	leftCanonical, leftErr := canonicalJSON(left, false)
	rightCanonical, rightErr := canonicalJSON(right, false)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftCanonical, rightCanonical)
}

func verifyFreshGcloudIssuance(durable gcloudReceipt, root string, issuanceCustody, authorityCustody gcloudAuthorityFileCustody, expectedOwner uint32, now time.Time) ([]byte, error) {
	if issuanceCustody.identity.info == nil || issuanceCustody.identity.uid != expectedOwner ||
		issuanceCustody.identity.mode.Perm()&0222 != 0 || len(issuanceCustody.data) == 0 || len(issuanceCustody.data) > maxGcloudAuthority {
		return nil, errors.New("owner-blocked: fresh Google Cloud CLI owner issuance is not custodied")
	}
	if _, err := decodeExactObject(issuanceCustody.data, []string{
		"contract", "schema_version", "issuer", "algorithm", "key_id", "receipt", "signature",
	}, nil); err != nil {
		return nil, errors.New("owner-blocked: fresh Google Cloud CLI owner issuance schema is invalid")
	}
	var issuance gcloudOwnerIssuanceDocument
	if err := strictDecode(issuanceCustody.data, &issuance); err != nil ||
		issuance.SchemaVersion != 1 || issuance.Contract != gcloudOwnerIssuance ||
		issuance.Issuer != gcloudOwnerIssuer || issuance.Algorithm != gcloudOwnerAlgorithm ||
		!shaPattern.MatchString(issuance.KeyID) || len(issuance.Receipt) == 0 {
		return nil, errors.New("owner-blocked: fresh Google Cloud CLI owner issuance is invalid")
	}
	if _, err := decodeExactObject(issuance.Receipt, []string{
		"schema_version", "contract", "version", "platform", "archive_name", "archive_sha256",
		"install_tree_sha256", "executable_path", "install_root_sha256", "issued_utc", "expires_utc",
		"issuance_id", "authority_key_id", "controller_sha256", "manifest_sha256", "trust_anchor_sha256",
	}, nil); err != nil {
		return nil, errors.New("owner-blocked: fresh Google Cloud CLI owner issuance receipt schema is invalid")
	}
	var authorization gcloudReceiptAuthorizationDocument
	if err := strictDecode(issuance.Receipt, &authorization); err != nil {
		return nil, errors.New("owner-blocked: fresh Google Cloud CLI owner issuance receipt is invalid")
	}
	fresh := authorization.signedReceipt(issuance.Signature)
	if issuance.KeyID != fresh.AuthorityKeyID {
		return nil, errors.New("owner-blocked: fresh Google Cloud CLI owner issuance signature is invalid")
	}
	if err := verifyGcloudReceiptAuthority(fresh, root, authorityCustody, expectedOwner, true, now); err != nil {
		return nil, fmt.Errorf("owner-blocked: fresh Google Cloud CLI owner issuance is invalid: %w", err)
	}
	if !sameDurableGcloudAuthorization(durable, fresh) {
		return nil, errors.New("owner-blocked: fresh Google Cloud CLI owner issuance does not authorize the sealed runtime")
	}
	canonical, err := canonicalJSON(gcloudReceiptAuthorization(fresh), false)
	if err != nil {
		return nil, errors.New("owner-blocked: fresh Google Cloud CLI owner issuance authorization is invalid")
	}
	return canonical, nil
}

func stableOpenFile(file *os.File) ([]byte, stableFileIdentity, error) {
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return nil, stableFileIdentity{}, errors.New("Google Cloud CLI custody file is not a regular file")
	}
	links, err := fileLinkCount(before)
	if err != nil || links != 1 {
		return nil, stableFileIdentity{}, errors.New("Google Cloud CLI custody file must have exactly one link")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, stableFileIdentity{}, errors.New("Google Cloud CLI custody file is unreadable")
	}
	data, readErr := io.ReadAll(file)
	after, statErr := file.Stat()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, stableFileIdentity{}, errors.New("Google Cloud CLI custody file is unreadable")
	}
	beforeLinks, beforeLinkErr := fileLinkCount(before)
	afterLinks, linkErr := fileLinkCount(after)
	beforeOwner, beforeOwnerErr := fileOwner(before)
	afterOwner, afterOwnerErr := fileOwner(after)
	if readErr != nil || statErr != nil || beforeLinkErr != nil || linkErr != nil ||
		beforeOwnerErr != nil || afterOwnerErr != nil ||
		beforeLinks != 1 || afterLinks != 1 || beforeOwner != afterOwner ||
		!os.SameFile(before, after) || before.Size() != after.Size() ||
		before.ModTime() != after.ModTime() || before.Mode() != after.Mode() {
		return nil, stableFileIdentity{}, errors.New("Google Cloud CLI custody file changed while read")
	}
	return data, stableFileIdentity{info: after, mode: after.Mode(), uid: afterOwner}, nil
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func gcloudTreeSHA256(root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", errors.New("Google Cloud CLI installation tree path is invalid")
	}
	var paths []string
	err = filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == root || entry.IsDir() {
			return nil
		}
		if entry.Name() == gcloudReceiptName {
			relative, relErr := filepath.Rel(root, current)
			if relErr != nil || filepath.Dir(relative) != "." {
				return errors.New("nested Google Cloud CLI custody receipt is forbidden")
			}
			return nil
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("unsupported Google Cloud CLI tree entry %q", current)
		}
		paths = append(paths, current)
		return nil
	})
	if err != nil {
		return "", errors.New("Google Cloud CLI installation tree is unreadable")
	}
	sort.Slice(paths, func(i, j int) bool {
		ri, _ := filepath.Rel(root, paths[i])
		rj, _ := filepath.Rel(root, paths[j])
		return filepath.ToSlash(ri) < filepath.ToSlash(rj)
	})
	tree := sha256.New()
	for _, current := range paths {
		rel, err := filepath.Rel(root, current)
		if err != nil {
			return "", err
		}
		rel = filepath.ToSlash(rel)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		kind := byte('F')
		var payload []byte
		if info.Mode()&os.ModeSymlink != 0 {
			kind = 'L'
			target, err := os.Readlink(current)
			if err != nil {
				return "", err
			}
			payload = []byte(target)
		} else {
			payload, _, err = stableFile(current)
			if err != nil {
				return "", err
			}
		}
		payloadHash := sha256.Sum256(payload)
		fmt.Fprintf(tree, "%c\x00%s\x00%d\x00", kind, rel, len(payload))
		_, _ = tree.Write(payloadHash[:])
	}
	return hex.EncodeToString(tree.Sum(nil)), nil
}

func gcloudTreeSHA256FromRoot(root *os.Root) (string, error) {
	var paths []string
	var walk func(string) error
	walk = func(relative string) error {
		name := relative
		if name == "" {
			name = "."
		}
		file, err := root.Open(name)
		if err != nil {
			return err
		}
		entries, readErr := file.ReadDir(0)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			return errors.New("private Google Cloud CLI snapshot is unreadable")
		}
		for _, entry := range entries {
			if entry.Name() == "." || entry.Name() == ".." {
				continue
			}
			if entry.Name() == gcloudReceiptName {
				if relative != "" {
					return errors.New("nested Google Cloud CLI custody receipt is forbidden")
				}
				continue
			}
			child := entry.Name()
			if relative != "" {
				child = pathpkg.Join(relative, entry.Name())
			}
			info, err := root.Lstat(child)
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 || info.Mode().IsRegular() {
				paths = append(paths, child)
				continue
			}
			if info.IsDir() {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(""); err != nil {
		return "", errors.New("private Google Cloud CLI snapshot is unreadable")
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
	tree := sha256.New()
	for _, current := range paths {
		info, err := root.Lstat(current)
		if err != nil {
			return "", err
		}
		kind := byte('F')
		var payload []byte
		if info.Mode()&os.ModeSymlink != 0 {
			kind = 'L'
			target, err := root.Readlink(current)
			if err != nil {
				return "", err
			}
			payload = []byte(target)
		} else {
			file, err := root.Open(current)
			if err != nil {
				return "", err
			}
			payload, _, err = stableOpenFile(file)
			_ = file.Close()
			if err != nil {
				return "", err
			}
		}
		payloadHash := sha256.Sum256(payload)
		fmt.Fprintf(tree, "%c\x00%s\x00%d\x00", kind, current, len(payload))
		_, _ = tree.Write(payloadHash[:])
	}
	return hex.EncodeToString(tree.Sum(nil)), nil
}

func safeArchivePath(name string) (string, error) {
	if name == "" || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") ||
		(len(name) >= 2 && name[1] == ':' && ((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z'))) {
		return "", errors.New("official archive contains an unsafe member")
	}
	normalized := strings.TrimSuffix(name, "/")
	if len(normalized) > maxGcloudPathBytes {
		return "", errors.New("official archive member path is too long")
	}
	clean := pathpkg.Clean(normalized)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") ||
		clean != normalized ||
		(clean != "google-cloud-sdk" && !strings.HasPrefix(clean, "google-cloud-sdk/")) {
		return "", errors.New("official archive contains an unsafe member")
	}
	depth := 1 + strings.Count(clean, "/")
	if depth > maxGcloudArchiveDepth {
		return "", errors.New("official archive member exceeds the depth limit")
	}
	return clean, nil
}

func safeSymlinkTarget(member, target string) error {
	if target == "" || strings.Contains(target, "\\") || strings.HasPrefix(target, "/") ||
		(len(target) >= 2 && target[1] == ':' && ((target[0] >= 'A' && target[0] <= 'Z') || (target[0] >= 'a' && target[0] <= 'z'))) {
		return errors.New("official archive contains an unsafe symlink")
	}
	resolved := pathpkg.Clean(pathpkg.Join(pathpkg.Dir(member), target))
	if resolved != "google-cloud-sdk" && !strings.HasPrefix(resolved, "google-cloud-sdk/") {
		return errors.New("official archive symlink escapes the SDK root")
	}
	if 1+strings.Count(resolved, "/") > maxGcloudArchiveDepth {
		return errors.New("official archive symlink exceeds the depth limit")
	}
	return nil
}

func ensureSafeDirectories(root, relativeDirectory string) error {
	if relativeDirectory == "." || relativeDirectory == "" {
		return nil
	}
	current := root
	for _, component := range strings.Split(filepath.FromSlash(relativeDirectory), string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
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
	if size < 0 || size > maxGcloudArchiveMember {
		return errors.New("official archive member size exceeds the limit")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
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
	if copyErr != nil && strings.Contains(copyErr.Error(), "official archive") {
		return copyErr
	}
	if copyErr != nil || written != size || chmodErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("official archive member could not be extracted exactly")
	}
	return nil
}

func extractOfficialGcloudArchive(archiveData []byte, archiveName, output string) (string, error) {
	if !strings.HasSuffix(archiveName, ".tar.gz") {
		return "", errors.New("Google Cloud CLI archive type is unsupported by the Linux proof client")
	}
	if int64(len(archiveData)) < 22 || int64(len(archiveData)) > maxGcloudArchiveOuter {
		return "", errors.New("official archive outer size is outside the accepted range")
	}
	if err := os.Mkdir(output, 0700); err != nil {
		return "", errors.New("private Google Cloud CLI extraction root is unsafe")
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(archiveData))
	if err != nil {
		return "", errors.New("retained Google Cloud CLI archive is not valid gzip")
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(&countingReader{r: gzipReader, compressed: int64(len(archiveData))})
	seen := make(map[string]struct{})
	var totalBytes int64
	for entries := 0; ; entries++ {
		if entries >= maxGcloudArchiveEntries {
			return "", errors.New("official archive has too many members")
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if strings.Contains(err.Error(), "official archive") {
				return "", err
			}
			return "", errors.New("retained Google Cloud CLI archive is invalid")
		}
		member, err := safeArchivePath(header.Name)
		if err != nil {
			return "", err
		}
		if _, duplicate := seen[member]; duplicate {
			return "", errors.New("official archive contains duplicate members")
		}
		seen[member] = struct{}{}
		if header.Size < 0 || header.Size > maxGcloudArchiveMember {
			return "", errors.New("official archive member size exceeds the limit")
		}
		totalBytes += header.Size
		if totalBytes < 0 || totalBytes > maxGcloudArchiveBytes {
			return "", errors.New("official archive expanded size exceeds the aggregate limit")
		}
		relativeParent := pathpkg.Dir(member)
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
		default:
			return "", errors.New("official archive contains an unsupported member type")
		}
	}
	root := filepath.Join(output, "google-cloud-sdk")
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("official archive lacks the canonical SDK root")
	}
	return root, nil
}

func snapshotGcloudRuntime(source, destination string) error {
	if err := os.Mkdir(destination, 0700); err != nil {
		return errors.New("private Google Cloud CLI snapshot destination already exists")
	}
	src, err := os.OpenRoot(source)
	if err != nil {
		return errors.New("private Google Cloud CLI runtime root descriptor could not be opened")
	}
	defer src.Close()
	dst, err := os.OpenRoot(destination)
	if err != nil {
		return errors.New("private Google Cloud CLI snapshot root descriptor could not be opened")
	}
	defer dst.Close()
	return snapshotRoot(src, dst, "")
}

func snapshotRoot(src, dst *os.Root, relative string) error {
	name := relative
	if name == "" {
		name = "."
	}
	directory, err := src.Open(name)
	if err != nil {
		return errors.New("private Google Cloud CLI runtime is unreadable")
	}
	entries, readErr := directory.ReadDir(0)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.New("private Google Cloud CLI runtime is unreadable")
	}
	for _, entry := range entries {
		if entry.Name() == "." || entry.Name() == ".." || entry.Name() == gcloudReceiptName {
			continue
		}
		if strings.Contains(entry.Name(), "/") || strings.Contains(entry.Name(), "\\") {
			return errors.New("private Google Cloud CLI runtime contains an unsafe name")
		}
		child := entry.Name()
		if relative != "" {
			child = pathpkg.Join(relative, entry.Name())
		}
		if 1+strings.Count(child, "/") > maxGcloudArchiveDepth {
			return errors.New("private Google Cloud CLI runtime exceeds the depth limit")
		}
		info, err := src.Lstat(child)
		if err != nil {
			return errors.New("private Google Cloud CLI runtime is unreadable")
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := src.Readlink(child)
			if err != nil {
				return errors.New("private Google Cloud CLI runtime is unreadable")
			}
			if err := safeSnapshotSymlink(child, target); err != nil {
				return err
			}
			if err := dst.Symlink(target, child); err != nil {
				return errors.New("private Google Cloud CLI snapshot could not be written")
			}
		case info.IsDir():
			if err := dst.Mkdir(child, 0700); err != nil {
				return errors.New("private Google Cloud CLI snapshot could not be written")
			}
			if err := snapshotRoot(src, dst, child); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			file, err := src.Open(child)
			if err != nil {
				return errors.New("private Google Cloud CLI runtime is unreadable")
			}
			payload, _, readErr := stableOpenFile(file)
			_ = file.Close()
			if readErr != nil {
				return readErr
			}
			mode := os.FileMode(0600)
			if info.Mode().Perm()&0111 != 0 {
				mode = 0700
			}
			created, err := dst.OpenFile(child, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return errors.New("private Google Cloud CLI snapshot could not be written")
			}
			_, writeErr := created.Write(payload)
			chmodErr := created.Chmod(mode)
			syncErr := created.Sync()
			closeCreated := created.Close()
			if writeErr != nil || chmodErr != nil || syncErr != nil || closeCreated != nil {
				return errors.New("private Google Cloud CLI snapshot could not be written")
			}
		default:
			return errors.New("private Google Cloud CLI runtime contains an unsupported entry")
		}
	}
	return nil
}

func safeSnapshotSymlink(member, target string) error {
	if target == "" || strings.Contains(target, "\\") || strings.HasPrefix(target, "/") ||
		(len(target) >= 2 && target[1] == ':' && ((target[0] >= 'A' && target[0] <= 'Z') || (target[0] >= 'a' && target[0] <= 'z'))) {
		return errors.New("private Google Cloud CLI runtime contains an unsafe symlink")
	}
	resolved := pathpkg.Clean(pathpkg.Join(pathpkg.Dir(member), target))
	if strings.HasPrefix(resolved, "../") || resolved == ".." {
		return errors.New("private Google Cloud CLI runtime symlink escapes the SDK root")
	}
	return nil
}

func writeExclusiveFile(path string, data []byte, mode os.FileMode) error {
	file, err := writeExclusiveHeld(path, data, mode)
	if err != nil {
		return err
	}
	return file.Close()
}

func writeExclusiveHeld(path string, data []byte, mode os.FileMode) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	written, writeErr := file.Write(data)
	chmodErr := file.Chmod(mode)
	syncErr := file.Sync()
	_, seekErr := file.Seek(0, io.SeekStart)
	if writeErr != nil || written != len(data) || chmodErr != nil || syncErr != nil || seekErr != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, errors.New("Google Cloud CLI custody file write was incomplete")
	}
	return file, nil
}

func openNoFollow(path string, flags int) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func overwriteHeld(file *os.File, size int64) {
	n := size
	if n > int64(maxGcloudCredential) {
		n = int64(maxGcloudCredential)
	}
	if n < 0 {
		n = 0
	}
	zeros := bytes.Repeat([]byte{0}, int(n))
	_, _ = file.Seek(0, io.SeekStart)
	_, _ = file.Write(zeros)
	_ = file.Sync()
}

func secureUnlinkHeld(file *os.File, path string) {
	if file != nil {
		info, err := file.Stat()
		if err == nil && info.Mode().IsRegular() {
			overwriteHeld(file, info.Size())
		}
		_ = file.Close()
	}
	_ = os.Remove(path)
}

func secureUnlink(path string) {
	file, err := openNoFollow(path, syscall.O_WRONLY)
	if err != nil {
		file, err = openNoFollow(path, syscall.O_RDONLY)
		if err != nil {
			_ = os.Remove(path)
			return
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			_ = file.Close()
			_ = os.Remove(path)
			return
		}
		_ = file.Chmod(0600)
		if runtime.GOOS == "linux" {
			upgraded, upErr := os.OpenFile(procSelfFd(int(file.Fd())), os.O_WRONLY, 0)
			runtime.KeepAlive(file)
			if upErr == nil {
				overwriteHeld(upgraded, info.Size())
				_ = upgraded.Close()
			}
		}
		_ = file.Close()
		_ = os.Remove(path)
		return
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		_ = os.Remove(path)
		return
	}
	overwriteHeld(file, info.Size())
	_ = file.Close()
	_ = os.Remove(path)
}

func resolveGcloudExecutable(selected string) (string, error) {
	resolved, err := exec.LookPath(selected)
	if err != nil {
		return "", errors.New("Google Cloud CLI executable was not found")
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", errors.New("Google Cloud CLI executable path is invalid")
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("Google Cloud CLI executable must be a regular non-symlink file")
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", errors.New("Google Cloud CLI executable path is unreadable")
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil || filepath.Base(canonical) != "gcloud" || filepath.Base(filepath.Dir(canonical)) != "bin" {
		return "", errors.New("Google Cloud CLI executable is outside the canonical SDK layout")
	}
	return canonical, nil
}

func authenticateGcloudCredential(input gcloudIdentityInput) (*boundGcloudIdentity, error) {
	if input.kind != gcloudServiceAccountKind && input.kind != gcloudWorkloadIdentityKind {
		return nil, errors.New("Google Cloud CLI credential kind is unsupported")
	}
	if !gcloudAccountPattern.MatchString(input.expectedAccount) {
		return nil, errors.New("Google Cloud CLI bound account is invalid")
	}
	if !projectPattern.MatchString(input.expectedProject) {
		return nil, errors.New("Google Cloud CLI bound project is invalid")
	}
	data, identity, err := stableFile(input.path)
	if err != nil {
		return nil, err
	}
	if identity.mode.Perm() != 0400 {
		return nil, errors.New("Google Cloud CLI credential must be immutable mode 0400")
	}
	if len(data) == 0 || int64(len(data)) > int64(maxGcloudCredential) {
		return nil, errors.New("Google Cloud CLI credential size is outside the accepted range")
	}
	expectedKeys := saCredentialKeys
	if input.kind == gcloudWorkloadIdentityKind {
		expectedKeys = wifCredentialKeys
	}
	if _, err := decodeExactObject(data, expectedKeys, nil); err != nil {
		return nil, errors.New("Google Cloud CLI credential keys are not exact")
	}
	var account, project string
	var subjectToken []byte
	if input.kind == gcloudServiceAccountKind {
		var parsed serviceAccountCredential
		if err := strictDecode(data, &parsed); err != nil || parsed.Type != "service_account" {
			return nil, errors.New("Google Cloud CLI credential is invalid")
		}
		if !saPrivateKeyPattern.MatchString(parsed.PrivateKey) ||
			!saPrivateKeyIDPattern.MatchString(parsed.PrivateKeyID) ||
			!saClientIDPattern.MatchString(parsed.ClientID) ||
			parsed.AuthURI != saAuthURI || parsed.TokenURI != saTokenURI {
			return nil, errors.New("Google Cloud CLI credential is invalid")
		}
		account, project = parsed.ClientEmail, parsed.ProjectID
	} else {
		var parsed workloadIdentityCredential
		if err := strictDecode(data, &parsed); err != nil || parsed.Type != "external_account" {
			return nil, errors.New("Google Cloud CLI credential is invalid")
		}
		if parsed.TokenURL != wifTokenURL || parsed.SubjectTokenType != wifSubjectTokenType ||
			!wifAudiencePattern.MatchString(parsed.Audience) {
			return nil, errors.New("Google Cloud CLI credential is invalid")
		}
		matched := wifEmailPattern.FindStringSubmatch(parsed.ServiceAccountImpersonationURL)
		if len(matched) != 2 {
			return nil, errors.New("Google Cloud CLI credential is invalid")
		}
		var source map[string]json.RawMessage
		if err := strictDecode(parsed.CredentialSource, &source); err != nil || !exactRawKeys(source, []string{"file"}) {
			return nil, errors.New("Google Cloud CLI credential is invalid")
		}
		var sourceFile string
		if err := strictDecode(source["file"], &sourceFile); err != nil ||
			!strings.HasPrefix(sourceFile, "/") || strings.Contains(sourceFile, "..") ||
			strings.Contains(sourceFile, "\\") {
			return nil, errors.New("Google Cloud CLI credential is invalid")
		}
		sourceData, sourceIdentity, sourceErr := stableFile(sourceFile)
		if sourceErr != nil || sourceIdentity.mode.Perm() != 0400 || len(sourceData) == 0 ||
			len(sourceData) > maxGcloudSubjectToken || bytes.IndexByte(sourceData, 0) >= 0 {
			return nil, errors.New("Google Cloud CLI workload identity subject token is not descriptor-authenticated mode 0400")
		}
		subjectToken = append([]byte(nil), sourceData...)
		account, project = matched[1], input.expectedProject
	}
	if account != input.expectedAccount || project != input.expectedProject {
		return nil, errors.New("Google Cloud CLI credential identity does not match the bound identity")
	}
	return &boundGcloudIdentity{
		kind: input.kind, expectedAccount: input.expectedAccount, expectedProject: input.expectedProject,
		data: append([]byte(nil), data...), subjectToken: subjectToken,
	}, nil
}

func runtimeGcloudCredential(identity *boundGcloudIdentity, subjectTokenPath string) ([]byte, error) {
	if identity == nil {
		return nil, errors.New("Google Cloud CLI credential is missing")
	}
	if identity.kind != gcloudWorkloadIdentityKind {
		if len(identity.subjectToken) != 0 || subjectTokenPath != "" {
			return nil, errors.New("Google Cloud CLI credential snapshot is invalid")
		}
		return append([]byte(nil), identity.data...), nil
	}
	if len(identity.subjectToken) == 0 || subjectTokenPath == "" {
		return nil, errors.New("Google Cloud CLI workload identity subject token snapshot is missing")
	}
	var parsed workloadIdentityCredential
	if err := strictDecode(identity.data, &parsed); err != nil {
		return nil, errors.New("Google Cloud CLI credential is invalid")
	}
	source, err := json.Marshal(map[string]string{"file": subjectTokenPath})
	if err != nil {
		return nil, errors.New("Google Cloud CLI credential snapshot is invalid")
	}
	parsed.CredentialSource = source
	encoded, err := json.Marshal(parsed)
	if err != nil {
		return nil, errors.New("Google Cloud CLI credential snapshot is invalid")
	}
	return encoded, nil
}

func (g *verifiedGcloud) bindIdentity(input gcloudIdentityInput) error {
	bound, err := authenticateGcloudCredential(input)
	if err != nil {
		return err
	}
	g.identity = bound
	return nil
}

func isolatedGcloudEnv(home, config, tmp, credentialFile, project string) ([]string, error) {
	if !projectPattern.MatchString(project) {
		return nil, errors.New("Google Cloud CLI bound project is invalid")
	}
	return []string{
		"HOME=" + home,
		"TMPDIR=" + tmp,
		"TMP=" + tmp,
		"TEMP=" + tmp,
		"PATH=/usr/bin:/bin",
		"LANG=C",
		"LC_ALL=C",
		"CLOUDSDK_CONFIG=" + config,
		"CLOUDSDK_ROOT_DIR=.",
		"CLOUDSDK_CORE_DISABLE_PROMPTS=1",
		"CLOUDSDK_CORE_PROJECT=" + project,
		"CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=" + credentialFile,
		"CLOUDSDK_PYTHON_SITEPACKAGES=0",
		"PYTHONNOUSERSITE=1",
		"PYTHONDONTWRITEBYTECODE=1",
	}, nil
}

func isolatedGcloudSealedEnv(home, config, tmp, project string) ([]string, error) {
	if !projectPattern.MatchString(project) {
		return nil, errors.New("Google Cloud CLI bound project is invalid")
	}
	root := procSelfFd(4)
	python := root + "/" + gcloudBundledPythonRelative
	return []string{
		"HOME=" + home,
		"TMPDIR=" + tmp,
		"TMP=" + tmp,
		"TEMP=" + tmp,
		"PATH=" + filepath.Dir(python) + ":/usr/bin:/bin",
		"LANG=C",
		"LC_ALL=C",
		"CLOUDSDK_CONFIG=" + config,
		"CLOUDSDK_ROOT_DIR=" + root,
		"CLOUDSDK_CORE_DISABLE_PROMPTS=1",
		"CLOUDSDK_CORE_PROJECT=" + project,
		"CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=" + procSelfFd(5),
		"CLOUDSDK_PYTHON=" + python,
		"CLOUDSDK_PYTHON_SITEPACKAGES=0",
		"PYTHONNOUSERSITE=1",
		"PYTHONDONTWRITEBYTECODE=1",
	}, nil
}

func verifyGcloudCustody(selected string) (*verifiedGcloud, error) {
	return verifyGcloudCustodyWithPin(selected, compiledGcloudReviewPin())
}

func verifyGcloudCustodyWithPin(selected string, pin gcloudReviewPin) (*verifiedGcloud, error) {
	if os.Geteuid() == 0 {
		return nil, errors.New("owner-blocked: root cannot verify an owner authority it can rewrite")
	}
	verified, err := verifyGcloudCustodyWithPinAndAuthority(
		selected, pin, gcloudOwnerAuthorityPath, gcloudOwnerIssuancePath, 0,
	)
	if err != nil {
		return nil, err
	}
	if err := verified.verifyProductionSealedRuntime(); err != nil {
		return nil, err
	}
	verified.productionSealed = true
	return verified, nil
}

func expectedProductionGcloudRoot(treeSHA256 string) (string, error) {
	if !shaPattern.MatchString(treeSHA256) || treeSHA256 == strings.Repeat("0", 64) {
		return "", errors.New("Google Cloud CLI production runtime tree identity is invalid")
	}
	return filepath.Join(gcloudProductionRuntimeRoot, treeSHA256), nil
}

func validateProductionGcloudRoot(root, treeSHA256 string) error {
	expected, err := expectedProductionGcloudRoot(treeSHA256)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != expected || root != expected {
		return errors.New("owner-blocked: Google Cloud CLI production runtime is outside its fixed sealed root")
	}
	return nil
}

func linuxEffectiveCapabilities() (uint64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil || len(data) == 0 || len(data) > 256*1024 {
		return 0, errors.New("owner-blocked: Linux effective capabilities are unavailable")
	}
	return parseLinuxCapEff(data)
}

func parseLinuxCapEff(data []byte) (uint64, error) {
	if len(data) == 0 || len(data) > 256*1024 || bytes.IndexByte(data, 0) >= 0 {
		return 0, errors.New("owner-blocked: Linux effective capabilities are invalid")
	}
	var value string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			if value != "" {
				return 0, errors.New("owner-blocked: Linux effective capabilities are ambiguous")
			}
			value = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		}
	}
	if value == "" || len(value) > 16 || strings.Trim(value, "0123456789abcdefABCDEF") != "" {
		return 0, errors.New("owner-blocked: Linux effective capabilities are invalid")
	}
	parsed, err := strconv.ParseUint(value, 16, 64)
	if err != nil {
		return 0, errors.New("owner-blocked: Linux effective capabilities are invalid")
	}
	return parsed, nil
}

func linuxFileImmutable(path string, info os.FileInfo) (bool, error) {
	if info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("Linux immutable state is not defined for symlinks")
	}
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	if info.IsDir() {
		flags |= syscall.O_DIRECTORY
	}
	fd, err := syscall.Open(path, flags, 0)
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

func safeRuntimeSymlink(root, current string) error {
	target, err := os.Readlink(current)
	if err != nil || target == "" || filepath.IsAbs(target) || strings.Contains(target, "\\") {
		return errors.New("Google Cloud CLI sealed runtime contains an unsafe symlink")
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(current), target))
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("Google Cloud CLI sealed runtime symlink escapes its root")
	}
	return nil
}

func verifyRootOwnedPath(path string, expectedDevice uint64, requireImmutable bool) (uint64, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		return 0, errors.New("owner-blocked: Google Cloud CLI sealed runtime path is invalid")
	}
	owner, err := fileOwner(info)
	if err != nil || owner != 0 || info.Mode().Perm()&0022 != 0 {
		return 0, errors.New("owner-blocked: Google Cloud CLI sealed runtime is not root-owned and non-writable")
	}
	statValue, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("owner-blocked: Google Cloud CLI sealed runtime device identity is unavailable")
	}
	device := uint64(statValue.Dev)
	if expectedDevice != 0 && device != expectedDevice {
		return 0, errors.New("owner-blocked: Google Cloud CLI sealed runtime crosses a mount boundary")
	}
	if info.Mode().IsRegular() {
		links, err := fileLinkCount(info)
		if err != nil || links != 1 {
			return 0, errors.New("owner-blocked: Google Cloud CLI sealed runtime contains a hard-linked file")
		}
	}
	if requireImmutable {
		immutable, err := linuxFileImmutable(path, info)
		if err != nil || !immutable {
			return 0, errors.New("owner-blocked: Google Cloud CLI production runtime is not FS_IMMUTABLE")
		}
	}
	return device, nil
}

func verifyLinuxSealedTree(root string) error {
	rootDevice, err := verifyRootOwnedPath(root, 0, true)
	if err != nil {
		return err
	}
	return filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("owner-blocked: Google Cloud CLI sealed runtime is unreadable")
		}
		info, err := os.Lstat(current)
		if err != nil {
			return errors.New("owner-blocked: Google Cloud CLI sealed runtime changed during verification")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			owner, ownerErr := fileOwner(info)
			statValue, statOK := info.Sys().(*syscall.Stat_t)
			if ownerErr != nil || owner != 0 || !statOK || uint64(statValue.Dev) != rootDevice {
				return errors.New("owner-blocked: Google Cloud CLI sealed runtime symlink custody is invalid")
			}
			return safeRuntimeSymlink(root, current)
		}
		if !gcloudSealedRuntimeModeAllowed(info) {
			return errors.New("owner-blocked: Google Cloud CLI sealed runtime mode is not exact 0555/0444")
		}
		if _, err := verifyRootOwnedPath(current, rootDevice, true); err != nil {
			return err
		}
		return nil
	})
}

func gcloudSealedRuntimeModeAllowed(info os.FileInfo) bool {
	if info.IsDir() {
		return info.Mode().Perm() == 0555
	}
	if info.Mode().IsRegular() {
		return info.Mode().Perm() == 0444 || info.Mode().Perm() == 0555
	}
	return false
}

func (g *verifiedGcloud) verifyProductionSealedRuntime() error {
	if runtime.GOOS != "linux" {
		return errors.New("owner-blocked: production Google Cloud CLI sealed runtime requires Linux")
	}
	if os.Geteuid() == 0 {
		return errors.New("owner-blocked: root cannot execute the Google Cloud CLI custody controller")
	}
	capabilities, err := linuxEffectiveCapabilities()
	if err != nil {
		return err
	}
	if capabilities&(uint64(1)<<linuxCapImmutable) != 0 {
		return errors.New("owner-blocked: Google Cloud CLI custody controller must not hold CAP_LINUX_IMMUTABLE")
	}
	if err := validateProductionGcloudRoot(g.root, g.treeSHA256); err != nil {
		return err
	}
	for _, ancestor := range []string{"/var", "/var/lib", "/var/lib/winsvpn", gcloudProductionRuntimeRoot} {
		if _, err := verifyRootOwnedPath(ancestor, 0, false); err != nil {
			return err
		}
	}
	if err := verifyLinuxSealedTree(g.root); err != nil {
		return err
	}
	observed, err := gcloudTreeSHA256(g.root)
	if err != nil || observed != g.treeSHA256 {
		return errors.New("owner-blocked: Google Cloud CLI sealed runtime tree does not match its signed receipt")
	}
	pythonPath := filepath.Join(g.root, filepath.FromSlash(gcloudBundledPythonRelative))
	pythonInfo, err := os.Lstat(pythonPath)
	if err != nil || !pythonInfo.Mode().IsRegular() || pythonInfo.Mode().Perm()&0111 == 0 {
		return errors.New("owner-blocked: Google Cloud CLI sealed bundled Python is unavailable")
	}
	return nil
}

func verifyGcloudCustodyWithPinAndAuthority(selected string, pin gcloudReviewPin, authorityPath, issuancePath string, authorityOwner uint32) (*verifiedGcloud, error) {
	if pin.version == "" || pin.platform != "linux_amd64" ||
		!strings.HasSuffix(pin.archiveName, ".tar.gz") || !shaPattern.MatchString(pin.archiveSHA256) ||
		pin.archiveSHA256 == strings.Repeat("0", 64) {
		return nil, errors.New("Google Cloud CLI reviewed platform pin is invalid")
	}
	executable, err := resolveGcloudExecutable(selected)
	if err != nil {
		return nil, err
	}
	executableData, executableIdentity, err := stableFile(executable)
	if err != nil || executableIdentity.mode.Perm()&0111 == 0 || executableIdentity.mode.Perm()&0022 != 0 {
		return nil, errors.New("Google Cloud CLI executable must be executable and not group/world writable")
	}
	root := filepath.Dir(filepath.Dir(executable))
	receiptPath := filepath.Join(root, gcloudReceiptName)
	receiptData, receiptIdentity, err := stableFile(receiptPath)
	if err != nil {
		return nil, err
	}
	if receiptIdentity.mode.Perm() != 0444 {
		return nil, errors.New("Google Cloud CLI custody receipt must be immutable mode 0444")
	}
	var receipt gcloudReceipt
	if err := strictDecode(receiptData, &receipt); err != nil {
		return nil, fmt.Errorf("Google Cloud CLI custody receipt is invalid: %w", err)
	}
	if receipt.SchemaVersion != 1 || receipt.Contract != gcloudReceiptContract ||
		receipt.Version != pin.version || receipt.Platform != pin.platform ||
		receipt.ArchiveName != pin.archiveName || receipt.ArchiveSHA256 != pin.archiveSHA256 ||
		receipt.ExecutablePath != "bin/gcloud" || !shaPattern.MatchString(receipt.InstallTreeSHA256) ||
		receipt.InstallTreeSHA256 == strings.Repeat("0", 64) {
		return nil, errors.New("Google Cloud CLI custody receipt does not match the generated reviewed pin")
	}
	authorityCustody, err := stableExternalAuthorityFile(authorityPath, authorityOwner)
	if err != nil {
		return nil, err
	}
	issuanceCustody, err := stableExternalAuthorityFile(issuancePath, authorityOwner)
	if err != nil {
		return nil, errors.New("owner-blocked: fresh Google Cloud CLI owner issuance is unavailable")
	}
	verificationTime := time.Now().UTC()
	if err := verifyGcloudReceiptAuthority(receipt, root, authorityCustody, authorityOwner, false, verificationTime); err != nil {
		return nil, err
	}
	freshAuthorization, err := verifyFreshGcloudIssuance(
		receipt, root, issuanceCustody, authorityCustody, authorityOwner, verificationTime,
	)
	if err != nil {
		return nil, err
	}
	archivePath := filepath.Join(root, gcloudCustodyArchiveName)
	archiveData, archiveIdentity, err := stableFile(archivePath)
	if err != nil {
		return nil, err
	}
	if archiveIdentity.mode.Perm() != 0444 {
		return nil, errors.New("Google Cloud CLI retained official archive must be immutable mode 0444")
	}
	if sha256Hex(archiveData) != pin.archiveSHA256 {
		return nil, errors.New("retained Google Cloud CLI archive does not match the reviewed platform pin")
	}
	scratch, err := os.MkdirTemp("", "winsvpn-gcloud-verify-")
	if err != nil {
		return nil, errors.New("Google Cloud CLI archive verification scratch could not be created")
	}
	defer os.RemoveAll(scratch)
	extracted, err := extractOfficialGcloudArchive(archiveData, pin.archiveName, filepath.Join(scratch, "archive"))
	if err != nil {
		return nil, err
	}
	runtimeTree, err := gcloudTreeSHA256(extracted)
	if err != nil {
		return nil, err
	}
	if err := writeExclusiveFile(filepath.Join(extracted, gcloudCustodyArchiveName), archiveData, 0400); err != nil {
		return nil, errors.New("retained archive could not be added to the derived SDK tree")
	}
	expectedTree, err := gcloudTreeSHA256(extracted)
	if err != nil {
		return nil, err
	}
	observedTree, err := gcloudTreeSHA256(root)
	if err != nil || observedTree != expectedTree || receipt.InstallTreeSHA256 != expectedTree {
		return nil, errors.New("Google Cloud CLI installation tree does not match its reviewed archive")
	}
	return &verifiedGcloud{
		executable: executable, root: root, receiptPath: receiptPath, archivePath: archivePath,
		receiptSHA256: sha256Hex(receiptData), treeSHA256: observedTree, runtimeTreeSHA256: runtimeTree,
		executableSHA256: sha256Hex(executableData), archiveSHA256: sha256Hex(archiveData),
		executableIdentity: executableIdentity, receiptIdentity: receiptIdentity, archiveIdentity: archiveIdentity,
		archiveData: append([]byte(nil), archiveData...), pin: pin,
		ownerAuthorization: gcloudOwnerAuthorizationCustody{
			authority: authorityCustody, issuance: issuanceCustody,
			freshAuthorization: append([]byte(nil), freshAuthorization...), authorityOwner: authorityOwner,
		},
	}, nil
}

func (g *verifiedGcloud) verifyOwnerAuthorizationUnchanged(receiptData []byte, now time.Time) error {
	fixed := g.ownerAuthorization
	authority, err := stableExternalAuthorityFile(fixed.authority.configuredPath, fixed.authorityOwner)
	if err != nil || !sameGcloudAuthorityFileCustody(authority, fixed.authority) {
		return errors.New("owner-blocked: Google Cloud CLI owner authority custody changed during execution")
	}
	issuance, err := stableExternalAuthorityFile(fixed.issuance.configuredPath, fixed.authorityOwner)
	if err != nil || !sameGcloudAuthorityFileCustody(issuance, fixed.issuance) {
		return errors.New("owner-blocked: fresh Google Cloud CLI owner issuance custody changed during execution")
	}
	var durable gcloudReceipt
	if err := strictDecode(receiptData, &durable); err != nil {
		return errors.New("owner-blocked: Google Cloud CLI custody receipt could not be revalidated")
	}
	if err := verifyGcloudReceiptAuthority(durable, g.root, authority, fixed.authorityOwner, false, now); err != nil {
		return err
	}
	freshAuthorization, err := verifyFreshGcloudIssuance(
		durable, g.root, issuance, authority, fixed.authorityOwner, now,
	)
	if err != nil {
		return err
	}
	if !bytes.Equal(freshAuthorization, fixed.freshAuthorization) {
		return errors.New("owner-blocked: fresh Google Cloud CLI owner authorization rotated during execution")
	}
	return nil
}

func (g *verifiedGcloud) verifyUnchangedAt(now time.Time) error {
	executableData, executableIdentity, executableErr := stableFile(g.executable)
	receiptData, receiptIdentity, receiptErr := stableFile(g.receiptPath)
	archiveData, archiveIdentity, archiveErr := stableFile(g.archivePath)
	if executableErr != nil || receiptErr != nil || archiveErr != nil ||
		!sameStableFile(executableIdentity, g.executableIdentity) ||
		!sameStableFile(receiptIdentity, g.receiptIdentity) ||
		!sameStableFile(archiveIdentity, g.archiveIdentity) ||
		sha256Hex(executableData) != g.executableSHA256 ||
		sha256Hex(receiptData) != g.receiptSHA256 ||
		sha256Hex(archiveData) != g.archiveSHA256 || !bytes.Equal(archiveData, g.archiveData) {
		return errors.New("Google Cloud CLI custody changed during execution")
	}
	tree, err := gcloudTreeSHA256(g.root)
	if err != nil || tree != g.treeSHA256 {
		return errors.New("Google Cloud CLI installation tree changed during execution")
	}
	if err := g.verifyOwnerAuthorizationUnchanged(receiptData, now); err != nil {
		return err
	}
	return nil
}

func (g *verifiedGcloud) verifyUnchanged() error {
	return g.verifyUnchangedAt(time.Now().UTC())
}

func freezePrivateRuntime(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.IsDir() {
			directories = append(directories, current)
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("private Google Cloud CLI runtime contains an unsupported entry")
		}
		mode := os.FileMode(0400)
		if info.Mode().Perm()&0111 != 0 {
			mode = 0500
		}
		return os.Chmod(current, mode)
	})
	if err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := os.Chmod(directories[index], 0500); err != nil {
			return err
		}
	}
	return nil
}

func thawPrivateRuntime(root string) {
	var directories []string
	_ = filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr == nil && entry.IsDir() {
			directories = append(directories, current)
		}
		return nil
	})
	for _, directory := range directories {
		_ = os.Chmod(directory, 0700)
	}
}

func (g *verifiedGcloud) runFromProductionSealedRuntime(ctx context.Context, runner commandRunner, args []string) (commandResult, error) {
	if !g.productionSealed {
		return commandResult{}, errors.New("owner-blocked: Google Cloud CLI production runtime was not sealed")
	}
	if err := g.verifyProductionSealedRuntime(); err != nil {
		return commandResult{}, err
	}
	scratch, err := os.MkdirTemp("", "winsvpn-gcloud-state-")
	if err != nil {
		return commandResult{}, errors.New("private Google Cloud CLI state could not be created")
	}
	home := filepath.Join(scratch, "home")
	config := filepath.Join(scratch, "config")
	tmp := filepath.Join(scratch, "tmp")
	credentialFile := filepath.Join(config, "bound_credential.json")
	subjectTokenFile := filepath.Join(config, "bound_subject_token")
	var credential *os.File
	var subjectToken *os.File
	defer func() {
		secureUnlinkHeld(credential, credentialFile)
		secureUnlinkHeld(subjectToken, subjectTokenFile)
		_ = os.Chmod(scratch, 0700)
		_ = os.RemoveAll(scratch)
	}()
	for _, directory := range []string{home, filepath.Join(home, ".config"), filepath.Join(home, ".config", "gcloud"), config, tmp} {
		if err := os.Mkdir(directory, 0700); err != nil {
			return commandResult{}, errors.New("private Google Cloud CLI isolated state could not be created")
		}
	}
	if len(g.identity.subjectToken) != 0 {
		subjectToken, err = writeExclusiveHeld(subjectTokenFile, g.identity.subjectToken, 0400)
		if err != nil {
			return commandResult{}, errors.New("Google Cloud CLI subject token snapshot could not be written")
		}
	}
	subjectDescriptorPath := ""
	if subjectToken != nil {
		subjectDescriptorPath = procSelfFd(6)
	}
	credentialData, err := runtimeGcloudCredential(g.identity, subjectDescriptorPath)
	if err != nil {
		return commandResult{}, err
	}
	credential, err = writeExclusiveHeld(credentialFile, credentialData, 0400)
	if err != nil {
		return commandResult{}, errors.New("Google Cloud CLI credential snapshot could not be written")
	}
	credentialBefore, credentialIdentity, err := stableOpenFile(credential)
	if err != nil || !bytes.Equal(credentialBefore, credentialData) {
		return commandResult{}, errors.New("Google Cloud CLI credential snapshot is not descriptor-bound")
	}
	var subjectIdentity stableFileIdentity
	if subjectToken != nil {
		subjectBefore, identity, subjectErr := stableOpenFile(subjectToken)
		if subjectErr != nil || !bytes.Equal(subjectBefore, g.identity.subjectToken) {
			return commandResult{}, errors.New("Google Cloud CLI subject token snapshot is not descriptor-bound")
		}
		subjectIdentity = identity
	}
	runtimeRoot, err := os.OpenRoot(g.root)
	if err != nil {
		return commandResult{}, errors.New("sealed Google Cloud CLI root descriptor could not be opened")
	}
	defer runtimeRoot.Close()
	heldTree, err := gcloudTreeSHA256FromRoot(runtimeRoot)
	if err != nil || heldTree != g.treeSHA256 {
		return commandResult{}, errors.New("sealed Google Cloud CLI descriptor tree does not match its signed receipt")
	}
	rootDirectory, err := runtimeRoot.Open(".")
	if err != nil {
		return commandResult{}, errors.New("sealed Google Cloud CLI root descriptor could not be held")
	}
	defer rootDirectory.Close()
	executableFile, err := runtimeRoot.Open("bin/gcloud")
	if err != nil {
		return commandResult{}, errors.New("sealed Google Cloud CLI executable descriptor could not be held")
	}
	defer executableFile.Close()
	executableData, executableIdentity, err := stableOpenFile(executableFile)
	if err != nil || sha256Hex(executableData) != g.executableSHA256 || !sameStableFile(executableIdentity, g.executableIdentity) {
		return commandResult{}, errors.New("sealed Google Cloud CLI executable does not match reviewed bytes")
	}
	pythonFile, err := runtimeRoot.Open(gcloudBundledPythonRelative)
	if err != nil {
		return commandResult{}, errors.New("sealed Google Cloud CLI bundled Python descriptor could not be held")
	}
	pythonInfo, pythonErr := pythonFile.Stat()
	_ = pythonFile.Close()
	if pythonErr != nil || !pythonInfo.Mode().IsRegular() || pythonInfo.Mode().Perm()&0111 == 0 {
		return commandResult{}, errors.New("sealed Google Cloud CLI bundled Python is invalid")
	}
	secureRunner, ok := runner.(custodyDescriptorRunner)
	if !ok {
		return commandResult{}, errors.New("Google Cloud CLI runner lacks descriptor-bound executable and identity execution")
	}
	env, err := isolatedGcloudSealedEnv(home, config, tmp, g.identity.expectedProject)
	if err != nil {
		return commandResult{}, err
	}
	command := append([]string{"bin/gcloud"}, args...)
	if err := g.verifyUnchanged(); err != nil {
		return commandResult{}, err
	}
	result, runErr := secureRunner.runFromCustody(
		ctx, executableFile, rootDirectory, credential, subjectToken, g.root, command, env,
	)
	postExecutable, postExecutableIdentity, executableErr := stableOpenFile(executableFile)
	credentialAfter, credentialAfterIdentity, credentialErr := stableOpenFile(credential)
	var subjectErr error
	if subjectToken != nil {
		subjectAfter, subjectAfterIdentity, readErr := stableOpenFile(subjectToken)
		if readErr != nil || !sameStableFile(subjectIdentity, subjectAfterIdentity) || !bytes.Equal(subjectAfter, g.identity.subjectToken) {
			subjectErr = errors.New("Google Cloud CLI subject token snapshot changed during execution")
		}
	}
	postTree, treeErr := gcloudTreeSHA256FromRoot(runtimeRoot)
	if executableErr != nil || credentialErr != nil || subjectErr != nil || treeErr != nil ||
		!bytes.Equal(postExecutable, executableData) || !sameStableFile(postExecutableIdentity, executableIdentity) ||
		!bytes.Equal(credentialAfter, credentialData) || !sameStableFile(credentialAfterIdentity, credentialIdentity) ||
		postTree != g.treeSHA256 {
		return commandResult{}, errors.New("sealed Google Cloud CLI runtime changed during execution")
	}
	if err := g.verifyProductionSealedRuntime(); err != nil {
		return commandResult{}, err
	}
	if err := g.verifyUnchanged(); err != nil {
		return commandResult{}, err
	}
	return result, runErr
}

func (g *verifiedGcloud) run(ctx context.Context, runner commandRunner, args []string) (commandResult, error) {
	if len(args) == 0 {
		return commandResult{}, errors.New("empty Google Cloud CLI argv")
	}
	if g.identity == nil {
		return commandResult{}, errors.New("owner blocker: Google Cloud CLI execution requires an exact descriptor-authenticated service-account credential or workload identity input")
	}
	if err := g.verifyUnchanged(); err != nil {
		return commandResult{}, err
	}
	if g.productionSealed {
		return g.runFromProductionSealedRuntime(ctx, runner, args)
	}
	scratch, err := os.MkdirTemp("", "winsvpn-gcloud-runtime-")
	if err != nil {
		return commandResult{}, errors.New("private Google Cloud CLI runtime could not be created")
	}
	home := filepath.Join(scratch, "home")
	config := filepath.Join(scratch, "config")
	tmp := filepath.Join(scratch, "tmp")
	credentialFile := filepath.Join(config, "bound_credential.json")
	subjectTokenFile := filepath.Join(config, "bound_subject_token")
	snapshot := filepath.Join(scratch, "runtime")
	var credential *os.File
	var subjectToken *os.File
	defer func() {
		secureUnlinkHeld(credential, credentialFile)
		secureUnlinkHeld(subjectToken, subjectTokenFile)
		_ = os.Chmod(scratch, 0700)
		thawPrivateRuntime(snapshot)
		thawPrivateRuntime(scratch)
		_ = os.RemoveAll(scratch)
	}()
	for _, directory := range []string{home, filepath.Join(home, ".config"), filepath.Join(home, ".config", "gcloud"), config, tmp} {
		if err := os.Mkdir(directory, 0700); err != nil {
			return commandResult{}, errors.New("private Google Cloud CLI isolated state could not be created")
		}
	}
	if len(g.identity.subjectToken) != 0 {
		subjectToken, err = writeExclusiveHeld(subjectTokenFile, g.identity.subjectToken, 0400)
		if err != nil {
			return commandResult{}, errors.New("Google Cloud CLI subject token snapshot could not be written")
		}
	}
	subjectDescriptorPath := ""
	if subjectToken != nil {
		subjectDescriptorPath = procSelfFd(6)
	}
	credentialData, err := runtimeGcloudCredential(g.identity, subjectDescriptorPath)
	if err != nil {
		return commandResult{}, err
	}
	credential, err = writeExclusiveHeld(credentialFile, credentialData, 0400)
	if err != nil {
		return commandResult{}, errors.New("Google Cloud CLI credential snapshot could not be written")
	}
	credentialBefore, credentialIdentity, err := stableOpenFile(credential)
	if err != nil || !bytes.Equal(credentialBefore, credentialData) {
		return commandResult{}, errors.New("Google Cloud CLI credential snapshot is not descriptor-bound")
	}
	var subjectIdentity stableFileIdentity
	if subjectToken != nil {
		subjectBefore, identity, subjectErr := stableOpenFile(subjectToken)
		if subjectErr != nil || !bytes.Equal(subjectBefore, g.identity.subjectToken) {
			return commandResult{}, errors.New("Google Cloud CLI subject token snapshot is not descriptor-bound")
		}
		subjectIdentity = identity
	}
	extracted, err := extractOfficialGcloudArchive(g.archiveData, g.pin.archiveName, filepath.Join(scratch, "archive"))
	if err != nil {
		return commandResult{}, err
	}
	runtimeTree, err := gcloudTreeSHA256(extracted)
	if err != nil || runtimeTree != g.runtimeTreeSHA256 {
		return commandResult{}, errors.New("private Google Cloud CLI runtime does not match the official archive")
	}
	if err := snapshotGcloudRuntime(extracted, snapshot); err != nil {
		return commandResult{}, err
	}
	snapshotTree, err := gcloudTreeSHA256(snapshot)
	if err != nil || snapshotTree != g.runtimeTreeSHA256 {
		return commandResult{}, errors.New("private Google Cloud CLI snapshot does not match the official archive")
	}
	executable := filepath.Join(snapshot, "bin", "gcloud")
	executableData, executableIdentity, err := stableFile(executable)
	if err != nil || executableIdentity.mode.Perm()&0111 == 0 {
		return commandResult{}, errors.New("private Google Cloud CLI runtime lacks its executable")
	}
	if err := freezePrivateRuntime(snapshot); err != nil {
		return commandResult{}, errors.New("private Google Cloud CLI runtime could not be frozen")
	}
	frozenData, frozenIdentity, err := stableFile(executable)
	if err != nil || !bytes.Equal(executableData, frozenData) || frozenIdentity.mode.Perm() != 0500 {
		return commandResult{}, errors.New("private Google Cloud CLI executable did not freeze exactly")
	}
	runtimeRoot, err := os.OpenRoot(snapshot)
	if err != nil {
		return commandResult{}, errors.New("private Google Cloud CLI root descriptor could not be opened")
	}
	defer runtimeRoot.Close()
	heldTree, err := gcloudTreeSHA256FromRoot(runtimeRoot)
	if err != nil || heldTree != g.runtimeTreeSHA256 {
		return commandResult{}, errors.New("private Google Cloud CLI descriptor snapshot does not match the official archive")
	}
	rootDirectory, err := runtimeRoot.Open(".")
	if err != nil {
		return commandResult{}, errors.New("private Google Cloud CLI root descriptor could not be held")
	}
	defer rootDirectory.Close()
	executableFile, err := runtimeRoot.Open("bin/gcloud")
	if err != nil {
		return commandResult{}, errors.New("private Google Cloud CLI executable descriptor could not be held")
	}
	defer executableFile.Close()
	descriptorData, descriptorIdentity, err := stableOpenFile(executableFile)
	if err != nil || !bytes.Equal(frozenData, descriptorData) || !sameStableFile(frozenIdentity, descriptorIdentity) {
		return commandResult{}, errors.New("private Google Cloud CLI descriptor does not match reviewed bytes")
	}
	secureRunner, ok := runner.(custodyDescriptorRunner)
	if !ok {
		return commandResult{}, errors.New("Google Cloud CLI runner lacks descriptor-bound executable and identity execution")
	}
	env, err := isolatedGcloudEnv(home, config, tmp, procSelfFd(5), g.identity.expectedProject)
	if err != nil {
		return commandResult{}, err
	}
	command := append([]string{"bin/gcloud"}, args...)
	if err := g.verifyUnchanged(); err != nil {
		return commandResult{}, err
	}
	var result commandResult
	var runErr error
	result, runErr = secureRunner.runFromCustody(
		ctx, executableFile, rootDirectory, credential, subjectToken, snapshot, command, env,
	)
	postData, postIdentity, postErr := stableOpenFile(executableFile)
	credentialAfter, credentialAfterIdentity, credentialErr := stableOpenFile(credential)
	var subjectErr error
	if subjectToken != nil {
		var subjectAfter []byte
		var subjectAfterIdentity stableFileIdentity
		subjectAfter, subjectAfterIdentity, subjectErr = stableOpenFile(subjectToken)
		if subjectErr == nil && (!sameStableFile(subjectIdentity, subjectAfterIdentity) || !bytes.Equal(subjectAfter, g.identity.subjectToken)) {
			subjectErr = errors.New("Google Cloud CLI subject token snapshot changed during execution")
		}
	}
	postTree, treeErr := gcloudTreeSHA256FromRoot(runtimeRoot)
	if postErr != nil || credentialErr != nil || subjectErr != nil || treeErr != nil ||
		!sameStableFile(frozenIdentity, postIdentity) ||
		!sameStableFile(credentialIdentity, credentialAfterIdentity) || !bytes.Equal(credentialAfter, credentialData) ||
		!bytes.Equal(frozenData, postData) || postTree != g.runtimeTreeSHA256 {
		return commandResult{}, errors.New("private Google Cloud CLI snapshot changed during execution")
	}
	if err := g.verifyUnchanged(); err != nil {
		return commandResult{}, err
	}
	return result, runErr
}
