package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/closedarchive"
	"winsvpn.local/winnprotocol/internal/phase1anchor"
	"winsvpn.local/winnprotocol/internal/securefile"
)

// pinAnchorRunner drives the real winn-phase1-anchor-pin binary, the same
// two-provider tool the producer used to call. Its exit status 75 means the
// providers are unreachable and the anchor is paused rather than failed; that
// distinction is preserved, because a paused anchor is resumable and a failed
// one invalidates the matrix.
type pinAnchorRunner struct {
	binary        string
	pendingRoot   string
	committedRoot string
	sshBinary     string
	sshKey        string
	knownHosts    string
	timeout       string
	providerOneID string
	providerOne   string
	providerOnePK string
	providerTwoID string
	providerTwo   string
	providerTwoPK string

	// frozen holds the bytes and open descriptors captured before the last
	// reversible gate. Once haveFrozen is set, no pathname from the operator's
	// configuration is ever reopened again.
	frozen     frozenTrust
	haveFrozen bool
}

var errAnchorPaused = errors.New("anchor paused: providers are unreachable")

func (r *pinAnchorRunner) Anchor(
	slot string,
	request []byte,
	previousOne, previousTwo string,
) (Receipts, error) {
	// The provider addresses are validated HERE, before either branch below.
	//
	// winn-phase1-anchor-pin validates them itself — both present, distinct,
	// and parsable as IP addresses — but the incumbent branch never invokes it.
	// A resume therefore reached adoption with completely unvalidated host
	// configuration, and the sealed configuration's host check compared the
	// slot against runner values that had themselves been checked by nothing.
	// Matching an unvalidated expectation proves nothing.
	//
	// Placing it above the committed-slot lookup is the point: the fresh-anchor
	// path and the resume path have to be validated on the same terms, or the
	// resume path is the weaker one and that is exactly where an attacker-
	// influenced state is most likely to be found.
	if err := r.requireValidProviderHosts(); err != nil {
		return Receipts{}, fmt.Errorf("anchor %s: %w", slot, err)
	}
	decoded, err := phase1anchor.DecodeRequest(bytes.NewReader(request))
	if err != nil {
		return Receipts{}, fmt.Errorf("anchor %s: %w", slot, err)
	}
	committed := filepath.Join(r.committedRoot, slot)
	// Only "it definitely is not there" may permit fresh anchoring.
	//
	// A bare `err == nil` check sends every OTHER Lstat failure — EACCES on a
	// locked-down parent, EIO on a failing disk, ELOOP, ENOTDIR — down the
	// fresh-anchor path. Each of those means "this process cannot tell whether
	// a committed slot exists", and re-anchoring under that uncertainty asks
	// two external providers to sign a second, conflicting statement about the
	// same ordinal. Not knowing is a reason to stop, not a reason to proceed.
	incumbent, statErr := os.Lstat(committed)
	switch {
	case statErr == nil:
		// An incumbent committed slot from an earlier attempt.
		//
		// Reading its receipt digests and carrying on would be trusting
		// whatever is on disk: the whole value of an anchor is that two
		// independent providers SIGNED something, and a resume that never
		// checks the signatures inherits none of it. Anyone able to write into
		// the matrix root could otherwise fabricate a slot, have this
		// controller adopt it, and chain every later anchor onto it.
		//
		// So an incumbent is verified exactly as an auditor verifies it: the
		// canonical request bytes must be the ones this run would have sent,
		// both receipts must carry valid provider signatures over that request
		// under the pinned keys, and both must chain to the previous receipts
		// this run is holding.
		if !incumbent.IsDir() || incumbent.Mode()&os.ModeSymlink != 0 {
			return Receipts{}, fmt.Errorf(
				"the committed anchor slot %s is not a real directory", slot,
			)
		}
		return r.verifyIncumbent(committed, decoded, previousOne, previousTwo)
	case errors.Is(statErr, os.ErrNotExist):
		// The only case that may proceed to fresh anchoring.
	default:
		return Receipts{}, fmt.Errorf(
			"cannot determine whether anchor slot %s is already committed "+
				"(%w); refusing to anchor again under that uncertainty, "+
				"because a second signature over the same ordinal cannot be "+
				"withdrawn", slot, statErr,
		)
	}

	pending := filepath.Join(r.pendingRoot, slot+".pin-pending")
	if err := os.MkdirAll(pending, 0o700); err != nil {
		return Receipts{}, err
	}
	// MkdirAll succeeds silently when the name already exists as a symbolic
	// link to a directory, so the pin tool would have written a slot somewhere
	// else entirely and this process would then have renamed that link onto the
	// committed name. The type is therefore checked after creation, not assumed
	// from it.
	if err := requirePrivateRealDirectory(pending); err != nil {
		return Receipts{}, fmt.Errorf(
			"anchor %s pending directory: %w", slot, err,
		)
	}
	// Create-once with exact-match resume. An overwriting write would let a
	// second attempt silently replace the request a first attempt may already
	// have sent to one provider, leaving the two providers signing different
	// bytes for the same slot.
	//
	// The incumbent is read through the same hardened reader the committed slot
	// uses: os.ReadFile followed a symbolic link planted at this name and was
	// unbounded, so the comparison could have been made against a file the
	// controller never wrote.
	requestPath := filepath.Join(r.pendingRoot, slot+".request.json")
	existing, readErr := readBoundedRegularFile(requestPath, 64<<10)
	switch {
	case readErr == nil:
		if !bytes.Equal(existing, request) {
			return Receipts{}, fmt.Errorf(
				"anchor %s already has a pending request with different "+
					"content; refusing to replace bytes a provider may have "+
					"already signed", slot,
			)
		}
	case errors.Is(readErr, os.ErrNotExist):
		if writeErr := securefile.AtomicWriteNew(
			requestPath, request, 0o600,
		); writeErr != nil {
			return Receipts{}, writeErr
		}
	default:
		return Receipts{}, readErr
	}

	// #nosec G204 -- every argument is operator-supplied controller
	// configuration (the anchor tool's own path, provider identities, and
	// paths this process composed), not attacker-controlled input. The binary
	// is named explicitly by the operator running the transition.
	// The child is given /dev/fd names backed by descriptors this process
	// opened before the last reversible gate. A child cannot be handed a Go
	// value, so it must receive a pathname — but /dev/fd/N resolves to an
	// already-open inode, so replacing anchors/provider-one.ed25519.pub after
	// the gate cannot change what the anchor tool reads. Passing the mutable
	// pathname here is what made the frozen-trust claim untrue.
	if !r.haveFrozen {
		return Receipts{}, errors.New(
			"the anchor runner was invoked before the frozen trust set was " +
				"adopted; it would read the operator's mutable pathnames",
		)
	}
	providerOnePath, providerTwoPath, knownHostsPath := trustDescriptorPaths()
	// #nosec G204 -- the anchor tool path and provider identities are
	// operator-supplied controller configuration; the trust arguments are
	// fixed /dev/fd names backed by this process's own anonymous snapshots.
	command := exec.Command(r.binary,
		"-pending-directory", pending,
		"-request", requestPath,
		"-ssh-binary", r.sshBinary,
		"-ssh-key", r.sshKey,
		"-known-hosts", knownHostsPath,
		"-timeout", r.timeout,
		"-provider-one-id", r.providerOneID,
		"-provider-one-host", r.providerOne,
		"-provider-one-public-key", providerOnePath,
		"-provider-one-previous-receipt", previousOne,
		"-provider-two-id", r.providerTwoID,
		"-provider-two-host", r.providerTwo,
		"-provider-two-public-key", providerTwoPath,
		"-provider-two-previous-receipt", previousTwo,
	)
	extra, err := r.frozen.extraFiles()
	if err != nil {
		return Receipts{}, fmt.Errorf("anchor %s: %w", slot, err)
	}
	command.ExtraFiles = extra
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) && exitError.ExitCode() == 75 {
			return Receipts{}, fmt.Errorf("%w (slot %s)", errAnchorPaused, slot)
		}
		return Receipts{}, fmt.Errorf("anchor %s: %w", slot, err)
	}
	// Atomic, no-replace, durable. os.Rename is not any of the three for a
	// directory: POSIX requires it to REPLACE an existing empty destination, so
	// on Linux a rename onto a committed slot left empty by an interrupted
	// attempt succeeds silently and a second set of provider receipts
	// overwrites the first for the same ordinal.
	if err := securefile.PublishDirectoryNoReplace(pending, committed); err != nil {
		return Receipts{}, fmt.Errorf("commit anchor slot %s: %w", slot, err)
	}
	_ = os.Remove(requestPath)
	// The freshly committed slot is verified on the same terms. A provider tool
	// that exited zero while writing something else is exactly the case a
	// controller must not propagate into the chain.
	return r.verifyIncumbent(committed, decoded, previousOne, previousTwo)
}

// requireValidProviderHosts applies the same basic rules to this controller's
// own provider addresses that the pin tool applies to the ones it is given.
//
// Restated here rather than imported because the pin tool enforces them in its
// CLI parsing, which the incumbent branch never reaches. The two must agree;
// they are checked against each other by the shared-fixture tests that run the
// real pin tool.
func (r *pinAnchorRunner) requireValidProviderHosts() error {
	if r.providerOne == "" || r.providerTwo == "" {
		return errors.New(
			"both anchor provider hosts are required; an unset address cannot " +
				"be compared against a committed slot's sealed configuration",
		)
	}
	if r.providerOne == r.providerTwo {
		return errors.New(
			"the two anchor providers share a host, so their receipts are one " +
				"witness wearing two names",
		)
	}
	for name, value := range map[string]string{
		"-anchor-provider-one-host": r.providerOne,
		"-anchor-provider-two-host": r.providerTwo,
	} {
		if net.ParseIP(value) == nil {
			return fmt.Errorf(
				"%s is %q, which is not an IP address; the anchor transport "+
					"contacts a literal address so that no name resolution "+
					"stands between this controller and the provider it "+
					"believes it is talking to", name, value,
			)
		}
	}
	return nil
}

// verifyIncumbent proves a committed anchor slot really carries what it claims.
func (r *pinAnchorRunner) verifyIncumbent(
	directory string,
	expected phase1anchor.Request,
	previousOne, previousTwo string,
) (Receipts, error) {
	// The frozen bytes, decoded in memory. Reopening the pathnames here would
	// re-introduce exactly the swap window the freeze exists to close, and this
	// function runs after anchoring as well as before it.
	if !r.haveFrozen {
		return Receipts{}, errors.New(
			"the incumbent verifier was invoked before the frozen trust set " +
				"was adopted",
		)
	}
	publicOne, err := decodeAnchorKey(r.frozen.providerOneKey)
	if err != nil {
		return Receipts{}, fmt.Errorf("frozen first provider key: %w", err)
	}
	publicTwo, err := decodeAnchorKey(r.frozen.providerTwoKey)
	if err != nil {
		return Receipts{}, fmt.Errorf("frozen second provider key: %w", err)
	}
	if bytes.Equal(publicOne, publicTwo) {
		return Receipts{}, errors.New(
			"the two anchor providers share a signing key, so their receipts " +
				"are not independent",
		)
	}

	// The slot is read through a root handle from here on, and it must hold
	// EXACTLY the shared artifact set.
	//
	// A subset match was the real gap: the previous version opened the four
	// files it happened to name and ignored everything else, so a slot missing
	// its provider-config, or carrying an extra planted file, was adopted as
	// complete — while the formal verifier this controller exists to satisfy
	// demands set equality and would have refused the same slot afterwards, once
	// the receipts were irreversible. The two sides now consult one definition
	// in internal/phase1anchor.
	root, err := openSlotRoot(directory)
	if err != nil {
		return Receipts{}, err
	}
	defer root.Close()
	if err := requireExactSlotSet(root); err != nil {
		return Receipts{}, fmt.Errorf(
			"the committed anchor slot %s is not a complete anchor slot: %w",
			filepath.Base(directory), err,
		)
	}

	// The terms the slot was produced under, checked before anything in it is
	// believed.
	//
	// This file used to be required by NAME and never read. A slot produced for
	// a different provider pair, under different signing keys, or chained to
	// different predecessors was therefore adopted and every later anchor was
	// chained onto it — and the disagreement surfaced only when the formal
	// verifier, which does check all of this, refused the finished matrix with
	// the provider signatures already irreversible.
	//
	// The expectation comes from this run's own frozen trust and configuration,
	// never from the document: a record that names its own provider identities
	// and is verified against those same names authenticates nothing. The
	// known-hosts digest is required to EQUAL the hash of the frozen bytes this
	// process is holding; the external verifier applies the same equality on
	// its side, against the digest the matrix's signed state binds. Neither
	// side settles for a shape check on it.
	configData, err := readSlotArtifact(
		root, phase1anchor.SlotProviderConfigName, 64<<10,
	)
	if err != nil {
		return Receipts{}, err
	}
	configuration, err := phase1anchor.RequireCanonicalSlotConfig(configData)
	if err != nil {
		return Receipts{}, fmt.Errorf(
			"the committed anchor slot %s: %w", filepath.Base(directory), err,
		)
	}
	frozenKnownHosts := sha256.Sum256(r.frozen.knownHosts)
	if err := configuration.Verify(phase1anchor.SlotConfigExpectation{
		ProviderOneID:    r.providerOneID,
		ProviderTwoID:    r.providerTwoID,
		ProviderOneKeyID: phase1anchor.PublicKeyID(publicOne),
		ProviderTwoKeyID: phase1anchor.PublicKeyID(publicTwo),
		PreviousOne:      previousOne,
		PreviousTwo:      previousTwo,
		KnownHostsDigest: hex.EncodeToString(frozenKnownHosts[:]),
		// This run's own provider addresses. The controller passed exactly
		// these to the pin tool, so an incumbent naming anything else was
		// produced under different transport configuration and is not this
		// run's slot. Distinctness alone would be satisfied by any two
		// different strings.
		ProviderOneHost: r.providerOne,
		ProviderTwoHost: r.providerTwo,
	}); err != nil {
		return Receipts{}, fmt.Errorf(
			"the committed anchor slot %s provider configuration: %w",
			filepath.Base(directory), err,
		)
	}

	// The bytes the providers actually signed have to be the bytes this run
	// would have sent — byte for byte.
	//
	// TrimSpace equality was too weak, and weak in a way that mattered: the
	// formal verifier requires the sealed request to be exactly the canonical
	// encoding plus one newline, so a slot this controller accepted under a
	// looser rule could still be refused at audit. Worse, Canonical() and
	// Digest() both hash a re-marshal, so leading or trailing whitespace,
	// reordered keys and duplicate object keys all compare equal under TrimSpace
	// and all still digest identically — meaning two auditors running different
	// JSON parsers could read different values out of the file this controller
	// had already chained onto.
	onDisk, err := readSlotArtifact(root, phase1anchor.SlotRequestName, 64<<10)
	if err != nil {
		return Receipts{}, err
	}
	canonical, err := expected.Canonical()
	if err != nil {
		return Receipts{}, err
	}
	if !bytes.Equal(onDisk, append(canonical, '\n')) {
		return Receipts{}, fmt.Errorf(
			"the committed anchor slot %s holds a request this run did not "+
				"produce, or does not hold it in the canonical sealed "+
				"encoding; refusing to adopt a foreign anchor",
			filepath.Base(directory),
		)
	}
	expectedDigest, err := expected.Digest()
	if err != nil {
		return Receipts{}, err
	}
	recordedDigest, err := readSlotDigest(
		root, phase1anchor.SlotRequestName+phase1anchor.SlotDigestSuffix,
	)
	if err != nil {
		return Receipts{}, err
	}
	if recordedDigest != expectedDigest {
		return Receipts{}, errors.New("committed anchor request digest mismatch")
	}

	one, err := verifyOneReceipt(
		root, phase1anchor.SlotProviderOneReceiptName,
		expected, r.providerOneID, publicOne, previousOne,
	)
	if err != nil {
		return Receipts{}, err
	}
	two, err := verifyOneReceipt(
		root, phase1anchor.SlotProviderTwoReceiptName,
		expected, r.providerTwoID, publicTwo, previousTwo,
	)
	if err != nil {
		return Receipts{}, err
	}
	return Receipts{
		RequestSHA256:    expectedDigest,
		ProviderOneSHA25: one,
		ProviderTwoSHA25: two,
	}, nil
}

func verifyOneReceipt(
	root *os.Root, name string,
	expected phase1anchor.Request,
	providerID string,
	public ed25519.PublicKey,
	previous string,
) (string, error) {
	data, err := readSlotArtifact(root, name, 64<<10)
	if err != nil {
		return "", err
	}
	receipt, err := phase1anchor.DecodeReceipt(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	if err := receipt.Verify(expected, providerID, public, previous); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	// Byte-canonical, on the same terms as the request above and as the formal
	// verifier. Verify() operates on a re-marshal, so it passes over a receipt
	// whose duplicate object keys or whitespace differ from the sealed bytes.
	canonical, err := receipt.Canonical()
	if err != nil {
		return "", err
	}
	if !bytes.Equal(data, append(canonical, '\n')) {
		return "", fmt.Errorf(
			"%s is not the canonical sealed encoding; the formal verifier "+
				"would refuse this slot", name,
		)
	}
	digest, err := receipt.Digest()
	if err != nil {
		return "", err
	}
	recorded, err := readSlotDigest(root, name+phase1anchor.SlotDigestSuffix)
	if err != nil {
		return "", err
	}
	if recorded != digest {
		return "", fmt.Errorf("%s digest mismatch", name)
	}
	return digest, nil
}

// decodeAnchorKey parses a provider key from bytes already held in memory.
// There is deliberately no path-taking variant left on this type: every
// remaining caller consumes the frozen bytes.
func decodeAnchorKey(content []byte) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(
		strings.TrimSpace(string(content)),
	)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 anchor provider key")
	}
	return ed25519.PublicKey(decoded), nil
}

// openSlotRoot opens a committed anchor slot as a confined root.
//
// Every read below it is then relative to an already-open directory: os.Root
// refuses any component that would leave the slot, so a symbolic link planted
// inside one cannot redirect a read to a file the controller was never pointed
// at. The directory itself is type-checked first, because a root opened on a
// symbolic link is a root somewhere else.
func openSlotRoot(directory string) (*os.Root, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf(
			"the anchor slot %s is not a real directory", filepath.Base(directory),
		)
	}
	return os.OpenRoot(directory)
}

// requireExactSlotSet proves a slot holds precisely the shared artifact set.
//
// Set EQUALITY, not containment, in both directions: a missing member means the
// slot is incomplete, and an extra member means something rode along inside a
// directory whose whole purpose is to be a fixed, verified artifact. Every entry
// must additionally be a regular file — a directory, symbolic link, FIFO or
// device node named after an expected artifact is not that artifact.
//
// The enumeration goes through the ALREADY-OPEN ROOT, never through the
// pathname. Listing the pathname and then reading through the root would let a
// rename between the two describe one directory and read another: the set check
// would pass over a replacement while every artifact came from the original, or
// the reverse. Both operations have to name the same inode, and a descriptor is
// the only thing that guarantees that.
func requireExactSlotSet(root *os.Root) error {
	directoryFile, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	entries, err := directoryFile.ReadDir(-1)
	if err != nil {
		return err
	}
	expected := phase1anchor.SlotArtifactSet()
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := expected[name]; !ok {
			return fmt.Errorf(
				"it holds %q, which is not part of the anchor slot artifact set",
				name,
			)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%q is not a regular file", name)
		}
		seen[name] = struct{}{}
	}
	for _, name := range phase1anchor.SlotArtifactNames() {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("it is missing %q", name)
		}
		// Present by name is not enough: re-check the type through the root, so
		// the member that will actually be opened is the one that was
		// classified. A directory entry's cached type and the inode reached by
		// a subsequent lookup are two different facts.
		info, err := root.Lstat(name)
		if err != nil {
			return fmt.Errorf("%q: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%q is not a regular file", name)
		}
	}
	return nil
}

// readSlotArtifact reads one slot member through a single hardened descriptor.
//
// os.ReadFile was three separate problems here: it follows symbolic links, it
// happily reads a FIFO or device node, and it is unbounded — so a slot member
// replaced by /dev/zero would have been read until the controller died. This
// opens once inside the root, re-stats the DESCRIPTOR rather than the path,
// requires a regular file, and refuses oversize rather than returning a prefix.
// A prefix is the dangerous outcome: part of a signed document presented as the
// whole of it.
func readSlotArtifact(
	root *os.Root, name string, maximum int64,
) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("anchor slot member %s is not a regular file", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf(
			"anchor slot member %s changed between inspection and open", name,
		)
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return nil, fmt.Errorf(
			"anchor slot member %s exceeds the %d-byte limit", name, maximum,
		)
	}
	return content, nil
}

// requirePrivateRealDirectory refuses anything that is not a real, private
// directory at the given name — in particular a symbolic link, which MkdirAll
// treats as success.
func requirePrivateRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("is a symbolic link")
	}
	if !info.IsDir() {
		return errors.New("is not a directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf(
			"has permissions %04o, want no group or other access",
			info.Mode().Perm(),
		)
	}
	return nil
}

// readBoundedRegularFile is readSlotArtifact for a path that has no enclosing
// root — the pending request, which lives beside the slot rather than inside
// it. It refuses symbolic links and special files, re-stats the descriptor it
// actually opened, and refuses oversize rather than returning a prefix.
func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symbolic link", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	file, err := os.Open(path) // #nosec G304 -- type-checked immediately above
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf(
			"%s changed between inspection and open", path,
		)
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", path, maximum)
	}
	return content, nil
}

// readSlotDigest reads a sidecar digest and requires it to be canonical.
func readSlotDigest(root *os.Root, name string) (string, error) {
	content, err := readSlotArtifact(root, name, 4<<10)
	if err != nil {
		return "", err
	}
	value, err := phase1anchor.ParseSidecarDigest(content)
	if err != nil {
		return "", fmt.Errorf("anchor slot member %s: %w", name, err)
	}
	return value, nil
}

func main() {
	matrixRoot := flag.String("matrix-root", "", "retrieved matrix root")
	finalizerSeed := flag.String(
		"finalizer-seed", "", "controller-only ML-DSA-65 finalizer seed",
	)
	expectedSource := flag.String(
		"expected-source-digest", "", "reviewed Auto source digest",
	)
	anchorPin := flag.String(
		"anchor-pin-binary", "", "winn-phase1-anchor-pin",
	)
	sshBinary := flag.String("anchor-ssh-binary", "/usr/bin/ssh", "ssh binary")
	sshKey := flag.String("anchor-ssh-key", "", "anchor transport key")
	knownHosts := flag.String("anchor-known-hosts", "", "anchor known_hosts")
	anchorTimeout := flag.String("anchor-timeout", "20s", "per-anchor timeout")
	providerOneID := flag.String("anchor-provider-one-id", "", "first provider id")
	providerOne := flag.String("anchor-provider-one-host", "", "first provider host")
	providerOnePK := flag.String(
		"anchor-provider-one-public-key", "", "first provider Ed25519 key",
	)
	providerTwoID := flag.String("anchor-provider-two-id", "", "second provider id")
	providerTwo := flag.String("anchor-provider-two-host", "", "second provider host")
	providerTwoPK := flag.String(
		"anchor-provider-two-public-key", "", "second provider Ed25519 key",
	)
	verifyBinary := flag.String(
		"verify-binary", "", "winn-phase1-matrix-verify built on this controller",
	)
	profilePath := flag.String("profiles", "", "frozen impairment profile JSON")
	expectedAWGEngine := flag.String(
		"expected-awg-engine-digest", "", "required Winn AWG engine digest",
	)
	sweepAge := flag.Duration(
		"temporary-sweep-age", 6*time.Hour,
		"remove abandoned temporary archives older than this",
	)
	flag.Parse()

	if *matrixRoot == "" || *finalizerSeed == "" || *expectedSource == "" {
		exitError("-matrix-root, -finalizer-seed and -expected-source-digest are required")
	}
	if *anchorPin == "" {
		exitError(
			"-anchor-pin-binary is required: this transition performs the " +
				"dual-provider anchoring the producer was forbidden to perform",
		)
	}
	// The verifier reads committed anchors from <root>/anchors, so that is
	// where they are written. A controller-private location would produce
	// anchors no verifier looks at.
	//
	// These directories are NOT created here. verifyProducerState proves the
	// producing host holds zero anchor artifacts, and it proves it by requiring
	// that path to be absent; creating it before that check ran would make
	// every fresh run reject itself. The controller creates it after its own
	// eligibility check has passed, in writeControllerState.
	anchorRoot := filepath.Join(*matrixRoot, "anchors")
	pendingRoot := filepath.Join(anchorRoot, "pending")
	committedRoot := filepath.Join(anchorRoot, "committed")

	if *verifyBinary == "" || *profilePath == "" || *expectedAWGEngine == "" {
		exitError(
			"-verify-binary, -profiles and -expected-awg-engine-digest are " +
				"required: this transition verifies with the real verifier, " +
				"never with a reimplementation of it",
		)
	}
	controller := &Controller{
		MatrixRoot:           *matrixRoot,
		FinalizerSeedPath:    *finalizerSeed,
		ExpectedSourceDigest: *expectedSource,
		AnchorProviderOneID:  *providerOneID,
		AnchorProviderOneKey: *providerOnePK,
		AnchorProviderTwoID:  *providerTwoID,
		AnchorProviderTwoKey: *providerTwoPK,
		AnchorKnownHosts:     *knownHosts,
		Out:                  os.Stdout,
		// finalizerKeyID is NOT computed here. Run loads the seed itself, and a
		// key id derived from a separate earlier read could describe a seed
		// that has since been replaced — producing anchors under signer B and
		// then failing final verification against the stale pin A, after the
		// receipts are irreversible. The controller injects the identity of the
		// signer it actually loaded.
		Verifier: &binaryVerifier{
			binary:            *verifyBinary,
			matrixRoot:        *matrixRoot,
			profiles:          *profilePath,
			expectedSource:    *expectedSource,
			expectedAWGEngine: *expectedAWGEngine,
			providerOneID:     *providerOneID,
			providerOnePK:     *providerOnePK,
			providerTwoID:     *providerTwoID,
			providerTwoPK:     *providerTwoPK,
		},
		Anchor: &pinAnchorRunner{
			binary:        *anchorPin,
			pendingRoot:   pendingRoot,
			committedRoot: committedRoot,
			sshBinary:     *sshBinary,
			sshKey:        *sshKey,
			knownHosts:    *knownHosts,
			timeout:       *anchorTimeout,
			providerOneID: *providerOneID,
			providerOne:   *providerOne,
			providerOnePK: *providerOnePK,
			providerTwoID: *providerTwoID,
			providerTwo:   *providerTwo,
			providerTwoPK: *providerTwoPK,
		},
	}
	// Sweep abandoned temporaries from an earlier interrupted attempt before
	// starting, never during: the age threshold is what keeps a concurrent
	// publication's in-flight file safe.
	if err := closedarchive.CleanTemporaries(
		filepath.Join(*matrixRoot, "evidence"), *sweepAge,
	); err != nil && !os.IsNotExist(err) {
		exitError(err.Error())
	}
	if err := controller.Run(); err != nil {
		if errors.Is(err, errAnchorPaused) {
			fmt.Fprintln(os.Stderr, "CONTROLLER_CLOSE_PAUSED:", err)
			os.Exit(75)
		}
		exitError(err.Error())
	}
}

func exitError(message string) {
	fmt.Fprintln(os.Stderr, "CONTROLLER_CLOSE_FAIL:", message)
	os.Exit(1)
}

// binaryVerifier runs the project's real verifier as a subprocess.
//
// A subprocess rather than a linked library, and a real binary rather than a
// stub, because the thing that has to be true is that the artifact an auditor
// would run accepts this state. A reimplementation could agree with the
// controller and disagree with the auditor, which is the failure mode worth
// preventing.
type binaryVerifier struct {
	binary string
	// finalizerKeyID is the controller's own signer identity, carried
	// explicitly rather than read back out of the artifacts being verified. A
	// checkpoint states which key signed it; believing that statement would
	// mean verifying a document against the credential the document nominates,
	// which authenticates nothing.
	finalizerKeyID    string
	matrixRoot        string
	profiles          string
	expectedSource    string
	expectedAWGEngine string
	providerOneID     string
	providerOnePK     string
	providerTwoID     string
	providerTwoPK     string

	frozen frozenTrust
}

// UseFrozenTrust and UseFinalizerKeyID point this verifier at the controller's
// frozen copies and at the signer the run actually loaded, replacing the
// operator's mutable paths and any separately derived identity.
func (v *binaryVerifier) UseFrozenTrust(frozen frozenTrust) {
	v.frozen = frozen
}

func (v *binaryVerifier) UseFinalizerKeyID(keyID string) {
	v.finalizerKeyID = keyID
}

func (r *pinAnchorRunner) UseFrozenTrust(frozen frozenTrust) {
	r.frozen = frozen
	r.haveFrozen = true
}

func (v *binaryVerifier) VerifyBatch(batch BatchVerification) error {
	// #nosec G204 -- the verifier binary and every pin are operator-supplied
	// controller configuration; the evidence path is composed by this process
	// from the matrix root it was given.
	command := exec.Command(v.binary,
		"-carrier-conservation-report", batch.EvidenceDirectory,
		"-audit-finalizer-key-id", batch.FinalizerKeyID,
		"-audit-run-id", batch.RunID,
		"-audit-producer-digest", batch.ProducerDigest,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, output)
	}
	return nil
}

func (v *binaryVerifier) VerifyMatrix(completeRecordName string) error {
	// Fail CLOSED when the frozen trust set is absent.
	//
	// This used to fall back to the operator's mutable pathnames whenever the
	// snapshots were nil, which quietly undid the whole point of freezing them:
	// a run where adoption was skipped, or where snapshotting failed, verified
	// the finished matrix against whatever those names pointed at by then —
	// after the anchors were already irreversible — and reported PASS. The
	// fallback was invisible precisely when it mattered, because it produced a
	// successful verification rather than an error.
	//
	// All three descriptors are required, not just the first: a partially
	// populated trust set would otherwise pass this check and then hand the
	// child a nil ExtraFiles entry.
	if v.frozen.providerOneFile == nil || v.frozen.providerTwoFile == nil ||
		v.frozen.knownHostsFile == nil {
		return errors.New(
			"the matrix verifier was invoked without a complete frozen trust " +
				"set; refusing to verify against the operator's mutable " +
				"pathnames, which can have been replaced since the last " +
				"reversible gate",
		)
	}
	providerOnePath, providerTwoPath, _ := trustDescriptorPaths()
	// #nosec G204 -- operator-supplied verifier binary and pins; the trust
	// arguments are fixed /dev/fd names backed by this process's snapshots.
	command := exec.Command(v.binary,
		"-matrix-root", v.matrixRoot,
		"-profiles", v.profiles,
		"-expected-source-digest", v.expectedSource,
		"-expected-awg-engine-digest", v.expectedAWGEngine,
		"-complete-record-name", completeRecordName,
		// The pin the per-batch checkpoint verification hard-requires. Without
		// it every real invocation fails closed for a plumbing reason rather
		// than a trust reason, which is indistinguishable from a genuine
		// refusal and therefore worse than useless.
		"-audit-finalizer-key-id", v.finalizerKeyID,
		"-audit-producer-digest", v.expectedSource,
		"-anchor-provider-one-id", v.providerOneID,
		"-anchor-provider-one-public-key", providerOnePath,
		"-anchor-provider-two-id", v.providerTwoID,
		"-anchor-provider-two-public-key", providerTwoPath,
	)
	// Unconditional: the guard above already established that all three
	// descriptors are present, so a conditional here could only reintroduce the
	// silent no-descriptor path it exists to remove.
	extra, err := v.frozen.extraFiles()
	if err != nil {
		return err
	}
	command.ExtraFiles = extra
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, output)
	}
	return nil
}
