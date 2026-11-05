package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"winsvpn.local/winnprotocol/internal/phase1anchor"
	"winsvpn.local/winnprotocol/internal/producersnapshot"
	"winsvpn.local/winnprotocol/internal/securefile"
)

// The frozen trust view.
//
// The controller's trust inputs — two provider public keys and the anchor
// known_hosts file — arrive as paths to files the operator owns and can change.
// Reading them repeatedly is the bug: the start record pins what one read saw,
// while the anchor tool and the verifier reopen the same MUTABLE paths later. A
// key replaced in between produces anchors under a different trust set than the
// signature attests to, and the disagreement surfaces only in the post-anchor
// verifier — after two providers have already signed something irreversible.
//
// So every trust input is read exactly once, into this view. The bytes are
// frozen into the matrix root, everything downstream is pointed at the frozen
// copies rather than the originals, and the same view is re-checked inside the
// last reversible gate. After that point the original files can move or vanish
// without affecting the run, which is the observable property the resume test
// asserts.
type trustView struct {
	providerOneKey   []byte
	providerTwoKey   []byte
	knownHosts       []byte
	providerOneKeyID string
	providerTwoKeyID string
	knownHostsSHA    string

	frozenProviderOneKey string
	frozenProviderTwoKey string
	frozenKnownHosts     string

	// Anonymous snapshots of the verified bytes, held for the life of the run.
	//
	// Two earlier attempts were wrong. Handing mutable PATHNAMES downstream let
	// a post-gate swap reach the irreversible step. Holding read-only
	// descriptors on those named files was no better: a descriptor refers to an
	// inode, and anyone with write access can modify that inode IN PLACE, after
	// which the descriptor reads the new bytes. Re-hashing the path before each
	// use does not close it either — an in-place write can land between the
	// check and the read, or between this process's check and a child's open.
	//
	// These descriptors point at unnamed inodes holding copies of the bytes
	// already verified against CONTROLLER_START. Nothing in the filesystem
	// names them, so there is nothing left to open, replace, or write through.
	providerOneFile *os.File
	providerTwoFile *os.File
	knownHostsFile  *os.File
}

// close releases the frozen descriptors.
func (v *trustView) close() {
	for _, file := range []*os.File{
		v.providerOneFile, v.providerTwoFile, v.knownHostsFile,
	} {
		if file != nil {
			_ = file.Close()
		}
	}
}

// descriptorPaths returns the three /dev/fd paths a child process should use,
// given the order the descriptors are passed in ExtraFiles.
//
// A subprocess needs a pathname; it cannot be handed a Go value. /dev/fd/N
// names an ALREADY-OPEN descriptor the child inherits, so what the child opens
// is the inode this process opened before the gate ran, not whatever the
// original name points at by the time the child gets there.
func trustDescriptorPaths() (providerOne, providerTwo, knownHosts string) {
	// ExtraFiles[0] becomes descriptor 3 in the child, and so on.
	return "/dev/fd/3", "/dev/fd/4", "/dev/fd/5"
}

// trustConsumer is implemented by collaborators that must use the frozen
// copies rather than the operator's original paths.
type trustConsumer interface {
	UseFrozenTrust(frozen frozenTrust)
}

// finalizerConsumer is implemented by collaborators that need the identity of
// the signer this run actually loaded — never one computed separately, which
// could describe a seed that has since been replaced.
type finalizerConsumer interface {
	UseFinalizerKeyID(keyID string)
}

// loadTrustInputs reads every trust input once and derives its identity.
func (c *Controller) loadTrustInputs() error {
	if c.AnchorProviderOneID == "" || c.AnchorProviderTwoID == "" {
		return errors.New("both anchor provider identities are required")
	}
	if c.AnchorProviderOneID == c.AnchorProviderTwoID {
		return errors.New(
			"the two anchor providers share an identity, so their receipts are " +
				"one witness wearing two names",
		)
	}
	view := &trustView{}
	var err error
	if view.providerOneKey, view.providerOneKeyID, err = readAnchorKey(
		c.AnchorProviderOneKey,
	); err != nil {
		return fmt.Errorf("first anchor provider key: %w", err)
	}
	if view.providerTwoKey, view.providerTwoKeyID, err = readAnchorKey(
		c.AnchorProviderTwoKey,
	); err != nil {
		return fmt.Errorf("second anchor provider key: %w", err)
	}
	if view.providerOneKeyID == view.providerTwoKeyID {
		return errors.New(
			"the two anchor providers share a signing key, so their receipts " +
				"are not independent",
		)
	}
	content, digest, err := producersnapshot.ReadRegular(
		c.AnchorKnownHosts, producersnapshot.MaximumRecordBytes, nil,
	)
	if err != nil {
		return fmt.Errorf("anchor known hosts: %w", err)
	}
	view.knownHosts = content
	view.knownHostsSHA = digest

	anchorRoot := filepath.Join(c.MatrixRoot, "anchors")
	view.frozenProviderOneKey = filepath.Join(anchorRoot, "provider-one.ed25519.pub")
	view.frozenProviderTwoKey = filepath.Join(anchorRoot, "provider-two.ed25519.pub")
	view.frozenKnownHosts = filepath.Join(anchorRoot, "known_hosts")
	c.trust = view
	return nil
}

// adoptFrozenTrust hands the anchor runner and the verifier the open
// descriptors — not pathnames — and the identity of the signer this run loaded.
func (c *Controller) adoptFrozenTrust(finalizerKeyID string) {
	for _, collaborator := range []any{c.Anchor, c.Verifier} {
		if consumer, ok := collaborator.(trustConsumer); ok {
			consumer.UseFrozenTrust(frozenTrust{
				providerOneKey:  c.trust.providerOneKey,
				providerTwoKey:  c.trust.providerTwoKey,
				knownHosts:      c.trust.knownHosts,
				providerOneFile: c.trust.providerOneFile,
				providerTwoFile: c.trust.providerTwoFile,
				knownHostsFile:  c.trust.knownHostsFile,
			})
		}
		if consumer, ok := collaborator.(finalizerConsumer); ok {
			consumer.UseFinalizerKeyID(finalizerKeyID)
		}
	}
}

// frozenTrust is what downstream collaborators receive: the bytes for anything
// this process checks itself, and the open descriptors for anything a child
// process must be given a name for.
type frozenTrust struct {
	providerOneKey []byte
	providerTwoKey []byte
	knownHosts     []byte

	providerOneFile *os.File
	providerTwoFile *os.File
	knownHostsFile  *os.File
}

// extraFiles rewinds every snapshot and returns them in the order
// trustDescriptorPaths assumes.
//
// The rewind is mandatory, not defensive. A descriptor read to EOF once yields
// nothing on a second read, and this runs once per anchor — genesis, then every
// batch, then the seal. Without it the first child would receive the keys and
// every later child would receive empty files, which SSH would report as an
// unrelated authentication failure partway through an irreversible chain.
func (f frozenTrust) extraFiles() ([]*os.File, error) {
	for _, item := range []struct {
		file     *os.File
		expected []byte
		label    string
	}{
		{f.providerOneFile, f.providerOneKey, "first provider key"},
		{f.providerTwoFile, f.providerTwoKey, "second provider key"},
		{f.knownHostsFile, f.knownHosts, "anchor known hosts"},
	} {
		if err := securefile.RewindSnapshot(
			item.file, item.expected,
		); err != nil {
			return nil, fmt.Errorf("%s snapshot: %w", item.label, err)
		}
	}
	return []*os.File{
		f.providerOneFile, f.providerTwoFile, f.knownHostsFile,
	}, nil
}

// requireFrozenTrustUnchanged re-derives the frozen trust identities and
// requires them to equal what the signed start record binds.
//
// Called inside the last reversible gate, alongside the producer snapshot and
// every anchor-bound digest, because all three describe the same question: is
// the thing about to be anchored the thing that was authorised.
func (c *Controller) requireFrozenTrustUnchanged(record *controllerStart) error {
	// Every value here comes from trustView — the bytes loadTrustInputs
	// actually read and that snapshotFrozenTrust will actually copy. Nothing
	// re-opens a path.
	//
	// The earlier version re-read the three frozen files and compared THOSE
	// bytes against the signed record. That is a different question from the
	// one that matters, and the difference is exploitable: swap the file before
	// loadTrustInputs so malicious bytes populate trustView, restore the
	// original before this check reopens the path, and the check passes while
	// the run proceeds on the malicious bytes. The anonymous snapshot taken
	// afterwards would then faithfully protect the wrong data — the swap
	// happened before the protection point, not after it.
	//
	// "Is what is already in memory authorised" and "is what is currently at
	// this path authorised" are only the same question when nothing can change
	// between the two reads, which is exactly what cannot be assumed here.
	switch {
	case c.trust == nil:
		return errors.New("the trust view has not been loaded")
	case c.trust.providerOneKeyID != record.AnchorProviderOneKey:
		return fmt.Errorf(
			"the loaded first provider key is %s, the signed start record "+
				"binds %s; the anchors would be created under a trust set the "+
				"signature does not cover",
			c.trust.providerOneKeyID, record.AnchorProviderOneKey,
		)
	case c.trust.providerTwoKeyID != record.AnchorProviderTwoKey:
		return fmt.Errorf(
			"the loaded second provider key is %s, the signed start record "+
				"binds %s", c.trust.providerTwoKeyID, record.AnchorProviderTwoKey,
		)
	case c.trust.knownHostsSHA != record.AnchorKnownHostsSHA:
		return fmt.Errorf(
			"the loaded anchor known hosts hash to %s, the signed start record "+
				"binds %s", c.trust.knownHostsSHA, record.AnchorKnownHostsSHA,
		)
	case record.FinalizerKeyID != c.finalizerKeyID:
		return fmt.Errorf(
			"the signed start record names finalizer %s, this run loaded %s; "+
				"the seed was replaced after the transition started",
			record.FinalizerKeyID, c.finalizerKeyID,
		)
	}
	return nil
}

// selectTrustInputs decides WHICH copies of the trust inputs this run reads.
//
// On a resume — a valid signed start record plus a complete frozen set — the
// frozen copies are adopted automatically. That is the default, not something a
// caller opts into: the operator's original paths may legitimately have moved
// or been rotated since the transition began, and a resume that insisted on
// re-reading them would fail for a reason unrelated to the evidence, while a
// resume that silently accepted whatever they now contain would anchor under a
// trust set the signature never covered.
//
// The one exception is the narrow crash window between publishing the start
// record and completing the freeze. There the frozen set is absent or partial
// and the operator's inputs are the only copies that exist; they are read, and
// then used solely to finish the create-once freeze, which refuses any file
// that disagrees with what is already there.
func (c *Controller) selectTrustInputs(started *controllerStart) error {
	anchorRoot := filepath.Join(c.MatrixRoot, "anchors")
	frozenOne := filepath.Join(anchorRoot, "provider-one.ed25519.pub")
	frozenTwo := filepath.Join(anchorRoot, "provider-two.ed25519.pub")
	frozenHosts := filepath.Join(anchorRoot, "known_hosts")

	complete := true
	for _, path := range []string{frozenOne, frozenTwo, frozenHosts} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			complete = false
			break
		}
	}
	if started != nil && complete {
		c.AnchorProviderOneKey = frozenOne
		c.AnchorProviderTwoKey = frozenTwo
		c.AnchorKnownHosts = frozenHosts
		c.usingFrozenTrust = true
	}
	if err := c.loadTrustInputs(); err != nil {
		return err
	}
	if c.mutateBetweenTrustReads != nil {
		c.mutateBetweenTrustReads()
	}
	// On a resume the trust set is checked against the signature immediately,
	// before any producer file is interpreted and long before anything is
	// anchored. The check reads trustView, not the paths, so a swap-then-restore
	// around these two steps cannot make it examine different bytes than the
	// ones the run will use.
	if started != nil && complete {
		if err := c.requireFrozenTrustUnchanged(started); err != nil {
			return err
		}
	}
	return nil
}

// snapshotFrozenTrust builds anonymous, unnamed copies of the verified trust
// bytes.
//
// The source is trustView's IN-MEMORY bytes — the ones already checked against
// the signed start record — not a re-read of any path. That ordering is what
// makes the snapshot meaningful: a swap landing before this point is caught by
// the verification those bytes already passed, and a swap landing after it has
// nothing to act on, because the snapshot no longer refers to any name.
//
// Called after the freeze and before the last reversible gate.
func (c *Controller) snapshotFrozenTrust() error {
	var err error
	if c.trust.providerOneFile, err = securefile.AnonymousSnapshot(
		c.trust.providerOneKey,
	); err != nil {
		return fmt.Errorf("first provider key snapshot: %w", err)
	}
	if c.trust.providerTwoFile, err = securefile.AnonymousSnapshot(
		c.trust.providerTwoKey,
	); err != nil {
		return fmt.Errorf("second provider key snapshot: %w", err)
	}
	if c.trust.knownHostsFile, err = securefile.AnonymousSnapshot(
		c.trust.knownHosts,
	); err != nil {
		return fmt.Errorf("anchor known hosts snapshot: %w", err)
	}
	return nil
}

// requirePersistedTrustUnchanged single-opens the on-disk frozen trust files
// and requires them to match the signed start record.
//
// This is a SEPARATE check from requireFrozenTrustUnchanged, and collapsing the
// two loses a real failure mode. That one asks "are the bytes this process
// loaded authorised", which catches a swap-before-load followed by a
// restore-before-check. This one asks "is the evidence on disk still what was
// signed", which catches corruption that was already there — a bug elsewhere
// writing bad bytes, a partial restore, a damaged copy — where nothing
// adversarial happened and the in-memory view is consistent with itself.
//
// The anonymous snapshots make post-gate anchor CONSUMPTION safe regardless of
// what the named files hold. They do not make corrupted persisted evidence
// acceptable: a matrix root whose frozen trust files no longer match the
// signature is not evidence anyone should anchor over, whatever this process
// happens to be holding in memory.
//
// It runs inside the last reversible gate, so corrupted evidence is refused
// before any provider is contacted.
func (c *Controller) requirePersistedTrustUnchanged(
	record *controllerStart,
) error {
	_, oneID, err := readAnchorKey(c.trust.frozenProviderOneKey)
	if err != nil {
		return fmt.Errorf("persisted first provider key: %w", err)
	}
	_, twoID, err := readAnchorKey(c.trust.frozenProviderTwoKey)
	if err != nil {
		return fmt.Errorf("persisted second provider key: %w", err)
	}
	_, hostsDigest, err := producersnapshot.ReadRegular(
		c.trust.frozenKnownHosts, producersnapshot.MaximumRecordBytes, nil,
	)
	if err != nil {
		return fmt.Errorf("persisted anchor known hosts: %w", err)
	}
	switch {
	case oneID != record.AnchorProviderOneKey:
		return fmt.Errorf(
			"the persisted first provider key is %s, the signed start record "+
				"binds %s; the evidence on disk no longer matches what was "+
				"signed", oneID, record.AnchorProviderOneKey,
		)
	case twoID != record.AnchorProviderTwoKey:
		return fmt.Errorf(
			"the persisted second provider key is %s, the signed start record "+
				"binds %s", twoID, record.AnchorProviderTwoKey,
		)
	case hostsDigest != record.AnchorKnownHostsSHA:
		return fmt.Errorf(
			"the persisted anchor known hosts hash to %s, the signed start "+
				"record binds %s", hostsDigest, record.AnchorKnownHostsSHA,
		)
	}
	return nil
}

func readAnchorKey(path string) ([]byte, string, error) {
	content, _, err := producersnapshot.ReadRegular(path, producersnapshot.MaximumRecordBytes, nil)
	if err != nil {
		return nil, "", err
	}
	decoded, err := base64.StdEncoding.DecodeString(
		strings.TrimSpace(string(content)),
	)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, "", errors.New("invalid Ed25519 public key")
	}
	return content, phase1anchor.PublicKeyID(ed25519.PublicKey(decoded)), nil
}

var _ = os.Lstat
