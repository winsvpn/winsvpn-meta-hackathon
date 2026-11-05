//go:build darwin

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func (t *transaction) bindExistingLedger() error {
	l, err := openLedger(t.receiptParent, t.ledgerLeaf)
	if err != nil {
		return err
	}
	h := l.head
	if h.Schema != schema || h.Candidate != t.cfg.Candidate || h.Canonical != t.cfg.Canonical ||
		h.Manifest != t.cfg.Manifest || h.Receipt != t.cfg.Receipt ||
		!sameDir(h.CandidateRoot, t.candidate.id) || !sameDir(h.CanonicalRoot, t.canonical.id) ||
		!sameDir(h.ReceiptParent, t.receiptParent.id) || !sameFull(h.ManifestObject, t.manifestID) ||
		len(h.Rows) != len(t.rows) {
		l.close()
		return errors.New("existing ledger binding drift; recovery refused")
	}
	if !sameChain(h.CandidateChain, t.candidateChain) || !sameChain(h.CanonicalChain, t.canonicalChain) ||
		!sameChain(h.ReceiptChain, t.receiptChain) {
		l.close()
		return errors.New("absolute ancestor identity chain drift; recovery refused")
	}
	for rel, want := range h.CandidateDirs {
		d, e := t.dir(t.candidate, t.candidateDirs, rel)
		if e != nil || !sameDir(d.id, want) {
			l.close()
			return fmt.Errorf("candidate parent rename/substitution drift: %s", rel)
		}
	}
	for rel, want := range h.CanonicalDirs {
		d, e := t.dir(t.canonical, t.canonicalDirs, rel)
		if e != nil || !sameDir(d.id, want) {
			l.close()
			return fmt.Errorf("canonical parent rename/substitution drift: %s", rel)
		}
	}
	for i := range h.Rows {
		if h.Rows[i] != t.rows[i] {
			l.close()
			return errors.New("existing ledger manifest rows drift")
		}
	}
	t.log = l
	t.tx = h.TxID
	t.equalIDs = h.EqualFiles
	t.mainInitial = h.MainInitial
	return nil
}

func sameChain(a, b []identity) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !sameDir(a[i], b[i]) {
			return false
		}
	}
	return true
}

func (t *transaction) ledgerExists() (bool, error) {
	id, err := t.receiptParent.statLeaf(t.ledgerLeaf)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if id.Type != unix.S_IFREG || id.Mode != 0600 || id.UID != t.receiptParent.id.UID {
		return false, errors.New("ledger leaf type/mode/owner invalid")
	}
	return true, nil
}

func hashIdentity(d *pinnedDir, leaf string, limit int64) (identity, error) {
	fd, err := d.openLeaf(leaf, unix.O_RDONLY, 0)
	if err != nil {
		return identity{}, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return identity{}, err
	}
	sha := ""
	if st.Mode&unix.S_IFMT == unix.S_IFREG {
		if st.Size < 0 || st.Size > limit {
			return identity{}, errors.New("recovery object exceeds bound")
		}
		sha, _, err = hashFD(fd, limit)
		if err != nil {
			return identity{}, err
		}
	}
	entry, err := d.statLeaf(leaf)
	if err != nil {
		return identity{}, err
	}
	got := identityOf(&st, sha)
	if !sameObject(got, entry) {
		return identity{}, errors.New("recovery descriptor/entry race")
	}
	return got, nil
}

func (t *transaction) dirByLabel(label string) (*pinnedDir, error) {
	if label == "@receipt" {
		return t.receiptParent, t.receiptParent.recheck()
	}
	return t.dir(t.canonical, t.canonicalDirs, label)
}

func (t *transaction) recover(cause error) error {
	if t.log == nil {
		return cause
	}
	t.log.fault = 0
	events := append([]event(nil), t.log.events...)
	// The durable commit decision is the transaction's point of no return:
	// finishSuccess appends it before cleanup, and the restart path in main
	// treats it as forward-only (verify and finish cleanup, never roll
	// back). Rolling back here would undo a decided commit in-process and
	// then append "rolled-back" after "commit-decided", a terminal pair the
	// restart path can never reconcile (it would demand the promoted final
	// state from a tree this rollback just reverted). Refuse and let the
	// rerun finish the decided commit forward.
	if commitDecided(events) {
		return fmt.Errorf("%v; RECOVERY REQUIRED: transaction is commit-decided; rollback refused, rerun to finish the decided cleanup", cause)
	}
	createdByName := map[string]identity{}
	for _, e := range events {
		if e.Phase == "done" && (e.Op == "create-file" || e.Op == "mkdir") {
			createdByName[e.Dir+"\x00"+e.Name] = e.Object
		}
	}

	// First resolve the atomic main swap. No other rollback deletion is allowed
	// until the activation identities are unambiguous.
	mainDir, mainLeaf, err := t.canonicalParent(mainPath)
	if err != nil {
		return fmt.Errorf("%v; RECOVERY REQUIRED: %w", cause, err)
	}
	mainStage := ".winn-e8-r7." + t.tx + ".main.stage"
	mainNow, mainErr := hashIdentity(mainDir, mainLeaf, e7MainSize+4096)
	stageNow, stageErr := hashIdentity(mainDir, mainStage, e7MainSize+4096)
	wasCommitted := false
	switch {
	case mainErr == nil && mainNow.SHA == e8MainSHA && sameObject(mainNow, stageIdentityFromEvents(events, mainStage)) &&
		stageErr == nil && stageNow.SHA == e7MainSHA && sameObject(stageNow, t.log.headForMainInitial(events)):
		wasCommitted = true
		_, err = t.mutate(event{
			Op: "recovery-rename-swap", Dir: "cmd/winn-phase1-soak-controller", Name: mainStage,
			OtherDir: "cmd/winn-phase1-soak-controller", OtherName: mainLeaf,
			Before: mainNow, Object: stageNow,
		}, func() (identity, error) {
			if err := unix.RenameatxNp(mainDir.fd, mainStage, mainDir.fd, mainLeaf, unix.RENAME_SWAP); err != nil {
				return identity{}, err
			}
			t.log.hook("recovery-main-rename-swap")
			if err := unix.Fsync(mainDir.fd); err != nil {
				return identity{}, err
			}
			t.log.hook("recovery-main-parent-fsync")
			return stageNow, nil
		})
		if err != nil {
			return fmt.Errorf("%v; RECOVERY REQUIRED: restore main: %w", cause, err)
		}
	case mainErr == nil && mainNow.SHA == e8MainSHA && sameObject(mainNow, stageIdentityFromEvents(events, mainStage)) &&
		errors.Is(stageErr, unix.ENOENT):
		// The success cleanup may have unlinked the local E7 inode immediately
		// before process death. Reconstruct an exact descriptor-verified E7
		// stage from the external recovery copy, journal its identity, swap it
		// atomically with E8, then remove only the exact displaced E8 object.
		wasCommitted = true
		rfd, x := t.receiptParent.openLeaf(t.recoveryLeaf, unix.O_RDONLY, 0)
		if x != nil {
			return fmt.Errorf("%v; RECOVERY REQUIRED: E7 recovery copy absent: %w", cause, x)
		}
		rf := os.NewFile(uintptr(rfd), t.recoveryLeaf)
		b, readErr := io.ReadAll(io.LimitReader(rf, e7MainSize+1))
		rf.Close()
		if readErr != nil {
			return fmt.Errorf("%v; RECOVERY REQUIRED: read E7 recovery copy: %w", cause, readErr)
		}
		if int64(len(b)) != e7MainSize || sumBytes(b) != e7MainSHA {
			return fmt.Errorf("%v; RECOVERY REQUIRED: E7 recovery bytes drift", cause)
		}
		restore := ".winn-e8-r7." + t.tx + ".recovery-restore.stage"
		restoreID, x := t.createCompleteFile(mainDir, "cmd/winn-phase1-soak-controller", restore, b, 0644)
		if x != nil {
			return fmt.Errorf("%v; RECOVERY REQUIRED: create restore stage: %w", cause, x)
		}
		_, x = t.mutate(event{
			Op: "recovery-rename-swap", Dir: "cmd/winn-phase1-soak-controller", Name: restore,
			OtherDir: "cmd/winn-phase1-soak-controller", OtherName: mainLeaf,
			Before: mainNow, Object: restoreID,
		}, func() (identity, error) {
			if err := unix.RenameatxNp(mainDir.fd, restore, mainDir.fd, mainLeaf, unix.RENAME_SWAP); err != nil {
				return identity{}, err
			}
			if err := unix.Fsync(mainDir.fd); err != nil {
				return identity{}, err
			}
			return restoreID, nil
		})
		if x != nil {
			return fmt.Errorf("%v; RECOVERY REQUIRED: external restore swap: %w", cause, x)
		}
		if _, x := t.unlinkExact(mainDir, "cmd/winn-phase1-soak-controller", restore, mainNow); x != nil {
			return fmt.Errorf("%v; RECOVERY REQUIRED: displaced E8 cleanup: %w", cause, x)
		}
	case mainErr == nil && mainNow.SHA == e7MainSHA:
		// No activation, or an already-recovered activation.
	default:
		return fmt.Errorf("%v; RECOVERY REQUIRED: main replacement/identity ambiguity; no rollback deletion attempted", cause)
	}

	// Remove transaction-published leaves in reverse manifest order, but only
	// when identity, type, mode, ownership, size, and hash equal the ledger.
	for i := len(t.rows) - 1; i >= 0; i-- {
		r := t.rows[i]
		if !absentPaths[r.Path] {
			continue
		}
		dp, dl, e := t.canonicalParent(r.Path)
		if e != nil {
			continue // node may not have reached publication
		}
		got, e := hashIdentity(dp, dl, r.Size)
		if errors.Is(e, unix.ENOENT) {
			continue
		}
		if e != nil {
			return fmt.Errorf("%v; RECOVERY REQUIRED: inspect %s: %w", cause, r.Path, e)
		}
		want := publishedIdentity(events, r.Path, dl)
		if want.Ino == 0 || !sameFull(got, want) || got.SHA != r.SHA {
			return fmt.Errorf("%v; RECOVERY REQUIRED: unrelated replacement at %s; deletion refused", cause, r.Path)
		}
		if _, e := t.unlinkExact(dp, filepath.ToSlash(filepath.Dir(r.Path)), dl, want); e != nil {
			return fmt.Errorf("%v; RECOVERY REQUIRED: rollback %s: %w", cause, r.Path, e)
		}
	}

	// Clean transaction-private stages. A create/record crash is adopted only
	// after recording the exact observed dev/inode/type/mode/uid/gid/size/hash.
	for _, e := range events {
		if e.Op != "create-file" || !strings.Contains(e.Name, t.tx) {
			continue
		}
		d, x := t.dirByLabel(e.Dir)
		if x != nil {
			continue
		}
		got, x := hashIdentity(d, e.Name, 64<<20)
		if errors.Is(x, unix.ENOENT) {
			continue
		}
		if x != nil {
			return fmt.Errorf("%v; RECOVERY REQUIRED: stage inspect: %w", cause, x)
		}
		recorded := createdByName[e.Dir+"\x00"+e.Name]
		if recorded.Ino == 0 {
			if x := t.log.append(event{Phase: "recovery-adopt", Op: "record-post-identity", Dir: e.Dir, Name: e.Name, Object: got}); x != nil {
				return fmt.Errorf("%v; RECOVERY REQUIRED: record stage identity: %w", cause, x)
			}
			recorded = got
		}
		if !sameFull(got, recorded) {
			return fmt.Errorf("%v; RECOVERY REQUIRED: stage replacement; deletion refused", cause)
		}
		if _, x := t.unlinkExact(d, e.Dir, e.Name, recorded); x != nil {
			return fmt.Errorf("%v; RECOVERY REQUIRED: stage cleanup: %w", cause, x)
		}
	}

	// Clean an unpublished staged node directory. The transaction UUID in the
	// name plus its durable intent establishes ownership; the exact observed
	// post-create identity is durably adopted before rmdir.
	for _, e := range events {
		if e.Op != "mkdir" || !strings.Contains(e.Name, t.tx) {
			continue
		}
		d, x := t.dirByLabel(e.Dir)
		if x != nil {
			continue
		}
		got, x := d.statLeaf(e.Name)
		if errors.Is(x, unix.ENOENT) {
			continue
		}
		if x != nil {
			return fmt.Errorf("%v; RECOVERY REQUIRED: node stage inspect: %w", cause, x)
		}
		recorded := createdByName[e.Dir+"\x00"+e.Name]
		if recorded.Ino == 0 {
			if x := t.log.append(event{Phase: "recovery-adopt", Op: "record-post-identity", Dir: e.Dir, Name: e.Name, Object: got}); x != nil {
				return fmt.Errorf("%v; RECOVERY REQUIRED: record node stage identity: %w", cause, x)
			}
			recorded = got
		}
		if !sameDir(got, recorded) {
			return fmt.Errorf("%v; RECOVERY REQUIRED: node stage replacement; rmdir refused", cause)
		}
		_, x = t.mutate(event{Op: "rmdir", Dir: e.Dir, Name: e.Name, Before: recorded}, func() (identity, error) {
			if err := unix.Unlinkat(d.fd, e.Name, unix.AT_REMOVEDIR); err != nil {
				return identity{}, err
			}
			if err := unix.Fsync(d.fd); err != nil {
				return identity{}, err
			}
			return recorded, nil
		})
		if x != nil {
			return fmt.Errorf("%v; RECOVERY REQUIRED: node stage cleanup: %w", cause, x)
		}
	}

	// Remove the exact created node directory only after its children are gone.
	cmd, _ := t.dir(t.canonical, t.canonicalDirs, "cmd")
	nodeLeaf := filepath.Base(nodeDir)
	nodeNow, nodeErr := cmd.statLeaf(nodeLeaf)
	if nodeErr == nil {
		want := renamedNodeIdentity(events, nodeLeaf)
		if want.Ino == 0 || !sameDir(nodeNow, want) {
			return fmt.Errorf("%v; RECOVERY REQUIRED: node replacement; rmdir refused", cause)
		}
		_, err := t.mutate(event{Op: "rmdir", Dir: "cmd", Name: nodeLeaf, Before: want}, func() (identity, error) {
			if err := unix.Unlinkat(cmd.fd, nodeLeaf, unix.AT_REMOVEDIR); err != nil {
				return identity{}, err
			}
			t.log.hook("recovery-node-unlinkat")
			if err := unix.Fsync(cmd.fd); err != nil {
				return identity{}, err
			}
			t.log.hook("recovery-node-parent-fsync")
			return want, nil
		})
		if err != nil {
			return fmt.Errorf("%v; RECOVERY REQUIRED: node rollback: %w", cause, err)
		}
	} else if !errors.Is(nodeErr, unix.ENOENT) {
		return fmt.Errorf("%v; RECOVERY REQUIRED: node inspect: %w", cause, nodeErr)
	}

	// A pre-activation recovery removes the exact external E7 copy. Once main
	// was activated it is retained with the receipt/ledger as recovery evidence.
	if !wasCommitted {
		if id, e := hashIdentity(t.receiptParent, t.recoveryLeaf, e7MainSize); e == nil {
			if id.SHA != e7MainSHA {
				return fmt.Errorf("%v; RECOVERY REQUIRED: external E7 replacement; deletion refused", cause)
			}
			if _, e := t.unlinkExact(t.receiptParent, "@receipt", t.recoveryLeaf, id); e != nil {
				return fmt.Errorf("%v; RECOVERY REQUIRED: external cleanup: %w", cause, e)
			}
		}
	}
	if gate, e := hashIdentity(t.canonical, ".winn-e8-r7-promotion.lock", 4096); e == nil {
		want := linkedIdentity(events, "", ".winn-e8-r7-promotion.lock")
		if want.Ino == 0 || !sameFull(gate, want) {
			return fmt.Errorf("%v; RECOVERY REQUIRED: writer gate replacement; unlink refused", cause)
		}
		if _, e := t.unlinkExact(t.canonical, "", ".winn-e8-r7-promotion.lock", want); e != nil {
			return fmt.Errorf("%v; RECOVERY REQUIRED: gate cleanup: %w", cause, e)
		}
	}
	_ = t.log.append(event{Phase: "terminal", Op: "rolled-back", Name: cause.Error()})
	return fmt.Errorf("STOP recovered exact E7 closure after transaction failure: %w", cause)
}

func stageIdentityFromEvents(es []event, leaf string) identity {
	for i := len(es) - 1; i >= 0; i-- {
		if es[i].Op == "create-file" && es[i].Name == leaf && es[i].Phase == "done" {
			return es[i].Object
		}
	}
	return identity{}
}

func (l *ledger) headForMainInitial(es []event) identity {
	for _, e := range es {
		if e.Op == "rename-swap" && strings.HasSuffix(e.OtherName, "main.go") {
			return e.Before
		}
	}
	// If death occurred after syscall but before the done record, the intent
	// already carries the exact E7 identity.
	return identity{}
}

func publishedIdentity(es []event, path, leaf string) identity {
	dir := filepath.ToSlash(filepath.Dir(path))
	for i := len(es) - 1; i >= 0; i-- {
		e := es[i]
		if e.Op == "link" && e.OtherDir == dir && e.OtherName == leaf {
			if e.Object.Ino != 0 {
				return e.Object
			}
			return stageIdentityFromEvents(es, e.Name)
		}
	}
	return identity{}
}

func linkedIdentity(es []event, dir, leaf string) identity {
	for i := len(es) - 1; i >= 0; i-- {
		e := es[i]
		if e.Op == "link" && e.OtherDir == dir && e.OtherName == leaf {
			if e.Object.Ino != 0 {
				return e.Object
			}
			return stageIdentityFromEvents(es, e.Name)
		}
	}
	return identity{}
}

func renamedNodeIdentity(es []event, leaf string) identity {
	for i := len(es) - 1; i >= 0; i-- {
		e := es[i]
		if e.Op == "rename-excl" && e.OtherName == leaf {
			if e.Object.Ino != 0 {
				return e.Object
			}
			for j := i - 1; j >= 0; j-- {
				if es[j].Op == "mkdir" && es[j].Name == e.Name && es[j].Phase == "done" {
					return es[j].Object
				}
			}
		}
	}
	return identity{}
}

func (t *transaction) removeLedgerAfterTerminalForTest() error {
	if os.Getenv("WINN_E8_R2_REMOVE_LEDGER") != "1" {
		return nil
	}
	return errors.New("ledger removal intentionally unsupported: audit evidence is append-only")
}
