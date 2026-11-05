//go:build darwin

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type transaction struct {
	cfg              config
	rows             []row
	byPath           map[string]row
	candidate        *pinnedDir
	canonical        *pinnedDir
	receiptParent    *pinnedDir
	candidateChain   []identity
	canonicalChain   []identity
	receiptChain     []identity
	candidateDirs    map[string]*pinnedDir
	canonicalDirs    map[string]*pinnedDir
	manifestParent   *pinnedDir
	manifestLeaf     string
	manifestID       identity
	receiptLeaf      string
	ledgerLeaf       string
	recoveryLeaf     string
	receiptStageLeaf string
	recoveryStage    string
	tx               string
	log              *ledger
	equalIDs         map[string]identity
	mainInitial      identity
	expectedUID      uint32
	expectedGID      uint32
	created          map[string]identity
	nodeID           identity
	mainStageID      identity
	mainCommitted    bool
	gateID           identity
}

func parseManifestFromDescriptor(path string) ([]row, *pinnedDir, string, identity, error) {
	path, err := cleanAbs(path)
	if err != nil {
		return nil, nil, "", identity{}, err
	}
	parent, leaf := filepath.Split(path)
	parent = strings.TrimSuffix(parent, string(filepath.Separator))
	if parent == "" {
		parent = "/"
	}
	pd, _, err := openPinnedAbsolute(parent)
	if err != nil {
		return nil, nil, "", identity{}, err
	}
	fd, err := pd.openLeaf(leaf, unix.O_RDONLY, 0)
	if err != nil {
		pd.close()
		return nil, nil, "", identity{}, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		pd.close()
		return nil, nil, "", identity{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0644 || st.Nlink != 1 ||
		st.Size != expectedManifestSize {
		pd.close()
		return nil, nil, "", identity{}, errors.New("manifest type/mode/nlink/size drift")
	}
	sha, n, err := hashFD(fd, expectedManifestSize)
	if err != nil || n != expectedManifestSize || sha != expectedManifestSHA {
		pd.close()
		return nil, nil, "", identity{}, errors.New("manifest hash drift")
	}
	dup, _ := unix.Dup(fd)
	f := os.NewFile(uintptr(dup), "manifest")
	defer f.Close()
	_, _ = f.Seek(0, 0)
	b, err := io.ReadAll(io.LimitReader(f, expectedManifestSize+1))
	if err != nil || len(b) != expectedManifestSize {
		pd.close()
		return nil, nil, "", identity{}, errors.New("manifest descriptor read failed")
	}
	var rows []row
	s := bufio.NewScanner(bytes.NewReader(b))
	inRows := false
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "a9a9e4e") {
			inRows = true
		}
		if !inRows {
			continue
		}
		if line == "" {
			break
		}
		parts := strings.Split(line, "  ")
		if len(parts) != 3 || len(parts[0]) != 64 {
			pd.close()
			return nil, nil, "", identity{}, fmt.Errorf("invalid manifest row %q", line)
		}
		n, e := strconv.ParseInt(parts[1], 10, 64)
		if e != nil || n < 0 || !safeRel(parts[2]) {
			pd.close()
			return nil, nil, "", identity{}, errors.New("invalid manifest row")
		}
		rows = append(rows, row{SHA: parts[0], Size: n, Path: parts[2]})
	}
	if len(rows) != 19 {
		pd.close()
		return nil, nil, "", identity{}, fmt.Errorf("manifest row count=%d", len(rows))
	}
	aggregate := func(rs []row) string {
		var x strings.Builder
		for _, r := range rs {
			fmt.Fprintf(&x, "%s  %d  %s\n", r.SHA, r.Size, r.Path)
		}
		return sumBytes([]byte(x.String()))
	}
	if aggregate(rows[:18]) != expectedProdSHA || aggregate(rows) != expectedAllSHA ||
		rows[12].Path != mainPath || rows[12].SHA != e8MainSHA {
		pd.close()
		return nil, nil, "", identity{}, errors.New("manifest exact closure drift")
	}
	return rows, pd, leaf, identityOf(&st, sha), nil
}

func newTransaction(c config) (*transaction, error) {
	rows, mp, ml, mid, err := parseManifestFromDescriptor(c.Manifest)
	if err != nil {
		return nil, err
	}
	t := &transaction{
		cfg: c, rows: rows, byPath: map[string]row{}, manifestParent: mp,
		manifestLeaf: ml, manifestID: mid, candidateDirs: map[string]*pinnedDir{},
		canonicalDirs: map[string]*pinnedDir{}, equalIDs: map[string]identity{},
		created: map[string]identity{},
	}
	for _, r := range rows {
		t.byPath[r.Path] = r
	}
	t.candidate, t.candidateChain, err = openPinnedAbsolute(c.Candidate)
	if err != nil {
		t.close()
		return nil, fmt.Errorf("candidate root: %w", err)
	}
	t.canonical, t.canonicalChain, err = openPinnedAbsolute(c.Canonical)
	if err != nil {
		t.close()
		return nil, fmt.Errorf("canonical root: %w", err)
	}
	t.expectedUID, t.expectedGID = t.canonical.id.UID, t.canonical.id.GID
	receipt, err := cleanAbs(c.Receipt)
	if err != nil {
		t.close()
		return nil, fmt.Errorf("receipt: %w", err)
	}
	rp, rl := filepath.Split(receipt)
	rp = strings.TrimSuffix(rp, string(filepath.Separator))
	if rp == "" {
		rp = "/"
	}
	t.receiptParent, t.receiptChain, err = openPinnedAbsolute(rp)
	if err != nil {
		t.close()
		return nil, fmt.Errorf("receipt parent: %w", err)
	}
	if chainsOverlapAtOrBelow(t.receiptChain, t.canonicalChain) ||
		chainsOverlapAtOrBelow(t.receiptChain, t.candidateChain) {
		t.close()
		return nil, errors.New("receipt parent is descriptor-descended from protected root")
	}
	if strings.Contains(rl, "/") || rl == "" || rl == "." || rl == ".." {
		t.close()
		return nil, errors.New("invalid receipt leaf")
	}
	t.receiptLeaf = rl
	t.ledgerLeaf = rl + ".ledger"
	t.recoveryLeaf = rl + ".e7-main"
	return t, nil
}

func (t *transaction) close() {
	if t.log != nil {
		_ = t.log.close()
	}
	for _, ds := range []map[string]*pinnedDir{t.candidateDirs, t.canonicalDirs} {
		for _, d := range ds {
			d.close()
		}
	}
	if t.manifestParent != nil {
		t.manifestParent.close()
	}
	if t.candidate != nil {
		t.candidate.close()
	}
	if t.canonical != nil {
		t.canonical.close()
	}
	if t.receiptParent != nil {
		t.receiptParent.close()
	}
}

func (t *transaction) dir(root *pinnedDir, cache map[string]*pinnedDir, rel string) (*pinnedDir, error) {
	if d := cache[rel]; d != nil {
		return d, d.recheck()
	}
	d, err := root.openDir(rel)
	if err != nil {
		return nil, err
	}
	if err := requireSameFilesystem(root, d); err != nil {
		d.close()
		return nil, fmt.Errorf("%w: %s", err, d.label)
	}
	cache[rel] = d
	return d, nil
}

func (t *transaction) candidateParent(path string) (*pinnedDir, string, error) {
	d, leaf, err := splitRel(path)
	if err != nil {
		return nil, "", err
	}
	p, err := t.dir(t.candidate, t.candidateDirs, d)
	return p, leaf, err
}

func (t *transaction) canonicalParent(path string) (*pinnedDir, string, error) {
	d, leaf, err := splitRel(path)
	if err != nil {
		return nil, "", err
	}
	p, err := t.dir(t.canonical, t.canonicalDirs, d)
	return p, leaf, err
}

func absent(d *pinnedDir, leaf string) error {
	_, err := d.statLeaf(leaf)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err == nil {
		return errors.New("required-absent object exists")
	}
	return err
}

func (t *transaction) preflight() error {
	if len(equalPaths) != 6 || len(absentPaths) != 12 {
		return errors.New("internal partition invalid")
	}
	for _, root := range []*pinnedDir{t.candidate, t.canonical, t.receiptParent, t.manifestParent} {
		if err := root.recheck(); err != nil {
			return err
		}
	}
	t.expectedUID, t.expectedGID = t.canonical.id.UID, t.canonical.id.GID
	var openBarriers []leafRef
	for _, r := range t.rows {
		sp, sl, err := t.candidateParent(r.Path)
		if err != nil {
			return err
		}
		if _, err := verifyLeaf(sp, sl, r, true); err != nil {
			return fmt.Errorf("candidate %s: %w", r.Path, err)
		}
		if absentPaths[r.Path] && strings.HasPrefix(r.Path, nodeDir+"/") {
			continue // the exclusively-absent node directory proves these absent
		}
		dp, dl, err := t.canonicalParent(r.Path)
		if err != nil {
			return err
		}
		switch {
		case equalPaths[r.Path]:
			id, err := verifyLeaf(dp, dl, r, true)
			if err != nil {
				return fmt.Errorf("equal %s: %w", r.Path, err)
			}
			openBarriers = append(openBarriers, leafRef{dp, dl, id})
			t.equalIDs[r.Path] = id
		case r.Path == mainPath:
			id, err := verifyLeaf(dp, dl, row{SHA: e7MainSHA, Size: e7MainSize, Path: mainPath}, true)
			if err != nil {
				return fmt.Errorf("E7 main: %w", err)
			}
			openBarriers = append(openBarriers, leafRef{dp, dl, id})
			t.mainInitial = id
		case absentPaths[r.Path]:
			if err := absent(dp, dl); err != nil {
				return fmt.Errorf("absent %s: %w", r.Path, err)
			}
		default:
			return fmt.Errorf("unpartitioned manifest path %s", r.Path)
		}
	}
	if err := lsofEmptySet(openBarriers); err != nil {
		return fmt.Errorf("present-destination open-file barrier: %w", err)
	}
	cmd, err := t.dir(t.canonical, t.canonicalDirs, "cmd")
	if err != nil {
		return err
	}
	if err := absent(cmd, filepath.Base(nodeDir)); err != nil {
		return errors.New("sealed-node directory must be absent")
	}
	for _, leaf := range []string{t.receiptLeaf, t.recoveryLeaf} {
		if err := absent(t.receiptParent, leaf); err != nil {
			return fmt.Errorf("external output %s: %w", leaf, err)
		}
	}
	return nil
}

func (t *transaction) recheckInitial() error {
	for _, r := range t.rows {
		if absentPaths[r.Path] && strings.HasPrefix(r.Path, nodeDir+"/") {
			continue
		}
		dp, dl, err := t.canonicalParent(r.Path)
		if err != nil {
			return err
		}
		switch {
		case equalPaths[r.Path]:
			id, err := verifyLeaf(dp, dl, r, true)
			if err != nil || !sameFull(id, t.equalIDs[r.Path]) {
				return fmt.Errorf("equal destination drift %s", r.Path)
			}
		case r.Path == mainPath:
			id, err := verifyLeaf(dp, dl, row{SHA: e7MainSHA, Size: e7MainSize, Path: mainPath}, true)
			if err != nil || !sameFull(id, t.mainInitial) {
				return errors.New("E7 main drift")
			}
		default:
			if err := absent(dp, dl); err != nil {
				return fmt.Errorf("destination drift %s", r.Path)
			}
		}
	}
	cmd, _ := t.dir(t.canonical, t.canonicalDirs, "cmd")
	return absent(cmd, filepath.Base(nodeDir))
}

func (t *transaction) beginLedger() error {
	t.tx = txID()
	candidateDirs := map[string]identity{}
	for k, d := range t.candidateDirs {
		candidateDirs[k] = d.id
	}
	canonicalDirs := map[string]identity{}
	for k, d := range t.canonicalDirs {
		canonicalDirs[k] = d.id
	}
	head := ledgerHeader{
		Schema: schema, TxID: t.tx, Candidate: t.cfg.Candidate, Canonical: t.cfg.Canonical,
		Manifest: t.cfg.Manifest, Receipt: t.cfg.Receipt, CandidateRoot: t.candidate.id,
		CanonicalRoot: t.canonical.id, ReceiptParent: t.receiptParent.id,
		ManifestObject: t.manifestID, CandidateChain: t.candidateChain,
		CanonicalChain: t.canonicalChain, ReceiptChain: t.receiptChain,
		CandidateDirs: candidateDirs, CanonicalDirs: canonicalDirs,
		EqualFiles: t.equalIDs, MainInitial: t.mainInitial, Rows: t.rows,
	}
	var err error
	t.log, err = newLedger(t.receiptParent, t.ledgerLeaf, head, t.cfg.FaultAt)
	return err
}

func (t *transaction) mutate(e event, fn func() (identity, error)) (identity, error) {
	return t.log.mutation(e, fn)
}

func (t *transaction) createCompleteFile(d *pinnedDir, dirLabel, leaf string, data []byte, mode uint32) (identity, error) {
	return t.mutate(event{Op: "create-file", Dir: dirLabel, Name: leaf}, func() (identity, error) {
		fd, err := d.openLeaf(leaf, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, mode)
		if err != nil {
			return identity{}, err
		}
		t.log.hook("create-openat:" + dirLabel + ":" + leaf)
		f := os.NewFile(uintptr(fd), leaf)
		n, werr := f.Write(data)
		t.log.hook("create-write:" + dirLabel + ":" + leaf)
		if werr == nil && n != len(data) {
			werr = io.ErrShortWrite
		}
		if werr == nil {
			werr = unix.Fchmod(fd, mode)
		}
		t.log.hook("create-fchmod:" + dirLabel + ":" + leaf)
		if werr == nil {
			werr = unix.Fchown(fd, int(d.id.UID), int(d.id.GID))
		}
		t.log.hook("create-fchown:" + dirLabel + ":" + leaf)
		if werr == nil {
			werr = f.Sync()
		}
		t.log.hook("create-file-fsync:" + dirLabel + ":" + leaf)
		var st unix.Stat_t
		if werr == nil {
			werr = unix.Fstat(fd, &st)
		}
		cerr := f.Close()
		t.log.hook("create-close:" + dirLabel + ":" + leaf)
		if werr == nil {
			werr = cerr
		}
		if werr != nil {
			return identity{}, werr
		}
		id := identityOf(&st, sumBytes(data))
		if id.Type != unix.S_IFREG || id.Mode != mode || id.Size != int64(len(data)) {
			return identity{}, errors.New("created file metadata mismatch")
		}
		if err := unix.Fsync(d.fd); err != nil {
			return identity{}, err
		}
		t.log.hook("create-dir-fsync:" + dirLabel + ":" + leaf)
		return id, nil
	})
}

func readExactSource(d *pinnedDir, leaf string, r row) ([]byte, identity, error) {
	id, err := verifyLeaf(d, leaf, r, true)
	if err != nil {
		return nil, identity{}, err
	}
	fd, err := d.openLeaf(leaf, unix.O_RDONLY, 0)
	if err != nil {
		return nil, identity{}, err
	}
	defer unix.Close(fd)
	f := os.NewFile(uintptr(fd), leaf)
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, r.Size+1))
	if err != nil || int64(len(b)) != r.Size || sumBytes(b) != r.SHA {
		return nil, identity{}, errors.New("source changed during copy")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || !sameObject(identityOf(&st, r.SHA), id) {
		return nil, identity{}, errors.New("source descriptor identity drift")
	}
	return b, id, nil
}

func (t *transaction) createGate() error {
	stage := ".winn-e8-r7." + t.tx + ".gate.stage"
	final := ".winn-e8-r7-promotion.lock"
	data := []byte("winn-e8-r7 transaction " + t.tx + "\n")
	id, err := t.createCompleteFile(t.canonical, "", stage, data, 0600)
	if err != nil {
		return err
	}
	t.gateID = id
	_, err = t.mutate(event{Op: "link", Dir: "", Name: stage, OtherDir: "", OtherName: final, Object: id}, func() (identity, error) {
		if err := unix.Linkat(t.canonical.fd, stage, t.canonical.fd, final, 0); err != nil {
			return identity{}, err
		}
		t.log.hook("gate-linkat")
		if err := unix.Fsync(t.canonical.fd); err != nil {
			return identity{}, err
		}
		t.log.hook("gate-dir-fsync")
		got, err := t.canonical.statLeaf(final)
		if err != nil || !sameObject(got, id) {
			return identity{}, errors.New("gate publish identity mismatch")
		}
		return id, nil
	})
	if err != nil {
		return err
	}
	_, err = t.unlinkExact(t.canonical, "", stage, id)
	return err
}

func (t *transaction) createNode() error {
	cmd, err := t.dir(t.canonical, t.canonicalDirs, "cmd")
	if err != nil {
		return err
	}
	stage := ".winn-e8-r7." + t.tx + ".node.stage"
	id, err := t.mutate(event{Op: "mkdir", Dir: "cmd", Name: stage}, func() (identity, error) {
		if err := unix.Mkdirat(cmd.fd, stage, 0755); err != nil {
			return identity{}, err
		}
		t.log.hook("node-mkdirat")
		stageFD, err := unix.Openat(cmd.fd, stage, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return identity{}, err
		}
		t.log.hook("node-openat")
		if err := unix.Fchmod(stageFD, 0755); err != nil {
			unix.Close(stageFD)
			return identity{}, err
		}
		t.log.hook("node-fchmod")
		if err := unix.Fchown(stageFD, int(cmd.id.UID), int(cmd.id.GID)); err != nil {
			unix.Close(stageFD)
			return identity{}, err
		}
		t.log.hook("node-fchown")
		if err := unix.Fsync(stageFD); err != nil {
			unix.Close(stageFD)
			return identity{}, err
		}
		t.log.hook("node-fsync")
		if err := unix.Close(stageFD); err != nil {
			return identity{}, err
		}
		t.log.hook("node-close")
		if err := unix.Fsync(cmd.fd); err != nil {
			return identity{}, err
		}
		t.log.hook("node-stage-parent-fsync")
		got, err := cmd.statLeaf(stage)
		if err != nil {
			return identity{}, err
		}
		if got.Type != unix.S_IFDIR || got.Mode != 0755 || got.UID != cmd.id.UID || got.GID != cmd.id.GID {
			return identity{}, errors.New("staged node metadata mismatch")
		}
		return got, nil
	})
	if err != nil {
		return err
	}
	final := filepath.Base(nodeDir)
	_, err = t.mutate(event{Op: "rename-excl", Dir: "cmd", Name: stage, OtherDir: "cmd", OtherName: final, Object: id}, func() (identity, error) {
		if err := unix.RenameatxNp(cmd.fd, stage, cmd.fd, final, unix.RENAME_EXCL); err != nil {
			return identity{}, err
		}
		t.log.hook("node-renameatx-np")
		if err := unix.Fsync(cmd.fd); err != nil {
			return identity{}, err
		}
		t.log.hook("node-final-parent-fsync")
		got, err := cmd.statLeaf(final)
		if err != nil || !sameFull(got, id) {
			return identity{}, errors.New("node publication identity mismatch")
		}
		return id, nil
	})
	if err != nil {
		return err
	}
	node, err := t.dir(t.canonical, t.canonicalDirs, nodeDir)
	if err != nil || !sameDir(node.id, id) {
		return errors.New("cannot retain exact published node descriptor")
	}
	t.nodeID = id
	return nil
}

func (t *transaction) stageAndPublish(r row) error {
	sp, sl, err := t.candidateParent(r.Path)
	if err != nil {
		return err
	}
	b, _, err := readExactSource(sp, sl, r)
	if err != nil {
		return err
	}
	dp, dl, err := t.canonicalParent(r.Path)
	if err != nil {
		return err
	}
	dir, _, _ := splitRel(r.Path)
	stage := ".winn-e8-r7." + t.tx + "." + dl + ".stage"
	id, err := t.createCompleteFile(dp, dir, stage, b, 0644)
	if err != nil {
		return err
	}
	_, err = t.mutate(event{Op: "link", Dir: dir, Name: stage, OtherDir: dir, OtherName: dl, Object: id}, func() (identity, error) {
		if err := unix.Linkat(dp.fd, stage, dp.fd, dl, 0); err != nil {
			return identity{}, err
		}
		t.log.hook("file-linkat:" + r.Path)
		if err := unix.Fsync(dp.fd); err != nil {
			return identity{}, err
		}
		t.log.hook("file-publish-parent-fsync:" + r.Path)
		got, err := dp.statLeaf(dl)
		if err != nil || !sameObject(got, id) {
			return identity{}, errors.New("published identity mismatch")
		}
		return id, nil
	})
	if err != nil {
		return err
	}
	t.created[r.Path] = id
	_, err = t.unlinkExact(dp, dir, stage, id)
	return err
}

func (t *transaction) unlinkExact(d *pinnedDir, dirLabel, leaf string, want identity) (identity, error) {
	return t.mutate(event{Op: "unlink", Dir: dirLabel, Name: leaf, Before: want}, func() (identity, error) {
		got, err := d.statLeaf(leaf)
		if err != nil {
			return identity{}, err
		}
		if !sameObject(got, want) || got.Type != want.Type || got.Mode != want.Mode ||
			got.UID != want.UID || got.GID != want.GID || got.Size != want.Size {
			return identity{}, errors.New("unlink exact identity/metadata refusal")
		}
		if want.SHA != "" && want.Type == unix.S_IFREG {
			v, err := hashIdentity(d, leaf, want.Size)
			if err != nil || !sameFull(v, want) {
				return identity{}, errors.New("unlink exact hash refusal")
			}
		}
		if err := unix.Unlinkat(d.fd, leaf, 0); err != nil {
			return identity{}, err
		}
		t.log.hook("unlinkat:" + dirLabel + ":" + leaf)
		if err := unix.Fsync(d.fd); err != nil {
			return identity{}, err
		}
		t.log.hook("unlink-parent-fsync:" + dirLabel + ":" + leaf)
		return want, nil
	})
}

func (t *transaction) prepareRecovery() error {
	mainDir, mainLeaf, _ := t.canonicalParent(mainPath)
	fd, err := mainDir.openLeaf(mainLeaf, unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), mainLeaf)
	b, err := io.ReadAll(io.LimitReader(f, e7MainSize+1))
	f.Close()
	if err != nil || int64(len(b)) != e7MainSize || sumBytes(b) != e7MainSHA {
		return errors.New("E7 recovery source drift")
	}
	t.recoveryStage = "." + t.recoveryLeaf + "." + t.tx + ".stage"
	id, err := t.createCompleteFile(t.receiptParent, "@receipt", t.recoveryStage, b, 0644)
	if err != nil {
		return err
	}
	_, err = t.mutate(event{Op: "link", Dir: "@receipt", Name: t.recoveryStage, OtherDir: "@receipt", OtherName: t.recoveryLeaf, Object: id}, func() (identity, error) {
		if err := unix.Linkat(t.receiptParent.fd, t.recoveryStage, t.receiptParent.fd, t.recoveryLeaf, 0); err != nil {
			return identity{}, err
		}
		t.log.hook("recovery-copy-linkat")
		if err := unix.Fsync(t.receiptParent.fd); err != nil {
			return identity{}, err
		}
		t.log.hook("recovery-copy-parent-fsync")
		return id, nil
	})
	if err != nil {
		return err
	}
	_, err = t.unlinkExact(t.receiptParent, "@receipt", t.recoveryStage, id)
	return err
}

func (t *transaction) stageMain() error {
	r := t.byPath[mainPath]
	sp, sl, _ := t.candidateParent(mainPath)
	b, _, err := readExactSource(sp, sl, r)
	if err != nil {
		return err
	}
	dp, dl, _ := t.canonicalParent(mainPath)
	stage := ".winn-e8-r7." + t.tx + ".main.stage"
	id, err := t.createCompleteFile(dp, "cmd/winn-phase1-soak-controller", stage, b, 0644)
	if err != nil {
		return err
	}
	t.mainStageID = id
	_ = dl
	return nil
}

func (t *transaction) commitMainSwap() error {
	dp, dl, _ := t.canonicalParent(mainPath)
	stage := ".winn-e8-r7." + t.tx + ".main.stage"
	old, err := verifyLeaf(dp, dl, row{SHA: e7MainSHA, Size: e7MainSize}, true)
	if err != nil || !sameFull(old, t.mainInitial) {
		return errors.New("last-moment E7 identity/hash/ownership drift")
	}
	if err := lsofEmptyBracketed(dp, dl, old); err != nil {
		return err
	}
	_, err = t.mutate(event{
		Op: "rename-swap", Dir: "cmd/winn-phase1-soak-controller", Name: stage,
		OtherDir: "cmd/winn-phase1-soak-controller", OtherName: dl,
		Before: old, Object: t.mainStageID,
	}, func() (identity, error) {
		if err := unix.RenameatxNp(dp.fd, stage, dp.fd, dl, unix.RENAME_SWAP); err != nil {
			return identity{}, err
		}
		t.log.hook("main-rename-swap")
		if err := unix.Fsync(dp.fd); err != nil {
			return identity{}, err
		}
		t.log.hook("main-parent-fsync")
		nowMain, err := verifyLeaf(dp, dl, t.byPath[mainPath], true)
		if err != nil || !sameFull(nowMain, t.mainStageID) {
			return identity{}, errors.New("post-swap E8 mismatch")
		}
		nowStage, err := verifyLeaf(dp, stage, row{SHA: e7MainSHA, Size: e7MainSize}, true)
		if err != nil || !sameFull(nowStage, t.mainInitial) {
			return identity{}, errors.New("post-swap retained E7 mismatch")
		}
		return t.mainStageID, nil
	})
	if err == nil {
		t.mainCommitted = true
	}
	return err
}

func (t *transaction) publishReceipt() error {
	body := map[string]any{
		"schema": "winn-e8-r7-promotion-recovery-receipt/2", "tx_id": t.tx,
		"candidate": t.cfg.Candidate, "canonical": t.cfg.Canonical,
		"manifest_sha256": expectedManifestSHA, "production18_sha256": expectedProdSHA,
		"source19_sha256": expectedAllSHA, "e7_recovery_leaf": t.recoveryLeaf,
		"main_before": t.mainInitial, "main_after": t.mainStageID,
	}
	b, _ := json.Marshal(body)
	b = append(b, '\n')
	t.receiptStageLeaf = "." + t.receiptLeaf + "." + t.tx + ".stage"
	id, err := t.createCompleteFile(t.receiptParent, "@receipt", t.receiptStageLeaf, b, 0444)
	if err != nil {
		return err
	}
	_, err = t.mutate(event{Op: "link", Dir: "@receipt", Name: t.receiptStageLeaf, OtherDir: "@receipt", OtherName: t.receiptLeaf, Object: id}, func() (identity, error) {
		if err := unix.Linkat(t.receiptParent.fd, t.receiptStageLeaf, t.receiptParent.fd, t.receiptLeaf, 0); err != nil {
			return identity{}, err
		}
		t.log.hook("receipt-linkat")
		if err := unix.Fsync(t.receiptParent.fd); err != nil {
			return identity{}, err
		}
		t.log.hook("receipt-parent-fsync")
		return id, nil
	})
	if err != nil {
		return err
	}
	_, err = t.unlinkExact(t.receiptParent, "@receipt", t.receiptStageLeaf, id)
	return err
}

func (t *transaction) verifyFinal() error {
	var prod, all strings.Builder
	var openBarriers []leafRef
	for i, r := range t.rows {
		dp, dl, err := t.canonicalParent(r.Path)
		if err != nil {
			return err
		}
		id, err := verifyLeaf(dp, dl, r, true)
		if err != nil {
			return fmt.Errorf("final %s: %w", r.Path, err)
		}
		if _, retained := t.equalIDs[r.Path]; !retained && (id.UID != dp.id.UID || id.GID != dp.id.GID) {
			return fmt.Errorf("final %s owner/group differs from pinned parent", r.Path)
		}
		openBarriers = append(openBarriers, leafRef{dp, dl, id})
		sp, sl, err := t.candidateParent(r.Path)
		if err != nil {
			return err
		}
		sourceBytes, _, err := readExactSource(sp, sl, r)
		if err != nil {
			return fmt.Errorf("final source byte assertion %s: %w", r.Path, err)
		}
		finalBytes, _, err := readExactSource(dp, dl, r)
		if err != nil || !bytes.Equal(sourceBytes, finalBytes) {
			return fmt.Errorf("final byte-equality assertion failed: %s", r.Path)
		}
		line := fmt.Sprintf("%s  %d  %s\n", r.SHA, r.Size, r.Path)
		all.WriteString(line)
		if i < 18 {
			prod.WriteString(line)
		}
		if want, ok := t.equalIDs[r.Path]; ok && !sameFull(id, want) {
			return fmt.Errorf("retained equal inode/metadata drift: %s", r.Path)
		}
	}
	if err := lsofEmptySet(openBarriers); err != nil {
		return fmt.Errorf("final open-file barrier: %w", err)
	}
	if sumBytes([]byte(prod.String())) != expectedProdSHA || sumBytes([]byte(all.String())) != expectedAllSHA {
		return errors.New("final aggregate digest drift")
	}
	node, err := t.dir(t.canonical, t.canonicalDirs, nodeDir)
	nodeWant := t.nodeID
	if nodeWant.Ino == 0 && t.log != nil {
		nodeWant = renamedNodeIdentity(t.log.events, filepath.Base(nodeDir))
	}
	if err != nil || !sameDir(node.id, nodeWant) {
		return errors.New("node identity drift")
	}
	fd, err := unix.Dup(node.fd)
	if err != nil {
		return err
	}
	names, err := os.NewFile(uintptr(fd), "node").Readdirnames(-1)
	if err != nil || len(names) != 4 {
		return errors.New("node exact census mismatch")
	}
	allow := map[string]bool{"main_linux.go": true, "main_unsupported.go": true, "sandbox_linux.go": true, "main_linux_test.go": true}
	for _, n := range names {
		if !allow[n] {
			return fmt.Errorf("unexpected node leaf %s", n)
		}
	}
	expectedTemps := map[string]map[string]bool{
		"": {".winn-e8-r7-promotion.lock": true},
		"cmd/winn-phase1-soak-controller": {
			".winn-e8-r7." + t.tx + ".main.stage": true,
		},
		"internal/realcycle": {},
		nodeDir:              {},
	}
	for rel, allowed := range expectedTemps {
		d, err := t.dir(t.canonical, t.canonicalDirs, rel)
		if err != nil {
			return err
		}
		fd, err := unix.Dup(d.fd)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), "census")
		dirNames, readErr := f.Readdirnames(-1)
		closeErr := f.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		for _, name := range dirNames {
			if strings.HasPrefix(name, ".winn-e8-r7.") && !allowed[name] {
				return fmt.Errorf("unexpected promotion temporary in %s: %s", rel, name)
			}
		}
	}
	return nil
}

func (t *transaction) execute() error {
	if err := t.preflight(); err != nil {
		return err
	}
	if err := t.beginLedger(); err != nil {
		return err
	}
	if err := t.createGate(); err != nil {
		return t.recover(errors.New("writer gate: " + err.Error()))
	}
	if err := t.recheckInitial(); err != nil {
		return t.recover(err)
	}
	if err := t.prepareRecovery(); err != nil {
		return t.recover(err)
	}
	if err := t.createNode(); err != nil {
		return t.recover(err)
	}
	for _, r := range t.rows {
		if absentPaths[r.Path] {
			if err := t.stageAndPublish(r); err != nil {
				return t.recover(err)
			}
		}
	}
	if len(t.created) != 12 {
		return t.recover(errors.New("did not publish exact 12 destinations"))
	}
	if err := t.stageMain(); err != nil {
		return t.recover(err)
	}
	if err := t.commitMainSwap(); err != nil {
		return t.recover(err)
	}
	if err := t.publishReceipt(); err != nil {
		return t.recover(err)
	}
	if err := t.verifyFinal(); err != nil {
		return t.recover(err)
	}
	if err := t.finishSuccess(); err != nil {
		if t.log != nil && commitDecided(t.log.events) {
			// Past the durable decision the only safe direction is forward:
			// the rerun's commit-decided path verifies and finishes cleanup.
			return err
		}
		return t.recover(err)
	}
	return nil
}

func (t *transaction) finishSuccess() error {
	if err := t.log.append(event{Phase: "decision", Op: "commit-decided", Dir: "", Name: ""}); err != nil {
		return err
	}
	return t.finishSuccessCleanup()
}

func (t *transaction) finishSuccessCleanup() error {
	dp, _, _ := t.canonicalParent(mainPath)
	mainStage := ".winn-e8-r7." + t.tx + ".main.stage"
	mainBefore := t.mainInitial
	if mainBefore.Ino == 0 {
		mainBefore = t.log.headForMainInitial(t.log.events)
	}
	if got, err := hashIdentity(dp, mainStage, e7MainSize); err == nil {
		if mainBefore.Ino == 0 || !sameFull(got, mainBefore) {
			return errors.New("commit cleanup E7 stage replacement; unlink refused")
		}
		if _, err := t.unlinkExact(dp, "cmd/winn-phase1-soak-controller", mainStage, mainBefore); err != nil {
			return err
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	gateWant := t.gateID
	if gateWant.Ino == 0 {
		gateWant = linkedIdentity(t.log.events, "", ".winn-e8-r7-promotion.lock")
	}
	if got, err := hashIdentity(t.canonical, ".winn-e8-r7-promotion.lock", 4096); err == nil {
		if gateWant.Ino == 0 || !sameFull(got, gateWant) {
			return errors.New("commit cleanup writer gate replacement; unlink refused")
		}
		if _, err := t.unlinkExact(t.canonical, "", ".winn-e8-r7-promotion.lock", gateWant); err != nil {
			return err
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err := t.log.append(event{Phase: "terminal", Op: "complete", Dir: "", Name: ""}); err != nil {
		return err
	}
	return nil
}

func (t *transaction) finishSuccessCleanupIdempotent() error {
	dp, _, _ := t.canonicalParent(mainPath)
	stage := ".winn-e8-r7." + t.tx + ".main.stage"
	if _, err := dp.statLeaf(stage); err == nil {
		return errors.New("terminal ledger retains main stage")
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	if _, err := t.canonical.statLeaf(".winn-e8-r7-promotion.lock"); err == nil {
		return errors.New("terminal ledger retains writer gate")
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}
