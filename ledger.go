//go:build darwin

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

type ledgerHeader struct {
	Schema         string              `json:"schema"`
	TxID           string              `json:"tx_id"`
	Candidate      string              `json:"candidate"`
	Canonical      string              `json:"canonical"`
	Manifest       string              `json:"manifest"`
	Receipt        string              `json:"receipt"`
	CandidateRoot  identity            `json:"candidate_root"`
	CanonicalRoot  identity            `json:"canonical_root"`
	ReceiptParent  identity            `json:"receipt_parent"`
	ManifestObject identity            `json:"manifest_object"`
	CandidateChain []identity          `json:"candidate_ancestor_chain"`
	CanonicalChain []identity          `json:"canonical_ancestor_chain"`
	ReceiptChain   []identity          `json:"receipt_ancestor_chain"`
	CandidateDirs  map[string]identity `json:"candidate_directories"`
	CanonicalDirs  map[string]identity `json:"canonical_directories"`
	EqualFiles     map[string]identity `json:"retained_equal_files"`
	MainInitial    identity            `json:"main_initial"`
	Rows           []row               `json:"rows"`
}

type event struct {
	Seq       int      `json:"seq"`
	Phase     string   `json:"phase"`
	Op        string   `json:"op"`
	Dir       string   `json:"dir"`
	Name      string   `json:"name"`
	OtherDir  string   `json:"other_dir,omitempty"`
	OtherName string   `json:"other_name,omitempty"`
	Before    identity `json:"before,omitempty"`
	Object    identity `json:"object,omitempty"`
}

type ledger struct {
	parent *pinnedDir
	name   string
	fd     int
	file   *os.File
	head   ledgerHeader
	events []event
	seq    int
	fault  int
	hooks  atomic.Int64
}

func newLedger(parent *pinnedDir, name string, head ledgerHeader, fault int) (*ledger, error) {
	fd, err := parent.openLeaf(name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	l := &ledger{parent: parent, name: name, fd: fd, file: os.NewFile(uintptr(fd), name), head: head, fault: fault}
	b, _ := json.Marshal(head)
	if _, err := l.file.Write(append(b, '\n')); err != nil {
		l.file.Close()
		return nil, err
	}
	if err := l.file.Sync(); err != nil {
		l.file.Close()
		return nil, err
	}
	if err := unix.Fsync(parent.fd); err != nil {
		l.file.Close()
		return nil, err
	}
	return l, nil
}

func openLedger(parent *pinnedDir, name string) (*ledger, error) {
	fd, err := parent.openLeaf(name, unix.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil {
		f.Close()
		return nil, err
	}
	lastNewline := bytes.LastIndexByte(raw, '\n')
	if lastNewline < 0 {
		f.Close()
		return nil, errors.New("empty ledger")
	}
	// A process/power death can leave only the last append torn. Ignore that
	// non-newline-terminated fragment; every prior record was fsynced before
	// the next append began.
	lines := bytes.Split(raw[:lastNewline], []byte{'\n'})
	if lastNewline+1 != len(raw) {
		if err := unix.Ftruncate(fd, int64(lastNewline+1)); err != nil {
			f.Close()
			return nil, fmt.Errorf("truncate torn ledger tail: %w", err)
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, fmt.Errorf("fsync repaired ledger: %w", err)
		}
	}
	var h ledgerHeader
	if len(lines) == 0 || json.Unmarshal(lines[0], &h) != nil || h.Schema != schema {
		f.Close()
		return nil, errors.New("invalid ledger header")
	}
	l := &ledger{parent: parent, name: name, fd: fd, file: f, head: h}
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		var e event
		if err := json.Unmarshal(line, &e); err != nil || e.Seq != l.seq+1 {
			f.Close()
			return nil, errors.New("invalid/nonmonotonic ledger event")
		}
		l.events = append(l.events, e)
		l.seq = e.Seq
	}
	_, err = f.Seek(0, 2)
	return l, err
}

func (l *ledger) close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	l.fd = -1
	return err
}

func (l *ledger) append(e event) error {
	l.seq++
	e.Seq = l.seq
	b, _ := json.Marshal(e)
	if _, err := l.file.Write(append(b, '\n')); err != nil {
		return err
	}
	l.hook("ledger-write:" + e.Phase + ":" + e.Op)
	if err := l.file.Sync(); err != nil {
		return err
	}
	l.hook("ledger-fsync:" + e.Phase + ":" + e.Op)
	l.events = append(l.events, e)
	return nil
}

func (l *ledger) hook(label string) {
	n := int(l.hooks.Add(1))
	if l.fault == n {
		// Process-death injection deliberately bypasses defers and error cleanup.
		_ = unix.Kill(unix.Getpid(), unix.SIGKILL)
		for {
		}
	}
	if v := os.Getenv("WINN_E8_R2_TRACE_HOOKS"); v != "" {
		fmt.Fprintf(os.Stderr, "HOOK %d %s\n", n, label)
	}
}

func (l *ledger) mutation(e event, fn func() (identity, error)) (identity, error) {
	e.Phase = "intent"
	if err := l.append(e); err != nil {
		return identity{}, err
	}
	l.hook("after-intent:" + e.Op + ":" + e.Name)
	obj, err := fn()
	l.hook("after-syscall:" + e.Op + ":" + e.Name)
	if err != nil {
		e.Phase = "error"
		if x := l.append(e); x != nil {
			return identity{}, fmt.Errorf("%v; record mutation error: %w", err, x)
		}
		return identity{}, err
	}
	e.Phase = "done"
	e.Object = obj
	if err := l.append(e); err != nil {
		return identity{}, err
	}
	l.hook("after-done:" + e.Op + ":" + e.Name)
	return obj, nil
}

func txID() string {
	var b [16]byte
	fd, err := unix.Open("/dev/urandom", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		panic(err)
	}
	defer unix.Close(fd)
	if _, err := unix.Read(fd, b[:]); err != nil {
		panic(err)
	}
	var x strings.Builder
	for _, v := range b {
		x.WriteString(fmt.Sprintf("%02x", v))
	}
	return x.String()
}

func parseFault(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, errors.New("--fault-at must be a positive mutation-boundary ordinal")
	}
	return n, nil
}
