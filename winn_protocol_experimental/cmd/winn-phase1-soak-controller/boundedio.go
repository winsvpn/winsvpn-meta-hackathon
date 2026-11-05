package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// boundedBuffer retains the final limit bytes and counts every byte it was
// offered.
//
// It never returns a short write and never returns an error, because a child
// process that gets EPIPE or a short write from its own stdout behaves
// differently -- it may die, or block, or retry -- and the controller would
// then be measuring its own back-pressure instead of the runner. Discarding is
// the correct behaviour: the bytes past the limit are not wanted, and the
// runner must not learn that.
type boundedBuffer struct {
	limit int64
	kept  []byte
	total int64
	start int
	full  bool
}

func newBoundedBuffer(limit int64) *boundedBuffer {
	if limit < 0 {
		limit = 0
	}
	return &boundedBuffer{limit: limit}
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := int64(len(p))
	b.total += n
	if b.limit == 0 || len(p) == 0 {
		return len(p), nil
	}
	limit := int(b.limit)
	if len(p) >= limit {
		b.kept = append(b.kept[:0], p[len(p)-limit:]...)
		b.start = 0
		b.full = true
		return len(p), nil
	}
	for _, value := range p {
		if len(b.kept) < limit {
			b.kept = append(b.kept, value)
			continue
		}
		b.kept[b.start] = value
		b.start = (b.start + 1) % limit
		b.full = true
	}
	return len(p), nil
}

func (b *boundedBuffer) Bytes() []byte {
	if !b.full || b.start == 0 {
		return append([]byte(nil), b.kept...)
	}
	result := make([]byte, 0, len(b.kept))
	result = append(result, b.kept[b.start:]...)
	result = append(result, b.kept[:b.start]...)
	return result
}
func (b *boundedBuffer) Total() int64    { return b.total }
func (b *boundedBuffer) Truncated() bool { return b.total > int64(len(b.kept)) }

// rotatingLog is an append-only log with a hard ceiling on the disk it can
// ever occupy: maxBytes per file, maxFiles files, and nothing else. The
// ceiling is a multiplication, not a hope -- there is no path through this
// type that produces an unrotated file, and no path that keeps more files than
// maxFiles.
type rotatingLog struct {
	mu        sync.Mutex
	directory string
	secure    *secureDirectory
	base      string
	maxBytes  int64
	maxFiles  int
	current   *os.File
	written   int64
	closed    bool
}

var errLogClosed = errors.New("rotating log is closed")

func newRotatingLog(
	directory, base string, maxBytes int64, maxFiles int,
) (*rotatingLog, error) {
	switch {
	case maxBytes <= 0:
		return nil, errors.New("rotating log needs a positive byte budget")
	case maxFiles < 1:
		return nil, errors.New("rotating log needs at least one file")
	case base == "" || base != filepath.Base(base):
		return nil, fmt.Errorf("rotating log base name is invalid: %q", base)
	}
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	l := &rotatingLog{
		directory: directory,
		base:      base,
		maxBytes:  maxBytes,
		maxFiles:  maxFiles,
	}
	secure, err := openSecureDirectory(directory)
	if err != nil {
		return nil, err
	}
	l.secure = secure
	if err := l.validateExistingSet(); err != nil {
		_ = secure.Close()
		return nil, err
	}
	if err := l.open(); err != nil {
		_ = secure.Close()
		return nil, err
	}
	return l, nil
}

func (l *rotatingLog) validateExistingSet() error {
	entries, err := l.secure.ReadDir()
	if err != nil {
		return fmt.Errorf("read log directory: %w", err)
	}
	for _, entry := range entries {
		index := -1
		switch {
		case entry.Name() == l.base:
			index = 0
		case strings.HasPrefix(entry.Name(), l.base+"."):
			suffix := strings.TrimPrefix(entry.Name(), l.base+".")
			parsed, parseErr := strconv.Atoi(suffix)
			if parseErr != nil || parsed < 1 {
				continue
			}
			index = parsed
		default:
			continue
		}
		if index >= l.maxFiles {
			return fmt.Errorf(
				"existing log %s exceeds the %d-file retention set",
				entry.Name(), l.maxFiles,
			)
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat existing log %s: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("existing log %s is not a regular file", entry.Name())
		}
		identity, err := identityFromInfo(info)
		if err != nil {
			return fmt.Errorf("identify existing log %s: %w", entry.Name(), err)
		}
		if identity.nlink != 1 {
			return fmt.Errorf(
				"existing log %s has %d hard links; logs require exclusive identity",
				entry.Name(), identity.nlink,
			)
		}
		if info.Size() > l.maxBytes {
			return fmt.Errorf(
				"existing log %s is %d bytes, above the exact %d-byte bound",
				entry.Name(), info.Size(), l.maxBytes,
			)
		}
	}
	return nil
}

func (l *rotatingLog) path() string {
	return filepath.Join(l.directory, l.base)
}

func (l *rotatingLog) open() error {
	// #nosec G304 -- the path is directory-joined with a validated base name
	// that filepath.Base has already been shown to fix-point.
	file, err := l.secure.Open(
		l.base, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600,
	)
	if err != nil {
		return fmt.Errorf("open log %s: %w", l.path(), err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("stat log %s: %w", l.path(), err)
	}
	l.current = file
	l.written = info.Size()
	return nil
}

// Budget is the maximum bytes this log can ever occupy on disk.
func (l *rotatingLog) Budget() int64 {
	return saturatingMultiply(l.maxBytes, int64(l.maxFiles))
}

func (l *rotatingLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return 0, errLogClosed
	}
	if err := l.secure.VerifyPath(); err != nil {
		l.closed = true
		return 0, fmt.Errorf("log directory continuity: %w", err)
	}
	info, err := l.current.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat current log: %w", err)
	}
	identity, err := identityFromInfo(info)
	if err != nil {
		return 0, fmt.Errorf("identify current log: %w", err)
	}
	if identity.nlink != 1 {
		return 0, fmt.Errorf(
			"current log lost exclusive identity (nlink=%d)", identity.nlink,
		)
	}
	total := 0
	for len(p) > 0 {
		if l.written >= l.maxBytes {
			if err := l.rotateLocked(); err != nil {
				l.closed = true
				if l.current != nil {
					_ = l.current.Close()
					l.current = nil
				}
				return total, err
			}
		}
		room := l.maxBytes - l.written
		take := int64(len(p))
		if take > room {
			take = room
		}
		n, err := l.current.Write(p[:int(take)])
		l.written += int64(n)
		total += n
		p = p[n:]
		if err != nil {
			return total, fmt.Errorf("append to log: %w", err)
		}
		if int64(n) != take {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (l *rotatingLog) rotateLocked() error {
	if err := l.validateExistingSet(); err != nil {
		return fmt.Errorf("validate rotation set: %w", err)
	}
	if err := l.current.Close(); err != nil {
		return fmt.Errorf("close log before rotation: %w", err)
	}
	l.current = nil
	// Shift down from the oldest so nothing is ever overwritten by a file
	// that has not yet been moved. The oldest is removed first, which is
	// what makes maxFiles a real ceiling rather than a target.
	oldest := filepath.Join(
		l.directory, fmt.Sprintf("%s.%d", l.base, l.maxFiles-1),
	)
	if err := l.secure.Remove(filepath.Base(oldest)); err != nil &&
		!os.IsNotExist(err) {
		return fmt.Errorf("remove oldest log: %w", err)
	}
	for index := l.maxFiles - 2; index >= 1; index-- {
		from := filepath.Join(
			l.directory, fmt.Sprintf("%s.%d", l.base, index),
		)
		to := filepath.Join(
			l.directory, fmt.Sprintf("%s.%d", l.base, index+1),
		)
		if err := l.secure.Rename(
			filepath.Base(from), filepath.Base(to),
		); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("rotate log %s: %w", from, err)
		}
	}
	if l.maxFiles > 1 {
		first := filepath.Join(l.directory, l.base+".1")
		if err := l.secure.Rename(l.base, filepath.Base(first)); err != nil &&
			!os.IsNotExist(err) {
			return fmt.Errorf("rotate current log: %w", err)
		}
	} else {
		// A single-file budget still has to be a budget. Truncating is
		// the only way to honour it without keeping a second file.
		if err := l.secure.Remove(l.base); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("truncate single log: %w", err)
		}
	}
	return l.open()
}

func (l *rotatingLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.current == nil {
		if l.secure != nil {
			err := l.secure.Close()
			l.secure = nil
			return err
		}
		return nil
	}
	err := l.current.Close()
	l.current = nil
	var findings []error
	if err != nil {
		findings = append(findings, fmt.Errorf("close log: %w", err))
	}
	if l.secure != nil {
		if closeErr := l.secure.Close(); closeErr != nil {
			findings = append(findings, closeErr)
		}
		l.secure = nil
	}
	return errors.Join(findings...)
}

// emitter is the controller's own output. It is bounded for the same reason
// the child's is: a controller that logs one line per retry and then retries
// in a tight loop for seven days fills the disk with its own commentary and
// takes the evidence directory down with it.
type emitter struct {
	mu    sync.Mutex
	sink  io.Writer
	limit int64
	used  int64
	over  bool
}

func newEmitter(sink io.Writer, limit int64) *emitter {
	return &emitter{sink: sink, limit: limit}
}

func (e *emitter) Printf(format string, args ...any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.over {
		return
	}
	line := fmt.Sprintf(format, args...)
	if !hasTrailingNewline(line) {
		line += "\n"
	}
	if e.used+int64(len(line)) > e.limit {
		e.over = true
		final := "winn-phase1-soak-controller: output budget reached; " +
			"further controller output is suppressed. Cycle evidence " +
			"continues to be written to the receipt log.\n"
		_, _ = io.WriteString(e.sink, final)
		return
	}
	e.used += int64(len(line))
	_, _ = io.WriteString(e.sink, line)
}

func hasTrailingNewline(s string) bool {
	return len(s) > 0 && s[len(s)-1] == '\n'
}
