package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	logFormat      = "winn-audit-hmac-sha256/v1"
	recordDomain   = "winn-audit-record/v1\x00"
	deviceDomain   = "winn-audit-device/v1\x00"
	maxRecordBytes = 64 << 10
	maxDetailBytes = 4096
)

type Sink interface {
	Record(event, deviceID, requestID, detail string) error
	Healthy() bool
}

type Log struct {
	mu       sync.Mutex
	file     *os.File
	key      [32]byte
	sequence uint64
	lastMAC  [32]byte
	now      func() time.Time
	healthy  atomic.Bool
	closed   bool
}

type record struct {
	Format         string `json:"format"`
	Sequence       uint64 `json:"sequence"`
	Timestamp      string `json:"timestamp"`
	Event          string `json:"event"`
	DeviceHash     string `json:"device_hash,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	Detail         string `json:"detail,omitempty"`
	PreviousMAC    string `json:"previous_mac"`
	Authentication string `json:"authentication"`
}

type unsignedRecord struct {
	Format      string `json:"format"`
	Sequence    uint64 `json:"sequence"`
	Timestamp   string `json:"timestamp"`
	Event       string `json:"event"`
	DeviceHash  string `json:"device_hash,omitempty"`
	RequestID   string `json:"request_id,omitempty"`
	Detail      string `json:"detail,omitempty"`
	PreviousMAC string `json:"previous_mac"`
}

func Open(path, keyPath string) (*Log, error) {
	keyData, err := securefile.ReadPrivateLimited(keyPath, 1024)
	if err != nil {
		return nil, fmt.Errorf("read audit key: %w", err)
	}
	defer clear(keyData)
	if len(keyData) != 32 {
		return nil, fmt.Errorf("audit key length is %d, want 32", len(keyData))
	}
	directory := filepath.Dir(path)
	if err := securefile.EnsurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	existing, err := os.Lstat(path)
	if err == nil && !existing.Mode().IsRegular() {
		return nil, errors.New("audit log path is not a regular file")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// #nosec G304 -- path is administrator configuration; its private parent
	// and any existing target were validated immediately above.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() ||
		(existing != nil && !os.SameFile(existing, opened)) {
		_ = file.Close()
		return nil, errors.New("audit log target changed or is not a regular file")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure audit log: %w", err)
	}
	log := &Log{file: file, now: time.Now}
	copy(log.key[:], keyData)
	if err := log.verifyExisting(); err != nil {
		_ = file.Close()
		clear(log.key[:])
		return nil, err
	}
	log.healthy.Store(true)
	return log, nil
}

func Verify(path, keyPath string) error {
	log, err := Open(path, keyPath)
	if err != nil {
		return err
	}
	return log.Close()
}

func (l *Log) Record(event, deviceID, requestID, detail string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("audit log is closed")
	}
	if event == "" {
		return l.fail(errors.New("audit event is empty"))
	}
	if len(detail) > maxDetailBytes {
		detail = detail[:maxDetailBytes]
	}
	next := record{
		Format:      logFormat,
		Sequence:    l.sequence + 1,
		Timestamp:   l.now().UTC().Format(time.RFC3339Nano),
		Event:       event,
		RequestID:   requestID,
		Detail:      detail,
		PreviousMAC: hex.EncodeToString(l.lastMAC[:]),
	}
	if deviceID != "" {
		next.DeviceHash = l.hashDevice(deviceID)
	}
	mac, err := l.authenticate(next)
	if err != nil {
		return l.fail(err)
	}
	next.Authentication = hex.EncodeToString(mac[:])
	encoded, err := json.Marshal(next)
	if err != nil {
		return l.fail(err)
	}
	if len(encoded)+1 > maxRecordBytes {
		return l.fail(errors.New("audit record exceeds size limit"))
	}
	encoded = append(encoded, '\n')
	written, err := l.file.Write(encoded)
	if err != nil {
		return l.fail(fmt.Errorf("append audit record: %w", err))
	}
	if written != len(encoded) {
		return l.fail(io.ErrShortWrite)
	}
	if err := l.file.Sync(); err != nil {
		return l.fail(fmt.Errorf("sync audit record: %w", err))
	}
	l.sequence = next.Sequence
	l.lastMAC = mac
	return nil
}

func (l *Log) Healthy() bool {
	return l.healthy.Load()
}

func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	l.healthy.Store(false)
	clear(l.key[:])
	return l.file.Close()
}

func (l *Log) verifyExisting() error {
	if _, err := l.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek audit log: %w", err)
	}
	scanner := bufio.NewScanner(l.file)
	scanner.Buffer(make([]byte, 4096), maxRecordBytes)
	var expectedSequence uint64 = 1
	var previousMAC [32]byte
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Bytes()
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		var entry record
		if err := decoder.Decode(&entry); err != nil {
			return fmt.Errorf("verify audit line %d: %w", lineNumber, err)
		}
		if err := requireEOF(decoder); err != nil {
			return fmt.Errorf("verify audit line %d: %w", lineNumber, err)
		}
		if entry.Format != logFormat {
			return fmt.Errorf("verify audit line %d: unsupported format", lineNumber)
		}
		if entry.Sequence != expectedSequence {
			return fmt.Errorf("verify audit line %d: sequence discontinuity", lineNumber)
		}
		if _, err := time.Parse(time.RFC3339Nano, entry.Timestamp); err != nil {
			return fmt.Errorf("verify audit line %d: invalid timestamp", lineNumber)
		}
		decodedPrevious, err := hex.DecodeString(entry.PreviousMAC)
		if err != nil || len(decodedPrevious) != sha256.Size ||
			subtle.ConstantTimeCompare(decodedPrevious, previousMAC[:]) != 1 {
			return fmt.Errorf("verify audit line %d: previous MAC mismatch", lineNumber)
		}
		decodedMAC, err := hex.DecodeString(entry.Authentication)
		if err != nil || len(decodedMAC) != sha256.Size {
			return fmt.Errorf("verify audit line %d: invalid authentication", lineNumber)
		}
		expectedMAC, err := l.authenticate(entry)
		if err != nil {
			return fmt.Errorf("verify audit line %d: %w", lineNumber, err)
		}
		if subtle.ConstantTimeCompare(decodedMAC, expectedMAC[:]) != 1 {
			return fmt.Errorf("verify audit line %d: authentication failed", lineNumber)
		}
		previousMAC = expectedMAC
		expectedSequence++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}
	l.sequence = expectedSequence - 1
	l.lastMAC = previousMAC
	if _, err := l.file.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek audit log end: %w", err)
	}
	return nil
}

func (l *Log) authenticate(entry record) ([32]byte, error) {
	unsigned := unsignedRecord{
		Format:      entry.Format,
		Sequence:    entry.Sequence,
		Timestamp:   entry.Timestamp,
		Event:       entry.Event,
		DeviceHash:  entry.DeviceHash,
		RequestID:   entry.RequestID,
		Detail:      entry.Detail,
		PreviousMAC: entry.PreviousMAC,
	}
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		return [32]byte{}, err
	}
	mac := hmac.New(sha256.New, l.key[:])
	_, _ = mac.Write([]byte(recordDomain))
	_, _ = mac.Write(encoded)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result, nil
}

func (l *Log) hashDevice(deviceID string) string {
	mac := hmac.New(sha256.New, l.key[:])
	_, _ = mac.Write([]byte(deviceDomain))
	_, _ = mac.Write([]byte(deviceID))
	return hex.EncodeToString(mac.Sum(nil))
}

func (l *Log) fail(err error) error {
	l.healthy.Store(false)
	return err
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("extra JSON value")
	}
	return err
}
