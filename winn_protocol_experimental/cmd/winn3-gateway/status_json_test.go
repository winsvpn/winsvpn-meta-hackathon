package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

type immediateReadFailureConn struct{}

func (immediateReadFailureConn) ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, errors.New("immediate read failure")
}
func (immediateReadFailureConn) WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error) {
	return 0, errors.New("unexpected write")
}
func (immediateReadFailureConn) SetReadDeadline(time.Time) error { return nil }
func (immediateReadFailureConn) Close() error                    { return nil }
func (immediateReadFailureConn) LocalAddr() net.Addr             { return &net.UDPAddr{} }

func TestServeDoesNotPublishListeningBeforeReadProbeSucceeds(t *testing.T) {
	srv := &server{conn: immediateReadFailureConn{}, proofListen: "127.0.0.1:51820"}
	var out bytes.Buffer
	err := srv.serve(context.Background(), &out)
	if err == nil || !strings.Contains(err.Error(), "failed before readiness publication") {
		t.Fatalf("serve error = %v", err)
	}
	if strings.Contains(out.String(), `"event":"listening"`) {
		t.Fatalf("listening status was published before the read probe succeeded: %s", out.String())
	}
}

func TestValidateProofStatusPathIsClosed(t *testing.T) {
	if err := validateProofStatusPath(""); err != nil {
		t.Fatalf("empty status path: %v", err)
	}
	if err := validateProofStatusPath(proofStatusPath); err != nil {
		t.Fatalf("canonical status path: %v", err)
	}
	if err := validateProofStatusPath("/tmp/status.json"); err == nil {
		t.Fatal("arbitrary status path was accepted")
	}
}

func TestProofStatusHasExactCollectorContract(t *testing.T) {
	delivered := uint64(7)
	got := proofStatusOf(serveStatus{
		Event:                 "posture",
		Ready:                 true,
		Forward:               &gatewayForwardStatus{},
		ProofProcessID:        1234,
		ProofProcessNonce:     "0123456789abcdef0123456789abcdef",
		ProofBootID:           "01234567-89ab-cdef-0123-456789abcdef",
		ProofProcessTicks:     4567,
		ProofProcessStarted:   "2026-08-25T04:00:00Z",
		ProofObservedUTC:      "2026-08-25T04:00:01Z",
		ProofObservedMonoNS:   123456789,
		ProofSequence:         9,
		InnerPacketsDelivered: &delivered,
		Reflected:             0,
		RxDeviceWrites:        9,
	})
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(encoded, &record); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"schema_version":          true,
		"contract":                true,
		"event":                   true,
		"ready":                   true,
		"forward":                 true,
		"process_id":              true,
		"process_nonce":           true,
		"boot_id":                 true,
		"process_start_ticks":     true,
		"process_started_utc":     true,
		"observed_utc":            true,
		"observed_monotonic_ns":   true,
		"sequence":                true,
		"inner_packets_delivered": true,
		"reflected":               true,
		"rx_device_writes":        true,
	}
	seen := make(map[string]bool, len(record))
	for key := range record {
		seen[key] = true
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("status keys = %v, want %v", seen, want)
	}
	if got.SchemaVersion != 2 ||
		got.Contract != "winsvpn-gcp-proof-winn3-status-v2" ||
		got.Event != "posture" || !got.Ready || got.ProcessID != 1234 ||
		got.ProcessNonce != "0123456789abcdef0123456789abcdef" ||
		got.BootID != "01234567-89ab-cdef-0123-456789abcdef" || got.ProcessStartTicks != 4567 ||
		got.ProcessStartedUTC != "2026-08-25T04:00:00Z" ||
		got.ObservedUTC != "2026-08-25T04:00:01Z" || got.ObservedMonotonicNS != 123456789 || got.Sequence != 9 ||
		!got.Forward || got.InnerPacketsDelivered != 7 ||
		got.Reflected != 0 || got.RxDeviceWrites != 9 {
		t.Fatalf("status = %+v", got)
	}
}

func TestWriteProofStatusFileIsAtomicOwnerOnlyAndRefusesUnsafeLeaf(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production proof status publication is Linux-only")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	status := proofStatus{SchemaVersion: 2, Contract: "winsvpn-gcp-proof-winn3-status-v2", Event: "posture", Ready: true, Forward: true}
	if err := writeProofStatusFile(path, status); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("published mode = %v", info.Mode())
	}
	if err := writeProofStatusFile(path, status); err != nil {
		t.Fatalf("safe replacement: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if err := writeProofStatusFile(path, status); err == nil {
		t.Fatal("symlinked status leaf was accepted")
	}
}

type failingStatusWriter struct{}

func (failingStatusWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestWriteServeStatusDoesNotPublishProofAfterOperatorWriteFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production proof status publication is Linux-only")
	}
	path := filepath.Join(t.TempDir(), "status.json")
	err := writeServeStatus(failingStatusWriter{}, path, serveStatus{Event: "posture", Ready: true})
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("writeServeStatus error = %v, want closed pipe", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("proof status exists after operator write failure: %v", err)
	}
}

func TestProofStatusMarksStoppedProcessUnready(t *testing.T) {
	got := proofStatusOf(serveStatus{Event: "stopped", Ready: true})
	if got.Event != "stopped" || got.Ready {
		t.Fatalf("stopped status remained acceptable: %+v", got)
	}
}

func TestLinuxProcessIdentityParsersRejectMalformedInput(t *testing.T) {
	if !validLinuxBootID("01234567-89ab-cdef-0123-456789abcdef") {
		t.Fatal("canonical lowercase boot ID was rejected")
	}
	for _, value := range []string{
		"01234567-89AB-cdef-0123-456789abcdef",
		"0123456789ab-cdef-0123-456789abcdef",
		"01234567-89ab-cdef-0123-456789abcdeg",
		"",
	} {
		if validLinuxBootID(value) {
			t.Fatalf("malformed boot ID was accepted: %q", value)
		}
	}
	fields := append([]string{"S"}, make([]string, 19)...)
	for index := 1; index < len(fields)-1; index++ {
		fields[index] = "1"
	}
	fields[len(fields)-1] = "777"
	ticks, err := parseLinuxProcessStartTicks("123 (name with spaces) " + strings.Join(fields, " "))
	if err != nil || ticks != 777 {
		t.Fatalf("start ticks = %d, %v", ticks, err)
	}
	for _, line := range []string{"", "123 bad", "123 (name) S 1 2", "123 (name) " + strings.Join(fields[:len(fields)-1], " ")} {
		if _, err := parseLinuxProcessStartTicks(line); err == nil {
			t.Fatalf("malformed process stat was accepted: %q", line)
		}
	}
}

func TestInvalidateProofStatusDoesNotRemoveAnotherProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production proof status publication is Linux-only")
	}
	path := filepath.Join(t.TempDir(), "status.json")
	status := proofStatus{SchemaVersion: 2, Contract: "winsvpn-gcp-proof-winn3-status-v2", ProcessNonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if err := writeProofStatusFile(path, status); err != nil {
		t.Fatal(err)
	}
	if err := invalidateProofStatusFile(path, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("foreign process status was removed: %v", err)
	}
	if err := invalidateProofStatusFile(path, status.ProcessNonce, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned status remains after invalidation: %v", err)
	}
}

func TestStartupInvalidationDoesNotRemoveLiveProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production proof status publication is Linux-only")
	}
	bootID, startTicks, err := proofProcessIdentity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "status.json")
	status := proofStatus{
		SchemaVersion: 2, Contract: "winsvpn-gcp-proof-winn3-status-v2",
		ProcessID: os.Getpid(), ProcessNonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BootID: bootID, ProcessStartTicks: startTicks,
		ProcessStartedUTC: "2026-08-25T04:00:00Z",
	}
	if err := writeProofStatusFile(path, status); err != nil {
		t.Fatal(err)
	}
	if err := invalidateProofStatusFile(path, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", true); err == nil {
		t.Fatal("startup invalidation removed an active process status")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("active process status was removed: %v", err)
	}
}

func TestProofStatusLeaseIsKernelSingleton(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production proof status lease is Linux-only")
	}
	first, err := acquireProofStatusLease(proofStatusPath)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := acquireProofStatusLease(proofStatusPath); err == nil {
		_ = second.Close()
		t.Fatal("second process lease was acquired while the first remained live")
	}
}

func TestWriteProofStatusFileDoesNotOverwriteAnotherProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production proof status publication is Linux-only")
	}
	path := filepath.Join(t.TempDir(), "status.json")
	first := proofStatus{
		SchemaVersion: 2, Contract: "winsvpn-gcp-proof-winn3-status-v2",
		ProcessID: 10, ProcessNonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BootID: "01234567-89ab-cdef-0123-456789abcdef", ProcessStartTicks: 100,
		ProcessStartedUTC: "2026-08-25T04:00:00Z",
	}
	if err := writeProofStatusFile(path, first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.ProcessID = 11
	second.ProcessNonce = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	second.ProcessStartTicks = 200
	if err := writeProofStatusFile(path, second); err == nil {
		t.Fatal("foreign process overwrote the current proof status")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got proofStatus
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !sameProofStatusProcess(got, first) {
		t.Fatalf("published identity changed: %+v", got)
	}
}

// The proof reader opens the status name directly; a replacement must never
// leave a moment in which that name does not exist, and must not leave the
// previous status behind under another name.
func TestWriteProofStatusFileReplacementNeverHidesTheName(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production proof status publication is Linux-only")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	status := proofStatus{SchemaVersion: 2, Contract: "winsvpn-gcp-proof-winn3-status-v2", Event: "posture", Ready: true}
	if err := writeProofStatusFile(path, status); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	missing := make(chan int, 1)
	go func() {
		count := 0
		for {
			select {
			case <-stop:
				missing <- count
				return
			default:
			}
			if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
				count++
			}
		}
	}()
	var writeErr error
	for i := 0; i < 500 && writeErr == nil; i++ {
		status.Sequence = uint64(i + 1)
		writeErr = writeProofStatusFile(path, status)
	}
	close(stop)
	if count := <-missing; count != 0 {
		t.Fatalf("status name was missing %d times during replacement", count)
	}
	if writeErr != nil {
		t.Fatalf("replacement: %v", writeErr)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if name := entry.Name(); name != "status.json" && name != ".status-json.lock" {
			t.Fatalf("replacement left %q behind", name)
		}
	}
}

func TestWriteProofStatusFileRefusesSymlinkedParent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production proof status publication is Linux-only")
	}
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(root, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	err := writeProofStatusFile(filepath.Join(linkedParent, "status.json"), proofStatus{})
	if err == nil {
		t.Fatal("symlinked proof status parent was accepted")
	}
	if _, err := os.Lstat(filepath.Join(realParent, "status.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("status escaped through symlinked parent: %v", err)
	}
}
