//go:build unix

package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/driver"
)

// Clearing of the application-owned key buffers (Round L, OI-L2).
//
// Each test keeps a reference to every buffer the key code takes ownership
// of, through winn3SecretAcquiredHook, and then checks the bytes themselves.
// "Cleared" here means those identified buffers read zero; it says nothing
// about copies the runtime or crypto/ecdh make (see winn3KeyMaterial).

type acquiredSecret struct {
	field  string
	buffer []byte
	// held is whether the buffer carried a non-zero byte when it was
	// acquired, so a test cannot pass by watching buffers that never held a
	// secret.
	held bool
}

type secretRecorder struct {
	mu      sync.Mutex
	entries []acquiredSecret
}

func recordAcquiredSecrets(t *testing.T) *secretRecorder {
	t.Helper()
	r := &secretRecorder{}
	previous := winn3SecretAcquiredHook
	winn3SecretAcquiredHook = func(field string, buffer []byte) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.entries = append(r.entries, acquiredSecret{
			field: field, buffer: buffer, held: !isZero(buffer),
		})
	}
	t.Cleanup(func() { winn3SecretAcquiredHook = previous })
	return r
}

func (r *secretRecorder) snapshot() []acquiredSecret {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]acquiredSecret(nil), r.entries...)
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func splitRound(entries []acquiredSecret) (material, round []acquiredSecret) {
	for _, e := range entries {
		if strings.HasPrefix(e.field, "round:") {
			round = append(round, e)
		} else {
			material = append(material, e)
		}
	}
	return material, round
}

// requireCleared fails unless entries is non-empty, at least one entry held
// a secret, and every entry now reads zero.
func requireCleared(t *testing.T, what string, entries []acquiredSecret) {
	t.Helper()
	if len(entries) == 0 {
		t.Fatalf("%s: no owned buffer was recorded; nothing is being cleared", what)
	}
	held := false
	for _, e := range entries {
		held = held || e.held
		if !isZero(e.buffer) {
			t.Errorf("%s: the %s buffer (%d bytes) still holds data", what, e.field, len(e.buffer))
		}
	}
	if !held {
		t.Fatalf("%s: no recorded buffer ever held a secret; the check is vacuous", what)
	}
}

func requireFieldHeld(t *testing.T, what, field string, entries []acquiredSecret) {
	t.Helper()
	for _, e := range entries {
		if e.field == field && e.held && !isZero(e.buffer) {
			return
		}
	}
	t.Fatalf("%s: no live %s buffer; it was cleared too early or never owned", what, field)
}

func writeFile(t *testing.T, path string, content []byte) string {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadMaterialClearsWhatItAcquiredOnEveryRefusal(t *testing.T) {
	for _, stage := range []struct {
		name   string
		mutate func(t *testing.T, dir string, document map[string]any)
		want   string
	}{
		{"static malformed", func(t *testing.T, dir string, d map[string]any) {
			d["static_path"] = writeFile(t, filepath.Join(dir, "short.key"),
				bytes.Repeat([]byte{0x5a}, 31))
		}, "static_path"},
		{"admission missing", func(t *testing.T, dir string, d map[string]any) {
			d["admission_path"] = filepath.Join(dir, "absent.key")
		}, "admission_path"},
		{"gateway static missing", func(t *testing.T, dir string, d map[string]any) {
			d["gateway_static_path"] = filepath.Join(dir, "absent.pub")
		}, "gateway_static_path"},
		{"gateway static malformed", func(t *testing.T, dir string, d map[string]any) {
			d["gateway_static_path"] = writeFile(t, filepath.Join(dir, "bad.pub"), []byte("zzzzz"))
		}, "gateway_static_path"},
		{"dual-auth ed25519 missing", func(t *testing.T, dir string, d map[string]any) {
			_, mlPath, _, _ := stagedDualAuth(t, dir)
			d["dual_auth_ed25519_pub_path"] = filepath.Join(dir, "absent_ed.pub")
			d["dual_auth_mldsa65_pub_path"] = mlPath
		}, "dual_auth_ed25519_pub_path"},
		{"dual-auth mldsa65 malformed", func(t *testing.T, dir string, d map[string]any) {
			edPath, _, _, _ := stagedDualAuth(t, dir)
			d["dual_auth_ed25519_pub_path"] = edPath
			d["dual_auth_mldsa65_pub_path"] = writeFile(t, filepath.Join(dir, "bad_ml.pub"), []byte("not hex\n"))
		}, "dual_auth_mldsa65_pub_path"},
	} {
		t.Run(stage.name, func(t *testing.T) {
			dir := t.TempDir()
			document := validKeys(t, dir)
			stage.mutate(t, dir, document)
			keys, err := loadWinn3Keys(writeKeys(t, dir, document))
			if err != nil {
				t.Fatalf("the document itself was refused: %v", err)
			}
			rec := recordAcquiredSecrets(t)
			if _, err := keys.readMaterial(); err == nil || !strings.Contains(err.Error(), stage.want) {
				t.Fatalf("readMaterial returned %v, want a %s refusal", err, stage.want)
			}
			requireCleared(t, stage.name, rec.snapshot())
		})
	}
}

func TestWipeClearsEveryOwnedAllocationIncludingTrimmedTails(t *testing.T) {
	dir := t.TempDir()
	document := validKeys(t, dir)
	// A trailing newline makes the admission view shorter than its
	// allocation; the tail must be cleared too.
	document["admission_path"] = writeFile(t, filepath.Join(dir, "admission_nl.key"),
		[]byte("lab-admission-secret-padded-to-32-bytes\r\n"))
	edPath, mlPath, _, _ := stagedDualAuth(t, dir)
	document["dual_auth_ed25519_pub_path"] = edPath
	document["dual_auth_mldsa65_pub_path"] = mlPath
	keys, err := loadWinn3Keys(writeKeys(t, dir, document))
	if err != nil {
		t.Fatal(err)
	}
	rec := recordAcquiredSecrets(t)
	m, err := keys.readMaterial()
	if err != nil {
		t.Fatalf("readMaterial: %v", err)
	}
	entries := rec.snapshot()
	for _, field := range []string{"static_path", "admission_path", "gateway_static_path",
		"dual_auth_ed25519_pub_path", "dual_auth_mldsa65_pub_path"} {
		requireFieldHeld(t, "before wipe", field, entries)
	}
	tail := false
	for _, e := range entries {
		if e.field == "admission_path" && bytes.Contains(e.buffer, []byte("\r\n")) {
			tail = true
		}
	}
	if !tail {
		t.Fatal("the owned admission buffer does not cover the trimmed newline")
	}
	m.wipe()
	requireCleared(t, "after wipe", entries)
}

func TestSessionConfigClearsItsTemporaryMaterial(t *testing.T) {
	dir := t.TempDir()
	document := validKeys(t, dir)
	keys, err := loadWinn3Keys(writeKeys(t, dir, document))
	if err != nil {
		t.Fatal(err)
	}
	rec := recordAcquiredSecrets(t)
	cfg, admission, err := keys.sessionConfig()
	if err != nil {
		t.Fatalf("sessionConfig: %v", err)
	}
	material, round := splitRound(rec.snapshot())
	requireCleared(t, "the temporary material", material)
	// What the caller got is its own and still usable.
	if cfg.Static == nil || string(admission) != "lab-admission-secret-padded-to-32-bytes" {
		t.Fatalf("the returned configuration is not intact: static=%v admission=%q", cfg.Static != nil, admission)
	}
	requireFieldHeld(t, "the caller's copy", "round:admission_path", round)
	for _, e := range round {
		if e.field == "round:static_path" && !isZero(e.buffer) {
			t.Fatal("the scalar copy handed to ecdh.NewPrivateKey was not cleared")
		}
	}
}

// TestARetiredRoundClearsItsCopiesWhileTheRecoveryCopyOutlivesIt: a round
// clears its own copies when it is retired; the generation's recovery copy
// stays until no successor can be built, and then goes too.
func TestARetiredRoundClearsItsCopiesWhileTheRecoveryCopyOutlivesIt(t *testing.T) {
	rec := recordAcquiredSecrets(t)
	s, hostSide := startSilentFrameServer(t)
	go func() { _, _ = io.Copy(io.Discard, hostSide) }()
	material, round1 := splitRound(rec.snapshot())
	requireFieldHeld(t, "round one", "round:admission_path", round1)
	requireFieldHeld(t, "the recovery copy", "admission_path", material)

	r1 := s.currentRound()
	_ = r1.loop.Close()
	waitUntil(t, 15*time.Second, "a successor round", func() bool {
		d := s.activeDevice.Load()
		return d != nil && d != r1.device
	})
	requireCleared(t, "retired round one", round1)
	requireFieldHeld(t, "the recovery copy after a rebuild", "admission_path", material)

	s.shutdown()
	select {
	case <-s.superDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the supervisor did not finish after a Stop")
	}
	requireCleared(t, "everything after a normal Stop", rec.snapshot())
}

// TestATerminalRefusalClearsTheRecoveryCopyAndTheFailedConfiguration.
func TestATerminalRefusalClearsTheRecoveryCopyAndTheFailedConfiguration(t *testing.T) {
	rec := recordAcquiredSecrets(t)
	s, hostSide := startSilentFrameServer(t)
	go func() { _, _ = io.Copy(io.Discard, hostSide) }()
	before := len(rec.snapshot())
	s.refuseNextBuild()
	_ = s.currentRound().loop.Close()
	select {
	case <-s.superDone:
	case <-time.After(10 * time.Second):
		t.Fatal("a terminal build refusal did not end the supervisor")
	}
	entries := rec.snapshot()
	if len(entries) <= before {
		t.Fatal("the refused round made no secret copy; the failed-configuration path is untested")
	}
	requireCleared(t, "everything after a terminal refusal", entries)
}

// TestAStopClearsTheRecoveryCopyEvenWhenItsBoundedWaitRunsOut: the
// supervisor is held inside a round's end, so shutdown's bounded wait expires
// first. The recovery copy must already be gone when shutdown returns.
func TestAStopClearsTheRecoveryCopyEvenWhenItsBoundedWaitRunsOut(t *testing.T) {
	rec := recordAcquiredSecrets(t)
	s, hostSide := startSilentFrameServer(t)
	go func() { _, _ = io.Copy(io.Discard, hostSide) }()
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	entered := make(chan struct{}, 1)
	s.roundEndHook = func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}
	material, _ := splitRound(rec.snapshot())
	_ = s.currentRound().loop.Close()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the round never reached its end hook")
	}

	s.shutdown()
	select {
	case <-s.superDone:
		t.Fatal("the supervisor finished; the bounded-wait path was not exercised")
	default:
	}
	if !isZero(s.material.admission) {
		t.Fatal("the server still holds the admission secret after Stop returned")
	}
	requireCleared(t, "the recovery copy when shutdown returns", material)

	unblock()
	select {
	case <-s.superDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the supervisor did not finish once released")
	}
	requireCleared(t, "everything once the supervisor finished", rec.snapshot())
}

// TestACancelBeforeTheFirstRoundIsHandedOverClearsEverything races a Stop
// against the supervisor's first Build, in both orders across iterations.
func TestACancelBeforeTheFirstRoundIsHandedOverClearsEverything(t *testing.T) {
	const pathMTU = 1500
	sizing, err := driver.NewSizing(pathMTU, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		rec := recordAcquiredSecrets(t)
		ring := newFrameKeyring(t)
		sock, _ := loopbackSocket(t)
		_, peer := loopbackSocket(t)
		hostSide, engineSide := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, hostSide) }()
		s := newWinn3FrameServer(ring.gatewayKeys, handOver(t, sock), engineSide)
		if err := s.open(context.Background(),
			frameCreate(peer, "10.8.1.1", "10.8.1.3", sizing, pathMTU)); err != nil {
			t.Fatalf("open: %v", err)
		}
		s.shutdown()
		select {
		case <-s.superDone:
		case <-time.After(10 * time.Second):
			t.Fatal("the supervisor did not finish after an immediate Stop")
		}
		requireCleared(t, "an immediate Stop", rec.snapshot())
		_ = hostSide.Close()
		_ = engineSide.Close()
	}
}

// TestInitialCreateStillRefusesAMissingKeyFile: Create is where the files are
// read, and a missing one is refused there, with what was read cleared.
func TestInitialCreateStillRefusesAMissingKeyFile(t *testing.T) {
	const pathMTU = 1500
	sizing, err := driver.NewSizing(pathMTU, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{"static_path", "admission_path"} {
		t.Run(missing, func(t *testing.T) {
			ring := newFrameKeyring(t)
			keys := ring.gatewayKeys
			absent := filepath.Join(t.TempDir(), "absent")
			if missing == "static_path" {
				keys.StaticPath = absent
			} else {
				keys.AdmissionPath = absent
			}
			rec := recordAcquiredSecrets(t)
			sock, _ := loopbackSocket(t)
			_, peer := loopbackSocket(t)
			hostSide, engineSide := net.Pipe()
			t.Cleanup(func() { _ = hostSide.Close(); _ = engineSide.Close() })
			s := newWinn3FrameServer(keys, handOver(t, sock), engineSide)
			t.Cleanup(s.shutdown)
			err := s.open(context.Background(),
				frameCreate(peer, "10.8.1.1", "10.8.1.3", sizing, pathMTU))
			if err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("Create returned %v, want a %s refusal", err, missing)
			}
			if missing == "admission_path" {
				requireCleared(t, "the static key read before the refusal", rec.snapshot())
			}
		})
	}
}
