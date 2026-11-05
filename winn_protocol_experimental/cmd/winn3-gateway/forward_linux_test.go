//go:build linux

package main

import (
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests exercise sharedGatewayTun.run's error handling using REAL
// *os.File values that are not a TUN device -- an os.Pipe and an AF_UNIX
// SOCK_DGRAM socketpair -- so they need no root, no CAP_NET_ADMIN and no
// kernel tun module, only a Linux build (sharedGatewayTun's real
// implementation is Linux-only; see forward_linux.go and forward_other.go).
// They construct sharedGatewayTun directly rather than through
// newSharedGatewayTun, which is the one part of this file that DOES need a
// real interface and is what the handoff document names as still unverified
// by this suite.
//
// A closed pipe's read end yielding a persistent error is a real,
// reproducible stand-in for "the device stopped producing anything and every
// Read call now returns immediately" -- the exact condition
// maxConsecutiveDeviceReadErrors exists for. A live TUN device would not
// itself return io.EOF in normal operation, but the loop's error handling
// does not distinguish io.EOF from any other Read error, so this is a
// faithful test of the retry/give-up logic even though the specific errno
// differs from what a deleted interface would actually produce.
//
// The SOCK_DGRAM socketpair, by contrast, models the SUCCESS path: a tun
// character device opened IFF_NO_PI delivers exactly one frame per read(2),
// and a plain file or pipe would coalesce the three packets into one read, so
// only a datagram-framed descriptor is a faithful stand-in for one-read-equals-
// one-packet (see TestRunProcessesReadsWithoutGivingUpBeforeTheThreshold).

// TestRunGivesUpAfterConsecutiveReadErrorsRatherThanSpinning is the pinned
// regression for the 2026-08-12 review finding: run's retry loop, against a
// PERSISTENTLY failing device, used to retry forever with no backoff. The
// in-code comment it replaced claimed each failed Read still blocks, which
// is false for a genuine error (read(2) blocks only while the answer is
// "no data yet"; once the kernel has an errno to report, every subsequent
// call returns immediately). A pipe whose write end is already closed
// reproduces that: every Read on the read end returns (0, io.EOF), with no
// blocking, forever.
func TestRunGivesUpAfterConsecutiveReadErrorsRatherThanSpinning(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close write end: %v", err)
	}
	defer r.Close()

	s := &sharedGatewayTun{file: r, name: "test-pipe", table: newForwardTable()}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.run(ctx)
	}()

	// maxConsecutiveDeviceReadErrors * deviceReadErrorBackoff is the
	// expected wall-clock cost of giving up (20 * 100ms = 2s as configured
	// today); this budget is deliberately generous so the test is not
	// flaky under load without being so long it stops being a good check
	// against the ORIGINAL bug, which would have made this loop never
	// return at all.
	budget := time.Duration(maxConsecutiveDeviceReadErrors)*deviceReadErrorBackoff + 5*time.Second
	select {
	case <-done:
	case <-time.After(budget):
		t.Fatalf("run did not give up within %s of a persistently failing device -- it is "+
			"spinning or hanging instead of giving up after %d consecutive errors",
			budget, maxConsecutiveDeviceReadErrors)
	}

	if !s.deviceGone.Load() {
		t.Fatal("run returned but did not set deviceGone")
	}
	stats := s.Stats()
	if stats.Malformed != maxConsecutiveDeviceReadErrors {
		t.Fatalf("Malformed = %d, want exactly %d (one per attempt before giving up)",
			stats.Malformed, maxConsecutiveDeviceReadErrors)
	}
	if !stats.DeviceGone {
		t.Fatal("Stats().DeviceGone is false after run gave up")
	}
}

// TestRunStopsPromptlyOnContextCancellationDuringBackoff pins the
// select-on-ctx fix to the backoff wait: a shutdown signalled while run is
// mid-backoff must not be delayed by a full deviceReadErrorBackoff for no
// reason.
func TestRunStopsPromptlyOnContextCancellationDuringBackoff(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close write end: %v", err)
	}
	defer r.Close()

	s := &sharedGatewayTun{file: r, name: "test-pipe", table: newForwardTable()}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.run(ctx)
	}()

	// Let run enter its first backoff wait, then cancel.
	time.Sleep(10 * time.Millisecond)
	start := time.Now()
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop within 2s of context cancellation")
	}
	if elapsed := time.Since(start); elapsed > deviceReadErrorBackoff {
		t.Fatalf("run took %s to stop after cancellation, want well under the %s backoff "+
			"(the wait should be interrupted by ctx.Done, not merely outlasted)",
			elapsed, deviceReadErrorBackoff)
	}
}

// TestRunProcessesReadsWithoutGivingUpBeforeTheThreshold is the positive
// case: successful reads must not be treated as errors, and consuming three
// valid packets followed by a brief no-more-data window far inside the
// give-up threshold must not report DeviceGone.
func TestRunProcessesReadsWithoutGivingUpBeforeTheThreshold(t *testing.T) {
	// The one-read-equals-one-packet assumption this test exercises is
	// correct for the real target -- a tun character device opened IFF_NO_PI
	// delivers exactly one frame per read(2), which is why run() must not be
	// changed. But a regular temp file (and os.Pipe) do not model it: both
	// coalesce, so one Read(65535) returns all three 20-byte packets
	// concatenated and Reads would be 1, not 3. The faithful stand-in is an
	// AF_UNIX SOCK_DGRAM socketpair, which preserves one datagram (one
	// packet) per read exactly like a tun frame.
	sv, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	// os.NewFile descriptors are not registered with the runtime poller, so
	// a Read blocked in the kernel cannot be interrupted by Close from
	// another goroutine on Linux: without this, the read-end close below
	// leaves run parked in read(2) forever and the package hits the go test
	// 10-minute timeout. Nonblocking mode makes a drained socket return
	// EAGAIN instead of blocking; run already treats that as a transient
	// read error (backoff plus ctx-select), and the read-end close then
	// lands on os.ErrClosed, which is what stops run deterministically.
	if err := unix.SetNonblock(sv[0], true); err != nil {
		t.Fatalf("set recv nonblocking: %v", err)
	}
	if err := unix.SetNonblock(sv[1], true); err != nil {
		t.Fatalf("set send nonblocking: %v", err)
	}
	recv := os.NewFile(uintptr(sv[0]), "test-dgram-recv")
	send := os.NewFile(uintptr(sv[1]), "test-dgram-send")
	defer recv.Close()
	defer send.Close()

	// 10.64.0.9 is never learned in the table below, so each copy of this
	// packet lands on UnknownDest rather than needing a real *driver.Loop
	// (SendInner would panic on the zero-value fakeLoop() this package's
	// other tests use as an opaque identity).
	pkt := ipv4Packet(t, "10.64.0.2", "10.64.0.9")
	for i := 0; i < 3; i++ {
		if _, err := send.Write(pkt); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}
	// Close the writer so the receive side drains. Once the three queued
	// datagrams are consumed, run's Read hits the "device stopped producing"
	// window this threshold exists for. After that point some kernels return
	// a durable EOF (Linux) while others report a one-shot ECONNRESET and
	// then block, so the test must not lean on which errno follows -- the
	// read-end close below is what makes run return deterministically on all
	// of them.
	if err := send.Close(); err != nil {
		t.Fatalf("close write end: %v", err)
	}

	s := &sharedGatewayTun{file: recv, name: "test-dgram", table: newForwardTable()}

	// Comfortably under maxConsecutiveDeviceReadErrors * deviceReadErrorBackoff
	// (2s as configured today). run()'s os.ErrClosed path, not this deadline,
	// is what stops the goroutine deterministically (see below).
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.run(ctx)
	}()

	// The three datagrams are already queued when run starts, so they are
	// consumed as three discrete reads almost immediately. Wait for all three
	// before forcing the read end shut so run() sees them all and never gets
	// to count them against itself; then os.ErrClosed makes run return without
	// tripping the give-up threshold, no matter which way the kernel reports
	// the drained-writer datagram socket. This keeps the test from blocking on
	// a kernel that stops reporting EOF after the first post-close read.
	deadline := time.Now().Add(10 * time.Second)
	for s.reads.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatal("run did not consume all three queued datagrams within 10s")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := recv.Close(); err != nil {
		t.Fatalf("close read end: %v", err)
	}
	<-done

	stats := s.Stats()
	if stats.Reads != 3 {
		t.Fatalf("Reads = %d, want 3", stats.Reads)
	}
	if stats.UnknownDest != 3 {
		t.Fatalf("UnknownDest = %d, want 3 (10.64.0.9 was never learned)", stats.UnknownDest)
	}
	if stats.DeviceGone {
		t.Fatal("DeviceGone is true after only successful reads plus a brief no-more-data " +
			"window well inside the give-up threshold")
	}
}
