//go:build linux

package main

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/tun"
)

// TestSharedGatewayTunCloseWaitsForAnInProgressWriteAndFailsLaterWrites is
// the descriptor lifecycle (Round X Turn 2, Seat C, OI-XB3; revision 3.3). A
// pipe stands in for one TUN queue descriptor. A write blocked in the kernel
// (the pipe is full) must complete, intact, before Close releases the
// descriptor; every write after Close must fail cleanly, as a device write
// failure whose cause is the closed file (os.ErrClosed's text: writeQueue wraps
// only tun.ErrDeviceWrite and formats the cause), never reach a reused
// descriptor.
func TestSharedGatewayTunCloseWaitsForAnInProgressWriteAndFailsLaterWrites(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s := &sharedGatewayTun{files: []*os.File{w}, file: w, writeMu: make([]sync.Mutex, 1), mtu: 1400}
	// Fill the pipe so the next write blocks in the kernel.
	fill := make([]byte, 1<<20)
	filled := make(chan int, 1)
	go func() {
		n, _ := w.Write(fill)
		filled <- n
	}()
	time.Sleep(20 * time.Millisecond) // the fill write is now blocked, holding no queue lock
	pkt := make([]byte, 1400)
	for i := range pkt {
		pkt[i] = 0x5a
	}
	wrote := make(chan error, 1)
	go func() {
		n, err := s.writeQueue(0, pkt)
		if err == nil && n != len(pkt) {
			err = errors.New("short write")
		}
		wrote <- err
	}()
	time.Sleep(20 * time.Millisecond) // writeQueue now holds writeMu[0], blocked behind the fill
	closed := make(chan struct{})
	go func() {
		_ = s.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close released the descriptor while a queue write was still in progress")
	case <-time.After(50 * time.Millisecond):
	}
	// Drain the pipe: the fill write and then the queued write complete.
	buf := make([]byte, 1<<16)
	total, want := 0, len(fill)+len(pkt)
	deadline := time.Now().Add(5 * time.Second)
	for total < want && time.Now().Before(deadline) {
		n, err := r.Read(buf)
		if err != nil {
			break
		}
		total += n
	}
	if err := <-wrote; err != nil {
		t.Fatalf("the in-progress queue write failed across Close: %v", err)
	}
	<-closed
	if total != want {
		t.Fatalf("read %d bytes, want %d: the in-progress write was cut off", total, want)
	}
	if _, err := s.writeQueue(0, pkt); err == nil || !errors.Is(err, tun.ErrDeviceWrite) || !strings.Contains(err.Error(), os.ErrClosed.Error()) {
		t.Fatalf("write after Close = %v, want tun.ErrDeviceWrite caused by %q", err, os.ErrClosed)
	}
	<-filled
}
