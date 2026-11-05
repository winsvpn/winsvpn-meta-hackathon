//go:build unix

package main

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestWinn3ProfileFIFOIsRefusedWithoutHanging is the Stat-before-Open
// control. os.Open of a FIFO with no writer blocks; a profile path that
// names one used to hang the datapath. The loader must refuse a non-regular
// file from Stat and return before Open.
func TestWinn3ProfileFIFOIsRefusedWithoutHanging(t *testing.T) {
	path := filepath.Join(t.TempDir(), "winn3.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := loadWinn3Profile(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was accepted as a profile")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("refused with %q, want regular file", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Open blocked on a FIFO; Stat-before-Open is missing")
	}
}
