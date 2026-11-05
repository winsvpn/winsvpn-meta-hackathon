package main

import (
	"errors"
	"io"
	"syscall"
	"testing"
)

// TestV3ScalarNeverReportsSuccessForUnsentBytes pins retainScalar, the v3
// scalar path: success only for a write the kernel accepted in full, a non-nil
// error for every failure and for any short write.
func TestV3ScalarNeverReportsSuccessForUnsentBytes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		n       int
		err     error
		wantErr error
	}{
		{"full write", 100, nil, nil},
		{"short write", 60, nil, io.ErrShortWrite},
		{"zero write", 0, nil, io.ErrShortWrite},
		{"refused", 0, syscall.ENOBUFS, syscall.ENOBUFS},
		{"permanent", 0, syscall.EBADF, syscall.EBADF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := retainScalar(nil, 100, func() (int, error) { return tc.n, tc.err })
			if tc.wantErr == nil {
				if err != nil || n != 100 {
					t.Fatalf("full write returned (%d, %v)", n, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("returned (%d, %v), want error %v: unsent bytes must never read as sent", n, err, tc.wantErr)
			}
		})
	}
}
