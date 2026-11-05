//go:build linux || android

package carrier

// Deterministic tests of the two scalar helpers, driven by scripted write
// callbacks so every attempt and counter delta is exact. They use only API the
// Round D v2 tree also has, so the counting defects show as RED there.

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func loopbackQueue(t *testing.T) *SocketErrorQueue {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	return newSocketErrorQueue(raw)
}

// script returns a write callback that fails with errs in order and then
// succeeds with n, and a pointer to how many times it ran.
func script(n int, errs ...error) (func() (int, error), *int) {
	calls := 0
	return func() (int, error) {
		calls++
		if calls <= len(errs) {
			return 0, errs[calls-1]
		}
		return n, nil
	}, &calls
}

func repeat(e error, k int) []error {
	out := make([]error, k)
	for i := range out {
		out[i] = e
	}
	return out
}

type scalarDelta struct{ refused, dropped, retries uint64 }

func deltaSince(before, after SocketErrorStats) scalarDelta {
	return scalarDelta{
		refused: after.ScalarRefused - before.ScalarRefused,
		dropped: after.ScalarDropped - before.ScalarDropped,
		retries: after.MatchingErrorRetries - before.MatchingErrorRetries,
	}
}

// TestCoverScalarExhaustionDropsOnceAfterSevenAttempts drives the cover path to
// exhaustion: 7 failed attempts, exactly one counted drop, and the success
// return that keeps quic-go's connection alive.
func TestCoverScalarExhaustionDropsOnceAfterSevenAttempts(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want scalarDelta
	}{
		// ENOBUFS retries are not matching-error retries.
		{"ENOBUFS", unix.ENOBUFS, scalarDelta{refused: 7, dropped: 1, retries: 0}},
		// A matching errno is retried 6 times before the 7th attempt drops.
		{"ECONNREFUSED", unix.ECONNREFUSED, scalarDelta{refused: 7, dropped: 1, retries: 6}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := loopbackQueue(t)
			write, calls := script(0, repeat(tc.err, 100)...)
			before := q.Stats()
			n, err := q.SendCoverScalar(1200, write)
			got := deltaSince(before, q.Stats())
			if n != 1200 || err != nil {
				t.Fatalf("exhausted cover write returned (%d, %v), want the success return (1200, nil)", n, err)
			}
			if *calls != 7 {
				t.Fatalf("cover write made %d attempts, want 7", *calls)
			}
			if got != tc.want {
				t.Fatalf("counter deltas %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestScalarHelpersCountEveryFailedAttempt pins the accounting contract of both
// helpers with exact deltas, including the terminal attempt, and the EMSGSIZE
// choice: excluded on the cover path, included on the v3 path.
func TestScalarHelpersCountEveryFailedAttempt(t *testing.T) {
	type call func(q *SocketErrorQueue, w func() (int, error)) (int, error)
	cover := func(q *SocketErrorQueue, w func() (int, error)) (int, error) { return q.SendCoverScalar(100, w) }
	retain := func(q *SocketErrorQueue, w func() (int, error)) (int, error) { return q.SendScalarRetain(w) }
	for _, tc := range []struct {
		name    string
		helper  call
		errs    []error
		calls   int
		wantErr error
		want    scalarDelta
	}{
		{"cover ECONNREFUSED then success", cover, []error{unix.ECONNREFUSED}, 2, nil, scalarDelta{refused: 1, retries: 1}},
		{"cover ENOBUFS x2 then success", cover, []error{unix.ENOBUFS, unix.ENOBUFS}, 3, nil, scalarDelta{refused: 2}},
		{"cover EMSGSIZE passes through uncounted", cover, []error{unix.EMSGSIZE}, 1, unix.EMSGSIZE, scalarDelta{}},
		{"cover EBADF passes through uncounted", cover, []error{unix.EBADF}, 1, unix.EBADF, scalarDelta{}},
		{"retain ENOBUFS returned at once, counted", retain, []error{unix.ENOBUFS}, 1, unix.ENOBUFS, scalarDelta{refused: 1}},
		{"retain ECONNREFUSED then success", retain, []error{unix.ECONNREFUSED}, 2, nil, scalarDelta{refused: 1, retries: 1}},
		{"retain ECONNREFUSED exhausted, terminal counted", retain, repeat(unix.ECONNREFUSED, 100), 5, unix.ECONNREFUSED, scalarDelta{refused: 5, retries: 4}},
		{"retain EMSGSIZE included, exhausted", retain, repeat(unix.EMSGSIZE, 100), 5, unix.EMSGSIZE, scalarDelta{refused: 5, retries: 4}},
		{"retain EBADF passes through uncounted", retain, []error{unix.EBADF}, 1, unix.EBADF, scalarDelta{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := loopbackQueue(t)
			write, calls := script(100, tc.errs...)
			before := q.Stats()
			_, err := tc.helper(q, write)
			got := deltaSince(before, q.Stats())
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil) != (err == nil) {
				t.Fatalf("returned %v, want %v", err, tc.wantErr)
			}
			if *calls != tc.calls {
				t.Fatalf("%d attempts, want %d", *calls, tc.calls)
			}
			if got != tc.want {
				t.Fatalf("counter deltas %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestScalarRetainNeverReportsSuccessForUnsentBytes: every failing script
// returns a non-nil error, never (n, nil).
func TestScalarRetainNeverReportsSuccessForUnsentBytes(t *testing.T) {
	for _, e := range []syscall.Errno{unix.ENOBUFS, unix.ECONNREFUSED, unix.EMSGSIZE,
		unix.EHOSTUNREACH, unix.EAGAIN, unix.EPERM, unix.EBADF} {
		q := loopbackQueue(t)
		write, _ := script(100, repeat(e, 100)...)
		n, err := q.SendScalarRetain(write)
		if err == nil {
			t.Fatalf("%v on every attempt returned success (%d, nil): unsent bytes reported sent", e, n)
		}
		if n != 0 {
			t.Fatalf("%v returned n=%d for a datagram the kernel refused", e, n)
		}
	}
}
