//go:build !linux

package main

// pinTxThread is the arm X2 hook on platforms without sched_setaffinity:
// nothing is pinned and the release is a no-op.
func pinTxThread() func() { return func() {} }
