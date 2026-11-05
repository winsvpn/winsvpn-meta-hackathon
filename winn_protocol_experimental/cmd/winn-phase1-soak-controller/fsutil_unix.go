//go:build unix

package main

// maximumSnapshotEntries bounds the descriptor-relative snapshot tree walk.
// That walk exists only on platforms with the Unix secure-directory backend.
const maximumSnapshotEntries = 500_000
