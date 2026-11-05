//go:build unix && !linux

package main

// rusageMaxRSSScale converts ru_maxrss to bytes. The BSDs, macOS included,
// already report bytes.
const rusageMaxRSSScale int64 = 1
