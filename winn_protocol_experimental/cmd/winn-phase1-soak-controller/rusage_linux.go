//go:build linux

package main

// rusageMaxRSSScale converts ru_maxrss to bytes. Linux reports kilobytes.
const rusageMaxRSSScale int64 = 1024
