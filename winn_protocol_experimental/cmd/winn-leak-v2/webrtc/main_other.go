//go:build !unix

// Command winn-webrtc-v2 is unavailable on platforms that cannot provide the
// POSIX process-group and signal guarantees required to prove Chromium and
// all of its descendants have been contained and reaped.
package main

import (
	"fmt"
	"io"
	"os"
)

const unsupportedPlatformMessage = "winn-webrtc-v2 requires a Unix platform"

func runUnsupportedPlatform(stderr io.Writer) int {
	fmt.Fprintln(stderr, unsupportedPlatformMessage)
	return 1
}

func main() {
	os.Exit(runUnsupportedPlatform(os.Stderr))
}
