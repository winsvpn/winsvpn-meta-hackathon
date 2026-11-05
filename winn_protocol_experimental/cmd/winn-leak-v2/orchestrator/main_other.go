//go:build !unix

// Command winn-leak-orchestrator-v2 is unavailable on platforms that cannot
// provide the POSIX process-group, credential, ownership, and signal
// guarantees required by the acceptance lifecycle.
package main

import (
	"fmt"
	"io"
	"os"
)

const unsupportedPlatformMessage = "winn-leak-orchestrator-v2 requires a Unix platform"

func runUnsupportedPlatform(stderr io.Writer) int {
	fmt.Fprintln(stderr, unsupportedPlatformMessage)
	return 1
}

func main() {
	os.Exit(runUnsupportedPlatform(os.Stderr))
}
