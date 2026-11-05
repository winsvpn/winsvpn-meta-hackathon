//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "FAIL: winn-teardown-e2e is Linux-only; cross-build with GOOS=linux")
	os.Exit(1)
}
