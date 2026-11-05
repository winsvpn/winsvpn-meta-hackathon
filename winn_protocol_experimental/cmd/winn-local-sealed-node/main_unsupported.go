//go:build !linux && winn_incomplete_e8

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "FAIL: local sealed node rehearsal is Linux-only")
	os.Exit(1)
}
