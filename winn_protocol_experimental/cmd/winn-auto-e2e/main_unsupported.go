//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(
		os.Stderr,
		"winn-auto-e2e requires Linux network namespaces, nftables, and AmneziaWG",
	)
	os.Exit(1)
}
