//go:build !windows

package main

import (
	"fmt"
	"os"
)

// This binary is Windows-only: it exists to own a Wintun adapter, and Wintun is
// a Windows driver. The stub exists so that `go build ./...` and `go vet ./...`
// on a maintainer's machine compile the PORTABLE half of this package -- the
// inner-packet rules in packet.go, which are the part most worth reviewing --
// instead of failing at the import of golang.zx2c4.com/wintun and skipping
// them. It mirrors winn3_device_tunfd_other.go, which exists for the same
// reason on the other side of the seam.
func main() {
	fmt.Fprintln(os.Stderr,
		"winn3-relay: this relay owns a Wintun adapter and runs on Windows "+
			"only. On Linux the equivalent is winn-datapath's tun-fd device "+
			"kind, which needs no relay at all.")
	os.Exit(2)
}
