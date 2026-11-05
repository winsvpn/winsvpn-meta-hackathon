// Command winn-leak-v2 provides the two process roles used by the Winn v3
// acceptance-grade leak suite:
//
//   - observer: controlled DNS (UDP and TCP), HTTP egress, and STUN
//     observation with fsync'd JSONL evidence.
//   - client: the Linux-only production direct-AWG candidate held at explicit
//     lifecycle barriers so an external harness can test prepare, commit,
//     outage, crash, and graceful-stop behavior.
//
// The client role is intentionally unavailable on non-Linux platforms. Browser
// WebRTC testing is performed by the external harness against observer's STUN
// endpoint; a headless non-browser substitute is not accepted as WebRTC proof.
package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("usage: winn-leak-v2 <observer|client> [flags]"))
	}
	var err error
	switch os.Args[1] {
	case "observer":
		err = runObserver(os.Args[2:])
	case "client":
		err = runClient(os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
