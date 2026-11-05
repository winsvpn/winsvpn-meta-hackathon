// Command winn-knock sends one internal/knock Single Packet Authorization
// datagram and exits.
//
// It is the minimal client half of the alternative connection-initiation path,
// for three uses:
//
//   - An operator verifying that a node's winn-knockd, key file and packet
//     sizing actually agree, without needing a full VPN client.
//   - A Linux client or script that wants to knock before running some other
//     tool (awg-quick, a browser, anything).
//   - Provisioning and rotation drills.
//
// A full Winn client does NOT need this binary: cmd/winn-carrier-client knocks
// via -spa-required, and the datapath route knocks via internal/knockdial over
// the host's already-protected socket, which is the correct thing to do on
// Android and is why knock.Send is not used there.
//
// # It cannot tell you whether the knock worked
//
// Nothing is ever sent back, on any path, by design: a knock's success and
// failure are indistinguishable on the wire, and that is the property the whole
// mechanism rests on. So a zero exit status here means "the datagram left this
// machine", never "the far side accepted it". Verify by attempting the real
// connection afterwards, or by reading winn-knockd's own counters on the node.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/knock"
)

func main() {
	var (
		keyPath      string
		target       string
		packetSize   int
		bucketWindow time.Duration
		maxSkew      time.Duration
		count        int
		interval     time.Duration
		timeout      time.Duration
	)

	flag.StringVar(&keyPath, "key", "",
		"REQUIRED. Path to this client's SPA key file: exactly ONE hex-encoded "+
			"key. A file with more than one line is refused rather than "+
			"guessed at, because during a rotation the wrong choice is silent.")
	flag.StringVar(&target, "target", "",
		"REQUIRED. host:port to send the knock to. This is the address "+
			"winn-knockd listens on, which is NOT the port being protected.")
	flag.IntVar(&packetSize, "packet-size", 0,
		"REQUIRED. Exact datagram size. Must equal the node's -packet-size "+
			"exactly; a mismatch fails closed and is silent.")
	flag.DurationVar(&bucketWindow, "bucket-window", 0,
		"Freshness bucket width. Zero uses internal/knock's default (10s). "+
			"Must match the node's.")
	flag.DurationVar(&maxSkew, "max-skew", 0,
		"Tolerated clock skew. Zero uses internal/knock's default (60s). "+
			"Must match the node's.")
	flag.IntVar(&count, "count", 1,
		"How many knocks to send. Each is a fresh datagram with its own nonce, "+
			"so extra knocks are not replays; more than one only helps against "+
			"packet loss on a lossy path.")
	flag.DurationVar(&interval, "interval", 200*time.Millisecond,
		"Delay between knocks when -count is greater than one.")
	flag.DurationVar(&timeout, "timeout", 10*time.Second,
		"Overall deadline.")

	flag.Usage = usage
	flag.Parse()

	if flag.NArg() > 0 {
		exitError("unexpected positional argument %q", flag.Arg(0))
	}
	if keyPath == "" {
		exitError("-key is required")
	}
	if target == "" {
		exitError("-target is required")
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		exitError("-target %q must be host:port: %v", target, err)
	}
	if packetSize < knock.HeaderSize {
		exitError(
			"-packet-size is required and must be at least %d; got %d",
			knock.HeaderSize, packetSize,
		)
	}
	if count < 1 {
		exitError("-count must be at least 1")
	}

	keys, err := knock.LoadKeysFromFile(keyPath)
	if err != nil {
		exitError("%v", err)
	}
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	if len(keys) != 1 {
		// Same rule carrierhost.wrapSPA enforces: a server takes several keys
		// for a rotation overlap, a client holds exactly one. Picking one
		// silently would let a rotation leave a device knocking with a key
		// nobody chose.
		exitError(
			"-key must name a file containing exactly one key for a client, "+
				"found %d", len(keys),
		)
	}

	options := knock.Options{BucketWindow: bucketWindow, MaxSkew: maxSkew}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for i := 0; i < count; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				exitError("deadline reached after %d knock(s)", i)
			case <-time.After(interval):
			}
		}
		if err := knock.Send(
			ctx, target, keys[0], packetSize, options,
		); err != nil {
			exitError("%v", err)
		}
	}

	// Deliberately says "sent", not "accepted". See the package doc.
	fmt.Fprintf(os.Stderr,
		"winn-knock: sent %d knock(s) of %d bytes to %s\n"+
			"winn-knock: NOTE nothing is ever sent back, so this does not mean "+
			"the node accepted it.\n",
		count, packetSize, target,
	)
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprint(out, `winn-knock - send one Single Packet Authorization knock

USAGE
  winn-knock -key PATH -target HOST:PORT -packet-size N [options]

EXIT STATUS
  0 means the datagram left this machine. It does NOT mean the node accepted
  it: nothing is ever sent back, on any path, by design. Confirm by making the
  real connection, or by reading winn-knockd's counters on the node.

THE KEY IS A CREDENTIAL
  It is a deployment-scoped shared secret, like an fwknop key or an unlisted
  bridge line -- not a per-device identity. Anyone holding it can knock. Give
  the file mode 0400, never commit it, never paste it into a chat or a ticket,
  and rotate it through the same out-of-band channel used for the trust-root
  fingerprint.

OPTIONS
`)
	flag.PrintDefaults()
}

func exitError(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(message, "\n") {
		message += "\n"
	}
	fmt.Fprint(os.Stderr, "winn-knock: "+message)
	os.Exit(1)
}
