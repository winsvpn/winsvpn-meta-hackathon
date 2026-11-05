// Command awgresponder is the FAR END of the AmneziaWG handshake that the Winn
// Android device check drives through the Winn engine.
//
// WHY THIS EXISTS. The bar for the WinnAwgDatagramSeam lane is a COMPLETED
// AmneziaWG handshake carried by the Winn engine, not "bytes moved". A
// handshake needs two AmneziaWG peers. The initiator is the real shipping
// engine: libam-go.so out of android/app/libs/amneziawg.aar, driven through
// org.amnezia.awg.GoBackend.awgTurnOn, owning the real tun. This program is the
// responder.
//
// IT CONTAINS NO CRYPTOGRAPHY OF ITS OWN. It uses the same official
// github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828 transport as the
// shipping AAR's libam-go.so. So both ends of the handshake use the identical
// implementation and a completed handshake is evidence about AmneziaWG, not
// about a re-implementation of it. Writing a hand-rolled Noise_IKpsk2
// responder here would have been exactly the "second, unreviewed cryptographic
// implementation" that datapath/config.go's ErrPayloadUnimplemented refuses.
//
// THE ONLY THING WRITTEN HERE IS A STUB TUN. device.NewDevice needs a
// tun.Device; the responder has no interest in inner packets, so the stub
// accepts writes and never produces reads. tun.CreateUnmonitoredTUNFromFD
// cannot be used because it calls Name(), a TUNGETIFF ioctl that only a real
// tun answers, and this process has no CAP_NET_ADMIN and no second VpnService.
//
// It is a DEVICE-CHECK FIXTURE. It is built only by
// android/devicecheck/build_devicecheck.sh, packaged only into the
// org.winsvpn.devicecheck debug APK, and is never part of the shipping app.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

func main() {
	listenPort := flag.Int("listen-port", 0, "UDP port to listen on (required)")
	privateKey := flag.String("private-key", "", "responder private key, base64 (required)")
	peerPublic := flag.String("peer-public-key", "", "initiator public key, base64 (required)")
	presharedKey := flag.String("preshared-key", "", "optional preshared key, base64")
	awgParams := flag.String("awg-params", "",
		"AmneziaWG obfuscation parameters as uapi lines, comma separated, e.g. \"jc=4,h1=1234\"")
	reportEvery := flag.Duration("report-every", 500*time.Millisecond,
		"how often to print a handshake report")
	runFor := flag.Duration("run-for", 90*time.Second, "exit after this long")
	verbose := flag.Bool("verbose", false, "pass amneziawg-go's own log lines through")
	flag.Parse()

	if err := run(
		*listenPort, *privateKey, *peerPublic, *presharedKey,
		*awgParams, *reportEvery, *runFor, *verbose,
	); err != nil {
		fmt.Printf("awgresponder: fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(
	listenPort int,
	privateKey, peerPublic, presharedKey, awgParams string,
	reportEvery, runFor time.Duration,
	verbose bool,
) error {
	if listenPort < 1 || listenPort > 65535 {
		return errors.New("-listen-port is required and must be a real port")
	}
	privateHex, err := decodeKey(privateKey)
	if err != nil {
		return fmt.Errorf("-private-key: %w", err)
	}
	peerHex, err := decodeKey(peerPublic)
	if err != nil {
		return fmt.Errorf("-peer-public-key: %w", err)
	}
	var pskHex string
	if presharedKey != "" {
		pskHex, err = decodeKey(presharedKey)
		if err != nil {
			return fmt.Errorf("-preshared-key: %w", err)
		}
	}

	level := device.LogLevelError
	if verbose {
		level = device.LogLevelVerbose
	}
	logger := device.NewLogger(level, "awgresponder ")

	stub := newStubTUN(1280)
	dev := device.NewDevice(stub, conn.NewStdNetBind(), logger)
	defer dev.Close()

	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", privateHex)
	fmt.Fprintf(&uapi, "listen_port=%d\n", listenPort)
	// The AmneziaWG obfuscation parameters must match the initiator's exactly
	// or the two speak different wire formats and nothing decodes. They are
	// passed in rather than defaulted so the harness controls both sides from
	// one place.
	for _, line := range splitParams(awgParams) {
		fmt.Fprintf(&uapi, "%s\n", line)
	}
	fmt.Fprintf(&uapi, "public_key=%s\n", peerHex)
	if pskHex != "" {
		fmt.Fprintf(&uapi, "preshared_key=%s\n", pskHex)
	}
	// A responder deliberately configures NO endpoint: it learns the
	// initiator's source address from the handshake initiation. That is also
	// why this side must keep roaming enabled, so
	// DisableSomeRoamingForBrokenMobileSemantics is NOT called here (the
	// Android initiator calls it, which is the point being verified: its peer
	// endpoint stays pinned to the loopback seam).
	fmt.Fprintf(&uapi, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&uapi, "allowed_ip=::/0\n")

	if err := dev.IpcSet(uapi.String()); err != nil {
		return fmt.Errorf("configure responder: %w", err)
	}
	if err := dev.Up(); err != nil {
		return fmt.Errorf("bring responder up: %w", err)
	}

	fmt.Printf("awgresponder: listening on udp/%d, awaiting a handshake from the initiator\n",
		listenPort)
	fmt.Printf("awgresponder: amneziawg-go transport, obfuscation=[%s]\n",
		strings.Join(splitParams(awgParams), " "))

	deadline := time.Now().Add(runFor)
	reported := false
	for time.Now().Before(deadline) {
		time.Sleep(reportEvery)
		state, err := dev.IpcGet()
		if err != nil {
			continue
		}
		handshake := uapiValue(state, "last_handshake_time_sec")
		rx := uapiValue(state, "rx_bytes")
		tx := uapiValue(state, "tx_bytes")
		if handshake != "" && handshake != "0" {
			if !reported {
				fmt.Printf("awgresponder: HANDSHAKE COMPLETE last_handshake_time_sec=%s "+
					"rx_bytes=%s tx_bytes=%s\n", handshake, rx, tx)
				reported = true
			} else {
				fmt.Printf("awgresponder: handshake=%s rx_bytes=%s tx_bytes=%s\n",
					handshake, rx, tx)
			}
		}
	}
	fmt.Printf("awgresponder: run window elapsed; handshake_seen=%v\n", reported)
	return nil
}

// decodeKey accepts the base64 form AmneziaWG configuration files use and
// returns the hex form its uapi wants.
func decodeKey(value string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key must decode to 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func splitParams(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func uapiValue(document, key string) string {
	for _, line := range strings.Split(document, "\n") {
		name, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if found && name == key {
			return value
		}
	}
	return ""
}

// ----------------------------------------------------------------------
// the stub tun
// ----------------------------------------------------------------------

// stubTUN is a tun.Device that never yields a packet and discards everything
// written to it. The responder exists to complete a handshake; it has no inner
// network to carry, and giving it one would add a second thing that could fail
// and confuse the verdict.
type stubTUN struct {
	events    chan tun.Event
	mtu       int
	closeOnce sync.Once
	closed    chan struct{}
}

func newStubTUN(mtu int) *stubTUN {
	stub := &stubTUN{
		events: make(chan tun.Event, 4),
		mtu:    mtu,
		closed: make(chan struct{}),
	}
	stub.events <- tun.EventUp
	return stub
}

func (stub *stubTUN) File() *os.File { return nil }

// Read blocks until Close. Returning (0, nil) in a loop would spin a core.
func (stub *stubTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-stub.closed
	return 0, os.ErrClosed
}

func (stub *stubTUN) Write(bufs [][]byte, offset int) (int, error) {
	return len(bufs), nil
}

func (stub *stubTUN) MTU() (int, error) { return stub.mtu, nil }

func (stub *stubTUN) Name() (string, error) { return "awgresponder", nil }

func (stub *stubTUN) Events() <-chan tun.Event { return stub.events }

func (stub *stubTUN) BatchSize() int { return 1 }

func (stub *stubTUN) Close() error {
	stub.closeOnce.Do(func() {
		close(stub.closed)
		close(stub.events)
	})
	return nil
}

var _ tun.Device = (*stubTUN)(nil)
var _ = net.IPv4len
