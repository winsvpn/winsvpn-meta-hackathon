// Command awg-carry-testpeer is a TEST FIXTURE: the node end of the carrying
// canary, for the Python suites that drive the real wins-awg-carry-client
// through the control-plane probe code. It is a real amneziawg-go v3
// responder on an in-process network stack with a DNS responder inside the
// tunnel. It prints one JSON line with its listen port and public key, then
// runs until stdin closes. It is never built for a hub.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"winsvpn.local/awgcarryclient/peer"
)

func main() {
	privateKey := flag.String("private-key", "", "node private key, base64 (default: a fresh key)")
	clientPublic := flag.String("client-public-key", "", "canary client public key, base64 (default: mint a throwaway client key pair and print it)")
	clientAddress := flag.String("client-address", "10.8.255.1", "the canary's inner address")
	innerAddress := flag.String("inner-address", "10.8.1.1", "the node's inner router address (DNS listens here)")
	dnsPort := flag.Uint("dns-port", 53, "DNS port inside the tunnel")
	profile := flag.String("profile", "", "obfuscation profile as UAPI lines, comma separated (jc=4,jmin=8,...)")
	name := flag.String("name", "hub.example.test", "the one name the DNS responder answers")
	address := flag.String("address", "192.0.2.7", "the address it answers with")
	silent := flag.Bool("silent", false, "never answer a DNS query (the handshake still completes)")
	flag.Parse()

	keys := peer.Keypair{Private: *privateKey}
	if keys.Private == "" {
		fresh, err := peer.NewKeypair()
		if err != nil {
			fatal(err)
		}
		keys = fresh
	}
	ready := map[string]any{"public_key": keys.Public}
	if *clientPublic == "" {
		// A test fixture only: the suites that drive the real client need a
		// throwaway canary key pair and have no X25519 of their own.
		minted, err := peer.NewKeypair()
		if err != nil {
			fatal(err)
		}
		*clientPublic = minted.Public
		ready["client_private_key"] = minted.Private
		ready["client_public_key"] = minted.Public
	}
	var lines []string
	for _, part := range strings.Split(*profile, ",") {
		if part = strings.TrimSpace(part); part != "" {
			lines = append(lines, part)
		}
	}
	p, err := peer.Start(peer.Config{
		PrivateKey:      keys.Private,
		ClientPublicKey: *clientPublic,
		ClientAddress:   netip.MustParseAddr(*clientAddress),
		InnerAddress:    netip.MustParseAddr(*innerAddress),
		DNSPort:         uint16(*dnsPort),
		Profile:         lines,
		Name:            *name,
		Address:         netip.MustParseAddr(*address),
		Silent:          *silent,
	})
	if err != nil {
		fatal(err)
	}
	defer p.Close()
	ready["port"] = p.Port
	line, _ := json.Marshal(ready)
	fmt.Println(string(line))
	// Run until the parent closes stdin; answer "status" with the counters.
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "status" {
			status, _ := json.Marshal(map[string]any{"queries": p.Queries(), "handshook": p.Handshook()})
			fmt.Println(string(status))
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "awg-carry-testpeer:", err)
	os.Exit(1)
}

var _ = io.EOF
