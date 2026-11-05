// Command wins-awg-carry-client is the hub's userspace AmneziaWG carrying
// canary client (design v17 section 3.15, ruling E; P-16 at integration).
//
// The carrying probe (wins_node_dataplane_probe.py --carry) starts one of
// these per transport and keeps it for a run. For every probe it writes one
// JSON request line on stdin: the hub canary private key, the node's public
// key, the canary address, the endpoint (for stealth and stealth_tls a
// loopback UDP relay the probe opened through the node's WebSocket and VLESS
// path), the node's served obfuscation profile, the DNS server inside the
// tunnel and the DNS query to carry. This process builds a fresh userspace
// AmneziaWG device on an in-process network stack (no tun device, no
// capability, no kernel module), handshakes with the served profile, sends
// the query to the resolver through the tunnel, and answers one JSON line
// echoing id, slug and transport with "dns_reply_hex": the decrypted reply,
// or "" when none came back before the deadline. The verdict is the parent's
// own validation of that reply, never this process's say-so.
//
// Nothing is kept between probes: each request gets its own device, socket
// and stack, torn down before the reply is written. A malformed request is
// refused with an "error" reply that carries no dns_reply_hex, which the
// parent treats as no verdict; so is a served profile the engine refuses to
// configure. No key ever reaches a log, a message or the
// reply; stderr carries nothing but a fatal usage error.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

// maxLine bounds one request line. The parent writes one compact JSON object
// per request; a served profile with five special junk chains stays far
// below this.
const maxLine = 1 << 20

type reply struct {
	ID          *int64  `json:"id,omitempty"`
	Slug        string  `json:"slug,omitempty"`
	Transport   string  `json:"transport,omitempty"`
	DNSReplyHex *string `json:"dns_reply_hex,omitempty"`
	Status      string  `json:"status,omitempty"`
	Detail      string  `json:"detail,omitempty"`
	Handshake   *bool   `json:"handshake,omitempty"`
	ElapsedMS   *int64  `json:"elapsed_ms,omitempty"`
	Error       string  `json:"error,omitempty"`
}

func main() {
	transport := flag.String("transport", "", "the transport this client serves: udp, stealth or stealth_tls")
	flag.Parse()
	if !transports[*transport] || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: wins-awg-carry-client --transport {udp|stealth|stealth_tls}")
		os.Exit(2)
	}
	os.Exit(serve(context.Background(), os.Stdin, os.Stdout, *transport, probe))
}

// prober is the one probe a request runs; tests substitute it.
type prober func(context.Context, *Request) Result

// serve answers requests until stdin ends. It never exits on a bad request:
// the refusal is the parent's to act on. It returns 0 at a clean end of
// input and 1 when stdout cannot be written.
func serve(ctx context.Context, in io.Reader, out io.Writer, transport string, run prober) int {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLine)
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		// An empty line is refused like any malformed request: the parent
		// never writes one, and one reply per line keeps the two in step.
		req, echo, err := parseRequest(scanner.Bytes(), transport)
		var answer reply
		if err != nil {
			answer = reply{ID: echo.ID, Slug: echo.Slug, Transport: echo.Transport, Error: "refused: " + err.Error()}
		} else {
			answer = render(req, run(ctx, req))
		}
		if err := encoder.Encode(answer); err != nil {
			return 1
		}
	}
	if err := scanner.Err(); err != nil {
		// An over-long or unreadable line is refused like any malformed
		// request; the parent sees no echo and restarts the client.
		_ = encoder.Encode(reply{Error: "refused: request line unreadable or longer than the limit"})
	}
	return 0
}

func render(req *Request, result Result) reply {
	id := req.ID
	switch result.Status {
	case statusRefused:
		return reply{ID: &id, Slug: req.Slug, Transport: req.Transport, Error: "refused: " + result.Detail}
	case statusDeviceFailed:
		// A fault on this host (in-process stack, socket bind, device start,
		// inner socket): nothing reached the node, so no verdict about it.
		return reply{ID: &id, Slug: req.Slug, Transport: req.Transport, Error: "local fault: " + result.Detail}
	}
	replyHex := ""
	if result.Status == statusCarried && len(result.Reply) > 0 {
		replyHex = hex.EncodeToString(result.Reply)
	}
	handshake := result.Handshake
	elapsed := result.Elapsed.Milliseconds()
	return reply{
		ID: &id, Slug: req.Slug, Transport: req.Transport,
		DNSReplyHex: &replyHex, Status: result.Status, Detail: result.Detail,
		Handshake: &handshake, ElapsedMS: &elapsed,
	}
}
