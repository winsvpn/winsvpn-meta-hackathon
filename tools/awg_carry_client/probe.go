package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

const (
	// A small inner MTU: the only inner traffic is one DNS exchange, and the
	// served profile's junk and padding sit outside this budget anyway.
	tunnelMTU = 1280
	// The query is re-sent until the deadline: packets handed to the device
	// before the handshake completes are queued one at a time, and the
	// handshake itself retries on the engine's own timer.
	resendInterval = time.Second
	// A reply larger than this is not a DNS reply to the canary question.
	maxDNSReply = 4096
)

// Status names in the reply. The parent reads none of them for the verdict,
// which is its own validation of dns_reply_hex; they are for the log.
const (
	statusCarried          = "carried"
	statusNoReply          = "no_reply"
	statusEndpointUnusable = "endpoint_unusable"
	statusDeviceFailed     = "device_failed"
	// The engine refused the request's configuration: nothing was sent, so
	// the reply carries no dns_reply_hex and the parent records no verdict.
	statusRefused = "refused"
)

// Result is what one probe found. Reply is the decrypted datagram that came
// back through the tunnel for the request's DNS question, or nil.
type Result struct {
	Status    string
	Detail    string
	Reply     []byte
	Handshake bool
	Elapsed   time.Duration
}

// probe runs one carrying proof: a fresh userspace AmneziaWG device with the
// served profile and the canary key, one handshake to the endpoint, the DNS
// query through the tunnel, and the first datagram that answers it. Nothing
// survives the call: the device, its socket and the in-process network stack
// are torn down before it returns.
func probe(ctx context.Context, req *Request) (result Result) {
	started := time.Now()
	ctx, cancel := context.WithDeadline(ctx, started.Add(req.Timeout))
	defer cancel()
	result = Result{Status: statusNoReply}
	defer func() { result.Elapsed = time.Since(started) }()

	endpoint, err := resolveEndpoint(ctx, req.EndpointHost, req.EndpointPort)
	if err != nil {
		result.Status, result.Detail = statusEndpointUnusable, err.Error()
		return result
	}

	tunDevice, inner, err := netstack.CreateNetTUN([]netip.Addr{req.LocalAddress}, nil, tunnelMTU)
	if err != nil {
		result.Status, result.Detail = statusDeviceFailed, "in-process network stack: "+err.Error()
		return result
	}
	dev := device.NewDevice(tunDevice, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()

	// Device section (keys first, then the served profile), then the one
	// peer. The private key is formatted here and nowhere else.
	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", req.privateKeyHex)
	for _, line := range req.ProfileLines {
		uapi.WriteString(line)
		uapi.WriteByte('\n')
	}
	uapi.WriteString("replace_peers=true\n")
	fmt.Fprintf(&uapi, "public_key=%s\n", req.peerPublicHex)
	fmt.Fprintf(&uapi, "endpoint=%s\n", endpoint.String())
	fmt.Fprintf(&uapi, "allowed_ip=%s/32\n", req.DNSServer.String())
	if err := dev.IpcSet(uapi.String()); err != nil {
		// Both keys were validated before, so only the served profile can
		// fail here (an I1 to I5 chain the engine cannot parse, overlapping
		// H ranges). That is a malformed request, not a verdict about the
		// node. The engine's errors can quote profile values (strconv text,
		// an unknown chain tag), so the reason is a fixed string.
		result.Status, result.Detail = statusRefused, "device configuration rejected"
		return result
	}
	if err := dev.Up(); err != nil {
		result.Status, result.Detail = statusDeviceFailed, "device did not come up: "+scrub(err.Error())
		return result
	}

	socket, err := inner.DialUDPAddrPort(netip.AddrPortFrom(req.LocalAddress, 0), netip.AddrPortFrom(req.DNSServer, req.DNSPort))
	if err != nil {
		result.Status, result.Detail = statusDeviceFailed, "inner UDP socket: "+err.Error()
		return result
	}
	defer socket.Close()

	reply, err := exchange(ctx, socket, req.DNSQuery)
	result.Handshake = handshakeCompleted(dev)
	if err == nil {
		result.Status, result.Reply = statusCarried, reply
		result.Detail = fmt.Sprintf("DNS reply of %d bytes decrypted through the tunnel", len(reply))
		return result
	}
	if result.Handshake {
		result.Detail = "handshake completed but no DNS reply came back through the tunnel before the deadline"
	} else {
		result.Detail = "no handshake with the endpoint before the deadline"
	}
	return result
}

// exchange sends the query, re-sending it every resendInterval, and returns
// the first datagram that is a response to it: same id, QR set. Anything
// else that arrives on the inner socket is ignored.
func exchange(ctx context.Context, socket net.Conn, query []byte) ([]byte, error) {
	buffer := make([]byte, maxDNSReply+1)
	deadline, _ := ctx.Deadline()
	for {
		if _, err := socket.Write(query); err != nil {
			return nil, fmt.Errorf("inner write: %w", err)
		}
		next := time.Now().Add(resendInterval)
		if next.After(deadline) {
			next = deadline
		}
		for time.Now().Before(next) {
			if err := socket.SetReadDeadline(next); err != nil {
				return nil, err
			}
			n, err := socket.Read(buffer)
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					break
				}
				return nil, fmt.Errorf("inner read: %w", err)
			}
			if n > maxDNSReply {
				continue
			}
			if isResponseTo(buffer[:n], query) {
				reply := make([]byte, n)
				copy(reply, buffer[:n])
				return reply, nil
			}
		}
		if !time.Now().Before(deadline) {
			return nil, errors.New("no reply before the deadline")
		}
	}
}

// isResponseTo is the client's own, minimal check: the parent re-validates
// the whole message. It only keeps the client from returning an unrelated
// datagram as the reply.
func isResponseTo(datagram, query []byte) bool {
	if len(datagram) < 12 {
		return false
	}
	return datagram[0] == query[0] && datagram[1] == query[1] && datagram[2]&0x80 != 0
}

// handshakeCompleted reads last_handshake_time_sec from the device. The UAPI
// document also holds the private key; only this one field leaves here.
func handshakeCompleted(dev *device.Device) bool {
	document, err := dev.IpcGet()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(document, "\n") {
		key, value, found := strings.Cut(line, "=")
		if found && key == "last_handshake_time_sec" {
			return value != "" && value != "0"
		}
	}
	return false
}

// resolveEndpoint turns the endpoint into one address and port: an IP
// literal as given, a name through the system resolver, IPv4 first.
func resolveEndpoint(ctx context.Context, host string, port uint16) (netip.AddrPort, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(addr.Unmap(), port), nil
	}
	resolver := net.Resolver{}
	for _, network := range []string{"ip4", "ip6"} {
		addrs, err := resolver.LookupNetIP(ctx, network, host)
		if err != nil || len(addrs) == 0 {
			continue
		}
		for _, addr := range addrs {
			addr = addr.Unmap()
			if addr.IsValid() && !addr.IsUnspecified() && !addr.IsMulticast() {
				return netip.AddrPortFrom(addr, port), nil
			}
		}
	}
	return netip.AddrPort{}, errors.New("endpoint host did not resolve")
}

// scrub keeps an engine error message to one line of printable ASCII.
func scrub(text string) string {
	var out strings.Builder
	for _, r := range text {
		if r >= 0x20 && r < 0x7f {
			out.WriteRune(r)
		} else {
			out.WriteByte(' ')
		}
		if out.Len() >= 200 {
			break
		}
	}
	return out.String()
}
