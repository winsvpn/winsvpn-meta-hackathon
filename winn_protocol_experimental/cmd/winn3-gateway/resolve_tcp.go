package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// TCP/53 for the inner DNS responder. Fable D21: an ordinary kernel TCP
// listening socket bound to exactly -inner-v4:53 inside this process. Started
// only when BOTH -forward and -resolver are on. In -forward mode the kernel
// already owns TCP for the host's own address on the tun, so no userspace
// TCP-over-tun stack is needed.
//
// claim() MUST keep refusing protocol 6. A SYN this wrapper stole would never
// reach the listener. TestResolverRefusesEverythingItMustNotClaim / "TCP rather
// than UDP" is load-bearing for that hand-off.
//
// An EDNS0 clamp is not this file and is not a fix: it only moves which box
// truncates. A wildcard bind after EADDRNOTAVAIL is a ship-stopper: with
// CAP_NET_BIND_SERVICE that would be an open resolver on the WAN.

const dnsTCPMaxMessage = 65535

var (
	errDNSTCPLengthZero = errors.New("dns tcp length is 0")
	errDNSTCPTooShort   = errors.New("dns tcp message shorter than a DNS header")
	errDNSTCPTooLong    = errors.New("dns tcp message exceeds 65535")
	errDNSTCPIDMismatch = errors.New("dns tcp reply transaction id mismatch")
	errDNSTCPWildcard   = errors.New("resolver TCP bind is a wildcard; this process binds exactly -inner-v4:53 and never 0.0.0.0 (open resolver on the WAN)")
)

// resolverLog is the only sink a per-query line would be allowed to use, and
// the production value discards everything. Tests replace it with a buffer to
// prove a query for example.com produces no bytes. Do not fmt.Fprintf query
// names, client addresses, or upstream addresses anywhere else either.
var resolverLog resolverLogger = discardResolverLog{}

type resolverLogger interface {
	Printf(format string, args ...any)
}

type discardResolverLog struct{}

func (discardResolverLog) Printf(string, ...any) {}

// resolverTCPListen is net.Listen, replaced in tests so a mocked EADDRNOTAVAIL
// can prove this file does not retry 0.0.0.0.
var resolverTCPListen = func(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

// resolverTCPListenPort is "53" in production. Tests set it to "0" so
// startResolverTCP can bind an ephemeral port on 127.0.0.1 without needing
// CAP_NET_BIND_SERVICE or a tun address. Production runServe never changes it.
var resolverTCPListenPort = strconv.Itoa(dnsPort)

// resolverTCPListenSpec is the one place production asks for a TCP bind.
// Tests call it with a high port. Network is always "tcp4"; address is always
// JoinHostPort(ours, port), never ":53" and never "0.0.0.0:53".
func resolverTCPListenSpec(ours netip.Addr, port string) (network, address string) {
	return "tcp4", net.JoinHostPort(ours.String(), port)
}

func resolverTCPAddressIsWildcard(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return true
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" || host == "*" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

func wrapResolverTCPListenError(err error, address string) error {
	switch {
	case errors.Is(err, syscall.EACCES):
		return fmt.Errorf("listen tcp4 %s: %w; binding port 53 needs CAP_NET_BIND_SERVICE in both CapabilityBoundingSet and AmbientCapabilities (write_unit grants it only when WINN3_GATEWAY_FORWARD=1 and WINN3_GATEWAY_RESOLVER=1)", address, err)
	case errors.Is(err, syscall.EADDRINUSE):
		return fmt.Errorf("listen tcp4 %s: %w; another process already bound this address:53 (the two-responders hazard: a host resolver such as AdGuard answering TCP here would log queries this process's contract forbids logging). Fail closed rather than continue UDP-only", address, err)
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return fmt.Errorf("listen tcp4 %s: %w; the address is not assigned on this host (in -forward mode newSharedGatewayTun must have completed first). This process does not fall back to 0.0.0.0:53, which with CAP_NET_BIND_SERVICE would be an open resolver on the WAN", address, err)
	default:
		return fmt.Errorf("listen tcp4 %s: %w", address, err)
	}
}

func listenResolverTCP(network, address string) (net.Listener, error) {
	if network != "tcp4" || resolverTCPAddressIsWildcard(address) {
		return nil, fmt.Errorf("%w: network=%q address=%q", errDNSTCPWildcard, network, address)
	}
	ln, err := resolverTCPListen(network, address)
	if err != nil {
		return nil, wrapResolverTCPListenError(err, address)
	}
	if ta, ok := ln.Addr().(*net.TCPAddr); !ok || ta.IP == nil || ta.IP.IsUnspecified() {
		addr := ln.Addr()
		_ = ln.Close()
		return nil, fmt.Errorf("resolver TCP bound unspecified address %v; refusing (would be an open resolver on the WAN)", addr)
	}
	return ln, nil
}

// startResolverTCP binds -inner-v4:53 and serves RFC 1035 TCP DNS. No-op when
// r is nil or forward is false: reflector mode has no host address, and a
// listen there would be EADDRNOTAVAIL or, worse, a bind on some other host
// address. Fail closed on listen error; do not continue UDP-only.
func startResolverTCP(ctx context.Context, r *gatewayResolver, forward bool, ours netip.Addr) error {
	if r == nil || !forward {
		return nil
	}
	if !ours.Is4() {
		return fmt.Errorf("resolver TCP listen needs an IPv4 -inner-v4, got %s", ours)
	}
	network, address := resolverTCPListenSpec(ours, resolverTCPListenPort)
	ln, err := listenResolverTCP(network, address)
	if err != nil {
		return err
	}
	// Publish before the accept loop so a caller (and tests) can observe the
	// listener without racing serveTCP's first line.
	r.setTCPListener(ln)
	go r.serveTCP(ctx, ln)
	return nil
}

func (r *gatewayResolver) setTCPListener(ln net.Listener) {
	r.tcpLnMu.Lock()
	r.tcpLn = ln
	r.tcpLnMu.Unlock()
}

func (r *gatewayResolver) tcpListener() net.Listener {
	r.tcpLnMu.Lock()
	defer r.tcpLnMu.Unlock()
	return r.tcpLn
}

func (r *gatewayResolver) tokensHeld() int {
	return len(r.sem)
}

func (r *gatewayResolver) serveTCP(ctx context.Context, ln net.Listener) {
	r.setTCPListener(ln)
	defer r.setTCPListener(nil)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go r.handleTCP(conn)
	}
}

func tcpClientAddr(a net.Addr) (netip.Addr, bool) {
	ta, ok := a.(*net.TCPAddr)
	if !ok || ta.IP == nil {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	if !ok {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

// handleTCP serves one accepted connection. The in-flight slot is taken at
// accept (bounds fds against idle SYNs from authenticated peers) and held for
// the connection's lifetime, including idle-until-first-byte and pipelined
// queries. One connection is one slot, not one slot per pipelined query.
// Queries on one conn are serialised. The upstream dial does not take a
// second slot.
func (r *gatewayResolver) handleTCP(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	client, ok := tcpClientAddr(conn.RemoteAddr())
	if !ok {
		r.tcpDropped.Add(1)
		return
	}

	r.tcpAccepted.Add(1)
	if !r.acquireClient(client) {
		r.tcpRefused.Add(1)
		return
	}
	select {
	case r.sem <- struct{}{}:
	default:
		r.releaseClient(client)
		r.tcpRefused.Add(1)
		return
	}
	defer func() {
		<-r.sem
		r.releaseClient(client)
	}()

	for {
		// READ deadline, not SetDeadline.
		//
		// This bounds how long an accepted connection may sit idle before its
		// first byte, and between pipelined queries. It must NOT also cover the
		// upstream exchange, and SetDeadline made it do exactly that: it arms
		// the write side at the same instant, and exchangeTCP is allowed to
		// spend the whole of r.timeout. So against a silent upstream the
		// sequence was: arm both deadlines for now+timeout, read the query in
		// microseconds, spend the full timeout upstream, then find the WRITE
		// deadline already expired and fail to send the SERVFAIL this code goes
		// to the trouble of building. The client got a closed connection —
		// io.EOF mid-frame — instead of an answer, which is both worse
		// behaviour and, for a resolver whose whole job is to be
		// indistinguishable from an ordinary one, a different observable than
		// every other DNS server on the internet produces. An ordinary resolver
		// answers SERVFAIL and keeps the connection.
		// TestResolverTCPTimeoutOnASilentUpstream pins it.
		if err := conn.SetReadDeadline(time.Now().Add(r.timeout)); err != nil {
			return
		}
		query, err := readDNSTCPFrame(conn)
		if err != nil {
			return
		}
		if query[2]&0x80 != 0 {
			// QR set: a response arriving as a query. Close, do not forward
			// (would make this process relay a forged answer upstream).
			r.tcpDropped.Add(1)
			return
		}
		answer, err := r.exchangeTCP(query)
		if err != nil {
			r.tcpUpstreamFailed.Add(1)
			servfail, ok := dnsServFailAnswer(query)
			if !ok {
				r.tcpDropped.Add(1)
				return
			}
			clearDNSTCPTruncation(servfail)
			if werr := r.writeTCPResponse(conn, servfail); werr != nil {
				r.tcpDropped.Add(1)
				return
			}
			continue
		}
		clearDNSTCPTruncation(answer)
		if err := r.writeTCPResponse(conn, answer); err != nil {
			r.tcpDropped.Add(1)
			return
		}
		r.tcpAnswered.Add(1)
	}
}

// writeTCPResponse writes one response under a FRESH write deadline.
//
// The deadline is armed here rather than at the top of the loop because the
// time already spent upstream is not the client's fault and must not be
// deducted from the budget for delivering the answer. r.timeout is the bound on
// each individual network operation, not on the sum of them; the in-flight
// ceiling and the per-client cap are what bound total connection lifetime, and
// they are unaffected by this.
func (r *gatewayResolver) writeTCPResponse(conn net.Conn, msg []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(r.timeout)); err != nil {
		return err
	}
	return writeDNSTCPFrame(conn, msg)
}

// clearDNSTCPTruncation clears TC. RFC 7766: never set TC on a TCP response.
// If the upstream TCP answer is unreadable that is failure, not truncation;
// if it arrives with TC set we still must not pass that bit on.
func clearDNSTCPTruncation(msg []byte) {
	if len(msg) >= 3 {
		msg[2] &^= 0x02
	}
}

// exchangeTCP performs one upstream round trip over TCP, same address:port as
// UDP exchange, same 2-byte framing. The client is on TCP because the answer
// did not fit UDP; forwarding over UDP recreates TC=1. One ephemeral dial per
// query, matching exchange's one ephemeral UDP socket; no pool.
func (r *gatewayResolver) exchangeTCP(payload []byte) ([]byte, error) {
	dialer := net.Dialer{Timeout: r.timeout}
	conn, err := dialer.Dial("tcp4", net.JoinHostPort(r.upstream.Addr().String(), strconv.Itoa(int(r.upstream.Port()))))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(r.timeout)); err != nil {
		return nil, err
	}
	if err := writeDNSTCPFrame(conn, payload); err != nil {
		return nil, err
	}
	answer, err := readDNSTCPFrame(conn)
	if err != nil {
		return nil, err
	}
	if answer[0] != payload[0] || answer[1] != payload[1] {
		return nil, errDNSTCPIDMismatch
	}
	return answer, nil
}

func dnsTCPFrame(msg []byte) ([]byte, error) {
	if len(msg) == 0 {
		return nil, errDNSTCPLengthZero
	}
	if len(msg) > dnsTCPMaxMessage {
		return nil, errDNSTCPTooLong
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(msg)))
	copy(out[2:], msg)
	return out, nil
}

func writeDNSTCPFrame(w io.Writer, msg []byte) error {
	framed, err := dnsTCPFrame(msg)
	if err != nil {
		return err
	}
	_, err = w.Write(framed)
	return err
}

func readDNSTCPFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return nil, errDNSTCPLengthZero
	}
	if n < dnsHeaderBytes {
		return nil, errDNSTCPTooShort
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
