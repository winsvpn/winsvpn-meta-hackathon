// Command winn3-probe (log prefix still "v3probe") is a winn/3 CLIENT that
// proves whether a packet handed to a -forward gateway actually reaches the
// internet and comes back. It lives at cmd/winn3-probe.
//
// It deliberately does NOT create a kernel tun device on the client side. A
// client-side tun addressed inside -forward-cidr would install a /32 host
// route that is more specific than the gateway tun's /24, so the kernel would
// short-circuit the reply straight to the client interface and the gateway's
// return path (sharedGatewayTun.run -> forwardTable.lookup -> Loop.SendInner)
// would never be exercised. With an in-memory device the ONLY route to the
// client's inner address on the host is the gateway's own /24, so a reply that
// arrives here has provably traversed that return path.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/dualsign"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "v3probe: %v\n", err)
		os.Exit(1)
	}
}

// memDevice is the client's inner side: an in-memory tun.Device.
type memDevice struct {
	mtu       int
	in        chan []byte
	out       chan []byte
	closeOnce sync.Once
	closed    chan struct{}
}

func newMemDevice(mtu int) *memDevice {
	return &memDevice{mtu: mtu, in: make(chan []byte, 64), out: make(chan []byte, 64), closed: make(chan struct{})}
}

func (d *memDevice) ReadPacket(buf []byte) (int, error) {
	select {
	case p := <-d.in:
		if len(p) > len(buf) {
			return 0, fmt.Errorf("memDevice: packet of %d bytes exceeds buffer of %d; copy would truncate silently", len(p), len(buf))
		}
		return copy(buf, p), nil
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

func (d *memDevice) WritePacket(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	select {
	case d.out <- cp:
		return len(p), nil
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

func (d *memDevice) MTU() int { return d.mtu }

func (d *memDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// icmpEcho builds a complete IPv4 + ICMP echo request.
func icmpEcho(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	icmp := make([]byte, 8+len(payload))
	icmp[0] = 8 // echo request
	icmp[1] = 0
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))

	total := 20 + len(icmp)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], 0)
	pkt[8] = 64 // TTL
	pkt[9] = 1  // ICMP
	s4, d4 := src.As4(), dst.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))
	copy(pkt[20:], icmp)
	return pkt
}

// dnsQueryWire builds a DNS query message: header + one QTYPE=A/QCLASS=IN
// question. Returned separately from the packet so the caller can match the
// transaction id on the reply.
func dnsQueryWire(txid uint16, name string) ([]byte, error) {
	msg := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(msg[0:2], txid)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // standard query, recursion desired
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS label %q in %q", label, name)
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)    // root label
	msg = append(msg, 0, 1) // QTYPE  A
	msg = append(msg, 0, 1) // QCLASS IN
	return msg, nil
}

// udpDNS builds a complete IPv4 + UDP + DNS query packet, including the UDP
// checksum over the IPv4 pseudo-header. The checksum is not optional here: the
// gateway's resolver reads the datagram after winn3/tun has validated it, and a
// zero-checksum datagram is indistinguishable from a corrupted one to anything
// downstream that checks.
func udpDNS(src, dst netip.Addr, srcPort, dstPort, txid uint16, name string) ([]byte, error) {
	dns, err := dnsQueryWire(txid, name)
	if err != nil {
		return nil, err
	}
	udpLen := 8 + len(dns)
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], dns)

	// UDP checksum over pseudo-header + UDP header + payload.
	s4, d4 := src.As4(), dst.As4()
	pseudo := make([]byte, 0, 12+udpLen)
	pseudo = append(pseudo, s4[:]...)
	pseudo = append(pseudo, d4[:]...)
	pseudo = append(pseudo, 0, 17)
	var lenb [2]byte
	binary.BigEndian.PutUint16(lenb[:], uint16(udpLen))
	pseudo = append(pseudo, lenb[:]...)
	pseudo = append(pseudo, udp...)
	ck := checksum(pseudo)
	if ck == 0 {
		ck = 0xffff // 0 means "no checksum" on the wire; 0xffff is its equivalent
	}
	binary.BigEndian.PutUint16(udp[6:8], ck)

	total := 20 + udpLen
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], txid)
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))
	copy(pkt[20:], udp)
	return pkt, nil
}

// describeDNS renders the parts of a DNS message that decide whether the
// resolver actually answered: rcode, the TC (truncated) bit, and any A records.
func describeDNS(msg []byte) string {
	if len(msg) < 12 {
		return " dns=<short>"
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	qd := binary.BigEndian.Uint16(msg[4:6])
	an := binary.BigEndian.Uint16(msg[6:8])
	out := fmt.Sprintf(" dns id=%d qr=%d rcode=%d TC=%d qd=%d an=%d",
		binary.BigEndian.Uint16(msg[0:2]), (flags>>15)&1, flags&0x0f, (flags>>9)&1, qd, an)
	// Walk past the questions, then decode answers far enough to print A records.
	off := 12
	skipName := func() bool {
		for off < len(msg) {
			l := int(msg[off])
			if l == 0 {
				off++
				return true
			}
			if l&0xc0 == 0xc0 { // compression pointer
				off += 2
				return true
			}
			off += 1 + l
		}
		return false
	}
	for i := 0; i < int(qd); i++ {
		if !skipName() || off+4 > len(msg) {
			return out
		}
		off += 4
	}
	for i := 0; i < int(an); i++ {
		if !skipName() || off+10 > len(msg) {
			return out
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return out
		}
		if typ == 1 && rdlen == 4 {
			out += fmt.Sprintf(" A=%s", netip.AddrFrom4([4]byte(msg[off:off+4])))
		}
		off += rdlen
	}
	return out
}

func describe(pkt []byte) string {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return fmt.Sprintf("non-IPv4 (%d bytes) %s", len(pkt), hex.EncodeToString(pkt[:min(len(pkt), 16)]))
	}
	ihl := int(pkt[0]&0x0f) * 4
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	proto := pkt[9]
	out := fmt.Sprintf("ipv4 %s -> %s proto=%d len=%d", src, dst, proto, len(pkt))
	if proto == 17 && len(pkt) >= ihl+8 {
		u := pkt[ihl:]
		out += fmt.Sprintf(" udp %d -> %d len=%d",
			binary.BigEndian.Uint16(u[0:2]), binary.BigEndian.Uint16(u[2:4]), binary.BigEndian.Uint16(u[4:6]))
		if len(u) > 8 {
			out += describeDNS(u[8:])
		}
	}
	if proto == 1 && len(pkt) >= ihl+8 {
		ic := pkt[ihl:]
		out += fmt.Sprintf(" icmp type=%d code=%d id=%d seq=%d",
			ic[0], ic[1], binary.BigEndian.Uint16(ic[4:6]), binary.BigEndian.Uint16(ic[6:8]))
		if len(ic) > 8 {
			out += fmt.Sprintf(" payload=%q", ic[8:min(len(ic), 8+40)])
		}
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func readKeyFile(path string) ([]byte, error) {
	raw, err := securefile.ReadPrivateLimited(path, 4096)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == hex.EncodedLen(core.KeySize) {
		if decoded, decErr := hex.DecodeString(trimmed); decErr == nil {
			return decoded, nil
		}
	}
	if len(raw) == core.KeySize {
		return raw, nil
	}
	return nil, fmt.Errorf("%s: %d bytes, expected %d raw or %d hex", path, len(raw), core.KeySize, hex.EncodedLen(core.KeySize))
}

// decodeHexKey reads a hex public-key flag value into exactly want bytes.
func decodeHexKey(text string, want int) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return nil, err
	}
	if len(raw) != want {
		return nil, fmt.Errorf("got %d bytes, want %d", len(raw), want)
	}
	return raw, nil
}

func readProbeDirKey(dir, name string) ([]byte, error) {
	b, err := readKeyFile(filepath.Join(dir, name))
	if err != nil {
		return nil, fmt.Errorf("-dir: expected %s from winn3-gateway -mode keygen: %w", name, err)
	}
	return b, nil
}

func run() error {
	o := defineProbeFlags(flag.CommandLine)
	flag.Parse()
	if err := refuseExtraProbeArgs(flag.CommandLine); err != nil {
		return err
	}
	parsed, err := validateProbeFlags(*o)
	if err != nil {
		return err
	}

	clientPriv, err := readProbeDirKey(o.dir, "client.key")
	if err != nil {
		return err
	}
	staticKey, err := core.NewStaticKey(clientPriv)
	if err != nil {
		return fmt.Errorf("-dir client.key: %w", err)
	}
	gwPubBytes, err := readProbeDirKey(o.dir, "static.pub")
	if err != nil {
		return err
	}
	gatewayStatic, err := core.NewPublicKey(gwPubBytes)
	if err != nil {
		return fmt.Errorf("-dir static.pub: %w", err)
	}
	// The admission secret is OPAQUE BYTES, never hex-decoded -- see
	// buildSessionConfig's comment in cmd/winn3-gateway/main.go. Both ends must
	// treat this file identically byte for byte or the gateway answers with
	// silence and the failure is indistinguishable from "nothing is there".
	rawSecret, err := securefile.ReadPrivateLimited(filepath.Join(o.dir, "admission.key"), 4096)
	if err != nil {
		return fmt.Errorf("-dir: expected admission.key from winn3-gateway -mode keygen: %w", err)
	}
	admission := bytes.TrimRight(rawSecret, "\r\n")
	if len(admission) < 32 {
		return fmt.Errorf(
			"-dir admission.key is %d bytes after trimming a trailing newline; winn3-gateway -mode keygen writes 64 hex characters which this binary uses as opaque bytes (not hex-decoded), and the admission tag needs at least 32",
			len(admission))
	}

	sizing := parsed.sizing
	gwAddr := parsed.gwAddr
	srcAddr := parsed.srcAddr
	dstAddr := parsed.dstAddr
	dnsAddr := parsed.dnsAddr

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	car, err := carrier.DialUDP(ctx, carrier.UDPConfig{
		Remote:         gwAddr,
		MaxMessageSize: sizing.MessageSize,
		PathMTU:        sizing.PathMTU,
		SocketBufferHook: func(requested, gotRead, gotWrite int, setErr error) {
			fmt.Printf("v3probe: udp socket buffers requested=%d granted_read=%d granted_write=%d",
				requested, gotRead, gotWrite)
			if setErr != nil {
				fmt.Printf(" set_err=%v", setErr)
			}
			fmt.Println()
		},
	})
	if err != nil {
		return fmt.Errorf("dial -gw %s: %w", o.gw, err)
	}
	captured := &capturingConn{Conn: car}

	dev := newMemDevice(sizing.InnerMTU)
	tunCfg := tun.Config{
		Assign: tun.Assignment{V4: srcAddr},
		Device: dev,
		Clock:  driver.SessionClock{Clock: driver.SystemClock{}},
	}
	sessionCfg := session.Config{
		Core: core.Config{
			Gateway: core.GatewayParams{
				AdmissionKeys: [][]byte{admission},
				GatewayID:     []byte(o.gatewayID),
			},
		},
		Static:        staticKey,
		GatewayStatic: gatewayStatic,
		Padding:       core.PadBucket,
	}
	if o.dualEDPub != "" || o.dualMLPub != "" {
		if o.dualEDPub == "" || o.dualMLPub == "" {
			return errors.New("-dual-ed-pub and -dual-ml-pub must be provided together")
		}
		edPub, err := decodeHexKey(o.dualEDPub, dualsign.Ed25519PublicKeySize)
		if err != nil {
			return fmt.Errorf("-dual-ed-pub: %w", err)
		}
		mlPub, err := decodeHexKey(o.dualMLPub, dualsign.MLDSA65PublicKeySize)
		if err != nil {
			return fmt.Errorf("-dual-ml-pub: %w", err)
		}
		sessionCfg.DualAuth = session.DualAuthConfig{
			Expected:      true,
			Ed25519Public: edPub,
			MLDSA65Public: mlPub,
		}
	}
	if parsed.rekeyAfter > 0 {
		sessionCfg.RekeyAfterMessages = parsed.rekeyAfter
	}
	loop, err := driver.NewClient(driver.Config{
		Session: sessionCfg,
		Sizing:  sizing,
		Carrier: captured,
		Tun:     &tunCfg,
	})
	if err != nil {
		return fmt.Errorf("session (-dir keys, -gateway-id, -inner, -path-mtu): %w", err)
	}
	done := make(chan struct{})
	runErrCh := make(chan error, 1)
	go func() {
		defer close(done)
		runErrCh <- loop.Run(ctx)
	}()
	defer func() {
		cancel()
		_ = loop.Close()
		_ = dev.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			fmt.Fprintln(os.Stderr, "v3probe: session loop did not exit within 5s after cancel")
		}
	}()

	if parsed.dnsMode {
		fmt.Printf("v3probe: dialed %s, inner %s, dns %s @ %s, inner MTU %d\n",
			o.gw, srcAddr, o.dnsName, dnsAddr, sizing.InnerMTU)
	} else if parsed.canary {
		fmt.Printf("v3probe: dialed %s, inner %s, reflect-to %s, canary rekey-after=%d, inner MTU %d\n",
			o.gw, srcAddr, parsed.reflectAddr, parsed.rekeyAfter, sizing.InnerMTU)
	} else {
		fmt.Printf("v3probe: dialed %s, inner %s, target %s, inner MTU %d\n",
			o.gw, srcAddr, dstAddr, sizing.InnerMTU)
	}

	deadline := time.Now().Add(handshakeWait)
	for time.Now().Before(deadline) {
		if loop.Tunnel().Gate().State() == tun.StateCarrying {
			break
		}
		select {
		case err := <-runErrCh:
			return fmt.Errorf(
				"the client session ended before the gate reached carrying (state %v): %w",
				loop.Tunnel().Gate().State(), unexpectedSessionEnd(err))
		case <-time.After(50 * time.Millisecond):
		}
	}
	if st := loop.Tunnel().Gate().State(); st != tun.StateCarrying {
		fmt.Printf("v3probe: HANDSHAKE absent state=%s wait=%s\n", st, handshakeWait)
		return fmt.Errorf(
			"the client gate never reached carrying (state %v) after %s -- no session. "+
				"This wait is handshakeWait, not -budget. A v3 gateway answers unauthenticated "+
				"datagrams with silence, so this is indistinguishable from a down path. Check "+
				"-gateway-id matches the gateway (no edge whitespace), -dir admission.key is the "+
				"same opaque bytes the gateway uses (not hex-decoded), -path-mtu matches, and -gw %s is reachable",
			st, handshakeWait, o.gw)
	}
	fmt.Println("v3probe: gate is CARRYING -- a real winn/3 session is up")
	dualAuth := "off"
	if sessionCfg.DualAuth.Expected {
		if !loop.Session().DualAuthVerified() {
			return errors.New(
				"the gate reached carrying without the requested dual-signature attestation")
		}
		dualAuth = "ok"
	}
	fmt.Printf("v3probe: HANDSHAKE ok state=carrying epoch=%d session=%s dual-auth=%s\n",
		loop.Session().Epoch(), loop.Session().State(), dualAuth)

	if parsed.canary {
		return runCanary(ctx, canaryRun{
			loop:     loop,
			dev:      dev,
			captured: captured,
			parsed:   parsed,
			opts:     *o,
			runErrCh: runErrCh,
			replies:  dev.out,
		})
	}

	// The tunnel delivers inbound packets by calling dev.WritePacket, which
	// queues them on dev.out. That queue IS the client's inbox.
	replies := dev.out

	id := uint16(os.Getpid() & 0xffff)
	var sent, got, unmatched int
	var outstanding [][]byte
	payload := []byte("winn3-forward-proof-20260812")
	for i := 0; i < o.count; i++ {
		var pkt []byte
		if parsed.dnsMode {
			// Source port varies per query so a stale reply cannot share a
			// 4-tuple with a later one; the transaction id is the other half.
			// countAsProbeReply is what actually refuses to count a mismatch —
			// uniqueness on the send side is not a receive-side check.
			pkt, err = udpDNS(srcAddr, dnsAddr, dnsUDPSrcPortBase+uint16(i), 53, id+uint16(i), o.dnsName)
			if err != nil {
				return fmt.Errorf("-dns: %w", err)
			}
		} else {
			pkt = icmpEcho(srcAddr, dstAddr, id, uint16(i+1), payload)
		}
		select {
		case err := <-runErrCh:
			return unexpectedSessionEnd(err)
		case dev.in <- pkt:
			sent++
			outstanding = append(outstanding, append([]byte(nil), pkt...))
			fmt.Printf("v3probe: SENT  %s\n", describe(pkt))
		case <-time.After(5 * time.Second):
			fmt.Println("v3probe: the device would not accept an outbound packet")
		}
		got, unmatched, outstanding = drainReplies(replies, outstanding, parsed.dnsMode, parsed.reflectAddr, got, unmatched)
		if i < o.count-1 {
			time.Sleep(o.interval)
		}
	}

	waitUntil := time.After(o.budget)
	for {
		select {
		case r := <-replies:
			got, unmatched, outstanding = noteReply(r, outstanding, parsed.dnsMode, parsed.reflectAddr, got, unmatched)
			if got >= sent {
				goto finish
			}
		case err := <-runErrCh:
			if got == 0 {
				return finishWithNoMatch(unmatched, parsed.dnsMode, parsed.canary, sent, int(loop.Tunnel().Stats().TxDroppedInvalid), o.budget, err)
			}
			goto finish
		case <-waitUntil:
			goto finish
		}
	}

finish:
	st := loop.Tunnel().Stats()
	fmt.Printf("v3probe: sent=%d received=%d unmatched=%d\n", sent, got, unmatched)
	fmt.Printf("v3probe: tunnel stats tx=%d rx=%d rx_dropped_invalid=%d tx_dropped_invalid=%d\n",
		st.TxPackets, st.RxPackets, st.RxDroppedInvalid, st.TxDroppedInvalid)
	if got == 0 {
		fmt.Println("v3probe: VERDICT no matching reply came back through the tunnel")
		return finishWithNoMatch(unmatched, parsed.dnsMode, parsed.canary, sent, int(st.TxDroppedInvalid), o.budget, nil)
	}
	fmt.Println("v3probe: VERDICT a matching reply came back through the winn/3 session")
	return nil
}
