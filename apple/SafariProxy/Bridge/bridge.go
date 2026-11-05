package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	safariBadHandle = -1
	safariClosed    = -2
	safariTimeout   = -3
	safariTooLarge  = -4
	safariIO        = -5
	safariArgument  = -6
	safariMaxFlows  = 1024
)

type safariStack struct {
	stack    *stack.Stack
	endpoint *channel.Endpoint
	ctx      context.Context
	cancel   context.CancelFunc
	closed   atomic.Bool
	life     sync.RWMutex
	mtu      int
	v4, v6   bool
}
type safariFlow struct {
	owner           *safariStack
	conn            net.Conn
	udp             bool
	closed          atomic.Bool
	readMu, writeMu sync.Mutex
}

var safariRegistry = struct {
	sync.Mutex
	next   int64
	stacks map[int64]*safariStack
	flows  map[int64]*safariFlow
}{stacks: make(map[int64]*safariStack), flows: make(map[int64]*safariFlow)}

func safariError(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, io.EOF) {
		return 0
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return safariClosed
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		return safariTimeout
	}
	return safariIO
}
func safariDeadline(ms int) time.Time { return time.Now().Add(time.Duration(ms) * time.Millisecond) }
func safariTimeoutValid(ms int) bool  { return ms > 0 && ms <= 120000 }
func safariGetStack(h int64) *safariStack {
	safariRegistry.Lock()
	defer safariRegistry.Unlock()
	return safariRegistry.stacks[h]
}
func safariGetFlow(h int64) *safariFlow {
	safariRegistry.Lock()
	defer safariRegistry.Unlock()
	return safariRegistry.flows[h]
}

func safariNewStack(v4, v6 string, mtu int) int64 {
	if mtu < 576 || mtu > 9000 || v4 == "" && v6 == "" {
		return safariArgument
	}
	var addresses []netip.Addr
	for i, s := range []string{v4, v6} {
		if s == "" {
			continue
		}
		a, e := netip.ParseAddr(s)
		if e != nil || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() || a.Is4In6() || (i == 0 && !a.Is4()) || (i == 1 && (!a.Is6() || mtu < 1280)) {
			return safariArgument
		}
		addresses = append(addresses, a)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &safariStack{stack: stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6}}), endpoint: channel.New(256, uint32(mtu), ""), ctx: ctx, cancel: cancel, mtu: mtu, v4: v4 != "", v6: v6 != ""}
	if e := s.stack.CreateNIC(1, s.endpoint); e != nil {
		s.shutdown()
		return safariIO
	}
	for _, a := range addresses {
		protocol := ipv6.ProtocolNumber
		if a.Is4() {
			protocol = ipv4.ProtocolNumber
		}
		if e := s.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: tcpip.AddrFromSlice(a.AsSlice()).WithPrefix()}, stack.AddressProperties{}); e != nil {
			s.shutdown()
			return safariIO
		}
	}
	if s.v4 {
		s.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if s.v6 {
		s.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}
	safariRegistry.Lock()
	defer safariRegistry.Unlock()
	if len(safariRegistry.stacks) >= 8 {
		s.shutdown()
		return safariTooLarge
	}
	safariRegistry.next++
	h := safariRegistry.next
	safariRegistry.stacks[h] = s
	return h
}
func (s *safariStack) shutdown() {
	if s.closed.Swap(true) {
		return
	}
	s.cancel()
	s.life.Lock()
	defer s.life.Unlock()
	s.endpoint.Close()
	s.stack.Close()
	s.stack.Wait()
}
func safariCloseStack(h int64) {
	safariRegistry.Lock()
	s := safariRegistry.stacks[h]
	delete(safariRegistry.stacks, h)
	var flows []*safariFlow
	if s != nil {
		for k, f := range safariRegistry.flows {
			if f.owner == s {
				flows = append(flows, f)
				delete(safariRegistry.flows, k)
			}
		}
	}
	safariRegistry.Unlock()
	if s == nil {
		return
	}
	s.cancel()
	for _, f := range flows {
		f.closed.Store(true)
		f.conn.Close()
	}
	s.shutdown()
}
func safariPacketProtocol(p []byte) (tcpip.NetworkProtocolNumber, bool) {
	if len(p) >= 20 && p[0]>>4 == 4 {
		h := int(p[0]&15) * 4
		return ipv4.ProtocolNumber, h >= 20 && h <= len(p) && int(binary.BigEndian.Uint16(p[2:4])) == len(p)
	}
	if len(p) >= 40 && p[0]>>4 == 6 {
		return ipv6.ProtocolNumber, int(binary.BigEndian.Uint16(p[4:6]))+40 == len(p)
	}
	return 0, false
}
func safariEnqueue(h int64, p []byte) int {
	s := safariGetStack(h)
	if s == nil {
		return safariBadHandle
	}
	protocol, ok := safariPacketProtocol(p)
	if !ok {
		return safariArgument
	}
	if len(p) > s.mtu {
		return safariTooLarge
	}
	if protocol == ipv4.ProtocolNumber && !s.v4 || protocol == ipv6.ProtocolNumber && !s.v6 {
		return safariArgument
	}
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed.Load() {
		return safariClosed
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), p...))})
	defer pkt.DecRef()
	s.endpoint.InjectInbound(protocol, pkt)
	return len(p)
}
func safariDequeue(h int64, b []byte, ms int) int {
	s := safariGetStack(h)
	if s == nil {
		return safariBadHandle
	}
	if len(b) < s.mtu {
		return safariTooLarge
	}
	if !safariTimeoutValid(ms) {
		return safariArgument
	}
	ctx, cancel := context.WithTimeout(s.ctx, time.Duration(ms)*time.Millisecond)
	defer cancel()
	p := s.endpoint.ReadContext(ctx)
	if p == nil {
		if s.closed.Load() || s.ctx.Err() != nil {
			return safariClosed
		}
		return safariTimeout
	}
	defer p.DecRef()
	view := p.ToView()
	defer view.Release()
	if view.Size() > len(b) {
		return safariTooLarge
	}
	return copy(b, view.AsSlice())
}
func safariDial(h int64, ip string, port, ms int, datagram bool) int64 {
	s := safariGetStack(h)
	if s == nil {
		return safariBadHandle
	}
	if !safariTimeoutValid(ms) || port < 1 || port > 65535 {
		return safariArgument
	}
	a, e := netip.ParseAddr(ip)
	if e != nil || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() || a.Is4In6() {
		return safariArgument
	}
	if a.Is4() && !s.v4 || a.Is6() && !s.v6 {
		return safariArgument
	}
	protocol := ipv6.ProtocolNumber
	if a.Is4() {
		protocol = ipv4.ProtocolNumber
	}
	target := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.AsSlice()), Port: uint16(port)}
	// Stack.Close and Wait require endpoint creation to have stopped. Close
	// cancels the context before taking the write lock, waking pending dials.
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed.Load() || s.ctx.Err() != nil {
		return safariClosed
	}
	var c net.Conn
	if datagram {
		c, e = gonet.DialUDP(s.stack, nil, &target, protocol)
	} else {
		ctx, cancel := context.WithTimeout(s.ctx, time.Duration(ms)*time.Millisecond)
		defer cancel()
		c, e = gonet.DialContextTCP(ctx, s.stack, target, protocol)
	}
	if e != nil {
		return int64(safariError(e))
	}
	safariRegistry.Lock()
	defer safariRegistry.Unlock()
	if safariRegistry.stacks[h] != s || s.ctx.Err() != nil {
		c.Close()
		return safariClosed
	}
	count := 0
	for _, f := range safariRegistry.flows {
		if f.owner == s {
			count++
		}
	}
	if count >= safariMaxFlows {
		c.Close()
		return safariTooLarge
	}
	safariRegistry.next++
	id := safariRegistry.next
	safariRegistry.flows[id] = &safariFlow{owner: s, conn: c, udp: datagram}
	return id
}
func safariRead(h int64, b []byte, ms int) int {
	f := safariGetFlow(h)
	if f == nil {
		return safariBadHandle
	}
	if len(b) == 0 || !safariTimeoutValid(ms) {
		return safariArgument
	}
	// The API rejects short UDP buffers before consuming a datagram.
	if f.udp && len(b) < 65535 {
		return safariTooLarge
	}
	f.readMu.Lock()
	defer f.readMu.Unlock()
	if e := f.conn.SetReadDeadline(safariDeadline(ms)); e != nil {
		return safariError(e)
	}
	n, e := f.conn.Read(b)
	if n > 0 {
		return n
	}
	if f.closed.Load() {
		return safariClosed
	}
	return safariError(e)
}
func safariWrite(h int64, b []byte, ms int) int {
	f := safariGetFlow(h)
	if f == nil {
		return safariBadHandle
	}
	if !safariTimeoutValid(ms) {
		return safariArgument
	}
	if len(b) > 65535 || f.udp && len(b) > 65507 {
		return safariTooLarge
	}
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	if e := f.conn.SetWriteDeadline(safariDeadline(ms)); e != nil {
		return safariError(e)
	}
	n, e := f.conn.Write(b)
	if n > 0 {
		return n
	}
	return safariError(e)
}
func safariCloseWrite(h int64) int {
	f := safariGetFlow(h)
	if f == nil {
		return safariBadHandle
	}
	if f.udp {
		return safariArgument
	}
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	return safariError(f.conn.(*gonet.TCPConn).CloseWrite())
}
func safariCloseFlow(h int64) {
	safariRegistry.Lock()
	f := safariRegistry.flows[h]
	delete(safariRegistry.flows, h)
	safariRegistry.Unlock()
	if f != nil {
		f.closed.Store(true)
		f.conn.Close()
	}
}
