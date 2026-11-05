package main

import (
	"context"
	"net"
	"net/netip"
	"time"
)

func (s *server) tcpLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case accepted := <-s.tcp.accepted:
			if ctx.Err() != nil {
				retireUnowned(accepted.driver)
				_ = accepted.stream.Close()
				return
			}
			s.admitTCP(ctx, accepted)
		}
	}
}

func (s *server) admitTCP(ctx context.Context, accepted *tcpAccepted) {
	s.mu.Lock()
	full := s.totalSlotsLocked() >= s.maxSessions
	s.mu.Unlock()
	if full && !s.reclaimSlot(time.Now()) {
		accepted.fallback()
		return
	}
	s.mu.Lock()
	if s.totalSlotsLocked() >= s.maxSessions {
		s.mu.Unlock()
		accepted.fallback()
		return
	}
	s.building++
	s.mu.Unlock()
	var remote netip.AddrPort
	if tcp, ok := accepted.remote.(*net.TCPAddr); ok {
		remote = tcp.AddrPort()
	}
	ps := &peerSession{remote: remote, done: make(chan struct{}), admittedAt: time.Now()}
	ps, err := s.startPeerSession(ctx, ps, accepted.stream, accepted.driver)
	if s.afterTCPStart != nil {
		s.afterTCPStart(ps, err)
	}
	s.mu.Lock()
	s.building--
	if err == nil && !ps.tcpReleased {
		select {
		case <-ps.done:
		default:
			if s.tcpPeers == nil {
				s.tcpPeers = make(map[*peerSession]struct{})
			}
			s.tcpPeers[ps] = struct{}{}
			s.admitted.Add(1)
		}
	}
	s.mu.Unlock()
	if err != nil {
		accepted.fallback()
	}
}

func (s *server) releaseTCPPeer(ps *peerSession) {
	ps.releaseOnce.Do(func() {
		s.mu.Lock()
		ps.tcpReleased = true
		delete(s.tcpPeers, ps)
		s.mu.Unlock()
		if s.holdTCPRelease != nil {
			s.holdTCPRelease()
		}
		ps.stop()
		_ = ps.loop.Close()
		_ = ps.conn.Close()
		_ = ps.dev.Close()
		s.mu.Lock()
		delete(s.retiring, ps)
		s.mu.Unlock()
	})
}
