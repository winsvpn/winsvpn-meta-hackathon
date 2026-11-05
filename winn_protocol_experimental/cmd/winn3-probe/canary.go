package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// replaySilenceWait is how long the other-source replay socket waits for a
// handshake reply. cmd/winn3-gateway's TestACapturedInitiationReplayedFromASecondAddressIsSilent
// uses 2s same-source / 3s other-source. A reply here is a gateway detector.
const replaySilenceWait = 3 * time.Second

// canaryRekeyWait is how long the volume ratchet may take after inner packets
// have been queued. The exchange is two frames (RekeyInit/RekeyAck) on a
// loopback socket; the budget exists for a loaded machine, not for the
// 5-45 minute time trigger.
const canaryRekeyWait = 30 * time.Second

// capturingConn records the first Send so a canary can replay that exact
// initiation from a second UDP source. Handshake retransmission re-sends the
// same bytes, so the first capture is the transcript the responder cached.
type capturingConn struct {
	carrier.Conn
	mu    sync.Mutex
	first []byte
}

func (c *capturingConn) Send(ctx context.Context, msg []byte) error {
	c.mu.Lock()
	if len(c.first) == 0 && len(msg) > 0 {
		c.first = append([]byte(nil), msg...)
	}
	c.mu.Unlock()
	return c.Conn.Send(ctx, msg)
}

func (c *capturingConn) First() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.first...)
}

type canaryRun struct {
	loop     *driver.Loop
	dev      *memDevice
	captured *capturingConn
	parsed   probeParsed
	opts     probeOptions
	runErrCh <-chan error
	replies  <-chan []byte
}

func runCanary(ctx context.Context, c canaryRun) error {
	initiation := c.captured.First()
	if len(initiation) == 0 {
		return fmt.Errorf("canary: handshake reached carrying but captured no initiation bytes; the wrapping carrier never saw Send")
	}
	fmt.Printf("v3probe: captured initiation %d bytes for replay\n", len(initiation))

	answered, n, err := replayInitiationFromOtherSource(c.parsed.gwAddr, initiation)
	if err != nil {
		return fmt.Errorf("canary replay (other-source): %w", err)
	}
	if answered {
		return fmt.Errorf(
			"canary REPLAY FAIL: a captured initiation replayed from a second UDP source was answered with %d bytes. "+
				"A v3 gateway must stay silent; a reply is a remote test for whether a Winn3 gateway is at this address. "+
				"cmd/winn3-gateway shares one handshake responder across peer addresses so this cache is process-wide",
			n)
	}
	fmt.Printf("v3probe: REPLAY other-source silent=true initiation_bytes=%d wait=%s\n", len(initiation), replaySilenceWait)

	if st := c.loop.Tunnel().Gate().State(); st != tun.StateCarrying {
		return fmt.Errorf("canary: gate left carrying after the replay probe (state %v)", st)
	}

	reflectTo := c.parsed.reflectAddr
	id := uint16(time.Now().UnixNano() & 0xffff)
	payload := []byte("winn3-canary-reflect-20260818")
	burst := c.opts.count
	needForRekey := int(c.parsed.rekeyAfter) + 16
	if needForRekey > burst {
		burst = needForRekey
	}

	var sent, got, unmatched int
	var outstanding [][]byte
	epochBefore := c.loop.Session().Epoch()
	fmt.Printf("v3probe: canary sending %d inner packets to reflector %s (rekey-after=%d epoch=%d)\n",
		burst, reflectTo, c.parsed.rekeyAfter, epochBefore)

	for i := 0; i < burst; i++ {
		select {
		case err := <-c.runErrCh:
			return unexpectedSessionEnd(err)
		default:
		}
		pkt := icmpEcho(c.parsed.srcAddr, reflectTo, id, uint16(i+1), payload)
		select {
		case err := <-c.runErrCh:
			return unexpectedSessionEnd(err)
		case c.dev.in <- pkt:
			sent++
			outstanding = append(outstanding, append([]byte(nil), pkt...))
			fmt.Printf("v3probe: SENT  %s\n", describe(pkt))
		case <-time.After(5 * time.Second):
			return fmt.Errorf("canary: the device would not accept outbound packet %d", i+1)
		}
		got, unmatched, outstanding = drainReplies(c.replies, outstanding, false, reflectTo, got, unmatched)
		if i < burst-1 {
			time.Sleep(c.opts.interval)
		}
	}

	waitUntil := time.Now().Add(c.opts.budget)
	rekeyDeadline := time.Now().Add(canaryRekeyWait)
	if rekeyDeadline.Before(waitUntil) {
		// Keep waiting for reflects until budget, and for rekey until the
		// longer of the two. A rekey that needs the full canaryRekeyWait
		// must not be cut short by a short -budget.
		_ = waitUntil
	}
	deadline := waitUntil
	if rekeyDeadline.After(deadline) {
		deadline = rekeyDeadline
	}

	rekeyOK := false
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return fmt.Errorf("canary cancelled: %w", ctx.Err())
		case err := <-c.runErrCh:
			if got == 0 {
				return finishWithNoMatch(unmatched, false, true, sent, int(c.loop.Tunnel().Stats().TxDroppedInvalid), c.opts.budget, err)
			}
			return fmt.Errorf("canary: session ended mid-canary after received=%d: %w", got, unexpectedSessionEnd(err))
		case r := <-c.replies:
			got, unmatched, outstanding = noteReply(r, outstanding, false, reflectTo, got, unmatched)
		case <-time.After(50 * time.Millisecond):
		}
		if !rekeyOK && canaryRekeyConverged(c.loop, epochBefore) {
			rekeyOK = true
			fmt.Printf("v3probe: REKEY ok rekeys=%d epoch=%d session=%s gate=%s\n",
				c.loop.Session().Stats().Rekeys, c.loop.Session().Epoch(),
				c.loop.Session().State(), c.loop.Tunnel().Gate().State())
		}
		if got >= sent && rekeyOK {
			break
		}
	}

	if got == 0 {
		fmt.Println("v3probe: VERDICT canary handshake=ok replay-safe=ok reflect=FAIL rekey=unproven")
		return finishWithNoMatch(unmatched, false, true, sent, int(c.loop.Tunnel().Stats().TxDroppedInvalid), c.opts.budget, nil)
	}
	if !rekeyOK {
		return fmt.Errorf(
			"canary REKEY FAIL: after %d inner packets Rekeys=%d epoch=%d (was %d) session=%s gate=%s; "+
				"wanted Rekeys>=1, StateEstablished, gate carrying, epoch advanced. reflect received=%d unmatched=%d",
			sent, c.loop.Session().Stats().Rekeys, c.loop.Session().Epoch(), epochBefore,
			c.loop.Session().State(), c.loop.Tunnel().Gate().State(), got, unmatched)
	}

	// Traffic across the new epoch: one more inner packet after the ratchet
	// has settled, so a rekey that advanced counters but stopped carrying
	// cannot print a green VERDICT.
	if st := c.loop.Tunnel().Gate().State(); st != tun.StateCarrying {
		return fmt.Errorf("canary: gate is %s after rekey, want carrying", st)
	}
	post := icmpEcho(c.parsed.srcAddr, reflectTo, id, uint16(burst+1), []byte("winn3-canary-post-rekey"))
	select {
	case err := <-c.runErrCh:
		return unexpectedSessionEnd(err)
	case c.dev.in <- post:
		sent++
		// Only this packet's reflection proves carrying after the ratchet; a
		// late reflection of an earlier burst packet must not satisfy it.
		outstanding = [][]byte{append([]byte(nil), post...)}
		fmt.Printf("v3probe: SENT  %s\n", describe(post))
	case <-time.After(5 * time.Second):
		return fmt.Errorf("canary: the device would not accept the post-rekey packet")
	}
	postDeadline := time.Now().Add(c.opts.budget)
	postGot := got
	for time.Now().Before(postDeadline) && got == postGot {
		select {
		case err := <-c.runErrCh:
			return unexpectedSessionEnd(err)
		case r := <-c.replies:
			got, unmatched, outstanding = noteReply(r, outstanding, false, reflectTo, got, unmatched)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if got == postGot {
		return fmt.Errorf(
			"canary REKEY FAIL: rekey counters advanced but no reflected packet came back after the ratchet (received stayed %d)",
			got)
	}

	st := c.loop.Tunnel().Stats()
	fmt.Printf("v3probe: sent=%d received=%d unmatched=%d\n", sent, got, unmatched)
	fmt.Printf("v3probe: tunnel stats tx=%d rx=%d rx_dropped_invalid=%d tx_dropped_invalid=%d\n",
		st.TxPackets, st.RxPackets, st.RxDroppedInvalid, st.TxDroppedInvalid)
	dualTok := "dual-auth=off"
	if c.loop.Session().DualAuthVerified() {
		dualTok = "dual-auth=ok"
	}
	fmt.Printf("v3probe: VERDICT canary handshake=ok replay-safe=ok rekey=ok reflect=ok %s epoch=%d rekeys=%d\n",
		dualTok, c.loop.Session().Epoch(), c.loop.Session().Stats().Rekeys)
	return nil
}

func canaryRekeyConverged(loop *driver.Loop, epochBefore uint32) bool {
	sess := loop.Session()
	return sess.Stats().Rekeys > 0 &&
		sess.State() == session.StateEstablished &&
		loop.Tunnel().Gate().State() == tun.StateCarrying &&
		sess.Epoch() > epochBefore
}

// replayInitiationFromOtherSource writes a captured initiation from a fresh
// UDP source and reports whether the gateway answered. Silence (timeout) is
// the pass. A reply is the detector the cover/ECH design exists to deny.
func replayInitiationFromOtherSource(gw *net.UDPAddr, initiation []byte) (answered bool, n int, err error) {
	src, err := net.DialUDP("udp4", nil, gw)
	if err != nil {
		return false, 0, err
	}
	defer func() { _ = src.Close() }()
	if _, err := src.Write(initiation); err != nil {
		return false, 0, err
	}
	_ = src.SetReadDeadline(time.Now().Add(replaySilenceWait))
	buf := make([]byte, 65535)
	n, err = src.Read(buf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return false, 0, nil
		}
		return false, 0, err
	}
	return n > 0, n, nil
}
