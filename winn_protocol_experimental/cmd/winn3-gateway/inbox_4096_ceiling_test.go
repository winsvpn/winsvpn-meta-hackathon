package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// The Spain UDP death delivered exactly 4096 datagrams (seq 0–4095) then tore
// the session down. Ruling D23 sized the production Pipe inbox at
// DefaultTokenWindow/2 so it tracks reorder tolerance. This file re-audits
// that derivation for a 4096 ceiling: a silent cap, a hardcoded 4096, or
// another receive-path buffer of 4096 that would become the new D23-shaped
// bottleneck. A full inbox returns ErrQueueFull and does not terminate a
// session (winn3/driver.TestAFullPeerInboxDropsAMessageTheTunLayerAlreadyCountedAsSent); these
// tests therefore ask whether a 4096 bound exists, not whether it would
// reproduce the Spain teardown by itself.

func TestProductionInboxDepthIsNot4096(t *testing.T) {
	pinNewSessionPipeDerivesDepthFromTheTokenWindow(t)

	window := core.DefaultTokenWindow
	tolerance := window/2 - 1
	if window != 1024 {
		t.Fatalf("DefaultTokenWindow=%d, want 1024; the shipping reorder cliff is window/2-1", window)
	}
	if tolerance != 511 {
		t.Fatalf("reorder tolerance = %d, want 511", tolerance)
	}
	// Moved 2026-10-10 (tunnel-speed round 2): the production inbox derives
	// from the window the GATEWAY configures, gatewayTokenWindow/4, not from
	// DefaultTokenWindow. Canada measured the 512 inbox as the uplink's loss
	// point (5,884 to 27,237 ErrQueueFull drops per upload run, 67 to 86%
	// inside the first two seconds, while the busiest consumer thread sat at
	// 0.29 to 0.31 cores); 8192 absorbs 51 ms at the 1.8 Gbit/s target rate
	// and keeps the contiguous-loss run far under the recent-loss cliff
	// gatewayTokenWindow/2-1 = 16,383 (a full inbox drops short runs, a
	// fraction 1-S/A of arrivals, never one long run).
	if inboxDepth != gatewayTokenWindow/4 {
		t.Fatalf("production inbox Depth = %d, want gatewayTokenWindow/4 = %d",
			inboxDepth, gatewayTokenWindow/4)
	}
	if gatewayTokenWindow != 32768 {
		t.Fatalf("gatewayTokenWindow=%d, want 32768; the inbox derivation and the "+
			"cliff arithmetic above are stated against this value", gatewayTokenWindow)
	}
	if inboxDepth == 4096 {
		t.Fatalf("production inbox Depth is 4096. That is the Spain UDP cutoff. " +
			"The inbox must stay derived from the token window; landing on the " +
			"observed death count needs a deliberate review, not an accident.")
	}
}

func TestNewPipeHasNo4096Ceiling(t *testing.T) {
	msg := []byte("x")

	t.Run("depth_4097_accepts_4097_and_rejects_the_next", func(t *testing.T) {
		p := mustPipe(t, 4097)
		defer p.Close()
		for i := 0; i < 4097; i++ {
			if err := p.Deliver(msg); err != nil {
				t.Fatalf("Deliver %d/4097: %v; NewPipe clamped or dropped before 4097, "+
					"which is a 4096-shaped ceiling on inbox depth", i+1, err)
			}
		}
		err := p.Deliver(msg)
		if !errors.Is(err, carrier.ErrQueueFull) {
			t.Fatalf("a 4097-deep inbox accepted a 4098th datagram (%v); this test cannot see a ceiling", err)
		}
	})

	t.Run("depth_4096_is_exactly_4096_not_a_hidden_larger_queue", func(t *testing.T) {
		p := mustPipe(t, 4096)
		defer p.Close()
		for i := 0; i < 4096; i++ {
			if err := p.Deliver(msg); err != nil {
				t.Fatalf("Deliver %d/4096: %v", i+1, err)
			}
		}
		err := p.Deliver(msg)
		if !errors.Is(err, carrier.ErrQueueFull) {
			t.Fatalf("a 4096-deep inbox accepted a 4097th datagram (%v)", err)
		}
	})
}

func TestReceivePathInboxesOnTunResolverForwardAreNot4096(t *testing.T) {
	if resolverInboxDepth != 256 {
		t.Fatalf("resolverInboxDepth=%d, want 256", resolverInboxDepth)
	}
	if reflectorDepth != 256 {
		t.Fatalf("reflectorDepth=%d, want 256", reflectorDepth)
	}
	if resolverInboxDepth == 4096 || reflectorDepth == 4096 {
		t.Fatal("a 4096-deep resolver or reflector inbox is the Spain packet count as a queue bound")
	}
	if tun.MaxIPPacket != 65535 {
		t.Fatalf("tun.MaxIPPacket=%d, want 65535 (a byte buffer, not a 4096-packet queue)", tun.MaxIPPacket)
	}

	// D23-class remainder: these inboxes are still narrower than the
	// advertised reorder tolerance of 511. They drop rather than block, so
	// they cannot by themselves tear a session down. They CAN silently lose
	// DNS replies (resolver) or reflected packets (non-forward) on a burst
	// the token window would still open. Spain's death was -forward UDP to a
	// high port, which does not queue through either of these.
	tolerance := core.DefaultTokenWindow/2 - 1
	if resolverInboxDepth >= tolerance {
		t.Fatalf("resolverInboxDepth=%d is no longer shallower than reorder tolerance %d; update this remainder note", resolverInboxDepth, tolerance)
	}
	if reflectorDepth >= tolerance {
		t.Fatalf("reflectorDepth=%d is no longer shallower than reorder tolerance %d; update this remainder note", reflectorDepth, tolerance)
	}
}

func TestNewPipeSourceHasNo4096DepthClamp(t *testing.T) {
	body := readCarrierPipeGo(t)
	fn := newPipeFuncBody(t, body)
	if bytes.Contains(fn, []byte("4096")) {
		t.Fatalf("winn3/carrier.NewPipe now mentions 4096:\n%s", fn)
	}
	if bytes.Contains(fn, []byte("1<<12")) || bytes.Contains(fn, []byte("1 << 12")) {
		t.Fatalf("winn3/carrier.NewPipe now mentions 1<<12:\n%s", fn)
	}
}

func TestForwardDeviceHasNoPacketInbox(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "forward.go"))
	if err != nil {
		t.Fatalf("reading forward.go: %v", err)
	}
	if bytes.Contains(body, []byte("make(chan []byte, 4096)")) {
		t.Fatal("forward.go now has a 4096-deep []byte channel")
	}
	// The forward device's read side is idle by design (return path is
	// sharedGatewayTun.run → Loop.SendInner). A packet inbox here would be a
	// new receive-path bound. Pin the absence of any buffered []byte channel.
	if bytes.Contains(body, []byte("make(chan []byte,")) {
		t.Fatal("forward.go now has a buffered []byte channel; the forward receive path was unbuffered")
	}
}

func readCarrierPipeGo(t *testing.T) []byte {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "winn3", "carrier", "pipe.go")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading pipe.go: %v", err)
	}
	return body
}

func newPipeFuncBody(t *testing.T, body []byte) []byte {
	t.Helper()
	start := bytes.Index(body, []byte("func NewPipe(cfg PipeConfig)"))
	if start < 0 {
		t.Fatal("pipe.go no longer contains NewPipe")
	}
	rest := body[start:]
	rel := bytes.Index(rest[1:], []byte("\nfunc "))
	if rel < 0 {
		t.Fatal("could not bound NewPipe")
	}
	return rest[:1+rel]
}

func TestDefaultPipeDepthIsStillSendParityNot4096(t *testing.T) {
	if carrier.DefaultPipeDepth != 256 {
		t.Fatalf("DefaultPipeDepth=%d, want 256 (send-queue parity, not a 4096 ceiling)", carrier.DefaultPipeDepth)
	}
	if strings.Contains(string(readCarrierPipeGo(t)), "DefaultPipeDepth = 4096") {
		t.Fatal("DefaultPipeDepth was raised to 4096")
	}
}
