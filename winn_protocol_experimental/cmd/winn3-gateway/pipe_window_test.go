package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
)

// TestTheProductionInboxHoldsTheReorderTolerance is the cmd/winn3-gateway
// half of the token-window story that netlab never sees.
//
// core.tokenWindow.consume force-advances at size/2, so the reordering a
// DefaultTokenWindow session will still open is size/2 − 1 = 511. That is
// pinned by TestReorderToleranceIsHalfTheWindowMinusOne through driver.Loop
// and tun — but that rig builds its Pipe at Depth 4096.
//
// server.newSession USED TO build the production Pipe with Depth left zero,
// which NewPipe resolves to DefaultPipeDepth (256). A burst of in-window
// datagrams that fits the token window was therefore dropped here, at
// Pipe.Deliver, with ErrQueueFull, before session.Driver.Deliver or
// Session.Open or tokenWindow.holds ever ran. server.readLoop logged that to
// stderr and answered the peer nothing. From the client: silent inner loss,
// the same shape as a censor. Loop.Stats.Unopenable did not move, because the
// datagram never reached Deliver.
//
// Ruling D23 fixed that by giving newSession an explicit
// `Depth: core.DefaultTokenWindow / 2`, DERIVED from the window rather than
// written as 512, so the inbox follows the tolerance if the window ever
// changes. DefaultPipeDepth itself was deliberately left at 256: its
// send-parity rationale is still coherent for its other users, all of which
// are preflight pipes that carry no traffic.
//
// 2026-10-10 (tunnel-speed round 2): the derivation moved from
// core.DefaultTokenWindow/2 (512) to gatewayTokenWindow/4 (8192), the window
// this binary actually configures, after Canada measured the 512 inbox as the
// uplink's loss point (5,884 to 27,237 ErrQueueFull drops per upload run,
// 67 to 86% inside the first two seconds, Q_lo at 93 to 96% of the phone's
// retransmits). The inbox no longer claims to hold the whole reorder
// tolerance of gatewayTokenWindow (16,383): it holds one quarter of the
// window, and a burst beyond it is dropped at the inbox and SURVIVED by the
// window, whose contiguous-loss cliff (16,383) the drop pattern cannot
// reach (a full inbox drops a fraction 1-S/A of arrivals in short runs, not
// one long run). What this test pins now is that the inbox still holds the
// OLD tolerance the ruling was written against (511) plus a wide margin, and
// that the derivation still tracks a token-window constant rather than a
// literal: see pinNewSessionPipeDerivesDepthFromTheTokenWindow.
func TestTheProductionInboxHoldsTheReorderTolerance(t *testing.T) {
	tolerance := core.DefaultTokenWindow/2 - 1
	if tolerance < 1 {
		t.Fatalf("DefaultTokenWindow=%d leaves a non-positive reorder tolerance", core.DefaultTokenWindow)
	}
	depth := (&server{}).pipeInboxDepth()
	if depth < 2*tolerance {
		t.Fatalf("inboxDepth=%d is under twice the old D23 tolerance %d; the "+
			"burst-absorption rationale for this depth is gone, re-audit before "+
			"changing it again", depth, tolerance)
	}

	t.Run("a_shallower_inbox_is_what_this_test_would_catch", func(t *testing.T) {
		p := mustPipe(t, 16)
		defer p.Close()
		msg := []byte("x")
		for i := 0; i < 16; i++ {
			if err := p.Deliver(msg); err != nil {
				t.Fatalf("Deliver %d/16 on a 16-deep inbox: %v", i+1, err)
			}
		}
		err := p.Deliver(msg)
		if !errors.Is(err, carrier.ErrQueueFull) {
			t.Fatalf("a 16-deep inbox accepted a 17th datagram (%v); this test cannot catch a too-small production inbox", err)
		}
	})

	t.Run("newSession_pipe_holds_the_token_window_tolerance", func(t *testing.T) {
		pinNewSessionPipeDerivesDepthFromTheTokenWindow(t)
		p := productionPeerPipe(t)
		defer p.Close()
		msg := []byte("x")
		for i := 0; i < depth; i++ {
			if err := p.Deliver(msg); err != nil {
				t.Fatalf("Deliver %d/%d: %v (newSession Depth=%d DefaultPipeDepth=%d "+
					"DefaultTokenWindow=%d old tolerance=%d). The production inbox must hold the "+
					"burst depth it is configured for. The pin above has already confirmed "+
					"newSession still sets Depth: s.pipeInboxDepth(), one of uplinkInboxDepths, so if this fires "+
					"the cause is in Pipe.Deliver rather than in the configured depth. A burst that the "+
					"token window would still open must not be dropped as ErrQueueFull in "+
					"server.readLoop before session.Driver.Deliver. From the client that is silent "+
					"inner loss, indistinguishable from a censor, and Unopenable does not move.",
					i+1, depth, err, depth, carrier.DefaultPipeDepth,
					core.DefaultTokenWindow, tolerance)
			}
		}
	})
}

// productionPeerPipe is the PipeConfig inside server.newSession, copied
// field-for-field. Depth carries the SAME call the binary uses
// (s.pipeInboxDepth(), whose values are the derived uplinkInboxDepths), not a
// literal 8192 and not a copy of the resulting number:
// pinNewSessionPipeDerivesDepthFromTheTokenWindow fails this file unless the
// two expressions still match, so this replica cannot drift away from the
// binary it claims to measure.
func productionPeerPipe(t *testing.T) *carrier.Pipe {
	t.Helper()
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	p, err := carrier.NewPipe(carrier.PipeConfig{
		Class:          carrier.ClassUDP,
		Out:            func([]byte) error { return nil },
		MaxMessageSize: sizing.MessageSize,
		PathMTU:        sizing.PathMTU,
		Depth:          (&server{}).pipeInboxDepth(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustPipe(t *testing.T, depth int) *carrier.Pipe {
	t.Helper()
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	p, err := carrier.NewPipe(carrier.PipeConfig{
		Class:          carrier.ClassUDP,
		Out:            func([]byte) error { return nil },
		MaxMessageSize: sizing.MessageSize,
		PathMTU:        sizing.PathMTU,
		Depth:          depth,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// pinNewSessionPipeDerivesDepthFromTheTokenWindow keeps productionPeerPipe
// honest. It reads this package's main.go next to this test file (not the
// process cwd — `go test ./cmd/winn3-gateway` is run from the module root)
// and requires that the NewPipe composite literal inside newSession sets
// Depth to the SAME derived expression the replica above uses. A test that
// invented its own Depth would pass while the binary kept dropping.
//
// This pin is INVERTED from the form it shipped in. It used to require that
// the literal had NO Depth field at all — that was how it made ruling D23's
// defect impossible to paper over from the test side, by refusing to let the
// replica quietly widen itself while the binary stayed at
// carrier.DefaultPipeDepth. Now that newSession sets Depth, the same duty
// points the other way: the replica must not drift from the binary, so the
// pin requires the expression instead of its absence. Both directions are the
// one rule "this test measures the binary, not a convenient copy of it".
//
// It matches the EXPRESSION, not the number, and that is deliberate. A
// hardcoded `Depth: 8192` would satisfy any check that only asked whether the
// inbox was big enough today, and would then silently stop tracking the
// window the day gatewayTokenWindow moves, reintroducing exactly this
// defect, in a form no test would catch, which is how it arrived the first
// time.
func pinNewSessionPipeDerivesDepthFromTheTokenWindow(t *testing.T) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate main.go next to this test")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "main.go"))
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	start := bytes.Index(body, []byte("func (s *server) newSession("))
	if start < 0 {
		t.Fatal("main.go no longer contains server.newSession; this test cannot see the production PipeConfig")
	}
	rest := body[start:]
	rel := bytes.Index(rest[1:], []byte("\nfunc "))
	if rel < 0 {
		t.Fatal("could not bound server.newSession")
	}
	fn := rest[:1+rel]
	pipe := bytes.Index(fn, []byte("carrier.NewPipe(carrier.PipeConfig{"))
	if pipe < 0 {
		t.Fatal("server.newSession no longer calls carrier.NewPipe; this test cannot see the production PipeConfig")
	}
	end := bytes.Index(fn[pipe:], []byte("})"))
	if end < 0 {
		t.Fatal("could not bound the NewPipe composite literal in server.newSession")
	}
	lit := litCode(fn[pipe : pipe+end])
	if !bytes.Contains(lit, []byte("Depth:")) {
		t.Fatal("server.newSession no longer sets PipeConfig.Depth, so NewPipe resolves the " +
			"production inbox back to carrier.DefaultPipeDepth (256) while the session's reorder " +
			"tolerance is gatewayTokenWindow/2 - 1 (16,383). That is ruling D23's defect: a burst " +
			"displacing 257-16,383 packets is dropped as ErrQueueFull in readLoop before " +
			"session.Driver.Deliver, which is silent inner loss after decryption, on a tunnel whose " +
			"status reads healthy and whose Unopenable never moves. Restore " +
			"Depth: s.pipeInboxDepth(), whose values derive from gatewayTokenWindow")
	}
	// The trailing comma is part of the match on purpose: without it this would
	// also accept `gatewayTokenWindow / 40` or `/ 4096`. gofmt puts a comma
	// on every field of a multi-line composite literal, so requiring it costs
	// nothing and closes a substring hole.
	// Since 2026-10-10 the depth is -uplink-inbox-depth (owner ruling): the
	// literal must call s.pipeInboxDepth(), and every value that can return
	// must still be a derivation of the token window, which the two
	// declarations below carry.
	if !bytes.Contains(stripSpace(lit), []byte("Depth:s.pipeInboxDepth(),")) ||
		!bytes.Contains(litCode(body), []byte("const inboxDepth = gatewayTokenWindow / 4\n")) ||
		!bytes.Contains(litCode(body), []byte("var uplinkInboxDepths = [...]int{inboxDepth / 4, inboxDepth / 2, inboxDepth}\n")) ||
		!bytes.Contains(litCode(body), []byte("var defaultUplinkInboxDepth = inboxDepth\n")) {
		t.Fatalf("server.newSession sets PipeConfig.Depth to something other than "+
			"s.pipeInboxDepth() over uplinkInboxDepths derived from gatewayTokenWindow / 4, so productionPeerPipe in this file is measuring a replica "+
			"rather than the binary. Note that a hardcoded depth is refused ON PURPOSE even when the "+
			"number is currently right: the inbox must be DERIVED from a token-window constant so that it "+
			"follows a change to the window. The literal now reads:\n%s", lit)
	}
}

// litCode strips line comments from a composite literal so the pins above
// match code rather than prose. Two reasons, and the second is the load-bearing
// one: newSession's Depth field carries a long rationale comment that would
// otherwise be part of the matched text, and — worse — a commented-out
// `// Depth: core.DefaultTokenWindow / 2` would satisfy the pin while the
// binary shipped no Depth at all.
//
// It cuts at the first `//` on each line, which is exact for this literal
// because nothing in it puts `//` inside a string. If that ever stops being
// true, this must become a go/ast walk rather than grow special cases.
func litCode(lit []byte) []byte {
	lines := bytes.Split(lit, []byte("\n"))
	for i, ln := range lines {
		if c := bytes.Index(ln, []byte("//")); c >= 0 {
			lines[i] = ln[:c]
		}
	}
	return bytes.Join(lines, []byte("\n"))
}

// stripSpace removes Go's source whitespace, so a textual pin on an expression
// is not also an unintended pin on gofmt's spacing decisions.
func stripSpace(b []byte) []byte {
	return bytes.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, b)
}
