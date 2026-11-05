//go:build darwin

package main

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
)

// Round A2 v3 on the C ABI: a status request that straddles the end of a live,
// proven round must not regress to connecting or publish that round's
// evidence as current. The same two windows as the frame host's
// winn3_frame_transition_test.go, forced with the package's test hooks.

type appleTransition struct {
	tunnel   *winn3Tunnel
	gw       *recoveryGateway
	provenRx float64

	armed    atomic.Bool
	onStatus func()

	holdRoundEnd bool
	roundEnded   chan struct{}
	release      chan struct{}
	roundOnce    sync.Once
}

func newAppleTransition(t *testing.T, holdRoundEnd bool) *appleTransition {
	t.Helper()
	a := &appleTransition{
		holdRoundEnd: holdRoundEnd,
		roundEnded:   make(chan struct{}),
		release:      make(chan struct{}),
	}
	// Installed before the tunnel exists, so before any goroutine reads them.
	winn3TestHookAfterSnapshot = func() {
		if a.armed.CompareAndSwap(true, false) {
			a.onStatus()
		}
	}
	winn3TestHookRoundEnd = func() {
		if !a.holdRoundEnd {
			return
		}
		a.roundOnce.Do(func() {
			close(a.roundEnded)
			<-a.release
		})
	}
	t.Cleanup(func() {
		select {
		case <-a.release:
		default:
			close(a.release)
		}
		if a.tunnel != nil {
			_ = a.tunnel.close()
		}
		winn3TestHookAfterSnapshot = nil
		winn3TestHookRoundEnd = nil
	})

	gwStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	cliStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	gwSock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback socket: %v", err)
	}
	t.Cleanup(func() { _ = gwSock.Close() })
	local, err := net.DialUDP("udp4", nil, gwSock.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	clientAddr := local.LocalAddr().(*net.UDPAddr)
	file, err := local.File()
	if err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	_ = local.Close()

	doc := baseConfig(t)
	doc["static_private"] = base64.StdEncoding.EncodeToString(cliStatic.Bytes())
	doc["gateway_static"] = base64.StdEncoding.EncodeToString(gwStatic.Public())
	doc["gateway_endpoint"] = gwSock.LocalAddr().String()
	a.tunnel, err = openWinn3(encode(t, doc), fd)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cfg, err := decodeWinn3Config(encode(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	admission, err := admissionProfile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	loop, _, _ := a.tunnel.round()
	a.gw = &recoveryGateway{
		t: t, sock: gwSock, client: clientAddr, sizing: loop.Sizing(),
		cfg: func() session.Config {
			return session.Config{
				Core:    core.Config{Gateway: admission.Gateway},
				Static:  gwStatic,
				Accept:  func([]byte) error { return nil },
				Padding: core.PadBucket,
			}
		},
	}
	a.gw.start()
	t.Cleanup(func() { _ = a.gw.loop.Close() })

	carryUp(t, a.tunnel, a.gw, recoveryPacket("10.13.0.2", "10.13.0.1", "up"))
	carryDown(t, a.tunnel, a.gw, recoveryPacket("10.13.0.1", "10.13.0.2", "down"))
	st := recoveryStatus(t, a.tunnel)
	if st["winn3_lifecycle"] != driver.LifecycleConnected || st["winn3_may_carry"] != true || st["winn3_rx_packets"] == float64(0) {
		t.Fatalf("round one is not live and proven: %v", st)
	}
	a.provenRx = st["winn3_rx_packets"].(float64)
	return a
}

func (a *appleTransition) straddle(t *testing.T, onStatus func()) map[string]any {
	t.Helper()
	a.onStatus = onStatus
	a.armed.Store(true)
	var st map[string]any
	if err := json.Unmarshal([]byte(a.tunnel.statusJSON()), &st); err != nil {
		t.Fatal(err)
	}
	if a.armed.Load() {
		t.Fatal("the status hook never ran; the window was not forced")
	}
	return st
}

func (a *appleTransition) requireRecovering(t *testing.T, st map[string]any) {
	t.Helper()
	if st["winn3_lifecycle"] != driver.LifecycleRecovering {
		t.Errorf("lifecycle %v, want %q: a proven tunnel that lost its round regressed", st["winn3_lifecycle"], driver.LifecycleRecovering)
	}
	if st["winn3_may_carry"] != false || st["winn3_gate_state"] == "carrying" {
		t.Errorf("may_carry %v gate %v while no round is proven", st["winn3_may_carry"], st["winn3_gate_state"])
	}
	for _, key := range []string{"winn3_rx_packets", "winn3_rx_offered", "winn3_tx_packets", "winn3_messages_received", "winn3_messages_sent"} {
		if st[key] != float64(0) {
			t.Errorf("%s = %v; round one's evidence (rx_packets was %v) published as current", key, st[key], a.provenRx)
		}
	}
}

func TestAnAppleStatusStraddlingASuccessorPublicationStaysRecovering(t *testing.T) {
	a := newAppleTransition(t, false)
	st := a.straddle(t, func() {
		a.gw.end()
		a.gw.start()
		deadline := time.Now().Add(30 * time.Second)
		for a.tunnel.rounds.Load() < 2 {
			if time.Now().After(deadline) {
				t.Error("no successor was published inside the window")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	})
	a.requireRecovering(t, st)
	a.requireRecovering(t, recoveryStatus(t, a.tunnel))
}

func TestAnAppleStatusStraddlingALatchedGateStaysRecovering(t *testing.T) {
	a := newAppleTransition(t, true)
	st := a.straddle(t, func() {
		a.gw.end()
		select {
		case <-a.roundEnded:
		case <-time.After(30 * time.Second):
			t.Error("round one's loop did not end")
		}
	})
	if a.tunnel.recovering.Load() {
		t.Fatal("the wrapper recorded the round's end inside the window; it was not held")
	}
	a.requireRecovering(t, st)
	close(a.release)
	a.gw.start()
	deadline := time.Now().Add(30 * time.Second)
	for a.tunnel.rounds.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("no successor")
		}
		time.Sleep(5 * time.Millisecond)
	}
	a.requireRecovering(t, recoveryStatus(t, a.tunnel))
}
