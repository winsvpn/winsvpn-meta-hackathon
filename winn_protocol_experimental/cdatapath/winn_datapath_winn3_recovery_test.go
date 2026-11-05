//go:build darwin

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// In-engine recovery across the C ABI. Loopback only: the gateway is a driver
// loop in this process on a 127.0.0.1 socket.

// recoveryGateway is the test's gateway: one socket, and one loop per round on
// a carrier wrapper that borrows it.
type recoveryGateway struct {
	t      *testing.T
	sock   *net.UDPConn
	client *net.UDPAddr
	sizing driver.Sizing
	cfg    func() session.Config

	loop *driver.Loop
	dev  *abiDevice
	done chan error
}

func (g *recoveryGateway) start() {
	g.t.Helper()
	car, err := carrier.NewUDP(carrier.UDPConfig{
		Conn: g.sock, Peer: g.client, OwnsConn: false,
		MaxMessageSize: g.sizing.MessageSize, PathMTU: g.sizing.PathMTU,
	})
	if err != nil {
		g.t.Fatal(err)
	}
	g.dev = newABIDevice(g.sizing.InnerMTU)
	g.loop, err = driver.NewGateway(driver.Config{
		Session: g.cfg(),
		Sizing:  g.sizing,
		Carrier: car,
		Tun: &tun.Config{
			Assign: tun.Assignment{
				V4:       netip.MustParseAddr("10.13.0.1"),
				RouterV4: netip.MustParseAddr("10.13.0.2"),
			},
			Device: g.dev,
		},
	})
	if err != nil {
		g.t.Fatal(err)
	}
	g.done = make(chan error, 1)
	loop, dev := g.loop, g.dev
	go func() {
		err := loop.Run(context.Background())
		dev.close()
		_ = car.Close()
		g.done <- err
	}()
}

// end closes this round's session with a CLOSE, which is the client's round
// dying, and waits for it.
func (g *recoveryGateway) end() {
	g.t.Helper()
	_ = g.loop.Close()
	select {
	case <-g.done:
	case <-time.After(10 * time.Second):
		g.t.Fatal("the gateway round did not end")
	}
}

func recoveryPacket(src, dst string, payload string) []byte {
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	p := make([]byte, 20+len(payload))
	p[0] = 0x45
	p[2], p[3] = byte(len(p)>>8), byte(len(p))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(p[i])<<8 | uint32(p[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	c := ^uint16(sum)
	p[10], p[11] = byte(c>>8), byte(c)
	copy(p[20:], payload)
	return p
}

// carryUp offers a packet at the client host until the gateway's device has it.
func carryUp(t *testing.T, tunnel *winn3Tunnel, g *recoveryGateway, packet []byte) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		if n := tunnel.writeInbound(packet); int(n) != len(packet) {
			t.Fatalf("the client host write returned %d", n)
		}
		if _, err := g.dev.take(buf, 300*time.Millisecond); err == nil {
			return
		}
	}
	t.Fatal("nothing reached the gateway")
}

// carryDown offers a packet at the gateway until the client host reads it.
func carryDown(t *testing.T, tunnel *winn3Tunnel, g *recoveryGateway, packet []byte) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		if _, err := g.dev.offer(packet); err != nil {
			t.Fatal(err)
		}
		n, err := tunnel.take(buf, 300)
		if err == nil && n > 0 {
			return
		}
		if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("the client host read failed: %v", err)
		}
	}
	t.Fatal("nothing reached the client host")
}

func recoveryStatus(t *testing.T, tunnel *winn3Tunnel) map[string]any {
	t.Helper()
	var st map[string]any
	if err := json.Unmarshal([]byte(tunnel.statusJSON()), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// TestAnAppleTunnelRecoversInsideTheEngineOnTheSameSocket is the frame host's
// recovery property on the C ABI: the gateway ends round one, a host read
// parked across the recovery is carried over to round two instead of being
// told the tunnel closed, status reflects round two only, the socket stays the
// one the host handed over, and close ends everything and closes it once.
func TestAnAppleTunnelRecoversInsideTheEngineOnTheSameSocket(t *testing.T) {
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
	defer gwSock.Close()
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
	tunnel, err := openWinn3(encode(t, doc), fd)
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
	gw := &recoveryGateway{
		t: t, sock: gwSock, client: clientAddr, sizing: tunnel.loop.Sizing(),
		cfg: func() session.Config {
			return session.Config{
				Core:    core.Config{Gateway: admission.Gateway},
				Static:  gwStatic,
				Accept:  func([]byte) error { return nil },
				Padding: core.PadBucket,
			}
		},
	}
	gw.start()

	up := recoveryPacket("10.13.0.2", "10.13.0.1", "round one up")
	down := recoveryPacket("10.13.0.1", "10.13.0.2", "round one down")
	carryUp(t, tunnel, gw, up)
	carryDown(t, tunnel, gw, down)
	if st := recoveryStatus(t, tunnel); st["winn3_rx_packets"] == float64(0) || st["winn3_lifecycle"] != driver.LifecycleConnected {
		t.Fatalf("round one never delivered, or did and is not connected: %v", st)
	}
	firstLoop, firstDev, _ := tunnel.round()

	// A host read parked across the whole recovery. It must come back with a
	// round-two packet, never with the closed code.
	parked := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := tunnel.take(buf, 60_000)
			if err != nil {
				parked <- err
				return
			}
			if n > 0 && string(buf[20:n]) == "round two down" {
				parked <- nil
				return
			}
		}
	}()

	gw.end()
	gw.start()

	// Sample the status inside the recovery window, which is at least the
	// retirement plus a first-window backoff draw. A sample counts only if the
	// window was still open after it was taken.
	sampled := false
	waitRound := time.Now().Add(30 * time.Second)
	for tunnel.rounds.Load() < 2 {
		if time.Now().After(waitRound) {
			t.Fatal("no second round")
		}
		if !sampled && tunnel.recovering.Load() {
			st := recoveryStatus(t, tunnel)
			if tunnel.recovering.Load() && tunnel.rounds.Load() == 1 {
				sampled = true
				if st["winn3_rx_packets"] != float64(0) || st["winn3_messages_received"] != float64(0) ||
					st["winn3_gate_state"] != tun.StateClosed.String() ||
					st["winn3_lifecycle"] != driver.LifecycleRecovering {
					t.Fatalf("status during recovery describes the dead round: %v", st)
				}
			}
		}
	}
	if !sampled {
		t.Log("the recovery window closed before a status sample; the in-window check did not run")
	}
	secondLoop, secondDev, _ := tunnel.round()
	if secondLoop == firstLoop || secondDev == firstDev {
		t.Fatal("round two reuses round one's loop or device")
	}
	if !firstDev.isClosed() || !firstDev.readMu.TryLock() {
		t.Fatal("round one's device was not retired before round two was published")
	}
	firstDev.readMu.Unlock()
	if st := recoveryStatus(t, tunnel); st["winn3_rx_packets"] != float64(0) || st["winn3_runtime_completed"] != false {
		t.Fatalf("status after recovery still describes round one: %v", st)
	}

	// Host writes during and after recovery never read as a closed tunnel.
	for range 32 {
		if n := tunnel.writeInbound(up); n == errClosed {
			t.Fatal("a host write after recovery was told the tunnel is closed")
		}
	}
	carryUp(t, tunnel, gw, recoveryPacket("10.13.0.2", "10.13.0.1", "round two up"))
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := gw.dev.offer(recoveryPacket("10.13.0.1", "10.13.0.2", "round two down")); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-parked:
			if err != nil {
				t.Fatalf("a host read parked across recovery returned %v", err)
			}
		case <-time.After(300 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatal("the parked host read never received round two's packet")
			}
			continue
		}
		break
	}
	if st := recoveryStatus(t, tunnel); st["winn3_rx_packets"] == float64(0) || st["winn3_lifecycle"] != driver.LifecycleConnected {
		t.Fatalf("round two's delivery is not in the status, or it is not connected: %v", st)
	}
	if tunnel.socketCloses.Load() != 0 {
		t.Fatal("the socket was closed during recovery")
	}

	if err := tunnel.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-tunnel.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the supervisor did not finish after close")
	}
	rounds := tunnel.rounds.Load()
	time.Sleep(time.Second)
	if tunnel.rounds.Load() != rounds {
		t.Fatal("a round was published after close")
	}
	if n := tunnel.socketCloses.Load(); n != 1 {
		t.Fatalf("the socket was closed %d times, want once", n)
	}
	if st := recoveryStatus(t, tunnel); st["winn3_lifecycle"] != driver.LifecycleStopped {
		t.Fatalf("lifecycle after close is %v, want stopped", st["winn3_lifecycle"])
	}
	if _, err := tunnel.socket.Write([]byte{0}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("the socket is open after close: %v", err)
	}
	if n := tunnel.writeInbound(up); n != errClosed {
		t.Fatalf("a host write after close returned %d, want the closed code", n)
	}
	gw.end()
}
