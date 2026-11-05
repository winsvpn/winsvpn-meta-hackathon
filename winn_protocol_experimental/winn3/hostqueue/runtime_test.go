package hostqueue

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Only ephemeral test keys are generated/read. No operator credentials or
// real endpoints are used by any test in this package.
func profileFixture(t *testing.T, endpoint string) (string, winn3Profile, session.Config) {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		path := filepath.Join(dir, name)
		if err := securefile.AtomicWrite(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	client, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlSeed, err := pqauth.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, mlSeed)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	admission := bytes.Repeat([]byte{7}, 32)
	p := winn3Profile{
		Version: winn3ProfileVersion, Role: "client", Plan: []string{"udp", "tcp", "tls"},
		PathMTU: carrier.DefaultPathMTU, GatewayID: "direct-host-test",
		Carrier:        winn3CarrierSpec{Class: "udp", Endpoint: endpoint},
		Inner:          winn3InnerSpec{V4: "10.64.0.2", RouterV4: "10.64.0.1"},
		Device:         winn3DeviceSpec{Kind: "wintun-direct", Name: "winsvpn3"},
		AllowOwnSocket: true, OuterSocketExclusion: "test fixture outer loopback route",
		Keys: winn3KeySpec{
			StaticPath: write("client.key", client.Bytes()), GatewayStaticPath: write("gateway.pub", gateway.Public()),
			AdmissionPath:          write("admission.key", admission),
			DualAuthEd25519PubPath: write("ed.pub", []byte(hex.EncodeToString(edPub))),
			DualAuthMLDSA65PubPath: write("ml.pub", []byte(hex.EncodeToString(signer.PublicBytes()))),
		},
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return write("profile.json", raw), p, session.Config{
		Static: gateway, Padding: core.PadBucket,
		Core:     core.Config{Gateway: core.GatewayParams{AdmissionKeys: [][]byte{admission}, GatewayID: []byte(p.GatewayID)}},
		Accept:   func([]byte) error { return nil },
		DualAuth: session.DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed},
	}
}

func writeProfile(t *testing.T, path string, p winn3Profile) {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.AtomicWrite(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDirectConfigurationFailsBeforeAdapterCreation(t *testing.T) {
	path, original, _ := profileFixture(t, "127.0.0.1:9")
	for name, mutate := range map[string]func(*winn3Profile){
		"no exclusion":          func(p *winn3Profile) { p.OuterSocketExclusion = "" },
		"no authority":          func(p *winn3Profile) { p.AllowOwnSocket = false },
		"fast PQ":               func(p *winn3Profile) { p.FastPQ = true },
		"missing dual key":      func(p *winn3Profile) { p.Keys.DualAuthMLDSA65PubPath = "" },
		"legacy relay":          func(p *winn3Profile) { p.Device.Kind = "loopback-udp"; p.Device.HostPort = 99 },
		"stray port":            func(p *winn3Profile) { p.Device.HostPort = 99 },
		"other adapter":         func(p *winn3Profile) { p.Device.Name = "winsvpn" },
		"gateway role":          func(p *winn3Profile) { p.Role = "gateway" },
		"DNS endpoint":          func(p *winn3Profile) { p.Carrier.Endpoint = "example.com:443" },
		"router aliases client": func(p *winn3Profile) { p.Inner.RouterV4 = p.Inner.V4 },
		"missing key file":      func(p *winn3Profile) { p.Keys.StaticPath = filepath.Join(t.TempDir(), "absent") },
	} {
		t.Run(name, func(t *testing.T) {
			p := original
			mutate(&p)
			writeProfile(t, path, p)
			called := false
			r, err := Open(t.Context(), path, func(int) (Device, error) { called = true; return nil, errors.New("factory must not run") })
			if r != nil || err == nil || called {
				t.Fatalf("refusal failed: runtime=%v error=%v factory=%v", r != nil, err, called)
			}
		})
	}
}

func TestDirectProfileRejectsDuplicateTrailingAndUnprotectedInput(t *testing.T) {
	path, p, _ := profileFixture(t, "127.0.0.1:9")
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		string(raw) + `{}`, string(raw) + ` broken`,
		strings.Replace(string(raw), `"fast_pq":false`, `"fast_pq":true,"fast_pq":false`, 1),
		strings.Replace(string(raw), `"fast_pq":false`, `"FAST_PQ":true,"fast_pq":false`, 1),
		strings.Replace(string(raw), `"version":`, `"unknown":0,"version":`, 1),
		strings.Repeat("[", 20) + "0" + strings.Repeat("]", 20),
	} {
		if err := securefile.AtomicWrite(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadWinn3Profile(path); err == nil {
			t.Fatal("accepted ambiguous profile")
		}
	}
	writeProfile(t, path, p)
	link := filepath.Join(filepath.Dir(path), "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWinn3Profile(link); err == nil {
		t.Fatal("accepted symlink profile")
	}
}

type testDevice struct {
	mtu     int
	read    chan []byte
	written chan []byte
	done    chan struct{}
	once    sync.Once
	closed  atomic.Int32
	reject  atomic.Bool
}

func newTestDevice(mtu int) *testDevice {
	return &testDevice{mtu: mtu, read: make(chan []byte, 4), written: make(chan []byte, 4), done: make(chan struct{})}
}
func (d *testDevice) MTU() int { return d.mtu }
func (d *testDevice) ReadPacket(buf []byte) (int, error) {
	select {
	case p := <-d.read:
		if len(buf) < len(p) {
			return 0, io.ErrShortBuffer
		}
		return copy(buf, p), nil
	case <-d.done:
		return 0, io.ErrClosedPipe
	}
}
func (d *testDevice) WritePacket(p []byte) (int, error) {
	if d.reject.Load() {
		return 0, errors.New("test native ring full")
	}
	select {
	case d.written <- bytes.Clone(p):
		return len(p), nil
	case <-d.done:
		return 0, io.ErrClosedPipe
	}
}
func (d *testDevice) Close() error { d.once.Do(func() { d.closed.Add(1); close(d.done) }); return nil }

type statusSink struct {
	mu       sync.Mutex
	statuses []winn3Status
}

func (s *statusSink) Write(p []byte) (int, error) {
	var status winn3Status
	if err := json.Unmarshal(p, &status); err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.statuses = append(s.statuses, status)
	s.mu.Unlock()
	return len(p), nil
}
func (s *statusSink) latest() winn3Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.statuses) == 0 {
		return winn3Status{}
	}
	return s.statuses[len(s.statuses)-1]
}
func eventually(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

func TestDirectRuntimeAuthenticatesDeliversAndRevokesPromotion(t *testing.T) {
	runDirectEndToEnd(t, false)
}

func TestDirectRuntimeRejectsWrongGatewayAttestation(t *testing.T) {
	runDirectEndToEnd(t, true)
}

func runDirectEndToEnd(t *testing.T, wrongAuth bool) {
	// Only the encrypted outer carrier uses UDP. Both inner devices are direct
	// in-process calls through the real profile loader, session and tun driver.
	outer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer outer.Close()
	path, p, gatewayCfg := profileFixture(t, outer.LocalAddr().String())
	if wrongAuth {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := securefile.AtomicWrite(p.Keys.DualAuthEd25519PubPath, []byte(hex.EncodeToString(public)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	classes, err := p.classes()
	if err != nil {
		t.Fatal(err)
	}
	sizing, err := driver.NewSizing(p.PathMTU, classes...)
	if err != nil {
		t.Fatal(err)
	}
	var remoteMu sync.Mutex
	var remote *net.UDPAddr
	pipe, err := carrier.NewPipe(carrier.PipeConfig{Class: carrier.ClassUDP, PathMTU: sizing.PathMTU, MaxMessageSize: sizing.MessageSize,
		Out: func(packet []byte) error {
			remoteMu.Lock()
			target := remote
			remoteMu.Unlock()
			if target == nil {
				return errors.New("client has not initiated")
			}
			_, err := outer.WriteToUDP(packet, target)
			return err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	bridgeDone := make(chan struct{})
	go func() {
		defer close(bridgeDone)
		buf := make([]byte, 65535)
		for {
			n, from, err := outer.ReadFromUDP(buf)
			if err != nil {
				return
			}
			remoteMu.Lock()
			remote = from
			remoteMu.Unlock()
			_ = pipe.Deliver(buf[:n])
		}
	}()
	defer func() { _ = outer.Close(); <-bridgeDone }()
	gatewayDevice := newTestDevice(sizing.InnerMTU)
	gateway, err := driver.NewGateway(driver.Config{Session: gatewayCfg, Carrier: pipe, Sizing: sizing,
		Tun: &tun.Config{Assign: tun.Assignment{V4: netip.MustParseAddr("10.64.0.3"), RouterV4: netip.MustParseAddr("10.64.0.1")}, Device: gatewayDevice,
			Clock: driver.SessionClock{Clock: driver.SystemClock{}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	gatewayDone := make(chan error, 1)
	go func() { gatewayDone <- gateway.Run(ctx) }()
	defer func() { cancel(); _ = gatewayDevice.Close(); _ = gateway.Close(); <-gatewayDone }()
	var native *testDevice
	r, err := Open(ctx, path, func(mtu int) (Device, error) { native = newTestDevice(mtu); return native, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	sink := &statusSink{}
	clientDone := make(chan error, 1)
	go func() { clientDone <- r.Run(ctx, sink) }()
	defer func() {
		cancel()
		select {
		case <-clientDone:
		case <-time.After(3 * time.Second):
			t.Error("client failed to stop")
		}
	}()
	if wrongAuth {
		eventually(t, "wrong attestation stops client", func() bool { return sink.latest().Event == "stopped" })
		if s := sink.latest(); s.PromotionReady || s.RxPackets != 0 || s.Posture != "bootstrap" {
			t.Fatal("wrong gateway attestation permitted promotion")
		}
		if r.loop.Carrying() {
			t.Fatal("wrong gateway attestation left gate carrying")
		}
		return
	}
	eventually(t, "dual-auth carrying gate", func() bool { return r.loop.Carrying() && gateway.Carrying() })
	if status := winn3StatusFrom("posture", r.loop, sizing, p.OuterSocketExclusion); status.PromotionReady || status.RxPackets != 0 {
		t.Fatal("handshake alone promoted")
	}
	packet := fixturePacket([4]byte{10, 64, 0, 3}, [4]byte{10, 64, 0, 2})
	native.reject.Store(true)
	if err := gateway.SendInner(packet); err != nil {
		t.Fatal(err)
	}
	eventually(t, "failed device write", func() bool { return r.loop.Tunnel().Stats().RxDroppedDevice > 0 })
	if r.loop.Tunnel().Stats().RxDeviceWrites != 0 {
		t.Fatal("failed ring write credited as delivered")
	}
	if status := winn3StatusFrom("posture", r.loop, sizing, p.OuterSocketExclusion); status.PromotionReady || status.RxPackets != 0 {
		t.Fatal("failed native write promoted")
	}
	native.reject.Store(false)
	if err := gateway.SendInner(packet); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-native.written:
		if !bytes.Equal(got, packet) {
			t.Fatal("packet altered")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no direct delivery")
	}
	// The shared tun layer also requires proof that the host device produces
	// packets. A write alone remains unproven, even with a direct device.
	if s := winn3StatusFrom("posture", r.loop, sizing, p.OuterSocketExclusion); s.PromotionReady {
		t.Fatal("unproven host device promoted on a write alone")
	}
	native.read <- fixturePacket([4]byte{10, 64, 0, 2}, [4]byte{10, 64, 0, 3})
	select {
	case <-gatewayDevice.written:
	case <-time.After(3 * time.Second):
		t.Fatal("no encrypted outbound delivery")
	}
	eventually(t, "published promotion", func() bool { return sink.latest().PromotionReady })
	native.read <- fixturePacket([4]byte{192, 0, 2, 9}, [4]byte{10, 64, 0, 3})
	eventually(t, "spoofed outbound source rejected", func() bool { return r.loop.Tunnel().Stats().TxDroppedInvalid > 0 })
	cancel()
	eventually(t, "stopped status", func() bool { return sink.latest().Event == "stopped" })
	if s := sink.latest(); s.PromotionReady || s.Posture != "bootstrap" {
		t.Fatal("shutdown retained promotion")
	}
	eventually(t, "native close", func() bool { return native.closed.Load() == 1 })
}

func fixturePacket(src, dst [4]byte) []byte {
	p := make([]byte, 28)
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	binary.BigEndian.PutUint16(p[20:22], 40000)
	binary.BigEndian.PutUint16(p[22:24], 40001)
	binary.BigEndian.PutUint16(p[24:26], 8)
	return p
}

func TestDirectFactoryFailureAndMTUMismatchCloseResources(t *testing.T) {
	path, _, _ := profileFixture(t, "127.0.0.1:9")
	for _, kind := range []string{"error", "nil", "mtu", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var native *testDevice
			r, err := Open(ctx, path, func(mtu int) (Device, error) {
				if kind == "nil" {
					return nil, nil
				}
				native = newTestDevice(mtu)
				switch kind {
				case "error":
					return native, errors.New("test factory failure")
				case "mtu":
					native.mtu++
				case "cancel":
					cancel()
				}
				return native, nil
			})
			if err == nil || r != nil {
				t.Fatal("invalid factory result accepted")
			}
			if native != nil && native.closed.Load() != 1 {
				t.Fatal("factory resource not closed")
			}
		})
	}
}

type shortStatusWriter struct{}

func (shortStatusWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestDirectStatusFailureClosesNativeAndCannotRestart(t *testing.T) {
	path, _, _ := profileFixture(t, "127.0.0.1:9")
	var native *testDevice
	r, err := Open(t.Context(), path, func(mtu int) (Device, error) { native = newTestDevice(mtu); return native, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Run(t.Context(), shortStatusWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("status error = %v", err)
	}
	if native.closed.Load() != 1 {
		t.Fatal("failed status left native adapter open")
	}
	if err := r.Run(t.Context(), io.Discard); err == nil {
		t.Fatal("closed runtime restarted")
	}
}

func TestDirectNativeReadFailureStopsRuntime(t *testing.T) {
	outer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer outer.Close()
	path, _, _ := profileFixture(t, outer.LocalAddr().String())
	var native *testDevice
	r, err := Open(t.Context(), path, func(mtu int) (Device, error) { native = newTestDevice(mtu); return native, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	sink := &statusSink{}
	done := make(chan error, 1)
	go func() { done <- r.Run(t.Context(), sink) }()
	eventually(t, "initial posture", func() bool { return sink.latest().Event == "posture" })
	_ = native.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("device failure was silent")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("failed device stranded runtime")
	}
	if s := sink.latest(); s.Event != "stopped" || s.PromotionReady {
		t.Fatal("missing stopped status")
	}
}

func TestDirectCloseBeforeRunClosesCarrierAndSession(t *testing.T) {
	path, _, _ := profileFixture(t, "127.0.0.1:9")
	for _, startupFailure := range []bool{false, true} {
		r, err := Open(t.Context(), path, func(mtu int) (Device, error) { return newTestDevice(mtu), nil })
		if err != nil {
			t.Fatal(err)
		}
		if startupFailure {
			closeUnstartedLoop(r.loop)
		} else {
			_ = r.Close()
		}
		if !r.loop.Session().State().Terminal() {
			t.Fatal("unstarted session left live")
		}
		if err := r.loop.Carrier().Send(t.Context(), []byte{1}); !errors.Is(err, carrier.ErrClosed) {
			t.Fatalf("unstarted carrier remained open: %v", err)
		}
		_ = r.Close()
		if err := r.Run(t.Context(), io.Discard); err == nil {
			t.Fatal("closed runtime restarted")
		}
	}
}
