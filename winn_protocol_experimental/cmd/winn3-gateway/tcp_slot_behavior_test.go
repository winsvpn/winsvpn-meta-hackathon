package main

import (
	"context"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// This test uses only the gateway and driver interfaces present in the
// pristine tree, so its baseline failure is a behavioral failure.
func TestTCPClosedSessionFreesSharedSlot(t *testing.T) {
	opts := operatorValueOptions(t)
	opts.plan = "udp,tcp"
	// Round W's path is off by default (-tcp-ingress). The environment turns it
	// on without naming a field the pristine tree lacks.
	t.Setenv("WINN3_GATEWAY_TCP_INGRESS", "1")
	opts.maxSessions = 1
	opts.runFor = 12 * time.Second
	output := &safeBuffer{}
	done := make(chan error, 1)
	go func() { done <- runServe(opts, output) }()
	t.Cleanup(func() {
		if err := <-done; err != nil {
			t.Errorf("runServe: %v", err)
		}
	})
	endpoint := waitListening(t, output, done, 5*time.Second)
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(opts.staticPath)
	start := func() (*driver.Loop, context.CancelFunc, <-chan error) {
		cfg := carrier.StreamConfig{
			Secret: readTestSecret(t, filepath.Join(dir, "admission.key")),
			Role:   carrier.RoleClient, MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU,
		}
		firstFlight := reflect.ValueOf(&cfg).Elem().FieldByName("TCPFirstFlight")
		if firstFlight.IsValid() {
			firstFlight.SetBool(true)
		}
		conn, err := carrier.DialStream(context.Background(), carrier.DialTCP(endpoint), cfg)
		if err != nil {
			t.Fatal(err)
		}
		static, err := core.NewStaticKey(readTestKey(t, filepath.Join(dir, "client.key")))
		if err != nil {
			t.Fatal(err)
		}
		gw, err := core.NewPublicKey(readTestKey(t, filepath.Join(dir, "static.pub")))
		if err != nil {
			t.Fatal(err)
		}
		dev := newTestDevice(sizing.InnerMTU)
		loop, err := driver.NewClient(driver.Config{
			Session: session.Config{
				Core: core.Config{Gateway: core.GatewayParams{
					AdmissionKeys: [][]byte{readTestSecret(t, filepath.Join(dir, "admission.key"))},
					GatewayID:     []byte(testGatewayID),
				}},
				Static: static, GatewayStatic: gw, Padding: core.PadBucket,
			},
			Sizing: sizing, Carrier: conn,
			Tun: &tun.Config{
				Assign: tun.Assignment{V4: netip.MustParseAddr(testClientInner)},
				Device: dev, Clock: driver.SessionClock{Clock: driver.SystemClock{}},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		runDone := make(chan error, 1)
		go func() { runDone <- loop.Run(ctx) }()
		t.Cleanup(func() {
			cancel()
			_ = loop.Close()
			_ = dev.Close()
			_ = conn.Close()
		})
		return loop, cancel, runDone
	}
	first, stopFirst, firstDone := start()
	waitFor(t, 4*time.Second, "first TCP session carrying", func() bool {
		return first.Tunnel().Gate().State() == tun.StateCarrying
	})
	_ = first.Close()
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first client close: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("first client did not finish its close")
	}
	stopFirst()
	_ = first.Carrier().Close()
	time.Sleep(2 * time.Second)
	second, _, _ := start()
	waitFor(t, 4*time.Second, "second TCP session carrying after first closed", func() bool {
		return second.Tunnel().Gate().State() == tun.StateCarrying
	})
}
