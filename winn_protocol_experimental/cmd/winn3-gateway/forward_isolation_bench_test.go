package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
)

// OI-5 cost on the uplink hot path. The same file runs on the tree before
// the fix (where benchIsolation is a no-op and WritePacket has no destination
// check) and after it, so the before and after numbers come from identical
// benchmark code. Run with:
//
//	go test ./cmd/winn3-gateway/ -run '^$' -bench 'WritePacket|ForwardIsolation' -benchmem -count 5
//
// Allocations must read 0 allocs/op in every WritePacket benchmark: the
// destination rule allocates nothing.

// benchDiscardWriter is an innerWriter that counts and drops.
type benchDiscardWriter struct{ n int }

func (w *benchDiscardWriter) write(pkt []byte) (int, error) {
	w.n++
	return len(pkt), nil
}

func benchIPv4Packet(src, dst string) []byte {
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	return pkt
}

// BenchmarkWritePacketPublicDestination is the common case: an accepted
// packet to the internet, no registry (the registry's cost is measured by the
// WithRegistry variant below and is the same before and after).
func BenchmarkWritePacketPublicDestination(b *testing.B) {
	tbl := newForwardTable()
	benchIsolation(b, tbl)
	dev := newGatewayForwardDevice(&benchDiscardWriter{}, tbl, 1400)
	dev.bind(fakeLoop())
	pkt := benchIPv4Packet("10.64.90.2", "8.8.8.8")
	if _, err := dev.WritePacket(pkt); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := dev.WritePacket(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWritePacketRefusedPoolDestination is the A-to-B refusal: on the
// tree before the fix this packet is WRITTEN (the benchmark then measures a
// write, and its name says what it would have measured).
func BenchmarkWritePacketRefusedPoolDestination(b *testing.B) {
	tbl := newForwardTable()
	benchIsolation(b, tbl)
	dev := newGatewayForwardDevice(&benchDiscardWriter{}, tbl, 1400)
	dev.bind(fakeLoop())
	if _, err := dev.WritePacket(benchIPv4Packet("10.64.90.2", "8.8.8.8")); err != nil {
		b.Fatal(err)
	}
	pkt := benchIPv4Packet("10.64.90.2", "10.64.90.3")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = dev.WritePacket(pkt)
	}
}

// BenchmarkWritePacketWithRegistry is the production path: a real
// authenticated session, the peer registry's per-packet authorization, then
// the destination rule.
func BenchmarkWritePacketWithRegistry(b *testing.B) {
	tbl, dev := newBenchAuthority(b)
	benchIsolation(b, tbl)
	pkt := benchIPv4Packet("10.10.0.2", "8.8.8.8")
	if _, err := dev.WritePacket(pkt); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := dev.WritePacket(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

// newBenchAuthority mirrors newAuthorityFixture on a *testing.B: a real
// gateway session authenticated by a registry that binds the client to
// 10.10.0.2, bound to a forward device over a discarding writer.
func newBenchAuthority(b *testing.B) (*forwardTable, *gatewayForwardDevice) {
	b.Helper()
	dir := b.TempDir()
	if err := runKeygen(dir, io.Discard); err != nil {
		b.Fatal(err)
	}
	readKey := func(name string) []byte {
		k, err := readKeyFile(filepath.Join(dir, name))
		if err != nil {
			b.Fatal(err)
		}
		return k
	}
	key := readKey("client.pub")
	body := fmt.Sprintf(`{"version":1,"peers":[{"static_public":%q,"inner_v4":"10.10.0.2","not_after":0}]}`,
		base64.StdEncoding.EncodeToString(key))
	path := filepath.Join(dir, "peers.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		b.Fatal(err)
	}
	r, err := newPeerRegistry(path, netip.MustParsePrefix("10.10.0.0/24"))
	if err != nil {
		b.Fatal(err)
	}
	gwCfg, err := buildSessionConfig(serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	}, r)
	if err != nil {
		b.Fatal(err)
	}
	clientKey, err := core.NewStaticKey(readKey("client.key"))
	if err != nil {
		b.Fatal(err)
	}
	gatewayKey, err := core.NewPublicKey(readKey("static.pub"))
	if err != nil {
		b.Fatal(err)
	}
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		b.Fatal(err)
	}
	newLoop := func(cfg session.Config, build func(driver.Config) (*driver.Loop, error)) *driver.Loop {
		pipe, err := carrier.NewPipe(carrier.PipeConfig{Class: carrier.ClassUDP, PathMTU: testPathMTU})
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { _ = pipe.Close() })
		loop, err := build(driver.Config{Session: cfg, Sizing: sizing, Carrier: pipe})
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { _ = loop.Close() })
		return loop
	}
	gw := newLoop(gwCfg, driver.NewGateway)
	cli := newLoop(session.Config{
		Core: gwCfg.Core, Static: clientKey, GatewayStatic: gatewayKey, Padding: core.PadBucket,
	}, driver.NewClient)
	for round := 0; round < 64; round++ {
		for _, pair := range [][2]*session.Driver{{cli.Session(), gw.Session()}, {gw.Session(), cli.Session()}} {
			for count := 0; count < 64; count++ {
				msg, err := pair[0].Poll()
				if err != nil {
					b.Fatal(err)
				}
				if msg == nil {
					break
				}
				if _, err := pair[1].Deliver(msg); err != nil {
					b.Fatal(err)
				}
			}
		}
		if cli.Session().State() == session.StateEstablished && gw.Session().State() == session.StateEstablished {
			break
		}
	}
	if cli.Session().State() != session.StateEstablished || gw.Session().State() != session.StateEstablished {
		b.Fatal("benchmark fixture failed to establish the session")
	}
	tbl := newForwardTable()
	tbl.registry = r
	dev := newGatewayForwardDevice(&benchDiscardWriter{}, tbl, sizing.InnerMTU, r)
	dev.bind(gw)
	b.Cleanup(func() { _ = dev.Close() })
	return tbl, dev
}
