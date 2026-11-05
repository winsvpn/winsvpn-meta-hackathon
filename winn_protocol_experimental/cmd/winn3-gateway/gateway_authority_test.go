package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
)

type authorityFixture struct {
	registry   *peerRegistry
	table      *forwardTable
	device     *gatewayForwardDevice
	writer     *fakeInnerWriter
	loop       *driver.Loop
	key        []byte
	addr       netip.Addr
	body       string
	gwCfg      session.Config
	clientKey  *core.StaticKey
	gatewayKey *core.PublicKey
	sizing     driver.Sizing
}

// Establish real session drivers so both forwarding directions must check the
// authenticated client key. No kernel TUN or network socket is needed.
func newAuthorityFixture(t *testing.T, expires int64) *authorityFixture {
	t.Helper()
	dir := t.TempDir()
	if err := runKeygen(dir, io.Discard); err != nil {
		t.Fatal(err)
	}
	key := readTestKey(t, filepath.Join(dir, "client.pub"))
	body := fmt.Sprintf(`{"version":1,"peers":[{"static_public":%q,"inner_v4":"10.10.0.2","not_after":%d}]}`,
		base64.StdEncoding.EncodeToString(key), expires)
	r, err := newPeerRegistry(writeRegistry(t, body), netip.MustParsePrefix("10.10.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	gwCfg, err := buildSessionConfig(serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	}, r)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := core.NewStaticKey(readTestKey(t, filepath.Join(dir, "client.key")))
	if err != nil {
		t.Fatal(err)
	}
	gatewayKey, err := core.NewPublicKey(readTestKey(t, filepath.Join(dir, "static.pub")))
	if err != nil {
		t.Fatal(err)
	}
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	newLoop := func(cfg session.Config, build func(driver.Config) (*driver.Loop, error)) *driver.Loop {
		pipe, err := carrier.NewPipe(carrier.PipeConfig{Class: carrier.ClassUDP, PathMTU: testPathMTU})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pipe.Close() })
		loop, err := build(driver.Config{Session: cfg, Sizing: sizing, Carrier: pipe})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = loop.Close() })
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
					t.Fatal(err)
				}
				if msg == nil {
					break
				}
				if _, err := pair[1].Deliver(msg); err != nil {
					t.Fatal(err)
				}
			}
		}
		if cli.Session().State() == session.StateEstablished && gw.Session().State() == session.StateEstablished {
			break
		}
	}
	if cli.Session().State() != session.StateEstablished || gw.Session().State() != session.StateEstablished ||
		!bytes.Equal(gw.Session().PeerStatic(), key) {
		t.Fatal("fixture failed to establish the authenticated client key")
	}
	table := newForwardTable()
	table.registry = r
	writer := &fakeInnerWriter{}
	device := newGatewayForwardDevice(writer, table, sizing.InnerMTU, r)
	device.bind(gw)
	t.Cleanup(func() { _ = device.Close() })
	f := &authorityFixture{
		registry:   r,
		table:      table,
		device:     device,
		writer:     writer,
		loop:       gw,
		key:        key,
		addr:       netip.MustParseAddr("10.10.0.2"),
		body:       body,
		gwCfg:      gwCfg,
		clientKey:  clientKey,
		gatewayKey: gatewayKey,
		sizing:     sizing,
	}
	if _, err := device.WritePacket(ipv4Packet(t, f.addr.String(), "8.8.8.8")); err != nil {
		t.Fatalf("initial authorized packet: %v", err)
	}
	f.checkForwarding(t, true)
	return f
}

func (f *authorityFixture) checkForwarding(t *testing.T, allowed bool) {
	t.Helper()
	// Check return routing first: it must refresh authority even when no
	// client packet or new handshake has arrived since the registry changed.
	if got, ok := f.table.lookup(f.addr); ok != allowed || (ok && got != f.loop) {
		t.Errorf("return lookup allowed = %v, want %v", ok, allowed)
	}
	before := len(f.writer.written)
	pkt := ipv4Packet(t, f.addr.String(), "8.8.8.8")
	n, err := f.device.WritePacket(pkt)
	if allowed {
		if err != nil || n != len(pkt) || len(f.writer.written) != before+1 {
			t.Fatalf("authorized outbound write = %d, %v; writes = %d", n, err, len(f.writer.written))
		}
		if got, ok := f.table.lookup(f.addr); !ok || got != f.loop {
			t.Fatal("authorized return lookup refused the learned session")
		}
	} else if !errors.Is(err, errGatewayPeerUnauthorized) || n != 0 || len(f.writer.written) != before {
		t.Errorf("revoked outbound write = %d, %v; writes = %d, want unchanged %d", n, err, len(f.writer.written), before)
	}
}

func (f *authorityFixture) newPeerLoop(t *testing.T) *driver.Loop {
	t.Helper()
	newLoop := func(cfg session.Config, build func(driver.Config) (*driver.Loop, error)) *driver.Loop {
		pipe, err := carrier.NewPipe(carrier.PipeConfig{Class: carrier.ClassUDP, PathMTU: testPathMTU})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pipe.Close() })
		loop, err := build(driver.Config{Session: cfg, Sizing: f.sizing, Carrier: pipe})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = loop.Close() })
		return loop
	}
	gw := newLoop(f.gwCfg, driver.NewGateway)
	cli := newLoop(session.Config{
		Core: f.gwCfg.Core, Static: f.clientKey, GatewayStatic: f.gatewayKey, Padding: core.PadBucket,
	}, driver.NewClient)
	for round := 0; round < 64; round++ {
		for _, pair := range [][2]*session.Driver{{cli.Session(), gw.Session()}, {gw.Session(), cli.Session()}} {
			for count := 0; count < 64; count++ {
				msg, err := pair[0].Poll()
				if err != nil {
					t.Fatal(err)
				}
				if msg == nil {
					break
				}
				if _, err := pair[1].Deliver(msg); err != nil {
					t.Fatal(err)
				}
			}
		}
		if cli.Session().State() == session.StateEstablished && gw.Session().State() == session.StateEstablished {
			break
		}
	}
	if cli.Session().State() != session.StateEstablished || gw.Session().State() != session.StateEstablished ||
		!bytes.Equal(gw.Session().PeerStatic(), f.key) {
		t.Fatal("failed to establish replacement session for the same authenticated client key")
	}
	return gw
}

func replaceAuthority(t *testing.T, path, body string) {
	t.Helper()
	replacement := path + ".new"
	if err := os.WriteFile(replacement, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
}

// Advance only the refresh cadence, leaving expiration on the real clock.
func dueAuthorityRefresh(r *peerRegistry) {
	r.refreshMu.Lock()
	r.lastCheck = time.Now().Add(-2 * time.Second)
	r.checkDue.Store(0)
	r.refreshMu.Unlock()
}

func TestGatewayAuthorityExpiresWithoutFileChange(t *testing.T) {
	t.Parallel()
	expires := time.Now().Unix() + 3
	f := newAuthorityFixture(t, expires)
	for time.Now().Unix() < expires {
		time.Sleep(10 * time.Millisecond)
	}
	// Keep refresh cached to prove expiry is checked on every inner lookup.
	f.registry.refreshMu.Lock()
	f.registry.markCheckedLocked()
	f.registry.refreshMu.Unlock()
	f.checkForwarding(t, false)
}

func TestGatewayAuthorityRevocationAndRestoration(t *testing.T) {
	cases := map[string]func(*testing.T, string){
		"removed_peer": func(t *testing.T, path string) { replaceAuthority(t, path, `{"version":1,"peers":[]}`) },
		"missing_file": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		},
		"malformed_json": func(t *testing.T, path string) { replaceAuthority(t, path, `{"version":1,"peers":[`) },
		"invalid_entry": func(t *testing.T, path string) {
			replaceAuthority(t, path, `{"version":1,"peers":[{"static_public":"bad","inner_v4":"10.10.0.2","not_after":0}]}`)
		},
		"reassigned_address": func(t *testing.T, path string) {
			_, key := registryKey(0x91)
			replaceAuthority(t, path, `{"version":1,"peers":[{"static_public":"`+key+`","inner_v4":"10.10.0.2","not_after":0}]}`)
		},
		"oversized_file": func(t *testing.T, path string) { replaceAuthority(t, path, strings.Repeat(" ", 1024*1024+1)) },
		"non_regular_file": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, revoke := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newAuthorityFixture(t, 0)
			revoke(t, f.registry.path)
			dueAuthorityRefresh(f.registry)
			f.checkForwarding(t, false)
			f.checkForwarding(t, false)
			if name == "non_regular_file" {
				if err := os.Remove(f.registry.path); err != nil {
					t.Fatal(err)
				}
			}
			replaceAuthority(t, f.registry.path, f.body)
			dueAuthorityRefresh(f.registry)
			f.checkForwarding(t, true)
		})
	}
}

func TestGatewayAuthorityRefreshCadenceAndCachedFailure(t *testing.T) {
	t.Parallel()
	f := newAuthorityFixture(t, 0)
	f.registry.refreshMu.Lock()
	f.registry.markCheckedLocked()
	f.registry.refreshMu.Unlock()
	replaceAuthority(t, f.registry.path, `{"version":1,"peers":[`)
	f.checkForwarding(t, true)
	time.Sleep(1100 * time.Millisecond)
	f.checkForwarding(t, false)
	replaceAuthority(t, f.registry.path, f.body)
	// A cached read error stays closed until the next successful refresh.
	f.checkForwarding(t, false)
	time.Sleep(1100 * time.Millisecond)
	f.checkForwarding(t, true)
}

func TestGatewayAuthorityRefreshDetectsIdentitySizeAndMtime(t *testing.T) {
	for _, change := range []string{"identity", "size", "mtime"} {
		t.Run(change, func(t *testing.T) {
			t.Parallel()
			f := newAuthorityFixture(t, 0)
			old, err := os.Stat(f.registry.path)
			if err != nil {
				t.Fatal(err)
			}
			// A same-length replacement keeps the peer but changes its address.
			body := strings.Replace(f.body, "10.10.0.2", "10.10.0.3", 1)
			switch change {
			case "identity":
				replaceAuthority(t, f.registry.path, body)
			case "size":
				body += " "
				fallthrough
			case "mtime":
				if err := os.WriteFile(f.registry.path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			mtime := old.ModTime()
			if change == "mtime" {
				mtime = mtime.Add(time.Second)
			}
			if err := os.Chtimes(f.registry.path, mtime, mtime); err != nil {
				t.Fatal(err)
			}
			updated, err := os.Stat(f.registry.path)
			if err != nil {
				t.Fatal(err)
			}
			if os.SameFile(old, updated) != (change != "identity") ||
				(old.Size() == updated.Size()) != (change != "size") ||
				old.ModTime().Equal(updated.ModTime()) != (change != "mtime") {
				t.Fatal("fixture did not isolate the requested metadata change")
			}
			dueAuthorityRefresh(f.registry)
			if _, ok := f.table.lookup(f.addr); ok {
				t.Fatal("return path reused an address no longer assigned to this peer")
			}
			if got, ok := f.registry.innerForPeer(f.key); !ok || got.String() != "10.10.0.3" {
				t.Fatalf("replacement authority = %v, %v", got, ok)
			}
			if _, err := f.device.WritePacket(ipv4Packet(t, f.addr.String(), "8.8.8.8")); !errors.Is(err, errGatewayInnerSourceMismatch) {
				t.Fatalf("old outbound address error = %v", err)
			}
		})
	}
}

func TestGatewayAuthorityHandshakeBypassesRefreshCadence(t *testing.T) {
	f := newAuthorityFixture(t, 0)
	replaceAuthority(t, f.registry.path, `{"version":1,"peers":[]}`)
	if err := f.registry.authorize(f.key); !errors.Is(err, errPeerNotAuthorized) {
		t.Fatalf("immediate revoked handshake error = %v", err)
	}
	f.checkForwarding(t, false)
	replaceAuthority(t, f.registry.path, f.body)
	if err := f.registry.authorize(f.key); err != nil {
		t.Fatalf("immediate restored handshake error = %v", err)
	}
	f.checkForwarding(t, true)
}

func TestGatewayAuthorityReturnLookupRequiresAuthenticatedKey(t *testing.T) {
	f := newAuthorityFixture(t, 0)
	unknown := netip.MustParseAddr("10.10.0.3")
	unauthenticated := fakeLoop()
	if !f.table.learn(unknown, unauthenticated) {
		t.Fatal("fixture did not learn the unauthenticated loop")
	}
	if _, ok := f.table.lookup(unknown); ok {
		t.Fatal("return lookup accepted a loop without an authenticated session")
	}
	f.table.forget(unknown, unauthenticated)
	if !f.table.learn(unknown, f.loop) {
		t.Fatal("fixture did not learn the wrong destination")
	}
	if _, ok := f.table.lookup(unknown); ok {
		t.Fatal("return lookup accepted the peer at a different destination")
	}
}

func TestGatewayAuthorityConcurrentRefreshAndLookups(t *testing.T) {
	f := newAuthorityFixture(t, 0)
	for _, allowed := range []bool{false, true, false, true} {
		body := `{"version":1,"peers":[`
		if allowed {
			body = f.body
		}
		replaceAuthority(t, f.registry.path, body)
		// A completed failed refresh must invalidate all previously published
		// indexes. Concurrent refreshes and lookups must preserve that denial.
		if err := f.registry.reload(); (err == nil) != allowed {
			t.Fatalf("reload error = %v, allowed = %v", err, allowed)
		}
		var wg sync.WaitGroup
		for worker := 0; worker < 8; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 16; i++ {
					if err := f.registry.authorize(f.key); (err == nil) != allowed {
						t.Errorf("concurrent authorize error = %v, allowed = %v", err, allowed)
					}
					if _, ok := f.registry.innerForPeer(f.key); ok != allowed {
						t.Errorf("concurrent outbound authority = %v, want %v", ok, allowed)
					}
					if _, ok := f.table.lookup(f.addr); ok != allowed {
						t.Errorf("concurrent return authority = %v, want %v", ok, allowed)
					}
				}
			}()
		}
		wg.Wait()
	}
}
