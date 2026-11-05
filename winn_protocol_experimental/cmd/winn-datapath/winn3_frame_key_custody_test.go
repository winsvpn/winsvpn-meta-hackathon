//go:build unix

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
)

// Key custody across in-engine recovery.
//
// The Android host (WinnV3Keys.destroy, called from VpnTunnelService right
// after CreateAck) truncates every key file the -winn3-keys document names to
// zero length, because its custody contract is that the engine "has
// acknowledged Create and loaded them into its private process memory". A
// round built after the first must therefore never go back to those paths.
// Measured on an S26 on 2026-09-23: the first post-promotion rebuild read a
// 0-byte static.key and the supervisor ended the tunnel terminally with
// "static_path: 0 bytes; expected 32 raw bytes or 64 hex characters".

// eraseKeyFilesLikeTheAndroidHost truncates every regular file in the key
// directory to zero length, which is exactly the state WinnV3Keys.destroy
// leaves behind (zero-length tombstones, never an unlink).
func eraseKeyFilesLikeTheAndroidHost(t *testing.T, keyDir string) {
	t.Helper()
	entries, err := os.ReadDir(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	erased := 0
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		if err := os.Truncate(filepath.Join(keyDir, entry.Name()), 0); err != nil {
			t.Fatal(err)
		}
		erased++
	}
	if erased == 0 {
		t.Fatalf("no key file was erased in %s; the test would prove nothing", keyDir)
	}
}

// TestARebuiltRoundSurvivesTheHostErasingItsKeyFilesAfterCreateAck is the
// device incident on loopback: two real frame hosts, a proven round, the host
// erases the key files, the gateway ends the session, and the client must
// build and carry a second round without the host doing anything.
func TestARebuiltRoundSurvivesTheHostErasingItsKeyFilesAfterCreateAck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	ring := newFrameKeyring(t)
	const pathMTU = 1500
	sizing, err := driver.NewSizing(pathMTU, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}
	clientSock, clientAddr := loopbackSocket(t)
	gatewaySock, gatewayAddr := loopbackSocket(t)
	client := startFrameEngine(t, ctx, ring.clientKeys, handOver(t, clientSock))
	gateway := startFrameEngine(t, ctx, ring.gatewayKeys, handOver(t, gatewaySock))
	client.create(t, frameCreate(gatewayAddr, "10.8.1.3", "10.8.1.1", sizing, pathMTU))
	gateway.create(t, frameCreate(clientAddr, "10.8.1.1", "10.8.1.3", sizing, pathMTU))
	_ = client.ack(t)
	_ = gateway.ack(t)

	up := func(text string) []byte {
		return ipv4Packet([4]byte{10, 8, 1, 3}, [4]byte{10, 8, 1, 1}, []byte(text))
	}
	down := func(text string) []byte {
		return ipv4Packet([4]byte{10, 8, 1, 1}, [4]byte{10, 8, 1, 3}, []byte(text))
	}
	carryPacket(t, client, gateway, up("round one up"), 45*time.Second)
	carryPacket(t, gateway, client, down("round one down"), 20*time.Second)

	// The host's post-CreateAck cleanup. Both ends share the fixture directory,
	// so the gateway frame host's own rebuild is held to the same contract.
	eraseKeyFilesLikeTheAndroidHost(t, filepath.Dir(ring.clientPath))

	firstLoop := client.server.currentLoop()
	firstSession := firstLoop.Session()
	_ = gateway.server.currentLoop().Close()

	waitUntil(t, 45*time.Second, "a fresh, established client session after the key files were erased", func() bool {
		if err := client.server.runErr.Load(); err != nil {
			t.Fatalf("the client supervisor ended instead of rebuilding: %v", *err)
		}
		l := client.server.currentLoop()
		return l != nil && l != firstLoop && l.Established()
	})
	if client.server.currentLoop().Session() == firstSession {
		t.Fatal("the recovered round reused the dead round's session")
	}
	carryPacket(t, client, gateway, up("round two up"), 45*time.Second)
	carryPacket(t, gateway, client, down("round two down"), 20*time.Second)

	select {
	case refusal := <-client.errs:
		t.Fatalf("the host was sent an Error frame during recovery: %s", refusal)
	default:
	}
	client.close(t)
	gateway.close(t)
}

// TestASuccessorRoundIsBuiltAfterTheKeyFilesAreErased is the same contract on
// one silent frame server, without a handshake: a successor must be published
// and the supervisor must not end.
func TestASuccessorRoundIsBuiltAfterTheKeyFilesAreErased(t *testing.T) {
	s, hostSide := startSilentFrameServer(t)
	go func() { _, _ = io.Copy(io.Discard, hostSide) }()
	r1 := s.currentRound()

	eraseKeyFilesLikeTheAndroidHost(t, filepath.Dir(s.keys.StaticPath))
	_ = r1.loop.Close()

	waitUntil(t, 15*time.Second, "a successor round after the key files were erased", func() bool {
		if err := s.runErr.Load(); err != nil {
			t.Fatalf("the supervisor ended instead of rebuilding: %v", *err)
		}
		d := s.activeDevice.Load()
		return d != nil && d != r1.device
	})
	select {
	case <-s.superDone:
		t.Fatal("the supervisor finished after publishing a successor")
	default:
	}
}

// refuseNextBuild makes every later round's Build fail with a configuration
// refusal, which nextRound marks terminal. It replaces pointing s.keys at a
// missing file, which stopped being a refusal once rounds stopped re-reading
// the key files. Set it before killing the live round.
func (s *winn3FrameServer) refuseNextBuild() {
	s.sessionTweak = func(cfg *session.Config) { cfg.Static = nil }
}
