package carrier

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLocalRelayPinsOneAWGPeer(t *testing.T) {
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	remote := newFakePacketConn()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RelayLocalUDP(ctx, local, remote, RelayConfig{MaxDatagram: 1200})
	}()

	first, err := net.DialUDP("udp", nil, local.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.DialUDP("udp", nil, local.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := first.Write([]byte("allowed")); err != nil {
		t.Fatal(err)
	}
	waitForWrites(t, remote, 1)
	if _, err := second.Write([]byte("rejected")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	remote.mu.Lock()
	writes := len(remote.writes)
	remote.mu.Unlock()
	if writes != 1 {
		t.Fatalf("relay accepted %d packets; unexpected local peer was not rejected", writes)
	}
	remote.reads <- packetResult{data: []byte("reply")}
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 20)
	count, err := first.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:count]) != "reply" {
		t.Fatalf("reply %q", buffer[:count])
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not stop")
	}
}

func TestLocalRelayRejectsAttackerBeforeExpectedAWGPeer(t *testing.T) {
	local, err := net.ListenUDP(
		"udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
	)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := net.DialUDP(
		"udp", nil, local.LocalAddr().(*net.UDPAddr),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer expected.Close()
	attacker, err := net.DialUDP(
		"udp", nil, local.LocalAddr().(*net.UDPAddr),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	remote := newFakePacketConn()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RelayLocalUDP(ctx, local, remote, RelayConfig{
			MaxDatagram:       1200,
			ExpectedLocalPeer: expected.LocalAddr().(*net.UDPAddr),
		})
	}()

	if _, err := attacker.Write([]byte("claim")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := expected.Write([]byte("allowed")); err != nil {
		t.Fatal(err)
	}
	waitForWrites(t, remote, 1)
	remote.mu.Lock()
	packet := string(remote.writes[0])
	remote.mu.Unlock()
	if packet != "allowed" {
		t.Fatalf("relayed packet = %q", packet)
	}
	remote.reads <- packetResult{data: []byte("reply")}
	_ = expected.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 20)
	count, err := expected.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:count]) != "reply" {
		t.Fatalf("reply %q", buffer[:count])
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not stop")
	}
}

func TestLocalRelayConcurrentCloseJoinsWorkers(t *testing.T) {
	local, err := net.ListenUDP(
		"udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
	)
	if err != nil {
		t.Fatal(err)
	}
	remote := &trackedRelayPacketConn{fakePacketConn: newFakePacketConn()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RelayLocalUDP(ctx, local, remote, RelayConfig{
			MaxDatagram: 1200,
		})
	}()
	deadline := time.Now().Add(time.Second)
	for remote.activeReads.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if remote.activeReads.Load() != 1 {
		t.Fatal("remote relay worker did not start")
	}

	var closers sync.WaitGroup
	closers.Add(3)
	go func() {
		defer closers.Done()
		cancel()
	}()
	go func() {
		defer closers.Done()
		_ = local.Close()
	}()
	go func() {
		defer closers.Done()
		_ = remote.Close()
	}()
	closers.Wait()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not return after concurrent close")
	}
	if active := remote.activeReads.Load(); active != 0 {
		t.Fatalf("relay returned with %d remote read workers active", active)
	}
}

type trackedRelayPacketConn struct {
	*fakePacketConn
	activeReads atomic.Int32
}

func (connection *trackedRelayPacketConn) ReadFrom(
	buffer []byte,
) (int, net.Addr, error) {
	connection.activeReads.Add(1)
	defer connection.activeReads.Add(-1)
	return connection.fakePacketConn.ReadFrom(buffer)
}

func waitForWrites(t *testing.T, connection *fakePacketConn, expected int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		connection.mu.Lock()
		count := len(connection.writes)
		connection.mu.Unlock()
		if count >= expected {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for relayed packet")
}
