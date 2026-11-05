package carrier

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/mobility"
)

func TestManagerFallsBackAndPreservesSession(t *testing.T) {
	h3 := &fakeDialer{errors: []error{errors.New("UDP blocked")}}
	h2Connection := newFakePacketConn()
	h2 := &fakeDialer{connections: []net.PacketConn{h2Connection}}
	manager := newTestManager(t, []Candidate{
		{Path: mobility.Path{ID: "h3", Carrier: mobility.HTTP3, Endpoint: "vpn:443", Priority: 0}, Dialer: h3},
		{Path: mobility.Path{ID: "h2", Carrier: mobility.HTTP2, Endpoint: "vpn:443", Priority: 10}, Dialer: h2},
	})
	defer manager.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	snapshot := manager.Snapshot()
	if snapshot.ActivePath != "h2" {
		t.Fatalf("active path %q, want H2 fallback", snapshot.ActivePath)
	}
	if snapshot.SessionID != "00112233445566778899aabbccddeeff" ||
		snapshot.TunnelGeneration != 9 {
		t.Fatalf("logical tunnel changed during fallback: %+v", snapshot)
	}
}

func TestManagerSelfHealsReadFailure(t *testing.T) {
	failed := newFakePacketConn()
	failed.reads <- packetResult{err: errors.New("path lost")}
	recovered := newFakePacketConn()
	recovered.reads <- packetResult{data: []byte("after-recovery")}
	first := &fakeDialer{connections: []net.PacketConn{failed}}
	second := &fakeDialer{connections: []net.PacketConn{recovered}}
	manager := newTestManager(t, []Candidate{
		{Path: mobility.Path{ID: "primary", Carrier: mobility.HTTP3, Endpoint: "a:443"}, Dialer: first},
		{Path: mobility.Path{ID: "fallback", Carrier: mobility.HTTP2, Endpoint: "b:443", Priority: 10}, Dialer: second},
	})
	defer manager.Close()
	if err := manager.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = manager.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 100)
	count, address, err := manager.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:count]) != "after-recovery" || address.String() != "fallback" {
		t.Fatalf("read %q from %v", buffer[:count], address)
	}
	snapshot := manager.Snapshot()
	if snapshot.ActivePath != "fallback" ||
		snapshot.SessionID != "00112233445566778899aabbccddeeff" ||
		snapshot.TunnelGeneration != 9 {
		t.Fatalf("recovery broke continuity: %+v", snapshot)
	}
}

func TestManagerMakeBeforeBreak(t *testing.T) {
	oldConnection := newFakePacketConn()
	newConnection := newFakePacketConn()
	oldDialer := &fakeDialer{connections: []net.PacketConn{oldConnection}}
	newDialer := &fakeDialer{
		errors:      []error{errors.New("probe rejected")},
		connections: []net.PacketConn{newConnection},
	}
	manager := newTestManager(t, []Candidate{
		{Path: mobility.Path{ID: "wifi", Carrier: mobility.HTTP3, Endpoint: "a:443"}, Dialer: oldDialer},
		{Path: mobility.Path{ID: "cell", Carrier: mobility.HTTP2, Endpoint: "b:443", Priority: 10}, Dialer: newDialer},
	})
	defer manager.Close()
	if err := manager.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Switch(context.Background(), "cell"); err == nil {
		t.Fatal("failed replacement probe was accepted")
	}
	if oldConnection.closed {
		t.Fatal("old carrier closed before replacement was ready")
	}
	if manager.Snapshot().ActivePath != "wifi" {
		t.Fatal("failed probe displaced healthy carrier")
	}
	if err := manager.Switch(context.Background(), "cell"); err != nil {
		t.Fatal(err)
	}
	if !oldConnection.closed {
		t.Fatal("old carrier remained open after atomic switch")
	}
	if manager.Snapshot().ActivePath != "cell" {
		t.Fatal("replacement path was not activated")
	}
}

func TestManagerBoundsHandoffRedundancyAndReusesSequence(t *testing.T) {
	oldConnection := newFakePacketConn()
	newConnection := newFakePacketConn()
	config := DefaultManagerConfig()
	config.DialTimeout = 100 * time.Millisecond
	config.RecoveryInitial = 10 * time.Millisecond
	config.RecoveryMaximum = 20 * time.Millisecond
	config.HandoffRedundancy = 250 * time.Millisecond
	config.RedundantDatagrams = 2
	manager, err := NewManager(
		context.Background(),
		"00112233445566778899aabbccddeeff", 9,
		[]Candidate{
			{
				Path:   mobility.Path{ID: "wifi", Carrier: mobility.HTTP3, Endpoint: "a:443"},
				Dialer: &fakeDialer{connections: []net.PacketConn{oldConnection}},
			},
			{
				Path:   mobility.Path{ID: "cell", Carrier: mobility.HTTP3, Endpoint: "b:443", Priority: 10},
				Dialer: &fakeDialer{connections: []net.PacketConn{newConnection}},
			},
		},
		mobility.DefaultConfig(), config,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if err := manager.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Switch(context.Background(), "cell"); err != nil {
		t.Fatal(err)
	}
	if oldConnection.closed {
		t.Fatal("previous carrier closed before the handoff redundancy window")
	}
	for _, payload := range []string{"one", "two", "three"} {
		if _, err := manager.WriteTo([]byte(payload), nil); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, time.Second, func() bool {
		oldConnection.mu.Lock()
		defer oldConnection.mu.Unlock()
		return oldConnection.closed
	})
	oldConnection.mu.Lock()
	oldSequences := append([]uint64(nil), oldConnection.sequences...)
	oldConnection.mu.Unlock()
	newConnection.mu.Lock()
	newSequences := append([]uint64(nil), newConnection.sequences...)
	newConnection.mu.Unlock()
	if len(oldSequences) != 2 || len(newSequences) != 3 {
		t.Fatalf(
			"redundant writes old=%v new=%v, want two and three",
			oldSequences, newSequences,
		)
	}
	if oldSequences[0] != newSequences[0] ||
		oldSequences[1] != newSequences[1] ||
		newSequences[2] <= newSequences[1] {
		t.Fatalf("handoff did not preserve global data sequence: old=%v new=%v", oldSequences, newSequences)
	}
}

func TestManagerStaysFailClosedWhenAllCarriersFail(t *testing.T) {
	dialer := &fakeDialer{errors: []error{
		errors.New("blocked"), errors.New("still blocked"), errors.New("blocked again"),
	}}
	manager := newTestManager(t, []Candidate{
		{Path: mobility.Path{ID: "h3", Carrier: mobility.HTTP3, Endpoint: "a:443"}, Dialer: dialer},
	})
	defer manager.Close()
	_ = manager.SetWriteDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := manager.WriteTo([]byte("must-not-leak"), nil); err == nil {
		t.Fatal("write escaped while all authenticated carriers were unavailable")
	}
	if manager.Snapshot().ActivePath != "" {
		t.Fatal("manager activated an unauthenticated path")
	}
}

func newTestManager(t *testing.T, candidates []Candidate) *Manager {
	t.Helper()
	config := DefaultManagerConfig()
	config.DialTimeout = 100 * time.Millisecond
	config.RecoveryInitial = 10 * time.Millisecond
	config.RecoveryMaximum = 20 * time.Millisecond
	manager, err := NewManager(
		context.Background(),
		"00112233445566778899aabbccddeeff",
		9,
		candidates,
		mobility.DefaultConfig(),
		config,
	)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

type fakeDialer struct {
	mu          sync.Mutex
	errors      []error
	connections []net.PacketConn
}

func (d *fakeDialer) Dial(context.Context) (net.PacketConn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.errors) > 0 {
		err := d.errors[0]
		d.errors = d.errors[1:]
		return nil, err
	}
	if len(d.connections) == 0 {
		return nil, errors.New("no scripted connection")
	}
	connection := d.connections[0]
	d.connections = d.connections[1:]
	return connection, nil
}

type packetResult struct {
	data []byte
	err  error
}

type fakePacketConn struct {
	mu        sync.Mutex
	reads     chan packetResult
	writes    [][]byte
	sequences []uint64
	closed    bool
	done      chan struct{}
	once      sync.Once
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{
		reads: make(chan packetResult, 4),
		done:  make(chan struct{}),
	}
}

func (c *fakePacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case result := <-c.reads:
		if result.err != nil {
			return 0, nil, result.err
		}
		return copy(buffer, result.data), fixedAddr("fake"), nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

func (c *fakePacketConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	return c.WriteSequenced(packet, nil, uint64(len(c.writes)+1))
}

func (c *fakePacketConn) WriteSequenced(packet []byte, _ net.Addr, sequence uint64) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.writes = append(c.writes, append([]byte(nil), packet...))
	c.sequences = append(c.sequences, sequence)
	return len(packet), nil
}

func (c *fakePacketConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.once.Do(func() { close(c.done) })
	return nil
}

func (c *fakePacketConn) LocalAddr() net.Addr              { return fixedAddr("fake") }
func (c *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition did not become true before timeout")
}
