package initauth

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type recordingPacketConn struct {
	net.PacketConn
	mu   sync.Mutex
	sent [][]byte
}

func (c *recordingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.sent = append(c.sent, append([]byte(nil), p...))
	c.mu.Unlock()
	return len(p), nil
}

func (c *recordingPacketConn) Close() error                     { return nil }
func (c *recordingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not used")
}

func (c *recordingPacketConn) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.sent))
	copy(out, c.sent)
	return out
}

func newSealer(t *testing.T, inner net.PacketConn, key []byte, clock *fakeClock) *Sealer {
	t.Helper()
	s, err := NewSealer(inner, SealerConfig{Key: key, Profile: fleetProfile, Now: clock.Now})
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return s
}

// AmneziaWG reuses its send buffers. Sealing in place would rewrite bytes the
// engine may still hold, which would present as an intermittent handshake
// failure through a gate that never answers — the hardest possible thing to
// diagnose in the field.
func TestTheSealerNeverModifiesTheCallersBuffer(t *testing.T) {
	clock := newFakeClock()
	rec := &recordingPacketConn{}
	s := newSealer(t, rec, testKey(t, 0xa1), clock)

	caller := makeInitiation(t, fleetProfile)
	before := append([]byte(nil), caller...)

	if _, err := s.WriteTo(caller, &net.UDPAddr{}); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if !bytes.Equal(caller, before) {
		t.Fatal("the sealer mutated the caller's buffer")
	}

	sent := rec.snapshot()
	if len(sent) != 1 {
		t.Fatalf("sent %d datagrams, want 1", len(sent))
	}
	if len(sent[0]) != len(caller) {
		t.Fatalf("length changed: %d -> %d", len(caller), len(sent[0]))
	}
	if !bytes.Equal(sent[0][fleetProfile.S1:], caller[fleetProfile.S1:]) {
		t.Fatal("the body was changed; only the S1 prefix may differ")
	}
	if bytes.Equal(sent[0][:fleetProfile.S1], caller[:fleetProfile.S1]) {
		t.Fatal("the prefix was not sealed")
	}
}

func TestTheSealerForwardsEveryNonInitiationDatagramByteForByte(t *testing.T) {
	clock := newFakeClock()
	rec := &recordingPacketConn{}
	s := newSealer(t, rec, testKey(t, 0xa1), clock)

	inputs := [][]byte{
		junkDatagram(27),
		junkDatagram(16),
		transportDatagram(),
		junkDatagram(1312),
	}
	for _, in := range inputs {
		if _, err := s.WriteTo(in, &net.UDPAddr{}); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}
	sent := rec.snapshot()
	if len(sent) != len(inputs) {
		t.Fatalf("sent %d, want %d", len(sent), len(inputs))
	}
	for i := range inputs {
		if !bytes.Equal(sent[i], inputs[i]) {
			t.Fatalf("datagram %d was modified; the sealer must only ever touch an initiation", i)
		}
	}
	if got := s.Stats(); got.Sealed != 0 || got.Passed != 4 {
		t.Fatalf("stats = %+v", got)
	}
}

// The property that lets the client half ship BEFORE the server half, which is
// the opposite of the firewall gate's rollout risk. To a gateway that is not
// checking, and to anything on the path, a sealing client is a non-sealing
// client: same datagram count, same sizes, same order, same bodies.
func TestASealingClientIsIndistinguishableFromTodaysClientToAnythingNotHoldingTheKey(t *testing.T) {
	clock := newFakeClock()
	rec := &recordingPacketConn{}
	s := newSealer(t, rec, testKey(t, 0xa1), clock)

	// The measured opening burst: two junk datagrams, then the initiation.
	burst := [][]byte{junkDatagram(27), junkDatagram(16), makeInitiation(t, fleetProfile)}
	for _, d := range burst {
		if _, err := s.WriteTo(d, &net.UDPAddr{}); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}

	sent := rec.snapshot()
	if len(sent) != len(burst) {
		t.Fatalf("the burst gained or lost a datagram: %d vs %d", len(sent), len(burst))
	}
	for i := range burst {
		if len(sent[i]) != len(burst[i]) {
			t.Fatalf("datagram %d changed size: %d -> %d", i, len(burst[i]), len(sent[i]))
		}
	}
	if len(sent[2]) != 164 {
		t.Fatalf("the initiation is %d bytes; the censor's measured rule matches 164", len(sent[2]))
	}
	// Everything a gateway or a middlebox actually parses is untouched.
	if !bytes.Equal(sent[2][fleetProfile.S1:], burst[2][fleetProfile.S1:]) {
		t.Fatal("the parsed portion of the initiation changed")
	}
}

func TestALegacyProfileWithNoRoomReportsCannotSealInsteadOfFailingTheConnection(t *testing.T) {
	rec := &recordingPacketConn{}
	_, err := NewSealer(rec, SealerConfig{
		Key:     testKey(t, 0xa1),
		Profile: Profile{S1: 0, H1Start: 1, H1End: 1},
	})
	if !errors.Is(err, ErrProfileCannotSeal) {
		t.Fatalf("err = %v, want ErrProfileCannotSeal so the caller can fall back to the bare socket", err)
	}
}

func TestSealerStatsAnswerWhetherTheAuthenticatorIsBeingAppliedAtAll(t *testing.T) {
	clock := newFakeClock()
	rec := &recordingPacketConn{}
	s := newSealer(t, rec, testKey(t, 0xa1), clock)

	for i := 0; i < 3; i++ {
		if _, err := s.WriteTo(makeInitiation(t, fleetProfile), &net.UDPAddr{}); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}
	for i := 0; i < 5; i++ {
		if _, err := s.WriteTo(transportDatagram(), &net.UDPAddr{}); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}
	got := s.Stats()
	if got.Sealed != 3 || got.Passed != 5 || got.Failed != 0 {
		t.Fatalf("stats = %+v", got)
	}
}

func TestTheSealerIsSafeUnderConcurrentWrites(t *testing.T) {
	clock := newFakeClock()
	rec := &recordingPacketConn{}
	s := newSealer(t, rec, testKey(t, 0xa1), clock)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 32; j++ {
				d, err := buildInitiation(fleetProfile)
				if err != nil {
					t.Errorf("rand: %v", err)
					return
				}
				if _, err := s.WriteTo(d, &net.UDPAddr{}); err != nil {
					t.Errorf("WriteTo: %v", err)
					return
				}
				if _, err := s.WriteTo(transportDatagram(), &net.UDPAddr{}); err != nil {
					t.Errorf("WriteTo: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	got := s.Stats()
	if got.Sealed != 16*32 || got.Passed != 16*32 {
		t.Fatalf("stats = %+v", got)
	}
	for _, d := range rec.snapshot() {
		if len(d) != 164 && len(d) != 32 {
			t.Fatalf("a concurrent write produced a %d-byte datagram", len(d))
		}
	}
}

// The whole thing, over real sockets: a sealing client and an enforcing gate,
// with a prober sharing the client's address.
func TestASealingClientAndAnEnforcingGateInteroperateOverRealSockets(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	gate := newTestGate(t, clock, ModeRequire, Limits{}, key)

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer serverConn.Close()
	gated := gate.WrapPacketConn(serverConn)

	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer clientConn.Close()
	sealing := newSealer(t, clientConn, key, clock)

	target := serverConn.LocalAddr()

	// An unauthorised peer on a different socket sends a well-formed but
	// unsealed initiation first. It must be consumed and discarded.
	rogue, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rogue.Close()
	if _, err := rogue.WriteTo(makeInitiation(t, fleetProfile), target); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Then the real client's opening burst, through the sealer.
	burst := [][]byte{junkDatagram(27), junkDatagram(16), makeInitiation(t, fleetProfile)}
	for _, d := range burst {
		if _, err := sealing.WriteTo(d, target); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}
	// And three transport datagrams behind it.
	for i := 0; i < 3; i++ {
		if _, err := sealing.WriteTo(transportDatagram(), target); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}

	if err := gated.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 2048)

	// The gate delivers the sealed initiation first: the rogue's initiation and
	// the client's own junk were consumed on the way.
	n, _, err := gated.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 164 {
		t.Fatalf("first delivered datagram is %d bytes, want the 164-byte initiation", n)
	}
	// The body must be exactly what the engine handed the sealer. The prefix
	// cannot be predicted from outside — it is the tag, and it depends on the
	// time bucket — so it is verified by the gate having admitted it at all.
	if !bytes.Equal(buf[fleetProfile.S1:n], burst[2][fleetProfile.S1:]) {
		t.Fatal("the delivered initiation's body does not match what the engine handed the sealer")
	}
	if bytes.Equal(buf[:fleetProfile.S1], burst[2][:fleetProfile.S1]) {
		t.Fatal("the delivered initiation still carries the engine's random prefix, so nothing was sealed")
	}
	// Then the three transport datagrams, byte-transparent.
	for i := 0; i < 3; i++ {
		n, _, err := gated.ReadFrom(buf)
		if err != nil {
			t.Fatalf("transport read %d: %v", i, err)
		}
		if n != 32 {
			t.Fatalf("transport read %d is %d bytes, want 32", i, n)
		}
	}

	// Nothing was ever written back, to anybody.
	for name, c := range map[string]net.PacketConn{"client": clientConn, "rogue": rogue} {
		if err := c.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatalf("deadline: %v", err)
		}
		if n, _, err := c.ReadFrom(buf); err == nil {
			t.Fatalf("the gate answered %s with %d bytes", name, n)
		}
	}

	snap := gate.Snapshot()
	if snap.Counters.Authenticated != 1 || snap.Counters.Established != 3 {
		t.Fatalf("counters: %+v", snap.Counters)
	}
	if snap.Counters.Unauthenticated != 1 || snap.Counters.NoGrant != 2 {
		t.Fatalf("counters: %+v", snap.Counters)
	}
	if got := sealing.Stats(); got.Sealed != 1 || got.Passed != 5 {
		t.Fatalf("sealer stats: %+v", got)
	}
}

func TestSealDatagramServesHostsThatOwnTheirOwnBuffers(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	s := newSealer(t, &recordingPacketConn{}, key, clock)

	d := makeInitiation(t, fleetProfile)
	if err := s.SealDatagram(d); err != nil {
		t.Fatalf("SealDatagram: %v", err)
	}
	if _, err := Verify(d, [][]byte{key}, fleetProfile, clock.Now(), Options{}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := s.SealDatagram(transportDatagram()); !errors.Is(err, ErrNotAnInitiation) {
		t.Fatalf("err = %v, want ErrNotAnInitiation so the caller sends it unchanged", err)
	}
}
