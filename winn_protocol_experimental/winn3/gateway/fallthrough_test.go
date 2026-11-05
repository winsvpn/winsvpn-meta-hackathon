package gateway

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

// TestAForgedPacketAimedAtALiveTokenDoesNotSpendTheAdmissionBudget is the
// guard for the fall-through that Handle's own comment used to claim was
// already closed.
//
// Dispatch used to return ErrNoRoute for both a miss and an AEAD failure.
// Handle then treated every Dispatch error as "try the handshake path", so a
// stream of forgeries that copied the 8-byte demux token off a small transport
// datagram spent the admission budget without the session key. Silence tests
// did not catch it: they only assert Reply == nil, which was already true.
//
// The fixture Seal is a 3-byte payload. TransportOverhead is 26. That is well
// under MaxHandshakeMessage (1024), so without the guard these forgeries
// WOULD reach ReadInitiation. The length assertion below is what stops this
// test going green against a fixture that never took the expensive path.
func TestAForgedPacketAimedAtALiveTokenDoesNotSpendTheAdmissionBudget(t *testing.T) {
	cfg := silentCfg()
	cfg.AdmissionRate = 1
	cfg.AdmissionBurst = 1
	h := newRealHarness(t, cfg)
	c := h.newClient(t, 1, 4)

	if len(c.msgs[1]) < core.TransportOverhead() {
		t.Fatalf("fixture message is %d bytes, below TransportOverhead=%d; Dispatch would drop it on length",
			len(c.msgs[1]), core.TransportOverhead())
	}
	if len(c.msgs[1]) > core.MaxHandshakeMessage {
		t.Fatalf("fixture message is %d bytes, over MaxHandshakeMessage=%d; Handle would drop it on length before admission even without the guard, so this test would not be testing the fall-through",
			len(c.msgs[1]), core.MaxHandshakeMessage)
	}

	before := h.gw.Stats()
	if before.Unauthenticated != 0 || before.Throttled != 0 || before.Handshakes != 0 {
		t.Fatalf("precondition: stats=%+v; newClient registers via Table.Register, not Handle", before)
	}

	bad := append([]byte(nil), c.msgs[1]...)
	bad[len(bad)-1] ^= 0x01
	const n = 20
	for i := 0; i < n; i++ {
		mustBeSilent(t, h.gw.Handle(bad, []byte("forger"), h.clock()),
			"a forged copy of a live-token transport message")
	}

	after := h.gw.Stats()
	if after.Unauthenticated != 0 {
		t.Fatalf("Unauthenticated=%d after %d forgeries aimed at a live token; Handle fell through to admission. A censor who copied the 8-byte token off the wire does not need the session key to produce this stream.",
			after.Unauthenticated, n)
	}
	if after.Throttled != 0 {
		t.Fatalf("Throttled=%d after forgeries aimed at a live token; the admission budget was spent", after.Throttled)
	}
	if got := h.gw.Table().Stats().OpenFailed; got != n {
		t.Fatalf("OpenFailed=%d, want %d: the forgeries must be counted as AEAD failures, not as index misses", got, n)
	}

	// The genuine message still opens: a failed AEAD must not consume the token.
	if res := h.gw.Handle(c.msgs[1], []byte("real"), h.clock()); res.Kind != KindTransport {
		t.Fatalf("the genuine message was invalidated by the forgeries: %s", res.Kind)
	}

	// The burst is still full, so a fresh client can still handshake. If the
	// forgeries had spent the one-token burst this would be KindDropped.
	if res := h.gw.Handle(h.initiation(t), []byte("new-client"), h.clock()); res.Kind != KindHandshake {
		t.Fatalf("a fresh client could not handshake after the forgeries: %s (Throttled=%d Unauthenticated=%d)",
			res.Kind, h.gw.Stats().Throttled, h.gw.Stats().Unauthenticated)
	}
}

// TestDispatchReturnsErrSessionWhenTheTokenHitsButTheAEADFails pins the table
// half of the same distinction. Handle's guard is `!errors.Is(err, ErrNoRoute)`;
// if Dispatch collapsed openFailed back into ErrNoRoute this would go red
// even if Handle's branch were still present.
func TestDispatchReturnsErrSessionWhenTheTokenHitsButTheAEADFails(t *testing.T) {
	tbl := testTable(t, smallCfg())
	_, f := registerFake(t, tbl, 1)
	f.reject[0] = true

	_, _, err := tbl.Dispatch(f.message(0), fixedNow)
	if err == nil {
		t.Fatal("a session that refused the message was reported as dispatched")
	}
	if !errors.Is(err, ErrSession) {
		t.Fatalf("openFailed returned %v, want ErrSession; ErrNoRoute here is what made Handle fall through to admission", err)
	}
	if errors.Is(err, ErrNoRoute) {
		t.Fatal("openFailed wrapped or equalled ErrNoRoute; Handle would treat it as a miss")
	}
	if got := tbl.Stats().OpenFailed; got != 1 {
		t.Fatalf("OpenFailed=%d, want 1", got)
	}
	if got := tbl.Stats().Missed; got != 0 {
		t.Fatalf("Missed=%d, want 0: an AEAD failure is not an index miss", got)
	}

	// A genuine miss is still ErrNoRoute, so Handle can still find initiations.
	noise := make([]byte, fakeMsgLen)
	for i := range noise {
		noise[i] = 0xA5
	}
	_, _, miss := tbl.Dispatch(noise, fixedNow)
	if !errors.Is(miss, ErrNoRoute) {
		t.Fatalf("a miss returned %v, want ErrNoRoute", miss)
	}
	if errors.Is(miss, ErrSession) {
		t.Fatal("a miss wrapped ErrSession; Handle would not try the handshake path")
	}
}

// TestAnEmptySourceSharesOneCellRatherThanBeingExempt pins the conservative
// answer in sourceGuard.allow. A carrier that cannot name its peer passes a
// nil or empty src. Treating that as unmetered would be an exemption any
// flooder could take by omitting the name; sharing one cell spends the
// per-source budget and leaves named sources alone.
func TestAnEmptySourceSharesOneCellRatherThanBeingExempt(t *testing.T) {
	cfg := silentCfg()
	cfg.AdmissionRate = 100000
	cfg.AdmissionBurst = 100000
	cfg.SourceRate = 3
	cfg.SourceBurst = 3
	h := newRealHarness(t, cfg)

	noise := make([]byte, 400)
	if _, err := rand.Read(noise); err != nil {
		t.Fatalf("rand: %v", err)
	}
	for i := 0; i < 20; i++ {
		binary.BigEndian.PutUint64(noise, uint64(i))
		h.gw.Handle(noise, nil, h.clock())
	}
	if got := h.gw.Stats().Unauthenticated; got > 3 {
		t.Fatalf("nil source got %d admission checks from a 3-token cell; an empty source must not be an exemption", got)
	}
	if got := h.gw.Stats().Unauthenticated; got == 0 {
		t.Fatal("nil source never reached admission; this test is not measuring the cell")
	}

	before := h.gw.Stats().Unauthenticated
	h.gw.Handle(noise, []byte("named"), h.clock())
	if h.gw.Stats().Unauthenticated == before {
		t.Fatal("a named source was throttled by the empty-source cell")
	}

	// Empty slice and nil must share the cell: both are "unknown".
	h2 := newRealHarness(t, cfg)
	for i := 0; i < 3; i++ {
		binary.BigEndian.PutUint64(noise, uint64(i))
		h2.gw.Handle(noise, nil, h2.clock())
	}
	afterNil := h2.gw.Stats().Unauthenticated
	h2.gw.Handle(noise, []byte{}, h2.clock())
	if h2.gw.Stats().Unauthenticated != afterNil {
		t.Fatalf("an empty slice got its own admission check (Unauthenticated %d → %d); it must share the unknown cell with nil",
			afterNil, h2.gw.Stats().Unauthenticated)
	}
}
