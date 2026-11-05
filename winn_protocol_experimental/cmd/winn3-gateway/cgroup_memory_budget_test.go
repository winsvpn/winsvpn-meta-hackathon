package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
)

// The installer (wins_winn3_gateway_install.sh derive_gateway_memory) bills
//
//	MemoryMax  = installerBaseKiB + installerSessionKiB * WINN3_GATEWAY_MAX_SESSIONS
//	MemoryHigh = 75% of MemoryMax
//	GOMEMLIMIT = 80% of MemoryHigh = 60% of MemoryMax
//
// GOMEMLIMIT is the binding term: Go does not read cgroup limits, so live heap
// above GOMEMLIMIT makes the collector run continuously, and live memory above
// MemoryHigh makes the kernel throttle reclaim. Both present as datapath
// silence. The limits are therefore judged against AGGREGATE live memory at
// the configured session count, not against one session and MemoryMax.
const (
	// installerBaseKiB moved from 96 to 208 MiB on 2026-10-10 with the
	// inbox deepening to gatewayTokenWindow/4 = 8192: four retiring
	// sessions bill 67.6 MiB (fixed 0.65 + inbox 16.25 each) to the base,
	// and the aggregate check at n=1 (153.9 MiB adversarial live) needs a
	// 163.2 MiB GOMEMLIMIT, which a 208 MiB base plus the 64 MiB session
	// term reaches. The Pipe's slabs allocate to the high water, so this is
	// the adversarial cgroup bound, not the typical cost.
	installerBaseKiB = 208 * 1024
	// installerSessionKiB moved from 40 to 64 MiB the same day: the
	// measured adversarial per-session bill became 38,764,032 B (36.97 MiB:
	// send queue 16.75, inbox 16.25, windows 3.31, fixed 0.65), which
	// needs a 61.7 MiB term at the 60% GOMEMLIMIT ratio. The data-plane
	// installer's derive_gateway_memory max_kib term and the host-fit
	// constants move with it (this file's pin reads that file).
	installerSessionKiB = 64 * 1024
)

// sharedLiveBytes is the process-wide live memory that does not scale with
// sessions: the demux admission queues at full occupancy (two sides of
// demuxChanDepth buffers of demuxBufferCapacity), the recvmmsg staging slots,
// and the process base. The base is MEASURED, not derived: the L12 v2 rig
// (Linux 6.8, arm64, cover listener and forward device on) read 11.0 to 11.4
// MiB RSS and 3.5 MiB heap in use with zero sessions; 16 MiB is that plus
// headroom.
func sharedLiveBytes(messageSize int) int {
	const processBase = 16 << 20
	buf := demuxBufferCapacity(messageSize)
	return demuxSideCount*demuxChanDepth*buf + demuxBatchSize*buf + processBase + asyncTunWriteBill()
}

// sessionBill is the per-session live-memory bill at adversarial occupancy.
// Every term is tied to the constant production uses, and the allocation
// behaviour behind each one is measured by the tests below rather than
// assumed.
type sessionBill struct {
	sendQueue int // gatewaySendQueue pooled slabs + the queue's slice backing
	windows   int // two token windows: the modeled transition allowance
	inbox     int // the configured inbox depth's pooled pipe slabs + their headers
	fixed     int // pipe, loop, device and goroutine stacks, measured
	asyncSub  int // -forward-async-write: the slab a submit blocked on a full queue holds
	sendFQ    int // -send-queue-fq: the flow queues' own storage (session.SendFQBytes)
}

func (b sessionBill) total() int {
	return b.sendQueue + b.windows + b.inbox + b.fixed + b.asyncSub + b.sendFQ
}

// windowBytes is one installed token window at the upper measured cost.
// index.go measured map entries at 37.5 to 51.8 B per token; consumed is one
// byte per counter. L12 v2 measured 37.1 B per token live at 65536
// (2,430,464 B in use after collection), so 52 + 1 is an upper bound.
func windowBytes() int { return gatewayTokenWindow*52 + gatewayTokenWindow }

func billFor(fixed int) sessionBill {
	sliceHdr := int(unsafe.Sizeof([]byte(nil)))
	timeSz := int(unsafe.Sizeof(time.Time{}))
	return sessionBill{
		// appendQueuedData grows the live slice by append, so its backing can
		// reach twice the live length before compaction reuses it. The
		// enqueue-time ring (sendqueue_codel.go) mirrors that storage and
		// bills the same way: one time.Time per queued packet, doubled.
		sendQueue: gatewaySendQueue*session.DataBufferSlabBytes + 2*gatewaySendQueue*(sliceHdr+timeSz),
		// core.installEpoch wipes the old window before building the new one,
		// but the old map is garbage until the next collection, and
		// admitReinitiation holds the old session live until the new response
		// is written. Two windows is the MODELED transition allowance for
		// those paths, not a bound on uncollected allocation in general: how
		// much garbage exists between collections depends on the collector.
		windows: 2 * windowBytes(),
		// One inbox slot (carrier.PipeSlotBytes: the slab pointer and the
		// admission time) + slice header + 2 KiB slab, at the depth
		// newSession builds (-uplink-inbox-depth, owner ruling 2026-10-10).
		inbox:    (&server{}).pipeInboxDepth() * (carrier.PipeBufferSlabBytes + carrier.PipeSlotBytes + sliceHdr),
		fixed:    fixed,
		asyncSub: asyncSubmitSessionBill,
		// Billed whether or not -send-queue-fq is on, which only makes the
		// bill larger; the slabs it orders are already in sendQueue.
		sendFQ: session.SendFQBytes(gatewaySendQueue),
	}
}

func totalAlloc() uint64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.TotalAlloc
}

func liveHeapAndStack() (heap, stack uint64) {
	runtime.GC()
	runtime.GC() // a second cycle empties the sync.Pool victim caches
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse, ms.StackInuse
}

// measureFixedPerSession builds k real peer sessions through server.newSession
// (pipe, driver loop, reflector device, goroutines) and returns the live heap
// plus stack each one costs before any handshake. No token window exists yet:
// that is allocated only after an authenticated initiation (see
// TestAnUnauthenticatedInitiationAllocatesNoTokenWindow).
func measureFixedPerSession(t *testing.T, k int) int {
	t.Helper()
	live, _ := measureFixedPerSessionAlloc(t, k)
	return live
}

// measureFixedPerSessionAlloc also returns the CUMULATIVE allocation
// (MemStats.TotalAlloc) per session, which counts garbage too: a window built
// and discarded shows here even though it leaves no live heap.
func measureFixedPerSessionAlloc(t *testing.T, k int) (live, alloc int) {
	t.Helper()
	srv, _ := newTestServer(t, k)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h0, s0 := liveHeapAndStack()
	a0 := totalAlloc()
	var sessions []*peerSession
	for i := 0; i < k; i++ {
		ps, err := srv.newSession(ctx, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(41000+i)))
		if err != nil {
			t.Fatalf("newSession %d: %v", i, err)
		}
		sessions = append(sessions, ps)
	}
	a1 := totalAlloc()
	h1, s1 := liveHeapAndStack()
	for _, ps := range sessions {
		ps.close()
	}
	return int((h1 - h0 + s1 - s0) / uint64(k)), int((a1 - a0) / uint64(k))
}

// TestInstallerSessionMemoryBudgetStillCoversAdversarialSession pins the
// installer's per-session and base terms against the production session
// shape in this binary, at the REAL configured send queue
// (gatewaySendQueue), the real token window (gatewayTokenWindow) and the
// real inbox (the configured -uplink-inbox-depth, server.pipeInboxDepth), and
// against aggregate live memory.
//
// It used to bill session.DefaultSendQueue (256) while production set
// SendQueue to 65536: a green that described a session production never
// built. The send-queue term is now the production constant, and
// TestTheSendQueueAllocatesLazilyAndAsBilled measures that the queue
// allocates exactly as this term assumes.
func TestInstallerSessionMemoryBudgetStillCoversAdversarialSession(t *testing.T) {
	pinNewSessionPipeDerivesDepthFromTheTokenWindow(t)
	pinInstallerDeriveGatewayMemoryFormula(t)

	sizing := productionSizing(t)
	fixed := measureFixedPerSession(t, 16)
	bill := billFor(fixed)
	perSession := installerSessionKiB * 1024
	t.Logf("per-session bill %d B (%.2f MiB): send queue %d, windows %d, inbox %d, fixed %d (measured); term %d B",
		bill.total(), mib(bill.total()), bill.sendQueue, bill.windows, bill.inbox, bill.fixed, perSession)

	// GOMEMLIMIT is 60% of MemoryMax, so the per-session term must carry the
	// per-session bill at that ratio, or aggregate live memory crosses
	// GOMEMLIMIT as sessions are added whatever the base is.
	if need := bill.total() * 10 / 6; perSession < need {
		t.Fatalf("installer per-session term %d B is below %d B, the per-session bill divided by the "+
			"60%% GOMEMLIMIT ratio. Raise installerSessionKiB and derive_gateway_memory together.",
			perSession, need)
	}

	// The session table may hold up to retirementAllowance sessions that have
	// been removed from the peer map and reclaimed but whose Loop.Run has not yet
	// returned. RetireIfQuiet (Driver.terminate) wipes the token window and the
	// send queue, but it does NOT close the separately owned carrier pipe, whose
	// inbox slabs are released only when releasePeer closes the pipe after
	// teardown. So a retiring session retains its fixed term AND its inbox until
	// teardown completes. That population does not scale with n, so it is billed
	// once against the base term, exactly as the shared process memory is.
	retirePer := bill.fixed + bill.inbox
	retire := retirementAllowance * retirePer
	shared := sharedLiveBytes(sizing.MessageSize) + retire
	t.Logf("retirement allowance %d * (fixed %d + inbox %d) = %d B (%.2f MiB) of retiring sessions, billed to the base",
		retirementAllowance, bill.fixed, bill.inbox, retire, mib(retire))
	for _, n := range []int{1, 2, 8, 64, 256, 1024} {
		maxBytes := (installerBaseKiB + installerSessionKiB*n) * 1024
		highBytes := maxBytes * 75 / 100
		gomem := highBytes * 80 / 100
		live := shared + n*bill.total()
		if live > gomem {
			t.Errorf("at %d sessions aggregate adversarial live memory is %d B (%.1f MiB) but GOMEMLIMIT is "+
				"%d B (%.1f MiB): the collector would run continuously below MemoryHigh %d B",
				n, live, mib(live), gomem, mib(gomem), highBytes)
		}
		t.Logf("n=%d: live %.1f MiB, GOMEMLIMIT %.1f MiB, MemoryHigh %.1f MiB, MemoryMax %.1f MiB",
			n, mib(live), mib(gomem), mib(highBytes), mib(maxBytes))
	}
}

// TestTheSendQueueAllocatesLazilyAndAsBilled establishes a production gateway
// session and fills its send queue to the configured bound. The queue
// allocates LAZILY: an established idle session holds no slabs, and filling
// it allocates one pooled 2 KiB slab per queued packet, which is what the
// send-queue term bills. If the queue allocated eagerly the fill would cost
// nothing; if it allocated per inner-MTU it would cost about two thirds.
func TestTheSendQueueAllocatesLazilyAndAsBilled(t *testing.T) {
	p := newProductionDriverPair(t, nil)
	inner := bytes.Repeat([]byte{0x45}, session.InnerMTU(productionSizing(t).MessageSize))
	h0, _ := liveHeapAndStack()
	queued := 0
	for {
		if err := p.gw.Enqueue(inner); err != nil {
			break
		}
		queued++
		if queued > 2*gatewaySendQueue {
			t.Fatal("the gateway send queue accepted more than twice gatewaySendQueue; it is not bounded by it")
		}
	}
	if queued != gatewaySendQueue {
		t.Fatalf("the gateway send queue filled at %d packets; production configures %d", queued, gatewaySendQueue)
	}
	h1, _ := liveHeapAndStack()
	grew := int(h1 - h0)
	slabs := gatewaySendQueue * session.DataBufferSlabBytes
	t.Logf("filling %d packets grew live heap by %d B (%.2f MiB); slabs alone are %d B; the term bills %d B",
		queued, grew, mib(grew), slabs, billFor(0).sendQueue)
	if grew < slabs*9/10 {
		t.Fatalf("filling the queue grew live heap by %d B, less than 90%% of %d slab bytes: the queue does "+
			"not allocate as billed (eager, or smaller slabs), so the send-queue term is not measured", grew, slabs)
	}
	if grew > billFor(0).sendQueue {
		t.Fatalf("filling the queue grew live heap by %d B, above the %d B send-queue term", grew, billFor(0).sendQueue)
	}
	runtime.KeepAlive(p)
}

// TestAnEpochTransitionRetainsOneTokenWindow forces an in-band rekey through
// the production session path and checks that, once collected, the session
// holds ONE window: the previous epoch's window is released, so the two
// windows the bill carries are a transient, never a steady state.
func TestAnEpochTransitionRetainsOneTokenWindow(t *testing.T) {
	p := newProductionDriverPair(t, func(c *session.Config) { c.RekeyAfterMessages = 4096 })
	payload := bytes.Repeat([]byte{0x45}, 600)
	h0, _ := liveHeapAndStack()
	epoch := p.gw.Epoch()
	for sent := 0; p.gw.Epoch() == epoch || p.cli.Epoch() != p.gw.Epoch(); sent++ {
		if sent > 4*4096 {
			t.Fatalf("no rekey completed within %d messages of a 4096-message trigger", sent)
		}
		_ = p.cli.Enqueue(payload)
		p.exchange()
		p.clk.t = p.clk.t.Add(10_000)
	}
	p.settle("rekey confirmation", func() bool {
		return p.cli.State() == session.StateEstablished && p.gw.State() == session.StateEstablished
	})
	h1, _ := liveHeapAndStack()
	delta := int(h1) - int(h0)
	t.Logf("after rekey %d -> %d: live heap moved %d B; one window is %d B upper", epoch, p.gw.Epoch(), delta, windowBytes())
	// Both ends rebuilt their windows. Retaining the previous epoch's window
	// on either end would add a whole window per end.
	if delta > windowBytes()/2 {
		t.Fatalf("live heap grew by %d B across one rekey; a retained previous-epoch window (%d B) is "+
			"the only thing that size", delta, windowBytes())
	}
}

// TestAnUnauthenticatedInitiationAllocatesNoTokenWindow sends
// unauthenticated initiations from many source addresses to a real server:
// each passes the admission tag (the readLoop screen admits only those) and
// is sealed to a gateway static key that is not this one, so ReadInitiation
// refuses it at the static-key decryption. Each address buys the half-open
// session (pipe, loop, device), which
// is bounded by -max-sessions, but no token window: core builds a window only
// in newSession, which only ResponderHandshake.WriteResponse and
// Initiator.ReadResponse reach, after the admission tag, the replay cache,
// the static-key decryption, the registry Accept and the payload decryption
// have all passed.
//
// Two checks. Live heap: no window-sized retained growth. Cumulative
// allocation (MemStats.TotalAlloc, which counts garbage): no window was built
// even briefly, since one build allocates about 37 B per token. A mutant that
// builds and discards a window at the top of ReadInitiation turns the second
// check red (L12 v3, recorded in the report).
func TestAnUnauthenticatedInitiationAllocatesNoTokenWindow(t *testing.T) {
	const peers = 32
	srv, gwAddr := newTestServer(t, peers)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readDone := make(chan error, 1)
	h0, _ := liveHeapAndStack()
	go func() { readDone <- srv.readLoop(ctx) }()
	defer func() {
		_ = srv.conn.SetReadDeadline(timeNow())
		<-readDone
		srv.closeAll()
	}()
	junk := make([][]byte, peers)
	for i := range junk {
		junk[i] = admissibleForeignInitiation(t, srv.sessionCfg)
	}
	a0 := totalAlloc()
	for i := 0; i < peers; i++ {
		c := dialLoopback(t, gwAddr)
		if _, err := c.Write(junk[i]); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 10*time.Second, "every junk sender holds a half-open session", func() bool {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		return len(srv.peers) == peers
	})
	waitFor(t, 10*time.Second, "every half-open session refused its junk initiation", func() bool {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		for _, ps := range srv.peers {
			if ps.loop.Session().Stats().Unopenable == 0 {
				return false
			}
		}
		return true
	})
	a1 := totalAlloc()
	h1, _ := liveHeapAndStack()
	per := (int(h1) - int(h0)) / peers
	perAlloc := int(a1-a0) / peers
	fixed, fixedAlloc := measureFixedPerSessionAlloc(t, peers)
	// One window build allocates at least 30 B per token (37 measured).
	windowAllocFloor := gatewayTokenWindow * 30
	t.Logf("cumulative allocation: %d B per junk initiation, %d B per session before any handshake; "+
		"a window build is at least %d B", perAlloc, fixedAlloc, windowAllocFloor)
	if perAlloc >= fixedAlloc+windowAllocFloor/2 {
		t.Fatalf("an unauthenticated initiation allocated %d B cumulatively, %d B more than a session before "+
			"any handshake: at least half a token-window build (%d B). A window is being constructed before "+
			"authentication", perAlloc, perAlloc-fixedAlloc, windowAllocFloor)
	}
	t.Logf("%d unauthenticated half-open sessions: %d B live heap each; a session before any handshake is %d B; "+
		"one token window is %d B", peers, per, fixed, windowBytes())
	// The pre-handshake session is the baseline, so it must itself hold no
	// window: a construction path that built one eagerly would move both
	// numbers together and pass the comparison below.
	if fixed >= windowBytes() {
		t.Fatalf("a session before any handshake already costs %d B, a whole token window (%d B) or more",
			fixed, windowBytes())
	}
	if per >= fixed+windowBytes()/2 {
		t.Fatalf("an unauthenticated initiation cost %d B of live heap: the %d B of a session before any "+
			"handshake plus at least half a token window (%d B)", per, fixed, windowBytes())
	}
	for _, ps := range srv.peers {
		if ps.loop.Session().Epoch() != 0 || ps.loop.Established() {
			t.Fatal("an unauthenticated initiation produced an established session")
		}
	}
}

func mib(b int) float64 { return float64(b) / float64(1<<20) }

func timeNow() time.Time { return time.Now() }

func productionSizing(t *testing.T) driver.Sizing {
	t.Helper()
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	return sizing
}

func dialLoopback(t *testing.T, to *net.UDPAddr) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp4", nil, to)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// pinInstallerDeriveGatewayMemoryFormula fails this file unless the installer
// still contains the session-derived assignments this budget test bills.
// A comment that "the installer uses N MiB" with no read of the script is
// the false-green this pin exists to close.
func pinInstallerDeriveGatewayMemoryFormula(t *testing.T) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// The formula moved from the retired unit installer into the data-plane
	// installer's derive_gateway_memory (found there 2026-10-10, tunnel-speed
	// round 2), so this pin follows it there.
	install := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "server", "wins_data_plane_setup_ONETOUCH.sh"))
	body, err := os.ReadFile(install) //nolint:gosec // test pin of a repo path
	if err != nil {
		t.Fatalf("read installer %s: %v", install, err)
	}
	needles := []string{
		fmt.Sprintf("max_kib=$((%d * 1024 + %d * n))", installerBaseKiB/1024, installerSessionKiB),
		"high_kib=$((max_kib * 75 / 100))",
		"gomem_bytes=$((high_kib * 1024 * 80 / 100))",
	}
	for _, n := range needles {
		if !bytes.Contains(body, []byte(n)) {
			t.Errorf("%s is missing %q; derive_gateway_memory drifted from the %d MiB base / %d MiB per session / "+
				"75%% High / 80%%-of-High GOMEMLIMIT formula this test bills",
				install, n, installerBaseKiB/1024, installerSessionKiB/1024)
		}
	}
	// 80% of MemoryMax is above MemoryHigh (75% of Max). That assignment
	// recreates the stall this product treats as worst-case.
	if bytes.Contains(body, []byte("gomem_bytes=$((max_kib * 1024 * 80 / 100))")) {
		t.Errorf("%s sets GOMEMLIMIT to 80%% of MemoryMax, which sits above MemoryHigh", install)
	}
	// TUNNEL-SPEED-2 Turn 9: a dedicated VPN node (the data-plane default)
	// carries no cgroup cap and keeps GOMEMLIMIT as a soft target no lower
	// than the formula's figure, so the aggregate check above still bounds
	// the collector's behaviour there. The pin reads the branch itself.
	dedicated := []string{
		`WINN3_GATEWAY_DEDICATED="${WINN3_GATEWAY_DEDICATED-1}"`,
		`WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX="infinity"`,
		`WINN3_GATEWAY_EFFECTIVE_MEMORY_HIGH="infinity"`,
		`if (( cap_bytes > gomem_bytes )); then`,
	}
	for _, n := range dedicated {
		if !bytes.Contains(body, []byte(n)) {
			t.Errorf("%s is missing %q; the dedicated-node memory mode (no cgroup cap, GOMEMLIMIT no lower than "+
				"the formula) drifted", install, n)
		}
	}
}
