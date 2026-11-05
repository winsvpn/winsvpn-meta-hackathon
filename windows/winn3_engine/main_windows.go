// SPDX-License-Identifier: MIT
//
// The default relay is described below. --in-process-candidate instead runs
// the Winn client and direct Wintun device together, before any relay socket
// is created. Its distinct control protocol is documented in direct_windows.go.
// The existing supervisor does not select this study candidate.
//
// The Windows tun relay for Winn Protocol v3.
//
// # What this binary is, in one paragraph
//
// It owns the Wintun adapter and moves RAW INNER IP PACKETS between that
// adapter and cmd/winn-datapath's loopback seam. It performs no cryptography,
// holds no key material, makes no routing decision and never touches the
// network. Encapsulation happens BELOW it, in the v3 carrier inside
// winn-datapath; route and address posture happens ABOVE it, in the privileged
// tunnel service. This process is the middle, and the middle is deliberately
// thin.
//
// # What it replaces, and why the replacement is not optional
//
// Today windows/awg_engine owns the one and only Wintun adapter. It is
// AmneziaWG: it reads inner IP packets off the adapter, ENCRYPTS them itself,
// and emits AmneziaWG outer datagrams, which windows_winn_engine.cpp then
// relays to winn-datapath as payload class "awg-datagram" for the v1 datapath
// to forward. Winn Protocol v3 is a STANDALONE protocol -- its own handshake,
// AEAD, rekey and framing -- and winn3/core IS the cryptography. There is no
// AmneziaWG anywhere beneath it. So under v3 the adapter must hand over inner
// packets in the clear to the layer that encrypts them, and that layer is
// winn-datapath, not AmneziaWG.
//
// Getting this backwards is the one mistake on this boundary that puts
// CLEARTEXT ON THE WIRE, so it is worth stating both directions explicitly:
//
//	inner packets -> a v1 (awg-datagram) engine  = cleartext to the gateway
//	AWG datagrams -> a v3 (ip-packet)   engine  = double encryption, all dropped
//
// The device kind in the winn-datapath profile is what keeps them apart, and
// neither engine accepts the other's payload class. This binary must be paired
// ONLY with `winn-datapath -winn3-profile` carrying `device.kind: loopback-udp`.
//
// # Why the cleartext leg over loopback is not a leak
//
// The containment is STRUCTURAL rather than a policy anyone has to enforce: a
// socket bound to 127.0.0.1 has no route off the device. This tree already
// rests on that argument five times -- Android's WinnAwgLoopbackSeam,
// internal/carrier.RelayLocalUDP, the Apple wrapper's seam, the Xray
// transport's loopback pin, and BindLinuxWinnSeam. This is the same shape
// rather than a new one. The seam additionally PINS ITS PEER: datagrams from
// any address other than the engine's own loopback port are counted and
// dropped, because a loopback port is otherwise writable by any unprivileged
// process on the machine and an unpinned seam would let one inject inner
// packets into somebody else's tunnel.
//
// # No configuration on the command line
//
// windows/awg_engine refuses to start with any argument at all, so that a
// compromised or confused caller cannot point it somewhere. This binary keeps
// that property: it takes no arguments and receives its two parameters on
// stdin, from the privileged service that already owns the pipe. The engine's
// loopback port is not knowable until winn-datapath has started, and
// winn-datapath cannot start until it knows this relay's port, so a control
// exchange is required regardless -- there is nothing to be gained by also
// having a command line.
//
// # Ordering, and the fail-closed property it buys
//
//	1. relay binds 127.0.0.1:0            -> prints "host-port <P>"
//	2. service starts winn-datapath with device.host_port = P
//	3. winn-datapath prints its ephemeral port on stderr
//	4. service writes "start mtu=<M> engine-port=<E>" to this relay's stdin
//	5. relay creates the Wintun adapter    -> prints "ready ..."
//	6. service installs the BOOTSTRAP posture on it: one /32, the inner next
//	   hop only, MTU = M, no default route, no IPv6, no DNS
//	7. service promotes only when winn-datapath's status document reports
//	   promotion_ready, which is gate == carrying AND rx_packets > 0
//
// THE ADAPTER DOES NOT EXIST UNTIL STEP 5. That is the property this ordering
// is for: there is no window in which Windows can have an interface it might
// route traffic to before the seam beneath it is wired to a running v3 engine.
// The relay cannot enforce steps 6 and 7 -- it has no route authority and
// deliberately never reads the status document -- but it can and does refuse to
// create an adapter at all until the layer that encrypts is reachable.
//
// # UNPROVEN ON REAL WINDOWS HARDWARE -- read before believing runtime claims
//
// Everything above this line and the code below it type-checks and cross-compiles
// for windows/amd64 and windows/arm64, and NOTHING beyond that has been verified
// on a real Windows host. The whole runtime envelope this relay exists for has
// never been executed on Windows:
//
//   - the v3 relay itself (this binary, the Wintun adapter it creates at step 5,
//     and both pumps in relay.go) has never carried a single packet on Windows;
//   - the datapath runtime seam between this relay and cmd/winn-datapath has never
//     transferred an inner packet on Windows;
//   - the route PIN (the outer-socket /32 and the bootstrap posture the privileged
//     service installs at step 6) has never been installed on a real Windows
//     routing table;
//   - PROMOTION (step 7, the gate == carrying AND rx_packets > 0 predicate) has
//     never promoted a real Windows adapter from bootstrap to carrying posture;
//   - the full POSTURE (default route, DNS, IPv6 gating) has never been applied to
//     a Windows interface.
//
// The closest existing evidence is the cross-compile script's own disclaimer --
// tools/build_windows_tunnel_service_xcompile.sh ends with:
//
//	COMPILED AND LINKED, NOT EXECUTED: no Windows hardware of either
//	architecture ran either binary. No privileged runtime behavior (route
//	pinning, service install, AWG interop) was exercised.
//
// That is still true of this relay and winn3_supervisor's route-pin/promotion/
// posture path. A green GOOS=windows go vet ./winn3_engine ./awg_engine is
// PROOF OF TYPE-CHECKING ONLY. It says the Windows branch compiles; it says
// nothing about whether the route pin, promotion, or posture work at runtime on
// real Windows hardware. Treat every runtime claim about Windows as unverified
// until a real Windows/ARM64 host has run the relay to carrying and back.

package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const (
	// adapterName is deliberately NOT windows/awg_engine's "winsvpn". The two
	// binaries must never be able to open each other's adapter: one carries
	// inner packets to a layer that encrypts them and the other carries inner
	// packets to a layer that already did, and a name collision would make that
	// difference a race rather than a refusal.
	adapterName = "winsvpn3"

	// tunnelType is shared with the sibling on purpose -- it is the Wintun
	// "pool" that keeps our adapters distinct from unrelated ones on the
	// machine, not a per-binary identifier.
	tunnelType = "WinsVPN"

	// stopEventName mirrors the sibling's, with this binary's own name in it.
	stopEventName = `Global\WinsVPN.Winn3Engine.Stop.v1`

	// ringCapacity is 4 MiB per direction. Wintun requires a power of two
	// between RingCapacityMin (128 kiB) and RingCapacityMax (64 MiB). At the
	// 1139-byte inner MTU this is roughly 3,600 packets of slack, which absorbs
	// a scheduler hiccup without letting a stalled seam grow the process
	// without bound.
	ringCapacity = 0x400000

	// pumpQuiesceTimeout bounds how long shutdown waits for both pumps to be
	// out of the Wintun ring before it gives up on freeing that ring by hand.
	//
	// Every way a pump can block is woken explicitly by the shutdown sequence
	// in main, so this should never elapse. It exists because the alternative
	// to a bound is a LocalSystem process that hangs forever holding an
	// adapter, and because the fallback is safe: the ring is simply left to
	// process exit, which is what released it before this ordering existed.
	// It is deliberately well under winn3_supervisor.cpp's kChildStopWaitMs
	// (5000 ms), so the drop accounting below still reaches the supervisor
	// before it stops waiting and terminates the job.
	pumpQuiesceTimeout = 2 * time.Second
)

func runningAsLocalSystem() bool {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return false
	}
	systemSID, err := windows.StringToSid("S-1-5-18")
	return err == nil && user.User.Sid.Equals(systemSID)
}

// createStopEvent mirrors windows/awg_engine's, including the refusal when the
// event already exists: a second instance of this relay would open a second
// adapter and the two would fight over the same seam.
func createStopEvent() (windows.Handle, bool) {
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)",
	)
	if err != nil {
		return 0, false
	}
	name, err := windows.UTF16PtrFromString(stopEventName)
	if err != nil {
		return 0, false
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, createErr := windows.CreateEvent(&attributes, 1, 0, name)
	if handle == 0 || createErr == windows.ERROR_ALREADY_EXISTS {
		if handle != 0 {
			windows.CloseHandle(handle)
		}
		return 0, false
	}
	if createErr != nil {
		windows.CloseHandle(handle)
		return 0, false
	}
	return handle, true
}

func main() {
	// Opt-in frame self-test. It runs BEFORE everything else -- before the seam
	// binds, before the adapter exists, and before the LocalSystem strictness
	// below -- so an unprivileged "winsvpnwinn3engine.exe --selftest" proves the
	// binary's framing conformance without touching a Wintun adapter or needing
	// to run as LocalSystem. Nothing else on the command line is recognised,
	// preserving the relay's "no arguments" property. See selftest.go.
	if len(os.Args) == 2 && (os.Args[1] == "--selftest" || os.Args[1] == "-selftest") {
		if err := runSelfTest(); err != nil {
			fmt.Fprintln(os.Stderr, "winn3-relay selftest: "+err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}

	// The direct candidate is explicit and retains the same privilege and
	// singleton boundary. No argument can select a profile, endpoint or key.
	directCandidate := len(os.Args) == 2 && os.Args[1] == "--in-process-candidate"
	if (len(os.Args) != 1 && !directCandidate) || !runningAsLocalSystem() {
		os.Exit(2)
	}
	stopEvent, ok := createStopEvent()
	if !ok {
		os.Exit(3)
	}
	defer windows.CloseHandle(stopEvent)
	if directCandidate {
		if err := runDirectCandidate(stopEvent); err != nil {
			fmt.Fprintln(os.Stderr, "winn3-direct: candidate stopped")
			os.Exit(10)
		}
		return
	}

	out := bufio.NewWriter(os.Stdout)
	fail := func(code int, format string, args ...any) {
		fmt.Fprintf(os.Stderr, "winn3-relay: "+format+"\n", args...)
		_ = out.Flush()
		os.Exit(code)
	}

	// Step 1: bind our half of the seam BEFORE anything else exists. Binding
	// first means winn-datapath's first inner packets queue in a receive buffer
	// instead of drawing ICMP port-unreachable while this relay is still
	// creating an adapter -- the same reason BindWindowsWinnSeam binds before
	// the AmneziaWG configuration is written.
	seam, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: 0,
	})
	if err != nil {
		fail(4, "bind loopback seam: %v", err)
	}
	defer func() { _ = seam.Close() }()
	const seamBufferBytes = 4 * 1024 * 1024
	if err := seam.SetReadBuffer(seamBufferBytes); err != nil {
		fail(4, "configure loopback seam receive buffer: %v", err)
	}
	if err := seam.SetWriteBuffer(seamBufferBytes); err != nil {
		fail(4, "configure loopback seam send buffer: %v", err)
	}
	hostPort := seam.LocalAddr().(*net.UDPAddr).Port
	fmt.Fprintf(out, "host-port %d\n", hostPort)
	if err := out.Flush(); err != nil {
		fail(4, "report host port: %v", err)
	}

	// Steps 2-4: wait for the service to tell us the engine's port and the
	// inner MTU it published. Until this arrives there is no adapter.
	control := bufio.NewScanner(os.Stdin)
	if !control.Scan() {
		fail(5, "stdin closed before a start command arrived")
	}
	cmd, err := parseStartCommand(control.Text())
	if err != nil {
		fail(5, "%v", err)
	}
	peer := netip.AddrPortFrom(
		netip.AddrFrom4([4]byte{127, 0, 0, 1}),
		//nolint:gosec // bounded by parseStartCommand
		uint16(cmd.enginePort),
	)

	// Step 5: now, and not before, create the adapter. The tunnel type is a
	// parameter of this call in golang.zx2c4.com/wintun -- amneziawg-go's
	// wrapper exposes it as the package-level tun.WintunTunnelType instead, and
	// reaching for that spelling here does not compile.
	adapter, err := wintun.CreateAdapter(adapterName, tunnelType, nil)
	if err != nil {
		fail(6, "create Wintun adapter %q: %v", adapterName, err)
	}

	session, err := adapter.StartSession(ringCapacity)
	if err != nil {
		fail(7, "start Wintun session: %v", err)
	}

	// THERE IS DELIBERATELY NO `defer session.End()` AND NO
	// `defer adapter.Close()` HERE, and neither is an omission.
	//
	// Freeing the ring is not something that may happen at an arbitrary point
	// in this function's unwind: it is only safe once both pumps are provably
	// out of it, which is a condition only the shutdown sequence at the bottom
	// of main can establish. See the ordering comment there. A deferred End()
	// would also have run a SECOND time on top of the explicit one -- End() has
	// a value receiver, so the handle it zeroes is a copy and the caller's
	// handle is passed to WintunEndSession twice. Every path out of this
	// function other than that sequence is os.Exit via fail(), which runs no
	// defers and leaves the adapter to process exit, exactly as before.

	// The LUID is how the privileged service addresses this interface when it
	// installs the bootstrap posture. It is reported rather than acted on: this
	// relay installs no address and no route.
	fmt.Fprintf(out, "ready name=%s luid=%d mtu=%d floor-mtu=%d ipv6=%v\n",
		adapterName, adapter.LUID(), cmd.mtu, winn3ShippingFloorInnerMTU,
		cmd.mtu >= winn3IPv6MinLinkMTU)
	if err := out.Flush(); err != nil {
		fail(7, "report readiness: %v", err)
	}

	var stats counters
	done := make(chan struct{})
	var closeOnce atomic.Bool
	shutdown := func() {
		if closeOnce.CompareAndSwap(false, true) {
			close(done)
		}
	}

	// quitTun is how shutdown brings pumpTunToSeam out of a parked wait on
	// Wintun's read-wait event WITHOUT ending the session underneath it. It is
	// manual-reset (the 1), so once it is signalled it stays signalled and the
	// wake cannot be missed by a pump that had not reached the wait yet.
	quitTun, err := windows.CreateEvent(nil, 1, 0, nil)
	if quitTun == 0 {
		fail(8, "create pump quit event: %v", err)
	}
	defer windows.CloseHandle(quitTun)

	// stopping is the last word on whether either pump may enter the ring. It
	// is set before quitTun is signalled, so a pump that wakes for any reason
	// finds it already true.
	var stopping atomic.Bool
	adapterSide := wintunSide{
		session:  session,
		readWait: session.ReadWaitEvent(),
		quit:     quitTun,
		stopping: &stopping,
	}

	// pumps is what makes the teardown below safe rather than hopeful: it is
	// the only way this goroutine can know that no other goroutine is still
	// inside a Wintun call.
	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() {
		defer pumps.Done()
		pumpTunToSeam(adapterSide, seam, peer, cmd.mtu, &stats, shutdown)
	}()
	go func() {
		defer pumps.Done()
		pumpSeamToTun(adapterSide, seam, peer, cmd.mtu, &stats, shutdown)
	}()

	// A closed stdin means the privileged service is gone. A relay that
	// outlived its supervisor would hold an adapter nobody is configuring and
	// a seam nobody is draining, so it exits rather than persisting.
	go func() {
		for control.Scan() {
			// Any further control input is currently unspecified; draining it
			// keeps the pipe from filling. Reaching EOF is the signal.
		}
		shutdown()
	}()

	stopRequested := make(chan struct{}, 1)
	go func() {
		waitResult, _ := windows.WaitForSingleObject(stopEvent, windows.INFINITE)
		if waitResult == windows.WAIT_OBJECT_0 {
			stopRequested <- struct{}{}
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, windows.SIGTERM)

	select {
	case <-stopRequested:
	case <-signals:
	case <-done:
	}

	// SHUTDOWN ORDERING. The ring is freed LAST, and only once nothing can be
	// reading it.
	//
	// What used to be here was `session.End()` followed by `seam.Close()`, on
	// the assertion that ending the session unblocks a parked ReceivePacket and
	// both pumps unwind on their own. They do not. End() frees the ring
	// immediately and synchronises with nothing, so pumpTunToSeam -- which
	// spends its idle life parked one call away from that memory -- dereferences
	// it after the free. On 2026-08-10, on the first Windows carry run, that
	// produced `Exception 0xc0000005` (ACCESS_VIOLATION) with goroutine 1
	// already past End() and inside seam.Close(), while pumpTunToSeam sat in
	// wintun.Session.ReceivePacket. Two things made it worse than a noisy exit:
	// the faulting process is NT AUTHORITY\SYSTEM (see runningAsLocalSystem)
	// and the crash pre-empted the drop accounting below, so the one number
	// that says whether packets were lost on the way out was destroyed. It read
	// as harmless because process death still releases the adapter.
	//
	// Looped on that same host, the old ordering failed EVERY teardown, 22 of
	// 22, in two ways: about a fifth access-violated as above, and the rest
	// never exited at all -- End() does not reliably signal the read-wait
	// event, so on a quiet adapter the pump simply stayed parked and this
	// goroutine sat in seam.Close() until the supervisor's 5-second wait
	// expired and TerminateJobObject killed it. Not one of the 22 printed the
	// drop accounting. So "unwind on their own" was not merely racy, it was
	// never true; the crash was only the loud half of it.
	//
	// The order below is the only one that is safe, and each step exists to
	// unblock a specific place a pump can be:
	//
	//	1. stopping   -- no pump enters a Wintun call again, whatever wakes it
	//	2. SetEvent   -- wakes pumpTunToSeam out of waitReadable's INFINITE wait
	//	3. seam.Close -- wakes pumpSeamToTun out of ReadFromUDPAddrPort, and
	//	                 pumpTunToSeam out of any parked WriteToUDPAddrPort
	//	4. pumps.Wait -- both pumps have RETURNED; the ring has no readers
	//	5. End/Close  -- and only now is it anyone's to free
	stopping.Store(true)
	_ = windows.SetEvent(quitTun)
	_ = seam.Close()

	quiesced := make(chan struct{})
	go func() {
		pumps.Wait()
		close(quiesced)
	}()

	ringFreed := false
	select {
	case <-quiesced:
		session.End()
		_ = adapter.Close()
		ringFreed = true
	case <-time.After(pumpQuiesceTimeout):
		// Every block above is woken explicitly, so this is not expected. If it
		// ever happens the ring is left to process exit rather than freed under
		// a live reader -- refusing to free it is the whole point of this
		// sequence, and an unfreed ring costs nothing that process teardown
		// does not already reclaim.
	}

	// The drop accounting, which now actually prints. On the quiesced path
	// these counters are final: both pumps have returned, so nothing can still
	// be adding to them as they are read.
	fmt.Fprintf(os.Stderr,
		"winn3-relay: tun->seam=%d seam->tun=%d invalid=%d oversize=%d "+
			"ring-full=%d foreign=%d\n",
		stats.tunToSeam.Load(), stats.seamToTun.Load(),
		stats.dropInvalid.Load(), stats.dropOversize.Load(),
		stats.dropRingFull.Load(), stats.foreign.Load())

	if !ringFreed {
		fmt.Fprintf(os.Stderr,
			"winn3-relay: pumps did not quiesce within %s; leaving the Wintun "+
				"ring for process exit rather than freeing it under a live "+
				"reader\n", pumpQuiesceTimeout)
		os.Exit(9)
	}
}

// wintunSide is the tunSide implementation over a live Wintun session.
//
// It is deliberately the only Wintun-aware code in the datapath: the pumps in
// relay.go make every decision about whether a packet may move, and this type
// only translates Wintun's calling convention into the interface they use.
type wintunSide struct {
	session  wintun.Session
	readWait windows.Handle

	// quit is a manual-reset event main signals exactly once, to bring
	// waitReadable out of an INFINITE wait without ending the session. Wintun's
	// own read-wait event is signalled by the driver when packets arrive and
	// there is no other way to interrupt it, which is why a second handle
	// exists rather than a flag alone.
	quit windows.Handle

	// stopping is the answer to "may this side touch the ring at all". It is
	// set before quit is signalled, and every entry point below checks it
	// FIRST, so once shutdown begins the pumps make no further Wintun call. It
	// is what lets main free the ring at all: without it a pump that woke for
	// an unrelated reason could still be inside ReceivePacket.
	stopping *atomic.Bool
}

func (w wintunSide) receivePacket() ([]byte, func(), error) {
	if w.stopping.Load() {
		return nil, nil, errTunClosed
	}
	packet, err := w.session.ReceivePacket()
	switch {
	case err == nil:
		return packet, func() { w.session.ReleaseReceivePacket(packet) }, nil
	case errors.Is(err, windows.ERROR_NO_MORE_ITEMS):
		return nil, nil, errTunAgain
	default:
		// ERROR_HANDLE_EOF on a session that has been ended, or
		// ERROR_INVALID_DATA on a corrupt ring. Neither is recoverable.
		return nil, nil, errTunClosed
	}
}

// waitReadable parks until either the driver has a packet or shutdown has been
// asked for. Waiting on BOTH handles is the difference between a pump that can
// be brought out of an idle wait and one that can only be freed out of it.
func (w wintunSide) waitReadable() error {
	event, err := windows.WaitForMultipleObjects(
		[]windows.Handle{w.readWait, w.quit}, false, windows.INFINITE)
	if err != nil {
		// WAIT_FAILED. The wait itself is no longer trustworthy, so unwind
		// rather than spin on it.
		return errTunClosed
	}
	if event != windows.WAIT_OBJECT_0 || w.stopping.Load() {
		// WAIT_OBJECT_0+1 is quit; WAIT_ABANDONED_0+n cannot happen on events
		// but is not a reason to keep reading either.
		return errTunClosed
	}
	return nil
}

func (w wintunSide) sendPacket(packet []byte) error {
	if w.stopping.Load() {
		return errTunClosed
	}
	send, err := w.session.AllocateSendPacket(len(packet))
	if err != nil {
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return errTunRingFull
		}
		return errTunClosed
	}
	copy(send, packet)
	w.session.SendPacket(send)
	return nil
}

var _ tunSide = wintunSide{}
