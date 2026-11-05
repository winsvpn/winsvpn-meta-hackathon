//go:build linux

package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestNetnsPumpSurvivesSustainedICMPWithHealthyTrafficAndBoundedCPU is the
// requirement-4 endurance test: for more than five seconds a healthy client
// keeps sending while the gateway draws a bounded stream of ICMP port
// unreachables from a closed peer. The shared pump must keep delivering, must
// not be declared dead by the recoverable-error timer, and must not spin a CPU.
func TestNetnsPumpSurvivesSustainedICMPWithHealthyTrafficAndBoundedCPU(t *testing.T) {
	requireGatewayL4Netns(t)
	gatewayL4Sh(t, "ip", "netns", "exec", "l4g", "tc", "qdisc", "replace", "dev", "l4g0", "root", "pfifo", "limit", "1000")
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", "l4g", "tc", "qdisc", "replace", "dev", "l4g0", "root", "pfifo", "limit", "1000").Run()
	})
	clientB := netip.MustParseAddrPort("10.44.2.3:4000")
	gone := netip.MustParseAddrPort("10.44.2.2:5000") // nothing binds this: ICMP port unreachable
	b := gatewayL4UDP(t, "l4c", clientB)
	real := gatewayL4UDP(t, "l4g", netip.MustParseAddrPort("10.44.1.1:0"))
	setRawRecvErrOn(t, real)
	split := newSplitUDP(real, demuxDatagramMin)
	defer split.stop()
	gwAddr := net.UDPAddrFromAddrPort(real.LocalAddr().(*net.UDPAddr).AddrPort())

	const runFor = 6 * time.Second
	var ruStart, ruEnd unix.Rusage
	_ = unix.Getrusage(unix.RUSAGE_SELF, &ruStart)
	deadline := time.Now().Add(runFor)

	var wg sync.WaitGroup
	var sent atomic.Int64

	// Healthy uplink: client B sends ~one datagram/ms for the whole run.
	wg.Add(1)
	go func() {
		defer wg.Done()
		seq := uint32(0)
		for time.Now().Before(deadline) {
			var p [8]byte
			binary.BigEndian.PutUint32(p[:], seq)
			if _, err := b.WriteToUDP(p[:], gwAddr); err == nil {
				sent.Add(1)
			}
			seq++
			time.Sleep(time.Millisecond)
		}
	}()

	// Bounded ICMP load: the gateway pokes a closed peer ~20 times/second.
	wg.Add(1)
	go func() {
		defer wg.Done()
		dst := net.UDPAddrFromAddrPort(gone)
		for time.Now().Before(deadline) {
			_, _ = split.v3.WriteToUDPAddrPort([]byte("poke"), netip.MustParseAddrPort(dst.String()))
			time.Sleep(50 * time.Millisecond)
		}
	}()

	// Reader: drain the v3 side for the whole run.
	var delivered atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for time.Now().Before(deadline.Add(300 * time.Millisecond)) {
			_ = split.v3.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_, _, err := split.v3.ReadFromUDPAddrPort(buf)
			if err == nil {
				delivered.Add(1)
			}
		}
	}()

	wg.Wait()
	_ = unix.Getrusage(unix.RUSAGE_SELF, &ruEnd)

	if splitStopped(split) {
		t.Fatal("the shared pump was declared dead during sustained recoverable ICMP")
	}
	s, d := sent.Load(), delivered.Load()
	faults := split.readFaults.Load()
	cpu := rusageSeconds(ruEnd) - rusageSeconds(ruStart)
	t.Logf("over %v: sent=%d delivered=%d pump_read_faults=%d process_cpu=%.2fs stats=%+v",
		runFor, s, d, faults, cpu, split.errq.Stats())
	if d < s*7/10 {
		t.Fatalf("delivered %d of %d healthy datagrams while ICMP flowed; the pump was starved", d, s)
	}
	// Bounded CPU: the whole process must not average even half a core over the
	// run. A busy retry of "not pollable" would peg one core (~6s CPU).
	if cpu > runFor.Seconds()*0.5 {
		t.Fatalf("process used %.2fs CPU over %v; the pump is spinning", cpu, runFor)
	}
}

func rusageSeconds(ru unix.Rusage) float64 {
	tv := func(t unix.Timeval) float64 { return float64(t.Sec) + float64(t.Usec)/1e6 }
	return tv(ru.Utime) + tv(ru.Stime)
}

// TestNetnsPumpNotDeclaredDeadUnderSustainedFaults keeps the shared socket in
// the "not pollable" poller state for longer than the recoverable-error
// threshold while ICMP keeps arriving, with no successful read to reset the
// episode. The pump must stay alive (degraded), never calling stop on a
// recoverable condition. RED on v1, whose 5 s episode timer calls stop.
func TestNetnsPumpNotDeclaredDeadUnderSustainedFaults(t *testing.T) {
	requireGatewayL4Netns(t)
	// A very slow egress so the send buffer, once full, stays full for the run.
	gatewayL4Sh(t, "ip", "netns", "exec", "l4g", "tc", "qdisc", "replace", "dev", "l4g0", "root",
		"tbf", "rate", "8kbit", "burst", "1200", "limit", "1000000")
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", "l4g", "tc", "qdisc", "replace", "dev", "l4g0", "root", "pfifo", "limit", "1000").Run()
	})
	clientB := netip.MustParseAddrPort("10.44.2.3:4000")
	gone := netip.MustParseAddrPort("10.44.2.2:5000")
	real := gatewayL4UDP(t, "l4g", netip.MustParseAddrPort("10.44.1.1:0"))
	if err := real.SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	setRawRecvErrOn(t, real)
	split := newSplitUDP(real, demuxDatagramMin)
	defer split.stop()

	const runFor = 7 * time.Second
	deadline := time.Now().Add(runFor)
	var wg sync.WaitGroup

	// Keep the send buffer full so the socket stays non-writable: every EPOLLERR
	// then arrives as an error-only wakeup that yields "not pollable" on read.
	wg.Add(1)
	go func() {
		defer wg.Done()
		dstB := net.UDPAddrFromAddrPort(clientB)
		for time.Now().Before(deadline) {
			for i := 0; i < 8; i++ {
				_, _ = split.v3.WriteToUDPAddrPort(make([]byte, 1000), netip.MustParseAddrPort(dstB.String()))
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	// Keep ICMP coming.
	wg.Add(1)
	go func() {
		defer wg.Done()
		dstGone := net.UDPAddrFromAddrPort(gone)
		for time.Now().Before(deadline) {
			_, _ = split.v3.WriteToUDPAddrPort([]byte("poke"), netip.MustParseAddrPort(dstGone.String()))
			time.Sleep(20 * time.Millisecond)
		}
	}()

	// Watch across the 5 s mark: the pump must never stop on its own.
	stoppedAt := time.Duration(-1)
	start := time.Now()
	for time.Now().Before(deadline) {
		if splitStopped(split) {
			stoppedAt = time.Since(start)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	wg.Wait()
	if stoppedAt >= 0 {
		t.Fatalf("the pump declared the shared socket dead after %v of recoverable faults; only closure or a descriptor failure may do that", stoppedAt)
	}
	if splitStopped(split) {
		t.Fatal("the pump stopped on a recoverable condition")
	}
	t.Logf("pump alive after %v of sustained faults; read faults=%d stats=%+v", runFor, split.readFaults.Load(), split.errq.Stats())
}
