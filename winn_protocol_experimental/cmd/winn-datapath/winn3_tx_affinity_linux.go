//go:build linux

package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

// pinTxThread is TUNNEL-SPEED-2 Turn 9 arm X2: it locks the calling
// goroutine, which is the one that runs driver.Loop.Run and therefore the
// write loop (every sendmsg and sendmmsg of the uplink), to its OS thread
// and pins that thread to the CPU named by WINN3_TX_CPU. The arm asks one
// question of the phone's kernel and Wi-Fi driver: does the uplink's
// receive-order inversion (33 to 44% on F1 against 1 to 4% on the downlink)
// follow the CPU the send syscalls run on, which is what a per-CPU transmit
// ring would produce, or not, which points at the UDP_SEGMENT super-datagram
// (arm X1). Unset leaves the loop exactly as before. The returned function
// restores the thread's previous affinity and unlocks it; a round that ends
// hands a clean thread back to the runtime.
func pinTxThread() func() {
	v := os.Getenv("WINN3_TX_CPU")
	if v == "" {
		return func() {}
	}
	cpu, err := strconv.Atoi(v)
	if err != nil || cpu < 0 || cpu >= 1024 {
		fmt.Fprintf(os.Stderr, "winn-debug: [winn3_frame.tx_affinity] WINN3_TX_CPU=%q ignored: not a cpu index\n", v)
		return func() {}
	}
	runtime.LockOSThread()
	var previous, want unix.CPUSet
	if err := unix.SchedGetaffinity(0, &previous); err != nil {
		fmt.Fprintf(os.Stderr, "winn-debug: [winn3_frame.tx_affinity] sched_getaffinity: %v; not pinned\n", err)
		runtime.UnlockOSThread()
		return func() {}
	}
	want.Zero()
	want.Set(cpu)
	if err := unix.SchedSetaffinity(0, &want); err != nil {
		fmt.Fprintf(os.Stderr, "winn-debug: [winn3_frame.tx_affinity] sched_setaffinity(cpu %d): %v; not pinned\n", cpu, err)
		runtime.UnlockOSThread()
		return func() {}
	}
	fmt.Fprintf(os.Stderr, "winn-debug: [winn3_frame.tx_affinity] write loop pinned to cpu %d\n", cpu)
	return func() {
		_ = unix.SchedSetaffinity(0, &previous)
		runtime.UnlockOSThread()
	}
}
