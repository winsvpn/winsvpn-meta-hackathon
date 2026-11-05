package main

import "fmt"

// asyncWriteDefaultEnv turns the -forward-async-write default OFF again
// without touching the unit file: WINN3_GATEWAY_ASYNC_WRITE=0.
const asyncWriteDefaultEnv = "WINN3_GATEWAY_ASYNC_WRITE"

// resolveAsyncWriteDefault applies asyncWriteDefaultEnv to a flag that was
// left at its default.
//
// The default flipped to ON on 2026-10-10 (tunnel-speed, item 7). Canada
// measured the serialized uplink consumer, one write(2) per inner packet with
// the kernel's forward path inside the syscall, capping a session near 30k
// msg/s (~340 Mbit/s) while the busiest thread sat at 0.29 to 0.31 cores:
// the process was not out of CPU, one goroutine was out of parallelism. The
// async writer is the measured fix (intake +19.9% alone, +46% with RPS), and
// its own CPU gate (forward_cpugate.go, fail-closed below two usable CPUs)
// already refuses it where it cannot help. The item 7 A/B failed its drop
// rules with the 512 inbox overflowing underneath both arms; the inbox
// deepening and this default are measured as one arm, and WINN3_GATEWAY_
// ASYNC_WRITE=0 plus the old inbox remains the rollback.
//
// The flag still wins when passed, in either direction: main records whether
// -forward-async-write appeared on the command line at all (flags.Visit), so
// -forward-async-write=false is a refusal, not a suggestion, and the empty
// environment keeps the new default.
func resolveAsyncWriteDefault(flagValue, flagSet bool, env string) (bool, error) {
	if flagSet {
		return flagValue, nil
	}
	switch env {
	case "", "1":
		return true, nil
	case "0":
		return false, nil
	default:
		return false, fmt.Errorf("%s=%q must be 1, 0 or unset; 0 restores the synchronous TUN write",
			asyncWriteDefaultEnv, env)
	}
}
