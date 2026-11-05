package main

import "fmt"

// sendQueueFQDefaultEnv turns the -send-queue-fq default OFF again without
// touching the unit file: WINN3_GATEWAY_SEND_QUEUE_FQ=0.
const sendQueueFQDefaultEnv = "WINN3_GATEWAY_SEND_QUEUE_FQ"

// resolveSendQueueFQDefault applies sendQueueFQDefaultEnv to a flag that was
// left at its default.
//
// The default flipped to ON on 2026-10-11 (TUNNEL-SPEED-2 Turn 14, the fleet
// reset build). The fair queue is the F1 mechanism the round selected at
// Turn 7 on Canada (2026-10-10, step 2): against the same build's single
// FIFO with CoDel it halved the loaded download p95 (123.2 and 132.4 ms
// against 212 to 313 ms) at no throughput cost (679 and 696 Mbit/s against
// the base's 654 mean, TCPTimeouts 65 and 66 against 73.5), the one
// download-side change that lowered latency, and the owner's rule adopts a
// loaded-latency gain. Every build since was named "F1 plus", but this flag
// stayed an A/B arm at false, so the Turn 12 arms (B, Bv) ran the single
// FIFO: their journals read send_queue_overflow 0 and send_queue_dropped 37
// to 113. The reset ships the measured mechanism as the default;
// WINN3_GATEWAY_SEND_QUEUE_FQ=0 is the rollback to the single FIFO.
//
// The flag still wins when passed, in either direction: main records whether
// -send-queue-fq appeared on the command line at all (flags.Visit), so
// -send-queue-fq=false is a refusal, not a suggestion, and the empty
// environment keeps the new default.
func resolveSendQueueFQDefault(flagValue, flagSet bool, env string) (bool, error) {
	if flagSet {
		return flagValue, nil
	}
	switch env {
	case "", "1":
		return true, nil
	case "0":
		return false, nil
	default:
		return false, fmt.Errorf("%s=%q must be 1, 0 or unset; 0 restores the single send FIFO",
			sendQueueFQDefaultEnv, env)
	}
}
