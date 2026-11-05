package main

import (
	"fmt"
	"strconv"
)

// freeRateEnv is -free-mbps's environment variable: the knob the shipped
// systemd unit carries no flag for, so an edit to the env file plus a restart
// is the whole change.
const freeRateEnv = "WINN3_GATEWAY_FREE_MBIT"

// resolveFreeMbps maps -free-mbps and WINN3_GATEWAY_FREE_MBIT the way
// resolveTCPIngress maps -tcp-ingress: the environment is read when the flag
// holds its default. The accepted value is a decimal integer in 0..100000
// (0 disables the cap), plus unset. Anything else is refused whatever the
// flag says, so a mistyped value never reads as a decision.
func resolveFreeMbps(flagValue int, env string) (int, error) {
	if env == "" {
		return flagValue, nil
	}
	value, err := strconv.Atoi(env)
	if err != nil || value < 0 || value > 100000 || strconv.Itoa(value) != env {
		return 0, fmt.Errorf("%s=%q must be a decimal integer from 0 (off) to 100000, or unset", freeRateEnv, env)
	}
	if flagValue != 100 {
		return flagValue, nil
	}
	return value, nil
}
