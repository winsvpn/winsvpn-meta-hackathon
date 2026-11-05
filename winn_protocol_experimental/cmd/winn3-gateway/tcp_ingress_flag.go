package main

import (
	"fmt"
	"net"
	"os"
)

// -tcp-ingress puts Round W's server path behind a switch that is OFF BY
// DEFAULT. Round W (4a18d2f) wrapped the cover listener on the gateway's TCP
// port in newTCPIngress, which classifies every TCP connection as a possible v3
// stream before the cover HTTPS listener sees it, whatever -plan says. The
// owner's ruling of 2026-09-24 ships the fleet "without TCP": Round W follows
// in its own rollout, after the hub serves a tcp plan and a device canary.
// Off, startCover builds the TCP cover listener exactly as the pre-W gateway
// (13f002a) did and the server has no TCP ingress; on, Round W's path is
// unchanged.

// tcpIngressEnv is -tcp-ingress's environment variable.
const tcpIngressEnv = "WINN3_GATEWAY_TCP_INGRESS"

// resolveTCPIngress maps -tcp-ingress and WINN3_GATEWAY_TCP_INGRESS the way
// resolveListenerDF maps -listener-df: the environment is read when the flag
// holds its default. The accepted values are the installer's own boolean
// values, 0 and 1, plus unset. Anything else is refused whatever the flag
// says, so a mistyped value never reads as a decision.
func resolveTCPIngress(flagOn bool, env string) (bool, error) {
	switch env {
	case "", "0":
		return flagOn, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("%s=%q must be 0, 1 or unset", tcpIngressEnv, env)
	}
}

// logTCPIngress writes the one startup line that states the TCP ingress state.
// A variable so a test can count the line and read its state.
var logTCPIngress = func(line string) { fmt.Fprintln(os.Stderr, line) }

func tcpIngressStateLine(on bool, addr net.Addr) string {
	if on {
		return fmt.Sprintf("winn3-gateway: TCP ingress on (-tcp-ingress, Round W): tcp/%s classifies "+
			"v3 streams before the cover HTTPS listener", addr)
	}
	return fmt.Sprintf("winn3-gateway: TCP ingress off (-tcp-ingress not set): tcp/%s serves cover "+
		"HTTPS only, as before Round W; no v3 session is built over TCP", addr)
}
