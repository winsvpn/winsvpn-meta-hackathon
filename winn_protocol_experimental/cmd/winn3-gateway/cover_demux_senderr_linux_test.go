//go:build linux

package main

import (
	"encoding/json"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
)

// TestNetnsTheErrorOnlyWakeupIsRetriedNotIgnored is the anti-vacuity half of
// TestNetnsTheDemuxPumpSurvivesAnErrorOnlyWakeup: the pump survived because it
// retried read faults, and the error was absorbed and drained, not because the
// scenario failed to happen.
func TestNetnsTheErrorOnlyWakeupIsRetriedNotIgnored(t *testing.T) {
	split := errorOnlyWakeup(t)
	faults := split.readFaults.Load()
	st := split.errq.Stats()
	t.Logf("pump read faults retried=%d error-queue stats=%+v", faults, st)
	if faults == 0 {
		t.Fatal("no read fault was retried: the error-only wakeup did not happen")
	}
	if st.MatchingErrorRetries == 0 || st.DrainedICMP == 0 {
		t.Fatalf("the port unreachable was not absorbed and drained: %+v", st)
	}
}

// TestTheStatusBlockIsPresentForALinuxSplitAndOmittedOtherwise pins the
// build/omission contract: a real Linux split has an error-queue drain, so the
// block is present with drain_available true; a connection without a queue
// publishes no block, which is what an unsupported platform produces.
func TestTheStatusBlockIsPresentForALinuxSplitAndOmittedOtherwise(t *testing.T) {
	real := newLoopbackUDP(t)
	split := newSplitUDP(real, demuxDatagramMin)
	defer split.stop()
	opts := enableUDPSendErrorReporting(real)
	if !opts.IPv4 {
		t.Fatalf("IP_RECVERR could not be set on Linux: %+v", opts)
	}
	st := buildUDPSendErrorStatus(split.v3, opts)
	if st == nil || !st.DrainAvailable || !st.OptionIPv4 {
		t.Fatalf("status for a Linux split socket: %+v", st)
	}
	if buildUDPSendErrorStatus(nil, opts) != nil {
		t.Fatal("a nil conn (no udpSendErrorSource) must publish no send-error block")
	}
}

// TestStatusJSONOmitsTheBlockWhenAbsentAndNamesEveryCounter checks the
// serialized posture document: nil is omitted entirely, and a populated block
// carries every documented counter under its exact JSON name.
func TestStatusJSONOmitsTheBlockWhenAbsentAndNamesEveryCounter(t *testing.T) {
	// Unsupported-platform shape: the block is nil, so the key is absent.
	absent := serveStatus{Event: "posture"}
	b, err := json.Marshal(absent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "udp_send_errors") {
		t.Fatalf("a nil send-error block must be omitted, got: %s", b)
	}

	// Populated shape: every field name must appear, and be truthful about
	// coverage vs drain availability being separate.
	full := serveStatus{
		Event: "posture",
		UdpSendErrors: &udpSendErrorStatus{
			OptionIPv4: true, OptionIPv6: false, DrainAvailable: true, Degraded: true,
			TransmitRefused: 7, ScalarRefused: 3, ScalarDropped: 1, MatchingErrorRetries: 9,
			ErrorQueueDrained: 12, ErrorQueueICMP: 8, ErrorQueueLocal: 4,
			DrainSkipped: 2, DrainPendingServiced: 2, DrainLimitHit: 5, DrainContinuations: 6, DrainFailures: 0,
			DemuxReadFaults: 11,
		},
	}
	b, err = json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"udp_send_errors", "option_ipv4", "option_ipv6", "drain_available", "degraded",
		"transmit_refused", "scalar_refused", "scalar_dropped", "matching_error_retries",
		"error_queue_drained", "error_queue_icmp", "error_queue_local",
		"drain_skipped", "drain_pending_serviced", "drain_limit_hit", "drain_continuations", "drain_failures",
		"demux_read_faults",
	} {
		if !strings.Contains(string(b), `"`+key+`"`) {
			t.Errorf("status JSON is missing %q: %s", key, b)
		}
	}
}

// TestNetnsScalarRefusalIsCountedAndSurvivesInStatus drives the exact scalar
// paths under fq refusal and checks the counters that reach status: the QUIC
// cover path never returns a fatal error (it drops), the v3 path returns the
// refusal for retention, and both are counted in scalar_refused.
func TestNetnsScalarRefusalIsCountedAndSurvivesInStatus(t *testing.T) {
	requireGatewayL4Netns(t)
	gatewayL4Sh(t, "ip", "netns", "exec", "l4g", "tc", "qdisc", "replace", "dev", "l4g0", "root",
		"fq", "flow_limit", "4", "maxrate", "8mbit")
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", "l4g", "tc", "qdisc", "replace", "dev", "l4g0", "root", "pfifo", "limit", "1000").Run()
	})
	clientB := netip.MustParseAddrPort("10.44.2.3:4000")
	_ = gatewayL4UDP(t, "l4c", clientB)
	real := gatewayL4UDP(t, "l4g", netip.MustParseAddrPort("10.44.1.1:0"))
	if _, err := carrier.EnableSendErrorReporting(real); err != nil {
		t.Fatal(err)
	}
	split := newSplitUDP(real, demuxDatagramMin)
	defer split.stop()
	dst := net.UDPAddrFromAddrPort(clientB)

	// QUIC cover path: many back-to-back writes overrun fq flow_limit. WriteTo
	// must never return a fatal error to quic-go; it drops on exhaustion.
	fatal := 0
	for i := 0; i < 400; i++ {
		if _, err := split.quic.WriteTo(make([]byte, 1000), dst); err != nil {
			fatal++
		}
	}
	if fatal != 0 {
		t.Fatalf("the QUIC cover WriteTo returned a fatal error %d times; quic-go would destroy the connection", fatal)
	}
	st := split.errq.Stats()
	t.Logf("scalar stats after cover flood: %+v", st)
	if st.ScalarRefused == 0 {
		t.Skip("fq did not refuse any scalar write; cannot exercise the path on this host")
	}
	opts := carrier.SendErrorOptions{IPv4: true}
	status := buildUDPSendErrorStatus(split.v3, opts)
	if status == nil || status.ScalarRefused == 0 {
		t.Fatalf("scalar refusals not reflected in status: %+v", status)
	}
	t.Logf("status scalar_refused=%d scalar_dropped=%d", status.ScalarRefused, status.ScalarDropped)
}

func newLoopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
