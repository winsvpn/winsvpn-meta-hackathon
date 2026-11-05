package main

import (
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// TestTxDropReasonKeysReachTheWire pins the JSON names of the outbound
// per-reason split. A host that saw only tx_dropped_invalid would still know
// something was refused, not which check fired — the same blindness the
// rx_drop_* keys closed on the inbound side.
func TestTxDropReasonKeysReachTheWire(t *testing.T) {
	encoded, err := json.Marshal(serveStatus{
		Event:               "posture",
		TxDroppedInvalid:    4,
		TxDropFamilyOff:     1,
		TxDropMartian:       1,
		TxDropSourceNotOurs: 1,
		TxDropMalformed:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	want := map[string]float64{
		"tx_dropped_invalid":      4,
		"tx_drop_family_off":      1,
		"tx_drop_martian":         1,
		"tx_drop_source_not_ours": 1,
		"tx_drop_malformed":       1,
	}
	for key, n := range want {
		got, ok := back[key]
		if !ok {
			t.Fatalf("status must publish %q; body=%s", key, encoded)
		}
		if got != n {
			t.Fatalf("%s is %v, want %v: %s", key, got, n, encoded)
		}
	}
	sum := back["tx_drop_family_off"].(float64) + back["tx_drop_martian"].(float64) +
		back["tx_drop_source_not_ours"].(float64) + back["tx_drop_malformed"].(float64)
	if sum != back["tx_dropped_invalid"].(float64) {
		t.Fatalf("JSON per-reason sum %v != tx_dropped_invalid %v", sum, back["tx_dropped_invalid"])
	}
}

// TestTxDropReasonsAreCopiedFromTunStats parses this file's own source.
//
// A field on serveStatus is worth nothing if status() never assigns it: the
// document still carries the key and it reads a permanent zero, which is
// indistinguishable from "the refusal never fired". That is worse than
// omitting the field. Written against the four += lines, so a later edit that
// declares the JSON keys and forgets the copy goes red here.
func TestTxDropReasonsAreCopiedFromTunStats(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	needles := []string{
		"out.TxDropFamilyOff += st.TxDropFamilyOff",
		"out.TxDropMartian += st.TxDropMartian",
		"out.TxDropSourceNotOurs += st.TxDropSourceNotOurs",
		"out.TxDropMalformed += st.TxDropMalformed",
		"out.TxDroppedInvalid += st.TxDroppedInvalid",
	}
	for _, n := range needles {
		if !strings.Contains(body, n) {
			t.Fatalf("status() no longer copies %q from tun.Stats; the JSON key would be a permanent zero", n)
		}
	}

	// The file must still parse. A truncated edit that leaves the needles in
	// a comment would pass the substring check and fail this.
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "main.go", src, 0); err != nil {
		t.Fatalf("main.go does not parse: %v", err)
	}
}

// TestTxDropReasonKeysPresentWhenZero pins that the four reason keys are
// published at zero. json omitempty on a uint64 would drop a never-fired
// reason from the document, which is indistinguishable from the field not
// existing — the same blindness the split exists to close. The non-zero
// marshal test cannot see that: omitempty keeps a 1.
func TestTxDropReasonKeysPresentWhenZero(t *testing.T) {
	encoded, err := json.Marshal(serveStatus{Event: "posture"})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"tx_dropped_invalid",
		"tx_drop_family_off",
		"tx_drop_martian",
		"tx_drop_source_not_ours",
		"tx_drop_malformed",
	} {
		got, ok := back[key]
		if !ok {
			t.Fatalf("status must publish %q even when zero (omitempty would hide a never-fired reason); body=%s", key, encoded)
		}
		if got != float64(0) {
			t.Fatalf("%s is %v, want 0: %s", key, got, encoded)
		}
	}
	for _, key := range []string{"tx_drop_not_for_us", "tx_drop_reflected"} {
		if _, ok := back[key]; ok {
			t.Fatalf("%q on the tx document is a zero-clause pass: outbound cannot return that sentinel; body=%s", key, encoded)
		}
	}
}

// TestTxDropReasonCountersDistinguishSourceNotOursFromCarried is the outbound
// analogue of TestDropReasonCountersDistinguishNotForUsFromDelivered: it
// drives a real tun.Tunnel built through parseAssignment (the seam runServe
// uses) and reads the same tun.Stats fields serveStatus sums.
//
// Three controls on one dual-stack tunnel, then family-off on a v4-only
// tunnel so that control cannot be a zero-clause on the dual-stack one:
//
//   - v4 whose source is not this endpoint -> ErrSourceNotOurs
//   - v4 addressed to this endpoint itself -> ErrMartian (not ErrReflected)
//   - v4 from this endpoint to a documentation dest -> carried (TxPackets)
//   - v6 on a v4-only assignment -> ErrFamilyOff
func TestTxDropReasonCountersDistinguishSourceNotOursFromCarried(t *testing.T) {
	sizing, _, err := buildServeSizing(serveOptions{pathMTU: 1450, plan: "udp"})
	if err != nil {
		t.Fatal(err)
	}
	assign, err := parseAssignment("10.64.0.1", "10.64.0.2", "2001:db8::1", "")
	if err != nil {
		t.Fatal(err)
	}
	dev := newReflector(sizing.InnerMTU, assign.V4)
	defer dev.Close()
	sink := &recordingSink{}
	tunnel, err := tun.New(tun.Config{
		Assign:                  assign,
		Device:                  dev,
		Sink:                    sink,
		Clock:                   driver.SessionClock{Clock: driver.SystemClock{}},
		CarrierFloorMessageSize: sizing.MessageSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	tunnel.SetState(tun.StateCarrying)

	const gwV4 = "10.64.0.1"
	const clientV4 = "10.64.0.2"
	const inetV4 = "192.0.2.1"

	err = tunnel.Outbound(buildIPv4ICMP(clientV4, inetV4))
	if !errors.Is(err, tun.ErrSourceNotOurs) {
		t.Fatalf("foreign source returned %v, want ErrSourceNotOurs", err)
	}
	st := tunnel.Stats()
	if st.TxDropSourceNotOurs != 1 {
		t.Fatal("foreign source did not increment TxDropSourceNotOurs")
	}
	if st.TxDropMartian != 0 || st.TxDropFamilyOff != 0 || st.TxDropMalformed != 0 {
		t.Fatalf("foreign source was miscategorised: martian=%d familyOff=%d malformed=%d",
			st.TxDropMartian, st.TxDropFamilyOff, st.TxDropMalformed)
	}
	if st.TxDroppedInvalid != 1 {
		t.Fatalf("TxDroppedInvalid=%d, want 1 — the total must not change", st.TxDroppedInvalid)
	}
	if st.TxPackets != 0 {
		t.Fatalf("a refused packet was counted as carried: tx_packets=%d", st.TxPackets)
	}

	err = tunnel.Outbound(buildIPv4ICMP(gwV4, gwV4))
	if !errors.Is(err, tun.ErrMartian) {
		t.Fatalf("self-addressed outbound returned %v, want ErrMartian", err)
	}
	st = tunnel.Stats()
	if st.TxDropMartian != 1 {
		t.Fatal("self-addressed outbound did not increment TxDropMartian")
	}
	if st.TxDropSourceNotOurs != 1 {
		t.Fatalf("the SourceNotOurs total changed when it should not: %d", st.TxDropSourceNotOurs)
	}

	err = tunnel.Outbound(buildIPv4ICMP(gwV4, inetV4))
	if err != nil {
		t.Fatalf("a valid outbound packet from this endpoint was refused: %v", err)
	}
	st = tunnel.Stats()
	if st.TxPackets != 1 {
		t.Fatalf("TxPackets=%d, want 1 after a valid outbound packet", st.TxPackets)
	}
	if st.TxDroppedInvalid != 2 {
		t.Fatalf("the valid packet moved TxDroppedInvalid to %d, want 2", st.TxDroppedInvalid)
	}
	if got := st.TxDropFamilyOff + st.TxDropMartian + st.TxDropSourceNotOurs + st.TxDropMalformed; got != st.TxDroppedInvalid {
		t.Fatalf("per-reason counters sum to %d but TxDroppedInvalid=%d", got, st.TxDroppedInvalid)
	}

	encoded, err := json.Marshal(serveStatus{
		Event:               "posture",
		TxPackets:           st.TxPackets,
		TxDroppedInvalid:    st.TxDroppedInvalid,
		TxDropFamilyOff:     st.TxDropFamilyOff,
		TxDropMartian:       st.TxDropMartian,
		TxDropSourceNotOurs: st.TxDropSourceNotOurs,
		TxDropMalformed:     st.TxDropMalformed,
	})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	if back["tx_drop_source_not_ours"] != float64(1) {
		t.Fatalf("JSON tx_drop_source_not_ours is %v, want 1: %s", back["tx_drop_source_not_ours"], encoded)
	}
	if back["tx_drop_martian"] != float64(1) {
		t.Fatalf("JSON tx_drop_martian is %v, want 1: %s", back["tx_drop_martian"], encoded)
	}
	if back["tx_dropped_invalid"] != float64(2) {
		t.Fatalf("JSON tx_dropped_invalid is %v, want 2: %s", back["tx_dropped_invalid"], encoded)
	}
	if back["tx_packets"] != float64(1) {
		t.Fatalf("JSON tx_packets is %v, want 1: %s", back["tx_packets"], encoded)
	}

	v4only, err := parseAssignment("10.64.0.1", "10.64.0.2", "", "")
	if err != nil {
		t.Fatal(err)
	}
	dev4 := newReflector(sizing.InnerMTU, v4only.V4)
	defer dev4.Close()
	tun4, err := tun.New(tun.Config{
		Assign:                  v4only,
		Device:                  dev4,
		Sink:                    sink,
		Clock:                   driver.SessionClock{Clock: driver.SystemClock{}},
		CarrierFloorMessageSize: sizing.MessageSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	tun4.SetState(tun.StateCarrying)
	err = tun4.Outbound(buildIPv6ICMP("2001:db8::2", "2001:db8::feed"))
	if !errors.Is(err, tun.ErrFamilyOff) {
		t.Fatalf("outbound v6 on a v4-only assignment returned %v, want ErrFamilyOff", err)
	}
	st4 := tun4.Stats()
	if st4.TxDropFamilyOff != 1 || st4.TxDroppedInvalid != 1 {
		t.Fatalf("v4-only v6 outbound: familyOff=%d invalid=%d, want 1/1", st4.TxDropFamilyOff, st4.TxDroppedInvalid)
	}
	if st4.TxDropSourceNotOurs != 0 || st4.TxDropMartian != 0 {
		t.Fatalf("family-off was miscategorised: sourceNotOurs=%d martian=%d",
			st4.TxDropSourceNotOurs, st4.TxDropMartian)
	}
}
