package main

import (
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Silent-refusal instance #5: operator-value whitespace.
//
// The gateway keys the admission tag with the operator string's RAW BYTES while
// every host that receives the value as transport text trims it. The two halves
// this suite had already closed were the host half — all four hosts moved onto
// the served base64 spelling on 2026-08-09, so none of them can reach a decoded
// byte — and the hub half, which refuses a whitespace-bearing value at upload IN
// THE REPO. The half that survived was the one no host can see: the gateway's
// own flag, against which nothing was compared.
//
// The remedy is a REFUSAL, not a trim. See validateOperatorValues for why, and
// note what the tests below hold as a consequence: TestGatewayIDIsRawBytes and
// TestTheGatewayKeysWithTheOperatorValueUntrimmed still pass, because the value
// keyed with has not changed. Only the set of values that can reach the keying
// has.

// operatorValueOptions is a serve configuration that is legitimate in every
// respect except the one the caller spoils.
func operatorValueOptions(t *testing.T) serveOptions {
	t.Helper()
	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	// runServe is the production entry point and therefore always requires a
	// live durable replay journal. Tests using this otherwise-valid baseline
	// provision one explicitly, then override it only in refusal cases.
	t.Setenv("WINN3_GATEWAY_REPLAY_JOURNAL", "1")
	t.Setenv("WINN3_REPLAY_JOURNAL", writeEmptyReplayJournal(t, dir))
	opts := serveOptions{
		listen:      "127.0.0.1:0",
		staticPath:  filepath.Join(dir, "static.key"),
		admission:   filepath.Join(dir, "admission.key"),
		gatewayID:   testGatewayID,
		innerV4:     testGatewayInner,
		routerV4:    testClientInner,
		plan:        "udp",
		pathMTU:     testPathMTU,
		maxSessions: 8,
		runFor:      500 * time.Millisecond,
	}
	writeLabCover(t).apply(&opts)
	return opts
}

// TestTheGatewayRefusesAGatewayIDCarryingEdgeWhitespace is the defect.
//
// Every value below produces a gateway that starts, reports healthy and refuses
// the whole fleet in silence, because a v3 gateway does not answer a datagram it
// could not authenticate. The refusal must name the flag, or the operator is
// left with "the node is blocked" and no line to change.
func TestTheGatewayRefusesAGatewayIDCarryingEdgeWhitespace(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"one trailing space, the shape a copy-paste makes", "winsgw01 "},
		{"one leading space", " winsgw01"},
		{"both ends", " winsgw01 "},
		{"a trailing tab", "winsgw01\t"},
		{"a trailing newline, the shape a shell heredoc makes", "winsgw01\n"},
		{"a trailing CRLF, the shape a Windows file makes", "winsgw01\r\n"},
		{"a leading no-break space", "\u00a0winsgw01"},
		{"a trailing ideographic space", "winsgw01\u3000"},
		{"a value that is nothing but whitespace once trimmed", "   "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := operatorValueOptions(t)
			opts.gatewayID = tc.value
			err := runServe(opts, new(bytes.Buffer))
			if err == nil {
				t.Fatalf("the gateway started with -gateway-id %q. It would key the "+
					"admission tag over %d bytes while every host that trims keys over "+
					"%d, and refuse every client in the fleet in silence.",
					tc.value, len(tc.value), len(strings.TrimSpace(tc.value)))
			}
			if !strings.Contains(err.Error(), "-gateway-id") {
				t.Errorf("the refusal does not name the flag:\n  %v", err)
			}
		})
	}
}

// TestTheWhitespaceRefusalReportsWhatItActuallyMeasured.
//
// A diagnostic string in this tree once read "4m0s of injected time" and turned
// out to be a hardcoded constant; it was relayed to the owner as evidence of a
// protocol defect. So this asserts the counts and the code points come from the
// VALUE rather than from the message: three different shapes, three different
// reports, and a value whose whitespace is invisible in a terminal must have its
// code points spelled out.
func TestTheWhitespaceRefusalReportsWhatItActuallyMeasured(t *testing.T) {
	for _, tc := range []struct {
		value string
		wants []string
		notes []string
	}{
		{
			value: "winsgw01 ",
			wants: []string{"1 trailing whitespace byte(s):", "U+0020"},
			// An ASCII space is one byte and one code point, so the code-point
			// clause must NOT appear: it is said only when the two differ.
			notes: []string{"leading", "code point(s)"},
		},
		{
			value: "\t\tw ",
			wants: []string{"2 leading whitespace byte(s):", "U+0009", "1 trailing whitespace byte(s):", "U+0020"},
			notes: []string{"code point(s)"},
		},
		{
			value: "winsgw01\r\n",
			wants: []string{"2 trailing whitespace byte(s):", "U+000D", "U+000A"},
			notes: []string{"leading", "code point(s)"},
		},
		{
			// One non-ASCII space is several BYTES. Bytes are the unit that
			// matters — the admission tag is computed over them and the
			// divergence is a byte-length one — but "2 leading whitespace
			// byte(s)" beside a single code point reads like a miscount unless
			// both are said. Operators name nodes in their own language, so this
			// is not a corner case in this fleet.
			value: "\u00a0winsgw01",
			wants: []string{"2 leading whitespace byte(s) in 1 code point(s):", "U+00A0"},
			notes: []string{"trailing"},
		},
		{
			value: "winsgw01\u3000",
			wants: []string{"3 trailing whitespace byte(s) in 1 code point(s):", "U+3000"},
			notes: []string{"leading"},
		},
	} {
		got := edgeWhitespaceReport(tc.value)
		for _, want := range tc.wants {
			if !strings.Contains(got, want) {
				t.Errorf("the report for %q does not contain %q:\n  %s", tc.value, want, got)
			}
		}
		// The negative half. A report that always mentions both ends is a
		// template, not a measurement.
		for _, absent := range tc.notes {
			if strings.Contains(got, absent) {
				t.Errorf("the report for %q mentions %q, which it does not have:\n  %s",
					tc.value, absent, got)
			}
		}
		// And the value itself, so an operator can diff it against the hub.
		if !strings.Contains(got, fmt.Sprintf("%x", tc.value)) {
			t.Errorf("the report for %q does not carry the value's bytes:\n  %s", tc.value, got)
		}
	}
	// A clean value has nothing to report beyond itself: no phantom "0 leading"
	// clause that would read as a finding.
	clean := edgeWhitespaceReport("winsgw01")
	for _, absent := range []string{"leading", "trailing"} {
		if strings.Contains(clean, absent) {
			t.Errorf("a clean value reports edge whitespace: %s", clean)
		}
	}
}

// TestTheOperatorValueIsRefusedBeforeTheSocketIsBound is the #8 shape applied to
// #5: validate where the operator is standing.
//
// The proof is by CONTENTION. The test holds the listen address itself, so a
// runServe that got as far as net.ListenUDP would fail with an address-in-use
// error instead. Only a refusal that happened strictly earlier can name
// -gateway-id.
func TestTheOperatorValueIsRefusedBeforeTheSocketIsBound(t *testing.T) {
	held, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()

	opts := operatorValueOptions(t)
	opts.listen = held.LocalAddr().String()
	opts.gatewayID = "winsgw01 "

	// The control: the same held address with a CLEAN gateway id must produce a
	// BIND failure. Without this the test would pass just as well against a
	// runServe that refused everything for some unrelated reason.
	clean := opts
	clean.gatewayID = "winsgw01"
	bindErr := runServe(clean, new(bytes.Buffer))
	if bindErr == nil {
		t.Fatal("two processes bound the same UDP port; this test's premise is wrong")
	}
	if strings.Contains(bindErr.Error(), "-gateway-id") {
		t.Fatalf("the control refusal names -gateway-id, so it is not a bind error: %v", bindErr)
	}

	err = runServe(opts, new(bytes.Buffer))
	if err == nil {
		t.Fatal("a gateway id carrying whitespace was accepted")
	}
	if !strings.Contains(err.Error(), "-gateway-id") {
		t.Fatalf("the refusal is %v; it does not name -gateway-id, so the whitespace "+
			"check did not run before the bind", err)
	}
	if strings.Contains(err.Error(), bindErr.Error()) {
		t.Fatalf("the refusal carries the bind error, so the socket was reached first: %v", err)
	}
}

// TestEveryLegitimateGatewayIDStillStartsServesAndStops is the OVER-FIRE
// CONTROL, and it is not optional.
//
// A validator that refuses a working gateway is a worse outage than the silence
// it was written to prevent: the silent gateway fails for whoever misconfigured
// it, and an over-eager one fails for everyone at once. Every value here must
// start, serve and stop cleanly.
func TestEveryLegitimateGatewayIDStillStartsServesAndStops(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"the ordinary operator name", "winsgw01"},
		{"the base64 spelling the descriptor carries", "d2luc2d3MDE="},
		{"INTERNAL whitespace, which somebody may well have meant", "wins gw 01"},
		{"a single character", "g"},
		{"punctuation and separators", "wins-gw_01.myanmar:3"},
		{"non-ASCII, because operators name nodes in their own language", "ရန်ကုန်-01"},
		{"the longest value core accepts", strings.Repeat("g", 255)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := operatorValueOptions(t)
			opts.gatewayID = tc.value
			if err := runServe(opts, new(bytes.Buffer)); err != nil {
				t.Fatalf("a legitimate -gateway-id %q was refused, which is a worse outage "+
					"than the silence this check exists to prevent: %v", tc.value, err)
			}
			// And the check has teeth on this value: the same string with one
			// space appended must be refused. Otherwise a validator that
			// accepted everything would pass this whole table.
			spoilt := opts
			spoilt.gatewayID = tc.value + " "
			if err := runServe(spoilt, new(bytes.Buffer)); err == nil {
				t.Fatalf("%q was accepted with a trailing space", tc.value)
			}
		})
	}
}

// TestTheWhitespaceCheckDoesNotChangeWhatTheGatewayKeysWith.
//
// The one thing that must NOT move. gateway_id is an authenticated input to the
// admission tag and the raw-bytes rule is what four other call sites in this
// tree agree with; a normalisation invented at this end would become a rule
// every host has to remember. The check narrows which values may reach the
// keying and leaves the keying alone.
func TestTheWhitespaceCheckDoesNotChangeWhatTheGatewayKeysWith(t *testing.T) {
	for _, id := range []string{"winsgw01", "wins gw 01", "d2luc2d3MDE="} {
		opts := operatorValueOptions(t)
		opts.gatewayID = id
		if err := validateOperatorValues(opts); err != nil {
			t.Fatalf("%q was refused: %v", id, err)
		}
		cfg, err := buildSessionConfig(opts)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(cfg.Core.Gateway.GatewayID); got != id {
			t.Errorf("the gateway keys with %q for -gateway-id %q; it must key with the "+
				"operator's raw bytes", got, id)
		}
	}
}
