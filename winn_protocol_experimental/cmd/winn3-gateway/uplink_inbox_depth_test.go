package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
)

// uplinkInboxDepthTestEnv runs this package's existing tests at one allowed
// -uplink-inbox-depth (owner ruling 2026-10-10: the depth is chosen between
// 1,536 and 8,192, so every allowed value must pass the same suite). Unset
// keeps the shipped default. A value outside uplinkInboxDepths fails the
// test binary at start rather than silently testing the default.
const uplinkInboxDepthTestEnv = "WINN3_TEST_UPLINK_INBOX_DEPTH"

func init() {
	v := os.Getenv(uplinkInboxDepthTestEnv)
	if v == "" {
		return
	}
	n, err := strconv.Atoi(v)
	if err != nil || n == 0 {
		panic(fmt.Sprintf("%s=%q is not an allowed inbox depth", uplinkInboxDepthTestEnv, v))
	}
	d, err := resolveUplinkInboxDepth(n)
	if err != nil {
		panic(fmt.Sprintf("%s: %v", uplinkInboxDepthTestEnv, err))
	}
	defaultUplinkInboxDepth = d
}

// TestEveryUplinkInboxDepthKeepsTheD23Bounds pins, for each value
// -uplink-inbox-depth accepts, the two bounds ruling D23 and its 2026-10-10
// revision rest on, and that a production-shaped pipe holds exactly that
// many messages and refuses the next as ErrQueueFull (a drop the token
// window survives, never a teardown).
func TestEveryUplinkInboxDepthKeepsTheD23Bounds(t *testing.T) {
	want := []int{2048, 4096, 8192}
	if len(uplinkInboxDepths) != len(want) {
		t.Fatalf("uplinkInboxDepths = %v, want %v", uplinkInboxDepths, want)
	}
	oldTolerance := core.DefaultTokenWindow/2 - 1
	cliff := gatewayTokenWindow/2 - 1
	for i, d := range uplinkInboxDepths {
		if d != want[i] {
			t.Fatalf("uplinkInboxDepths[%d] = %d, want %d (owner ruling 2026-10-10)", i, d, want[i])
		}
		if d < 1536 || d > 8192 {
			t.Fatalf("depth %d is outside the owner's 1,536 to 8,192 range", d)
		}
		if d&(d-1) != 0 {
			t.Fatalf("depth %d is not a power of two", d)
		}
		if d > gatewayTokenWindow/4 {
			t.Fatalf("depth %d is above the D23 derivation gatewayTokenWindow/4 = %d", d, gatewayTokenWindow/4)
		}
		if d < 2*oldTolerance {
			t.Fatalf("depth %d is under twice the old D23 reorder tolerance %d", d, oldTolerance)
		}
		if d >= cliff {
			t.Fatalf("depth %d is not under the recent-loss cliff gatewayTokenWindow/2-1 = %d; "+
				"the window must stay wider than the inbox so a burst the inbox drops is survived", d, cliff)
		}
		if got, err := resolveUplinkInboxDepth(d); err != nil || got != d {
			t.Fatalf("resolveUplinkInboxDepth(%d) = %d, %v", d, got, err)
		}
		if got := (&server{inboxDepth: d}).pipeInboxDepth(); got != d {
			t.Fatalf("a server built with depth %d builds pipes at %d", d, got)
		}
		t.Run(fmt.Sprintf("pipe_holds_exactly_%d", d), func(t *testing.T) {
			p := mustPipe(t, d)
			defer p.Close()
			msg := []byte("x")
			for j := 0; j < d; j++ {
				if err := p.Deliver(msg); err != nil {
					t.Fatalf("Deliver %d/%d: %v", j+1, d, err)
				}
			}
			if err := p.Deliver(msg); !errors.Is(err, carrier.ErrQueueFull) {
				t.Fatalf("a %d-deep inbox accepted message %d (%v)", d, d+1, err)
			}
		})
	}
	if os.Getenv(uplinkInboxDepthTestEnv) == "" && defaultUplinkInboxDepth != inboxDepth {
		t.Fatalf("the shipped -uplink-inbox-depth default is %d, want inboxDepth = %d until the "+
			"owner-ruled arms pick a depth", defaultUplinkInboxDepth, inboxDepth)
	}
	if got := (&server{}).pipeInboxDepth(); got != defaultUplinkInboxDepth {
		t.Fatalf("a server built without the flag uses depth %d, want the default %d", got, defaultUplinkInboxDepth)
	}
}

func TestUplinkInboxDepthRefusesUnmeasuredValues(t *testing.T) {
	for _, d := range []int{-1, 1, 512, 1024, 1536, 2047, 2049, 3072, 4095, 6144, 8191, 8193, 16384, gatewayTokenWindow} {
		if got, err := resolveUplinkInboxDepth(d); err == nil {
			t.Fatalf("resolveUplinkInboxDepth(%d) accepted %d; only %v are allowed", d, got, uplinkInboxDepths)
		}
	}
	if got, err := resolveUplinkInboxDepth(0); err != nil || got != defaultUplinkInboxDepth {
		t.Fatalf("resolveUplinkInboxDepth(0) = %d, %v; want the default %d", got, err, defaultUplinkInboxDepth)
	}
}

// TestUplinkInboxDepthFlagReachesTheResourceProfile drives the flag through
// run, so the flag, its validation and the resource accounting the
// installer's memory figures rest on are tested as one path.
func TestUplinkInboxDepthFlagReachesTheResourceProfile(t *testing.T) {
	for _, d := range uplinkInboxDepths {
		var out bytes.Buffer
		if err := run([]string{"-mode", "resources", "-uplink-inbox-depth", strconv.Itoa(d)}, &out); err != nil {
			t.Fatalf("-uplink-inbox-depth %d: %v", d, err)
		}
		var p resourceProfile
		if err := json.Unmarshal(out.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		if p.PipeInboxPackets != uint64(d) {
			t.Fatalf("-uplink-inbox-depth %d: pipe_inbox_packets %d", d, p.PipeInboxPackets)
		}
		if want := uint64(d) * max(p.PipeBufferSlabBytes, p.MessageBytes); p.PipePayloadBackingPerSessionBytes != want {
			t.Fatalf("-uplink-inbox-depth %d: per-session pipe backing %d B, want %d B",
				d, p.PipePayloadBackingPerSessionBytes, want)
		}
	}
	var out bytes.Buffer
	if err := run([]string{"-mode", "resources"}, &out); err != nil {
		t.Fatal(err)
	}
	var p resourceProfile
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.PipeInboxPackets != uint64(defaultUplinkInboxDepth) {
		t.Fatalf("no flag: pipe_inbox_packets %d, want the default %d", p.PipeInboxPackets, defaultUplinkInboxDepth)
	}
	err := run([]string{"-mode", "resources", "-uplink-inbox-depth", "1536"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "-uplink-inbox-depth") {
		t.Fatalf("resources at 1536: got %v, want the -uplink-inbox-depth refusal", err)
	}
	err = run([]string{"-mode", "serve", "-listen", "127.0.0.1:0", "-inner-v4", "10.64.0.1",
		"-uplink-inbox-depth", "3000"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "-uplink-inbox-depth") {
		t.Fatalf("serve at 3000: got %v, want the -uplink-inbox-depth refusal", err)
	}
}

// TestServeWiresTheUplinkInboxDepth pins the one line unit tests cannot
// reach without a forwarding host: runServe's server literal carries the
// resolved depth, so the flag is not validated and then dropped.
func TestServeWiresTheUplinkInboxDepth(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(body, []byte("srv := &server{"))
	if start < 0 {
		t.Fatal("main.go no longer builds the server as srv := &server{")
	}
	end := bytes.Index(body[start:], []byte("\n\t}\n"))
	if end < 0 {
		t.Fatal("could not bound runServe's server literal")
	}
	lit := stripSpace(litCode(body[start : start+end]))
	if !bytes.Contains(lit, []byte("inboxDepth:opts.uplinkInboxDepth,")) {
		t.Fatal("runServe's server literal does not set inboxDepth from opts.uplinkInboxDepth; " +
			"-uplink-inbox-depth would be validated and then ignored")
	}
	resolved := bytes.Index(body, []byte("depth, err := resolveUplinkInboxDepth(opts.uplinkInboxDepth)\n\tif err != nil {\n\t\treturn err\n\t}\n\topts.uplinkInboxDepth = depth\n"))
	if resolved < 0 || resolved > start {
		t.Fatal("runServe no longer resolves -uplink-inbox-depth into opts before it builds the server")
	}
}

// TestAsyncTunWriteIsOnByDefault pins the owner ruling of 2026-10-10
// (multicore is always on): with -forward and no -forward-async-write on the
// command line the async writer runs, WINN3_GATEWAY_ASYNC_WRITE=0 is the
// rollback, an explicit flag wins either way, and any other value is refused.
func TestAsyncTunWriteIsOnByDefault(t *testing.T) {
	for _, tc := range []struct {
		flagValue, flagSet bool
		env                string
		want               bool
		wantErr            bool
	}{
		{false, false, "", true, false},
		{false, false, "1", true, false},
		{false, false, "0", false, false},
		{false, true, "", false, false},
		{false, true, "1", false, false},
		{true, true, "0", true, false},
		{false, false, "yes", false, true},
	} {
		got, err := resolveAsyncWriteDefault(tc.flagValue, tc.flagSet, tc.env)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Fatalf("resolveAsyncWriteDefault(%v, %v, %q) = %v, %v; want %v, error %v",
				tc.flagValue, tc.flagSet, tc.env, got, err, tc.want, tc.wantErr)
		}
	}
	if asyncWriteDefaultEnv != "WINN3_GATEWAY_ASYNC_WRITE" {
		t.Fatalf("the rollback variable is %q, want WINN3_GATEWAY_ASYNC_WRITE", asyncWriteDefaultEnv)
	}
}
