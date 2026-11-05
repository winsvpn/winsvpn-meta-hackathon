package main

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"reflect"
	"strconv"
	"testing"
)

func TestResourceProfileValidatedSizing(t *testing.T) {
	for _, tc := range []struct {
		mtu, sessions                                        int
		message, inner, send, pipe, admitted, staging, total uint64
	}{
		{1450, 64, 1402, 1373, 16777216, 16777216, 33554432, 262144, 2181300224},
		{8192, 2, 8144, 8115, 66478080, 66715648, 66715648, 521216, 333624320},
	} {
		p, err := buildResourceProfile(serveOptions{pathMTU: tc.mtu, plan: "udp", maxSessions: tc.sessions, uplinkInboxDepth: inboxDepth})
		if err != nil {
			t.Fatal(err)
		}
		got := []uint64{p.MessageBytes, p.InnerPayloadBytes, p.SendPayloadBackingPerSessionBytes, p.PipePayloadBackingPerSessionBytes, p.SharedDemuxAdmittedBackingBytes, p.SharedDemuxStagingBackingBytes, p.ConfiguredQueuePayloadBackingBytes}
		want := []uint64{tc.message, tc.inner, tc.send, tc.pipe, tc.admitted, tc.staging, tc.total}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("profile arithmetic %v, want %v", got, want)
		}
		if p.SchemaVersion != 1 || p.AccountingScope != "queue_payload_backing_only" || p.SendQueuePackets != 8192 || p.PipeInboxPackets != uint64(inboxDepth) || p.DemuxSides != 2 || p.DemuxPacketsPerSide != 4096 || p.BatchReceiveSlots != 64 {
			t.Fatal("resource contract changed")
		}
		if p.SendBufferSlabBytes != 2048 || p.PipeBufferSlabBytes != 2048 {
			t.Fatal("allocator slab contract changed")
		}
	}
}

func TestResourceProfileRejectsInvalidAndOverflow(t *testing.T) {
	for _, opts := range []serveOptions{
		{pathMTU: 1450, plan: "udp", maxSessions: 0},
		{pathMTU: 1450, plan: "udp", maxSessions: -1},
		{pathMTU: 0, plan: "udp", maxSessions: 1},
		{pathMTU: 1450, plan: "invalid", maxSessions: 1},
		{pathMTU: 1450, plan: "udp,udp", maxSessions: 1},
	} {
		if _, err := buildResourceProfile(opts); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	if _, err := resourceProduct(math.MaxUint64, 2); err == nil {
		t.Fatal("product overflow accepted")
	}
	if _, err := resourceSum(math.MaxUint64, 1); err == nil {
		t.Fatal("sum overflow accepted")
	}
	if n, err := resourceProduct(math.MaxUint64, 1); err != nil || n != math.MaxUint64 {
		t.Fatal("valid product rejected")
	}
	if n, err := resourceSum(math.MaxUint64-1, 1); err != nil || n != math.MaxUint64 {
		t.Fatal("valid sum rejected")
	}
	if strconv.IntSize == 64 {
		if _, err := buildResourceProfile(serveOptions{pathMTU: 1450, plan: "udp", maxSessions: int(^uint(0) >> 1)}); err == nil {
			t.Fatal("configured total overflow accepted")
		}
	}
}

func TestResourceCLIWithoutKeysOrSockets(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"-mode", "resources", "-plan", " UDP, , TCP, TLS ", "-max-sessions", "2", "-path-mtu", "1450", "-listen", "invalid listen address", "-static", "missing-static-file", "-admission", "missing-admission-file", "-forward"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(&out)
	dec.DisallowUnknownFields()
	var p resourceProfile
	if err := dec.Decode(&p); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.MigrationPlan, []string{"udp", "tcp", "tls"}) || p.MaxSessions != 2 || p.PathMTU != 1450 {
		t.Fatal("CLI identity mismatch")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		t.Fatalf("extra output: %v", err)
	}
	var invalid bytes.Buffer
	if err := run([]string{"-mode", "resources", "-max-sessions", "0"}, &invalid); err == nil || invalid.Len() != 0 {
		t.Fatal("invalid CLI must not emit a profile")
	}
}

func TestResourceProfileConstructorSourcePin(t *testing.T) {
	pinNewSessionPipeDerivesDepthFromTheTokenWindow(t)
}
