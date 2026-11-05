package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestSendQueueFQIsOnByDefault pins the 2026-10-11 default flip (TUNNEL-SPEED-2
// Turn 14, the reset build): with no -send-queue-fq on the command line the
// per-host-pair fair queue runs, WINN3_GATEWAY_SEND_QUEUE_FQ=0 is the
// rollback, an explicit flag wins either way, and any other value is refused.
func TestSendQueueFQIsOnByDefault(t *testing.T) {
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
		got, err := resolveSendQueueFQDefault(tc.flagValue, tc.flagSet, tc.env)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Fatalf("resolveSendQueueFQDefault(%v, %v, %q) = %v, %v; want %v, error %v",
				tc.flagValue, tc.flagSet, tc.env, got, err, tc.want, tc.wantErr)
		}
	}
	if sendQueueFQDefaultEnv != "WINN3_GATEWAY_SEND_QUEUE_FQ" {
		t.Fatalf("the rollback variable is %q, want WINN3_GATEWAY_SEND_QUEUE_FQ", sendQueueFQDefaultEnv)
	}
}

// TestServeResolvesTheSendQueueFQDefault pins the wiring: the flag default is
// true, main records whether the flag was passed, and runServe resolves the
// environment into opts before it builds the server, so a refusal happens
// before the socket exists and the resolved value is what newSession reads
// (server.sendQueueFQ, SetSendQueueFQ on every UDP peer session).
func TestServeResolvesTheSendQueueFQDefault(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`sendQueueFQ := flags.Bool("send-queue-fq", true,`)) {
		t.Fatal("the -send-queue-fq flag default is no longer true")
	}
	if !bytes.Contains(body, []byte("if f.Name == \"send-queue-fq\" {\n\t\t\tsendQueueFQSet = true\n")) {
		t.Fatal("main no longer records whether -send-queue-fq was passed (flags.Visit)")
	}
	start := bytes.Index(body, []byte("srv := &server{"))
	if start < 0 {
		t.Fatal("main.go no longer builds the server as srv := &server{")
	}
	resolved := bytes.Index(body, []byte(
		"sendFQ, err := resolveSendQueueFQDefault(opts.sendQueueFQ, opts.sendQueueFQSet,\n\t\tos.Getenv(sendQueueFQDefaultEnv))\n"))
	if resolved < 0 || resolved > start {
		t.Fatal("runServe no longer resolves -send-queue-fq into opts before it builds the server")
	}
	if !bytes.Contains(body[start:], []byte("sendQueueFQ:         opts.sendQueueFQ,")) {
		t.Fatal("the server literal no longer carries opts.sendQueueFQ")
	}
}
