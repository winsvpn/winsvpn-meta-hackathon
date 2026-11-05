package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func decodeReplies(t *testing.T, out []byte) []map[string]any {
	t.Helper()
	var replies []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(out), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var reply map[string]any
		if err := json.Unmarshal(line, &reply); err != nil {
			t.Fatalf("reply is not JSON: %q", line)
		}
		replies = append(replies, reply)
	}
	return replies
}

func TestServeAnswersOneLinePerRequestWithTheEchoAndTheReply(t *testing.T) {
	seen := 0
	fake := func(_ context.Context, req *Request) Result {
		seen++
		if seen == 1 {
			reply := append([]byte{}, req.DNSQuery...)
			reply[2] |= 0x80
			return Result{Status: statusCarried, Reply: reply, Handshake: true, Elapsed: 1500 * time.Millisecond}
		}
		return Result{Status: statusNoReply, Detail: "no handshake", Elapsed: 20 * time.Second}
	}
	first := validRequest()
	second := validRequest()
	second["id"] = 8
	second["slug"] = "lab-2"
	in := string(encode(t, first)) + "\n" + string(encode(t, second)) + "\n"
	var out bytes.Buffer
	if rc := serve(context.Background(), strings.NewReader(in), &out, "udp", fake); rc != 0 {
		t.Fatalf("rc %d", rc)
	}
	replies := decodeReplies(t, out.Bytes())
	if len(replies) != 2 || seen != 2 {
		t.Fatalf("%d replies for 2 requests (probed %d)", len(replies), seen)
	}
	want := validRequest()
	query, _ := hex.DecodeString(want["dns_query_hex"].(string))
	query[2] |= 0x80
	if replies[0]["id"] != float64(7) || replies[0]["slug"] != "lab-1" || replies[0]["transport"] != "udp" {
		t.Fatalf("echo wrong: %v", replies[0])
	}
	if replies[0]["dns_reply_hex"] != hex.EncodeToString(query) || replies[0]["status"] != statusCarried || replies[0]["handshake"] != true {
		t.Fatalf("carried reply wrong: %v", replies[0])
	}
	if replies[1]["id"] != float64(8) || replies[1]["slug"] != "lab-2" || replies[1]["dns_reply_hex"] != "" || replies[1]["status"] != statusNoReply {
		t.Fatalf("no-reply verdict wrong: %v", replies[1])
	}
	if _, present := replies[1]["error"]; present {
		t.Fatal("a probed request carries no error")
	}
}

func TestServeRefusesMalformedLinesWithoutAVerdictAndKeepsGoing(t *testing.T) {
	probed := 0
	fake := func(_ context.Context, req *Request) Result {
		probed++
		return Result{Status: statusNoReply}
	}
	bad := validRequest()
	bad["transport"] = "stealth"
	in := "garbage\n" + string(encode(t, bad)) + "\n" + string(encode(t, validRequest())) + "\n"
	var out bytes.Buffer
	if rc := serve(context.Background(), strings.NewReader(in), &out, "udp", fake); rc != 0 {
		t.Fatalf("rc %d", rc)
	}
	replies := decodeReplies(t, out.Bytes())
	if len(replies) != 3 || probed != 1 {
		t.Fatalf("%d replies, %d probes", len(replies), probed)
	}
	for _, refused := range replies[:2] {
		if _, present := refused["dns_reply_hex"]; present {
			t.Fatalf("a refusal carries dns_reply_hex: %v", refused)
		}
		if !strings.HasPrefix(refused["error"].(string), "refused: ") {
			t.Fatalf("no refusal reason: %v", refused)
		}
	}
	if _, present := replies[0]["id"]; present {
		t.Fatalf("garbage got an id: %v", replies[0])
	}
	if replies[1]["id"] != float64(7) || replies[1]["slug"] != "lab-1" || replies[1]["transport"] != "stealth" {
		t.Fatalf("a readable refusal echoes what it read: %v", replies[1])
	}
	if replies[2]["dns_reply_hex"] != "" {
		t.Fatalf("the valid request after a refusal was not probed: %v", replies[2])
	}
}

func TestServeNeverPrintsKeyMaterial(t *testing.T) {
	fake := func(_ context.Context, req *Request) Result {
		return Result{Status: statusDeviceFailed, Detail: "device configuration refused: failed to parse jc"}
	}
	request := validRequest()
	in := string(encode(t, request)) + "\n"
	var out bytes.Buffer
	serve(context.Background(), strings.NewReader(in), &out, "udp", fake)
	text := out.String()
	for _, secret := range []string{testKey(0x11), strings.Repeat("11", 32)} {
		if strings.Contains(text, secret) {
			t.Fatal("the reply carries the private key")
		}
	}
}

func TestAnOverLongLineIsRefusedNotProbed(t *testing.T) {
	probed := false
	fake := func(_ context.Context, req *Request) Result { probed = true; return Result{} }
	in := strings.Repeat("x", maxLine+10) + "\n"
	var out bytes.Buffer
	serve(context.Background(), strings.NewReader(in), &out, "udp", fake)
	replies := decodeReplies(t, out.Bytes())
	if probed || len(replies) != 1 || !strings.Contains(replies[0]["error"].(string), "refused") {
		t.Fatalf("probed=%v replies=%v", probed, replies)
	}
}

func TestRenderMapsOnlyACarriedResultToAReply(t *testing.T) {
	req := &Request{ID: 3, Slug: "s", Transport: "udp"}
	carried := render(req, Result{Status: statusCarried, Reply: []byte{1, 2}})
	if *carried.DNSReplyHex != "0102" {
		t.Fatalf("carried hex %q", *carried.DNSReplyHex)
	}
	// A reply that is not a carried verdict must never surface bytes, even
	// if the result struct holds some.
	for _, status := range []string{statusNoReply, statusEndpointUnusable} {
		r := render(req, Result{Status: status, Reply: []byte{1, 2}})
		if *r.DNSReplyHex != "" {
			t.Fatalf("%s rendered %q", status, *r.DNSReplyHex)
		}
	}
	empty := render(req, Result{Status: statusCarried})
	if *empty.DNSReplyHex != "" {
		t.Fatal("a carried status without bytes rendered a reply")
	}
}

func TestServeRefusesAnEmptyRequestLine(t *testing.T) {
	probed := false
	fake := func(_ context.Context, _ *Request) Result {
		probed = true
		return Result{}
	}
	var out bytes.Buffer
	rc := serve(context.Background(), strings.NewReader("\n"+string(encode(t, validRequest()))+"\n"), &out, "udp", fake)
	replies := decodeReplies(t, out.Bytes())
	if rc != 0 || !probed || len(replies) != 2 {
		t.Fatalf("rc=%d probed=%v replies=%v", rc, probed, replies)
	}
	if _, present := replies[0]["dns_reply_hex"]; present {
		t.Fatal("an empty request produced a verdict")
	}
	reason, ok := replies[0]["error"].(string)
	if !ok || !strings.HasPrefix(reason, "refused: ") {
		t.Fatalf("missing refusal: %v", replies[0])
	}
	if replies[1]["id"] != float64(7) {
		t.Fatalf("the request after the empty line was not answered in step: %v", replies[1])
	}
}

// A configuration the engine rejects is no verdict about the node: the reply
// echoes the request and carries an error, never a dns_reply_hex.
func TestAnEngineRefusalRendersNoVerdict(t *testing.T) {
	req := &Request{ID: 3, Slug: "s", Transport: "udp"}
	refused := render(req, Result{Status: statusRefused, Detail: "device configuration rejected", Reply: []byte{1, 2}})
	if refused.DNSReplyHex != nil || refused.Handshake != nil || !strings.HasPrefix(refused.Error, "refused: ") {
		t.Fatalf("a refusal rendered a verdict: %+v", refused)
	}
	if refused.ID == nil || *refused.ID != 3 || refused.Slug != "s" || refused.Transport != "udp" {
		t.Fatalf("a refusal does not echo the request: %+v", refused)
	}
	fake := func(_ context.Context, _ *Request) Result {
		return Result{Status: statusRefused, Detail: "device configuration rejected"}
	}
	var out bytes.Buffer
	serve(context.Background(), strings.NewReader(string(encode(t, validRequest()))+"\n"), &out, "udp", fake)
	replies := decodeReplies(t, out.Bytes())
	if len(replies) != 1 || replies[0]["id"] != float64(7) {
		t.Fatalf("replies %v", replies)
	}
	if _, present := replies[0]["dns_reply_hex"]; present {
		t.Fatalf("an engine refusal carries dns_reply_hex: %v", replies[0])
	}
}

// A fault on the hub itself is no verdict about the node: the reply echoes
// the request and carries an error, never a dns_reply_hex.
func TestAHubLocalFaultRendersNoVerdict(t *testing.T) {
	req := &Request{ID: 4, Slug: "s", Transport: "stealth"}
	local := render(req, Result{Status: statusDeviceFailed, Detail: "device did not come up: bind", Reply: []byte{1, 2}})
	if local.DNSReplyHex != nil || local.Handshake != nil || !strings.HasPrefix(local.Error, "local fault: ") {
		t.Fatalf("a hub-local fault rendered a verdict: %+v", local)
	}
	if local.ID == nil || *local.ID != 4 || local.Slug != "s" || local.Transport != "stealth" {
		t.Fatalf("a hub-local fault does not echo the request: %+v", local)
	}
}
