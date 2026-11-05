//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"golang.org/x/sys/unix"
)

// TestStatusJSONCarriesExactScalarCounterValues drives both scalar helpers on a
// real split socket with scripted writes whose outcomes are known, then checks
// the exact NUMBERS the serialized posture document publishes, not only that
// the keys exist.
func TestStatusJSONCarriesExactScalarCounterValues(t *testing.T) {
	real := newLoopbackUDP(t)
	split := newSplitUDP(real, demuxDatagramMin)
	defer split.stop()
	opts := enableUDPSendErrorReporting(real)
	q := split.errq

	fail := func(errs ...error) func() (int, error) {
		i := 0
		return func() (int, error) {
			i++
			if i <= len(errs) {
				return 0, errs[i-1]
			}
			return 100, nil
		}
	}
	many := func(e error) []error {
		out := make([]error, 50)
		for i := range out {
			out[i] = e
		}
		return out
	}

	// Cover: ENOBUFS to exhaustion: 7 refused, 1 dropped, 0 matching retries.
	if n, err := q.SendCoverScalar(100, fail(many(unix.ENOBUFS)...)); n != 100 || err != nil {
		t.Fatalf("cover exhaustion returned (%d, %v)", n, err)
	}
	// Cover: one ECONNREFUSED then success: 1 refused, 1 matching retry.
	if _, err := q.SendCoverScalar(100, fail(unix.ECONNREFUSED)); err != nil {
		t.Fatal(err)
	}
	// Cover: EMSGSIZE passes through to quic-go, uncounted.
	if _, err := q.SendCoverScalar(100, fail(unix.EMSGSIZE)); err != unix.EMSGSIZE {
		t.Fatalf("cover EMSGSIZE returned %v", err)
	}
	// v3: ENOBUFS returned for retention: 1 refused.
	if _, err := q.SendScalarRetain(fail(unix.ENOBUFS)); err != unix.ENOBUFS {
		t.Fatalf("v3 ENOBUFS returned %v", err)
	}
	// v3: synchronous-looking EMSGSIZE, included and exhausted: 5 refused, 4
	// matching retries, error returned.
	if _, err := q.SendScalarRetain(fail(many(unix.EMSGSIZE)...)); err != unix.EMSGSIZE {
		t.Fatalf("v3 EMSGSIZE returned %v", err)
	}

	b, err := json.Marshal(serveStatus{Event: "posture", UdpSendErrors: buildUDPSendErrorStatus(split.v3, opts)})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		UdpSendErrors map[string]any `json:"udp_send_errors"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	want := map[string]string{
		"scalar_refused":         "14", // 7 + 1 + 0 + 1 + 5
		"scalar_dropped":         "1",
		"matching_error_retries": "5", // 0 + 1 + 0 + 0 + 4
		"transmit_refused":       "0",
	}
	for key, v := range want {
		num, ok := doc.UdpSendErrors[key].(json.Number)
		if got := num.String(); !ok || got != v {
			t.Errorf("status %s = %s, want %s (document %s)", key, got, v, b)
		}
	}
}
