package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func startTestIngest(t *testing.T) (string, func()) {
	t.Helper()
	inner := netip.MustParseAddr("10.99.0.1")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{
		Handler:           newSpeedtestIngestServer().handler(),
		ReadHeaderTimeout: speedtestReadTimeout,
		ReadTimeout:       speedtestHandlerTimeout,
		WriteTimeout:      speedtestHandlerTimeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    4 << 10,
	}
	go func() { _ = server.Serve(listener) }()
	stop := func() { _ = server.Close() }
	_ = inner
	_ = context.Background()
	_ = startSpeedtestIngest
	return "http://" + listener.Addr().String(), stop
}

func TestSpeedtestUploadCountsBytes(t *testing.T) {
	base, stop := startTestIngest(t)
	defer stop()
	payload := bytes.Repeat([]byte{0xAB}, 8<<20)
	reader := bytes.NewReader(payload)
	resp, err := http.Post(base+"/speedtest/up", "application/octet-stream", reader)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte(`"received_bytes":8388608`)) {
		t.Fatalf("server counted wrong bytes: %s", body)
	}
}

func TestSpeedtestDownloadServesRequestedBytes(t *testing.T) {
	base, stop := startTestIngest(t)
	defer stop()
	resp, err := http.Get(base + "/speedtest/down?bytes=1048576")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if n != 1048576 {
		t.Fatalf("served %d bytes, want 1048576", n)
	}
}

func TestSpeedtestDownloadBusyReturnsWithoutWaiting(t *testing.T) {
	s := newSpeedtestIngestServer()
	for i := 0; i < cap(s.concurrent); i++ {
		s.concurrent <- struct{}{}
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/speedtest/down?bytes=1", nil)
	done := make(chan struct{})
	go func() {
		s.handleDownload(recorder, request)
		close(done)
	}()
	select {
	case <-done:
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("busy download status = %d, want 503", recorder.Code)
		}
	case <-time.After(time.Second):
		// Unblock the old implementation before failing the test.
		<-s.concurrent
		<-done
		t.Fatal("busy download waited for a slot instead of returning 503")
	}
}

func TestSpeedtestDownloadCapEnforced(t *testing.T) {
	base, stop := startTestIngest(t)
	defer stop()
	resp, err := http.Get(base + "/speedtest/down?bytes=999999999999")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	n, _ := io.Copy(io.Discard, resp.Body)
	if n != speedtestMaxDownloadBytes {
		t.Fatalf("served %d bytes, want cap %d", n, speedtestMaxDownloadBytes)
	}
}

func TestSpeedtestMethodGating(t *testing.T) {
	base, stop := startTestIngest(t)
	defer stop()
	resp, err := http.Get(base + "/speedtest/up")
	if err != nil {
		t.Fatalf("get up: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /up status = %d, want 405", resp.StatusCode)
	}
	resp2, err := http.Post(base+"/speedtest/down", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("post down: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /down status = %d, want 405", resp2.StatusCode)
	}
}

func TestSpeedtestConcurrentCapBound(t *testing.T) {
	base, stop := startTestIngest(t)
	defer stop()
	down := func(done chan<- error) {
		resp, err := http.Get(base + "/speedtest/down?bytes=104857600")
		if err != nil {
			done <- err
			return
		}
		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		done <- err
	}
	// Three downloads fit well inside the slot cap and must all complete. The
	// full-cap refusal is TestSpeedtestDownloadBusyReturnsWithoutWaiting.
	done := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go down(done)
	}
	for i := 0; i < 3; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("download %d: %v", i, err)
			}
		case <-time.After(60 * time.Second):
			t.Fatalf("download %d timed out", i)
		}
	}
}
