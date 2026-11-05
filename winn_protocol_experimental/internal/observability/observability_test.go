package observability

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthReadinessAndMetrics(t *testing.T) {
	registry := New()
	server := httptest.NewServer(registry.Handler())
	defer server.Close()

	assertStatus(t, server.URL+"/healthz", http.StatusOK)
	assertStatus(t, server.URL+"/readyz", http.StatusServiceUnavailable)

	notReadyMetrics, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	notReadyBody, err := io.ReadAll(notReadyMetrics.Body)
	_ = notReadyMetrics.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if notReadyMetrics.StatusCode != http.StatusOK {
		t.Fatalf("/metrics while not ready status = %d", notReadyMetrics.StatusCode)
	}
	if !strings.Contains(string(notReadyBody), "winn_protocol_ready 0") {
		t.Fatalf("metrics before SetReady must report ready 0:\n%s", notReadyBody)
	}
	if strings.Contains(string(notReadyBody), "winn_protocol_ready 1") {
		t.Fatalf("metrics before SetReady must not report ready 1:\n%s", notReadyBody)
	}
	if notReadyMetrics.Header.Get("Cache-Control") != "no-store" ||
		notReadyMetrics.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers missing: Cache-Control=%q X-Content-Type-Options=%q",
			notReadyMetrics.Header.Get("Cache-Control"),
			notReadyMetrics.Header.Get("X-Content-Type-Options"))
	}

	registry.SetReady(true)
	registry.Inc("rekey_committed")
	registry.Inc("rekey_committed")
	registry.ObserveDuration("carrier_recovery", 125*time.Millisecond)
	assertStatus(t, server.URL+"/readyz", http.StatusOK)

	response, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `winn_protocol_events_total{event="rekey_committed"} 2`) ||
		!strings.Contains(string(body), `winn_protocol_duration_seconds_count{operation="carrier_recovery"} 1`) ||
		!strings.Contains(string(body), `winn_protocol_duration_seconds_sum{operation="carrier_recovery"} 0.125000000`) ||
		!strings.Contains(string(body), "winn_protocol_ready 1") {
		t.Fatalf("unexpected metrics:\n%s", body)
	}
}

func assertStatus(t *testing.T, url string, expected int) {
	t.Helper()
	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != expected {
		t.Fatalf("%s status = %d, want %d", url, response.StatusCode, expected)
	}
}
