package mobility

import (
	"math"
	"sync"
	"testing"
	"time"
)

const testSessionID = "00112233445566778899aabbccddeeff"

func TestSessionID(t *testing.T) {
	sessionID, err := NewSessionID()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidSessionID(sessionID) {
		t.Fatalf("invalid generated ID %q", sessionID)
	}
	if ValidSessionID("00112233445566778899AABBCCDDEEFF") {
		t.Fatal("uppercase session ID accepted")
	}
}

func TestMobilityPreservesSessionAndGeneration(t *testing.T) {
	engine := testEngine(t)
	now := time.Unix(1_800_000_000, 0)
	mustObserve(t, engine, Observation{
		PathID: "wifi-h3", Success: true, RTT: 20 * time.Millisecond,
		Loss: 0, Throughput: 100, At: now,
	})
	if err := engine.Activate("wifi-h3", now); err != nil {
		t.Fatal(err)
	}
	if err := engine.Fail("wifi-h3", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	mustObserve(t, engine, Observation{
		PathID: "cell-h2", Success: true, RTT: 60 * time.Millisecond,
		Loss: .01, Throughput: 20, At: now.Add(2 * time.Second),
	})
	if err := engine.Activate("cell-h2", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	snapshot := engine.Snapshot(now.Add(2 * time.Second))
	if snapshot.SessionID != testSessionID || snapshot.TunnelGeneration != 7 {
		t.Fatalf("continuity invariant changed: %+v", snapshot)
	}
	if snapshot.ActivePath != "cell-h2" || snapshot.Phase != Online {
		t.Fatalf("unexpected recovered state: %+v", snapshot)
	}
	if snapshot.Switches != 1 {
		t.Fatalf("failover switch count = %d, want 1", snapshot.Switches)
	}
}

func TestHysteresisAndCooldownPreventFlapping(t *testing.T) {
	engine := testEngine(t)
	now := time.Unix(1_800_000_000, 0)
	mustObserve(t, engine, Observation{
		PathID: "wifi-h3", Success: true, RTT: 25 * time.Millisecond,
		Throughput: 50, At: now,
	})
	mustObserve(t, engine, Observation{
		PathID: "cell-h2", Success: true, RTT: 20 * time.Millisecond,
		Throughput: 50, At: now,
	})
	if err := engine.Activate("wifi-h3", now); err != nil {
		t.Fatal(err)
	}
	selected, err := engine.Select(now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if selected.ID != "wifi-h3" {
		t.Fatalf("cooldown allowed flap to %s", selected.ID)
	}
	for sample := 0; sample < 8; sample++ {
		mustObserve(t, engine, Observation{
			PathID: "cell-h2", Success: true, RTT: time.Millisecond,
			Throughput: 10_000, At: now.Add(20*time.Second + time.Duration(sample)*time.Millisecond),
		})
	}
	selected, err = engine.Select(now.Add(20 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if selected.ID != "cell-h2" {
		t.Fatalf("clear improvement was not selected: %s", selected.ID)
	}
}

func TestFailedPathBackoffAndFailClosed(t *testing.T) {
	engine := testEngine(t)
	now := time.Unix(1_800_000_000, 0)
	if err := engine.Fail("wifi-h3", now); err != nil {
		t.Fatal(err)
	}
	if err := engine.Fail("cell-h2", now); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Select(now.Add(100 * time.Millisecond)); err == nil {
		t.Fatal("all failed paths should be temporarily ineligible")
	}
	if engine.Snapshot(now).Phase != Recovering {
		t.Fatal("engine did not remain fail closed while recovering")
	}
	if _, err := engine.Select(now.Add(time.Second)); err != nil {
		t.Fatalf("paths did not become probe-eligible: %v", err)
	}
}

func TestFailedAlternateProbeRestoresOnlinePhase(t *testing.T) {
	engine := testEngine(t)
	now := time.Unix(1_800_000_000, 0)
	mustObserve(t, engine, Observation{
		PathID: "wifi-h3", Success: true, RTT: 20 * time.Millisecond, At: now,
	})
	if err := engine.Activate("wifi-h3", now); err != nil {
		t.Fatal(err)
	}
	if err := engine.BeginProbe(); err != nil {
		t.Fatal(err)
	}
	if err := engine.Fail("cell-h2", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	snapshot := engine.Snapshot(now.Add(time.Second))
	if snapshot.Phase != Online || snapshot.ActivePath != "wifi-h3" {
		t.Fatalf("failed alternate probe disrupted active path: %+v", snapshot)
	}
}

func TestConcurrentObservationIsRaceSafe(t *testing.T) {
	engine := testEngine(t)
	now := time.Unix(1_800_000_000, 0)
	var wait sync.WaitGroup
	for worker := 0; worker < 20; worker++ {
		wait.Add(1)
		go func(offset int) {
			defer wait.Done()
			for sample := 0; sample < 100; sample++ {
				path := "wifi-h3"
				if (offset+sample)%2 == 0 {
					path = "cell-h2"
				}
				_ = engine.Observe(Observation{
					PathID: path, Success: true,
					RTT:        time.Duration(10+sample) * time.Millisecond,
					Loss:       float64(sample%10) / 100,
					Throughput: 25, At: now.Add(time.Duration(sample) * time.Millisecond),
				})
				_ = engine.Snapshot(now)
			}
		}(worker)
	}
	wait.Wait()
}

func TestObserveRejectsInfiniteThroughput(t *testing.T) {
	engine := testEngine(t)
	now := time.Unix(1_800_000_000, 0)
	if err := engine.Observe(Observation{
		PathID: "wifi-h3", Success: true, RTT: time.Millisecond,
		Throughput: math.Inf(1), At: now,
	}); err == nil {
		t.Fatal("accepted +Inf throughput")
	}
	if err := engine.Observe(Observation{
		PathID: "wifi-h3", Success: true, RTT: time.Millisecond,
		Throughput: math.Inf(-1), At: now,
	}); err == nil {
		t.Fatal("accepted -Inf throughput")
	}
	mustObserve(t, engine, Observation{
		PathID: "wifi-h3", Success: true, RTT: time.Millisecond,
		Throughput: 100, At: now,
	})
	mustObserve(t, engine, Observation{
		PathID: "cell-h2", Success: true, RTT: time.Millisecond,
		Throughput: 100, At: now,
	})
	if err := engine.Activate("wifi-h3", now); err != nil {
		t.Fatal(err)
	}
	selected, err := engine.Select(now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if selected.ID != "wifi-h3" {
		t.Fatalf("Select after rejected Inf = %s, want wifi-h3", selected.ID)
	}
	for _, path := range engine.Snapshot(now).Paths {
		if math.IsInf(path.Score, 0) || math.IsInf(path.ThroughputMbps, 0) {
			t.Fatalf("non-finite snapshot for %s: score=%v throughput=%v", path.Path.ID, path.Score, path.ThroughputMbps)
		}
	}
}

func TestActivateRejectsZeroTime(t *testing.T) {
	engine := testEngine(t)
	now := time.Unix(1_800_000_000, 0)
	mustObserve(t, engine, Observation{
		PathID: "wifi-h3", Success: true, RTT: time.Millisecond,
		Throughput: 100, At: now,
	})
	if err := engine.Activate("wifi-h3", time.Time{}); err == nil {
		t.Fatal("Activate accepted a zero time")
	}
	if snap := engine.Snapshot(now); snap.ActivePath != "" {
		t.Fatalf("zero-time Activate committed active path %q", snap.ActivePath)
	}
	if err := engine.Activate("wifi-h3", now); err != nil {
		t.Fatal(err)
	}
	if snap := engine.Snapshot(now); snap.ActivePath != "wifi-h3" {
		t.Fatalf("valid Activate did not commit: %+v", snap)
	}
}

func testEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := New(testSessionID, 7, []Path{
		{ID: "wifi-h3", Carrier: HTTP3, Endpoint: "vpn.example:443"},
		{ID: "cell-h2", Carrier: HTTP2, Endpoint: "vpn.example:443"},
	}, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func mustObserve(t *testing.T, engine *Engine, observation Observation) {
	t.Helper()
	if err := engine.Observe(observation); err != nil {
		t.Fatal(err)
	}
}
