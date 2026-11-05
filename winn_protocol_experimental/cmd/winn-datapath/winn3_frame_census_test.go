package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/datapath/duplex"
)

// The uplink ring's high-water mark is the deepest it has been, and it never
// falls when the ring drains.
func TestToEngineRingHighWaterIsMonotone(t *testing.T) {
	ring := newToEngineRing(16)
	ring.lowWater = 1
	for i := 0; i < 5; i++ {
		if acc, open := ring.pushOne([]byte{byte(i)}); !acc || !open {
			t.Fatalf("push %d refused", i)
		}
	}
	dst := make([][]byte, 3)
	if n, ok := ring.popBatch(dst); !ok || n != 3 {
		t.Fatalf("pop: n=%d ok=%v", n, ok)
	}
	if n, open := ring.pushBatch([][]byte{{9}, {10}}); n != 2 || !open {
		t.Fatalf("pushBatch: n=%d open=%v", n, open)
	}
	got := ring.Telemetry()
	if got.HighWater != 5 {
		t.Fatalf("high water = %d, want 5 (depth now %d)", got.HighWater, ring.depth())
	}
	if ring.depth() != 4 {
		t.Fatalf("depth = %d, want 4", ring.depth())
	}
}

// The downlink census counts what the pump wrote to the host, how deep toHost
// got, and publishes it in the frame-mode status document only when nonzero.
func TestFrameDeviceHostCensusReachesStatus(t *testing.T) {
	device, err := newWinn3FrameDevice(1280)
	if err != nil {
		t.Fatal(err)
	}
	packet := bytes.Repeat([]byte{0x45}, 100)
	for i := 0; i < 7; i++ {
		if _, err := device.WritePacket(packet); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := device.hostHighWater.Load(); got != 7 {
		t.Fatalf("host high water = %d, want 7", got)
	}

	var out bytes.Buffer
	server := &winn3FrameServer{writer: duplex.NewWriter(&out)}
	done := make(chan struct{})
	go server.pump(device, done)
	deadline := time.Now().Add(5 * time.Second)
	for device.hostWritePackets.Load() < 7 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	_ = device.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pump did not exit after Close")
	}

	census := device.telemetry()
	if census.HostWritePackets != 7 {
		t.Fatalf("host write packets = %d, want 7", census.HostWritePackets)
	}
	if census.HostWriteBatches == 0 || census.HostWriteBatches > 7 {
		t.Fatalf("host write batches = %d, want 1..7", census.HostWriteBatches)
	}
	if census.HostWriteMaxNanos > census.HostWriteNanos {
		t.Fatalf("max write %d exceeds total %d", census.HostWriteMaxNanos, census.HostWriteNanos)
	}
	if census.HostQueueHighWater != 7 || census.HostQueueDepth != 0 {
		t.Fatalf("host queue census = %+v", census)
	}
	if want := 7 * (duplex.HeaderSize + len(packet)); out.Len() != want {
		t.Fatalf("pump wrote %d bytes to the host, want %d", out.Len(), want)
	}

	var status winn3Status
	status.Event = "posture"
	winn3PublishFrameTelemetry(&status, census)
	encoded, err := winn3EncodeStatus(status)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"host_queue_high_water", "host_write_packets", "host_write_batches"} {
		if _, ok := members[key]; !ok {
			t.Fatalf("%s missing from %s", key, encoded)
		}
	}
	for _, key := range []string{"dropped_to_host", "engine_queue_high_water", "host_queue_depth"} {
		if _, ok := members[key]; ok {
			t.Fatalf("%s is zero and must be omitted: %s", key, encoded)
		}
	}
	// promotion_ready is always encoded, so the census never makes a document
	// the host-side parser refuses.
	if _, err := decodeWinn3Status(encoded); err != nil {
		t.Fatalf("census document refused by the host-side parser: %v", err)
	}

	// The desktop document is built without the census and must not carry it.
	desktop, err := winn3EncodeStatus(winn3StatusFrom("posture", nil, server.sizing, ""))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(desktop, []byte("host_")) || bytes.Contains(desktop, []byte("ring_")) {
		t.Fatalf("desktop document carries frame census: %s", desktop)
	}
}
