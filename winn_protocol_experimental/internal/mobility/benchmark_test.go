package mobility

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkPathSelection(benchmark *testing.B) {
	paths := make([]Path, 32)
	now := time.Unix(1_800_000_000, 0)
	for index := range paths {
		paths[index] = Path{
			ID: fmt.Sprintf("path-%02d", index), Carrier: HTTP3,
			Endpoint: fmt.Sprintf("node-%02d.example:443", index),
			Priority: float64(index),
		}
	}
	engine, err := New("00112233445566778899aabbccddeeff", 1, paths, DefaultConfig())
	if err != nil {
		benchmark.Fatal(err)
	}
	for index := range paths {
		if err := engine.Observe(Observation{
			PathID: paths[index].ID, Success: true,
			RTT:  time.Duration(index+1) * time.Millisecond,
			Loss: float64(index) / 1000, Throughput: 100,
			At: now,
		}); err != nil {
			benchmark.Fatal(err)
		}
	}
	benchmark.ReportAllocs()
	benchmark.ResetTimer()
	for index := 0; index < benchmark.N; index++ {
		if _, err := engine.Select(now.Add(time.Minute)); err != nil {
			benchmark.Fatal(err)
		}
	}
}
