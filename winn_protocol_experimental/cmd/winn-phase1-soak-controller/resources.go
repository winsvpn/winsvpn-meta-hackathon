package main

import (
	"fmt"
)

// ResourceSample is what one cycle cost.
//
// Available distinguishes "this cycle used no measurable memory", which never
// happens, from "this platform could not tell us", which happens on every
// non-Linux host. Without it a cross-platform test would happily assert on
// zeroes and prove nothing.
type ResourceSample struct {
	Available bool `json:"available"`
	// MaxRSSBytes is the greater of the leader's wait4 high-water value and
	// Linux's sampled aggregate across the owned process group, normalised to
	// bytes.
	MaxRSSBytes int64 `json:"max_rss_bytes"`
	// UserCPUNanos and SystemCPUNanos come from getrusage on the reaped
	// child.
	UserCPUNanos   int64 `json:"user_cpu_nanos"`
	SystemCPUNanos int64 `json:"system_cpu_nanos"`
	// PeakThreads and PeakOpenFiles are sampled from /proc while the child
	// runs, so they are a high-water mark over the samples taken rather
	// than a true maximum. ProcSampled says whether any sample succeeded.
	ProcSampled    bool  `json:"proc_sampled"`
	PeakThreads    int64 `json:"peak_threads"`
	PeakOpenFiles  int64 `json:"peak_open_files"`
	PeakVmRSSBytes int64 `json:"peak_vm_rss_bytes"`
	SampleCount    int64 `json:"sample_count"`
}

// ResourceBounds are the ceilings a cycle may not exceed.
//
// A zero bound means unenforced. That is stated rather than defaulted, and
// config.go refuses a soak whose memory bound is zero: an unbounded soak is the
// thing this file exists to prevent.
type ResourceBounds struct {
	MaxRSSBytes    int64
	MaxThreads     int64
	MaxOpenFiles   int64
	MaxOutputBytes int64
}

// ExceededBound is a bound a cycle broke.
type ExceededBound struct {
	Bound    string `json:"bound"`
	Observed int64  `json:"observed"`
	Limit    int64  `json:"limit"`
}

// check returns every bound the sample broke, in a fixed order.
//
// A sample that could not be taken never reports a violation. Reporting one
// would fail a healthy soak on any platform without /proc, which is exactly the
// "test passes for the wrong reason" shape inverted into a false alarm.
func (b ResourceBounds) check(
	sample ResourceSample, stdoutBytes, stderrBytes int64,
) []ExceededBound {
	var broken []ExceededBound
	consider := func(name string, observed, limit int64, measured bool) {
		if !measured || limit <= 0 || observed <= limit {
			return
		}
		broken = append(broken, ExceededBound{
			Bound: name, Observed: observed, Limit: limit,
		})
	}
	consider("max_rss_bytes", sample.MaxRSSBytes, b.MaxRSSBytes, sample.Available)
	consider("peak_threads", sample.PeakThreads, b.MaxThreads, sample.ProcSampled)
	consider("peak_open_files", sample.PeakOpenFiles, b.MaxOpenFiles, sample.ProcSampled)
	consider("stdout_bytes", stdoutBytes, b.MaxOutputBytes, true)
	consider("stderr_bytes", stderrBytes, b.MaxOutputBytes, true)
	return broken
}

func formatBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MiB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.2f KiB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
