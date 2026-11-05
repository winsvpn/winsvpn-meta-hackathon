//go:build linux

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// hostCPUFacts reads this process's affinity and cgroup v2 limits. See
// forward_cpugate.go. Any read that fails is recorded as unreadable, and the
// gate then keeps the async path off.
func hostCPUFacts() cpuFacts {
	var f cpuFacts
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		f.affErr = err
	} else if f.affinity = set.Count(); f.affinity < 1 {
		f.affErr = os.ErrInvalid
	}
	cg, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		f.quotaErr = err
		return f
	}
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		f.quotaErr = err
		return f
	}
	f.quota, f.limited, f.cpuset, f.quotaErr = cgroupFacts(string(cg), string(mi), os.DirFS("/"))
	return f
}
