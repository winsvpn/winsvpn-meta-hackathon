//go:build !linux

package main

import "errors"

// hostCPUFacts: no sched_getaffinity or cgroups here, so both are unreadable
// and the gate keeps the async path off. -forward itself is Linux-only.
func hostCPUFacts() cpuFacts {
	err := errors.New("CPU facts are read on Linux only")
	return cpuFacts{affErr: err, quotaErr: err}
}
