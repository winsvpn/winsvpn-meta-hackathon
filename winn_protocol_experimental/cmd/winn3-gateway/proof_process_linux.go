//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

func proofProcessIdentity() (string, uint64, error) {
	bootBytes, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", 0, err
	}
	bootID := strings.TrimSpace(string(bootBytes))
	if !validLinuxBootID(bootID) {
		return "", 0, errors.New("invalid Linux boot ID")
	}
	statBytes, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return "", 0, err
	}
	startTicks, err := parseLinuxProcessStartTicks(string(statBytes))
	if err != nil {
		return "", 0, err
	}
	return bootID, startTicks, nil
}

func proofStatusProcessIsLive(status proofStatus) (bool, error) {
	bootBytes, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return false, err
	}
	bootID := strings.TrimSpace(string(bootBytes))
	if !validLinuxBootID(bootID) || !validLinuxBootID(status.BootID) {
		return false, errors.New("invalid Linux boot ID in proof status ownership check")
	}
	if status.BootID != bootID {
		return false, nil
	}
	if status.ProcessID <= 0 || status.ProcessStartTicks == 0 {
		return false, errors.New("invalid process identity in proof status ownership check")
	}
	statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", status.ProcessID))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	startTicks, err := parseLinuxProcessStartTicks(string(statBytes))
	if err != nil {
		return false, err
	}
	return startTicks == status.ProcessStartTicks, nil
}
