package main

import (
	"errors"
	"strconv"
	"strings"
)

func validLinuxBootID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func parseLinuxProcessStartTicks(line string) (uint64, error) {
	closeParen := strings.LastIndex(line, ")")
	if closeParen < 0 {
		return 0, errors.New("invalid /proc/self/stat")
	}
	fields := strings.Fields(line[closeParen+1:])
	if len(fields) <= 19 {
		return 0, errors.New("short /proc/self/stat")
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTicks == 0 {
		return 0, errors.New("invalid process start ticks")
	}
	return startTicks, nil
}
