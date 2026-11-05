//go:build unix

package main

import (
	"bufio"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// merge folds a /proc observation into the running high-water marks.
func (s *ResourceSample) merge(threads, openFiles, rssBytes int64) {
	s.Available = true
	s.ProcSampled = true
	s.SampleCount++
	if threads > s.PeakThreads {
		s.PeakThreads = threads
	}
	if openFiles > s.PeakOpenFiles {
		s.PeakOpenFiles = openFiles
	}
	if rssBytes > s.PeakVmRSSBytes {
		s.PeakVmRSSBytes = rssBytes
	}
	if rssBytes > s.MaxRSSBytes {
		s.MaxRSSBytes = rssBytes
	}
}

// procSample reads one observation of a live process from /proc.
//
// Every field is independently optional. A process that exits mid-read makes
// each of these fail with ESRCH or ENOENT, and that is an ordinary outcome
// rather than an error worth propagating: the caller merges whatever it got.
func procSample(procRoot string, pid int) (threads, openFiles, rssBytes int64) {
	base := filepath.Join(procRoot, strconv.Itoa(pid))
	// #nosec G304 -- procRoot is a fixed configuration value and pid is an
	// integer this controller forked; neither is attacker-shaped text.
	statusFile, err := os.Open(filepath.Join(base, "status"))
	if err == nil {
		scanner := bufio.NewScanner(statusFile)
		// A malicious or corrupt /proc entry must not be able to make this
		// allocate without limit.
		scanner.Buffer(make([]byte, 0, 4096), 1<<16)
		for scanner.Scan() {
			name, value, found := strings.Cut(scanner.Text(), ":")
			if !found {
				continue
			}
			value = strings.TrimSpace(value)
			switch name {
			case "Threads":
				if n, err := strconv.ParseInt(value, 10, 64); err == nil {
					threads = n
				}
			case "VmRSS":
				rssBytes = parseKilobyteField(value)
			}
		}
		_ = statusFile.Close()
	}
	if entries, err := os.ReadDir(filepath.Join(base, "fd")); err == nil {
		openFiles = int64(len(entries))
	}
	return threads, openFiles, rssBytes
}

// procGroupSample sums every live member of pgid. Resource ceilings apply to
// the owned process group, not merely to its leader.
func procGroupSample(
	procRoot string, pgid int,
) (threads, openFiles, rssBytes int64, supported bool) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, 0, 0, false
	}
	supported = true
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || !entry.IsDir() {
			continue
		}
		// #nosec G304 -- entry.Name comes from ReadDir and is accepted only
		// after strict positive-decimal PID parsing; it cannot contain a slash.
		raw, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "stat"))
		if err != nil {
			continue
		}
		closeParen := strings.LastIndexByte(string(raw), ')')
		if closeParen < 0 || closeParen+2 >= len(raw) {
			continue
		}
		fields := strings.Fields(string(raw[closeParen+2:]))
		if len(fields) < 3 {
			continue
		}
		observedGroup, err := strconv.Atoi(fields[2])
		if err != nil || observedGroup != pgid {
			continue
		}
		memberThreads, memberFiles, memberRSS := procSample(procRoot, pid)
		threads = saturatingAdd(threads, memberThreads)
		openFiles = saturatingAdd(openFiles, memberFiles)
		rssBytes = saturatingAdd(rssBytes, memberRSS)
	}
	return threads, openFiles, rssBytes, supported
}

type procRelationship struct {
	parent int
	group  int
}

// detectEscapedDescendant reports a process that is still a descendant of the
// owned leader but has changed process group. Process-group signals and
// accounting cannot contain that process; formal execution therefore needs an
// atomically joined cgroup-v2 cycle scope.
func detectEscapedDescendant(
	procRoot string, leaderPID, ownedPGID int,
) (escaped, supported bool) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return false, false
	}
	supported = true
	table := make(map[int]procRelationship)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || !entry.IsDir() {
			continue
		}
		// #nosec G304 -- entry.Name comes from ReadDir and is accepted only
		// after strict positive-decimal PID parsing; it cannot contain a slash.
		raw, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "stat"))
		if err != nil {
			continue
		}
		closeParen := strings.LastIndexByte(string(raw), ')')
		if closeParen < 0 || closeParen+2 >= len(raw) {
			continue
		}
		fields := strings.Fields(string(raw[closeParen+2:]))
		if len(fields) < 3 {
			continue
		}
		parent, parentErr := strconv.Atoi(fields[1])
		group, groupErr := strconv.Atoi(fields[2])
		if parentErr == nil && groupErr == nil {
			table[pid] = procRelationship{parent: parent, group: group}
		}
	}
	descendants := map[int]struct{}{leaderPID: {}}
	for changed := true; changed; {
		changed = false
		for pid, relationship := range table {
			if _, known := descendants[pid]; known {
				continue
			}
			if _, parentKnown := descendants[relationship.parent]; parentKnown {
				descendants[pid] = struct{}{}
				changed = true
			}
		}
	}
	for pid := range descendants {
		if pid == leaderPID {
			continue
		}
		if relationship, ok := table[pid]; ok && relationship.group != ownedPGID {
			return true, true
		}
	}
	return false, true
}

func saturatingAdd(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// parseKilobyteField reads a /proc "12345 kB" field into bytes.
func parseKilobyteField(value string) int64 {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0
	}
	n, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	if len(fields) > 1 && strings.EqualFold(fields[1], "kB") {
		return saturatingMultiply(n, 1024)
	}
	return n
}
