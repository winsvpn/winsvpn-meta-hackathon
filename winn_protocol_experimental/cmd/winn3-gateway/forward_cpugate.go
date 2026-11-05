package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// This file is -forward-async-write's CPU gate. The async path hands TUN
// writes to other goroutines so that one session can use a second core; with
// fewer than two usable CPUs there is nothing to overlap with, and on the L63
// rig (2026-09-26, rev2) the handoff queue at one CPU coincided with a session
// dying on liveness probes under 1.7 Gbit/s paced UDP upload that the
// synchronous path survived. So the flag enables the async path only when the
// process can use at least two CPUs, and otherwise behaves exactly as if the
// flag were off.
//
// Usable CPUs is the smallest of: the scheduler affinity count
// (sched_getaffinity), the cgroup v2 cpuset of the process's own cgroup
// (cpuset.cpus.effective), and the cgroup v2 CPU bandwidth limit (cpu.max
// quota/period, the smallest along the visible cgroup path).
// runtime.GOMAXPROCS is NOT used: since Go 1.25 it follows cgroup limits but
// rounds any limit below 2 UP to 2 (runtime/cgroup_linux.go
// adjustCgroupGOMAXPROCS), so it cannot tell one usable CPU from two.
//
// The gate FAILS CLOSED (revision 3.1). A limit it cannot read is
// UNREADABLE, never "no limit", and an unreadable affinity or limit keeps the
// async path off. Revision 3 looked for cpu.max under a fixed /sys/fs/cgroup
// and read an absent file as "no limit"; under `ip netns exec`, which mounts a
// fresh /sys with no cgroup2 in it, it enabled the async path at
// CPUQuota=100% (aicore, 2026-09-27). The cgroup2 mount is now located the
// way Go's runtime does it (internal/runtime/cgroup parseCPUMount): the first
// cgroup2 line in /proc/self/mountinfo whose root is a prefix of the process's
// cgroup path. The gate is evaluated once, at startup.
//
// A cgroup namespace shows only the part of the hierarchy below its root;
// a limit set above that root is enforced by the kernel but not visible here,
// as it is not to Go's runtime.

// asyncGateMinCPUs is the usable-CPU floor for the async path.
const asyncGateMinCPUs = 2

var (
	// errNoCgroup2Mount: no cgroup2 mount in /proc/self/mountinfo reaches
	// this process's cgroup (for example a fresh /sys from ip netns exec).
	errNoCgroup2Mount = errors.New("no cgroup2 mount reaches this process's cgroup")
	// errCgroupNotVisible: the mount is there but the process's own cgroup
	// directory is not.
	errCgroupNotVisible = errors.New("this process's cgroup directory is not visible under the cgroup2 mount")
)

// cpuFacts is what the host reported, and what could not be read.
type cpuFacts struct {
	affinity int
	affErr   error

	quota    float64 // CPUs of cgroup bandwidth; meaningful only when limited
	limited  bool
	cpuset   int // CPUs in cpuset.cpus.effective; 0 when absent
	quotaErr error
}

// asyncGate is the startup decision and the facts it rests on.
type asyncGate struct {
	enable bool
	usable float64
	facts  cpuFacts
}

func (g asyncGate) String() string {
	f := g.facts
	aff := strconv.Itoa(f.affinity)
	if f.affErr != nil {
		aff = fmt.Sprintf("UNREADABLE (%v)", f.affErr)
	}
	q := "no cgroup CPU limit"
	switch {
	case f.quotaErr != nil:
		q = fmt.Sprintf("cgroup CPU limit UNREADABLE (%v)", f.quotaErr)
	case f.limited:
		q = fmt.Sprintf("cgroup CPU limit %.2f", f.quota)
	}
	if f.quotaErr == nil && f.cpuset > 0 {
		q += fmt.Sprintf(", cpuset %d", f.cpuset)
	}
	state := "enabled"
	switch {
	case f.affErr != nil || f.quotaErr != nil:
		state = "DISABLED (a CPU limit could not be read; the gate fails closed; forwarding writes synchronously, as without the flag)"
	case !g.enable:
		state = fmt.Sprintf("DISABLED (below %d usable CPUs; forwarding writes synchronously, as without the flag)", asyncGateMinCPUs)
	}
	return fmt.Sprintf("%s: %.2f usable CPUs (affinity %s, %s)", state, g.usable, aff, q)
}

// decideAsyncWrites is the gate's pure decision. Any unreadable fact keeps
// the async path off.
func decideAsyncWrites(f cpuFacts) asyncGate {
	g := asyncGate{facts: f, usable: float64(f.affinity)}
	if f.affErr != nil || f.quotaErr != nil {
		return g
	}
	if f.cpuset > 0 && float64(f.cpuset) < g.usable {
		g.usable = float64(f.cpuset)
	}
	if f.limited && f.quota < g.usable {
		g.usable = f.quota
	}
	g.enable = g.usable >= asyncGateMinCPUs
	return g
}

// asyncEnabler is the one method startAsyncWrites needs from the shared device.
type asyncEnabler interface{ enableAsyncWrites() }

// startAsyncWrites decides, logs the decision, and enables the async path
// only when the gate allows it.
func startAsyncWrites(dev asyncEnabler, facts cpuFacts, log io.Writer) asyncGate {
	g := decideAsyncWrites(facts)
	fmt.Fprintf(log, "winn3-gateway: -forward-async-write %s\n", g)
	if g.enable {
		dev.enableAsyncWrites()
	}
	return g
}

// startAsyncWritesOnThisHost is startAsyncWrites with this process's own
// facts. main calls it for -forward-async-write.
func startAsyncWritesOnThisHost(dev asyncEnabler, log io.Writer) asyncGate {
	return startAsyncWrites(dev, hostCPUFacts(), log)
}

// parseCPUMax parses a cgroup v2 cpu.max file: "max <period>" (unlimited) or
// "<quota> <period>", both in microseconds.
func parseCPUMax(s string) (cpus float64, limited bool, err error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return 0, false, fmt.Errorf("cpu.max %q: want two fields", s)
	}
	period, err := strconv.ParseUint(f[1], 10, 64)
	if err != nil || period == 0 {
		return 0, false, fmt.Errorf("cpu.max %q: bad period", s)
	}
	if f[0] == "max" {
		return 0, false, nil
	}
	quota, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("cpu.max %q: bad quota", s)
	}
	return float64(quota) / float64(period), true, nil
}

// parseCPUList counts the CPUs in a cpuset list such as "0-3,8,10-11".
func parseCPUList(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty cpuset list")
	}
	n := 0
	for _, part := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 0 {
			return 0, fmt.Errorf("cpuset list %q: bad entry %q", s, part)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a {
				return 0, fmt.Errorf("cpuset list %q: bad range %q", s, part)
			}
		}
		n += b - a + 1
	}
	return n, nil
}

// cgroupV2Path returns the process's cgroup v2 path from /proc/self/cgroup
// ("0::/some/path"). ok is false on a v1-only host.
func cgroupV2Path(procSelfCgroup string) (string, bool) {
	for _, line := range strings.Split(procSelfCgroup, "\n") {
		if rest, found := strings.CutPrefix(line, "0::"); found {
			return rest, true
		}
	}
	return "", false
}

// unescapeMountPath undoes /proc/self/mountinfo's octal escapes (\040 etc.).
func unescapeMountPath(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+4 > len(s) {
			return "", fmt.Errorf("mountinfo path %q: bad escape", s)
		}
		v, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			return "", fmt.Errorf("mountinfo path %q: bad escape", s)
		}
		b.WriteByte(byte(v))
		i += 3
	}
	return b.String(), nil
}

// cgroupMount is the cgroup2 mount that reaches a cgroup: dir is the
// directory of that cgroup, top the directory of the mount's root, and
// realRoot whether the mount's root is the hierarchy root.
type cgroupMount struct {
	dir, top string
	realRoot bool
}

// findCgroup2Mount mirrors Go's runtime (internal/runtime/cgroup
// parseCPUMount): the first cgroup2 line whose root (field 4) is a prefix of
// cgroup; the directory is the mount point (field 5) plus cgroup without the
// root. A path outside the cgroup namespace ("/..") cannot be reached.
func findCgroup2Mount(mountinfo, cgroup string) (cgroupMount, error) {
	if !strings.HasPrefix(cgroup, "/") {
		return cgroupMount{}, fmt.Errorf("cgroup path %q is not absolute", cgroup)
	}
	for _, line := range strings.Split(mountinfo, "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		pf, qf := strings.Fields(pre), strings.Fields(post)
		if len(pf) < 5 || len(qf) < 1 || qf[0] != "cgroup2" {
			continue
		}
		root, err := unescapeMountPath(pf[3])
		if err != nil {
			return cgroupMount{}, err
		}
		mnt, err := unescapeMountPath(pf[4])
		if err != nil {
			return cgroupMount{}, err
		}
		if !hasPathPrefix(cgroup, root) {
			continue
		}
		rel := strings.TrimPrefix(cgroup, root)
		if root == "/" {
			rel = cgroup
		}
		if rel == "/.." || strings.HasPrefix(rel, "/../") {
			continue
		}
		return cgroupMount{dir: path.Clean(mnt + "/" + rel), top: path.Clean(mnt), realRoot: root == "/"}, nil
	}
	return cgroupMount{}, errNoCgroup2Mount
}

// hasPathPrefix reports whether p is prefix or below it, by path component.
func hasPathPrefix(p, prefix string) bool {
	if prefix == "/" {
		return strings.HasPrefix(p, "/")
	}
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

// readCgroupLimits walks from m.dir up to m.top on fsys (paths are absolute
// and read relative to fsys's root) and returns the smallest cpu.max limit and
// the leaf's cpuset.cpus.effective count. It never reads a missing file as
// "no limit" unless the file's absence is itself proven:
//   - the leaf directory must exist;
//   - a level without cpu.max is unlimited only if its parent's
//     cgroup.subtree_control does not enable "cpu" (no cpu controller there);
//   - the hierarchy root has no cpu.max by design; a namespaced mount's top
//     without cpu.max cannot be checked and is unreadable.
func readCgroupLimits(fsys fs.FS, m cgroupMount) (quota float64, limited bool, cpuset int, err error) {
	rel := func(p string) string { return strings.TrimPrefix(path.Clean(p), "/") }
	if st, serr := fs.Stat(fsys, rel(m.dir)); serr != nil || !st.IsDir() {
		return 0, false, 0, errCgroupNotVisible
	}
	if b, rerr := fs.ReadFile(fsys, rel(m.dir+"/cpuset.cpus.effective")); rerr == nil {
		if cpuset, err = parseCPUList(string(b)); err != nil {
			return 0, false, 0, err
		}
	} else if !errors.Is(rerr, fs.ErrNotExist) {
		return 0, false, 0, rerr
	}
	p := path.Clean(m.dir)
	for {
		b, rerr := fs.ReadFile(fsys, rel(p+"/cpu.max"))
		switch {
		case rerr == nil:
			c, lim, perr := parseCPUMax(string(b))
			if perr != nil {
				return 0, false, 0, perr
			}
			if lim && (!limited || c < quota) {
				quota, limited = c, true
			}
		case !errors.Is(rerr, fs.ErrNotExist):
			return 0, false, 0, rerr
		case p == m.top:
			if !m.realRoot {
				return 0, false, 0, fmt.Errorf("%s has no cpu.max and its parent is not visible", p)
			}
		default:
			sc, serr := fs.ReadFile(fsys, rel(path.Dir(p)+"/cgroup.subtree_control"))
			if serr != nil {
				return 0, false, 0, fmt.Errorf("%s has no cpu.max and %s/cgroup.subtree_control is unreadable: %w", p, path.Dir(p), serr)
			}
			for _, c := range strings.Fields(string(sc)) {
				if c == "cpu" {
					return 0, false, 0, fmt.Errorf("%s has no cpu.max although its parent enables the cpu controller", p)
				}
			}
		}
		if p == m.top || p == "/" {
			return quota, limited, cpuset, nil
		}
		p = path.Dir(p)
	}
}

// cgroupFacts combines the three reads into the quota part of cpuFacts.
func cgroupFacts(procSelfCgroup, mountinfo string, fsys fs.FS) (quota float64, limited bool, cpuset int, err error) {
	cg, ok := cgroupV2Path(procSelfCgroup)
	if !ok {
		return 0, false, 0, errors.New("no cgroup v2 entry in /proc/self/cgroup")
	}
	m, err := findCgroup2Mount(mountinfo, cg)
	if err != nil {
		return 0, false, 0, err
	}
	return readCgroupLimits(fsys, m)
}
