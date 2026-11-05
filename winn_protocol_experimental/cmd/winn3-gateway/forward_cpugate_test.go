package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// Revision 3.1 gate tests. The fixtures are real shapes: aicoreRemountedSys is
// /proc/self/mountinfo as `ip netns exec` leaves it on aicore (iproute2 6.1,
// 2026-09-27: a fresh sysfs and no cgroup2), and hostMounts is the same host
// seen through `nsenter --net` (cgroup2 at /sys/fs/cgroup).
const (
	aicoreRemountedSys = "8194 8177 0:124 / /sys rw,relatime - sysfs l63diag rw\n"
	hostMounts         = "28 33 0:25 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw\n" +
		"37 28 0:31 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot\n"
	scopeCgroup = "0::/system.slice/run-r1.scope\n"
)

// hostFS is a cgroupfs under /sys/fs/cgroup with the cpu controller enabled
// down to the scope, as systemd sets it up for a CPUQuota= scope.
func hostFS(scopeMax string) fstest.MapFS {
	return fstest.MapFS{
		"sys/fs/cgroup/cgroup.subtree_control":                           {Data: []byte("cpuset cpu io memory pids\n")},
		"sys/fs/cgroup/system.slice/cgroup.subtree_control":              {Data: []byte("cpu memory pids\n")},
		"sys/fs/cgroup/system.slice/cpu.max":                             {Data: []byte("max 100000\n")},
		"sys/fs/cgroup/system.slice/run-r1.scope/cpu.max":                {Data: []byte(scopeMax + "\n")},
		"sys/fs/cgroup/system.slice/run-r1.scope/cgroup.subtree_control": {Data: []byte("\n")},
	}
}

func facts(affinity int, cg, mi string, fsys fstest.MapFS) cpuFacts {
	f := cpuFacts{affinity: affinity}
	f.quota, f.limited, f.cpuset, f.quotaErr = cgroupFacts(cg, mi, fsys)
	return f
}

// /sys remounted without cgroup2 (ip netns exec): the quota is UNREADABLE and
// the gate is off at any affinity. Revision 3 read this as "no limit".
func TestGateFailsClosedWhenSysIsRemountedWithoutCgroup(t *testing.T) {
	f := facts(16, scopeCgroup, aicoreRemountedSys, hostFS("100000 100000"))
	if !errors.Is(f.quotaErr, errNoCgroup2Mount) {
		t.Fatalf("quota error %v, want errNoCgroup2Mount", f.quotaErr)
	}
	g := decideAsyncWrites(f)
	if g.enable || !strings.Contains(g.String(), "UNREADABLE") || !strings.Contains(g.String(), "fails closed") {
		t.Fatalf("gate %v %q: an unreadable quota must keep async off and say so", g.enable, g)
	}
}

func TestGateReadsTheQuotaThroughMountinfo(t *testing.T) {
	for _, c := range []struct {
		max    string
		enable bool
		usable float64
	}{{"100000 100000", false, 1}, {"150000 100000", false, 1.5}, {"200000 100000", true, 2}, {"max 100000", true, 16}} {
		g := decideAsyncWrites(facts(16, scopeCgroup, hostMounts, hostFS(c.max)))
		if g.facts.quotaErr != nil || g.enable != c.enable || g.usable != c.usable {
			t.Errorf("cpu.max %q: enable %v usable %.2f err %v, want %v %.2f", c.max, g.enable, g.usable, g.facts.quotaErr, c.enable, c.usable)
		}
	}
}

func TestMissingCPUMax(t *testing.T) {
	// The cpu controller is not enabled for the scope: no cpu.max is correct
	// and means no limit at that level.
	noCtl := hostFS("max 100000")
	delete(noCtl, "sys/fs/cgroup/system.slice/run-r1.scope/cpu.max")
	noCtl["sys/fs/cgroup/system.slice/cgroup.subtree_control"] = &fstest.MapFile{Data: []byte("memory pids\n")}
	if g := decideAsyncWrites(facts(4, scopeCgroup, hostMounts, noCtl)); g.facts.quotaErr != nil || !g.enable {
		t.Errorf("controller disabled: gate %v err %v, want enabled with no limit", g.enable, g.facts.quotaErr)
	}
	// The parent enables cpu but the file is absent: inconsistent, UNREADABLE.
	missing := hostFS("max 100000")
	delete(missing, "sys/fs/cgroup/system.slice/run-r1.scope/cpu.max")
	if g := decideAsyncWrites(facts(4, scopeCgroup, hostMounts, missing)); g.facts.quotaErr == nil || g.enable {
		t.Errorf("cpu.max missing under an enabled controller: gate %v err %v, want off and unreadable", g.enable, g.facts.quotaErr)
	}
	// The process's own cgroup directory is not there at all.
	gone := fstest.MapFS{"sys/fs/cgroup/cgroup.subtree_control": {Data: []byte("cpu\n")}}
	if g := decideAsyncWrites(facts(4, scopeCgroup, hostMounts, gone)); !errors.Is(g.facts.quotaErr, errCgroupNotVisible) || g.enable {
		t.Errorf("own cgroup not visible: gate %v err %v, want off and errCgroupNotVisible", g.enable, g.facts.quotaErr)
	}
	// A namespaced mount whose top has no cpu.max cannot be checked upward.
	ns := fstest.MapFS{"sys/fs/cgroup/cgroup.subtree_control": {Data: []byte("\n")}}
	nsMount := "40 28 0:31 /system.slice/run-r1.scope /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n"
	if g := decideAsyncWrites(facts(4, scopeCgroup, nsMount, ns)); g.facts.quotaErr == nil || g.enable {
		t.Errorf("namespaced top without cpu.max: gate %v err %v, want off and unreadable", g.enable, g.facts.quotaErr)
	}
}

func TestNestedCgroupTakesTheSmallestVisibleLimit(t *testing.T) {
	cg := "0::/system.slice/app.slice/gw.service\n"
	fsys := fstest.MapFS{
		"sys/fs/cgroup/cgroup.subtree_control":                        {Data: []byte("cpu\n")},
		"sys/fs/cgroup/system.slice/cgroup.subtree_control":           {Data: []byte("cpu\n")},
		"sys/fs/cgroup/system.slice/cpu.max":                          {Data: []byte("100000 100000\n")},
		"sys/fs/cgroup/system.slice/app.slice/cgroup.subtree_control": {Data: []byte("cpu\n")},
		"sys/fs/cgroup/system.slice/app.slice/cpu.max":                {Data: []byte("400000 100000\n")},
		"sys/fs/cgroup/system.slice/app.slice/gw.service/cpu.max":     {Data: []byte("max 100000\n")},
	}
	g := decideAsyncWrites(facts(16, cg, hostMounts, fsys))
	if g.facts.quotaErr != nil || g.facts.quota != 1 || g.enable {
		t.Fatalf("limit 1 CPU on a grandparent: quota %.2f err %v gate %v, want 1.00 and off", g.facts.quota, g.facts.quotaErr, g.enable)
	}
	fsys["sys/fs/cgroup/system.slice/cpu.max"] = &fstest.MapFile{Data: []byte("max 100000\n")}
	fsys["sys/fs/cgroup/system.slice/app.slice/gw.service/cpu.max"] = &fstest.MapFile{Data: []byte("300000 100000\n")}
	if g := decideAsyncWrites(facts(16, cg, hostMounts, fsys)); g.facts.quota != 3 || !g.enable {
		t.Fatalf("leaf 3 under parent 4: quota %.2f gate %v, want 3.00 and on", g.facts.quota, g.enable)
	}
}

func TestCpusetLimit(t *testing.T) {
	for _, c := range []struct {
		list   string
		enable bool
		usable float64
		bad    bool
	}{{"2", false, 1, false}, {"2-3", true, 2, false}, {"0-3,8,10-11", true, 7, false}, {"3-1", false, 16, true}, {"x", false, 16, true}} {
		fsys := hostFS("max 100000")
		fsys["sys/fs/cgroup/system.slice/run-r1.scope/cpuset.cpus.effective"] = &fstest.MapFile{Data: []byte(c.list + "\n")}
		g := decideAsyncWrites(facts(16, scopeCgroup, hostMounts, fsys))
		if (g.facts.quotaErr != nil) != c.bad || g.enable != c.enable || g.usable != c.usable {
			t.Errorf("cpuset %q: enable %v usable %.2f err %v, want %v %.2f bad=%v", c.list, g.enable, g.usable, g.facts.quotaErr, c.enable, c.usable, c.bad)
		}
	}
}

func TestGateFailsClosedWhenAffinityIsUnreadable(t *testing.T) {
	f := facts(16, scopeCgroup, hostMounts, hostFS("max 100000"))
	f.affErr = errors.New("sched_getaffinity: EPERM")
	if g := decideAsyncWrites(f); g.enable || !strings.Contains(g.String(), "affinity UNREADABLE") {
		t.Fatalf("gate %v %q: unreadable affinity must keep async off", g.enable, g)
	}
}

func TestAsyncGateDecision(t *testing.T) {
	for _, c := range []struct {
		name string
		f    cpuFacts
		want bool
		use  float64
	}{
		{"one cpu", cpuFacts{affinity: 1}, false, 1},
		{"two cpus", cpuFacts{affinity: 2}, true, 2},
		{"quota 1.5", cpuFacts{affinity: 4, quota: 1.5, limited: true}, false, 1.5},
		{"quota 2", cpuFacts{affinity: 4, quota: 2, limited: true}, true, 2},
		{"affinity bounds a larger quota", cpuFacts{affinity: 1, quota: 4, limited: true}, false, 1},
		{"cpuset bounds", cpuFacts{affinity: 8, cpuset: 1}, false, 1},
		{"quota unreadable", cpuFacts{affinity: 16, quotaErr: errors.New("x")}, false, 16},
	} {
		if g := decideAsyncWrites(c.f); g.enable != c.want || g.usable != c.use {
			t.Errorf("%s: enable %v usable %.2f, want %v %.2f", c.name, g.enable, g.usable, c.want, c.use)
		}
	}
}

func TestFindCgroup2MountMirrorsGo(t *testing.T) {
	bind := "40 28 0:31 /system.slice /mnt/cg\\040x rw - cgroup2 cgroup2 rw\n" + hostMounts
	m, err := findCgroup2Mount(bind, "/system.slice/run-r1.scope")
	if err != nil || m.dir != "/mnt/cg x/run-r1.scope" || m.top != "/mnt/cg x" || m.realRoot {
		t.Errorf("bind mount of /system.slice: %+v %v, want the first matching line, unescaped", m, err)
	}
	if _, err := findCgroup2Mount(hostMounts, "/../../init.scope"); !errors.Is(err, errNoCgroup2Mount) {
		t.Errorf("path outside the cgroup namespace: %v, want errNoCgroup2Mount", err)
	}
	other := "40 28 0:31 /other.slice /mnt/o rw - cgroup2 cgroup2 rw\n"
	if _, err := findCgroup2Mount(other, "/system.slice/x"); !errors.Is(err, errNoCgroup2Mount) {
		t.Errorf("mount root not a prefix: %v, want errNoCgroup2Mount", err)
	}
	// Root /system.slice is a string prefix of /system.slicex/y but not a
	// path prefix: that mount does not reach the cgroup.
	if _, err := findCgroup2Mount("40 28 0:31 /system.slice /m rw - cgroup2 cgroup2 rw\n", "/system.slicex/y"); !errors.Is(err, errNoCgroup2Mount) {
		t.Errorf("root that is only a string prefix: %v, want errNoCgroup2Mount", err)
	}
}

type fakeEnabler struct{ calls int }

func (f *fakeEnabler) enableAsyncWrites() { f.calls++ }

func TestStartAsyncWritesEnablesOnlyWhenTheGateAllows(t *testing.T) {
	for _, c := range []struct {
		f    cpuFacts
		want int
		log  string
	}{
		{cpuFacts{affinity: 1}, 0, "DISABLED (below 2"},
		{cpuFacts{affinity: 16, quotaErr: errNoCgroup2Mount}, 0, "fails closed"},
		{cpuFacts{affinity: 4}, 1, "enabled: 4.00 usable CPUs"},
	} {
		dev := &fakeEnabler{}
		var log bytes.Buffer
		g := startAsyncWrites(dev, c.f, &log)
		if dev.calls != c.want || g.enable != (c.want == 1) {
			t.Errorf("%+v: enable called %d times, want %d", c.f, dev.calls, c.want)
		}
		if !strings.Contains(log.String(), c.log) || !strings.Contains(log.String(), "-forward-async-write") {
			t.Errorf("%+v: startup log %q does not state the decision (%q)", c.f, log.String(), c.log)
		}
	}
}

func TestParseCPUMax(t *testing.T) {
	for _, c := range []struct {
		in      string
		cpus    float64
		limited bool
		bad     bool
	}{{"max 100000\n", 0, false, false}, {"150000 100000\n", 1.5, true, false}, {"50000 100000", 0.5, true, false},
		{"garbage", 0, false, true}, {"100000 0", 0, false, true}, {"x 100000", 0, false, true}} {
		cpus, limited, err := parseCPUMax(c.in)
		if (err != nil) != c.bad || cpus != c.cpus || limited != c.limited {
			t.Errorf("parseCPUMax(%q) = %v %v %v", c.in, cpus, limited, err)
		}
	}
}

// --- rev3: the uplink peer-key cache ---------------------------------------

func TestForwardDeviceCachesAPrivateCopyOfThePeerKeyForUplink(t *testing.T) {
	f := newAuthorityFixture(t, time.Now().Add(time.Hour).Unix())
	f.device.mu.Lock()
	loop, peer := f.device.peerLoop, f.device.peer
	f.device.mu.Unlock()
	if loop != f.loop || !bytes.Equal(peer, f.key) {
		t.Fatalf("after an authorized write the device caches loop %p key %x; want the bound loop and its key", loop, peer)
	}
	if live := f.loop.Session().PeerStatic(); len(live) > 0 && &live[0] == &peer[0] {
		t.Fatal("the device cache aliases the session's own peer key slice")
	}
}

func TestForwardDeviceUplinkCacheIsUsedOnlyForTheBoundLoop(t *testing.T) {
	f := newAuthorityFixture(t, time.Now().Add(time.Hour).Unix())
	wrong := bytes.Repeat([]byte{9}, len(f.key))
	pkt := ipv4Packet(t, f.addr.String(), "8.8.8.8")
	f.device.mu.Lock()
	f.device.peerLoop, f.device.peer = f.loop, wrong
	f.device.mu.Unlock()
	if _, err := f.device.WritePacket(pkt); !errors.Is(err, errGatewayPeerUnauthorized) {
		t.Fatalf("WritePacket with a cached unknown key for the bound loop = %v; the cache must be consulted", err)
	}
	f.device.mu.Lock()
	f.device.peerLoop, f.device.peer = nil, wrong
	f.device.mu.Unlock()
	if _, err := f.device.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket with a cache entry for another loop = %v; it must fall back to the session", err)
	}
}

// Rebinding is not a production path (main binds once per session), but a
// cache that outlived it would authorize one session with another's key.
func TestForwardDeviceUplinkCacheDoesNotSurviveARebind(t *testing.T) {
	f1 := newAuthorityFixture(t, time.Now().Add(time.Hour).Unix())
	f2 := newAuthorityFixture(t, time.Now().Add(time.Hour).Unix())
	if bytes.Equal(f1.key, f2.key) {
		t.Fatal("fixtures share a key; the test needs two identities")
	}
	f1.device.bind(f2.loop) // f1's registry does not know f2's key
	if _, err := f1.device.WritePacket(ipv4Packet(t, f1.addr.String(), "8.8.8.8")); !errors.Is(err, errGatewayPeerUnauthorized) {
		t.Fatalf("after rebinding to another session WritePacket = %v; the previous session's cached key was used", err)
	}
}
