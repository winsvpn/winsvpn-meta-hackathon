#!/usr/bin/env python3
"""Win's VPN v3 ONETOUCH performance bench harness (design 5.7, 10.0 to 10.6, slice P3).

What it is: the code that runs the section 5.7 trials and decides them by rule R
(10.0). It has four parts, each usable alone.

  1. Trial registry and bench order (5.7): which trial is latency or throughput, its
     arms, cells, stages and venue, and the order the trials must run in.
  2. Arm control: apply a trial arm to a node, read it back, and revert it, with the
     revert plan and a dead-man revert script written BEFORE anything changes.
  3. A scheduler and two measurement backends: a synthetic dry-run backend (no host
     is contacted) and a command backend that runs one operator-supplied measurement
     command per run and reads one JSON run record from its stdout.
  4. Analysis: rule R for the paired matrix, connect time (p95 at most 4.0 s), the
     replay-journal storm (P-19), go-live latency (p95 at most 180 s with every proof
     newer than completion), the uncapped Ryzen acceptance run (1.8 Gbit/s), the
     epoll_ctl decline check (PERF-1), and hub cost (P-15, P-16, P-23).

Venue rule (5.3, 5.7, 10.6, fact 4): a performance figure counts only from a canary
node of the node class or from aicore. The emulated Tier B guest, the l80 VM and a
dry run can exercise this code, but a run recorded from them is never adoptable.

Run records (JSON lines, one per run). Keys: trial, stage, arm, role (base_a, base_b
or cand), rep, profile (a or b), test (tcp1, tcp4, udp), dir (up or down), started,
alive, idle_p50_ms, ld_p50_ms, ld_p99_ms, ld_jitter_ms, ld_loss_pct, thr_mbps,
sessions_started, sessions_failed, failure_class, and, where the trial needs them,
awg_mbps, xray_mbps, awg_ld_p99_ms, xray_ld_p99_ms, cpu_total_pct (percent of ALL usable CPUs,
0 to 100, not a per-core sum), and on a pinned stage gw_cpus_observed (the CPU count the gateway
was actually pinned to, read on the venue; a record without it cannot support a pinned stage).
run_trial adds node_class_id and binary_sha256, which must match the stage's node class record. The qdisc backlog,
TX drop, softirq, softnet, inbox, RcvbufErrors and retransmission fields are recorded
for the evidence and are never inputs to rule R (10.0, "Loss" paragraph).

Usage: winn3_perf_bench.py <command> [options]; winn3_perf_bench.py --help lists them.
Standard library only; Python 3.9 or newer.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import math
import os
import random
import re
import shlex
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True

VERSION = 1

# ---------------------------------------------------------------------------
# Constants the design fixes (10.0, 5.7)
# ---------------------------------------------------------------------------
BAR_MS = 50.0                       # owner's loaded rise over idle (10.0 item 3)
START_FAIL_ALLOWANCE = 1.0 / 200.0  # MCR line 87 canary bar (10.0 item 1)
BUSY_POLL_CPU_CEILING_PP = 5.0      # 10.0 item 1, busy polling (P-3)
CONNECT_P95_LIMIT_S = 4.0           # 5.7 connect time
CONNECT_MIN_RUNS = 10               # 5.7: 10 per network type per node class
CONNECT_NETWORKS = ("wifi", "cellular")
CONNECT_STAGES = ("hub_config_fetch", "allocation", "handshake", "first_carried_packet")
GOLIVE_P95_LIMIT_S = 180.0          # 5.7 go-live latency budget
GOLIVE_MIN_INSTALLS = 10
GOLIVE_PROOFS = ("served_profile_canary", "awg_carry_udp", "awg_carry_stealth",
                 "awg_carry_stealth_tls", "v3_canary", "offnode_gate")
RYZEN_TARGET_MBPS = 1800.0          # 5.7 uncapped Ryzen acceptance run
RYZEN_RUNS = 10
RYZEN_FLOWS = 4
RYZEN_MIN_SECONDS = 20
STORM_P95_LIMIT_S = 2.0             # P-19: group commit only above this
STORM_TIMEOUT_S = 30.0
STORM_OVER_CAPACITY_ATTEMPTS = 4
EPOLL_FEW_CALLS = 10                # 10.2 "at most a few calls" (reading, see report)
SESSION_KIB = 40960                 # G: floor((cap_kib - 98304) / 40960)
SESSION_BASE_KIB = 98304
SESSIONS_CAP = 64
DEFAULT_MIN_REPS = 10               # rule R fixes no n; the multicore round needed >= 10
PROFILES = ("a", "b")
TESTS = ("tcp1", "tcp4", "udp")
EXTRA_TESTS = ("tcp8",)             # P-17 uses a single session with 8 download streams (10.2)
DIRS = ("up", "down")
PERF_VENUES = ("canary", "aicore")  # the only venues whose figures can be adopted
# systemd-detect-virt values that are real hardware ("none") or a hardware-accelerated guest. Any other
# value, or none recorded, is not evidence of a real venue (fail closed; 5.7 head, fact 4).
NOT_EMULATED_VIRT = ("none", "kvm", "amazon", "microsoft", "vmware", "oracle", "xen", "google")
AICORE_CPU = "8845HS"               # 10.6: aicore is a Ryzen 7 PRO 8845HS
CONNECT_ENDPOINT = "first_dns_answer"   # 5.7 and 10.6: tap to the first carried DNS answer
NOISE_NOTE = "beyond noise = outside the run's own base-against-base spread (10.0)"

LATENCY_METRICS = ("ld_p50_ms", "ld_p99_ms", "ld_jitter_ms", "ld_loss_pct")


def full_matrix():
    """The 5.7 matrix: per profile, one flow, four flows and paced UDP, both directions."""
    return tuple((p, t, d) for p in PROFILES for t in TESTS for d in DIRS)


# ---------------------------------------------------------------------------
# Small statistics
# ---------------------------------------------------------------------------
def is_num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and not (isinstance(x, float) and math.isnan(x))


def median(xs):
    s = sorted(xs)
    n = len(s)
    if n == 0:
        raise ValueError("median of nothing")
    if n % 2:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) / 2.0


def nearest_rank(xs, p):
    """Nearest-rank percentile (p in 0..100). Infinity sorts last, so a failure counts as slow."""
    s = sorted(xs)
    if not s:
        raise ValueError("percentile of nothing")
    k = max(1, math.ceil(p / 100.0 * len(s)))
    return s[k - 1]


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Memory fit (P-8, P-19): chicago has 1967 MiB and fits 22 sessions
# ---------------------------------------------------------------------------
def sessions_that_fit(mem_total_kib):
    """G gateway_sessions_that_fit over cap_kib = floor(MemTotal / 2)."""
    numerator = mem_total_kib // 2 - SESSION_BASE_KIB
    return 0 if numerator <= 0 else numerator // SESSION_KIB


def default_max_sessions(mem_total_kib):
    return min(SESSIONS_CAP, sessions_that_fit(mem_total_kib))


# ---------------------------------------------------------------------------
# Node class evidence and the venue guard (5.7 head, fact 4)
# ---------------------------------------------------------------------------
def parse_cpuset(text):
    """'0-3,5' -> 5 CPUs. Raises ValueError on anything else."""
    text = text.strip()
    if not text:
        raise ValueError("empty cpuset")
    total = 0
    for part in text.split(","):
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", part.strip())
        if not m:
            raise ValueError("bad cpuset item %r" % part)
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) is not None else lo
        if hi < lo:
            raise ValueError("bad cpuset range %r" % part)
        total += hi - lo + 1
    return total


def _read(path, limit=1 << 20):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return None


def cpu_model(cpuinfo_text):
    """x86 prints 'model name'. arm64 prints no name, so the implementer and part codes stand in."""
    for key in ("model name", "Model", "Hardware", "cpu model"):
        m = re.search(r"^%s\s*:\s*(.+)$" % re.escape(key), cpuinfo_text or "", re.M | re.I)
        if m:
            return m.group(1).strip()
    imp = re.search(r"^CPU implementer\s*:\s*(\S+)", cpuinfo_text or "", re.M)
    part = re.search(r"^CPU part\s*:\s*(\S+)", cpuinfo_text or "", re.M)
    if imp and part:
        return "arm64 implementer %s part %s" % (imp.group(1), part.group(1))
    return None


def mem_total_kib(meminfo_text):
    m = re.search(r"^MemTotal:\s+(\d+)\s+kB\s*$", meminfo_text or "", re.M)
    return int(m.group(1)) if m else None


def detect_emulation(virt_name, venue_declared=None):
    """True when the guest is instruction-emulated.

    systemd-detect-virt prints 'qemu' for TCG emulation (the CPUID hypervisor leaf
    reads TCGTCGTCGTCG) and 'kvm' for a hardware-accelerated guest, which is what a
    VPS canary is. A CPU model of 'QEMU Virtual CPU' alone is therefore not proof of
    emulation: ordinary VPS nodes report it too.
    """
    name = (virt_name or "").strip().lower()
    if name in ("qemu", "bochs", "tcg"):
        return True
    return (venue_declared or "").lower() in ("tier_b", "emulated")


def read_node_class(proc="/proc", cgroup="/sys/fs/cgroup", virt_name="", provider="",
                    node_label="", binary_path=None, venue="", gateway_cgroup=None, reader=None,
                    binary_sha256=None):
    """Node class record for a run's evidence. Never contains a hostname or an address. reader(path)
    returns a file's text or None, so a record can describe a VM that is read through a runner."""
    reader = reader or _read
    cpuinfo = reader(os.path.join(proc, "cpuinfo")) or ""
    meminfo = reader(os.path.join(proc, "meminfo")) or ""
    cpuset_paths = []
    if gateway_cgroup:
        cpuset_paths.append(os.path.join(cgroup, gateway_cgroup.strip("/"), "cpuset.cpus.effective"))
    cpuset_paths.append(os.path.join(cgroup, "cpuset.cpus.effective"))
    usable = None
    for path in cpuset_paths:
        text = reader(path)
        if text and text.strip():
            try:
                usable = parse_cpuset(text)
                break
            except ValueError:
                continue
    if usable is None:
        usable = len(re.findall(r"^processor\s*:", cpuinfo, re.M)) or None
    mem = mem_total_kib(meminfo)
    rec = {
        "node_label": node_label,
        "cpu_model": cpu_model(cpuinfo),
        "usable_cpus": usable,
        "ram_kib": mem,
        "max_sessions_default": default_max_sessions(mem) if mem else None,
        "provider": provider,
        "virt": (virt_name or "").strip() or None,
        "venue": venue,
        "emulated": detect_emulation(virt_name, venue),
        "binary_sha256": binary_sha256 or (sha256_file(binary_path) if binary_path and os.path.isfile(binary_path) else None),
    }
    rec["class_id"] = sha256_bytes(canonical({k: rec[k] for k in
                                              ("cpu_model", "usable_cpus", "ram_kib", "provider", "binary_sha256")}).encode())[:16]
    return rec


def parse_os_release(text):
    m = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', text or "", re.M)
    return m.group(1) if m else None


def host_facts(reader=None, run=None):
    """OS release, systemd version and root disk size, which Tier B must re-read on the guest before
    it starts (5.3). Read only. run(argv) -> text or None."""
    reader = reader or _read
    run = run or (lambda argv: (lambda p: p.stdout if p.returncode == 0 else None)(
        subprocess.run(argv, capture_output=True, text=True)) if _which(argv[0]) else None)
    sysd = run(["systemctl", "--version"]) or ""
    first = sysd.splitlines()[0] if sysd else None
    try:
        import shutil
        disk = shutil.disk_usage("/").total
    except OSError:
        disk = None
    return {"os_release": parse_os_release(reader("/etc/os-release")), "systemd": first, "root_disk_bytes": disk,
            "machine": os.uname().machine if hasattr(os, "uname") else None}


def _which(name):
    import shutil
    return shutil.which(name)


def detect_virt():
    """systemd-detect-virt, or '' when it is missing. 'qemu' is TCG emulation, 'kvm' is hardware accelerated."""
    if not _which("systemd-detect-virt"):
        return ""
    p = subprocess.run(["systemd-detect-virt"], capture_output=True, text=True)
    return p.stdout.strip()


def node_class_via(runner, provider="", label="", binary=None, venue="", gateway_cgroup=None):
    """The node class of the machine a runner reaches (read only: cat, systemd-detect-virt, sha256sum)."""
    def reader(path):
        r = runner.run(["cat", path])
        return r.out if r.rc == 0 else None
    virt = (runner.run(["systemd-detect-virt"]).out or "").strip()    # exits 1 and prints 'none' on bare metal
    sha = None
    if binary:
        r = runner.run(["sha256sum", binary])
        if r.rc == 0 and r.out.split():
            sha = r.out.split()[0]
    return read_node_class(virt_name=virt, provider=provider, node_label=label, venue=venue, reader=reader,
                           binary_sha256=sha, gateway_cgroup=gateway_cgroup)


def venue_eligibility(node_class):
    """(eligible, reasons). Performance figures need a canary or aicore venue, real hardware
    or a hardware-accelerated guest, and the full node class evidence (5.7 head)."""
    reasons = []
    nc = node_class or {}
    if nc.get("venue") not in PERF_VENUES:
        reasons.append("venue %r is not one of %s" % (nc.get("venue"), "/".join(PERF_VENUES)))
    if nc.get("emulated"):
        reasons.append("emulated guest (fact 4): no throughput, latency or duration figure counts")
    elif nc.get("emulated") is not False or nc.get("virt") not in NOT_EMULATED_VIRT:
        reasons.append("virtualization evidence %r is missing or not a recognised real or hardware-accelerated venue"
                       % (nc.get("virt"),))
    for key in ("cpu_model", "usable_cpus", "ram_kib", "provider", "binary_sha256", "class_id"):
        if not nc.get(key):
            reasons.append("node class evidence lacks %s" % key)
    if nc.get("venue") == "aicore" and AICORE_CPU not in str(nc.get("cpu_model") or ""):
        reasons.append("venue aicore needs the %s CPU (10.6), the node reports %r" % (AICORE_CPU, nc.get("cpu_model")))
    return (not reasons), reasons


def mask_ips(text, table=None):
    """Replace public IPv4 addresses by stable typed placeholders (evidence is shared)."""
    table = {} if table is None else table

    def sub(m):
        ip = m.group(0)
        parts = [int(x) for x in ip.split(".")]
        if any(p > 255 for p in parts):
            return ip
        if (parts[0] in (10, 127) or (parts[0] == 192 and parts[1] == 168) or
                (parts[0] == 172 and 16 <= parts[1] <= 31) or ip == "0.0.0.0"):
            return ip
        return "[IP_%d]" % table.setdefault(ip, len(table) + 1)

    return re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", sub, text)


# ---------------------------------------------------------------------------
# Trial registry (5.7 "Bench order", 10.0, 10.2)
# ---------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class Arm:
    name: str
    kind: str                 # knob kind; 'base' for the base arm
    params: tuple = ()        # sorted (key, value) pairs

    @property
    def p(self):
        return dict(self.params)


def _arm(name, kind, **params):
    return Arm(name, kind, tuple(sorted(params.items())))


@dataclasses.dataclass(frozen=True)
class Stage:
    name: str
    venue: str                # canary or aicore
    role: str = "screen"      # screen: every arm; confirm: only the chosen arm
    gw_cpus: tuple = ()       # gateway pinned to this many CPUs; () is the natural count


@dataclasses.dataclass(frozen=True)
class Trial:
    id: str
    title: str
    group: str                # latency or throughput (bench order)
    purpose: str              # latency or throughput (rule R item 2)
    kind: str                 # config (this harness applies it) or binary (own gateway round)
    base: Arm
    arms: tuple
    cells: tuple
    stages: tuple
    ref: str = ""
    side_traffic: bool = False      # AWG and Xray carried at the same time (P-3, P-4, P-10, P-22: node-wide knobs)
    cpu_ceiling_pp: float = 0.0     # busy polling total CPU ceiling (P-3), 0 = none
    background: tuple = ()          # services that must be loaded during the run (P-10)
    conditional_on: str = ""        # P-24 runs only if P-17 shows the stated pattern
    together_with: str = ""         # P-44 with P-39


DL_CELLS = (("a", "tcp1", "down"), ("b", "tcp1", "down"))
RING_CELLS = (("a", "tcp8", "down"), ("b", "tcp8", "down"))
BASE_FQ = _arm("base", "base")


def _config(tid, title, group, purpose, base, arms, cells, stages, ref, **kw):
    return Trial(tid, title, group, purpose, "config", base, tuple(arms), tuple(cells), tuple(stages), ref, **kw)


def _binary(tid, title, group, purpose, ref, cells=None, together_with=""):
    return Trial(tid, title, group, purpose, "binary", BASE_FQ, (_arm("candidate", "binary"),),
                 tuple(cells or full_matrix()),
                 (Stage("canary", "canary"),), ref, together_with=together_with)


def build_registry():
    t = {}
    t["P-17"] = _config(
        "P-17", "winn3gw0 ring (txqueuelen)", "latency", "latency",
        _arm("ring10000", "tun_qlen", qlen=10000),
        [_arm("ring4096", "tun_qlen", qlen=4096), _arm("ring2048", "tun_qlen", qlen=2048),
         _arm("ring1024", "tun_qlen", qlen=1024)],
        RING_CELLS,
        [Stage("aicore_cpu1", "aicore", "screen", (1,)), Stage("aicore_cpu2", "aicore", "screen", (2,)),
         Stage("canary_confirm", "canary", "confirm")],
        "10.2 P-17; 5.7 trial list")
    t["P-4"] = _config(
        "P-4", "WAN fq flow_limit", "latency", "latency",
        _arm("fl256", "fq_flow_limit", flow_limit=256),
        [_arm("fl100", "fq_flow_limit", flow_limit=100), _arm("fl1024", "fq_flow_limit", flow_limit=1024),
         _arm("fl2048", "fq_flow_limit", flow_limit=2048)],
        DL_CELLS, [Stage("canary", "canary")], "10.2 P-4 (ii); 5.7 trial list",
        side_traffic=True)      # the WAN fq carries AWG and Xray too: 10.0 item 1 clause is mandatory
    t["P-22"] = _config(
        "P-22", "WAN fq quantum", "latency", "latency",
        _arm("q1280", "fq_quantum", quantum=1280), [_arm("q1514", "fq_quantum", quantum=1514)],
        full_matrix(), [Stage("canary", "canary")], "10.2 P-22",
        side_traffic=True)      # the WAN fq carries AWG and Xray too: 10.0 item 1 clause is mandatory
    t["P-3"] = _config(
        "P-3", "busy poll", "latency", "latency",
        _arm("bp_off", "busy_poll", busy_poll=0, busy_read=0),
        [_arm("bp50", "busy_poll", busy_poll=50, busy_read=50)],
        full_matrix(), [Stage("canary", "canary")], "10.2 P-3", side_traffic=True,
        cpu_ceiling_pp=BUSY_POLL_CPU_CEILING_PP)
    t["P-10"] = _config(
        "P-10", "gateway CPUWeight and IOWeight", "latency", "latency",
        _arm("w100", "cgroup_weights", cpu_weight=100, io_weight=100),
        [_arm("w400_500", "cgroup_weights", cpu_weight=400, io_weight=500)],
        full_matrix(), [Stage("canary", "canary")], "10.2 P-10", side_traffic=True,
        background=("suricata", "awg", "xray"))
    t["P-18"] = _binary("P-18", "smaller upload standing queues", "latency", "latency", "10.2 P-18",
                        cells=tuple(c for c in full_matrix() if c[2] == "up"))
    t["P-41"] = _binary("P-41", "replay screen off the commit", "latency", "latency", "10E P-41")
    t["P-46"] = _binary("P-46", "refused run retries after the batch", "latency", "latency", "10F P-46")
    t["P-24"] = _config(
        "P-24", "noqueue on winn3gw0", "throughput", "throughput",
        _arm("mq_fq", "base"), [_arm("noqueue", "tun_noqueue")],
        (("a", "tcp1", "down"), ("a", "tcp4", "down"), ("b", "tcp1", "down"), ("b", "tcp4", "down")),
        [Stage("aicore", "aicore")],
        "10.2 P-24", conditional_on="P-17")
    for tid, title, ref in (
            ("P-20", "demux slice preallocation", "10.2 P-20"),
            ("P-21", "batch-mode observability", "10.2 P-21"),
            ("P-25", "UDP GRO on the 9111 listener", "10.2 P-25"),
            ("P-26", "10A P-26", "10A P-26"),
            ("P-27", "serialized reservation", "10A P-27"),
            ("P-28", "one peer lookup per datagram", "10A P-28"),
            ("P-29", "batch credit return on close", "10A P-29"),
            ("P-31", "early return for an empty batch", "10B P-31"),
            ("P-32", "reusable receive-deadline timer", "10B P-32"),
            ("P-35", "reuse destination authorization in a batch", "10C P-35"),
            ("P-36", "cheaper per-packet authorization", "10D P-36"),
            ("P-39", "count tun reads in batches", "10D P-39"),
            ("P-40", "cheaper roaming lookup", "10D P-40")):
        t[tid] = _binary(tid, title, "throughput", "throughput", ref)
    t["P-44"] = _binary("P-44", "count dispatch outcomes per batch", "throughput", "throughput",
                        "10E P-44", together_with="P-39")
    return t


TRIALS = build_registry()

# 5.7 "Bench order", item 1 to 3. P-17 first, then the latency trials, then throughput.
BENCH_ORDER = ("P-17", "P-4", "P-22", "P-3", "P-10", "P-18", "P-41", "P-46",
               "P-24", "P-20", "P-21", "P-25", "P-26", "P-27", "P-28", "P-29", "P-31", "P-32",
               "P-35", "P-36", "P-39", "P-40", "P-44")


def check_bench_order(order=BENCH_ORDER, trials=None):
    """Raise unless the order holds the 5.7 contract (used by the plan and the tests)."""
    trials = trials or TRIALS
    if sorted(order) != sorted(trials):
        raise ValueError("bench order and registry differ: %s" % sorted(set(order) ^ set(trials)))
    if order[0] != "P-17":
        raise ValueError("P-17 must run first")
    seen_throughput = False
    for tid in order:
        g = trials[tid].group
        if g == "throughput":
            seen_throughput = True
        elif seen_throughput:
            raise ValueError("latency trial %s after a throughput trial" % tid)
    return True


RULE_R_OUTCOMES = ("ADOPT", "REJECT", "NO_PURPOSE", "INCONCLUSIVE", "OWNER_RULING_CANDIDATE")


def trial_may_start(tid, state, trials=None, order=BENCH_ORDER):
    """(ok, why). A trial starts only when every earlier trial in the bench order has a recorded
    outcome in state (trial id to verdict string). A trial that needs its own gateway round is not
    skipped silently: record it as NOT_RUN first. P-24 also needs its condition recorded as met."""
    trials = trials or TRIALS
    if tid not in trials:
        return False, "unknown trial %s" % tid
    for prior in order[:order.index(tid)]:
        if prior not in state:
            return False, "%s has no recorded outcome yet (bench order); record NOT_RUN if it waits for its gateway round" % prior
        v = state[prior]
        if v == "NOT_RUN" and trials[prior].kind != "binary":
            return False, "%s is a config trial and must be decided by rule R; NOT_RUN is only for gateway-round trials" % prior
        if v != "NOT_RUN" and v not in RULE_R_OUTCOMES:
            return False, "%s has outcome %r, which is not a final rule R outcome" % (prior, v)
        if v == "NOT_RUN" and not str(state.get(prior + ".deferral") or "").strip():
            return False, ("%s is NOT_RUN without a recorded deferral reason; a deferral is a record, not a completion "
                           "(state set --verdict NOT_RUN --reason ...)" % prior)
    cond = trials[tid].conditional_on
    if cond and (state.get(tid + ".condition") != "met"
                 or not re.fullmatch(r"[0-9a-f]{64}", str(state.get(tid + ".condition_evidence") or ""))):
        return False, ("%s is conditional on %s showing its pattern (record it with p24-condition --state, which binds "
                       "the digest of the %s runs it read)" % (tid, cond, cond))
    return True, ""


def deferred_priors(tid, state, order=BENCH_ORDER):
    """The earlier trials recorded as NOT_RUN, with their reasons, for the later trial's record."""
    return {p: state.get(p + ".deferral") for p in order[:order.index(tid)] if state.get(p) == "NOT_RUN"}


def plan_json():
    out = []
    for tid in BENCH_ORDER:
        tr = TRIALS[tid]
        out.append({
            "id": tid, "title": tr.title, "group": tr.group, "purpose": tr.purpose, "kind": tr.kind,
            "ref": tr.ref, "base": tr.base.name,
            "arms": [{"name": a.name, "kind": a.kind, "params": a.p} for a in tr.arms],
            "cells": ["%s %s %s" % c for c in tr.cells],
            "stages": [{"name": s.name, "venue": s.venue, "role": s.role, "gw_cpus": list(s.gw_cpus)} for s in tr.stages],
            "side_traffic": tr.side_traffic, "background": list(tr.background),
            "conditional_on": tr.conditional_on, "together_with": tr.together_with,
            "deferred": "own gateway round (binary change)" if tr.kind == "binary" else "",
        })
    return out


# ---------------------------------------------------------------------------
# Schedule: base, base repeat and every candidate interleaved, fresh session per run
# ---------------------------------------------------------------------------
def arm_names(trial):
    return ["base_a"] + [a.name for a in trial.arms] + ["base_b"]


def schedule(trial, reps, seed, stage=None, only_arms=None):
    """Deterministic order. For each rep and cell every arm appears once, in a seeded shuffle,
    so no arm owns a time slot (5.7: paired base against candidate in the same run)."""
    names = [n for n in arm_names(trial) if only_arms is None or n in only_arms or n in ("base_a", "base_b")]
    out = []
    for rep in range(1, reps + 1):
        for cell in trial.cells:
            rng = random.Random("%s/%s/%s/%s/%s" % (seed, trial.id, stage or "", rep, "/".join(cell)))
            order = list(names)
            rng.shuffle(order)
            for arm in order:
                out.append({"trial": trial.id, "stage": stage, "arm": arm, "rep": rep,
                            "profile": cell[0], "test": cell[1], "dir": cell[2]})
    return out


def role_of(arm_name):
    return {"base_a": "base_a", "base_b": "base_b"}.get(arm_name, "cand")


# ---------------------------------------------------------------------------
# Rule R (10.0)
# ---------------------------------------------------------------------------
def _alive(r):
    return bool(r.get("started")) and bool(r.get("alive", True))


def index_runs(runs):
    idx = {}
    for r in runs:
        key = (r.get("stage"), r.get("arm"), (r.get("profile"), r.get("test"), r.get("dir")), r.get("rep"))
        idx[key] = r
    return idx


def _reps(idx, stage, arm, cell):
    return sorted({k[3] for k in idx if k[0] == stage and k[1] == arm and k[2] == cell})


def paired(idx, stage, arm_x, arm_y, cell, field):
    """[(rep, x, y)] over reps where both runs started, survived and carry a number."""
    out = []
    for rep in _reps(idx, stage, arm_y, cell):
        x = idx.get((stage, arm_x, cell, rep))
        y = idx.get((stage, arm_y, cell, rep))
        if x and y and _alive(x) and _alive(y) and is_num(x.get(field)) and is_num(y.get(field)):
            out.append((rep, x[field], y[field]))
    return out


def noise_and_effect(idx, stage, arm, cell, field, base_a="base_a", base_b="base_b"):
    """(n_base_pairs, noise, n_cand_pairs, effect). noise = max |Rb - Ra| over the cell's base
    pairs; effect = median(C - Ra). Either is None when there are no pairs."""
    bp = paired(idx, stage, base_a, base_b, cell, field)
    cp = paired(idx, stage, base_a, arm, cell, field)
    noise = max(abs(b - a) for _, a, b in bp) if bp else None
    effect = median([c - a for _, a, c in cp]) if cp else None
    return len(bp), noise, len(cp), effect


def _rate(runs):
    """(start failures, attempts). sessions_started counts sessions that came up, sessions_failed
    attempts that did not; without those keys a run that started is one success, else one failure."""
    failed = sum(int(r.get("sessions_failed", 0 if r.get("started") else 1)) for r in runs)
    started = sum(int(r.get("sessions_started", 1 if r.get("started") else 0)) for r in runs)
    return failed, failed + started


def session_failure_check(idx, stage, arm):
    cand = [r for k, r in idx.items() if k[0] == stage and k[1] == arm]
    base = [r for k, r in idx.items() if k[0] == stage and k[1] in ("base_a", "base_b")]
    reasons = []
    cf, ct = _rate(cand)
    bf, bt = _rate(base)
    crate = cf / ct if ct else 0.0
    brate = bf / bt if bt else 0.0
    if ct and crate > brate + START_FAIL_ALLOWANCE + 1e-12:
        reasons.append("start-failure rate %.4f exceeds base %.4f plus 1/200" % (crate, brate))
    ccls = {r.get("failure_class") for r in cand if r.get("failure_class")}
    bcls = {r.get("failure_class") for r in base if r.get("failure_class")}
    new = sorted(ccls - bcls)
    if new:
        reasons.append("adds session-failure class %s" % ",".join(new))
    return reasons, {"cand_failed": cf, "cand_total": ct, "base_failed": bf, "base_total": bt}


def rise_ms(idx, stage, arm, profile, cells, min_n=1):
    """Worst cell of the profile: median over reps of (loaded p50 minus idle p50). None (not measured)
    unless EVERY cell of the profile has at least min_n runs with both numbers: a partial profile
    cannot establish the owner's bar (10.0 item 3)."""
    worst = None
    for cell in cells:
        if cell[0] != profile:
            continue
        vals = []
        for rep in _reps(idx, stage, arm, cell):
            r = idx.get((stage, arm, cell, rep))
            if r and _alive(r) and is_num(r.get("ld_p50_ms")) and is_num(r.get("idle_p50_ms")):
                vals.append(r["ld_p50_ms"] - r["idle_p50_ms"])
        if len(vals) < max(1, min_n):
            return None
        m = median(vals)
        worst = m if worst is None else max(worst, m)
    return worst


def background_problems(trial, idx, stage):
    """P-10 measures with Suricata, AWG and Xray loaded at the same time. A run that does not show
    each of them carrying load (a positive number under 'background') cannot support the trial."""
    if not trial.background:
        return []
    bad = 0
    for k, r in idx.items():
        if k[0] != stage or not _alive(r):
            continue
        bg = r.get("background")
        if not isinstance(bg, dict) or not all(is_num(bg.get(n)) and bg[n] > 0 for n in trial.background):
            bad += 1
    return ["%d runs lack positive background load for %s" % (bad, "/".join(trial.background))] if bad else []


def cpu_ceiling_for(trial, usable_cpus):
    """10.0 item 1: busy polling may add at most 5 points of total CPU "on a 4-vCPU node", which is
    0.2 of one core. On other node classes the stricter of 5 points and the same 0.2 core
    (5 * 4 / usable CPUs points) applies. Unknown CPU count: 5 points (such a stage is not adoptable)."""
    if not trial.cpu_ceiling_pp:
        return 0.0
    if not is_num(usable_cpus) or usable_cpus <= 0:
        return trial.cpu_ceiling_pp
    return min(trial.cpu_ceiling_pp, trial.cpu_ceiling_pp * 4.0 / usable_cpus)


def evaluate_arm(trial, idx, stage, arm, min_reps=DEFAULT_MIN_REPS, usable_cpus=None):
    """Item 1 and item 2 for one candidate arm of one stage, plus its rise per profile."""
    cpu_ceiling = cpu_ceiling_for(trial, usable_cpus)
    res = {"arm": arm, "reject": [], "inconclusive": [], "effects": {}, "latency_fall": [],
           "throughput_gain": [], "throughput_lower": [], "score_latency": 0.0, "score_throughput": 0.0}
    required = list(LATENCY_METRICS) + ["thr_mbps"]
    optional = ["awg_mbps", "xray_mbps", "awg_ld_p99_ms", "xray_ld_p99_ms"]
    venue = next((s.venue for s in trial.stages if s.name == stage), None)
    # 10.0 item 1's AWG and Xray clause applies to every trial: mandatory wherever AWG and Xray run (every
    # canary stage, and the node-wide knobs), measured-if-present on the v3-only aicore rig.
    if trial.side_traffic or venue == "canary":
        required, optional = required + optional, []
    if trial.cpu_ceiling_pp:
        required.append("cpu_total_pct")
    for cell in trial.cells:
        label = "%s %s %s" % cell
        for field in required + optional:
            nb, noise, nc, eff = noise_and_effect(idx, stage, arm, cell, field)
            if nb < min_reps or nc < min_reps or noise is None or eff is None:
                if field in required:
                    res["inconclusive"].append("%s %s: %d base pairs, %d candidate pairs, need %d" % (label, field, nb, nc, min_reps))
                continue
            res["effects"]["%s|%s" % (label, field)] = {"effect": eff, "noise": noise, "n": nc}
            if field in LATENCY_METRICS and eff > noise:
                res["reject"].append("%s raises %s by %.3f beyond noise %.3f" % (label, field, eff, noise))
            if field == "ld_p50_ms" and eff < -noise:
                res["latency_fall"].append(cell)
                res["score_latency"] += -eff
            if field == "thr_mbps":
                if eff > noise:
                    res["throughput_gain"].append(cell)
                    res["score_throughput"] += eff
                elif eff < -noise:
                    res["throughput_lower"].append(cell)
            if field in ("awg_mbps", "xray_mbps") and eff < -noise:
                res["reject"].append("%s lowers %s by %.3f beyond noise %.3f" % (label, field, -eff, noise))
            if field in ("awg_ld_p99_ms", "xray_ld_p99_ms") and eff > noise:
                res["reject"].append("%s raises %s by %.3f beyond noise %.3f" % (label, field, eff, noise))
            if field == "cpu_total_pct" and eff > cpu_ceiling:
                res["reject"].append("%s raises total CPU by %.2f pp, above the %.1f pp ceiling" % (label, eff, cpu_ceiling))
    res["inconclusive"] += background_problems(trial, idx, stage)
    fail_reasons, fail_counts = session_failure_check(idx, stage, arm)
    res["reject"] += fail_reasons
    res["sessions"] = fail_counts
    res["rise_ms"] = {p: rise_ms(idx, stage, arm, p, trial.cells, min_reps) for p in PROFILES}
    res["cpu_ceiling_pp"] = cpu_ceiling
    lowers_p50_keeps_thr = bool(res["latency_fall"]) and not res["throughput_lower"]
    if trial.purpose == "latency":
        res["serves_purpose"] = lowers_p50_keeps_thr
        res["score"] = res["score_latency"]
    else:
        res["serves_purpose"] = bool(res["throughput_gain"])
        res["score"] = res["score_throughput"]
    # Item 3 branch: a candidate that lowers loaded p50 without lowering throughput is judged
    # under (a) whatever the trial's own purpose (10.0 item 3, the "both" bullet).
    res["judged_under"] = "a" if (lowers_p50_keeps_thr and res["serves_purpose"]) else ("b" if res["serves_purpose"] else None)
    return res


def owner_bar_notes(rise_by_profile, branch):
    """The record lines item 3 requires. Under (a) the exact phrase is 'owner bar not met: rise X ms,
    gap X - 50 ms' with the numbers filled in; it never reads as meeting the owner's target."""
    notes = []
    for p in PROFILES:
        r = rise_by_profile.get(p)
        if r is None:
            notes.append("profile %s: rise not measured" % p)
        elif branch == "a" and r > BAR_MS:
            notes.append("profile %s: owner bar not met: rise %.1f ms, gap %.1f ms" % (p, r, r - BAR_MS))
        elif r > BAR_MS:
            notes.append("profile %s: rise %.1f ms is over the 50 ms limit by %.1f ms" % (p, r, r - BAR_MS))
        else:
            notes.append("profile %s: owner bar met: rise %.1f ms" % (p, r))
    return notes


def decide_screen(trial, idx, stage, arms=None, min_reps=DEFAULT_MIN_REPS, usable_cpus=None):
    """Items 1 to 3 for one stage. Returns the stage result with a verdict. Any arm without enough
    paired data makes the stage INCONCLUSIVE (the best arm cannot be named), and the base stays."""
    names = arms or [a.name for a in trial.arms]
    per_arm = {n: evaluate_arm(trial, idx, stage, n, min_reps, usable_cpus) for n in names}
    base_rise = {p: rise_ms(idx, stage, "base_a", p, trial.cells, min_reps) for p in PROFILES}
    out = {"stage": stage, "arms": per_arm, "base_rise_ms": base_rise, "chosen": None,
           "verdict": None, "branch": None, "notes": [], "noise_definition": NOISE_NOTE,
           "score_definition": "sum over cells of the improvements that are beyond noise only (ms of loaded p50 "
                               "fall, or Mbit/s of gain); cells within noise add 0; ties go to the earlier arm"}
    if any(r["inconclusive"] for r in per_arm.values()):
        out["verdict"] = "INCONCLUSIVE"
        out["notes"].append("not enough paired runs for a decision; the base stays")
        return out
    passing = [n for n in names if not per_arm[n]["reject"]]
    if not passing:
        out["verdict"] = "REJECT"
        out["notes"].append("every candidate fails item 1; the base stays")
        return out
    serving = [n for n in passing if per_arm[n]["serves_purpose"]]
    if not serving:
        out["verdict"] = "NO_PURPOSE"
        out["notes"].append("no candidate that passes item 1 serves the trial's purpose; the base stays")
        return out
    best = max(serving, key=lambda n: (per_arm[n]["score"], -serving.index(n)))
    chosen = per_arm[best]
    out["chosen"] = best
    out["branch"] = chosen["judged_under"]
    out["notes"] += owner_bar_notes(chosen["rise_ms"], chosen["judged_under"])
    out["notes"].append("base rise at the time of the trial: " + ", ".join(
        "%s %s" % (p, "n/a" if base_rise[p] is None else "%.1f ms" % base_rise[p]) for p in PROFILES))
    out["notes"].append("item 3 branch (%s)" % chosen["judged_under"])
    if chosen["judged_under"] == "a":
        out["verdict"] = "ADOPT"
    else:
        over = [p for p in PROFILES if chosen["rise_ms"].get(p) is None or chosen["rise_ms"][p] > BAR_MS]
        if over:
            out["verdict"] = "OWNER_RULING_CANDIDATE"
            unmeasured = [p for p in over if chosen["rise_ms"].get(p) is None]
            out["evidence_incomplete"] = unmeasured
            if unmeasured:
                out["notes"].append("rise not measured on profile %s: evidence incomplete, which is not a measured "
                                    "exceedance; the base stays until the rise is measured" % ",".join(unmeasured))
            out["notes"].append("throughput candidate over the 50 ms bar on profile %s: the base stays; "
                                "the paired numbers go to the owner and nothing is adopted without a ruling" % ",".join(over))
        else:
            out["verdict"] = "ADOPT"
    return out


def decide_trial(trial, runs, node_classes=None, min_reps=DEFAULT_MIN_REPS):
    """Whole-trial decision across stages. node_classes maps a stage name to its node class record.

    Screen stages must each pass item 1 and the purpose for an arm; the arm with the best mean
    score goes forward; a confirm stage then judges that arm alone; the confirm stage's verdict
    is the trial's. A trial with only screen stages is decided by its (single) stage."""
    node_classes = node_classes or {}
    stage_results = {}
    ineligible = []
    for st in trial.stages:
        sruns = [r for r in runs if r.get("stage") == st.name and r.get("trial") == trial.id]
        ok, reasons = venue_eligibility(node_classes.get(st.name))
        if ok and node_classes[st.name].get("venue") != st.venue:
            ok, reasons = False, ["stage %s needs venue %s, got %s" % (st.name, st.venue, node_classes[st.name].get("venue"))]
        if ok:
            bad = {r.get("venue") for r in sruns if r.get("venue") != st.venue}
            if bad:
                ok, reasons = False, ["run records carry venue %s, stage needs %s" % (sorted(map(str, bad)), st.venue)]
        if ok:
            nc = node_classes[st.name]
            unbound = sum(1 for r in sruns if r.get("node_class_id") != nc.get("class_id")
                          or r.get("binary_sha256") != nc.get("binary_sha256"))
            if unbound:
                ok, reasons = False, ["%d run records do not carry the stage's node class id and binary digest" % unbound]
        if ok and st.gw_cpus:
            unpinned = sum(1 for r in sruns if r.get("gw_cpus_observed") != st.gw_cpus[0])
            if unpinned:
                ok, reasons = False, ["%d run records lack evidence that the gateway was pinned to %d CPU(s)"
                                      % (unpinned, st.gw_cpus[0])]
        if not ok:
            ineligible.append((st.name, reasons))
        stage_results[st.name] = {"runs": len(sruns), "eligible": ok, "ineligible_reasons": reasons}
    screens = [s for s in trial.stages if s.role == "screen"]
    confirms = [s for s in trial.stages if s.role == "confirm"]
    chosen = None
    result = {"trial": trial.id, "title": trial.title, "purpose": trial.purpose, "stages": stage_results,
              "rule_r_verdict": None, "adoptable": False, "chosen_arm": None, "notes": []}
    screen_decisions = {}
    for s in screens:
        sruns = [r for r in runs if r.get("stage") == s.name and r.get("trial") == trial.id]
        screen_decisions[s.name] = decide_screen(trial, index_runs(sruns), s.name, min_reps=min_reps,
                                                 usable_cpus=(node_classes.get(s.name) or {}).get("usable_cpus"))
        stage_results[s.name]["decision"] = screen_decisions[s.name]
    if len(screens) == 1 and not confirms:
        d = screen_decisions[screens[0].name]
        result["rule_r_verdict"], result["chosen_arm"], result["notes"] = d["verdict"], d["chosen"], list(d["notes"])
        result["branch"] = d["branch"]
    else:
        survivors = None
        for s in screens:
            d = screen_decisions[s.name]
            if d["verdict"] == "INCONCLUSIVE":
                result["rule_r_verdict"] = "INCONCLUSIVE"
                result["notes"].append("screen stage %s is inconclusive" % s.name)
                survivors = []
                break
            ok_arms = {n for n, a in d["arms"].items() if not a["reject"] and not a["inconclusive"] and a["serves_purpose"]}
            survivors = ok_arms if survivors is None else survivors & ok_arms
        if result["rule_r_verdict"] is None:
            if not survivors:
                rejected = any(d["verdict"] == "REJECT" for d in screen_decisions.values())
                result["rule_r_verdict"] = "REJECT" if rejected else "NO_PURPOSE"
                result["notes"].append("no arm passes item 1 and the purpose in every screen stage; the base stays")
            else:
                def mean_score(n):
                    return sum(screen_decisions[s.name]["arms"][n]["score"] for s in screens) / len(screens)
                names = [a.name for a in trial.arms]
                chosen = max(sorted(survivors, key=names.index), key=lambda n: (mean_score(n), -names.index(n)))
                result["chosen_arm"] = chosen
                result["notes"].append("arm %s goes forward from the pinned stages (mean score %.2f)" % (chosen, mean_score(chosen)))
                if confirms:
                    cs = confirms[0]
                    cruns = [r for r in runs if r.get("stage") == cs.name and r.get("trial") == trial.id]
                    if not cruns:
                        result["rule_r_verdict"] = "PENDING_CONFIRM"
                        result["notes"].append("confirmation on a canary node at its natural CPU count has not run")
                    else:
                        d = decide_screen(trial, index_runs(cruns), cs.name, arms=[chosen], min_reps=min_reps,
                                          usable_cpus=(node_classes.get(cs.name) or {}).get("usable_cpus"))
                        stage_results[cs.name]["decision"] = d
                        result["rule_r_verdict"] = d["verdict"]
                        result["branch"] = d["branch"]
                        result["notes"] += d["notes"]
                else:
                    last = screen_decisions[screens[-1].name]
                    result["rule_r_verdict"], result["branch"] = last["verdict"], last["branch"]
    eligible_all = not ineligible
    result["min_reps"] = min_reps
    if min_reps < DEFAULT_MIN_REPS:
        ineligible.append(("min_reps", ["decided with %d paired runs per cell, the ruled minimum is %d" % (min_reps, DEFAULT_MIN_REPS)]))
        eligible_all = False
    result["adoptable"] = bool(result["rule_r_verdict"] == "ADOPT" and eligible_all)
    if ineligible:
        result["notes"].append("NOT ADOPTABLE: " + "; ".join("%s: %s" % (n, " / ".join(r)) for n, r in ineligible))
    return result


def p24_condition(runs, stage, base_arm="ring10000", smallest_arm="ring1024", backlog_pkts=2.0, trial=None):
    """P-24 runs only if P-17 shows fq child backlog at about 0 while winn3gw0 TX drops rise.
    'About 0' is read as a median of the per-run maximum child backlog of at most backlog_pkts for
    every ring arm of P-17 ON EACH PROFILE (a pooled median could hide a profile with backlog), and
    every ring arm must be present on every profile; 'rise' as the smallest ring's median TX drops
    above the base ring's, and above 0, on at least one profile (on the cellular profile the ring
    may never fill). Only rows labelled with the P-17 trial id count: a file of another trial's
    rows cannot meet the condition however its stages and arms are named."""
    trial = trial or TRIALS["P-17"]
    runs = [r for r in runs if r.get("trial") == trial.id]
    rings = [base_arm] + [a.name for a in trial.arms]

    def med(arm, field, profile):
        vals = [r[field] for r in runs if r.get("stage") == stage and r.get("arm") in
                ((arm, "base_a", "base_b") if arm == base_arm else (arm,)) and r.get("profile") == profile
                and is_num(r.get(field)) and _alive(r)]
        return median(vals) if vals else None
    per_profile, backlog_ok, drops_rise, missing = {}, True, False, []
    for p in PROFILES:
        rec = {"backlog_median_by_arm": {}}
        for a in rings:
            m = med(a, "fq_child_backlog_pkts_max", p)
            rec["backlog_median_by_arm"][a] = m
            if m is None:
                missing.append("%s profile %s" % (a, p))
                backlog_ok = False
            elif m > backlog_pkts:
                backlog_ok = False
        d_small, d_base = med(smallest_arm, "tx_drops", p), med(base_arm, "tx_drops", p)
        rec.update({"tx_drops_smallest": d_small, "tx_drops_base": d_base,
                    "drops_rise": d_small is not None and d_base is not None and d_small > d_base and d_small > 0})
        drops_rise = drops_rise or rec["drops_rise"]
        per_profile[p] = rec
    return {"met": bool(backlog_ok and drops_rise), "backlog_ok": backlog_ok, "drops_rise": drops_rise,
            "missing": missing, "profiles": per_profile}


# ---------------------------------------------------------------------------
# Connect time (5.7, 10.6)
# ---------------------------------------------------------------------------
def _total_s(r):
    if not r.get("ok", True) or not is_num(r.get("total_ms")):
        return math.inf
    return r["total_ms"] / 1000.0


def connect_groups(rows):
    g = {}
    for r in rows:
        g.setdefault((r.get("node_class"), r.get("network")), []).append(r)
    return g


def stage_samples(rows, stage):
    return [r["stages_ms"][stage] / 1000.0 for r in rows
            if r.get("ok", True) and isinstance(r.get("stages_ms"), dict) and is_num(r["stages_ms"].get(stage))]


def analyze_connect_time(rows, baseline_rows=None, limit_s=CONNECT_P95_LIMIT_S, min_runs=CONNECT_MIN_RUNS):
    """Pass: p95 at most 4.0 s in each network type and node class (nearest rank; a failed run is
    infinitely slow). On a miss, a per-stage breakdown; the miss blocks S7 only when a stage is
    slower than the pre-change baseline of the same node class beyond that baseline's own noise
    (read as its max minus min); otherwise it is recorded as an owner-target gap and opens a
    gateway round. A miss with no baseline blocks until one exists."""
    groups = connect_groups(rows)
    base_groups = connect_groups(baseline_rows or [])
    classes = sorted({k[0] for k in groups}, key=str)
    out = {"limit_s": limit_s, "groups": {}, "verdict": None, "blocks_s7": False,
           "opens_gateway_round": False, "insufficient": [], "wrong_endpoint": [], "endpoint": CONNECT_ENDPOINT}
    for nc in classes:
        for net in CONNECT_NETWORKS:
            key = "%s|%s" % (nc, net)
            rs = groups.get((nc, net), [])
            g = {"n": len(rs), "failures": sum(1 for r in rs if _total_s(r) == math.inf)}
            out["groups"][key] = g
            # a timed run must end at the first carried DNS answer; another end point (a carried ping, an
            # engine packet) can serve as a historical baseline only, never as a pass run
            wrong = sum(1 for r in rs if _total_s(r) != math.inf and r.get("endpoint") != CONNECT_ENDPOINT)
            if wrong:
                g["verdict"] = "WRONG_ENDPOINT"
                g["wrong_endpoint_rows"] = wrong
                out["wrong_endpoint"].append(key)
                continue
            if len(rs) < min_runs:
                g["verdict"] = "INSUFFICIENT_RUNS"
                g["need"] = min_runs
                out["insufficient"].append(key)
                continue
            totals = [_total_s(r) for r in rs]
            g["p50_s"], g["p95_s"], g["max_s"] = median(totals), nearest_rank(totals, 95), max(totals)
            if g["p95_s"] <= limit_s:
                g["verdict"] = "PASS"
                continue
            g["verdict"] = "MISS"
            breakdown, slower, incomplete = {}, [], []
            brs = base_groups.get((nc, net), [])
            n_ok = sum(1 for r in rs if _total_s(r) != math.inf)
            for st in CONNECT_STAGES:
                s_ = stage_samples(rs, st)
                b_ = stage_samples(brs, st)
                # every successful run must carry every stage (a run without first-time allocation records 0),
                # and the baseline needs min_runs measured samples; anything less leaves the miss unresolved
                if not s_ or len(s_) < n_ok or len(b_) < min_runs:
                    incomplete.append(st)
                rec = {"n": len(s_), "median_s": median(s_) if s_ else None, "p95_s": nearest_rank(s_, 95) if s_ else None}
                if s_ and b_:
                    noise = max(b_) - min(b_)
                    delta = median(s_) - median(b_)
                    rec.update({"baseline_median_s": median(b_), "baseline_noise_s": noise, "delta_s": delta,
                                "slower_than_baseline": delta > noise})
                    if delta > noise:
                        slower.append(st)
                breakdown[st] = rec
            g["breakdown"], g["slower_stages"], g["incomplete_stages"] = breakdown, slower, incomplete
            if not brs:
                g["miss_class"] = "NEEDS_BASELINE"
                out["blocks_s7"] = True
            elif slower:
                g["miss_class"] = "BLOCKS_S7"
                out["blocks_s7"] = True
            elif incomplete:
                g["miss_class"] = "STAGE_EVIDENCE_INCOMPLETE"
                out["blocks_s7"] = True
            else:
                g["miss_class"] = "OWNER_TARGET_GAP"
                out["opens_gateway_round"] = True
    if out["blocks_s7"]:
        out["verdict"] = "MISS_BLOCKS_S7"
    elif out["wrong_endpoint"]:
        out["verdict"] = "WRONG_ENDPOINT"
    elif out["insufficient"] or not classes:
        out["verdict"] = "INSUFFICIENT_RUNS"
    elif out["opens_gateway_round"]:
        out["verdict"] = "MISS_OWNER_TARGET_GAP"
    else:
        out["verdict"] = "PASS"
    return out


def connect_rows_from_ct4m(rows, node_class, network):
    """Adapter for connect-time-20261001/measure/analyze.py rows (attempts_phases.json). Seconds
    from t0. CT4-M has no carried DNS answer: its end point is ping_carry (the first carried reply),
    else carry (the engine's first delivered packet), and each row says which. Such rows can serve
    only as a historical baseline; analyze_connect_time refuses them as pass runs. 'allocation' is
    not separable on the phone (it sits inside the hub refresh) and stays missing. An attempt the
    analysis could not time ("error") is kept as a failed attempt, never dropped; a network switch
    is a different kind of attempt and is left out."""
    out = []
    for r in rows:
        if r.get("kind") == "switch":
            continue
        if "error" in r:
            out.append({"node_class": node_class, "network": network, "ok": False, "total_ms": None, "stages_ms": {},
                        "endpoint": None, "error": str(r["error"])[:200]})
            continue
        end = r.get("ping_carry") if r.get("ping_carry") is not None else r.get("carry")
        endpoint = "first_ping_reply" if r.get("ping_carry") is not None else ("first_delivered_packet" if end is not None else None)
        hub = None
        if r.get("candidate") is not None:
            hub = r["candidate"] - (r["handler"] if r.get("handler") is not None else 0.0)
        hs = (r["gate_carrying"] - r["datapath"]) if r.get("gate_carrying") is not None and r.get("datapath") is not None else None
        fc = (end - r["gate_carrying"]) if end is not None and r.get("gate_carrying") is not None else None
        st = {}
        for name, v in (("hub_config_fetch", hub), ("handshake", hs), ("first_carried_packet", fc)):
            if v is not None:
                st[name] = round(v * 1000.0, 1)
        out.append({"node_class": node_class, "network": network, "ok": end is not None,
                    "total_ms": round(end * 1000.0, 1) if end is not None else None, "stages_ms": st, "endpoint": endpoint})
    return out


# ---------------------------------------------------------------------------
# Replay-journal storm (P-19, 5.7)
# ---------------------------------------------------------------------------
def parse_fio_fsync_p99_ms(fio_json_text):
    """p99 fsync latency in ms from `fio --output-format=json --rw=write --bs=4k --fsync=1`."""
    doc = json.loads(fio_json_text)
    job = doc["jobs"][0]
    for section in ("sync", "write"):
        lat = job.get(section, {}).get("lat_ns", {})
        pct = lat.get("percentile", {})
        for key in ("99.000000", "99.00", "99"):
            if key in pct:
                return pct[key] / 1e6
    raise ValueError("no p99 latency in fio output")


def analyze_storm(rec, min_reps=DEFAULT_MIN_REPS):
    """rec: {mem_total_kib, max_sessions, fio_p99_ms, sessions_tested, restart_to_carrying_s: [..]
    (None = timeout), over_capacity_refusals: n, over_capacity_attempts: n}. Host fit is never
    waived: the test size must equal min(64, max-sessions) and max-sessions must not exceed the fit."""
    out = {"verdict": None, "notes": []}
    if not is_num(rec.get("mem_total_kib")) or rec["mem_total_kib"] <= 0:
        out["verdict"] = "HOST_FIT_UNKNOWN"
        out["notes"].append("no MemTotal recorded: without the fit, 'host fit is never waived' cannot be shown")
        return out
    if not is_num(rec.get("fio_p99_ms")):
        out["verdict"] = "MISSING_FSYNC_MEASUREMENT"
        out["notes"].append("5.7 needs the per-node-class fio --fsync=1 p99 with the storm")
        return out
    fit_cap = default_max_sessions(rec["mem_total_kib"])
    n_expected = min(SESSIONS_CAP, rec["max_sessions"])
    out["sessions_expected"] = n_expected
    if rec["max_sessions"] > fit_cap:
        out["verdict"] = "HOST_FIT_WAIVED"
        out["notes"].append("max-sessions %d exceeds the host fit %d: host fit is never waived for the benchmark"
                            % (rec["max_sessions"], fit_cap))
        return out
    if rec.get("sessions_tested") != n_expected:
        out["verdict"] = "WRONG_STORM_SIZE"
        out["notes"].append("storm must use min(64, max-sessions) = %d sessions, got %s" % (n_expected, rec.get("sessions_tested")))
        return out
    times = [STORM_TIMEOUT_S if t is None else min(float(t), STORM_TIMEOUT_S) for t in rec.get("restart_to_carrying_s", [])]
    out["timeouts"] = sum(1 for t in rec.get("restart_to_carrying_s", []) if t is None or t >= STORM_TIMEOUT_S)
    if len(times) < min_reps:
        out["verdict"] = "INSUFFICIENT_RUNS"
        out["notes"].append("%d storm runs, need %d" % (len(times), min_reps))
        return out
    out["storm_p50_s"], out["storm_p95_s"] = median(times), nearest_rank(times, 95)
    out["fio_fsync_p99_ms"] = rec.get("fio_p99_ms")
    refused = rec.get("over_capacity_refusals")
    out["over_capacity"] = {"attempts": rec.get("over_capacity_attempts"), "refused": refused}
    if rec.get("over_capacity_attempts") != STORM_OVER_CAPACITY_ATTEMPTS:
        out["notes"].append("over-capacity test should make %d attempts" % STORM_OVER_CAPACITY_ATTEMPTS)
    out["propose_group_commit"] = out["storm_p95_s"] > STORM_P95_LIMIT_S
    out["verdict"] = "GROUP_COMMIT_PROPOSED" if out["propose_group_commit"] else "NO_GROUP_COMMIT"
    out["notes"].append("the journal stays on either way (ruled); group commit goes to its own round under the journal ruling")
    return out


# ---------------------------------------------------------------------------
# Go-live latency (5.7)
# ---------------------------------------------------------------------------
def analyze_golive(installs, required=GOLIVE_PROOFS, limit_s=GOLIVE_P95_LIMIT_S, min_installs=GOLIVE_MIN_INSTALLS):
    """installs: [{slug, deployment_completed_at, operator_enabled_at, proofs: {name: ok_at}}]
    with epoch seconds. Every required proof must exist and be strictly later than completion."""
    out = {"n": len(installs), "stale_proofs": [], "missing_proofs": [], "late_proofs": [], "walls_s": [], "verdict": None}
    for i, inst in enumerate(installs):
        done = inst["deployment_completed_at"]
        en = inst.get("operator_enabled_at")
        for name in required:
            ok_at = (inst.get("proofs") or {}).get(name)
            if ok_at is None:
                out["missing_proofs"].append({"install": i, "proof": name})
            elif not ok_at > done:
                out["stale_proofs"].append({"install": i, "proof": name, "ok_at": ok_at, "completed_at": done})
            elif en is not None and ok_at > en:
                # the enable event must follow every required proof, or it was not a lawful automatic go-live
                out["late_proofs"].append({"install": i, "proof": name, "ok_at": ok_at, "enabled_at": en})
        if en is None:
            out["missing_proofs"].append({"install": i, "proof": "operator_enabled"})
        else:
            out["walls_s"].append(en - done)
    if out["stale_proofs"] or out["missing_proofs"] or out["late_proofs"]:
        out["verdict"] = ("PROOF_NOT_NEWER_THAN_COMPLETION" if out["stale_proofs"] else
                          "MISSING_PROOF" if out["missing_proofs"] else "ENABLED_BEFORE_PROOF")
        return out
    if len(installs) < min_installs:
        out["verdict"] = "INSUFFICIENT_INSTALLS"
        return out
    out["p50_s"], out["p95_s"], out["max_s"] = median(out["walls_s"]), nearest_rank(out["walls_s"], 95), max(out["walls_s"])
    out["verdict"] = "PASS" if out["p95_s"] <= limit_s else "MISS"
    return out


# ---------------------------------------------------------------------------
# Uncapped Ryzen acceptance (5.7)
# ---------------------------------------------------------------------------
def analyze_ryzen(runs, lock_owner=None):
    """runs: [{dir, mbps, flows, seconds, profile, gw_cpu_per_core: [..], ld_p50_ms, ld_p99_ms,
    ld_jitter_ms, ld_loss_pct}]. Pass: median at least 1.8 Gbit/s in each direction. A miss blocks
    nothing; it records the shortfall with gateway CPU per core and opens a gateway round."""
    out = {"verdict": None, "dirs": {}, "problems": []}
    if not lock_owner:
        out["problems"].append("no aicore bench lock owner recorded (aicore_bench_lock_canonical_20260929)")
    for d in DIRS:
        rs = [r for r in runs if r.get("dir") == d]
        info = {"n": len(rs)}
        if len(rs) != RYZEN_RUNS:
            out["problems"].append("%s: %d runs, need exactly %d" % (d, len(rs), RYZEN_RUNS))
        for r in rs:
            if r.get("flows") != RYZEN_FLOWS or (r.get("seconds") or 0) < RYZEN_MIN_SECONDS:
                out["problems"].append("%s: run is not %d flows for at least %d s" % (d, RYZEN_FLOWS, RYZEN_MIN_SECONDS))
                break
        if any(r.get("profile") not in ("none", "uncapped") for r in rs):
            out["problems"].append("%s: the profile a netem shaper must be removed (it caps near 1.67 Gbit/s)" % d)
        if rs and all(is_num(r.get("mbps")) for r in rs):
            info["median_mbps"] = median([r["mbps"] for r in rs])
            info["min_mbps"] = min(r["mbps"] for r in rs)
            info["pass"] = info["median_mbps"] >= RYZEN_TARGET_MBPS
            if not info["pass"]:
                info["shortfall_mbps"] = RYZEN_TARGET_MBPS - info["median_mbps"]
                cores = [r.get("gw_cpu_per_core") for r in rs if r.get("gw_cpu_per_core")]
                if cores:
                    n = max(len(c) for c in cores)
                    info["gw_cpu_per_core_median"] = [median([c[i] for c in cores if i < len(c)]) for i in range(n)]
            for f in ("ld_p50_ms", "ld_p99_ms", "ld_jitter_ms", "ld_loss_pct"):
                v = [r[f] for r in rs if is_num(r.get(f))]
                if v:
                    info[f + "_median"] = median(v)
        else:
            out["problems"].append("%s: runs lack a numeric mbps" % d)
        out["dirs"][d] = info
    if out["problems"]:
        out["verdict"] = "INVALID_RUN"
    elif all(out["dirs"][d].get("pass") for d in DIRS):
        out["verdict"] = "PASS"
    else:
        out["verdict"] = "MISS"
        out["opens_gateway_round"] = ["P-18", "P-20", "P-21", "P-25"]
        out["blocks"] = "nothing in this design (the per-packet path is unchanged by the integration, 10.1)"
    return out


# ---------------------------------------------------------------------------
# epoll_ctl decline check (5.7, 10.2 PERF-1)
# ---------------------------------------------------------------------------
def parse_strace_summary(text, syscall="epoll_ctl"):
    """Calls column of the `strace -f -c` row for a syscall; 0 when a valid summary has no such row.
    None when the text is not a summary (no '% time ... calls ... syscall' header, or no syscall row
    at all): an empty or malformed trace never establishes zero calls."""
    lines = (text or "").splitlines()
    if not any("% time" in l and "calls" in l and "syscall" in l for l in lines):
        return None
    rows, found = 0, None
    for line in lines:
        parts = line.split()
        if len(parts) < 5 or parts[-1] == "total":
            continue
        nums = [p for p in parts[:-1] if re.fullmatch(r"\d+(?:\.\d+)?", p)]
        # columns: % time, seconds, usecs/call, calls, [errors]
        if len(nums) >= 4 and len(nums) == len(parts) - 1:
            rows += 1
            if parts[-1] == syscall:
                found = int(nums[3])
    if rows == 0:
        return None
    return 0 if found is None else found


def analyze_epoll(strace_text, seconds, attached_after_startup, limit=EPOLL_FEW_CALLS):
    out = {"calls": parse_strace_summary(strace_text), "seconds": seconds, "limit": limit}
    if out["calls"] is None:
        out["verdict"] = "INVALID_RUN"
        out["note"] = "the strace output is not a -c summary with syscall rows; it cannot show zero calls"
    elif not attached_after_startup or seconds < 20:
        out["verdict"] = "INVALID_RUN"
        out["note"] = "needs strace attached after startup for a 20 s single-session download"
    else:
        out["verdict"] = "DECLINE_CONFIRMED" if out["calls"] <= limit else "REOPEN_PERF1"
    return out


# ---------------------------------------------------------------------------
# winn3gw0 queue helper across restarts and reboots (5.7 read-backs, P-5)
# ---------------------------------------------------------------------------
QUEUE_RESTARTS = 20
QUEUE_REBOOTS = 3
QUEUE_STATE_PATH = "/run/winsvpn/winn3gw-queues.state"


def queue_record_matches(rec, expect_qlen=10000):
    """One record: the helper's state names the gateway's current MainPID and winn3gw0 ifindex with
    result ok, the helper ran exactly once for this start, the root is mq or a single fq with the
    calibrated children, and the queue length is the fleet constant (or the P-17 value)."""
    st = rec.get("state") or {}
    return bool(st.get("result") == "ok" and is_num(rec.get("main_pid")) and st.get("main_pid") == rec.get("main_pid")
                and is_num(rec.get("ifindex")) and st.get("ifindex") == rec.get("ifindex")
                and rec.get("helper_runs") == 1 and rec.get("children_match") is True
                and rec.get("qlen") == expect_qlen)


def analyze_queue_restarts(records, restarts=QUEUE_RESTARTS, reboots=QUEUE_REBOOTS, expect_qlen=10000, systemd_version=None):
    """records: [{kind: restart|kill|reboot, main_pid, ifindex, state{result,main_pid,ifindex},
    helper_runs, children_match, qlen}]. Pass: 20 of 20 restarts (an automatic restart after a kill
    included) and 3 of 3 reboots match, and the installed systemd version is recorded."""
    out = {"restart_records": 0, "restart_matches": 0, "kill_records": 0, "reboot_records": 0,
           "reboot_matches": 0, "problems": [], "systemd_version": systemd_version}
    for r in records:
        ok = queue_record_matches(r, expect_qlen)
        if r.get("kind") in ("restart", "kill"):
            out["restart_records"] += 1
            out["restart_matches"] += 1 if ok else 0
            out["kill_records"] += 1 if r.get("kind") == "kill" else 0
        elif r.get("kind") == "reboot":
            out["reboot_records"] += 1
            out["reboot_matches"] += 1 if ok else 0
        else:
            out["problems"].append("unknown record kind %r" % r.get("kind"))
    if out["restart_records"] < restarts:
        out["problems"].append("%d restarts recorded, need %d" % (out["restart_records"], restarts))
    if out["kill_records"] < 1:
        out["problems"].append("no automatic restart after a kill was recorded")
    if out["reboot_records"] < reboots:
        out["problems"].append("%d reboots recorded, need %d" % (out["reboot_records"], reboots))
    if not systemd_version:
        out["problems"].append("the installed systemd version is not recorded")
    mismatched = (out["restart_records"] - out["restart_matches"]) + (out["reboot_records"] - out["reboot_matches"])
    if mismatched:
        out["problems"].append("%d records do not match" % mismatched)
    out["verdict"] = "PASS" if not out["problems"] else "FAIL"
    return out


def restart_once(runner, kind, unit="winn3-gateway.service", gw_dev="winn3gw0", helper_unit="wins-winn3gw-queues.service",
                 state_path=QUEUE_STATE_PATH, wait_s=60, clock=lambda: 0.0, sleep=lambda s: None):
    """Restart (systemctl restart) or kill (SIGKILL, so systemd restarts it on its own) the gateway,
    wait until the helper's state names the new MainPID, and return the record analyze_queue_restarts
    reads. The caller must have run this only on a canary or Tier A node that the operator named."""
    t0 = clock()
    since = int(t0) if t0 else 0
    if kind == "kill":
        runner.run(["systemctl", "kill", "-s", "KILL", unit])
    else:
        runner.run(["systemctl", "restart", unit])
    deadline = t0 + wait_s
    rec = {"kind": kind, "main_pid": None, "ifindex": None, "state": None, "helper_runs": None,
           "children_match": None, "qlen": None}
    while True:
        pid = (runner.run(["systemctl", "show", "-p", "MainPID", "--value", unit]).out or "").strip()
        link = runner.run(["ip", "-o", "link", "show", "dev", gw_dev]).out or ""
        m_idx, m_q = re.match(r"\s*(\d+):", link), re.search(r"\bqlen\s+(\d+)", link)
        st_raw = runner.run(["cat", state_path]).out
        try:
            st = json.loads(st_raw) if st_raw else None
        except ValueError:
            st = None
        rec.update({"main_pid": int(pid) if pid.isdigit() and int(pid) > 0 else None,
                    "ifindex": int(m_idx.group(1)) if m_idx else None, "state": st,
                    "qlen": int(m_q.group(1)) if m_q else None})
        if rec["main_pid"] and isinstance(st, dict) and st.get("main_pid") == rec["main_pid"]:
            break
        if clock() >= deadline:
            break
        sleep(1)
    j = runner.run(["journalctl", "-u", helper_unit, "--since", "@%d" % since, "--no-pager", "-o", "cat"]).out or ""
    rec["helper_runs"] = len([l for l in j.splitlines() if l.startswith("Started ")])
    tc = runner.run(["tc", "-j", "qdisc", "show", "dev", gw_dev]).out
    try:
        lines = parse_qdisc_json(tc)
        kids = [q for q in lines if q["where"] != "root" and q["kind"] == "fq"]
        root = [q for q in lines if q["where"] == "root"]
        rec["children_match"] = bool(root and ((root[0]["kind"] == "mq" and kids and all(
            q["opts"].get("flow_limit") == 256 and q["opts"].get("quantum") == 1280 for q in kids))
            or (root[0]["kind"] == "fq" and root[0]["opts"].get("flow_limit") == 256)))
    except ArmError:
        rec["children_match"] = None
    return rec


# ---------------------------------------------------------------------------
# Hub cost (5.7 hub cost, 10.4)
# ---------------------------------------------------------------------------
def cpu_seconds_per_hour(usage_usec_start, usage_usec_end, wall_s):
    if wall_s <= 0 or usage_usec_end < usage_usec_start:
        raise ValueError("bad cpu.stat window")
    return (usage_usec_end - usage_usec_start) / 1e6 * 3600.0 / wall_s


def analyze_hub_cost(rec):
    """rec: {units: {name: {before: {usage_usec_start, usage_usec_end, wall_s}, after: {...}}},
    inner_addresses_in_use_ms: {before: x, after: y}, slugs: 64}. P-23 is adopted only if the
    wall time still exceeds 10 ms at 64 slugs after P-15."""
    out = {"units": {}, "problems": []}
    if rec.get("slugs") != 64:
        out["problems"].append("hub-lite must hold 64 simulated slugs")
    for name, w in rec.get("units", {}).items():
        b = cpu_seconds_per_hour(w["before"]["usage_usec_start"], w["before"]["usage_usec_end"], w["before"]["wall_s"])
        a = cpu_seconds_per_hour(w["after"]["usage_usec_start"], w["after"]["usage_usec_end"], w["after"]["wall_s"])
        out["units"][name] = {"before_cpu_s_per_hour": b, "after_cpu_s_per_hour": a, "lower_after": a < b}
    ia = rec.get("inner_addresses_in_use_ms", {})
    out["inner_addresses_in_use_ms"] = ia
    out["p23_needed"] = bool(is_num(ia.get("after")) and ia["after"] > 10.0)
    if "p16_probe_cpu_fraction" in rec:
        out["p16_under_2_percent_of_one_core"] = rec["p16_probe_cpu_fraction"] < 0.02
    out["verdict"] = "INVALID_RUN" if out["problems"] else "RECORDED"
    return out


# ---------------------------------------------------------------------------
# Arm control: capture, apply, read back, revert (10.2 P-3, P-4, P-10, P-17, P-22, P-24)
# ---------------------------------------------------------------------------
class ArmError(Exception):
    pass


class RevertFailed(ArmError):
    pass


@dataclasses.dataclass
class RunResult:
    rc: int
    out: str = ""
    err: str = ""


@dataclasses.dataclass
class Target:
    wan_dev: str = "eth0"
    gw_dev: str = "winn3gw0"
    unit: str = "winn3-gateway.service"
    netns: str = ""

    def net(self, argv):
        """tc and ip run inside the namespace when one is set; sysctl and systemctl never do."""
        return (["ip", "netns", "exec", self.netns] + list(argv)) if self.netns else list(argv)


# The fq options this harness reads, changes and restores. tc prints sizes and times with units and
# rounding ("25Kb", "1ms"), which cannot be fed back, so every capture uses `tc -j`, whose integers
# are lossless: bytes for quantum, initial_quantum and maxrate (bytes per second), microseconds
# for refill_delay.
FQ_KEYS = ("limit", "flow_limit", "quantum", "initial_quantum", "refill_delay", "maxrate")
TC_SHOW = ["tc", "-j", "qdisc", "show", "dev"]


def parse_qdisc_json(text):
    """`tc -j qdisc show dev X` -> [{kind, handle, where ('root' or 'parent:<id>'), opts{FQ_KEYS}}]."""
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise ArmError("tc -j output is not JSON: %s" % exc)
    out = []
    for q in doc:
        kind = q.get("kind", "")
        opts = {k: q.get("options", {}).get(k) for k in FQ_KEYS if kind == "fq" and k in q.get("options", {})}
        where = "root" if q.get("root") else "parent:%s" % q.get("parent", "")
        out.append({"kind": kind, "handle": str(q.get("handle", "0:")).rstrip(":") or "0", "where": where, "opts": opts})
    return out


def tree_signature(lines):
    """What a revert must reproduce: kind, position and the fq options this harness touches."""
    return sorted(((q["kind"], q["where"], tuple(sorted(q["opts"].items()))) for q in lines), key=repr)


def fq_argv(opts):
    argv = []
    for k in FQ_KEYS:
        if k in opts:
            v = opts[k]
            argv += [k, "%dus" % v if k == "refill_delay" else ("%dbps" % v if k == "maxrate" else str(v))]
    return argv


def qdisc_restore_cmds(dev, lines, net):
    """Rebuild the commands that recreate a captured qdisc tree, or raise for a kind this does not know."""
    cmds = []
    for q in sorted(lines, key=lambda q: (q["where"] != "root", q["where"])):
        kind = q["kind"]
        if kind not in ("mq", "fq", "noqueue"):
            raise ArmError("cannot restore qdisc kind %r on %s from a capture; refusing to change it" % (kind, dev))
        if kind == "mq" and q["where"] == "root" and q["handle"] in ("0", ""):
            raise ArmError("%s has a default mq root (handle 0:); a rebuilt mq gets a new handle and its children "
                           "cannot be named, so the capture is not restorable; refusing to change it" % dev)
        argv = ["tc", "qdisc", "replace", "dev", dev]
        if q["where"] == "root":
            argv.append("root")
            if kind == "mq":
                argv += ["handle", q["handle"] + ":"]   # children name this handle as their parent
        else:
            argv += ["parent", q["where"][len("parent:"):]]
        argv.append(kind)
        if kind == "fq":
            argv += fq_argv(q["opts"])
        cmds.append(net(argv))
    return cmds


class Knob:
    """One kind of arm. capture/apply/check/revert never touch the host themselves; they return
    argv lists or read through the supplied read(argv) -> text callable."""
    kind = ""

    def capture(self, t, read):
        raise NotImplementedError

    def apply(self, t, arm, state):
        raise NotImplementedError

    def check(self, t, arm, state, read):
        raise NotImplementedError

    def revert(self, t, state):
        raise NotImplementedError

    def check_reverted(self, t, state, read):
        raise NotImplementedError

    def verify_sh(self, t, state):
        """sh conditions (each exits 0 when restored) the dead-man script checks before it removes the marker."""
        raise NotImplementedError


class FqFlowLimit(Knob):
    kind = "fq_flow_limit"
    key = "wan"
    field = "flow_limit"
    param = "flow_limit"

    def _dev(self, t):
        return t.wan_dev

    def capture(self, t, read):
        text = read(t.net(TC_SHOW + [self._dev(t)]))
        lines = parse_qdisc_json(text)
        root = [q for q in lines if q["where"] == "root"]
        if len(root) != 1 or root[0]["kind"] != "fq":
            raise ArmError("%s: the root qdisc of %s is not a single fq; refusing" % (self.kind, self._dev(t)))
        qdisc_restore_cmds(self._dev(t), lines, t.net)  # proves it can be restored
        require_dead_man_comparable(self._dev(t), text)
        return {"dev": self._dev(t), "tc": text}

    def apply(self, t, arm, state):
        root = [q for q in parse_qdisc_json(state["tc"]) if q["where"] == "root"][0]
        o = dict(root["opts"])
        o[self.field] = int(arm.p[self.param])
        return [t.net(["tc", "qdisc", "replace", "dev", state["dev"], "root", "fq"] + fq_argv(o))]

    def check(self, t, arm, state, read):
        text = read(t.net(TC_SHOW + [state["dev"]]))
        root = [q for q in parse_qdisc_json(text) if q["where"] == "root"]
        if len(root) != 1 or root[0]["kind"] != "fq":
            return ["root qdisc is no longer a single fq"]
        want = int(arm.p[self.param])
        got = root[0]["opts"].get(self.field)
        out = []
        if got != want:
            out.append("%s reads %s, wanted %s" % (self.field, got, want))
        orig = [q for q in parse_qdisc_json(state["tc"]) if q["where"] == "root"][0]["opts"]
        for k, v in orig.items():
            if k != self.field and root[0]["opts"].get(k) != v:
                out.append("%s changed from %s to %s" % (k, v, root[0]["opts"].get(k)))
        return out

    def revert(self, t, state):
        return qdisc_restore_cmds(state["dev"], parse_qdisc_json(state["tc"]), t.net)

    def check_reverted(self, t, state, read):
        a = tree_signature(parse_qdisc_json(read(t.net(TC_SHOW + [state["dev"]]))))
        b = tree_signature(parse_qdisc_json(state["tc"]))
        return [] if a == b else ["qdisc tree differs from the capture: %r != %r" % (a, b)]

    def verify_sh(self, t, state):
        return [_captured_qdisc_sh(t, state)]


class FqQuantum(FqFlowLimit):
    kind = "fq_quantum"
    field = "quantum"
    param = "quantum"


class TunQlen(Knob):
    kind = "tun_qlen"

    def capture(self, t, read):
        text = read(t.net(["ip", "-o", "link", "show", "dev", t.gw_dev]))
        m = re.search(r"\bqlen\s+(\d+)", text)
        if not m:
            raise ArmError("cannot read txqueuelen of %s" % t.gw_dev)
        return {"dev": t.gw_dev, "qlen": int(m.group(1))}

    def apply(self, t, arm, state):
        return [t.net(["ip", "link", "set", "dev", state["dev"], "txqueuelen", str(arm.p["qlen"])])]

    def check(self, t, arm, state, read):
        m = re.search(r"\bqlen\s+(\d+)", read(t.net(["ip", "-o", "link", "show", "dev", state["dev"]])))
        got = int(m.group(1)) if m else None
        return [] if got == arm.p["qlen"] else ["txqueuelen reads %s, wanted %s" % (got, arm.p["qlen"])]

    def revert(self, t, state):
        return [t.net(["ip", "link", "set", "dev", state["dev"], "txqueuelen", str(state["qlen"])])]

    def check_reverted(self, t, state, read):
        m = re.search(r"\bqlen\s+(\d+)", read(t.net(["ip", "-o", "link", "show", "dev", state["dev"]])))
        got = int(m.group(1)) if m else None
        return [] if got == state["qlen"] else ["txqueuelen reads %s, wanted %s" % (got, state["qlen"])]

    def verify_sh(self, t, state):
        return [_qlen_sh(t, state["dev"], state["qlen"])]


class TunNoqueue(Knob):
    kind = "tun_noqueue"

    def capture(self, t, read):
        text = read(t.net(TC_SHOW + [t.gw_dev]))
        lines = parse_qdisc_json(text)
        qdisc_restore_cmds(t.gw_dev, lines, t.net)
        require_dead_man_comparable(t.gw_dev, text)
        link = read(t.net(["ip", "-o", "link", "show", "dev", t.gw_dev]))
        m = re.search(r"\bqlen\s+(\d+)", link)
        return {"dev": t.gw_dev, "tc": text, "qlen": int(m.group(1)) if m else None}

    def apply(self, t, arm, state):
        return [t.net(["tc", "qdisc", "replace", "dev", state["dev"], "root", "noqueue"])]

    def check(self, t, arm, state, read):
        roots = [q for q in parse_qdisc_json(read(t.net(TC_SHOW + [state["dev"]]))) if q["where"] == "root"]
        out = [] if len(roots) == 1 and roots[0]["kind"] == "noqueue" else ["root qdisc is not noqueue"]
        m = re.search(r"\bqlen\s+(\d+)", read(t.net(["ip", "-o", "link", "show", "dev", state["dev"]])))
        if state.get("qlen") is not None and (not m or int(m.group(1)) != state["qlen"]):
            out.append("txqueuelen changed while switching to noqueue (P-24 keeps the P-17 value)")
        return out

    def revert(self, t, state):
        # Delete the root first so a stale noqueue cannot shadow the rebuilt tree; children follow the root.
        cmds = [t.net(["tc", "qdisc", "del", "dev", state["dev"], "root"])]
        cmds += qdisc_restore_cmds(state["dev"], parse_qdisc_json(state["tc"]), t.net)
        if state.get("qlen") is not None:
            cmds.append(t.net(["ip", "link", "set", "dev", state["dev"], "txqueuelen", str(state["qlen"])]))
        return cmds

    def check_reverted(self, t, state, read):
        a = tree_signature(parse_qdisc_json(read(t.net(TC_SHOW + [state["dev"]]))))
        b = tree_signature(parse_qdisc_json(state["tc"]))
        out = [] if a == b else ["qdisc tree differs from the capture"]
        if state.get("qlen") is not None:
            m = re.search(r"\bqlen\s+(\d+)", read(t.net(["ip", "-o", "link", "show", "dev", state["dev"]])))
            got = int(m.group(1)) if m else None
            if got != state["qlen"]:
                out.append("txqueuelen reads %s, wanted %s" % (got, state["qlen"]))
        return out

    def verify_sh(self, t, state):
        out = [_captured_qdisc_sh(t, state)]
        if state.get("qlen") is not None:
            out.append(_qlen_sh(t, state["dev"], state["qlen"]))
        return out


# The `tc -j` fields the kernel assigns on a rebuild (key, value pattern valid in sed BRE and in Python re).
# They are never part of the dead-man's proof; everything else in the output is.
QDISC_IGNORED = (("handle", '"[^"]*"'), ("refcnt", "[0-9]*"))
# qdisc_normal in POSIX sh, for the dead-man script: tr, sed and sort only (coreutils and sed, which
# every Debian and Ubuntu system carries; the installers already run all three on the nodes). The C
# locale makes tr's [:space:] the six ASCII blanks and sort a byte order, as in qdisc_normal.
QDISC_NORMAL_SH = ("LC_ALL=C tr -d '[:space:]' | LC_ALL=C sed -e 's/^\\[//' -e 's/]$//' -e 's/},{/}\\\n{/g'"
                   + "".join(" -e 's/,\"%s\":%s//g'" % kv for kv in QDISC_IGNORED) + " | LC_ALL=C sort")


def qdisc_normal(text):
    """`tc -j qdisc show` output as one sorted line per qdisc, with whitespace, the outer brackets and
    the QDISC_IGNORED fields removed: the same text transform QDISC_NORMAL_SH applies on the node. A
    rebuilt tree (P-24's revert deletes the root and recreates it) gets fresh handles and may be dumped
    in another order; its kind, position (root or parent) and every option must still equal the
    capture, and no qdisc may be missing, extra or duplicated."""
    text = re.sub(r"[ \t\n\v\f\r]", "", text)
    text = re.sub(r"^\[", "", text)
    text = re.sub(r"\]$", "", text)
    text = text.replace("},{", "}\n{")
    for key, value in QDISC_IGNORED:
        text = re.sub(',"%s":%s' % (key, value), "", text)
    return "\n".join(sorted(text.split("\n")))


def require_dead_man_comparable(dev, text):
    """Refuse, before anything changes, a capture the text transform would not split into exactly its
    qdiscs (each line one whole qdisc object, minus the ignored fields and nothing else). On such a
    capture the dead-man could never prove its own revert, or its line split could pair fragments of
    different qdiscs; the transform is sound only on the shape this checks."""
    try:
        doc = json.loads(text)
        got = sorted(json.dumps(json.loads(line), sort_keys=True) for line in qdisc_normal(text).split("\n"))
        want = sorted(json.dumps({k: v for k, v in q.items() if k not in dict(QDISC_IGNORED)}, sort_keys=True)
                      for q in doc)
    except (ValueError, TypeError, AttributeError):
        got, want = None, []
    if not want or got != want:
        raise ArmError("the qdisc tree of %s cannot be compared by the dead-man script (its text does not split "
                       "into exactly its qdiscs); refusing to change it" % dev)


def _captured_qdisc_sh(t, state):
    """Before the dead-man removes the marker, the read-back must hold the captured tree: every qdisc
    with its kind, position and options, none missing, none extra (one field, or the root kind alone,
    would accept a tree whose other options or children were never restored). Handles and refcounts are
    what the kernel assigns on a rebuild, and `tc -j` lists qdiscs in hash order, which follows the
    handles; so both are ignored, as check_reverted ignores them. Compared byte for byte (Turn 3), a
    P-24 revert, which always rebuilds the children with fresh handles, could never clear its own marker.
    The first `&&` keeps a failed `tc` fail-closed (the pipeline's own status would be sort's)."""
    show = shlex.join(t.net(TC_SHOW + [state["dev"]]))
    expected = shlex.quote(qdisc_normal(state["tc"]))
    return ('perf_qdisc=$(%s) && perf_qdisc=$(printf %%s "$perf_qdisc" | %s) && [ "$perf_qdisc" = %s ]'
            % (show, QDISC_NORMAL_SH, expected))


def _qlen_sh(t, dev, qlen):
    return "%s | grep -Eq %s" % (shlex.join(t.net(["ip", "-o", "link", "show", "dev", dev])),
                                 shlex.quote(" qlen %d([^0-9]|$)" % qlen))


class BusyPoll(Knob):
    kind = "busy_poll"
    keys = ("net.core.busy_poll", "net.core.busy_read")

    def capture(self, t, read):
        return {k: int(read(["sysctl", "-n", k]).strip()) for k in self.keys}

    def apply(self, t, arm, state):
        return [["sysctl", "-w", "net.core.busy_poll=%d" % arm.p["busy_poll"], "net.core.busy_read=%d" % arm.p["busy_read"]]]

    def check(self, t, arm, state, read):
        out = []
        for k, want in (("net.core.busy_poll", arm.p["busy_poll"]), ("net.core.busy_read", arm.p["busy_read"])):
            got = int(read(["sysctl", "-n", k]).strip())
            if got != want:
                out.append("%s reads %d, wanted %d" % (k, got, want))
        return out

    def revert(self, t, state):
        return [["sysctl", "-w"] + ["%s=%d" % (k, state[k]) for k in self.keys]]

    def check_reverted(self, t, state, read):
        return ["%s reads %s, wanted %d" % (k, read(["sysctl", "-n", k]).strip(), state[k])
                for k in self.keys if int(read(["sysctl", "-n", k]).strip()) != state[k]]

    def verify_sh(self, t, state):
        return ['[ "$(sysctl -n %s)" = %s ]' % (k, shlex.quote(str(state[k]))) for k in self.keys]


class CgroupWeights(Knob):
    kind = "cgroup_weights"

    def _show(self, t, read):
        text = read(["systemctl", "show", t.unit, "-p", "LoadState", "-p", "CPUWeight", "-p", "IOWeight"])
        return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)

    def capture(self, t, read):
        s = self._show(t, read)
        if s.get("LoadState", "").strip() != "loaded":
            raise ArmError("unit %s is not loaded (LoadState %r); refusing" % (t.unit, s.get("LoadState")))
        if "CPUWeight" not in s or "IOWeight" not in s:
            raise ArmError("cannot read CPUWeight and IOWeight of %s" % t.unit)
        return {"unit": t.unit, "CPUWeight": s["CPUWeight"].strip(), "IOWeight": s["IOWeight"].strip()}

    @staticmethod
    def _setting(value):
        return "" if value in ("[not set]", "", "infinity") else value

    def apply(self, t, arm, state):
        return [["systemctl", "set-property", "--runtime", state["unit"],
                 "CPUWeight=%d" % arm.p["cpu_weight"], "IOWeight=%d" % arm.p["io_weight"]]]

    def check(self, t, arm, state, read):
        s = self._show(t, read)
        out = []
        for k, want in (("CPUWeight", arm.p["cpu_weight"]), ("IOWeight", arm.p["io_weight"])):
            if s.get(k, "").strip() != str(want):
                out.append("%s reads %s, wanted %s" % (k, s.get(k), want))
        return out

    def revert(self, t, state):
        return [["systemctl", "set-property", "--runtime", state["unit"],
                 "CPUWeight=" + self._setting(state["CPUWeight"]), "IOWeight=" + self._setting(state["IOWeight"])]]

    def check_reverted(self, t, state, read):
        s = self._show(t, read)
        return ["%s reads %s, wanted %s" % (k, s.get(k), state[k]) for k in ("CPUWeight", "IOWeight")
                if s.get(k, "").strip() != state[k]]

    def verify_sh(self, t, state):
        return ['[ "$(systemctl show %s -p %s --value)" = %s ]' % (shlex.quote(state["unit"]), k, shlex.quote(state[k]))
                for k in ("CPUWeight", "IOWeight")]


KNOBS = {k.kind: k for k in (FqFlowLimit(), FqQuantum(), TunQlen(), TunNoqueue(), BusyPoll(), CgroupWeights())}


def knob_for(arm):
    if arm.kind == "binary":
        raise ArmError("a binary arm needs its own gateway round; this harness does not swap binaries")
    if arm.kind not in KNOBS:
        raise ArmError("no knob for arm kind %r" % arm.kind)
    return KNOBS[arm.kind]


TRIAL_STATE_DIR = "/var/lib/winsvpn/perf-trial"
TRIAL_ENV = "/etc/winsvpn/perf-trial.env"


def revert_script(trial_id, plan_cmds, marker_path=TRIAL_ENV, checks=()):
    """The dead-man script. Plain sh, no Python or jq on the node (aicore, where P-24 runs, is not
    provisioned by the installers); the qdisc read-back uses tr, sed and sort only. Every revert command is attempted even if
    an earlier one fails, but each failure is remembered; then every read-back check runs. The marker
    is removed only when every command and every check succeeded; otherwise it stays (the drift stays
    visible) and the script exits 1, so the unit is left failed."""
    lines = ["#!/bin/sh", "# winn3 perf bench revert for trial %s; safe to run more than once" % trial_id, "set +e", "fail=0"]
    for argv in plan_cmds:
        lines.append(shlex.join(argv) + " || fail=1")
    for cond in checks:
        lines.append(cond + " || fail=1")
    lines.append('if [ "$fail" -eq 0 ]; then %s || fail=1; fi' % shlex.join(["rm", "-f", marker_path]))
    lines.append('if [ "$fail" -ne 0 ]; then echo %s >&2; fi'
                 % shlex.quote("winn3 perf bench revert for trial %s: not proven; %s kept" % (trial_id, marker_path)))
    lines.append('exit "$fail"')
    return "\n".join(lines) + "\n"


def _env_value(v):
    return re.sub(r"[^A-Za-z0-9_.:/=,+-]", "_", str(v))


def marker_text(trial_id, arm_name, started, values=None):
    """The harness file 10.2 P-4 (i) names. It names the arm applied now and its values, so the drift
    flag reports exactly what is live while the file exists."""
    vals = ",".join("%s=%s" % (k, _env_value(v)) for k, v in sorted((values or {}).items()))
    return ("# winn3 perf bench trial in progress; the node-perf readback reports this file as drift.\n"
            "# Arm values are applied live and do not survive a reboot. Remove this file only through revert.\n"
            "WINS_PERF_TRIAL=%s/%s\nWINS_PERF_TRIAL_VALUES=%s\nWINS_PERF_TRIAL_STARTED=%s\n"
            % (trial_id, arm_name, vals or "captured", started))


class ArmController:
    """Applies trial arms to one node through a runner. A revert plan and a dead-man script are
    written before the first change; the node is returned to the captured state at the end and
    the read-back must match, otherwise RevertFailed is raised with the residual state, and the
    marker file and the dead-man timer are left in place."""

    def __init__(self, runner, target, trial, state_dir=TRIAL_STATE_DIR, marker_path=TRIAL_ENV,
                 dead_man_minutes=0, clock=utc_now, unit_prefix="winn3-perf-revert"):
        self.runner, self.t, self.trial = runner, target, trial
        self.state_dir, self.marker = state_dir, marker_path
        self.dead_man_minutes = dead_man_minutes
        self.clock = clock
        self.states = {}      # knob kind -> captured state
        self.current = None   # None: the captured original; else the arm name applied last
        self.began = False
        self.dead_man_unit = None
        self._dm_base, self._dm_seq = None, 0
        self.unit_prefix = unit_prefix
        self.dead_man_units = []   # timers whose stop is not yet confirmed
        self.started_at = None
        self.plan_path = self.script_path = None
        self.log = []

    def _read(self, argv):
        r = self.runner.run(argv)
        if r.rc != 0:
            raise ArmError("read failed (rc %d): %s: %s" % (r.rc, shlex.join(argv), r.err.strip()[:200]))
        return r.out

    def _do(self, argv, stdin=None):
        r = self.runner.run(argv, stdin=stdin)
        self.log.append((list(argv), r.rc))
        if r.rc != 0:
            raise ArmError("command failed (rc %d): %s: %s" % (r.rc, shlex.join(argv), r.err.strip()[:200]))
        return r

    def kinds(self):
        arms = (self.trial.base,) + tuple(self.trial.arms)
        return sorted({a.kind for a in arms if a.kind != "base"})

    def revert_plan(self):
        return [c for kind in reversed(self.kinds()) for c in KNOBS[kind].revert(self.t, self.states[kind])]

    def revert_checks(self):
        return [c for kind in reversed(self.kinds()) for c in KNOBS[kind].verify_sh(self.t, self.states[kind])]

    def _write_marker(self, arm):
        self._do(["tee", self.marker], stdin=marker_text(self.trial.id, arm.name, self.started_at,
                                                         None if arm.kind == "base" else arm.p))

    def begin(self):
        if self.began:
            raise ArmError("begin called twice")
        r = self.runner.run(["test", "-e", self.marker])
        if r.rc == 0:
            raise ArmError("%s already exists: another trial is in progress or an earlier revert is not proven; "
                           "refusing to start" % self.marker)
        if r.rc != 1:
            raise ArmError("cannot check for %s (rc %d); refusing to start" % (self.marker, r.rc))
        for kind in self.kinds():
            self.states[kind] = KNOBS[kind].capture(self.t, self._read)  # raises before anything changes
        plan = self.revert_plan()
        sid = "%s-%s" % (self.trial.id, re.sub(r"\W", "", self.clock()))
        self.plan_path = os.path.join(self.state_dir, "revert-%s.json" % sid)
        self.script_path = os.path.join(self.state_dir, "revert-%s.sh" % sid)
        self._do(["install", "-d", "-m", "0700", self.state_dir])
        self._do(["tee", self.plan_path], stdin=json.dumps({"trial": self.trial.id, "states": self.states, "plan": plan}, sort_keys=True))
        self._do(["tee", self.script_path], stdin=revert_script(self.trial.id, plan, self.marker, self.revert_checks()))
        self._do(["chmod", "0700", self.script_path])
        if self.dead_man_minutes:
            self._dm_base = "%s-%s" % (self.unit_prefix, re.sub(r"\W", "", sid).lower())
            self._rearm_dead_man()
        try:
            self._do(["install", "-d", "-m", "0755", os.path.dirname(self.marker)])
            self.started_at = self.clock()
            self._do(["tee", self.marker], stdin=marker_text(self.trial.id, "base", self.started_at))
        except ArmError:
            # nothing has been changed yet: do not leave a timer behind for a trial that never started
            if self.dead_man_unit:
                self.runner.run(["systemctl", "stop", self.dead_man_unit + ".timer"])
            raise
        self.began = True
        return plan

    def switch(self, arm_name):
        """Put the node in the named arm and prove it by reading it back. base_a and base_b are the
        trial's base arm; a base arm of kind 'base' means the captured original."""
        if not self.began:
            raise ArmError("begin first")
        arms = {a.name: a for a in (self.trial.base,) + tuple(self.trial.arms)}
        if arm_name in ("base_a", "base_b"):
            arm_name = self.trial.base.name
        if arm_name == self.current:
            return
        arm = arms[arm_name]
        try:
            self._assert_guarded()
            if self.dead_man_unit:
                self._rearm_dead_man()
            self._write_marker(arm)
            if arm.kind == "base":
                self._revert_all()
            else:
                knob = knob_for(arm)
                for cmd in knob.apply(self.t, arm, self.states[arm.kind]):
                    self._do(cmd)
                bad = knob.check(self.t, arm, self.states[arm.kind], self._read)
                if bad:
                    raise ArmError("read-back after applying %s failed: %s" % (arm.name, "; ".join(bad)))
        except ArmError:
            self.finish()
            raise
        self.current = arm.name

    def _rearm_dead_man(self):
        """Keep every unresolved timer until both its timer and service stop."""
        self._dm_seq += 1
        unit = "%s-%d" % (self._dm_base, self._dm_seq)
        self._do(["systemd-run", "--unit", unit,
                  "--on-active=%dm" % self.dead_man_minutes,
                  "/bin/sh", self.script_path])
        self.dead_man_units.append(unit)
        old, self.dead_man_unit = self.dead_man_unit, unit
        if old:
            r = self.runner.run(["systemctl", "stop",
                                 old + ".timer", old + ".service"])
            if r.rc != 0:
                raise ArmError("could not stop the previous dead-man %s (rc %d)"
                               % (old, r.rc))
            self.dead_man_units.remove(old)

    def _assert_guarded(self):
        """Before every change: the dead-man timer is still pending and the marker still exists. A timer
        that has fired has already reverted the node and removed the marker; changing the node after
        that would leave a live arm with no marker and no dead-man."""
        if self.dead_man_unit and self.runner.run(["systemctl", "is-active", "--quiet", self.dead_man_unit + ".timer"]).rc != 0:
            raise ArmError("dead-man timer %s is no longer pending; stopping the trial" % self.dead_man_unit)
        if self.runner.run(["test", "-f", self.marker]).rc != 0:
            raise ArmError("trial marker %s is gone; stopping the trial" % self.marker)

    def assert_guarded(self):
        """Public form of the guard, for the caller to run after each measurement: a dead-man that fired
        during a run has reverted the node, so that run did not measure the arm it is labelled with."""
        self._assert_guarded()

    def _revert_all(self):
        failures = []
        for cmd in self.revert_plan():
            r = self.runner.run(cmd)
            self.log.append((list(cmd), r.rc))
            if r.rc != 0:
                failures.append("%s: rc %d %s" % (shlex.join(cmd), r.rc, r.err.strip()[:120]))
        for kind in self.kinds():
            failures += KNOBS[kind].check_reverted(self.t, self.states[kind], self._read)
        if failures:
            raise RevertFailed("; ".join(failures))
        self.current = None

    def finish(self):
        """Clear the marker only after restore and all reverter stops succeed."""
        if not self.began:
            return
        self._revert_all()
        failures = []
        for unit in list(self.dead_man_units):
            r = self.runner.run(["systemctl", "stop",
                                 unit + ".timer", unit + ".service"])
            if r.rc != 0:
                failures.append("%s: rc %d" % (unit, r.rc))
            else:
                self.dead_man_units.remove(unit)
        if failures:
            raise ArmError("dead-man stop not proven; marker kept: "
                           + "; ".join(failures))
        self.dead_man_unit = None
        # A reverter stopped mid-script may have left a half revert: prove again, and revert again only
        # when something is left over (a second P-24 revert is one more reset of the tun queues).
        residual = []
        for kind in self.kinds():
            residual += KNOBS[kind].check_reverted(self.t, self.states[kind], self._read)
        if residual:
            self._revert_all()
        r = self.runner.run(["rm", "-f", self.marker])
        if r.rc != 0 or self.runner.run(["test", "-e", self.marker]).rc != 1:
            raise ArmError("reverted, but %s could not be removed (rc %d)"
                           % (self.marker, r.rc))
        self.began = False


def revert_from_plan(runner, target, plan_doc, marker_path=TRIAL_ENV):
    """Run a stored revert plan (the JSON begin() wrote) and prove the node matches its captured
    state. Returns the list of residual differences; the marker is removed only when it is empty."""
    failures = []
    for cmd in plan_doc["plan"]:
        r = runner.run(cmd)
        if r.rc != 0:
            failures.append("%s: rc %d %s" % (shlex.join(cmd), r.rc, r.err.strip()[:120]))

    def read(argv):
        r = runner.run(argv)
        if r.rc != 0:
            raise ArmError("read failed: %s" % shlex.join(argv))
        return r.out
    for kind, state in plan_doc["states"].items():
        failures += KNOBS[kind].check_reverted(target, state, read)
    if not failures:
        runner.run(["rm", "-f", marker_path])
    return failures


# ---------------------------------------------------------------------------
# Runners
# ---------------------------------------------------------------------------
class LocalRunner:
    def __init__(self, sudo=False):
        self.sudo = sudo

    def run(self, argv, stdin=None, timeout=120):
        argv = (["sudo", "-n"] if self.sudo else []) + list(argv)
        try:
            p = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError as exc:
            return RunResult(127, "", str(exc))
        except subprocess.TimeoutExpired:
            return RunResult(124, "", "timeout")
        return RunResult(p.returncode, p.stdout, p.stderr)


class ColimaRunner:
    """Runs argv as root inside one named local Colima VM. This class never starts or stops a VM."""

    def __init__(self, profile, colima="colima"):
        self.profile, self.colima = profile, colima

    def command(self, argv):
        # limactl keeps each argument as one word on the remote side, so argv goes through as is.
        return [self.colima, "ssh", "-p", self.profile, "--", "sudo", "-n"] + list(argv)

    def run(self, argv, stdin=None, timeout=300):
        try:
            p = subprocess.run(self.command(argv), input=stdin, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError as exc:
            return RunResult(127, "", str(exc))
        except subprocess.TimeoutExpired:
            return RunResult(124, "", "timeout")
        return RunResult(p.returncode, p.stdout, p.stderr)


class SshRunner:
    """Remote node runner, for the canary trials. It refuses to build a command for a host that is
    not in the operator's allow list. Nothing in this harness or its tests runs it against a host."""

    def __init__(self, host, allow, ssh_options=("-o", "BatchMode=yes")):
        if host not in allow:
            raise ArmError("host %r is not in the allow list" % host)
        self.host, self.opts = host, tuple(ssh_options)

    def command(self, argv):
        return ["ssh"] + list(self.opts) + [self.host, "--", shlex.join(argv)]

    def run(self, argv, stdin=None, timeout=300):
        try:
            p = subprocess.run(self.command(argv), input=stdin, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return RunResult(124, "", "timeout")
        return RunResult(p.returncode, p.stdout, p.stderr)


# ---------------------------------------------------------------------------
# Canonical aicore bench lock (aicore_bench_lock_canonical_20260929)
# ---------------------------------------------------------------------------
class BenchLock:
    """A DIRECTORY created with mkdir (atomic, fails if it exists) holding an 'owner' file. It is
    released only by its owner, and only after teardown and host-state verification. A flock on a
    plain file at the same path is not compatible and is never used."""

    def __init__(self, runner, owner, path="/home/aicore/.bench.lock", clock=utc_now):
        self.runner, self.owner, self.path, self.clock = runner, owner, path, clock

    def acquire(self, pid):
        r = self.runner.run(["mkdir", self.path])
        if r.rc != 0:
            raise ArmError("bench lock %s is held or unavailable: %s" % (self.path, r.err.strip()[:120]))
        r = self.runner.run(["tee", self.path + "/owner"], stdin="%s %s %s\n" % (self.owner, self.clock(), pid))
        if r.rc != 0:
            self.runner.run(["rmdir", self.path])
            raise ArmError("could not write the lock owner file")

    def release(self, host_state_verified):
        if not host_state_verified:
            raise ArmError("refusing to release the bench lock before teardown and host-state verification")
        r = self.runner.run(["cat", self.path + "/owner"])
        if r.rc != 0 or r.out.split()[:1] != [self.owner]:
            raise ArmError("bench lock is not owned by %s; not releasing it" % self.owner)
        r = self.runner.run(["rm", "-rf", self.path])
        if r.rc != 0:
            raise ArmError("bench lock removal failed")


# ---------------------------------------------------------------------------
# Measurement backends
# ---------------------------------------------------------------------------
RUN_KEYS = ("started", "alive", "idle_p50_ms", "ld_p50_ms", "ld_p99_ms", "ld_jitter_ms", "ld_loss_pct", "thr_mbps")


def validate_run_record(rec):
    """Reasons a measurement record cannot be used (empty list when fine)."""
    bad = []
    for k in RUN_KEYS:
        if k not in rec:
            bad.append("missing %s" % k)
    for k in ("idle_p50_ms", "ld_p50_ms", "ld_p99_ms", "ld_jitter_ms", "ld_loss_pct", "thr_mbps"):
        if k in rec and rec[k] is not None and not is_num(rec[k]):
            bad.append("%s is not a number" % k)
    return bad


L63_LABEL = re.compile(r"^([A-Za-z0-9]+)_([A-Za-z0-9]+)_(a|b)_(tcp\d+|udp\d*)_(up|down)_r(\d+)$")


def record_from_l63(o, trial, arm_map, stage_map, venue):
    """One line of the aicore rig's runs_*.jsonl (lane L63 point script, analysed by l53_analyze.py)
    as a run record. Labels read <stage>_<arm>_<profile>_<test>_<dir>_r<rep>. Returns None for a label
    this mapping does not name, so a stray line is never guessed at."""
    m = L63_LABEL.match(o.get("rundir", ""))
    if not m or m.group(2) not in arm_map or m.group(1) not in stage_map:
        return None
    stage, arm, profile, test, direction, rep = m.groups()
    meta = o.get("meta", "")
    started = "carriage=1" in meta and "NO CARRIAGE" not in meta
    alive = started and str(o.get("client_alive")) == "1" and (o.get("post_rx") or 0) >= 100
    udp = test.startswith("udp")
    thr = o.get("%s_mbps" % direction) if udp else o.get("rx_mbps")
    # the whole failure line, whitespace collapsed: a cut prefix would merge distinct classes (10.0 item 1)
    fail = " ".join(str(o.get("cl_fail") or o.get("gw_fail") or "").split())
    return {"trial": trial, "stage": stage_map[stage], "arm": arm_map[arm], "role": role_of(arm_map[arm]), "rep": int(rep),
            "profile": profile, "test": "udp" if udp else test, "dir": direction, "started": bool(started), "alive": bool(alive),
            "idle_p50_ms": o.get("idle_p50"), "ld_p50_ms": o.get("ld_p50_ms"), "ld_p99_ms": o.get("ld_p99_ms"),
            "ld_jitter_ms": o.get("ld_jitter_ms"), "ld_loss_pct": o.get("ld_loss_pct"), "thr_mbps": thr,
            "sessions_started": 1 if started else 0, "sessions_failed": 0 if started else 1,
            "failure_class": None if alive else (fail or ("no_carriage" if not started else "died")),
            "retrans": o.get("retr"), "tx_drops": o.get("gw_tun_txdrop"), "inbox_drops": o.get("gw_inbox_drop"),
            "rcvbuf_errors": o.get("gw_rcvbuf"), "gw_cpu_cores": o.get("gw_cpu"), "venue": venue,
            "gw_cpus_observed": o.get("gw_cpus_observed")}


class DryRunBackend:
    """Synthetic runs from a scenario. No process is started and no host is contacted."""
    SCENARIOS = {
        # name: {arm: {metric: delta}}; noise is the seeded jitter below.
        "neutral": {},
        "latency_win": {"*cand*": {"ld_p50_ms": -45.0, "ld_p99_ms": -40.0}},
        "latency_win_loses_throughput": {"*cand*": {"ld_p50_ms": -45.0, "thr_mbps": -80.0}},
        "latency_win_raises_jitter": {"*cand*": {"ld_p50_ms": -45.0, "ld_jitter_ms": 6.0}},
        "throughput_win_over_bar": {"*cand*": {"thr_mbps": 90.0}},
        "throughput_win_and_latency_win": {"*cand*": {"thr_mbps": 90.0, "ld_p50_ms": -30.0}},
        "all_worse": {"*cand*": {"ld_p50_ms": 40.0, "ld_p99_ms": 50.0}},
    }
    BASE = {"a": dict(idle=70.0, rise=120.0, thr=800.0), "b": dict(idle=85.0, rise=127.0, thr=85.0)}

    def __init__(self, scenario="neutral", seed=1, venue="dry_run"):
        if scenario not in self.SCENARIOS:
            raise ArmError("unknown scenario %r" % scenario)
        self.scenario, self.seed, self.venue = scenario, seed, venue

    def measure(self, ctx):
        rng = random.Random("%s/%s/%s/%s/%s/%s/%s/%s" % (self.seed, ctx["trial"], ctx["stage"], ctx["arm"], ctx["profile"], ctx["test"], ctx["dir"], ctx["rep"]))
        b = self.BASE[ctx["profile"]]
        deltas = {}
        if role_of(ctx["arm"]) == "cand":
            deltas = self.SCENARIOS[self.scenario].get("*cand*", {})
        g = lambda s: rng.gauss(0.0, s)
        idle = b["idle"] + g(0.3)
        p50 = idle + b["rise"] + deltas.get("ld_p50_ms", 0.0) + g(2.0)
        rec = {"started": True, "alive": True, "idle_p50_ms": round(idle, 3), "ld_p50_ms": round(p50, 3),
               "ld_p99_ms": round(p50 + 24.0 + deltas.get("ld_p99_ms", deltas.get("ld_p50_ms", 0.0)) + g(3.0), 3),
               "ld_jitter_ms": round(max(0.1, 4.0 + deltas.get("ld_jitter_ms", 0.0) + g(0.3)), 3),
               "ld_loss_pct": round(max(0.0, 0.2 + deltas.get("ld_loss_pct", 0.0) + g(0.05)), 3),
               "thr_mbps": round(b["thr"] + deltas.get("thr_mbps", 0.0) + g(6.0), 3),
               "sessions_started": 1, "sessions_failed": 0, "failure_class": None,
               "awg_mbps": round(300.0 + deltas.get("awg_mbps", 0.0) + g(3.0), 3),
               "xray_mbps": round(250.0 + deltas.get("xray_mbps", 0.0) + g(3.0), 3),
               "awg_ld_p99_ms": round(60.0 + deltas.get("awg_ld_p99_ms", 0.0) + g(1.0), 3),
               "xray_ld_p99_ms": round(70.0 + deltas.get("xray_ld_p99_ms", 0.0) + g(1.0), 3),
               "cpu_total_pct": round(40.0 + deltas.get("cpu_total_pct", 0.0) + g(0.8), 3),
               "venue": self.venue}
        if ctx.get("gw_cpus"):
            rec["gw_cpus_observed"] = ctx["gw_cpus"][0]     # synthetic; a dry run is never adoptable anyway
        trial = TRIALS.get(ctx["trial"])
        if trial and trial.background:
            rec["background"] = {n: round(30.0 + g(2.0), 2) for n in trial.background}
        return rec


class CommandBackend:
    """One operator-supplied command per run. The template is split with shlex and each field is
    substituted into the resulting argv (never through a shell). It must print one JSON object
    with the run record keys as its last stdout line. Placeholders: {trial} {stage} {arm} {rep}
    {profile} {test} {dir} {gw_cpus} {secs}."""

    def __init__(self, template, runner=None, secs=20, timeout=300, venue="functional"):
        self.template, self.runner, self.secs, self.timeout, self.venue = template, runner or LocalRunner(), secs, timeout, venue
        self.last_raw = None    # (argv, rc, stdout, stderr) of the last measurement, for the evidence

    def argv(self, ctx):
        fields = dict(ctx)
        fields["secs"] = self.secs
        fields["gw_cpus"] = ",".join(map(str, ctx.get("gw_cpus", ()))) or "natural"
        # only the named placeholders are replaced, so a literal brace in the command is left alone
        return [re.sub(r"\{(trial|stage|arm|rep|profile|test|dir|gw_cpus|secs)\}", lambda m: str(fields[m.group(1)]), part)
                for part in shlex.split(self.template)]

    def _failed(self, cls):
        return {"started": False, "alive": False, "failure_class": cls, "sessions_started": 0,
                "sessions_failed": 1, "venue": self.venue}

    def measure(self, ctx):
        argv = self.argv(ctx)
        r = self.runner.run(argv, timeout=self.timeout)
        self.last_raw = (argv, r.rc, r.out, r.err)
        if r.rc != 0:
            return self._failed("measure_command_rc_%d" % r.rc)
        try:
            rec = json.loads(r.out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return self._failed("measure_output_not_json")
        rec.setdefault("venue", self.venue)
        return rec


class Evidence:
    """Raw output and records under one directory, with a SHA-256 manifest (5.7: each test records
    its raw output with the node class and the binary digest)."""

    def __init__(self, root):
        self.root = root
        os.makedirs(root, exist_ok=True)
        self.ip_table = {}

    def path(self, *parts):
        p = os.path.join(self.root, *parts)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def append_run(self, rec):
        with open(self.path("runs.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(canonical(rec) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def write_json(self, name, obj):
        with open(self.path(name), "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=1, sort_keys=True)
            fh.write("\n")

    def save_raw(self, name, text):
        with open(self.path("raw", name), "w", encoding="utf-8") as fh:
            fh.write(mask_ips(text, self.ip_table))

    def manifest(self):
        entries = {}
        for dp, _, files in os.walk(self.root):
            for f in sorted(files):
                full = os.path.join(dp, f)
                rel = os.path.relpath(full, self.root)
                if rel != "MANIFEST.json":
                    entries[rel] = sha256_file(full)
        self.write_json("MANIFEST.json", {"version": VERSION, "files": dict(sorted(entries.items()))})
        return entries


def run_trial(trial, backend, evidence, node_classes, reps, seed, stages=None, controller_factory=None,
              min_reps=DEFAULT_MIN_REPS, log=lambda s: None, prior_runs=()):
    """Run the stages of a trial in order and return (decision, runs). controller_factory(stage)
    returns an ArmController, or None when the arms are set outside (a dry run). A confirm stage
    runs only the arm the screen stages chose, and is skipped when they chose none. prior_runs are
    the trial's runs from earlier invocations (the P-17 aicore stages run on another host)."""
    prior = [r for r in prior_runs if r.get("trial") == trial.id and r.get("stage") not in (stages or ())]
    runs = []
    for st in trial.stages:
        if stages and st.name not in stages:
            continue
        nc = node_classes.get(st.name, {})
        only = None
        if st.role == "confirm":
            chosen = decide_trial(trial, prior + runs, node_classes, min_reps).get("chosen_arm")
            if not chosen:
                log("%s: no arm goes forward, confirm stage %s skipped" % (trial.id, st.name))
                continue
            only = {chosen}
        ctrl = controller_factory(st) if controller_factory else None
        try:
            if ctrl:
                ctrl.begin()
            for item in schedule(trial, reps, seed, st.name, only):
                if ctrl:
                    ctrl.switch(item["arm"])
                if hasattr(backend, "last_raw"):
                    backend.last_raw = None
                rec = backend.measure(dict(item, gw_cpus=st.gw_cpus))
                if ctrl:
                    ctrl.assert_guarded()      # a dead-man that fired mid-run reverted the node: not this arm's run
                raw = getattr(backend, "last_raw", None)
                if raw:
                    name = "measure_%s_%s_%s_r%d_%s_%s_%s.txt" % (trial.id, st.name, item["arm"], item["rep"],
                                                                  item["profile"], item["test"], item["dir"])
                    evidence.save_raw(name, "argv: %s\nrc: %d\n--- stdout\n%s\n--- stderr\n%s\n"
                                      % (shlex.join(map(str, raw[0])), raw[1], raw[2], raw[3]))
                bad = validate_run_record(rec) if rec.get("started") else []
                rec.update(item)
                rec["role"] = role_of(item["arm"])
                rec["node_class_id"] = nc.get("class_id")
                rec["binary_sha256"] = nc.get("binary_sha256")
                if bad:
                    rec.update({"started": False, "alive": False, "failure_class": "bad_record: " + "; ".join(bad)})
                if raw:
                    rec["raw"] = "raw/" + name
                rec.setdefault("venue", nc.get("venue"))
                evidence.append_run(rec)
                runs.append(rec)
                log("%s %s %s rep %d %s %s %s" % (trial.id, st.name, item["arm"], item["rep"], item["profile"], item["test"], item["dir"]))
        finally:
            if ctrl:
                try:
                    ctrl.finish()
                finally:
                    evidence.save_raw("arms_%s_%s_commands.txt" % (trial.id, st.name),
                                      "\n".join("rc=%d %s" % (rc, shlex.join(c)) for c, rc in ctrl.log) + "\n")
        evidence.write_json("node_class_%s.json" % st.name, nc)
    decision = decide_trial(trial, prior + runs, node_classes, min_reps)
    evidence.write_json("verdict_%s.json" % trial.id, decision)
    return decision, runs


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------
def _load_jsonl(path):
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip().startswith("{")]


def _load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _emit(obj):
    print(json.dumps(obj, indent=1, sort_keys=True))


def dry_node_class(venue="dry_run"):
    return {"venue": venue, "emulated": False, "cpu_model": "synthetic", "usable_cpus": 4, "ram_kib": 4194304,
            "provider": "dry-run", "binary_sha256": "0" * 64, "class_id": "dryrun"}


def cmd_plan(args):
    check_bench_order()
    _emit(plan_json())
    return 0


def cmd_dry_run(args):
    check_bench_order()
    ev = Evidence(args.out)
    summary = {}
    for tid in args.trial or [t for t in BENCH_ORDER if TRIALS[t].kind == "config"]:
        trial = TRIALS[tid]
        if trial.kind == "binary":
            summary[tid] = {"rule_r_verdict": "NOT_RUN", "why": "own gateway round (binary change)"}
            continue
        ncs = {st.name: dry_node_class() for st in trial.stages}
        decision, _ = run_trial(trial, DryRunBackend(args.scenario, args.seed), ev, ncs, args.reps, args.seed,
                                min_reps=args.min_reps)
        summary[tid] = {"rule_r_verdict": decision["rule_r_verdict"], "adoptable": decision["adoptable"],
                        "chosen_arm": decision["chosen_arm"], "notes": decision["notes"]}
    ev.write_json("dry_run_summary.json", summary)
    ev.manifest()
    _emit(summary)
    return 0


def cmd_analyze(args):
    trial = TRIALS[args.trial]
    runs = [r for r in _load_jsonl(args.runs) if r.get("trial") == trial.id]
    ncs = _load_json(args.node_classes) if args.node_classes else {}
    _emit(decide_trial(trial, runs, ncs, args.min_reps))
    return 0


def cmd_connect_time(args):
    out = analyze_connect_time(_load_jsonl(args.runs), _load_jsonl(args.baseline) if args.baseline else None,
                               min_runs=args.min_runs)
    _emit(out)
    return 0 if out["verdict"] == "PASS" else 1


def cmd_evidence(args):
    virt = detect_virt() if args.virt == "auto" else args.virt
    nc = read_node_class(virt_name=virt, provider=args.provider, node_label=args.label,
                         binary_path=args.binary, venue=args.venue)
    ok, reasons = venue_eligibility(nc)
    _emit({"node_class": nc, "facts": host_facts(), "performance_eligible": ok, "reasons": reasons})
    return 0


def cmd_connect_ingest(args):
    """Turn connect-time-20261001/measure/analyze.py output (attempts_phases.json) into run rows."""
    rows = connect_rows_from_ct4m(_load_json(args.phases), args.node_class, args.network)
    with open(args.out, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(canonical(r) + "\n")
    _emit({"rows": len(rows), "failed": sum(1 for r in rows if not r["ok"])})
    return 0


def cmd_storm(args):
    _emit(analyze_storm(_load_json(args.input), args.min_reps))
    return 0


def cmd_golive(args):
    _emit(analyze_golive(_load_json(args.input)))
    return 0


def cmd_ryzen(args):
    _emit(analyze_ryzen(_load_json(args.input), args.lock_owner or None))
    return 0


def cmd_hub_cost(args):
    _emit(analyze_hub_cost(_load_json(args.input)))
    return 0


def cmd_epoll(args):
    with open(args.strace_output, "r", encoding="utf-8") as fh:
        _emit(analyze_epoll(fh.read(), args.seconds, args.attached_after_startup))
    return 0


def cmd_queue_restarts(args):
    """Analyse recorded restarts, or with --execute drive N restarts on a node the operator named."""
    if not args.execute:
        _emit(analyze_queue_restarts(_load_json(args.input), args.restarts, args.reboots, args.qlen, args.systemd_version))
        return 0
    if not args.out:
        raise SystemExit("--execute needs --out")
    runner = make_runner(args.runner, args.allow_host or [])
    recs = []
    for i in range(args.restarts):
        kind = "kill" if (i % 5 == 4) else "restart"
        recs.append(restart_once(runner, kind, clock=time.time, sleep=time.sleep, wait_s=args.wait))
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(recs, fh, indent=1, sort_keys=True)
    _emit({"records": len(recs), "written": args.out, "note": "add the reboot records after each reboot, then re-run without --execute"})
    return 0


def _write_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def cmd_state(args):
    state = {}
    if os.path.exists(args.file):
        state = _load_json(args.file)
    if args.action == "set":
        if not args.trial or not args.verdict:
            raise SystemExit("state set needs --trial and --verdict")
        if args.trial not in TRIALS:
            raise SystemExit("state set records trial outcomes only; %r is not a trial (a P-24 condition is "
                             "recorded by p24-condition --state)" % args.trial)
        if args.verdict == "NOT_RUN":
            if TRIALS[args.trial].kind != "binary":
                raise SystemExit("%s is a config trial: it needs a rule R outcome, not NOT_RUN" % args.trial)
            if not (args.reason or "").strip():
                raise SystemExit("NOT_RUN is a deferral record: give --reason (why, and what gate remains)")
            state[args.trial + ".deferral"] = args.reason.strip()
        elif args.verdict not in RULE_R_OUTCOMES:
            raise SystemExit("verdict must be one of %s or NOT_RUN" % ", ".join(RULE_R_OUTCOMES))
        state[args.trial] = args.verdict
        _write_json_atomic(args.file, state)
    if args.action == "may-start":
        ok, why = trial_may_start(args.trial, state)
        print("yes" if ok else "no: " + why)
        return 0 if ok else 1
    _emit(state)
    return 0


def make_runner(spec, allow_hosts):
    if spec == "local":
        return LocalRunner()
    if spec.startswith("colima:"):
        return ColimaRunner(spec.split(":", 1)[1])
    if spec.startswith("ssh:"):
        return SshRunner(spec.split(":", 1)[1], allow_hosts)
    raise SystemExit("runner must be local, colima:<profile> or ssh:<host>")


def cmd_run(args):
    """Run one config trial's stage on a node. Without --execute it prints what it would do and
    changes nothing. It never runs against a host the operator did not list in --allow-host."""
    trial = TRIALS[args.trial]
    if trial.kind != "config":
        raise SystemExit("%s changes the gateway binary and needs its own gateway round" % trial.id)
    stage = next((s for s in trial.stages if s.name == args.stage), None)
    if stage is None:
        raise SystemExit("trial %s has no stage %s" % (trial.id, args.stage))
    runner = make_runner(args.runner, args.allow_host or [])
    target = Target(args.wan_dev, args.gw_dev, args.unit, args.netns)
    plan = {"trial": trial.id, "stage": stage.name, "runner": args.runner, "reps": args.reps,
            "schedule_runs": len(schedule(trial, args.reps, args.seed, stage.name)),
            "arms": [a.name for a in (trial.base,) + tuple(trial.arms)], "stage_venue": stage.venue,
            "node_class": "read from the node through the runner when --execute is given"}
    if not args.execute:
        plan["note"] = "dry plan only; nothing was contacted or changed; add --execute to apply arms"
        _emit(plan)
        return 0
    if args.dead_man_minutes < 1:
        raise SystemExit("--execute needs --dead-man-minutes of at least 1")
    deferred = {}
    if not args.state and not args.functional:
        raise SystemExit("bench order: --execute needs --state (the bench-order state file); only a --functional run may omit it")
    if args.state:
        st_doc = _load_json(args.state) if os.path.exists(args.state) else {}
        ok, why = trial_may_start(trial.id, st_doc)
        if not ok:
            raise SystemExit("bench order: " + why)
        deferred = deferred_priors(trial.id, st_doc)
    nc = node_class_via(runner, args.provider, args.label, args.binary, args.venue, args.gateway_cgroup)
    eligible, reasons = venue_eligibility(nc)
    if eligible and nc.get("venue") != stage.venue:
        eligible, reasons = False, ["stage %s needs venue %s, got %s" % (stage.name, stage.venue, nc.get("venue"))]
    if not eligible and not args.functional:
        # a serving canary takes the exposure of the arms only for figures that can count
        raise SystemExit("venue not eligible for performance figures (%s); nothing was changed. "
                         "Use --functional for a functional run, which is never adoptable" % "; ".join(reasons))
    prior = _load_jsonl(args.prior_runs) if args.prior_runs else []
    if stage.role == "confirm" and not prior:
        raise SystemExit("stage %s confirms the arm chosen by the earlier stages: pass their runs with --prior-runs" % stage.name)
    ev = Evidence(args.out)
    backend = CommandBackend(args.measure_cmd, secs=args.secs, venue=args.venue)
    make = lambda st: ArmController(runner, target, trial, dead_man_minutes=args.dead_man_minutes)
    lock = BenchLock(runner, args.lock_owner, args.lock_path) if stage.venue == "aicore" else None
    # SIGTERM and SIGHUP (a closed terminal or ssh session) end Python without running finally;
    # turn them into an exception so run_trial reverts the node at once instead of at the dead-man.
    def _stop(signum, frame):
        raise KeyboardInterrupt("signal %d" % signum)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _stop)
    if lock:
        lock.acquire(os.getpid())
    decision, _ = run_trial(trial, backend, ev, {stage.name: nc}, args.reps, args.seed, stages={stage.name},
                            controller_factory=make, min_reps=args.min_reps, log=lambda m: print(m, file=sys.stderr),
                            prior_runs=prior)
    if lock:
        lock.release(host_state_verified=True)      # reached only when finish() proved the revert
    if deferred:
        decision["notes"].append("ran with earlier gateway-round trials deferred, not run: " +
                                 "; ".join("%s (%s)" % kv for kv in sorted(deferred.items())))
    if args.functional:
        decision["adoptable"] = False
        decision["notes"].append("functional run: never adoptable, and no verdict is written to the state file")
    ev.write_json("verdict_%s.json" % trial.id, decision)
    ev.manifest()
    if args.state and not args.functional and len(trial.stages) == 1:
        state = _load_json(args.state) if os.path.exists(args.state) else {}
        state[trial.id] = decision["rule_r_verdict"]
        _write_json_atomic(args.state, state)
    elif args.state and not args.functional:
        decision["state_note"] = ("multi-stage trial: run 'analyze' over every stage's runs, then 'state set' the verdict; "
                                  "for P-17 also run 'p24-condition'")
    _emit(decision)
    return 0


def cmd_ingest_l63(args):
    arm_map = dict(x.split("=", 1) for x in args.arm_map.split(","))
    stage_map = dict(x.split("=", 1) for x in args.stage_map.split(","))
    n = skipped = 0
    with open(args.out, "a", encoding="utf-8") as fh:
        for o in _load_jsonl(args.runs):
            rec = record_from_l63(o, args.trial, arm_map, stage_map, args.venue)
            if rec is None:
                skipped += 1
                continue
            fh.write(canonical(rec) + "\n")
            n += 1
    _emit({"written": n, "skipped": skipped})
    return 0


def cmd_p24_condition(args):
    d = p24_condition(_load_jsonl(args.runs), args.stage)
    d["runs_sha256"] = sha256_file(args.runs)
    if args.state:
        state = _load_json(args.state) if os.path.exists(args.state) else {}
        state["P-24.condition"] = "met" if d["met"] else "not_met"
        state["P-24.condition_evidence"] = d["runs_sha256"]     # the P-17 runs the condition was read from
        _write_json_atomic(args.state, state)
    _emit(d)
    return 0 if d["met"] else 1


def cmd_revert(args):
    runner = make_runner(args.runner, args.allow_host or [])
    failures = revert_from_plan(runner, Target(args.wan_dev, args.gw_dev, args.unit, args.netns), _load_json(args.plan))
    _emit({"residual": failures})
    return 1 if failures else 0


def build_parser():
    ap = argparse.ArgumentParser(description="Win's VPN v3 performance bench harness (design 5.7)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("plan", help="print the trial plan and bench order as JSON").set_defaults(fn=cmd_plan)
    p = sub.add_parser("dry-run", help="run trials against the synthetic backend; contacts nothing")
    p.add_argument("--out", required=True)
    p.add_argument("--scenario", default="neutral", choices=sorted(DryRunBackend.SCENARIOS))
    p.add_argument("--trial", action="append", choices=sorted(TRIALS))
    p.add_argument("--reps", type=int, default=10)
    p.add_argument("--min-reps", type=int, default=DEFAULT_MIN_REPS)
    p.add_argument("--seed", type=int, default=1)
    p.set_defaults(fn=cmd_dry_run)
    p = sub.add_parser("analyze", help="decide one trial from a runs.jsonl by rule R")
    p.add_argument("--trial", required=True, choices=sorted(TRIALS))
    p.add_argument("--runs", required=True)
    p.add_argument("--node-classes", help="JSON: stage name to node class record")
    p.add_argument("--min-reps", type=int, default=DEFAULT_MIN_REPS)
    p.set_defaults(fn=cmd_analyze)
    p = sub.add_parser("connect-time", help="p95 at most 4.0 s per network type and node class")
    p.add_argument("--runs", required=True)
    p.add_argument("--baseline")
    p.add_argument("--min-runs", type=int, default=CONNECT_MIN_RUNS)
    p.set_defaults(fn=cmd_connect_time)
    p = sub.add_parser("evidence", help="read-only node class record and venue eligibility of THIS machine")
    p.add_argument("--venue", default="")
    p.add_argument("--provider", default="")
    p.add_argument("--label", default="")
    p.add_argument("--virt", default="auto", help="output of systemd-detect-virt; auto runs it here")
    p.add_argument("--binary")
    p.set_defaults(fn=cmd_evidence)
    p = sub.add_parser("connect-ingest", help="CT4-M attempts_phases.json to connect-time run rows")
    p.add_argument("--phases", required=True)
    p.add_argument("--node-class", required=True)
    p.add_argument("--network", required=True, choices=CONNECT_NETWORKS)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_connect_ingest)
    p = sub.add_parser("storm", help="P-19 replay-journal storm record")
    p.add_argument("--input", required=True)
    p.add_argument("--min-reps", type=int, default=DEFAULT_MIN_REPS)
    p.set_defaults(fn=cmd_storm)
    p = sub.add_parser("golive", help="go-live latency over fresh installs")
    p.add_argument("--input", required=True)
    p.set_defaults(fn=cmd_golive)
    p = sub.add_parser("ryzen", help="uncapped Ryzen acceptance runs")
    p.add_argument("--input", required=True)
    p.add_argument("--lock-owner", default="")
    p.set_defaults(fn=cmd_ryzen)
    p = sub.add_parser("hub-cost", help="hub cost record")
    p.add_argument("--input", required=True)
    p.set_defaults(fn=cmd_hub_cost)
    p = sub.add_parser("epoll", help="strace -f -c epoll_ctl decline check")
    p.add_argument("--strace-output", required=True)
    p.add_argument("--seconds", type=float, required=True)
    p.add_argument("--attached-after-startup", action="store_true")
    p.set_defaults(fn=cmd_epoll)
    p = sub.add_parser("queue-restarts", help="winn3gw0 queue helper across 20 restarts and 3 reboots (analysis, or --execute to drive restarts)")
    p.add_argument("--input")
    p.add_argument("--out")
    p.add_argument("--restarts", type=int, default=QUEUE_RESTARTS)
    p.add_argument("--reboots", type=int, default=QUEUE_REBOOTS)
    p.add_argument("--qlen", type=int, default=10000)
    p.add_argument("--systemd-version")
    p.add_argument("--wait", type=int, default=60)
    p.add_argument("--runner", default="local")
    p.add_argument("--allow-host", action="append")
    p.add_argument("--execute", action="store_true")
    p.set_defaults(fn=cmd_queue_restarts)
    p = sub.add_parser("ingest-l63", help="aicore rig runs_*.jsonl (lane L63 point script) to run records")
    p.add_argument("--runs", required=True)
    p.add_argument("--out", required=True, help="runs.jsonl to append to")
    p.add_argument("--trial", required=True, choices=sorted(TRIALS))
    p.add_argument("--arm-map", required=True, help="label arm token to arm name, for example Ra=base_a,Rb=base_b,C=ring2048")
    p.add_argument("--stage-map", required=True, help="label stage token to stage name, for example s1=aicore_cpu1,s2=aicore_cpu2")
    p.add_argument("--venue", default="aicore")
    p.set_defaults(fn=cmd_ingest_l63)
    p = sub.add_parser("p24-condition", help="does P-17's data show backlog about 0 while TX drops rise (P-24 runs only then)")
    p.add_argument("--runs", required=True)
    p.add_argument("--stage", required=True)
    p.add_argument("--state", help="bench-order state file: records the condition bound to the digest of --runs")
    p.set_defaults(fn=cmd_p24_condition)
    p = sub.add_parser("state", help="bench-order state file: show, set, may-start")
    p.add_argument("action", choices=("show", "set", "may-start"))
    p.add_argument("--file", required=True)
    p.add_argument("--trial")
    p.add_argument("--verdict")
    p.add_argument("--reason", help="required with NOT_RUN: why the gateway-round trial is deferred and what gate remains")
    p.set_defaults(fn=cmd_state)
    for name, fn in (("run", cmd_run), ("revert", cmd_revert)):
        p = sub.add_parser(name, help="apply the arms of one trial stage on a node" if name == "run" else "run a stored revert plan")
        p.add_argument("--runner", default="local", help="local, colima:<profile> or ssh:<host>")
        p.add_argument("--allow-host", action="append", help="hosts ssh: may name (none by default)")
        p.add_argument("--wan-dev", default="eth0")
        p.add_argument("--gw-dev", default="winn3gw0")
        p.add_argument("--unit", default="winn3-gateway.service")
        p.add_argument("--netns", default="")
        if name == "run":
            p.add_argument("--trial", required=True, choices=sorted(TRIALS))
            p.add_argument("--stage", required=True)
            p.add_argument("--out", required=True)
            p.add_argument("--venue", required=True)
            p.add_argument("--provider", default="")
            p.add_argument("--label", default="")
            p.add_argument("--binary", help="gateway binary path ON THE NODE, hashed for the node class record")
            p.add_argument("--measure-cmd", required=True,
                           help="argv template run on THIS machine (the load generator side); prints one JSON run record")
            p.add_argument("--reps", type=int, default=10)
            p.add_argument("--min-reps", type=int, default=DEFAULT_MIN_REPS)
            p.add_argument("--secs", type=int, default=20)
            p.add_argument("--seed", type=int, default=1)
            p.add_argument("--dead-man-minutes", type=int, default=20,
                           help="re-armed before every arm change; must exceed the longest single run")
            p.add_argument("--prior-runs", help="runs.jsonl of the trial's earlier stages (needed by a confirm stage)")
            p.add_argument("--lock-owner", default="winn3-perf-bench", help="owner name for the aicore bench lock")
            p.add_argument("--lock-path", default="/home/aicore/.bench.lock")
            p.add_argument("--state", help="bench-order state file to enforce (required with --execute unless --functional)")
            p.add_argument("--gateway-cgroup", help="the gateway's cgroup path, so usable CPUs are the gateway's own")
            p.add_argument("--functional", action="store_true",
                           help="allow a venue that cannot yield performance figures; the result is never adoptable")
            p.add_argument("--execute", action="store_true")
        else:
            p.add_argument("--plan", required=True)
        p.set_defaults(fn=fn)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
