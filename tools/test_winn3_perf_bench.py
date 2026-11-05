#!/usr/bin/env python3
"""Tests for tools/winn3_perf_bench.py (design 5.7, 10.0, 10.2 to 10.6; slice P3).

No host is contacted. Arm control runs against FakeSystem, a small in-memory model of tc, ip,
sysctl, systemctl and the file commands the controller uses. Measurement uses synthetic records.

  python3 tools/test_winn3_perf_bench.py          (or: python3 -m pytest tools/test_winn3_perf_bench.py)

WINN3_PERF_BENCH_MODULE points the suite at another copy of the module, and WINN3_PERF_BENCH_LOCAL_MODULE
at another copy of the local driver; the mutant runner uses both.
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.environ.get("WINN3_PERF_BENCH_MODULE") or os.path.join(HERE, "winn3_perf_bench.py")
_spec = importlib.util.spec_from_file_location("winn3_perf_bench_under_test", MODULE_PATH)
wb = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = wb
_spec.loader.exec_module(wb)
sys.modules["winn3_perf_bench"] = wb           # the local driver imports it by this name
_lspec = importlib.util.spec_from_file_location("winn3_perf_bench_local_under_test",
                                                os.environ.get("WINN3_PERF_BENCH_LOCAL_MODULE") or os.path.join(HERE, "winn3_perf_bench_local.py"))
local = importlib.util.module_from_spec(_lspec)
sys.modules[_lspec.name] = local
_pspec = importlib.util.spec_from_file_location("winn3_perf_probe_under_test", os.path.join(HERE, "winn3_perf_probe.py"))
probe = importlib.util.module_from_spec(_pspec)
sys.modules[_pspec.name] = probe
_pspec.loader.exec_module(probe)
_lspec.loader.exec_module(local)


# ---------------------------------------------------------------------------
# Helpers: node classes and synthetic run records
# ---------------------------------------------------------------------------
def node_class(venue="canary", **kw):
    aicore = venue == "aicore"
    nc = {"venue": venue, "emulated": False, "cpu_model": "AMD Ryzen 7 PRO 8845HS" if aicore else "AMD EPYC",
          "usable_cpus": 4, "ram_kib": 4194304, "provider": "p", "binary_sha256": "a" * 64, "class_id": "c1",
          "virt": "none" if aicore else "kvm"}
    nc.update(kw)
    return nc


BASE_VALUES = {"idle_p50_ms": {"a": 70.0, "b": 85.0}, "ld_p50_ms": 190.0, "ld_p99_ms": 215.0, "ld_jitter_ms": 4.0,
               "ld_loss_pct": 0.2, "thr_mbps": 800.0, "awg_mbps": 300.0, "xray_mbps": 250.0,
               "awg_ld_p99_ms": 60.0, "xray_ld_p99_ms": 70.0, "cpu_total_pct": 40.0}
NOISE = {"ld_p50_ms": 2.0, "ld_p99_ms": 3.0, "ld_jitter_ms": 0.3, "ld_loss_pct": 0.05, "thr_mbps": 10.0,
         "awg_mbps": 3.0, "xray_mbps": 3.0, "awg_ld_p99_ms": 1.0, "xray_ld_p99_ms": 1.0, "cpu_total_pct": 0.5}


def build_runs(trial, stage="canary", reps=10, cand=None, noise=None, venue="canary", extras=None,
               failures=None, only_cells=None):
    """Runs where base_a is BASE_VALUES, base_b alternates +/- noise, and each candidate arm adds a
    constant delta. cand: arm name -> {metric: delta}. failures: arm -> list of (rep, failure_class)."""
    noise = dict(NOISE, **(noise or {}))
    cand = cand or {}
    failures = failures or {}
    runs = []
    pinned = next((s.gw_cpus[0] for s in trial.stages if s.name == stage and s.gw_cpus), None)
    for cell in (only_cells or trial.cells):
        profile, test, direction = cell
        for rep in range(1, reps + 1):
            for arm in ["base_a", "base_b"] + [a.name for a in trial.arms]:
                rec = {"trial": trial.id, "stage": stage, "arm": arm, "rep": rep, "profile": profile, "test": test,
                       "dir": direction, "started": True, "alive": True, "venue": venue,
                       "sessions_started": 1, "sessions_failed": 0, "failure_class": None,
                       "node_class_id": "c1", "binary_sha256": "a" * 64}
                if pinned:
                    rec["gw_cpus_observed"] = pinned
                for m in ("ld_p50_ms", "ld_p99_ms", "ld_jitter_ms", "ld_loss_pct", "thr_mbps", "awg_mbps", "xray_mbps",
                          "awg_ld_p99_ms", "xray_ld_p99_ms", "cpu_total_pct"):
                    v = BASE_VALUES[m]
                    if arm == "base_b":
                        v += noise[m] * (1 if rep % 2 else -1)
                    elif arm in cand:
                        v += cand[arm].get(m, 0.0)
                    rec[m] = v
                rec["idle_p50_ms"] = BASE_VALUES["idle_p50_ms"][profile]
                if trial.background:
                    rec["background"] = {n: 35.0 for n in trial.background}
                if arm in cand and "rise" in cand[arm]:
                    rec["ld_p50_ms"] = rec["idle_p50_ms"] + cand[arm]["rise"]
                if extras and "base_rise" in extras and not (arm in cand and "rise" in cand[arm]):
                    # every arm without its own rise sits at the base rise (candidates that change nothing)
                    delta = cand.get(arm, {}).get("ld_p50_ms", 0.0)
                    rec["ld_p50_ms"] = rec["idle_p50_ms"] + extras["base_rise"] + delta + (noise["ld_p50_ms"] * (1 if rep % 2 else -1) if arm == "base_b" else 0)
                for frep, cls in failures.get(arm, []):
                    if frep == rep:
                        rec.update({"started": False, "alive": False, "sessions_started": 0, "sessions_failed": 1, "failure_class": cls})
                runs.append(rec)
    return runs


def decide(trial_id, runs, stage_venues=None, min_reps=10):
    trial = wb.TRIALS[trial_id]
    ncs = {st.name: node_class(st.venue) for st in trial.stages}
    ncs.update(stage_venues or {})
    return wb.decide_trial(trial, runs, ncs, min_reps)


def screen(trial_id, runs, stage="canary", min_reps=10):
    trial = wb.TRIALS[trial_id]
    return wb.decide_screen(trial, wb.index_runs([r for r in runs if r["stage"] == stage]), stage, min_reps=min_reps)


# ---------------------------------------------------------------------------
# FakeSystem: tc, ip, sysctl, systemctl and files
# ---------------------------------------------------------------------------
FQ_DEFAULT = {"limit": 20480, "flow_limit": 256, "buckets": 1024, "orphan_mask": 1023, "quantum": 1280,
              "initial_quantum": 25600, "low_rate_threshold": 68750, "refill_delay": 1000, "timer_slack": 10000,
              "horizon": 10000000, "horizon_drop": None}


class FakeSystem:
    MUTATORS = (("tc", "qdisc", "replace"), ("tc", "qdisc", "del"), ("ip", "link", "set"), ("sysctl", "-w"),
                ("systemctl", "set-property"))

    def __init__(self, gw_children="fq", silent_revert_dev=None):
        self.files, self.dirs, self.timers, self.log = {}, set(), set(), []
        self.fail = []              # (substring of the joined argv, rc)
        self.ignore = []            # substrings: succeed with rc 0 but do nothing (a silently ignored command)
        self.qdisc = {
            "eth0": [{"kind": "fq", "handle": "8001:", "root": True, "options": dict(FQ_DEFAULT)}],
            "winn3gw0": [{"kind": "mq", "handle": "1:", "root": True, "options": {}}] + [
                {"kind": gw_children, "handle": "800%d:" % n, "parent": "1:%d" % n,
                 "options": dict(FQ_DEFAULT, limit=10240) if gw_children == "fq" else {}} for n in range(1, 5)],
        }
        self.qlen = {"winn3gw0": 10000, "eth0": 1000}
        self.sysctl = {"net.core.busy_poll": "0", "net.core.busy_read": "0"}
        self.units = {"winn3-gateway.service": {"LoadState": "loaded", "CPUWeight": "[not set]", "IOWeight": "[not set]"}}
        self.netns_seen = []
        self.noqueue_resets_qlen = False
        self.gw_pid, self.ifindex, self.helper_runs, self.helper_writes_state = 100, 7, 1, True
        self.journal = []
        self.virt = "kvm"

    # -- plumbing
    def run(self, argv, stdin=None, timeout=0):
        argv = list(argv)
        joined = shlex.join(argv)
        self.log.append(joined)
        for sub, rc in self.fail:
            if sub in joined:
                return wb.RunResult(rc, "", "injected failure")
        if argv[:3] == ["ip", "netns", "exec"]:
            self.netns_seen.append(argv[3])
            argv = argv[4:]
        for sub in self.ignore:
            if sub in joined:
                return wb.RunResult(0, "", "")
        fn = getattr(self, "cmd_" + argv[0].replace("-", "_"), None)
        if fn is None:
            return wb.RunResult(127, "", "unknown command %s" % argv[0])
        return fn(argv, stdin)

    def mutations(self):
        out = []
        for i, line in enumerate(self.log):
            toks = shlex.split(line)
            if toks[:3] == ["ip", "netns", "exec"]:
                toks = toks[4:]
            if any(tuple(toks[:len(m)]) == m for m in self.MUTATORS):
                out.append(i)
        return out

    def index_of(self, sub):
        return next(i for i, l in enumerate(self.log) if sub in l)

    # -- files
    def cmd_install(self, argv, stdin):
        self.dirs.add(argv[-1])
        return wb.RunResult(0)

    def cmd_tee(self, argv, stdin):
        self.files[argv[1]] = stdin or ""
        return wb.RunResult(0)

    def cmd_chmod(self, argv, stdin):
        return wb.RunResult(0 if argv[-1] in self.files else 1)

    def cmd_rm(self, argv, stdin):
        if "-rf" in argv:
            self.dirs.discard(argv[-1])
        self.files.pop(argv[-1], None)
        return wb.RunResult(0)

    def cmd_cat(self, argv, stdin):
        return wb.RunResult(0, self.files[argv[1]]) if argv[1] in self.files else wb.RunResult(1, "", "no such file")

    def cmd_mkdir(self, argv, stdin):
        if argv[1] in self.dirs:
            return wb.RunResult(1, "", "File exists")
        self.dirs.add(argv[1])
        return wb.RunResult(0)

    def cmd_rmdir(self, argv, stdin):
        self.dirs.discard(argv[1])
        return wb.RunResult(0)

    # -- tc and ip
    def cmd_tc(self, argv, stdin):
        if argv[1:3] == ["-j", "qdisc"]:
            tree = self.qdisc[argv[5]]
            if getattr(self, "dump_children_reversed", False):    # tc -j lists children in hash order
                tree = [q for q in tree if q.get("root")] + [q for q in reversed(tree) if not q.get("root")]
            return wb.RunResult(0, json.dumps(tree))
        dev = argv[argv.index("dev") + 1]
        if argv[1:3] == ["qdisc", "del"]:
            self.qdisc[dev] = []
            return wb.RunResult(0)
        rest = argv[argv.index(dev) + 1:]
        if rest[0] == "root":
            pos, rest = {"root": True}, rest[1:]
        else:
            pos, rest = {"parent": rest[1]}, rest[2:]
            if int(pos["parent"].split(":")[0] or "0", 16) == 0:   # like the kernel: major 0 is never found
                return wb.RunResult(2, "", "Error: Failed to find specified qdisc.\n")
        handle = None
        if rest[0] == "handle":
            handle, rest = rest[1], rest[2:]
        kind, opts_in = rest[0], rest[1:]
        opts = {}
        for k, v in zip(opts_in[::2], opts_in[1::2]):
            if k == "refill_delay":
                opts[k] = int(v[:-2])
            elif k == "maxrate":
                opts[k] = int(v[:-3])
            else:
                opts[k] = int(v)
        cur = self.qdisc[dev]
        match = [q for q in cur if bool(q.get("root")) == bool(pos.get("root")) and q.get("parent") == pos.get("parent")]
        if match and match[0]["kind"] == kind:
            match[0]["options"].update(opts)
            return wb.RunResult(0)
        if pos.get("root"):
            cur[:] = []
        else:
            cur[:] = [q for q in cur if q not in match]
        # like the kernel: a fresh qdisc gets a handle no earlier qdisc had, an fq dumps every option
        # (defaults for the ones not given) and the keys come in tc's order: kind, handle, position, options
        self.handle_seq = getattr(self, "handle_seq", 0x9000) + 1
        q = {"kind": kind, "handle": handle or "%x:" % self.handle_seq}
        q.update(pos)
        q["options"] = dict(FQ_DEFAULT, **opts) if kind == "fq" else {}
        cur.append(q)
        if kind == "noqueue" and self.noqueue_resets_qlen and dev in self.qlen:
            self.qlen[dev] = 0
        return wb.RunResult(0)

    def cmd_ip(self, argv, stdin):
        if argv[1:3] == ["-o", "link"]:
            dev = argv[-1]
            root = [q for q in self.qdisc.get(dev, []) if q.get("root")]
            return wb.RunResult(0, "%d: %s: <BROADCAST,UP> mtu 1500 qdisc %s state UP mode DEFAULT group default qlen %d\\    link/ether 0\n"
                                % (self.ifindex, dev, root[0]["kind"] if root else "noqueue", self.qlen[dev]))
        if argv[1:3] == ["link", "set"]:
            self.qlen[argv[argv.index("dev") + 1]] = int(argv[-1])
            return wb.RunResult(0)
        return wb.RunResult(1, "", "unsupported ip")

    # -- sysctl and systemd
    def cmd_sysctl(self, argv, stdin):
        if argv[1] == "-n":
            return wb.RunResult(0, self.sysctl[argv[2]] + "\n")
        for kv in argv[2:]:
            k, v = kv.split("=")
            self.sysctl[k] = v
        return wb.RunResult(0)

    def cmd_systemctl(self, argv, stdin):
        if argv[1:4] == ["show", "-p", "MainPID"]:
            return wb.RunResult(0, "%d\n" % self.gw_pid)
        if argv[1] in ("restart", "kill"):
            self.gw_pid += 1
            self.journal = ["Started wins-winn3gw-queues.service - queue helper.\n"] * self.helper_runs
            if self.helper_writes_state:
                self.files[wb.QUEUE_STATE_PATH] = json.dumps({"result": "ok", "main_pid": self.gw_pid, "ifindex": self.ifindex})
            return wb.RunResult(0)
        if argv[1] == "show":
            u = self.units.get(argv[2], {"LoadState": "not-found", "CPUWeight": "[not set]", "IOWeight": "[not set]"})
            props = [argv[i + 1] for i, a in enumerate(argv) if a == "-p"]
            return wb.RunResult(0, "".join("%s=%s\n" % (p, u[p]) for p in props))
        if argv[1] == "set-property":
            u = self.units[argv[3]]
            for kv in argv[4:]:
                k, v = kv.split("=", 1)
                u[k] = v if v else "[not set]"
            return wb.RunResult(0)
        if argv[1] == "stop":
            for unit in argv[2:]:
                self.timers.discard(unit)
            return wb.RunResult(0)
        if argv[1:3] == ["is-active", "--quiet"]:
            return wb.RunResult(0 if argv[3] in self.timers else 3)
        return wb.RunResult(1, "", "unsupported systemctl")

    def cmd_test(self, argv, stdin):
        return wb.RunResult(0 if argv[1:2] in (["-f"], ["-e"]) and argv[2] in self.files else 1)

    def cmd_journalctl(self, argv, stdin):
        return wb.RunResult(0, "".join(self.journal))

    def cmd_systemd_detect_virt(self, argv, stdin):
        return wb.RunResult(0 if self.virt != "none" else 1, self.virt + "\n")

    def cmd_sha256sum(self, argv, stdin):
        return wb.RunResult(0, "%s  %s\n" % ("c" * 64, argv[1])) if argv[1] in self.files else wb.RunResult(1, "", "no such file")

    def cmd_systemd_run(self, argv, stdin):
        unit = argv[argv.index("--unit") + 1]
        self.timers.add(unit + ".timer")
        return wb.RunResult(0)


def controller(fs, trial_id, **kw):
    trial = wb.TRIALS[trial_id]
    return wb.ArmController(fs, wb.Target(), trial, state_dir="/var/lib/winsvpn/perf-trial", clock=lambda: "2026-10-07T00:00:00Z", **kw)


def wan_flow(fs):
    return fs.qdisc["eth0"][0]["options"]["flow_limit"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class Stats(unittest.TestCase):
    def test_median_and_nearest_rank(self):
        self.assertEqual(wb.median([3, 1, 2]), 2)
        self.assertEqual(wb.median([1, 2, 3, 4]), 2.5)
        self.assertEqual(wb.nearest_rank(list(range(1, 11)), 95), 10)
        self.assertEqual(wb.nearest_rank(list(range(1, 21)), 95), 19)
        self.assertEqual(wb.nearest_rank([1.0, 2.0, float("inf")], 95), float("inf"))
        with self.assertRaises(ValueError):
            wb.median([])

    def test_cpuset(self):
        self.assertEqual(wb.parse_cpuset("0-3"), 4)
        self.assertEqual(wb.parse_cpuset("0-1,4,6-7"), 5)
        for bad in ("", "a", "3-1", "1,,2"):
            with self.assertRaises(ValueError):
                wb.parse_cpuset(bad)

    def test_chicago_fits_22_sessions(self):
        # design 10.2 P-8: chicago has 1967 MiB, fit 22
        self.assertEqual(wb.sessions_that_fit(1967 * 1024), 22)
        self.assertEqual(wb.default_max_sessions(1967 * 1024), 22)
        self.assertEqual(wb.default_max_sessions(64 * 1024 * 1024), 64)
        self.assertEqual(wb.sessions_that_fit(100 * 1024), 0)

    def test_mask_ips_keeps_private_and_is_stable(self):
        table = {}
        out = wb.mask_ips("a 203.0.113.9 b 10.8.1.1 c 203.0.113.9 d 8.8.4.4 e 192.168.1.2 f 127.0.0.1 g 999.1.1.1", table)
        self.assertIn("[IP_1]", out)
        self.assertEqual(out.count("[IP_1]"), 2)
        self.assertIn("[IP_2]", out)
        for keep in ("10.8.1.1", "192.168.1.2", "127.0.0.1", "999.1.1.1"):
            self.assertIn(keep, out)
        self.assertNotIn("203.0.113.9", out)


class Registry(unittest.TestCase):
    def test_bench_order_contract(self):
        self.assertTrue(wb.check_bench_order())
        self.assertEqual(wb.BENCH_ORDER[0], "P-17")
        groups = [wb.TRIALS[t].group for t in wb.BENCH_ORDER]
        first_tp = groups.index("throughput")
        self.assertNotIn("latency", groups[first_tp:])

    def test_bench_order_breaks_are_detected(self):
        order = list(wb.BENCH_ORDER)
        order[0], order[1] = order[1], order[0]
        with self.assertRaises(ValueError):
            wb.check_bench_order(tuple(order))
        order = list(wb.BENCH_ORDER)
        order.remove("P-24")
        order.insert(1, "P-24")                     # a throughput trial before the latency trials
        with self.assertRaises(ValueError):
            wb.check_bench_order(tuple(order))
        with self.assertRaises(ValueError):
            wb.check_bench_order(wb.BENCH_ORDER[:-1])

    def test_every_design_trial_is_present_with_its_arms(self):
        T = wb.TRIALS
        self.assertEqual([a.p["flow_limit"] for a in [T["P-4"].base] + list(T["P-4"].arms)], [256, 100, 1024, 2048])
        self.assertEqual([a.p["qlen"] for a in [T["P-17"].base] + list(T["P-17"].arms)], [10000, 4096, 2048, 1024])
        self.assertEqual(T["P-3"].arms[0].p, {"busy_poll": 50, "busy_read": 50})
        self.assertEqual(T["P-3"].base.p, {"busy_poll": 0, "busy_read": 0})
        self.assertEqual(T["P-10"].arms[0].p, {"cpu_weight": 400, "io_weight": 500})
        self.assertEqual(T["P-10"].base.p, {"cpu_weight": 100, "io_weight": 100})
        self.assertEqual([a.p["quantum"] for a in [T["P-22"].base] + list(T["P-22"].arms)], [1280, 1514])
        self.assertEqual(T["P-24"].arms[0].kind, "tun_noqueue")
        for tid in ("P-18", "P-41", "P-46", "P-20", "P-21", "P-25", "P-26", "P-27", "P-28", "P-29", "P-31",
                    "P-32", "P-35", "P-36", "P-39", "P-40", "P-44"):
            self.assertEqual(T[tid].kind, "binary", tid)
        self.assertEqual(T["P-44"].together_with, "P-39")

    def test_p17_measures_a_single_session_with_eight_download_streams(self):
        self.assertEqual(wb.TRIALS["P-17"].cells, (("a", "tcp8", "down"), ("b", "tcp8", "down")))
        self.assertEqual(wb.TRIALS["P-4"].cells, (("a", "tcp1", "down"), ("b", "tcp1", "down")))
        self.assertEqual(wb.record_from_l63(dict(IngestL63.LINE, rundir="s1_C_a_tcp8_down_r1"), "P-17",
                                            IngestL63.AM, IngestL63.SM, "aicore")["test"], "tcp8")

    def test_trial_purposes_and_groups(self):
        T = wb.TRIALS
        for tid in ("P-17", "P-4", "P-22", "P-3", "P-10", "P-18", "P-41", "P-46"):
            self.assertEqual((T[tid].group, T[tid].purpose), ("latency", "latency"), tid)
        for tid in ("P-24", "P-20", "P-21", "P-25", "P-44"):
            self.assertEqual((T[tid].group, T[tid].purpose), ("throughput", "throughput"), tid)

    def test_p17_stages_pin_cpus_on_aicore_then_confirm_on_canary(self):
        st = wb.TRIALS["P-17"].stages
        self.assertEqual([(s.venue, s.role, s.gw_cpus) for s in st],
                         [("aicore", "screen", (1,)), ("aicore", "screen", (2,)), ("canary", "confirm", ())])

    def test_p3_and_p10_need_side_traffic_and_p3_has_cpu_ceiling(self):
        T = wb.TRIALS
        self.assertTrue(T["P-3"].side_traffic and T["P-10"].side_traffic)
        self.assertEqual(T["P-3"].cpu_ceiling_pp, 5.0)
        self.assertEqual(T["P-10"].background, ("suricata", "awg", "xray"))

    def test_matrix_is_both_profiles_one_four_flows_and_paced_udp_both_directions(self):
        m = wb.full_matrix()
        self.assertEqual(len(m), 12)
        self.assertEqual({c[0] for c in m}, {"a", "b"})
        self.assertEqual({c[1] for c in m}, {"tcp1", "tcp4", "udp"})
        self.assertEqual({c[2] for c in m}, {"up", "down"})

    def test_order_gate_blocks_until_priors_have_outcomes(self):
        ok, why = wb.trial_may_start("P-4", {})
        self.assertFalse(ok)
        self.assertIn("P-17", why)
        self.assertTrue(wb.trial_may_start("P-17", {})[0])
        self.assertTrue(wb.trial_may_start("P-4", {"P-17": "ADOPT"})[0])
        done = {t: ("NOT_RUN" if wb.TRIALS[t].kind == "binary" else "REJECT") for t in wb.BENCH_ORDER[:wb.BENCH_ORDER.index("P-24")]}
        done.update({t + ".deferral": "own gateway round" for t, v in list(done.items()) if v == "NOT_RUN"})
        ok, why = wb.trial_may_start("P-24", done)
        self.assertFalse(ok)
        self.assertIn("conditional", why)
        done["P-24.condition"] = "met"
        done["P-24.condition_evidence"] = "d" * 64
        self.assertTrue(wb.trial_may_start("P-24", done)[0])
        self.assertFalse(wb.trial_may_start("P-99", {})[0])

    def test_binary_trials_cannot_be_applied_by_this_harness(self):
        with self.assertRaises(wb.ArmError):
            wb.knob_for(wb.TRIALS["P-18"].arms[0])

    def test_plan_lists_every_trial_in_order(self):
        plan = wb.plan_json()
        self.assertEqual([p["id"] for p in plan], list(wb.BENCH_ORDER))
        self.assertTrue(all(p["deferred"] for p in plan if p["kind"] == "binary"))
        json.dumps(plan)


class Schedule(unittest.TestCase):
    def test_every_arm_once_per_rep_and_cell_with_both_bases(self):
        t = wb.TRIALS["P-4"]
        s = wb.schedule(t, 3, 7, "canary")
        self.assertEqual(len(s), 3 * len(t.cells) * (len(t.arms) + 2))
        for rep in (1, 2, 3):
            for cell in t.cells:
                arms = sorted(i["arm"] for i in s if i["rep"] == rep and (i["profile"], i["test"], i["dir"]) == cell)
                self.assertEqual(arms, sorted(wb.arm_names(t)))
        self.assertIn("base_a", wb.arm_names(t))
        self.assertIn("base_b", wb.arm_names(t))

    def test_deterministic_and_seed_sensitive_and_interleaved(self):
        t = wb.TRIALS["P-4"]
        self.assertEqual(wb.schedule(t, 5, 1, "x"), wb.schedule(t, 5, 1, "x"))
        self.assertNotEqual(wb.schedule(t, 5, 1, "x"), wb.schedule(t, 5, 2, "x"))
        firsts = {wb.schedule(t, 1, seed, "x")[0]["arm"] for seed in range(30)}
        self.assertGreater(len(firsts), 1)       # no arm owns the first slot

    def test_only_arms_keeps_both_bases(self):
        t = wb.TRIALS["P-17"]
        s = wb.schedule(t, 2, 1, "canary_confirm", {"ring2048"})
        self.assertEqual({i["arm"] for i in s}, {"base_a", "base_b", "ring2048"})

    def test_roles(self):
        self.assertEqual([wb.role_of(a) for a in ("base_a", "base_b", "fl100")], ["base_a", "base_b", "cand"])


class RuleR(unittest.TestCase):
    t = wb.TRIALS["P-4"]

    def lat(self, **extra):
        d = {"ld_p50_ms": -40.0, "ld_p99_ms": -35.0}
        d.update(extra)
        return d

    def test_latency_win_is_adopted_under_a_and_records_the_gap(self):
        runs = build_runs(self.t, cand={"fl100": self.lat()}, extras={"base_rise": 120.0})
        r = screen("P-4", runs)
        self.assertEqual((r["verdict"], r["chosen"], r["branch"]), ("ADOPT", "fl100", "a"))
        # candidate rise = 190 - 70 = 150 - 40 = 80 on a (idle 70) -> measured from run records
        self.assertTrue(any(n.startswith("profile a: owner bar not met: rise ") and ", gap " in n for n in r["notes"]), r["notes"])
        self.assertTrue(any(n.startswith("base rise at the time of the trial: a ") for n in r["notes"]))
        self.assertTrue(any(n == "item 3 branch (a)" for n in r["notes"]))

    def test_owner_bar_note_has_exact_numbers(self):
        runs = build_runs(self.t, cand={"fl100": {"ld_p50_ms": -40.0, "rise": 77.5}})
        r = screen("P-4", runs)
        self.assertIn("profile a: owner bar not met: rise 77.5 ms, gap 27.5 ms", r["notes"])
        self.assertIn("profile b: owner bar not met: rise 77.5 ms, gap 27.5 ms", r["notes"])

    def test_rise_under_the_bar_reads_met(self):
        runs = build_runs(self.t, cand={"fl100": {"ld_p50_ms": -40.0, "rise": 30.0}})
        r = screen("P-4", runs)
        self.assertEqual(r["verdict"], "ADOPT")
        self.assertIn("profile a: owner bar met: rise 30.0 ms", r["notes"])
        self.assertFalse(any("not met" in n for n in r["notes"]))

    def test_rise_exactly_50_meets_the_bar(self):
        runs = build_runs(self.t, cand={"fl100": {"ld_p50_ms": -40.0, "rise": 50.0}})
        r = screen("P-4", runs)
        self.assertFalse(any("not met" in n for n in r["notes"]))

    def test_latency_candidate_over_the_bar_is_still_adopted_branch_a(self):
        # base rise 300 ms, candidate rise 200 ms: a fall of 100 ms that is still far over the 50 ms bar
        runs = build_runs(self.t, cand={"fl100": {"rise": 200.0}}, extras={"base_rise": 300.0})
        r = screen("P-4", runs)
        self.assertEqual((r["verdict"], r["branch"]), ("ADOPT", "a"))
        self.assertIn("profile a: owner bar not met: rise 200.0 ms, gap 150.0 ms", r["notes"])
        self.assertIn("base rise at the time of the trial: a 300.0 ms, b 300.0 ms", r["notes"])

    def every_arm(self, delta):
        return {a.name: dict(delta) for a in self.t.arms}

    def test_raise_beyond_noise_in_each_metric_rejects(self):
        for metric, delta in (("ld_p50_ms", 5.0), ("ld_p99_ms", 5.0), ("ld_jitter_ms", 1.0), ("ld_loss_pct", 0.5)):
            d = {"ld_p50_ms": -40.0}
            d[metric] = delta
            r = screen("P-4", build_runs(self.t, cand=self.every_arm(d)))
            self.assertEqual(r["verdict"], "REJECT", metric)
            self.assertTrue(any(metric in x for x in r["arms"]["fl100"]["reject"]), metric)
            only = screen("P-4", build_runs(self.t, cand={"fl100": d}))
            self.assertTrue(only["arms"]["fl100"]["reject"], metric)          # rejected, whatever the others do
            self.assertEqual(only["arms"]["fl1024"]["reject"], [])

    def test_raise_exactly_at_noise_is_not_beyond_noise(self):
        # base_b alternates by 2.0 ms on p50, so noise R = 2.0; a +2.0 effect is not beyond it
        runs = build_runs(self.t, cand={"fl100": {"ld_p99_ms": 3.0, "ld_p50_ms": -40.0}})
        r = screen("P-4", runs)
        self.assertEqual(r["arms"]["fl100"]["reject"], [])
        self.assertEqual(r["verdict"], "ADOPT")
        runs = build_runs(self.t, cand={"fl100": {"ld_p99_ms": 3.01, "ld_p50_ms": -40.0}})
        r = screen("P-4", runs)
        self.assertTrue(r["arms"]["fl100"]["reject"])
        self.assertNotEqual(r["chosen"], "fl100")

    def test_fall_within_noise_does_not_serve_the_purpose(self):
        r = screen("P-4", build_runs(self.t, cand={"fl100": {"ld_p50_ms": -1.9}}))
        self.assertEqual(r["verdict"], "NO_PURPOSE")
        r = screen("P-4", build_runs(self.t, cand={"fl100": {"ld_p50_ms": -2.0}}))
        self.assertEqual(r["verdict"], "NO_PURPOSE")           # equal to the spread is not beyond it
        r = screen("P-4", build_runs(self.t, cand={"fl100": {"ld_p50_ms": -2.5}}))
        self.assertEqual(r["verdict"], "ADOPT")

    def test_latency_win_that_lowers_throughput_does_not_serve(self):
        r = screen("P-4", build_runs(self.t, cand={"fl100": {"ld_p50_ms": -40.0, "thr_mbps": -30.0}}))
        self.assertEqual(r["verdict"], "NO_PURPOSE")
        self.assertTrue(r["arms"]["fl100"]["throughput_lower"])

    def test_noise_is_the_base_against_base_spread(self):
        # same -8 ms effect: beyond a 2 ms spread, within a 9 ms spread
        quiet = screen("P-4", build_runs(self.t, cand={"fl100": {"ld_p50_ms": -8.0}}))
        loud = screen("P-4", build_runs(self.t, cand={"fl100": {"ld_p50_ms": -8.0}}, noise={"ld_p50_ms": 9.0}))
        self.assertEqual(quiet["verdict"], "ADOPT")
        self.assertEqual(loud["verdict"], "NO_PURPOSE")

    def test_start_failure_rate_bar_is_base_plus_one_in_200(self):
        t = self.t
        # 12 cells would be 1200 sessions; with 2 cells x 10 reps = 20 candidate sessions
        runs = build_runs(t, cand={"fl100": self.lat()}, failures={"fl100": [(1, "ratchet")]})
        r = screen("P-4", runs, min_reps=5)
        self.assertNotEqual(r["chosen"], "fl100")          # 2 of 20 failed (both cells) = 10 percent
        self.assertTrue(any("start-failure rate" in x for x in r["arms"]["fl100"]["reject"]))
        # exactly 1 in 200: 200 candidate sessions, 1 failure, base clean
        sessions = [{"sessions_started": 199, "sessions_failed": 1}]
        base = [{"sessions_started": 200, "sessions_failed": 0}]
        idx = {("s", "fl100", ("a", "tcp1", "down"), 1): dict(sessions[0], started=True, alive=True, failure_class=None),
               ("s", "base_a", ("a", "tcp1", "down"), 1): dict(base[0], started=True, alive=True, failure_class=None)}
        reasons, counts = wb.session_failure_check(idx, "s", "fl100")
        self.assertEqual(reasons, [])
        idx[("s", "fl100", ("a", "tcp1", "down"), 1)]["sessions_failed"] = 2
        idx[("s", "fl100", ("a", "tcp1", "down"), 1)]["sessions_started"] = 198
        self.assertTrue(wb.session_failure_check(idx, "s", "fl100")[0])

    def test_new_failure_class_rejects_even_at_a_low_rate(self):
        t = self.t
        runs = build_runs(t, cand={"fl100": self.lat()}, failures={"fl100": [(1, "new_class")]})
        for r in runs:                                  # pad sessions so the rate bar alone would pass
            if r["arm"] == "fl100" and r["started"]:
                r["sessions_started"] = 1000
        res = screen("P-4", runs)
        self.assertTrue(any("adds session-failure class new_class" in x for x in res["arms"]["fl100"]["reject"]))
        runs = build_runs(t, cand={"fl100": self.lat()}, failures={"fl100": [(1, "known")], "base_a": [(2, "known")]})
        for r in runs:
            if r["started"]:
                r["sessions_started"] = 1000
        res = screen("P-4", runs)
        self.assertFalse(any("adds session-failure class" in x for x in res["arms"]["fl100"]["reject"]))

    def test_dead_runs_are_left_out_of_the_pairs(self):
        runs = build_runs(self.t, cand={"fl100": self.lat()})
        for r in runs:
            if r["arm"] == "fl100" and r["rep"] <= 3:
                r["alive"] = False
        r = screen("P-4", runs)
        self.assertEqual(r["verdict"], "INCONCLUSIVE")          # 7 pairs left, 10 needed
        r = screen("P-4", runs, min_reps=7)
        self.assertEqual(r["verdict"], "ADOPT")

    def test_not_enough_pairs_is_inconclusive_and_the_base_stays(self):
        r = screen("P-4", build_runs(self.t, reps=4, cand={"fl100": self.lat()}))
        self.assertEqual(r["verdict"], "INCONCLUSIVE")
        self.assertIsNone(r["chosen"])

    def test_one_inconclusive_arm_blocks_naming_a_best(self):
        runs = build_runs(self.t, cand={"fl100": self.lat()})
        runs = [x for x in runs if not (x["arm"] == "fl2048" and x["rep"] > 3)]
        self.assertEqual(screen("P-4", runs)["verdict"], "INCONCLUSIVE")

    def test_best_candidate_goes_forward_and_ties_pick_the_earlier_arm(self):
        runs = build_runs(self.t, cand={"fl100": {"ld_p50_ms": -20.0}, "fl1024": {"ld_p50_ms": -60.0}, "fl2048": {"ld_p50_ms": 30.0}})
        r = screen("P-4", runs)
        self.assertEqual(r["chosen"], "fl1024")
        runs = build_runs(self.t, cand={"fl100": {"ld_p50_ms": -30.0}, "fl1024": {"ld_p50_ms": -30.0}})
        self.assertEqual(screen("P-4", runs)["chosen"], "fl100")

    def test_a_rejected_arm_cannot_be_chosen_however_good_its_p50(self):
        runs = build_runs(self.t, cand={"fl100": {"ld_p50_ms": -90.0, "ld_jitter_ms": 5.0}, "fl1024": {"ld_p50_ms": -10.0}})
        self.assertEqual(screen("P-4", runs)["chosen"], "fl1024")

    def test_every_candidate_rejected_means_reject(self):
        runs = build_runs(self.t, cand={a.name: {"ld_p50_ms": 30.0} for a in self.t.arms})
        r = screen("P-4", runs)
        self.assertEqual(r["verdict"], "REJECT")
        self.assertIsNone(r["chosen"])

    def test_tcp_retransmissions_and_tx_drops_are_not_inputs(self):
        runs = build_runs(self.t, cand={"fl100": self.lat()})
        for r in runs:
            if r["arm"] == "fl100":
                r.update({"retrans": 99999, "tx_drops": 99999, "rcvbuf_errors": 5, "softnet_drops": 7, "inbox_drops": 9})
        self.assertEqual(screen("P-4", runs)["verdict"], "ADOPT")

    def test_awg_xray_clause_for_p10(self):
        t = wb.TRIALS["P-10"]
        good = {"ld_p50_ms": -40.0}
        self.assertEqual(screen("P-10", build_runs(t, cand={"w400_500": good}))["verdict"], "ADOPT")
        for metric, delta in (("awg_mbps", -20.0), ("xray_mbps", -20.0), ("awg_ld_p99_ms", 5.0), ("xray_ld_p99_ms", 5.0)):
            r = screen("P-10", build_runs(t, cand={"w400_500": dict(good, **{metric: delta})}))
            self.assertEqual(r["verdict"], "REJECT", metric)
            self.assertTrue(any(metric in x for x in r["arms"]["w400_500"]["reject"]), metric)

    def test_p10_needs_suricata_awg_and_xray_loaded_at_the_same_time(self):
        t = wb.TRIALS["P-10"]
        runs = build_runs(t, cand={"w400_500": {"ld_p50_ms": -40.0}})
        self.assertEqual(screen("P-10", runs)["verdict"], "ADOPT")
        for drop in ({"suricata": 0.0}, {"awg": None}, "missing"):
            bad = build_runs(t, cand={"w400_500": {"ld_p50_ms": -40.0}})
            for r in bad:
                if drop == "missing":
                    r.pop("background")
                else:
                    r["background"].update(drop)
            res = screen("P-10", bad)
            self.assertEqual(res["verdict"], "INCONCLUSIVE", drop)
            self.assertTrue(any("background load" in x for x in res["arms"]["w400_500"]["inconclusive"]))

    def test_other_trials_do_not_need_background_load(self):
        runs = build_runs(wb.TRIALS["P-4"], cand={"fl100": {"ld_p50_ms": -40.0}})
        self.assertNotIn("background", runs[0])
        self.assertEqual(screen("P-4", runs)["verdict"], "ADOPT")

    def test_p10_without_awg_xray_numbers_is_inconclusive(self):
        t = wb.TRIALS["P-10"]
        runs = build_runs(t, cand={"w400_500": {"ld_p50_ms": -40.0}})
        for r in runs:
            for k in ("awg_mbps", "xray_mbps", "awg_ld_p99_ms", "xray_ld_p99_ms"):
                r.pop(k)
        self.assertEqual(screen("P-10", runs)["verdict"], "INCONCLUSIVE")

    def test_awg_xray_are_checked_when_present_on_any_trial(self):
        runs = build_runs(self.t, cand={"fl100": {"ld_p50_ms": -40.0, "awg_mbps": -30.0}})
        r = screen("P-4", runs)
        self.assertTrue(any("awg_mbps" in x for x in r["arms"]["fl100"]["reject"]))
        self.assertNotEqual(r["chosen"], "fl100")
        runs = build_runs(self.t, cand={"fl100": {"ld_p50_ms": -40.0}})
        for r in runs:
            r.pop("awg_mbps")
        self.assertEqual(screen("P-4", runs)["verdict"], "INCONCLUSIVE")  # the WAN fq carries AWG: mandatory for P-4

    def test_awg_xray_clause_is_mandatory_for_node_wide_knobs_only(self):
        self.assertEqual({t for t, tr in wb.TRIALS.items() if tr.side_traffic}, {"P-3", "P-4", "P-10", "P-22"})
        t = wb.TRIALS["P-22"]
        runs = build_runs(t, cand={"q1514": {"ld_p50_ms": -40.0}})
        for r in runs:
            r.pop("xray_ld_p99_ms")
        self.assertEqual(screen("P-22", runs)["verdict"], "INCONCLUSIVE")
        t = wb.TRIALS["P-17"]
        runs = build_runs(t, stage="aicore_cpu1", venue="aicore", cand={"ring2048": {"ld_p50_ms": -40.0}})
        for r in runs:
            for k in ("awg_mbps", "xray_mbps", "awg_ld_p99_ms", "xray_ld_p99_ms"):
                r.pop(k)
        self.assertEqual(screen("P-17", runs, stage="aicore_cpu1")["verdict"], "ADOPT")   # the aicore rig carries v3 only

    def test_busy_poll_cpu_ceiling_is_five_points(self):
        t = wb.TRIALS["P-3"]
        ok = screen("P-3", build_runs(t, cand={"bp50": {"ld_p50_ms": -40.0, "cpu_total_pct": 5.0}}))
        self.assertEqual(ok["verdict"], "ADOPT")
        bad = screen("P-3", build_runs(t, cand={"bp50": {"ld_p50_ms": -40.0, "cpu_total_pct": 5.1}}))
        self.assertEqual(bad["verdict"], "REJECT")
        self.assertTrue(any("above the 5.0 pp ceiling" in x for x in bad["arms"]["bp50"]["reject"]))

    def test_cpu_is_not_checked_for_other_trials(self):
        runs = build_runs(self.t, cand={"fl100": {"ld_p50_ms": -40.0, "cpu_total_pct": 30.0}})
        self.assertEqual(screen("P-4", runs)["verdict"], "ADOPT")


class RuleRThroughput(unittest.TestCase):
    t = wb.TRIALS["P-24"]

    def test_throughput_gain_with_rise_under_the_bar_is_adopted_under_b(self):
        runs = build_runs(self.t, cand={"noqueue": {"thr_mbps": 60.0, "rise": 40.0}}, extras={"base_rise": 40.0})
        r = screen("P-24", runs, stage="canary")
        self.assertEqual((r["verdict"], r["branch"], r["chosen"]), ("ADOPT", "b", "noqueue"))

    def test_throughput_gain_over_the_bar_is_an_owner_ruling_candidate_not_adopted(self):
        runs = build_runs(self.t, cand={"noqueue": {"thr_mbps": 60.0, "rise": 90.0}}, extras={"base_rise": 90.0})
        r = screen("P-24", runs)
        self.assertEqual(r["verdict"], "OWNER_RULING_CANDIDATE")
        self.assertEqual(r["branch"], "b")
        self.assertTrue(any("nothing is adopted without a ruling" in n for n in r["notes"]))

    def test_over_the_bar_on_one_profile_only_is_enough_to_withhold(self):
        runs = build_runs(self.t, cand={"noqueue": {"thr_mbps": 60.0, "rise": 40.0}}, extras={"base_rise": 40.0})
        self.assertEqual(screen("P-24", runs)["verdict"], "ADOPT")           # 40 ms on both profiles
        for x in runs:
            if x["profile"] == "b":
                x["ld_p50_ms"] += 11.0                                       # every arm: 51 ms on profile b only
        r = screen("P-24", runs)
        self.assertEqual(r["verdict"], "OWNER_RULING_CANDIDATE")
        self.assertIn("profile b: rise 51.0 ms is over the 50 ms limit by 1.0 ms", r["notes"])

    def test_candidate_improving_both_is_judged_under_a(self):
        runs = build_runs(self.t, cand={"noqueue": {"thr_mbps": 60.0, "ld_p50_ms": -30.0}})
        r = screen("P-24", runs)
        self.assertEqual((r["verdict"], r["branch"]), ("ADOPT", "a"))
        self.assertTrue(any("owner bar not met" in n for n in r["notes"]))

    def test_rise_of_a_profile_is_its_worst_cell(self):
        runs = build_runs(self.t, cand={"noqueue": {"thr_mbps": 60.0, "rise": 40.0}}, extras={"base_rise": 40.0})
        for x in runs:
            if x["profile"] == "a" and x["test"] == "tcp4":
                x["ld_p50_ms"] += 20.0                                      # every arm: 60 ms in the 4-flow cell
        r = screen("P-24", runs)
        self.assertEqual(r["verdict"], "OWNER_RULING_CANDIDATE")
        self.assertIn("profile a: rise 60.0 ms is over the 50 ms limit by 10.0 ms", r["notes"])

    def test_an_unmeasured_profile_cannot_pass_branch_b(self):
        runs = build_runs(self.t, cand={"noqueue": {"thr_mbps": 60.0, "rise": 40.0}}, extras={"base_rise": 40.0})
        for x in runs:
            if x["profile"] == "b":
                x.pop("idle_p50_ms")
        r = screen("P-24", runs)
        self.assertEqual(r["verdict"], "OWNER_RULING_CANDIDATE")
        self.assertIn("profile b: rise not measured", r["notes"])

    def test_throughput_gain_within_noise_is_no_purpose(self):
        r = screen("P-24", build_runs(self.t, cand={"noqueue": {"thr_mbps": 9.0}}))
        self.assertEqual(r["verdict"], "NO_PURPOSE")

    def test_throughput_candidate_that_raises_latency_is_rejected(self):
        r = screen("P-24", build_runs(self.t, cand={"noqueue": {"thr_mbps": 60.0, "ld_p50_ms": 8.0}}))
        self.assertEqual(r["verdict"], "REJECT")

    def test_latency_trial_does_not_take_a_throughput_gain_alone(self):
        r = screen("P-4", build_runs(wb.TRIALS["P-4"], cand={"fl100": {"thr_mbps": 80.0}}))
        self.assertEqual(r["verdict"], "NO_PURPOSE")


class MultiStage(unittest.TestCase):
    t = wb.TRIALS["P-17"]

    def runs(self, cpu1, cpu2, confirm=None):
        out = build_runs(self.t, stage="aicore_cpu1", cand=cpu1, venue="aicore")
        out += build_runs(self.t, stage="aicore_cpu2", cand=cpu2, venue="aicore")
        if confirm is not None:
            out += build_runs(self.t, stage="canary_confirm", cand=confirm, venue="canary")
        return out

    def test_arm_must_pass_both_pinned_stages_then_confirm_decides(self):
        win = {"ring2048": {"ld_p50_ms": -60.0}, "ring4096": {"ld_p50_ms": -20.0}}
        d = decide("P-17", self.runs(win, win, {"ring2048": {"ld_p50_ms": -50.0}}))
        self.assertEqual((d["rule_r_verdict"], d["chosen_arm"], d["adoptable"]), ("ADOPT", "ring2048", True))

    def test_pending_confirm_without_canary_runs(self):
        win = {"ring2048": {"ld_p50_ms": -60.0}}
        d = decide("P-17", self.runs(win, win))
        self.assertEqual((d["rule_r_verdict"], d["chosen_arm"], d["adoptable"]), ("PENDING_CONFIRM", "ring2048", False))

    def test_arm_failing_one_pinned_stage_is_dropped(self):
        a = {"ring2048": {"ld_p50_ms": -60.0}, "ring1024": {"ld_p50_ms": -30.0}}
        b = {"ring2048": {"ld_p50_ms": -60.0, "ld_jitter_ms": 5.0}, "ring1024": {"ld_p50_ms": -30.0}}
        d = decide("P-17", self.runs(a, b, {"ring1024": {"ld_p50_ms": -25.0}}))
        self.assertEqual(d["chosen_arm"], "ring1024")

    def test_best_is_by_mean_score_across_pinned_stages(self):
        a = {"ring2048": {"ld_p50_ms": -60.0}, "ring1024": {"ld_p50_ms": -70.0}}
        b = {"ring2048": {"ld_p50_ms": -60.0}, "ring1024": {"ld_p50_ms": -20.0}}
        d = decide("P-17", self.runs(a, b))
        self.assertEqual(d["chosen_arm"], "ring2048")

    def test_confirm_rejection_withholds_adoption(self):
        win = {"ring2048": {"ld_p50_ms": -60.0}}
        d = decide("P-17", self.runs(win, win, {"ring2048": {"ld_p50_ms": 12.0}}))
        self.assertEqual(d["rule_r_verdict"], "REJECT")
        self.assertFalse(d["adoptable"])

    def test_no_survivor_is_no_purpose_or_reject(self):
        d = decide("P-17", self.runs({}, {}))
        self.assertEqual(d["rule_r_verdict"], "NO_PURPOSE")
        d = decide("P-17", self.runs({"ring2048": {"ld_p50_ms": 30.0}, "ring4096": {"ld_p50_ms": 30.0}, "ring1024": {"ld_p50_ms": 30.0}}, {}))
        self.assertEqual(d["rule_r_verdict"], "REJECT")

    def test_inconclusive_screen_stage_is_inconclusive(self):
        win = {"ring2048": {"ld_p50_ms": -60.0}}
        r = build_runs(self.t, stage="aicore_cpu1", reps=3, cand=win, venue="aicore") + build_runs(self.t, stage="aicore_cpu2", cand=win, venue="aicore")
        self.assertEqual(decide("P-17", r)["rule_r_verdict"], "INCONCLUSIVE")

    def test_p24_condition(self):
        def mk(backlog, drops_small, drops_base):
            rs = []
            for arm, drops in (("ring10000", drops_base), ("ring4096", 0), ("ring2048", 0), ("ring1024", drops_small)):
                for rep in range(1, 6):
                    for prof in ("a", "b"):
                        rs.append({"trial": "P-17", "stage": "aicore_cpu1", "arm": arm, "started": True, "alive": True,
                                   "profile": prof, "fq_child_backlog_pkts_max": backlog, "tx_drops": drops})
            return rs
        self.assertTrue(wb.p24_condition(mk(0, 900, 0), "aicore_cpu1")["met"])
        self.assertFalse(wb.p24_condition(mk(50, 900, 0), "aicore_cpu1")["met"])       # backlog is not about 0
        self.assertFalse(wb.p24_condition(mk(0, 0, 0), "aicore_cpu1")["met"])           # drops do not rise
        self.assertFalse(wb.p24_condition(mk(0, 5, 900), "aicore_cpu1")["met"])         # drops fall as the ring shrinks
        self.assertFalse(wb.p24_condition([], "aicore_cpu1")["met"])


class VenueGuard(unittest.TestCase):
    def test_eligibility_rules(self):
        self.assertTrue(wb.venue_eligibility(node_class("canary"))[0])
        self.assertTrue(wb.venue_eligibility(node_class("aicore"))[0])
        for venue in ("tier_b", "l80", "dry_run", "functional", ""):
            ok, reasons = wb.venue_eligibility(node_class(venue))
            self.assertFalse(ok, venue)
            self.assertTrue(reasons)
        ok, reasons = wb.venue_eligibility(node_class("canary", emulated=True))
        self.assertFalse(ok)
        self.assertTrue(any("emulated" in r for r in reasons))
        for key in ("cpu_model", "usable_cpus", "ram_kib", "provider", "binary_sha256"):
            ok, reasons = wb.venue_eligibility(node_class("canary", **{key: None}))
            self.assertFalse(ok, key)
            self.assertTrue(any(key in r for r in reasons))
        self.assertFalse(wb.venue_eligibility(None)[0])

    def test_detect_emulation(self):
        self.assertTrue(wb.detect_emulation("qemu"))                 # TCG: the Tier B guest
        self.assertFalse(wb.detect_emulation("kvm"))                 # a VPS canary is hardware accelerated
        self.assertFalse(wb.detect_emulation("none"))
        self.assertFalse(wb.detect_emulation("microsoft"))
        self.assertTrue(wb.detect_emulation("", "tier_b"))
        self.assertTrue(wb.detect_emulation("KVM", "emulated"))

    def test_adopt_with_ineligible_venue_is_not_adoptable(self):
        t = wb.TRIALS["P-4"]
        runs = build_runs(t, cand={"fl100": {"ld_p50_ms": -40.0}}, venue="tier_b")
        d = decide("P-4", runs, {"canary": node_class("tier_b")})
        self.assertEqual(d["rule_r_verdict"], "ADOPT")
        self.assertFalse(d["adoptable"])
        self.assertTrue(any("NOT ADOPTABLE" in n for n in d["notes"]))

    def test_run_records_with_a_different_venue_than_the_stage_are_not_adoptable(self):
        t = wb.TRIALS["P-4"]
        runs = build_runs(t, cand={"fl100": {"ld_p50_ms": -40.0}}, venue="l80")
        d = decide("P-4", runs)
        self.assertFalse(d["adoptable"])

    def test_stage_venue_mismatch(self):
        t = wb.TRIALS["P-4"]
        d = decide("P-4", build_runs(t, cand={"fl100": {"ld_p50_ms": -40.0}}), {"canary": node_class("aicore")})
        self.assertFalse(d["adoptable"])
        self.assertTrue(any("needs venue canary" in n for n in d["notes"]))

    def test_adoptable_when_everything_holds(self):
        t = wb.TRIALS["P-4"]
        d = decide("P-4", build_runs(t, cand={"fl100": {"ld_p50_ms": -40.0}}))
        self.assertTrue(d["adoptable"])

    def test_emulated_node_class_blocks(self):
        t = wb.TRIALS["P-4"]
        d = decide("P-4", build_runs(t, cand={"fl100": {"ld_p50_ms": -40.0}}), {"canary": node_class("canary", emulated=True)})
        self.assertFalse(d["adoptable"])

    def test_read_node_class_from_proc_and_cgroup(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "proc"))
            os.makedirs(os.path.join(d, "cg", "system.slice", "winn3-gateway.service"))
            open(os.path.join(d, "proc", "cpuinfo"), "w").write("processor\t: 0\nmodel name\t: AMD Ryzen 7 PRO 8845HS\nprocessor\t: 1\n")
            open(os.path.join(d, "proc", "meminfo"), "w").write("MemTotal:        2014208 kB\n")
            open(os.path.join(d, "cg", "cpuset.cpus.effective"), "w").write("0-5\n")
            open(os.path.join(d, "cg", "system.slice", "winn3-gateway.service", "cpuset.cpus.effective"), "w").write("0-1\n")
            binp = os.path.join(d, "gw")
            open(binp, "wb").write(b"binary")
            nc = wb.read_node_class(os.path.join(d, "proc"), os.path.join(d, "cg"), "kvm", "ovh", "canary-x", binp, "canary",
                                    gateway_cgroup="system.slice/winn3-gateway.service")
            self.assertEqual(nc["cpu_model"], "AMD Ryzen 7 PRO 8845HS")
            self.assertEqual(nc["usable_cpus"], 2)              # the gateway's cgroup, not the machine
            self.assertEqual(nc["ram_kib"], 2014208)
            self.assertEqual(nc["max_sessions_default"], 22)
            self.assertEqual(nc["binary_sha256"], wb.sha256_bytes(b"binary"))
            self.assertFalse(nc["emulated"])
            nc2 = wb.read_node_class(os.path.join(d, "proc"), os.path.join(d, "cg"), "", "", "", None, "canary")
            self.assertEqual(nc2["usable_cpus"], 6)             # machine cpuset when no gateway cgroup is named
            self.assertTrue(wb.read_node_class(os.path.join(d, "proc"), os.path.join(d, "cg"), "qemu", "", "", None, "tier_b")["emulated"])
            text = json.dumps(nc)
            self.assertNotIn(socket.gethostname(), text.replace("canary-x", ""))

    def test_arm64_cpu_model_fallback(self):
        self.assertEqual(wb.cpu_model("CPU implementer\t: 0x61\nCPU part\t: 0x023\n"), "arm64 implementer 0x61 part 0x023")
        self.assertIsNone(wb.cpu_model("processor : 0\n"))


class ConnectTime(unittest.TestCase):
    def rows(self, totals_s, nc="c1", net="wifi", stages=None, ok=None):
        out = []
        for i, t in enumerate(totals_s):
            r = {"node_class": nc, "network": net, "ok": True if ok is None else ok[i], "total_ms": t * 1000.0,
                 "endpoint": "first_dns_answer"}
            if stages:
                r["stages_ms"] = {k: v * 1000.0 for k, v in stages.items()}
            out.append(r)
        return out

    def both(self, totals, **kw):
        return self.rows(totals, net="wifi", **kw) + self.rows(totals, net="cellular", **kw)

    def test_pass_at_exactly_four_seconds(self):
        t = [3.0] * 9 + [4.0]
        self.assertEqual(wb.analyze_connect_time(self.both(t))["verdict"], "PASS")

    def test_miss_just_over_four_seconds(self):
        t = [3.0] * 9 + [4.001]
        r = wb.analyze_connect_time(self.both(t))
        self.assertNotEqual(r["verdict"], "PASS")
        self.assertEqual(r["groups"]["c1|wifi"]["verdict"], "MISS")

    def test_p95_of_ten_runs_is_the_slowest_run(self):
        t = [1.0] * 9 + [9.0]
        self.assertEqual(wb.analyze_connect_time(self.both(t))["groups"]["c1|wifi"]["p95_s"], 9.0)

    def test_a_failed_run_counts_as_infinitely_slow(self):
        ok = [True] * 9 + [False]
        r = wb.analyze_connect_time(self.rows([1.0] * 10, ok=ok) + self.rows([1.0] * 10, net="cellular"))
        self.assertEqual(r["groups"]["c1|wifi"]["verdict"], "MISS")
        self.assertEqual(r["groups"]["c1|wifi"]["failures"], 1)

    def test_a_missing_total_counts_as_a_failure(self):
        rows = self.rows([1.0] * 10)
        rows[0]["total_ms"] = None
        rows[0]["ok"] = True
        r = wb.analyze_connect_time(rows + self.rows([1.0] * 10, net="cellular"))
        self.assertEqual(r["groups"]["c1|wifi"]["failures"], 1)

    def test_ten_runs_per_network_type_and_node_class_are_required(self):
        r = wb.analyze_connect_time(self.rows([1.0] * 9) + self.rows([1.0] * 10, net="cellular"))
        self.assertEqual(r["verdict"], "INSUFFICIENT_RUNS")
        self.assertEqual(r["groups"]["c1|wifi"]["verdict"], "INSUFFICIENT_RUNS")
        r = wb.analyze_connect_time(self.rows([1.0] * 10))                   # cellular missing entirely
        self.assertEqual(r["verdict"], "INSUFFICIENT_RUNS")
        self.assertEqual(r["groups"]["c1|cellular"]["n"], 0)
        self.assertEqual(wb.analyze_connect_time([])["verdict"], "INSUFFICIENT_RUNS")

    def test_every_node_class_must_pass(self):
        rows = self.both([1.0] * 10, nc="c1") + self.both([1.0] * 9 + [5.0], nc="c2")
        r = wb.analyze_connect_time(rows)
        self.assertNotEqual(r["verdict"], "PASS")
        self.assertEqual(r["groups"]["c1|wifi"]["verdict"], "PASS")
        self.assertEqual(r["groups"]["c2|cellular"]["verdict"], "MISS")

    STAGES = {"hub_config_fetch": 2.0, "allocation": 0.5, "handshake": 1.0, "first_carried_packet": 1.0}

    def test_miss_with_a_slower_stage_than_baseline_blocks_s7(self):
        slow = [dict(self.STAGES, hub_config_fetch=3.5)]
        rows = []
        for net in ("wifi", "cellular"):
            rows += self.rows([5.0] * 10, net=net, stages=slow[0])
        base = []
        for net in ("wifi", "cellular"):
            for i in range(10):
                base += self.rows([4.0], net=net, stages=dict(self.STAGES, hub_config_fetch=2.0 + 0.05 * i))
        r = wb.analyze_connect_time(rows, base)
        g = r["groups"]["c1|wifi"]
        self.assertEqual(g["miss_class"], "BLOCKS_S7")
        self.assertEqual(g["slower_stages"], ["hub_config_fetch"])
        self.assertEqual(r["verdict"], "MISS_BLOCKS_S7")
        self.assertTrue(r["blocks_s7"])
        self.assertIn("p95_s", g["breakdown"]["handshake"])

    def test_miss_within_baseline_noise_is_an_owner_target_gap_that_opens_a_gateway_round(self):
        rows, base = [], []
        for net in ("wifi", "cellular"):
            rows += self.rows([4.5] * 10, net=net, stages=self.STAGES)
            for i in range(10):
                base += self.rows([4.5], net=net, stages={k: v + 0.1 * ((i % 3) - 1) for k, v in self.STAGES.items()})
        r = wb.analyze_connect_time(rows, base)
        self.assertEqual(r["groups"]["c1|wifi"]["miss_class"], "OWNER_TARGET_GAP")
        self.assertEqual(r["verdict"], "MISS_OWNER_TARGET_GAP")
        self.assertFalse(r["blocks_s7"])
        self.assertTrue(r["opens_gateway_round"])

    def test_delta_equal_to_baseline_noise_is_not_slower(self):
        base = []
        for i in range(10):
            base += self.rows([4.5], stages=dict(self.STAGES, handshake=1.0 + 0.1 * (i % 2)))
        rows = self.rows([4.5] * 10, stages=dict(self.STAGES, handshake=1.1))
        r = wb.analyze_connect_time(rows + self.rows([1.0] * 10, net="cellular"), base)
        self.assertEqual(r["groups"]["c1|wifi"]["slower_stages"], [])      # delta 0.05 against noise 0.1

    def test_miss_without_a_baseline_blocks_until_one_exists(self):
        r = wb.analyze_connect_time(self.both([5.0] * 10, stages=self.STAGES))
        self.assertEqual(r["groups"]["c1|wifi"]["miss_class"], "NEEDS_BASELINE")
        self.assertTrue(r["blocks_s7"])

    def test_ct4m_adapter_maps_phases_skips_switches_and_keeps_errors(self):
        rows = [{"server": "x", "kind": "cold", "handler": 0.05, "candidate": 3.35, "datapath": 3.6, "gate_carrying": 4.1,
                 "carry": 4.6, "ping_carry": 4.9},
                {"server": "x", "kind": "switch", "carry": 1.0}, {"server": "x", "kind": "cold", "error": "no t0"},
                {"server": "x", "kind": "warm", "handler": 0.05, "candidate": 0.4, "datapath": 0.5, "gate_carrying": 1.0, "carry": 1.5}]
        out = wb.connect_rows_from_ct4m(rows, "c1", "wifi")
        self.assertEqual(len(out), 3)
        self.assertEqual((out[1]["ok"], out[1]["total_ms"], out[1]["error"]), (False, None, "no t0"))
        out = [out[0], out[2]]
        self.assertEqual([r["endpoint"] for r in out], ["first_ping_reply", "first_delivered_packet"])
        self.assertEqual(out[0]["total_ms"], 4900.0)
        self.assertEqual(out[0]["stages_ms"]["hub_config_fetch"], 3300.0)
        self.assertEqual(out[0]["stages_ms"]["handshake"], 500.0)
        self.assertEqual(out[0]["stages_ms"]["first_carried_packet"], 800.0)
        self.assertNotIn("allocation", out[0]["stages_ms"])
        self.assertEqual(out[1]["total_ms"], 1500.0)
        self.assertTrue(out[1]["ok"])


class Storm(unittest.TestCase):
    def rec(self, **kw):
        r = {"mem_total_kib": 1967 * 1024, "max_sessions": 22, "fio_p99_ms": 9.5, "sessions_tested": 22,
             "restart_to_carrying_s": [1.0] * 10, "over_capacity_attempts": 4, "over_capacity_refusals": 4}
        r.update(kw)
        return r

    def test_chicago_uses_22_sessions(self):
        r = wb.analyze_storm(self.rec())
        self.assertEqual(r["sessions_expected"], 22)
        self.assertEqual(r["verdict"], "NO_GROUP_COMMIT")

    def test_storm_size_is_min_64_and_max_sessions(self):
        r = wb.analyze_storm(self.rec(sessions_tested=64))
        self.assertEqual(r["verdict"], "WRONG_STORM_SIZE")
        r = wb.analyze_storm(self.rec(mem_total_kib=64 * 1024 * 1024, max_sessions=64, sessions_tested=64))
        self.assertEqual(r["sessions_expected"], 64)
        r = wb.analyze_storm(self.rec(mem_total_kib=64 * 1024 * 1024, max_sessions=100, sessions_tested=64))
        self.assertEqual(r["verdict"], "HOST_FIT_WAIVED")

    def test_host_fit_is_never_waived(self):
        r = wb.analyze_storm(self.rec(max_sessions=64, sessions_tested=64))      # 64 on a 1967 MiB node
        self.assertEqual(r["verdict"], "HOST_FIT_WAIVED")

    def test_group_commit_only_when_p95_is_over_two_seconds(self):
        self.assertEqual(wb.analyze_storm(self.rec(restart_to_carrying_s=[2.0] * 10))["verdict"], "NO_GROUP_COMMIT")
        self.assertEqual(wb.analyze_storm(self.rec(restart_to_carrying_s=[1.0] * 9 + [2.01]))["verdict"], "GROUP_COMMIT_PROPOSED")

    def test_a_timeout_counts_as_the_30_second_limit(self):
        r = wb.analyze_storm(self.rec(restart_to_carrying_s=[1.0] * 9 + [None]))
        self.assertEqual(r["storm_p95_s"], 30.0)
        self.assertEqual(r["timeouts"], 1)
        r = wb.analyze_storm(self.rec(restart_to_carrying_s=[1.0] * 9 + [99.0]))
        self.assertEqual(r["storm_p95_s"], 30.0)

    def test_too_few_runs(self):
        self.assertEqual(wb.analyze_storm(self.rec(restart_to_carrying_s=[1.0] * 3))["verdict"], "INSUFFICIENT_RUNS")

    def test_over_capacity_attempts_are_four(self):
        r = wb.analyze_storm(self.rec(over_capacity_attempts=3))
        self.assertTrue(any("4 attempts" in n for n in r["notes"]))

    def test_fio_parse(self):
        doc = {"jobs": [{"sync": {"lat_ns": {"percentile": {"99.000000": 12500000}}}}]}
        self.assertAlmostEqual(wb.parse_fio_fsync_p99_ms(json.dumps(doc)), 12.5)
        with self.assertRaises(ValueError):
            wb.parse_fio_fsync_p99_ms(json.dumps({"jobs": [{}]}))


class GoLive(unittest.TestCase):
    def installs(self, n=10, wall=100.0, proof_lag=10.0):
        out = []
        for i in range(n):
            done = 1000.0 + i
            out.append({"deployment_completed_at": done, "operator_enabled_at": done + wall,
                        "proofs": {p: done + proof_lag for p in wb.GOLIVE_PROOFS}})
        return out

    def test_pass_under_180_seconds_at_p95(self):
        r = wb.analyze_golive(self.installs())
        self.assertEqual(r["verdict"], "PASS")

    def test_p95_over_the_budget_is_a_miss(self):
        i = self.installs()
        i[0]["operator_enabled_at"] = i[0]["deployment_completed_at"] + 180.5
        self.assertEqual(wb.analyze_golive(i)["verdict"], "MISS")
        i[0]["operator_enabled_at"] = i[0]["deployment_completed_at"] + 180.0
        self.assertEqual(wb.analyze_golive(i)["verdict"], "PASS")

    def test_every_proof_must_be_newer_than_completion(self):
        for lag in (0.0, -5.0):
            r = wb.analyze_golive(self.installs(proof_lag=lag))
            self.assertEqual(r["verdict"], "PROOF_NOT_NEWER_THAN_COMPLETION", lag)
            self.assertEqual(len(r["stale_proofs"]), 10 * len(wb.GOLIVE_PROOFS))

    def test_one_stale_proof_is_enough(self):
        i = self.installs()
        i[4]["proofs"]["v3_canary"] = i[4]["deployment_completed_at"] - 1
        r = wb.analyze_golive(i)
        self.assertEqual(r["verdict"], "PROOF_NOT_NEWER_THAN_COMPLETION")
        self.assertEqual(r["stale_proofs"][0]["proof"], "v3_canary")

    def test_missing_proof_or_enable_time(self):
        i = self.installs()
        del i[2]["proofs"]["offnode_gate"]
        self.assertEqual(wb.analyze_golive(i)["verdict"], "MISSING_PROOF")
        i = self.installs()
        i[2]["operator_enabled_at"] = None
        self.assertEqual(wb.analyze_golive(i)["verdict"], "MISSING_PROOF")

    def test_ten_installs_are_needed(self):
        self.assertEqual(wb.analyze_golive(self.installs(9))["verdict"], "INSUFFICIENT_INSTALLS")

    def test_required_proofs_are_the_design_set(self):
        self.assertEqual(set(wb.GOLIVE_PROOFS), {"served_profile_canary", "awg_carry_udp", "awg_carry_stealth",
                                                 "awg_carry_stealth_tls", "v3_canary", "offnode_gate"})


class Ryzen(unittest.TestCase):
    def runs(self, up=1900.0, down=1900.0, n=10, **kw):
        out = []
        for d, v in (("up", up), ("down", down)):
            for i in range(n):
                r = {"dir": d, "mbps": v + i, "flows": 4, "seconds": 20, "profile": "none", "gw_cpu_per_core": [90.0, 80.0, 70.0],
                     "ld_p50_ms": 5.0, "ld_p99_ms": 9.0, "ld_jitter_ms": 1.0, "ld_loss_pct": 0.0}
                r.update(kw)
                out.append(r)
        return out

    def test_pass_when_both_medians_reach_1800(self):
        self.assertEqual(wb.analyze_ryzen(self.runs(), "lane")["verdict"], "PASS")

    def test_median_not_the_best_run(self):
        r = wb.analyze_ryzen(self.runs(up=1795.0), "lane")
        self.assertEqual(r["dirs"]["up"]["median_mbps"], 1799.5)
        self.assertEqual(r["verdict"], "MISS")

    def test_a_miss_records_shortfall_cpu_and_the_gateway_rounds(self):
        r = wb.analyze_ryzen(self.runs(down=1000.0), "lane")
        self.assertEqual(r["verdict"], "MISS")
        d = r["dirs"]["down"]
        self.assertAlmostEqual(d["shortfall_mbps"], 800.0 - 4.5)
        self.assertEqual(d["gw_cpu_per_core_median"], [90.0, 80.0, 70.0])
        self.assertEqual(r["opens_gateway_round"], ["P-18", "P-20", "P-21", "P-25"])
        self.assertIn("nothing", r["blocks"])

    def test_both_directions_must_pass(self):
        self.assertEqual(wb.analyze_ryzen(self.runs(up=2000.0, down=1500.0), "lane")["verdict"], "MISS")

    def test_run_shape_is_enforced(self):
        self.assertEqual(wb.analyze_ryzen(self.runs(n=9), "lane")["verdict"], "INVALID_RUN")
        self.assertEqual(wb.analyze_ryzen(self.runs(flows=1), "lane")["verdict"], "INVALID_RUN")
        self.assertEqual(wb.analyze_ryzen(self.runs(seconds=10), "lane")["verdict"], "INVALID_RUN")
        self.assertEqual(wb.analyze_ryzen(self.runs(profile="a"), "lane")["verdict"], "INVALID_RUN")   # netem shaper still on
        self.assertEqual(wb.analyze_ryzen(self.runs(), None)["verdict"], "INVALID_RUN")                  # no bench lock owner

    def test_loaded_latency_is_recorded(self):
        d = wb.analyze_ryzen(self.runs(), "lane")["dirs"]["up"]
        self.assertEqual(d["ld_p99_ms_median"], 9.0)


class Epoll(unittest.TestCase):
    TABLE = ("% time     seconds  usecs/call     calls    errors syscall\n"
             "------ ----------- ----------- --------- --------- ----------------\n"
             " 61.20    0.012000          12      1000           futex\n"
             "  0.10    0.000010           3         @CALLS@         1 epoll_ctl\n"
             "------ ----------- ----------- --------- --------- ----------------\n")

    @classmethod
    def table(cls, calls):
        return cls.TABLE.replace("@CALLS@", str(calls))

    def test_parse(self):
        self.assertEqual(wb.parse_strace_summary(self.table(7)), 7)
        head = self.TABLE.splitlines()[0] + "\n"
        self.assertEqual(wb.parse_strace_summary(head + " 61.20    0.012000          12      1000           futex\n"), 0)
        no_errors = "  0.10    0.000010           3         4           epoll_ctl\n"
        self.assertEqual(wb.parse_strace_summary(head + no_errors), 4)

    def test_decline_confirmed_at_a_few_calls(self):
        self.assertEqual(wb.analyze_epoll(self.table(10), 20, True)["verdict"], "DECLINE_CONFIRMED")
        self.assertEqual(wb.analyze_epoll(self.table(11), 20, True)["verdict"], "REOPEN_PERF1")

    def test_run_must_be_a_20_second_attach_after_startup(self):
        self.assertEqual(wb.analyze_epoll(self.table(1), 19.9, True)["verdict"], "INVALID_RUN")
        self.assertEqual(wb.analyze_epoll(self.table(1), 20, False)["verdict"], "INVALID_RUN")


class QueueRestarts(unittest.TestCase):
    def rec(self, kind="restart", **kw):
        r = {"kind": kind, "main_pid": 5, "ifindex": 9, "state": {"result": "ok", "main_pid": 5, "ifindex": 9},
             "helper_runs": 1, "children_match": True, "qlen": 10000}
        r.update(kw)
        return r

    def good(self):
        return [self.rec("kill" if i % 5 == 4 else "restart") for i in range(20)] + [self.rec("reboot") for _ in range(3)]

    def test_pass_at_20_of_20_and_3_of_3(self):
        r = wb.analyze_queue_restarts(self.good(), systemd_version="systemd 255 (255.4-1ubuntu8.15)")
        self.assertEqual(r["verdict"], "PASS", r["problems"])
        self.assertEqual((r["restart_matches"], r["reboot_matches"], r["kill_records"]), (20, 3, 4))

    def test_every_shortfall_fails(self):
        v = "systemd 255"
        self.assertEqual(wb.analyze_queue_restarts(self.good()[1:], systemd_version=v)["verdict"], "FAIL")          # 19 restarts
        self.assertEqual(wb.analyze_queue_restarts(self.good()[:-1], systemd_version=v)["verdict"], "FAIL")         # 2 reboots
        self.assertEqual(wb.analyze_queue_restarts(self.good(), systemd_version=None)["verdict"], "FAIL")
        no_kill = [self.rec("restart") for _ in range(20)] + [self.rec("reboot") for _ in range(3)]
        r = wb.analyze_queue_restarts(no_kill, systemd_version=v)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertTrue(any("kill" in p for p in r["problems"]))
        self.assertEqual(wb.analyze_queue_restarts(self.good() + [self.rec("weird")], systemd_version=v)["verdict"], "FAIL")

    def test_each_mismatch_kind_fails(self):
        v = "systemd 255"
        for change in ({"state": {"result": "ok", "main_pid": 4, "ifindex": 9}},      # stale MainPID
                       {"state": {"result": "ok", "main_pid": 5, "ifindex": 8}},      # stale ifindex
                       {"state": {"result": "failed", "main_pid": 5, "ifindex": 9}},
                       {"state": None}, {"helper_runs": 2}, {"helper_runs": 0}, {"children_match": False},
                       {"children_match": None}, {"qlen": 9999}, {"main_pid": None}):
            recs = self.good()
            recs[7] = dict(recs[7], **change)
            self.assertEqual(wb.analyze_queue_restarts(recs, systemd_version=v)["verdict"], "FAIL", change)
            recs = self.good()
            recs[21] = dict(recs[21], **change)
            self.assertEqual(wb.analyze_queue_restarts(recs, systemd_version=v)["verdict"], "FAIL", change)

    def test_ring_value_is_the_expected_qlen(self):
        recs = [dict(r, qlen=2048) for r in self.good()]
        self.assertEqual(wb.analyze_queue_restarts(recs, expect_qlen=2048, systemd_version="s")["verdict"], "PASS")
        self.assertEqual(wb.analyze_queue_restarts(recs, systemd_version="s")["verdict"], "FAIL")

    def clock(self):
        t = [0.0]

        def tick():
            t[0] += 1.0
            return t[0]
        return tick

    def test_restart_once_reads_the_new_incarnation(self):
        fs = FakeSystem()
        for kind in ("restart", "kill"):
            rec = wb.restart_once(fs, kind, clock=self.clock())
            self.assertTrue(wb.queue_record_matches(rec), rec)
            self.assertEqual(rec["main_pid"], fs.gw_pid)
        self.assertTrue(any(l == "systemctl kill -s KILL winn3-gateway.service" for l in fs.log))
        self.assertTrue(any(l == "systemctl restart winn3-gateway.service" for l in fs.log))

    def test_a_helper_that_never_wrote_state_or_ran_twice_is_a_mismatch(self):
        fs = FakeSystem()
        fs.helper_writes_state = False
        rec = wb.restart_once(fs, "restart", clock=self.clock(), wait_s=3)
        self.assertFalse(wb.queue_record_matches(rec))
        fs = FakeSystem()
        fs.helper_runs = 2
        rec = wb.restart_once(fs, "restart", clock=self.clock())
        self.assertEqual(rec["helper_runs"], 2)
        self.assertFalse(wb.queue_record_matches(rec))

    def test_a_stale_state_file_from_the_old_pid_is_not_accepted(self):
        fs = FakeSystem()
        fs.helper_writes_state = False
        fs.files[wb.QUEUE_STATE_PATH] = json.dumps({"result": "ok", "main_pid": 100, "ifindex": 7})
        rec = wb.restart_once(fs, "restart", clock=self.clock(), wait_s=3)
        self.assertFalse(wb.queue_record_matches(rec))

    def test_cli_analysis_and_execute_guard(self):
        c = Cli()
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "q.json")
            json.dump(self.good(), open(f, "w"))
            rc, out = c.call("queue-restarts", "--input", f, "--systemd-version", "systemd 255")
            self.assertEqual(json.loads(out)["verdict"], "PASS")
        with self.assertRaises(SystemExit):
            c.call("queue-restarts", "--execute")


class HubCost(unittest.TestCase):
    def test_cpu_seconds_per_hour(self):
        self.assertAlmostEqual(wb.cpu_seconds_per_hour(0, 2_000_000, 600), 12.0)
        for bad in ((0, 1, 0), (5, 1, 10)):
            with self.assertRaises(ValueError):
                wb.cpu_seconds_per_hour(*bad)

    def rec(self, after_ms=4.0, slugs=64):
        w = lambda a, b: {"usage_usec_start": 0, "usage_usec_end": a, "wall_s": b}
        return {"slugs": slugs, "units": {"hub": {"before": w(6_000_000, 600), "after": w(3_000_000, 600)}},
                "inner_addresses_in_use_ms": {"before": 40.0, "after": after_ms}, "p16_probe_cpu_fraction": 0.01}

    def test_p23_only_if_still_over_10_ms_after_the_cache(self):
        self.assertFalse(wb.analyze_hub_cost(self.rec(10.0))["p23_needed"])
        self.assertTrue(wb.analyze_hub_cost(self.rec(10.1))["p23_needed"])

    def test_cpu_before_and_after(self):
        u = wb.analyze_hub_cost(self.rec())["units"]["hub"]
        self.assertTrue(u["lower_after"])
        self.assertAlmostEqual(u["before_cpu_s_per_hour"], 36.0)

    def test_needs_64_slugs(self):
        self.assertEqual(wb.analyze_hub_cost(self.rec(slugs=10))["verdict"], "INVALID_RUN")

    def test_p16_bound(self):
        r = self.rec()
        r["p16_probe_cpu_fraction"] = 0.03
        self.assertFalse(wb.analyze_hub_cost(r)["p16_under_2_percent_of_one_core"])


class ArmControl(unittest.TestCase):
    def test_flow_limit_arms_apply_read_back_and_revert(self):
        fs = FakeSystem()
        c = controller(fs, "P-4")
        c.begin()
        for name, want in (("base_a", 256), ("fl100", 100), ("fl1024", 1024), ("fl2048", 2048), ("base_b", 256)):
            c.switch(name)
            self.assertEqual(wan_flow(fs), want, name)
            self.assertEqual(fs.qdisc["eth0"][0]["options"]["limit"], 20480)       # nothing else moved
            self.assertEqual(fs.qdisc["eth0"][0]["options"]["quantum"], 1280)
        c.finish()
        self.assertEqual(fs.qdisc["eth0"][0]["options"], FQ_DEFAULT)

    def test_revert_restores_a_live_value_that_was_not_the_base(self):
        fs = FakeSystem()
        fs.qdisc["eth0"][0]["options"]["flow_limit"] = 100          # UK, Oregon: live 100
        c = controller(fs, "P-4")
        c.begin()
        c.switch("base_a")
        self.assertEqual(wan_flow(fs), 256)                          # the base arm is applied explicitly
        c.switch("fl2048")
        c.finish()
        self.assertEqual(wan_flow(fs), 100)

    def test_quantum_arm(self):
        fs = FakeSystem()
        c = controller(fs, "P-22")
        c.begin()
        c.switch("q1514")
        self.assertEqual(fs.qdisc["eth0"][0]["options"]["quantum"], 1514)
        self.assertEqual(wan_flow(fs), 256)
        c.finish()
        self.assertEqual(fs.qdisc["eth0"][0]["options"]["quantum"], 1280)

    def test_other_fq_options_survive_including_maxrate(self):
        fs = FakeSystem()
        fs.qdisc["eth0"][0]["options"]["maxrate"] = 12500000
        c = controller(fs, "P-4")
        c.begin()
        c.switch("fl1024")
        self.assertEqual(fs.qdisc["eth0"][0]["options"]["maxrate"], 12500000)
        self.assertIn("maxrate 12500000bps", "\n".join(fs.log))
        c.finish()

    def test_ring_arms(self):
        fs = FakeSystem()
        c = controller(fs, "P-17")
        c.begin()
        for name, want in (("ring4096", 4096), ("ring2048", 2048), ("ring1024", 1024), ("base_a", 10000)):
            c.switch(name)
            self.assertEqual(fs.qlen["winn3gw0"], want)
        c.switch("ring1024")
        fs.qlen["winn3gw0"] = 777
        c.finish()
        self.assertEqual(fs.qlen["winn3gw0"], 10000)

    def test_ring_revert_restores_the_captured_value_whatever_it_was(self):
        fs = FakeSystem()
        fs.qlen["winn3gw0"] = 7777
        c = controller(fs, "P-17")
        c.begin()
        c.switch("ring2048")
        c.finish()
        self.assertEqual(fs.qlen["winn3gw0"], 7777)

    def test_noqueue_revert_restores_a_qlen_the_kernel_reset(self):
        fs = FakeSystem()
        fs.noqueue_resets_qlen = True
        c = controller(fs, "P-24")
        c.begin()
        with self.assertRaises(wb.ArmError) as cm:
            c.switch("noqueue")                                             # the read-back sees qlen move
        self.assertIn("txqueuelen changed", str(cm.exception))
        self.assertEqual(fs.qlen["winn3gw0"], 10000)                         # the failed switch still reverted it
        self.assertEqual([q["kind"] for q in fs.qdisc["winn3gw0"]][0], "mq")

    def test_noqueue_arm_and_revert_rebuilds_the_mq_tree(self):
        fs = FakeSystem()
        before = wb.tree_signature(wb.parse_qdisc_json(json.dumps(fs.qdisc["winn3gw0"])))
        c = controller(fs, "P-24")
        c.begin()
        c.switch("noqueue")
        self.assertEqual([q["kind"] for q in fs.qdisc["winn3gw0"]], ["noqueue"])
        self.assertEqual(fs.qlen["winn3gw0"], 10000)
        c.switch("base_a")
        self.assertEqual(wb.tree_signature(wb.parse_qdisc_json(json.dumps(fs.qdisc["winn3gw0"]))), before)
        c.switch("noqueue")
        c.finish()
        self.assertEqual(wb.tree_signature(wb.parse_qdisc_json(json.dumps(fs.qdisc["winn3gw0"]))), before)

    def test_busy_poll_arm_restores_the_original_values_not_zero(self):
        fs = FakeSystem()
        fs.sysctl.update({"net.core.busy_poll": "20", "net.core.busy_read": "30"})
        c = controller(fs, "P-3")
        c.begin()
        c.switch("bp50")
        self.assertEqual((fs.sysctl["net.core.busy_poll"], fs.sysctl["net.core.busy_read"]), ("50", "50"))
        c.switch("base_a")
        self.assertEqual((fs.sysctl["net.core.busy_poll"], fs.sysctl["net.core.busy_read"]), ("0", "0"))
        c.switch("bp50")
        c.finish()
        self.assertEqual((fs.sysctl["net.core.busy_poll"], fs.sysctl["net.core.busy_read"]), ("20", "30"))

    def test_cgroup_weight_arm_restores_not_set_and_numbers(self):
        fs = FakeSystem()
        c = controller(fs, "P-10")
        c.begin()
        c.switch("w400_500")
        self.assertEqual((fs.units["winn3-gateway.service"]["CPUWeight"], fs.units["winn3-gateway.service"]["IOWeight"]), ("400", "500"))
        c.switch("base_a")
        self.assertEqual(fs.units["winn3-gateway.service"]["CPUWeight"], "100")
        c.switch("w400_500")
        c.finish()
        self.assertEqual((fs.units["winn3-gateway.service"]["CPUWeight"], fs.units["winn3-gateway.service"]["IOWeight"]), ("[not set]", "[not set]"))
        fs2 = FakeSystem()
        fs2.units["winn3-gateway.service"].update({"CPUWeight": "250", "IOWeight": "300"})
        c = controller(fs2, "P-10")
        c.begin()
        c.switch("w400_500")
        c.finish()
        self.assertEqual((fs2.units["winn3-gateway.service"]["CPUWeight"], fs2.units["winn3-gateway.service"]["IOWeight"]), ("250", "300"))

    def test_unit_not_loaded_is_refused_before_any_change(self):
        fs = FakeSystem()
        c = wb.ArmController(fs, wb.Target(unit="missing.service"), wb.TRIALS["P-10"])
        with self.assertRaises(wb.ArmError):
            c.begin()
        self.assertEqual(fs.mutations(), [])
        self.assertEqual(fs.files, {})

    def test_plan_script_and_marker_exist_before_the_first_change(self):
        fs = FakeSystem()
        c = controller(fs, "P-4", dead_man_minutes=45)
        c.begin()
        c.switch("fl1024")
        first_change = fs.mutations()[0]
        for what in ("revert-P-4-20261007T000000Z.json", "revert-P-4-20261007T000000Z.sh", "perf-trial.env"):
            self.assertLess(fs.index_of(what), first_change, what)
        self.assertLess(fs.index_of("systemd-run"), first_change)
        self.assertIn("/etc/winsvpn/perf-trial.env", fs.files)
        self.assertIn("WINS_PERF_TRIAL=P-4/fl1024", fs.files["/etc/winsvpn/perf-trial.env"])
        plan = json.loads(fs.files[c.plan_path])
        self.assertEqual(plan["trial"], "P-4")
        self.assertTrue(plan["plan"])
        c.finish()

    def test_dead_man_timer_is_set_and_cancelled(self):
        fs = FakeSystem()
        c = controller(fs, "P-4", dead_man_minutes=45)
        c.begin()
        self.assertEqual(len(fs.timers), 1)
        self.assertTrue(any("--on-active=45m" in l for l in fs.log))
        c.finish()
        self.assertEqual(fs.timers, set())
        fs = FakeSystem()
        c = controller(fs, "P-4")
        c.begin()
        self.assertEqual(fs.timers, set())          # none requested

    def test_a_marker_that_cannot_be_written_stops_the_trial_and_the_timer(self):
        fs = FakeSystem()
        fs.fail.append(("tee /etc/winsvpn/perf-trial.env", 1))
        c = controller(fs, "P-4", dead_man_minutes=30)
        with self.assertRaises(wb.ArmError):
            c.begin()
        self.assertEqual(fs.timers, set())
        self.assertEqual(fs.mutations(), [])
        with self.assertRaises(wb.ArmError):
            c.switch("fl100")                                       # the trial never began

    def test_the_marker_directory_is_created_first(self):
        fs = FakeSystem()
        controller(fs, "P-4").begin()
        self.assertLess(fs.index_of("install -d -m 0755 /etc/winsvpn"), fs.index_of("tee /etc/winsvpn/perf-trial.env"))

    def test_finish_removes_the_marker_and_is_idempotent(self):
        fs = FakeSystem()
        c = controller(fs, "P-4")
        c.begin()
        c.switch("fl2048")
        c.finish()
        self.assertNotIn("/etc/winsvpn/perf-trial.env", fs.files)
        n = len(fs.log)
        c.finish()
        self.assertEqual(len(fs.log), n)

    def test_revert_script_text(self):
        fs = FakeSystem()
        c = controller(fs, "P-4")
        plan = c.begin()
        script = fs.files[c.script_path]
        self.assertTrue(script.startswith("#!/bin/sh\n"))
        self.assertIn("set +e", script)
        for cmd in plan:
            self.assertIn(shlex.join(cmd) + " || fail=1", script)
        self.assertIn('if [ "$fail" -eq 0 ]; then rm -f /etc/winsvpn/perf-trial.env || fail=1; fi', script)
        self.assertTrue(script.rstrip().endswith('exit "$fail"'))
        # quoting survives an argument with a space
        s = wb.revert_script("T", [["echo", "a b", "c;d"]])
        self.assertIn("echo 'a b' 'c;d'", s)

    def test_a_failing_apply_reverts_and_raises(self):
        fs = FakeSystem()
        c = controller(fs, "P-4")
        c.begin()
        c.switch("fl100")
        fs.fail.append(("flow_limit 2048", 1))
        with self.assertRaises(wb.ArmError):
            c.switch("fl2048")
        fs.fail.clear()
        self.assertEqual(wan_flow(fs), 256)
        self.assertNotIn("/etc/winsvpn/perf-trial.env", fs.files)

    def test_a_silently_ignored_apply_is_caught_by_the_read_back(self):
        fs = FakeSystem()
        c = controller(fs, "P-4")
        c.begin()
        fs.ignore.append("flow_limit 1024")
        with self.assertRaises(wb.ArmError) as cm:
            c.switch("fl1024")
        self.assertIn("read-back", str(cm.exception))
        self.assertEqual(wan_flow(fs), 256)

    def test_busy_poll_read_back_catches_a_refused_write(self):
        fs = FakeSystem()
        c = controller(fs, "P-3")
        c.begin()
        fs.ignore.append("sysctl -w net.core.busy_poll=50")
        with self.assertRaises(wb.ArmError):
            c.switch("bp50")

    def test_revert_failure_keeps_marker_and_timer_and_raises(self):
        fs = FakeSystem()
        c = controller(fs, "P-4", dead_man_minutes=30)
        c.begin()
        c.switch("fl2048")
        fs.fail.append(("tc qdisc replace dev eth0 root fq", 1))
        with self.assertRaises(wb.RevertFailed):
            c.finish()
        self.assertIn("/etc/winsvpn/perf-trial.env", fs.files)       # drift stays visible
        self.assertEqual(len(fs.timers), 1)                          # the dead-man timer stays armed
        fs.fail.clear()
        c.finish()                                                   # a retry succeeds
        self.assertEqual(wan_flow(fs), 256)
        self.assertEqual(fs.timers, set())

    def test_a_revert_that_reports_success_but_changes_nothing_is_caught(self):
        fs = FakeSystem()
        c = controller(fs, "P-4")
        c.begin()
        c.switch("fl2048")
        fs.ignore.append("flow_limit 256")
        with self.assertRaises(wb.RevertFailed):
            c.finish()

    def test_unrestorable_qdisc_is_refused_before_any_change(self):
        fs = FakeSystem(gw_children="fq_codel")
        c = controller(fs, "P-24")
        with self.assertRaises(wb.ArmError) as cm:
            c.begin()
        self.assertIn("fq_codel", str(cm.exception))
        self.assertEqual(fs.mutations(), [])
        self.assertEqual(fs.files, {})

    def test_a_non_fq_wan_root_is_refused(self):
        fs = FakeSystem()
        fs.qdisc["eth0"] = [{"kind": "mq", "handle": "1:", "root": True, "options": {}}]
        with self.assertRaises(wb.ArmError):
            controller(fs, "P-4").begin()
        self.assertEqual(fs.mutations(), [])

    def test_begin_twice_and_switch_before_begin(self):
        fs = FakeSystem()
        c = controller(fs, "P-4")
        with self.assertRaises(wb.ArmError):
            c.switch("fl100")
        c.begin()
        with self.assertRaises(wb.ArmError):
            c.begin()
        c.finish()

    def test_netns_prefix_for_tc_and_ip_but_not_sysctl_or_systemctl(self):
        fs = FakeSystem()
        t = wb.Target(netns="ns1")
        c = wb.ArmController(fs, t, wb.TRIALS["P-4"], clock=lambda: "T")
        c.begin()
        c.switch("fl1024")
        c.finish()
        self.assertTrue(all(l.startswith("ip netns exec ns1 tc ") for l in fs.log if " tc " in l or l.startswith("tc ")))
        fs = FakeSystem()
        c = wb.ArmController(fs, t, wb.TRIALS["P-3"], clock=lambda: "T")
        c.begin()
        c.switch("bp50")
        c.finish()
        self.assertTrue(any(l.startswith("sysctl -w") for l in fs.log))
        self.assertFalse(any("netns" in l and "sysctl" in l for l in fs.log))

    def test_revert_from_plan(self):
        fs = FakeSystem()
        c = controller(fs, "P-4")
        c.begin()
        c.switch("fl2048")
        doc = json.loads(fs.files[c.plan_path])                     # as a crashed controller left it
        self.assertEqual(wan_flow(fs), 2048)
        residual = wb.revert_from_plan(fs, wb.Target(), doc)
        self.assertEqual(residual, [])
        self.assertEqual(wan_flow(fs), 256)
        self.assertNotIn("/etc/winsvpn/perf-trial.env", fs.files)

    def test_revert_from_plan_reports_residuals_and_keeps_the_marker(self):
        fs = FakeSystem()
        c = controller(fs, "P-4")
        c.begin()
        c.switch("fl2048")
        doc = json.loads(fs.files[c.plan_path])
        fs.ignore.append("flow_limit 256")
        residual = wb.revert_from_plan(fs, wb.Target(), doc)
        self.assertTrue(residual)
        self.assertIn("/etc/winsvpn/perf-trial.env", fs.files)

    def test_qdisc_helpers(self):
        raw = json.dumps([{"kind": "mq", "handle": "1:", "root": True, "options": {}},
                          {"kind": "fq", "handle": "8007:", "parent": "1:1", "options": dict(FQ_DEFAULT, maxrate=125)}])
        lines = wb.parse_qdisc_json(raw)
        self.assertEqual(lines[1]["where"], "parent:1:1")
        self.assertEqual(lines[1]["opts"]["maxrate"], 125)
        self.assertNotIn("buckets", lines[1]["opts"])
        cmds = wb.qdisc_restore_cmds("d", lines, lambda a: a)
        self.assertEqual(cmds[0], ["tc", "qdisc", "replace", "dev", "d", "root", "handle", "1:", "mq"])
        self.assertIn("refill_delay", cmds[1])
        self.assertIn("1000us", cmds[1])
        self.assertIn("125bps", cmds[1])
        with self.assertRaises(wb.ArmError):
            wb.parse_qdisc_json("not json")
        with self.assertRaises(wb.ArmError):
            wb.qdisc_restore_cmds("d", [{"kind": "htb", "handle": "1", "where": "root", "opts": {}}], lambda a: a)


class NodeClassVia(unittest.TestCase):
    def test_reads_the_node_through_the_runner_and_never_the_controller(self):
        fs = FakeSystem()
        fs.files.update({"/proc/cpuinfo": "processor : 0\nmodel name : Intel Xeon Gold\nprocessor : 1\n",
                         "/proc/meminfo": "MemTotal:        2014208 kB\n", "/usr/local/bin/winn3-gateway": "x"})
        nc = wb.node_class_via(fs, "ovh", "canary-x", "/usr/local/bin/winn3-gateway", "canary")
        self.assertEqual((nc["cpu_model"], nc["usable_cpus"], nc["ram_kib"], nc["virt"]), ("Intel Xeon Gold", 2, 2014208, "kvm"))
        self.assertEqual(nc["binary_sha256"], "c" * 64)
        self.assertFalse(nc["emulated"])
        self.assertTrue(wb.venue_eligibility(nc)[0])
        self.assertIn("cat /proc/cpuinfo", fs.log)

    def test_an_emulated_guest_is_flagged_through_a_runner(self):
        fs = FakeSystem()
        fs.virt = "qemu"
        fs.files.update({"/proc/cpuinfo": "model name : QEMU TCG CPU version 2.5+\n", "/proc/meminfo": "MemTotal: 12242036 kB\n"})
        nc = wb.node_class_via(fs, "x", "amd64t", None, "tier_b")
        self.assertTrue(nc["emulated"])
        self.assertFalse(wb.venue_eligibility(nc)[0])

    def test_bare_metal_none_is_not_emulation(self):
        fs = FakeSystem()
        fs.virt = "none"
        nc = wb.node_class_via(fs, "x", "aicore", None, "aicore")
        self.assertEqual(nc["virt"], "none")
        self.assertFalse(nc["emulated"])

    def test_a_missing_binary_leaves_the_digest_empty(self):
        nc = wb.node_class_via(FakeSystem(), "x", "n", "/no/such", "canary")
        self.assertIsNone(nc["binary_sha256"])


class Runners(unittest.TestCase):
    def test_ssh_runner_needs_the_allow_list(self):
        with self.assertRaises(wb.ArmError):
            wb.SshRunner("canary-1", [])
        with self.assertRaises(wb.ArmError):
            wb.SshRunner("canary-1", ["canary-2"])
        r = wb.SshRunner("canary-1", ["canary-1"])
        self.assertEqual(r.command(["tc", "qdisc", "show"]), ["ssh", "-o", "BatchMode=yes", "canary-1", "--", "tc qdisc show"])

    def test_colima_runner_passes_argv_as_words_and_never_manages_the_vm(self):
        r = wb.ColimaRunner("l80")
        cmd = r.command(["ip", "netns", "exec", "ns", "tc", "x y"])
        self.assertEqual(cmd[:5], ["colima", "ssh", "-p", "l80", "--"])
        self.assertEqual(cmd[5:7], ["sudo", "-n"])
        self.assertEqual(cmd[-1], "x y")
        self.assertNotIn("start", cmd)
        self.assertNotIn("stop", cmd)

    def test_make_runner(self):
        self.assertIsInstance(wb.make_runner("local", []), wb.LocalRunner)
        self.assertIsInstance(wb.make_runner("colima:l80", []), wb.ColimaRunner)
        with self.assertRaises(wb.ArmError):
            wb.make_runner("ssh:h", [])
        with self.assertRaises(SystemExit):
            wb.make_runner("carrier-pigeon", [])

    def test_local_runner_handles_missing_binary_and_timeout(self):
        r = wb.LocalRunner()
        self.assertEqual(r.run(["/nonexistent/binary"]).rc, 127)
        self.assertEqual(r.run([sys.executable, "-c", "print('x')"]).out.strip(), "x")
        self.assertEqual(r.run([sys.executable, "-c", "import time;time.sleep(5)"], timeout=0.3).rc, 124)


class BenchLockTests(unittest.TestCase):
    def test_mkdir_is_the_lock_and_second_acquire_fails(self):
        fs = FakeSystem()
        a = wb.BenchLock(fs, "lane-a", "/home/aicore/.bench.lock", clock=lambda: "T")
        a.acquire(123)
        self.assertIn("/home/aicore/.bench.lock", fs.dirs)
        self.assertEqual(fs.files["/home/aicore/.bench.lock/owner"], "lane-a T 123\n")
        b = wb.BenchLock(fs, "lane-b", "/home/aicore/.bench.lock")
        with self.assertRaises(wb.ArmError):
            b.acquire(9)
        self.assertEqual(fs.files["/home/aicore/.bench.lock/owner"], "lane-a T 123\n")    # untouched

    def test_release_needs_verification_and_ownership(self):
        fs = FakeSystem()
        a = wb.BenchLock(fs, "lane-a", clock=lambda: "T")
        a.acquire(1)
        with self.assertRaises(wb.ArmError):
            a.release(False)
        self.assertIn("/home/aicore/.bench.lock", fs.dirs)
        with self.assertRaises(wb.ArmError):
            wb.BenchLock(fs, "lane-b").release(True)
        self.assertIn("/home/aicore/.bench.lock", fs.dirs)
        a.release(True)
        self.assertNotIn("/home/aicore/.bench.lock", fs.dirs)

    def test_it_is_a_directory_not_a_flock_file(self):
        fs = FakeSystem()
        wb.BenchLock(fs, "x", clock=lambda: "T").acquire(1)
        self.assertFalse(any("flock" in l for l in fs.log))
        self.assertTrue(fs.log[0].startswith("mkdir "))


class Backends(unittest.TestCase):
    def test_dry_run_backend_is_deterministic_and_seeded(self):
        b1, b2 = wb.DryRunBackend("latency_win", 5), wb.DryRunBackend("latency_win", 5)
        ctx = {"trial": "P-4", "stage": "canary", "arm": "fl100", "rep": 1, "profile": "a", "test": "tcp1", "dir": "down"}
        self.assertEqual(b1.measure(ctx), b2.measure(ctx))
        self.assertNotEqual(b1.measure(ctx), wb.DryRunBackend("latency_win", 6).measure(ctx))
        base = b1.measure(dict(ctx, arm="base_a"))
        cand = b1.measure(ctx)
        self.assertLess(cand["ld_p50_ms"], base["ld_p50_ms"] - 20)

    def test_dry_run_scenarios_exist_and_reject_unknown(self):
        with self.assertRaises(wb.ArmError):
            wb.DryRunBackend("nope")
        self.assertIn("neutral", wb.DryRunBackend.SCENARIOS)

    def test_command_backend_substitutes_without_a_shell(self):
        seen = []

        class R:
            def run(self, argv, stdin=None, timeout=0):
                seen.append(argv)
                return wb.RunResult(0, "noise\n" + json.dumps({"started": True, "alive": True}) + "\n")
        b = wb.CommandBackend("tool --arm {arm} --p {profile} --secs {secs} --cpus {gw_cpus}; echo pwned", runner=R(), secs=7)
        rec = b.measure({"trial": "T", "stage": "s", "arm": "a b", "rep": 1, "profile": "a", "test": "tcp1", "dir": "down", "gw_cpus": (1, 2)})
        self.assertEqual(seen[0], ["tool", "--arm", "a b", "--p", "a", "--secs", "7", "--cpus", "1,2;", "echo", "pwned"])
        self.assertEqual(rec["venue"], "functional")
        b3 = wb.CommandBackend("tool '{\"a\": 1}' {arm} {unknown}", runner=R())
        b3.measure({"trial": "T", "stage": "s", "arm": "x", "rep": 1, "profile": "a", "test": "t", "dir": "d"})
        self.assertEqual(seen[-1], ["tool", '{"a": 1}', "x", "{unknown}"])
        b2 = wb.CommandBackend("tool {gw_cpus}", runner=R())
        b2.measure({"trial": "T", "stage": "s", "arm": "x", "rep": 1, "profile": "a", "test": "t", "dir": "d", "gw_cpus": ()})
        self.assertEqual(seen[-1], ["tool", "natural"])

    def test_command_backend_failures_become_failed_runs(self):
        class Bad:
            def __init__(self, rc, out):
                self.rc, self.out = rc, out

            def run(self, argv, stdin=None, timeout=0):
                return wb.RunResult(self.rc, self.out)
        ctx = {"trial": "T", "stage": "s", "arm": "x", "rep": 1, "profile": "a", "test": "t", "dir": "d"}
        r = wb.CommandBackend("x", runner=Bad(3, "")).measure(ctx)
        self.assertEqual((r["started"], r["failure_class"]), (False, "measure_command_rc_3"))
        r = wb.CommandBackend("x", runner=Bad(0, "not json")).measure(ctx)
        self.assertEqual(r["failure_class"], "measure_output_not_json")
        r = wb.CommandBackend("x", runner=Bad(0, "")).measure(ctx)
        self.assertEqual(r["failure_class"], "measure_output_not_json")
        self.assertEqual((r["sessions_started"], r["sessions_failed"]), (0, 1))

    def test_record_validation(self):
        good = {"started": True, "alive": True, "idle_p50_ms": 1, "ld_p50_ms": 2, "ld_p99_ms": 3, "ld_jitter_ms": 1,
                "ld_loss_pct": 0, "thr_mbps": 5}
        self.assertEqual(wb.validate_run_record(good), [])
        self.assertIn("missing thr_mbps", wb.validate_run_record({k: v for k, v in good.items() if k != "thr_mbps"}))
        self.assertTrue(wb.validate_run_record(dict(good, ld_p50_ms="slow")))
        self.assertTrue(wb.validate_run_record(dict(good, ld_p50_ms=True)))


class EndToEnd(unittest.TestCase):
    def test_run_trial_with_arm_control_writes_evidence_and_leaves_the_node_clean(self):
        fs = FakeSystem()
        trial = wb.TRIALS["P-4"]

        class Backend(wb.DryRunBackend):
            def measure(self, ctx):
                rec = super().measure(ctx)
                rec["flow_limit_seen"] = wan_flow(fs)
                return rec
        with tempfile.TemporaryDirectory() as d:
            ev = wb.Evidence(d)
            decision, runs = wb.run_trial(trial, Backend("latency_win", 3, venue="canary"), ev, {"canary": node_class("canary")},
                                          10, 3, controller_factory=lambda st: controller(fs, "P-4"))
            self.assertEqual(decision["rule_r_verdict"], "ADOPT")
            self.assertTrue(decision["adoptable"])
            self.assertEqual(len(runs), 10 * 2 * 5)
            by_arm = {}
            for r in runs:
                by_arm.setdefault(r["arm"], set()).add(r["flow_limit_seen"])
            self.assertEqual(by_arm, {"base_a": {256}, "base_b": {256}, "fl100": {100}, "fl1024": {1024}, "fl2048": {2048}})
            self.assertEqual(wan_flow(fs), 256)
            self.assertNotIn("/etc/winsvpn/perf-trial.env", fs.files)
            lines = open(os.path.join(d, "runs.jsonl")).read().splitlines()
            self.assertEqual(len(lines), len(runs))
            self.assertEqual(json.loads(lines[0])["node_class_id"], "c1")
            self.assertEqual(json.loads(lines[0])["binary_sha256"], "a" * 64)
            self.assertTrue(os.path.exists(os.path.join(d, "verdict_P-4.json")))
            self.assertTrue(os.path.exists(os.path.join(d, "node_class_canary.json")))
            man = ev.manifest()
            self.assertNotIn("MANIFEST.json", ev.manifest())                 # a second pass does not list itself
            self.assertIn("runs.jsonl", man)
            self.assertEqual(man["runs.jsonl"], wb.sha256_file(os.path.join(d, "runs.jsonl")))
            self.assertNotIn("MANIFEST.json", man)

    def test_arm_failure_mid_trial_still_reverts(self):
        fs = FakeSystem()
        trial = wb.TRIALS["P-4"]

        class Boom(wb.DryRunBackend):
            n = 0

            def measure(self, ctx):
                Boom.n += 1
                if Boom.n == 12:
                    raise RuntimeError("tool crashed")
                return super().measure(ctx)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RuntimeError):
                wb.run_trial(trial, Boom("neutral", 1), wb.Evidence(d), {"canary": node_class()}, 3, 1,
                             controller_factory=lambda st: controller(fs, "P-4", dead_man_minutes=10))
        self.assertEqual(wan_flow(fs), 256)
        self.assertNotIn("/etc/winsvpn/perf-trial.env", fs.files)
        self.assertEqual(fs.timers, set())

    def test_a_bad_record_becomes_a_failed_run_not_a_silent_zero(self):
        class Bad(wb.DryRunBackend):
            def measure(self, ctx):
                rec = super().measure(ctx)
                if ctx["arm"] == "fl100":
                    del rec["thr_mbps"]
                return rec
        with tempfile.TemporaryDirectory() as d:
            _, runs = wb.run_trial(wb.TRIALS["P-4"], Bad("latency_win", 1), wb.Evidence(d), {"canary": node_class()}, 2, 1)
        bad = [r for r in runs if r["arm"] == "fl100"]
        self.assertTrue(all(not r["started"] and r["failure_class"].startswith("bad_record") for r in bad))

    def test_multi_stage_trial_runs_confirm_only_for_the_chosen_arm(self):
        trial = wb.TRIALS["P-17"]
        with tempfile.TemporaryDirectory() as d:
            ncs = {s.name: node_class(s.venue) for s in trial.stages}
            decision, runs = wb.run_trial(trial, wb.DryRunBackend("latency_win", 2, venue="x"), wb.Evidence(d), ncs, 10, 2)
        stages = {r["stage"] for r in runs}
        self.assertEqual(stages, {"aicore_cpu1", "aicore_cpu2", "canary_confirm"})
        confirm_arms = {r["arm"] for r in runs if r["stage"] == "canary_confirm"}
        self.assertEqual(confirm_arms, {"base_a", "base_b", decision["chosen_arm"]})

    def test_confirm_is_skipped_when_no_arm_goes_forward(self):
        trial = wb.TRIALS["P-17"]
        with tempfile.TemporaryDirectory() as d:
            ncs = {s.name: node_class(s.venue) for s in trial.stages}
            _, runs = wb.run_trial(trial, wb.DryRunBackend("all_worse", 2), wb.Evidence(d), ncs, 10, 2)
        self.assertNotIn("canary_confirm", {r["stage"] for r in runs})

    def test_dry_run_is_never_adoptable_whatever_the_scenario(self):
        for sc in wb.DryRunBackend.SCENARIOS:
            with tempfile.TemporaryDirectory() as d:
                decision, _ = wb.run_trial(wb.TRIALS["P-4"], wb.DryRunBackend(sc, 4), wb.Evidence(d),
                                           {"canary": wb.dry_node_class()}, 10, 4)
            self.assertFalse(decision["adoptable"], sc)

    def test_dry_run_scenario_verdicts(self):
        want = {"latency_win": "ADOPT", "latency_win_loses_throughput": "NO_PURPOSE", "latency_win_raises_jitter": "REJECT",
                "all_worse": "REJECT"}
        for sc, verdict in want.items():
            with tempfile.TemporaryDirectory() as d:
                decision, _ = wb.run_trial(wb.TRIALS["P-4"], wb.DryRunBackend(sc, 1), wb.Evidence(d),
                                           {"canary": wb.dry_node_class()}, 10, 1)
            self.assertEqual(decision["rule_r_verdict"], verdict, sc)
        for sc, verdict in (("throughput_win_over_bar", "OWNER_RULING_CANDIDATE"), ("throughput_win_and_latency_win", "ADOPT")):
            with tempfile.TemporaryDirectory() as d:
                decision, _ = wb.run_trial(wb.TRIALS["P-24"], wb.DryRunBackend(sc, 1), wb.Evidence(d),
                                           {"aicore": wb.dry_node_class()}, 10, 1)
            self.assertEqual(decision["rule_r_verdict"], verdict, sc)

    def test_dry_run_covers_the_side_traffic_trials(self):
        for tid in ("P-10", "P-3"):
            with tempfile.TemporaryDirectory() as d:
                decision, runs = wb.run_trial(wb.TRIALS[tid], wb.DryRunBackend("latency_win", 1), wb.Evidence(d),
                                              {"canary": wb.dry_node_class()}, 10, 1)
            self.assertEqual(decision["rule_r_verdict"], "ADOPT", tid)
            self.assertTrue(all("awg_mbps" in r and "xray_mbps" in r for r in runs), tid)
            if tid == "P-10":
                self.assertTrue(all(set(r["background"]) == {"suricata", "awg", "xray"} for r in runs))

    def test_evidence_raw_text_is_ip_masked(self):
        with tempfile.TemporaryDirectory() as d:
            ev = wb.Evidence(d)
            ev.save_raw("x.txt", "peer 198.51.100.7 and 10.8.1.1")
            txt = open(os.path.join(d, "raw", "x.txt")).read()
            self.assertNotIn("198.51.100.7", txt)
            self.assertIn("10.8.1.1", txt)


class Cli(unittest.TestCase):
    def call(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = wb.main(list(argv))
        return rc, buf.getvalue()

    def test_plan(self):
        rc, out = self.call("plan")
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)[0]["id"], "P-17")

    def test_dry_run_then_analyze_reproduces_the_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            rc, out = self.call("dry-run", "--out", d, "--scenario", "latency_win", "--trial", "P-4", "--reps", "10")
            self.assertEqual(rc, 0)
            summary = json.loads(out)
            self.assertEqual(summary["P-4"]["rule_r_verdict"], "ADOPT")
            self.assertFalse(summary["P-4"]["adoptable"])
            self.assertTrue(os.path.exists(os.path.join(d, "MANIFEST.json")))
            ncs = os.path.join(d, "ncs.json")
            json.dump({"canary": wb.dry_node_class()}, open(ncs, "w"))
            rc, out = self.call("analyze", "--trial", "P-4", "--runs", os.path.join(d, "runs.jsonl"), "--node-classes", ncs)
            self.assertEqual(json.loads(out)["rule_r_verdict"], "ADOPT")
            self.assertFalse(json.loads(out)["adoptable"])

    def test_dry_run_marks_binary_trials_not_run(self):
        with tempfile.TemporaryDirectory() as d:
            rc, out = self.call("dry-run", "--out", d, "--trial", "P-18")
        self.assertEqual(json.loads(out)["P-18"]["rule_r_verdict"], "NOT_RUN")

    def test_state_commands(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "state.json")
            self.assertEqual(self.call("state", "may-start", "--file", f, "--trial", "P-17")[0], 0)
            rc, out = self.call("state", "may-start", "--file", f, "--trial", "P-4")
            self.assertEqual(rc, 1)
            self.assertIn("P-17", out)
            self.call("state", "set", "--file", f, "--trial", "P-17", "--verdict", "ADOPT")
            self.assertEqual(self.call("state", "may-start", "--file", f, "--trial", "P-4")[0], 0)
            self.assertEqual(json.load(open(f)), {"P-17": "ADOPT"})
            with self.assertRaises(SystemExit):
                self.call("state", "set", "--file", f, "--trial", "P-17")

    def test_connect_time_exit_status(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "r.jsonl")
            rows = [{"node_class": "c", "network": n, "ok": True, "total_ms": 1000, "endpoint": "first_dns_answer"}
                    for n in ("wifi", "cellular") for _ in range(10)]
            open(f, "w").write("\n".join(json.dumps(r) for r in rows))
            self.assertEqual(self.call("connect-time", "--runs", f)[0], 0)
            rows[0]["total_ms"] = 9000
            open(f, "w").write("\n".join(json.dumps(r) for r in rows))
            self.assertEqual(self.call("connect-time", "--runs", f)[0], 1)

    def test_other_analysis_commands_run(self):
        with tempfile.TemporaryDirectory() as d:
            def w(name, obj):
                p = os.path.join(d, name)
                json.dump(obj, open(p, "w"))
                return p
            rec = {"mem_total_kib": 1967 * 1024, "max_sessions": 22, "sessions_tested": 22, "restart_to_carrying_s": [1.0] * 10,
                   "over_capacity_attempts": 4, "over_capacity_refusals": 4, "fio_p99_ms": 9.5}
            self.assertEqual(json.loads(self.call("storm", "--input", w("s.json", rec))[1])["verdict"], "NO_GROUP_COMMIT")
            self.assertEqual(json.loads(self.call("golive", "--input", w("g.json", GoLive().installs()))[1])["verdict"], "PASS")
            self.assertEqual(json.loads(self.call("ryzen", "--input", w("r.json", Ryzen().runs()), "--lock-owner", "me")[1])["verdict"], "PASS")
            hc = HubCost().rec()
            self.assertEqual(json.loads(self.call("hub-cost", "--input", w("h.json", hc))[1])["verdict"], "RECORDED")
            sp = os.path.join(d, "st.txt")
            open(sp, "w").write(Epoll.table(3))
            self.assertEqual(json.loads(self.call("epoll", "--strace-output", sp, "--seconds", "20", "--attached-after-startup")[1])["verdict"],
                             "DECLINE_CONFIRMED")

    def test_run_without_execute_changes_nothing_and_ssh_needs_allow_list(self):
        rc, out = self.call("run", "--trial", "P-4", "--stage", "canary", "--out", "/nonexistent/x", "--venue", "canary",
                            "--measure-cmd", "echo {arm}")
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertIn("dry plan only", doc["note"])
        self.assertEqual(doc["schedule_runs"], 10 * 2 * 5)
        self.assertIn("when --execute", doc["node_class"])          # nothing was read from any machine
        with self.assertRaises(wb.ArmError):
            self.call("run", "--trial", "P-4", "--stage", "canary", "--out", "/x", "--venue", "canary",
                      "--measure-cmd", "echo", "--runner", "ssh:canary-1", "--execute")
        with self.assertRaises(SystemExit):
            self.call("run", "--trial", "P-18", "--stage", "canary", "--out", "/x", "--venue", "canary", "--measure-cmd", "echo")
        with self.assertRaises(SystemExit):
            self.call("run", "--trial", "P-4", "--stage", "nope", "--out", "/x", "--venue", "canary", "--measure-cmd", "echo")

    def test_run_execute_drives_arms_through_the_runner_and_records_state(self):
        import unittest.mock as mock
        fs = FakeSystem()
        rec = {"started": True, "alive": True, "idle_p50_ms": 70, "ld_p50_ms": 190, "ld_p99_ms": 215, "ld_jitter_ms": 4,
               "ld_loss_pct": 0.2, "thr_mbps": 800, "awg_mbps": 300, "xray_mbps": 250, "awg_ld_p99_ms": 60, "xray_ld_p99_ms": 70}
        cmd = "%s -c %s" % (shlex.quote(sys.executable), shlex.quote("import json;print(json.dumps(%r))" % rec))
        fs.files.update({"/proc/cpuinfo": "processor : 0\nmodel name : X\nprocessor : 1\n", "/proc/meminfo": "MemTotal: 4194304 kB\n", "/gw": "b"})
        with tempfile.TemporaryDirectory() as d:
            state = os.path.join(d, "state.json")
            json.dump({"P-17": "ADOPT"}, open(state, "w"))
            with mock.patch.object(wb, "make_runner", return_value=fs):
                rc, out = self.call("run", "--trial", "P-4", "--stage", "canary", "--out", os.path.join(d, "ev"), "--venue", "canary",
                                    "--provider", "ovh", "--binary", "/gw", "--measure-cmd", cmd, "--reps", "2", "--min-reps", "2",
                                    "--execute", "--state", state, "--dead-man-minutes", "5")
            self.assertEqual(rc, 0)
            doc = json.loads(out)
            self.assertEqual(doc["rule_r_verdict"], "NO_PURPOSE")           # identical records: nothing moves
            self.assertEqual(json.load(open(state))["P-4"], "NO_PURPOSE")
            self.assertEqual(json.load(open(state))["P-17"], "ADOPT")
            runs = [json.loads(l) for l in open(os.path.join(d, "ev", "runs.jsonl"))]
            self.assertEqual(len(runs), 2 * 2 * 5)
            self.assertEqual({r["venue"] for r in runs}, {"canary"})         # the operator's declared venue rides on every record
            self.assertEqual(runs[0]["binary_sha256"], "c" * 64)
            self.assertTrue(os.path.exists(os.path.join(d, "ev", "MANIFEST.json")))
        self.assertEqual(wan_flow(fs), 256)
        self.assertNotIn("/etc/winsvpn/perf-trial.env", fs.files)
        self.assertEqual(fs.timers, set())
        self.assertFalse(doc["adoptable"])

    def test_multi_stage_run_does_not_write_a_final_verdict_into_state(self):
        import unittest.mock as mock
        fs = FakeSystem()
        rec = {"started": True, "alive": True, "idle_p50_ms": 70, "ld_p50_ms": 190, "ld_p99_ms": 215, "ld_jitter_ms": 4,
               "ld_loss_pct": 0.2, "thr_mbps": 800}
        cmd = "%s -c %s" % (shlex.quote(sys.executable), shlex.quote("import json;print(json.dumps(%r))" % rec))
        fs.files.update({"/proc/cpuinfo": "processor : 0\nmodel name : AMD Ryzen 7 PRO 8845HS\n", "/proc/meminfo": "MemTotal: 4194304 kB\n",
                         "/gw": "b"})
        with tempfile.TemporaryDirectory() as d:
            state = os.path.join(d, "state.json")
            with mock.patch.object(wb, "make_runner", return_value=fs):
                rc, out = self.call("run", "--trial", "P-17", "--stage", "aicore_cpu1", "--out", os.path.join(d, "ev"), "--venue", "aicore",
                                    "--provider", "aicore", "--binary", "/gw",
                                    "--measure-cmd", cmd, "--reps", "1", "--min-reps", "1", "--execute", "--state", state)
            self.assertIn("state_note", json.loads(out))
            self.assertFalse(os.path.exists(state))
        self.assertEqual(fs.qlen["winn3gw0"], 10000)

    def test_p24_condition_command(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "r.jsonl")
            rows = []
            for arm, drops in (("base_a", 0), ("ring4096", 0), ("ring2048", 0), ("ring1024", 900)):
                for rep in range(3):
                    for prof in ("a", "b"):
                        rows.append({"trial": "P-17", "stage": "aicore_cpu1", "arm": arm, "started": True, "alive": True,
                                     "profile": prof, "fq_child_backlog_pkts_max": 0, "tx_drops": drops})
            open(f, "w").write("\n".join(json.dumps(r) for r in rows))
            rc, out = self.call("p24-condition", "--runs", f, "--stage", "aicore_cpu1")
            self.assertEqual((rc, json.loads(out)["met"]), (0, True))
            rc, out = self.call("p24-condition", "--runs", f, "--stage", "nope")
            self.assertEqual(rc, 1)

    def test_run_enforces_bench_order_state(self):
        with tempfile.TemporaryDirectory() as d:
            st = os.path.join(d, "st.json")
            with self.assertRaises(SystemExit) as cm:
                self.call("run", "--trial", "P-4", "--stage", "canary", "--out", d, "--venue", "canary",
                          "--measure-cmd", "echo", "--execute", "--state", st)
            self.assertIn("bench order", str(cm.exception))

    def test_evidence_command_reports_this_machine_as_ineligible_without_a_venue(self):
        rc, out = self.call("evidence", "--provider", "x", "--virt", "")
        doc = json.loads(out)
        self.assertFalse(doc["performance_eligible"])
        self.assertIn("facts", doc)

    def test_os_release_and_host_facts(self):
        self.assertEqual(wb.parse_os_release('NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 24.04.4 LTS"\n'), "Ubuntu 24.04.4 LTS")
        self.assertIsNone(wb.parse_os_release(""))
        f = wb.host_facts(reader=lambda p: 'PRETTY_NAME="X 1"\n', run=lambda argv: "systemd 255 (255.4-1ubuntu8)\n+PAM\n")
        self.assertEqual((f["os_release"], f["systemd"]), ("X 1", "systemd 255 (255.4-1ubuntu8)"))
        self.assertGreater(f["root_disk_bytes"], 0)
        f = wb.host_facts(reader=lambda p: None, run=lambda argv: None)
        self.assertIsNone(f["systemd"])

    def test_connect_ingest_command(self):
        with tempfile.TemporaryDirectory() as d:
            src, out = os.path.join(d, "p.json"), os.path.join(d, "o.jsonl")
            json.dump([{"server": "x", "kind": "cold", "handler": 0.0, "candidate": 3.0, "datapath": 3.2, "gate_carrying": 3.7, "carry": 4.2},
                       {"server": "x", "kind": "cold", "handler": 0.0, "candidate": 3.0}], open(src, "w"))
            rc, text = self.call("connect-ingest", "--phases", src, "--node-class", "c1", "--network", "wifi", "--out", out)
            self.assertEqual(json.loads(text), {"rows": 2, "failed": 1})
            rows = [json.loads(l) for l in open(out)]
            self.assertEqual(rows[0]["total_ms"], 4200.0)
            self.assertFalse(rows[1]["ok"])

    def test_revert_command(self):
        fs = FakeSystem()
        c = controller(fs, "P-4")
        c.begin()
        c.switch("fl2048")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "plan.json")
            open(p, "w").write(fs.files[c.plan_path])
            import unittest.mock as mock
            with mock.patch.object(wb, "make_runner", return_value=fs):
                rc, out = self.call("revert", "--plan", p)
        self.assertEqual(rc, 0)
        self.assertEqual(wan_flow(fs), 256)


class IngestL63(unittest.TestCase):
    LINE = {"rundir": "s1_C_a_tcp1_down_r1", "bin": "cand", "profile": "a", "test": "tcp1", "dir": "down", "carriage": "1",
            "client_alive": "1", "idle_p50": 66.1, "ld_p50_ms": 68.14, "ld_p95_ms": 75.89, "ld_p99_ms": 85.85, "ld_jitter_ms": 2.11,
            "ld_loss_pct": 0.58, "post_rx": 200, "rx_mbps": 1105.6, "retr": 7974, "gw_cpu": 0.4, "gw_inbox_drop": 0,
            "gw_tun_txdrop": 829, "gw_rcvbuf": 0, "up_mbps": None, "down_mbps": None, "cl_fail": "", "gw_fail": "",
            "meta": "label=s1_C_a_tcp1_down_r1 bin=cand carriage=1 after=2 client_alive=1 end=2026-09-26T18:22:59Z "}
    AM = {"Ra": "base_a", "Rb": "base_b", "C": "ring2048"}
    SM = {"s1": "aicore_cpu1"}

    def test_maps_the_rig_fields(self):
        r = wb.record_from_l63(self.LINE, "P-17", self.AM, self.SM, "aicore")
        self.assertEqual((r["stage"], r["arm"], r["role"], r["rep"], r["profile"], r["test"], r["dir"]),
                         ("aicore_cpu1", "ring2048", "cand", 1, "a", "tcp1", "down"))
        self.assertEqual((r["idle_p50_ms"], r["ld_p50_ms"], r["ld_p99_ms"], r["thr_mbps"]), (66.1, 68.14, 85.85, 1105.6))
        self.assertTrue(r["started"] and r["alive"])
        self.assertEqual((r["tx_drops"], r["retrans"], r["venue"]), (829, 7974, "aicore"))
        self.assertEqual(wb.validate_run_record(r), [])

    def test_udp_throughput_is_the_directional_field(self):
        o = dict(self.LINE, rundir="s1_Ra_b_udp40_up_r3", test="udp40", dir="up", up_mbps=39.9, rx_mbps=None)
        r = wb.record_from_l63(o, "P-17", self.AM, self.SM, "aicore")
        self.assertEqual((r["test"], r["thr_mbps"], r["arm"], r["rep"]), ("udp", 39.9, "base_a", 3))

    def test_failed_runs(self):
        o = dict(self.LINE, meta="NO CARRIAGE", carriage="0")
        r = wb.record_from_l63(o, "P-17", self.AM, self.SM, "aicore")
        self.assertEqual((r["started"], r["alive"], r["failure_class"]), (False, False, "no_carriage"))
        o = dict(self.LINE, meta=self.LINE["meta"] + "NO CARRIAGE")           # both markers: the stricter one wins
        self.assertFalse(wb.record_from_l63(o, "P-17", self.AM, self.SM, "aicore")["started"])
        o = dict(self.LINE, client_alive="0", cl_fail="handshake failed")
        r = wb.record_from_l63(o, "P-17", self.AM, self.SM, "aicore")
        self.assertEqual((r["started"], r["alive"], r["failure_class"]), (True, False, "handshake failed"))
        o = dict(self.LINE, post_rx=50)
        self.assertFalse(wb.record_from_l63(o, "P-17", self.AM, self.SM, "aicore")["alive"])

    def test_unnamed_labels_are_skipped_not_guessed(self):
        for label in ("s9_C_a_tcp1_down_r1", "s1_X_a_tcp1_down_r1", "garbage", "s1_C_c_tcp1_down_r1"):
            self.assertIsNone(wb.record_from_l63(dict(self.LINE, rundir=label), "P-17", self.AM, self.SM, "aicore"), label)

    def test_cli_appends_and_counts(self):
        with tempfile.TemporaryDirectory() as d:
            src, out = os.path.join(d, "runs_s1.jsonl"), os.path.join(d, "runs.jsonl")
            open(src, "w").write(json.dumps(self.LINE) + "\n" + json.dumps(dict(self.LINE, rundir="zz_C_a_tcp1_down_r1")) + "\n")
            rc, text = Cli().call("ingest-l63", "--runs", src, "--out", out, "--trial", "P-17",
                                  "--arm-map", "Ra=base_a,Rb=base_b,C=ring2048", "--stage-map", "s1=aicore_cpu1")
            self.assertEqual(json.loads(text), {"written": 1, "skipped": 1})
            self.assertEqual(json.loads(open(out).readline())["arm"], "ring2048")


class LocalDriver(unittest.TestCase):
    class Vm:
        def __init__(self, netns=()):
            self.log, self.netns = [], list(netns)
            self.r = wb.ColimaRunner("l80")

        def run(self, argv, stdin=None, check=True, timeout=300):
            self.log.append(shlex.join(argv))
            if argv[:3] == ["ip", "netns", "list"]:
                return wb.RunResult(0, "\n".join(self.netns) + "\n")
            return wb.RunResult(0, "")

    def test_rig_up_refuses_when_the_namespaces_exist(self):
        vm = self.Vm(netns=["p3c"])
        with self.assertRaises(wb.ArmError):
            local.rig_up(vm)
        self.assertEqual([l for l in vm.log if "add" in l or "systemd-run" in l], [])

    def test_rig_down_touches_only_named_things_and_never_the_vm(self):
        vm = self.Vm(netns=["p3c", "p3s", "other-lane-ns"])
        local.rig_down(vm)
        joined = "\n".join(vm.log)
        self.assertIn("systemctl stop p3bench-server.service", joined)
        self.assertIn("systemctl stop p3bench-gw.service", joined)
        self.assertIn("ip netns del p3c", joined)
        self.assertIn("ip netns del p3s", joined)
        self.assertNotIn("other-lane-ns", joined)
        self.assertIn("rm -rf /tmp/p3bench", joined)
        for banned in ("pkill", "killall", "kill ", "colima", "limactl", "netns delete", "ip -all"):
            self.assertNotIn(banned, joined)

    def test_rig_down_without_namespaces_deletes_nothing(self):
        vm = self.Vm()
        local.rig_down(vm)
        self.assertFalse(any("netns del" in l for l in vm.log))

    def test_main_refuses_when_the_vm_is_not_running_and_never_starts_it(self):
        import unittest.mock as mock
        with mock.patch.object(local, "colima_state", return_value="Stopped"), \
                mock.patch.object(local.subprocess, "run") as run:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                rc = local.main(["down"])
        self.assertEqual(rc, 2)
        self.assertIn("never starts a VM", err.getvalue())
        run.assert_not_called()

    def test_colima_state_parses_the_list(self):
        import unittest.mock as mock
        out = "PROFILE    STATUS     ARCH       CPUS\nl80        Running    aarch64    4\namd64t     Stopped    x86_64     6\n"
        with mock.patch.object(local.subprocess, "run", return_value=mock.Mock(stdout=out)):
            self.assertEqual(local.colima_state("l80"), "Running")
            self.assertEqual(local.colima_state("amd64t"), "Stopped")
            self.assertEqual(local.colima_state("nope"), "")

    def test_local_trial_is_restaged_to_the_l80_venue(self):
        t = local.local_trial(wb.TRIALS["P-4"], cells=(("a", "udp", "down"),))
        self.assertEqual([(s.name, s.venue) for s in t.stages], [("l80_local", "l80")])
        self.assertEqual(t.cells, (("a", "udp", "down"),))
        self.assertEqual([a.name for a in t.arms], [a.name for a in wb.TRIALS["P-4"].arms])
        self.assertNotIn("l80", wb.PERF_VENUES)

    def test_target_and_names_are_the_documented_ones(self):
        t = local.target()
        self.assertEqual((t.wan_dev, t.gw_dev, t.netns, t.unit), ("p3s0", "p3g0", "p3s", "p3bench-gw.service"))
        self.assertTrue(all(n.startswith("p3") for n in (local.NS_C, local.NS_S)))


class SeatP3Fixes(unittest.TestCase):
    """Implementation-review fixes: dead-man liveness, NOT_RUN scope, default mq root, confirm stage
    from earlier runs, busy-poll ceiling per node class, the ruled minimum of 10 reps, aicore lock."""

    def test_no_change_after_the_dead_man_has_fired(self):
        fs = FakeSystem()
        c = controller(fs, "P-4", dead_man_minutes=30)
        c.begin()
        c.switch("fl100")
        fs.timers.clear()                                   # the timer fired: the script reverted the node
        fs.qdisc["eth0"][0]["options"]["flow_limit"] = 256
        fs.files.pop("/etc/winsvpn/perf-trial.env")
        with self.assertRaises(wb.ArmError):
            c.switch("fl1024")
        self.assertFalse(any("flow_limit 1024" in l for l in fs.log))
        self.assertEqual(wan_flow(fs), 256)

    def test_dead_man_is_re_armed_before_every_change_and_one_stays_pending(self):
        fs = FakeSystem()
        c = controller(fs, "P-4", dead_man_minutes=20)
        c.begin()
        for name in ("fl100", "base_a", "fl2048", "base_b", "fl1024"):
            c.switch(name)
            self.assertEqual(fs.timers, {c.dead_man_unit + ".timer"}, name)
        self.assertEqual(sum(1 for l in fs.log if l.startswith("systemd-run ")), 6)
        self.assertTrue(c.dead_man_unit.endswith("-6"))
        first = fs.index_of("tc qdisc replace dev eth0 root fq limit 20480 flow_limit 2048")
        self.assertLess(max(i for i, l in enumerate(fs.log[:first]) if l.startswith("systemd-run ")), first)
        c.finish()
        self.assertEqual(fs.timers, set())

    def test_p3_p10_p22_use_the_5_7_matrix(self):
        for tid in ("P-3", "P-10", "P-22"):
            self.assertEqual(wb.TRIALS[tid].cells, wb.full_matrix(), tid)
        self.assertEqual(wb.TRIALS["P-4"].cells, (("a", "tcp1", "down"), ("b", "tcp1", "down")))   # 10.2: single-session download
        runs = build_runs(wb.TRIALS["P-3"], cand={"bp50": {"ld_p50_ms": -40.0}})
        for r in runs:
            if (r["arm"], r["test"], r["dir"]) == ("bp50", "udp", "up"):
                r["ld_p99_ms"] += 30.0
        self.assertEqual(screen("P-3", runs)["verdict"], "REJECT")

    def test_no_change_once_the_marker_is_gone(self):
        fs = FakeSystem()
        c = controller(fs, "P-4")
        c.begin()
        fs.files.pop("/etc/winsvpn/perf-trial.env")
        with self.assertRaises(wb.ArmError):
            c.switch("fl2048")
        self.assertFalse(any("flow_limit 2048" in l for l in fs.log))

    def test_not_run_only_for_gateway_round_trials(self):
        ok, why = wb.trial_may_start("P-4", {"P-17": "NOT_RUN"})
        self.assertFalse(ok)
        self.assertIn("config trial", why)
        self.assertFalse(wb.trial_may_start("P-4", {"P-17": "PENDING_CONFIRM"})[0])
        self.assertFalse(wb.trial_may_start("P-4", {"P-17": "done"})[0])
        self.assertTrue(wb.trial_may_start("P-4", {"P-17": "INCONCLUSIVE"})[0])
        done = {t: "ADOPT" for t in ("P-17", "P-4", "P-22", "P-3", "P-10")}
        done.update({"P-18": "NOT_RUN", "P-41": "NOT_RUN", "P-46": "NOT_RUN", "P-24.condition": "met",
                     "P-18.deferral": "r", "P-41.deferral": "r", "P-46.deferral": "r", "P-24.condition_evidence": "e" * 64})
        self.assertTrue(wb.trial_may_start("P-24", done)[0])

    def test_default_mq_root_is_refused_before_any_change(self):
        fs = FakeSystem()
        fs.qdisc["winn3gw0"][0]["handle"] = "0:"
        for q in fs.qdisc["winn3gw0"][1:]:
            q["parent"] = ":" + q["parent"].split(":")[1]
        c = controller(fs, "P-24", dead_man_minutes=30)
        with self.assertRaises(wb.ArmError):
            c.begin()
        self.assertEqual(fs.mutations(), [])
        self.assertEqual(fs.timers, set())

    def test_confirm_stage_runs_in_its_own_invocation_from_prior_runs(self):
        t = wb.TRIALS["P-17"]
        ncs = {s.name: node_class(s.venue) for s in t.stages}
        with tempfile.TemporaryDirectory() as d:
            _, screen_runs = wb.run_trial(t, wb.DryRunBackend("latency_win", 1, venue="aicore"), wb.Evidence(d), ncs, 10, 1,
                                          stages={"aicore_cpu1", "aicore_cpu2"})
            dec, runs = wb.run_trial(t, wb.DryRunBackend("latency_win", 1, venue="canary"), wb.Evidence(d), ncs, 10, 1,
                                     stages={"canary_confirm"}, prior_runs=screen_runs)
        self.assertEqual({r["arm"] for r in runs}, {"base_a", "base_b", dec["chosen_arm"]})
        self.assertEqual(dec["rule_r_verdict"], "ADOPT")
        self.assertTrue(dec["adoptable"])

    def test_confirm_stage_cli_needs_prior_runs(self):
        with self.assertRaises(SystemExit):
            wb.main(["run", "--trial", "P-17", "--stage", "canary_confirm", "--out", "/nonexistent", "--venue", "canary",
                     "--measure-cmd", "true", "--execute"])

    def test_busy_poll_ceiling_is_0_2_core_at_most_5_points(self):
        self.assertEqual(wb.cpu_ceiling_for(wb.TRIALS["P-3"], 4), 5.0)
        self.assertEqual(wb.cpu_ceiling_for(wb.TRIALS["P-3"], 8), 2.5)
        self.assertEqual(wb.cpu_ceiling_for(wb.TRIALS["P-3"], 2), 5.0)
        self.assertEqual(wb.cpu_ceiling_for(wb.TRIALS["P-4"], 8), 0.0)
        runs = build_runs(wb.TRIALS["P-3"], cand={"bp50": {"ld_p50_ms": -40.0, "cpu_total_pct": 3.0}})
        self.assertEqual(decide("P-3", runs, {"canary": node_class(usable_cpus=4)})["rule_r_verdict"], "ADOPT")
        self.assertEqual(decide("P-3", runs, {"canary": node_class(usable_cpus=8)})["rule_r_verdict"], "REJECT")

    def test_fewer_than_ten_reps_is_never_adoptable(self):
        runs = build_runs(wb.TRIALS["P-4"], reps=5, cand={"fl100": {"ld_p50_ms": -40.0}})
        d = decide("P-4", runs, min_reps=5)
        self.assertEqual(d["rule_r_verdict"], "ADOPT")
        self.assertFalse(d["adoptable"])
        self.assertTrue(decide("P-4", build_runs(wb.TRIALS["P-4"], cand={"fl100": {"ld_p50_ms": -40.0}}))["adoptable"])

    def _aicore_run(self, fs):
        import unittest.mock as mock
        rec = {"started": True, "alive": True, "idle_p50_ms": 70, "ld_p50_ms": 190, "ld_p99_ms": 215, "ld_jitter_ms": 4,
               "ld_loss_pct": 0.2, "thr_mbps": 800}
        cmd = "%s -c %s" % (shlex.quote(sys.executable), shlex.quote("import json;print(json.dumps(%r))" % rec))
        fs.files.update({"/proc/cpuinfo": "processor : 0\nmodel name : AMD Ryzen 7 PRO 8845HS\n", "/proc/meminfo": "MemTotal: 4194304 kB\n",
                         "/gw": "b"})
        old = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP)}
        try:
            with tempfile.TemporaryDirectory() as d, mock.patch.object(wb, "make_runner", return_value=fs), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                wb.main(["run", "--trial", "P-17", "--stage", "aicore_cpu1", "--out", os.path.join(d, "ev"), "--venue", "aicore",
                         "--measure-cmd", cmd, "--reps", "1", "--min-reps", "1", "--execute", "--functional"])
                trapped = all(signal.getsignal(s) not in (signal.SIG_DFL, signal.SIG_IGN) for s in old)
        finally:
            for s, h in old.items():
                signal.signal(s, h)
        return trapped

    def test_aicore_stage_takes_and_releases_the_canonical_lock(self):
        fs = FakeSystem()
        self.assertTrue(self._aicore_run(fs))                # SIGTERM and SIGHUP revert at once
        self.assertTrue(any(l == "mkdir /home/aicore/.bench.lock" for l in fs.log))
        self.assertLess(fs.index_of("mkdir /home/aicore/.bench.lock"), fs.mutations()[0])
        self.assertNotIn("/home/aicore/.bench.lock", fs.dirs)

    def test_aicore_stage_refuses_a_held_lock(self):
        fs = FakeSystem()
        fs.dirs.add("/home/aicore/.bench.lock")
        with self.assertRaises(wb.ArmError):
            self._aicore_run(fs)
        self.assertEqual(fs.mutations(), [])


class T2Fixes(unittest.TestCase):
    """Turn 1 to Turn 2 fixes (Sol's DISAGREE items and the P3-QUESTIONS rulings). Each test fails on
    the Turn 1 tree and passes here; the mutants named U* in the runner each break one of them."""

    # -- the dead-man script, run for real by /bin/sh against PATH shims
    SYSCTL_SHIM = ("#!/bin/sh\n"
                   "if [ \"$1\" = \"-w\" ]; then\n"
                   "  [ \"${FAKE_W_RC:-0}\" != 0 ] && exit \"$FAKE_W_RC\"\n"
                   "  [ \"${FAKE_IGNORE:-0}\" = 1 ] && exit 0\n"
                   "  shift; for kv in \"$@\"; do echo \"${kv#*=}\" > \"$FAKE_DIR/${kv%%=*}\"; done; exit 0\n"
                   "fi\n"
                   "if [ \"$1\" = \"-n\" ]; then cat \"$FAKE_DIR/$2\"; exit 0; fi\n"
                   "exit 2\n")

    def _dead_man(self, d, **env):
        """Build P-3's dead-man script through the controller, leave the node at busy_poll 50 with the
        marker present, run the script with sh, and return (rc, marker still there, values after)."""
        fs = FakeSystem()
        marker = os.path.join(d, "perf-trial.env")
        c = controller(fs, "P-3", marker_path=marker)
        c.begin()
        script = os.path.join(d, "revert.sh")
        open(script, "w").write(fs.files[c.script_path])
        bindir = os.path.join(d, "bin")
        os.makedirs(bindir, exist_ok=True)
        open(os.path.join(bindir, "sysctl"), "w").write(self.SYSCTL_SHIM)
        os.chmod(os.path.join(bindir, "sysctl"), 0o755)
        for k in wb.BusyPoll.keys:
            open(os.path.join(d, k), "w").write("50\n")
        open(marker, "w").write("x")
        e = {"PATH": bindir + ":/usr/bin:/bin", "FAKE_DIR": d}
        e.update(env)
        p = subprocess.run(["/bin/sh", script], env=e, capture_output=True, text=True, timeout=30)
        vals = [open(os.path.join(d, k)).read().strip() for k in wb.BusyPoll.keys]
        return p.returncode, os.path.exists(marker), vals

    def test_dead_man_script_keeps_the_marker_unless_the_revert_is_proven(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self._dead_man(d), (0, False, ["0", "0"]))                      # proven: marker gone
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self._dead_man(d, FAKE_W_RC="1"), (1, True, ["50", "50"]))      # revert command failed
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self._dead_man(d, FAKE_IGNORE="1"), (1, True, ["50", "50"]))    # "succeeded", changed nothing

    def test_dead_man_script_attempts_every_command_after_a_failure(self):
        with tempfile.TemporaryDirectory() as d:
            later, marker = os.path.join(d, "later"), os.path.join(d, "m")
            open(marker, "w").write("x")
            script = os.path.join(d, "s.sh")
            open(script, "w").write(wb.revert_script("T", [["false"], ["touch", later]], marker_path=marker))
            p = subprocess.run(["/bin/sh", script], env={"PATH": "/usr/bin:/bin"}, capture_output=True, timeout=30)
            self.assertEqual((p.returncode, os.path.exists(later), os.path.exists(marker)), (1, True, True))

    def test_every_config_knob_has_dead_man_read_back_checks(self):
        for tid in ("P-17", "P-4", "P-22", "P-3", "P-10", "P-24"):
            fs = FakeSystem()
            c = controller(fs, tid)
            c.begin()
            checks = c.revert_checks()
            self.assertTrue(checks, tid)
            for cond in checks:
                self.assertIn(cond + " || fail=1", fs.files[c.script_path], tid)

    def test_fq_dead_man_check_matches_the_exact_value(self):
        fs = FakeSystem()
        c = controller(fs, "P-4")
        c.begin()
        (cond,) = c.revert_checks()
        captured = c.states["fq_flow_limit"]["tc"]
        with tempfile.TemporaryDirectory() as d:
            bindir = os.path.join(d, "bin")
            os.makedirs(bindir)
            open(os.path.join(bindir, "tc"), "w").write("#!/bin/sh\ncat \"$FAKE_JSON\"\n")
            os.chmod(os.path.join(bindir, "tc"), 0o755)
            # Turn 3: the whole captured tree must come back (Astra T2 finding 1): every option, not one
            # field; a reformatted equal tree, or one the kernel gave a new handle or refcount, is the same tree
            compact = json.dumps(json.loads(captured), separators=(",", ":"))
            renumbered = json.dumps([dict(q, handle="8ffe:", refcnt=3) for q in json.loads(captured)])
            for text, want in ((captured, 0), (captured + "\n", 0), (compact, 0), (renumbered, 0),
                               ('[{"kind":"fq","handle":"8001:","root":true,"options":{"limit":20480,"flow_limit":256}}]', 1),
                               ('[{"kind": "fq", "options": {"flow_limit": 256, "quantum": 1280}}]', 1),
                               (captured.replace('"flow_limit": 256', '"flow_limit": 2560'), 1),
                               (captured.replace('"root": true', '"parent": "1:1"'), 1),
                               ('[{"kind":"fq","options":{"flow_limit":25,"x":6}}]', 1)):
                j = os.path.join(d, "q.json")
                open(j, "w").write(text)
                p = subprocess.run(["/bin/sh", "-c", cond], env={"PATH": bindir + ":/usr/bin:/bin", "FAKE_JSON": j},
                                   capture_output=True, timeout=30)
                self.assertEqual(p.returncode != 0, bool(want), text)

    # -- controller: revert proof, marker and timers
    def test_noqueue_revert_proves_the_ring_length(self):
        fs = FakeSystem()
        c = controller(fs, "P-24")
        c.begin()
        c.switch("noqueue")
        fs.qlen["winn3gw0"] = 111                    # something changed the ring while noqueue was live
        fs.ignore.append("txqueuelen 10000")          # and the restore is silently ignored
        with self.assertRaises(wb.RevertFailed) as cm:
            c.finish()
        self.assertIn("txqueuelen", str(cm.exception))
        self.assertIn("/etc/winsvpn/perf-trial.env", fs.files)

    def test_finish_does_not_claim_success_when_the_marker_or_timer_stays(self):
        # Turn 3 order (Astra T2 finding 2): every reverter is stopped before the marker goes, so a timer
        # can never fire after the marker is cleared and a later trial has started
        fs = FakeSystem()
        c = controller(fs, "P-4", dead_man_minutes=20)
        c.begin()
        fs.fail.append(("rm -f /etc/winsvpn/perf-trial.env", 1))
        with self.assertRaises(wb.ArmError):
            c.finish()
        self.assertIn("/etc/winsvpn/perf-trial.env", fs.files)     # the drift marker stays
        self.assertEqual(fs.timers, set())                         # and no reverter is left to race a later trial
        self.assertTrue(c.began)
        fs.fail[:] = []
        c.finish()
        self.assertNotIn("/etc/winsvpn/perf-trial.env", fs.files)
        fs = FakeSystem()
        c = controller(fs, "P-4", dead_man_minutes=20)
        c.begin()
        fs.fail[:] = [("systemctl stop winn3-perf-revert", 5)]
        with self.assertRaises(wb.ArmError):
            c.finish()
        self.assertIn("/etc/winsvpn/perf-trial.env", fs.files)     # a timer that will not stop keeps the marker
        self.assertEqual(len(fs.timers), 1)
        fs.fail[:] = []
        c.finish()
        self.assertEqual((fs.timers, c.dead_man_units), (set(), []))
        self.assertNotIn("/etc/winsvpn/perf-trial.env", fs.files)

    def test_a_previous_timer_that_will_not_stop_ends_the_trial(self):
        fs = FakeSystem()
        c = controller(fs, "P-4", dead_man_minutes=20)
        c.begin()
        fs.fail.append(("systemctl stop winn3-perf-revert", 5))
        with self.assertRaises(wb.ArmError):
            c.switch("fl2048")
        self.assertFalse(any("flow_limit 2048" in l for l in fs.log))

    def test_marker_names_the_live_arm_and_a_second_trial_is_refused(self):
        fs = FakeSystem()
        c = controller(fs, "P-4")
        c.begin()
        c.switch("fl1024")
        text = fs.files["/etc/winsvpn/perf-trial.env"]
        self.assertIn("WINS_PERF_TRIAL=P-4/fl1024", text)
        self.assertIn("WINS_PERF_TRIAL_VALUES=flow_limit=1024", text)
        before = len(fs.mutations())
        with self.assertRaises(wb.ArmError):
            controller(fs, "P-3").begin()           # the marker of the running trial is there
        self.assertEqual(len(fs.mutations()), before)
        c.finish()
        self.assertNotIn("/etc/winsvpn/perf-trial.env", fs.files)

    def test_a_run_during_which_the_dead_man_fired_is_not_recorded(self):
        fs = FakeSystem()

        class Fires(wb.DryRunBackend):
            n = 0

            def measure(self, ctx):
                Fires.n += 1
                if Fires.n == 7:                      # the dead-man ran in the middle of this run
                    fs.timers.clear()
                    fs.files.pop("/etc/winsvpn/perf-trial.env", None)
                    fs.qdisc["eth0"][0]["options"]["flow_limit"] = 256
                return super().measure(ctx)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(wb.ArmError):
                wb.run_trial(wb.TRIALS["P-4"], Fires("neutral", 1, venue="canary"), wb.Evidence(d), {"canary": node_class()},
                             2, 1, controller_factory=lambda st: controller(fs, "P-4", dead_man_minutes=20))
            lines = open(os.path.join(d, "runs.jsonl")).read().splitlines()
        self.assertEqual(len(lines), 6)

    # -- bench order and its state file
    def _eligible_fs(self):
        fs = FakeSystem()
        fs.files.update({"/proc/cpuinfo": "processor : 0\nmodel name : X\nprocessor : 1\n",
                         "/proc/meminfo": "MemTotal: 4194304 kB\n", "/gw": "b"})
        return fs

    def _run(self, fs, *extra):
        import unittest.mock as mock
        rec = {"started": True, "alive": True, "idle_p50_ms": 70, "ld_p50_ms": 190, "ld_p99_ms": 215, "ld_jitter_ms": 4,
               "ld_loss_pct": 0.2, "thr_mbps": 800, "awg_mbps": 300, "xray_mbps": 250, "awg_ld_p99_ms": 60, "xray_ld_p99_ms": 70}
        cmd = "%s -c %s" % (shlex.quote(sys.executable), shlex.quote("import json;print(json.dumps(%r))" % rec))
        with tempfile.TemporaryDirectory() as d, mock.patch.object(wb, "make_runner", return_value=fs):
            return Cli().call("run", "--trial", "P-4", "--stage", "canary", "--out", os.path.join(d, "ev"), "--venue", "canary",
                              "--provider", "ovh", "--binary", "/gw", "--measure-cmd", cmd, "--reps", "1", "--min-reps", "1",
                              "--execute", *[a.replace("@D", d) for a in extra])

    def test_execute_needs_the_bench_order_state(self):
        fs = self._eligible_fs()
        with self.assertRaises(SystemExit) as cm:
            self._run(fs)
        self.assertIn("bench order", str(cm.exception))
        self.assertEqual(fs.mutations(), [])

    def test_execute_refuses_an_ineligible_venue_before_any_change(self):
        fs = self._eligible_fs()
        fs.virt = "qemu"
        with tempfile.TemporaryDirectory() as d:
            st = os.path.join(d, "st.json")
            json.dump({"P-17": "ADOPT"}, open(st, "w"))
            with self.assertRaises(SystemExit) as cm:
                self._run(fs, "--state", st)
            self.assertIn("not eligible", str(cm.exception))
            self.assertEqual(fs.mutations(), [])
            rc, out = self._run(fs, "--state", st, "--functional")      # explicitly functional: runs, never counts
            self.assertFalse(json.loads(out)["adoptable"])
            self.assertEqual(json.load(open(st)), {"P-17": "ADOPT"})       # and writes no verdict

    def test_not_run_is_a_deferral_with_a_reason_and_state_set_validates(self):
        priors = {"P-17": "ADOPT", "P-4": "REJECT", "P-22": "NO_PURPOSE", "P-3": "INCONCLUSIVE", "P-10": "ADOPT",
                  "P-41": "NOT_RUN", "P-46": "NOT_RUN", "P-41.deferral": "r", "P-46.deferral": "r",
                  "P-24.condition": "met", "P-24.condition_evidence": "e" * 64}
        ok, why = wb.trial_may_start("P-24", dict(priors, **{"P-18": "NOT_RUN"}))
        self.assertFalse(ok)
        self.assertIn("deferral", why)
        self.assertTrue(wb.trial_may_start("P-24", dict(priors, **{"P-18": "NOT_RUN", "P-18.deferral": "gateway round 3"}))[0])
        self.assertEqual(wb.deferred_priors("P-24", dict(priors, **{"P-18": "NOT_RUN", "P-18.deferral": "g"}))["P-18"], "g")
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "s.json")
            for argv in (("--trial", "P-4", "--verdict", "done"), ("--trial", "P-4", "--verdict", "NOT_RUN", "--reason", "x"),
                         ("--trial", "P-18", "--verdict", "NOT_RUN"), ("--trial", "P-24.condition", "--verdict", "met"),
                         ("--trial", "P-17", "--verdict", "PENDING_CONFIRM")):
                with self.assertRaises(SystemExit, msg=argv):
                    Cli().call("state", "set", "--file", f, *argv)
            self.assertFalse(os.path.exists(f))
            Cli().call("state", "set", "--file", f, "--trial", "P-18", "--verdict", "NOT_RUN", "--reason", "own gateway round")
            self.assertEqual(json.load(open(f)), {"P-18": "NOT_RUN", "P-18.deferral": "own gateway round"})

    # -- P-24 condition (OQ10)
    def _ring_rows(self, backlog=None, drops=None, arms=("base_a", "ring4096", "ring2048", "ring1024"), reps=(("a", 3), ("b", 3))):
        rows = []
        for prof, n in reps:
            for arm in arms:
                for rep in range(n):
                    rows.append({"trial": "P-17", "stage": "aicore_cpu1", "arm": arm, "started": True, "alive": True,
                                 "profile": prof, "fq_child_backlog_pkts_max": (backlog or {}).get((arm, prof), 0),
                                 "tx_drops": (drops or {"ring1024": 900}).get(arm, 0)})
        return rows

    def test_p24_condition_is_per_profile_and_needs_every_ring(self):
        self.assertTrue(wb.p24_condition(self._ring_rows(), "aicore_cpu1")["met"])
        # profile b holds a backlog on the 2048 ring; pooled with profile a's three zeros the median would be 0
        hidden = self._ring_rows(backlog={("ring2048", "b"): 50}, reps=(("a", 3), ("b", 2)))
        self.assertFalse(wb.p24_condition(hidden, "aicore_cpu1")["met"])
        missing = self._ring_rows(arms=("base_a", "ring4096", "ring1024"))
        d = wb.p24_condition(missing, "aicore_cpu1")
        self.assertFalse(d["met"])
        self.assertIn("ring2048 profile a", d["missing"])

    def test_p24_condition_is_recorded_bound_to_the_p17_runs(self):
        with tempfile.TemporaryDirectory() as d:
            f, st = os.path.join(d, "r.jsonl"), os.path.join(d, "st.json")
            open(f, "w").write("\n".join(json.dumps(r) for r in self._ring_rows()))
            rc, out = Cli().call("p24-condition", "--runs", f, "--stage", "aicore_cpu1", "--state", st)
            self.assertEqual(rc, 0)
            state = json.load(open(st))
            self.assertEqual(state["P-24.condition"], "met")
            self.assertEqual(state["P-24.condition_evidence"], wb.sha256_file(f))
        priors = {t: ("NOT_RUN" if wb.TRIALS[t].kind == "binary" else "ADOPT") for t in wb.BENCH_ORDER[:wb.BENCH_ORDER.index("P-24")]}
        priors.update({t + ".deferral": "r" for t in priors if wb.TRIALS[t].kind == "binary"})
        self.assertFalse(wb.trial_may_start("P-24", dict(priors, **{"P-24.condition": "met"}))[0])   # asserted by hand
        self.assertTrue(wb.trial_may_start("P-24", dict(priors, **state))[0])

    # -- venue evidence (S9, OQ16) and pinning (OQ7)
    def test_venue_needs_recognised_virtualization_evidence(self):
        for virt in (None, "", "unknown-hv", "qemu", "docker"):
            ok, reasons = wb.venue_eligibility(node_class("canary", virt=virt, emulated=wb.detect_emulation(virt or "")))
            self.assertFalse(ok, virt)
        nc = node_class("canary")
        del nc["emulated"]
        self.assertFalse(wb.venue_eligibility(nc)[0])
        for virt in ("kvm", "none", "microsoft"):
            self.assertTrue(wb.venue_eligibility(node_class("canary", virt=virt))[0], virt)

    def test_aicore_venue_needs_the_8845hs(self):
        ok, reasons = wb.venue_eligibility(node_class("aicore", cpu_model="AMD EPYC 7763"))
        self.assertFalse(ok)
        self.assertTrue(any("8845HS" in r for r in reasons))
        self.assertTrue(wb.venue_eligibility(node_class("aicore"))[0])

    def test_records_must_carry_the_stage_node_class_and_binary(self):
        t = wb.TRIALS["P-4"]
        runs = build_runs(t, cand={"fl100": {"ld_p50_ms": -40.0}})
        self.assertTrue(decide("P-4", runs)["adoptable"])
        for key, bad in (("node_class_id", "other"), ("binary_sha256", "b" * 64)):
            r2 = [dict(r) for r in runs]
            r2[3][key] = bad
            d = decide("P-4", r2)
            self.assertFalse(d["adoptable"], key)
            self.assertTrue(any("node class id and binary digest" in n for n in d["notes"]), key)

    def test_pinned_stage_needs_pinning_evidence(self):
        t = wb.TRIALS["P-17"]
        win = {"ring2048": {"ld_p50_ms": -60.0}}
        runs = (build_runs(t, stage="aicore_cpu1", cand=win, venue="aicore") + build_runs(t, stage="aicore_cpu2", cand=win, venue="aicore")
                + build_runs(t, stage="canary_confirm", cand=win, venue="canary"))
        self.assertTrue(decide("P-17", runs)["adoptable"])
        for r in runs:
            if r["stage"] == "aicore_cpu2":
                r["gw_cpus_observed"] = 4                       # the gateway ran on its natural count, not pinned to 2
        d = decide("P-17", runs)
        self.assertEqual(d["rule_r_verdict"], "ADOPT")
        self.assertFalse(d["adoptable"])
        self.assertTrue(any("pinned to 2 CPU" in n for n in d["notes"]))

    # -- rule R inputs (S5, OQ5, OQ6)
    def test_awg_xray_are_mandatory_on_every_canary_stage(self):
        t = wb.TRIALS["P-17"]
        runs = build_runs(t, stage="canary_confirm", venue="canary", cand={"ring2048": {"ld_p50_ms": -40.0}})
        for r in runs:
            r.pop("awg_mbps")
        d = wb.decide_screen(t, wb.index_runs(runs), "canary_confirm", arms=["ring2048"])
        self.assertEqual(d["verdict"], "INCONCLUSIVE")
        runs = build_runs(t, stage="aicore_cpu1", venue="aicore", cand={"ring2048": {"ld_p50_ms": -40.0}})
        for r in runs:
            r.pop("awg_mbps")
        self.assertEqual(wb.decide_screen(t, wb.index_runs(runs), "aicore_cpu1", arms=["ring2048"])["verdict"], "ADOPT")

    def test_a_partial_profile_cannot_establish_the_bar(self):
        t = wb.TRIALS["P-24"]
        runs = build_runs(t, stage="aicore", venue="aicore", cand={"noqueue": {"thr_mbps": 90.0, "rise": 30.0}},
                          extras={"base_rise": 30.0})
        self.assertEqual(screen("P-24", runs, stage="aicore")["verdict"], "ADOPT")
        for r in runs:
            if r["arm"] == "noqueue" and r["profile"] == "b" and r["rep"] > 2:
                r.pop("idle_p50_ms")                   # only 2 of 10 runs in each profile b cell carry the idle figure
        d = screen("P-24", runs, stage="aicore")
        self.assertEqual(d["verdict"], "OWNER_RULING_CANDIDATE")
        self.assertEqual(d["evidence_incomplete"], ["b"])
        self.assertTrue(any("evidence incomplete" in n for n in d["notes"]))
        self.assertIn("score_definition", d)

    # -- connect time (S6, S7, OQ11)
    def test_ct4m_errors_are_failed_attempts_and_ping_rows_cannot_pass(self):
        ok = {"server": "x", "kind": "cold", "handler": 0.05, "candidate": 0.4, "datapath": 0.5, "gate_carrying": 1.0,
              "carry": 1.5, "ping_carry": 1.6}
        rows = []
        for net in ("wifi", "cellular"):
            out = wb.connect_rows_from_ct4m([ok] * 10 + [{"server": "x", "kind": "cold", "error": "no t0"}], "c1", net)
            self.assertEqual((len(out), sum(1 for r in out if not r["ok"])), (11, 1))
            rows += out
        r = wb.analyze_connect_time(rows)
        self.assertNotEqual(r["verdict"], "PASS")
        self.assertEqual(r["verdict"], "WRONG_ENDPOINT")
        self.assertEqual(r["groups"]["c1|wifi"]["verdict"], "WRONG_ENDPOINT")

    def test_a_miss_without_stage_evidence_stays_unresolved(self):
        ct = ConnectTime()
        rows, base = [], []
        for net in ("wifi", "cellular"):
            rows += ct.rows([5.0] * 10, net=net)
            base += ct.rows([4.0] * 10, net=net)
        r = wb.analyze_connect_time(rows, base)
        self.assertEqual(r["groups"]["c1|wifi"]["miss_class"], "STAGE_EVIDENCE_INCOMPLETE")
        self.assertTrue(r["blocks_s7"])
        self.assertEqual(r["verdict"], "MISS_BLOCKS_S7")
        rows, base = [], []                                   # a stage missing from some baseline runs only
        for net in ("wifi", "cellular"):
            rows += ct.rows([4.5] * 10, net=net, stages=ConnectTime.STAGES)
            base += ct.rows([4.5] * 5, net=net, stages=ConnectTime.STAGES) + ct.rows([4.5] * 5, net=net)
        r = wb.analyze_connect_time(rows, base)
        self.assertEqual(r["groups"]["c1|wifi"]["incomplete_stages"], list(wb.CONNECT_STAGES))
        self.assertTrue(r["blocks_s7"])

    # -- L63 ingestion (S8)
    def test_l63_failure_classes_are_not_cut(self):
        prefix = "2026-09-26T18:22:59.123456Z winn3-client[4242]: session error: "
        a = wb.record_from_l63(dict(IngestL63.LINE, client_alive="0", cl_fail=prefix + "replay ratchet stale"),
                               "P-17", IngestL63.AM, IngestL63.SM, "aicore")
        b = wb.record_from_l63(dict(IngestL63.LINE, client_alive="0", cl_fail=prefix + "authorization refused by peer"),
                               "P-17", IngestL63.AM, IngestL63.SM, "aicore")
        self.assertNotEqual(a["failure_class"], b["failure_class"])
        self.assertTrue(b["failure_class"].endswith("authorization refused by peer"))
        t = wb.TRIALS["P-4"]
        runs = build_runs(t, cand={"fl100": {"ld_p50_ms": -40.0}},
                          failures={"base_a": [(1, a["failure_class"])], "fl100": [(1, b["failure_class"])]})
        self.assertEqual(screen("P-4", runs)["arms"]["fl100"]["reject"][-1], "adds session-failure class " + b["failure_class"])

    # -- raw evidence (S11)
    def test_measure_output_and_arm_commands_are_kept_as_raw_evidence(self):
        fs = FakeSystem()
        rec = {"started": True, "alive": True, "idle_p50_ms": 70, "ld_p50_ms": 190, "ld_p99_ms": 215, "ld_jitter_ms": 4,
               "ld_loss_pct": 0.2, "thr_mbps": 800}
        code = "import json,sys;print('raw-tool-line 198.51.100.9');print(json.dumps(%r));sys.stderr.write('warn\\n')" % rec
        backend = wb.CommandBackend("%s -c %s" % (shlex.quote(sys.executable), shlex.quote(code)), venue="canary")
        with tempfile.TemporaryDirectory() as d:
            _, runs = wb.run_trial(wb.TRIALS["P-22"], backend, wb.Evidence(d), {"canary": node_class()}, 1, 1,
                                   controller_factory=lambda st: controller(fs, "P-22"))
            self.assertTrue(all(r.get("raw", "").startswith("raw/measure_P-22_canary_") for r in runs))
            text = open(os.path.join(d, runs[0]["raw"])).read()
            self.assertIn("raw-tool-line", text)
            self.assertIn("warn", text)
            self.assertNotIn("198.51.100.9", text)                     # masked like every raw file
            arms_path = os.path.join(d, "raw", "arms_P-22_canary_commands.txt")
            self.assertTrue(os.path.exists(arms_path))
            arms = open(arms_path).read()
            self.assertIn("quantum 1514", arms)

    # -- analyses (OQ12, OQ13, OQ14)
    def test_storm_needs_fit_and_fsync_evidence(self):
        st = Storm()
        r = st.rec()
        del r["mem_total_kib"]
        self.assertEqual(wb.analyze_storm(r)["verdict"], "HOST_FIT_UNKNOWN")
        r = st.rec()
        del r["fio_p99_ms"]
        self.assertEqual(wb.analyze_storm(r)["verdict"], "MISSING_FSYNC_MEASUREMENT")
        self.assertEqual(wb.analyze_storm(st.rec())["verdict"], "NO_GROUP_COMMIT")

    def test_epoll_needs_a_real_summary(self):
        head = Epoll.TABLE.splitlines()[0] + "\n"
        for text in ("", "strace: attach: ptrace(PTRACE_SEIZE, 1): Operation not permitted\n", head,
                     "  0.10    0.000010           3         4           epoll_ctl\n"):
            self.assertEqual(wb.analyze_epoll(text, 20, True)["verdict"], "INVALID_RUN", repr(text))
        self.assertEqual(wb.analyze_epoll(head + " 61.20    0.012000          12      1000           futex\n", 20, True)["verdict"],
                         "DECLINE_CONFIRMED")

    def test_golive_enable_must_follow_every_proof(self):
        inst = GoLive().installs()
        inst[4]["proofs"]["offnode_gate"] = inst[4]["operator_enabled_at"] + 1.0
        r = wb.analyze_golive(inst)
        self.assertEqual(r["verdict"], "ENABLED_BEFORE_PROOF")
        self.assertEqual(r["late_proofs"][0]["proof"], "offnode_gate")

    # -- local driver (S10)
    def test_local_main_never_tears_down_a_rig_it_did_not_make(self):
        import unittest.mock as mock
        vm = LocalDriver.Vm(netns=["p3c"])
        with tempfile.TemporaryDirectory() as d, mock.patch.object(local, "colima_state", return_value="Running"), \
                mock.patch.object(local, "Vm", return_value=vm), contextlib.redirect_stderr(io.StringIO()):
            rc = local.main(["all", "--out", d])
        self.assertEqual(rc, 2)
        self.assertFalse(any("netns del" in l or "rm -rf" in l or "systemctl stop" in l for l in vm.log), vm.log)

    def test_local_teardown_stops_only_its_own_dead_man_timers(self):
        class Vm(LocalDriver.Vm):
            def run(self, argv, stdin=None, check=True, timeout=300):
                self.log.append(shlex.join(argv))
                if argv[:2] == ["systemctl", "list-units"]:
                    return wb.RunResult(0, "winn3-perf-revert-p-4-20261008t0000z-3.timer loaded active waiting x\n"
                                           "p3bench-revert-p-4-20261008t0000z-1.timer loaded active waiting y\n")
                return super().run(argv, stdin, check, timeout)
        vm = Vm()
        local.rig_down(vm)
        joined = "\n".join(vm.log)
        self.assertIn("systemctl stop p3bench-revert-p-4-20261008t0000z-1.timer", joined)
        self.assertNotIn("stop winn3-perf-revert", joined)


class T3Fixes(unittest.TestCase):
    """Turn 2 to Turn 3 fixes (Astra's four T2 findings). Each test fails on P3/t2 and passes here;
    the mutants named V* in the runner each break one of them."""

    # -- finding 1: the dead-man's qdisc read-back must prove the whole captured tree
    def _sh(self, cond, tc_text, ip_text=""):
        with tempfile.TemporaryDirectory() as d:
            bindir = os.path.join(d, "bin")
            os.makedirs(bindir)
            for name, var in (("tc", "FAKE_TC"), ("ip", "FAKE_IP")):
                open(os.path.join(bindir, name), "w").write("#!/bin/sh\ncat \"$%s\"\n" % var)
                os.chmod(os.path.join(bindir, name), 0o755)
            for var, text in (("FAKE_TC", tc_text), ("FAKE_IP", ip_text)):
                open(os.path.join(d, var), "w").write(text)
            p = subprocess.run(["/bin/sh", "-c", cond], capture_output=True, timeout=30,
                               env={"PATH": bindir + ":/usr/bin:/bin", "FAKE_TC": os.path.join(d, "FAKE_TC"),
                                    "FAKE_IP": os.path.join(d, "FAKE_IP")})
            return p.returncode

    def _all_sh(self, conds, tc_text, ip_text=""):
        return 0 if all(self._sh(c, tc_text, ip_text) == 0 for c in conds) else 1

    def _py(self, c, kind, tc_text, ip_text=""):
        read = lambda argv: tc_text if "tc" in argv else ip_text
        return wb.KNOBS[kind].check_reverted(c.t, c.states[kind], read)

    def test_dead_man_qdisc_checks_need_the_whole_captured_tree(self):
        for tid, kind in (("P-4", "fq_flow_limit"), ("P-22", "fq_quantum")):
            fs = FakeSystem()
            c = controller(fs, tid)
            c.begin()
            captured = c.states[kind]["tc"]
            conds = c.revert_checks()
            self.assertEqual(self._all_sh(conds, captured + "\n"), 0, tid)              # unchanged capture: proven
            partial = json.dumps([dict(fs.qdisc["eth0"][0], options=dict(FQ_DEFAULT, limit=1))])
            self.assertTrue(self._py(c, kind, partial), tid)                          # Python already rejects it
            self.assertEqual(self._all_sh(conds, partial), 1, tid)                     # and so must the dead-man
        fs = FakeSystem()
        c = controller(fs, "P-24")
        c.begin()
        captured = c.states["tun_noqueue"]["tc"]
        conds = c.revert_checks()
        link = fs.run(["ip", "-o", "link", "show", "dev", "winn3gw0"]).out
        self.assertEqual(self._all_sh(conds, captured, link), 0)
        root_only = json.dumps(fs.qdisc["winn3gw0"][:1])                              # mq root back, fq children missing
        self.assertTrue(self._py(c, "tun_noqueue", root_only, link))
        self.assertEqual(self._all_sh(conds, root_only, link), 1)
        # Turn 4 (P3-P24-EXACT): compared semantically, still every Astra counterexample above fails, and so do these
        entries = json.loads(captured)
        moved = json.dumps([entries[0], dict(entries[1], parent="1:1"), dict(entries[2], parent="1:1")] + entries[3:])
        self.assertTrue(self._py(c, "tun_noqueue", moved, link))                       # two children on 1:1, none on 1:2
        self.assertEqual(self._all_sh(conds, moved, link), 1)
        extra = json.dumps(entries + [dict(entries[1], parent="1:5")])
        self.assertEqual(self._all_sh(conds, extra, link), 1)                         # a child the capture never had
        duplicate = json.dumps(entries + [dict(entries[1], handle="8fff:")])
        self.assertEqual(self._all_sh(conds, duplicate, link), 1)                     # one child twice
        child = json.dumps([entries[0], dict(entries[1], options=dict(entries[1]["options"], flow_limit=1))] + entries[2:])
        self.assertEqual(self._all_sh(conds, child, link), 1)                         # one child's option off
        moved_root = json.dumps([{"kind": "mq", "handle": "1:", "parent": "ffff:fff1", "options": {}}] + entries[1:])
        self.assertEqual(self._all_sh(conds, moved_root, link), 1)                    # the mq is no longer the root
        c.switch("noqueue")
        noqueue = json.dumps(fs.qdisc["winn3gw0"])
        self.assertEqual(self._all_sh(conds, noqueue, link), 1)                       # the arm itself is never proof
        c.switch("base_a")                                                            # the revert rebuilds the tree
        rebuilt = json.dumps(fs.qdisc["winn3gw0"])
        self.assertNotEqual([q["handle"] for q in fs.qdisc["winn3gw0"]], [q["handle"] for q in entries])
        self.assertEqual(self._all_sh(conds, rebuilt, link), 0)                       # new handles: still proven
        self.assertEqual(self._all_sh(conds, json.dumps([entries[0]] + list(reversed(entries[1:]))), link), 0)
        fs.qlen["winn3gw0"] = 1000
        short = fs.run(["ip", "-o", "link", "show", "dev", "winn3gw0"]).out
        self.assertEqual(self._all_sh(conds, captured, short), 1)                    # tree right, ring wrong

    # -- finding 2: a timer whose stop failed stays known until it is stopped
    def test_a_timer_that_will_not_stop_keeps_the_marker_and_blocks_the_next_trial(self):
        fs = FakeSystem()
        c = controller(fs, "P-3", dead_man_minutes=20)
        c.begin()
        old = c.dead_man_unit
        fs.fail.append(("systemctl stop %s.timer" % old, 5))
        with self.assertRaises(wb.ArmError):
            c.switch("bp50")
        self.assertIn(old + ".timer", fs.timers)                  # the old timer is still pending
        self.assertIn("/etc/winsvpn/perf-trial.env", fs.files)    # so the marker stays
        self.assertTrue(c.began)
        self.assertEqual(c.dead_man_units, [old])
        before = len(fs.mutations())
        with self.assertRaises(wb.ArmError):
            controller(fs, "P-3").begin()                         # and no second trial can start under it
        self.assertEqual(len(fs.mutations()), before)
        fs.fail[:] = []
        c.finish()                                                # recovery: stop it, prove, clear
        self.assertEqual((fs.timers, c.dead_man_units, c.began), (set(), [], False))
        self.assertNotIn("/etc/winsvpn/perf-trial.env", fs.files)

    def test_finish_stops_each_reverter_service_and_proves_the_revert_again(self):
        class Killed(FakeSystem):
            stuck = False

            def cmd_systemctl(self, argv, stdin):
                if argv[1] == "stop" and any(u.endswith(".service") for u in argv[2:]):
                    # the reverter had fired and is stopped mid-script: its 'qdisc del root' ran, the rebuild did not
                    self.qdisc["winn3gw0"] = []
                    if self.stuck:
                        self.ignore.append("qdisc replace dev winn3gw0")    # and the tree cannot be rebuilt now
                return super().cmd_systemctl(argv, stdin)
        fs = Killed()
        c = controller(fs, "P-24", dead_man_minutes=20)
        c.begin()
        first = c.dead_man_unit
        c.switch("noqueue")
        self.assertIn("systemctl stop %s.timer %s.service" % (first, first), fs.log)     # re-arm stops both too
        unit = c.dead_man_unit
        c.finish()
        self.assertIn("systemctl stop %s.timer %s.service" % (unit, unit), fs.log)
        self.assertEqual(wb.tree_signature(wb.parse_qdisc_json(json.dumps(fs.qdisc["winn3gw0"]))),
                         wb.tree_signature(wb.parse_qdisc_json(c.states["tun_noqueue"]["tc"])))
        self.assertNotIn("/etc/winsvpn/perf-trial.env", fs.files)
        fs = Killed()
        c = controller(fs, "P-24", dead_man_minutes=20)
        c.begin()
        c.switch("noqueue")
        fs.stuck = True
        with self.assertRaises(wb.RevertFailed):
            c.finish()                                            # the proof after the stops fails
        self.assertIn("/etc/winsvpn/perf-trial.env", fs.files)    # so the marker stays
        self.assertTrue(c.began)

    # -- finding 3: the P-24 condition reads P-17 rows only
    def test_p24_condition_counts_only_p17_rows(self):
        rows = T2Fixes._ring_rows(self)
        self.assertTrue(wb.p24_condition(rows, "aicore_cpu1")["met"])
        for bad in ("P-99", "P-24", None):
            d = wb.p24_condition([dict(r, trial=bad) for r in rows], "aicore_cpu1")
            self.assertFalse(d["met"], bad)
            self.assertIn("ring10000 profile a", d["missing"], bad)
        unlabelled = [{k: v for k, v in r.items() if k != "trial"} for r in rows]
        self.assertFalse(wb.p24_condition(unlabelled, "aicore_cpu1")["met"])
        # P-17's own rows hold a backlog on the 2048 ring; foreign rows must not pull its median to 0
        own = T2Fixes._ring_rows(self, backlog={("ring2048", "a"): 50, ("ring2048", "b"): 50})
        foreign = [dict(r, trial="P-99") for r in T2Fixes._ring_rows(self, reps=(("a", 5), ("b", 5)))]
        self.assertFalse(wb.p24_condition(own + foreign, "aicore_cpu1")["met"])
        with tempfile.TemporaryDirectory() as d:
            f, st = os.path.join(d, "r.jsonl"), os.path.join(d, "st.json")
            open(f, "w").write("\n".join(json.dumps(dict(r, trial="P-99")) for r in rows))
            rc, out = Cli().call("p24-condition", "--runs", f, "--stage", "aicore_cpu1", "--state", st)
            self.assertEqual((rc, json.load(open(st))["P-24.condition"]), (1, "not_met"))

    # -- finding 4: a normal run saves its deferrals in the verdict it writes
    def test_a_normal_run_saves_its_deferrals_in_the_verdict(self):
        import unittest.mock as mock
        fs = FakeSystem()
        fs.files.update({"/proc/cpuinfo": "processor : 0\nmodel name : AMD Ryzen 7 PRO 8845HS\nprocessor : 1\n",
                         "/proc/meminfo": "MemTotal: 4194304 kB\n", "/gw": "b"})
        priors = {t: ("NOT_RUN" if wb.TRIALS[t].kind == "binary" else "ADOPT") for t in wb.BENCH_ORDER[:wb.BENCH_ORDER.index("P-24")]}
        priors.update({t + ".deferral": "own gateway round " + t for t in list(priors) if wb.TRIALS[t].kind == "binary"})
        priors.update({"P-24.condition": "met", "P-24.condition_evidence": "e" * 64})
        rec = {"started": True, "alive": True, "idle_p50_ms": 70, "ld_p50_ms": 190, "ld_p99_ms": 215, "ld_jitter_ms": 4,
               "ld_loss_pct": 0.2, "thr_mbps": 800}
        cmd = "%s -c %s" % (shlex.quote(sys.executable), shlex.quote("import json;print(json.dumps(%r))" % rec))
        old = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP)}
        try:
            with tempfile.TemporaryDirectory() as d, mock.patch.object(wb, "make_runner", return_value=fs):
                st, ev = os.path.join(d, "st.json"), os.path.join(d, "ev")
                json.dump(priors, open(st, "w"))
                rc, out = Cli().call("run", "--trial", "P-24", "--stage", "aicore", "--out", ev, "--venue", "aicore",
                                     "--provider", "aicore", "--binary", "/gw", "--measure-cmd", cmd, "--reps", "1",
                                     "--min-reps", "1", "--execute", "--state", st)
                verdict = os.path.join(ev, "verdict_P-24.json")
                saved = json.load(open(verdict))
                manifest = json.load(open(os.path.join(ev, "MANIFEST.json")))["files"]
                self.assertEqual(manifest["verdict_P-24.json"], wb.sha256_file(verdict))
        finally:
            for s, h in old.items():
                signal.signal(s, h)
        self.assertEqual(rc, 0)
        for doc in (json.loads(out), saved):
            note = [n for n in doc["notes"] if n.startswith("ran with earlier gateway-round trials deferred")]
            self.assertEqual(len(note), 1)
            for t in ("P-18", "P-41", "P-46"):
                self.assertIn("%s (own gateway round %s)" % (t, t), note[0])

    # -- guard for the local driver: finish() now clears dead_man_unit
    def test_local_arms_smoke_finishes_every_trial_on_a_fake_node(self):
        fs = FakeSystem()
        fs.qdisc = {"p3s0": fs.qdisc["eth0"], "p3g0": fs.qdisc["winn3gw0"]}
        fs.qlen = {"p3s0": 1000, "p3g0": 10000}
        fs.units["p3bench-gw.service"] = fs.units.pop("winn3-gateway.service")

        class Vm:
            r = fs

            def run(self, argv, stdin=None, check=True, timeout=300):
                r = fs.run(argv, stdin)
                if check and r.rc != 0:
                    raise wb.ArmError("fake vm: rc %d: %s" % (r.rc, shlex.join(argv)))
                return r
        with tempfile.TemporaryDirectory() as d:
            try:
                out = local.arms_smoke(Vm(), wb.Evidence(d))
            except Exception as exc:                  # e.g. reading the unit name finish() has cleared
                self.fail("arms_smoke raised %s: %s" % (type(exc).__name__, exc))
        for tid in wb.BENCH_ORDER:
            if wb.TRIALS[tid].kind == "config":
                self.assertFalse(out[tid]["marker_after"], tid)
                self.assertEqual(len(out[tid]["arms"]), 1 + len(wb.TRIALS[tid].arms), tid)
        self.assertEqual(fs.timers, set())


class T4Fixes(unittest.TestCase):
    """Turn 3 to Turn 4 fixes (Fable's P3-T3 and P3-P24-EXACT DISAGREE: the P-24 dead-man could never
    remove its marker after its own revert; Claude's and Fable's finish() advisory). Each test fails on
    P3/t3 and passes here; the mutants V3 (retargeted) and V13 to V17 each break one of them."""

    SHIM = ("#!%s -IB\n"
            "import importlib.util, json, os, sys\n"
            "spec = importlib.util.spec_from_file_location('p3_suite_shim', os.environ['FAKE_SUITE'])\n"
            "T = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(T)\n"
            "st = json.load(open(os.environ['FAKE_STATE']))\n"
            "fs = T.FakeSystem()\n"
            "fs.qdisc, fs.qlen, fs.handle_seq = st['qdisc'], st['qlen'], st['handle_seq']\n"
            "fs.ignore, fs.dump_children_reversed = st['ignore'], st['reversed']\n"
            "r = fs.run([os.path.basename(sys.argv[0])] + sys.argv[1:])\n"
            "st.update(qdisc=fs.qdisc, qlen=fs.qlen, handle_seq=fs.handle_seq)\n"
            "json.dump(st, open(os.environ['FAKE_STATE'], 'w'))\n"
            "sys.stdout.write(r.out)\n"
            "sys.stderr.write(r.err)\n"
            "sys.exit(r.rc)\n")

    def _run_dead_man(self, d, fs, c, marker, shell, ignore=(), reverse=True):
        """Run the generated dead-man script with `shell`, its tc and ip answered by a FakeSystem that
        starts from fs's current state and is changed by the script's own commands. Returns (rc,
        marker still there, the winn3gw0 tree the script left behind)."""
        bindir = os.path.join(d, "bin")
        os.makedirs(bindir, exist_ok=True)
        for name in ("tc", "ip"):
            open(os.path.join(bindir, name), "w").write(self.SHIM % sys.executable)
            os.chmod(os.path.join(bindir, name), 0o755)
        state = os.path.join(d, "state.json")
        json.dump({"qdisc": fs.qdisc, "qlen": fs.qlen, "handle_seq": getattr(fs, "handle_seq", 0x9000),
                   "ignore": list(ignore), "reversed": reverse}, open(state, "w"))
        script = os.path.join(d, "revert.sh")
        open(script, "w").write(fs.files[c.script_path])
        open(marker, "w").write("x")
        env = {"PATH": bindir + ":/usr/bin:/bin", "FAKE_STATE": state, "FAKE_SUITE": os.path.abspath(__file__)}
        for k in ("WINN3_PERF_BENCH_MODULE", "WINN3_PERF_BENCH_LOCAL_MODULE"):
            if os.environ.get(k):
                env[k] = os.environ[k]
        p = subprocess.run([shell, script], env=env, capture_output=True, text=True, timeout=120)
        return p.returncode, os.path.exists(marker), json.load(open(state))["qdisc"]["winn3gw0"], p.stderr

    def _shells(self):
        return [sh for sh in ("/bin/sh", "/bin/dash") if os.path.exists(sh)]

    def test_p24_dead_man_clears_its_marker_after_its_own_revert(self):
        # Fable's reproduction: the trial is on noqueue when the dead-man fires; the script deletes the root
        # and rebuilds mq and its fq children, which get fresh handles and are dumped in another order
        for shell in self._shells():
            with tempfile.TemporaryDirectory() as d:
                marker = os.path.join(d, "perf-trial.env")
                fs = FakeSystem()
                c = controller(fs, "P-24", marker_path=marker)
                c.begin()
                c.switch("noqueue")
                captured = json.loads(c.states["tun_noqueue"]["tc"])
                rc, kept, tree, err = self._run_dead_man(d, fs, c, marker, shell)
                self.assertEqual((rc, kept), (0, False), (shell, err))
                self.assertTrue(all(q["handle"] != p["handle"] for q, p in zip(tree[1:], captured[1:])), shell)
                self.assertEqual(wb.tree_signature(wb.parse_qdisc_json(json.dumps(tree))),
                                 wb.tree_signature(wb.parse_qdisc_json(json.dumps(captured))), shell)
            with tempfile.TemporaryDirectory() as d:
                marker = os.path.join(d, "perf-trial.env")
                fs = FakeSystem()
                c = controller(fs, "P-24", marker_path=marker)
                c.begin()
                c.switch("noqueue")
                # one child's rebuild is silently ignored: the read-back must still refuse
                rc, kept, tree, err = self._run_dead_man(d, fs, c, marker, shell, ignore=["parent 1:3"])
                self.assertEqual((rc, kept, len(tree)), (1, True, 4), shell)
            with tempfile.TemporaryDirectory() as d:
                marker = os.path.join(d, "perf-trial.env")
                fs = FakeSystem()
                c = controller(fs, "P-24", marker_path=marker)
                c.begin()
                c.switch("noqueue")
                # the root comes back, no child does
                rc, kept, tree, err = self._run_dead_man(d, fs, c, marker, shell, ignore=["parent 1:"])
                self.assertEqual((rc, kept, len(tree)), (1, True, 1), shell)

    def test_fq_dead_men_still_clear_their_marker_after_their_revert(self):
        for tid, arm in (("P-4", "fl1024"), ("P-22", None)):
            for shell in self._shells():
                with tempfile.TemporaryDirectory() as d:
                    marker = os.path.join(d, "perf-trial.env")
                    fs = FakeSystem()
                    c = controller(fs, tid, marker_path=marker)
                    c.begin()
                    c.switch(arm or wb.TRIALS[tid].arms[0].name)
                    rc, kept, _, err = self._run_dead_man(d, fs, c, marker, shell)
                    self.assertEqual((rc, kept), (0, False), (tid, shell, err))

    def test_shell_and_python_normalise_alike(self):
        fs = FakeSystem()
        c = controller(fs, "P-24")
        c.begin()
        captured = c.states["tun_noqueue"]["tc"]
        entries = json.loads(captured)
        texts = [captured, json.dumps(entries, separators=(",", ":")), json.dumps(entries, indent=2),
                 json.dumps([dict(q, handle="8ffe:", refcnt=2) for q in entries]),
                 json.dumps([entries[0]] + list(reversed(entries[1:]))), json.dumps(entries + [entries[2]]),
                 json.dumps(entries[:1]), "[]", fs.run(["tc", "-j", "qdisc", "show", "dev", "eth0"]).out]
        for shell in self._shells():
            for text in texts:
                p = subprocess.run([shell, "-c", 'printf %s "$IN" | ' + wb.QDISC_NORMAL_SH], capture_output=True,
                                   text=True, timeout=30, env={"PATH": "/usr/bin:/bin", "IN": text})
                self.assertEqual((p.returncode, p.stdout.rstrip("\n")), (0, wb.qdisc_normal(text)), (shell, text))
        self.assertEqual(wb.qdisc_normal(captured), wb.qdisc_normal(texts[3]))
        self.assertEqual(wb.qdisc_normal(captured), wb.qdisc_normal(texts[4]))
        self.assertNotEqual(wb.qdisc_normal(captured), wb.qdisc_normal(texts[5]))

    def test_a_capture_the_dead_man_cannot_compare_is_refused_before_any_change(self):
        good = FakeSystem().qdisc["winn3gw0"]
        handle_first = [dict([("handle", q["handle"])] + [(k, v) for k, v in q.items() if k != "handle"]) for q in good]
        nested = [good[0]] + [dict(q, options=dict(q["options"], bands=[{"a": 1}, {"b": 2}])) for q in good[1:]]
        for tree in (handle_first, nested):
            fs = FakeSystem()
            fs.qdisc["winn3gw0"] = tree
            with self.assertRaises(wb.ArmError) as cm:
                controller(fs, "P-24").begin()
            self.assertIn("cannot be compared by the dead-man", str(cm.exception))
            self.assertEqual(fs.mutations(), [])
            self.assertNotIn("/etc/winsvpn/perf-trial.env", fs.files)
        fs = FakeSystem()
        fs.qdisc["eth0"] = [dict([("handle", "8001:")] + [(k, v) for k, v in fs.qdisc["eth0"][0].items() if k != "handle"])]
        with self.assertRaises(wb.ArmError):
            controller(fs, "P-4").begin()
        self.assertEqual(fs.mutations(), [])
        for text in ("[]", "{}", '[{"kind":"fq"},{"kind":"fq"}', '["fq"]'):
            with self.assertRaises(wb.ArmError, msg=text):
                wb.require_dead_man_comparable("eth0", text)
        wb.require_dead_man_comparable("winn3gw0", json.dumps(good))

    def test_finish_reverts_once_when_nothing_is_left(self):
        # Claude's and Fable's advisory: prove after the stops, revert again only when something is left
        fs = FakeSystem()
        c = controller(fs, "P-24", dead_man_minutes=20)
        c.begin()
        c.switch("noqueue")
        start = len(fs.log)
        c.finish()
        dels = [l for l in fs.log[start:] if l == "tc qdisc del dev winn3gw0 root"]
        self.assertEqual(len(dels), 1)                            # one tun queue reset at the end, not two
        self.assertNotIn("/etc/winsvpn/perf-trial.env", fs.files)
        self.assertEqual(fs.timers, set())


class Hygiene(unittest.TestCase):
    FILES = ("winn3_perf_bench.py", "winn3_perf_probe.py", "winn3_perf_bench_local.py", "test_winn3_perf_bench.py",
             "test_winn3_perf_bench_mutants.py")

    def test_no_long_dashes_and_no_spaced_hyphen_connectors(self):
        for name in self.FILES:
            path = os.path.join(HERE, name)
            if not os.path.exists(path):
                continue
            text = open(path, encoding="utf-8").read()
            self.assertNotIn(chr(0x2014), text, name)
            self.assertNotIn(chr(0x2013), text, name)
            for i, line in enumerate(text.splitlines(), 1):
                code, _, comment = line.partition("#")
                prose = comment if comment else (line if line.strip().startswith(('"""', "#")) or not code.strip() else "")
                # a spaced hyphen between two words stands in for a dash; arithmetic between numbers does not
                self.assertIsNone(re.search(r"[A-Za-z]{3,} - [A-Za-z]{3,}", prose), "%s:%d" % (name, i))

    def test_ascii_only(self):
        for name in self.FILES:
            path = os.path.join(HERE, name)
            if os.path.exists(path):
                open(path, encoding="ascii").read()

    def test_no_secret_shaped_literals(self):
        for name in self.FILES:
            path = os.path.join(HERE, name)
            if os.path.exists(path):
                text = open(path, encoding="utf-8").read()
                self.assertIsNone(re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY", text), name)


class Probe(unittest.TestCase):
    def test_percentile(self):
        self.assertEqual(probe.pct([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 50), 5)
        self.assertEqual(probe.pct([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 99), 10)
        self.assertIsNone(probe.pct([], 50))

    def test_header_roundtrip(self):
        self.assertEqual(probe.HDR.unpack(probe.HDR.pack(b"P", 7, 99)), (b"P", 7, 99))
        self.assertEqual(probe.START.unpack(probe.START.pack(130.0, 1400, 5.0)), (130.0, 1400, 5.0))

    def test_loopback_run_emits_a_valid_record(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        srv = subprocess.Popen([sys.executable, os.path.join(HERE, "winn3_perf_probe.py"), "server", "--bind", "127.0.0.1:%d" % port,
                                "--max-secs", "20"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            out = subprocess.run([sys.executable, os.path.join(HERE, "winn3_perf_probe.py"), "client", "--server", "127.0.0.1:%d" % port,
                                  "--profile", "a", "--secs", "1", "--idle-secs", "0.4", "--offered", "a=20,b=20"],
                                 capture_output=True, text=True, timeout=30)
        finally:
            srv.terminate()
            srv.wait(timeout=10)
        self.assertEqual(out.returncode, 0, out.stderr)
        rec = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertTrue(rec["started"] and rec["alive"], rec)
        self.assertEqual(wb.validate_run_record(rec), [])
        self.assertGreater(rec["thr_mbps"], 1.0)
        self.assertGreater(rec["ld_p50_ms"], 0)
        self.assertEqual(rec["failure_class"], None)


if __name__ == "__main__":
    unittest.main(verbosity=1)
