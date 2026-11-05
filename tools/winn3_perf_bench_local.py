#!/usr/bin/env python3
"""Local functional run of winn3_perf_bench.py inside the l80 Colima VM, network namespaces only.

What it proves: the harness applies, reads back and reverts every config arm on a real kernel
(tc fq, txqueuelen, noqueue, busy_poll, CPUWeight and IOWeight, the dead-man timer), and that a
paired trial runs end to end and is decided by rule R. What it does not prove: any speed figure.
The VM is an emulation-free arm64 guest on the operator Mac, not a canary node or aicore, so every
record carries venue 'l80' and no verdict from it is adoptable (5.7, 10.6).

Safety: it uses only a VM the operator names (default l80), never starts, stops or restarts it,
creates only the namespaces p3c and p3s, the veths p3c0/p3s0/p3g0/p3g1, the transient units
p3bench-server and p3bench-gw, dead-man timers named p3bench-revert-*, and the directory
/tmp/p3bench, and removes exactly those by name. If p3c or p3s already exists it refuses and
removes nothing (they belong to someone else); it never stops another trial's winn3-perf-revert timer.
It restores the two busy-poll sysctls to the values it read. No other host is contacted.

  winn3_perf_bench_local.py all --out DIR [--profile l80] [--reps 5] [--secs 5]
  winn3_perf_bench_local.py down            (teardown only, idempotent)
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import winn3_perf_bench as wb  # noqa: E402

NS_C, NS_S = "p3c", "p3s"
WORK = "/tmp/p3bench"
SERVER_UNIT, GW_UNIT = "p3bench-server", "p3bench-gw"
ADDR_C, ADDR_S = "10.77.0.1", "10.77.0.2"
PORT = 7777
FQ_WAN = ["limit", "20480", "flow_limit", "256", "maxrate", "100mbit", "quantum", "1280",
          "initial_quantum", "25600", "refill_delay", "1ms"]
FQ_TUN = ["limit", "10240", "flow_limit", "256", "quantum", "1280", "initial_quantum", "25600", "refill_delay", "1ms"]
DEAD_MAN_PREFIX = "p3bench-revert"     # this tool's own dead-man timers; other trials use winn3-perf-revert


class RigExists(wb.ArmError):
    """The rig's namespaces exist before this run made them: they are not ours to remove."""


def colima_state(profile):
    p = subprocess.run(["colima", "list"], capture_output=True, text=True)
    for line in p.stdout.splitlines():
        parts = line.split()
        if parts and parts[0] == profile:
            return parts[1] if len(parts) > 1 else ""
    return ""


class Vm:
    def __init__(self, profile):
        self.r = wb.ColimaRunner(profile)

    def run(self, argv, stdin=None, check=True, timeout=300):
        res = self.r.run(argv, stdin=stdin, timeout=timeout)
        if check and res.rc != 0:
            raise wb.ArmError("vm command failed (rc %d): %s: %s" % (res.rc, " ".join(argv), res.err.strip()[-300:]))
        return res


def rig_up(vm):
    for ns in (NS_C, NS_S):
        if ns in vm.run(["ip", "netns", "list"]).out.split():
            raise RigExists("namespace %s already exists; run 'down' first or check for another lane" % ns)
    vm.run(["install", "-d", "-m", "0755", WORK, WORK + "/state"])
    with open(os.path.join(HERE, "winn3_perf_probe.py"), "r", encoding="utf-8") as fh:
        vm.run(["tee", WORK + "/probe.py"], stdin=fh.read())
    for ns in (NS_C, NS_S):
        vm.run(["ip", "netns", "add", ns])
        vm.run(["ip", "-n", ns, "link", "set", "lo", "up"])
    vm.run(["ip", "link", "add", "p3c0", "type", "veth", "peer", "name", "p3s0"])
    vm.run(["ip", "link", "set", "p3c0", "netns", NS_C])
    vm.run(["ip", "link", "set", "p3s0", "netns", NS_S])
    for ns, dev, addr in ((NS_C, "p3c0", ADDR_C), (NS_S, "p3s0", ADDR_S)):
        vm.run(["ip", "-n", ns, "addr", "add", addr + "/24", "dev", dev])
        vm.run(["ip", "-n", ns, "link", "set", dev, "up"])
    vm.run(["ip", "netns", "exec", NS_S, "tc", "qdisc", "replace", "dev", "p3s0", "root", "fq"] + FQ_WAN)
    # a multi-queue tun stand-in (mq root with fq children), the shape P-5 builds on winn3gw0
    vm.run(["ip", "-n", NS_S, "link", "add", "p3g0", "numtxqueues", "4", "numrxqueues", "4", "type", "veth", "peer", "name", "p3g1"])
    vm.run(["ip", "-n", NS_S, "link", "set", "p3g0", "up"])
    vm.run(["ip", "-n", NS_S, "link", "set", "p3g1", "up"])
    vm.run(["ip", "-n", NS_S, "link", "set", "dev", "p3g0", "txqueuelen", "10000"])
    vm.run(["ip", "netns", "exec", NS_S, "tc", "qdisc", "replace", "dev", "p3g0", "root", "handle", "1:", "mq"])
    for n in range(1, 5):
        vm.run(["ip", "netns", "exec", NS_S, "tc", "qdisc", "replace", "dev", "p3g0", "parent", "1:%d" % n, "fq"] + FQ_TUN)
    vm.run(["systemd-run", "--unit", GW_UNIT, "--collect", "sleep", "3000"])
    vm.run(["systemd-run", "--unit", SERVER_UNIT, "--collect", "ip", "netns", "exec", NS_S, "python3",
            WORK + "/probe.py", "server", "--bind", "%s:%d" % (ADDR_S, PORT), "--max-secs", "3000"])


def rig_down(vm):
    """Remove exactly what rig_up made, by name. Safe to run when nothing exists."""
    for unit in (SERVER_UNIT, GW_UNIT):
        vm.run(["systemctl", "stop", unit + ".service"], check=False)
    present = vm.run(["ip", "netns", "list"], check=False).out.split()
    for ns in (NS_C, NS_S):
        if ns in present:
            vm.run(["ip", "netns", "del", ns], check=False)
    # a dead-man timer a failed run of this tool may have left (its own prefix only)
    for line in vm.run(["systemctl", "list-units", "--all", "--no-legend", "--plain", DEAD_MAN_PREFIX + "-*"], check=False).out.splitlines():
        name = line.split()[0] if line.split() else ""
        if name.startswith(DEAD_MAN_PREFIX + "-") and name.endswith(".timer"):
            vm.run(["systemctl", "stop", name], check=False)
    vm.run(["rm", "-rf", WORK], check=False)


def leftovers(vm):
    out = []
    if set(vm.run(["ip", "netns", "list"], check=False).out.split()) & {NS_C, NS_S}:
        out.append("namespace")
    for unit in (SERVER_UNIT, GW_UNIT):
        if vm.run(["systemctl", "is-active", unit + ".service"], check=False).out.strip() == "active":
            out.append(unit)
    if DEAD_MAN_PREFIX + "-" in vm.run(["systemctl", "list-timers", "--all", "--no-legend"], check=False).out:
        out.append("dead-man timer")
    if vm.run(["test", "-e", WORK], check=False).rc == 0:
        out.append(WORK)
    return out


def target():
    return wb.Target(wan_dev="p3s0", gw_dev="p3g0", unit=GW_UNIT + ".service", netns=NS_S)


def local_trial(trial, cells=None):
    """The registry trial re-staged for the l80 VM: same arms, local venue, optional cell override."""
    st = wb.Stage("l80_local", "l80")
    # the l80 rig carries v3 only, so the AWG and Xray clause cannot be measured there (functional check)
    return dataclasses.replace(trial, stages=(st,), cells=tuple(cells or trial.cells), side_traffic=False)


def arms_smoke(vm, ev):
    """Every config trial's arms: capture, apply, read back, revert, prove the revert."""
    out = {}
    busy0 = [vm.run(["sysctl", "-n", k]).out.strip() for k in wb.BusyPoll.keys]
    for tid in wb.BENCH_ORDER:
        trial = wb.TRIALS[tid]
        if trial.kind != "config":
            continue
        ctrl = wb.ArmController(vm.r, target(), trial, state_dir=WORK + "/state", marker_path=WORK + "/perf-trial.env",
                                dead_man_minutes=1, unit_prefix=DEAD_MAN_PREFIX)
        rec = {"arms": [], "marker_during": None, "marker_after": None, "plan_written": False, "dead_man_unit": None}
        ctrl.begin()
        rec["plan_written"] = vm.run(["test", "-s", ctrl.plan_path], check=False).rc == 0 and vm.run(["test", "-x", ctrl.script_path], check=False).rc == 0
        rec["marker_during"] = vm.run(["test", "-s", WORK + "/perf-trial.env"], check=False).rc == 0
        rec["dead_man_unit"] = ctrl.dead_man_unit
        rec["dead_man_timer_active"] = vm.run(["systemctl", "is-active", ctrl.dead_man_unit + ".timer"], check=False).out.strip()
        try:
            for arm in [trial.base] + list(trial.arms):
                if arm.kind == "base":
                    ctrl.switch("base_a")
                else:
                    ctrl.switch(arm.name)
                rec["arms"].append(arm.name)
        finally:
            last_unit = ctrl.dead_man_unit      # finish() clears it once every timer is proven stopped
            ctrl.finish()
        rec["marker_after"] = vm.run(["test", "-e", WORK + "/perf-trial.env"], check=False).rc == 0
        rec["dead_man_timer_after"] = vm.run(["systemctl", "is-active", last_unit + ".timer"], check=False).out.strip()
        out[tid] = rec
        ev.save_raw("arms_smoke_%s_commands.txt" % tid, "\n".join("rc=%d %s" % (rc, " ".join(c)) for c, rc in ctrl.log))
    busy1 = [vm.run(["sysctl", "-n", k]).out.strip() for k in wb.BusyPoll.keys]
    out["busy_poll_before_after"] = [busy0, busy1]
    return out


def trial_run(vm, ev, reps, secs, tid="P-4"):
    trial = local_trial(wb.TRIALS[tid], cells=(("a", "udp", "down"), ("b", "udp", "down")))
    template = ("ip netns exec %s python3 %s/probe.py client --server %s:%d --profile {profile} --secs {secs} "
                "--idle-secs 1.5 --dev p3c0 --offered a=130,b=130" % (NS_C, WORK, ADDR_S, PORT))
    backend = wb.CommandBackend(template, runner=vm.r, secs=secs, timeout=120, venue="l80")
    reader = lambda path: vm.run(["cat", path], check=False).out or None
    virt = vm.run(["systemd-detect-virt"], check=False).out.strip()
    with open(os.path.join(HERE, "winn3_perf_probe.py"), "rb") as fh:
        probe_sha = wb.sha256_bytes(fh.read())
    nc = wb.read_node_class(virt_name=virt, venue="l80", provider="local colima l80", node_label="l80",
                            reader=reader, binary_sha256=probe_sha)
    ctrl = lambda st: wb.ArmController(vm.r, target(), trial, state_dir=WORK + "/state", marker_path=WORK + "/perf-trial.env",
                                       dead_man_minutes=30, unit_prefix=DEAD_MAN_PREFIX)
    decision, runs = wb.run_trial(trial, backend, ev, {"l80_local": nc}, reps, 1, controller_factory=ctrl,
                                  min_reps=min(reps, wb.DEFAULT_MIN_REPS), log=lambda m: print(m, file=sys.stderr))
    ev.save_raw("p3s0_qdisc_after.txt", vm.run(["ip", "netns", "exec", NS_S, "tc", "-s", "qdisc", "show", "dev", "p3s0"]).out)
    return decision, runs


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("all")
    a.add_argument("--out", required=True)
    a.add_argument("--profile", default="l80")
    a.add_argument("--reps", type=int, default=5)
    a.add_argument("--secs", type=int, default=5)
    d = sub.add_parser("down")
    d.add_argument("--profile", default="l80")
    args = ap.parse_args(argv)
    if colima_state(args.profile) != "Running":
        print("colima profile %s is not Running; this tool never starts a VM" % args.profile, file=sys.stderr)
        return 2
    vm = Vm(args.profile)
    if args.cmd == "down":
        rig_down(vm)
        print(json.dumps({"leftovers": leftovers(vm)}))
        return 0
    ev = wb.Evidence(args.out)
    summary = {"profile": args.profile, "venue": "l80", "note": "functional only; no verdict from this run is adoptable"}
    try:
        rig_up(vm)
    except RigExists as exc:
        # nothing was created, and what exists is not ours: no teardown
        print(str(exc), file=sys.stderr)
        return 2
    except BaseException:
        rig_down(vm)        # a partial rig of our own
        raise
    try:
        summary["arms_smoke"] = arms_smoke(vm, ev)
        decision, runs = trial_run(vm, ev, args.reps, args.secs)
        summary["trial"] = {k: decision[k] for k in ("trial", "rule_r_verdict", "adoptable", "chosen_arm", "notes")}
        summary["trial"]["runs"] = len(runs)
    finally:
        rig_down(vm)
        summary["leftovers_after_teardown"] = leftovers(vm)
    ev.write_json("local_summary.json", summary)
    ev.manifest()
    print(json.dumps(summary, indent=1, sort_keys=True))
    return 1 if summary["leftovers_after_teardown"] else 0


if __name__ == "__main__":
    sys.exit(main())
