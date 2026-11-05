#!/usr/bin/env python3
"""Tier A harness (design v17 5.1, 5.2 and the namespace-runnable part of 5.3).

Tier A runs on the aarch64 colima guest l80 (the x86_64 guest amd64t is also
accepted for the same namespace scenarios). Every fixture runs inside
`unshare -m -n -p -f --mount-proc` as root: a private network namespace for the
iptables rules, overlay and tmpfs mounts for /etc, /var/lib, /usr/local and
/run, and a client namespace joined by a veth pair for real darkness probes.
Nothing outside those namespaces is changed, the guest is never started,
stopped or restarted, and no other profile is touched.

usage:
  tier_a.py list [--json]
  tier_a.py plan  [--vm l80] [--profile quick|full] [--only ID,...]
  tier_a.py run   [--vm l80] [--profile quick|full] [--only ID,...] [--installer FILE]
                  [--scratch DIR] [--evidence DIR] [--lanes N]

`--lanes N` (default 1, the serial run) splits the quick scenarios over N concurrent `sudo unshare` runs, each
with its own FX_RUN, namespaces, overlays and /run, then runs every `full` scenario (the real 20 s and 30 s bounds,
the contention runs and the sweeps) in one lane after them, so no other lane competes for CPU while a bound is timed.

`plan` prints what `run` would do and executes nothing. Scenarios that need
parts that are not in the tree under test (the hub app, the signer, the
canary) or a real systemd are listed as `blocked` with the reason, and are
reported as skipped, never as passed.
"""
import argparse
import base64
import concurrent.futures
import io
import json
import os
import re
import shlex
import shutil
import sys
import tarfile
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pred_cases  # noqa: E402
import scenarios  # noqa: E402
from tier_common import (Evidence, HarnessRefusal, Installer, VmRunner, bundle, node_class,  # noqa: E402
                         parse_fixture_output, plan_digest, sha256_file, summarize, utc_now)

DEFAULT_SCRATCH = Path.home() / ".cache" / "winsvpn-s7-tiers"


def case_files(installer):
    """The generated fixture inputs (predicate rulesets and tables)."""
    extra = {}
    index = []
    for item in pred_cases.cases():
        extra["cases/%s.rules" % item["id"]] = item["rules"]
        index.append("\t".join((item["id"], item["expect"], item["mode"], item["design"])))
    for name, text in pred_cases.states().items():
        extra["states/%s.rules" % name] = text
    extra["cases/index.tsv"] = "\n".join(index) + "\n"
    extra["cases/absence.tsv"] = "\n".join("%d\t%s\t%s" % (rc, msg, "pass" if ok else "fail")
                                           for rc, msg, ok in pred_cases.ABSENCE_WRAPPERS) + "\n"
    return extra


def select(profile, only):
    chosen = []
    for item in scenarios.SCENARIOS:
        if only and item["id"] not in only and item["group"] not in only:
            continue
        if item["profile"] == "full" and profile != "full":
            continue
        chosen.append(item)
    return chosen


def stage_bundle(runner, bundle_dir, run_id):
    """The path the guest reads the bundle at. l80 mounts the home directory; amd64t does not, so the bundle is pushed.

    Returns (guest_path, pushed_dir or None). A pushed copy is a base64 tar.gz piped through stdin into /tmp/s7bundle.<id>.
    """
    probe = runner.run("test -f %s/MANIFEST.json" % shlex.quote(str(bundle_dir)), timeout=60, purpose="is the bundle visible in the guest")
    if probe.ok:
        return str(bundle_dir), None
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        tar.add(bundle_dir, arcname=".")
    guest = "/tmp/s7bundle.%s" % run_id
    pushed = runner.run("mkdir -p %s && base64 -d | tar -xzf - -C %s" % (guest, guest), timeout=300, purpose="push the bundle",
                        input_text=base64.b64encode(archive.getvalue()).decode())
    if not pushed.ok:
        raise HarnessRefusal("could not push the bundle: " + pushed.stderr[-200:])
    return guest, guest


def missing_tools(runner, items):
    """{scenario id: [program, ...]} for every chosen scenario whose `needs` the guest lacks. Read-only (`command -v`)."""
    wanted = sorted({tool for item in items for tool in item.get("needs", ())})
    if not wanted:
        return {}
    probe = runner.run("for t in %s; do command -v \"$t\" >/dev/null 2>&1 || echo \"missing $t\"; done; true" % " ".join(wanted),
                       timeout=60, purpose="which programs the scenarios need are installed")
    if getattr(probe, "dry", False):
        return {}
    absent = set(re.findall(r"^missing (\S+)$", probe.stdout, re.M))
    if probe.returncode != 0:
        absent = set(wanted)
    return {item["id"]: [t for t in item.get("needs", ()) if t in absent] for item in items
            if any(t in absent for t in item.get("needs", ()))}


def run_fixtures(installer, vm, fixtures, profile, scratch, timeout=900, runner=None):
    """Build a bundle from `installer`, run the named fixture functions in the guest's namespaces, and parse.

    Returns (summary, stdout, stderr, returncode, bundle_digest). Used by `run` and by the mutant runner.
    """
    runner = runner or VmRunner(vm, dry_run=False)
    run_id = uuid.uuid4().hex[:8]
    bundle_dir = Path(scratch) / ("bundle-" + installer.sha256[:12] + "-" + run_id)
    digest = bundle(installer, bundle_dir, case_files(installer))
    guest_dir, pushed = stage_bundle(runner, bundle_dir, run_id)
    command = remote_command(guest_dir, run_id, profile, fixtures)
    result = runner.run(command, timeout=timeout, purpose="Tier A namespace scenarios")
    if pushed:
        runner.run("rm -rf %s" % shlex.quote(pushed), timeout=60, purpose="remove the pushed bundle")
    summary = summarize(parse_fixture_output(result.stdout))
    shutil.rmtree(bundle_dir, ignore_errors=True)
    return summary, result.stdout, result.stderr, result.returncode, digest


def remote_command(bundle_dir, run_id, profile, ids):
    # The remote shell is `sh -c`; the namespaces are made by one `sudo unshare`. FX_RUN names the
    # scratch mount point, which is removed after the namespaces are gone.
    return ("sudo -n env FX_RUN=%(run)s unshare -m -n -p -f --mount-proc bash %(dir)s/fx_main.sh "
            "--profile %(profile)s %(ids)s; rc=$?; sudo -n rmdir /tmp/s7ns.%(run)s 2>/dev/null; exit $rc") % {
        "run": run_id, "dir": str(bundle_dir), "profile": profile, "ids": " ".join(ids)}


def lane_split(runnable, lanes):
    """[(phase, [fixture, ...]), ...]: phase 0 holds the quick scenarios round-robin over `lanes` lanes, phase 1 every
    full one in a single lane. With one lane, one group in registry order (the serial run)."""
    if lanes <= 1:
        return [(0, [item["fixture"] for item in runnable])]
    quick = [item["fixture"] for item in runnable if item["profile"] != "full"]
    full = [item["fixture"] for item in runnable if item["profile"] == "full"]
    groups = [(0, quick[k::lanes]) for k in range(lanes) if quick[k::lanes]]
    if full:
        groups.append((1, full))
    return groups


def lane_commands(guest_dir, run_id, profile, groups):
    """The remote command of each lane, in lane order; each lane has its own FX_RUN."""
    return [remote_command(guest_dir, "%s-%d" % (run_id, index), profile, ids) for index, (_, ids) in enumerate(groups)]


def run_lanes(runner, guest_dir, run_id, profile, groups, timeout):
    """Runs the phase-0 groups concurrently, then phase 1. Returns (stdout, stderr, worst rc, commands)."""
    outputs, commands = {}, dict(enumerate(lane_commands(guest_dir, run_id, profile, groups)))
    for phase in sorted({g[0] for g in groups}):
        batch = [(index, ids) for index, (ph, ids) in enumerate(groups) if ph == phase]
        def one(entry):
            index, _ = entry
            return index, runner.run(commands[index], timeout=timeout, purpose="Tier A namespace scenarios, lane %d" % index)
        with concurrent.futures.ThreadPoolExecutor(max(1, len(batch))) as pool:
            for index, result in pool.map(one, batch):
                outputs[index] = result
    order = sorted(outputs)
    stdout = "".join(outputs[i].stdout for i in order)
    stderr = "".join("[lane %d]\n%s" % (i, outputs[i].stderr) for i in order)
    worst = max((outputs[i].returncode for i in order), key=lambda rc: (rc != 0, rc))
    return stdout, stderr, worst, [commands[i] for i in order]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("list", "plan", "run"))
    parser.add_argument("--vm", default="l80")
    parser.add_argument("--profile", choices=("quick", "full"), default="quick")
    parser.add_argument("--only", default="")
    parser.add_argument("--installer")
    parser.add_argument("--scratch", default=str(DEFAULT_SCRATCH))
    parser.add_argument("--evidence")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--lanes", type=int, default=1)
    args = parser.parse_args(argv)
    only = {x for x in args.only.split(",") if x}
    unknown = only - {i["id"] for i in scenarios.SCENARIOS} - {i["group"] for i in scenarios.SCENARIOS}
    if unknown:
        raise HarnessRefusal("unknown scenario or group: " + ", ".join(sorted(unknown)))

    if args.command == "list":
        rows = scenarios.SCENARIOS
        if args.json:
            print(json.dumps(rows, indent=1, sort_keys=True))
        else:
            for item in rows:
                state = item.get("blocked") and ("blocked: " + item["blocked"]) or item["profile"]
                print("%-34s %-8s %s" % (item["id"], item["group"], state))
        return 0

    chosen = select(args.profile, only)
    installer = Installer(args.installer)
    scratch = Path(args.scratch)
    dry = args.command == "plan"
    plan = []
    runner = VmRunner(args.vm, dry_run=dry, plan=plan)
    lacking = missing_tools(runner, [item for item in chosen if not item.get("blocked")])
    chosen = [dict(item, blocked="needs %s, which is not installed on %s (read-only check)" % (", ".join(lacking[item["id"]]), args.vm))
              if item["id"] in lacking else item for item in chosen]
    runnable = [item for item in chosen if not item.get("blocked")]
    blocked = [item for item in chosen if item.get("blocked")]
    run_id = uuid.uuid4().hex[:8]
    bundle_dir = scratch / ("bundle-" + installer.sha256[:12] + "-" + run_id)
    scratch.mkdir(parents=True, exist_ok=True)
    digest = bundle(installer, bundle_dir, case_files(installer))
    ids = [item["fixture"] for item in runnable]
    command = remote_command(bundle_dir, run_id, args.profile, ids)
    cls = node_class(runner)
    if dry:
        runner.run(command, purpose="Tier A namespace scenarios (the bundle is pushed first when the guest cannot see this path)")
        print(json.dumps({"vm": args.vm, "installer_sha256": installer.sha256, "bundle_sha256": digest,
                          "run_id": run_id, "scenarios": [item["id"] for item in runnable],
                          "needs": {item["id"]: item["needs"] for item in runnable if item.get("needs")},
                          "blocked": {item["id"]: item["blocked"] for item in blocked},
                          "plan": plan, "plan_sha256": plan_digest(plan)}, indent=1))
        return 0

    started = time.time()
    guest_dir, pushed = stage_bundle(runner, bundle_dir, run_id)
    # The header records the command(s) really run: the guest path of the bundle, and with --lanes N each lane's command.
    if args.lanes <= 1:
        command = remote_command(guest_dir, run_id, args.profile, ids)
    else:
        command = lane_commands(guest_dir, run_id, args.profile, lane_split(runnable, args.lanes))
    header = {"tier": "A", "vm": args.vm, "profile": args.profile, "installer": str(installer.path),
              "installer_sha256": installer.sha256, "gateway_binary_pin_sha256": installer.binary_pin,
              "bundle_sha256": digest, "node_class": cls,
              "command": command, "lanes": max(1, args.lanes)}
    evidence_dir = Path(args.evidence) if args.evidence else scratch / ("evidence-" + run_id)
    evidence = Evidence(evidence_dir, header)
    if args.lanes <= 1:
        result = runner.run(command, timeout=args.timeout, purpose="Tier A namespace scenarios")
    else:
        stdout, stderr, rc, commands = run_lanes(runner, guest_dir, run_id, args.profile, lane_split(runnable, args.lanes), args.timeout)
        result = type("LaneResult", (), {"stdout": stdout, "stderr": stderr, "returncode": rc})()
        result.stderr = "LANE COMMANDS\n" + "\n".join(commands) + "\n" + result.stderr
    if pushed:
        runner.run("rm -rf %s" % shlex.quote(pushed), timeout=60, purpose="remove the pushed bundle")
    rows = parse_fixture_output(result.stdout)
    summary = summarize(rows)
    failed = 0
    fixture_to_item = {item["fixture"]: item for item in runnable}
    for fixture, item in fixture_to_item.items():
        entry = summary.get(fixture, {"ok": 0, "not-ok": 0, "skip": 0, "note": 0, "failures": []})
        raw = "\n".join(line for line in result.stdout.splitlines() if re.match(r"^S7 \S+ %s( |$)" % re.escape(fixture), line))
        if entry["not-ok"] or not entry["ok"]:
            status = "fail"
            failed += 1
        elif entry["skip"]:
            status = "partial"
        else:
            status = "pass"
        evidence.record(item["id"], status, "ok=%d not-ok=%d skip=%d" % (entry["ok"], entry["not-ok"], entry["skip"]), raw)
        print("%-8s %-34s ok=%-3d not-ok=%-3d skip=%d" % (status, item["id"], entry["ok"], entry["not-ok"], entry["skip"]))
        for failure in entry["failures"][:8]:
            print("    not ok: " + failure[:300])
    for item in blocked:
        evidence.record(item["id"], "blocked", item["blocked"], "")
        print("blocked  %-34s %s" % (item["id"], item["blocked"]))
    evidence.record("_runner", "rc=%d" % result.returncode, "seconds=%.1f" % (time.time() - started),
                    "STDOUT\n" + result.stdout + "\nSTDERR\n" + result.stderr)
    print("evidence: %s (rc=%d, %.1f s, %d scenarios failed)" % (evidence_dir, result.returncode, time.time() - started, failed))
    return 0 if (failed == 0 and result.returncode == 0) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except HarnessRefusal as exc:
        print("refused: " + str(exc), file=sys.stderr)
        sys.exit(2)
