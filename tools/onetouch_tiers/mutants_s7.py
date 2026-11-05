#!/usr/bin/env python3
"""Mutant runner (design v17 5.6): apply one exact-count edit set to the installer, run the kill tests, report.

usage:
  mutants_s7.py list
  mutants_s7.py check                      every edit applies exactly the stated number of times
  mutants_s7.py baseline [--vm l80]        the kill tests pass on the unmutated installer (a vacuous kill is a harness bug)
  mutants_s7.py run [--only SUBSTR] [--group G] [--vm l80] [--jobs 3] [--profile quick|full] [--scratch DIR]
                    [--results FILE]

A mutant is KILLED when any of its kill tests fails (a Tier A scenario on the guest, or a pytest file on this
Mac). SURVIVED means every kill test passed on the mutated installer. BAD-PATTERN means the edit did not apply.
PENDING mutants belong to a slice or a tier that is not in the tree under test; they are listed, never counted.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mutant_defs  # noqa: E402
import scenarios  # noqa: E402
import tier_a  # noqa: E402
from tier_common import DP_RELATIVE, LINUX_DIR, ROOT, Installer, VmRunner, sha256_bytes  # noqa: E402

DEFAULT_SCRATCH = Path.home() / ".cache" / "winsvpn-s7-tiers"
BASH = os.environ.get("WINS_TEST_BASH", str(Path.home() / ".homebrew/Homebrew/bin/bash"))
# Kill files run in one pytest invocation with -x, fastest suite first, so a cheap killer ends the run early
# (measured on the operator Mac: S7 about 5 s, S5 and S4 about 15 to 25 s each). The kill verdict does not change.
PYTEST_ORDER = (mutant_defs.S7, mutant_defs.S5, mutant_defs.S4)
# The S7 registry self-check applies every registered edit to the installer under test. In a mirror that installer is
# the mutated one, so the check fails for every registered mutant: it is not a kill test and must not count as one.
REGISTRY_SELF_CHECK = "test_winn3_onetouch_s7.py::MutantRegistry::test_every_edit_applies_the_stated_number_of_times"
FIXTURE_OF = {item["id"]: item["fixture"] for item in scenarios.SCENARIOS}
ITEM_OF = {item["id"]: item for item in scenarios.SCENARIOS}
PROFILE_OF = {item["id"]: item["profile"] for item in scenarios.SCENARIOS}


def apply_edits(text, edits):
    for old, new, count in edits:
        found = text.count(old)
        if found != count:
            return None, "pattern found %d times, expected %d: %r" % (found, count, old[:70])
        text = text.replace(old, new)
    return text, ""


def make_mirror(mutated_text, scratch, tag):
    mirror = Path(scratch) / ("mirror-" + tag)
    shutil.rmtree(mirror, ignore_errors=True)
    (mirror / "server").mkdir(parents=True)
    os.symlink(ROOT / "tools", mirror / "tools")
    for entry in (ROOT / "server").iterdir():
        target = mirror / "server" / entry.name
        if entry.name == Path(DP_RELATIVE).name:
            target.write_text(mutated_text)
        elif entry.name.startswith("test_winn3_onetouch_s"):
            shutil.copy(entry, target)
        else:
            os.symlink(entry, target)
    return mirror


def ordered(files):
    return sorted(files, key=lambda f: (PYTEST_ORDER.index(f) if f in PYTEST_ORDER else len(PYTEST_ORDER), f))


def fixture_text_digest():
    """The digest of the fixture text a Tier A kill ran with (every file of linux/ and the generated case files),
    which is the part of each mutant's bundle that does not change with the mutated installer."""
    manifest = {"linux/" + p.name: sha256_bytes(p.read_bytes()) for p in sorted(LINUX_DIR.iterdir()) if p.is_file()}
    for name, body in sorted(tier_a.case_files(None).items()):
        manifest[name] = sha256_bytes(body.encode())
    return sha256_bytes(json.dumps(manifest, sort_keys=True).encode())


def run_pytest(mutated_text, files, scratch, tag):
    files = ordered(files)
    mirror = make_mirror(mutated_text, scratch, tag)
    env = dict(os.environ, TZ="UTC", PYTHONDONTWRITEBYTECODE="1", WINS_TEST_BASH=BASH)
    try:
        done = subprocess.run([sys.executable, "-B", "-m", "pytest", "-q", "-x", "-rfE", "-p", "no:cacheprovider", "--deselect", REGISTRY_SELF_CHECK]
                              + [Path(f).name for f in files],
                              cwd=mirror / "server", env=env, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        shutil.rmtree(mirror, ignore_errors=True)
        return False, "pytest timeout"
    shutil.rmtree(mirror, ignore_errors=True)
    lines = [line for line in (done.stdout + done.stderr).splitlines() if line.strip()]
    # the detail names the test that killed the mutant (pytest's FAILED, SUBFAILED or ERROR summary line), else the last line
    named = [line for line in lines if line.startswith(("FAILED ", "ERROR ", "SUBFAILED"))][:1]
    tail = named or lines[-1:]
    return done.returncode == 0, (tail[0][:140] if tail else "")


def run_cmds(mutated_text, commands, scratch, tag):
    """argv lists run in a mirror root whose installer is the mutated one; python3 means this interpreter."""
    mirror = make_mirror(mutated_text, scratch, tag + "-cmd")
    env = dict(os.environ, TZ="UTC", PYTHONDONTWRITEBYTECODE="1")
    try:
        for argv in commands:
            argv = [sys.executable if a == "python3" else a for a in argv]
            done = subprocess.run(argv, cwd=mirror, env=env, capture_output=True, text=True, timeout=300)
            if done.returncode:
                line = [l for l in (done.stdout + done.stderr).splitlines() if l.strip()][:1]
                return False, (line[0][:140] if line else "rc=%d" % done.returncode)
    finally:
        shutil.rmtree(mirror, ignore_errors=True)
    return True, ""


def unavailable_note(lacking):
    return "; ".join("%s needs %s" % (k, ",".join(v)) for k, v in sorted(lacking.items()))


def run_tier_a(mutated_path, vm, ids, scratch, timeout):
    """(ok, detail, unavailable): ok is False when a scenario killed the mutant. A scenario whose guest program is
    missing (scenarios.py `needs`) is not run, so a skip can never read as a kill, and it is named in `unavailable`.
    ok is None when no scenario could run: the arm neither killed nor passed it."""
    installer = Installer(mutated_path)
    lacking = tier_a.missing_tools(VmRunner(vm, dry_run=False), [ITEM_OF[i] for i in ids])
    ids = [i for i in ids if i not in lacking]
    if not ids:
        return None, "", unavailable_note(lacking)
    profile = "full" if any(PROFILE_OF[i] == "full" for i in ids) else "quick"
    fixtures = [FIXTURE_OF[i] for i in ids]
    summary, stdout, stderr, rc, _ = tier_a.run_fixtures(installer, vm, fixtures, profile, scratch, timeout=timeout)
    failed = [f for f in fixtures if summary.get(f, {}).get("not-ok") or not summary.get(f, {}).get("ok")]
    if rc == 124:
        return False, "guest run timed out (a hung scenario kills the mutant)", unavailable_note(lacking)
    detail = ""
    for f in failed:
        entry = summary.get(f, {})
        detail = (entry.get("failures") or ["no ok line printed"])[0][:130]
        break
    return not failed, detail, unavailable_note(lacking)


def run_one(mutant, base_text, args, scratch):
    if mutant["status"] == "equivalent":
        return mutant["id"], "EQUIVALENT", mutant["note"][:90]
    if mutant["status"] != "runnable":
        return mutant["id"], "PENDING", mutant.get("owner", "")
    text, why = apply_edits(base_text, mutant["edits"])
    if text is None:
        return mutant["id"], "BAD-PATTERN", why
    if args.command == "check":
        return mutant["id"], "OK-PATTERN", ""
    mutated = Path(scratch) / ("mutated-" + mutant["id"] + ".sh")
    mutated.write_text(text)
    killers = []
    if mutant["cmd"]:
        ok, detail = run_cmds(text, mutant["cmd"], scratch, mutant["id"])
        if not ok:
            killers.append("check: " + detail)
    for pytest_files in [mutant["pytest"]] if mutant["pytest"] else []:
        if killers and not args.all_kills:
            break
        ok, detail = run_pytest(text, pytest_files, scratch, mutant["id"])
        if not ok:
            killers.append("pytest: " + detail)
    unavailable = ""
    tier_a_ran = False
    if mutant["tier_a"] and not (killers and not args.all_kills):
        if args.profile == "quick" and mutant["profile"] == "full":
            if not killers:
                mutated.unlink(missing_ok=True)
                return mutant["id"], "SKIPPED-FULL", "needs --profile full"
        else:
            ok, detail, unavailable = run_tier_a(mutated, args.vm, mutant["tier_a"], scratch, args.timeout)
            tier_a_ran = ok is not None
            if ok is False:
                killers.append("tier A: " + detail)
    mutated.unlink(missing_ok=True)
    if not mutant["tier_a"] and not mutant["pytest"] and not mutant["cmd"]:
        return mutant["id"], "NO-KILL-TEST", ""
    note = "; ".join(killers) + ("; unavailable: " + unavailable if unavailable else "")
    if not killers and unavailable and not tier_a_ran and not mutant["pytest"] and not mutant["cmd"]:
        # every kill test is a scenario this guest cannot run: neither killed nor survived
        return mutant["id"], "UNAVAILABLE", ("unavailable: " + unavailable)[:200]
    return mutant["id"], ("KILLED" if killers else "SURVIVED"), note.strip("; ")[:200]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("list", "check", "baseline", "run"))
    parser.add_argument("--only", default="")
    parser.add_argument("--group", default="")
    parser.add_argument("--vm", default="l80")
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--profile", choices=("quick", "full"), default="quick")
    parser.add_argument("--scratch", default=str(DEFAULT_SCRATCH))
    parser.add_argument("--results")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--all-kills", action="store_true", help="run every kill test even after one kills")
    parser.add_argument("--installer")
    args = parser.parse_args(argv)
    chosen = [mu for mu in mutant_defs.MUTANTS if (not args.only or args.only in mu["id"]) and (not args.group or args.group == mu["group"])]
    if args.command == "list":
        for mu in chosen:
            kill = ", ".join(mu["tier_a"] + [Path(p).name for p in mu["pytest"]]) or mu.get("kill_test", "")
            print("%-9s %-40s %-14s %s" % (mu["status"], mu["id"], mu["group"], kill))
        count = lambda status: len([m for m in chosen if m["status"] == status])  # noqa: E731
        print("%d mutants: %d runnable, %d equivalent, %d pending" % (len(chosen), count("runnable"), count("equivalent"), count("pending")))
        return 0
    scratch = Path(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    installer = Installer(args.installer)
    base_text = installer.text

    if args.command == "baseline":
        wanted = sorted({i for mu in chosen if mu["status"] == "runnable" for i in mu["tier_a"]})
        profile = "full" if (args.profile == "full") else "quick"
        wanted = [i for i in wanted if profile == "full" or PROFILE_OF[i] == "quick"]
        summary, stdout, stderr, rc, _ = tier_a.run_fixtures(installer, args.vm, [FIXTURE_OF[i] for i in wanted], profile, scratch, timeout=1800)
        bad = [i for i in wanted if summary.get(FIXTURE_OF[i], {}).get("not-ok") or not summary.get(FIXTURE_OF[i], {}).get("ok")]
        pytest_files = sorted({f for mu in chosen if mu["status"] == "runnable" for f in mu["pytest"]})
        for f in pytest_files:
            ok, detail = run_pytest(base_text, [f], scratch, "baseline")
            print("baseline pytest %-34s %s %s" % (Path(f).name, "ok" if ok else "FAIL", detail))
            if not ok:
                bad.append(f)
        print("baseline Tier A scenarios: %d, failing: %s" % (len(wanted), bad or "none"))
        return 1 if bad else 0

    results = []
    runnable = [mu for mu in chosen if mu["status"] != "pending"]
    with ThreadPoolExecutor(max(1, args.jobs)) as pool:
        for outcome in pool.map(lambda mu: run_one(mu, base_text, args, scratch), runnable):
            results.append(outcome)
            print("%-42s %-12s %s" % outcome, flush=True)
    pend = [mu for mu in chosen if mu["status"] == "pending"]
    counts = {}
    for _, status, _ in results:
        counts[status] = counts.get(status, 0) + 1
    print("mutants run: %d  %s  pending (other slice or Tier B): %d" % (
        len(results), "  ".join("%s=%d" % kv for kv in sorted(counts.items())), len(pend)))
    out = Path(args.results) if args.results else scratch / "mutants_s7.results.txt"
    with open(out, "w") as stream:
        stream.write("# installer_sha256=%s\n" % installer.sha256)
        stream.write("# fixture_text_sha256=%s (linux/ and the case files every Tier A kill ran with)\n" % fixture_text_digest())
        for mid, status, note in results:
            stream.write("%s\t%s\t%s\n" % (mid, status, note))
        for mu in pend:
            stream.write("%s\tPENDING\t%s | %s\n" % (mu["id"], mu.get("owner", ""), mu.get("kill_test", "")))
    return 1 if counts.get("SURVIVED") or counts.get("BAD-PATTERN") else 0


if __name__ == "__main__":
    sys.exit(main())
