#!/usr/bin/env python3
"""Tier B harness (design v17 5.3 and 5.7): the real installer, real systemd, a real or full-system guest.

This tool contacts nothing unless `run --execute --authorization FILE` is given, and the authorization file
must be written by the owner and carry the digest of the exact plan `plan` prints (`plan_sha256=<digest>`) and a
`target=<name>` line for the target. Without those, `plan` and `list` are the only modes, and they make no
connection of any kind: they print what would run.

usage:
  tier_b.py list
  tier_b.py staging [--installer FILE] [--var k=v ...]
  tier_b.py plan  --target colima:amd64t|ssh:ALIAS [--only ID,...] [--have a,b] [--var k=v ...] [--installer FILE]
  tier_b.py run   --target ... --execute --authorization FILE [--state FILE] ...
  tier_b.py resume --target ... --execute --authorization FILE --state FILE

Targets are `colima:amd64t` (the local x86_64 guest, emulated: functional checks only, never a performance figure)
or `ssh:ALIAS` (a host the owner names; the alias is resolved by the owner's ssh configuration, with
BatchMode and strict host key checking). The lane that wrote this tool ran `plan` and the structure tests only.

`staging` prints what the `installer-staged` requirement claims (catalogue.STAGED) with the digests the staging check
will demand, and the check itself; it contacts nothing. `local` steps run a hub-lite tool on this Mac against the
scratch state directory `{hublite_state}` (never a host), and `evaluate` steps judge earlier captures with a pure
function from readbacks.py or tierb_eval.py; an evaluate step marked `stop` ends its scenario when it fails.
"""
import argparse
import ast
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import hub_lite  # noqa: E402
import readbacks  # noqa: E402
import shims as shimlib  # noqa: E402
import tier_b_catalogue as catalogue  # noqa: E402
import tierb_eval  # noqa: E402
from tier_common import (ROOT, Evidence, HarnessRefusal, HostGuard, Installer, VmRunner, plan_digest,  # noqa: E402
                         scan_forbidden, sha256_bytes, sha256_file, utc_now)

HELPERS = ("fx_probe.py", "s7_probe_from_ns.sh", "s7_check_rules.sh", "s7_tb09.sh", "s7_docker_proxy.py")
EXIT_OWNER = 3
# The only programs a `local` step may run, all on this Mac and all against the scratch hub-lite state.
LOCAL_TOOLS = ("hub_lite.py", "tierb_hub.py")
# Facts an evaluate step may name with a leading @ (they come from the plan, never from the target).
EVALUATE_FACTS = ("installer_sha256", "binary_pin", "slug")
# What the plan digest binds besides the data plane: the control-plane installer the local steps run (hub_lite reads
# main.py, the signer and the prober from it) and every harness file (harness_files), all relative to ROOT.
HERE_RELATIVE = HERE.relative_to(ROOT).as_posix()
CP_RELATIVE = hub_lite.CP_INSTALLER.relative_to(hub_lite.REPO).as_posix()
# The directories the harness puts on sys.path before it imports, relative to ROOT: this one (tier_b, tierb_hub),
# tools/ (tier_common, for winn3_gateway_block) and server/ (hub_lite, for the H1 signer test's heredoc extractor).
IMPORT_DIRS = (HERE_RELATIVE, "tools", "server")


def imported_names(source):
    """Top-level names a Python source imports: `import`, absolute `from` (also inside functions) and
    importlib.import_module("literal")."""
    names = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module.split(".")[0])
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "import_module"
              and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            names.add(node.args[0].value.split(".")[0])
    return names


def harness_files():
    """Every harness file Tier B loads or ships, as sorted ROOT-relative paths, derived from the code: each module in
    this directory, each file in linux/ (HELPERS, which `run` copies to the target, are among them), and the closure
    of repository modules this tool and the LOCAL_TOOLS import from IMPORT_DIRS (a name found in more than one
    directory counts every copy)."""
    found = {p.relative_to(ROOT).as_posix() for p in (ROOT / HERE_RELATIVE).glob("*.py") if p.is_file()}
    found.update(p.relative_to(ROOT).as_posix() for p in (ROOT / HERE_RELATIVE / "linux").iterdir()
                 if p.is_file() and not p.name.startswith("."))
    found.update("%s/linux/%s" % (HERE_RELATIVE, name) for name in HELPERS)
    queue, seen = ["%s/%s" % (HERE_RELATIVE, name) for name in (Path(__file__).name,) + LOCAL_TOOLS], set()
    while queue:
        rel = queue.pop()
        if rel in seen:
            continue
        seen.add(rel)
        found.add(rel)
        for name in imported_names((ROOT / rel).read_text(encoding="utf-8")):
            queue.extend(c for c in ("%s/%s.py" % (d, name) for d in IMPORT_DIRS) if (ROOT / c).is_file())
    return sorted(found)


def harness_digests():
    """{ROOT-relative path: sha256} of harness_files()."""
    return {rel: sha256_file(ROOT / rel) for rel in harness_files()}


def root_command(remote):
    """The target-side command line that runs `remote` as root, byte for byte.

    The target's own shell parses this line first (the ssh login shell, or the guest's `sh -c` for colima). A single-quoted
    argument reaches `bash -c` unchanged: no `$`, `$(...)` or `$?` is expanded by that outer shell as the login user, and a
    newline stays a newline, so here-documents and multi-line shim installs survive.
    """
    return "sudo -n bash -c " + shlex.quote(remote)


class SshTarget:
    """An owner-named host. BatchMode, strict host keys, and nothing else is invented here."""

    def __init__(self, alias):
        if not re.fullmatch(r"[A-Za-z0-9._-]+", alias):
            raise HarnessRefusal("odd ssh alias %r" % alias)
        self.alias = alias
        self.name = "ssh:" + alias

    def argv(self, remote):
        return ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", self.alias,
                root_command(remote)]

    def run(self, remote, timeout, input_text=None):
        try:
            done = subprocess.run(self.argv(remote), capture_output=True, text=True, timeout=timeout, input=input_text)
        except subprocess.TimeoutExpired as exc:
            # a hung step still leaves an evidence row (rc 124, as VmRunner reports a timeout)
            out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return 124, out, err + "\nharness timeout after %s s" % timeout
        return done.returncode, done.stdout, done.stderr


class ColimaTarget:
    def __init__(self, profile, dry_run):
        self.runner = VmRunner(profile, dry_run=dry_run)
        self.name = "colima:" + profile

    def run(self, remote, timeout, input_text=None):
        result = self.runner.run(root_command(remote), timeout=timeout, input_text=input_text)
        return result.returncode, result.stdout, result.stderr


def make_target(spec, dry_run):
    kind, _, name = spec.partition(":")
    if kind == "colima":
        return ColimaTarget(name, dry_run)
    if kind == "ssh":
        return SshTarget(name)
    raise HarnessRefusal("target must be colima:PROFILE or ssh:ALIAS")


def resolve(text, variables):
    """Replace {name} for the harness variables only; every other brace (awk, docker formats, shell) stays as written."""
    def replace(match):
        return variables[match.group(1)] if match.group(1) in variables else match.group(0)
    out = re.sub(r"\{([a-z_]+)\}", replace, text)
    unresolved = re.findall(r"\{(installer|secrets_file|shim_dir|work|deploy_args|hublite_state|slug|endpoint_ip)\}", out)
    if unresolved:
        raise HarnessRefusal("unresolved placeholder %s" % unresolved[0])
    return out


def helper_texts(installer):
    texts = {}
    for name in HELPERS:
        texts[name] = (HERE / "linux" / name).read_text()
    texts["latch_predicate.py"] = installer.heredoc("WINS_LATCH_PY") + "\n"
    return texts


def render_scenarios(chosen, variables):
    """The fully resolved plan: every command string with its placeholders filled. Deterministic."""
    plan = []
    for item in chosen:
        steps = []
        for step in item["steps"]:
            rendered = dict(step)
            if step["kind"] == "run":
                rendered["cmd"] = resolve(step["cmd"], variables)
                scan_forbidden(rendered["cmd"])
            elif step["kind"] == "shim":
                rendered["install"] = shimlib.install_commands(variables["shim_dir"], step["shims"])
                rendered["shims"] = {k: [v[0], v[1]] for k, v in step["shims"].items()}
                scan_forbidden(rendered["install"])
            elif step["kind"] == "unshim":
                rendered["remove"] = shimlib.remove_commands(variables["shim_dir"])
            elif step["kind"] in ("owner", "hub"):
                rendered["text"] = resolve(step["text"], variables)
            elif step["kind"] == "local":
                rendered["argv"] = [resolve(arg, variables) for arg in step["argv"]]
                if not rendered["argv"] or rendered["argv"][0] not in LOCAL_TOOLS:
                    raise HarnessRefusal("a local step may run only %s, not %r" % (", ".join(LOCAL_TOOLS), rendered["argv"][:1]))
                scan_forbidden(" ".join(rendered["argv"]))
            elif step["kind"] == "evaluate":
                evaluator(step["fn"])
                for arg in step["args"]:
                    if arg.startswith("@") and arg[1:] not in EVALUATE_FACTS:
                        raise HarnessRefusal("evaluate %s names an unknown fact %s" % (step["name"], arg))
            steps.append(rendered)
        plan.append({"id": item["id"], "design": item["design"], "requires": list(item["requires"]),
                     "destructive": item["destructive"], "outline": bool(item.get("outline")), "steps": steps})
    return plan


def evaluator(name):
    """An evaluate step's function: readbacks.py first, then tierb_eval.py. Pure functions of captured text only."""
    for module in (readbacks, tierb_eval):
        fn = getattr(module, name, None)
        if callable(fn) and not name.startswith("_"):
            return fn
    raise HarnessRefusal("no evaluator named %s in readbacks or tierb_eval" % name)


def run_evaluate(step, captures, facts):
    """The verdict dict of one evaluate step. An evaluator that raises is a failed judgement, not a harness crash."""
    args = [facts.get(a[1:], "") if a.startswith("@") else captures.get(a, "") for a in step["args"]]
    try:
        verdict = evaluator(step["fn"])(*args)
    except Exception as exc:  # noqa: BLE001  (a reading the evaluator cannot parse fails the check)
        verdict = {"pass": False, "reason": "%s raised %s: %s" % (step["fn"], type(exc).__name__, exc)}
    if not isinstance(verdict, dict) or "pass" not in verdict:
        verdict = {"pass": False, "reason": "%s returned no verdict" % step["fn"]}
    return verdict


def local_argv(step, variables):
    """argv of a local step: the tool from this directory under the running Python, with --state. -E and -P (no
    PYTHON* variables, no unsafe sys.path entry) but not -I: hub_lite imports server/test_hub_h1_descriptor_signer.py,
    which imports pytest, and on this Mac pytest is in the user site that -I would drop."""
    state = os.path.expanduser(variables["hublite_state"])
    return [sys.executable, "-E", "-P", "-B", str(HERE / step["argv"][0])] + list(step["argv"][1:]) + ["--state", state]


def run_local(step, variables, captures, timeout=900):
    """Run one local step on this Mac. Returns (rc, stdout, stderr). It contacts no host: hub_lite's guard refuses
    any connection that is not AF_UNIX or loopback."""
    stdin = captures.get(step["stdin_capture"], "") if step.get("stdin_capture") else None
    try:
        done = subprocess.run(local_argv(step, variables), capture_output=True, text=True, timeout=timeout, input=stdin)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return 124, out, "harness timeout after %s s" % timeout
    return done.returncode, done.stdout, done.stderr


def check_expect(step, captures):
    value = captures.get(step["capture"], "")
    how, want = step["how"], step["value"]
    text = value.strip()
    padded = "\n" + text + "\n"
    if how == "contains":
        return want in value
    if how == "not_contains":
        return want not in padded and want not in value
    if how == "equals":
        return text == want
    if how == "regex":
        return re.search(want, value) is not None
    if how == "equals_capture":
        return text == captures.get(want, "").strip()
    raise HarnessRefusal("unknown expectation kind " + how)


def execute(plan, target, evidence, variables, state, have, guard_out, state_path, facts=None):
    """Run the resolved plan. Returns 0, or EXIT_OWNER at an owner checkpoint, or 1 on a failed check."""
    facts = dict(facts or {})
    facts.setdefault("slug", variables.get("slug", ""))
    failed = 0
    for scenario_index, item in enumerate(plan):
        if scenario_index < state.get("scenario", 0):
            continue
        missing = [r for r in item["requires"] if r not in have]
        if missing:
            evidence.record(item["id"], "blocked", "requires not declared with --have: " + ",".join(missing), "")
            print("blocked  %-40s needs %s" % (item["id"], ",".join(missing)))
            continue
        if item["outline"]:
            evidence.record(item["id"], "outline", "written as an outline; refuse to run", "")
            print("outline  %-40s not executable as written" % item["id"])
            continue
        captures = state.get("captures", {}) if scenario_index == state.get("scenario", 0) else {}
        log = []
        status = "pass"
        for step_index, step in enumerate(item["steps"]):
            if scenario_index == state.get("scenario", 0) and step_index < state.get("step", 0):
                continue
            kind = step["kind"]
            if kind == "owner":
                state_out = {"scenario": scenario_index, "step": step_index + 1, "captures": captures}
                Path(state_path).write_text(json.dumps(state_out))
                print("OWNER CHECKPOINT in %s: %s\nthen: tier_b.py resume --state %s" % (item["id"], step["text"], state_path))
                evidence.record(item["id"], "owner-checkpoint", step["text"], "\n".join(log))
                return EXIT_OWNER
            if kind == "hub":
                log.append("HUB STEP (needs hub-lite): " + step["text"])
                status = "partial"
                continue
            if kind == "run":
                rc, out, err = target.run(step["cmd"], step["timeout"])
                if step.get("private"):
                    # identity material (an admission secret) crosses to hub-lite but never into the evidence
                    shown = "(private capture: %d bytes, sha256 %s)\n" % (len(out.encode()), sha256_bytes(out.encode()))
                else:
                    shown = out
                log.append("$ " + step["cmd"] + "\n" + shown + err + "rc=%d" % rc)
                if step.get("capture"):
                    captures[step["capture"]] = out
                if step["rc"] is not None and rc != step["rc"]:
                    status = "fail"
                    log.append("FAIL: expected rc %s" % step["rc"])
                    break
            elif kind == "local":
                rc, out, err = run_local(step, variables, captures)
                log.append("local " + " ".join(step["argv"]) + "\n" + out + err + "rc=%d" % rc)
                if step.get("capture"):
                    captures[step["capture"]] = out
                if step["rc"] is not None and rc != step["rc"]:
                    status = "fail"
                    log.append("FAIL: expected rc %s" % step["rc"])
                    break
            elif kind == "shim":
                rc, out, err = target.run(step["install"], 120)
                log.append("shims installed rc=%d" % rc)
            elif kind == "unshim":
                target.run(step["remove"], 120)
            elif kind == "expect":
                if not check_expect(step, captures):
                    status = "fail"
                    log.append("FAIL: %s (%s %r on %s)" % (step.get("note", ""), step["how"], step["value"], step["capture"]))
                else:
                    log.append("ok: %s" % step.get("note", ""))
            elif kind == "evaluate":
                verdict = run_evaluate(step, captures, facts)
                log.append("evaluate %s: %s" % (step["name"], json.dumps(verdict, sort_keys=True, default=str)))
                if not verdict.get("pass"):
                    status = "fail"
                    if step.get("stop"):
                        log.append("STOP: %s failed; the rest of %s is not run" % (step["name"], item["id"]))
                        break
        evidence.record(item["id"], status, "", "\n".join(log))
        print("%-8s %s" % (status, item["id"]))
        if status == "fail":
            failed += 1
        state = {}
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("list", "staging", "plan", "run", "resume"))
    parser.add_argument("--target", default="colima:amd64t")
    parser.add_argument("--only", default="")
    parser.add_argument("--have", default="")
    parser.add_argument("--var", action="append", default=[])
    parser.add_argument("--installer")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--authorization")
    parser.add_argument("--state", default="tier_b.state.json")
    parser.add_argument("--evidence")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    scenarios = catalogue.catalogue()
    only = {x for x in args.only.split(",") if x}
    chosen = [s for s in scenarios if not only or s["id"] in only]
    if args.command == "list":
        for item in scenarios:
            tags = ",".join(item["requires"]) or "-"
            print("%-42s %-8s needs: %s%s" % (item["id"], item["profile"], tags, "  [destructive]" if item["destructive"] else ""))
        return 0

    variables = dict(catalogue.VARS)
    for pair in args.var:
        key, _, value = pair.partition("=")
        variables[key] = value
    installer = Installer(args.installer)
    if args.command == "staging":
        print(json.dumps(staging_text(installer, variables), indent=1))
        return 0
    plan = render_scenarios(chosen, variables)
    helpers = helper_texts(installer)
    have = {x for x in args.have.split(",") if x}
    # `have` decides which scenarios run rather than report blocked, so the owner's digest covers it too. So do the
    # control-plane installer and the harness code the local steps and the target run.
    cp_sha256, harness = sha256_file(ROOT / CP_RELATIVE), harness_digests()
    digest_body = {"target": args.target, "installer_sha256": installer.sha256, "scenarios": plan,
                   "helpers": {k: sha256_bytes(v.encode()) for k, v in helpers.items()}, "variables": variables,
                   "have": sorted(have), "control_plane_installer_sha256": cp_sha256, "harness_sha256": harness}
    digest = plan_digest(digest_body)

    if args.command == "plan" or not args.execute:
        text = {"dry_run": True, "plan_sha256": digest, "target": args.target, "installer_sha256": installer.sha256, "have": sorted(have),
                "control_plane_installer_sha256": cp_sha256, "harness_sha256": harness,
                "scenarios": [{"id": p["id"], "design": p["design"], "requires": p["requires"], "destructive": p["destructive"],
                               "outline": p["outline"], "steps": len(p["steps"])} for p in plan]}
        if args.json:
            text["resolved"] = plan
        print(json.dumps(text, indent=1))
        if args.command != "plan":
            print("not executing: pass --execute and --authorization FILE (the owner writes plan_sha256=%s and target=%s)" % (digest, args.target),
                  file=sys.stderr)
        return 0

    # execution: owner authorization is mandatory
    guard = HostGuard(digest, args.authorization, execute=True)
    guard.permit()
    lines = [x.strip() for x in Path(args.authorization).read_text().splitlines()]
    if "target=" + args.target not in lines:
        raise HarnessRefusal("authorization lacks target=" + args.target)
    target = make_target(args.target, dry_run=False)
    evidence = Evidence(args.evidence or ("tier-b-evidence-" + digest[:12]),
                        {"tier": "B", "target": args.target, "plan_sha256": digest, "installer_sha256": installer.sha256,
                         "gateway_binary_pin_sha256": installer.binary_pin})
    work = variables["work"]
    state = json.loads(Path(args.state).read_text()) if args.command == "resume" else {}
    if args.command == "run":
        target.run("install -d -m 700 %s" % work, 60)
        for name, text in helpers.items():
            target.run("cat > %s/%s" % (work, name), 60, input_text=text)
    return execute(plan, target, evidence, variables, state, have, None, args.state,
                   facts={"installer_sha256": installer.sha256, "binary_pin": installer.binary_pin, "slug": variables["slug"]})


def staging_text(installer, variables):
    """What `installer-staged` claims, resolved, with the digests the staging check demands. Contacts nothing."""
    return {"installer_sha256": installer.sha256, "binary_pin": installer.binary_pin,
            "binary_record_line": "%s  winn3-gateway-linux-amd64" % installer.binary_pin,
            "items": [{"path": resolve(path, variables), "what": what} for path, what in catalogue.STAGED],
            "cover_keys": list(catalogue.COVER_KEYS),
            "cover_source": "python3 -I -B tools/onetouch_tiers/cover_material.py generate --out DIR --cover-host NAME "
                            "(DIR/cover.env holds the five lines)",
            "edge_stub": "scenarios that need hub-lite and edge-stub also stage NODE_BOOTSTRAP_TOKEN from "
                         "`tools/onetouch_tiers/tierb_hub.py grant --slug {slug} --state {hublite_state}` (0600 file, never printed); "
                         "the guest's HUB_API_BASE reaches `hub_lite.py serve` from that state through the stubbed edge, its "
                         "public-IP lookups answer {endpoint_ip}, and the deploy's SSH session arrives over the stubbed management "
                         "tunnel (loopback source, DP FIX-6a): the SSH recovery guard's arm refuses a private source such as "
                         "colima's (DP 10076)".replace("{slug}", variables["slug"]).replace("{hublite_state}", variables["hublite_state"])
                         .replace("{endpoint_ip}", variables["endpoint_ip"]),
            "check": resolve(catalogue.STAGING_CHECK, variables),
            "judged_by": "tierb_eval.evaluate_staging(check output, installer_sha256, binary_pin)"}


if __name__ == "__main__":
    try:
        sys.exit(main())
    except HarnessRefusal as exc:
        print("refused: " + str(exc), file=sys.stderr)
        sys.exit(2)
