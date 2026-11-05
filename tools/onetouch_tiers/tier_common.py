"""Shared code for the S7 tier harnesses (design v17 sections 5.1 to 5.7).

What lives here:
  * VmRunner: the only way the harness reaches a VM. It speaks `colima ssh -p
    <profile> --` for the two local profiles the design allows (l80 and
    amd64t) and refuses everything else, including any attempt to start,
    stop, restart or delete a profile. Dry run records the command and runs
    nothing.
  * HostGuard: the gate for Tier B against real hosts. A real host is never
    contacted unless an owner-written authorization file carries the digest of
    the exact dry-run plan.
  * Evidence: one directory per run, a JSONL index plus the raw output of each
    scenario with its SHA-256, the node class, the DP digest and the bundle
    digest (5.7 "records its raw output ... with the node class").
  * bundle(): turns the installer under test into a self-contained directory
    the Linux fixtures source (the extracted functions, the two guard
    programs rendered the way the installer renders them, the fixtures).

Nothing here reads a key, a token or a secrets file. Test material is made up
inside the fixtures and lives in a tmpfs that disappears with the namespace.
"""
import datetime
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from winn3_gateway_block import segment  # noqa: E402  (the repo's own bash segmenter)

DP_RELATIVE = "server/wins_data_plane_setup_ONETOUCH.sh"

# Design 5.1 and 5.3: Tier A uses l80 (aarch64), Tier B uses amd64t (x86_64).
# The lane brief allows the two local profiles for test namespaces only.
ALLOWED_PROFILES = ("l80", "amd64t")
# colima sub-commands that change a VM. None of them is ever issued.
FORBIDDEN_COLIMA_VERBS = ("start", "stop", "restart", "delete", "kill", "prune", "template", "update", "nerdctl")


class HarnessRefusal(Exception):
    """The harness refused to do something it must never do."""


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# VM access
# ---------------------------------------------------------------------------
class Result:
    def __init__(self, argv, returncode, stdout, stderr, seconds, dry=False):
        self.argv = argv
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.seconds = seconds
        self.dry = dry

    @property
    def ok(self):
        return self.returncode == 0


class VmRunner:
    """Runs commands in a local colima guest, in a namespace the caller sets up."""

    def __init__(self, profile, dry_run=True, plan=None, colima="colima"):
        if profile not in ALLOWED_PROFILES:
            raise HarnessRefusal("profile %r is not one of %s" % (profile, ", ".join(ALLOWED_PROFILES)))
        self.profile = profile
        self.dry_run = dry_run
        self.plan = plan if plan is not None else []
        self.colima = colima

    def argv(self, remote):
        """The full local argv for a remote shell command string."""
        if not isinstance(remote, str) or not remote.strip():
            raise HarnessRefusal("empty remote command")
        self.check_remote(remote)
        return [self.colima, "ssh", "-p", self.profile, "--", "sh", "-c", remote]

    @staticmethod
    def check_remote(remote):
        """No remote command may manage VMs or power. An unparseable command string is refused."""
        lexer = shlex.shlex(remote, posix=True, punctuation_chars=";&|()")
        lexer.whitespace_split = True
        try:
            tokens = list(lexer)
        except ValueError as exc:
            raise HarnessRefusal("unparseable remote command: %s" % exc)
        commands, current = [], []
        for token in tokens:
            if token and set(token) <= set(";&|()"):
                commands.append(current)
                current = []
            else:
                current.append(token)
        commands.append(current)
        for words in commands:
            while words and (words[0] in ("sudo", "env", "nice", "timeout", "exec", "time", "nohup") or words[0].startswith("-")
                             or "=" in words[0].split("/")[0]):
                words = words[1:]
            if not words:
                continue
            text = " ".join(words)
            if words[0] in ("colima", "limactl") and any(t in FORBIDDEN_COLIMA_VERBS for t in words[1:3]):
                raise HarnessRefusal("refusing a VM management command: " + text)
            if words[0] in ("poweroff", "reboot", "halt", "shutdown"):
                raise HarnessRefusal("refusing to power-manage the guest: " + text)
            if words[0] == "systemctl" and len(words) > 1 and words[1] in ("reboot", "poweroff", "halt", "kexec"):
                raise HarnessRefusal("refusing to power-manage the guest: " + text)
            if words[0] in ("pkill", "killall"):
                raise HarnessRefusal("never pkill by pattern: " + text)

    def run(self, remote, timeout=300, purpose="", input_text=None):
        argv = self.argv(remote)
        self.plan.append({"vm": self.profile, "purpose": purpose, "remote": remote})
        if self.dry_run:
            return Result(argv, 0, "", "", 0.0, dry=True)
        started = datetime.datetime.now()
        try:
            # colima ssh changes into the caller's working directory inside the guest; /tmp exists in every guest
            done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input_text, cwd="/tmp")
        except subprocess.TimeoutExpired as exc:
            # on POSIX the partial output of a timed-out run is bytes even with text=True
            out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return Result(argv, 124, out, err + "\nharness timeout", timeout)
        seconds = (datetime.datetime.now() - started).total_seconds()
        return Result(argv, done.returncode, done.stdout, done.stderr, seconds)


FORBIDDEN_COMMAND = re.compile(
    # `sudo` may carry options (`sudo -n`), as every Tier B step does
    r"(^|[;&|(`]|\$\(|&&|\|\||\bsudo(\s+-\S+)*\s+|\bexec\s+)\s*"
    r"(pkill|killall|poweroff|halt|shutdown|reboot|init\s+[06]|systemctl\s+(reboot|poweroff|halt|kexec)"
    r"|(colima|limactl)\s+(start|stop|restart|delete|kill|prune|template)"
    r"|mkfs\S*|dd\s+if=\S+\s+of=/dev/)\b"
    # `rm` of the root sits outside the trailing \b: after `/` at the end of a line or before a space there is no word
    # boundary. Any option words (`-Rf`, `-r -f`, `--`) and a quoted `/` or `/*` are refused; `/tmp/x` is not.
    r"|(^|[;&|(`]|\$\(|&&|\|\||\bsudo(\s+-\S+)*\s+|\bexec\s+)\s*rm\s+(-\S*\s+)*[\"']?/\*?[\"']?(?=[\s;&|)`]|$)",
    re.MULTILINE)


def scan_forbidden(text):
    """Tier B commands are long scripts; this scans them for the few things no harness step may ever run."""
    found = FORBIDDEN_COMMAND.search(text)
    if found:
        raise HarnessRefusal("forbidden command in a harness step: " + found.group(0).strip())
    return True


# ---------------------------------------------------------------------------
# Real hosts (Tier B)
# ---------------------------------------------------------------------------
class HostGuard:
    """Tier B talks to a real host only with the owner's written authorization.

    The authorization file must contain a line `plan_sha256=<digest>` where the
    digest is that of the exact plan the dry run printed. A different plan, a
    host the plan does not name, or a missing file means no contact.
    """

    def __init__(self, plan_digest, authorization=None, execute=False):
        self.plan_digest = plan_digest
        self.authorization = authorization
        self.execute = execute

    def permit(self):
        if not self.execute:
            return False
        if not self.authorization:
            raise HarnessRefusal("--execute needs --authorization FILE written by the owner")
        text = Path(self.authorization).read_text()
        lines = [line.strip() for line in text.splitlines()]
        if "plan_sha256=" + self.plan_digest not in lines:
            raise HarnessRefusal("authorization does not carry this plan's digest " + self.plan_digest)
        return True


def plan_digest(plan):
    return sha256_bytes(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode())


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
class Evidence:
    """A directory of raw outputs plus index.jsonl (5.7: raw output with node class and digests)."""

    def __init__(self, directory, header):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.header = dict(header)
        self.header["started"] = utc_now()
        (self.directory / "header.json").write_text(json.dumps(self.header, indent=1, sort_keys=True) + "\n")
        self.index = self.directory / "index.jsonl"

    def record(self, scenario, status, detail="", raw=""):
        raw_bytes = raw.encode() if isinstance(raw, str) else raw
        name = re.sub(r"[^A-Za-z0-9._-]", "_", scenario) + ".out"
        (self.directory / name).write_bytes(raw_bytes)
        row = {"scenario": scenario, "status": status, "detail": detail, "time": utc_now(),
               "raw": name, "raw_sha256": sha256_bytes(raw_bytes)}
        with open(self.index, "a") as stream:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
        return row


NODE_CLASS_COMMAND = (
    "uname -m; "
    "(lscpu 2>/dev/null | grep -m1 'Model name') || grep -m1 -E '^(model name|Model|Hardware)' /proc/cpuinfo || echo 'model name: unknown'; "
    "cat /sys/fs/cgroup/cpuset.cpus.effective 2>/dev/null || echo unknown; "
    "grep -m1 MemTotal /proc/meminfo; "
    "systemd-detect-virt 2>/dev/null || echo none; "
    ". /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\"; "
    "systemctl --version | head -1; "
    "iptables --version 2>/dev/null || echo iptables-missing; "
    "df -B1G / | tail -1"
)


def node_class(runner):
    """CPU model, usable CPUs from cpuset.cpus.effective, RAM and provider (5.7)."""
    if runner.dry_run:
        runner.run(NODE_CLASS_COMMAND, purpose="node class read-back")
        return {"dry_run": True}
    result = runner.run(NODE_CLASS_COMMAND, timeout=60, purpose="node class read-back")
    lines = result.stdout.splitlines()
    keys = ("machine", "cpu_model", "usable_cpus", "mem_total", "virt", "os", "systemd", "iptables", "root_fs")
    info = dict(zip(keys, lines))
    info["provider"] = "local colima profile " + runner.profile
    info["emulated"] = info.get("virt", "") in ("qemu",) and runner.profile == "amd64t"
    return info


# ---------------------------------------------------------------------------
# The installer under test
# ---------------------------------------------------------------------------
class Installer:
    """Reads functions and embedded programs out of the data-plane installer."""

    def __init__(self, path=None):
        self.path = Path(path) if path else ROOT / DP_RELATIVE
        self.text = self.path.read_text()
        self.lines = self.text.split("\n")
        self._items = None
        self.sha256 = sha256_bytes(self.text.encode())

    @property
    def items(self):
        if self._items is None:
            self._items = segment(self.lines)
        return self._items

    def function(self, name, last=True):
        found = [i for i in self.items if i["kind"] == "func" and i["name"] == name]
        if not found:
            raise HarnessRefusal("installer has no top-level function " + name)
        item = found[-1] if last else found[0]
        return "\n".join(self.lines[item["start"]:item["end"] + 1])

    @property
    def binary_pin(self):
        """The certified gateway binary digest the installer pins (design 2.3: the digest is a constant)."""
        match = re.search(r"^WINN3_ONETOUCH_BINARY_SHA256=([0-9a-f]{64})$", self.text, re.M)
        return match.group(1) if match else ""

    def has_function(self, name):
        return any(i["kind"] == "func" and i["name"] == name for i in self.items)

    def heredoc(self, marker):
        """The body of a quoted here-document, like S4's tests read it."""
        opening = "<<'" + marker + "'\n"
        if opening not in self.text:
            raise HarnessRefusal("installer has no here-document " + marker)
        return self.text.split(opening, 1)[1].split("\n" + marker + "\n", 1)[0]


GUARD_FUNCTIONS = ("wins_late_failure_hold", "wins_latch_rules_inspect", "wins_latch_rules_dominate")


def render_guard(installer, marker):
    """The guard program as winn3_prepend_shared_functions leaves it installed."""
    body = installer.heredoc(marker)
    if not body.startswith("#!/usr/bin/env bash"):
        raise HarnessRefusal(marker + " does not start with a shebang")
    shared = "\n".join(installer.function(name) for name in GUARD_FUNCTIONS)
    return "#!/usr/bin/env bash\n" + shared + "\n" + body.split("\n", 1)[1] + "\n"


# Functions of the installer the exit handler tests source, by name. Order is not important.
HANDLER_FUNCTIONS = (
    "wins_late_failure_hold", "wins_latch_rules_inspect", "wins_latch_rules_dominate", "winn3_latch_file_safe",
    "winn3_latch_dominates", "winn3_late_record", "winn3_late_command", "winn3_recovery_source",
    "winn3_late_repair_live", "winn3_late_stop_services", "winn3_late_diagnose", "winn3_late_fallback",
    "winn3_late_fence", "winn3_late_settle_command", "winn3_late_settle", "winn3_late_failure_on_exit",
    "winn3_late_failure_reassert", "winn3_installer_exit", "winn3_resume_repair_before_guard",
    "winn3_installer_fw_lock", "winn3_installer_fw_unlock", "wins_fw_lock", "wins_fw_unlock",
    "deploy_firewall_rollback_on_exit", "data_plane_installer_path", "data_plane_installer_sha256",
    "wins_serving_start", "winn3_write_serving_activator",
)

EDGE_FUNCTIONS = GUARD_FUNCTIONS + ("winn3gw_render_chains",)


def render_edge(installer):
    """wins-edge-hardening as write_edge_hardening_script plus winn3_prepend_shared_functions leave it (DP 11853)."""
    body = installer.heredoc("WINS_EDGE_EOF")
    shared = "\n".join(installer.function(name) for name in EDGE_FUNCTIONS)
    return "#!/usr/bin/env bash\n" + shared + "\n" + body.split("\n", 1)[1] + "\n"


LINUX_DIR = HERE / "linux"


def bundle(installer, out_dir, extra_files=None):
    """Write the directory the Linux fixtures source. Returns its SHA-256 manifest digest."""
    out = Path(out_dir)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    (out / "dp").mkdir()
    for name in HANDLER_FUNCTIONS:
        (out / "dp" / (name + ".sh")).write_text(installer.function(name) + "\n")
    (out / "dp" / "guard_local_serving").write_text(render_guard(installer, "WINS_NODE_LOCAL_SERVING_GUARD"))
    (out / "dp" / "guard_ssh_recovery").write_text(render_guard(installer, "WINS_NODE_SSH_RECOVERY_GUARD"))
    (out / "dp" / "edge_hardening").write_text(render_edge(installer))
    (out / "dp" / "latch_predicate.py").write_text(installer.heredoc("WINS_LATCH_PY") + "\n")
    for source in sorted(LINUX_DIR.iterdir()):
        if source.is_file():
            shutil.copy2(source, out / source.name)
    for name, body in (extra_files or {}).items():
        target = out / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    manifest = {}
    for path in sorted(out.rglob("*")):
        if path.is_file():
            manifest[str(path.relative_to(out))] = sha256_file(path)
    digest = sha256_bytes(json.dumps(manifest, sort_keys=True).encode())
    (out / "MANIFEST.json").write_text(json.dumps({"installer_sha256": installer.sha256, "files": manifest,
                                                   "digest": digest}, indent=1, sort_keys=True) + "\n")
    return digest


def parse_fixture_output(text):
    """Lines the Linux fixtures print: `S7 ok|not-ok|skip|note <scenario> <rest>`."""
    rows = []
    for line in text.splitlines():
        match = re.match(r"^S7 (ok|not-ok|skip|note) (\S+) ?(.*)$", line)
        if match:
            rows.append({"kind": match.group(1), "scenario": match.group(2), "text": match.group(3)})
    return rows


def summarize(rows):
    summary = {}
    for row in rows:
        entry = summary.setdefault(row["scenario"], {"ok": 0, "not-ok": 0, "skip": 0, "note": 0, "failures": []})
        entry[row["kind"]] += 1
        if row["kind"] == "not-ok":
            entry["failures"].append(row["text"])
    return summary
