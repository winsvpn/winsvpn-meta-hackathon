"""Shared sandbox helpers for the fleet reset suites (2026-10-09).

The suites run SHIPPED installer functions and heredocs, extracted verbatim,
under Bash 4+. Host effects are faked by small scripts on a private PATH:
GNU stat/sha256sum/realpath (macOS has BSD tools), a find that understands the
GNU `-perm /077` probe the installers use, findmnt, and a logging systemctl.
Absolute host paths are rewritten into a per-test directory by the caller.
Nothing here touches the host's systemd, /etc, /var or /boot.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import textwrap
from pathlib import Path

try:
    import _toolchain  # noqa: F401  (V-01 preflight)

    BASH = _toolchain.bash4()
except ModuleNotFoundError:  # pragma: no cover
    BASH = os.environ.get("WINS_TEST_BASH") or shutil.which("bash") or "/bin/bash"

ROOT = Path(__file__).resolve().parents[1]
REAL_FIND = shutil.which("find", path="/usr/bin:/bin") or "/usr/bin/find"


def installer(env_name: str, relative: str) -> Path:
    """The installer under test; a mutant run points env_name at a copy."""
    return Path(os.environ.get(env_name, str(ROOT / relative)))


def function_text(source: str, name: str) -> str:
    """`name() { ... }` from column 0 to the first column-0 closing brace."""
    signature = f"\n{name}() {{\n"
    start = source.find(signature)
    if start < 0:
        raise AssertionError(f"installer defines no function {name}")
    start += 1
    end = source.index("\n}\n", start) + 3
    return source[start:end]


def heredoc(source: str, header: str, terminator: str) -> str:
    """The body of the here-document opened on the line that contains header."""
    start = source.index(header)
    start = source.index("\n", start) + 1
    end = source.index(f"\n{terminator}\n", start)
    return source[start:end] + "\n"


SHIMS = {
    "stat": r'''#!/usr/bin/env python3
import os, stat, sys
args = sys.argv[1:]
follow = False
fmt = None
paths = []
i = 0
while i < len(args):
    a = args[i]
    if a in ("-c", "--format"):
        fmt = args[i + 1]; i += 2; continue
    if a == "-Lc":
        follow = True; fmt = args[i + 1]; i += 2; continue
    if a == "-L":
        follow = True; i += 1; continue
    if a == "--":
        i += 1; continue
    paths.append(a); i += 1
rc = 0
for p in paths:
    try:
        st = os.stat(p) if follow else os.lstat(p)
    except OSError as exc:
        sys.stderr.write("stat: cannot stat %r: %s\n" % (p, exc)); rc = 1; continue
    uid = os.environ.get("FLEET_STAT_UID", "0")
    out = fmt
    out = out.replace("%u", uid).replace("%g", os.environ.get("FLEET_STAT_GID", "0"))
    out = out.replace("%U", "root" if uid == "0" else uid).replace("%G", "root")
    out = out.replace("%a", format(stat.S_IMODE(st.st_mode), "o")).replace("%s", str(st.st_size))
    out = out.replace("%Z", str(int(st.st_ctime))).replace("%i", str(st.st_ino)).replace("%n", p)
    print(out)
sys.exit(rc)
''',
    "sha256sum": r'''#!/usr/bin/env python3
import hashlib, sys
names = [a for a in sys.argv[1:] if not a.startswith("-")]
if not names:
    print("%s  -" % hashlib.sha256(sys.stdin.buffer.read()).hexdigest())
for n in names:
    with open(n, "rb") as fh:
        print("%s  %s" % (hashlib.sha256(fh.read()).hexdigest(), n))
''',
    "realpath": r'''#!/usr/bin/env python3
import os, sys
must = False
paths = []
for a in sys.argv[1:]:
    if a == "-e":
        must = True
    elif a == "--":
        continue
    else:
        paths.append(a)
rc = 0
for p in paths:
    if must and not os.path.exists(p):
        rc = 1; continue
    print(os.path.realpath(p))
sys.exit(rc)
''',
    "find": r'''#!/usr/bin/env python3
import os, stat, sys
a = sys.argv[1:]
if len(a) == 6 and a[1:] == ["-prune", "-perm", "/077", "-print", "-quit"]:
    if os.path.lexists(a[0]) and stat.S_IMODE(os.lstat(a[0]).st_mode) & 0o077:
        print(a[0])
    sys.exit(0)
os.execv("%(find)s", ["find"] + a)
''',
    "chown": r'''#!/bin/sh
# Ownership cannot change without root here; record the request instead.
printf 'chown %s\n' "$*" >> "${FLEET_CALLS:-/dev/null}"
''',
    "sed": r'''#!/bin/sh
# GNU `sed -i EXPR FILE` (the installers' form) on a BSD sed host.
if [ "$1" = "-i" ]; then shift; exec /usr/bin/sed -i '' "$@"; fi
exec /usr/bin/sed "$@"
''',
    "findmnt": r'''#!/usr/bin/env python3
import os, sys
a = sys.argv[1:]
target = a[a.index("-M") + 1] if "-M" in a else ""
state = os.environ.get("FLEET_MOUNTS", "")
if state and os.path.exists(state):
    for line in open(state):
        parts = line.split()
        if len(parts) == 2 and parts[0] == target:
            print(parts[1]); sys.exit(0)
sys.exit(1)
''',
}


class Sandbox:
    """A temporary directory with a shim bin directory first on PATH."""

    def __init__(self, extra_shims: dict[str, str] | None = None):
        self.tmp = Path(tempfile.mkdtemp(prefix="fr-"))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.calls = self.tmp / "calls.log"
        shims = dict(SHIMS)
        shims.update(extra_shims or {})
        for name, body in shims.items():
            path = self.bin / name
            path.write_text(body.replace("%(find)s", REAL_FIND) if name == "find" else body)
            path.chmod(0o755)

    def path(self, *parts: str) -> Path:
        p = self.tmp.joinpath(*parts)
        return p

    def env(self, **extra: str) -> dict:
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(self.tmp),
            "TMPDIR": str(self.tmp),
            "LC_ALL": "C",
            "FLEET_CALLS": str(self.calls),
        }
        env.update({k: str(v) for k, v in extra.items()})
        return env

    def run(self, script: str, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run([BASH, "-c", script], capture_output=True, text=True,
                              env=self.env(**extra), timeout=120)

    def logged(self) -> list[str]:
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def cleanup(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)


def stub_functions(*names: str, rc: int = 0) -> str:
    """Bash functions that log their name and arguments and return rc."""
    return "\n".join(
        f'{n}() {{ printf "%s\\n" "{n} $*" >> "$FLEET_CALLS"; return {rc}; }}' for n in names
    ) + "\n"


LOG_STUBS = textwrap.dedent('''
    log() { printf '[INFO] %s\\n' "$*"; }
    warn() { printf '[WARN] %s\\n' "$*" >&2; }
    err() { printf '[ERR] %s\\n' "$*" >&2; }
''')
