#!/bin/bash
# Production parent for the retained-descriptor dependency-freeze worker.
#
# The worker runs on the release Python pinned for this host by
# tools/toolchain-pins.json (tools.python.reviewed_executable_path and
# tools.python.executable_sha256). This parent refuses an interpreter whose
# bytes differ from the pin; the worker independently binds its kernel process
# image to the same pinned path and bytes before granting production authority.

set -euo pipefail

readonly expected_name=run_release_dependency_freeze.sh
readonly controller_name=release_dependency_freeze.py
readonly pin_reader=/usr/bin/python3

fail() {
  printf 'RELEASE DEPENDENCY FREEZE PARENT: FAIL: %s\n' "$*" >&2
  exit 1
}

[[ "${BASH_SOURCE[0]}" == /* && "${BASH_SOURCE[0]}" != /dev/fd/* ]] ||
  fail "parent must be invoked by its absolute repository path"
[[ "${BASH_SOURCE[0]##*/}" == "$expected_name" && ! -L "${BASH_SOURCE[0]}" ]] ||
  fail "parent path is symbolic or substituted"
readonly tool_dir="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly controller="$tool_dir/$controller_name"
readonly pins="$tool_dir/toolchain-pins.json"
readonly repo="$(cd -P "$tool_dir/.." && pwd)"
[[ "$controller" == "$repo/tools/$controller_name" && -f "$controller" && ! -L "$controller" ]] ||
  fail "reviewed dependency-freeze controller is unavailable"
[[ -f "$pins" && ! -L "$pins" ]] ||
  fail "reviewed toolchain pins are unavailable"
[[ "$(/usr/bin/id -u)" != 0 ]] ||
  fail "worker parent refuses euid 0"
[[ $# -ge 1 ]] ||
  fail "a dependency-freeze command is required"

case "$(/usr/bin/uname -s)/$(/usr/bin/uname -m)" in
  Darwin/arm64) host_key=darwin_arm64 ;;
  Darwin/x86_64) host_key=darwin_amd64 ;;
  *) fail "the dependency-freeze worker is reviewed for macOS release hosts only" ;;
esac

pin_record="$(
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$pin_reader" -I -S - "$pins" "$host_key" <<'PY'
import json
import os
import re
import sys


def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        python = json.load(handle, object_pairs_hook=reject_duplicates)["tools"]["python"]
    path = python["reviewed_executable_path"][sys.argv[2]]
    digest = python["executable_sha256"][sys.argv[2]]
    version = python["version"]
except (OSError, KeyError, TypeError, ValueError) as error:
    raise SystemExit(f"release Python pin is unavailable: {error}")
if (
    not isinstance(path, str)
    or not path.startswith("/")
    or os.path.normpath(path) != path
    or any(character in path for character in "|\n\r\0")
):
    raise SystemExit("release Python path pin is malformed")
if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
    raise SystemExit("release Python SHA-256 pin is malformed")
if version != "3.14.7":
    raise SystemExit("release Python version pin drifted")
print(path, digest, sep="|")
PY
)" || fail "tools/toolchain-pins.json does not pin a release Python for $host_key"
IFS='|' read -r python python_sha256 <<<"$pin_record"
readonly python python_sha256

[[ -f "$python" && -x "$python" && ! -L "$python" ]] ||
  fail "pinned release Python is not a regular non-symlink executable: $python"
observed_sha256="$(/usr/bin/shasum -a 256 -- "$python")" ||
  fail "pinned release Python could not be hashed: $python"
observed_sha256="${observed_sha256%% *}"
[[ "$observed_sha256" == "$python_sha256" ]] ||
  fail "pinned release Python bytes do not match tools/toolchain-pins.json: observed=$observed_sha256 pin=$python_sha256"

# The worker keeps every selected input and its ancestor chain open until it
# returns: about 14,845 descriptors for the Android set at release 1.0.16+33.
# PowerShell on macOS hands its children a soft limit of 10240, and the formal
# Android producer runs under PowerShell, so raise the soft limit here, within
# the hard limit, for every caller.
readonly required_open_files=131072
soft_open_files="$(ulimit -Sn)" ||
  fail "cannot read the open-file soft limit"
readonly soft_open_files
[[ "$soft_open_files" == unlimited || "$soft_open_files" =~ ^[0-9]+$ ]] ||
  fail "unexpected open-file soft limit: $soft_open_files"
if [[ "$soft_open_files" != unlimited ]] && (( soft_open_files < required_open_files )); then
  ulimit -Sn "$required_open_files" 2>/dev/null ||
    fail "cannot raise the open-file soft limit to $required_open_files (soft $soft_open_files, hard $(ulimit -Hn))"
fi

# Bash-created descriptor 9 is retained across env and the Python exec. The
# worker recompiles the bytes from this same descriptor and compares them to
# the code executing from /dev/fd/9 before granting production authority.
exec 9<"$controller"
[[ -r /dev/fd/9 ]] || fail "retained controller descriptor is unavailable"

exec /usr/bin/env -i \
  HOME=/private/tmp \
  LANG=C \
  LC_ALL=C \
  PATH=/usr/bin:/bin \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONNOUSERSITE=1 \
  TMPDIR=/private/tmp \
  "$python" -I -S /dev/fd/9 \
  --_wins-release-dependency-worker-fd 9 "$@"
