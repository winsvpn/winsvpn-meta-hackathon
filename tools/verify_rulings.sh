#!/bin/bash
# verify_rulings.sh: check every ruled invariant in docs/rulings/RULINGS.lock.
#
# Run by the DISPATCHER after every lane merge and before any release build:
#   tools/verify_rulings.sh [repo_root]
#
# Exit 0: every invariant holds. Exit 1: at least one violated (each named).
# Exit 2: the lockfile is missing or empty, which is itself a failure, so a
# lane cannot pass this check by deleting or emptying the lockfile.
#
# Deliberately boring: fixed-string grep per entry, no pipelines on the
# checked path (a pipeline can eat an exit code), no test cache, no shared
# scratch state. See memory: lane verification lies; this runs outside it.

set -u
set -o pipefail

ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
LOCK="$ROOT/docs/rulings/RULINGS.lock"

if [ ! -f "$LOCK" ]; then
  echo "RULINGS: FAIL lockfile missing: $LOCK"
  exit 2
fi

# E-05/E1 (audit 2026-08-28): the old whole-file `grep -qF` was satisfied by
# the pinned literal's own corpse inside a comment -- commenting out the
# ruled assignment kept the gate green. Matching now runs against a
# comment-stripped view of source files: line comments and multiline block
# comments are removed, while quoted strings and Markdown content survive.
# Read errors and unterminated block comments fail the gate.
# In a shell script (.sh) only # starts a comment: /* is a glob there and //
# part of a path, so neither opens a comment (design v17 2.8: the data-plane
# installer's `[[ "${1:-}" == /* ]]` read as a block comment that never ends).
stripped() {
  python3 - "$1" <<'PYSCAN'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
if path.suffix == ".md":
    sys.stdout.write(source)
    raise SystemExit(0)
shell = path.suffix == ".sh"
output = []
i = 0
block_depth = 0
quote = None
while i < len(source):
    char = source[i]
    pair = source[i:i + 2]
    if block_depth:
        if pair == "/*":
            block_depth += 1
            i += 2
        elif pair == "*/":
            block_depth -= 1
            i += 2
            output.append(" ")
        else:
            if char == "\n":
                output.append("\n")
            i += 1
        continue
    if quote is not None:
        output.append(char)
        i += 1
        if char == "\\" and i < len(source):
            output.append(source[i])
            i += 1
        elif char == quote:
            quote = None
        continue
    if pair == "/*" and not shell:
        block_depth = 1
        output.append(" ")
        i += 2
    elif (pair == "//" and not shell) or char == "#":
        end = source.find("\n", i)
        i = len(source) if end < 0 else end
    else:
        if char in ("'", '"'):
            quote = char
        output.append(char)
        i += 1
if block_depth:
    raise SystemExit("Unterminated block comment in " + str(path))
sys.stdout.write("".join(output))
PYSCAN
}

contains_live() {
  # $1 = file, $2 = literal
  local content
  if ! content="$(stripped "$1")"; then
    echo "RULINGS: FAIL cannot parse $1" >&2
    exit 2
  fi
  grep -qF -- "$2" <<< "$content"
}

checked=0
failed=0

while IFS= read -r line; do
  case "$line" in
    ''|'#'*) continue ;;
  esac

  kind="${line%% :: *}"
  kind="${kind//[[:space:]]/}"
  rest="${line#* :: }"
  path="${rest%% :: *}"
  literal="${rest#* :: }"

  if [ -z "$kind" ] || [ -z "$path" ] || [ -z "$literal" ] || [ "$rest" = "$line" ] || [ "$literal" = "$rest" ]; then
    echo "RULINGS: FAIL malformed entry: $line"
    failed=$((failed + 1))
    continue
  fi

  file="$ROOT/$path"
  checked=$((checked + 1))

  if [ ! -f "$file" ]; then
    echo "RULINGS: FAIL missing file: $path"
    failed=$((failed + 1))
    continue
  fi

  if [ "$kind" = "REQUIRE" ]; then
    if contains_live "$file" "$literal"; then
      echo "RULINGS: ok   REQUIRE $path :: $literal"
    else
      echo "RULINGS: FAIL REQUIRE $path :: $literal (literal absent)"
      failed=$((failed + 1))
    fi
  elif [ "$kind" = "FORBID" ]; then
    if contains_live "$file" "$literal"; then
      echo "RULINGS: FAIL FORBID $path :: $literal (literal present)"
      failed=$((failed + 1))
    else
      echo "RULINGS: ok   FORBID $path :: $literal"
    fi
  else
    echo "RULINGS: FAIL unknown entry kind '$kind': $line"
    failed=$((failed + 1))
  fi
done < "$LOCK"

if [ "$checked" -eq 0 ]; then
  echo "RULINGS: FAIL lockfile has no entries: $LOCK"
  exit 2
fi

# ---------------------------------------------------------------------------
# APPLE enforceRoutes drift guard (added 2026-08-11).
#
# The generic RULINGS.lock loop above is driven by whatever the lockfile says,
# so it can be weakened by an edit to the lockfile itself. These checks are
# hardcoded in the script and re-assert the ruled posture independently of the
# lockfile: the iOS and macOS Apple runners must each keep a literal
# `enforceRoutes = true` (never `false`) at the ruled application sites.
#
# Per the false-green catalogue, a check that only asserts a POSITIVE fact can
# be satisfied by a leftover literal in a comment or a dead path. So each file
# is checked BOTH ways: the `= true` literal must be present (REQUIRE) AND the
# `= false` literal must be absent (FORBID). A revert of the posture fails the
# FORBID arm even if a stale `= true` string survives somewhere else.
# ---------------------------------------------------------------------------
apple_checked=0
apple_failed=0

apple_require_literal() {
  # apple_require_literal <path> <literal>
  local p="$1" lit="$2"
  local f="$ROOT/$p"
  apple_checked=$((apple_checked + 1))
  if [ ! -f "$f" ]; then
    echo "RULINGS(apple): FAIL missing file: $p"
    apple_failed=$((apple_failed + 1))
    return
  fi
  if contains_live "$f" "$lit"; then
    echo "RULINGS(apple): ok   REQUIRE $p :: $lit"
  else
    echo "RULINGS(apple): FAIL REQUIRE $p :: $lit (enforceRoutes=true drifted)"
    apple_failed=$((apple_failed + 1))
  fi
}

apple_forbid_literal() {
  # apple_forbid_literal <path> <literal>
  local p="$1" lit="$2"
  local f="$ROOT/$p"
  apple_checked=$((apple_checked + 1))
  if [ ! -f "$f" ]; then
    echo "RULINGS(apple): FAIL missing file: $p"
    apple_failed=$((apple_failed + 1))
    return
  fi
  if contains_live "$f" "$lit"; then
    echo "RULINGS(apple): FAIL FORBID $p :: $lit (enforceRoutes=false reintroduced)"
    apple_failed=$((apple_failed + 1))
  else
    echo "RULINGS(apple): ok   FORBID $p :: $lit"
  fi
}

if [ "${WINS_SKIP_APPLE_DRIFT:-0}" = "1" ]; then
  echo "RULINGS(apple): FAIL apple enforceRoutes drift guard may not be skipped in a release gate (WINS_SKIP_APPLE_DRIFT=1)"
  apple_failed=$((apple_failed + 1))
else
  # macOS: single source of posture is WinsMacRoutePosture.enforceRoutes,
  # which is ruled `true`; the connect path must keep reading from it.
  apple_require_literal "macos/Runner/RouteAudit.swift" "static let enforceRoutes = true"
  apple_forbid_literal "macos/Runner/RouteAudit.swift" "static let enforceRoutes = false"
  apple_require_literal "macos/Runner/MainFlutterWindow.swift" "tunnelProtocol.enforceRoutes = WinsMacRoutePosture.enforceRoutes"
  apple_forbid_literal "macos/Runner/MainFlutterWindow.swift" "enforceRoutes = false"

  # iOS: runner applies the ruled `true` literal directly.
  apple_require_literal "ios/Runner/AppDelegate.swift" "tunnelProtocol.enforceRoutes = true"
  apple_forbid_literal "ios/Runner/AppDelegate.swift" "enforceRoutes = false"
fi

if [ "$apple_failed" -gt 0 ]; then
  echo "RULINGS(apple): $apple_failed of $apple_checked apple enforceRoutes checks FAILED."
  echo "RULINGS(apple): the iOS/macOS enforceRoutes = true posture drifted. Do not"
  echo "RULINGS(apple): merge or release; restore the ruled posture or produce a dated"
  echo "RULINGS(apple): ruling document first."
  exit 1
fi

# ---------------------------------------------------------------------------
# ReleasePython v2 has no updater or transition agent (ruled 2026-09-03).
#
# RULINGS.lock entries name exact paths, so a new source file could otherwise
# introduce a v2 updater without touching the locked v1 updater source. Scan all
# tracked content except the lock entry that names the forbidden literal, and
# reject any tracked pathname that combines v2 with updater. The path is
# assembled below so this verifier does not match its own source. The release
# gate separately requires a clean tree, so untracked source cannot become
# reviewed release input.
# ---------------------------------------------------------------------------
releasepython_v2_failed=0
v2_authority_directory="/Library/WinsVPN/ReleasePythonAuthority/v2"
v2_updater_path="${v2_authority_directory}/owner-updater"
# Both checks below read git's index. Outside a work tree git fails, and a
# failure must never read as "nothing tracked": each git status is checked.
if [ "$(git -C "$ROOT" rev-parse --is-inside-work-tree 2>/dev/null)" != "true" ]; then
  echo "RULINGS(releasepython): FAIL $ROOT is not a git work tree, so tracked content cannot be checked"
  releasepython_v2_failed=$((releasepython_v2_failed + 1))
else
  git -C "$ROOT" grep -qiF -- "$v2_updater_path" -- . ':(exclude)docs/rulings/RULINGS.lock'
  v2_grep_status=$?
  if [ "$v2_grep_status" -eq 0 ]; then
    echo "RULINGS(releasepython): FAIL tracked content contains forbidden v2 updater path"
    releasepython_v2_failed=$((releasepython_v2_failed + 1))
  elif [ "$v2_grep_status" -eq 1 ]; then
    echo "RULINGS(releasepython): ok   no tracked content contains a v2 updater path"
  else
    echo "RULINGS(releasepython): FAIL git grep exited $v2_grep_status; tracked content was not checked"
    releasepython_v2_failed=$((releasepython_v2_failed + 1))
  fi

  if tracked_paths="$(git -C "$ROOT" ls-files)"; then
    tracked_v2_updater_paths="$(awk 'tolower($0) ~ /v2/ && tolower($0) ~ /updater/' <<< "$tracked_paths")"
    if [ -n "$tracked_v2_updater_paths" ]; then
      echo "RULINGS(releasepython): FAIL tracked v2 updater tool pathname exists"
      printf '%s\n' "$tracked_v2_updater_paths"
      releasepython_v2_failed=$((releasepython_v2_failed + 1))
    else
      echo "RULINGS(releasepython): ok   no tracked v2 updater tool pathname exists"
    fi
  else
    echo "RULINGS(releasepython): FAIL git ls-files failed; tracked pathnames were not checked"
    releasepython_v2_failed=$((releasepython_v2_failed + 1))
  fi
fi

if [ "$releasepython_v2_failed" -gt 0 ]; then
  echo "RULINGS(releasepython): v2 is a four-leaf generation with no updater."
  echo "RULINGS(releasepython): produce a new dated owner ruling before changing this posture."
  exit 1
fi

if [ "$failed" -gt 0 ]; then
  echo "RULINGS: $failed of $checked invariant checks FAILED. A ruled decision"
  echo "RULINGS: has been changed without a ruling event. Do not merge, do not"
  echo "RULINGS: release; restore the invariant or produce a dated ruling doc."
  exit 1
fi

# E5: a gutted lockfile (most entries deleted) is a failure, not a pass.
EXPECTED_CHECKS=59
EXPECTED_APPLE_CHECKS=6
if [ "$checked" -lt "$EXPECTED_CHECKS" ]; then
  echo "RULINGS: FAIL only $checked invariant checks ran; the lockfile is expected to carry at least $EXPECTED_CHECKS entries. If entries were deliberately retired, update EXPECTED_CHECKS in this script alongside the ruling document."
  exit 1
fi
if [ "$apple_checked" -lt "$EXPECTED_APPLE_CHECKS" ]; then
  echo "RULINGS(apple): FAIL only $apple_checked apple checks ran; at least $EXPECTED_APPLE_CHECKS are expected."
  exit 1
fi
echo "RULINGS: all $checked invariant checks passed."
echo "RULINGS(apple): all $apple_checked apple enforceRoutes checks passed."
exit 0
