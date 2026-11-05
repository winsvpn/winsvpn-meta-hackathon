#!/usr/bin/env python3
"""An operation that fails with an `Error` must not be handled as an `Exception`.

WHY THIS EXISTS
---------------
On 2026-08-08 Android lint ran on this project for the first time and found an
API 26 call under `minSdk 24` in `WinnCarrierProfile.kt`. The API level was not
the interesting part. The interesting part was that the call was *already*
wrapped in `catch (_: Exception)` and that this did nothing, because a class
missing from the runtime raises `NoClassDefFoundError` -- an `Error`, which is
not an `Exception`. The handler looked like a fallback and was in fact a crash
on every API 24 and 25 handset.

A sweep for the same shape found a second one that lint CANNOT see, because
nothing about it is an API level: `System.loadLibrary` raises
`UnsatisfiedLinkError`, also an `Error`, and both of `VpnTunnelService`'s engine
run loops caught `Exception`. There it was worse than a crash -- the handler
that was skipped is the one calling `clearRestartConfig()`, so the service came
back and did it again, indefinitely.

`ApiLevelGateTest.kt` pins those two fixes at their two call sites. It cannot
catch the third occurrence in a file nobody has looked at yet. This gate is the
general form: it finds the *shape* anywhere in any Android module, including the
ones that have no Kotlin test task at all (`wear_os`, `android/devicecheck`).

WHY IT IS PYTHON AND NOT LINT
-----------------------------
Two reasons, both practical:

  1. Lint has no detector for this. `NewApi` sees the API level; nothing in the
     standard detector set sees "this catch clause cannot catch what this call
     throws". The second defect above had no API-level component at all.
  2. This runs with no Android SDK, no Gradle, no JDK -- so it is already in
     the local Python suite via `tools/run_test_suite.py`. GitHub workflows are
     backup-only refusal sentinels and must not compile Android satellites.
     This gate costs milliseconds and catches the exact class twice measured
     this week.

NON-VACUITY IS THE POINT. Four verification artifacts in this project were found
passing-while-broken on 2026-08-08 alone. So `test_the_gate_has_teeth` feeds the
analyzer the pre-fix form of BOTH real defects and fails if either is accepted,
and `test_the_gate_accepts_the_real_fixes` feeds it the shipped form of both and
fails if either is rejected. A gate that cannot fail is not a gate.
"""

from __future__ import annotations

import pathlib
import re
import unittest
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Every Android Kotlin source tree in the repository. `android/devicecheck` is
# included deliberately: it copies the shipping host sources in byte-for-byte,
# so the same defect can reach it, and it has no test task of its own.
SCAN_ROOTS = (
    ("android/app/src/main", 26),
    ("android/devicecheck/app/src/main", 24),
    ("wear_os/app/src/main", 30),
)

# An operation whose documented failure mode is an `Error` rather than an
# `Exception`, and the catch clauses that genuinely cover it.
#
# `Throwable` covers everything. `LinkageError` is the common supertype of both
# concrete errors below. The specific type is the preferred fix -- see
# `VpnTunnelService.ensureAwgNativeLoaded`, which catches `UnsatisfiedLinkError`
# alone and rethrows `IOException`, rather than widening to `Throwable` and
# swallowing `OutOfMemoryError` into a teardown path that then allocates.
_THROWABLE = frozenset({"Throwable", "java.lang.Throwable", "kotlin.Throwable"})
_LINKAGE = frozenset({"Error", "LinkageError", "java.lang.Error", "java.lang.LinkageError"})


@dataclass(frozen=True)
class RiskyOperation:
    """A call whose failure mode is an `Error`."""

    # Matched against comment- and string-stripped source, so a doc comment that
    # merely *mentions* `System.loadLibrary` -- and this repository's comments
    # mention it constantly -- can never be mistaken for a call.
    pattern: str
    raises: str
    covered_by: frozenset[str]
    why: str
    unavailable_below_api: int | None = None


RISKY_OPERATIONS = (
    RiskyOperation(
        pattern=r"\bSystem\s*\.\s*load(?:Library)?\s*\(",
        raises="UnsatisfiedLinkError",
        covered_by=_THROWABLE | _LINKAGE | {"UnsatisfiedLinkError", "java.lang.UnsatisfiedLinkError"},
        why=(
            "System.loadLibrary raises UnsatisfiedLinkError when the .so is absent "
            "for this device's ABI. UnsatisfiedLinkError is an Error, so a "
            "catch (Exception) handler does not run and the thread dies with the "
            "cleanup that handler was written to do left undone."
        ),
    ),
    RiskyOperation(
        # `java.nio.file` did not exist on Android before API 26. Below that the
        # class is simply absent from the runtime, so touching it raises
        # NoClassDefFoundError at the point of first use -- not an Exception.
        pattern=r"\bjava\s*\.\s*nio\s*\.\s*file\s*\.",
        raises="NoClassDefFoundError",
        covered_by=_THROWABLE
        | _LINKAGE
        | {"NoClassDefFoundError", "ExceptionInInitializerError", "java.lang.NoClassDefFoundError"},
        why=(
            "java.nio.file is absent from the Android runtime below API 26, so the "
            "first touch raises NoClassDefFoundError. That is an Error; a "
            "catch (Exception) fallback beside it never runs, and every device "
            "below the gate crashes on the line that looks protected."
        ),
        unavailable_below_api=26,
    ),
    RiskyOperation(
        # Same shape, same API level, different package. Not yet used in this
        # tree; listed so the first use is born covered rather than discovered.
        pattern=r"\bjava\s*\.\s*time\s*\.",
        raises="NoClassDefFoundError",
        covered_by=_THROWABLE
        | _LINKAGE
        | {"NoClassDefFoundError", "ExceptionInInitializerError", "java.lang.NoClassDefFoundError"},
        why=(
            "java.time is absent from the Android runtime below API 26 (without "
            "desugaring), so the first touch raises NoClassDefFoundError, which a "
            "catch (Exception) handler cannot catch."
        ),
        unavailable_below_api=26,
    ),
)


# --------------------------------------------------------------------------
# Kotlin lexing: enough to know what is code and what is not.
# --------------------------------------------------------------------------


def strip_comments_and_strings(source: str) -> str:
    """Blank out comments and string literals, preserving every byte offset.

    Offsets are preserved (blanked, not deleted) so a finding can be reported at
    its true line number in the real file.

    This is not a nicety in this repository. The sources carry very long
    explanatory comments that quote `catch (e: Exception)` and
    `System.loadLibrary` verbatim -- `VpnTunnelService.ensureAwgNativeLoaded`'s
    own doc comment contains both. A gate that scanned raw text would report the
    prose describing the fix as the defect it fixed.
    """
    out = list(source)
    i = 0
    n = len(source)

    def blank(start: int, end: int) -> None:
        for k in range(start, min(end, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if ch == "/" and nxt == "/":
            end = source.find("\n", i)
            end = n if end == -1 else end
            blank(i, end)
            i = end
            continue

        if ch == "/" and nxt == "*":
            # Kotlin block comments nest.
            depth = 1
            j = i + 2
            while j < n and depth:
                if source[j] == "/" and j + 1 < n and source[j + 1] == "*":
                    depth += 1
                    j += 2
                elif source[j] == "*" and j + 1 < n and source[j + 1] == "/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
            continue

        if source.startswith('"""', i):
            end = source.find('"""', i + 3)
            end = n if end == -1 else end + 3
            blank(i, end)
            i = end
            continue

        if ch in ('"', "'"):
            j = i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == ch or source[j] == "\n":
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
            continue

        i += 1

    return "".join(out)


def _match_block(code: str, open_at: int) -> int:
    """Return the offset one past the `}` closing the `{` at `open_at`."""
    depth = 0
    for i in range(open_at, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    raise ValueError(f"unterminated block opened at offset {open_at}")


_CATCH_TYPE = re.compile(r"catch\s*\(\s*[A-Za-z_][\w]*\s*:\s*([\w.]+)")


@dataclass(frozen=True)
class TryBlock:
    body_start: int
    body_end: int
    caught: frozenset[str]


def find_try_blocks(code: str) -> list[TryBlock]:
    """Every `try { ... } catch (x: T) ...` in comment-stripped Kotlin `code`."""
    blocks: list[TryBlock] = []
    for match in re.finditer(r"\btry\b\s*\{", code):
        open_at = code.index("{", match.start())
        try:
            body_end = _match_block(code, open_at)
        except ValueError:
            continue

        # Walk the chain of `catch`/`finally` clauses that follow the body.
        caught: set[str] = set()
        cursor = body_end
        while True:
            tail = code[cursor : cursor + 400]
            clause = re.match(r"\s*catch\s*\(", tail)
            if not clause:
                break
            type_match = _CATCH_TYPE.match(tail.strip())
            if type_match:
                caught.add(type_match.group(1))
            clause_brace = code.find("{", cursor)
            if clause_brace == -1:
                break
            try:
                cursor = _match_block(code, clause_brace)
            except ValueError:
                break
        blocks.append(TryBlock(open_at, body_end, frozenset(caught)))
    return blocks


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    operation: RiskyOperation
    caught: tuple[str, ...]

    def __str__(self) -> str:
        seen = ", ".join(sorted(self.caught)) if self.caught else "(no enclosing catch)"
        return (
            f"{self.path}:{self.line}: {self.operation.raises} is not caught here.\n"
            f"    enclosing catch clauses: {seen}\n"
            f"    {self.operation.why}\n"
            f"    Fix: catch {self.operation.raises} explicitly (preferred, see "
            f"VpnTunnelService.ensureAwgNativeLoaded) or catch Throwable."
        )


def analyze(source: str, path: str = "<memory>", min_sdk: int = 24) -> list[Finding]:
    """Every risky operation in `source` not covered by a handler that runs."""
    code = strip_comments_and_strings(source)
    blocks = find_try_blocks(code)
    findings: list[Finding] = []

    for operation in RISKY_OPERATIONS:
        if (
            operation.unavailable_below_api is not None
            and min_sdk >= operation.unavailable_below_api
        ):
            continue
        for hit in re.finditer(operation.pattern, code):
            at = hit.start()
            enclosing = [b for b in blocks if b.body_start <= at < b.body_end]
            caught: set[str] = set()
            for block in enclosing:
                caught |= block.caught
            # Covered when ANY enclosing handler can actually catch it. An
            # operation with no enclosing try at all is reported too: these
            # calls propagate an Error out of whatever thread they run on, and
            # in `VpnTunnelService` that thread was a bare `Thread {}` with no
            # uncaught handler -- which is precisely how the defect shipped.
            if caught & operation.covered_by:
                continue
            findings.append(
                Finding(
                    path=path,
                    line=source.count("\n", 0, at) + 1,
                    operation=operation,
                    caught=tuple(sorted(caught)),
                )
            )
    return findings


def scan_repository() -> list[Finding]:
    findings: list[Finding] = []
    for root, min_sdk in SCAN_ROOTS:
        base = ROOT / root
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.kt")):
            # `.bak_*` snapshots are backups of edited files, not sources.
            if ".bak_" in path.name or "/build/" in path.as_posix():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            findings.extend(
                analyze(
                    text,
                    path.relative_to(ROOT).as_posix(),
                    min_sdk=min_sdk,
                )
            )
    return findings


# --------------------------------------------------------------------------
# The gate.
# --------------------------------------------------------------------------

# SHRINK-ONLY RATCHET. Every entry is a real occurrence of the defect shape that
# predates this gate, reviewed and consciously accepted with the reason below.
# Adding an entry is a code review conversation; removing one needs no approval.
# A file:line that stops being a finding must be deleted from this list -- the
# gate fails on a stale entry, so the ratchet cannot silently rot into a
# blanket exemption.
ACCEPTED: dict[str, str] = {}


class AndroidErrorShapeGate(unittest.TestCase):
    """`Error` must not be left to a handler written for `Exception`."""

    # ---- non-vacuity: the gate must reject both real defects --------------

    def test_the_gate_has_teeth(self) -> None:
        """The pre-fix form of both 2026-08-08 defects must be rejected."""
        # VpnTunnelService, as it stood before the fix: loadLibrary inside a run
        # loop that catches Exception.
        pre_fix_load_library = """
            private fun startAwgEngineThread() {
                Thread {
                    try {
                        System.loadLibrary("am-go")
                        runEngine()
                    } catch (e: Exception) {
                        clearRestartConfig()
                    }
                }.start()
            }
        """
        findings = analyze(pre_fix_load_library)
        self.assertEqual(
            1,
            len(findings),
            "the pre-fix loadLibrary defect must be reported; got: "
            + "\n".join(str(f) for f in findings),
        )
        self.assertEqual("UnsatisfiedLinkError", findings[0].operation.raises)
        self.assertEqual(("Exception",), findings[0].caught)

        # WinnCarrierProfile, as it stood before the fix: java.nio.file under
        # minSdk 24 with an Exception fallback that never runs.
        pre_fix_nio = """
            private fun isOwnerOnly(file: File): Boolean {
                return try {
                    val p = java.nio.file.Files.getPosixFilePermissions(file.toPath())
                    p.isEmpty()
                } catch (_: Exception) {
                    true
                }
            }
        """
        findings = analyze(pre_fix_nio)
        self.assertEqual(1, len(findings), "the pre-fix java.nio.file defect must be reported")
        self.assertEqual("NoClassDefFoundError", findings[0].operation.raises)

    def test_an_unhandled_risky_call_is_reported(self) -> None:
        """No enclosing try at all is still a finding, not a free pass."""
        self.assertEqual(1, len(analyze('fun f() { System.loadLibrary("am-go") }')))

    # ---- non-vacuity: the gate must accept both real fixes ----------------

    def test_the_gate_accepts_the_real_fixes(self) -> None:
        """The shipped form of both fixes must pass, or the gate is noise."""
        shipped_load_library = """
            private fun ensureAwgNativeLoaded() {
                try {
                    System.loadLibrary("am-go")
                } catch (e: UnsatisfiedLinkError) {
                    throw IOException("not present for this ABI", e)
                }
            }
        """
        self.assertEqual([], analyze(shipped_load_library))

        shipped_nio = """
            private fun nioPosixModeOrNull(file: File): Int? {
                return try {
                    java.nio.file.Files.getPosixFilePermissions(file.toPath()).size
                } catch (_: Throwable) {
                    null
                }
            }
        """
        self.assertEqual([], analyze(shipped_nio))

    def test_an_outer_handler_counts(self) -> None:
        """Coverage by an enclosing (not immediately adjacent) catch is real."""
        nested = """
            fun f() {
                try {
                    try {
                        System.loadLibrary("am-go")
                    } catch (e: IllegalStateException) {
                    }
                } catch (t: Throwable) {
                }
            }
        """
        self.assertEqual([], analyze(nested))

    # ---- non-vacuity: prose must never be mistaken for code --------------

    def test_comments_and_strings_are_not_code(self) -> None:
        """This repository's comments quote both defects verbatim."""
        prose = '''
            /**
             * `System.loadLibrary` does not throw an `Exception` -- it throws
             * `UnsatisfiedLinkError`. Both loops are wrapped in
             * `catch (e: Exception)`, so the `Error` walked straight past.
             */
            fun describe(): String = "System.loadLibrary raises UnsatisfiedLinkError"
        '''
        self.assertEqual([], analyze(prose), "a comment mentioning the defect is not the defect")

    def test_the_stripper_preserves_line_numbers(self) -> None:
        source = 'fun a() {}\n// comment\n/* block\n   block */\nSystem.loadLibrary("x")\n'
        stripped = strip_comments_and_strings(source)
        self.assertEqual(len(source), len(stripped))
        self.assertEqual(source.count("\n"), stripped.count("\n"))
        self.assertIn("System.loadLibrary", stripped)

    # ---- the real tree ----------------------------------------------------

    def test_the_ratchet_has_no_stale_entries(self) -> None:
        live = {f"{f.path}:{f.line}" for f in scan_repository()}
        stale = sorted(set(ACCEPTED) - live)
        self.assertEqual(
            [],
            stale,
            "ACCEPTED entries that are no longer findings -- delete them, or the "
            "ratchet decays into a blanket exemption: " + ", ".join(stale),
        )

    def test_no_error_is_handled_as_an_exception(self) -> None:
        findings = [f for f in scan_repository() if f"{f.path}:{f.line}" not in ACCEPTED]
        self.assertEqual(
            [],
            findings,
            "\n\n" + "\n\n".join(str(f) for f in findings) + "\n",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
