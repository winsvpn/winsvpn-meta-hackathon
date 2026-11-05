#!/usr/bin/env python3
"""Regression contract: firewall-transaction cleanup must not use `trap ... RETURN`.

Both `write_iptables()` (server/wins_control_plane_setup_ONETOUCH.sh) and
`apply_firewall()` (inside the wins-edge-hardening heredoc in
server/wins_data_plane_setup_ONETOUCH.sh) build their atomic iptables-restore
transaction in a handful of `local` temp-file variables, and used to register
a `trap cleanup_*_firewall_transaction RETURN` to remove those temp files
whenever the function returned.

A bash RETURN trap does fire correctly when the function that set it
returns. The bug is what happens *after* that: the trap stays globally armed
afterward (it is not automatically cleared), so its closure over that
function's now-out-of-scope `local` variables goes stale. It only fires
*again* if some later, *enclosing* function itself returns without having
re-armed or cleared the trap first -- plain sibling calls at the same level
do not retrigger it (verified empirically; see the tests below for both
shapes).

This matters for real, not just in the abstract:

  - Control-plane `main()` calls `write_iptables` three times and then keeps
    going for dozens more setup steps before falling off its own end with no
    explicit `exit`. That ordinary, final return from `main()` is itself a
    function return, so the stale trap (armed by the third write_iptables
    call) fires there too, against locals that no longer exist -- an
    unbound-variable crash under `set -u` (both scripts run under
    `set -Eeuo pipefail`), right after every real deployment step already
    succeeded. Confirmed by reproducing this exact
    main()-calls-write_iptables-then-keeps-going shape on real bash 5.2.21.
  - Data-plane `apply_firewall` is currently only ever called once, at the
    generated wins-edge-hardening script's true top level (not wrapped in an
    enclosing function), so it does not hit this today -- also confirmed
    empirically. It is fixed anyway, to match the established
    explicit-cleanup convention already used by
    `cleanup_core_firewall_transaction_workspace` in
    server/wins_core_server_setup_ONETOUCH.sh, and so it stays safe if
    apply_firewall is ever called more than once or from inside a helper.

The fix removes the trap and instead calls the cleanup function explicitly on
every exit path (every early `return` plus the final fallthrough).
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CONTROL_PLANE_PATH = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
DATA_PLANE_PATH = ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh"
CONTROL_PLANE_SOURCE = CONTROL_PLANE_PATH.read_text(encoding="utf-8")
DATA_PLANE_SOURCE = DATA_PLANE_PATH.read_text(encoding="utf-8")


def function_definition(source: str, signature: str) -> str:
    """Return `name() { ... }` verbatim, balancing braces so the whole
    function body (including nested `{ ... }` blocks) is captured."""
    start = source.index(signature)
    depth = 0
    brace_idx = source.index("{", start)
    for idx in range(brace_idx, len(source)):
        char = source[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : idx + 1]
    raise AssertionError(f"unbalanced braces while extracting {signature}")


def run_bash(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", script],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )


def cleanup_call_sites(body: str, cleanup_name: str) -> int:
    """Count calls to `cleanup_name`, excluding its own `name() {`
    definition line and every comment line. A comment that names the cleanup
    function (Round SU's firewall-lock note in apply_firewall does) is not an
    exit path, so it must not change the count."""
    code = "\n".join(
        line for line in body.splitlines() if not line.lstrip().startswith("#")
    )
    total_mentions = len(re.findall(re.escape(cleanup_name), code))
    definition_lines = len(re.findall(rf"{re.escape(cleanup_name)}\(\)\s*\{{", code))
    return total_mentions - definition_lines


class FirewallTransactionCleanupScopingTests(unittest.TestCase):
    def test_write_iptables_does_not_register_a_return_trap(self) -> None:
        body = function_definition(CONTROL_PLANE_SOURCE, "write_iptables() {")
        self.assertNotRegex(
            body,
            r"trap\s+cleanup_hub_firewall_transaction\s+RETURN",
            "write_iptables must not leak a RETURN trap across function boundaries",
        )
        self.assertIn("cleanup_hub_firewall_transaction() {", body)

    def test_apply_firewall_does_not_register_a_return_trap(self) -> None:
        body = function_definition(DATA_PLANE_SOURCE, "apply_firewall() {")
        self.assertNotRegex(
            body,
            r"trap\s+cleanup_edge_firewall_transaction\s+RETURN",
            "apply_firewall must not leak a RETURN trap across function boundaries",
        )
        self.assertIn("cleanup_edge_firewall_transaction() {", body)

    def test_write_iptables_cleans_up_on_every_exit_path(self) -> None:
        body = function_definition(CONTROL_PLANE_SOURCE, "write_iptables() {")
        # Only returns *after* the temp files (and cleanup_*) exist need
        # guarding; the two early-validation `return 1`s before that point
        # (bad SURICATA_NFQUEUE_FAIL_OPEN / missing Cloudflare allowlist)
        # have nothing to clean up yet.
        after_cleanup_def = body[body.index("cleanup_hub_firewall_transaction() {") :]
        # write_iptables defines two of its own nested helper functions
        # (hub_restore_rule, and a same-named `iptables` shell function
        # override); their internal `return 1`s exit *those* helpers, not
        # write_iptables itself, so they must not require a cleanup call.
        for nested_signature in ("hub_restore_rule() {", "iptables() {"):
            nested_body = function_definition(after_cleanup_def, nested_signature)
            after_cleanup_def = after_cleanup_def.replace(nested_body, "", 1)
        return_count = len(re.findall(r"^\s*return 1\s*$", after_cleanup_def, flags=re.MULTILINE))
        call_sites = cleanup_call_sites(body, "cleanup_hub_firewall_transaction")
        # One explicit call per early `return 1` plus one for the success
        # fallthrough (its exact position in the body doesn't matter, only
        # that every exit path -- early or normal -- passes through one).
        self.assertEqual(call_sites, return_count + 1, body)

    def test_apply_firewall_cleans_up_on_every_exit_path(self) -> None:
        body = function_definition(DATA_PLANE_SOURCE, "apply_firewall() {")
        # Same reasoning: the SURICATA_NFQUEUE_FAIL_OPEN/PUBLIC_VPN_INGRESS_ADMISSION
        # validation and the Suricata-health `return 1`s all happen before the
        # temp files exist.
        after_cleanup_def = body[body.index("cleanup_edge_firewall_transaction() {") :]
        return_count = len(re.findall(r"^\s*return 1\s*$", after_cleanup_def, flags=re.MULTILINE))
        call_sites = cleanup_call_sites(body, "cleanup_edge_firewall_transaction")
        self.assertEqual(call_sites, return_count + 1, body)

    def test_call_site_count_ignores_comments_but_not_calls(self) -> None:
        # Anti-vacuity for the comment exclusion: a comment mention adds
        # nothing, while a call (bare, or inside `|| { ...; }`) still counts.
        body = (
            "f() {\n"
            "  cleanup_x() {\n"
            "    :\n"
            "  }\n"
            "  # cleanup_x releases the lock on every exit path.\n"
            "    #cleanup_x\n"
            "  step || { cleanup_x; return 1; }\n"
            "  cleanup_x\n"
            "}\n"
        )
        self.assertEqual(cleanup_call_sites(body, "cleanup_x"), 2)
        self.assertEqual(cleanup_call_sites(body.replace("  cleanup_x\n}", "}"), "cleanup_x"), 1)

    def test_control_plane_main_calls_write_iptables_three_times(self) -> None:
        self.assertEqual(
            len(re.findall(r"\n\s*write_iptables\s*\n", CONTROL_PLANE_SOURCE)),
            3,
            "expected main() to call write_iptables exactly 3 times (pins the "
            "real-world shape the crash-repro test below mirrors)",
        )

    def test_main_is_a_function_invoked_at_top_level_in_control_plane(self) -> None:
        self.assertRegex(CONTROL_PLANE_SOURCE, r"\nmain\(\)\s*\{")
        self.assertRegex(CONTROL_PLANE_SOURCE, r'\nmain "\$@"\s*\n?\Z')

    def test_leaked_return_trap_crashes_when_the_enclosing_main_later_returns(
        self,
    ) -> None:
        """Prove the real, verified mechanism: the trap fires correctly for
        its own function, stays armed, and only re-fires -- crashing on
        stale locals -- when an *enclosing* function (main-shaped, calling
        the trap-setter and then continuing on to do other work) eventually
        returns. This is the actual pre-fix shape of
        server/wins_control_plane_setup_ONETOUCH.sh's main()."""
        script = r"""
set -Eeuo pipefail
buggy_write_iptables_like() {
  local transaction="txn-local-value"
  cleanup() { printf 'cleanup fired, transaction=%s\n' "${transaction}"; }
  trap cleanup RETURN
  printf 'buggy_write_iptables_like ran\n'
}
other_step() { printf 'other_step ran\n'; }
main() {
  buggy_write_iptables_like
  other_step
  other_step
  printf 'main about to fall off its own end\n'
}
main
printf 'UNREACHABLE_IF_MAIN_DID_NOT_CRASH\n'
"""
        result = run_bash(script)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("UNREACHABLE_IF_MAIN_DID_NOT_CRASH", result.stdout)
        self.assertIn("main about to fall off its own end", result.stdout)
        self.assertIn("unbound variable", result.stdout)

    def test_explicit_cleanup_pattern_survives_the_enclosing_main_returning(
        self,
    ) -> None:
        """The fixed pattern (no trap, explicit calls on every exit path)
        applied to the same main()-wraps-the-function shape must NOT crash,
        proving the fix mechanism itself is sound."""
        script = r"""
set -Eeuo pipefail
fixed_write_iptables_like() {
  local transaction="txn-local-value"
  cleanup() { printf 'cleanup fired, transaction=%s\n' "${transaction}"; }
  printf 'fixed_write_iptables_like ran\n'
  cleanup
}
other_step() { printf 'other_step ran\n'; }
main() {
  fixed_write_iptables_like
  other_step
  other_step
  printf 'main about to fall off its own end\n'
}
main
printf 'REACHED_END\n'
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("REACHED_END", result.stdout)

    def test_data_plane_heredoc_calls_apply_firewall_followed_by_log(self) -> None:
        self.assertRegex(
            DATA_PLANE_SOURCE,
            r"\n\s*apply_firewall\n\s*log ",
            "expected apply_firewall to be followed by a log call in the generated script",
        )

    def test_apply_firewall_is_not_wrapped_in_an_enclosing_function_today(self) -> None:
        """Documents *why* the data-plane case doesn't crash today (no
        enclosing function to leak into) so this stops being true the moment
        someone wraps the generated script's top-level calls in a helper --
        matching this test to that change is the intended signal."""
        heredoc_start = DATA_PLANE_SOURCE.index("cat > /usr/local/bin/wins-edge-hardening")
        heredoc_end = DATA_PLANE_SOURCE.index("\nWINS_EDGE_EOF", heredoc_start)
        heredoc_body = DATA_PLANE_SOURCE[heredoc_start:heredoc_end]
        call_site = heredoc_body.index("\napply_firewall\n")
        # Nothing between the last top-level function definition's closing
        # brace and the apply_firewall call site should be a `{` that would
        # indicate apply_firewall is invoked from inside another function
        # rather than at this script's true top level.
        preceding = heredoc_body[:call_site]
        last_line = preceding.rstrip().rsplit("\n", 1)[-1]
        self.assertEqual(
            last_line.strip(),
            "wins_preflight_ssh_path_survives",
            "expected apply_firewall to be called directly at top level, "
            "immediately after wins_preflight_ssh_path_survives",
        )


if __name__ == "__main__":
    unittest.main()
