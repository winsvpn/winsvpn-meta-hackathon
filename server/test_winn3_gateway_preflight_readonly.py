#!/usr/bin/env python3
"""--preflight on wins_winn3_gateway_install.sh must not mutate the host.

The 2026-08-12 defect: report_firewall() executed
`iptables -I WINVPN-INPUT ...` when WINN3_GATEWAY_MANAGE_FIREWALL=1, and
main()'s --preflight branch called report_firewall. Usage text said
"Change nothing".

This suite is the regression net:

* A call-graph walk from every command --preflight actually runs. A future
  mutating call added to any reachable function must fail this file.
* A mocked-iptables harness: report_firewall with MANAGE_FIREWALL=1 must
  not invoke `iptables -I`; apply_listen_firewall must place the rules through
  the installed boot helper's --listen-only mode (which puts them behind the
  WINVPN-INPUT guard jumps), never with its own position-1 `iptables -I`
  (OI-G3.3).
* Scanner teeth, in memory, never against the shared tree: a live `-I` in
  a preflight-reachable function must fail this file, including
  `/sbin/iptables -I`, `/usr/sbin/iptables -I`, and `ipt_gw -I`. The same
  text in a comment or a warn string is not a hit; a comment-only edit of
  the live source still passes.
* Three controls against the live installer: no-mutation (pass), comment-only
  (pass), deliberate insert / apply-call / chmod / modprobe (must go red
  naming the break).
* Filesystem mutators (chmod/chown/mkdir/modprobe/touch/tee/rm) as well as
  iptables -I: a "helpful" inspect that chmod's a key or modprobes tun is
  the same class of defect as the original insert.

Run: python3 server/test_winn3_gateway_preflight_readonly.py
"""

from __future__ import annotations

import _toolchain  # noqa: F401  (V-01 preflight)
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from winn3_gateway_test_support import gateway_source


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = Path(
    os.environ.get(
        "WINN3_GATEWAY_INSTALLER",
        str(ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh"),
    )
)
INSTALLER = gateway_source(INSTALLER, legacy=True)
SCRATCH = Path(tempfile.gettempdir()) / "deploy_preflight_readonly"

# Functions that exist to change host state. None of these may be reachable
# from the --preflight execution path.
MUTATING_FUNCTION_NAMES = frozenset(
    {
        "apply_listen_firewall",
        "apply_forwarding_firewall",
        "ensure_ip_forward",
        "ensure_udp_socket_buffers",
        "ensure_jump_gw",
        "teardown_forwarding_firewall",
        "ensure_service_user",
        "install_binary",
        "write_env_file",
        "write_unit",
        "enable_service",
        "start_service",
        "install_gateway_maintenance",
        "install_gateway_maintenance_packages",
        "write_fail2ban_sshd_jail",
        "write_gateway_recovery_contract",
        "write_gateway_backup_env",
        "write_gateway_backup_script",
        "write_gateway_backup_timer",
        "write_gateway_weekly_maintenance",
        "run_initial_gateway_backup",
        "restore_unattended_upgrades",
        "wait_for_fail2ban",
        # --install's certificate mode change and its held-descriptor
        # helper; --preflight reaches only report_credential_cert_modes.
        "normalize_credential_cert_modes",
        "fchmod_credential_cert_held_fd",
        # Design v17 S2: the shared firewall lock creates its lock file, the
        # locked writers and the INPUT jump placement change the live rules,
        # the helper is rendered and activated through systemd, and the
        # backup host identity may be minted and pinned.
        "wins_fw_lock",
        "wins_fw_unlock",
        "place_winn3gw_input_jump",
        "apply_forwarding_firewall_locked",
        "teardown_forwarding_firewall_locked",
        "winn3gw_render_helper",
        "winn3gw_activate",
        "resolve_node_backup_host_id",
        # Implementation review T1 (Sol-S2-T1-2): writes a tmpfiles.d entry
        # and creates /run/xtables.lock.
        "prepare_wins_xtables_lock",
    }
)

# `/` is load-bearing: `/sbin/iptables -I` must count. Without it, rewriting
# the original defect with an absolute path would survive this suite.
_CMD_START = r"(?:^|[\s;|&`(/])"
IPTABLES_INVOKE = re.compile(
    _CMD_START + r"((?:ip6?tables|ipt_gw|ipt6_gw)\b.*)$", re.MULTILINE
)
MUTATING_IPTABLES_FLAG = re.compile(
    r"(?:^|\s)(-[IADNXEPRFZ]\b|--(?:append|delete|insert|replace|"
    r"new-chain|delete-chain|rename-chain|flush|policy|zero)\b)"
)
SYSCTL_WRITE = re.compile(
    _CMD_START + r"sysctl\s+(?:(?:-w|--write)\b|[A-Za-z0-9._]+=)",
    re.MULTILINE,
)
SYSTEMCTL_MUTATE = re.compile(
    _CMD_START + r"systemctl\s+"
    r"(?:enable|disable|start|stop|restart|mask|unmask|daemon-reload)\b",
    re.MULTILINE,
)
INSTALL_CMD = re.compile(_CMD_START + r"install\s+", re.MULTILINE)
GROUPADD_CMD = re.compile(_CMD_START + r"groupadd\b", re.MULTILINE)
USERADD_CMD = re.compile(_CMD_START + r"useradd\b", re.MULTILINE)
RESTORE_CMD = re.compile(_CMD_START + r"ip6?tables-restore\b", re.MULTILINE)
NFT_MUTATE = re.compile(
    _CMD_START + r"nft\s+(?:add|insert|delete|flush|create|replace)\b",
    re.MULTILINE,
)
IP_MUTATE = re.compile(
    _CMD_START + r"ip(?:\s+-[46])*(?:\s+-o)?\s+"
    r"(?:link|addr|address|route|rule|tuntap|tunnel|netns)\s+"
    r"(?:add|del|delete|change|replace|set|flush)\b",
    re.MULTILINE,
)
# Helpful-inspection mutators. The original defect was iptables -I inside
# report_firewall; the same shape with chmod 600 on a key, or modprobe tun
# inside preflight_forwarding, would also make --preflight lie.
CHMOD_CMD = re.compile(_CMD_START + r"chmod\s+", re.MULTILINE)
CHOWN_CMD = re.compile(_CMD_START + r"chown\s+", re.MULTILINE)
MKDIR_CMD = re.compile(_CMD_START + r"mkdir\s+", re.MULTILINE)
MODPROBE_CMD = re.compile(_CMD_START + r"modprobe\s+", re.MULTILINE)
TOUCH_CMD = re.compile(_CMD_START + r"touch\s+", re.MULTILINE)
TEE_CMD = re.compile(_CMD_START + r"tee\s+", re.MULTILINE)
RM_CMD = re.compile(_CMD_START + r"rm\s+", re.MULTILINE)

# Exact shape of the 2026-08-12 defect, taken from
# wins_winn3_gateway_install.sh.bak_20260812_v3_gateway_unit_fix
# (report_firewall). Embedded so this file does not depend on a sibling
# lane's backup remaining on disk.
HISTORICAL_DEFECT_REPORT_FIREWALL = """
report_firewall() {
  local port="${WINN3_GATEWAY_LISTEN##*:}"
  local policy
  policy="$( { iptables -S INPUT 2>/dev/null || true; } | awk '/^-P INPUT/ {print $3}' || true)"
  if iptables -L WINVPN-INPUT -n >/dev/null 2>&1; then
    if iptables -C WINVPN-INPUT -p udp --dport "${port}" -j ACCEPT >/dev/null 2>&1; then
      log "  UDP ${port} is already accepted."
    else
      warn "    iptables -I WINVPN-INPUT -p udp --dport ${port} -j ACCEPT"
      if [[ "${WINN3_GATEWAY_MANAGE_FIREWALL}" == "1" ]]; then
        log "  WINN3_GATEWAY_MANAGE_FIREWALL=1: inserting it."
        iptables -I WINVPN-INPUT -p udp --dport "${port}" -j ACCEPT
      else
        warn "  Not applied. Set WINN3_GATEWAY_MANAGE_FIREWALL=1 to apply, or add it by hand."
      fi
    fi
  fi
}
"""


def fold_line_continuations(text: str) -> str:
    """Join `cmd \\<newline> -I ...` so a split iptables insert is still a hit."""
    return re.sub(r"\\\n[ \t]*", " ", text)


def strip_shell_noise(text: str) -> str:
    """Drop heredocs, comments and quoted strings so remaining tokens are commands.

    A warn/log line that *documents* `iptables -I` must not count as executing
    it. The live insert is an unquoted command and survives this strip.
    Heredocs are stripped because usage() mentions function names that are
    not calls.
    """
    text = fold_line_continuations(text)
    text = re.sub(
        r"""<<[-]?[ \t]*(['\"]?)(\w+)\1[^\n]*\n.*?\n\2\n""",
        "\n",
        text,
        flags=re.DOTALL,
    )
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "'":
            i += 1
            while i < n and text[i] != "'":
                i += 1
            if i < n:
                i += 1
            out.append(" ")
            continue
        if ch == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                i += 1
            if i < n:
                i += 1
            out.append(" ")
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def function_definition(source: str, signature: str) -> str:
    """Return `name() { ... }` with braces balanced, including nested blocks."""
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


def parse_functions(source: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for match in re.finditer(
        r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{", source, re.MULTILINE
    ):
        name = match.group(1)
        found[name] = function_definition(source, match.group(0))
    return found


def extract_if_fi(source: str, start: int) -> str:
    """Return the `if ... fi` compound starting at source[start].

    Only line-leading `if`/`fi` count. A word-boundary search counted the
    word "if" inside `log "... if needed ..."` and a comment "if it applies"
    in main(), so LiveInstallerTests.setUpClass raised unbalanced if/fi on
    both the live installer and this lane's pre-edit backup (16 if / 14 fi).
    `elif` is not `if`.
    """
    depth = 0
    for match in re.finditer(r"(?m)^[ \t]*(if|fi)\b", source[start:]):
        if match.group(1) == "if":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return source[start : start + match.end()]
    raise AssertionError("unbalanced if/fi")


def strip_non_preflight_mode_branches(main_src: str) -> str:
    """Remove every `if [[ "${WINN3_GATEWAY_MODE}" == "<not preflight>" ]]` compound."""
    pattern = 'if [[ "${WINN3_GATEWAY_MODE}" == "'
    result = main_src
    while True:
        pos = 0
        removed = False
        while True:
            found_at = result.find(pattern, pos)
            if found_at < 0:
                break
            rest = result[found_at + len(pattern) :]
            mode = rest.split('"', 1)[0]
            block = extract_if_fi(result, found_at)
            if mode != "preflight":
                result = result[:found_at] + result[found_at + len(block) :]
                removed = True
                break
            pos = found_at + len(block)
        if not removed:
            break
    return result


def preflight_executed_text(source: str) -> str:
    """Text main() runs for --preflight: unconditionals + the preflight branch.

    Other WINN3_GATEWAY_MODE== branches are stripped so a teardown/apply/install call is not
    blamed on preflight. An unconditional call added before the preflight
    `if` still remains, which is the point.
    """
    main = function_definition(source, "main() {")
    stripped = strip_non_preflight_mode_branches(main)
    marker = 'if [[ "${WINN3_GATEWAY_MODE}" == "preflight" ]]; then'
    start = stripped.index(marker)
    block = extract_if_fi(stripped, start)
    return stripped[:start] + block


def calls_in(text: str, known: dict[str, str]) -> set[str]:
    stripped = strip_shell_noise(text)
    found: set[str] = set()
    for name in known:
        if re.search(
            r"(?:^|[\s;|&`$(){}])" + re.escape(name) + r"(?:\s|$|[;|&)])",
            stripped,
            re.MULTILINE,
        ):
            found.add(name)
    return found


def reachable_from_preflight(source: str) -> set[str]:
    funcs = parse_functions(source)
    executed = preflight_executed_text(source)
    stack = list(calls_in(executed, funcs))
    seen: set[str] = set()
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        body = funcs.get(name)
        if body is None:
            continue
        for callee in calls_in(body, funcs):
            if callee not in seen:
                stack.append(callee)
    return seen


def mutating_command_hits(text: str) -> list[str]:
    stripped = strip_shell_noise(text)
    hits: list[str] = []
    for match in IPTABLES_INVOKE.finditer(stripped):
        args = match.group(1)
        flag = MUTATING_IPTABLES_FLAG.search(args)
        if flag:
            hits.append(f"iptables-mutate {flag.group(1)} in: {args.strip()[:120]}")
    for rx, label in (
        (SYSCTL_WRITE, "sysctl-write"),
        (SYSTEMCTL_MUTATE, "systemctl-mutate"),
        (INSTALL_CMD, "install-cmd"),
        (GROUPADD_CMD, "groupadd"),
        (USERADD_CMD, "useradd"),
        (RESTORE_CMD, "iptables-restore"),
        (NFT_MUTATE, "nft-mutate"),
        (IP_MUTATE, "ip-mutate"),
        (CHMOD_CMD, "chmod"),
        (CHOWN_CMD, "chown"),
        (MKDIR_CMD, "mkdir"),
        (MODPROBE_CMD, "modprobe"),
        (TOUCH_CMD, "touch"),
        (TEE_CMD, "tee"),
        (RM_CMD, "rm"),
    ):
        for match in rx.finditer(stripped):
            snippet = match.group(0).strip()[:120]
            hits.append(f"{label}: {snippet}")
    return hits


def preflight_mutation_problems(source: str) -> list[str]:
    """Every mutating command on the --preflight call graph, named by function."""
    funcs = parse_functions(source)
    reachable = reachable_from_preflight(source)
    problems: list[str] = []
    executed = preflight_executed_text(source)
    for hit in mutating_command_hits(executed):
        problems.append(f"main-preflight-path: {hit}")
    for name in sorted(reachable):
        body = funcs[name]
        for hit in mutating_command_hits(body):
            problems.append(f"{name}: {hit}")
    overlap = reachable & MUTATING_FUNCTION_NAMES
    for name in sorted(overlap):
        problems.append(f"mutating-function-reachable: {name}")
    return problems


def _scratch_dir() -> Path:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    return SCRATCH


def run_mocked_firewall(func_body: str, func_name: str) -> subprocess.CompletedProcess[str]:
    """Run one extracted function against a fake iptables that logs argv.

    The fake reports: INPUT policy DROP, WINVPN-INPUT exists, the ACCEPT rule
    is missing until `-I` or the fake boot helper's --listen-only run is seen,
    then `-C` succeeds. TRACE is a file under this lane's scratch dir, never
    /tmp.
    """
    scratch = _scratch_dir()
    with tempfile.TemporaryDirectory(
        prefix="preflight-fw-", dir=str(scratch)
    ) as tmp:
        trace = Path(tmp) / "iptables.trace"
        script = Path(tmp) / "harness.sh"
        helper = Path(tmp) / "winn3-gateway-firewall"
        # The fake boot helper carries the literal apply_listen_firewall
        # probes for, and records that it ran in the same trace.
        helper.write_text(
            "#!/usr/bin/env bash\n"
            "case \"${1:-}\" in\n"
            "  --listen-only) listen_only=1 ;;\n"
            "esac\n"
            f"printf 'HELPER %s\\n' \"$*\" >> {trace.as_posix()!r}\n"
            f": > {(Path(tmp) / 'placed').as_posix()!r}\n",
            encoding="utf-8",
        )
        helper.chmod(0o700)
        script.write_text(
            f"""set -euo pipefail
TRACE={trace.as_posix()!r}
: > "$TRACE"
INSERTED=0
WINN3_GATEWAY_LISTEN=0.0.0.0:51833
WINN3_GATEWAY_MANAGE_FIREWALL=1
WINN3_GATEWAY_FIREWALL_HELPER={helper.as_posix()!r}
PLACED={(Path(tmp) / 'placed').as_posix()!r}
iptables() {{
  printf 'IPTABLES %s\\n' "$*" >> "$TRACE"
  case "$1" in
    -S) printf '%s\\n' "-P INPUT DROP"; return 0 ;;
    -L) return 0 ;;
    -C)
      if [[ "$INSERTED" == "1" || -e "$PLACED" ]]; then return 0; fi
      return 1
      ;;
    -I)
      INSERTED=1
      printf 'INSERT %s\\n' "$*" >> "$TRACE"
      return 0
      ;;
    *) return 0 ;;
  esac
}}
winn3gw_log() {{ :; }}
winn3gw_warn() {{ :; }}
winn3gw_err() {{ printf '%s\\n' "$*" >&2; }}
{func_body}
{func_name}
printf 'TRACE_BEGIN\\n'
cat "$TRACE"
printf 'TRACE_END\\n'
""",
            encoding="utf-8",
        )
        return subprocess.run(
            ["bash", str(script)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


class ExtractIfFiTests(unittest.TestCase):
    """The WINN3_GATEWAY_MODE-branch stripper must not treat English 'if' as bash `if`."""

    def test_log_line_containing_if_needed_does_not_unbalance(self) -> None:
        src = (
            'if [[ "${WINN3_GATEWAY_MODE}" == "apply-listen-firewall" ]]; then\n'
            '  log "--- apply-listen-firewall: inserting the UDP listen-port ACCEPT rule if needed ---"\n'
            "  return 0\n"
            "fi\n"
            'if [[ "${WINN3_GATEWAY_MODE}" == "preflight" ]]; then\n'
            "  preflight_udp_socket_buffers\n"
            "fi\n"
        )
        block = extract_if_fi(src, 0)
        self.assertTrue(
            block.startswith('if [[ "${WINN3_GATEWAY_MODE}" == "apply-listen-firewall" ]]'),
            block,
        )
        self.assertTrue(block.rstrip().endswith("fi"), block)
        self.assertNotIn("preflight_udp_socket_buffers", block)

    def test_comment_containing_if_it_applies_does_not_unbalance(self) -> None:
        src = (
            'if [[ "${WINN3_GATEWAY_MODE}" == "preflight" ]]; then\n'
            "  # contains the resolver line and the /24 warning if it applies\n"
            "  preflight_udp_socket_buffers\n"
            "fi\n"
        )
        block = extract_if_fi(src, 0)
        self.assertIn("preflight_udp_socket_buffers", block)
        self.assertTrue(block.rstrip().endswith("fi"), block)

    def test_nested_if_fi_still_extracts_the_outer(self) -> None:
        src = (
            'if [[ "${WINN3_GATEWAY_MODE}" == "preflight" ]]; then\n'
            '  if [[ -s "$x" ]]; then\n'
            "    verify_staged_binary\n"
            "  fi\n"
            "  preflight_udp_socket_buffers\n"
            "fi\n"
            "ensure_udp_socket_buffers\n"
        )
        block = extract_if_fi(src, 0)
        self.assertIn("preflight_udp_socket_buffers", block)
        self.assertNotIn("ensure_udp_socket_buffers", block)

    def test_word_boundary_matcher_is_what_this_fix_would_catch(self) -> None:
        src = (
            'if [[ "${WINN3_GATEWAY_MODE}" == "apply-listen-firewall" ]]; then\n'
            '  log "rule if needed"\n'
            "fi\n"
        )
        depth = 0
        ended = False
        for match in re.finditer(r"\b(if|fi)\b", src):
            if match.group(1) == "if":
                depth += 1
            else:
                depth -= 1
                if depth == 0:
                    ended = True
                    break
        self.assertFalse(
            ended,
            "word-boundary matcher must go red on 'if needed' so the "
            "line-leading matcher is not a zero-clause",
        )
        block = extract_if_fi(src, 0)
        self.assertTrue(block.rstrip().endswith("fi"), block)


class ScannerTeethTests(unittest.TestCase):
    """Prove the scanner can go red. Fixtures are strings, not the live file."""

    def test_unquoted_iptables_insert_is_a_hit(self) -> None:
        body = 'report_firewall() {\n  iptables -I WINVPN-INPUT -p udp --dport 9 -j ACCEPT\n}\n'
        hits = mutating_command_hits(body)
        self.assertTrue(hits, "scanner missed a live iptables -I")
        self.assertTrue(any("iptables-mutate -I" in h for h in hits), hits)

    def test_comment_iptables_insert_is_not_a_hit(self) -> None:
        body = 'report_firewall() {\n  # iptables -I WINVPN-INPUT -p udp --dport 9 -j ACCEPT\n}\n'
        self.assertEqual(mutating_command_hits(body), [])

    def test_quoted_iptables_insert_is_not_a_hit(self) -> None:
        body = (
            'report_firewall() {\n'
            '  warn "    iptables -I WINVPN-INPUT -p udp --dport ${port} -j ACCEPT"\n'
            "}\n"
        )
        self.assertEqual(mutating_command_hits(body), [])

    def test_backslash_continued_insert_is_a_hit(self) -> None:
        body = (
            "report_firewall() {\n"
            "  iptables \\\n"
            "    -I WINVPN-INPUT -p udp --dport 9 -j ACCEPT\n"
            "}\n"
        )
        hits = mutating_command_hits(body)
        self.assertTrue(
            any("iptables-mutate -I" in h for h in hits),
            f"scanner missed a line-continued iptables -I: {hits}",
        )

    def test_sbin_iptables_insert_is_a_hit(self) -> None:
        """Absolute path was a scanner hole: `/sbin/iptables -I` is still an insert."""
        body = (
            "report_firewall() {\n"
            "  /sbin/iptables -I WINVPN-INPUT -p udp --dport 9 -j ACCEPT\n"
            "}\n"
        )
        hits = mutating_command_hits(body)
        self.assertTrue(
            any("iptables-mutate -I" in h for h in hits),
            f"scanner missed /sbin/iptables -I: {hits}",
        )

    def test_usr_sbin_iptables_insert_is_a_hit(self) -> None:
        body = (
            "report_firewall() {\n"
            "  /usr/sbin/iptables -I WINVPN-INPUT -p udp --dport 9 -j ACCEPT\n"
            "}\n"
        )
        hits = mutating_command_hits(body)
        self.assertTrue(
            any("iptables-mutate -I" in h for h in hits),
            f"scanner missed /usr/sbin/iptables -I: {hits}",
        )

    def test_sbin_iptables_list_is_not_a_hit(self) -> None:
        body = "report_firewall() {\n  /sbin/iptables -S INPUT\n}\n"
        self.assertEqual(mutating_command_hits(body), [])

    def test_ipt_gw_insert_is_a_hit(self) -> None:
        body = (
            "report_firewall() {\n"
            "  ipt_gw -I WINVPN-INPUT -p udp --dport 9 -j ACCEPT\n"
            "}\n"
        )
        hits = mutating_command_hits(body)
        self.assertTrue(
            any("iptables-mutate -I" in h for h in hits),
            f"scanner missed ipt_gw -I: {hits}",
        )

    def test_ipt6_gw_insert_is_a_hit(self) -> None:
        # OI-5 added ipt6_gw (ip6tables -w 10) beside ipt_gw; a writer through
        # it must count exactly as one through ipt_gw does.
        body = (
            "report_firewall() {\n"
            "  ipt6_gw -I INPUT 1 -i winn3gw0 -j DROP\n"
            "}\n"
        )
        hits = mutating_command_hits(body)
        self.assertTrue(
            any("iptables-mutate -I" in h for h in hits),
            f"scanner missed ipt6_gw -I: {hits}",
        )

    def test_sbin_chmod_is_a_hit(self) -> None:
        body = "inspect_credentials() {\n  /bin/chmod 600 /etc/winn/static.key\n}\n"
        hits = mutating_command_hits(body)
        self.assertTrue(any("chmod" in h for h in hits), hits)

    def test_sysctl_n_is_not_a_write(self) -> None:
        body = 'preflight_forwarding() {\n  ipf="$(sysctl -n net.ipv4.ip_forward)"\n}\n'
        self.assertEqual(mutating_command_hits(body), [])

    def test_sysctl_w_is_a_write(self) -> None:
        body = 'ensure_ip_forward() {\n  sysctl -w net.ipv4.ip_forward=1 >/dev/null\n}\n'
        hits = mutating_command_hits(body)
        self.assertTrue(any("sysctl-write" in h for h in hits), hits)

    def test_sysctl_assign_without_dash_w_is_a_write(self) -> None:
        body = 'ensure_ip_forward() {\n  sysctl net.ipv4.ip_forward=1\n}\n'
        hits = mutating_command_hits(body)
        self.assertTrue(any("sysctl-write" in h for h in hits), hits)

    def test_ip_link_show_is_not_a_write(self) -> None:
        body = 'preflight_forwarding() {\n  ip link show winn3gw0\n}\n'
        self.assertEqual(mutating_command_hits(body), [])

    def test_ip_link_add_is_a_write(self) -> None:
        body = 'preflight_forwarding() {\n  ip link add winn3gw0 type tun\n}\n'
        hits = mutating_command_hits(body)
        self.assertTrue(any("ip-mutate" in h for h in hits), hits)

    def test_iptables_wait_flag_is_not_a_write(self) -> None:
        body = 'ipt_gw() { iptables -w 10 "$@"; }\n'
        self.assertEqual(mutating_command_hits(body), [])

    def test_unquoted_chmod_is_a_hit(self) -> None:
        body = 'inspect_credentials() {\n  chmod 600 /etc/winn/static.key\n}\n'
        hits = mutating_command_hits(body)
        self.assertTrue(any("chmod" in h for h in hits), hits)

    def test_comment_chmod_is_not_a_hit(self) -> None:
        body = 'inspect_credentials() {\n  # chmod 600 /etc/winn/static.key\n}\n'
        self.assertEqual(mutating_command_hits(body), [])

    def test_quoted_chmod_is_not_a_hit(self) -> None:
        body = (
            'inspect_credentials() {\n'
            '  warn "chmod 600 ${WINN3_GATEWAY_STATIC_KEY_PATH}"\n'
            "}\n"
        )
        self.assertEqual(mutating_command_hits(body), [])

    def test_unquoted_modprobe_is_a_hit(self) -> None:
        body = 'preflight_forwarding() {\n  modprobe tun\n}\n'
        hits = mutating_command_hits(body)
        self.assertTrue(any("modprobe" in h for h in hits), hits)

    def test_quoted_modprobe_is_not_a_hit(self) -> None:
        body = (
            'preflight_forwarding() {\n'
            '  err "modprobe tun if the module is missing"\n'
            "}\n"
        )
        self.assertEqual(mutating_command_hits(body), [])

    def test_unquoted_rm_is_a_hit(self) -> None:
        body = 'ensure_ip_forward() {\n  rm -f /tmp/x\n}\n'
        hits = mutating_command_hits(body)
        self.assertTrue(any("rm" in h for h in hits), hits)

    def test_historical_defect_body_is_a_hit(self) -> None:
        hits = mutating_command_hits(HISTORICAL_DEFECT_REPORT_FIREWALL)
        self.assertTrue(
            any("iptables-mutate -I" in h for h in hits),
            f"scanner missed the historical insert: {hits}",
        )
        # The quoted documentation line must not be the only hit.
        unquoted = [
            h for h in hits if "iptables-mutate -I" in h and "warn" not in h
        ]
        self.assertTrue(unquoted, hits)


class LiveInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INSTALLER.read_text(encoding="utf-8")
        cls.funcs = parse_functions(cls.source)
        cls.reachable = reachable_from_preflight(cls.source)

    def test_installer_is_where_this_suite_says(self) -> None:
        self.assertTrue(INSTALLER.is_file(), INSTALLER)
        self.assertIn("report_firewall() {", self.source)
        self.assertIn("apply_listen_firewall() {", self.source)

    def test_usage_and_header_still_claim_preflight_changes_nothing(self) -> None:
        # The retained CLI header belongs to G. Function bodies above are DP.
        # Since slice S6 the real G is a tombstone, so the header is read from
        # the frozen copy of the pre-tombstone G.
        legacy = (ROOT / "server" / "testdata" / "winn3_gateway_install_retired"
                  / "wins_winn3_gateway_install.sh.snapshot").read_text(encoding="utf-8")
        header = "\n".join(legacy.splitlines()[:8])
        self.assertIn("--preflight", header)
        self.assertIn("changes nothing", header)
        usage = function_definition(self.source, "usage() {")
        self.assertIn("Change nothing", usage)
        self.assertIn("Never inserts a firewall rule", usage)
        self.assertIn("--apply-listen-firewall", usage)

    def test_preflight_reachable_set_includes_inspection_not_apply(self) -> None:
        for name in (
            "require_root",
            "refuse_on_hub",
            "require_supported_production_os",
            "validate_config",
            "verify_staged_binary",
            "report_firewall",
            "preflight_forwarding",
            "preflight_resolver",
            "preflight_udp_socket_buffers",
            "inspect_credentials",
            "assert_forward_cidr_disjoint",
            "announce_non_forwarding_gateway",
            "preflight_maintenance",
            "data_plane_weekly_present",
        ):
            self.assertIn(name, self.reachable, f"missing seed {name}: {sorted(self.reachable)}")
        # admission_fingerprint is called as
        #   fp="$(admission_fingerprint "${WINN3_GATEWAY_ADMISSION_KEY_PATH}")"
        # strip_shell_noise eats the double-quoted command substitution, so
        # the walker cannot see it. Pin the call in inspect_credentials
        # instead of requiring it in reachable.
        self.assertIn(
            "admission_fingerprint",
            self.funcs["inspect_credentials"],
            "inspect_credentials lost the admission_fingerprint call",
        )
        self.assertNotIn("apply_listen_firewall", self.reachable)
        self.assertNotIn("ensure_ip_forward", self.reachable)
        self.assertNotIn("ensure_udp_socket_buffers", self.reachable)
        self.assertNotIn("apply_forwarding_firewall", self.reachable)
        overlap = self.reachable & MUTATING_FUNCTION_NAMES
        self.assertEqual(overlap, set(), f"mutating function reachable from preflight: {overlap}")

    def test_no_mutating_command_in_any_preflight_reachable_body(self) -> None:
        problems = preflight_mutation_problems(self.source)
        self.assertEqual(problems, [], "preflight path mutates:\n" + "\n".join(problems))

    def test_apply_listen_firewall_places_through_the_boot_helper(self) -> None:
        # OI-G3.3: a bare `iptables -I WINVPN-INPUT` lands at position 1,
        # above both guard jumps. The one placement lives in the boot helper.
        body = self.funcs["apply_listen_firewall"]
        hits = mutating_command_hits(body)
        self.assertFalse(
            any("iptables-mutate -I" in h for h in hits),
            f"apply_listen_firewall inserts on its own again; hits={hits}",
        )
        self.assertIn('"${helper}" --listen-only', body)

    def test_report_firewall_has_no_insert(self) -> None:
        body = self.funcs["report_firewall"]
        self.assertEqual(mutating_command_hits(body), [])
        # Mentions in warn/log strings are documentation, not a branch.
        # The original defect was an unquoted `if [[ "${WINN3_GATEWAY_MANAGE_FIREWALL}" == "1" ]]`.
        stripped = strip_shell_noise(body)
        self.assertNotIn("WINN3_GATEWAY_MANAGE_FIREWALL", stripped)

    def test_install_path_calls_apply_when_env_is_one(self) -> None:
        main = self.funcs["main"]
        self.assertIn("apply_listen_firewall", main)
        self.assertIn('WINN3_GATEWAY_MODE=apply-listen-firewall', main)
        self.assertIn('WINN3_GATEWAY_MANAGE_FIREWALL', main)
        apply_mode = extract_if_fi(
            main, main.index('if [[ "${WINN3_GATEWAY_MODE}" == "apply-listen-firewall" ]]; then')
        )
        self.assertIn("apply_listen_firewall", apply_mode)
        preflight = extract_if_fi(
            main, main.index('if [[ "${WINN3_GATEWAY_MODE}" == "preflight" ]]; then')
        )
        self.assertNotIn("apply_listen_firewall", preflight)

    def test_comment_only_edit_of_live_source_still_passes(self) -> None:
        needle = "report_firewall() {"
        self.assertEqual(self.source.count(needle), 1)
        neutral = self.source.replace(
            needle,
            needle + "\n  # comment-only control: iptables -I must not count\n",
            1,
        )
        self.assertEqual(preflight_mutation_problems(neutral), [])

    def test_injected_insert_in_report_firewall_is_caught(self) -> None:
        needle = "report_firewall() {"
        self.assertEqual(self.source.count(needle), 1)
        mutated = self.source.replace(
            needle,
            needle + "\n  iptables -I WINVPN-INPUT -p udp --dport 1 -j ACCEPT\n",
            1,
        )
        problems = preflight_mutation_problems(mutated)
        self.assertTrue(
            any("iptables-mutate -I" in p for p in problems),
            f"full-source walk missed injected -I: {problems}",
        )
        self.assertTrue(
            any(p.startswith("report_firewall:") for p in problems),
            problems,
        )

    def test_injected_apply_call_in_preflight_branch_is_caught(self) -> None:
        needle = "    inspect_credentials || creds_ok=1\n    report_firewall\n"
        self.assertEqual(self.source.count(needle), 1)
        mutated = self.source.replace(
            needle,
            needle + "    apply_listen_firewall\n",
            1,
        )
        problems = preflight_mutation_problems(mutated)
        self.assertTrue(
            any("mutating-function-reachable: apply_listen_firewall" in p for p in problems),
            f"call-graph missed apply_listen_firewall added to the preflight branch: {problems}",
        )

    def test_injected_ensure_jump_gw_in_preflight_branch_is_caught(self) -> None:
        needle = "    inspect_credentials || creds_ok=1\n    report_firewall\n"
        self.assertEqual(self.source.count(needle), 1)
        mutated = self.source.replace(
            needle,
            needle + "    ensure_jump_gw filter FORWARD WINN3GW-FORWARD\n",
            1,
        )
        problems = preflight_mutation_problems(mutated)
        self.assertTrue(
            any("mutating-function-reachable: ensure_jump_gw" in p for p in problems),
            f"call-graph missed ensure_jump_gw added to the preflight branch: {problems}",
        )

    def test_injected_sbin_insert_in_report_firewall_is_caught(self) -> None:
        needle = "report_firewall() {"
        self.assertEqual(self.source.count(needle), 1)
        mutated = self.source.replace(
            needle,
            needle + "\n  /sbin/iptables -I WINVPN-INPUT -p udp --dport 1 -j ACCEPT\n",
            1,
        )
        problems = preflight_mutation_problems(mutated)
        self.assertTrue(
            any("iptables-mutate -I" in p for p in problems),
            f"full-source walk missed injected /sbin/iptables -I: {problems}",
        )
        self.assertTrue(
            any(p.startswith("report_firewall:") for p in problems),
            problems,
        )

    def test_injected_ipt_gw_insert_in_report_firewall_is_caught(self) -> None:
        needle = "report_firewall() {"
        self.assertEqual(self.source.count(needle), 1)
        mutated = self.source.replace(
            needle,
            needle + "\n  ipt_gw -I WINVPN-INPUT -p udp --dport 1 -j ACCEPT\n",
            1,
        )
        problems = preflight_mutation_problems(mutated)
        self.assertTrue(
            any("iptables-mutate -I" in p for p in problems),
            f"full-source walk missed injected ipt_gw -I: {problems}",
        )

    def test_injected_ipt6_gw_insert_in_report_firewall_is_caught(self) -> None:
        needle = "report_firewall() {"
        self.assertEqual(self.source.count(needle), 1)
        mutated = self.source.replace(
            needle,
            needle + "\n  ipt6_gw -I INPUT 1 -i winn3gw0 -j DROP\n",
            1,
        )
        problems = preflight_mutation_problems(mutated)
        self.assertTrue(
            any("iptables-mutate -I" in p for p in problems),
            f"full-source walk missed injected ipt6_gw -I: {problems}",
        )

    def test_historical_defect_grafted_onto_live_source_is_caught(self) -> None:
        """Put the original insert back inside live report_firewall; walk must go red."""
        live = self.funcs["report_firewall"]
        graft = (
            '      if [[ "${WINN3_GATEWAY_MANAGE_FIREWALL}" == "1" ]]; then\n'
            '        iptables -I WINVPN-INPUT -p udp --dport "${port}" -j ACCEPT\n'
            "      fi\n"
        )
        # Insert the historical branch just after the function opens, so the
        # graft cannot miss if warn-text around the live inspect path moves.
        mutated_fn = live.replace("report_firewall() {", "report_firewall() {\n" + graft, 1)
        mutated = self.source.replace(live, mutated_fn, 1)
        problems = preflight_mutation_problems(mutated)
        self.assertTrue(
            any("iptables-mutate -I" in p for p in problems),
            f"historical graft survived: {problems}",
        )

    def test_live_preflight_forwarding_mentions_modprobe_only_in_err_text(self) -> None:
        """Live source documents `modprobe tun` in an err string. That must not
        count as executing it. If quote-stripping breaks, this goes red."""
        body = self.funcs["preflight_forwarding"]
        self.assertIn("modprobe tun", body)
        self.assertEqual(mutating_command_hits(body), [])

    def test_ensure_ip_forward_writes_and_is_not_reachable(self) -> None:
        """Positive control: the scanner sees writes in a mutating function
        the walk must not reach. A green here plus a green on the preflight
        walk is not the same as a scanner that never fires."""
        body = self.funcs["ensure_ip_forward"]
        hits = mutating_command_hits(body)
        self.assertTrue(any("sysctl-write" in h for h in hits), hits)
        self.assertTrue(any("install-cmd" in h for h in hits), hits)
        # rm moved into _upsert_forward_sysctl_conf when conntrack persist
        # was factored out; the persist path must still be a write.
        helper = self.funcs["_upsert_forward_sysctl_conf"]
        helper_hits = mutating_command_hits(helper)
        self.assertTrue(any("rm" in h for h in helper_hits), helper_hits)
        self.assertNotIn("ensure_ip_forward", self.reachable)

    def test_ensure_udp_socket_buffers_writes_and_is_not_reachable(self) -> None:
        """Positive control for the UDP-buffer sysctl raise: writes exist,
        and --preflight must not reach them. preflight_udp_socket_buffers
        is the inspect half and must stay a non-write."""
        body = self.funcs["ensure_udp_socket_buffers"]
        hits = mutating_command_hits(body)
        self.assertTrue(any("sysctl-write" in h for h in hits), hits)
        self.assertTrue(any("install-cmd" in h for h in hits), hits)
        self.assertTrue(any("rm" in h for h in hits), hits)
        self.assertNotIn("ensure_udp_socket_buffers", self.reachable)
        pf = self.funcs["preflight_udp_socket_buffers"]
        self.assertEqual(mutating_command_hits(pf), [])
        self.assertIn("preflight_udp_socket_buffers", self.reachable)

    def test_injected_chmod_in_inspect_credentials_is_caught(self) -> None:
        needle = "inspect_credentials() {"
        self.assertEqual(self.source.count(needle), 1)
        mutated = self.source.replace(
            needle,
            needle + "\n  chmod 600 /etc/winn/static.key\n",
            1,
        )
        problems = preflight_mutation_problems(mutated)
        self.assertTrue(
            any("chmod" in p for p in problems),
            f"walk missed injected chmod: {problems}",
        )
        self.assertTrue(
            any(p.startswith("inspect_credentials:") for p in problems),
            problems,
        )

    def test_comment_chmod_in_inspect_credentials_still_passes(self) -> None:
        needle = "inspect_credentials() {"
        self.assertEqual(self.source.count(needle), 1)
        neutral = self.source.replace(
            needle,
            needle + "\n  # chmod 600 must not count\n",
            1,
        )
        self.assertEqual(preflight_mutation_problems(neutral), [])

    def test_injected_modprobe_in_preflight_forwarding_is_caught(self) -> None:
        needle = "preflight_forwarding() {"
        self.assertEqual(self.source.count(needle), 1)
        mutated = self.source.replace(
            needle,
            needle + "\n  modprobe tun\n",
            1,
        )
        problems = preflight_mutation_problems(mutated)
        self.assertTrue(
            any("modprobe" in p for p in problems),
            f"walk missed injected modprobe: {problems}",
        )
        self.assertTrue(
            any(p.startswith("preflight_forwarding:") for p in problems),
            problems,
        )


class MockedIptablesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INSTALLER.read_text(encoding="utf-8")

    def _trace(self, proc: subprocess.CompletedProcess[str]) -> str:
        self.assertIn("TRACE_BEGIN", proc.stdout, proc.stdout + proc.stderr)
        _, rest = proc.stdout.split("TRACE_BEGIN\n", 1)
        trace, _ = rest.split("TRACE_END\n", 1)
        return trace

    def test_report_firewall_does_not_insert_even_when_manage_is_one(self) -> None:
        body = function_definition(self.source, "report_firewall() {")
        proc = run_mocked_firewall(body, "report_firewall")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        trace = self._trace(proc)
        self.assertNotIn("INSERT", trace, trace)
        self.assertNotIn("IPTABLES -I", trace)
        self.assertIn("IPTABLES -S", trace)
        self.assertIn("IPTABLES -L", trace)
        self.assertIn("IPTABLES -C", trace)

    def test_apply_listen_firewall_does_place(self) -> None:
        body = function_definition(self.source, "apply_listen_firewall() {")
        proc = run_mocked_firewall(body, "apply_listen_firewall")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        trace = self._trace(proc)
        self.assertIn("HELPER --listen-only", trace, trace)
        self.assertNotIn("IPTABLES -I", trace, trace)
        self.assertIn("IPTABLES -C WINVPN-INPUT -p udp --dport 51833 -j ACCEPT", trace)
        self.assertIn("IPTABLES -C WINVPN-INPUT -p tcp --dport 51833 -j ACCEPT", trace)


if __name__ == "__main__":
    os.chdir(ROOT)
    raise SystemExit(unittest.main(verbosity=2))
