#!/usr/bin/env python3
"""A-DEP-004: SSH password authentication is never global on the core.

CORE_SSH_PASSWORD_AUTH=1 used to flip PasswordAuthentication (and
KbdInteractiveAuthentication) to yes for the WHOLE sshd, exposing a password
prompt on port 22 to every address on the internet behind fail2ban alone.
This file pins the scoped posture:

  * the drop-in's global section is always PasswordAuthentication no /
    KbdInteractiveAuthentication no;
  * password login, when requested, exists only inside a
    `Match Address <cidr> User <admin>` block, appended after the global
    section so the scope is enforced by sshd itself, not by the firewall;
  * asking for passwords without a CIDR is a deploy error, never a fallback
    to a broader scope;
  * the root user is refused the password scope outright.

The harden_sshd function is executed for real (sourced, with the
system-touching commands stubbed), so what these tests assert on is the
actual drop-in text the fleet would install -- not a copy of it.

Run: python3 server/test_wins_core_sshd_password_scope.py
"""

from __future__ import annotations

import _toolchain  # noqa: F401  (V-01 preflight)

# V-01: the core script sources associative arrays (Bash 4+).
_BASH = _toolchain.bash4()

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(
    os.environ.get(
        "WINS_CORE_SCRIPT",
        str(ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh"),
    )
)


# Runs the real harden_sshd with the system commands stubbed. The fake sshd
# answers -T with the posture a real sshd would compute from the drop-in this
# very function writes: no/no from every address except the operator CIDR
# (192.0.2.10/32), which sees yes/yes. If the drop-in ever regresses to a
# global yes, the fake sshd stays consistent with the regression and the
# CAPTURED-config assertions below catch it.
HARNESS = r'''
set -Eeuo pipefail
source "$1"
CAPTURE="$2"
MODE="$3"

install() {
  if [[ "${1:-}" == "-d" ]]; then return 0; fi
  if [[ "${*: -1}" == *"/20-wins-core.conf" ]]; then
    cp -- "${*: -2:1}" "$CAPTURE"
  fi
  return 0
}
prepare_core_ssh_authorized_keys() { :; }
ssh-keygen() { return 0; }
sshd() {
  case "${1:-}" in
    -t) return 0 ;;
    -T)
      spec="$*"
      addr="${spec##*addr=}"
      if [[ "$addr" == 192.0.2.10 ]]; then
        printf 'passwordauthentication yes\nkbdinteractiveauthentication yes\npermitrootlogin no\nallowtcpforwarding no\n'
      else
        # allowusers reflects the REAL AllowUsers harden_sshd wrote: the admin
        # user plus SUDO_USER when the suite runs under sudo (it does on the
        # Linux CI host, where SUDO_USER is legitimately appended). Emitting
        # the computed variable instead of a hardcoded "myadmin" keeps the
        # effective-config check honest on both invocation shapes.
        printf 'port 22\npermitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\nallowtcpforwarding no\ndisableforwarding yes\nallowusers %s\n' "${allow_users}"
      fi
      ;;
  esac
}
systemctl() { return 0; }
mkdir() { return 0; }
fail2ban-client() { return 0; }

CORE_SSH_ADMIN_USER=myadmin
case "$MODE" in
  scoped)   CORE_SSH_PASSWORD_AUTH=1; CORE_SSH_PASSWORD_AUTH_CIDR=192.0.2.10/32 ;;
  unscoped) CORE_SSH_PASSWORD_AUTH=1; CORE_SSH_PASSWORD_AUTH_CIDR="" ;;
  rootuser) CORE_SSH_PASSWORD_AUTH=1; CORE_SSH_PASSWORD_AUTH_CIDR=192.0.2.10/32; CORE_SSH_ADMIN_USER=root ;;
  badcidr)  CORE_SSH_PASSWORD_AUTH=1; CORE_SSH_PASSWORD_AUTH_CIDR="203.0.113.999/32" ;;
  broad0)   CORE_SSH_PASSWORD_AUTH=1; CORE_SSH_PASSWORD_AUTH_CIDR="0.0.0.0/0" ;;
  broad1)   CORE_SSH_PASSWORD_AUTH=1; CORE_SSH_PASSWORD_AUTH_CIDR="128.0.0.0/1" ;;
  broad8)   CORE_SSH_PASSWORD_AUTH=1; CORE_SSH_PASSWORD_AUTH_CIDR="10.0.0.0/8" ;;
  broad16)  CORE_SSH_PASSWORD_AUTH=1; CORE_SSH_PASSWORD_AUTH_CIDR="192.168.0.0/16" ;;
  bareip)   CORE_SSH_PASSWORD_AUTH=1; CORE_SSH_PASSWORD_AUTH_CIDR="192.0.2.10" ;;
  off)      CORE_SSH_PASSWORD_AUTH=0 ;;
esac

set +e
harden_sshd
rc=$?
set -e
printf 'RC=%s\n' "$rc"
if [[ -f "$CAPTURE" ]]; then
  printf 'CAPTURED\n'
  cat "$CAPTURE"
fi
printf 'DONE\n'
'''


def _run_harden_sshd(mode: str) -> tuple[int, str, str, str | None]:
    with tempfile.TemporaryDirectory() as tmp:
        capture = Path(tmp) / "20-wins-core.conf"
        proc = subprocess.run(
            [
                "bash",
                "-c",
                HARNESS,
                "_",
                str(SCRIPT),
                str(capture),
                mode,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        captured = (
            capture.read_text(encoding="utf-8") if capture.exists() else None
        )
        return proc.returncode, proc.stdout, proc.stderr, captured


class CoreSshPasswordScopeTests(unittest.TestCase):
    def test_script_parses(self) -> None:
        proc = subprocess.run(
            ["bash", "-n", str(SCRIPT)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_password_auth_without_a_cidr_is_a_deploy_error(self) -> None:
        rc, out, err, captured = _run_harden_sshd("unscoped")
        self.assertEqual(out.strip().splitlines()[-1:], ["DONE"], out + err)
        self.assertIn("RC=1", out)
        self.assertIn("requires CORE_SSH_PASSWORD_AUTH_CIDR", err)
        self.assertIn("never enabled globally", err)
        self.assertIsNone(captured, "no drop-in may be written for a refused config")

    def test_the_root_user_is_refused_the_password_scope(self) -> None:
        rc, out, err, captured = _run_harden_sshd("rootuser")
        self.assertIn("RC=1", out, out + err)
        self.assertIn("refuses the root user", err)
        self.assertIsNone(captured)

    def test_a_malformed_cidr_is_refused(self) -> None:
        rc, out, err, captured = _run_harden_sshd("badcidr")
        self.assertIn("RC=1", out, out + err)
        self.assertIn("must be a single host (/32)", err)
        self.assertIsNone(captured)

    def test_broad_prefixes_are_refused(self) -> None:
        """B-03 (audits 2026-08-28, three reports): a /1 opened password
        authentication for half of IPv4 while both sshd -T scope checks
        passed. Every non-/32 prefix is a deploy error now."""
        for mode, cidr in (
            ("broad0", "0.0.0.0/0"),
            ("broad1", "128.0.0.0/1"),
            ("broad8", "10.0.0.0/8"),
            ("broad16", "192.168.0.0/16"),
            ("bareip", "192.0.2.10"),
        ):
            with self.subTest(cidr=cidr):
                rc, out, err, captured = _run_harden_sshd(mode)
                self.assertIn("RC=1", out, out + err)
                self.assertIn("must be a single host (/32)", err)
                self.assertIsNone(captured)

    def test_password_auth_is_scoped_to_a_match_block(self) -> None:
        rc, out, err, captured = _run_harden_sshd("scoped")
        self.assertIn("RC=0", out, out + err)
        self.assertIn("RC=0", out)
        self.assertIsNotNone(captured, "the drop-in was never written")
        assert captured is not None
        # The global section is no/no, unconditionally.
        self.assertIn("PasswordAuthentication no", captured)
        self.assertIn("KbdInteractiveAuthentication no", captured)
        # The scoped exception is a Match block naming BOTH the CIDR and the
        # non-root user.
        self.assertIn("Match Address 192.0.2.10/32 User myadmin", captured)
        # yes appears exactly twice (password + kbd), both AFTER the Match
        # line, never before it.
        match_at = captured.index("Match Address")
        before = captured[:match_at]
        after = captured[match_at:]
        self.assertNotIn("PasswordAuthentication yes", before)
        self.assertNotIn("KbdInteractiveAuthentication yes", before)
        self.assertIn("PasswordAuthentication yes", after)
        self.assertIn("KbdInteractiveAuthentication yes", after)
        self.assertEqual(captured.count("PasswordAuthentication yes"), 1)
        self.assertEqual(captured.count("KbdInteractiveAuthentication yes"), 1)
        # The Match block must come after the global section, so sshd applies
        # it as an exception, not as the default.
        self.assertLess(
            captured.index("PasswordAuthentication no"),
            captured.index("Match Address"),
        )

    def test_password_auth_off_writes_no_match_block(self) -> None:
        rc, out, err, captured = _run_harden_sshd("off")
        self.assertIn("RC=0", out, out + err)
        self.assertIsNotNone(captured)
        assert captured is not None
        self.assertNotIn("Match Address", captured)
        self.assertNotIn("PasswordAuthentication yes", captured)
        self.assertNotIn("KbdInteractiveAuthentication yes", captured)
        self.assertIn("PasswordAuthentication no", captured)
        self.assertIn("KbdInteractiveAuthentication no", captured)

    def test_the_old_global_flip_is_gone_from_the_source(self) -> None:
        """The regression shape: PasswordAuthentication %s interpolation.

        As long as the effective value is interpolated from a variable, some
        caller can make it yes globally. The literal no is the invariant.
        """
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("'PasswordAuthentication %s\\n'", text)
        self.assertNotIn("'KbdInteractiveAuthentication %s\\n'", text)


if __name__ == "__main__":
    unittest.main()
