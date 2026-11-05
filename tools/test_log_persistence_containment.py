#!/usr/bin/env python3
"""Round U OI-U3: journal disk-copy containment, Suricata rotation, AWG log cap.

What is real and what is a fake:

  REAL: the shipped shell functions, extracted verbatim from the role
        installers and executed by bash. Only their absolute /etc/ and /var/
        paths are rewritten into a per-test sandbox directory.

  FAKE: systemctl, systemd-analyze, dpkg-query, systemd-cat, journalctl,
        logrotate, docker and apt are stubs on a PATH that holds nothing else
        but the ordinary file utilities. The systemd-analyze stub merges the
        sandbox's journald drop-ins by FILENAME across directories, the rule
        journald.conf(5) states, so the merge-order defect is reproduced, not
        assumed. Each stub can be told to fail, which is how every "must fail
        the deploy" branch is driven.

Nothing here touches the host's systemd, journal or /var/log. A real-host
check of the same functions is still a deployment postcondition.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "server"
ROLES = (
    "wins_control_plane_setup_ONETOUCH.sh",
    "wins_core_server_setup_ONETOUCH.sh",
    "wins_data_plane_setup_ONETOUCH.sh",
    "wins_cowrie_honeypot_ONETOUCH.sh",
    "wins_honeynet_setup_ONETOUCH.sh",
)
SURICATA_ROLES = ("wins_data_plane_setup_ONETOUCH.sh", "wins_core_server_setup_ONETOUCH.sh")
F11_HELPERS_START = "# --- F-11 step 5a helpers: no second copy of the journal on disk ------------\n"
# Ubuntu 24.04 /etc/logrotate.conf (logrotate 3.21.0-2build1, noble), rebuilt
# from git.launchpad.net/ubuntu/+source/logrotate branch applied/ubuntu/noble:
# examples/logrotate.conf with debian/ubuntu-logrotate.conf inserted after line
# 6 (debian/rules). SHA-256 of that file, computed 2026-09-24.
STOCK_LOGROTATE_SHA256 = "fc0877189d2feacbfca441dfa4ddeffaebbd074635c48fbf1c70672e62954fe9"
FILE_TOOLS = (
    "sed", "tail", "grep", "cat", "chmod", "chown", "mv", "rm", "mkdir", "install", "cmp",
    "date", "basename", "head", "sort", "tr", "env", "sh", "touch", "ls", "cp",
)


def _bash() -> str | None:
    for candidate in (shutil.which("bash"), "/opt/homebrew/bin/bash", "/usr/local/bin/bash", "/bin/bash"):
        if not candidate or not os.path.exists(candidate):
            continue
        out = subprocess.run([candidate, "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True)
        if out.returncode == 0 and out.stdout.strip().isdigit() and int(out.stdout.strip()) >= 4:
            return candidate
    return None


BASH = _bash()


def function_text(source: str, name: str) -> str:
    start = source.index(f"\n{name}() {{\n") + 1
    end = source.index("\n}\n", start) + 3
    return source[start:end]


def f11_helpers(source: str) -> str:
    start = source.index(F11_HELPERS_START)
    end_fn = source.index("\nwins_f11_syslog_rollback() {\n", start)
    end = source.index("\n}\n", end_fn) + 3
    return source[start:end]


STUBS = {
    # State lives in $FAKE/units/<unit>.{active,enabled,load}.
    "systemctl": r'''
u() { printf '%s/units/%s' "$FAKE" "$1"; }
get() { cat "$(u "$1").$2" 2>/dev/null || printf '%s' "$3"; }
put() { printf '%s' "$3" > "$(u "$1").$2"; }
cmd="$1"; shift
quiet=0; value=0; now=0; props=()
args=()
while (($#)); do
  case "$1" in
    --quiet) quiet=1 ;;
    --value) value=1 ;;
    --now) now=1 ;;
    -p) shift; props+=("$1") ;;
    *) args+=("$1") ;;
  esac
  shift
done
printf '%s %s\n' "$cmd" "${args[*]}" >> "$FAKE/systemctl.log"
case "$cmd" in
  show)
    for p in "${props[@]}"; do
      case "$p" in
        LoadState) v="$(get "${args[0]}" load not-found)" ;;
        ActiveState) v="$(get "${args[0]}" active inactive)" ;;
        UnitFileState) v="$(get "${args[0]}" enabled '')" ;;
      esac
      if ((value)); then printf '%s\n' "$v"; else printf '%s=%s\n' "$p" "$v"; fi
    done ;;
  stop)
    [[ -n "${FAIL_STOP:-}" ]] && exit 1
    for a in "${args[@]}"; do [[ "${STUCK_ACTIVE:-}" == "$a" ]] || put "$a" active inactive; done ;;
  start)
    for a in "${args[@]}"; do put "$a" active active; done ;;
  mask)
    [[ -n "${FAIL_MASK:-}" ]] && exit 1
    for a in "${args[@]}"; do [[ -n "${MASK_NOOP:-}" ]] || put "$a" enabled masked; done ;;
  unmask)
    for a in "${args[@]}"; do put "$a" enabled "$(cat "$FAKE/units/$a.enabled.orig" 2>/dev/null || printf enabled)"; done ;;
  enable)
    [[ -n "${FAIL_ENABLE:-}" ]] && exit 1
    for a in "${args[@]}"; do
      put "$a" enabled enabled
      if ((now)) && [[ -z "${TIMER_STAYS_INACTIVE:-}" ]]; then put "$a" active active; fi
    done ;;
  restart)
    [[ -n "${FAIL_RESTART:-}" && "${args[0]}" == systemd-journald ]] && exit 1
    put "${args[0]}" active active ;;
  is-active)
    s="$(get "${args[0]}" active inactive)"
    ((quiet)) || printf '%s\n' "$s"
    [[ "$s" == active ]] ;;
  is-enabled)
    s="$(get "${args[0]}" enabled disabled)"
    printf '%s\n' "$s"
    [[ "$s" == enabled ]] ;;
  *) exit 1 ;;
esac
''',
    "systemd-analyze": r'''
[[ -n "${FAIL_ANALYZE:-}" ]] && exit 1
[[ -n "${ANALYZE_EMPTY:-}" ]] && exit 0
[[ "$1 $2" == "cat-config systemd/journald.conf" ]] || exit 2
printf '# %s/etc/systemd/journald.conf\n[Journal]\n#ForwardToSyslog=yes\n' "$SANDBOX"
for f in $( { ls "$SANDBOX/etc/systemd/journald.conf.d" "$SANDBOX/usr/lib/systemd/journald.conf.d" 2>/dev/null; } | grep '\.conf$' | sort -u ); do
  for d in "$SANDBOX/etc/systemd/journald.conf.d" "$SANDBOX/usr/lib/systemd/journald.conf.d"; do
    if [[ -f "$d/$f" ]]; then printf '\n# %s\n' "$d/$f"; cat "$d/$f"; break; fi
  done
done
''',
    "dpkg-query": r'''
[[ "${RSYSLOG_PKG:-}" == installed && "$*" == *rsyslog* ]] && { printf 'ii '; exit 0; }
exit 1
''',
    "systemd-cat": r'''
line="$(cat)"
[[ -n "${JOURNAL_DROPS:-}" ]] && exit 0
printf '%s\n' "$line" >> "$FAKE/journal"
[[ -n "${LEAK_TO:-}" ]] && printf 'host wins-f11-probe: %s\n' "$line" >> "$SANDBOX$LEAK_TO"
exit 0
''',
    "journalctl": r'''
cat "$FAKE/journal" 2>/dev/null
exit 0
''',
    "sleep": "exit 0\n",
    "logrotate": r'''
[[ "$1" == -d ]] || exit 2
case "$2" in
  */logrotate.d/wins-suricata)
    [[ -n "${FAIL_LR_POLICY:-}" ]] && { echo "error: wins-suricata:3 bad line" >&2; exit 1; }
    echo "rotating pattern: /var/log/suricata/eve.json /var/log/suricata/fast.log after 1 days" >&2 ;;
  */logrotate.conf)
    [[ -f "$2" ]] || { echo "error: cannot stat $2" >&2; exit 1; }
    if [[ -z "${LR_CONF_SILENT:-}" ]] && grep -Eq '^[[:space:]]*include[[:space:]]+' "$2" && [[ -f "$SANDBOX/etc/logrotate.d/wins-suricata" ]]; then
      # Real logrotate echoes the path as the (sandbox-rewritten) policy names it.
      echo "considering log $SANDBOX/var/log/suricata/eve.json" >&2
    fi
    [[ -n "${OTHER_POLICY_ERRORS:-}" ]] && { echo "error: other policy" >&2; exit 1; } ;;
esac
exit 0
''',
    "docker": r'''
[[ "$1" == inspect ]] || exit 2
printf '%s\n' "${DOCKER_LOG_CONFIG:-}"
''',
}


@unittest.skipUnless(BASH, "needs bash 4 or newer (the installers target Ubuntu's bash 5)")
class Sandbox(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="wins-logctl-"))
        self.root = self.tmp / "root"
        self.fake = self.tmp / "fake"
        self.bin = self.tmp / "bin"
        for d in (self.root / "etc/systemd/journald.conf.d", self.root / "usr/lib/systemd/journald.conf.d",
                  self.root / "var/log", self.root / "var/lib", self.root / "etc/logrotate.d",
                  self.fake / "units", self.bin):
            d.mkdir(parents=True, exist_ok=True)
        for tool in FILE_TOOLS:
            path = shutil.which(tool)
            if path:
                (self.bin / tool).symlink_to(path)
        for name, body in STUBS.items():
            p = self.bin / name
            p.write_text(f"#!{BASH}\n" + body, encoding="utf-8")
            p.chmod(0o755)
        self.env = {"PATH": str(self.bin), "FAKE": str(self.fake), "SANDBOX": str(self.root), "HOME": str(self.tmp)}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sandboxed(self, text: str) -> str:
        # One pass, so a sandbox path that itself contains /var/ is not
        # rewritten twice.
        root = str(self.root)
        return re.sub(r"(?<![\w.-])/(etc|var)/", lambda m: f"{root}/{m.group(1)}/", text)

    def unit(self, name: str, load: str, active: str, enabled: str):
        base = self.fake / "units" / name
        Path(f"{base}.load").write_text(load)
        Path(f"{base}.active").write_text(active)
        Path(f"{base}.enabled").write_text(enabled)
        Path(f"{base}.enabled.orig").write_text(enabled)

    def state(self, name: str, what: str) -> str:
        return (self.fake / "units" / f"{name}.{what}").read_text()

    def run_bash(self, script: str, **env) -> subprocess.CompletedProcess:
        full = dict(self.env, **{k: str(v) for k, v in env.items()})
        return subprocess.run([BASH, "-c", script], capture_output=True, text=True, env=full, timeout=60)


class SyslogContainmentTests(Sandbox):
    """contain_syslog_disk_copy, executed from the shipped F-11 block."""

    ROLE = ROLES[0]

    def setUp(self):
        super().setUp()
        source = (SERVER / self.ROLE).read_text(encoding="utf-8")
        if F11_HELPERS_START not in source:
            self.fail(f"{self.ROLE} has no F-11 step 5a helpers (contain_syslog_disk_copy)")
        self.helpers = self.sandboxed(f11_helpers(source))
        # The shipped distro file and the role's own 99- drop-in.
        (self.root / "usr/lib/systemd/journald.conf.d/syslog.conf").write_text("[Journal]\nForwardToSyslog=yes\n")
        (self.root / "etc/systemd/journald.conf.d/99-winsvpn.conf").write_text("[Journal]\nStorage=volatile\nForwardToSyslog=no\n")
        (self.root / "var/log/syslog").write_text("older line\n")
        self.unit("systemd-journald.service", "loaded", "active", "static")

    def rsyslog_installed(self):
        self.unit("rsyslog.service", "loaded", "active", "enabled")
        self.unit("syslog.socket", "loaded", "active", "static")
        self.pkg = "installed"

    def contain(self, **env) -> subprocess.CompletedProcess:
        env.setdefault("RSYSLOG_PKG", getattr(self, "pkg", "absent"))
        script = (
            "set -Eeuo pipefail\n"
            "_f11_log()  { printf '[INFO] %s\\n' \"$*\"; }\n"
            "_f11_warn() { printf '[WARN] %s\\n' \"$*\" >&2; }\n"
            "_f11_err()  { printf '[ERR] %s\\n' \"$*\" >&2; }\n"
            + self.helpers + "\ncontain_syslog_disk_copy volatile\n"
        )
        return self.run_bash(script, **env)

    def assert_refused(self, proc, needle):
        self.assertNotEqual(proc.returncode, 0, f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn(needle, proc.stderr)
        self.assertNotIn("F-11 verified", proc.stdout)

    def test_the_merge_order_defect_is_real_in_the_model(self):
        # Anti-vacuity for every test below: the 99- drop-in alone loses to the
        # rsyslog package's syslog.conf.
        proc = self.run_bash(
            self.helpers + "\n_f11_err() { :; }\n_f11_effective_forward_to_syslog\n")
        self.assertEqual(proc.stdout.strip(), "yes", proc.stderr)

    def test_contains_an_installed_rsyslog_and_verifies_it(self):
        self.rsyslog_installed()
        proc = self.contain()
        self.assertEqual(proc.returncode, 0, f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("F-11 verified: a fresh journal entry was recorded", proc.stdout)
        for unit in ("rsyslog.service", "syslog.socket"):
            self.assertEqual(self.state(unit, "active"), "inactive")
            self.assertEqual(self.state(unit, "enabled"), "masked")
        dropin = self.root / "etc/systemd/journald.conf.d/zz-winsvpn-no-syslog.conf"
        self.assertEqual(dropin.read_text(), "[Journal]\nForwardToSyslog=no\n")
        prior = (self.root / "var/lib/winsvpn/f11-syslog-prior-state").read_text()
        for line in ("rsyslog=present", "zz_dropin=absent", "rsyslog.service.ActiveState=active",
                     "rsyslog.service.UnitFileState=enabled", "syslog.socket.ActiveState=active"):
            self.assertIn(line + "\n", prior)
        self.assertEqual((self.root / "var/lib/winsvpn/f11-syslog-prior-state").stat().st_mode & 0o777, 0o600)

    def test_absent_rsyslog_is_handled_explicitly(self):
        proc = self.contain(RSYSLOG_PKG="absent")
        self.assertEqual(proc.returncode, 0, f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("rsyslog is not installed", proc.stdout)
        self.assertIn("F-11 verified", proc.stdout)
        log = (self.fake / "systemctl.log").read_text()
        self.assertNotIn("stop ", log)
        self.assertIn("rsyslog=absent\n", (self.root / "var/lib/winsvpn/f11-syslog-prior-state").read_text())

    def test_absent_rsyslog_with_another_syslog_daemon_fails(self):
        self.unit("syslog.socket", "loaded", "active", "static")
        self.assert_refused(self.contain(RSYSLOG_PKG="absent"), "an unknown syslog daemon")

    def test_missing_systemd_analyze_fails(self):
        self.rsyslog_installed()
        (self.bin / "systemd-analyze").unlink()
        self.assert_refused(self.contain(), "systemd-analyze is not available")

    def test_failing_systemd_analyze_fails(self):
        self.rsyslog_installed()
        self.assert_refused(self.contain(FAIL_ANALYZE=1), "cat-config systemd/journald.conf failed")

    def test_no_forward_assignment_is_ambiguous_and_fails(self):
        self.rsyslog_installed()
        self.assert_refused(self.contain(ANALYZE_EMPTY=1), "no ForwardToSyslog assignment")

    def test_a_later_drop_in_that_re_enables_forwarding_fails(self):
        self.rsyslog_installed()
        (self.root / "usr/lib/systemd/journald.conf.d/zzz-vendor.conf").write_text("[Journal]\nForwardToSyslog=yes\n")
        self.assert_refused(self.contain(), "effective ForwardToSyslog=yes")

    def test_stop_failure_fails(self):
        self.rsyslog_installed()
        self.assert_refused(self.contain(FAIL_STOP=1), "could not stop rsyslog.service")

    def test_mask_failure_fails(self):
        self.rsyslog_installed()
        self.assert_refused(self.contain(FAIL_MASK=1), "could not mask")

    def test_unit_still_active_after_stop_fails(self):
        self.rsyslog_installed()
        self.assert_refused(self.contain(STUCK_ACTIVE="rsyslog.service"), "rsyslog.service is 'active' after stop")

    def test_unit_not_masked_after_mask_fails(self):
        self.rsyslog_installed()
        self.assert_refused(self.contain(MASK_NOOP=1), "after mask, not 'masked'")

    def test_journald_restart_failure_fails(self):
        self.rsyslog_installed()
        self.assert_refused(self.contain(FAIL_RESTART=1), "systemd-journald did not restart")

    def test_probe_missing_from_the_journal_fails(self):
        self.rsyslog_installed()
        self.assert_refused(self.contain(JOURNAL_DROPS=1), "never appeared in the journal")

    def test_probe_copied_to_disk_fails(self):
        self.rsyslog_installed()
        self.assert_refused(self.contain(LEAK_TO="/var/log/syslog"), "also written to")

    def test_prior_state_survives_a_rerun(self):
        self.rsyslog_installed()
        self.assertEqual(self.contain().returncode, 0)
        first = (self.root / "var/lib/winsvpn/f11-syslog-prior-state").read_text()
        self.assertEqual(self.contain().returncode, 0)
        second = (self.root / "var/lib/winsvpn/f11-syslog-prior-state").read_text()
        self.assertEqual(first, second)
        self.assertIn("rsyslog.service.ActiveState=active\n", second)

    def rollback(self) -> subprocess.CompletedProcess:
        script = (
            "set -Eeuo pipefail\n_f11_log() { printf '%s\\n' \"$*\"; }\n_f11_err() { printf '%s\\n' \"$*\" >&2; }\n"
            + self.helpers + "\nwins_f11_syslog_rollback\n"
        )
        return self.run_bash(script)

    def test_rollback_restores_the_recorded_state(self):
        # Case 1 of Round U Turn 2: the zz drop-in was originally absent, so
        # rollback removes it.
        self.rsyslog_installed()
        self.assertEqual(self.contain().returncode, 0)
        self.assertIn("zz_dropin=absent\n", (self.root / "var/lib/winsvpn/f11-syslog-prior-state").read_text())
        self.assertFalse((self.root / "var/lib/winsvpn/f11-zz-winsvpn-no-syslog.conf.prior").exists())
        proc = self.rollback()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.state("rsyslog.service", "enabled"), "enabled")
        self.assertEqual(self.state("rsyslog.service", "active"), "active")
        self.assertEqual(self.state("syslog.socket", "active"), "active")
        self.assertFalse((self.root / "etc/systemd/journald.conf.d/zz-winsvpn-no-syslog.conf").exists())

    def test_rollback_restores_a_pre_existing_zz_dropin_bytes_and_mode(self):
        # Case 2 of Round U Turn 2: a zz drop-in with other contents and mode
        # existed. Containment overwrites it; rollback restores those bytes
        # and that mode exactly.
        self.rsyslog_installed()
        zz = self.root / "etc/systemd/journald.conf.d/zz-winsvpn-no-syslog.conf"
        original = b"[Journal]\n# operator's own file\nForwardToSyslog=no\nMaxLevelStore=info\n"
        zz.write_bytes(original)
        zz.chmod(0o640)
        self.assertEqual(self.contain().returncode, 0)
        self.assertEqual(zz.read_text(), "[Journal]\nForwardToSyslog=no\n")
        prior_dir = self.root / "var/lib/winsvpn"
        self.assertIn("zz_dropin=present\n", (prior_dir / "f11-syslog-prior-state").read_text())
        copy = prior_dir / "f11-zz-winsvpn-no-syslog.conf.prior"
        self.assertEqual(copy.read_bytes(), original)
        self.assertEqual(copy.stat().st_mode & 0o777, 0o640)
        self.assertEqual(prior_dir.stat().st_mode & 0o777, 0o700)
        # A re-run must not replace the retained original with our own file.
        self.assertEqual(self.contain().returncode, 0)
        self.assertEqual(copy.read_bytes(), original)
        proc = self.rollback()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(zz.read_bytes(), original)
        self.assertEqual(zz.stat().st_mode & 0o777, 0o640)

    def test_rollback_refuses_when_the_retained_copy_is_missing(self):
        self.rsyslog_installed()
        zz = self.root / "etc/systemd/journald.conf.d/zz-winsvpn-no-syslog.conf"
        zz.write_text("[Journal]\nForwardToSyslog=no\n# mine\n")
        self.assertEqual(self.contain().returncode, 0)
        (self.root / "var/lib/winsvpn/f11-zz-winsvpn-no-syslog.conf.prior").unlink()
        proc = self.rollback()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("prior zz drop-in copy", proc.stderr)

    def test_a_symlinked_zz_dropin_is_not_recorded_or_followed(self):
        self.rsyslog_installed()
        target = self.tmp / "elsewhere.conf"
        target.write_text("x\n")
        (self.root / "etc/systemd/journald.conf.d/zz-winsvpn-no-syslog.conf").symlink_to(target)
        self.assert_refused(self.contain(), "could not record the prior syslog state")
        self.assertEqual(target.read_text(), "x\n")


class ContainmentIsWiredIntoEveryRoleTests(unittest.TestCase):
    def test_every_role_calls_containment_and_no_longer_warns_past_a_failed_restart(self):
        for role in ROLES:
            source = (SERVER / role).read_text(encoding="utf-8")
            harden = function_text(source, "harden_crash_artifacts")
            self.assertIn('  contain_syslog_disk_copy "${journal_storage}" || return 1\n', harden, role)
            self.assertNotIn("journal settings apply at next boot", harden, role)
            self.assertLess(harden.index("99-winsvpn.conf <<EOF"), harden.index("contain_syslog_disk_copy"), role)
            self.assertLess(harden.index("contain_syslog_disk_copy"), harden.index("verify_crash_artifacts_suppressed"), role)

    def test_helpers_are_identical_in_every_role(self):
        texts = {r: f11_helpers((SERVER / r).read_text(encoding="utf-8")) for r in ROLES}
        for role, text in texts.items():
            self.assertEqual(text, texts[ROLES[0]], role)


class SuricataRotationTests(Sandbox):
    ROLE = SURICATA_ROLES[0]

    def setUp(self):
        super().setUp()
        source = (SERVER / self.ROLE).read_text(encoding="utf-8")
        if "\nwins_ensure_suricata_rotation() {\n" not in source:
            self.fail(f"{self.ROLE} has no wins_ensure_suricata_rotation")
        self.funcs = self.sandboxed(
            function_text(source, "wins_write_stock_logrotate_conf")
            + function_text(source, "wins_ensure_suricata_rotation"))
        (self.root / "etc/logrotate.d/wins-suricata").write_text("/var/log/suricata/eve.json {\n rotate 3\n}\n")
        self.unit("logrotate.timer", "loaded", "inactive", "disabled")
        # chown to root is not possible unprivileged; the stub records it.
        (self.bin / "chown").unlink(missing_ok=True)
        (self.bin / "chown").write_text(f"#!{BASH}\nexit 0\n")
        (self.bin / "chown").chmod(0o755)

    def ensure(self, preamble: str = "", **env) -> subprocess.CompletedProcess:
        script = (
            "set -Eeuo pipefail\n"
            "log()  { printf '[INFO] %s\\n' \"$*\"; }\n"
            "warn() { printf '[WARN] %s\\n' \"$*\" >&2; }\n"
            "err()  { printf '[ERR] %s\\n' \"$*\" >&2; }\n"
            "APT_GET=(apt-get)\n"
            "apt_retry() { printf '%s\\n' \"$*\" >> \"$FAKE/apt.log\"; [[ -n \"${APT_OK:-}\" ]] || return 1; "
            "cp \"$FAKE/logrotate.real\" \"$FAKE/../bin/logrotate\"; }\n"
            + preamble + self.funcs + "\nwins_ensure_suricata_rotation\n"
        )
        return self.run_bash(script, **env)

    def assert_refused(self, proc, needle):
        self.assertNotEqual(proc.returncode, 0, f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn(needle, proc.stderr)

    def test_missing_logrotate_conf_is_restored_byte_for_byte_and_verified(self):
        # The Netherlands case measured 2026-09-24.
        proc = self.ensure()
        self.assertEqual(proc.returncode, 0, f"stdout={proc.stdout}\nstderr={proc.stderr}")
        # The sandbox rewrote the include path; undo that before hashing.
        conf = (self.root / "etc/logrotate.conf").read_text().replace(str(self.root), "").encode()
        self.assertEqual(hashlib.sha256(conf).hexdigest(), STOCK_LOGROTATE_SHA256)
        self.assertEqual(self.state("logrotate.timer", "enabled"), "enabled")
        self.assertEqual(self.state("logrotate.timer", "active"), "active")
        self.assertIn("Suricata log rotation verified", proc.stdout)

    def test_existing_logrotate_conf_is_left_alone(self):
        custom = f"weekly\nrotate 4\ninclude {self.root}/etc/logrotate.d\n# operator note\n"
        (self.root / "etc/logrotate.conf").write_text(custom)
        self.assertEqual(self.ensure().returncode, 0)
        self.assertEqual((self.root / "etc/logrotate.conf").read_text(), custom)

    def test_logrotate_conf_without_the_include_fails(self):
        (self.root / "etc/logrotate.conf").write_text("weekly\nrotate 4\n")
        self.assert_refused(self.ensure(), "; the Suricata policy would never run")

    def test_failed_policy_dry_run_fails(self):
        self.assert_refused(self.ensure(FAIL_LR_POLICY=1), "logrotate.d/wins-suricata failed")

    def test_whole_config_dry_run_failure_fails(self):
        # Round U Turn 2: the timer runs logrotate on /etc/logrotate.conf, so a
        # policy that makes that run exit nonzero must fail the install, even
        # though the output still names the Suricata path.
        proc = self.ensure(OTHER_POLICY_ERRORS=1)
        self.assert_refused(proc, "logrotate.conf failed:")
        self.assertIn("error: other policy", proc.stderr)
        self.assertNotIn("Suricata log rotation verified", proc.stdout)

    def test_whole_config_run_that_never_reaches_the_policy_fails(self):
        self.assert_refused(self.ensure(LR_CONF_SILENT=1), "never reaches")

    def test_timer_enable_failure_fails(self):
        self.assert_refused(self.ensure(FAIL_ENABLE=1), "logrotate.timer could not be enabled")

    def test_timer_that_stays_inactive_fails(self):
        self.assert_refused(self.ensure(TIMER_STAYS_INACTIVE=1), "logrotate.timer is not active")

    def test_missing_logrotate_is_installed(self):
        shutil.copy(self.bin / "logrotate", self.fake / "logrotate.real")
        (self.bin / "logrotate").unlink()
        proc = self.ensure(APT_OK=1)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("install -y logrotate", (self.fake / "apt.log").read_text())

    def test_missing_logrotate_that_cannot_be_installed_fails(self):
        shutil.copy(self.bin / "logrotate", self.fake / "logrotate.real")
        (self.bin / "logrotate").unlink()
        self.assert_refused(self.ensure(), "Could not install logrotate")


class SuricataRotationCoreRoleTests(SuricataRotationTests):
    ROLE = SURICATA_ROLES[1]


class SuricataPolicyTextTests(unittest.TestCase):
    def test_policy_retains_three_rotations_and_says_so(self):
        for role in SURICATA_ROLES:
            source = (SERVER / role).read_text(encoding="utf-8")
            body = source.split("cat > /etc/logrotate.d/wins-suricata <<'EOF'\n", 1)[1].split("\nEOF\n", 1)[0]
            rotate = [line.split() for line in body.splitlines() if line.split()[:1] == ["rotate"]]
            self.assertEqual(rotate, [["rotate", "3"]], role)
            # Real-host finding (L26 v3): without su, logrotate skips the
            # OISF package's group-writable /var/log/suricata when the policy
            # is read on its own.
            su = [line.split() for line in body.splitlines() if line.split()[:1] == ["su"]]
            self.assertEqual(su, [["su", "root", "adm"]], role)
            self.assertNotIn("maxage", body, role)
            head = source[:source.index("cat > /etc/logrotate.d/wins-suricata <<'EOF'\n")][-900:]
            self.assertIn("Retain 3 rotations", head, role)
            self.assertNotRegex(head, r"(?i)three days|3 days", role)
            after = source.split("cat > /etc/logrotate.d/wins-suricata <<'EOF'\n", 1)[1]
            after = after[after.index("\nEOF\n"):][:1200]
            self.assertIn("  wins_ensure_suricata_rotation || return 1\n", after, role)
            self.assertFalse("reported issues; review /etc/logrotate.d/wins-suricata" in source,
                             f"{role} still downgrades a failed policy dry run to a warning")
            self.assertEqual(function_text(source, "wins_ensure_suricata_rotation"),
                             function_text((SERVER / SURICATA_ROLES[0]).read_text(encoding="utf-8"),
                                           "wins_ensure_suricata_rotation"), role)


class AwgContainerLogBoundTests(Sandbox):
    def setUp(self):
        super().setUp()
        self.source = (SERVER / "wins_data_plane_setup_ONETOUCH.sh").read_text(encoding="utf-8")
        self.install_awg = function_text(self.source, "install_awg")

    def test_docker_run_bounds_the_log_and_install_awg_recreates_the_container(self):
        run = self.install_awg[self.install_awg.index("  docker run -d \\\n"):]
        run = run[:run.index('tail -f /dev/null"')]
        for opt in ("--log-driver json-file", "--log-opt max-size=1m", "--log-opt max-file=2"):
            self.assertIn(opt, run)
        # Recreation: an existing container keeps its old log config, so the
        # function must remove it before creating the bounded one.
        self.assertLess(self.install_awg.index('docker rm -f "${AWG_CONTAINER_NAME:-$AWG_CONTAINER_NAME_DEFAULT}"'),
                        self.install_awg.index("  docker run -d \\\n"))
        self.assertIn("re-running\n  # this installer on a node IS the recreation step", self.install_awg)

    def _verify_snippet(self) -> str:
        start = self.install_awg.index("  local awg_log_config\n")
        end = self.install_awg.index("  fi\n", start) + len("  fi\n")
        return "check() {\n" + self.install_awg[start:end] + "}\n"

    def test_running_container_log_bound_is_verified(self):
        self.assertLess(self.install_awg.index("  docker run -d \\\n"), self.install_awg.index("  local awg_log_config\n"))
        script = ("set -Eeuo pipefail\nerr() { printf '[ERR] %s\\n' \"$*\" >&2; }\n"
                  "AWG_CONTAINER_NAME_DEFAULT=amnezia-awg2\n" + self._verify_snippet() + "check\n")
        ok = self.run_bash(script, DOCKER_LOG_CONFIG="json-file 1m 2")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        for bad in ("json-file  ", "json-file 10m 3", "local 1m 2", ""):
            proc = self.run_bash(script, DOCKER_LOG_CONFIG=bad)
            self.assertNotEqual(proc.returncode, 0, f"accepted log config {bad!r}")
            self.assertIn("AmneziaWG container log is not bounded", proc.stderr)


if __name__ == "__main__":
    if not BASH:
        print("NOTE: no bash 4+ found; the executed tests will skip")
    result = unittest.main(module=__name__, argv=["log-persistence"], exit=False, verbosity=2)
    if not result.result.wasSuccessful():
        raise SystemExit(1)
    print("Log persistence containment tests passed")
