#!/usr/bin/env python3
"""Fleet reset plan 2026-10-08 (FLEET1): data-plane installer changes.

The SHIPPED bash of server/wins_data_plane_setup_ONETOUCH.sh is extracted and
run under Bash 4+ with host effects faked (fleet_reset_testlib) and absolute
host paths rewritten into a per-test directory. Nothing on the host changes.

  TP-D1  an unreachable rclone remote stops the install, and a failed upload
         stops the nightly backup, only when remote backup is required;
         otherwise the archive is kept root-only on the node.
  TP-D3  the retired-flag refusal and --help no longer send the operator to the
         standalone gateway installer (the v3 gateway is part of this one).
  TP-R1  (owner-directed, RAM-only nodes) Suricata and nginx logs live on
         size-capped tmpfs mounts that the daemons require at boot, the
         on-disk copies are removed, Xray logs to the volatile journal, and
         postflight refuses anything else. FLEET1 Turn 2 (seat performance
         item): Suricata writes its eve stats record once a minute (stats.
         interval, the key the installed suricata.yaml carries) instead of
         every 8 s, so the RAM-only log holds about 1/7 of those records.
         FLEET1 Turn 6 (Astra): a mount, unit, state, configuration or
         directory probe that fails is never a pass, whatever it printed.
         FLEET1 Turn 7 (Astra): called beneath `||` as main and postflight
         call them, a unit or drop-in write, spec read or unit-name step that
         fails stops both functions before any further change.

Run: python3 -B -m pytest -q -p no:cacheprovider server/test_fleet_reset_dp_installer.py
     WINS_FLEET_DP=/path/to/installer ... (mutant runs)
"""

from __future__ import annotations

import re
import subprocess
import textwrap
import unittest
from pathlib import Path

import fleet_reset_testlib as lib

DP = lib.installer("WINS_FLEET_DP", "server/wins_data_plane_setup_ONETOUCH.sh")
SRC = DP.read_text(encoding="utf-8")


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.sb = lib.Sandbox()

    def tearDown(self) -> None:
        self.sb.cleanup()


# --- TP-D1 ---------------------------------------------------------------------

class RcloneOptionalRemoteTests(Case):
    RCLONE = r'''#!/bin/sh
printf 'rclone %s\n' "$*" >> "$FLEET_CALLS"
case "$1" in
  listremotes) echo "GoogleDrive_secured:" ;;
  lsd) exit 1 ;;
  config) echo '{"GoogleDrive_secured": {"type": "crypt"}}' ;;
  copy) exit "${FLEET_RCLONE_COPY_RC:-0}" ;;
  cryptcheck) exit 0 ;;
esac
'''

    def setUp(self) -> None:
        super().setUp()
        (self.sb.bin / "rclone").write_text(self.RCLONE)
        (self.sb.bin / "rclone").chmod(0o755)

    def configure(self, required: str) -> subprocess.CompletedProcess:
        fn = lib.function_text(SRC, "configure_rclone_credentials")
        fn = fn.replace("/root/.config/rclone", str(self.sb.path("rclone"))).replace("/etc/winsvpn", str(self.sb.path("etc")))
        conf = self.sb.path("rclone.conf.src")
        conf.write_text("[GoogleDrive_secured]\ntype = crypt\n")
        script = lib.LOG_STUBS + lib.stub_functions("rclone_crypt_remote_contract") + textwrap.dedent(f'''
            sleep() {{ :; }}
            resolve_node_backup_host_id() {{ RESOLVED_BACKUP_HOST_ID=node-1; }}
            REQUIRE_REMOTE_BACKUP_DEFAULT=1
            RCLONE_REMOTE_DEFAULT=GoogleDrive_secured
            RCLONE_CONFIG_SOURCE={conf}
            REQUIRE_REMOTE_BACKUP={required}
        ''') + fn + "\nconfigure_rclone_credentials\n"
        return self.sb.run(script)

    def test_an_unreachable_remote_stops_a_required_backup(self) -> None:
        r = self.configure("1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Unable to access required rclone remote", r.stderr)

    def test_an_unreachable_optional_remote_does_not_stop_the_install(self) -> None:
        r = self.configure("0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Remote backup is optional here", r.stderr)
        self.assertNotIn("[ERR]", r.stderr)
        self.assertEqual(sum(1 for c in self.sb.logged() if c.startswith("rclone lsd")), 3)

    def upload(self, required: str, copy_rc: str) -> subprocess.CompletedProcess:
        body = lib.heredoc(SRC, "cat > /usr/local/bin/wins-node-backup <<'EOF'", "EOF")
        start = body.index('if command -v rclone >/dev/null 2>&1 && [[ -f "${RCLONE_CONFIG_FILE}" ]]; then')
        segment = body[start:]
        upload = self.sb.path("upload")
        upload.mkdir()
        (upload / "a.tar.gz").write_text("archive")
        (upload / "a.tar.gz.sha256").write_text("sum")
        conf = self.sb.path("rclone.conf")
        conf.write_text("x")
        script = textwrap.dedent(f'''
            set -Eeuo pipefail
            SOURCE_ROOT={self.sb.path("root")}
            root_path() {{ printf '%s/%s' "${{SOURCE_ROOT%/}}" "$1"; }}
            RCLONE_CONFIG_FILE={conf}
            UPLOAD_DIR={upload}
            ARCHIVE_NAME=a.tar.gz
            REMOTE=GoogleDrive_secured:winsvpn-backups/node-1
            REQUIRED={required}
        ''') + segment
        return self.sb.run(script, FLEET_RCLONE_COPY_RC=copy_rc)

    def local_copy(self) -> list[str]:
        d = self.sb.path("root", "var", "backups", "winsvpn")
        return sorted(p.name for p in d.iterdir()) if d.exists() else []

    def test_a_failed_optional_upload_keeps_the_archive_root_only_on_the_node(self) -> None:
        r = self.upload("0", "1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("root-only local backup retained", r.stderr)
        self.assertEqual(self.local_copy(), ["a.tar.gz", "a.tar.gz.sha256"])
        self.assertEqual(oct(self.sb.path("root", "var", "backups", "winsvpn").stat().st_mode & 0o777), "0o700")

    def test_a_failed_required_upload_fails_the_run(self) -> None:
        r = self.upload("1", "1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Required encrypted rclone backup upload failed", r.stderr)

    def test_a_good_upload_is_verified_and_keeps_no_local_copy(self) -> None:
        r = self.upload("0", "0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("uploaded and integrity-verified", r.stdout)
        self.assertEqual(self.local_copy(), [])
        self.assertTrue(any(c.startswith("rclone cryptcheck") for c in self.sb.logged()))


# --- TP-D3 ---------------------------------------------------------------------

class RetiredFlagGuidanceTests(Case):
    def test_the_refusal_says_the_gateway_is_part_of_this_installer(self) -> None:
        script = (lib.LOG_STUBS + "WINN_PROTOCOL_V3_ENABLE_DEFAULT=1\n"
                  + lib.function_text(SRC, "refuse_retired_winn_protocol_v3_enable")
                  + "\nrefuse_retired_winn_protocol_v3_enable || echo REFUSED\n")
        r = self.sb.run(script)
        self.assertIn("REFUSED", r.stdout)
        self.assertIn("installed by this data-plane installer itself", r.stderr)
        self.assertNotIn("Use the standalone gateway installer instead", r.stderr)

    def test_help_names_the_staged_gateway_files(self) -> None:
        line = next(l for l in SRC.splitlines() if "WINN_PROTOCOL_V3_ENABLE=1 is retired and refused" in l)
        self.assertIn("winn3-gateway-linux-amd64 and its .sha256", line)
        self.assertNotIn("Use server/" + "wins_winn3_gateway" + "_install.sh", SRC)


# --- TP-R1 ---------------------------------------------------------------------

SYSTEMCTL = r'''#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "$FLEET_CALLS"
# FLEET1 Turn 6: FLEET_STATE names the service ActiveState (else FLEET_ACTIVE
# gives active or inactive); FLEET_STATE_PROBE_FAIL=1 makes both state probes
# fail, as when systemctl cannot reach the manager (show still prints
# "inactive", so only the exit status tells the failure apart).
state_of() {
  if [[ -n "${FLEET_STATE:-}" ]]; then printf '%s\n' "$FLEET_STATE"
  elif [[ " ${FLEET_ACTIVE:-} " == *" $1 "* ]]; then echo active
  else echo inactive; fi
}
case "$1" in
  is-active)
    [[ "${FLEET_STATE_PROBE_FAIL:-0}" == 1 ]] && exit 1
    unit="$2"; [[ "$2" == --quiet ]] && unit="$3"
    case "$(state_of "$unit")" in active|reloading) exit 0 ;; *) exit 3 ;; esac ;;
  start)
    if [[ "$2" == *.mount ]]; then
      where="$(sed -n 's/^Where=//p' "$FLEET_UNITS/$2")"
      [[ -d "$where" ]] || mkdir -p "$where"
      printf '%s tmpfs\n' "$where" >> "$FLEET_MOUNTS"
    fi ;;
  is-enabled) [[ -e "$FLEET_UNITS/enabled.$2" ]] && echo enabled || echo disabled ;;
  enable) touch "$FLEET_UNITS/enabled.$2" ;;
  show)
    if [[ " $* " == *" ActiveState "* ]]; then
      [[ "${FLEET_STATE_PROBE_FAIL:-0}" == 1 ]] && { echo inactive; exit 1; }
      [[ "${FLEET_STATE_EMPTY:-0}" == 1 ]] && { echo; exit 0; }
      state_of "$2"; exit 0
    fi
    for f in "$FLEET_UNITS/$2.d"/*.conf; do [[ -e "$f" ]] && sed -n 's/^RequiresMountsFor=//p' "$f"; done | paste -sd ' ' - ;;
esac
exit 0
'''


class VolatileNodeLogTests(Case):
    def setUp(self) -> None:
        super().setUp()
        (self.sb.bin / "systemctl").write_text(SYSTEMCTL)
        (self.sb.bin / "systemctl").chmod(0o755)
        self.units = self.sb.path("units")
        self.units.mkdir()
        self.var = self.sb.path("var", "log")
        self.mounts = self.sb.path("mounts")
        self.mounts.write_text("")
        self.xray = self.sb.path("xray-config.json")

    def functions(self) -> str:
        start = SRC.index("# --- TP-R1: RAM-only node logs")
        end = SRC.index("# --- F-11: crash dumps, journals, swap and hibernation (HANDOFF 3g)", start)
        text = SRC[start:end].replace("/var/log/", str(self.var) + "/")
        return text.replace("/usr/local/etc/xray/config.json", str(self.xray))

    def run_fn(self, call: str, active: str = "", **env: str) -> subprocess.CompletedProcess:
        script = lib.LOG_STUBS + "set -Eeuo pipefail\n" + self.functions() + "\n" + call + "\n"
        return self.sb.run(script, WINS_SYSTEMD_UNIT_DIR=str(self.units), FLEET_UNITS=str(self.units),
                           FLEET_MOUNTS=str(self.mounts), FLEET_ACTIVE=active, **env)

    def seed_disk_logs(self) -> None:
        for rel in ("suricata/eve.json", "suricata/fast.log.1.gz", "nginx/access.log", "nginx/wins-node.error.log"):
            p = self.var / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("203.0.113.77 client\n")

    def test_logs_move_into_ram_and_the_disk_copies_are_removed(self) -> None:
        self.seed_disk_logs()
        r = self.run_fn("install_volatile_node_logs", active="suricata.service nginx.service")
        self.assertEqual(r.returncode, 0, r.stderr)
        for name, where, size, mode in (("var-log-suricata.mount", "suricata", "256m", "0750"),
                                        ("var-log-nginx.mount", "nginx", "64m", "0755")):
            unit = next(u for u in self.units.glob(f"*{where}.mount") if not u.name.startswith("enabled."))
            text = unit.read_text()
            self.assertIn(f"Where={self.var}/{where}", text)
            self.assertIn("Type=tmpfs", text)
            self.assertIn(f"Options=mode={mode},uid=0,gid=0,nosuid,nodev,noexec,size={size}", text)
            self.assertIn("WantedBy=local-fs.target", text)
        self.assertEqual(sorted(p.name for p in (self.var / "suricata").iterdir()), [])
        self.assertEqual(sorted(p.name for p in (self.var / "nginx").iterdir()), [])
        for service, where in (("suricata.service", "suricata"), ("nginx.service", "nginx")):
            dropin = self.units / f"{service}.d" / "31-winsvpn-volatile-logs.conf"
            self.assertIn(f"RequiresMountsFor={self.var}/{where}", dropin.read_text())
        calls = self.sb.logged()
        for service in ("suricata.service", "nginx.service"):
            stop = calls.index(f"systemctl stop {service}")
            mount = next(i for i, c in enumerate(calls) if c.startswith("systemctl start") and c.endswith(".mount") and i > stop)
            self.assertLess(stop, mount)
            self.assertIn(f"systemctl start {service}", calls[mount:])

    def test_the_real_paths_and_systemd_unit_names(self) -> None:
        self.assertIn('NODE_VOLATILE_LOG_SPECS_DEFAULT="suricata.service|/var/log/suricata|${SURICATA_LOG_TMPFS_SIZE:-256m}|0750 '
                      'nginx.service|/var/log/nginx|${NGINX_LOG_TMPFS_SIZE:-64m}|0755"', SRC)
        script = lib.function_text(SRC, "wins_volatile_log_mount_unit_name") + (
            "\nwins_volatile_log_mount_unit_name /var/log/suricata; echo; wins_volatile_log_mount_unit_name /var/log/nginx\n")
        self.assertEqual(self.sb.run(script).stdout.split(), ["var-log-suricata.mount", "var-log-nginx.mount"])

    def test_a_stopped_service_is_not_started(self) -> None:
        r = self.run_fn("install_volatile_node_logs", active="")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.sb.logged()
        self.assertNotIn("systemctl start suricata.service", calls)
        self.assertNotIn("systemctl stop nginx.service", calls)

    def test_a_rerun_on_tmpfs_deletes_nothing_and_restarts_nothing(self) -> None:
        self.assertEqual(self.run_fn("install_volatile_node_logs").returncode, 0)
        (self.var / "suricata" / "eve.json").write_text("in ram\n")
        self.sb.calls.unlink()
        r = self.run_fn("install_volatile_node_logs", active="suricata.service nginx.service")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((self.var / "suricata" / "eve.json").exists())
        self.assertFalse(any(c.startswith("systemctl stop") for c in self.sb.logged()))

    def test_a_symlinked_log_directory_is_refused(self) -> None:
        self.var.mkdir(parents=True)
        target = self.sb.path("elsewhere")
        target.mkdir()
        (self.var / "suricata").symlink_to(target)
        r = self.run_fn("install_volatile_node_logs")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("is a symlink", r.stderr)

    def test_a_bad_size_is_refused(self) -> None:
        r = self.run_fn("install_volatile_node_logs", SURICATA_LOG_TMPFS_SIZE="lots")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("must be a size", r.stderr)

    def test_postflight_check(self) -> None:
        self.xray.write_text('{"log": {"loglevel": "warning", "access": "none", "error": ""}}')
        self.assertEqual(self.run_fn("install_volatile_node_logs").returncode, 0)
        r = self.run_fn("verify_volatile_node_logs")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.xray.write_text('{"log": {"error": "/var/log/xray/error.log"}}')
        r = self.run_fn("verify_volatile_node_logs")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Xray still writes its error log to a file", r.stderr)
        self.xray.write_text('{"log": {"error": ""}}')
        self.mounts.write_text("")
        r = self.run_fn("verify_volatile_node_logs")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("is not a RAM-only tmpfs", r.stderr)

    def test_xray_logs_to_the_journal_and_its_old_file_is_removed(self) -> None:
        start = SRC.index("\ninstall_xray() {\n")
        cfg = SRC[start:SRC.index("\nnode_origin_cert_valid() {\n", start)]
        self.assertIn('    "access": "none",\n    "error": ""\n', cfg)
        self.assertNotIn("/var/log/xray/error.log", cfg)
        tail = cfg[cfg.index("  systemctl restart xray.service\n"):]
        self.assertIn("find /var/log/xray -xdev -maxdepth 1 -type f -name 'error.log*' -delete", tail)

    def test_main_mounts_before_any_daemon_is_configured_and_postflight_checks(self) -> None:
        main = lib.function_text(SRC[SRC.rindex("\nmain() {\n"):], "main")
        order = [main.index(s) for s in ("  harden_crash_artifacts\n", "  install_volatile_node_logs || exit 1\n",
                                         "  install_xray\n", "  write_nginx\n", "  install_data_ids_ips\n")]
        self.assertEqual(order, sorted(order))
        self.assertIn("  verify_volatile_node_logs || return 1\n", lib.function_text(SRC, "postflight_data_plane"))

    def test_the_f11_journal_gates_are_untouched(self) -> None:
        for needle in ('_f11_err "F-11: Storage=volatile but /var/log/journal exists after the journald restart"',
                       "for f in /var/log/syslog /var/log/messages /var/log/user.log /var/log/daemon.log /var/log/kern.log /var/log/auth.log; do"):
            self.assertIn(needle, SRC)

    # --- FLEET1 Turn 6: a probe that fails is never a pass ---------------------

    def disk_logs_present(self) -> list[str]:
        return sorted(str(p.relative_to(self.var)) for p in self.var.rglob("*") if p.is_file())

    def test_a_mount_probe_that_fails_is_never_already_tmpfs(self) -> None:
        # findmnt prints "tmpfs" and then fails: the rerun skip must not take it.
        (self.sb.bin / "findmnt").write_text("#!/bin/sh\necho tmpfs\nexit 1\n")
        self.seed_disk_logs()
        r = self.run_fn("install_volatile_node_logs", active="suricata.service nginx.service")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("is already a RAM-only tmpfs", r.stdout)
        self.assertIn("is not a tmpfs after", r.stderr)

    def test_a_state_probe_that_fails_refuses_before_any_disk_change(self) -> None:
        self.seed_disk_logs()
        before = self.disk_logs_present()
        r = self.run_fn("install_volatile_node_logs", active="suricata.service nginx.service",
                        FLEET_STATE_PROBE_FAIL="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Could not read the state of suricata.service", r.stderr)
        self.assertEqual(self.disk_logs_present(), before)
        self.assertFalse(any(c.startswith("systemctl start") for c in self.sb.logged()))
        self.assertEqual(self.mounts.read_text(), "")

    def test_an_unknown_service_state_refuses_before_any_disk_change(self) -> None:
        self.seed_disk_logs()
        before = self.disk_logs_present()
        r = self.run_fn("install_volatile_node_logs", FLEET_STATE="maintenance")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Could not tell whether suricata.service is running (ActiveState 'maintenance')", r.stderr)
        self.assertEqual(self.disk_logs_present(), before)
        self.assertEqual(self.mounts.read_text(), "")

    def test_an_empty_service_state_refuses_before_any_disk_change(self) -> None:
        self.seed_disk_logs()
        before = self.disk_logs_present()
        r = self.run_fn("install_volatile_node_logs", FLEET_STATE_EMPTY="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Could not tell whether suricata.service is running (ActiveState '')", r.stderr)
        self.assertEqual(self.disk_logs_present(), before)
        self.assertEqual(self.mounts.read_text(), "")

    def test_an_activating_service_is_stopped_first_and_started_again(self) -> None:
        self.seed_disk_logs()
        r = self.run_fn("install_volatile_node_logs", FLEET_STATE="activating")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.sb.logged()
        for service in ("suricata.service", "nginx.service"):
            stop = calls.index(f"systemctl stop {service}")
            mount = next(i for i, c in enumerate(calls) if c.startswith("systemctl start") and c.endswith(".mount")
                         and i > stop)
            self.assertIn(f"systemctl start {service}", calls[mount:])

    def test_a_failed_service_is_neither_stopped_nor_started(self) -> None:
        r = self.run_fn("install_volatile_node_logs", FLEET_STATE="failed")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.sb.logged()
        for service in ("suricata.service", "nginx.service"):
            self.assertNotIn(f"systemctl stop {service}", calls)
            self.assertNotIn(f"systemctl start {service}", calls)

    def test_a_deactivating_service_is_stopped_and_left_stopped(self) -> None:
        r = self.run_fn("install_volatile_node_logs", FLEET_STATE="deactivating")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.sb.logged()
        for service in ("suricata.service", "nginx.service"):
            self.assertIn(f"systemctl stop {service}", calls)
            self.assertNotIn(f"systemctl start {service}", calls)

    def verify_with_xray_dir(self, **env: str) -> subprocess.CompletedProcess:
        self.xray.write_text('{"log": {"loglevel": "warning", "access": "none", "error": ""}}')
        self.assertEqual(self.run_fn("install_volatile_node_logs").returncode, 0)
        return self.run_fn("verify_volatile_node_logs", **env)

    def test_an_xray_log_directory_that_cannot_be_read_is_never_a_pass(self) -> None:
        (self.sb.bin / "find").write_text(
            "#!/bin/sh\nfor a in \"$@\"; do\n  if [ \"$a\" = 'error.log*' ] && [ \"${FLEET_FIND_FAIL:-0}\" = 1 ]; then\n"
            "    echo 'find: xray: Input/output error' >&2; exit 1\n  fi\ndone\n"
            f"exec {lib.REAL_FIND} \"$@\"\n")
        (self.var / "xray").mkdir(parents=True)
        self.assertEqual(self.verify_with_xray_dir().returncode, 0)
        r = self.verify_with_xray_dir(FLEET_FIND_FAIL="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("could not read", r.stderr)
        self.assertNotIn("TP-R1 verified", r.stdout)

    def test_a_leftover_xray_error_log_is_refused_also_behind_a_symlink(self) -> None:
        r = self.verify_with_xray_dir()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("TP-R1 verified", r.stdout)
        xray_dir = self.var / "xray"
        xray_dir.mkdir()
        (xray_dir / "access.log").write_text("none\n")
        self.assertEqual(self.verify_with_xray_dir().returncode, 0)
        (xray_dir / "error.log.1").write_text("203.0.113.77 rejected\n")
        r = self.verify_with_xray_dir()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("an on-disk Xray error log is still present", r.stderr)
        xray_dir.rename(self.sb.path("xray-real"))
        xray_dir.symlink_to(self.sb.path("xray-real"))
        r = self.verify_with_xray_dir()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("an on-disk Xray error log is still present", r.stderr)

    # --- FLEET1 Turn 7 (Astra): main and postflight call these beneath `||`,
    # where errexit is off, so each command checks its own status. Every call
    # below is made the way main and postflight make it.

    INSTALL = "install_volatile_node_logs || exit $?"
    VERIFY = "verify_volatile_node_logs || exit $?"
    # The Nth spec read, or the Nth unit-name step, fails after doing its work
    # (the variables are set, so only the status tells the failure apart).
    # Install reads specs 1-2 in its write loop and 3-4 in its mount loop.
    STEP_FAILS = textwrap.dedent('''
        fleet_reads=0
        read() {
          builtin read "$@" || return
          fleet_reads=$((fleet_reads + 1))
          (( fleet_reads != ${FLEET_READ_FAILS_AT:-0} ))
        }
        wins_volatile_log_mount_unit_name() {
          local path="${1#/}" n
          n=$(( $(cat "$FLEET_UNIT_COUNT" 2>/dev/null || echo 0) + 1 ))
          echo "$n" > "$FLEET_UNIT_COUNT"
          printf '%s.mount' "${path//\\//-}"
          (( n != ${FLEET_UNIT_FAILS_AT:-0} ))
        }
    ''')

    def unit_file(self, where: str) -> Path:
        return self.units / (str(self.var / where).lstrip("/").replace("/", "-") + ".mount")

    def assert_refused_before_any_change(self, r: subprocess.CompletedProcess, before: list[str]) -> None:
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("now lives in RAM", r.stdout)
        self.assertNotIn("is already a RAM-only tmpfs", r.stdout)
        self.assertNotIn("systemctl daemon-reload", self.sb.logged())
        self.assertEqual(self.disk_logs_present(), before)
        self.assertEqual(self.mounts.read_text(), "")

    def test_a_mount_unit_that_cannot_be_written_refuses_before_any_change(self) -> None:
        self.seed_disk_logs()
        before = self.disk_logs_present()
        self.unit_file("suricata").mkdir()  # the here-document cannot open it
        r = self.run_fn(self.INSTALL, active="suricata.service nginx.service")
        self.assert_refused_before_any_change(r, before)

    def test_a_service_drop_in_that_cannot_be_written_refuses_before_any_change(self) -> None:
        self.seed_disk_logs()
        before = self.disk_logs_present()
        (self.units / "suricata.service.d" / "31-winsvpn-volatile-logs.conf").mkdir(parents=True)
        r = self.run_fn(self.INSTALL, active="suricata.service nginx.service")
        self.assert_refused_before_any_change(r, before)

    def test_a_failed_write_on_a_rerun_over_tmpfs_is_never_a_success(self) -> None:
        self.assertEqual(self.run_fn(self.INSTALL).returncode, 0)
        conf = self.units / "nginx.service.d" / "31-winsvpn-volatile-logs.conf"
        conf.unlink()
        conf.mkdir()
        self.sb.calls.unlink()
        r = self.run_fn(self.INSTALL)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("is already a RAM-only tmpfs", r.stdout)
        self.assertNotIn("systemctl daemon-reload", self.sb.logged())

    def test_a_spec_read_or_unit_name_step_that_fails_stops_the_install(self) -> None:
        for variable, at, stage in (("FLEET_READ_FAILS_AT", "1", "write"), ("FLEET_READ_FAILS_AT", "3", "mount"),
                                    ("FLEET_UNIT_FAILS_AT", "1", "write"), ("FLEET_UNIT_FAILS_AT", "3", "mount")):
            with self.subTest(step=variable, at=at):
                self.sb.calls.unlink(missing_ok=True)
                counter = self.sb.path("unit-count")
                counter.unlink(missing_ok=True)
                for unit in list(self.units.iterdir()):
                    if unit.is_dir():
                        lib.shutil.rmtree(unit)
                    else:
                        unit.unlink()
                self.mounts.write_text("")
                self.seed_disk_logs()
                before = self.disk_logs_present()
                r = self.run_fn(self.STEP_FAILS + self.INSTALL, active="suricata.service nginx.service",
                                FLEET_UNIT_COUNT=str(counter), **{variable: at})
                self.assertNotEqual(r.returncode, 0)
                self.assertNotIn("now lives in RAM", r.stdout)
                calls = self.sb.logged()
                self.assertFalse(any(c.startswith("systemctl enable") for c in calls))
                self.assertEqual(self.disk_logs_present(), before)
                self.assertEqual(self.mounts.read_text(), "")
                if stage == "write":
                    self.assertNotIn("systemctl daemon-reload", calls)
                    self.assertEqual(sorted(p.name for p in self.units.iterdir()), [])
                else:
                    self.assertIn("systemctl daemon-reload", calls)

    def test_a_spec_read_or_unit_name_step_that_fails_never_verifies(self) -> None:
        self.xray.write_text('{"log": {"loglevel": "warning", "access": "none", "error": ""}}')
        self.assertEqual(self.run_fn(self.INSTALL).returncode, 0)
        counter = self.sb.path("unit-count")
        self.assertEqual(self.run_fn(self.STEP_FAILS + self.VERIFY, FLEET_UNIT_COUNT=str(counter)).returncode, 0)
        for variable in ("FLEET_READ_FAILS_AT", "FLEET_UNIT_FAILS_AT"):
            with self.subTest(step=variable):
                counter.unlink(missing_ok=True)
                r = self.run_fn(self.STEP_FAILS + self.VERIFY, FLEET_UNIT_COUNT=str(counter), **{variable: "1"})
                self.assertNotEqual(r.returncode, 0)
                self.assertNotIn("TP-R1 verified", r.stdout)


class VolatileNodeLogProbeStatusTests(unittest.TestCase):
    # FLEET1 Turn 5 vote (Astra), applied as written.
    def probe(self, **overrides: str) -> subprocess.CompletedProcess:
        functions = "\n".join(lib.function_text(SRC, name) for name in (
            "wins_path_is_tmpfs_mount",
            "wins_volatile_log_mount_unit_name",
            "verify_volatile_node_logs",
        ))
        stubs = r'''
findmnt() { printf 'tmpfs\n'; return "$FINDMNT_RC"; }
systemctl() {
  case "$1" in
    is-enabled) printf 'enabled\n'; return "$ENABLED_RC" ;;
    show) printf '/synthetic/log\n'; return "$SHOW_RC" ;;
    *) return 90 ;;
  esac
}
grep() { return "$GREP_RC"; }
compgen() { return 1; }
NODE_VOLATILE_LOG_SPECS_DEFAULT='synthetic.service|/synthetic/log|64m|0755'
'''
        env = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "FINDMNT_RC": "0",
            "ENABLED_RC": "0",
            "SHOW_RC": "0",
            "GREP_RC": "1",
        }
        env.update(overrides)
        script = ("set -Eeuo pipefail\n" + lib.LOG_STUBS + functions
                  + stubs + "\nverify_volatile_node_logs || exit $?\n")
        return subprocess.run(
            [lib.BASH, "-c", script], capture_output=True, text=True,
            env=env, timeout=10,
        )

    def test_successful_probes_verify(self) -> None:
        result = self.probe()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("TP-R1 verified", result.stdout)

    def test_failed_probes_never_verify(self) -> None:
        faults = {
            "FINDMNT_RC": ("1", "not a RAM-only tmpfs"),
            "ENABLED_RC": ("1", "is not enabled"),
            "SHOW_RC": ("1", "could not read the mount requirements"),
            "GREP_RC": ("2", "could not read the Xray logging configuration"),
        }
        for variable, (status, message) in faults.items():
            with self.subTest(probe=variable):
                result = self.probe(**{variable: status})
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertNotIn("TP-R1 verified", result.stdout)
                self.assertIn(message, result.stderr)


# --- TP-S2 (owner, 2026-10-09): Spain zram at 75% of RAM, config only --------

class SpainZramSettingsTests(Case):
    def render(self, percent: str, max_mb: str) -> subprocess.CompletedProcess:
        gen = self.sb.path("zram-generator")
        gen.write_text("#!/bin/sh\n")
        gen.chmod(0o755)
        script = lib.LOG_STUBS + textwrap.dedent(f'''
            set -Eeuo pipefail
            ENABLE_ZRAM_SWAP_DEFAULT=1 ZRAM_SWAP_PERCENT_DEFAULT=50 ZRAM_SWAP_MAX_MB_DEFAULT=2048
            ZRAM_SWAP_PERCENT={percent} ZRAM_SWAP_MAX_MB={max_mb}
            WINS_ZRAM_GENERATOR_PATH={gen}
            WINS_ZRAM_CONFIG_PATH={self.sb.path("etc", "zram-generator.conf")}
        ''') + lib.function_text(SRC, "validate_zram_policy_settings") + lib.function_text(
            SRC, "configure_zram_swap") + "\nconfigure_zram_swap render-only\n"
        return self.sb.run(script)

    def test_the_installer_takes_the_spain_values_without_a_code_change(self) -> None:
        r = self.render("75", "3072")
        self.assertEqual(r.returncode, 0, r.stderr)
        conf = self.sb.path("etc", "zram-generator.conf").read_text()
        self.assertIn("zram-size = min(ram * 75 / 100, 3072)", conf)
        self.assertNotIn("writeback-device", conf.split("\n", 1)[1])

    def test_out_of_range_values_are_still_refused(self) -> None:
        for percent, max_mb in (("101", "3072"), ("75", "9000"), ("24", "3072")):
            with self.subTest(percent=percent, max_mb=max_mb):
                self.assertNotEqual(self.render(percent, max_mb).returncode, 0)

    def test_disk_swap_stays_off_by_default(self) -> None:
        self.assertIn('ENABLE_WINS_SWAPFILE_DEFAULT="${ENABLE_WINS_SWAPFILE:-0}"', SRC)
        self.assertIn('WINS_CRYPTSWAP_ENABLED_DEFAULT="${WINS_CRYPTSWAP_ENABLED:-0}"', SRC)


# --- TP-R1 follow-up: Suricata stats interval ------------------------------------

# The shape the installer writes on the fleet (captured from Germany and
# Chicago on 2026-09-25: a top-level `stats` mapping, `interval: 8`).
STOCK_SURICATA_YAML = textwrap.dedent('''\
    %YAML 1.1
    ---
    suricata-version: '8.0'
    vars:
      address-groups:
        HOME_NET: '[192.168.0.0/16]'
    stats:
      enabled: true
      interval: 8
      exception-policy: null
    outputs:
    - fast:
        enabled: true
        filename: fast.log
''')


class SuricataStatsIntervalTests(Case):
    def render(self) -> dict:
        import yaml

        # The YAML rewrite is the first PYEOF heredoc after the function opens.
        # lib.function_text stops at the first column-0 "}", which is now the
        # logrotate policy's (A1-ARGON-F1 moved it above the rewrite).
        body = SRC[SRC.index("\ninstall_data_ids_ips() {\n"):]
        start = body.index("<<'PYEOF'\n") + len("<<'PYEOF'\n")
        program = body[start:body.index("\nPYEOF\n", start)]
        cfg = self.sb.path("suricata.yaml")
        cfg.write_text(STOCK_SURICATA_YAML)
        script = self.sb.path("render.py")
        script.write_text(program)
        r = subprocess.run(["python3", "-I", "-B", str(script), str(cfg), "203.0.113.7/32", "1"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        text = cfg.read_text()
        self.assertTrue(text.startswith("%YAML 1.1\n---\n"))
        return yaml.safe_load(text)

    def test_stats_are_written_once_a_minute_and_stay_enabled(self) -> None:
        data = self.render()
        self.assertEqual(data["stats"]["interval"], 60)
        self.assertIs(data["stats"]["enabled"], True)
        eve = next(o["eve-log"] for o in data["outputs"] if "eve-log" in o)
        self.assertIn({"stats": {"totals": True, "threads": False, "deltas": True}}, eve["types"])
        self.assertEqual(data["nfq"]["mode"], "repeat")


if __name__ == "__main__":
    unittest.main()
