#!/usr/bin/env python3
"""Gemini L05 F-2 and F-3 on the Core installer, offline.

F-2: install_core_ids_ips must never leave a refused Suricata configuration or
ruleset behind, because the package-security rollback validates and restarts
whatever rule files are on disk (its preimage holds none of them). The
installer's own install_core_ids_ips and its suricata_deploy_snapshot/restore
pair run against a private root; only the host-mutating edges are doubles
(suricata, suricata-update, systemctl, ip, chown, the YAML rewrite and the
log-rotation proof). The generated action-policy script runs for real.

F-3: every warning the Core weekly maintenance logs must also be counted, so
weekly-maintenance.status reports it, as on the control and data planes.
"""
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest


INSTALLER = Path(os.environ.get(
    'WINS_AUDIT_INSTALLER',
    str(Path(__file__).with_name('wins_core_server_setup_ONETOUCH.sh')),
))
BASH = shutil.which('bash') or '/bin/bash'

OLD_CONFIG = 'vars:\n  address-groups: {}\nlast-good: config\n'
OLD_RULES = 'alert http any any -> any any (msg:"known good"; sid:2000001; rev:1;)\n'
OLD_LOCAL = ''.join(
    'drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"WINS CORE IPS old %d"; sid:992000%d; rev:1;)\n'
    % (n, n) for n in range(1, 6))
BROKEN_RULE = 'alert http any any -> any any (msg:"upstream"; BROKEN_SYNTAX_KEYWORD; sid:2000002; rev:1;)'
BYPASS_RULE = 'pass ip any any -> any any (msg:"unreviewed bypass"; sid:2200001; rev:1;)'
GOOD_RULE = 'alert http any any -> any any (msg:"new reviewed"; sid:2000003; rev:1;)'


def function_text(text, name, required=True):
    match = re.search(r'^' + re.escape(name) + r'\(\) \{.*?^\}\n', text, re.M | re.S)
    if match is None and required:
        raise AssertionError(f'{name} not found in {INSTALLER}')
    return match.group() if match else ''


class CoreIdsDeploySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('WINS_AUDIT_TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'root'
        self.bin = Path(self.temp.name) / 'bin'
        self.log = Path(self.temp.name) / 'calls.log'
        for sub in ('etc/suricata', 'etc/systemd/system', 'etc/logrotate.d', 'etc/tmpfiles.d',
                    'var/lib/suricata/rules', 'usr/local/bin', 'run', 'proc'):
            (self.root / sub).mkdir(parents=True)
        self.bin.mkdir()
        self.cfg = self.root / 'etc/suricata/suricata.yaml'
        self.rules_dir = self.root / 'var/lib/suricata/rules'
        self.rules = self.rules_dir / 'suricata.rules'
        self.local = self.rules_dir / 'wins-local.rules'
        self.cfg.write_text(OLD_CONFIG)
        (self.root / 'proc/meminfo').write_text('MemTotal:        4000000 kB\n')
        self.queue = Path(self.temp.name) / 'nfnetlink_queue'
        self.queue.write_text('0 0 0 0 0 0 0 0 0\n')

        text = INSTALLER.read_text()
        body = re.search(r'^install_core_ids_ips\(\) \{\n.*?(?=^[A-Za-z_][A-Za-z0-9_]*\(\) \{)',
                         text, re.M | re.S)
        self.assertIsNotNone(body, 'install_core_ids_ips not found')
        body = body.group()
        r = str(self.root)
        for old, new in (
            ('/var/lib/suricata/rules', r + '/var/lib/suricata/rules'),
            ('/etc/suricata/', r + '/etc/suricata/'),
            ('/etc/systemd/system/', r + '/etc/systemd/system/'),
            ('/etc/logrotate.d/', r + '/etc/logrotate.d/'),
            ('/etc/tmpfiles.d/', r + '/etc/tmpfiles.d/'),
            ('/usr/local/bin/wins-suricata-action-policy', r + '/usr/local/bin/wins-suricata-action-policy'),
            ('/run/wins-suricata-deploy', r + '/run/wins-suricata-deploy'),
            ('/proc/meminfo', r + '/proc/meminfo'),
        ):
            body = body.replace(old, new)
        self.functions = (function_text(text, 'suricata_deploy_snapshot', required=False)
                          + function_text(text, 'suricata_deploy_restore', required=False)
                          + body)

        self.write_stub('suricata', '''case "${1:-}" in
  --build-info) echo 'NFQ support: yes' ;;
  -T) ! grep -q BROKEN "$WINS_TEST_RULES/suricata.rules" ;;
  *) exit 64 ;;
esac
''')
        self.write_stub('suricata-update', '''out="$WINS_TEST_RULES"
while (($#)); do
  if [[ "$1" == --output ]]; then out="$2"; shift; fi
  shift
done
printf '%s\\n' "$WINS_TEST_NEW_RULE" > "$out/suricata.rules"
''')
        self.write_stub('systemctl', '''case "${1:-}" in
  restart|start) printf 'started-with %s\\n' "$(cat "$WINS_TEST_RULES/suricata.rules")" >> "$WINS_TEST_LOG" ;;
  show) printf '%s\\n' '{ argv[]=/usr/bin/suricata -D --pidfile /run/suricata.pid -q 0 -c /etc/suricata/suricata.yaml }' ;;
esac
exit 0
''')
        # GNU wc prints a bare count for stdin; BSD wc pads it. The generated
        # action-policy script compares the bare count.
        self.write_stub('wc', '/usr/bin/wc "$@" | sed "s/^ *//"\n')

    def write_stub(self, name, body):
        path = self.bin / name
        path.write_text('#!' + BASH + '\n' + body)
        path.chmod(0o700)

    def run_install(self, new_rule, rotation_rc=0, python_rc=0):
        script = '\n'.join([
            'set -Eeuo pipefail',
            'log() { printf "LOG %s\\n" "$*"; }',
            'warn() { printf "WARN %s\\n" "$*"; }',
            'err() { printf "ERR %s\\n" "$*" >&2; }',
            'ip() { :; }',
            'chown() { :; }',
            # python_rc != 0 models a rewrite that fails after it has
            # started writing (for example ENOSPC in write_text).
            'python3() { cat >/dev/null; printf "%s\\n" "vars: {}" "rewritten: config" > "$2"; '
            f'return {python_rc}; }}',
            f'wins_ensure_suricata_rotation() {{ return {rotation_rc}; }}',
            'wait_for_suricata() { :; }',
            'install_core_failure_hold_firewall() { printf "HOLD %s\\n" "$*" >> "$WINS_TEST_LOG"; }',
            'INSTALL_CORE_IDS_IPS=1',
            'INSTALL_CORE_IDS_IPS_DEFAULT=1',
            'CORE_INGRESS_CIDR=10.9.1.0/24',
            'CORE_NFQUEUE_PROC_PATH=' + shlex.quote(str(self.queue)),
            self.functions,
            'install_core_ids_ips',
        ])
        env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                   WINS_TEST_RULES=str(self.rules_dir), WINS_TEST_NEW_RULE=new_rule,
                   WINS_TEST_LOG=str(self.log))
        return subprocess.run([BASH, '-c', script], env=env, text=True,
                              capture_output=True, timeout=30)

    def protected_host(self):
        self.rules.write_text(OLD_RULES)
        self.local.write_text(OLD_LOCAL)

    def leftovers(self):
        return sorted(str(p) for d in (self.rules_dir, self.root / 'run')
                      for p in d.iterdir() if p.is_dir())

    def started(self):
        return self.log.read_text() if self.log.exists() else ''

    def test_failed_config_test_puts_last_good_set_back(self):
        self.protected_host()
        result = self.run_install(BROKEN_RULE)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.rules.read_text(), OLD_RULES,
                         'a ruleset that failed suricata -T stayed for the rollback to validate')
        self.assertEqual(self.cfg.read_text(), OLD_CONFIG)
        self.assertEqual(self.local.read_text(), OLD_LOCAL)
        self.assertEqual(self.leftovers(), [])
        self.assertNotIn('started-with', self.started())

    def test_refused_bypass_import_never_reaches_active_rules(self):
        self.protected_host()
        result = self.run_install(BYPASS_RULE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('blocking or bypass action', result.stderr)
        self.assertEqual(self.rules.read_text(), OLD_RULES,
                         'a refused bypass rule stayed for the rollback to restart Suricata with')
        self.assertEqual(self.cfg.read_text(), OLD_CONFIG)
        self.assertEqual(self.local.read_text(), OLD_LOCAL)
        self.assertEqual(self.leftovers(), [])
        self.assertNotIn('started-with', self.started())

    def test_fresh_host_refusal_removes_the_new_files(self):
        result = self.run_install(BROKEN_RULE)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.rules.exists(), 'a refused first ruleset stayed on a fresh host')
        self.assertFalse(self.local.exists())
        self.assertEqual(self.cfg.read_text(), OLD_CONFIG)
        self.assertEqual(self.leftovers(), [])

    def test_failed_rotation_gate_leaves_the_set_untouched(self):
        """A1-ARGON-F1: the log-rotation gate used to refuse after the YAML
        rewrite and the local rules, with no restore. A refusal must leave the
        Suricata set as it was and no snapshot directory in /run."""
        self.protected_host()
        result = self.run_install(GOOD_RULE, rotation_rc=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.cfg.read_text(), OLD_CONFIG,
                         'the unvalidated rewrite stayed after the rotation gate refused')
        self.assertEqual(self.local.read_text(), OLD_LOCAL)
        self.assertEqual(self.rules.read_text(), OLD_RULES)
        self.assertEqual(self.leftovers(), [])
        self.assertNotIn('started-with', self.started())

    def test_failed_yaml_rewrite_puts_last_good_set_back(self):
        """A1-ARGON-F1: a rewrite that fails part way must not leave a
        damaged suricata.yaml or the snapshot directory behind."""
        self.protected_host()
        result = self.run_install(GOOD_RULE, python_rc=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.cfg.read_text(), OLD_CONFIG,
                         'a partly rewritten suricata.yaml stayed after the rewrite failed')
        self.assertEqual(self.local.read_text(), OLD_LOCAL)
        self.assertEqual(self.rules.read_text(), OLD_RULES)
        self.assertEqual(self.leftovers(), [])
        self.assertNotIn('started-with', self.started())

    def test_fresh_host_rotation_refusal_removes_the_new_files(self):
        result = self.run_install(GOOD_RULE, rotation_rc=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.local.exists(), 'wins-local.rules stayed on a fresh host')
        self.assertFalse(self.rules.exists())
        self.assertEqual(self.cfg.read_text(), OLD_CONFIG)
        self.assertEqual(self.leftovers(), [])

    def test_valid_import_is_promoted_and_nothing_is_left_behind(self):
        self.protected_host()
        result = self.run_install(GOOD_RULE)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.rules.read_text(), GOOD_RULE + '\n')
        self.assertIn('rewritten: config', self.cfg.read_text())
        self.assertEqual(self.leftovers(), [])
        self.assertIn('started-with ' + GOOD_RULE, self.started())
        self.assertNotIn('HOLD', self.started())


class CoreWeeklyMaintenanceWarningTests(unittest.TestCase):
    def run_maintenance(self, *commands):
        text = INSTALLER.read_text()
        start = text.index("cat > /usr/local/bin/wins-weekly-maintenance <<'EOF'\n")
        source = text[start:].split('\nEOF', 1)[0]
        functions = [function_text(source, name) for name in (
            'run_step', 'wait_for_package_manager', 'restore_unattended_upgrades',
            'write_maintenance_status')]
        functions.append(next(line for line in source.splitlines() if line.startswith('maint_warn()')))
        final = source[source.index('if (( MAINT_WARNINGS > 0 )); then'):]
        final = final[:final.index('\nfi') + 3]
        with tempfile.TemporaryDirectory(dir=os.environ.get('WINS_AUDIT_TMPDIR')) as directory:
            root = Path(directory)
            script = '\n'.join([
                'set -Eeuo pipefail',
                'LOG_FILE=' + shlex.quote(str(root / 'maintenance.log')),
                'STATUS_FILE=' + shlex.quote(str(root / 'maintenance.status')),
                'MAINT_ROLE=core-hop',
                'MAINT_WARNINGS=0',
                'DISK_ROOT_PCT=1; SWAP_STATE=protected',
                'OS_REBOOT_REQUIRED=0; OS_REBOOT_REASONS=none',
                'OS_RUNNING_KERNEL=fixture; OS_EXPECTED_KERNEL=fixture',
                'OS_HELD=none; OS_UPGRADABLE=none',
                'hostname() { printf "fixture\\n"; }',
                'log() { printf "%s\\n" "$*"; }',
                'sleep() { :; }',
                'package_manager_busy() { return 0; }',
                'systemctl() { return 1; }',
                *functions,
                *commands,
                final,
                'cat "$STATUS_FILE"',
            ])
            result = subprocess.run([BASH, '-c', script], capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout

    def test_failed_step_is_counted(self):
        output = self.run_maintenance('run_step "apt update" false')
        self.assertIn('WARN apt update failed; continuing maintenance', output)
        self.assertIn('outcome=completed-with-warnings', output)
        self.assertIn('warnings=1', output)

    def test_busy_package_manager_is_counted(self):
        output = self.run_maintenance('wait_for_package_manager || true')
        self.assertIn('WARN package manager remained busy for 300s', output)
        self.assertIn('outcome=completed-with-warnings', output)
        self.assertIn('warnings=1', output)

    def test_unrestored_security_updates_are_counted(self):
        output = self.run_maintenance('restore_unattended_upgrades')
        self.assertIn('WARN automatic security-update services could not be restored', output)
        self.assertIn('outcome=completed-with-warnings', output)
        self.assertIn('warnings=1', output)

    def test_clean_run_stays_ok(self):
        output = self.run_maintenance('run_step "apt update" true')
        self.assertIn('outcome=ok', output)
        self.assertIn('warnings=0', output)


if __name__ == '__main__':
    unittest.main()
