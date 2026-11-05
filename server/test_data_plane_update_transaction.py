#!/usr/bin/env python3
"""Offline failure tests for the generated data-plane Suricata updater.

Only the extracted updater runs. Package downloads, Suricata, systemd and
flock are test doubles. All paths that would mutate the host are redirected.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


INSTALLER = Path(os.environ.get(
    'WINS_AUDIT_INSTALLER',
    str(Path(__file__).with_name('wins_data_plane_setup_ONETOUCH.sh')),
))
BASH = shutil.which('bash') or '/bin/bash'


class UpdateTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('WINS_AUDIT_TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rules = self.root / 'rules'
        self.rules.mkdir()
        self.active = self.rules / 'suricata.rules'
        self.old = 'alert tcp any any -> any 80 (msg:"old"; sid:9100001; rev:1;)\n'
        self.active.write_text(self.old)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.log = self.root / 'activated'
        text = INSTALLER.read_text()
        marker = "cat > /usr/local/bin/wins-suricata-update <<'EOF'\n"
        script = text.split(marker, 1)[1].split('\nEOF', 1)[0] + '\n'
        script = script.replace('/run/lock/wins-suricata-update.lock', str(self.root / 'update.lock'))
        script = script.replace('/var/lib/suricata/rules', str(self.rules))
        self.script = self.root / 'update.sh'
        self.script.write_text(script)
        self.write_stub('flock', 'exit 0\n')
        self.write_stub('suricata-update', '''output="$WINS_SURICATA_RULES_DIR"
while (($#)); do
  if [[ "$1" == --output ]]; then output="$2"; shift; fi
  shift
done
printf '%s\\n' "$WINS_TEST_NEW_RULE" > "$output/suricata.rules"
''')
        self.write_stub('suricata', '[[ "${WINS_TEST_CONFIG_FAIL:-0}" != 1 ]]\n')
        self.write_stub('systemctl', '[[ "$1" == is-active ]]\n')
        self.write_stub('suricatasc', 'cat "$WINS_SURICATA_RULES_DIR/suricata.rules" >> "$WINS_TEST_ACTIVATED"\n')

    def write_stub(self, name, body):
        path = self.bin / name
        path.write_text('#!' + BASH + '\n' + body)
        path.chmod(0o700)

    def run_update(self, rule, **extra):
        env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                   WINS_SURICATA_RULES_DIR=str(self.rules),
                   WINS_SURICATA_ACTION_POLICY_BIN='/usr/bin/true',
                   WINS_TEST_NEW_RULE=rule, WINS_TEST_ACTIVATED=str(self.log), **extra)
        return subprocess.run([BASH, str(self.script)], env=env, text=True,
                              capture_output=True, timeout=10)

    def test_rejected_blocking_rule_never_replaces_live_file(self):
        result = self.run_update('drop tcp any any -> any 80 (msg:"bad"; sid:9100002; rev:1;)')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.active.read_text(), self.old,
                         'rejected blocking rule persisted at boot-time rules path')
        self.assertFalse(self.log.exists(), 'rejected blocking rules were reloaded')

    def test_failed_config_test_restores_previous_file(self):
        result = self.run_update('alert tcp any any -> any 80 (msg:"new"; sid:9100003; rev:1;)',
                                 WINS_TEST_CONFIG_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.active.read_text(), self.old,
                         'failed config test left candidate at boot-time rules path')
        if self.log.exists():
            self.assertEqual(self.log.read_text(), self.old)

    def test_valid_update_publishes_and_reloads_candidate(self):
        candidate = 'alert tcp any any -> any 80 (msg:"new"; sid:9100003; rev:1;)'
        result = self.run_update(candidate)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.active.read_text(), candidate + '\n')
        self.assertEqual(self.log.read_text(), candidate + '\n')


if __name__ == '__main__':
    unittest.main()
