#!/usr/bin/env python3
"""Bounded tests of extracted weekly-maintenance result accounting."""
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
    str(Path(__file__).with_name('wins_data_plane_setup_ONETOUCH.sh')),
))
BASH = shutil.which('bash') or '/bin/bash'


class MaintenanceStatusTests(unittest.TestCase):
    def run_status(self, command):
        text = INSTALLER.read_text()
        start = text.index("cat > /usr/local/bin/wins-weekly-maintenance <<'EOF'\n")
        source = text[start:].split('\nEOF', 1)[0]
        functions = []
        for name in ('run_step', 'write_maintenance_status'):
            match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', source, re.M | re.S)
            self.assertIsNotNone(match)
            functions.append(match.group())
        functions.append(next(line for line in source.splitlines() if line.startswith('maint_warn()')))
        final = source[source.index('if (( MAINT_WARNINGS > 0 )); then'):]
        final = final[:final.index('\nfi') + 3]
        with tempfile.TemporaryDirectory(dir=os.environ.get('WINS_AUDIT_TMPDIR')) as directory:
            root = Path(directory)
            script = '\n'.join([
                'set -Eeuo pipefail',
                'LOG_FILE=' + shlex.quote(str(root / 'maintenance.log')),
                'STATUS_FILE=' + shlex.quote(str(root / 'maintenance.status')),
                'MAINT_ROLE=data-plane',
                'MAINT_WARNINGS=0',
                'DISK_ROOT_PCT=1; SWAP_STATE=protected',
                'OS_REBOOT_REQUIRED=0; OS_REBOOT_REASONS=none',
                'OS_RUNNING_KERNEL=fixture; OS_EXPECTED_KERNEL=fixture',
                'OS_HELD=none; OS_UPGRADABLE=none',
                'hostname() { printf "fixture\\n"; }',
                'log() { printf "%s\\n" "$*"; }',
                *functions,
                'run_step "fallback canary" ' + command,
                final,
                'cat "$STATUS_FILE"',
            ])
            result = subprocess.run([BASH, '-c', script], capture_output=True,
                                    text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout

    def test_failed_step_records_warning(self):
        output = self.run_status('false')
        self.assertIn('WARN fallback canary failed', output)
        self.assertIn('outcome=completed-with-warnings', output)
        self.assertIn('warnings=1', output)

    def test_successful_step_records_ok(self):
        output = self.run_status('true')
        self.assertIn('outcome=ok', output)
        self.assertIn('warnings=0', output)


if __name__ == '__main__':
    unittest.main()
