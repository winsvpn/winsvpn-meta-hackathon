#!/usr/bin/env python3
"""Exercise the emitted node backup with real local archives, offline.

The contract ownership check is faked because this test runs as a normal user.
Tar, compression, checksums, backup copying and retention use real files.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest


INSTALLER = Path(os.environ.get(
    'WINS_AUDIT_INSTALLER',
    str(Path(__file__).with_name('wins_data_plane_setup_ONETOUCH.sh')),
))
BASH = shutil.which('bash') or '/bin/bash'
TAR = shutil.which('gtar') or shutil.which('tar')


class NodeBackupRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('WINS_AUDIT_TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.runtime = self.root / 'run'
        self.runtime.mkdir()
        etc = self.source / 'etc/winsvpn'
        etc.mkdir(parents=True)
        (etc / 'backup.env').write_text('BACKUP_HOST_ID=fixture\nREQUIRE_REMOTE_BACKUP=0\n')
        (etc / 'node-install-contract.env').write_text(
            'WINS_NODE_INSTALL_ID=00000000-0000-0000-0000-000000000001\n'
            'WINS_NODE_INSTALL_EPOCH=1\n'
            'WINS_NODE_RESTORE_ORDER=fresh-install-then-state\n')
        (etc / 'node-install-contract.env').chmod(0o600)
        binary = self.source / 'usr/local/libexec/winn/winn3-gateway'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(os.urandom(256 * 1024))
        self.backups = self.source / 'var/backups/winsvpn'
        self.backups.mkdir(parents=True)
        self.old = self.backups / 'wins-node-backup-fixture-20200101_000000.tar.gz'
        self.old.write_bytes(b'old archive fixture')
        self.old_sum = self.old.with_name(self.old.name + '.sha256')
        self.old_sum.write_text('old checksum fixture\n')
        for path in (self.old, self.old_sum):
            os.utime(path, (time.time() - 100 * 86400,) * 2)
        self.unrelated = self.backups / 'adoption-rollback-keep.tar.gz'
        self.unrelated.write_bytes(b'keep')
        os.utime(self.unrelated, (time.time() - 100 * 86400,) * 2)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.stub('stat', '''case "$2" in
  %u) printf '0\\n' ;;
  %a) printf '600\\n' ;;
  *) exit 90 ;;
esac
''')
        self.stub('tar', 'exec ' + shlex.quote(TAR) + ' "$@"\n')
        self.stub('date', '''case "$1" in
  +%Y%m%d_%H%M%S) printf '%s\\n' "$WINS_TEST_STAMP" ;;
  +%s) printf '2000000000\\n' ;;
  *) exit 91 ;;
esac
''')
        text = INSTALLER.read_text()
        marker = "cat > /usr/local/bin/wins-node-backup <<'EOF'\n"
        script = text.split(marker, 1)[1].split('\nEOF', 1)[0] + '\n'
        self.script = self.root / 'backup.sh'
        self.script.write_text(script)

    def stub(self, name, body):
        path = self.bin / name
        path.write_text('#!' + BASH + '\n' + body)
        path.chmod(0o700)

    def backup(self, stamp):
        env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                   WINS_BACKUP_SOURCE_ROOT=str(self.source),
                   WINS_BACKUP_RUNTIME_ROOT=str(self.runtime), WINS_TEST_STAMP=stamp)
        return subprocess.run([BASH, str(self.script)], env=env, text=True,
                              capture_output=True, timeout=15)

    def test_local_backups_are_bounded_and_unrelated_restore_points_survive(self):
        for stamp in ('20261013_024500', '20261014_024500', '20261015_024500'):
            result = self.backup(stamp)
            self.assertEqual(result.returncode, 0, result.stderr)
        current = sorted(self.backups.glob('wins-node-backup-fixture-202610*.tar.gz'))
        self.assertEqual(len(current), 3)
        total = sum(path.stat().st_size for path in current)
        print(f'fixture_archive_count={len(current)} total_archive_bytes={total} oldest_archive_retained={self.old.exists()}')
        for path in current:
            result = subprocess.run([TAR, '-tzf', str(path)], capture_output=True,
                                    text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('./etc/winsvpn/node-backup-recovery.env', result.stdout)
        self.assertTrue(self.unrelated.exists())
        self.assertFalse(self.old.exists(), '100-day-old sensitive backup is never pruned')
        self.assertFalse(self.old_sum.exists())


if __name__ == '__main__':
    unittest.main()
