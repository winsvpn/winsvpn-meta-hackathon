"""The charge keyring rename must be durable before publication continues."""

import ast
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().parents[1] / "server/wins_control_plane_setup_ONETOUCH.sh"


class ChargeKeyringDurabilityTest(unittest.TestCase):
    def test_file_and_parent_directory_are_synced(self):
        source = INSTALLER.read_text()
        start = source.index('  cat > "${APP_DIR}/main.py" <<\'PYEOF\'')
        end = source.index("\nPYEOF", start)
        module = ast.parse(source[source.index("\n", start) + 1:end])
        writer = next(
            node for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name == "_winn3_write_keyring"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "charge-keys.json"
            kinds = []
            real_fsync = os.fsync

            class OsProxy:
                def __getattr__(self, name):
                    return getattr(os, name)

                @staticmethod
                def fsync(fd):
                    kinds.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
                    real_fsync(fd)

            namespace = {
                "WINN3_CHARGE_KEYRING_PATH": str(path),
                "Path": Path,
                "json": json,
                "os": OsProxy(),
                "secrets": secrets,
            }
            exec(compile(ast.Module(body=[writer], type_ignores=[]), str(INSTALLER), "exec"), namespace)
            ring = {"active": "fixture", "keys": {}}
            namespace["_winn3_write_keyring"](ring)
            self.assertEqual(json.loads(path.read_text()), ring)
            self.assertEqual(kinds, ["file", "directory"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
