#!/usr/bin/env python3
"""Regression coverage for the fleet-reset release identity and launcher wiring."""
import ast
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import android_release_publication as publication
import test_android_release_publication as fixtures


class ReleasePipelineRegression(unittest.TestCase):
    def test_publication_identity_matches_active_builds(self):
        version, build = re.search(r'^version: (\S+)\+(\d+)$',
                                  (ROOT / 'pubspec.yaml').read_text(), re.M).groups()
        self.assertEqual(publication.EXACT_VERSION_NAME, version)
        self.assertEqual(publication.EXACT_PHONE_VERSION_CODE, int(build))
        self.assertEqual(publication.EXACT_TV_VERSION_CODE, int(build) * 100 + 2)
        self.assertEqual(publication.EXACT_WEAR_VERSION_CODE, int(build) * 100 + 1)
        for relative, code in [('android/app/build.gradle.kts', int(build)),
                               ('wear_os/app/build.gradle.kts', int(build) * 100 + 1)]:
            source = (ROOT / relative).read_text()
            self.assertIn(f'versionCode = {code}', source)
            self.assertIn(f'versionName = "{version}"', source)

    def test_current_aab_identity_and_old_code_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / 'phone.aab'
            fixtures.write_signed_package(package, 'current', kind='aab', version_code=33)
            identity = publication._extract_android_package_identity(package, 'aab')
            self.assertEqual(identity['version_code'], 33)
            fixtures.write_signed_package(package, 'stale', kind='aab', version_code=30)
            with self.assertRaises(publication.PublicationError):
                publication._extract_android_package_identity(package, 'aab')

    def test_apple_collector_identity_matches_pubspec(self):
        source = ast.parse((ROOT / 'tools/apple_final_evidence_collector.py').read_text())
        values = {node.targets[0].id: ast.literal_eval(node.value)
                  for node in source.body if isinstance(node, ast.Assign)
                  and isinstance(node.targets[0], ast.Name)
                  and node.targets[0].id in {'CANONICAL_RELEASE', 'CANONICAL_APP_VERSION',
                                            'CANONICAL_BUILD_NUMBER'}}
        release = re.search(r'^version: (\S+)$', (ROOT / 'pubspec.yaml').read_text(), re.M)[1]
        self.assertEqual(values['CANONICAL_RELEASE'], release)
        self.assertEqual(values['CANONICAL_APP_VERSION'] + '+' + values['CANONICAL_BUILD_NUMBER'], release)

    def test_macos_callers_use_authenticated_parent(self):
        for relative in ['tools/build_apple_release_candidates.sh', 'wear_os/tools/prepare_release.sh']:
            source = (ROOT / relative).read_text()
            self.assertIn('DEPENDENCY_FREEZE="${ROOT}/tools/run_release_dependency_freeze.sh"', source)
            self.assertIn('/bin/bash "${DEPENDENCY_FREEZE}"', source)
            self.assertNotIn('"${PYTHON_BIN}" "${DEPENDENCY_FREEZE}"', source)
            self.assertNotIn('wins_release_python_run "${DEPENDENCY_FREEZE}"', source)

    def test_direct_worker_stays_fail_closed(self):
        result = subprocess.run([sys.executable, str(ROOT / 'tools/release_dependency_freeze.py'),
                                 'verify-index', '--repo', str(ROOT), '--index',
                                 str(ROOT / '.artifacts/absent/RELEASE_INPUT_INDEX.json')],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 1)
        self.assertIn('production authority requires the pinned release Python worker', result.stderr)


if __name__ == '__main__':
    unittest.main()
