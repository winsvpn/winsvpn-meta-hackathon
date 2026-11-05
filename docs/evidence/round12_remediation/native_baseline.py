#!/usr/bin/env python3
"""Check the two residual macOS helper failures against exact pre-edit test bytes."""
import json
from pathlib import Path
import sys
import types
import unittest

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
baseline = json.loads((OUT / 'baseline.json').read_text())
relative = 'tools/native_messaging/test_native_host_registration.py'
source = (Path(baseline['backup']) / relative).read_text()
module = types.ModuleType('round12_native_baseline')
module.__file__ = str(ROOT / relative)
sys.modules[module.__name__] = module
sys.path.insert(0, str(ROOT / 'tools/native_messaging'))
exec(compile(source, module.__file__, 'exec'), module.__dict__)
cls = module.MacOSNativeHostHelperContractTests
names = ['test_macos_helper_first_rollback_failure_still_restores_later_files',
         'test_macos_helper_owner_blocks_edge_without_touching_live_registration']
result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(cls(name) for name in names))
expected = len(result.failures) == 2 and not result.errors and all(
    'source-freeze receipt' in trace for case, trace in result.failures)
summary = dict(tests_run=result.testsRun, failures=[case.id() for case, trace in result.failures],
               same_source_freeze_failures=expected)
(OUT / 'native-baseline-results.json').write_text(json.dumps(summary, indent=2) + '\n')
raise SystemExit(0 if expected else 1)
