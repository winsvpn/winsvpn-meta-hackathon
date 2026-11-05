#!/usr/bin/env python3
"""Re-run Linux store engine staging tests beside the packaging tree."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[3]
ORIGIN = ROOT / "tools/test_linux_store_engine_staging.py"


def _load() -> object:
    spec = importlib.util.spec_from_file_location(
        "test_linux_store_engine_staging", ORIGIN
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load store engine staging tests")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_MODULE = _load()
LinuxStoreEngineStagingTests = _MODULE.LinuxStoreEngineStagingTests


if __name__ == "__main__":
    unittest.main()
