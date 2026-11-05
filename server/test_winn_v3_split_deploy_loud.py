#!/usr/bin/env python3
"""Shim. Canonical suite is tools/test_winn_protocol_v3_split_deploy.py.

validate_deployment_scripts.py subprocesses that tools path. This file
exists so a server/ winn3 test glob still finds the suite.
"""

from __future__ import annotations

import _toolchain  # noqa: F401  (V-01 preflight)
import runpy
from pathlib import Path

CANONICAL = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "test_winn_protocol_v3_split_deploy.py"
)

if __name__ == "__main__":
    runpy.run_path(str(CANONICAL), run_name="__main__")
