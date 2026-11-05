#!/usr/bin/env python3
"""Fail-closed G19 adapter for public web download custody.

This script does not reimplement APK, PE, digest, sidecar, or manifest
identity checks. It loads the exact tools/website_security_audit.py file and
requires PASS from audit_public_download_regressions, audit_downloads, and
audit_download_manifest. All-pending releases with an absent web/downloads
directory remain a pass. The file-backed import cannot be shadowed by a
regular `tools` package earlier on sys.path.
"""
from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

AUDIT_MODULE_NAME = "winsvpn_authoritative_website_security_audit"
AUDIT_MODULE_PATH = ROOT / "tools" / "website_security_audit.py"
AUTHORITATIVE_AUDITS = (
    "audit_public_download_regressions",
    "audit_downloads",
    "audit_download_manifest",
)


def load_audit_module() -> Any:
    if AUDIT_MODULE_PATH.is_symlink() or not AUDIT_MODULE_PATH.is_file():
        raise RuntimeError(f"authoritative audit path is missing or symbolic: {AUDIT_MODULE_PATH}")
    resolved = AUDIT_MODULE_PATH.resolve(strict=True)
    if resolved != AUDIT_MODULE_PATH:
        raise RuntimeError(f"authoritative audit path resolved elsewhere: {resolved}")
    spec = importlib.util.spec_from_file_location(AUDIT_MODULE_NAME, resolved)
    if spec is None or spec.loader is None:
        raise RuntimeError("authoritative audit module spec could not be created")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if Path(module.__file__).resolve(strict=True) != resolved:
        raise RuntimeError("authoritative audit module loaded from an unexpected path")
    return module


def collect_audit_results(audit_module: Any | None = None) -> list[Any]:
    module = load_audit_module() if audit_module is None else audit_module
    results: list[Any] = []
    for name in AUTHORITATIVE_AUDITS:
        fn = getattr(module, name, None)
        if not callable(fn):
            results.append(("FAIL", f"authoritative audit {name} is missing"))
            continue
        try:
            batch = fn()
        except Exception as exc:
            results.append(("FAIL", f"{name} raised: {type(exc).__name__}: {exc}"))
            continue
        if not isinstance(batch, list):
            results.append(("FAIL", f"{name} returned a non-list result"))
            continue
        if not batch:
            results.append(("FAIL", f"{name} returned no findings"))
            continue
        results.extend(batch)
    return results


def non_pass_findings(results: Iterable[Any]) -> list[str]:
    failures: list[str] = []
    for item in results:
        if not isinstance(item, tuple) or len(item) != 2:
            failures.append(f"malformed audit result: {item!r}")
            continue
        status, message = item
        if status != "PASS":
            failures.append(f"{status}: {message}")
    return failures


def report(results: Sequence[Any]) -> int:
    failures = non_pass_findings(results)
    if not results:
        print("FAIL")
        print("authoritative download audits returned no findings")
        return 1
    if failures:
        print("FAIL")
        for item in failures:
            print(item)
        return 1
    print(f"PASS {len(results)} authoritative download custody checks")
    return 0


def main() -> int:
    try:
        results = collect_audit_results()
    except Exception as exc:
        print("FAIL")
        print(f"download custody adapter could not load authoritative audits: {exc}")
        return 1
    return report(results)


if __name__ == "__main__":
    raise SystemExit(main())
