#!/usr/bin/env python3
"""Fail-closed download-routing tests for web/_worker.js.

Pass a worker path as argv[1] to point at a private copy (mutation harness).
Default is the deploy-tree worker. The test proves /downloads paths reach only
Pages' static-asset binding, ignore the empty redirect table, and reject the
HTML homepage fallback used for missing assets.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path

DEPLOY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKER = DEPLOY_ROOT / "web" / "_worker.js"
CALL_NEEDLE = "downloadAssetDecision("
FN_RE = re.compile(
    r"export function downloadAssetDecision\(pathname, redirects, authorizedPaths\) \{.*?\n\}",
    re.S,
)


def release_node() -> Path:
    raw = os.environ.get("WINS_RELEASE_NODE", "")
    path = Path(raw)
    if not raw or not path.is_absolute() or path.is_symlink():
        raise SystemExit("FAIL: authenticated absolute WINS_RELEASE_NODE is required")
    try:
        info = path.stat()
    except OSError as exc:
        raise SystemExit(f"FAIL: WINS_RELEASE_NODE is unavailable: {exc}") from exc
    if not path.is_file() or not os.access(path, os.X_OK) or info.st_nlink != 1:
        raise SystemExit("FAIL: WINS_RELEASE_NODE must be one executable regular file")
    return path


def node_environment() -> dict[str, str]:
    result = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
    for name in ("HOME", "TMPDIR"):
        value = os.environ.get(name)
        if value:
            result[name] = value
    return result


def extract_function(source: str) -> str:
    match = FN_RE.search(source)
    if not match:
        raise SystemExit("FAIL: downloadAssetDecision function not found in worker source")
    return match.group(0)


def run_cases(function_src: str, cases: list[dict]) -> list[dict]:
    harness = f"""
{function_src}
const cases = {json.dumps(cases)};
const out = [];
for (const c of cases) {{
  const redirects = new Map(c.redirects || []);
  const authorizedPaths = new Set(c.authorizedPaths || []);
  const got = downloadAssetDecision(c.pathname, redirects, authorizedPaths);
  out.push({{ name: c.name, expected: c.expected, got }});
}}
process.stdout.write(JSON.stringify(out));
"""
    proc = subprocess.run(
        [str(release_node()), "--input-type=module", "-e", harness],
        check=False,
        capture_output=True,
        text=True,
        env=node_environment(),
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"FAIL: node harness exit {proc.returncode}")
    return json.loads(proc.stdout)


def run_manifest_case(source: str, payload: dict) -> list[str]:
    module_url = "data:text/javascript;base64," + base64.b64encode(
        source.encode("utf-8")
    ).decode("ascii")
    harness = """
const worker = await import(process.argv[1]);
const paths = [...worker.downloadManifestBoundPaths(JSON.parse(process.argv[2]))].sort();
process.stdout.write(JSON.stringify(paths));
"""
    proc = subprocess.run(
        [
            str(release_node()),
            "--input-type=module",
            "-e",
            harness,
            module_url,
            json.dumps(payload, separators=(",", ":")),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=node_environment(),
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"FAIL: manifest harness exit {proc.returncode}")
    return json.loads(proc.stdout)


def main() -> int:
    worker = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_WORKER
    source = worker.read_text(encoding="utf-8")
    failures = []

    if "const downloadRedirects = new Map();" not in source:
        failures.append("release download redirect table is not explicitly empty")
    if 'if (target) return { action: "redirect", target };' in source:
        failures.append("downloadAssetDecision still honors placeholder redirects")
    if "Response.redirect(downloadDecision.target" in source:
        failures.append("Worker still 302s download placeholder targets")
    if 'downloadDecision.action === "asset"' not in source:
        failures.append("Worker does not route downloads through the asset binding")
    if "downloadManifestBoundPaths" not in source:
        failures.append("Worker does not derive the download allowlist from the deployed manifest")
    if "export function downloadManifestBoundPaths" not in source:
        failures.append("download manifest allowlist is not executable by the regression harness")
    if 'contentType.toLowerCase().includes("text/html")' not in source:
        failures.append("Worker does not reject the HTML homepage fallback")
    if '"x-wins-download-route": "static-asset"' not in source:
        failures.append("Worker does not mark the live download asset route")
    if CALL_NEEDLE not in source:
        failures.append(f"fetch() does not call {CALL_NEEDLE!r}")
    if "env.ASSETS.fetch(request)" not in source:
        failures.append("ASSETS.fetch(request) missing — cannot check order")
    call_at = source.find(CALL_NEEDLE)
    assets_at = source.find("env.ASSETS.fetch(request)")
    if call_at < 0 or assets_at < 0 or call_at > assets_at:
        failures.append("downloadAssetDecision is not invoked before ASSETS.fetch(request)")

    function_src = extract_function(source)
    cases = [
        {
            "name": "empty_map_apk_static_path",
            "pathname": "/downloads/wins-vpn-android.apk",
            "redirects": [],
            "expected": {"action": "not_found"},
        },
        {
            "name": "empty_map_exe_static_path",
            "pathname": "/downloads/WinsVPN-Setup.exe",
            "redirects": [],
            "expected": {"action": "not_found"},
        },
        {
            "name": "empty_map_downloads_dir",
            "pathname": "/downloads",
            "redirects": [],
            "expected": {"action": "not_found"},
        },
        {
            "name": "empty_map_downloads_slash",
            "pathname": "/downloads/",
            "redirects": [],
            "expected": {"action": "not_found"},
        },
        {
            "name": "index_continues",
            "pathname": "/index.html",
            "redirects": [],
            "expected": {"action": "continue"},
        },
        {
            "name": "releases_manifest_continues",
            "pathname": "/releases/downloads.json",
            "redirects": [],
            "expected": {"action": "continue"},
        },
        {
            "name": "populated_redirect_map_stays_blocked",
            "pathname": "/downloads/wins-vpn-android-20260812.apk",
            "redirects": [
                [
                    "/downloads/wins-vpn-android-20260812.apk",
                    "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.0/wins-vpn-android.apk",
                ]
            ],
            "expected": {"action": "not_found"},
        },
        {
            "name": "github_placeholder_stays_blocked",
            "pathname": "/downloads/WinsVPN-Setup.exe",
            "redirects": [
                [
                    "/downloads/WinsVPN-Setup.exe",
                    "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.0/WinsVPN-Setup.exe",
                ]
            ],
            "expected": {"action": "not_found"},
        },
        {
            "name": "unmapped_sibling_stays_blocked",
            "pathname": "/downloads/wins-vpn-android.apk",
            "redirects": [
                [
                    "/downloads/wins-vpn-android-20260812.apk",
                    "https://example.invalid/wins-vpn-android-20260812.apk",
                ]
            ],
            "expected": {"action": "not_found"},
        },
        {
            "name": "manifest_authorized_asset_uses_static_binding",
            "pathname": "/downloads/wins-vpn-linux-x64.tar.gz",
            "redirects": [],
            "authorizedPaths": ["/downloads/wins-vpn-linux-x64.tar.gz"],
            "expected": {"action": "asset"},
        },
        {
            "name": "manifest_authorization_is_exact_path_only",
            "pathname": "/downloads/wins-vpn-linux-arm64.tar.gz",
            "redirects": [],
            "authorizedPaths": ["/downloads/wins-vpn-linux-x64.tar.gz"],
            "expected": {"action": "not_found"},
        },
        {
            "name": "traversal_dotdot_encoded_blocked",
            "pathname": "/downloads/%2e%2e/index.html",
            "redirects": [],
            "authorizedPaths": ["/downloads/wins-vpn-linux-x64.tar.gz"],
            "expected": {"action": "not_found"},
        },
        {
            "name": "traversal_double_encoded_blocked",
            "pathname": "/downloads/%252e%252e/index.html",
            "redirects": [],
            "authorizedPaths": ["/downloads/wins-vpn-linux-x64.tar.gz"],
            "expected": {"action": "not_found"},
        },
        {
            "name": "traversal_backslash_blocked",
            "pathname": "/downloads/..\\index.html",
            "redirects": [],
            "authorizedPaths": ["/downloads/wins-vpn-linux-x64.tar.gz"],
            "expected": {"action": "not_found"},
        },
        {
            "name": "traversal_null_byte_blocked",
            "pathname": "/downloads/wins-vpn-linux-x64.tar.gz%00",
            "redirects": [],
            "authorizedPaths": ["/downloads/wins-vpn-linux-x64.tar.gz"],
            "expected": {"action": "not_found"},
        },
        {
            "name": "traversal_dot_segment_blocked",
            "pathname": "/downloads/./wins-vpn-linux-x64.tar.gz",
            "redirects": [],
            "authorizedPaths": ["/downloads/wins-vpn-linux-x64.tar.gz"],
            "expected": {"action": "not_found"},
        },
        {
            "name": "pkg_path_blocked",
            "pathname": "/pkg",
            "redirects": [],
            "authorizedPaths": ["/downloads/wins-vpn-linux-x64.tar.gz"],
            "expected": {"action": "not_found"},
        },
        {
            "name": "pkg_child_blocked",
            "pathname": "/pkg/test.tar.gz",
            "redirects": [],
            "authorizedPaths": ["/downloads/wins-vpn-linux-x64.tar.gz"],
            "expected": {"action": "not_found"},
        },
    ]
    results = run_cases(function_src, cases)
    for row in results:
        got = row["got"]
        expected = row["expected"]
        if got != expected:
            failures.append(f"{row['name']}: expected {expected} got {got}")

    filename = "wins-vpn-linux-x64.tar.gz"
    receipts = {
        key: {
            "receipt_filename": f"{filename}.{suffix}.json",
            "receipt_sha256": "b" * 64,
        }
        for key, suffix in (
            ("winn_provenance", "winn"),
            ("privacy", "privacy"),
            ("release_receipt", "release"),
            ("publication_receipt", "publication"),
        )
    }
    manifest_paths = run_manifest_case(
        source,
        {
            "schema": "winsvpn-download-manifest-v2",
            "release_id": "v1.0.16+33",
            "artifacts": [
                {
                    "id": "linux-x64",
                    "status": "available",
                    "delivery": {
                        "kind": "direct",
                        "url": f"https://winsvpn.org/downloads/{filename}",
                    },
                    "artifact": {
                        "filename": filename,
                        "sha256": "a" * 64,
                        "bytes": 1,
                        "signature": {
                            "kind": "publication_signature_sha256",
                            "sha256": "c" * 64,
                        },
                        **receipts,
                    },
                }
            ],
        },
    )
    sigstore_path = f"/downloads/{filename}.sigstore.json"
    if sigstore_path not in manifest_paths:
        failures.append("manifest-authorized Linux Sigstore bundle stays blocked")

    if failures:
        print("FAIL")
        for item in failures:
            print(item)
        return 1
    print(f"PASS {len(results) + 1} cases worker={worker}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
