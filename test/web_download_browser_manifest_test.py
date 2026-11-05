#!/usr/bin/env python3
"""Execute the homepage's own download-manifest validator and renderer.

The browser code in web/index.html is the last gate before a visitor clicks.
This harness runs the exact inline source (no copy) under WINS_RELEASE_NODE with
a minimal DOM stand-in and checks the owner rulings of 2026-10-25: one entry per
architecture, Windows visibly labelled Unsigned under the owner waiver, Apple
entries store_pending, and every incomplete or v1 manifest refused.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "web" / "index.html"
START = "      const downloadManifestUrl = "
END = "      async function loadDownloadManifest() {"


def release_node() -> Path:
    raw = os.environ.get("WINS_RELEASE_NODE", "")
    path = Path(raw)
    if not raw or not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise SystemExit("FAIL: authenticated absolute WINS_RELEASE_NODE is required")
    return path


def browser_source() -> str:
    text = INDEX.read_text(encoding="utf-8")
    start = text.index(START)
    end = text.index(END, start)
    return text[start:end]


HARNESS = r"""
const elements = [];
globalThis.window = { location: { origin: "https://winsvpn.org" } };
globalThis.document = {
  createElement(tag) {
    const node = {
      tag, dataset: {}, attributes: {}, textContent: "", title: "", href: "",
      listeners: [], children: [], after: [],
      setAttribute(name, value) { this.attributes[name] = String(value); },
      getAttribute(name) { return this.attributes[name] ?? null; },
      addEventListener(type, fn) { if (type === "click") this.listeners.push(fn); },
      appendChild(child) { this.children.push(child); return child; },
      insertAdjacentElement(where, node) { this.after.push(node); return node; },
    };
    elements.push(node);
    return node;
  },
  getElementById() { return null; },
};
const SOURCE = Buffer.from(process.argv[1], "base64").toString("utf8");
const cases = JSON.parse(Buffer.from(process.argv[2], "base64").toString("utf8"));
const run = new Function("cases", SOURCE + `
  const results = [];
  for (const item of cases) {
    try {
      const entries = normalizedDownloadEntries(item.payload);
      const container = { children: [], replaceChildren(...nodes) { this.children = nodes; } };
      renderDownloadSurface(container, entries);
      results.push({
        name: item.name,
        ok: true,
        entries: entries.map((entry) => ({
          id: entry.id, available: entry.available, storePending: !!entry.storePending,
          unsignedLabel: entry.unsignedLabel || "", url: entry.url || null,
        })),
        rendered: container.children.map((node) => ({
          text: node.textContent,
          disabled: node.getAttribute("aria-disabled"),
          aria: node.getAttribute("aria-label"),
          status: node.dataset.downloadStatus || "",
          signature: node.dataset.downloadSignature || "",
          host: node.dataset.downloadHost || "",
          href: node.href || "",
          visibleHash: node.children.find((child) => child.className === "download-sha256")?.textContent || "",
          click: (() => {
            if (node.dataset.downloadHost !== "github-release") return null;
            const first = { prevented: false, preventDefault() { this.prevented = true; } };
            node.listeners.forEach((fn) => fn(first));
            const notice = node.after[0] || null;
            const second = { prevented: false, preventDefault() { this.prevented = true; } };
            node.listeners.forEach((fn) => fn(second));
            return {
              firstPrevented: first.prevented,
              secondPrevented: second.prevented,
              noticeText: notice ? notice.textContent : "",
              continueHref: notice && notice.children[0] ? notice.children[0].href : "",
            };
          })(),
        })),
      });
    } catch (error) {
      results.push({ name: item.name, ok: false, error: String(error && error.message) });
    }
  }
  return results;
`);
process.stdout.write(JSON.stringify(run(cases)));
"""


def receipts(filename: str) -> dict[str, object]:
    return {
        "winn_provenance": {
            "kind": "website_download_winn_provenance_receipt_v1",
            "receipt_filename": f"{filename}.winn.json",
            "receipt_sha256": "f" * 64,
            "primary": "winn/3",
            "fallback": "winn/1",
            "fallback_order": ["awg", "xray"],
        },
        "privacy": {
            "kind": "release_artifact_privacy_receipt_v1",
            "receipt_filename": f"{filename}.privacy.json",
            "receipt_sha256": "d" * 64,
        },
        "release_receipt": {
            "kind": "release_publication_receipt_v1",
            "receipt_filename": f"{filename}.release.json",
            "receipt_sha256": "e" * 64,
        },
        "publication_receipt": {
            "kind": "website_download_publication_receipt_v1",
            "receipt_filename": f"{filename}.publication.json",
            "receipt_sha256": "a" * 64,
        },
    }


def available(entry_id: str, label: str, filename: str, arch: str, signature: dict, extra: dict | None = None) -> dict:
    artifact = {
        "filename": filename,
        "sha256": "1" * 64,
        "bytes": 1000,
        "canonical_release": "1.0.16+33",
        "package_identity": "org.winsvpn.app",
        "version": "1.0.16",
        "architecture": [arch],
        "signature": signature,
        **receipts(filename),
    }
    artifact.update(extra or {})
    return {
        "id": entry_id,
        "label": label,
        "status": "available",
        "delivery": {"kind": "direct", "url": f"https://winsvpn.org/downloads/{filename}"},
        "artifact": artifact,
    }


def main() -> int:
    pending = json.loads((ROOT / "web" / "releases" / "downloads.json").read_text("utf-8"))
    waiver = "9" * 64
    unsigned_sig = {"kind": "unsigned_owner_waiver", "sha256": waiver}
    label = {"label": "Unsigned", "waiver_filename": "download-unsigned-waiver.json", "waiver_sha256": waiver}

    def with_entry(index: int, entry: dict, base: dict | None = None) -> dict:
        payload = json.loads(json.dumps(base or pending))
        payload["artifacts"][index] = entry
        return payload

    published = with_entry(0, available("windows-x64", "Windows x64", "WinsVPN-UNSIGNED-LOCAL-Setup.exe", "x64", unsigned_sig, {"unsigned_waiver": label}))
    published = with_entry(3, available("linux-x64", "Linux x64", "wins-vpn-linux-x64.tar.gz", "x64", {"kind": "publication_signature_sha256", "sha256": "c" * 64}), published)
    pinned = "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.16-33/"
    linux_sig = {"kind": "publication_signature_sha256", "sha256": "c" * 64}

    def github_entry(entry_id: str, label: str, filename: str, arch: str, url: str, signature: dict, extra: dict | None = None) -> dict:
        entry = available(entry_id, label, filename, arch, signature, extra)
        entry["delivery"] = {"kind": "github_release", "url": url}
        return entry

    github_published = with_entry(
        0,
        github_entry("windows-x64", "Windows x64", "WinsVPN-UNSIGNED-LOCAL-Setup.exe", "x64",
                     pinned + "WinsVPN-UNSIGNED-LOCAL-Setup.exe", unsigned_sig, {"unsigned_waiver": label}),
    )
    github_published = with_entry(
        3,
        github_entry("linux-x64", "Linux x64", "wins-vpn-linux-x64.tar.gz", "x64", pinned + "wins-vpn-linux-x64.tar.gz", linux_sig),
        github_published,
    )
    v1 = json.loads(json.dumps(pending))
    v1["schema"] = "winsvpn-download-manifest-v1"
    store_pending_linux = json.loads(json.dumps(pending))
    store_pending_linux["artifacts"][3]["status"] = "store_pending"
    cases = [
        {"name": "committed_pending", "payload": pending},
        {"name": "per_platform_launch", "payload": published},
        {"name": "unsigned_without_label", "payload": with_entry(0, available("windows-x64", "Windows x64", "WinsVPN-UNSIGNED-LOCAL-Setup.exe", "x64", unsigned_sig, {"unsigned_waiver": {**label, "label": ""}}))},
        {"name": "unsigned_under_signed_name", "payload": with_entry(0, available("windows-x64", "Windows x64", "WinsVPN-Setup.exe", "x64", unsigned_sig, {"unsigned_waiver": label}))},
        {"name": "unsigned_linux", "payload": with_entry(3, available("linux-x64", "Linux x64", "wins-vpn-linux-x64.tar.gz", "x64", unsigned_sig, {"unsigned_waiver": label}))},
        {"name": "arm64_entry_with_x64_artifact", "payload": with_entry(1, available("windows-arm64", "Windows ARM64", "WinsVPN-UNSIGNED-LOCAL-Setup.exe", "x64", unsigned_sig, {"unsigned_waiver": label}))},
        {"name": "v1_schema", "payload": v1},
        {"name": "android_available", "payload": with_entry(2, available("android", "Android", "wins-vpn-android.apk", "arm64-v8a", {"kind": "apk_signer_certificate_sha256", "sha256": "4ebbff15a1274e7b072767fa37f00e8ffbeafab80cb61b51a5ab598af6dbe6ee"}, {"architecture": ["arm64-v8a", "armeabi-v7a", "x86_64"]}))},
        {"name": "signed_windows_available", "payload": with_entry(0, available("windows-x64", "Windows x64", "WinsVPN-Setup.exe", "x64", {"kind": "authenticode_signer_certificate_sha256", "sha256": "b" * 64}, {"windows_verification": {"kind": "winverifytrust_receipt_v1", "receipt_filename": "WinsVPN-Setup.exe.authenticode.json", "receipt_sha256": "d" * 64, "approved_signer_subject": "CN=Win's VPN", "approved_signer_certificate_sha256": "b" * 64}}))},
        {"name": "github_pinned", "payload": github_published},
        {"name": "github_old_tag", "payload": with_entry(3, github_entry("linux-x64", "Linux x64", "wins-vpn-linux-x64.tar.gz", "x64", pinned.replace("v1.0.16-33", "v1.0.0") + "wins-vpn-linux-x64.tar.gz", linux_sig))},
        {"name": "github_plus_tag", "payload": with_entry(3, github_entry("linux-x64", "Linux x64", "wins-vpn-linux-x64.tar.gz", "x64", pinned.replace("v1.0.16-33", "v1.0.16+33") + "wins-vpn-linux-x64.tar.gz", linux_sig))},
        {"name": "github_other_repo", "payload": with_entry(3, github_entry("linux-x64", "Linux x64", "wins-vpn-linux-x64.tar.gz", "x64", pinned.replace("winsvpn-downloads", "fork") + "wins-vpn-linux-x64.tar.gz", linux_sig))},
        {"name": "store_pending_direct_entry", "payload": store_pending_linux},
    ]
    proc = subprocess.run(
        [
            str(release_node()),
            "-e",
            HARNESS,
            base64.b64encode(browser_source().encode("utf-8")).decode("ascii"),
            base64.b64encode(json.dumps(cases).encode("utf-8")).decode("ascii"),
        ],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        print(f"FAIL: node harness exit {proc.returncode}")
        return 1
    results = {row["name"]: row for row in json.loads(proc.stdout)}
    failures: list[str] = []

    row = results["committed_pending"]
    ids = [entry["id"] for entry in row.get("entries", [])]
    if not row["ok"] or ids != ["windows-x64", "windows-arm64", "android", "linux-x64", "linux-arm64", "macos", "ios"]:
        failures.append(f"committed manifest is not seven pending per-architecture entries: {row}")
    elif any(entry["available"] for entry in row["entries"]):
        failures.append("committed manifest exposes an available entry")
    else:
        rendered = {item["text"]: item for item in row["rendered"]}
        if rendered["MacBook (macOS)"]["status"] != "store_pending" or "App Store release pending" not in rendered["iPhone (iOS)"]["aria"]:
            failures.append(f"Apple entries are not rendered store_pending: {row['rendered']}")

    row = results["per_platform_launch"]
    if not row["ok"]:
        failures.append(f"per-platform launch manifest refused: {row}")
    else:
        texts = [item["text"] for item in row["rendered"]]
        windows = row["rendered"][0]
        if texts[0] != "Windows x64 (Unsigned)" or windows["signature"] != "unsigned" or "Unsigned installer" not in windows["aria"]:
            failures.append(f"unsigned Windows button is not visibly labelled: {windows}")
        if texts[3] != "Linux x64" or row["entries"][3]["url"] != "https://winsvpn.org/downloads/wins-vpn-linux-x64.tar.gz":
            failures.append(f"Linux entry rendered wrongly: {row['rendered'][3]} {row['entries'][3]}")
        if row["rendered"][1]["disabled"] != "true" or row["rendered"][5]["status"] != "store_pending":
            failures.append("non-published entries are not disabled while others launch")

    row = results["github_pinned"]
    if not row["ok"]:
        failures.append(f"pinned GitHub release manifest refused: {row}")
    else:
        windows, linux = row["rendered"][0], row["rendered"][3]
        if windows["href"] != pinned + "WinsVPN-UNSIGNED-LOCAL-Setup.exe" or windows["host"] != "github-release" or windows["text"] != "Windows x64 (Unsigned)":
            failures.append(f"pinned GitHub Windows button is wrong: {windows}")
        if linux["href"] != pinned + "wins-vpn-linux-x64.tar.gz" or linux["host"] != "github-release":
            failures.append(f"pinned GitHub Linux button is wrong: {linux}")
        click = windows["click"] or {}
        if (
            "1" * 64 not in windows["visibleHash"]
            or "1" * 64 not in linux["visibleHash"]
            or
            not click.get("firstPrevented")
            or click.get("secondPrevented")
            or "1" * 64 not in click.get("noticeText", "")
            or click.get("continueHref") != pinned + "WinsVPN-UNSIGNED-LOCAL-Setup.exe"
        ):
            failures.append(f"expected SHA-256 is not shown before navigating to GitHub: {click}")

    for name in (
        "android_available",
        "signed_windows_available",
        "github_old_tag",
        "github_plus_tag",
        "github_other_repo",
        "unsigned_without_label",
        "unsigned_under_signed_name",
        "unsigned_linux",
        "arm64_entry_with_x64_artifact",
        "v1_schema",
        "store_pending_direct_entry",
    ):
        if results[name]["ok"]:
            failures.append(f"{name} was accepted by the browser validator")

    if failures:
        print("FAIL")
        for item in failures:
            print(item)
        return 1
    print(f"PASS {len(cases)} browser manifest cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
