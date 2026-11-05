#!/usr/bin/env python3
"""
Generate dynamic SHA-256 and metadata manifest for all downloadable binaries
located in /var/www/winsvpn/downloads/.
Can be run standalone or triggered via systemd path unit/cron on upload.
"""

import os
import sys
import json
import hashlib
from datetime import datetime, timezone

DOWNLOAD_DIR = os.environ.get("DOWNLOAD_DIR", "/var/www/winsvpn/downloads")
OUTPUT_FILE = os.path.join(DOWNLOAD_DIR, "hashes.json")
CHECKSUM_FILE = os.path.join(DOWNLOAD_DIR, "SHA256SUMS.txt")

PLATFORM_META = {
    "wins-vpn-android.apk": {
        "platform": "Android",
        "label": "Universal APK (ARM64, ARMv7, x86_64)",
        "verify_cmd": "shasum -a 256 wins-vpn-android.apk"
    },
    "wins-vpn-android-tv.apk": {
        "platform": "Android TV",
        "label": "Leanback Android TV APK",
        "verify_cmd": "shasum -a 256 wins-vpn-android-tv.apk"
    },
    "WinsVPN-Setup.exe": {
        "platform": "Windows",
        "label": "Windows 64-bit Installer (x64)",
        "verify_cmd": "CertUtil -hashfile WinsVPN-Setup.exe SHA256"
    },
    "WinsVPN-Setup-arm64.exe": {
        "platform": "Windows",
        "label": "Windows ARM64 Installer",
        "verify_cmd": "CertUtil -hashfile WinsVPN-Setup-arm64.exe SHA256"
    },
    "WinsVPN-macOS.zip": {
        "platform": "macOS",
        "label": "macOS Universal App Bundle",
        "verify_cmd": "shasum -a 256 WinsVPN-macOS.zip"
    },
    "wins-vpn-linux-x64.tar.gz": {
        "platform": "Linux",
        "label": "Linux x86_64 Standalone Tarball",
        "verify_cmd": "sha256sum wins-vpn-linux-x64.tar.gz"
    },
    "wins-vpn-linux-arm64.tar.gz": {
        "platform": "Linux",
        "label": "Linux ARM64 Standalone Tarball",
        "verify_cmd": "sha256sum wins-vpn-linux-arm64.tar.gz"
    },
    "wins-vpn-companion-chrome.zip": {
        "platform": "Chrome",
        "label": "Chrome Companion Extension",
        "verify_cmd": "shasum -a 256 wins-vpn-companion-chrome.zip"
    },
    "wins-vpn-companion-firefox.xpi": {
        "platform": "Firefox",
        "label": "Firefox Signed Extension (.xpi)",
        "verify_cmd": "shasum -a 256 wins-vpn-companion-firefox.xpi"
    },
    "wins-vpn-companion-firefox.zip": {
        "platform": "Firefox",
        "label": "Firefox Extension Archive",
        "verify_cmd": "shasum -a 256 wins-vpn-companion-firefox.zip"
    },
    "wins-vpn-companion-edge.zip": {
        "platform": "Edge",
        "label": "Microsoft Edge Extension",
        "verify_cmd": "CertUtil -hashfile wins-vpn-companion-edge.zip SHA256"
    },
    "wins-vpn-proxy-safari.zip": {
        "platform": "Safari",
        "label": "Safari Extension Package",
        "verify_cmd": "shasum -a 256 wins-vpn-proxy-safari.zip"
    }
}

def human_size(bytes_val: int) -> str:
    if bytes_val >= 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024 * 1024):.2f} GB"
    if bytes_val >= 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.1f} MB"
    if bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f} KB"
    return f"{bytes_val} B"

def compute_sha256(file_path: str) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()

def main():
    if not os.path.isdir(DOWNLOAD_DIR):
        print(f"Error: Directory {DOWNLOAD_DIR} does not exist", file=sys.stderr)
        sys.exit(1)

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = {
        "updated_at": now_iso,
        "mirror": "https://sync.winsvpn.org/downloads/",
        "files": {}
    }
    checksum_lines = []

    for filename in sorted(os.listdir(DOWNLOAD_DIR)):
        if filename.startswith(".") or filename in ("hashes.json", "SHA256SUMS.txt", "test.txt"):
            continue
        full_path = os.path.join(DOWNLOAD_DIR, filename)
        if not os.path.isfile(full_path):
            continue

        size = os.path.getsize(full_path)
        sha = compute_sha256(full_path)
        meta = PLATFORM_META.get(filename, {
            "platform": "Generic",
            "label": filename,
            "verify_cmd": f"sha256sum {filename}"
        })

        manifest["files"][filename] = {
            "sha256": sha,
            "bytes": size,
            "size": human_size(size),
            "platform": meta.get("platform", "Generic"),
            "label": meta.get("label", filename),
            "verify_cmd": meta.get("verify_cmd", f"sha256sum {filename}"),
            "url": f"https://sync.winsvpn.org/downloads/{filename}"
        }
        checksum_lines.append(f"{sha}  {filename}")

    # Write hashes.json
    tmp_json = OUTPUT_FILE + ".tmp"
    with open(tmp_json, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    os.replace(tmp_json, OUTPUT_FILE)
    os.chmod(OUTPUT_FILE, 0o644)

    # Write SHA256SUMS.txt
    tmp_txt = CHECKSUM_FILE + ".tmp"
    with open(tmp_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(checksum_lines) + "\n")
    os.replace(tmp_txt, CHECKSUM_FILE)
    os.chmod(CHECKSUM_FILE, 0o644)

    print(f"Successfully updated hashes for {len(manifest['files'])} files at {now_iso}")

if __name__ == "__main__":
    main()
