#!/usr/bin/env python3
"""Generate/check the Go proof client's deterministic gcloud pin contract."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import gcloud_custody


TOOLS = Path(__file__).resolve().parent
OUTPUT = TOOLS / "gcp_proof_client" / "gcloud_pin_generated.go"


def render(pin_manifest: Path | None = None) -> str:
    pin = gcloud_custody.validate_google_cloud_cli_pin(
        pin_manifest or TOOLS / "toolchain-pins.json"
    )
    platform = "linux_amd64"
    return f'''// Code generated from tools/toolchain-pins.json by generate_gcloud_go_pin.py. DO NOT EDIT.
package main

const (
\treviewedGcloudVersion       = "{pin['version']}"
\treviewedGcloudPlatform      = "{platform}"
\treviewedGcloudArchiveName   = "{pin['archive_name'][platform]}"
\treviewedGcloudArchiveSHA256 = "{pin['archive_sha256'][platform]}"
\tgcloudReceiptName           = ".winsvpn-gcloud-custody-v1.json"
\tgcloudCustodyArchiveName    = ".winsvpn-gcloud-official-archive"
\tgcloudReceiptContract       = "winsvpn-gcloud-install-custody-v1"
)
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != expected:
            print("generated Go gcloud pin is stale", file=sys.stderr)
            return 2
        return 0
    OUTPUT.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
