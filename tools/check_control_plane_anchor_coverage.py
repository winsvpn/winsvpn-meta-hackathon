#!/usr/bin/env python3
"""Check that every control-plane host serves a chain ending at an anchor
compiled into lib/control_plane_pinning.dart.

Run daily from the repository root on an operator machine:
    python3 tools/check_control_plane_anchor_coverage.py
or offline against saved chains named <host>.pem:
    python3 tools/check_control_plane_anchor_coverage.py \
        --chain-dir test/fixtures/control_plane_chains_20261004

Exit 0 when every host validates. Exit 1 when any host does not: Cloudflare
is serving a chain installed apps refuse, so the owner must ship a build with
the new root and post the signed update notice. Exit 2 on a usage or
environment error.
"""
import argparse
import pathlib
import re
import subprocess
import sys
import tempfile

HOSTS = (
    "winsvpn.org",
    "www.winsvpn.org",
    "sync.winsvpn.org",
    "hub.winsvpn.org",
    "sync.winsvpn.com",
    "www.winsvpn.com",
    "a.app-cloud-sync.net",
    "z.app-cloud-sync.net",
)
SOURCE = pathlib.Path("lib/control_plane_pinning.dart")
PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S
)
ANCHOR_START = "const String kControlPlanePinnedCertificatePem = '''"


def compiled_anchors() -> list[str]:
    text = SOURCE.read_text(encoding="utf-8")
    if ANCHOR_START not in text:
        raise SystemExit(f"anchor block not found in {SOURCE}")
    block = text.split(ANCHOR_START, 1)[1].split("''';", 1)[0]
    anchors = PEM_RE.findall(block)
    if not anchors:
        raise SystemExit(f"no anchor certificates in {SOURCE}")
    return anchors


def live_chain(host: str) -> list[str]:
    result = subprocess.run(
        ["openssl", "s_client", "-showcerts", "-servername", host,
         "-connect", f"{host}:443"],
        input=b"", capture_output=True, timeout=20, check=False,
    )
    return PEM_RE.findall(result.stdout.decode("utf-8", errors="replace"))


def verify(host: str, chain: list[str], anchors: pathlib.Path,
           work: pathlib.Path) -> tuple[bool, str]:
    if not chain:
        return False, "no certificate received"
    leaf = work / f"{host}.leaf.pem"
    leaf.write_text(chain[0] + "\n", encoding="ascii")
    command = ["openssl", "verify", "-no-CApath", "-no-CAstore",
               "-CAfile", str(anchors), "-verify_hostname", host]
    if len(chain) > 1:
        untrusted = work / f"{host}.untrusted.pem"
        untrusted.write_text("\n".join(chain[1:]) + "\n", encoding="ascii")
        command += ["-untrusted", str(untrusted)]
    command.append(str(leaf))
    result = subprocess.run(command, capture_output=True, text=True,
                            check=False)
    lines = (result.stdout + result.stderr).strip().splitlines()
    return result.returncode == 0, lines[-1] if lines else ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chain-dir", type=pathlib.Path)
    args = parser.parse_args()
    try:
        anchors = compiled_anchors()
    except (OSError, SystemExit) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    failed = False
    with tempfile.TemporaryDirectory() as raw_work:
        work = pathlib.Path(raw_work)
        anchor_file = work / "anchors.pem"
        anchor_file.write_text("\n".join(anchors) + "\n", encoding="ascii")
        for host in HOSTS:
            if args.chain_dir is not None:
                path = args.chain_dir / f"{host}.pem"
                chain = PEM_RE.findall(path.read_text(encoding="ascii"))
            else:
                try:
                    chain = live_chain(host)
                except subprocess.TimeoutExpired:
                    chain = []
            ok, detail = verify(host, chain, anchor_file, work)
            failed = failed or not ok
            print(f"{'OK  ' if ok else 'FAIL'} {host}: {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
