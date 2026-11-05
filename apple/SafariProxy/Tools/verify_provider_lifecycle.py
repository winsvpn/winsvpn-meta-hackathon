#!/usr/bin/env python3
"""Compile unmodified Safari provider sources against local test doubles.

Production deadlines are retained. No NetworkExtension profile, Keychain item,
external network service or engine is used. DNS wire tests add assigned-family
resolver coverage beyond SafariRuntimeTests.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys

FIXTURE_DIR = Path(__file__).resolve().parents[1] / 'Tests/ProviderLifecycle'
FIXTURES = {name: (FIXTURE_DIR / name).read_text() for name in
            ('ProviderStubs.swift', 'ProviderTests.swift', 'DNSWireStubs.swift', 'DNSWireTests.swift')}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path,
                        help="Repository root or the apple/SafariProxy directory")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    source = args.source_root.resolve()
    if (source / "apple/SafariProxy").is_dir():
        source = source / "apple/SafariProxy"
    required = ["Provider/DNSProxyProvider.swift", "Provider/TransparentProxyProvider.swift",
                "Shared/SafariDNSWire.swift", "Shared/SafariForwardError.swift"]
    for name in required:
        if not (source / name).is_file():
            parser.error("Missing source file: " + str(source / name))
    swiftc = shutil.which("swiftc")
    if not swiftc:
        parser.error("swiftc is unavailable")
    out = args.output_dir.resolve()
    if out == source:
        parser.error("Output directory must differ from the source directory")
    out.mkdir(parents=True, exist_ok=True)
    for name, contents in FIXTURES.items():
        (out / name).write_text(contents)
    checks = []
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def run(argv, name, timeout):
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, start_new_session=True)
        timed_out = False
        try:
            output, _ = process.communicate(timeout=timeout)
            status = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            output, _ = process.communicate()
            status = 124
        (out / (name + ".log")).write_text(output)
        checks.append({"argv": argv, "exit_code": status, "timeout": timed_out,
                       "log": name + ".log"})
        print(name + ": exit " + str(status), flush=True)
        if status:
            print(output[-6000:], flush=True)
        return status == 0

    common = [swiftc, "-swift-version", "5", "-module-cache-path", str(out / "module-cache")]
    status = 0
    suites = [
        ("providers", [str(out / "ProviderStubs.swift"),
                       str(source / "Provider/DNSProxyProvider.swift"),
                       str(source / "Provider/TransparentProxyProvider.swift"),
                       str(out / "ProviderTests.swift")], 50),
        ("dns-wire", [str(out / "DNSWireStubs.swift"),
                      str(source / "Shared/SafariForwardError.swift"),
                      str(source / "Shared/SafariDNSWire.swift"),
                      str(out / "DNSWireTests.swift")], 15),
    ]
    try:
        for name, files, timeout in suites:
            binary = out / (name + "-tests")
            if not run(common + files + ["-o", str(binary)], name + "-build", 120):
                status = 1
                continue
            if not run([str(binary)], name + "-run", timeout):
                status = 1
    finally:
        receipt = {"started_utc": started,
                   "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   "source_root": str(source),
                   "source_sha256": {name: hashlib.sha256((source/name).read_bytes()).hexdigest()
                                     for name in required},
                   "fixture_sha256": {name: hashlib.sha256(value.encode()).hexdigest()
                                      for name, value in FIXTURES.items()},
                   "checks": checks,
                   "scope": "Actual provider and DNS-wire source with local test doubles; no installed NE, engine or Keychain proof"}
        (out / "checks.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return status

if __name__ == "__main__":
    sys.exit(main())
