from pathlib import Path
import argparse
import os
import subprocess

parser = argparse.ArgumentParser(description="Offline receive-sizing fixtures; no archive or provider")
parser.add_argument("--swiftc", default="/usr/bin/swiftc")
parser.add_argument("--output-dir", required=True, type=Path)
args = parser.parse_args()
source = Path(__file__).resolve().parents[1]
output = args.output_dir.resolve()
output.mkdir(parents=True, exist_ok=False)
env = os.environ.copy()
env["CLANG_MODULE_CACHE_PATH"] = str(output / "clang-cache")
subprocess.run([
    args.swiftc, "-swift-version", "5", "-module-cache-path", str(output / "swift-cache"),
    str(source / "apple/WinsTunnelCore/WinsWinn3Datapath.swift"),
    str(source / "tools/apple_receive_sizing/main.swift"),
    "-o", str(output / "sizing-tests"),
], env=env, check=True, timeout=120)
for case in ["scalar_short", "batch_short", "scalar_ordinary", "batch_ordinary",
             "batch_prefix_short", "scalar_stale", "batch_stale"]:
    subprocess.run([str(output / "sizing-tests"), case], env=env, check=True, timeout=10)
