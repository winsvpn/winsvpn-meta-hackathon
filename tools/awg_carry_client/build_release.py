#!/usr/bin/env python3
"""Build the pinned wins-awg-carry-client binaries and their receipt.

Mirrors the winn3-probe pattern (server/winn3-probe.build.json): a static,
trimmed, VCS-free, CGO-free build for linux amd64 and arm64 from the module
cache only (GOPROXY=off), built REPEATS times per architecture and refused
unless every repeat is byte-identical. The receipt records the artifact
digests and sizes, the build environment and flags, the toolchain, a digest of
every source file of this module, and every module linked into the binary with
its go.sum hash and its license (read from the module cache).

    python3 -I tools/awg_carry_client/build_release.py \
        --go /path/to/go1.27.1/bin/go --out server --checked-live-utc 2026-10-08T18:02Z

The control-plane installer pins the digests this writes
(install_awg_carry_client) and refuses any other bytes.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
NAME = "awg-carry-client"
TARGETS = ("amd64", "arm64")
FLAGS = ["-trimpath", "-buildvcs=false"]
ENVIRONMENT = {"CGO_ENABLED": "0", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOFLAGS": ""}
REPEATS = 3
LICENSE_NAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "LICENSE.BSD")


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(go: str, args: list, env: dict, cwd: pathlib.Path) -> str:
    done = subprocess.run([go, *args], cwd=cwd, env=env, capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(f"{go} {' '.join(args)} failed ({done.returncode}):\n{done.stderr}")
    return done.stdout


def build_env(go: str, arch: str, cache: pathlib.Path) -> dict:
    env = {key: os.environ[key] for key in ("PATH", "HOME", "GOMODCACHE", "GOPATH") if key in os.environ}
    env.update(ENVIRONMENT)
    env.update({"GOOS": "linux", "GOARCH": arch, "GOCACHE": str(cache)})
    return env


def build_once(go: str, arch: str, cache: pathlib.Path, out: pathlib.Path) -> None:
    run(go, ["build", *FLAGS, "-o", str(out), "."], build_env(go, arch, cache), HERE)


def source_files() -> dict:
    files = {}
    for path in sorted(HERE.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(HERE).as_posix()
        if path.suffix == ".go" or relative in ("go.mod", "go.sum", "build_release.py"):
            files[relative] = sha256(path)
    return files


def license_of(directory: str) -> dict:
    for name in LICENSE_NAMES:
        path = pathlib.Path(directory, name)
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            return {"file": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "kind": license_kind(text)}
    return {"file": None, "sha256": None, "kind": "unknown"}


def license_kind(text: str) -> str:
    head = text[:4000].lower()
    if "apache license" in head and "version 2.0" in head:
        return "Apache-2.0"
    if "permission is hereby granted, free of charge" in head:
        return "MIT"
    if "redistribution and use in source and binary forms" in head:
        return "BSD-3-Clause" if "neither the name" in head else "BSD-2-Clause"
    return "unknown"


def linked_modules(go: str, binary: pathlib.Path, env: dict) -> list:
    """Every module linked into the binary, from its embedded build info."""
    modules = []
    for line in run(go, ["version", "-m", str(binary)], env, HERE).splitlines():
        parts = line.strip().split("\t")
        if parts and parts[0] == "dep" and len(parts) >= 3:
            modules.append({"path": parts[1], "version": parts[2], "sum": parts[3] if len(parts) > 3 else None})
    cache = pathlib.Path(run(go, ["env", "GOMODCACHE"], env, HERE).strip())
    for module in modules:
        # The module cache escapes upper-case letters as "!x"; no lookup is
        # needed, the build just read these directories.
        escaped = "".join("!" + c.lower() if c.isupper() else c for c in module["path"])
        directory = cache / f"{escaped}@{module['version']}"
        module["license"] = license_of(str(directory)) if directory.is_dir() else {"file": None, "sha256": None, "kind": "unknown"}
    return modules


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--go", default=shutil.which("go"), help="the Go toolchain to build with")
    parser.add_argument("--out", required=True, help="directory that receives the binaries and the receipt")
    parser.add_argument("--checked-live-utc", required=True, help="when the module pins were checked against upstream")
    args = parser.parse_args()
    if not args.go or not os.access(args.go, os.X_OK):
        raise SystemExit("no Go toolchain (--go)")
    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    toolchain = run(args.go, ["version"], build_env(args.go, "amd64", out), HERE).strip().removeprefix("go version ")
    receipt = {
        "artifacts": {},
        "environment": {key: ENVIRONMENT[key] for key in sorted(ENVIRONMENT) if key != "GOFLAGS"},
        "flags": FLAGS,
        "module": "winsvpn.local/awgcarryclient",
        "package": ".",
        "pins_checked_live_utc": args.checked_live_utc,
        "repeats": REPEATS,
        "source_files": source_files(),
        "toolchain": toolchain,
    }
    with tempfile.TemporaryDirectory(prefix="awg-carry-client-build-") as scratch:
        scratch_path = pathlib.Path(scratch)
        for arch in TARGETS:
            digests = []
            built = None
            for repeat in range(REPEATS):
                # A fresh build cache for every repeat, so a repeat can never
                # be a cache hit of the one before it.
                cache = scratch_path / f"cache-{arch}-{repeat}"
                target = scratch_path / f"{NAME}-{arch}-{repeat}"
                build_once(args.go, arch, cache, target)
                digests.append(sha256(target))
                built = target
                shutil.rmtree(cache, ignore_errors=True)
            if len(set(digests)) != 1:
                raise SystemExit(f"{arch}: {REPEATS} builds differ: {digests}")
            data = built.read_bytes()
            machine = int.from_bytes(data[18:20], "little")
            if data[:6] != b"\x7fELF\x02\x01" or machine != {"amd64": 62, "arm64": 183}[arch]:
                raise SystemExit(f"{arch}: not the expected ELF64 machine ({machine})")
            final = out / f"{NAME}-linux-{arch}"
            with tempfile.NamedTemporaryFile(dir=out, prefix="." + final.name + ".", delete=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), 0o755)
            os.replace(stream.name, final)
            receipt["artifacts"][arch] = {
                "GOARCH": arch, "GOOS": "linux", "bytes": len(data), "file": final.name,
                "sha256": digests[0], "repeat_sha256": digests,
            }
            if arch == TARGETS[0]:
                receipt["modules"] = linked_modules(args.go, final, build_env(args.go, arch, scratch_path / "list-cache"))
    receipt_path = out / f"{NAME}.build.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    for arch, artifact in receipt["artifacts"].items():
        print(f"{arch}: {artifact['sha256']} {artifact['bytes']} bytes ({REPEATS} identical builds)")
    print(f"receipt: {receipt_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
