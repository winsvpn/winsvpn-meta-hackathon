#!/usr/bin/env python3
"""Build the Safari flow bridge and unchanged Winn engine as one offline archive."""
from __future__ import annotations

import argparse
import base64
import datetime
import difflib
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

EXTRA_MODULES = ("github.com/google/btree", "golang.org/x/exp", "golang.org/x/time", "gvisor.dev/gvisor")
BRIDGE_FILES = ("bridge.go", "exports.go", "bridge_test.go")
SOURCE_SUFFIXES = {".go", ".h", ".c", ".s", ".S", ".mod", ".sum"}
EXCLUDED_DIRS = {"build", "cache", "vendor", "testdata"}
PLATFORMS = {"macos": ("macosx", "darwin", "arm64-apple-macos12.0"), "ios": ("iphoneos", "ios", "arm64-apple-ios16.0")}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def requirements(text: str) -> dict[str, str]:
    result = {}
    block = False
    for original in text.splitlines():
        line = original.split("//", 1)[0].strip()
        if line == "require (":
            block = True
            continue
        if block and line == ")":
            block = False
            continue
        if line.startswith("require "):
            line = line[len("require "):]
        elif not block:
            continue
        fields = line.split()
        if fields:
            if len(fields) != 2 or not fields[1].startswith("v"):
                raise ValueError("unsupported module requirement: " + original)
            if fields[0] in result and result[fields[0]] != fields[1]:
                raise ValueError("conflicting module requirement: " + fields[0])
            result[fields[0]] = fields[1]
    return result


def source_inputs(root: Path) -> dict[str, bytes]:
    result = {}
    for directory, names, files in os.walk(root, followlinks=False):
        names[:] = sorted(n for n in names if not n.startswith(".") and n not in EXCLUDED_DIRS)
        for name in sorted(files):
            path = Path(directory) / name
            if path.suffix not in SOURCE_SUFFIXES:
                continue
            if path.is_symlink():
                raise ValueError("source symlink is not an immutable input: " + str(path.relative_to(root)))
            result[str(path.relative_to(root))] = path.read_bytes()
    for required in ("go.mod", "go.sum", "cdatapath/winn_datapath.go"):
        if required not in result:
            raise ValueError("missing engine source " + required)
    return result


def hash1(entries: dict[str, bytes]) -> str:
    value = hashlib.sha256()
    for name, content in sorted(entries.items()):
        if "\n" in name:
            raise ValueError("invalid module filename")
        value.update((digest(content) + "  " + name + "\n").encode())
    return "h1:" + base64.b64encode(value.digest()).decode()


def stage_module(cache: Path, private: Path, name: str, version: str, sums: dict[tuple[str, str], str]) -> dict[str, str]:
    escaped = "".join("!" + c.lower() if c.isupper() else c for c in name)
    source = cache / (escaped + "@" + version)
    target = private / (escaped + "@" + version)
    metadata = cache / "cache/download" / escaped / "@v"
    expected = sums.get((name, version))
    expected_mod = sums.get((name, version + "/go.mod"))
    if not source.is_dir() or not expected or not expected_mod:
        raise ValueError("missing exact cached module or pinned sum: " + name + "@" + version)
    prefix = name + "@" + version + "/"
    entries = {}
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError("module symlink refused: " + name)
        if path.is_file():
            entries[prefix + path.relative_to(source).as_posix()] = path.read_bytes()
    if hash1(entries) != expected:
        raise ValueError("cached source checksum mismatch: " + name + "@" + version)
    mod = metadata / (version + ".mod")
    archive = metadata / (version + ".zip")
    if not mod.is_file() or not archive.is_file():
        raise ValueError("missing exact offline module metadata/archive: " + name + "@" + version)
    if hash1({"go.mod": mod.read_bytes()}) != expected_mod:
        raise ValueError("cached go.mod checksum mismatch: " + name)
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        if len(set(names)) != len(names):
            raise ValueError("duplicate module ZIP entry: " + name)
        archived = {n: z.read(n) for n in names if not n.endswith("/")}
    if hash1(archived) != expected:
        raise ValueError("cached archive checksum mismatch: " + name + "@" + version)
    shutil.copytree(source, target)
    destination = private / "cache/download" / escaped / "@v"
    destination.mkdir(parents=True, exist_ok=True)
    for suffix in (".mod", ".info", ".zip", ".ziphash"):
        path = metadata / (version + suffix)
        if path.is_file():
            shutil.copyfile(path, destination / path.name)
    return {"version": version, "module_h1": expected, "go_mod_h1": expected_mod, "zip_sha256": digest(archive.read_bytes())}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", type=Path, required=True, help="Installed Go executable matching the engine go.mod")
    parser.add_argument("--module-cache", type=Path, required=True, help="Read-only existing Go module cache")
    parser.add_argument("--output", type=Path, required=True, help="Private build output directory")
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[3], help="Repository root")
    parser.add_argument("--bridge-source", type=Path, default=Path(__file__).resolve().parents[1] / "Bridge")
    parser.add_argument("--platform", choices=("all", "macos", "ios"), default="all")
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("this helper builds and tests on a macOS arm64 host")
    repo, bridge, cache, output, go = [p.resolve() for p in (args.source_root, args.bridge_source, args.module_cache, args.output, args.go)]
    engine = repo / "winn_protocol_experimental"
    for protected in (engine, bridge, cache):
        if output == protected or protected in output.parents or output in protected.parents:
            raise ValueError("output must not overlap an engine, bridge or module-cache input")
    if not go.is_file() or not os.access(go, os.X_OK):
        raise ValueError("Go executable is unavailable")
    output.mkdir(parents=True, exist_ok=True)
    base_env = os.environ.copy()
    base_env.update({"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off", "GONOPROXY": "none", "GOPRIVATE": "", "GOSUMDB": "off", "GOTELEMETRY": "off", "GOFLAGS": "-mod=readonly", "GOOS": "darwin", "GOARCH": "arm64", "CGO_ENABLED": "1"})
    version = subprocess.check_output([str(go), "version"], env=base_env, text=True, timeout=30).strip()
    original = source_inputs(engine)
    module_text = original["go.mod"].decode()
    match = re.search(r"^go\s+(\S+)\s*$", module_text, re.M)
    if not match or version.split()[:3] != ["go", "version", "go" + match.group(1)]:
        raise ValueError("Go version does not match engine go.mod: " + version)
    carry_mod_path = repo / "tools/awg_carry_client/go.mod"
    carry_sum_path = repo / "tools/awg_carry_client/go.sum"
    carry_mod, carry_sum = carry_mod_path.read_bytes(), carry_sum_path.read_bytes()
    engine_pins, carry_pins = requirements(module_text), requirements(carry_mod.decode())
    if re.search(r"^\s*(replace|exclude)\b", module_text + "\n" + carry_mod.decode(), re.M):
        raise ValueError("module replace/exclude requires an explicit build-helper update")
    additions = {name: carry_pins[name] for name in EXTRA_MODULES if name not in engine_pins}
    pins = {**additions, **engine_pins}
    updated = module_text + "\nrequire (\n" + "".join("\t" + n + " " + v + "\n" for n, v in sorted(additions.items())) + ")\n"
    sum_lines = sorted(set(original["go.sum"].decode().splitlines()) | set(carry_sum.decode().splitlines()))
    sums = {}
    for line in sum_lines:
        if not line:
            continue
        name, revision, checksum = line.split()
        if (name, revision) in sums and sums[(name, revision)] != checksum:
            raise ValueError("conflicting dependency checksum: " + name + " " + revision)
        sums[(name, revision)] = checksum
    bridge_bytes = {name: (bridge / name).read_bytes() for name in BRIDGE_FILES}
    test_names = re.findall(r"^func\s+(Test\w+)\(t \*testing\.T\)", bridge_bytes["bridge_test.go"].decode(), re.M)
    if len(test_names) < 7 or len(test_names) != len(set(test_names)):
        raise ValueError("expected at least the seven named bridge acceptance tests")
    selected = tuple(PLATFORMS) if args.platform == "all" else (args.platform,)
    sdk = {}
    for name in selected:
        sdk_name, _, target = PLATFORMS[name]
        path = subprocess.check_output(["xcrun", "--sdk", sdk_name, "--show-sdk-path"], text=True, timeout=30).strip()
        clang = subprocess.check_output(["xcrun", "--sdk", sdk_name, "--find", "clang"], text=True, timeout=30).strip()
        settings = Path(path) / "SDKSettings.json"
        sdk[name] = {"sdk": path, "target": target, "clang": clang, "clang_sha256": digest(Path(clang).read_bytes()), "sdk_settings_sha256": digest(settings.read_bytes())}
    identity = {"schema": 1, "source": {k: digest(v) for k, v in original.items()}, "bridge": {k: digest(v) for k, v in bridge_bytes.items()}, "carry_mod": digest(carry_mod), "carry_sum": digest(carry_sum), "overlay_mod": digest(updated.encode()), "overlay_sum": digest(("\n".join(sum_lines) + "\n").encode()), "go_version": version, "go_executable_sha256": digest(go.read_bytes()), "sdk": sdk, "builder_sha256": digest(Path(__file__).read_bytes()), "tests": test_names}
    input_digest = digest(canonical(identity))
    receipt_path = output / "build-receipt.json"
    if receipt_path.is_file():
        previous = json.loads(receipt_path.read_text())
        if previous.get("input_sha256") == input_digest and previous.get("status") == "passed":
            artifacts = previous.get("artifacts", {})
            expected = {"libSafariWinn-" + p + "-arm64" + suffix for p in selected for suffix in (".a", ".h")}
            if expected == set(artifacts) and all((output / name).is_file() and digest((output / name).read_bytes()) == artifacts[name] for name in expected):
                print("Reused verified build receipt " + input_digest)
                return 0
    work = Path(tempfile.mkdtemp(prefix="engine-", dir=output))
    staged = work / "source"
    staged.mkdir()
    write_json(work / "input-manifest.json", identity)
    (work / "go-mod-overlay.diff").write_text("".join(difflib.unified_diff(module_text.splitlines(True), updated.splitlines(True), fromfile="winn_protocol_experimental/go.mod", tofile="generated-safari-engine/go.mod")))
    for relative, data in original.items():
        target = staged / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (staged / "go.mod").write_text(updated)
    (staged / "go.sum").write_text("\n".join(sum_lines) + "\n")
    for name, data in bridge_bytes.items():
        (staged / "cdatapath" / ("safari_" + name)).write_bytes(data)
    private_cache = work / "gomodcache"
    private_cache.mkdir()
    dependency_receipt = {name: stage_module(cache, private_cache, name, ver, sums) for name, ver in sorted(pins.items())}
    write_json(work / "dependencies.json", dependency_receipt)
    for directory in ("tmp", "gocache", "gopath"):
        (work / directory).mkdir()
    base_env.update({"GOMODCACHE": str(private_cache), "GOCACHE": str(work / "gocache"), "GOPATH": str(work / "gopath"), "TMPDIR": str(work / "tmp")})
    records = []
    receipt = {"schema": 1, "status": "running", "input_sha256": input_digest, "work": str(work.relative_to(output)), "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "commands": records, "artifacts": {}}
    write_json(receipt_path, receipt)

    def run(name: str, command: list[str], env: dict[str, str], timeout: int) -> None:
        log = work / (name + ".log")
        start = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            with log.open("w") as f:
                result = subprocess.run(command, cwd=staged, env=env, text=True, stdout=f, stderr=subprocess.STDOUT, timeout=timeout)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
        records.append({"name": name, "argv": command, "start_utc": start, "exit": code, "log": str(log.relative_to(output))})
        write_json(receipt_path, receipt)
        if code:
            receipt["status"] = "failed"
            write_json(receipt_path, receipt)
            raise RuntimeError(name + " failed with exit " + str(code) + "; see " + str(log))
        print(name + ": passed", flush=True)

    run("bridge-tests", [str(go), "test", "-race", "-count=1", "-timeout=120s", "-run", "^(" + "|".join(test_names) + ")$", "-v", "./cdatapath"], base_env, 300)
    artifacts = {}
    for name in selected:
        platform_env = base_env.copy()
        details = sdk[name]
        flags = "-target " + details["target"] + " -isysroot " + details["sdk"]
        platform_env.update({"GOOS": PLATFORMS[name][1], "CC": details["clang"], "CGO_CFLAGS": flags, "CGO_LDFLAGS": flags})
        archive = work / ("libSafariWinn-" + name + "-arm64.a")
        run(name, [str(go), "build", "-mod=readonly", "-pgo=off", "-trimpath", "-buildvcs=false", "-buildmode=c-archive", "-o", str(archive), "./cdatapath"], platform_env, 600)
        for source in (archive, archive.with_suffix(".h")):
            artifacts[source.name] = digest(source.read_bytes())
    # Publish only after every requested build and every bridge test passed.
    for name, checksum in artifacts.items():
        temporary = output / (name + ".new")
        shutil.copyfile(work / name, temporary)
        if digest(temporary.read_bytes()) != checksum:
            raise ValueError("artifact changed during publication: " + name)
        temporary.replace(output / name)
    receipt.update({"status": "passed", "completed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "artifacts": artifacts, "dependencies_sha256": digest(canonical(dependency_receipt)), "tests": test_names})
    write_json(receipt_path, receipt)
    print("Combined archives ready in " + str(output))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError, KeyError) as error:
        print("build_engine: " + str(error), file=sys.stderr)
        raise SystemExit(1)
