#!/usr/bin/env python3
"""Test support for consumers of tools/winn_release.py (not shipped, not run).

It builds signed Winn release directories with a throwaway Ed25519 seed, and
installs a "racing" stand-in for tools/winn_release.py into a scratch tools
directory. The stand-in runs the REAL driver (copied beside it) but, around
every `verify` call, swaps the release directory's contents: the genuine,
correctly signed files are in place while the driver reads them, and an
attacker's files are in place before and after. A consumer that takes its
expected digests from anything but the bytes the driver verified (a manifest
read before or after verification) stages the attacker's bytes; a consumer
that takes them from `verify --print-manifest` refuses.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import shutil
from typing import Any, Mapping, Optional

TOOLS = pathlib.Path(__file__).resolve().parent
DRIVER = TOOLS / "winn_release.py"
TEST_SEED = bytes(range(32))
WRONG_SEED = bytes(range(1, 33))

RACING_DRIVER = r'''#!/usr/bin/env python3
"""Racing stand-in for tools/winn_release.py (test only)."""
import importlib.util, json, os, pathlib, shutil, sys

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("real_winn_release", here / "real_winn_release.py")
real = importlib.util.module_from_spec(spec)
spec.loader.exec_module(real)
argv = sys.argv[1:]
log = os.environ.get("WINN_RACE_LOG")
if log:
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(argv) + "\n")


def install(source):
    release = pathlib.Path(argv[argv.index("--release") + 1])
    for path in sorted(pathlib.Path(source).rglob("*")):
        if path.is_file():
            target = release / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                target.unlink()
            shutil.copyfile(path, target)


racing = argv[:1] == ["verify"] and "--release" in argv
if racing and os.environ.get("WINN_RACE_GENUINE"):
    install(os.environ["WINN_RACE_GENUINE"])
try:
    status = real.main(argv)
    sys.stdout.flush()
finally:
    if racing and os.environ.get("WINN_RACE_ATTACKER"):
        install(os.environ["WINN_RACE_ATTACKER"])
sys.exit(status)
'''


def load_driver(path: pathlib.Path = DRIVER) -> Any:
    spec = importlib.util.spec_from_file_location(f"_winn_release_testkit_{abs(hash(str(path)))}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def public_key_hex(seed: bytes = TEST_SEED) -> str:
    return load_driver().ed25519_public(seed).hex()


def authority_document(seed: bytes = TEST_SEED) -> bytes:
    return (json.dumps({
        "algorithm": "ed25519",
        "contract": "winsvpn-winn-release-authority-v1",
        "public_key": public_key_hex(seed),
    }, sort_keys=True) + "\n").encode("ascii")


def write_release(release: pathlib.Path, images: Mapping[str, tuple[str, bytes]], *,
                  seed: Optional[bytes] = TEST_SEED, signature_seed: Optional[bytes] = None,
                  forge_signature: bool = False, extra: Optional[Mapping[str, Any]] = None) -> dict:
    """Write a release holding IMAGES {target: (file name, bytes)}.

    seed signs the manifest (None leaves it unsigned). signature_seed signs
    with a different key while naming the seed's public key, and
    forge_signature writes a well-formed document with a junk signature over
    the right manifest digest: both must be refused by a real verifier.
    """
    driver = load_driver()
    artifacts = []
    for target, (name, data) in sorted(images.items()):
        path = release / "artifacts" / target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        artifacts.append({
            "target": target, "path": f"artifacts/{target}/{name}", "sha256": digest,
            "size": len(data), "header_path": None, "header_sha256": None,
            "build_a_sha256": digest, "build_b_sha256": digest,
        })
    manifest = {
        "contract": driver.MANIFEST_CONTRACT,
        "source": {"binding": "git-archive", "commit": "a" * 40, "path": "winn_protocol_experimental",
                   "tree_sha256": "b" * 64},
        "toolchains": {"go": {"version": "1.27.1", "archive_sha256": "c" * 64,
                              "install_tree_sha256": "d" * 64, "executable_sha256": "e" * 64}},
        "producer": {"build_winn_protocol_engine.sh": "1" * 64, "winn_release.py": "2" * 64,
                     "toolchain-pins.json": "3" * 64},
        "skipped_targets": {},
        "artifacts": artifacts,
    }
    manifest.update(extra or {})
    payload = driver.canonical_json(manifest)
    (release / "manifest.json").write_bytes(payload)
    if seed is not None:
        signer = signature_seed if signature_seed is not None else seed
        signature = driver.ed25519_sign(signer, driver.SIGNATURE_DOMAIN + payload)
        if forge_signature:
            signature = bytes(64)
        (release / "manifest.sig.json").write_bytes(driver.canonical_json({
            "algorithm": "ed25519",
            "contract": driver.SIGNATURE_CONTRACT,
            "manifest_sha256": hashlib.sha256(payload).hexdigest(),
            "public_key": driver.ed25519_public(seed).hex(),
            "signature": signature.hex(),
        }))
    return manifest


def install_racing_driver(tools: pathlib.Path, seed: bytes = TEST_SEED,
                          real_driver: pathlib.Path = DRIVER) -> None:
    """tools/winn_release.py becomes the racer; the real driver sits beside it."""
    tools.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(real_driver, tools / "real_winn_release.py")
    (tools / "winn_release.py").write_text(RACING_DRIVER, encoding="utf-8")
    (tools / "winn_release_authority.json").write_bytes(authority_document(seed))


def race_environment(genuine: pathlib.Path, attacker: pathlib.Path,
                     log: Optional[pathlib.Path] = None) -> dict[str, str]:
    environment = {"WINN_RACE_GENUINE": str(genuine), "WINN_RACE_ATTACKER": str(attacker)}
    if log is not None:
        environment["WINN_RACE_LOG"] = str(log)
    return environment


def prepare_race(base: pathlib.Path, genuine_images: Mapping[str, tuple[str, bytes]],
                 attacker_images: Mapping[str, tuple[str, bytes]]) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    """Return (release, genuine, attacker) directories.

    genuine is a correctly signed release. attacker carries other engine
    bytes, a canonical manifest naming them, and a signature document naming
    that manifest's digest and the trusted public key with a junk signature.
    The release directory starts in the attacker's state.
    """
    genuine = base / "race-genuine"
    attacker = base / "race-attacker"
    write_release(genuine, genuine_images)
    write_release(attacker, attacker_images, forge_signature=True)
    release = base / "release"
    shutil.copytree(attacker, release)
    return release, genuine, attacker
