from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parent.parent
VALIDATOR = ROOT / "tools/validate_flutter_package_config.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_flutter_package_config", VALIDATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = load_validator()


@pytest.fixture()
def fixture(tmp_path: Path) -> dict[str, object]:
    project = (tmp_path / "project").resolve()
    flutter = (tmp_path / "flutter").resolve()
    cache = (tmp_path / "pub-cache").resolve()
    for path in (
        project / ".dart_tool",
        project / "lib",
        cache / "hosted/pub.dev/archive-4.2.0/lib",
        cache / "hosted-hashes/pub.dev",
    ):
        path.mkdir(parents=True, exist_ok=True)
    sdk_roots = {
        "flutter": "packages/flutter",
        "flutter_localizations": "packages/flutter_localizations",
        "flutter_test": "packages/flutter_test",
        "sky_engine": "bin/cache/pkg/sky_engine",
    }
    for relative in sdk_roots.values():
        (flutter / relative / "lib").mkdir(parents=True)
    digest = "a" * 64
    lock = {
        "packages": {
            "archive": {
                "dependency": "direct main",
                "description": {"name": "archive", "sha256": digest, "url": "https://pub.dev"},
                "source": "hosted",
                "version": "4.2.0",
            },
            **{
                name: {
                    "dependency": "transitive",
                    "description": "flutter",
                    "source": "sdk",
                    "version": "0.0.0",
                }
                for name in sdk_roots
            },
        },
        "sdks": {"dart": ">=3.13.0 <4.0.0", "flutter": ">=3.47.0"},
    }
    lock_path = project / "pubspec.lock"
    lock_path.write_text(yaml.safe_dump(lock, sort_keys=False), encoding="utf-8")
    (cache / "hosted-hashes/pub.dev/archive-4.2.0.sha256").write_text(digest + "\n", encoding="ascii")
    packages = [
        {
            "name": "archive",
            "rootUri": (cache / "hosted/pub.dev/archive-4.2.0").as_uri(),
            "packageUri": "lib/",
            "languageVersion": "3.0",
        }
    ]
    packages.extend(
        {
            "name": name,
            "rootUri": (flutter / relative).as_uri(),
            "packageUri": "lib/",
            "languageVersion": "3.11",
        }
        for name, relative in sdk_roots.items()
    )
    packages.append({"name": "wins_vpn", "rootUri": "../", "packageUri": "lib/", "languageVersion": "3.2"})
    document = {
        "configVersion": 2,
        "packages": packages,
        "generator": "pub",
        "generatorVersion": "3.13.5",
        "flutterRoot": flutter.as_uri(),
        "flutterVersion": "3.47.6",
        "pubCache": cache.as_uri(),
    }
    config = project / ".dart_tool/package_config.json"
    config.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return {
        "project": project,
        "flutter": flutter,
        "cache": cache,
        "lock": lock_path,
        "config": config,
        "document": document,
        "lock_data": lock,
    }


def run(fixture: dict[str, object], *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            "--package-config",
            str(fixture["config"]),
            "--lockfile",
            str(fixture["lock"]),
            "--project-root",
            str(fixture["project"]),
            "--flutter-root",
            str(fixture["flutter"]),
            "--pub-cache",
            str(fixture["cache"]),
            "--flutter-version",
            "3.47.6",
            "--dart-version",
            "3.13.5",
            *extra,
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def namespace(fixture: dict[str, object], **overrides: object) -> argparse.Namespace:
    values = {
        "package_config": str(fixture["config"]),
        "lockfile": str(fixture["lock"]),
        "project_root": str(fixture["project"]),
        "flutter_root": str(fixture["flutter"]),
        "pub_cache": str(fixture["cache"]),
        "flutter_version": "3.47.6",
        "dart_version": "3.13.5",
        "expected_digest": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def rewrite(fixture: dict[str, object]) -> None:
    Path(fixture["config"]).write_text(json.dumps(fixture["document"], indent=2) + "\n", encoding="utf-8")


def rewrite_lock(fixture: dict[str, object]) -> None:
    Path(fixture["lock"]).write_text(yaml.safe_dump(fixture["lock_data"], sort_keys=False), encoding="utf-8")


def test_valid_mapping_and_digest_recheck(fixture: dict[str, object]) -> None:
    first = run(fixture)
    assert first.returncode == 0, first.stderr
    digest = first.stdout.strip()
    assert len(digest) == 64
    assert run(fixture, "--expected-digest", digest).returncode == 0


@pytest.mark.parametrize(
    "field,value",
    [("configVersion", 1), ("generator", "other"), ("generatorVersion", "3.12.0"), ("flutterVersion", "3.44.6")],
)
def test_rejects_metadata_drift(fixture: dict[str, object], field: str, value: object) -> None:
    fixture["document"][field] = value
    rewrite(fixture)
    assert run(fixture).returncode == 1


def test_rejects_duplicate_json_keys(fixture: dict[str, object]) -> None:
    raw = Path(fixture["config"]).read_text(encoding="utf-8")
    Path(fixture["config"]).write_text(
        raw.replace('"configVersion": 2,', '"configVersion": 2,\n  "configVersion": 2,'),
        encoding="utf-8",
    )
    assert run(fixture).returncode == 1


def test_rejects_non_finite_json_numbers(fixture: dict[str, object]) -> None:
    raw = Path(fixture["config"]).read_text(encoding="utf-8")
    Path(fixture["config"]).write_text(raw.replace('"configVersion": 2', '"configVersion": NaN'), encoding="utf-8")
    assert run(fixture).returncode == 1


def test_rejects_float_config_version(fixture: dict[str, object]) -> None:
    raw = Path(fixture["config"]).read_text(encoding="utf-8")
    Path(fixture["config"]).write_text(raw.replace('"configVersion": 2', '"configVersion": 2.0'), encoding="utf-8")
    assert run(fixture).returncode == 1


def test_rejects_trailing_json_data(fixture: dict[str, object]) -> None:
    Path(fixture["config"]).write_bytes(Path(fixture["config"]).read_bytes() + b"{}\n")
    assert run(fixture).returncode == 1


def test_rejects_deep_json_nesting(fixture: dict[str, object]) -> None:
    Path(fixture["config"]).write_text("[" * 40 + "]" * 40 + "\n", encoding="utf-8")
    assert run(fixture).returncode == 1


def test_rejects_wrong_pub_cache(fixture: dict[str, object], tmp_path: Path) -> None:
    other = (tmp_path / "other").resolve()
    other.mkdir()
    fixture["document"]["pubCache"] = other.as_uri()
    rewrite(fixture)
    assert run(fixture).returncode == 1


def test_rejects_substituted_lockfile(fixture: dict[str, object]) -> None:
    substituted = Path(fixture["project"]) / "substituted.lock"
    substituted.write_bytes(Path(fixture["lock"]).read_bytes())
    fixture["lock"] = substituted
    assert run(fixture).returncode == 1


def test_rejects_hardlinked_lockfile(fixture: dict[str, object]) -> None:
    alias = Path(fixture["project"]) / "lock-alias"
    alias.hardlink_to(Path(fixture["lock"]))
    assert run(fixture).returncode == 1


def test_rejects_hardlinked_package_config(fixture: dict[str, object]) -> None:
    alias = Path(fixture["project"]) / "config-alias"
    alias.hardlink_to(Path(fixture["config"]))
    assert run(fixture).returncode == 1


def test_rejects_package_root_escape(fixture: dict[str, object], tmp_path: Path) -> None:
    escaped = (tmp_path / "escaped").resolve()
    (escaped / "lib").mkdir(parents=True)
    fixture["document"]["packages"][0]["rootUri"] = escaped.as_uri()
    rewrite(fixture)
    assert run(fixture).returncode == 1


def test_rejects_relative_file_root_uri(fixture: dict[str, object]) -> None:
    fixture["document"]["packages"][0]["rootUri"] = "file:../"
    rewrite(fixture)
    assert run(fixture).returncode == 1


def test_rejects_dotdot_file_root_uri(fixture: dict[str, object]) -> None:
    cache = Path(fixture["cache"])
    fixture["document"]["packages"][0]["rootUri"] = (cache / "hosted/pub.dev/archive-4.2.0/../archive-4.2.0").as_uri()
    rewrite(fixture)
    assert run(fixture).returncode == 1


def test_rejects_relative_hosted_root_escape(fixture: dict[str, object]) -> None:
    fixture["document"]["packages"][0]["rootUri"] = "../../pub-cache/hosted/pub.dev/archive-4.2.0"
    rewrite(fixture)
    assert run(fixture).returncode == 1


def test_rejects_non_exact_root_package_uri(fixture: dict[str, object]) -> None:
    fixture["document"]["packages"][-1]["rootUri"] = Path(fixture["project"]).as_uri()
    rewrite(fixture)
    assert run(fixture).returncode == 1


def test_rejects_hosted_hash_drift(fixture: dict[str, object]) -> None:
    (Path(fixture["cache"]) / "hosted-hashes/pub.dev/archive-4.2.0.sha256").write_text("b" * 64 + "\n", encoding="ascii")
    assert run(fixture).returncode == 1


def test_rejects_missing_or_duplicate_package(fixture: dict[str, object]) -> None:
    fixture["document"]["packages"].append(dict(fixture["document"]["packages"][0]))
    rewrite(fixture)
    assert run(fixture).returncode == 1


def test_rejects_lock_package_missing_from_config(fixture: dict[str, object]) -> None:
    fixture["document"]["packages"] = [item for item in fixture["document"]["packages"] if item["name"] != "archive"]
    rewrite(fixture)
    assert run(fixture).returncode == 1


def test_rejects_root_package_in_lockfile(fixture: dict[str, object]) -> None:
    fixture["lock_data"]["packages"]["wins_vpn"] = {
        "dependency": "direct main",
        "description": {"name": "wins_vpn", "sha256": "c" * 64, "url": "https://pub.dev"},
        "source": "hosted",
        "version": "1.0.0",
    }
    rewrite_lock(fixture)
    assert run(fixture).returncode == 1


def test_rejects_version_path_escape(fixture: dict[str, object]) -> None:
    fixture["lock_data"]["packages"]["archive"]["version"] = "4.2.0/../../evil"
    rewrite_lock(fixture)
    assert run(fixture).returncode == 1


def test_rejects_yaml_aliases(fixture: dict[str, object]) -> None:
    Path(fixture["lock"]).write_text(
        "packages:\n  archive: &a\n    dependency: direct main\n    description: *a\n",
        encoding="utf-8",
    )
    assert run(fixture).returncode == 1


def test_rejects_duplicate_yaml_keys(fixture: dict[str, object]) -> None:
    raw = Path(fixture["lock"]).read_text(encoding="utf-8")
    Path(fixture["lock"]).write_text(raw.replace("  archive:\n", "  archive:\n  archive:\n", 1), encoding="utf-8")
    assert run(fixture).returncode == 1


@pytest.mark.parametrize("value", [None, "3", "03.1", "3.-1", "3.11.0", 3.1, ""])
def test_rejects_absent_or_invalid_language_version(fixture: dict[str, object], value: object) -> None:
    package = fixture["document"]["packages"][0]
    if value is None:
        package.pop("languageVersion")
    else:
        package["languageVersion"] = value
    rewrite(fixture)
    assert run(fixture).returncode == 1


def test_rejects_digest_change(fixture: dict[str, object]) -> None:
    assert run(fixture, "--expected-digest", "0" * 64).returncode == 1


def test_rejects_hostile_mutation_after_snapshot(fixture: dict[str, object]) -> None:
    first = run(fixture)
    assert first.returncode == 0, first.stderr
    digest = first.stdout.strip()
    Path(fixture["config"]).write_bytes(Path(fixture["config"]).read_bytes() + b" ")
    mutated = run(fixture, "--expected-digest", digest)
    assert mutated.returncode == 1


def test_rejects_symbolic_library_root(fixture: dict[str, object]) -> None:
    library = Path(fixture["cache"]) / "hosted/pub.dev/archive-4.2.0/lib"
    library.rmdir()
    library.symlink_to(Path(fixture["project"]) / "lib", target_is_directory=True)
    assert run(fixture).returncode == 1


def test_rejects_symbolic_path_component(fixture: dict[str, object], tmp_path: Path) -> None:
    alias = (tmp_path / "project-alias").resolve()
    if alias.exists():
        alias.unlink()
    alias.symlink_to(fixture["project"], target_is_directory=True)
    fixture["project"] = alias
    fixture["config"] = alias / ".dart_tool/package_config.json"
    fixture["lock"] = alias / "pubspec.lock"
    assert run(fixture).returncode == 1


def test_rejects_config_replacement_before_open(fixture: dict[str, object]) -> None:
    config = Path(fixture["config"])
    original = validator.os.open

    def raced(path: str | bytes | os.PathLike[str], flags: int, *args: object, **kwargs: object) -> int:
        target = Path(os.fsdecode(path))
        if target == config and not flags & getattr(os, "O_DIRECTORY", 0):
            replacement = config.parent / "replacement.json"
            replacement.write_text("{}\n", encoding="utf-8")
            os.replace(replacement, config)
        return original(path, flags, *args, **kwargs)

    validator.os.open = raced
    try:
        with pytest.raises(validator.Refused, match="replaced before it was opened"):
            validator._validate(namespace(fixture))
    finally:
        validator.os.open = original


def test_rejects_lockfile_replacement_before_open(fixture: dict[str, object]) -> None:
    lock = Path(fixture["lock"])
    original = validator.os.open

    def raced(path: str | bytes | os.PathLike[str], flags: int, *args: object, **kwargs: object) -> int:
        target = Path(os.fsdecode(path))
        if target == lock and not flags & getattr(os, "O_DIRECTORY", 0):
            replacement = lock.parent / "replacement.lock"
            replacement.write_text("packages: {}\n", encoding="utf-8")
            os.replace(replacement, lock)
        return original(path, flags, *args, **kwargs)

    validator.os.open = raced
    try:
        with pytest.raises(validator.Refused, match="replaced before it was opened"):
            validator._validate(namespace(fixture))
    finally:
        validator.os.open = original
