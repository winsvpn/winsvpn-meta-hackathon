"""EXT-33: strict pubspec version parsing without external project fixtures."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from store_version import read_pubspec_manifest_version


@pytest.mark.parametrize("version", ["1.0.17-beta.1+34", "01.0.16+33", "1.00.16", "65536.0.0", "1.0.65536", "1.0", "1.0.16+bad"])
def test_invalid_version_refused(tmp_path, version):
    pubspec = tmp_path / "pubspec.yaml"
    pubspec.write_text(f"version: {version}\n")
    with pytest.raises(ValueError):
        read_pubspec_manifest_version(pubspec)


@pytest.mark.parametrize("line", ["1.0.16+33", "'1.0.16+33' # current", '"1.0.16+33"', "65535.0.0"])
def test_store_legal_version_accepted(tmp_path, line):
    pubspec = tmp_path / "pubspec.yaml"
    pubspec.write_text(f"version: {line}\n")
    assert read_pubspec_manifest_version(pubspec) in {"1.0.16", "65535.0.0"}


def test_duplicate_version_refused(tmp_path):
    pubspec = tmp_path / "pubspec.yaml"
    pubspec.write_text("version: 1.0.16+33\nversion: 1.0.16+33\n")
    with pytest.raises(ValueError):
        read_pubspec_manifest_version(pubspec)

