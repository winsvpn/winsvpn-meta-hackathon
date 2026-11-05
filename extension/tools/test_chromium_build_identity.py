"""Local build identities retain exact allowlists without receipt expiry."""
import copy
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import assert_chrome_zip as gate


@pytest.fixture
def identity_tree(tmp_path, monkeypatch):
    record = json.loads((gate.ROOT / "store_listings/store_identity.json").read_bytes())
    for relative in gate.CHROMIUM_HOST_MANIFEST_RELS.values():
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((gate.REPO_ROOT / relative).read_bytes())
    path = tmp_path / "extension/store_listings/store_identity.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(record), encoding="utf-8")
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    return record, path


def test_build_identity_does_not_require_an_owner_receipt(identity_tree):
    record, path = identity_tree
    record.pop("owner_identity_receipt")
    path.write_text(json.dumps(record), encoding="utf-8")
    assert gate.build_native_identities() == {
        browser: record["stores"][f"{browser}-extension-package"]["store_id"]
        for browser in ("chrome", "edge")
    }


@pytest.mark.parametrize("browser", ["chrome", "edge"])
@pytest.mark.parametrize("field,value", [
    ("store_id", "a" * 32),
    ("listing_name", "Wrong target"),
    ("native_host_template", "other.json"),
    ("native_host_allowlist", ["chrome-extension://*/"]),
])
def test_build_identity_rejects_record_drift(identity_tree, browser, field, value):
    record, path = identity_tree
    record["stores"][f"{browser}-extension-package"][field] = value
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(gate.PackageError, match="does not match"):
        gate.build_native_identities()


@pytest.mark.parametrize("field,value", [
    ("contract", "wrong"), ("schema_version", True),
    ("native_host_name", "wrong"), ("stores", []),
])
def test_build_identity_rejects_schema_drift(identity_tree, field, value):
    record, path = identity_tree
    record[field] = value
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(gate.PackageError, match="invalid schema"):
        gate.build_native_identities()


def test_build_identity_rejects_duplicate_missing_and_symlink_record(identity_tree):
    record, path = identity_tree
    path.write_text('{"contract":"first",' + json.dumps(record)[1:], encoding="utf-8")
    with pytest.raises(gate.PackageError, match="duplicate manifest key"):
        gate.build_native_identities()
    path.unlink()
    with pytest.raises(gate.PackageError, match="unavailable or invalid"):
        gate.build_native_identities()
    target = path.with_name("record.json")
    target.write_text(json.dumps(record), encoding="utf-8")
    path.symlink_to(target)
    with pytest.raises(gate.PackageError, match="unavailable or invalid"):
        gate.build_native_identities()


def test_build_identity_rejects_shared_id_even_when_record_agrees(identity_tree):
    record, path = identity_tree
    chrome = record["stores"]["chrome-extension-package"]
    edge = copy.deepcopy(record["stores"]["edge-extension-package"])
    edge["store_id"] = chrome["store_id"]
    edge["native_host_allowlist"] = chrome["native_host_allowlist"]
    record["stores"]["edge-extension-package"] = edge
    path.write_text(json.dumps(record), encoding="utf-8")
    manifest = gate.REPO_ROOT / gate.CHROMIUM_HOST_MANIFEST_RELS["edge"]
    document = gate.jsonc.loads(manifest.read_text())
    document["allowed_origins"] = edge["native_host_allowlist"]
    manifest.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(gate.PackageError, match="must be distinct"):
        gate.build_native_identities()


def test_build_identity_cli_is_exact(identity_tree, capsys):
    assert gate.main(["assert_chrome_zip.py", "--native-identities"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    with pytest.raises(gate.PackageError, match="usage is exactly"):
        gate.main(["assert_chrome_zip.py", "--native-identities", "extra"])


@pytest.mark.parametrize("browser", ["chrome", "edge"])
def test_zip_checker_reports_release_identity_drift(tmp_path, monkeypatch, browser):
    record = json.loads(gate.checks.RELEASE_IDENTITY_MAP_PATH.read_bytes())
    mapping = record["platform_mappings"]["browser_extensions"]
    mapping["version"] = "9.9.9"
    mapping["target_versions"] = {
        target: "9.9.9" for target in gate.checks.EXTENSION_RELEASE_TARGETS.values()
    }
    path = tmp_path / "release-identity.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    monkeypatch.setattr(gate.checks, "RELEASE_IDENTITY_MAP_PATH", path)
    payload = (gate.ROOT / "dist" / f"wins-vpn-companion-{browser}.zip").read_bytes()
    result = gate.inspect_bytes(payload, browser)
    assert result["ok"] is False
    assert any("must equal pubspec" in failure for failure in result["failures"])
