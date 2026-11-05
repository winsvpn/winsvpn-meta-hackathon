#!/usr/bin/env python3
"""Firefox native-messaging identity binding for produced XPIs.

Firefox authorizes the desktop bridge by joining two facts: the add-on declares
an id in browser_specific_settings.gecko.id, and the installed native-host
manifest must list exactly that id in allowed_extensions. When the two disagree,
Firefox refuses the bridge silently, so a package that built with one id while
the shipped host allows another is a package that cannot route and does not say
why. These tests pin that assert_firefox_zip.py binds the produced XPI's id to
both canonical sources: the manifest fragment and the shipped host manifest.

No browser, no packaged artifact, no network and no signing are used.
"""
from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import assert_firefox_zip as afz  # noqa: E402

HOST_MANIFEST = (
    "tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json"
)
FRAGMENT = "extension/manifest/firefox.jsonc"


def _write_docs(root: Path, *, fragment_id: str, allowed: list[str]) -> None:
    host = root / HOST_MANIFEST
    host.parent.mkdir(parents=True, exist_ok=True)
    host.write_text(
        json.dumps(
            {
                "name": "org.winsvpn.bridge",
                "description": "Win's VPN browser bridge",
                "path": afz.NATIVE_HOST_TEMPLATE_PATH,
                "type": "stdio",
                "allowed_extensions": allowed,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    fragment = root / FRAGMENT
    fragment.parent.mkdir(parents=True, exist_ok=True)
    fragment.write_text(
        '{\n'
        '  "browser_specific_settings": {\n'
        '    "gecko": { "id": "%s" }\n'
        '  }\n'
        '}\n' % fragment_id,
        encoding="utf-8",
    )


def _overwrite_identity_doc(root: Path, relative: str, payload: bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _host_identity_payload(*, allowed: object = ...) -> bytes:
    document: dict[str, object] = {
        "name": afz.NATIVE_HOST_NAME,
        "path": afz.NATIVE_HOST_TEMPLATE_PATH,
        "type": afz.NATIVE_HOST_TYPE,
    }
    if allowed is not ...:
        document["allowed_extensions"] = allowed
    return json.dumps(document).encode("utf-8")


def _minimal_zip(gecko_id: str) -> bytes:
    manifest = {
        "manifest_version": 3,
        "name": afz.EXPECTED_NAME,
        "version": "1.0.0",
        "description": "Fixture only.",
        "browser_specific_settings": {"gecko": {"id": gecko_id}},
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "manifest.json", json.dumps(manifest).encode("utf-8")
        )
    return buffer.getvalue()


def test_real_repo_identity_sources_match_gate_constant() -> None:
    # The canonical sources a freshly-built XPI is judged against must agree with
    # the gate's constant, or the gate would be checking a different identity than
    # the host actually installed.
    assert afz.canonical_firefox_gecko_id() == afz.GECKO_ID
    assert afz.canonical_firefox_host_allowed_extensions() == [afz.GECKO_ID]


def test_firefox_host_identity_cli_checks_the_actual_template(capsys) -> None:
    assert afz.main(["assert_firefox_zip.py", "--check-host-identity"]) == 0
    assert "FIREFOX HOST IDENTITY: PASS" in capsys.readouterr().out


def test_firefox_host_identity_cli_refuses_drift(tmp_path, monkeypatch, capsys) -> None:
    _write_docs(tmp_path, fragment_id=afz.GECKO_ID, allowed=["other@example.org"])
    monkeypatch.setattr(afz, "REPO_ROOT", tmp_path)
    assert afz.main(["assert_firefox_zip.py", "--check-host-identity"]) == 1
    captured = capsys.readouterr()
    assert "PASS" not in captured.out
    assert "FIREFOX HOST IDENTITY: FAIL" in captured.err


def test_fragment_drift_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_docs(
        tmp_path, fragment_id="drifted@example.org", allowed=[afz.GECKO_ID]
    )
    monkeypatch.setattr(afz, "REPO_ROOT", tmp_path)
    failures = afz.identity_binding_failures(afz.GECKO_ID)
    assert any("canonical fragment" in f for f in failures)


def test_host_manifest_drift_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_docs(
        tmp_path, fragment_id=afz.GECKO_ID, allowed=["other@example.org"]
    )
    monkeypatch.setattr(afz, "REPO_ROOT", tmp_path)
    failures = afz.identity_binding_failures(afz.GECKO_ID)
    assert any("allowed_extensions" in f for f in failures)
    # The produced XPI that carries the host's id, not the canonical id, fails the
    # fragment side of the binding in the same run.
    failures_other = afz.identity_binding_failures("other@example.org")
    assert any("canonical fragment" in f for f in failures_other)


def test_matching_identity_has_no_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_docs(
        tmp_path, fragment_id=afz.GECKO_ID, allowed=[afz.GECKO_ID]
    )
    monkeypatch.setattr(afz, "REPO_ROOT", tmp_path)
    assert afz.identity_binding_failures(afz.GECKO_ID) == []


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("name", None, "must name exactly"),
        ("name", "org.attacker.bridge", "must name exactly"),
        ("type", None, "must have type"),
        ("type", "socket", "must have type"),
        ("path", None, "installer-owned path placeholder"),
        ("path", "/tmp/attacker-host", "installer-owned path placeholder"),
    ],
    ids=(
        "missing-name",
        "drifted-name",
        "missing-type",
        "drifted-type",
        "missing-path",
        "drifted-path",
    ),
)
def test_host_identity_schema_drift_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
    expected: str,
) -> None:
    _write_docs(tmp_path, fragment_id=afz.GECKO_ID, allowed=[afz.GECKO_ID])
    host_path = tmp_path / HOST_MANIFEST
    document = json.loads(host_path.read_text(encoding="utf-8"))
    if value is None:
        document.pop(field)
    else:
        document[field] = value
    host_path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(afz, "REPO_ROOT", tmp_path)
    with pytest.raises(afz.PackageError, match=expected):
        afz.canonical_firefox_host_allowed_extensions()
    result = afz.inspect_bytes(_minimal_zip(afz.GECKO_ID))
    assert result["ok"] is False
    assert any(expected in failure for failure in result["failures"])


@pytest.mark.parametrize(
    "allowed",
    [
        ["attacker@example.org", afz.GECKO_ID],
        [afz.GECKO_ID, "attacker@example.org"],
    ],
    ids=("unauthorized-first-valid-last", "valid-first-unauthorized-last"),
)
def test_host_identity_rejects_mixed_authorized_and_unauthorized_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    allowed: list[str],
) -> None:
    _write_docs(tmp_path, fragment_id=afz.GECKO_ID, allowed=allowed)
    monkeypatch.setattr(afz, "REPO_ROOT", tmp_path)
    with pytest.raises(afz.PackageError, match="exactly one non-empty"):
        afz.canonical_firefox_host_allowed_extensions()
    result = afz.inspect_bytes(_minimal_zip(afz.GECKO_ID))
    assert result["ok"] is False
    assert any("exactly one non-empty" in failure for failure in result["failures"])


def test_identity_binding_fails_closed_when_documents_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(afz, "REPO_ROOT", tmp_path)
    with pytest.raises(afz.PackageError):
        afz.canonical_firefox_gecko_id()
    with pytest.raises(afz.PackageError):
        afz.canonical_firefox_host_allowed_extensions()
    failures = afz.identity_binding_failures(afz.GECKO_ID)
    assert any("Firefox manifest fragment" in f and "unavailable" in f for f in failures)
    assert any("Firefox native-host manifest" in f and "unavailable" in f for f in failures)
    result = afz.inspect_bytes(_minimal_zip(afz.GECKO_ID))
    assert result["ok"] is False
    assert any("Firefox manifest fragment" in f for f in result["failures"])
    assert any("Firefox native-host manifest" in f for f in result["failures"])


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"\xff", "unparseable"),
        (b"{", "unparseable"),
        (b"[]", "must be a JSON object"),
        (_host_identity_payload(), "exactly one non-empty"),
        (_host_identity_payload(allowed=None), "exactly one non-empty"),
        (_host_identity_payload(allowed=[]), "exactly one non-empty"),
        (
            _host_identity_payload(
                allowed=["companion@winsvpn.org", "other@example.org"]
            ),
            "exactly one non-empty",
        ),
        (
            b'{"allowed_extensions": ["companion@winsvpn.org"], '
            b'"allowed_extensions": ["other@example.org"]}',
            "duplicate manifest key",
        ),
        (
            b'{"allowed_extensions": ["companion@winsvpn.org"], '
            b'"metadata": {"score": NaN}}',
            "non-finite JSON number",
        ),
        (
            b'{"allowed_extensions": ["companion@winsvpn.org"], '
            b'"metadata": {"score": Infinity}}',
            "non-finite JSON number",
        ),
        (
            b'{"allowed_extensions": ["companion@winsvpn.org"], '
            b'"metadata": {"score": -Infinity}}',
            "non-finite JSON number",
        ),
        (
            b'{"allowed_extensions": ["companion@winsvpn.org"], '
            b'"metadata": {"score": 1e400}}',
            "non-finite JSON number",
        ),
    ],
    ids=(
        "invalid-utf8",
        "invalid-json",
        "non-object",
        "missing-identity",
        "null-identity",
        "absent-identity",
        "multiple-identities",
        "duplicate-identity-key",
        "nested-nan",
        "nested-infinity",
        "nested-negative-infinity",
        "overflow-to-infinity",
    ),
)
def test_host_identity_document_failures_are_not_skipped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    expected: str,
) -> None:
    _write_docs(tmp_path, fragment_id=afz.GECKO_ID, allowed=[afz.GECKO_ID])
    _overwrite_identity_doc(tmp_path, HOST_MANIFEST, payload)
    monkeypatch.setattr(afz, "REPO_ROOT", tmp_path)
    with pytest.raises(afz.PackageError):
        afz.canonical_firefox_host_allowed_extensions()
    failures = afz.identity_binding_failures(afz.GECKO_ID)
    assert any(
        "Firefox native-host manifest" in failure and expected in failure
        for failure in failures
    )


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"\xff", "unparseable"),
        (b"{", "unparseable"),
        (b"[]", "must be a JSON object"),
        (b"{}", "malformed browser_specific_settings"),
        (
            b'{"browser_specific_settings": {"gecko": []}}',
            "malformed browser_specific_settings.gecko",
        ),
        (
            b'{"browser_specific_settings": {"gecko": {}}}',
            "malformed gecko.id",
        ),
        (
            b'{"browser_specific_settings": {"gecko": {"id": ""}}}',
            "malformed gecko.id",
        ),
        (
            b'{"browser_specific_settings": {"gecko": {'
            b'"id": "companion@winsvpn.org", "id": "other@example.org"}}}',
            "duplicate manifest key",
        ),
        (
            b'{"browser_specific_settings": {"gecko": {'
            b'"id": "companion@winsvpn.org", '
            b'"metadata": {"score": NaN}}}}',
            "non-finite JSON number",
        ),
        (
            b'{"browser_specific_settings": {"gecko": {'
            b'"id": "companion@winsvpn.org", '
            b'"metadata": {"score": Infinity}}}}',
            "non-finite JSON number",
        ),
        (
            b'{"browser_specific_settings": {"gecko": {'
            b'"id": "companion@winsvpn.org", '
            b'"metadata": {"score": -Infinity}}}}',
            "non-finite JSON number",
        ),
        (
            b'{"browser_specific_settings": {"gecko": {'
            b'"id": "companion@winsvpn.org", '
            b'"metadata": {"score": 1e400}}}}',
            "non-finite JSON number",
        ),
    ],
    ids=(
        "invalid-utf8",
        "invalid-json",
        "non-object",
        "missing-settings",
        "malformed-gecko",
        "missing-id",
        "empty-id",
        "duplicate-id-key",
        "nested-nan",
        "nested-infinity",
        "nested-negative-infinity",
        "overflow-to-infinity",
    ),
)
def test_fragment_identity_document_failures_are_not_skipped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    expected: str,
) -> None:
    _write_docs(tmp_path, fragment_id=afz.GECKO_ID, allowed=[afz.GECKO_ID])
    _overwrite_identity_doc(tmp_path, FRAGMENT, payload)
    monkeypatch.setattr(afz, "REPO_ROOT", tmp_path)
    with pytest.raises(afz.PackageError):
        afz.canonical_firefox_gecko_id()
    failures = afz.identity_binding_failures(afz.GECKO_ID)
    assert any(
        "Firefox manifest fragment" in failure and expected in failure
        for failure in failures
    )


@pytest.mark.parametrize(
    ("fragment_id", "allowed", "expected"),
    [
        ("PLACEHOLDER_FIREFOX_EXTENSION_ID", [afz.GECKO_ID], "canonical fragment"),
        (afz.GECKO_ID, ["PLACEHOLDER_FIREFOX_EXTENSION_ID"], "allowed_extensions"),
    ],
    ids=("fragment-placeholder", "host-placeholder"),
)
def test_placeholder_firefox_identity_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fragment_id: str,
    allowed: list[str],
    expected: str,
) -> None:
    _write_docs(tmp_path, fragment_id=fragment_id, allowed=allowed)
    monkeypatch.setattr(afz, "REPO_ROOT", tmp_path)
    failures = afz.identity_binding_failures(afz.GECKO_ID)
    assert any(expected in failure for failure in failures)


def test_inspect_bytes_applies_identity_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Prove the produced-XPI inspection path actually invokes the binding: a
    # synthetic disagreement must surface as a failure inside inspect_bytes.
    _write_docs(
        tmp_path, fragment_id="drifted@example.org", allowed=[afz.GECKO_ID]
    )
    monkeypatch.setattr(afz, "REPO_ROOT", tmp_path)
    result = afz.inspect_bytes(_minimal_zip(afz.GECKO_ID))
    assert any("canonical fragment" in f for f in result["failures"])
    assert result["gecko_id"] == afz.GECKO_ID


def test_inspect_bytes_real_produced_xpi_has_no_binding_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A produced XPI carrying the canonical id, judged against canonical docs,
    # must not trip the identity binding.
    _write_docs(
        tmp_path, fragment_id=afz.GECKO_ID, allowed=[afz.GECKO_ID]
    )
    monkeypatch.setattr(afz, "REPO_ROOT", tmp_path)
    result = afz.inspect_bytes(_minimal_zip(afz.GECKO_ID))
    assert not any("allowed_extensions" in f for f in result["failures"])
    assert not any("canonical fragment" in f for f in result["failures"])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
