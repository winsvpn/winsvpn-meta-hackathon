#!/usr/bin/env python3
"""Hostile regressions for the Firefox verifier --fixed ProxyInfo mutator.

These tests do not launch a browser and do not touch packaged artifacts. They
pin that make_https_proxy_variant operates on the current inline live-endpoint
return object and cannot attest an HTTPS variant that is not actually there.
They also pin --fixed tunnel-state routing: TLS mode advertises the TLS
proxy port, HTTP mode advertises the HTTP port, event capture is bound to
that advertised port, and a loopback CONNECT proves Firefox-target state
would hit TLS -- with negative plaintext-port cases.
"""
from __future__ import annotations

import io
import json
import shutil
import socketserver
import sys
import threading
import time
import zipfile
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
EXT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

import verify_firefox  # noqa: E402
import assert_firefox_zip as afz  # noqa: E402

LIVE_HTTP = verify_firefox.LIVE_HTTP_PROXY_RETURN
LIVE_HTTPS = verify_firefox.LIVE_HTTPS_PROXY_RETURN
REAL_ADAPTER = EXT / "src" / "adapters" / "firefox.js"

STALE_CONST_INFO_HTTP = (
    "const info = { type: 'http', host: endpoint.host, port: endpoint.port };\n"
    "return info;\n"
)
STALE_CONST_INFO_HTTPS = (
    "const info = { type: 'https', host: endpoint.host, port: endpoint.port };\n"
    "return info;\n"
)
INLINE_HTTP = LIVE_HTTP + "\n"
INLINE_HTTPS = LIVE_HTTPS + "\n"
CURRENT_SHAPE = (
    "return { type: 'http', host: LOOPBACK_HOST, port: 1 };\n"
    "return { type: 'direct' };\n"
    f"{LIVE_HTTP}\n"
    "return { type: 'http', host: ep.host, port: ep.port };\n"
    "return { type: 'http', host: LOOPBACK_HOST, port: 1 };\n"
)


def _zip_with_manifest_json(payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", payload)
    return buffer.getvalue()


@pytest.mark.parametrize("value", ("NaN", "Infinity", "-Infinity", "1e400"))
def test_zip_gate_rejects_non_finite_manifest_json(value: str) -> None:
    payload = (
        '{"manifest_version": 3, "browser_specific_settings": '
        '{"gecko": {"metadata": {"score": %s}}}}' % value
    ).encode("ascii")
    result = afz.inspect_bytes(_zip_with_manifest_json(payload))
    assert result["ok"] is False
    assert any("non-finite JSON number" in failure for failure in result["failures"])


def test_zip_gate_rejects_duplicate_nested_manifest_identity_key() -> None:
    payload = (
        b'{"manifest_version": 3, "browser_specific_settings": {"gecko": {'
        b'"id": "companion@winsvpn.org", "id": "attacker@example.org"}}}'
    )
    result = afz.inspect_bytes(_zip_with_manifest_json(payload))
    assert result["ok"] is False
    assert any("duplicate manifest key: id" in failure for failure in result["failures"])


def _write_package(root: Path, adapter_source: str) -> Path:
    adapter = root / "src" / "adapters" / "firefox.js"
    adapter.parent.mkdir(parents=True, exist_ok=True)
    adapter.write_text(adapter_source, encoding="utf-8")
    return root


def _read_adapter(package: Path) -> str:
    return (package / "src" / "adapters" / "firefox.js").read_text(encoding="utf-8")


def _variant(package: Path) -> Path:
    return verify_firefox.make_https_proxy_variant(package, package)


def test_fixed_mutator_rejects_stale_const_info_http_shape(tmp_path: Path, capsys):
    pkg = _write_package(tmp_path, STALE_CONST_INFO_HTTP)
    with pytest.raises(verify_firefox.FixedVariantError, match="stale"):
        _variant(pkg)
    out = capsys.readouterr().out
    assert "already declares ProxyInfo type 'https'" not in out
    assert "http' -> 'https'" not in out
    assert _read_adapter(pkg) == STALE_CONST_INFO_HTTP
    with pytest.raises(verify_firefox.FixedVariantError, match="stale"):
        verify_firefox.proxy_type_in(pkg)


def test_fixed_mutator_stale_const_info_https_cannot_claim_variant(
    tmp_path: Path, capsys
):
    pkg = _write_package(tmp_path, STALE_CONST_INFO_HTTPS)
    with pytest.raises(verify_firefox.FixedVariantError, match="stale"):
        _variant(pkg)
    out = capsys.readouterr().out
    assert "already declares ProxyInfo type 'https'" not in out
    assert _read_adapter(pkg) == STALE_CONST_INFO_HTTPS
    with pytest.raises(verify_firefox.FixedVariantError, match="refusing to claim"):
        verify_firefox.proxy_type_in(pkg)


def test_fixed_mutator_rejects_duplicate_live_http_returns(tmp_path: Path, capsys):
    source = INLINE_HTTP + INLINE_HTTP
    pkg = _write_package(tmp_path, source)
    with pytest.raises(
        verify_firefox.FixedVariantError, match="duplicate/ambiguous"
    ):
        _variant(pkg)
    out = capsys.readouterr().out
    assert "already declares ProxyInfo type 'https'" not in out
    assert "http' -> 'https'" not in out
    assert _read_adapter(pkg) == source


def test_fixed_mutator_rejects_ambiguous_http_and_https_returns(
    tmp_path: Path, capsys
):
    source = INLINE_HTTP + INLINE_HTTPS
    pkg = _write_package(tmp_path, source)
    with pytest.raises(
        verify_firefox.FixedVariantError, match="duplicate/ambiguous"
    ):
        _variant(pkg)
    out = capsys.readouterr().out
    assert "already declares ProxyInfo type 'https'" not in out
    assert _read_adapter(pkg) == source
    with pytest.raises(verify_firefox.FixedVariantError, match="duplicate/ambiguous"):
        verify_firefox.proxy_type_in(pkg)


def test_fixed_mutator_rejects_noop_rewrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
):
    pkg = _write_package(tmp_path, CURRENT_SHAPE)
    monkeypatch.setattr(
        verify_firefox, "_rewrite_live_http_to_https", lambda text: text
    )
    with pytest.raises(verify_firefox.FixedVariantError, match="no-op"):
        _variant(pkg)
    out = capsys.readouterr().out
    assert "already declares ProxyInfo type 'https'" not in out
    assert "http' -> 'https'" not in out
    assert _read_adapter(pkg) == CURRENT_SHAPE
    assert verify_firefox.proxy_type_in(pkg) == "http"


def test_fixed_mutator_already_https_is_byte_identical_noop(tmp_path: Path, capsys):
    pkg = _write_package(tmp_path, INLINE_HTTPS)
    before = _read_adapter(pkg)
    _variant(pkg)
    out = capsys.readouterr().out
    assert "already declares ProxyInfo type 'https'" in out
    assert "http' -> 'https'" not in out
    assert _read_adapter(pkg) == before
    assert verify_firefox.proxy_type_in(pkg) == "https"


def test_fixed_mutator_applies_current_inline_http_object(tmp_path: Path, capsys):
    pkg = _write_package(tmp_path, CURRENT_SHAPE)
    assert verify_firefox.proxy_type_in(pkg) == "http"
    _variant(pkg)
    out = capsys.readouterr().out
    assert "http' -> 'https'" in out
    assert "already declares ProxyInfo type 'https'" not in out
    updated = _read_adapter(pkg)
    assert LIVE_HTTP not in updated
    assert updated.count(LIVE_HTTPS) == 1
    assert verify_firefox.proxy_type_in(pkg) == "https"
    assert updated.count("return { type: 'http', host: LOOPBACK_HOST, port: 1 };") == 2
    assert "return { type: 'http', host: ep.host, port: ep.port };" in updated
    assert "return { type: 'direct' };" in updated


def test_fixed_mutator_rewrites_shipping_firefox_adapter(tmp_path: Path, capsys):
    source = REAL_ADAPTER.read_text(encoding="utf-8")
    assert LIVE_HTTP in source
    assert "const info = { type: 'http', host: endpoint.host, port: endpoint.port };" not in source
    pkg = _write_package(tmp_path, source)
    assert verify_firefox.proxy_type_in(pkg) == "http"
    _variant(pkg)
    out = capsys.readouterr().out
    assert "http' -> 'https'" in out
    assert "already declares ProxyInfo type 'https'" not in out
    updated = _read_adapter(pkg)
    assert LIVE_HTTP not in updated
    assert updated.count(LIVE_HTTPS) == 1
    assert verify_firefox.proxy_type_in(pkg) == "https"
    assert updated.count("return [{ type: 'http', host: LOOPBACK_HOST, port: 1 }, null];") == 3
    assert "host: ep.host" not in updated


def test_fixed_mutator_is_copy_only_when_dest_differs(tmp_path: Path):
    src = _write_package(tmp_path / "src", CURRENT_SHAPE)
    dest = tmp_path / "dest"
    shutil.copytree(src, dest)
    verify_firefox.make_https_proxy_variant(src, dest)
    assert _read_adapter(src) == CURRENT_SHAPE
    updated = _read_adapter(dest)
    assert LIVE_HTTP not in updated
    assert updated.count(LIVE_HTTPS) == 1
    assert verify_firefox.proxy_type_in(dest) == "https"
    assert verify_firefox.proxy_type_in(src) == "http"


def test_verifier_classifies_and_mutates_the_minified_shipping_shape(tmp_path: Path, capsys):
    # tools/store_js_minifier.py (esbuild) rewrites the packaged adapter with
    # no spaces, double quotes, and no trailing semicolon before it ships.
    # The verifier and the --fixed mutator must both work on those exact
    # bytes, not only on the authored source shape.
    minified = (
        'const{settings,endpoint}=this._live;if(!settings||!endpoint)'
        '{return{type:"http",host:LOOPBACK_HOST,port:1}}'
        'if(!isInScope(settings,host)){return{type:"direct"}}'
        f'{verify_firefox.LIVE_HTTP_PROXY_RETURN_MINIFIED}'
        'return{type:"http",host:ep.host,port:ep.port}'
        'return{type:"http",host:LOOPBACK_HOST,port:1}'
    )
    pkg = _write_package(tmp_path, minified)
    assert verify_firefox.proxy_type_in(pkg) == "http"
    verify_firefox.make_https_proxy_variant(pkg, pkg)
    out = capsys.readouterr().out
    assert "http' -> 'https'" in out
    updated = _read_adapter(pkg)
    assert verify_firefox.LIVE_HTTP_PROXY_RETURN_MINIFIED not in updated
    assert updated.count(verify_firefox.LIVE_HTTPS_PROXY_RETURN_MINIFIED) == 1
    assert verify_firefox.proxy_type_in(pkg) == "https"
    assert 'return{type:"http",host:LOOPBACK_HOST,port:1}' in updated
    assert 'return{type:"http",host:ep.host,port:ep.port}' in updated


def test_verifier_rejects_both_shapes_present_at_once(tmp_path: Path):
    both = f"{INLINE_HTTP}{verify_firefox.LIVE_HTTP_PROXY_RETURN_MINIFIED}"
    with pytest.raises(verify_firefox.FixedVariantError, match="duplicate/ambiguous"):
        verify_firefox.live_proxy_type_in_text(both)


@pytest.fixture(autouse=True)
def _reset_capture():
    verify_firefox._TLS_EVENTS.clear()
    verify_firefox.dev_endpoint.log = verify_firefox._capture
    yield
    verify_firefox._TLS_EVENTS.clear()
    verify_firefox.dev_endpoint.log = verify_firefox._capture


def _harness(tmp_path: Path, *, tls_mode: bool) -> verify_firefox.Harness:
    work = tmp_path / "work"
    work.mkdir()
    h = verify_firefox.Harness(tmp_path, work, keep=True)
    h.tls_mode = tls_mode
    return h


def _state_port(h: verify_firefox.Harness) -> int:
    return int(json.loads(h.state_file.read_text(encoding="utf-8"))["proxyPort"])


class _AcceptAndClose(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        return


class _DummyMarker(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _dummy_marker(port: int) -> socketserver.ThreadingTCPServer:
    srv = _DummyMarker(("127.0.0.1", port), _AcceptAndClose)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _wait_connects(h: verify_firefox.Harness, mark: float, *, n: int = 1) -> list:
    deadline = time.time() + 2.0
    events: list = []
    while time.time() < deadline:
        events = h.endpoint_events(mark, kinds=("connect",))
        if len(events) >= n:
            return events
        time.sleep(0.05)
    return events


def test_http_mode_set_tunnel_state_advertises_http_port(tmp_path: Path):
    h = _harness(tmp_path, tls_mode=False)
    h.set_tunnel_state("connected")
    advertised = _state_port(h)
    assert advertised == h.proxy_port
    assert advertised == h.advertised_proxy_port()
    assert advertised != h.tls_proxy_port
    assert h.tls_proxy_port == 0


def test_tls_mode_set_tunnel_state_advertises_tls_port_not_http(tmp_path: Path):
    h = _harness(tmp_path, tls_mode=True)
    h.start_tls_proxy()
    try:
        h.set_tunnel_state("connected")
        advertised = _state_port(h)
        assert advertised == h.tls_proxy_port
        assert advertised == h.advertised_proxy_port()
        assert advertised != h.proxy_port
        assert advertised > 0
    finally:
        h.stop_tls_proxy()


def test_tls_mode_loopback_connect_hits_advertised_tls_port(tmp_path: Path):
    h = _harness(tmp_path, tls_mode=True)
    marker = _dummy_marker(h.http_port)
    h.start_tls_proxy()
    try:
        h.set_tunnel_state("connected")
        advertised = _state_port(h)
        assert advertised == h.tls_proxy_port
        assert advertised != h.proxy_port
        verify_firefox._TLS_EVENTS.clear()
        mark = 0.0
        result = verify_firefox.loopback_proxy_connect(
            advertised, token=h.token, use_tls=True
        )
        assert result["tls_error"] == ""
        assert result["ok"] is True
        events = _wait_connects(h, mark)
        assert len(events) >= 1
        assert all(e.get("port") == advertised for e in events)
        assert events[0].get("authenticated") is True
        assert events[0].get("target") == verify_firefox.ROUTED_HOST
        # Negative: the plaintext HTTP port is not the advertised hop.
        missed = verify_firefox.loopback_proxy_connect(
            h.proxy_port, token=h.token, use_tls=True
        )
        assert missed["ok"] is False
        assert all(e.get("port") != h.proxy_port for e in h.endpoint_events(mark))
    finally:
        h.stop_tls_proxy()
        marker.shutdown()
        marker.server_close()


def test_tls_mode_plaintext_connect_to_tls_port_is_not_connect(tmp_path: Path):
    h = _harness(tmp_path, tls_mode=True)
    h.start_tls_proxy()
    try:
        h.set_tunnel_state("connected")
        advertised = _state_port(h)
        verify_firefox._TLS_EVENTS.clear()
        mark = 0.0
        result = verify_firefox.loopback_proxy_connect(
            advertised, token=h.token, use_tls=False
        )
        assert result["ok"] is False
        time.sleep(0.2)
        assert h.endpoint_events(mark, kinds=("connect",)) == []
    finally:
        h.stop_tls_proxy()


def test_tls_mode_endpoint_events_ignore_plaintext_port_connects(tmp_path: Path):
    h = _harness(tmp_path, tls_mode=True)
    h.start_tls_proxy()
    try:
        h.set_tunnel_state("connected")
        advertised = _state_port(h)
        assert advertised != h.proxy_port
        mark = time.time()
        verify_firefox._TLS_EVENTS[:] = [
            {
                "t": mark,
                "kind": "connect",
                "target": "plaintext.wv-test.invalid",
                "port": h.proxy_port,
                "authenticated": True,
            }
        ]
        h.endpoint_log.write_text(
            json.dumps({
                "t": mark,
                "kind": "connect",
                "target": "plaintext.wv-test.invalid",
                "port": h.proxy_port,
                "authenticated": True,
            })
            + "\n",
            encoding="utf-8",
        )
        assert h.endpoint_events(mark, kinds=("connect",)) == []
        # Wrong-port capture stays dropped after a real TLS CONNECT too.
        marker = _dummy_marker(h.http_port)
        try:
            result = verify_firefox.loopback_proxy_connect(
                advertised, token=h.token, use_tls=True
            )
            assert result["ok"] is True
            events = _wait_connects(h, mark)
            assert len(events) >= 1
            assert all(e.get("port") == advertised for e in events)
            assert all(e.get("port") != h.proxy_port for e in events)
            assert all(
                e.get("target") != "plaintext.wv-test.invalid" for e in events
            )
        finally:
            marker.shutdown()
            marker.server_close()
    finally:
        h.stop_tls_proxy()


def test_http_mode_endpoint_events_still_read_plaintext_log(tmp_path: Path):
    h = _harness(tmp_path, tls_mode=False)
    h.set_tunnel_state("connected")
    assert _state_port(h) == h.proxy_port
    mark = time.time()
    payload = {
        "t": mark,
        "kind": "connect",
        "target": "routed.wv-test.invalid",
        "port": h.proxy_port,
        "authenticated": True,
    }
    h.endpoint_log.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    events = h.endpoint_events(mark, kinds=("connect",))
    assert len(events) == 1
    assert events[0]["port"] == h.proxy_port
    assert events[0]["target"] == "routed.wv-test.invalid"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
