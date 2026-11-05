#!/usr/bin/env python3
"""A stand-in for the desktop bridge's local proxy, plus a marker web server.

Mirrors `lib/browser_bridge_proxy.dart` closely enough to be evidence:

  * loopback-only HTTP CONNECT proxy, no plain-HTTP forwarding
  * bearer token presented as HTTP Basic in Proxy-Authorization, where the
    username is ignored and the password is the token
  * 407 with `Proxy-Authenticate: Basic realm="wins-bridge"` when absent or wrong
  * 503 when the tunnel gate is shut, and the auth check happens FIRST so an
    unauthenticated caller cannot use the proxy as an oracle for whether the
    VPN is up

Two things make it useful as evidence rather than plumbing:

  1. IT LOGS THE TARGET OF EVERY CONNECT. A CONNECT line carries a hostname, so
     seeing the name arrive here proves the browser did not resolve it locally.
     That is the DNS question, answered by observation.

  2. IT IS A CATCH-ALL. Whatever host is requested, it connects to the local
     marker server. The whole test therefore runs against names under
     `.invalid`, which RFC 2606 guarantees will never resolve. A name that
     cannot resolve is the sharpest probe available: if the page loads, the name
     must have been handed to the proxy; if it fails to resolve, the browser
     resolved it itself and did not use the proxy.

     Nothing leaves the machine and no real host is ever contacted.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

LOG_LOCK = threading.Lock()
LOG_PATH = None
MARKER = "WV-MARKER-OK"


def log(event: dict) -> None:
    event["t"] = time.time()
    line = json.dumps(event)
    with LOG_LOCK:
        if LOG_PATH:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        print(line, flush=True)


def make_proxy_cert(directory: Path) -> tuple[Path, Path]:
    """OBSOLETE: the bridge's TLS certificate, removed per ruling 2026-08-07.

    Firefox now uses webRequest over plaintext, no certificate, no cert9.db
    write. This function is kept as a stub so old harnesses that import it do
    not break, but it is not used for routing. See docs/handoff/
    BROWSER_EXTENSION_FIREFOX_TLS_BRIDGE_20260807.md for the withdrawn design.
    """
    key = directory / "bridge-proxy.key"
    crt = directory / "bridge-proxy.crt"
    if key.exists() and crt.exists():
        return key, crt
    directory.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-days", "2",
         # Anonymous on purpose, and it must stay that way: this subject is
         # what lands in a real profile's cert9.db, which survives removing
         # the extension and uninstalling the app. See the block above
         # kBridgeProxyCertificateOpenSslRecipe in lib/browser_bridge_proxy.dart.
         "-subj", "/CN=localhost",
         "-addext", "basicConstraints=critical,CA:FALSE",
         "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
         "-addext", "extendedKeyUsage=serverAuth",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True,
    )
    return key, crt


def make_cert(directory: Path) -> tuple[Path, Path]:
    """A self-signed certificate for *.wv-test.invalid.

    This is the FAKE INTERNET behind the proxy, not the bridge -- see
    `make_proxy_cert` above for that one.

    `basicConstraints=critical,CA:FALSE` is explicit, and it was not always.
    `openssl req -x509` defaults to `CA:TRUE`, and mozilla::pkix refuses a
    certificate marked `CA:TRUE` when it is presented as an end-entity server
    certificate, whatever trust record the profile holds for it. Nobody noticed
    for as long as every Firefox run opened its session with
    `acceptInsecureCerts`, which switches certificate checking off browser-wide
    -- the first run with checking ON failed here, on the scaffolding, before
    reaching anything under test. That is a small illustration of the larger
    point: a flag that makes a whole class of failure invisible makes every
    result that depended on it partial.
    """
    key = directory / "marker.key"
    crt = directory / "marker.crt"
    if key.exists() and crt.exists():
        return key, crt
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-days", "2",
         "-subj", "/CN=wv-test.invalid",
         "-addext", "basicConstraints=critical,CA:FALSE",
         "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
         "-addext", "extendedKeyUsage=serverAuth",
         "-addext", "subjectAltName=DNS:wv-test.invalid,DNS:*.wv-test.invalid"],
        check=True, capture_output=True,
    )
    return key, crt


class MarkerHandler(socketserver.StreamRequestHandler):
    timeout = 15

    def handle(self) -> None:
        try:
            request = self.rfile.readline(65536).decode("latin-1").strip()
        except OSError:
            return
        host_header = ""
        while True:
            try:
                line = self.rfile.readline(65536)
            except OSError:
                break
            if not line or line in (b"\r\n", b"\n"):
                break
            if line.lower().startswith(b"host:"):
                host_header = line.decode("latin-1").split(":", 1)[1].strip()
        log({"kind": "http", "request": request, "host_header": host_header})
        body = (
            f"<!doctype html><meta charset=utf-8><title>{MARKER}</title>"
            f"<h1>{MARKER}</h1><p id=host>{host_header}</p>"
        ).encode()
        try:
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Cache-Control: no-store\r\nConnection: close\r\n\r\n" + body
            )
        except OSError:
            pass


class TlsServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, context: ssl.SSLContext):
        self.context = context
        super().__init__(addr, handler)

    def get_request(self):
        sock, addr = self.socket.accept()
        try:
            return self.context.wrap_socket(sock, server_side=True), addr
        except (ssl.SSLError, OSError) as e:
            log({"kind": "tls_error", "detail": str(e)[:120]})
            try:
                sock.close()
            except OSError:
                pass
            raise


class ConnectProxyHandler(socketserver.StreamRequestHandler):
    timeout = 20
    token = ""
    marker_port = 0
    gate_file = ""

    def handle(self) -> None:
        try:
            self._handle()
        except OSError as e:
            log({"kind": "proxy_error", "detail": str(e)[:120]})

    def _tunnel_open(self) -> bool:
        if not self.gate_file:
            return True
        try:
            with open(self.gate_file, "r", encoding="utf-8") as fh:
                return json.load(fh).get("proxyReady") is True
        except (OSError, json.JSONDecodeError, AttributeError):
            return False

    def _handle(self) -> None:
        request_line = self.rfile.readline(65536).decode("latin-1", "replace").strip()
        headers: list[str] = []
        while True:
            line = self.rfile.readline(65536)
            if not line or line in (b"\r\n", b"\n"):
                break
            headers.append(line.decode("latin-1", "replace").strip())

        parts = request_line.split()
        method = parts[0] if parts else ""
        target = parts[1] if len(parts) > 1 else ""

        if method != "CONNECT":
            # Plain-HTTP forwarding is deliberately not implemented, exactly as
            # the desktop bridge does not implement it: a second parser and a
            # second class of header smuggling for no gain.
            log({"kind": "proxy_refused_method", "method": method, "target": target})
            self._respond(405, "Method Not Allowed")
            return

        supplied = ""
        for header in headers:
            if header.lower().startswith("proxy-authorization:"):
                value = header.split(":", 1)[1].strip()
                if value.lower().startswith("basic "):
                    try:
                        decoded = base64.b64decode(value[6:].strip()).decode("utf-8", "replace")
                        supplied = decoded.split(":", 1)[1] if ":" in decoded else ""
                    except Exception:  # noqa: BLE001
                        supplied = ""

        # Authentication BEFORE the tunnel gate, so that a caller who cannot
        # authenticate learns nothing about whether the VPN is up.
        if not self.token or supplied != self.token:
            log({"kind": "proxy_407", "target": target, "had_header": bool(supplied)})
            self._respond(407, "Proxy Authentication Required",
                          extra='Proxy-Authenticate: Basic realm="wins-bridge"\r\n')
            return

        if not self._tunnel_open():
            log({"kind": "proxy_503", "target": target})
            self._respond(503, "Tunnel Not Connected")
            return

        # THE OBSERVATION THIS FILE EXISTS FOR: the CONNECT target is a name,
        # which means the browser did not resolve it.
        host = target.rsplit(":", 1)[0]
        log({"kind": "connect", "target": host, "raw": target, "authenticated": True})

        try:
            upstream = socket.create_connection(("127.0.0.1", self.marker_port), timeout=10)
        except OSError:
            self._respond(502, "Bad Gateway")
            return
        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self._relay(self.connection, upstream)

    def _respond(self, code: int, reason: str, extra: str = "") -> None:
        try:
            self.wfile.write(
                f"HTTP/1.1 {code} {reason}\r\n{extra}Content-Length: 0\r\n"
                "Connection: close\r\n\r\n".encode("latin-1")
            )
        except OSError:
            pass

    @staticmethod
    def _relay(a: socket.socket, b: socket.socket) -> None:
        def pump(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        t = threading.Thread(target=pump, args=(a, b), daemon=True)
        t.start()
        pump(b, a)
        t.join(timeout=2)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    global LOG_PATH
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--proxy-port", type=int, required=True)
    ap.add_argument("--http-port", type=int, required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--gate-file", default="")
    ap.add_argument("--certdir", required=True)
    ap.add_argument("--log")
    args = ap.parse_args()
    LOG_PATH = args.log

    certdir = Path(args.certdir)
    certdir.mkdir(parents=True, exist_ok=True)
    key, crt = make_cert(certdir)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(crt), keyfile=str(key))

    marker = TlsServer(("127.0.0.1", args.http_port), MarkerHandler, context)
    handler = type("BoundConnectHandler", (ConnectProxyHandler,), {
        "token": args.token,
        "marker_port": args.http_port,
        "gate_file": args.gate_file,
    })
    proxy = Server(("127.0.0.1", args.proxy_port), handler)

    threading.Thread(target=marker.serve_forever, daemon=True).start()
    log({"kind": "ready", "proxy_port": args.proxy_port, "http_port": args.http_port,
         "token_len": len(args.token)})
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
