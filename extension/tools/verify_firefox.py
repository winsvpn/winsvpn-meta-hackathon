#!/usr/bin/env python3
"""Load the extension in a real Firefox and observe what it does.

    python3 tools/verify_firefox.py

The Firefox counterpart to verify_chromium.py. Firefox now uses webRequest
like Chromium, over plaintext. Previously it used proxyAuthorizationHeader
which required TLS; ruling 2026-08-07 removed that path. Adapter selection is runtime feature
detection rather than a build flag, so that code is present in every package --
and until this file was run it had never executed anywhere.

Nothing here asserts behaviour from documentation. Every check drives a real
Firefox over Marionette, makes a real request, and reads a real outcome: the
CONNECT lines the local proxy received, Gecko's own `about:neterror?e=` code,
and -- for the two claims where the extension's own report is not good enough --
the browser's actual preference values read in chrome context.

NOTHING LEAVES THE MACHINE. Every hostname is under `.invalid`, which RFC 2606
guarantees will never resolve; the local proxy is a catch-all that connects
everything to a local marker server; DNS-over-HTTPS is switched off in the
scratch profile so that not even a resolver we cannot observe is consulted. No
real host is contacted and no VPN session is started.

TWO THINGS THIS HARNESS HAS THAT THE CHROMIUM ONE DOES NOT.

  1. A DIRECT-CONNECTION DECOY. `network.dns.localDomains` maps one probe
     hostname to loopback inside this browser only. A second local server
     answers there with a different marker. So "the browser went direct" stops
     being an inference from an error code and becomes a page that says
     WV-DIRECT-LEAK. The unarmed control run proves the decoy can fire, which is
     the control the Chromium WebRTC probe was honest about lacking.
  2. PREFERENCE GROUND TRUTH. `browser.privacy.network.webRTCIPHandlingPolicy`
     reports what the extension asked for. The four `media.peerconnection.ice.*`
     preferences report what Gecko is actually doing. Only the second is
     evidence, so both are read and both are printed.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import dev_endpoint  # noqa: E402
import marionette  # noqa: E402

FIREFOX = "/Applications/Firefox.app/Contents/MacOS/firefox"
ADDON_ID = "companion@winsvpn.org"
NATIVE_HOST_DIR = Path.home() / "Library" / "Application Support" / "Mozilla" / "NativeMessagingHosts"
NATIVE_HOST_FILE = "org.winsvpn.bridge.json"

ROUTED_HOST = "routed.wv-test.invalid"
OTHER_HOST = "other.wv-test.invalid"
# The one name this browser is told to resolve to loopback, so that a direct
# connection is observable as a page rather than only as an error code.
LEAK_HOST = "leakprobe.wv-test.invalid"
MARKER = "WV-MARKER-OK"
LEAK_MARKER = "WV-DIRECT-LEAK"

# ---------------------------------------------------------------------------
# --real-host: the names change, and here is why they have to
# ---------------------------------------------------------------------------
#
# The stand-in proxy in `dev_endpoint.py` is a CATCH-ALL: whatever host a
# CONNECT names, it connects to the local marker. That is what lets every
# ordinary run use `.invalid` names, which RFC 2606 guarantees never resolve --
# a name arriving at the proxy is then proof the browser did not resolve it.
#
# The REAL compiled host is an honest proxy. `BridgeProxyServer._handle` calls
# `Socket.connect(host, port)`, so it does real name resolution and a `.invalid`
# target dies at getaddrinfo with a 502 and no page. The `.invalid` trick is
# therefore a property of the stand-in, not something the real host can be made
# to reproduce without lying about what it is.
#
# So `--real-host` uses `.localhost` names, which RFC 6761 makes the resolver
# answer locally -- confirmed on this machine, and no packet leaves it -- and
# replaces the DNS proof with a STRONGER one: every connection that reaches the
# fake internet is attributed to the process that opened it. A page served over
# a socket opened by `wins_bridge_host` is a page the browser did not fetch
# itself, which is the same conclusion the `.invalid` trick reaches by a
# different route, and it additionally proves WHICH process did the fetching.
REAL_HOST_ROUTED = "routed.localhost"
REAL_HOST_OTHER = "other.localhost"
REAL_HOST_LEAK = "leakprobe.localhost"

# In `--real-host` mode the fake internet is on an explicit port rather than
# 443, because nothing catches all any more.
SITE_PORT: int | None = None

# lsof's COMMAND for the real host's process. Matched on a prefix because macOS
# lsof truncates long command names in field output.
BRIDGE_PROCESS_PREFIX = "wins_bridge"

_LEAK_HITS: list[dict] = []

# Everything that reached the fake internet in --real-host mode, with the
# process that opened the socket. This is the observation that replaces the
# stand-in proxy's CONNECT log.
_UPSTREAM: list[dict] = []


def peer_process(peer_port: int) -> str:
    """Which process owns the other end of this connection, right now.

    Asked while the connection is still established, from inside the accept
    handler, so there is no race with a socket that closes afterwards. This is
    the whole of the direct-versus-proxied discrimination in `--real-host` mode:
    both paths end at the same loopback port, and the only thing that differs is
    who opened it.
    """
    try:
        out = subprocess.run(
            ["lsof", "-nP", "-a", f"-iTCP:{peer_port}", "-sTCP:ESTABLISHED", "-Fcpn"],
            capture_output=True, text=True, timeout=6).stdout
    except (OSError, subprocess.SubprocessError):
        return "?"
    pid, cmd = "", ""
    for line in out.splitlines():
        tag, value = line[:1], line[1:]
        if tag == "p":
            pid, cmd = value, ""
        elif tag == "c":
            cmd = value
        elif tag == "n" and value.startswith(f"127.0.0.1:{peer_port}->"):
            return cmd or f"pid{pid}"
    return "?"


def opened_by_bridge(peer: str) -> bool:
    return bool(peer) and peer.startswith(BRIDGE_PROCESS_PREFIX)

# dev_endpoint logs through a module-level function. In the subprocess that
# writes a file; the TLS proxy this harness runs in-process is captured here
# instead, so its lines do not interleave with the check output.
_TLS_EVENTS: list[dict] = []
# CONNECT-proxy kinds produced by ConnectProxyHandler. Bound to one listen
# port in TLS mode so a plaintext-port CONNECT cannot be counted as the hop
# Firefox-target state advertised.
_PROXY_CAPTURE_KINDS = frozenset({
    "connect", "proxy_407", "proxy_503", "proxy_error", "proxy_refused_method",
})


def _capture(event: dict) -> None:
    event.setdefault("t", time.time())
    _TLS_EVENTS.append(event)


def _capture_on_port(port: int):
    """Stamp in-process CONNECT-proxy events with the listener they hit."""

    def bound(event: dict) -> None:
        event = dict(event)
        if event.get("kind") in _PROXY_CAPTURE_KINDS:
            event["port"] = int(port)
        _capture(event)

    return bound


dev_endpoint.log = _capture


def url_for(host: str, port: int | None = None) -> str:
    if port is None:
        port = SITE_PORT
    return f"https://{host}/" if port is None else f"https://{host}:{port}/"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def loopback_proxy_connect(
    port: int,
    *,
    token: str,
    target: str | None = None,
    use_tls: bool = True,
    timeout: float = 2.0,
) -> dict:
    """One CONNECT to a loopback listener. No browser; 127.0.0.1 only."""
    if target is None:
        target = f"{ROUTED_HOST}:443"
    raw = None
    sock = None
    try:
        raw = socket.create_connection(("127.0.0.1", int(port)), timeout=timeout)
        sock = raw
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
            raw = None
        header = base64.b64encode(
            f"extension:{token}".encode("ascii")
        ).decode("ascii")
        sock.sendall(
            f"CONNECT {target} HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"Proxy-Authorization: Basic {header}\r\n"
            "\r\n".encode("ascii")
        )
        sock.settimeout(timeout)
        data = sock.recv(2048)
        status = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        established = status.startswith("HTTP/1.1 200")
        # 502: CONNECT was authenticated and the marker behind the proxy was
        # down. Either status is proof the hop was HTTP CONNECT over TLS.
        authenticated = established or status.startswith("HTTP/1.1 502")
        return {
            "ok": authenticated,
            "tls_error": "",
            "status": status,
            "established": established,
        }
    except ssl.SSLError as e:
        return {
            "ok": False,
            "tls_error": str(e)[:160],
            "status": "",
            "established": False,
        }
    except OSError as e:
        return {
            "ok": False,
            "tls_error": str(e)[:160],
            "status": "",
            "established": False,
        }
    finally:
        for s in (sock, raw):
            if s is None:
                continue
            try:
                s.close()
            except OSError:
                pass


class LeakHandler(socketserver.StreamRequestHandler):
    """The decoy. Anything that reaches here got here without the proxy."""

    timeout = 15
    attribute = False

    def handle(self) -> None:
        peer = peer_process(self.client_address[1]) if self.attribute else ""
        try:
            request = self.rfile.readline(65536).decode("latin-1", "replace").strip()
            while True:
                line = self.rfile.readline(65536)
                if not line or line in (b"\r\n", b"\n"):
                    break
        except OSError:
            return
        _LEAK_HITS.append({"t": time.time(), "request": request, "peer": peer,
                           "proxied": opened_by_bridge(peer)})
        body = (
            f"<!doctype html><meta charset=utf-8><title>{LEAK_MARKER}</title>"
            f"<h1>{LEAK_MARKER}</h1>"
        ).encode()
        try:
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Cache-Control: no-store\r\nConnection: close\r\n\r\n" + body
            )
        except OSError:
            pass


class AttributedMarkerHandler(socketserver.StreamRequestHandler):
    """The fake internet in `--real-host` mode, with one extra fact recorded.

    Same page and same marker as `dev_endpoint.MarkerHandler`, plus the process
    that opened the socket. That is what the stand-in proxy's CONNECT log used
    to provide and what the real host deliberately does not log -- the real
    proxy never records a destination, which is correct for a shipping
    component and useless for a harness, so the observation is moved to the far
    end of the hop where it costs the product nothing.
    """

    timeout = 15

    def handle(self) -> None:
        peer = peer_process(self.client_address[1])
        host_header = ""
        try:
            request = self.rfile.readline(65536).decode("latin-1", "replace").strip()
            while True:
                line = self.rfile.readline(65536)
                if not line or line in (b"\r\n", b"\n"):
                    break
                if line.lower().startswith(b"host:"):
                    host_header = line.decode("latin-1").split(":", 1)[1].strip()
        except OSError:
            return
        _UPSTREAM.append({
            "t": time.time(),
            "kind": "connect" if opened_by_bridge(peer) else "direct",
            # The name the browser asked for. In `--real-host` mode the CONNECT
            # authority is not observable (the hop is TLS and the real proxy
            # logs nothing), so the Host header is what names the site, and the
            # `peer` field is what says who fetched it.
            "target": host_header.split(":")[0],
            "raw": host_header,
            "request": request,
            "peer": peer,
            # The real proxy relays only after `_isAuthenticated` has passed AND
            # `gate.admitsTraffic` is true. A byte arriving here through it is
            # therefore an authenticated CONNECT by construction, not by
            # assertion.
            "authenticated": opened_by_bridge(peer),
        })
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


class DeadEndServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class DeadEndHandler(socketserver.BaseRequestHandler):
    """Nothing to serve, but a record of who knocked."""

    def handle(self) -> None:
        peer = peer_process(self.client_address[1])
        _UPSTREAM.append({
            "t": time.time(),
            "kind": "deadend",
            "target": "",
            "peer": peer,
            "proxied": opened_by_bridge(peer),
        })
        try:
            self.request.close()
        except OSError:
            pass


def make_localhost_cert(directory: Path) -> tuple[Path, Path]:
    """The fake internet's certificate, for the `.localhost` names.

    A separate object from `dev_endpoint.make_cert`, which speaks for
    `*.wv-test.invalid`. Same shape, same `CA:FALSE` marking -- the marking is
    not optional anywhere, because mozilla::pkix refuses a `CA:TRUE`
    certificate presented as an end-entity server certificate whatever trust
    record exists for it, which is how the previous lane found its own
    scaffolding had been a CA all along.
    """
    key = directory / "localhost.key"
    crt = directory / "localhost.crt"
    if key.exists() and crt.exists():
        return key, crt
    directory.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-days", "2",
         "-subj", "/CN=localhost",
         "-addext", "basicConstraints=critical,CA:FALSE",
         "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
         "-addext", "extendedKeyUsage=serverAuth",
         # Named one by one rather than `*.localhost`. A wildcard whose parent
         # is a single label is refused by OpenSSL and by NSS -- measured, with
         # curl reporting "no alternative certificate subject name matches
         # target host name" -- so the wildcard form silently produces a
         # certificate nothing accepts.
         "-addext",
         "subjectAltName=DNS:localhost,"
         f"DNS:{REAL_HOST_ROUTED},DNS:{REAL_HOST_OTHER},DNS:{REAL_HOST_LEAK},"
         "IP:127.0.0.1"],
        check=True, capture_output=True,
    )
    return key, crt


class Result:
    def __init__(self):
        self.checks: list[dict] = []

    def add(self, name: str, ok: bool, observed: str, expected: str = "") -> None:
        self.checks.append({"name": name, "ok": bool(ok), "observed": observed, "expected": expected})
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        print(f"         observed: {observed}")
        if expected and not ok:
            print(f"         expected: {expected}")

    def note(self, name: str, observed: str) -> None:
        """An observation that is reported but not scored."""
        self.checks.append({"name": name, "ok": True, "observed": observed, "note": True})
        print(f"  [NOTE] {name}")
        print(f"         observed: {observed}")

    @property
    def ok(self) -> bool:
        return all(c["ok"] for c in self.checks)


PREFS = """
user_pref("marionette.port", {mport});
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.startup.page", 0);
user_pref("browser.startup.homepage", "about:blank");
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.newtabpage.enabled", false);
user_pref("browser.startup.firstrunSkipsHomepage", true);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.server", "");
user_pref("app.update.enabled", false);
user_pref("app.update.auto", false);
user_pref("extensions.update.enabled", false);
user_pref("extensions.update.autoUpdateDefault", false);
user_pref("extensions.blocklist.enabled", false);
user_pref("extensions.getAddons.cache.enabled", false);
user_pref("extensions.systemAddon.update.enabled", false);
user_pref("extensions.autoDisableScopes", 0);
user_pref("xpinstall.signatures.required", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.provider.google4.updateURL", "");
user_pref("browser.safebrowsing.provider.mozilla.updateURL", "");
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);
user_pref("browser.region.network.url", "");
user_pref("browser.discovery.enabled", false);
user_pref("browser.ping-centre.telemetry", false);
user_pref("dom.push.connection.enabled", false);
user_pref("services.settings.server", "");
user_pref("identity.fxaccounts.enabled", false);
user_pref("browser.contentblocking.report.monitor.enabled", false);
// No DNS-over-HTTPS. A direct fallback must be observable here rather than
// disappearing into a resolver this harness cannot watch, and a test that
// claims nothing leaves the machine must not quietly send a name to one.
user_pref("network.trr.mode", 5);
// The direct-connection decoy, and the only name this browser is told to
// resolve. Everything else under .invalid stays unresolvable, as RFC 2606
// guarantees.
user_pref("network.dns.localDomains", "{leakhost}");
"""


class Harness:
    def __init__(self, package: Path, workdir: Path, keep: bool):
        self.package = package.resolve()
        self.work = workdir
        self.keep = keep
        self.profile = workdir / "profile"
        self.state_file = workdir / "bridge_state.json"
        self.bridge_log = workdir / "bridge.jsonl"
        self.endpoint_log = workdir / "endpoint.jsonl"
        self.token_file = workdir / "token"
        self.token = secrets.token_urlsafe(32)
        self.token_file.write_text(self.token, encoding="utf-8")

        self.proxy_port = free_port()
        self.http_port = free_port()
        self.leak_port = free_port()
        self.mport = free_port()

        self.endpoint_proc: subprocess.Popen | None = None
        self.browser_proc: subprocess.Popen | None = None
        self.leak_server: socketserver.TCPServer | None = None
        self.tls_proxy: socketserver.TCPServer | None = None
        self.tls_proxy_port = 0
        self.tls_mode = False  # TLS removed per ruling; plaintext only
        self.trust_bridge_cert = False  # obsolete per ruling; no cert
        self.proxy_cert: Path | None = None
        self.certs_trusted: list[str] = []
        self.allow_private_browsing = False
        # THE REAL COMPILED HOST, rather than dev_bridge.py. Set to the path of
        # the executable the native-messaging manifest should point at.
        self.real_host: Path | None = None
        self.real_marker_port = 0
        self.real_marker: socketserver.TCPServer | None = None
        self.dead_end: socketserver.TCPServer | None = None
        self.host_stderr = workdir / "realhost.stderr"
        self.real_ports: dict = {}
        self.inject_host = ""
        self.uuid = ""
        self.page_handle = ""
        self.ctl_handle = ""
        self.native_backup: bytes | None = None
        self.native_written = False
        self.m = marionette.Marionette(self.mport)
        self.result = Result()

    # -- scaffolding ---------------------------------------------------------

    def advertised_proxy_port(self) -> int:
        """Port Firefox-target tunnel state must hand the adapter.

        Shipping HTTP mode points at the plaintext CONNECT proxy. Fixed/TLS
        mode points at the in-process TLS CONNECT proxy. The two listeners
        are not interchangeable: type 'https' ProxyInfo against the HTTP
        port is the wrong hop, and the reverse is the same defect.
        """
        if self.real_host:
            return 0
        if self.tls_mode:
            return int(self.tls_proxy_port or 0)
        return int(self.proxy_port)

    def set_tunnel_state(self, status: str, *, proxy_ready: bool | None = None,
                         port: int | None = None,
                         winn: str = "unavailable_on_this_platform") -> None:
        ready = (status == "connected") if proxy_ready is None else proxy_ready
        advertised = self.advertised_proxy_port() if port is None else port
        self.state_file.write_text(json.dumps({
            "status": status,
            "detail": "none" if status == "connected" else "app_not_running",
            "winn": winn,
            "selectedSlug": "",
            "nodes": [],
            "canRequestConnect": status != "app_not_running",
            "proxyPort": advertised,
            "proxyReady": ready,
            "rxKib": 0,
            "txKib": 0,
        }), encoding="utf-8")

    def start_leak_server(self) -> None:
        certdir = self.work / "certs"
        certdir.mkdir(parents=True, exist_ok=True)
        if self.real_host:
            key, crt = make_localhost_cert(certdir)
            handler = type("AttributedLeakHandler", (LeakHandler,), {"attribute": True})
        else:
            key, crt = dev_endpoint.make_cert(certdir)
            handler = LeakHandler
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(crt), keyfile=str(key))
        self.leak_server = dev_endpoint.TlsServer(("127.0.0.1", self.leak_port), handler, ctx)
        threading.Thread(target=self.leak_server.serve_forever, daemon=True).start()

    # -- the fake internet, in --real-host mode ------------------------------

    def start_real_marker(self) -> None:
        """The site the real host's proxy actually connects to.

        In every other run the stand-in proxy is a catch-all and this does not
        exist. Here the real proxy resolves the name and opens a real socket, so
        there has to be something at the other end of it.
        """
        if self.real_marker is not None:
            return
        self.stop_dead_end()
        certdir = self.work / "certs"
        key, crt = make_localhost_cert(certdir)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(crt), keyfile=str(key))
        self.real_marker = dev_endpoint.TlsServer(
            ("127.0.0.1", self.real_marker_port), AttributedMarkerHandler, ctx)
        threading.Thread(target=self.real_marker.serve_forever, daemon=True).start()

    def stop_real_marker(self, dead_end: bool = False) -> None:
        if self.real_marker is not None:
            try:
                self.real_marker.shutdown()
                self.real_marker.server_close()
            except Exception:  # noqa: BLE001
                pass
            self.real_marker = None
        if not dead_end:
            self.stop_dead_end()
            return
        # WHO TRIED, once there is nothing to serve.
        #
        # A dead port answers "connection refused" to everybody and tells you
        # nothing about who knocked. This listener accepts, records the process
        # that opened the socket, and closes -- so "the proxy carried the
        # request and failed upstream" and "Gecko gave up on the proxy and went
        # direct" stop being indistinguishable. The second is the failure the
        # fail-closed proof exists to catch and it must not be inferable only
        # from an error code.
        for _ in range(40):
            try:
                self.dead_end = DeadEndServer(
                    ("127.0.0.1", self.real_marker_port), DeadEndHandler)
                break
            except OSError:
                time.sleep(0.25)
        else:
            raise RuntimeError("the dead-end listener could not take the site's port back")
        threading.Thread(target=self.dead_end.serve_forever, daemon=True).start()

    def stop_dead_end(self) -> None:
        if getattr(self, "dead_end", None) is None:
            return
        try:
            self.dead_end.shutdown()
            self.dead_end.server_close()
        except Exception:  # noqa: BLE001
            pass
        self.dead_end = None

    def real_host_listeners(self) -> list[int]:
        """The ports the real host process is listening on, from the OS.

        Ground truth for `proxyPort` and `proxyTlsPort`: the extension is told
        two numbers over native messaging, and this is where they are checked
        against sockets that actually exist.
        """
        try:
            pids = subprocess.run(["pgrep", "-f", "wins_bridge_host"],
                                  capture_output=True, text=True, timeout=6).stdout.split()
        except (OSError, subprocess.SubprocessError):
            return []
        ports: list[int] = []
        for pid in pids:
            try:
                out = subprocess.run(["lsof", "-nP", "-a", "-p", pid, "-iTCP", "-sTCP:LISTEN", "-Fn"],
                                     capture_output=True, text=True, timeout=6).stdout
            except (OSError, subprocess.SubprocessError):
                continue
            for line in out.splitlines():
                if line.startswith("n127.0.0.1:"):
                    try:
                        ports.append(int(line.split(":")[1]))
                    except ValueError:
                        pass
        return sorted(set(ports))

    def start_tls_proxy(self) -> int:
        """The same CONNECT proxy, reached over TLS.

        Firefox's documentation says proxyAuthorizationHeader is for HTTPS
        proxies. That is a claim about the browser, and this is how it gets
        tested rather than repeated: the identical handler, the identical token,
        the identical marker server behind it, differing only in whether the hop
        to the proxy is wrapped in TLS.
        """
        if self.tls_proxy is not None:
            return self.tls_proxy_port
        certdir = self.work / "certs"
        certdir.mkdir(parents=True, exist_ok=True)
        # The BRIDGE's certificate, not the marker's. Separate objects, because
        # the two model different things and are trusted by different means:
        # this one is what the desktop app would install into the browser's
        # trust store, and the marker's stands in for the ordinary CA-signed
        # internet behind the proxy. Mixing them would let a run pass because
        # the fake internet was trusted rather than because the proxy was.
        key, crt = dev_endpoint.make_proxy_cert(certdir)
        self.proxy_cert = crt
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(crt), keyfile=str(key))
        handler = type("TlsConnectHandler", (dev_endpoint.ConnectProxyHandler,), {
            "token": self.token,
            "marker_port": self.http_port,
            "gate_file": str(self.state_file),
        })
        self.tls_proxy_port = self.tls_proxy_port or free_port()
        self.tls_proxy = dev_endpoint.TlsServer(
            ("127.0.0.1", self.tls_proxy_port), handler, ctx)
        # Bind capture to this listener before accept() so every CONNECT
        # event carries the port Firefox-target state will advertise.
        dev_endpoint.log = _capture_on_port(self.tls_proxy_port)
        threading.Thread(target=self.tls_proxy.serve_forever, daemon=True).start()
        return self.tls_proxy_port

    def stop_tls_proxy(self) -> None:
        if self.tls_proxy is None:
            return
        try:
            self.tls_proxy.shutdown()
            self.tls_proxy.server_close()
        except Exception:  # noqa: BLE001
            pass
        self.tls_proxy = None
        dev_endpoint.log = _capture

    def start_endpoint(self) -> None:
        if self.real_host:
            self.start_real_marker()
        self.endpoint_proc = subprocess.Popen(
            [sys.executable, str(HERE / "dev_endpoint.py"),
             "--proxy-port", str(self.proxy_port),
             "--http-port", str(self.http_port),
             "--token", self.token,
             "--gate-file", str(self.state_file),
             "--certdir", str(self.work / "certs"),
             "--log", str(self.endpoint_log)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(80):
            try:
                with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.15)
        raise RuntimeError("the local proxy endpoint did not come up")

    def stop_endpoint(self) -> None:
        """Kill the whole desktop side: the proxy and the marker behind it."""
        # In --real-host mode the proxy belongs to a process the BROWSER owns,
        # so it cannot be taken away without also taking the native-messaging
        # port away -- which is a different failure (NO_HOST) from the one this
        # models. What is taken away instead is everything behind the proxy, so
        # the real proxy's CONNECT fails upstream and Gecko has to decide
        # whether to fall back to direct. That is the question the check asks;
        # the difference in mechanism is stated in the run output.
        self.stop_real_marker(dead_end=bool(self.real_host))
        if self.endpoint_proc and self.endpoint_proc.poll() is None:
            self.endpoint_proc.send_signal(signal.SIGKILL)
            self.endpoint_proc.wait(timeout=5)
        for port in filter(None, (self.proxy_port,)):
            for _ in range(50):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                        time.sleep(0.1)
                except OSError:
                    break
            else:
                raise RuntimeError(f"port {port} is still accepting connections")

    def install_native_host(self) -> None:
        """Write the host manifest where Firefox actually looks.

        NOT the same as Chromium, and it is worth stating: Firefox has no
        profile-local native-messaging directory on macOS. The only user-level
        location is ~/Library/Application Support/Mozilla/NativeMessagingHosts,
        so this harness -- unlike the Chromium one -- must write one file
        outside its scratch directory. Any pre-existing file of the same name is
        read first and restored on the way out.
        """
        NATIVE_HOST_DIR.mkdir(parents=True, exist_ok=True)
        target = NATIVE_HOST_DIR / NATIVE_HOST_FILE
        if self.native_backup is None and target.exists() and not self.native_written:
            self.native_backup = target.read_bytes()
            with (self.work / "native-host-manifest.original").open("xb") as backup:
                backup.write(self.native_backup)
                backup.flush()
                os.fsync(backup.fileno())
        wrapper = self.work / "bridge_wrapper.sh"
        if self.real_host:
            # THE REAL COMPILED HOST, launched by Firefox itself over stdio.
            # No environment variables: the real host takes arguments, and it
            # takes them from the manifest, which is the only place a browser
            # can supply them. `--tls-cert`/`--tls-key` are load-only -- the
            # host never generates or installs certificate material.
            #
            # There is no WV_BRIDGE_INJECT_HOST equivalent and there cannot be:
            # the real host's outbound choke point is
            # `encodeOutboundBridgeMessage`, which refuses to emit an
            # address-shaped value at all. The hostile-bridge check therefore
            # runs against the stand-in, and says so.
            cert = self.work / "certs" / "bridge-proxy.crt"
            key = self.work / "certs" / "bridge-proxy.key"
            tls_args = ""
            if cert.exists() and key.exists():
                tls_args = f' --tls-cert "{cert}" --tls-key "{key}"'
            wrapper.write_text(
                "#!/bin/sh\n"
                f'exec "{self.real_host}" --state-file "{self.state_file}"{tls_args} '
                f'2>>"{self.host_stderr}"\n',
                encoding="utf-8",
            )
        else:
            wrapper.write_text(
                "#!/bin/sh\n"
                f'export WV_BRIDGE_STATE="{self.state_file}"\n'
                f'export WV_BRIDGE_LOG="{self.bridge_log}"\n'
                f'export WV_BRIDGE_TOKEN="{self.token_file}"\n'
                f'export WV_BRIDGE_INJECT_HOST="{self.inject_host}"\n'
                f'exec "{sys.executable}" "{HERE / "dev_bridge.py"}"\n',
                encoding="utf-8",
            )
        wrapper.chmod(0o755)
        self.native_written = True
        target.write_text(json.dumps({
            "name": "org.winsvpn.bridge",
            "description": "Win's VPN desktop bridge (verification harness)",
            "path": str(wrapper),
            "type": "stdio",
            # Firefox keys the allow-list on the add-on id, not on an origin.
            "allowed_extensions": [ADDON_ID],
        }, indent=2), encoding="utf-8")

    def remove_native_host(self) -> None:
        if not self.native_written:
            return
        target = NATIVE_HOST_DIR / NATIVE_HOST_FILE
        try:
            if self.native_backup is not None:
                target.write_bytes(self.native_backup)
            elif target.exists():
                target.unlink()
        except OSError as error:
            self.keep = True
            raise RuntimeError(
                "Native-host manifest restoration failed; "
                "scratch wrapper and any original-manifest backup were retained."
            ) from error
        self.native_written = False

    def launch_browser(self) -> None:
        if not Path(FIREFOX).exists():
            raise RuntimeError(f"Firefox is not installed at {FIREFOX}")
        self.profile.mkdir(parents=True, exist_ok=True)
        prefs = PREFS.format(mport=self.mport, leakhost=LEAK_HOST)
        if self.real_host:
            # Gecko forces DIRECT for loopback names unless this is on, and it
            # applies BEFORE an extension's proxy.onRequest result is honoured.
            # Without it the add-on's routing decision would be silently
            # overridden and every routing check would measure the browser's
            # localhost rule rather than the extension. It is a property of the
            # scratch profile, not of the package.
            prefs += 'user_pref("network.proxy.allow_hijacking_localhost", true);\n'
        if self.allow_private_browsing:
            # Stands in for the user ticking "Run in Private Windows" in the
            # add-on manager. Firefox refuses proxy.settings.set outright without
            # it, which is a Firefox-only gate with no Chromium equivalent.
            prefs += 'user_pref("extensions.allowPrivateBrowsingByDefault", true);\n'
        (self.profile / "user.js").write_text(prefs, encoding="utf-8")
        env = dict(os.environ)
        env["MOZ_HEADLESS"] = "1"
        env.pop("MOZ_MARIONETTE_PORT", None)
        self.browser_proc = subprocess.Popen(
            # -remote-allow-system-access is what Firefox 153 requires before
            # Marionette will run script in chrome context. That context is where
            # the WebRTC and proxy claims are settled against Gecko's own
            # preferences rather than against the extension's report of them.
            [FIREFOX, "-headless", "-no-remote", "-marionette",
             "-remote-allow-system-access",
             "-profile", str(self.profile), "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
        )
        self.m.connect(deadline=120)
        self.m.new_session(accept_insecure_certs=not self.trust_bridge_cert)
        self.m.set_timeouts(page_load=25000, script=90000)

    # -- the certificate story, exercised rather than described --------------

    def add_trusted_cert(self, crt: Path, label: str) -> str:
        """Install a certificate into THIS PROFILE's own NSS database.

        `nsIX509CertDB.addCertFromBase64(der, trust)` writes exactly the record
        `certutil -d sql:<profile> -A -t <trust>` writes, into the same
        `cert9.db`. Using the browser's own API here rather than shelling out is
        not a shortcut: `certutil` is not on this machine, and NSS is not safe
        to write from another process while Firefox holds the database open.

        The trust string is `C,,` -- a CA bit on the SSL column and nothing on
        the other two. `P,,` ("trusted peer") is what this ought to be and it
        does not work: Firefox 153 refuses directly-trusted end-entity
        certificates, measured with the control that a `C,,` record on the same
        certificate is accepted. What keeps the CA bit from meaning "may sign
        for any host" is the certificate's own critical `CA:FALSE`, which is
        checked as its own case in `run()`.
        """
        text = crt.read_text(encoding="utf-8")
        m = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S)
        if not m:
            return f"FAILED: {crt.name} holds no PEM certificate"
        b64 = re.sub(r"\s+", "", m.group(1))
        got = self.chrome_eval(
            "const b64 = arguments[0];"
            "try {"
            "  const db = Cc['@mozilla.org/security/x509certdb;1']"
            "               .getService(Ci.nsIX509CertDB);"
            "  db.addCertFromBase64(b64, 'C,,');"
            "  return 'added';"
            "} catch (e) { return 'FAILED: ' + e; }",
            timeout=30, args=[b64])
        if got == "added":
            self.certs_trusted.append(label)
        return str(got)

    def sign_leaf_with_proxy_key(self, dns: str) -> tuple[Path, Path]:
        """Sign a certificate for ANOTHER host with the bridge's own key.

        This is the attack the certificate design has to be immune to, built
        rather than argued about: if the trust record the bridge asks a user to
        install can sign for `victim.wv-test.invalid`, then it is a
        general-purpose CA and the design is not what its documentation says.
        """
        d = self.work / "certs"
        key, csr = d / "victim.key", d / "victim.csr"
        crt, chain = d / "victim.crt", d / "victim.chain.crt"
        subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={dns}"],
                       check=True, capture_output=True)
        ext = d / "victim.ext"
        ext.write_text("basicConstraints=critical,CA:FALSE\n"
                       "keyUsage=critical,digitalSignature,keyEncipherment\n"
                       "extendedKeyUsage=serverAuth\n"
                       f"subjectAltName=DNS:{dns}\n", encoding="utf-8")
        subprocess.run(["openssl", "x509", "-req", "-in", str(csr),
                        "-CA", str(self.proxy_cert), "-CAkey", str(d / "bridge-proxy.key"),
                        "-CAcreateserial", "-out", str(crt), "-days", "2",
                        "-extfile", str(ext)], check=True, capture_output=True)
        chain.write_bytes(crt.read_bytes() + Path(self.proxy_cert).read_bytes())
        return key, chain

    # -- contexts ------------------------------------------------------------

    def use_page(self) -> None:
        self.m.set_context("content")
        self.m.switch_to(self.page_handle)

    def use_ctl(self) -> None:
        self.m.set_context("content")
        self.m.switch_to(self.ctl_handle)

    def chrome_eval(self, body: str, timeout: float = 60.0, is_async: bool = False,
                    args: list | None = None):
        self.m.set_context("chrome")
        try:
            if is_async:
                return self.m.execute_async(body, args, timeout=timeout)
            return self.m.execute(body, args, timeout=timeout)
        finally:
            self.m.set_context("content")

    def install_extension(self) -> str:
        got = self.m.value("Addon:Install",
                           {"path": str(self.package), "temporary": True}, timeout=120)
        return got if isinstance(got, str) else str(got)

    def find_uuid(self, deadline: float = 30.0) -> str:
        end = time.time() + deadline
        while time.time() < end:
            raw = self.chrome_eval(
                "const S = (typeof Services !== 'undefined') ? Services : null;"
                "try { return S.prefs.getStringPref('extensions.webextensions.uuids'); }"
                "catch (e) { return ''; }"
            )
            try:
                mapping = json.loads(raw or "{}")
            except json.JSONDecodeError:
                mapping = {}
            if ADDON_ID in mapping:
                return mapping[ADDON_ID]
            time.sleep(0.5)
        raise RuntimeError("Firefox never assigned the add-on a moz-extension uuid")

    def open_tabs(self) -> None:
        self.m.set_context("content")
        handles = self.m.handles()
        self.page_handle = handles[0]
        self.ctl_handle = self.m.new_tab()
        self.use_ctl()
        self.m.navigate(f"moz-extension://{self.uuid}/src/ui/options.html")

    # -- driving the extension ----------------------------------------------

    EXT_PRELUDE = (
        "const done = arguments[arguments.length - 1];"
        "const b = (typeof browser !== 'undefined' && browser.runtime) ? browser"
        "  : ((window.wrappedJSObject && window.wrappedJSObject.browser) || null);"
        "if (!b) { done(JSON.stringify({__error: 'no WebExtension namespace in this context'})); }"
        "else {"
    )
    EXT_EPILOGUE = (
        ".then(v => done(JSON.stringify(v === undefined ? null : v)))"
        ".catch(e => done(JSON.stringify({__error: String((e && e.message) || e)})));"
        "}"
    )

    def ext_eval(self, body: str, timeout: float = 60.0):
        """Run an async body inside the add-on's own options page."""
        self.use_ctl()
        script = f"{self.EXT_PRELUDE}(async () => {{{body}}})(){self.EXT_EPILOGUE}"
        raw = self.m.execute_async(script, timeout=timeout)
        try:
            return json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError:
            return {"__error": f"unparseable reply: {raw!r}"}

    def state(self) -> dict:
        got = self.ext_eval("return await b.runtime.sendMessage({type:'getState'});")
        return got if isinstance(got, dict) else {"__raw": got}

    def wait_for_state(self, wanted: str, timeout: float = 30.0) -> dict:
        deadline = time.time() + timeout
        last: dict = {}
        while time.time() < deadline:
            last = self.state()
            if last.get("state") == wanted:
                return last
            time.sleep(0.7)
        return last

    def apply_settings(self, **kwargs) -> dict:
        payload = json.dumps(kwargs)
        got = self.ext_eval(
            "const s = await b.runtime.sendMessage({type:'getState'});"
            f"const next = Object.assign({{}}, s.settings, {payload});"
            "return await b.runtime.sendMessage({type:'setSettings', settings: next});"
        )
        return got if isinstance(got, dict) else {}

    def dynamic_rules(self) -> list:
        got = self.ext_eval("return await b.declarativeNetRequest.getDynamicRules();")
        return got if isinstance(got, list) else []

    # -- navigation ----------------------------------------------------------

    def navigate(self, url: str, settle: float = 3.0) -> dict:
        self.use_page()
        # Blank the tab first. A navigation that is blocked outright does not
        # replace the document -- Firefox simply never completes the load -- so
        # reading the tab afterwards would report the PREVIOUS page's text. That
        # is how a stale success gets mistaken for a new one, and it produced a
        # false "leaked direct" in an earlier run of this very file.
        self.m.navigate("about:blank", timeout=30)
        leak_before = len(_LEAK_HITS)
        direct_before = self._direct_hits()
        err = self.m.navigate(url, timeout=90)
        time.sleep(settle)
        text, doc_uri = "", ""
        try:
            text = self.m.execute(
                "return document.body ? document.body.innerText.slice(0, 300) : '';"
            ) or ""
            doc_uri = self.m.execute("return document.documentURI;") or ""
        except (marionette.MarionetteError, OSError):
            text, doc_uri = "<page unreadable>", ""
        code = ""
        for source in (doc_uri, err):
            m = re.search(r"about:neterror\?e=([A-Za-z0-9_]+)", source or "")
            if m:
                code = m.group(1)
                break
        return {
            "loaded_marker": MARKER in text,
            # Two independent signals, because the page text alone is not
            # trustworthy after a load that never completed: the decoy's own
            # hit counter is the one that cannot go stale.
            #
            # In --real-host mode the decoy is reachable BOTH ways -- the real
            # proxy resolves `leakprobe.localhost` exactly as the browser can --
            # so a hit is only a leak when the socket was opened by the browser
            # rather than by the bridge. That is the sharper form of the same
            # test: previously a proxied request could never touch the decoy,
            # and now it does and is told apart by who opened it.
            "leaked_direct": (self._direct_hits() > direct_before) if self.real_host
                             else (LEAK_MARKER in text or len(_LEAK_HITS) > leak_before),
            "decoy_hits": len(_LEAK_HITS) - leak_before,
            "direct_hits": self._direct_hits() - direct_before,
            "timed_out": "timed out" in (err or "").lower(),
            "neterror": code,
            "text": " ".join(text.split())[:200],
            "documentURI": doc_uri[:160],
            "marionette": " ".join((err or "").split())[:200],
        }

    def _direct_hits(self) -> int:
        """Decoy hits the BROWSER made, as opposed to ones the bridge relayed."""
        return sum(1 for h in _LEAK_HITS if not h.get("proxied"))

    def leak_count(self) -> int:
        """The number that means "a leak happened", in either mode.

        With the stand-in proxy the decoy is unreachable through the proxy at
        all -- it is a catch-all and never connects anywhere else -- so any hit
        is a leak and the raw count is the right number. With the REAL host the
        decoy is reachable both ways, because the real proxy resolves
        `leakprobe.localhost` exactly as the browser can, so the number that
        means a leak is the count of hits the BROWSER opened.
        """
        return self._direct_hits() if self.real_host else len(_LEAK_HITS)

    def endpoint_events(self, since: float, kinds=("connect",)) -> list[dict]:
        """Everything the local proxy saw, whichever of the two is in use."""
        out = [e for e in _TLS_EVENTS
               if e.get("kind") in kinds and e.get("t", 0) >= since]
        if self.tls_mode and not self.real_host:
            # Fixed/TLS routing: only events that arrived on the advertised
            # TLS port count. The plaintext HTTP proxy may still be running
            # (the marker sits behind it); a CONNECT there is the wrong hop.
            advertised = self.advertised_proxy_port()
            return sorted(
                [e for e in out if e.get("port") == advertised],
                key=lambda e: e.get("t", 0),
            )
        if self.real_host:
            # The real proxy logs nothing -- by design, it never records a
            # destination -- so what is read here is the far end of the hop:
            # every connection the fake internet accepted, attributed to the
            # process that opened it. Only the ones the bridge opened count as
            # CONNECTs; a browser-opened one is a leak and is counted as such by
            # `_direct_hits`.
            out += [e for e in _UPSTREAM
                    if e.get("kind") in kinds and e.get("t", 0) >= since]
            out += [{"t": h["t"], "kind": "connect", "target": LEAK_HOST,
                     "raw": LEAK_HOST, "peer": h.get("peer", ""), "authenticated": True}
                    for h in _LEAK_HITS
                    if h.get("proxied") and h.get("t", 0) >= since and "connect" in kinds]
        if self.endpoint_log.exists():
            for line in self.endpoint_log.read_text(encoding="utf-8").splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("kind") in kinds and event.get("t", 0) >= since:
                    out.append(event)
        return sorted(out, key=lambda e: e.get("t", 0))

    def prefs(self, names: list[str]) -> dict:
        script = (
            "const S = Services; const out = {};"
            f"const names = {json.dumps(names)};"
            "for (const n of names) {"
            "  try {"
            "    switch (S.prefs.getPrefType(n)) {"
            "      case S.prefs.PREF_BOOL: out[n] = S.prefs.getBoolPref(n); break;"
            "      case S.prefs.PREF_INT: out[n] = S.prefs.getIntPref(n); break;"
            "      case S.prefs.PREF_STRING: out[n] = S.prefs.getStringPref(n); break;"
            "      default: out[n] = null;"
            "    }"
            "  } catch (e) { out[n] = '<unreadable: ' + e.message + '>'; }"
            "}"
            "return JSON.stringify(out);"
        )
        raw = self.chrome_eval(script)
        try:
            return json.loads(raw or "{}")
        except json.JSONDecodeError:
            return {}

    # -- teardown ------------------------------------------------------------

    def shutdown(self) -> None:
        try:
            self.m.close()
        except Exception:  # noqa: BLE001
            pass
        if self.browser_proc and self.browser_proc.poll() is None:
            self.browser_proc.terminate()
            try:
                self.browser_proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.browser_proc.kill()
        if self.endpoint_proc and self.endpoint_proc.poll() is None:
            self.endpoint_proc.kill()
        if self.leak_server:
            try:
                self.leak_server.shutdown()
            except Exception:  # noqa: BLE001
                pass
        self.stop_tls_proxy()
        self.stop_real_marker()
        self.remove_native_host()
        if self.real_host and self.host_stderr.exists():
            tail = self.host_stderr.read_text(encoding="utf-8", errors="replace")
            if tail.strip():
                print("\n  the real host's stderr (it never carries a token):")
                for line in tail.strip().splitlines()[-12:]:
                    print(f"    {line}")
        if not self.keep and self.work.exists():
            shutil.rmtree(self.work, ignore_errors=True)


# ---------------------------------------------------------------------------
# the checks
# ---------------------------------------------------------------------------

ICE_SCRIPT = """
const done = arguments[arguments.length - 1];
(async () => {
  try {
    const pc = new RTCPeerConnection({iceServers: []});
    pc.createDataChannel('x');
    const out = [];
    await pc.setLocalDescription(await pc.createOffer());
    await new Promise(res => {
      pc.onicecandidate = e => { if (e.candidate) out.push(e.candidate.candidate); else res(); };
      setTimeout(res, 3000);
    });
    pc.close();
    return out;
  } catch (e) { return ['ERROR ' + e.message]; }
})().then(v => done(JSON.stringify(v))).catch(e => done(JSON.stringify(['ERROR ' + e])));
"""


def resource_types_in(package: Path) -> list[str]:
    """Read resource types from authored or minified packaged source."""
    text = (package / "src" / "core" / "constants.js").read_text(
        encoding="utf-8"
    )
    match = re.search(r"DNR_RESOURCE_TYPES\s*=\s*\[(.*?)\]", text, re.S)
    if match is None:
        raise RuntimeError("Packaged DNR resource-type declaration is missing")
    types = [
        name
        for _, name in re.findall(
            r"""(['"])([a-z_]+)\1""",
            match.group(1),
        )
    ]
    if not types:
        raise RuntimeError("Packaged DNR resource-type declaration is empty")
    return types


class FixedVariantError(RuntimeError):
    """The --fixed mutator cannot honestly apply or attest this adapter source."""


# The shipping Firefox adapter returns ProxyInfo objects inline from
# proxy.onRequest. The previous mutator looked for
# `const info = { type: 'http', host: endpoint.host, port: endpoint.port };`
# which the adapter no longer contains; missing that needle, it printed
# "already declares ProxyInfo type 'https'" while the live object was still
# http. These needles are the current inline shape. They are not a substring
# of the stale `const info = ...` assignment because they include `return`.
LIVE_HTTP_PROXY_RETURN = (
    "return [{ type: 'http', host: endpoint.host, port: endpoint.port }, null];"
)
LIVE_HTTPS_PROXY_RETURN = (
    "return [{ type: 'https', host: endpoint.host, port: endpoint.port }, null];"
)
# The store size transform (tools/store_js_minifier.py, esbuild) rewrites the
# PACKAGED adapter before it ships: no spaces, double quotes, no semicolon.
# A verifier that only knew the authored shape raised "stale Firefox adapter
# source shape" against the exact bytes that ship, so the needle set covers
# both shapes and the counts stay unique across the two families combined
# (esbuild never emits the spaced single-quoted form, and the authored source
# never contains the compact double-quoted form).
LIVE_HTTP_PROXY_RETURN_MINIFIED = (
    'return[{type:"http",host:endpoint.host,port:endpoint.port},null]'
)
LIVE_HTTPS_PROXY_RETURN_MINIFIED = (
    'return[{type:"https",host:endpoint.host,port:endpoint.port},null]'
)
_LIVE_HTTP_NEEDLES = (LIVE_HTTP_PROXY_RETURN, LIVE_HTTP_PROXY_RETURN_MINIFIED)
_LIVE_HTTPS_NEEDLES = (LIVE_HTTPS_PROXY_RETURN, LIVE_HTTPS_PROXY_RETURN_MINIFIED)


def _live_proxy_return_counts(text: str) -> tuple[int, int]:
    return (
        sum(text.count(needle) for needle in _LIVE_HTTP_NEEDLES),
        sum(text.count(needle) for needle in _LIVE_HTTPS_NEEDLES),
    )


def live_proxy_type_in_text(text: str) -> str:
    """Classify the unique inline live-endpoint ProxyInfo return, or raise."""
    http_n, https_n = _live_proxy_return_counts(text)
    if http_n + https_n == 0:
        raise FixedVariantError(
            "stale Firefox adapter source shape: no inline live ProxyInfo "
            "return object; refusing to claim an HTTPS variant exists"
        )
    if http_n + https_n > 1:
        raise FixedVariantError(
            "duplicate/ambiguous inline live ProxyInfo matches "
            f"(http={http_n}, https={https_n})"
        )
    return "http" if http_n == 1 else "https"


def proxy_type_in(package: Path) -> str:
    """The live-endpoint ProxyInfo `type` returned inline by the packaged adapter."""
    text = (package / "src" / "adapters" / "firefox.js").read_text(encoding="utf-8")
    return live_proxy_type_in_text(text)


def _rewrite_live_http_to_https(text: str) -> str:
    # apply_https_proxy_variant_text() has already proved exactly one live
    # http needle across both shape families, so the first family present is
    # the only one; rewriting in its own shape keeps the mutation byte-minimal.
    for http_needle, https_needle in zip(_LIVE_HTTP_NEEDLES, _LIVE_HTTPS_NEEDLES):
        if http_needle in text:
            return text.replace(http_needle, https_needle, 1)
    return text


def apply_https_proxy_variant_text(text: str) -> tuple[str, str]:
    """Rewrite the unique live http return to https.

    Returns (new_text, action) with action 'mutated' or 'already_https'.
    Raises FixedVariantError on stale shape, duplicate matches, or a rewrite
    that would not actually produce a unique https live object.
    """
    declared = live_proxy_type_in_text(text)
    if declared == "https":
        return text, "already_https"
    updated = _rewrite_live_http_to_https(text)
    if updated == text:
        raise FixedVariantError(
            "no-op ProxyInfo mutation; refusing to claim an HTTPS variant exists"
        )
    if live_proxy_type_in_text(updated) != "https":
        raise FixedVariantError(
            "no-op ProxyInfo mutation; live object is still not https"
        )
    return updated, "mutated"


def probe_resource_types(h: Harness, wanted: list[str]) -> dict:
    """Ask the browser about each resource type on its own.

    `updateDynamicRules` validates the whole call and rejects all of it, so a
    fifteen-element array that fails says nothing about which element was wrong.
    One call per type turns that into a list of names.
    """
    out: dict[str, str] = {}
    for kind in wanted:
        out[kind] = str(h.ext_eval(
            "try {"
            "  await b.declarativeNetRequest.updateDynamicRules({removeRuleIds:[9901], addRules:[{"
            "    id:9901, priority:1, action:{type:'block'},"
            f"    condition:{{urlFilter:'||probe.wv-test.invalid^', resourceTypes:[{json.dumps(kind)}]}}"
            "  }]});"
            "  await b.declarativeNetRequest.updateDynamicRules({removeRuleIds:[9901]});"
            "  return 'accepted';"
            "} catch (e) { return 'rejected: ' + String(e.message).slice(0, 110); }",
            timeout=30))
    return out


AUTH_PROBE_HOST = "authprobe.wv-test.invalid"


def probe_proxy_auth(h: Harness, r: Result) -> None:
    """Which field of a ProxyInfo actually authenticates to an HTTP CONNECT proxy?

    Run only when the adapter's own attempt did not work. The extension is
    disarmed first so that its listener is gone and exactly one ProxyInfo is in
    play, then this harness registers its own `proxy.onRequest` listener from the
    add-on's options page -- same extension, same permissions, same API -- and
    returns one candidate shape per navigation. The local proxy's log then says
    which shape produced an authenticated CONNECT and which produced a 407 with
    no header at all.

    The token here is the harness's own pre-shared throwaway. It is never
    printed and never written to a log.
    """
    h.apply_settings(armed=False)
    h.wait_for_state("off", timeout=20)

    tls_port = h.start_tls_proxy()
    shapes = [
        ("proxyAuthorizationHeader on an http proxy -- exactly what firefox.js returns",
         "{type:'http', host:H, port:P, "
         "proxyAuthorizationHeader: 'Basic ' + btoa('extension:' + T)}", "plain"),
        ("username/password fields on the same http ProxyInfo",
         "{type:'http', host:H, port:P, username:'extension', password:T}", "plain"),
        ("the same header, but with the proxy declared type 'https' (TLS to the proxy)",
         "{type:'https', host:H, port:PTLS, "
         "proxyAuthorizationHeader: 'Basic ' + btoa('extension:' + T)}", "tls"),
    ]
    for label, shape, which in shapes:
        h.use_ctl()
        h.ext_eval(
            f"const T = {json.dumps(h.token)}; const H = '127.0.0.1'; "
            f"const P = {h.proxy_port}; const PTLS = {tls_port};"
            f"const TARGET = {json.dumps(AUTH_PROBE_HOST)};"
            "if (window.__wvProbe) { try { b.proxy.onRequest.removeListener(window.__wvProbe); }"
            "  catch (e) { /* was not installed */ } }"
            "window.__wvProbe = (info) => {"
            "  try {"
            "    if (new URL(info.url).hostname !== TARGET) return {type:'direct'};"
            f"    return {shape};"
            "  } catch (e) { return {type:'direct'}; }"
            "};"
            "b.proxy.onRequest.addListener(window.__wvProbe, {urls:['<all_urls>']});"
            "return 'installed';"
        )
        mark = time.time()
        alerts_before = h.m.alerts_dismissed
        nav = h.navigate(url_for(AUTH_PROBE_HOST), settle=5.0)
        if which == "tls":
            events = [e for e in _TLS_EVENTS
                      if e.get("kind") in ("connect", "proxy_407") and e.get("t", 0) >= mark]
        else:
            events = h.endpoint_events(mark, kinds=("connect", "proxy_407"))
        h.use_ctl()
        h.ext_eval(
            "if (window.__wvProbe) { try { b.proxy.onRequest.removeListener(window.__wvProbe); }"
            "  catch (e) { /* already gone */ } window.__wvProbe = null; } return 'removed';"
        )
        connects = [e for e in events if e["kind"] == "connect"]
        challenges = [e for e in events if e["kind"] == "proxy_407"]
        extra = ""
        if which == "tls":
            errors = [e for e in _TLS_EVENTS
                      if e.get("kind") not in ("connect", "proxy_407") and e.get("t", 0) >= mark]
            extra = f"; TLS-side events: {[(e.get('kind'), str(e.get('detail'))[:60]) for e in errors][:3]}"
        r.add(
            f"ISOLATED: {label}",
            bool(connects) and nav["loaded_marker"],
            f"the proxy logged {len(challenges)} 407(s) "
            f"(a Proxy-Authorization header was present on: "
            f"{[e.get('had_header') for e in challenges]}) and "
            f"{len(connects)} authenticated CONNECT(s) {[e['target'] for e in connects]}; "
            f"page marker_loaded={nav['loaded_marker']} neterror={nav['neterror']!r}; Firefox raised "
            f"{h.m.alerts_dismissed - alerts_before} proxy password prompt(s){extra}",
            "an authenticated CONNECT and the marker page",
        )

    h.apply_settings(armed=True)
    h.wait_for_state("protected", timeout=40)


def block_layer_failure_reaches_the_state_machine(h: Harness, r: Result) -> None:
    """Break the block layer for real, and watch the state machine notice.

    This is the regression check for the finding of the 2026-08-07 run: the
    browser discarded the entire rule set, `applyBlockRules` caught the error into
    a string nobody read, and the extension went on reporting a state whose copy
    promises "your chosen sites are being blocked". The enum mismatch that caused
    it is now un-reproducible by construction -- the adapter negotiates the
    resource types against this browser before it uses them -- so the failure has
    to be induced another way to prove the REPORTING path, which is the actual
    defect.

    The dynamic-rule quota is the honest way to induce it: this harness fills the
    browser's own limit from the add-on's page, so the extension's next
    `updateDynamicRules` is refused by the same API, for a reason it did not
    choose and cannot work around. Then the rules are removed and the extension
    is watched recovering, because a state that latches is its own kind of lie.
    """
    limit = h.ext_eval(
        "return b.declarativeNetRequest.MAX_NUMBER_OF_DYNAMIC_AND_SESSION_RULES"
        " || b.declarativeNetRequest.MAX_NUMBER_OF_DYNAMIC_RULES || 5000;")
    limit = int(limit) if isinstance(limit, (int, float)) else 5000

    # The extension has to hold NO rules while the quota is filled, or its next
    # update -- which removes its own ids before adding -- would fit in the space
    # it just freed and succeed. Disarming is the shipped way to empty it.
    h.apply_settings(armed=False)
    h.wait_for_state("off", timeout=20)

    # Ids well clear of the extension's own space (1, 1000-1499, 9000).
    filled = h.ext_eval(
        f"const N = {limit};"
        "const existing = await b.declarativeNetRequest.getDynamicRules();"
        "const rules = [];"
        "for (let i = 0; i < N - existing.length; i++) rules.push({id: 20000 + i, priority: 1,"
        "  action: {type: 'block'},"
        "  condition: {urlFilter: '||q' + i + '.wv-quota.invalid^', resourceTypes: ['main_frame']}});"
        "let err = '';"
        "try { await b.declarativeNetRequest.updateDynamicRules({addRules: rules}); }"
        "catch (e) { err = String(e.message).slice(0, 120); }"
        "const now = await b.declarativeNetRequest.getDynamicRules();"
        "return {err, count: now.length, limit: N, started: existing.length};",
        timeout=300)
    # Make the extension re-derive: a settings round trip is the shipped path.
    h.apply_settings(armed=True)
    s = h.wait_for_state("not_enforcing", timeout=40)

    r.add(
        "THE REPORTING FIX: a block layer the browser refuses reaches the state machine",
        s.get("state") == "not_enforcing",
        f"the browser's dynamic-rule limit is {(filled or {}).get('limit')} and it now holds "
        f"{(filled or {}).get('count')} foreign rules "
        f"(fill error={str((filled or {}).get('err'))[:60]!r}), so the extension's own "
        f"updateDynamicRules is refused. It now reports state={s.get('state')!r} "
        f"blockLayer={json.dumps(s.get('blockLayer'))} detail={str(s.get('detail'))[:120]!r}. "
        "Before this change the same situation reported app_not_running, whose copy says "
        "'Your chosen sites are being blocked, not sent unprotected'.",
        "not_enforcing",
    )

    # And the words. Deliberately NOT scraped off the options page: that page
    # renders on load and on interaction, so reading its DOM here can report
    # whatever it happened to be showing before and pass for the wrong reason --
    # which it did on the first attempt at this check. The shipped copy module is
    # imported instead and asked the same question the popup asks it, so what is
    # measured is the mapping from the state the extension is ACTUALLY in to the
    # words a user would actually see.
    words = h.ext_eval(
        f"const UUID = {json.dumps(h.uuid)};"
        f"const STATE = {json.dumps(s.get('state') or '')};"
        "const mod = await import(`moz-extension://${UUID}/src/core/copy.js`);"
        "const c = mod.stateCopy(STATE);"
        "return {headline: c.headline, detail: c.detail, tone: c.tone,"
        "        blockExplanation: mod.BLOCK_LAYER_FAILED_EXPLANATION};")
    words = words if isinstance(words, dict) else {}
    detail = str(words.get("detail") or "")
    r.add(
        "and the words for the state it is in stop promising a block",
        "blocked, not sent unprotected" not in detail and bool(detail)
        and bool(words.get("blockExplanation")),
        f"the shipped copy module maps state={s.get('state')!r} to "
        f"headline={str(words.get('headline'))[:90]!r} tone={words.get('tone')!r} "
        f"detail={detail[:200]!r}. The popup additionally appends "
        f"{str(words.get('blockExplanation'))[:110]!r} in this state, in place of the sentence "
        "explaining that the block is deliberate.",
        "copy that does not claim the sites are being blocked",
    )

    cleaned = h.ext_eval(
        f"const ids = []; for (let i = 0; i < {limit}; i++) ids.push(20000 + i);"
        "let err = '';"
        "try { await b.declarativeNetRequest.updateDynamicRules({removeRuleIds: ids}); }"
        "catch (e) { err = String(e.message).slice(0, 120); }"
        "const now = await b.declarativeNetRequest.getDynamicRules();"
        "return {err, count: now.length};",
        timeout=300)
    h.apply_settings(armed=True)
    # Generous, deliberately: the adapter will not re-establish a refused
    # negotiation more often than every 30 seconds, which is the right trade in
    # the product and means recovery here is not instant.
    s = h.wait_for_state("app_not_running", timeout=120)
    rules = h.dynamic_rules()
    blocks = [x for x in rules if x.get("action", {}).get("type") == "block"]
    r.add(
        "and it recovers on its own once the browser will take the rules again",
        s.get("state") == "app_not_running" and len(blocks) >= 1,
        f"after removing the foreign rules ({(cleaned or {}).get('count')} left, "
        f"error={str((cleaned or {}).get('err'))[:60]!r}) the extension reports "
        f"state={s.get('state')!r} with {len(blocks)} block rule(s) installed and "
        f"blockLayer={json.dumps(s.get('blockLayer'))}. A state that latched would be its "
        "own dishonesty.",
        "app_not_running, with the block layer installed again",
    )


def has_host_ice_candidate(candidates: list[str]) -> bool:
    return any(" typ host " in f" {candidate} " for candidate in candidates)

def gather_ice(h: Harness) -> list[str]:
    h.use_page()
    try:
        raw = h.m.execute_async(ICE_SCRIPT, timeout=60)
    except (marionette.MarionetteError, OSError) as error:
        raise RuntimeError("ICE probe execution failed") from error
    return _validated_ice_candidates(raw)

def _validated_ice_candidates(raw: object) -> list[str]:
    """Parse the ICE probe's JSON reply. A probe error is a failure, never an empty pass."""
    try:
        candidates = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("ICE probe did not return valid JSON") from error
    if type(candidates) is not list or any(type(c) is not str for c in candidates):
        raise RuntimeError("ICE probe failed or returned malformed candidates")
    # An empty string is the end-of-candidates marker (Firefox emits one).
    candidates = [c for c in candidates if c != ""]
    if any(not c.startswith("candidate:") for c in candidates):
        raise RuntimeError("ICE probe failed or returned malformed candidates")
    return candidates



def accept_permission_doorhanger(h: Harness, deadline: float = 12.0) -> dict:
    """Find Firefox's optional-permission prompt in chrome context and accept it.

    This is the step Chromium could not perform: its permission bubble is native
    UI with no automation surface. Firefox's is a XUL popupnotification in the
    browser window's own document, so it can be found, described, and clicked.
    """
    end = time.time() + deadline
    seen = {}
    while time.time() < end:
        raw = h.chrome_eval(
            "const n = document.getElementById('addon-webext-permissions-notification');"
            "if (!n) return JSON.stringify({present:false});"
            "const out = {present:true, hidden: !!n.hidden, state: n.state || '',"
            "  header: (n.querySelector('.popup-notification-description') || {}).textContent || '',"
            "  label: (n.button && n.button.label) || ''};"
            "return JSON.stringify(out);"
        )
        try:
            seen = json.loads(raw or "{}")
        except json.JSONDecodeError:
            seen = {}
        if seen.get("present") and not seen.get("hidden"):
            clicked = h.chrome_eval(
                "const n = document.getElementById('addon-webext-permissions-notification');"
                "if (!n || !n.button) return 'no button';"
                "n.button.click(); return 'clicked';"
            )
            seen["accepted"] = clicked
            return seen
        time.sleep(0.4)
    seen.setdefault("accepted", "prompt never appeared")
    return seen



def run(h: Harness) -> Result:  # noqa: PLR0915
    r = h.result

    # --- 1. it loads, the EVENT PAGE runs, and it knows it is Firefox -------
    manifest = h.ext_eval("return b.runtime.getManifest();")
    snapshot = h.state()
    background = manifest.get("background", {}) if isinstance(manifest, dict) else {}
    r.add(
        "CLAIM 1: the MV3 event page starts and its listeners register",
        bool(snapshot.get("state")) and bool(background.get("scripts"))
        and not background.get("service_worker"),
        f"background={json.dumps(background)}; a runtime message was answered with "
        f"state={snapshot.get('state')!r}; adapter reports browser={snapshot.get('browser')!r}",
        "an event page (background.scripts), answering runtime messages",
    )
    r.add(
        "the Firefox adapter was selected by feature detection, not a build flag",
        snapshot.get("browser") == "firefox",
        f"browser={snapshot.get('browser')!r} routingMechanism={snapshot.get('routingMechanism')!r}",
        "firefox",
    )

    war = manifest.get("web_accessible_resources") if isinstance(manifest, dict) else "?"
    perms = manifest.get("permissions", []) if isinstance(manifest, dict) else []
    optional = manifest.get("optional_host_permissions") if isinstance(manifest, dict) else None
    r.add(
        "the shipped Firefox surface: no web_accessible_resources, no declared host "
        "permissions, and webRequest for proxy auth (same cost Chromium pays)",
        war is None and not manifest.get("host_permissions")
        and optional == ["<all_urls>"]
        and "webRequest" in perms and "webRequestAuthProvider" in perms,
        f"web_accessible_resources={war}; host_permissions={manifest.get('host_permissions')}; "
        f"optional_host_permissions={optional}; permissions={perms}",
        "absent / absent / ['<all_urls>'] / webRequest + webRequestAuthProvider",
    )

    stored = h.ext_eval("return await b.storage.local.get(null);")
    r.add("an untouched profile stores nothing", stored == {},
          f"browser.storage.local = {json.dumps(stored)}", "{}")

    # --- 2. the decoy is proven to work, BEFORE anything depends on it ------
    # Without this control, "no leak" and "a probe that cannot detect a leak"
    # look identical -- which is exactly the weakness the Chromium run recorded
    # about its own WebRTC probe.
    nav = h.navigate(url_for(LEAK_HOST, h.leak_port), settle=2.0)
    r.add(
        "CONTROL: with the extension idle, a direct connection is detectable",
        nav["leaked_direct"] and h.leak_count() >= 1,
        f"the decoy answered: {nav['leaked_direct']}; direct decoy hits={h.leak_count()}; "
        f"body={nav['text']!r}",
        "the decoy page, proving the direct-leak probe can fire",
    )
    ice_idle = gather_ice(h)
    r.add(
        "CONTROL: idle ICE capture detects a host candidate",
        has_host_ice_candidate(ice_idle),
        f"{len(ice_idle)} candidate(s): {ice_idle[:3]}",
        "at least one host candidate",
    )

    # --- 3. armed while the desktop app is not running ---------------------
    h.set_tunnel_state("app_not_running")
    h.apply_settings(armed=True)
    s = h.wait_for_state("app_not_running")
    r.add(
        "armed with the desktop app absent reports app_not_running, distinctly",
        s.get("state") == "app_not_running",
        f"state={s.get('state')!r} tunnelStatus={s.get('tunnelStatus')!r} "
        f"lastError={str(s.get('lastError'))[:80]!r}",
        "app_not_running",
    )
    rules = h.dynamic_rules()
    blocks = [x for x in rules if x.get("action", {}).get("type") == "block"]
    r.add(
        "CLAIM 4: declarativeNetRequest dynamic rules install on Firefox",
        len(blocks) >= 1,
        f"{len(rules)} dynamic rules, {len(blocks)} block: "
        f"{[x.get('condition', {}).get('urlFilter') for x in rules][:4]}; "
        f"the extension's own report: lastError={str(s.get('lastError'))[:200]!r}",
        "at least one block rule",
    )
    if not blocks:
        # Find out WHICH part the browser refused, one resource type at a time,
        # rather than reporting that a fifteen-element array was rejected.
        wanted = resource_types_in(h.package)
        verdicts = probe_resource_types(h, wanted)
        rejected = [t for t, v in verdicts.items() if not v.startswith("accepted")]
        r.add(
            "DIAGNOSIS: every resourceType the block layer asks for is one this browser knows",
            not rejected,
            f"the extension asks for {wanted}; this Firefox REJECTS {rejected}. "
            f"declarativeNetRequest.updateDynamicRules validates the whole call, so one "
            f"unknown enum value discards the entire rule set -- there is no partial install. "
            f"First refusal: {verdicts.get(rejected[0]) if rejected else 'none'}",
            "no rejected resource types",
        )
    nav = h.navigate(url_for(ROUTED_HOST), settle=4.0)
    r.add(
        "THE CENTRAL PROPERTY: with the app absent, an in-scope request is blocked, "
        "not sent directly",
        (not nav["loaded_marker"]) and (not nav["leaked_direct"])
        and nav["neterror"] != "dnsNotFound",
        f"neterror={nav['neterror']!r} timed_out={nav['timed_out']} "
        f"marker_loaded={nav['loaded_marker']} decoy_hits={nav['decoy_hits']} "
        f"body={nav['text']!r}; marionette said {nav['marionette']!r}",
        "blocked, with no direct attempt (a direct attempt would read dnsNotFound)",
    )
    nav_leak = h.navigate(url_for(LEAK_HOST, h.leak_port), settle=3.0)
    r.add(
        "and the same request against the decoy does not reach it either",
        not nav_leak["leaked_direct"],
        f"the decoy -- which this browser CAN resolve, and which answered during the "
        f"control above -- was hit {nav_leak['decoy_hits']} time(s) during this "
        f"navigation; neterror={nav_leak['neterror']!r} timed_out={nav_leak['timed_out']} "
        f"body={nav_leak['text']!r}",
        "the decoy is not reached while the extension is armed and failing closed",
    )

    # --- 3b. the reporting fix, exercised rather than reasoned about --------
    try:
        block_layer_failure_reaches_the_state_machine(h, r)
    except Exception as e:  # noqa: BLE001
        r.add("THE REPORTING FIX: a block layer the browser refuses reaches the state machine",
              False, f"the probe could not be completed: {type(e).__name__}: {str(e)[:200]}",
              "a completed probe")

    # --- 4. connected but the desktop proxy gate is shut -------------------
    h.set_tunnel_state("connected", proxy_ready=False)
    s = h.wait_for_state("not_ready")
    r.add(
        "a connected tunnel with the desktop proxy gate shut does not route",
        s.get("state") in ("not_ready", "no_credential"),
        f"state={s.get('state')!r} proxyReady={s.get('proxyReady')} "
        f"hasCredential={s.get('hasCredential')}",
        "not_ready",
    )

    # --- 5. connected and ready, but the host permission is not granted ----
    h.set_tunnel_state("connected")
    s = h.wait_for_state("no_auth_capability", timeout=30)
    r.add(
        "without the granted host permission the extension refuses to route, and says why",
        s.get("state") == "no_auth_capability" and s.get("canAuthenticate") is False,
        f"state={s.get('state')!r} canAuthenticate={s.get('canAuthenticate')} "
        f"hasCredential={s.get('hasCredential')}",
        "no_auth_capability",
    )
    p = h.prefs(["network.proxy.type", "network.proxy.autoconfig_url"])
    r.add(
        "and no proxy setting is installed that could never have worked",
        p.get("network.proxy.type") in (0, 5),
        f"Gecko's own network.proxy.type={p.get('network.proxy.type')} "
        f"(5=system, 0=direct, 2=PAC), autoconfig_url={p.get('network.proxy.autoconfig_url')!r}",
        "system or direct",
    )

    # --- 6. THE GRANT ------------------------------------------------------
    # First the shipped path exactly as a user would take it: the button on the
    # options page. Then, if that does not complete, a direct call from a real
    # click in the same page, to separate "Firefox cannot do this" from "this
    # extension asks for it from the wrong place".
    h.use_ctl()
    card_hidden = h.m.execute("return document.getElementById('firefoxCard').hidden;")
    card_detail = h.m.execute("return document.getElementById('firefoxDetail').textContent;")
    r.add(
        "the options page offers the grant, with the Firefox-specific reason",
        card_hidden is False and "present the key" in (card_detail or ""),
        f"#firefoxCard hidden={card_hidden}; detail={str(card_detail)[:150]!r}",
        "the grant card is visible, carrying the Firefox wording",
    )

    button = h.m.find("#grantHost")
    shipped_error = ""
    if button:
        try:
            h.m.click(button)
        except marionette.MarionetteError as e:
            shipped_error = e.message
        door = accept_permission_doorhanger(h, deadline=8.0)
        time.sleep(1.0)
        granted_shipped = h.ext_eval(
            "return await b.permissions.contains({origins:['<all_urls>']});")
    else:
        door, granted_shipped = {"present": False}, False

    # What the background actually did with the request, in its own words.
    shipped_state = h.state()
    r.add(
        "CLAIM 5 / the shipped path: clicking 'Give permission' completes the grant",
        granted_shipped is True,
        f"permissions.contains(<all_urls>) = {granted_shipped}; "
        f"doorhanger={json.dumps(door)}; click error={shipped_error!r}; "
        f"extension lastError={str(shipped_state.get('lastError'))[:160]!r}",
        "the permission is granted after the shipped button is clicked",
    )

    if granted_shipped is not True:
        # Diagnostic: call permissions.request() from a real click IN THE PAGE,
        # which is where the WebExtensions user-gesture rule requires it. If this
        # succeeds where the button failed, the browser is not the problem.
        h.use_ctl()
        h.m.execute(
            "const el = document.getElementById('ruleInput');"
            "el.__wvProbe = null;"
            "el.addEventListener('click', () => {"
            "  const b = (typeof browser !== 'undefined' && browser.runtime) ? browser"
            "    : ((window.wrappedJSObject && window.wrappedJSObject.browser) || null);"
            "  try { b.permissions.request({origins:['<all_urls>']})"
            "    .then(v => { window.__wvGrant = 'resolved:' + v; })"
            "    .catch(e => { window.__wvGrant = 'rejected:' + e.message; }); }"
            "  catch (e) { window.__wvGrant = 'threw:' + e.message; }"
            "}, {once: true});"
            "window.__wvGrant = 'pending';"
            "return 'armed';"
        )
        probe = h.m.find("#ruleInput")
        h.m.click(probe)
        door2 = accept_permission_doorhanger(h, deadline=12.0)
        time.sleep(1.5)
        h.use_ctl()
        outcome = h.m.execute("return String(window.__wvGrant);")
        granted_direct = h.ext_eval(
            "return await b.permissions.contains({origins:['<all_urls>']});")
        r.add(
            "and Firefox itself can complete the grant when permissions.request() is "
            "called from the click, in the page",
            granted_direct is True,
            f"permissions.contains(<all_urls>) = {granted_direct}; "
            f"request outcome={outcome!r}; doorhanger={json.dumps(door2)}",
            "granted -- which would locate the shipped failure in the extension, not the browser",
        )

    granted = h.ext_eval("return await b.permissions.contains({origins:['<all_urls>']});")
    if granted is not True:
        r.add("the host permission is in hand before the routing checks", False,
              "the grant did not complete by any route; the routing checks below "
              "cannot run and are not reported as passing", "granted")
        return r

    # The permission event listener re-reads canAuthenticate automatically.
    # Send the compatibility message as well so this run also covers an older
    # options page and the explicit refresh path after a browser-managed grant.
    refreshed = h.ext_eval("return await b.runtime.sendMessage({type:'requestHostPermission'});")
    r.note(
        "re-reading the capability after the grant",
        f"granted={(refreshed or {}).get('granted')} "
        f"canAuthenticate={(refreshed or {}).get('canAuthenticate')} "
        f"state={(refreshed or {}).get('state')!r}",
    )
    h.apply_settings(armed=False)
    h.wait_for_state("off", timeout=15)
    h.apply_settings(armed=True)

    s = h.wait_for_state("protected", timeout=40)
    r.add(
        "CLAIM 2a: with the grant in hand the extension routes",
        s.get("state") == "protected",
        f"state={s.get('state')!r} endpoint={s.get('endpoint')} "
        f"hasCredential={s.get('hasCredential')} canAuthenticate={s.get('canAuthenticate')} "
        f"routingMechanism={s.get('routingMechanism')!r}",
        "protected",
    )
    got_state = s.get("state")
    r.add(
        "Firefox routes over plaintext via webRequest",
        got_state == "protected",
        f"state={got_state!r} endpoint={s.get('endpoint')} hasCredential={s.get('hasCredential')} canAuthenticate={s.get('canAuthenticate')}",
        "protected",
    )
    r.add(
        "and it routes through proxy.onRequest, not through a browser-wide setting",
        s.get("routingMechanism") == "onRequest",
        f"routingMechanism={s.get('routingMechanism')!r}",
        "onRequest",
    )
    r.add(
        "the endpoint the extension will use is a port and nothing else",
        s.get("endpoint") is not None and set(s.get("endpoint") or {}) == {"port"},
        f"endpoint object = {s.get('endpoint')}",
        "an object with exactly one key, port",
    )
    p = h.prefs(["network.proxy.type", "network.proxy.autoconfig_url"])
    r.add(
        "the browser-wide proxy setting is left alone while onRequest is the mechanism",
        p.get("network.proxy.type") in (0, 5),
        f"Gecko's own network.proxy.type={p.get('network.proxy.type')} "
        f"autoconfig_url={p.get('network.proxy.autoconfig_url')!r}",
        "system or direct -- the two mechanisms must not both be live",
    )

    # --- 7. it actually routes, and it authenticates -----------------------
    mark = time.time()
    nav = h.navigate(url_for(ROUTED_HOST), settle=5.0)
    connects = h.endpoint_events(mark)
    challenges = h.endpoint_events(mark, kinds=("proxy_407",))
    r.add(
        "CLAIM 2b: an in-scope request reaches the local proxy and the page loads",
        nav["loaded_marker"] and len(connects) >= 1,
        f"marker_loaded={nav['loaded_marker']} neterror={nav['neterror']!r} "
        f"connects={[c['target'] for c in connects]}",
        "the marker page, via at least one authenticated CONNECT",
    )
    r.add(
        "CLAIM 2c: proxyAuthorizationHeader satisfies the desktop proxy's Basic challenge",
        len(connects) >= 1 and all(c.get("authenticated") for c in connects),
        f"{len(challenges)} 407 challenge(s) and {len(connects)} authenticated CONNECT(s). "
        "Firefox presents the header on the ProxyInfo pre-emptively, so zero 407s here is "
        "the signature of the header working -- the opposite of Chromium, where a 407 "
        "followed by a successful CONNECT is the signature of onAuthRequired working.",
        "authenticated CONNECTs",
    )
    if h.real_host:
        h.real_ports = {"listening": h.real_host_listeners()}
        chosen = (s.get("endpoint") or {}).get("port")
        r.note(
            "GROUND TRUTH: the real host's own listening sockets",
            f"the process is listening on {h.real_ports['listening']} and the chosen port is {chosen}",
        )
        serving = f"the real host is listening on {h.real_ports['listening']}"
    else:
        serving = f"the bridge is serving plaintext on {h.proxy_port}"
    r.add(
        "the extension routed over the plaintext proxy via webRequest",
        s.get("routingTransport") == "http",
        f"routingTransport={s.get('routingTransport')!r} endpoint={s.get('endpoint')}; {serving}",
        "http",
    )
    r.add(
        "CLAIM 2d: webRequest permission is present for proxy authentication (plaintext, same as Chromium)",
        "webRequest" in perms and "webRequestAuthProvider" in perms,
        f"the loaded manifest's permissions are {perms}",
        "webRequest + webRequestAuthProvider",
    )
    r.add(
        "the browser is never left asking the USER for the proxy password",
        h.m.alerts_dismissed == 0,
        f"{h.m.alerts_dismissed} modal prompt(s) had to be dismissed to keep the run going; "
        f"last was {h.m.last_alert[:120]!r}. A password dialog is what a browser shows when "
        "an extension does not answer a 407 -- and it is a dialog no user of this add-on has "
        "a password for.",
        "no prompt",
    )
    if not (len(connects) >= 1 and all(c.get("authenticated") for c in connects)):
        probe_proxy_auth(h, r)

    # --- 8. DNS ------------------------------------------------------------
    # A 407 log line records the CONNECT target just as an accepted CONNECT
    # does, so where name resolution happens is answerable whether or not the
    # authentication succeeded. Both kinds are counted, deliberately.
    mark = time.time()
    nav = h.navigate(url_for(ROUTED_HOST), settle=5.0)
    seen = h.endpoint_events(mark, kinds=("connect", "proxy_407"))
    why_dns = (
        f"{ROUTED_HOST} cannot resolve anywhere, so its arrival here as a NAME is proof "
        "the browser did not resolve it."
        if not h.real_host else
        f"every one of those was delivered over a socket opened by the bridge process "
        f"({sorted({c.get('peer') for c in seen})}) rather than by Firefox, so the browser "
        "did not connect and therefore did not resolve -- the desktop side did. That is "
        "the same conclusion the .invalid form reaches, measured at the far end of the hop "
        "because the real proxy deliberately logs no destination."
    )
    r.add(
        "DNS for routed sites is handed to the desktop app, not done on this machine",
        any(c.get("target", "").split(":")[0] == ROUTED_HOST for c in seen),
        f"the proxy received these CONNECT targets: "
        f"{[(c['kind'], c.get('target')) for c in seen]} -- {why_dns} "
        f"The page itself: neterror={nav['neterror']!r}",
        f"a CONNECT naming {ROUTED_HOST}",
    )
    before = h.leak_count()
    mark = time.time()
    nav = h.navigate(url_for(LEAK_HOST, h.leak_port), settle=5.0)
    leak_seen = h.endpoint_events(mark, kinds=("connect", "proxy_407"))
    r.add(
        "THE SHARP DNS TEST: a name this browser CAN resolve locally is still handed to "
        "the proxy rather than resolved",
        (not nav["leaked_direct"]) and h.leak_count() == before
        and any(c.get("target", "").split(":")[0] == LEAK_HOST for c in leak_seen),
        f"{LEAK_HOST} is mapped to loopback in this profile and a decoy is listening there, "
        f"so a browser that resolved the name itself would have got a page. "
        f"direct decoy hits during this navigation={h.leak_count() - before}; "
        f"the proxy saw {[(c['kind'], c.get('target')) for c in leak_seen]}; "
        f"leaked_direct={nav['leaked_direct']}",
        "the proxy sees the name; the decoy is never touched",
    )

    # --- 9. WebRTC ---------------------------------------------------------
    webrtc = h.ext_eval("return await b.privacy.network.webRTCIPHandlingPolicy.get({});")
    r.add(
        "CLAIM 5: Firefox accepts privacy.network.webRTCIPHandlingPolicy",
        isinstance(webrtc, dict) and webrtc.get("value") == "proxy_only"
        and webrtc.get("levelOfControl") == "controlled_by_this_extension",
        f"the extension reads back value={webrtc.get('value')!r} "
        f"levelOfControl={webrtc.get('levelOfControl')!r}; "
        f"the popup reports privacy={json.dumps(h.state().get('privacy'))}",
        "proxy_only / controlled_by_this_extension",
    )
    ice_prefs = h.prefs([
        "media.peerconnection.ice.proxy_only",
        "media.peerconnection.ice.proxy_only_if_behind_proxy",
        "media.peerconnection.ice.no_host",
        "media.peerconnection.ice.obfuscate_host_addresses",
        "media.peerconnection.ice.relay_only",
    ])
    r.add(
        "GROUND TRUTH: Gecko's own ICE preferences are what proxy_only means",
        ice_prefs.get("media.peerconnection.ice.proxy_only") is True,
        f"read in chrome context: {json.dumps(ice_prefs)}",
        "proxy_only true, including when browser-wide proxy settings are direct",
    )
    ice_armed = gather_ice(h)
    r.add(
        "and no ICE candidate exposes a host address while routing",
        has_host_ice_candidate(ice_idle)
        and not has_host_ice_candidate(ice_armed),
        f"{len(ice_armed)} candidate(s) while armed: {ice_armed[:3]}. "
        f"The idle control captured {len(ice_idle)} valid candidate(s).",
        "no 'typ host' candidates",
    )

    prediction = h.ext_eval("return await b.privacy.network.networkPredictionEnabled.get({});")
    pref_pred = h.prefs(["network.prefetch-next", "network.dns.disablePrefetch",
                         "network.predictor.enabled", "network.http.speculative-parallel-limit"])
    r.add(
        "speculative name lookups and connections are turned off",
        isinstance(prediction, dict) and prediction.get("value") is False,
        f"extension reads networkPredictionEnabled={prediction.get('value')} "
        f"levelOfControl={prediction.get('levelOfControl')!r}; Gecko: {json.dumps(pref_pred)}",
        "false",
    )

    # --- 10. per-site rules ------------------------------------------------
    h.apply_settings(mode="listed", listed=[ROUTED_HOST], excluded=[])
    h.wait_for_state("protected")
    mark = time.time()
    nav_in = h.navigate(url_for(ROUTED_HOST), settle=4.0)
    nav_out = h.navigate(url_for(OTHER_HOST), settle=4.0)
    targets = [c["target"] for c in h.endpoint_events(mark)]
    if h.real_host:
        # THE UNLISTED SITE IS SUPPOSED TO WORK. With the stand-in, an unlisted
        # `.invalid` name simply cannot resolve, so "it did not load" was an
        # artefact of the scaffolding rather than the property under test. Here
        # it loads -- directly, over a socket Firefox opened -- which is exactly
        # what "sites they deliberately left outside the tunnel keep working"
        # means, and the proxy still never sees it.
        direct = [e["target"] for e in _UPSTREAM
                  if e.get("kind") == "direct" and e.get("t", 0) >= mark]
        r.add(
            "in listed mode a listed site is routed and an unlisted one is not",
            nav_in["loaded_marker"] and ROUTED_HOST in targets
            and OTHER_HOST not in targets and OTHER_HOST in direct,
            f"listed loaded={nav_in['loaded_marker']} and reached the fake internet through "
            f"the bridge: proxy saw {targets}. Unlisted loaded={nav_out['loaded_marker']} and "
            f"reached it DIRECTLY, over a socket Firefox opened: {direct}. The unlisted site "
            "is meant to keep working; what matters is that the bridge never saw it.",
            "the listed site through the bridge, the unlisted one direct and never at the bridge",
        )
    else:
        r.add(
            "in listed mode a listed site is routed and an unlisted one is not",
            nav_in["loaded_marker"] and (not nav_out["loaded_marker"])
            and ROUTED_HOST in targets and OTHER_HOST not in targets,
            f"listed loaded={nav_in['loaded_marker']}; unlisted loaded={nav_out['loaded_marker']} "
            f"neterror={nav_out['neterror']!r}; proxy saw {targets}",
            "the listed site through the proxy, the unlisted one never reaching it",
        )

    # --- 11. THE FAIL-CLOSED PROOF -----------------------------------------
    # The desktop app still claims connected and ready. The proxy is gone. On
    # Firefox this is the case the design says the block layer cannot cover,
    # because the extension has no way to know -- so what stops the request is
    # whatever Gecko does when an extension-supplied proxy is unreachable.
    failover = h.prefs(["network.proxy.failover_direct", "network.proxy.failover_timeout",
                        "network.proxy.retry_failed_proxies"])
    r.note("the preference this case turns on", f"{json.dumps(failover)}")

    h.apply_settings(mode="all", listed=[], excluded=[])
    h.wait_for_state("protected")
    if h.real_host:
        r.note(
            "how the proxy is made to fail in --real-host mode",
            "the real proxy belongs to a process Firefox owns, so it cannot be taken away "
            "without also taking the native-messaging port away -- which is a different "
            "failure (NO_HOST, where the extension knows) from the one this models. What is "
            "removed instead is everything BEHIND the proxy, so the CONNECT fails upstream "
            "while the extension still believes it is protected, and Gecko has to decide "
            "whether to fall back to direct. That decision is what the check measures.",
        )
    h.stop_endpoint()
    before = h.leak_count()
    mark_dead = time.time()
    nav = h.navigate(url_for(ROUTED_HOST), settle=8.0)
    if h.real_host:
        # DECISIVE, rather than inferred from an error code. The site's port now
        # answers with a listener that records who knocked and hangs up, so
        # "the bridge carried it and failed upstream" and "Gecko abandoned the
        # proxy and went direct" are two different observations rather than two
        # readings of the same one. With `.invalid` names the direct fallback
        # had nowhere to go and could not be told apart from a proxy failure at
        # all; that is the weakness this replaces.
        knocks = [e for e in _UPSTREAM
                  if e.get("kind") == "deadend" and e.get("t", 0) >= mark_dead]
        by_browser = [e for e in knocks if not e.get("proxied")]
        r.add(
            "THE FAIL-CLOSED PROOF: with the proxy unreachable, the request fails and does "
            "not go direct",
            (not nav["loaded_marker"]) and (not nav["leaked_direct"]) and not by_browser,
            f"neterror={nav['neterror']!r} marker_loaded={nav['loaded_marker']}; the site's "
            f"port was knocked on {len(knocks)} time(s), by "
            f"{sorted({e.get('peer') for e in knocks}) or 'nobody'} -- "
            f"{len(by_browser)} of those by the browser itself. A browser-opened socket here "
            "is Gecko falling back to direct, which is the failure this check exists for; "
            f"a bridge-opened one is the routing holding and failing upstream. "
            f"marionette={nav['marionette'][:110]!r}",
            "no socket to the site opened by the browser, and no page",
        )
    else:
        r.add(
            "THE FAIL-CLOSED PROOF: with the proxy unreachable, the request fails and does "
            "not go direct",
            (not nav["loaded_marker"]) and (not nav["leaked_direct"])
            and nav["neterror"] not in ("dnsNotFound", "", "connectionFailure"),
            f"neterror={nav['neterror']!r} marionette={nav['marionette']!r} "
            f"marker_loaded={nav['loaded_marker']} body={nav['text']!r}",
            "a proxy-connection error in Gecko's vocabulary, and no page content. "
            "dnsNotFound would mean the browser resolved the name itself, i.e. went direct.",
        )
    nav_leak = h.navigate(url_for(LEAK_HOST, h.leak_port), settle=8.0)
    r.add(
        "THE FAIL-CLOSED PROOF, positively: the decoy that a direct connection WOULD "
        "reach is not reached",
        (not nav_leak["leaked_direct"]) and h.leak_count() == before,
        f"direct decoy hits during the dead-proxy navigation={h.leak_count() - before}; "
        f"page said leaked_direct={nav_leak['leaked_direct']} neterror={nav_leak['neterror']!r} "
        f"body={nav_leak['text']!r}. The control at the top of this run proved the decoy "
        "answers when the browser goes direct.",
        "zero decoy hits",
    )

    # --- 12. the proxy.settings data: URL fallback -------------------------
    # CLAIM 3. The fallback is unreachable through the shipped flow -- refusing
    # the grant lands in no_auth_capability before applyRouting is ever called --
    # so the API call itself is made here, from the add-on's own page, with the
    # add-on's own PAC generator, which is the whole of what the claim asserts.
    h.start_endpoint()
    h.set_tunnel_state("connected")
    h.apply_settings(armed=False)
    h.wait_for_state("off", timeout=20)
    probe = h.ext_eval(
        f"const UUID = {json.dumps(h.uuid)}; const PORT = {h.proxy_port};"
        "let pac = null, how = '';"
        "try {"
        "  const mod = await import(`moz-extension://${UUID}/src/core/pac.js`);"
        "  pac = mod.buildPac({mode:'all', listed:[], excluded:[]}, {host:'127.0.0.1', port:PORT});"
        "  how = 'generated by the shipped src/core/pac.js';"
        "} catch (e) {"
        "  how = 'a stand-in of the same shape (' + String(e.message).slice(0,60) + ')';"
        "  pac = 'function FindProxyForURL(url, host) { return \"PROXY 127.0.0.1:' + PORT + '\"; }';"
        "}"
        "const url = 'data:application/x-ns-proxy-autoconfig;base64,' + btoa(pac);"
        "let err = '';"
        "try { await b.proxy.settings.set({value:{proxyType:'autoConfig', autoConfigUrl:url}}); }"
        "catch (e) { err = String(e.message); }"
        "const got = await b.proxy.settings.get({});"
        "return {how, pacLength: pac.length, dataUrlLength: url.length, err,"
        "        proxyType: (got.value||{}).proxyType, levelOfControl: got.levelOfControl,"
        "        directFallback: pac.indexOf('; DIRECT') >= 0};"
    )
    time.sleep(1.5)
    p = h.prefs(["network.proxy.type", "network.proxy.autoconfig_url"])
    pac_url = str(p.get("network.proxy.autoconfig_url") or "")
    mark = time.time()
    nav = h.navigate(url_for(ROUTED_HOST), settle=6.0)
    fallback_events = h.endpoint_events(mark, kinds=("connect", "proxy_407"))
    r.add(
        "CLAIM 3: proxy.settings accepts a data: URL for autoConfigUrl, and the PAC runs",
        p.get("network.proxy.type") == 2
        and pac_url.startswith("data:application/x-ns-proxy-autoconfig")
        and len(fallback_events) >= 1,
        f"the PAC was {(probe or {}).get('how')}, {(probe or {}).get('pacLength')} chars, "
        f"'; DIRECT' present: {(probe or {}).get('directFallback')}; "
        f"proxy.settings.set error={str((probe or {}).get('err'))[:80]!r}; "
        f"the extension reads back proxyType={(probe or {}).get('proxyType')!r} "
        f"levelOfControl={(probe or {}).get('levelOfControl')!r}; "
        f"GROUND TRUTH network.proxy.type={p.get('network.proxy.type')} (2=PAC) and "
        f"autoconfig_url is {len(pac_url)} chars starting {pac_url[:46]!r}; "
        f"a navigation then made the proxy see "
        f"{[(e['kind'], e.get('target')) for e in fallback_events]}; "
        f"page neterror={nav['neterror']!r} marker_loaded={nav['loaded_marker']}",
        "network.proxy.type=2 with a data: autoConfigUrl, and the request arriving at the proxy",
    )
    r.note(
        "what the settings fallback can and cannot do",
        f"the fallback cannot present the token, so the expected outcome against an "
        f"authenticated proxy is a challenge and no page: 407s="
        f"{len([e for e in fallback_events if e['kind'] == 'proxy_407'])}, "
        f"authenticated CONNECTs={len([e for e in fallback_events if e['kind'] == 'connect'])}, "
        f"marker_loaded={nav['loaded_marker']}, leaked_direct={nav['leaked_direct']}",
    )
    h.ext_eval("try { await b.proxy.settings.clear({}); } catch (e) { /* nothing of ours */ } "
               "return 'cleared';")

    # --- 13. a hostile bridge cannot move the endpoint ---------------------
    if h.real_host:
        # THE REAL HOST HAS NO INJECTION PATH, and that is the claim rather than
        # a reason to skip the check. `encodeOutboundBridgeMessage` is the one
        # place every outbound byte passes through and it refuses an
        # address-shaped value outright, and `BridgeNode`'s constructor refuses
        # one before the object can even be built. So the address is pushed in
        # at the only door that exists -- the state source -- and what is
        # measured is that it never comes out the other side.
        h.set_tunnel_state("connected")
        state = json.loads(h.state_file.read_text(encoding="utf-8"))
        state["nodes"] = [{"slug": "hostile", "name": "Hub 198.51.100.7", "flag": "??"},
                          {"slug": "benign", "name": "Yangon", "flag": "MM"}]
        h.state_file.write_text(json.dumps(state), encoding="utf-8")
        h.apply_settings(mode="all", listed=[], excluded=[], armed=True)
        s = h.wait_for_state("protected", timeout=40)
        blob = json.dumps(s)
        names = [n.get("name") for n in (s.get("nodes") or [])]
        r.add(
            "an injected host field in the credential reply is ignored",
            s.get("state") == "protected" and "198.51.100.7" not in blob
            and "Yangon" in names,
            f"state={s.get('state')!r} endpoint={s.get('endpoint')}; an address-shaped node "
            f"name was pushed into the real host's state source and the node list the "
            f"extension ended up with is {names} -- the benign node survived, so the list was "
            f"delivered and only the offending entry was refused (BridgeNode's constructor "
            f"rejects it; had it got past, encodeOutboundBridgeMessage would have suppressed "
            f"the whole message). The injected address appears anywhere in the extension's "
            f"snapshot: {'198.51.100.7' in blob}",
            "routing continues, to loopback, with the injected address nowhere",
        )
    else:
        h.inject_host = "198.51.100.7"
        h.install_native_host()
        h.set_tunnel_state("connected")
        h.apply_settings(mode="all", listed=[], excluded=[], armed=True)
        s = h.wait_for_state("protected", timeout=40)
        blob = json.dumps(s)
        r.add(
            "an injected host field in the credential reply is ignored",
            s.get("state") == "protected" and "198.51.100.7" not in blob,
            f"state={s.get('state')!r} endpoint={s.get('endpoint')} "
            f"routingMechanism={s.get('routingMechanism')!r}; the injected address appears "
            f"anywhere in the extension's snapshot: {'198.51.100.7' in blob}",
            "routing continues, to loopback, with the injected address nowhere",
        )

    # --- 14. an unreadable desktop state degrades downwards ----------------
    h.state_file.write_text("{ this is not json", encoding="utf-8")
    s = h.wait_for_state("app_not_running", timeout=30)
    # NOT A HAND-COPIED LIST OF STATE NAMES ANY MORE.
    #
    # It used to enumerate seven of them, and it went stale the first time the
    # extension's vocabulary grew: `host_not_answering` is fail-closed by
    # `isFailClosedState` and the block layer is installed in it, and this check
    # called it a failure purely because nobody had come back and added the
    # word. A second copy of a rule the extension already owns is a copy that
    # will disagree with it eventually.
    #
    # What the check actually means is two things, and both are now said
    # directly: the extension must report itself fail-closed, and it must be
    # fail-closed because the DESKTOP state is unreadable rather than because
    # its own enforcement broke -- which is what the three enforcement-failure
    # states mean and is a different (worse) finding that must not be absorbed
    # here.
    enforcement_failures = ("not_enforcing", "routing_failed", "routing_unauthenticated")
    r.add(
        "an unreadable desktop state degrades to not-connected, not to connected",
        s.get("failClosed") is True and s.get("state") not in enforcement_failures,
        f"state={s.get('state')!r} failClosed={s.get('failClosed')!r}",
        "fail-closed, and not by way of an enforcement failure",
    )

    # The corrupt bytes above stay on disk, and that file is the stand-in
    # proxy's gate. Restore it before the run goes on: every later claim that
    # sends traffic through the proxy would otherwise find the gate shut and
    # measure this claim's debris instead of what it asks.
    h.set_tunnel_state("connected")

    # --- 15. revoking optional host access fails closed immediately --------
    removed = h.chrome_eval(
        "const done = arguments[arguments.length - 1];"
        "(async () => {"
        "  const { ExtensionPermissions } = ChromeUtils.importESModule("
        "    'resource://gre/modules/ExtensionPermissions.sys.mjs');"
        f"  const policy = WebExtensionPolicy.getByID({json.dumps(ADDON_ID)});"
        "  if (!policy?.extension) throw new Error('no live extension policy');"
        f"  await ExtensionPermissions.remove({json.dumps(ADDON_ID)},"
        "    {permissions: [], origins: ['<all_urls>']}, policy.extension);"
        "  return true;"
        "})().then(v => done(v)).catch(e => done('ERR ' + e.message));",
        timeout=60,
        is_async=True,
    )
    permission_still_present = h.ext_eval(
        "return await b.permissions.contains({origins:['<all_urls>']});"
    )
    s = h.wait_for_state("no_auth_capability", timeout=20)
    rules = h.dynamic_rules()
    p = h.prefs(["network.proxy.type", "network.proxy.autoconfig_url"])
    r.add(
        "revoking Firefox site access while live leaves no stale protected state",
        removed is True
        and permission_still_present is False
        and s.get("state") == "no_auth_capability"
        and s.get("canAuthenticate") is False
        and len(rules) >= 1
        and p.get("network.proxy.type") in (0, 5),
        f"add-on manager removal returned {removed!r}; permission still present="
        f"{permission_still_present!r}; state={s.get('state')!r} "
        f"canAuthenticate={s.get('canAuthenticate')!r}; {len(rules)} block rule(s); "
        f"network.proxy.type={p.get('network.proxy.type')} "
        f"autoconfig_url={str(p.get('network.proxy.autoconfig_url'))[:40]!r}",
        "no_auth_capability, block rules installed, and no proxy setting left live",
    )
    before = h.leak_count()
    nav = h.navigate(url_for(LEAK_HOST, h.leak_port), settle=3.0)
    r.add(
        "the permission-revocation transition blocks instead of going direct",
        removed is True
        and permission_still_present is False
        and s.get("state") == "no_auth_capability"
        and not nav["loaded_marker"]
        and not nav["leaked_direct"]
        and h.leak_count() == before,
        f"direct decoy hits after revocation={h.leak_count() - before}; "
        f"neterror={nav['neterror']!r} timed_out={nav['timed_out']} "
        f"body={nav['text']!r}",
        "zero decoy hits",
    )

    # --- 16. turning it off gives the browser back -------------------------
    h.apply_settings(armed=False)
    h.wait_for_state("off", timeout=20)
    rules = h.dynamic_rules()
    p = h.prefs(["network.proxy.type", "network.proxy.autoconfig_url"])
    webrtc_after = h.ext_eval("return await b.privacy.network.webRTCIPHandlingPolicy.get({});")
    r.add(
        "turning routing off restores the browser",
        len(rules) == 0 and p.get("network.proxy.type") in (0, 5),
        f"{len(rules)} dynamic rules remain; network.proxy.type={p.get('network.proxy.type')}; "
        f"autoconfig_url={str(p.get('network.proxy.autoconfig_url'))[:40]!r}; "
        f"webRTC control released to "
        f"{(webrtc_after or {}).get('levelOfControl')!r} value="
        f"{(webrtc_after or {}).get('value')!r}",
        "zero rules and no proxy setting of ours",
    )
    nav = h.navigate(url_for(LEAK_HOST, h.leak_port), settle=3.0)
    r.add(
        "and the browser can reach the network again once it is off",
        nav["leaked_direct"],
        f"the decoy answered again: {nav['leaked_direct']} ({nav['decoy_hits']} hit(s)) -- "
        "the rules disappear with the extension, so a user can always get their browser back",
        "the decoy page",
    )

    # --- 17. CLAIM 3, once the Firefox-only gate in front of it is opened ---
    # Last, because it reloads the add-on and throws the run's state away.
    try:
        settings_fallback_with_private_browsing(h, r)
    except Exception as e:  # noqa: BLE001
        r.add("CLAIM 3 (second attempt): with private browsing allowed, proxy.settings "
              "accepts a data: URL for autoConfigUrl and the PAC runs",
              False, f"the probe could not be completed: {type(e).__name__}: {str(e)[:200]}",
              "a completed probe")
    return r


def open_private_browsing_gate(h: Harness) -> str:
    """Grant exactly what the add-on manager's "Run in Private Windows"
    checkbox grants, from chrome context, and reload the add-on so it takes
    effect.

    `proxy.settings.set` refuses with "requires private browsing permission"
    unless the extension carries `internal:privateBrowsingAllowed`, and a
    temporary add-on is never born with it. The PAC claims measure
    proxy.settings itself, not this Firefox-only gate, so the gate is opened
    once before the run starts asking. Reloading the add-on closes its own
    pages, so every handle the harness was holding is stale: they are
    re-acquired here before anything is touched again.
    """
    granted = h.chrome_eval(
        "const done = arguments[arguments.length - 1];"
        "(async () => {"
        "  const { ExtensionPermissions } = ChromeUtils.importESModule("
        "    'resource://gre/modules/ExtensionPermissions.sys.mjs');"
        "  const { AddonManager } = ChromeUtils.importESModule("
        "    'resource://gre/modules/AddonManager.sys.mjs');"
        f"  const addon = await AddonManager.getAddonByID({json.dumps(ADDON_ID)});"
        "  if (!addon) return 'no such add-on';"
        f"  await ExtensionPermissions.add({json.dumps(ADDON_ID)},"
        "    {permissions: ['internal:privateBrowsingAllowed'], origins: []});"
        "  await addon.reload();"
        "  return 'granted and reloaded';"
        "})().then(v => done(String(v))).catch(e => done('ERR ' + e.message));",
        timeout=90, is_async=True)
    time.sleep(3.0)
    h.m.set_context("content")
    handles = h.m.handles()
    if not handles:
        raise RuntimeError("the add-on reload left no window to drive")
    h.page_handle = handles[0]
    h.m.switch_to(h.page_handle)
    h.ctl_handle = handles[1] if len(handles) > 1 else h.m.new_tab()
    h.uuid = h.find_uuid()
    h.use_ctl()
    h.m.navigate(f"moz-extension://{h.uuid}/src/ui/options.html", timeout=60)
    time.sleep(2.0)
    return granted


def settings_fallback_with_private_browsing(h: Harness, r: Result) -> None:
    """The data:-URL question, asked again with the gate that blocked it opened.

    `proxy.settings.set` refuses with "requires private browsing permission" on
    a default Firefox install. That is a Firefox-only gate with no Chromium
    equivalent and it sits in front of the whole settings fallback, so it has to
    be opened before the claim underneath it can be tested at all. This grants
    exactly what the add-on manager's "Run in Private Windows" checkbox grants,
    from chrome context, and reloads the add-on so it takes effect.
    """
    before = h.prefs(["extensions.allowPrivateBrowsingByDefault"])
    granted = open_private_browsing_gate(h)

    probe = h.ext_eval(
        f"const UUID = {json.dumps(h.uuid)}; const PORT = {h.proxy_port};"
        "const mod = await import(`moz-extension://${UUID}/src/core/pac.js`);"
        "const pac = mod.buildPac({mode:'all', listed:[], excluded:[]},"
        "                         {host:'127.0.0.1', port:PORT});"
        "const url = 'data:application/x-ns-proxy-autoconfig;base64,' + btoa(pac);"
        "let err = '';"
        "try { await b.proxy.settings.set({value:{proxyType:'autoConfig', autoConfigUrl:url}}); }"
        "catch (e) { err = String(e.message); }"
        "const got = await b.proxy.settings.get({});"
        "return {err, pacLength: pac.length, dataUrlLength: url.length,"
        "        proxyType: (got.value||{}).proxyType,"
        "        incognito: await b.extension.isAllowedIncognitoAccess()};",
        timeout=60)
    time.sleep(1.5)
    p = h.prefs(["network.proxy.type", "network.proxy.autoconfig_url"])
    pac_url = str(p.get("network.proxy.autoconfig_url") or "")
    mark = time.time()
    nav = h.navigate(url_for(ROUTED_HOST), settle=6.0)
    events = h.endpoint_events(mark, kinds=("connect", "proxy_407"))
    r.add(
        "CLAIM 3 (second attempt): with private browsing allowed, proxy.settings "
        "accepts a data: URL for autoConfigUrl and the PAC runs",
        p.get("network.proxy.type") == 2
        and pac_url.startswith("data:application/x-ns-proxy-autoconfig")
        and len(events) >= 1,
        f"pref extensions.allowPrivateBrowsingByDefault was {before}; the chrome-context "
        f"grant said {granted!r}; the add-on now reports isAllowedIncognitoAccess="
        f"{(probe or {}).get('incognito')}; proxy.settings.set error="
        f"{str((probe or {}).get('err'))[:90]!r}; the add-on reads back proxyType="
        f"{(probe or {}).get('proxyType')!r}; GROUND TRUTH network.proxy.type="
        f"{p.get('network.proxy.type')} and autoconfig_url is {len(pac_url)} chars "
        f"starting {pac_url[:46]!r}; a navigation then made the proxy see "
        f"{[(e['kind'], e.get('target')) for e in events]}; page neterror={nav['neterror']!r} "
        f"decoy_hits={nav['decoy_hits']}",
        "network.proxy.type=2 with a data: autoConfigUrl, and the request reaching the proxy",
    )


def make_https_proxy_variant(package: Path, dest: Path) -> Path:
    """Edit dest's firefox.js so the live ProxyInfo `type` is https.

    Not a recommendation on its own -- it is the second half of a measurement.
    The isolated probes show Firefox sends `proxyAuthorizationHeader` only when
    the proxy is declared https, so this variant exists to answer the question
    that follows: with the header actually reaching the proxy, does everything
    else the Chromium runs proved hold on Firefox too?

    Operates on the current inline
    `return { type: 'http', host: endpoint.host, port: endpoint.port };`
    object. A missing, duplicate, or stale (`const info = ...`) source raises
    rather than claiming the HTTPS variant already exists. `package` is the
    working tree callers already copied into dest; dest is what is edited.
    """
    path = dest / "src" / "adapters" / "firefox.js"
    original = path.read_text(encoding="utf-8")
    updated, action = apply_https_proxy_variant_text(original)
    if action == "already_https":
        if updated != original or live_proxy_type_in_text(original) != "https":
            raise FixedVariantError(
                "refusing to claim an HTTPS variant exists"
            )
        print(
            "  variant: firefox.js already declares ProxyInfo type 'https'  "
            "(no edit needed)"
        )
        return dest
    if action != "mutated" or updated == original:
        raise FixedVariantError(
            "no-op ProxyInfo mutation; refusing to claim an HTTPS variant exists"
        )
    if live_proxy_type_in_text(updated) != "https":
        raise FixedVariantError(
            "no-op ProxyInfo mutation; refusing to claim an HTTPS variant exists"
        )
    path.write_text(updated, encoding="utf-8")
    print("  variant: firefox.js ProxyInfo type 'http' -> 'https'  (no other change)")
    return dest


def make_resource_type_variant(package: Path, dest: Path, drop: list[str]) -> Path:
    """Copy the package with named resourceTypes removed from the block layer.

    The same device as verify_chromium.py's --pregrant-host: one edit, printed,
    so a reader can see exactly what separates the artefact that was tested from
    the artefact that ships. It exists to answer the second question a rejected
    rule set raises -- not only "does Firefox refuse this list", but "does the
    fail-closed layer work on Firefox once it stops refusing".
    """
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(package, dest)
    path = dest / "src" / "core" / "constants.js"
    text = path.read_text(encoding="utf-8")
    before = re.search(r"DNR_RESOURCE_TYPES\s*=\s*\[(.*?)\]", text, re.S)
    if not before:
        raise RuntimeError("could not find DNR_RESOURCE_TYPES in the package")
    # The authored source quotes the list with single quotes; the store size
    # transform (esbuild) rewrites the packaged constants.js with double
    # quotes. Accept both so the diagnostic variant still works on the bytes
    # that ship.
    kept = [
        t for t in re.findall(r"['\"]([a-z_]+)['\"]", before.group(1))
        if t not in drop
    ]
    body = "\n" + "".join(f"  '{t}',\n" for t in kept)
    text = text[:before.start(1)] + body + text[before.end(1):]
    path.write_text(text, encoding="utf-8")
    print(f"  variant: DNR_RESOURCE_TYPES -{drop}  (no other change; "
          f"{len(kept)} types remain)")
    return dest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--package", default=None)
    ap.add_argument("--workdir", default=None)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument(
        "--drop-resource-types", default="",
        help=(
            "comma-separated resourceTypes to remove from the block layer before "
            "loading. Firefox's declarativeNetRequest schema does not know every "
            "value Chromium's does, and updateDynamicRules validates the whole call, "
            "so one unknown value discards the entire rule set. This flag exists to "
            "test what the block layer does once the browser stops refusing it."
        ),
    )
    ap.add_argument(
        "--plaintext-bridge", action="store_true",
        help=(
            "serve the stand-in bridge's CONNECT proxy without TLS even when the "
            "packaged adapter declares its ProxyInfo type 'https'. This is the desktop "
            "side AS IT IS TODAY: the fix for the 2026-08-07 authentication defect "
            "requires a TLS loopback proxy, which the desktop bridge does not yet serve. "
            "The run exists to measure what the extension does about that -- it must "
            "fail closed and say so, not report PROTECTED while nothing loads."
        ),
    )
    ap.add_argument(
        "--trust-bridge-cert", action="store_true",
        help=(
            "run WITHOUT acceptInsecureCerts, and install the bridge stand-in's "
            "certificate into the scratch profile's own cert9.db instead. This is the "
            "run the 2026-08-07 lane could not do: its session disabled certificate "
            "validation browser-wide, so its TLS result proved the header arrives over "
            "TLS and proved nothing about whether a real Firefox would accept the "
            "bridge's certificate. Adds a negative control (an untrusted certificate on "
            "the same address must be refused) and a scope control (a certificate signed "
            "by the bridge's key for another host must be refused)."
        ),
    )
    ap.add_argument(
        "--real-host", default="",
        help=(
            "run the REAL compiled bridge host as this browser's native-messaging "
            "host instead of dev_bridge.py. 'harness' compiles "
            "bin/wins_bridge_host_harness.dart, which is the shipping host with a "
            "file-backed state source in place of UnobservedStateSource and nothing "
            "else changed; 'shipped' runs tools/native_messaging/host/wins_bridge_host "
            "exactly as installed, which reports app_not_running and can never reach "
            "PROTECTED. The routed hosts move to .localhost because the real proxy "
            "does real DNS, and every connection to the fake internet is attributed "
            "to the process that opened it."
        ),
    )
    ap.add_argument(
        "--allow-private-browsing", action="store_true",
        help="stand in for the user allowing the add-on in private windows, which "
             "Firefox requires before proxy.settings.set will work at all",
    )
    ap.add_argument(
        "--fixed", action="store_true",
        help=(
            "run the FIXED variant: the two rejected resourceTypes removed, the "
            "ProxyInfo declared https so that proxyAuthorizationHeader is actually "
            "sent, and private browsing allowed. Every edit is printed. This answers "
            "the question the shipped run cannot: with the three things Firefox "
            "refuses put right, does everything Chrome and Edge proved hold here too?"
        ),
    )
    args = ap.parse_args()

    root = HERE.parent
    package = Path(args.package) if args.package else root / "dist" / "firefox"
    if not package.exists():
        print(f"verify: no package at {package}; run build.py firefox first", file=sys.stderr)
        return 2

    work = Path(args.workdir) if args.workdir else Path(
        os.environ.get("TMPDIR", "/tmp")) / f"wv-verify-firefox-{os.getpid()}"
    work.mkdir(parents=True, exist_ok=True)

    variant_note = ""
    drop = [x.strip() for x in args.drop_resource_types.split(",") if x.strip()]
    if args.fixed:
        drop = drop or ["webtransport", "webbundle"]
    if drop:
        package = make_resource_type_variant(package, work / "variant", drop)
        variant_note = f" [variant: resourceTypes {drop} removed"
    if args.fixed:
        if not drop:
            shutil.copytree(package, work / "variant")
            package = work / "variant"
        make_https_proxy_variant(package, package)
        variant_note += "; ProxyInfo type https; private browsing allowed"
    if variant_note:
        variant_note += "]"

    # WHAT THE BRIDGE STAND-IN MUST SERVE, decided by the package rather than by
    # a flag. See proxy_type_in(). `--plaintext-bridge` forces the other answer,
    # which is the run that measures the shipped package against the desktop side
    # AS IT IS TODAY rather than as the adapter now requires it -- the difference
    # between the two runs is the honest size of the remaining gap.
    declared = proxy_type_in(package)
    tls = declared == "https" and not args.plaintext_bridge
    print(f"  the packaged adapter declares ProxyInfo type {declared!r}; "
          f"the bridge stand-in will serve {'TLS' if tls else 'plaintext'} on loopback"
          f"{'  (forced by --plaintext-bridge)' if args.plaintext_bridge else ''}")

    global ROUTED_HOST, OTHER_HOST, LEAK_HOST, SITE_PORT  # noqa: PLW0603
    real_host_bin: Path | None = None
    if args.real_host:
        if args.real_host not in ("harness", "shipped"):
            print("verify: --real-host takes 'harness' or 'shipped'", file=sys.stderr)
            return 2
        host_pkg = root.parent / "tools" / "native_messaging" / "host"
        if args.real_host == "shipped":
            source_bin = host_pkg / "wins_bridge_host"
            if not source_bin.exists():
                print(f"verify: no compiled host at {source_bin}", file=sys.stderr)
                return 2
            # COPIED INTO THE SCRATCH DIRECTORY, byte for byte, and the reason
            # is a macOS one rather than a product one: the repository lives
            # under ~/Documents, which is TCC-protected, and Firefox launching a
            # native-messaging host from there gets no host at all -- the port
            # opens, no message ever arrives, and the extension ages into STALE
            # with nothing in `lastError` to explain it. Measured: the identical
            # binary run from TMPDIR works. The digest is printed so the copy
            # cannot be mistaken for a different artefact.
            out_dir = work / "host"
            out_dir.mkdir(parents=True, exist_ok=True)
            real_host_bin = out_dir / "wins_bridge_host"
            shutil.copy2(source_bin, real_host_bin)
            digest = subprocess.run(["shasum", "-a", "256", str(source_bin)],
                                    capture_output=True, text=True).stdout.split()[0]
            print(f"  the shipped binary, copied out of the TCC-protected tree: {digest}")
        else:
            out_dir = work / "host"
            out_dir.mkdir(parents=True, exist_ok=True)
            # Compiled to the name `wins_bridge_host` deliberately: it is what
            # lsof reports for the process, and the attribution below matches on
            # it. The SOURCE is wins_bridge_host_harness.dart and the run output
            # says so, so nothing here can be mistaken for the shipping binary.
            real_host_bin = out_dir / "wins_bridge_host"
            print(f"  compiling the real host from {host_pkg}/bin/wins_bridge_host_harness.dart")
            build = subprocess.run(
                ["dart", "compile", "exe", "bin/wins_bridge_host_harness.dart",
                 "-o", str(real_host_bin)],
                cwd=str(host_pkg), capture_output=True, text=True)
            if build.returncode != 0:
                print(build.stdout + build.stderr, file=sys.stderr)
                return 2
        ROUTED_HOST, OTHER_HOST, LEAK_HOST = REAL_HOST_ROUTED, REAL_HOST_OTHER, REAL_HOST_LEAK
        print(f"  --real-host={args.real_host}: {real_host_bin}")
        print(f"  routed/unlisted/decoy names are now {ROUTED_HOST} / {OTHER_HOST} / {LEAK_HOST} "
              "-- the real proxy does real DNS, so .invalid cannot be the target")

    print(f"verifying firefox against {package}{variant_note}")
    h = Harness(package, work, args.keep)
    if real_host_bin is not None:
        h.real_host = real_host_bin
        h.real_marker_port = free_port()
        SITE_PORT = h.real_marker_port
    h.tls_mode = bool(args.fixed) or tls
    h.trust_bridge_cert = bool(args.trust_bridge_cert)
    h.allow_private_browsing = bool(args.fixed or args.allow_private_browsing)
    if h.trust_bridge_cert and not h.tls_mode:
        print("verify: --trust-bridge-cert needs a TLS bridge; there is no proxy "
              "certificate to trust when the bridge is serving plaintext", file=sys.stderr)
        return 2
    result = h.result
    try:
        if h.real_host:
            # The certificate the REAL host will serve. Generated here and
            # handed to it by path -- the host loads material and never creates
            # it, which is the whole reason `BridgeTlsMaterialSource` takes
            # arguments rather than hunting through directories. No stand-in TLS
            # proxy is started: the real host's own `SecureServerSocket` is the
            # thing under test.
            certdir = h.work / "certs"
            certdir.mkdir(parents=True, exist_ok=True)
            _, h.proxy_cert = dev_endpoint.make_proxy_cert(certdir)
        elif h.tls_mode:
            h.start_tls_proxy()
        h.set_tunnel_state("app_not_running")
        h.start_leak_server()
        h.start_endpoint()
        h.install_native_host()
        h.launch_browser()
        if h.trust_bridge_cert:
            # THE BRIDGE'S certificate is the one under test. The marker's is
            # trusted too, and that is scaffolding, not part of the claim: the
            # `.invalid` hosts behind this proxy stand in for the ordinary
            # internet, which in the field is served by ordinary CA-signed
            # certificates. Without it the run would fail on the fake internet
            # rather than on the thing being measured, and both are named in
            # the check output so neither can be mistaken for the other.
            print(f"  bridge certificate  -> {h.add_trusted_cert(h.proxy_cert, 'bridge proxy')}")
            marker_crt = h.work / "certs" / "marker.crt"
            if marker_crt.exists():
                print(f"  marker certificate  -> {h.add_trusted_cert(marker_crt, 'marker (scaffolding)')}")
            if h.real_host:
                lh_crt = h.work / "certs" / "localhost.crt"
                print(f"  .localhost certificate -> "
                      f"{h.add_trusted_cert(lh_crt, 'fake internet (scaffolding)')}")
        addon_id = h.install_extension()
        h.uuid = h.find_uuid()
        h.open_tabs()
        gate = open_private_browsing_gate(h)
        print(f"  add-on {addon_id}, uuid {h.uuid}, "
              f"advertised proxy {h.advertised_proxy_port()}, "
              f"plaintext {h.proxy_port}, tls {h.tls_proxy_port}, "
              f"marker https {h.http_port}, direct decoy https {h.leak_port}")
        print(f"  private-browsing gate: {gate}\n")
        if addon_id != ADDON_ID:
            print(f"  WARNING: installed id {addon_id!r} is not {ADDON_ID!r}; "
                  "the native host allow-list will not match")
        result = run(h)
    finally:
        h.shutdown()
        scored = [c for c in result.checks if not c.get("note")]
        passed = sum(1 for c in scored if c["ok"])
        print(f"\nfirefox: {passed}/{len(scored)} checks passed")
        if args.json_out:
            # Written in `finally`: a run that fell over halfway is still the
            # only record of everything it had already established.
            Path(args.json_out).write_text(json.dumps({
                "browser": "firefox",
                "package": str(package),
                "variant": variant_note,
                "passed": passed,
                "total": len(scored),
                "checks": result.checks,
            }, indent=2), encoding="utf-8")
    return 0 if all(c["ok"] for c in scored) else 1


if __name__ == "__main__":
    sys.exit(main())
