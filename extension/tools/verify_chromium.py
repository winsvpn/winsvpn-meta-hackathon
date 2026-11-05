#!/usr/bin/env python3
"""Load the extension in a real Chromium browser and observe what it does.

    python3 tools/verify_chromium.py --browser chrome
    python3 tools/verify_chromium.py --browser edge

Nothing here asserts behaviour from documentation. Every check drives the real
browser through the DevTools protocol, makes a real request, and reads the real
outcome -- the network stack's own error string, the proxy setting the browser
is actually holding, the address type the SOCKS endpoint actually received.

NOTHING LEAVES THE MACHINE. Every hostname used is under `.invalid`, which
RFC 2606 guarantees will never resolve, and the SOCKS endpoint is a catch-all
that connects everything to a local marker server. A name that cannot resolve is
the sharpest possible probe: if a page loads, the name must have been handed to
the proxy; if it fails to resolve, the browser must have tried to resolve it
itself and therefore did not use the proxy.

Three pieces of scaffolding, all local:
  dev_endpoint.py  a SOCKS5 endpoint that logs the address type of every CONNECT
  dev_bridge.py    the reference native-messaging host, driven by a JSON file
  cdp.py           a dependency-free DevTools client
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import re
import secrets
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cdp  # noqa: E402
import dev_endpoint  # noqa: E402

ROUTED_HOST = "routed.wv-test.invalid"
OTHER_HOST = "other.wv-test.invalid"
MARKER = "WV-MARKER-OK"

# --real-host: the stand-in proxy is a catch-all and the REAL compiled host is
# an honest proxy that does real DNS, so a `.invalid` CONNECT target dies at
# getaddrinfo. RFC 6761 makes `.localhost` answer locally with no packet leaving
# the machine, and every connection to the fake internet is then attributed to
# the process that opened it -- a stronger observation than "the name could not
# have resolved", and the only one available once the proxy is real. Reasoned
# out in full in tools/verify_firefox.py, which shares this design.
# MEASURED, and it decides the shape of the whole Chromium run: Chromium
# IMPLICITLY BYPASSES THE PROXY for `localhost` and `*.localhost`, before the
# PAC is consulted and with no extension-visible way to turn it off
# (`ProxyBypassRules::MatchesImplicitRules`; `--proxy-bypass-list` applies only
# to `--proxy-server`, and an extension's own config replaces it). A first
# attempt with `.localhost` names loaded the page with ZERO CONNECTs and every
# extension auth counter at zero -- the request never reached the proxy at all.
#
# So Chromium cannot use the one name family the real proxy can resolve. What it
# can use is an ADDRESS form the implicit rules do not cover: `0.0.0.0`, which
# macOS connect(2) routes to loopback (measured) and which is not in
# 127.0.0.0/8, ::1, or the link-local ranges the implicit rules name. The site
# checks therefore use that, and the DNS and per-site checks keep an unresolvable
# `.invalid` NAME, where the proof becomes the error code: a browser that
# resolved the name itself would report ERR_NAME_NOT_RESOLVED, and one that
# handed it to the proxy gets ERR_TUNNEL_CONNECTION_FAILED from the real host's
# own failed lookup.
REAL_HOST_ROUTED = "0.0.0.0"
REAL_HOST_NAME = "routed.wv-test.invalid"
REAL_HOST_OTHER = "other.wv-test.invalid"
SITE_PORT: int | None = None
BRIDGE_PROCESS_PREFIX = "wins_bridge"
_UPSTREAM: list[dict] = []

# https, not http. The desktop bridge implements CONNECT only and deliberately
# does not forward plain HTTP, so the tests use the scheme the product actually
# supports. The certificate is self-signed and the browser is launched with
# --ignore-certificate-errors: the properties under test are routing, blocking
# and where the name resolution happens, none of which the certificate affects.
def url_for(host: str) -> str:
    return f"https://{host}/" if SITE_PORT is None else f"https://{host}:{SITE_PORT}/"


def peer_process(peer_port: int) -> str:
    """Which process owns the other end of this connection, right now."""
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


class AttributedMarkerHandler(socketserver.StreamRequestHandler):
    """The fake internet in --real-host mode, plus who fetched the page."""

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
            "target": host_header.split(":")[0],
            "raw": host_header,
            "request": request,
            "peer": peer,
            # The real proxy relays only after `_isAuthenticated` has passed and
            # the gate has admitted. A byte arriving here through it is an
            # authenticated CONNECT by construction.
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

BROWSERS = {
    "chrome": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "edge": "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Result:
    def __init__(self):
        self.checks: list[dict] = []

    def add(self, name: str, ok: bool, observed: str, expected: str = "") -> None:
        self.checks.append({"name": name, "ok": bool(ok), "observed": observed, "expected": expected})
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {name}")
        print(f"         observed: {observed}")
        if expected and not ok:
            print(f"         expected: {expected}")

    @property
    def ok(self) -> bool:
        return all(c["ok"] for c in self.checks)


class Harness:
    def __init__(self, browser: str, package: Path, workdir: Path, keep: bool):
        self.browser = browser
        self.package = package.resolve()
        self.work = workdir
        self.keep = keep
        self.profile = workdir / "profile"
        self.state_file = workdir / "bridge_state.json"
        self.bridge_log = workdir / "bridge.jsonl"
        self.endpoint_log = workdir / "endpoint.jsonl"
        self.proxy_port = free_port()
        self.http_port = free_port()
        self.token_file = workdir / "token"
        # Pre-shared so the stand-in bridge and the stand-in proxy agree. The
        # real host generates its own and tells nobody but the extension.
        self.token = secrets.token_urlsafe(32)
        self.token_file.write_text(self.token, encoding="utf-8")
        self.cdp_port = free_port()
        self.endpoint_proc: subprocess.Popen | None = None
        # THE REAL COMPILED HOST rather than dev_bridge.py.
        self.real_host: Path | None = None
        self.real_marker_port = 0
        self.real_marker: socketserver.TCPServer | None = None
        self.host_stderr = workdir / "realhost.stderr"
        self.inject_host = ""
        self.pregranted = False
        self.browser_proc: subprocess.Popen | None = None
        self.ext_id = ""
        self.sw: cdp.Target | None = None
        self.page: cdp.Target | None = None
        self.ctl: cdp.Target | None = None
        self.result = Result()

    # -- scaffolding ---------------------------------------------------------

    def set_tunnel_state(self, status: str, *, proxy_ready: bool | None = None,
                         port: int | None = None, winn: str = "unavailable_on_this_platform") -> None:
        """Write the bridge status snapshot, in the contract's own shape."""
        ready = (status == "connected") if proxy_ready is None else proxy_ready
        payload = {
            "status": status,
            "detail": "none" if status == "connected" else "app_not_running",
            "winn": winn,
            "selectedSlug": "",
            "nodes": [],
            "canRequestConnect": status != "app_not_running",
            # In --real-host mode the host overlays the proxy facts from its
            # own bound sockets (`BridgeHost._snapshot` -> `copyWithProxy`), so
            # a number here would be discarded. `proxyReady` is the one proxy
            # fact the state source owns.
            "proxyPort": 0 if self.real_host else (self.proxy_port if port is None else port),
            "proxyReady": ready,
            "rxKib": 0,
            "txKib": 0,
        }
        self.state_file.write_text(json.dumps(payload), encoding="utf-8")

    def start_real_marker(self) -> None:
        """The site the real host's proxy actually connects to."""
        if self.real_marker is not None:
            return
        certdir = self.work / "certs"
        certdir.mkdir(parents=True, exist_ok=True)
        key, crt = dev_endpoint.make_cert(certdir)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(crt), keyfile=str(key))
        self.real_marker = dev_endpoint.TlsServer(
            ("127.0.0.1", self.real_marker_port), AttributedMarkerHandler, ctx)
        threading.Thread(target=self.real_marker.serve_forever, daemon=True).start()

    def stop_real_marker(self) -> None:
        if self.real_marker is None:
            return
        try:
            self.real_marker.shutdown()
            self.real_marker.server_close()
        except Exception:  # noqa: BLE001
            pass
        self.real_marker = None

    def real_host_listeners(self) -> list[int]:
        """The ports the real host process is listening on, read from the OS."""
        try:
            pids = subprocess.run(["pgrep", "-f", "wins_bridge_host"],
                                  capture_output=True, text=True, timeout=6).stdout.split()
        except (OSError, subprocess.SubprocessError):
            return []
        ports: list[int] = []
        for pid in pids:
            try:
                out = subprocess.run(
                    ["lsof", "-nP", "-a", "-p", pid, "-iTCP", "-sTCP:LISTEN", "-Fn"],
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
        # In --real-host mode the proxy belongs to a process the browser owns,
        # so what is removed is everything BEHIND it: the CONNECT then fails
        # upstream while the extension still believes it is protected.
        self.stop_real_marker()
        if self.endpoint_proc and self.endpoint_proc.poll() is None:
            self.endpoint_proc.send_signal(signal.SIGKILL)
            self.endpoint_proc.wait(timeout=5)
        # Wait for the port to actually stop accepting, so "unreachable proxy"
        # means unreachable rather than "probably unreachable by now".
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=0.3):
                    time.sleep(0.1)
            except OSError:
                return
        raise RuntimeError("the proxy port is still accepting connections")

    def install_native_host(self) -> None:
        """Write the host manifest inside the throwaway profile.

        VERIFIED, not assumed: Chromium on macOS looks for user-level native
        messaging manifests under <user-data-dir>/NativeMessagingHosts, so a
        --user-data-dir run needs nothing written into the real Chrome or Edge
        support directory. That matters for a verification run on someone's own
        machine: the whole test is contained in a scratch directory.
        """
        hosts = self.profile / "NativeMessagingHosts"
        hosts.mkdir(parents=True, exist_ok=True)
        wrapper = self.work / "bridge_wrapper.sh"
        if self.real_host:
            # The REAL compiled host, launched by the browser over stdio. No
            # environment variables: the real host takes arguments, and it takes
            # them from the manifest. No TLS material either -- the Chromium
            # decision leaves these two on the plaintext listener, and this run
            # is that decision measured against the real thing.
            wrapper.write_text(
                "#!/bin/sh\n"
                f'exec "{self.real_host}" --state-file "{self.state_file}" '
                f'2>>"{self.host_stderr}"\n',
                encoding="utf-8",
            )
            wrapper.chmod(0o755)
            (hosts / "org.winsvpn.bridge.json").write_text(
                json.dumps({
                    "name": "org.winsvpn.bridge",
                    "description": "Win's VPN desktop bridge (verification harness)",
                    "path": str(wrapper),
                    "type": "stdio",
                    "allowed_origins": [f"chrome-extension://{self.ext_id}/"],
                }, indent=2),
                encoding="utf-8",
            )
            return
        wrapper.write_text(
            "#!/bin/sh\n"
            f'export WV_BRIDGE_STATE="{self.state_file}"\n'
            f'export WV_BRIDGE_LOG="{self.bridge_log}"\n'
            # Pre-shared so the stand-in bridge and the stand-in proxy agree on
            # one token. The real host generates its own and tells nobody but
            # the extension. Omitting this export is what produced a run in
            # which the extension answered 32 challenges and the proxy rejected
            # all 32 -- indistinguishable from a broken auth path until the
            # extension's own counters showed it was answering.
            f'export WV_BRIDGE_TOKEN="{self.token_file}"\n'
            f'export WV_BRIDGE_INJECT_HOST="{self.inject_host}"\n'
            # An absolute interpreter path, because the native host is launched
            # by the browser with an environment that is not the shell's. The
            # first attempt at this used /usr/bin/python3, which on macOS is a
            # developer-tools shim that exits immediately, and the only symptom
            # was "Native host has exited".
            f'exec "{sys.executable}" "{HERE / "dev_bridge.py"}"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        (hosts / "org.winsvpn.bridge.json").write_text(
            json.dumps({
                "name": "org.winsvpn.bridge",
                "description": "Win's VPN desktop bridge (verification harness)",
                "path": str(wrapper),
                "type": "stdio",
                "allowed_origins": [f"chrome-extension://{self.ext_id}/"],
            }, indent=2),
            encoding="utf-8",
        )

    def launch_browser(self) -> None:
        binary = BROWSERS[self.browser]
        if not Path(binary).exists():
            raise RuntimeError(f"{self.browser} is not installed at {binary}")
        self.profile.mkdir(parents=True, exist_ok=True)
        self.browser_proc = subprocess.Popen(
            [binary,
             f"--user-data-dir={self.profile}",
             # Chrome 137 and later ignore --load-extension. The supported route
             # for automation is the CDP Extensions domain, which this switch
             # enables. Discovered by watching --load-extension silently do
             # nothing: the browser started, the extension was absent, and there
             # was no error anywhere.
             "--enable-unsafe-extension-debugging",
             f"--remote-debugging-port={self.cdp_port}",
             "--no-first-run", "--no-default-browser-check",
             "--disable-background-networking", "--disable-component-update",
             "--disable-sync",
             # The marker server presents a self-signed certificate for a
             # .invalid name. Nothing under test depends on certificate
             # validation; routing, blocking and name handling are all decided
             # before TLS starts.
             "--ignore-certificate-errors",
             "--headless=new", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        cdp.wait_for_endpoint(self.cdp_port, timeout=45)

    def load_extension(self) -> None:
        info = cdp.wait_for_endpoint(self.cdp_port)
        browser_target = cdp.Target(info["webSocketDebuggerUrl"])
        try:
            got = browser_target.call("Extensions.loadUnpacked", {"path": str(self.package)})
            self.ext_id = got["id"]
        finally:
            browser_target.close()

    def attach(self) -> None:
        deadline = time.time() + 25
        while time.time() < deadline:
            for t in cdp.list_targets(self.cdp_port):
                if t["type"] == "service_worker" and self.ext_id in t["url"]:
                    self.sw = cdp.Target(t["webSocketDebuggerUrl"])
                    self.sw.call("Runtime.enable")
                    return
            time.sleep(0.4)
        raise RuntimeError("the extension's service worker never appeared")

    def attach_page(self) -> None:
        """Two page targets, for two different jobs.

        `page` is an ordinary tab used to make navigations and watch them fail
        or succeed. `ctl` is the extension's own options page, used to send
        runtime messages to the service worker -- the same path the popup uses.
        A service worker cannot sendMessage to itself (there is no other
        receiving end), so control has to come from an extension page, and
        using the real one means the messaging path is exercised rather than
        bypassed.
        """
        for t in cdp.list_targets(self.cdp_port):
            if t["type"] == "page" and t["url"].startswith(("about:", "chrome://newtab")):
                self.page = cdp.Target(t["webSocketDebuggerUrl"])
                break
        if self.page is None:
            raise RuntimeError("no plain page target to drive")
        self.page.call("Page.enable")
        self.page.call("Network.enable")
        self.page.call("Runtime.enable")

        info = cdp.wait_for_endpoint(self.cdp_port)
        browser_target = cdp.Target(info["webSocketDebuggerUrl"])
        ctl_url = f"chrome-extension://{self.ext_id}/src/ui/options.html"
        try:
            browser_target.call("Target.createTarget", {"url": ctl_url})
        finally:
            browser_target.close()

        deadline = time.time() + 20
        while time.time() < deadline:
            for t in cdp.list_targets(self.cdp_port):
                if t["type"] == "page" and self.ext_id in t["url"]:
                    self.ctl = cdp.Target(t["webSocketDebuggerUrl"])
                    self.ctl.call("Runtime.enable")
                    if self.ctl.evaluate("typeof chrome !== 'undefined' && !!chrome.runtime"):
                        return
            time.sleep(0.4)
        raise RuntimeError("the extension's options page never became drivable")

    # -- driving the extension ----------------------------------------------

    def sw_eval(self, expression: str, timeout: float = 25.0):
        """Evaluate in the extension's service worker, waking it if necessary."""
        for attempt in range(3):
            try:
                if self.sw is None:
                    self.attach()
                return self.sw.evaluate(expression, timeout=timeout)
            except (ConnectionError, TimeoutError, RuntimeError):
                if attempt == 2:
                    raise
                try:
                    if self.sw:
                        self.sw.close()
                except Exception:  # noqa: BLE001
                    pass
                self.sw = None
                time.sleep(1.0)
        return None

    def ctl_eval(self, expression: str, timeout: float = 25.0):
        return self.ctl.evaluate(expression, timeout=timeout)

    def apply_settings(self, **kwargs) -> dict:
        payload = json.dumps(kwargs)
        return json.loads(self.ctl_eval(
            f"(async()=>{{const s=await chrome.runtime.sendMessage({{type:'getState'}});"
            f"const next=Object.assign({{}}, s.settings, {payload});"
            f"return JSON.stringify(await chrome.runtime.sendMessage({{type:'setSettings',settings:next}}));}})()"
        ))

    def state(self) -> dict:
        return json.loads(self.ctl_eval(
            "(async()=>JSON.stringify(await chrome.runtime.sendMessage({type:'getState'})))()"
        ))

    def wait_for_state(self, wanted: str, timeout: float = 25.0) -> dict:
        deadline = time.time() + timeout
        last = {}
        while time.time() < deadline:
            last = self.state()
            if last.get("state") == wanted:
                return last
            time.sleep(0.7)
        return last

    def navigate(self, url: str, settle: float = 4.0) -> dict:
        """Navigate and report what the network stack actually did."""
        self.page.clear_events()
        try:
            self.page.call("Page.navigate", {"url": url}, timeout=20)
        except RuntimeError:
            pass
        self.page.pump(settle)
        failures = [f for f in self.page.take_events("Network.loadingFailed")]
        text = ""
        try:
            text = self.page.evaluate("document.body ? document.body.innerText.slice(0,200) : ''") or ""
        except Exception:  # noqa: BLE001
            text = "<page unreadable>"
        return {
            "loaded_marker": MARKER in text,
            "text": text.replace("\n", " ")[:160],
            "errors": sorted({f.get("errorText", "") for f in failures if f.get("errorText")}),
            "location": self._location(),
        }

    def _location(self) -> str:
        try:
            return self.page.evaluate("location.href") or ""
        except Exception:  # noqa: BLE001
            return "<unreadable>"

    def endpoint_events(self, since: float, kinds=("connect",)) -> list[dict]:
        out = []
        if self.real_host:
            # The real proxy logs nothing -- it never records a destination --
            # so what is read here is the far end of the hop: every connection
            # the fake internet accepted, attributed to the process that opened
            # it. A browser-opened one is a leak and is NOT a CONNECT.
            out += [e for e in _UPSTREAM
                    if e.get("kind") in kinds and e.get("t", 0) >= since]
        if not self.endpoint_log.exists():
            return out
        for line in self.endpoint_log.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("kind") in kinds and event.get("t", 0) >= since:
                out.append(event)
        return out

    # -- teardown ------------------------------------------------------------

    def shutdown(self) -> None:
        for target in (self.ctl, self.page, self.sw):
            try:
                if target:
                    target.close()
            except Exception:  # noqa: BLE001
                pass
        if self.browser_proc and self.browser_proc.poll() is None:
            self.browser_proc.terminate()
            try:
                self.browser_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.browser_proc.kill()
        if self.endpoint_proc and self.endpoint_proc.poll() is None:
            self.endpoint_proc.kill()
        if not self.keep and self.work.exists():
            shutil.rmtree(self.work, ignore_errors=True)


# ---------------------------------------------------------------------------
# the checks
# ---------------------------------------------------------------------------

def resource_types_in(package: Path) -> list[str]:
    """The block layer's wanted resourceTypes, read out of the packaged source."""
    text = (package / "src" / "core" / "constants.js").read_text(encoding="utf-8")
    m = re.search(r"DNR_RESOURCE_TYPES\s*=\s*\[(.*?)\]", text, re.S)
    return re.findall(r"[\"']([a-z_]+)[\"']", m.group(1)) if m else []


def grant_click_is_where_the_gesture_is(h: Harness, r: Result) -> None:
    """Is Chromium subject to the same user-gesture rule the Firefox run found?

    §5.2 of the Chrome/Edge handoff recorded the grant click as UNVERIFIED,
    because Chromium's permission bubble is native UI a headless browser cannot
    present. The Firefox run then showed that the click never got as far as the
    bubble: the options page messaged the background, the background called
    `permissions.request()`, and a runtime message handler is not a user input
    handler. That indirection was in this browser's code too, so the question
    stops being "can the bubble be accepted" -- which is still unanswerable here
    -- and becomes "does the call reach the point of asking at all", which is
    answerable and is what actually broke.

    The old path is reproduced exactly rather than approximated: a temporary
    message listener is registered in the service worker over CDP, the options
    page sends it a message from a real gesture, and the listener calls
    `permissions.request()` -- which is what the shipped code did until today.
    Nothing awaits the call, because a `permissions.request()` that gets as far as
    asking puts up native UI a headless browser cannot present and never settles.
    That distinction is the measurement: a call that never settles reached the
    point of asking, and a call that rejects never did.
    """
    def fire(target, setup: str, gesture: bool = True) -> None:
        target.call("Runtime.evaluate", {
            "expression": setup, "awaitPromise": False,
            "returnByValue": True, "userGesture": gesture,
        }, timeout=25)

    def poll(target, expression: str, seconds: float = 8.0) -> str:
        deadline = time.time() + seconds
        seen = "pending"
        while time.time() < deadline:
            got = target.call("Runtime.evaluate", {
                "expression": expression, "awaitPromise": False, "returnByValue": True,
            }, timeout=20)
            seen = str(got.get("result", {}).get("value"))
            if seen != "pending":
                return seen
            time.sleep(0.5)
        return seen

    # 1. THE OLD PATH, rebuilt in the worker: a runtime message handler calling
    #    permissions.request(). This is what options.js used to do.
    # `__wvOldRan` disambiguates the two ways `__wvOld` can stay 'pending': the
    # handler never ran, or it ran and the call never settled. Without it a
    # message that simply was not delivered reads exactly like a call that
    # reached the point of asking, and this probe would be reporting nothing.
    fire(h.sw,
         "globalThis.__wvOld = 'pending'; globalThis.__wvOldRan = 'no';"
         "chrome.runtime.onMessage.addListener((m, s, respond) => {"
         "  if (!m || m.type !== '__wvOldGrantPath') return false;"
         "  globalThis.__wvOldRan = 'yes';"
         "  try { chrome.permissions.request({origins:['<all_urls>']})"
         "    .then(v => { globalThis.__wvOld = 'resolved:' + v; })"
         "    .catch(e => { globalThis.__wvOld = 'rejected:' + e.message; }); }"
         "  catch (e) { globalThis.__wvOld = 'threw:' + e.message; }"
         "  respond({ok: true}); return false;"
         "});")
    fire(h.ctl, "chrome.runtime.sendMessage({type:'__wvOldGrantPath'}); true")
    ran = poll(h.sw, "globalThis.__wvOldRan === 'yes' ? 'yes' : 'pending'", seconds=8.0)
    old = poll(h.sw, "String(globalThis.__wvOld)", seconds=8.0)

    # What "correct" looks like here is not obvious and is worth stating. If
    # Chromium rejects the call, this browser has the Firefox defect and removing
    # the indirection fixed it here too. If Chromium ACCEPTS it, then §5.2's
    # "unverified" was unverified for the reason it said -- the bubble -- and the
    # indirection was not the blocker on this browser. Either answer is reported;
    # the check fails only if the probe could not tell them apart.
    conclusive = ran == "yes"
    verdict = ("Chromium REJECTS it, exactly as Firefox does"
               if old.startswith(("rejected:", "threw:"))
               else "Chromium ACCEPTS it and puts up the bubble, which a headless browser "
                    "cannot present -- so this browser did NOT have the Firefox defect")
    r.add(
        "CHROMIUM, DEFECT 3: what this browser does when a message handler calls "
        "permissions.request()",
        conclusive,
        f"the service worker's message handler ran (ran={ran!r}) and Chromium answered "
        f"{old[:150]!r}. {verdict}. §5.2 of the Chrome/Edge handoff recorded the grant click as "
        "unverified because the permission bubble is native UI; the indirection was removed "
        "from both adapters regardless, because on Firefox it was measured to be the blocker "
        "and a call that needs a gesture belongs where the gesture is.",
        "a probe that reached the handler, so its answer means something",
    )

    # The shipped path, driven the way a user drives it. Chromium's bubble is
    # native UI with no automation surface, so a granted permission is not
    # obtainable here and is not claimed; what IS obtainable is proof that the
    # click reaches `permissions.request()` at all, which is exactly what the
    # old indirection prevented.
    outcome, box = "the button was not found", None
    try:
        fire(h.ctl,
             "window.__wvGrantSeen = 'pending';"
             "const orig = chrome.permissions.request.bind(chrome.permissions);"
             "chrome.permissions.request = (p) => { window.__wvGrantSeen = JSON.stringify(p);"
             "  return orig(p); };"
             "true")
        got = h.ctl.call("Runtime.evaluate", {
            # scrollIntoView first. The grant card sits well down a long options
            # page, so its bounding box can be below the viewport -- and a click
            # dispatched at those coordinates lands on whatever is actually there,
            # which is how a probe reports "the button did nothing" about a button
            # it never hit.
            "expression": "(()=>{const b=document.getElementById('grantHost');"
                          "if(!b || b.offsetParent === null) return '';"
                          "b.scrollIntoView({block:'center'});"
                          "const r=b.getBoundingClientRect();"
                          "return JSON.stringify({x:r.x+r.width/2, y:r.y+r.height/2,"
                          "  w:r.width, h:r.height});})()",
            "awaitPromise": False, "returnByValue": True,
        }, timeout=20)
        box = got.get("result", {}).get("value")
        if box:
            at = json.loads(box)
            for kind in ("mousePressed", "mouseReleased"):
                h.ctl.call("Input.dispatchMouseEvent", {
                    "type": kind, "x": at["x"], "y": at["y"],
                    "button": "left", "clickCount": 1,
                }, timeout=20)
            outcome = poll(h.ctl, "String(window.__wvGrantSeen)", seconds=8.0)
    except (RuntimeError, ConnectionError, TimeoutError, json.JSONDecodeError) as e:
        outcome = f"the click could not be driven: {type(e).__name__}: {e}"

    r.add(
        "and the shipped button now reaches permissions.request() from the click itself",
        isinstance(outcome, str) and "<all_urls>" in outcome,
        f"a trusted click on #grantHost (box {box}) was dispatched and permissions.request() "
        f"was called with {str(outcome)[:120]!r}. Chromium's permission bubble is native UI with no "
        "automation surface, so whether the USER would then have granted it is still not "
        "answerable here and is not claimed. What the old path could not do was get this far.",
        "permissions.request called with <all_urls> from the page",
    )


def run(h: Harness) -> Result:
    r = h.result

    # --- 1. it loads, and it stores nothing --------------------------------
    name = h.sw_eval("chrome.runtime.getManifest().name")
    perms = h.sw_eval("JSON.stringify(chrome.runtime.getManifest().permissions)")
    r.add("extension loads and its service worker runs", bool(name), f"name={name!r} permissions={perms}")

    war = h.sw_eval("JSON.stringify(chrome.runtime.getManifest().web_accessible_resources || null)")
    hostperms = h.sw_eval("JSON.stringify(chrome.runtime.getManifest().host_permissions || null)")
    expected_hosts = '["<all_urls>"]' if h.pregranted else "null"
    r.add(
        "no web_accessible_resources, and host permissions exactly as the package declares",
        war == "null" and hostperms == expected_hosts,
        f"web_accessible_resources={war} host_permissions={hostperms}"
        + (" (the pre-granted variant declares <all_urls>; the shipped package asks for it on a click)"
           if h.pregranted else " (the shipped package declares none)"),
        f"web_accessible_resources null, host_permissions {expected_hosts}",
    )

    stored = h.sw_eval("(async()=>JSON.stringify(await chrome.storage.local.get(null)))()")
    r.add("an untouched profile stores nothing", stored == "{}",
          f"chrome.storage.local = {stored}", "{}")

    # --- 2. armed while the desktop app is not running ---------------------
    h.set_tunnel_state("app_not_running")
    ice_idle = gather_ice(h)
    r.add(
        "CONTROL: idle ICE capture detects a host candidate",
        has_host_ice_candidate(ice_idle),
        f"{len(ice_idle)} candidate(s): {ice_idle[:3]}",
        "at least one host candidate",
    )
    h.apply_settings(armed=True)
    s = h.wait_for_state("app_not_running")
    r.add(
        "armed with the desktop app absent reports app_not_running, distinctly",
        s.get("state") == "app_not_running",
        f"state={s.get('state')!r} tunnelStatus={s.get('tunnelStatus')!r}",
        "app_not_running",
    )

    rules = json.loads(h.sw_eval("(async()=>JSON.stringify(await chrome.declarativeNetRequest.getDynamicRules()))()"))
    blocks = [x for x in rules if x["action"]["type"] == "block"]
    r.add("a block rule is installed while the app is absent", len(blocks) >= 1,
          f"{len(rules)} dynamic rules, {len(blocks)} block", "at least one block rule")

    # The Firefox run made this worth asking on Chromium too. Firefox 153 rejects
    # two of the fifteen resource types and discards the whole rule set for it,
    # so the adapter now intersects the wanted list with what the running browser
    # accepts. The narrow fix would have been to delete the two values from the
    # shared list, which would have cost Chromium two types it can genuinely
    # emit. This is the check that says whether that cost was avoided.
    wanted = resource_types_in(h.package)
    installed = sorted({t for x in rules for t in x.get("condition", {}).get("resourceTypes", [])})
    dropped = (s.get("blockLayer") or {}).get("dropped")
    r.add(
        "and Chromium keeps every resource type the block layer asks for",
        sorted(set(wanted)) == installed and not dropped,
        f"the shared list asks for {len(wanted)} types; the rules Chromium accepted carry "
        f"{len(installed)}, and the extension reports it dropped {dropped}. Firefox rejects "
        "webtransport and webbundle; both are legal here and both are still covered, because "
        "the list is narrowed per browser at runtime rather than trimmed in the shared source.",
        f"all {len(wanted)} types, nothing dropped",
    )

    nav = h.navigate(url_for(ROUTED_HOST))
    r.add(
        "THE CENTRAL PROPERTY: with the app absent, an in-scope request is blocked, not sent directly",
        (not nav["loaded_marker"]) and any("BLOCKED" in e.upper() for e in nav["errors"]),
        f"errors={nav['errors']} marker_loaded={nav['loaded_marker']} body={nav['text']!r}",
        "a blocking error, and no page",
    )

    # --- 3. connected but the desktop proxy gate is shut -------------------
    # Two independent facts must agree before anything is routed. This is the
    # case where the tunnel is up and the bridge still says no.
    h.set_tunnel_state("connected", proxy_ready=False)
    s = h.wait_for_state("not_ready")
    r.add(
        "a connected tunnel with the desktop proxy gate shut does not route",
        s.get("state") in ("not_ready", "no_credential"),
        f"state={s.get('state')!r} proxyReady={s.get('proxyReady')} hasCredential={s.get('hasCredential')}",
        "not_ready",
    )

    # --- 4. connected and ready --------------------------------------------
    h.set_tunnel_state("connected")

    if not h.pregranted:
        # THE UNGRANTED PATH, which is what a freshly installed extension is in
        # until the user grants host access from the options page. Chromium will
        # not deliver the proxy challenge without it, so the extension cannot
        # authenticate -- and the thing that matters is that it says so and
        # blocks, rather than installing routing that could never work.
        s = h.wait_for_state("no_auth_capability", timeout=30)
        r.add(
            "without the granted host permission the extension refuses to route, and says why",
            s.get("state") == "no_auth_capability" and s.get("canAuthenticate") is False,
            f"state={s.get('state')!r} canAuthenticate={s.get('canAuthenticate')} "
            f"hasCredential={s.get('hasCredential')}",
            "no_auth_capability",
        )
        nav = h.navigate(url_for(ROUTED_HOST), settle=5.0)
        r.add(
            "and in-scope traffic is blocked rather than sent unauthenticated",
            (not nav["loaded_marker"]) and any("BLOCKED" in e.upper() for e in nav["errors"]),
            f"errors={nav['errors']} marker_loaded={nav['loaded_marker']}",
            "a blocking error, and no page",
        )
        after = json.loads(h.sw_eval(
            "(async()=>{const g=await chrome.proxy.settings.get({});"
            "return JSON.stringify({mode:g.value.mode});})()"
        ))
        r.add(
            "and no proxy setting is installed that could never have worked",
            after["mode"] in ("system", "direct"),
            f"proxy mode={after['mode']!r}",
            "system or direct",
        )
        try:
            grant_click_is_where_the_gesture_is(h, r)
        except Exception as e:  # noqa: BLE001
            r.add("CHROMIUM, DEFECT 3: the old path -- a message handler calling "
                  "permissions.request() -- cannot grant here either",
                  False, f"the probe could not be completed: {type(e).__name__}: {str(e)[:200]}",
                  "a completed probe")
        h.apply_settings(armed=False)
        h.wait_for_state("off")
        r.add(
            "turning routing off restores the browser",
            json.loads(h.sw_eval(
                "(async()=>{const g=await chrome.proxy.settings.get({});"
                "const r=await chrome.declarativeNetRequest.getDynamicRules();"
                "return JSON.stringify({mode:g.value.mode, rules:r.length});})()"
            ))["rules"] == 0,
            "zero dynamic rules remain",
            "zero",
        )
        return r

    s = h.wait_for_state("protected", timeout=30)
    r.add(
        "with the tunnel up and the gate open, the extension routes",
        s.get("state") == "protected",
        f"state={s.get('state')!r} endpoint={s.get('endpoint')} hasCredential={s.get('hasCredential')} "
        f"canAuthenticate={s.get('canAuthenticate')}",
        "protected",
    )
    r.add(
        "the endpoint the extension will use is a port and nothing else",
        s.get("endpoint") is not None and set(s.get("endpoint") or {}) == {"port"},
        f"endpoint object = {s.get('endpoint')}",
        "an object with exactly one key, port",
    )

    pac = json.loads(h.sw_eval(
        "(async()=>{const g=await chrome.proxy.settings.get({});const v=g.value;"
        "return JSON.stringify({mode:v.mode, mandatory:!!(v.pacScript&&v.pacScript.mandatory),"
        "pac:(v.pacScript&&v.pacScript.data)||'', loc:g.levelOfControl});})()"
    ))
    r.add(
        "the proxy setting is a mandatory PAC owned by this extension",
        pac["mode"] == "pac_script" and pac["mandatory"] and pac["loc"] == "controlled_by_this_extension",
        f"mode={pac['mode']!r} mandatory={pac['mandatory']} levelOfControl={pac['loc']!r}",
        "pac_script, mandatory, controlled_by_this_extension",
    )
    body = pac["pac"]
    r.add(
        "the PAC has no DIRECT fallback for in-scope hosts",
        "; DIRECT" not in body,
        f"PAC is {len(body)} chars; occurrences of '; DIRECT' = {body.count('; DIRECT')}",
        "zero",
    )
    r.add(
        "the PAC performs no name resolution",
        not any(fn in body for fn in ("dnsResolve", "isInNet", "isResolvable", "myIpAddress")),
        "no dnsResolve / isInNet / isResolvable / myIpAddress in the PAC body",
        "none of those helpers",
    )
    r.add(
        "the PAC names loopback and no other address",
        "127.0.0.1" in body and not re.search(r"(?<![\d.])(?!127\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", body),
        "the only dotted quad in the generated PAC is 127.0.0.1",
        "one address, loopback",
    )

    mark = time.time()
    nav = h.navigate(url_for(ROUTED_HOST), settle=6.0)
    connects = h.endpoint_events(mark)
    challenges = h.endpoint_events(mark, kinds=("proxy_407",))
    r.add(
        "an in-scope request reaches the local proxy and the page loads",
        nav["loaded_marker"] and len(connects) >= 1,
        f"marker_loaded={nav['loaded_marker']} errors={nav['errors']} "
        f"connects={[c['target'] for c in connects]}",
        "the marker page, via at least one authenticated CONNECT",
    )
    stats = h.state().get("authStats") or {}
    if h.real_host:
        # THE REAL PROXY LOGS NOTHING -- it never records a destination -- so the
        # 407 is not observable at the proxy. Two independent things stand in
        # for it, and neither is the extension's own opinion of itself:
        #   * a byte reached the fake internet over a socket the BRIDGE opened,
        #     and `_handle` relays only after `_isAuthenticated` has passed and
        #     the gate has admitted, so the relay is the authentication;
        #   * the extension's own counters, reported beside it, agree.
        # An extension that answered wrongly would leave Chromium re-challenged
        # and the page would carry a proxy-auth error instead of a marker.
        r.add(
            "the extension answered the proxy's authentication challenge",
            any(c.get("authenticated") for c in connects) and stats.get("answered", 0) >= 1,
            f"{len(connects)} relayed CONNECT(s) through the REAL host, opened by "
            f"{sorted({c.get('peer') for c in connects})}; extension auth counters {stats}. "
            "The real proxy checks Proxy-Authorization BEFORE the tunnel gate and relays "
            "nothing until both pass, so a byte arriving at the far end IS the "
            "authentication -- there is no separate log line to read, and none is needed.",
            "at least one relayed CONNECT and at least one answered challenge",
        )
        # THE DNS OBSERVATION, by error code rather than by proxy log. The name
        # cannot resolve anywhere, so a browser that resolved it itself reports
        # ERR_NAME_NOT_RESOLVED; one that handed it to the proxy gets the real
        # host's own failed lookup back as ERR_TUNNEL_CONNECTION_FAILED.
        nav_name = h.navigate(url_for(REAL_HOST_NAME), settle=6.0)
        errs = " ".join(nav_name["errors"])
        r.add(
            "DNS for routed sites is handed to the desktop app, not done on this machine",
            "TUNNEL_CONNECTION_FAILED" in errs and "NAME_NOT_RESOLVED" not in errs,
            f"navigating {REAL_HOST_NAME} produced {nav_name['errors']}. "
            "ERR_NAME_NOT_RESOLVED would mean this browser resolved the name itself; "
            "ERR_TUNNEL_CONNECTION_FAILED means it handed the name to the proxy and the "
            "proxy is the one that could not resolve it -- which is the desktop side "
            "doing the lookup, measured rather than inferred from a log line the real "
            "host deliberately does not write.",
            "ERR_TUNNEL_CONNECTION_FAILED and no name-resolution error",
        )
    else:
        r.add(
            "the extension answered the proxy's authentication challenge",
            len(challenges) >= 1 and any(c.get("authenticated") for c in connects),
            f"{len(challenges)} 407 challenge(s), then {len(connects)} authenticated CONNECT(s); "
            f"extension auth counters {stats}. "
            "The browser always tries once without credentials, so a 407 followed by a "
            "successful CONNECT is the signature of onAuthRequired working.",
            "at least one 407 followed by an authenticated CONNECT",
        )

        # THE DNS OBSERVATION. A CONNECT line carries a name. Seeing the name arrive
        # at the proxy proves the browser did not resolve it here.
        r.add(
            "DNS for routed sites is handed to the desktop app, not done on this machine",
            any(c["target"] == ROUTED_HOST for c in connects),
            f"CONNECT targets received: {[c['target'] for c in connects]}",
            f"a CONNECT naming {ROUTED_HOST}",
        )

    # --- 5. WebRTC and speculative lookups ---------------------------------
    webrtc = json.loads(h.sw_eval(
        "(async()=>JSON.stringify(await chrome.privacy.network.webRTCIPHandlingPolicy.get({})))()"
    ))
    r.add(
        "WebRTC is pinned to disable_non_proxied_udp by this extension",
        webrtc.get("value") == "disable_non_proxied_udp"
        and webrtc.get("levelOfControl") == "controlled_by_this_extension",
        f"value={webrtc.get('value')!r} levelOfControl={webrtc.get('levelOfControl')!r}",
        "disable_non_proxied_udp / controlled_by_this_extension",
    )
    prediction = json.loads(h.sw_eval(
        "(async()=>JSON.stringify(await chrome.privacy.network.networkPredictionEnabled.get({})))()"
    ))
    r.add(
        "speculative name lookups and connections are turned off",
        prediction.get("value") is False,
        f"networkPredictionEnabled={prediction.get('value')} levelOfControl={prediction.get('levelOfControl')!r}",
        "false",
    )

    ice_armed = gather_ice(h)
    r.add(
        "no ICE candidate exposes a host address while routing",
        has_host_ice_candidate(ice_idle)
        and not has_host_ice_candidate(ice_armed),
        f"{len(ice_armed)} candidate(s) while armed: {ice_armed[:3]}. "
        f"The idle control captured {len(ice_idle)} valid candidate(s).",
        "no 'typ host' candidates",
    )

    # --- 6. per-site rules -------------------------------------------------
    if h.real_host:
        # Two NAMES here rather than the address form used for the data path:
        # `rules.js` refuses a numeric rule outright ("Addresses are not
        # supported here. Use the website name."), which is itself the property
        # being relied on -- a rule written as an address would be an address
        # written into the browser profile. Both names are unresolvable, and the
        # two error codes are the discriminator: the listed one reaches the real
        # proxy and comes back with the proxy's own failed lookup; the unlisted
        # one is resolved by the browser, which cannot resolve it either.
        h.apply_settings(mode="listed", listed=[REAL_HOST_NAME], excluded=[])
        h.wait_for_state("protected")
        nav_in = h.navigate(url_for(REAL_HOST_NAME), settle=5.0)
        nav_out = h.navigate(url_for(OTHER_HOST), settle=5.0)
        in_errs, out_errs = " ".join(nav_in["errors"]), " ".join(nav_out["errors"])
        r.add(
            "in listed mode a listed site is routed and an unlisted one is not",
            "TUNNEL_CONNECTION_FAILED" in in_errs and "NAME_NOT_RESOLVED" in out_errs
            and not nav_out["loaded_marker"],
            f"the listed name produced {nav_in['errors']} -- the proxy's own failed lookup, "
            f"so it was routed; the unlisted name produced {nav_out['errors']} -- this "
            "browser's failed lookup, so it was not. Neither name resolves anywhere, which "
            "is what makes the two error codes tell them apart.",
            "a tunnel error for the listed name and a name-resolution error for the unlisted one",
        )
    else:
        h.apply_settings(mode="listed", listed=[ROUTED_HOST], excluded=[])
        h.wait_for_state("protected")
        mark = time.time()
        nav_in = h.navigate(url_for(ROUTED_HOST), settle=5.0)
        nav_out = h.navigate(url_for(OTHER_HOST), settle=5.0)
        targets = [c["target"] for c in h.endpoint_events(mark)]
        r.add(
            "in listed mode a listed site is routed and an unlisted one is not",
            nav_in["loaded_marker"] and (not nav_out["loaded_marker"])
            and ROUTED_HOST in targets and OTHER_HOST not in targets,
            f"listed loaded={nav_in['loaded_marker']}; unlisted loaded={nav_out['loaded_marker']} "
            f"errors={nav_out['errors']}; proxy saw {targets}",
            "the listed site through the proxy, the unlisted one never reaching it",
        )

    # --- 7. THE FAIL-CLOSED PROOF ------------------------------------------
    # The desktop app still claims to be connected and ready. The proxy is gone.
    # This is the exact situation in which a browser that falls back to a direct
    # connection betrays the user, and the only way to know which one this is is
    # to do it.
    h.apply_settings(mode="all", listed=[], excluded=[])
    h.wait_for_state("protected")
    h.stop_endpoint()
    nav = h.navigate(url_for(ROUTED_HOST), settle=8.0)
    r.add(
        "THE FAIL-CLOSED PROOF: with the proxy unreachable, the request fails and does not go direct",
        (not nav["loaded_marker"]) and any(
            "PROXY" in e.upper() or "BLOCKED" in e.upper() or "TUNNEL" in e.upper() for e in nav["errors"]
        ),
        f"errors={nav['errors']} marker_loaded={nav['loaded_marker']} body={nav['text']!r}",
        "a proxy-connection error, and no page content",
    )

    # --- 8. a hostile bridge cannot move the endpoint ----------------------
    # The contract has no host field, so the bridge cannot legitimately name an
    # address. This checks what happens when one tries anyway: a credential
    # reply carrying an extra `host` naming a routable address. The extension
    # must ignore it and keep using loopback. 198.51.100.7 is RFC 5737
    # documentation space -- routable in form, allocated to nobody.
    h.inject_host = "198.51.100.7"
    h.install_native_host()
    h.start_endpoint()
    h.set_tunnel_state("connected")
    h.apply_settings(armed=False)
    h.wait_for_state("off")
    h.apply_settings(armed=True)
    s = h.wait_for_state("protected", timeout=30)
    pac2 = h.sw_eval(
        "(async()=>{const g=await chrome.proxy.settings.get({});"
        "return (g.value.pacScript && g.value.pacScript.data) || '';})()"
    )
    r.add(
        "an injected host field in the credential reply is ignored",
        s.get("state") == "protected" and "198.51.100.7" not in (pac2 or ""),
        f"state={s.get('state')!r}; the injected address appears in the PAC: "
        f"{'198.51.100.7' in (pac2 or '')}; loopback appears: {'127.0.0.1' in (pac2 or '')}",
        "routing continues, to loopback, with the injected address nowhere",
    )

    # --- 9. an unreadable desktop state degrades downwards ------------------
    h.state_file.write_text("{ this is not json", encoding="utf-8")
    s = h.wait_for_state("app_not_running", timeout=30)
    # The extension's own `failClosed` rather than a hand-copied list of five
    # state names, which is what this was and which goes stale the first time
    # the vocabulary grows. See the same check in verify_firefox.py for the
    # reasoning; the second clause keeps an ENFORCEMENT failure from being
    # absorbed here, because that is a different and worse finding.
    enforcement_failures = ("not_enforcing", "routing_failed", "routing_unauthenticated")
    r.add(
        "an unreadable desktop state degrades to not-connected, not to connected",
        s.get("failClosed") is True and s.get("state") not in enforcement_failures,
        f"state={s.get('state')!r} failClosed={s.get('failClosed')!r}",
        "fail-closed, and not by way of an enforcement failure",
    )

    # --- 10. turning it off gives the browser back -------------------------
    h.apply_settings(armed=False)
    h.wait_for_state("off")
    after = json.loads(h.sw_eval(
        "(async()=>{const g=await chrome.proxy.settings.get({});"
        "const r=await chrome.declarativeNetRequest.getDynamicRules();"
        "return JSON.stringify({mode:g.value.mode, rules:r.length});})()"
    ))
    r.add(
        "turning routing off restores the browser",
        after["mode"] in ("system", "direct") and after["rules"] == 0,
        f"proxy mode={after['mode']!r}, {after['rules']} dynamic rules remain",
        "system/direct and zero rules",
    )

    return r


def has_host_ice_candidate(candidates: list[str]) -> bool:
    return any(" typ host " in f" {candidate} " for candidate in candidates)

def gather_ice(h: Harness) -> list:
    ice = h.page.evaluate("""(async()=>{
      try {
        const pc = new RTCPeerConnection({iceServers: []});
        pc.createDataChannel('x');
        const out = [];
        await pc.setLocalDescription(await pc.createOffer());
        await new Promise(res => {
          pc.onicecandidate = e => { if (e.candidate) out.push(e.candidate.candidate); else res(); };
          setTimeout(res, 2500);
        });
        pc.close();
        return JSON.stringify(out);
      } catch (e) { return JSON.stringify(['ERROR ' + e.message]); }
    })()""", timeout=20)
    return _validated_ice_candidates(ice)


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


def make_pregranted_variant(package: Path, dest: Path) -> Path:
    """Copy the package with optional_host_permissions promoted to host_permissions.

    Exactly one manifest key moves; no source file is touched. The diff is
    printed so a reader can see that this is the only difference between what
    was tested and what ships.
    """
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(package, dest)
    manifest_path = dest / "manifest.json"
    m = json.loads(manifest_path.read_text(encoding="utf-8"))
    optional = m.pop("optional_host_permissions", None)
    if not optional:
        raise RuntimeError("the package has no optional_host_permissions to promote")
    m["host_permissions"] = optional
    manifest_path.write_text(json.dumps(m, indent=2) + "\n", encoding="utf-8")
    print(f"  variant manifest: -optional_host_permissions {optional} "
          f"+host_permissions {optional}  (no other change)")
    return dest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--browser", choices=sorted(BROWSERS), default="chrome")
    ap.add_argument("--package", default=None)
    ap.add_argument("--workdir", default=None)
    ap.add_argument("--keep", action="store_true", help="leave the scratch profile behind")
    ap.add_argument(
        "--pregrant-host",
        action="store_true",
        help=(
            "run against a variant of the package whose optional <all_urls> permission is "
            "promoted to a granted one. Chromium only delivers webRequest.onAuthRequired for "
            "URLs the extension has host access to, and the shipped package asks for that "
            "access from a click in the options page -- a native bubble that a headless "
            "browser cannot present and no CDP method can accept. This flag exists so the "
            "authentication path can be exercised for real; the variant differs from the "
            "shipped package by exactly one manifest key and nothing else."
        ),
    )
    ap.add_argument(
        "--real-host", default="",
        help=(
            "run the REAL compiled bridge host as this browser's native-messaging "
            "host instead of dev_bridge.py. 'harness' compiles "
            "bin/wins_bridge_host_harness.dart -- the shipping host with a "
            "file-backed state source in place of UnobservedStateSource and nothing "
            "else changed. The routed hosts move to .localhost because the real "
            "proxy does real DNS, and every connection to the fake internet is "
            "attributed to the process that opened it."
        ),
    )
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args()

    root = HERE.parent
    package = Path(args.package) if args.package else root / "dist" / (
        "chrome" if args.browser in ("chrome", "edge") else args.browser
    )
    if args.browser == "edge" and not args.package:
        package = root / "dist" / "edge"
    if not package.exists():
        print(f"verify: no package at {package}; run build.py first", file=sys.stderr)
        return 2

    work = Path(args.workdir) if args.workdir else Path(
        os.environ.get("TMPDIR", "/tmp")) / f"wv-verify-{args.browser}-{os.getpid()}"
    work.mkdir(parents=True, exist_ok=True)

    variant_note = ""
    if args.pregrant_host:
        package = make_pregranted_variant(package, work / "pregranted")
        variant_note = " [variant: <all_urls> promoted from optional to granted]"

    global ROUTED_HOST, OTHER_HOST, SITE_PORT  # noqa: PLW0603
    real_host_bin: Path | None = None
    if args.real_host:
        if args.real_host not in ("harness", "shipped"):
            print("verify: --real-host takes 'harness' or 'shipped'", file=sys.stderr)
            return 2
        host_pkg = root.parent / "tools" / "native_messaging" / "host"
        if args.real_host == "shipped":
            real_host_bin = host_pkg / "wins_bridge_host"
            if not real_host_bin.exists():
                print(f"verify: no compiled host at {real_host_bin}", file=sys.stderr)
                return 2
        else:
            out_dir = work / "host"
            out_dir.mkdir(parents=True, exist_ok=True)
            # Compiled to the name `wins_bridge_host` because that is what lsof
            # reports for the process and what the attribution matches on. The
            # SOURCE is wins_bridge_host_harness.dart and the run says so.
            real_host_bin = out_dir / "wins_bridge_host"
            print(f"  compiling the real host from "
                  f"{host_pkg}/bin/wins_bridge_host_harness.dart")
            built = subprocess.run(
                ["dart", "compile", "exe", "bin/wins_bridge_host_harness.dart",
                 "-o", str(real_host_bin)],
                cwd=str(host_pkg), capture_output=True, text=True)
            if built.returncode != 0:
                print(built.stdout + built.stderr, file=sys.stderr)
                return 2
        ROUTED_HOST, OTHER_HOST = REAL_HOST_ROUTED, REAL_HOST_OTHER
        print(f"  --real-host={args.real_host}: {real_host_bin}")
        print(f"  the routed site is now {ROUTED_HOST} and the unlisted one {OTHER_HOST}; "
              f"the name claims use {REAL_HOST_NAME}. The real proxy does real DNS, so "
              ".invalid cannot be a destination, and Chromium bypasses .localhost.")

    print(f"verifying {args.browser} against {package}{variant_note}")
    h = Harness(args.browser, package, work, args.keep)
    if real_host_bin is not None:
        h.real_host = real_host_bin
        h.real_marker_port = free_port()
        SITE_PORT = h.real_marker_port
    h.pregranted = args.pregrant_host
    try:
        h.set_tunnel_state("app_not_running")
        h.start_endpoint()
        h.ext_id = cdp.unpacked_extension_id(str(package))
        h.profile.mkdir(parents=True, exist_ok=True)
        h.install_native_host()
        h.launch_browser()
        h.load_extension()
        h.install_native_host()  # rewrite with the id the browser actually gave
        h.attach()
        h.attach_page()
        print(f"  extension id {h.ext_id}, proxy {h.proxy_port}, marker https {h.http_port}\n")
        result = run(h)
    finally:
        h.shutdown()
        if h.real_host and h.host_stderr.exists():
            tail = h.host_stderr.read_text(encoding="utf-8", errors="replace")
            if tail.strip():
                print("\n  the real host's stderr (it never carries a token):")
                for line in tail.strip().splitlines()[-10:]:
                    print(f"    {line}")

    total = len(result.checks)
    passed = sum(1 for c in result.checks if c["ok"])
    print(f"\n{args.browser}: {passed}/{total} checks passed")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps({
            "browser": args.browser,
            "package": str(package),
            "passed": passed,
            "total": total,
            "checks": result.checks,
        }, indent=2), encoding="utf-8")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
