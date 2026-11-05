#!/usr/bin/env python3
"""A dependency-free Marionette client, the Firefox counterpart to cdp.py.

Firefox has no DevTools-protocol endpoint that a --remote-debugging-port hands
out, and the CDP shim it used to carry was removed. What it does have is
Marionette: the same automation channel geckodriver drives, spoken over a plain
TCP socket with `<length>:<json>` framing. That is simple enough to implement
here in the standard library, which is the whole point -- this tree has no
third-party dependencies at build time or at test time, and a verification
harness that pulls a package from a registry is a verification harness that can
be compromised for everyone who runs it.

Three things this gives that nothing else would have:

  * `Addon:Install` with `temporary: true` is the same code path `about:debugging`
    uses for an unsigned build, so the package is loaded the way a reviewer would
    load it rather than through a signing bypass.
  * `Marionette:SetContext chrome` runs script with the browser's own privileges,
    which is how the WebRTC and proxy claims are checked against Gecko's actual
    preference values rather than against the extension's report of them.
  * `WebDriver:ElementClick` produces a real, trusted click. That is what makes
    the optional-permission grant testable at all: the doorhanger it raises is a
    piece of browser UI, and it can be found and clicked in chrome context.
"""

from __future__ import annotations

import json
import socket
import time

WEBDRIVER_ELEMENT_KEY = "element-6066-11e4-a52e-4f735466cecf"


class MarionetteError(RuntimeError):
    def __init__(self, kind: str, message: str, payload: dict | None = None):
        super().__init__(f"{kind}: {message}")
        self.kind = kind
        self.message = message or ""
        self.payload = payload or {}


class Marionette:
    """One connection, one session. Not thread-safe, and does not need to be."""

    def __init__(self, port: int, host: str = "127.0.0.1", timeout: float = 120.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.buf = b""
        self.msgid = 0
        self.hello: dict = {}
        self.session: dict = {}
        # Modal prompts this client had to dismiss to keep going, and the last
        # one's text. Both are findings in their own right.
        self.alerts_dismissed = 0
        self.last_alert = ""

    # -- transport -----------------------------------------------------------

    def connect(self, deadline: float = 90.0) -> dict:
        end = time.time() + deadline
        last: Exception | None = None
        while time.time() < end:
            try:
                s = socket.create_connection((self.host, self.port), timeout=10)
                s.settimeout(self.timeout)
                self.sock = s
                self.hello = self._read_packet()
                return self.hello
            except OSError as e:  # noqa: PERF203
                last = e
                time.sleep(0.3)
        raise RuntimeError(f"marionette never accepted a connection on {self.port}: {last}")

    def close(self) -> None:
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = None

    def _read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("marionette closed the connection")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _read_packet(self):
        digits = b""
        while True:
            c = self._read_exact(1)
            if c == b":":
                break
            if not c.isdigit():
                raise ValueError(f"malformed marionette frame near {digits + c!r}")
            digits += c
            if len(digits) > 12:
                raise ValueError("implausible marionette frame length")
        return json.loads(self._read_exact(int(digits)).decode("utf-8"))

    # -- commands ------------------------------------------------------------

    def call(self, command: str, params: dict | None = None, timeout: float | None = None):
        """Send a command.

        A modal browser prompt makes Marionette refuse every subsequent command,
        and one of the things under test here produces exactly that: when the
        add-on fails to answer a proxy's 407, Firefox asks the *user* for the
        proxy password. That is evidence, not an accident, so it is counted and
        recorded rather than thrown away -- and then dismissed, so the run can
        carry on and find out what else is true.
        """
        try:
            return self._call_once(command, params, timeout)
        except MarionetteError as e:
            if "unexpected alert open" not in f"{e.kind} {e.message}".lower():
                raise
            self.alerts_dismissed += 1
            self.last_alert = e.message
            try:
                self._call_once("WebDriver:DismissAlert", {}, 30)
            except MarionetteError:
                pass
            return self._call_once(command, params, timeout)

    def _call_once(self, command: str, params: dict | None = None, timeout: float | None = None):
        if self.sock is None:
            raise RuntimeError("not connected")
        self.msgid += 1
        mid = self.msgid
        body = json.dumps([0, mid, command, params or {}]).encode("utf-8")
        self.sock.sendall(str(len(body)).encode("ascii") + b":" + body)

        previous = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            while True:
                packet = self._read_packet()
                # Anything that is not the reply to this id is an out-of-band
                # frame; ignoring it rather than treating it as the answer is
                # what keeps a slow command from being answered by a stray one.
                if isinstance(packet, list) and len(packet) == 4 and packet[0] == 1 and packet[1] == mid:
                    _, _, err, result = packet
                    if err:
                        raise MarionetteError(
                            str(err.get("error", "error")), str(err.get("message", "")), err
                        )
                    return result
        finally:
            try:
                self.sock.settimeout(previous)
            except OSError:
                pass

    def value(self, command: str, params: dict | None = None, timeout: float | None = None):
        got = self.call(command, params, timeout)
        if isinstance(got, dict) and "value" in got:
            return got["value"]
        return got

    # -- session -------------------------------------------------------------

    def new_session(self, accept_insecure_certs: bool = True) -> dict:
        """Start a session, and CHECK the capability was honoured rather than sent.

        Marionette accepts more than one shape for the capabilities parameter and
        silently ignores the ones it does not recognise -- a request that is
        accepted and dropped, which is the failure mode this project keeps
        finding in guards. `acceptInsecureCerts` is load-bearing here (the marker
        server is self-signed), so the returned capabilities are read back and
        another shape is tried if it did not take.
        """
        want = bool(accept_insecure_certs)
        shapes = [
            {"capabilities": {"alwaysMatch": {"acceptInsecureCerts": want}}},
            {"alwaysMatch": {"acceptInsecureCerts": want}},
            {"acceptInsecureCerts": want},
        ]
        last: dict = {}
        for params in shapes:
            try:
                got = self.call("WebDriver:NewSession", params, timeout=90) or {}
            except MarionetteError:
                continue
            last = got
            if not want or (got.get("capabilities") or {}).get("acceptInsecureCerts") is True:
                self.session = got
                return got
            try:
                self.call("WebDriver:DeleteSession", {})
            except MarionetteError:
                pass
        self.session = last
        return last

    def set_timeouts(self, page_load: int = 25000, script: int = 60000, implicit: int = 0) -> None:
        self.call("WebDriver:SetTimeouts",
                  {"pageLoad": page_load, "script": script, "implicit": implicit})

    def set_context(self, context: str) -> None:
        self.call("Marionette:SetContext", {"value": context})

    # -- script --------------------------------------------------------------

    def execute(self, script: str, args=None, timeout: float | None = 90.0):
        return self.value("WebDriver:ExecuteScript",
                          {"script": script, "args": args or [], "newSandbox": False},
                          timeout=timeout)

    def execute_async(self, script: str, args=None, timeout: float | None = 90.0):
        return self.value("WebDriver:ExecuteAsyncScript",
                          {"script": script, "args": args or [], "newSandbox": False},
                          timeout=timeout)

    # -- windows and navigation ---------------------------------------------

    def handles(self) -> list:
        return self.value("WebDriver:GetWindowHandles") or []

    def switch_to(self, handle: str) -> None:
        self.call("WebDriver:SwitchToWindow", {"handle": handle, "focus": True})

    def new_tab(self) -> str:
        got = self.call("WebDriver:NewWindow", {"type": "tab", "focus": True}) or {}
        return got.get("handle") or got.get("value", {}).get("handle", "")

    def navigate(self, url: str, timeout: float = 90.0) -> str:
        """Navigate. Returns '' on success, or Marionette's own error message.

        A load that ends on Firefox's network error page is reported by
        Marionette as `Reached error page: about:neterror?e=<code>&u=<url>`,
        which carries Gecko's own name for what went wrong. That string is
        evidence, so it is returned rather than raised.
        """
        try:
            self.call("WebDriver:Navigate", {"url": url}, timeout=timeout)
            return ""
        except MarionetteError as e:
            return e.message or e.kind
        except (TimeoutError, socket.timeout):
            return "navigation timed out"

    def find(self, css: str):
        got = self.value("WebDriver:FindElement", {"using": "css selector", "value": css})
        if isinstance(got, dict):
            return got.get(WEBDRIVER_ELEMENT_KEY)
        return None

    def click(self, element_id: str) -> None:
        self.call("WebDriver:ElementClick", {"id": element_id}, timeout=60)
