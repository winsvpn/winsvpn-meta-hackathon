#!/usr/bin/env python3
"""Where can a real browser actually LAUNCH the native-messaging host from?

This answers a question that documentation cannot, and the reason it cannot is
the whole point: the manifest is identical, the binary is byte-for-byte
identical, and the only thing that differs between a host that works and a host
that produces nothing at all is the DIRECTORY the executable sits in. macOS TCC
gates `~/Documents`, `~/Desktop` and `~/Downloads` per-application, so the
answer is a property of the running browser's own permission record on this
machine, not of the file.

It was found by accident on 2026-08-07 -- the shipped host scored 26/48 from
`~/Documents` and 28/48 from `TMPDIR`, same bytes, same manifest -- and
`docs/handoff/BROWSER_EXTENSION_REAL_HOST_JOINED_20260807.md` §4.4 handed it to
the installer. This tool is that finding turned into a measurement anybody can
repeat.

    python3 tools/probe_host_location.py --browser chrome
    python3 tools/probe_host_location.py --browser edge
    python3 tools/probe_host_location.py --browser firefox
    python3 tools/probe_host_location.py --browser all

For each candidate directory it copies the real compiled host there, writes the
real manifest shape pointing straight at it (which is what
`install_native_host.sh` writes -- no wrapper script, because a wrapper in a
readable directory would hide exactly the failure being measured), loads a
throwaway extension into a scratch profile of the real browser, and calls
`runtime.connectNative`. What it records is what the browser DID:

  * whether `connectNative` threw;
  * whether the port disconnected, and after how long;
  * `port.error` (Firefox) and `runtime.lastError` (Chromium) VERBATIM -- these
    two are the raw material for the extension's own diagnostic, so they are
    read here rather than guessed at;
  * whether a reply arrived, which only a running host can produce;
  * and, independently of the browser, whether a process running that exact
    binary appeared in the OS process table during the window.

That last one is the ground truth the browser cannot fake. A `hello` reply and
a process sighting agreeing is a host that launched; both absent is a host that
never existed.

Containment: scratch profiles, a throwaway extension with `nativeMessaging` and
nothing else, no network, no VPN session. The Firefox manifest location is
shared (Gecko has no profile-local one on macOS) and is backed up and restored.
Every directory this tool creates, it removes.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import cdp  # noqa: E402
from marionette import Marionette  # noqa: E402

HOST_NAME = "org.winsvpn.bridge"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
EDGE = "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
FIREFOX = "/Applications/Firefox.app/Contents/MacOS/firefox"
FIREFOX_ADDON_ID = "hostprobe@winsvpn.org"
# The shipping add-on's own id, used by --mode extension.
FIREFOX_PACKAGE_ID = "companion@winsvpn.org"
FIREFOX_NATIVE_DIR = (
    Path.home() / "Library" / "Application Support" / "Mozilla" / "NativeMessagingHosts"
)

REPO = HERE.parent.parent
DEFAULT_HOST = REPO / "tools" / "native_messaging" / "host" / "wins_bridge_host"

# The candidate directories, each with what it is and why it is on the list.
#
# `in-tree` is not a copy: it is the file the installer's default `host-path`
# points at today, measured where it actually sits.
CANDIDATES: list[tuple[str, str, str]] = [
    ("in-tree",
     str(REPO / "tools" / "native_messaging" / "host"),
     "the installer's default today: the repository, under ~/Documents"),
    ("desktop",
     str(Path.home() / "Desktop" / "wv-host-location-probe"),
     "~/Desktop -- TCC-protected, and a plausible place a user unzips a build"),
    ("downloads",
     str(Path.home() / "Downloads" / "wv-host-location-probe"),
     "~/Downloads -- TCC-protected, and where a downloaded build lands"),
    ("user-support",
     str(Path.home() / "Library" / "Application Support" / "Win's VPN"
         / "NativeMessagingHost"),
     "the proposed PER-USER location: ~/Library/Application Support"),
    ("app-bundle",
     "/Applications/WV Host Location Probe.app/Contents/Resources",
     "the proposed SYSTEM-WIDE location, shaped as the app bundle it would ship in"),
    ("tmpdir",
     str(Path(os.environ.get("TMPDIR", "/tmp")) / "wv-host-location-probe"),
     "the control: the directory the 2026-08-07 run proved works"),
]

PROBE_SCRIPT = """
const NAME = %s;
const out = {
  threw: '', postThrew: '', disconnected: false, portError: '', lastError: '',
  messages: [], disconnectMs: 0,
};
const t0 = Date.now();
let port = null;
try {
  port = API.runtime.connectNative(NAME);
} catch (e) {
  out.threw = String((e && e.message) || e);
}
if (!port) { return out; }
await new Promise((resolve) => {
  let settled = false;
  const finish = () => { if (!settled) { settled = true; resolve(); } };
  port.onMessage.addListener((m) => {
    out.messages.push(JSON.stringify(m).slice(0, 240));
    // A reply is proof of a process. Nothing else needs waiting for.
    setTimeout(finish, 250);
  });
  port.onDisconnect.addListener((p) => {
    out.disconnected = true;
    out.disconnectMs = Date.now() - t0;
    // BOTH are read, because the two browsers put the reason in different
    // places and neither documents the other's. Firefox sets `port.error`;
    // Chromium sets `runtime.lastError` and only inside this callback.
    if (p && p.error) {
      out.portError = String((p.error && p.error.message) || p.error);
    }
    const le = API.runtime.lastError;
    if (le) { out.lastError = String((le && le.message) || le); }
    finish();
  });
  try {
    port.postMessage({ v: 1, id: '1', type: 'hello' });
  } catch (e) {
    out.postThrew = String((e && e.message) || e);
  }
  setTimeout(finish, %d);
});
out.elapsedMs = Date.now() - t0;
try { port.disconnect(); } catch (e) { /* already gone */ }
return out;
"""


def probe_body(wait_ms: int) -> str:
    return PROBE_SCRIPT % (json.dumps(HOST_NAME), wait_ms)


# In `--mode extension` the throwaway probe is replaced by THE SHIPPING
# EXTENSION, armed, and what is read is its own snapshot -- the same object the
# popup renders and the same one a support request would quote. That is the only
# way to check the half of this defect that is about diagnostics rather than
# about launching: the browser reports nothing either way, so what matters is
# what the extension says about a silence it can only observe.
EXTENSION_PROBE = """
const s0 = await API.runtime.sendMessage({type: 'getState'});
const next = Object.assign({}, s0.settings, {armed: true});
await API.runtime.sendMessage({type: 'setSettings', settings: next});
await new Promise((r) => setTimeout(r, %d));
const s = await API.runtime.sendMessage({type: 'getState'});
return {
  state: s.state, detail: s.detail, tunnelStatus: s.tunnelStatus,
  lastError: s.lastError, hostAnswered: s.hostAnswered,
  hostOpenAgeMs: s.hostOpenAgeMs, requestsSent: s.requestsSent,
  statusAgeMs: s.statusAgeMs, failClosed: s.failClosed,
};
"""


def extension_body(settle_ms: int) -> str:
    return EXTENSION_PROBE % settle_ms


# ---------------------------------------------------------------------------
# Ground truth from the OS, not from the browser
# ---------------------------------------------------------------------------


class ProcessWatch:
    """Poll the process table for anything running exactly this binary."""

    def __init__(self, binary: Path):
        self.binary = str(binary)
        self.seen: list[str] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                out = subprocess.run(["ps", "-Ao", "pid=,args="], capture_output=True,
                                     text=True, timeout=5).stdout
            except (OSError, subprocess.SubprocessError):
                out = ""
            for line in out.splitlines():
                if self.binary in line and "ps -Ao" not in line:
                    trimmed = line.strip()[:160]
                    if trimmed not in self.seen:
                        self.seen.append(trimmed)
            self._stop.wait(0.15)

    def __enter__(self) -> ProcessWatch:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._thread.join(timeout=3)

    def lingering(self) -> list[str]:
        """Hosts still running this path after the pair: reported, never signalled.

        A host stuck in dyld waiting on TCC never exits by itself. This tool
        cannot prove it started a given process (on macOS `ps` shows argv[0],
        which any process can set to this path), so nothing is signalled. The
        survivors are listed for the person running the probe.
        """
        try:
            out = subprocess.run(["ps", "-Ao", "pid=,args="], capture_output=True,
                                 text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            return ["(process table unreadable; lingering hosts not checked)"]
        return [line.strip()[:160] for line in out.splitlines()
                if self.binary in line and "ps -Ao" not in line]


# ---------------------------------------------------------------------------
# The throwaway extension
# ---------------------------------------------------------------------------


def write_probe_extension(root: Path, browser: str) -> Path:
    """A two-file extension with `nativeMessaging` and nothing else."""
    pkg = root / f"probe-ext-{browser}"
    if pkg.exists():
        shutil.rmtree(pkg)
    pkg.mkdir(parents=True)
    if browser == "firefox":
        (pkg / "manifest.json").write_text(json.dumps({
            "manifest_version": 2,
            "name": "WV host location probe",
            "version": "1.0",
            "permissions": ["nativeMessaging"],
            "browser_specific_settings": {"gecko": {"id": FIREFOX_ADDON_ID}},
            "background": {"scripts": ["bg.js"]},
        }, indent=2), encoding="utf-8")
        (pkg / "bg.js").write_text("// nothing; the probe runs in probe.html\n",
                                   encoding="utf-8")
        (pkg / "probe.html").write_text(
            "<!doctype html><meta charset=utf-8><title>probe</title>\n",
            encoding="utf-8")
    else:
        (pkg / "manifest.json").write_text(json.dumps({
            "manifest_version": 3,
            "name": "WV host location probe",
            "version": "1.0",
            "permissions": ["nativeMessaging"],
            "background": {"service_worker": "sw.js"},
        }, indent=2), encoding="utf-8")
        (pkg / "sw.js").write_text("// the probe is evaluated in this worker\n",
                                   encoding="utf-8")
    return pkg


# ---------------------------------------------------------------------------
# Placing the host
# ---------------------------------------------------------------------------


def place_host(source: Path, directory: str) -> tuple[Path, Path | None]:
    """Put the real host at `directory`, which must not exist yet.

    Returns (path, created_root): the topmost directory this call created,
    which is the only thing remove_placed() may delete, or None when the
    candidate is the source itself. An existing candidate directory (for
    example an installed per-user host) raises FileExistsError, an OSError the
    caller already reports as UNPLACEABLE, and is left byte-for-byte intact.
    """
    target_dir = Path(directory)
    target = target_dir / source.name
    if target.resolve() == source.resolve():
        return target, None
    if target_dir.exists() or target_dir.is_symlink():
        raise FileExistsError(f"refusing to use existing directory {target_dir}")
    created_root = target_dir
    while not created_root.parent.exists():
        created_root = created_root.parent
    target_dir.mkdir(parents=True)
    try:
        shutil.copy2(source, target)
        target.chmod(0o755)
    except OSError:
        shutil.rmtree(created_root, ignore_errors=True)
        raise
    return target, created_root


def remove_placed(created_root: Path | None) -> None:
    """Remove exactly the directory tree place_host() created, nothing above it."""
    if created_root is None:
        return
    shutil.rmtree(created_root)


# ---------------------------------------------------------------------------
# Chromium
# ---------------------------------------------------------------------------


def run_chromium(browser: str, host_path: Path, work: Path, wait_ms: int,
                 mode: str = "raw") -> dict:
    binary = CHROME if browser == "chrome" else EDGE
    if not Path(binary).exists():
        return {"error": f"{browser} is not installed at {binary}"}
    profile = work / f"profile-{browser}"
    if profile.exists():
        shutil.rmtree(profile)
    profile.mkdir(parents=True)

    pkg = (HERE.parent / "dist" / browser).resolve() if mode == "extension" \
        else write_probe_extension(work, browser)
    if not pkg.exists():
        return {"error": f"no built package at {pkg}; run build.py first"}
    port = free_port()
    proc = subprocess.Popen(
        [binary, f"--user-data-dir={profile}", "--enable-unsafe-extension-debugging",
         f"--remote-debugging-port={port}", "--no-first-run",
         "--no-default-browser-check", "--disable-background-networking",
         "--disable-component-update", "--disable-sync",
         "--headless=new", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    sw = None
    try:
        cdp.wait_for_endpoint(port, timeout=45)
        info = cdp.wait_for_endpoint(port)
        browser_target = cdp.Target(info["webSocketDebuggerUrl"])
        try:
            got = browser_target.call("Extensions.loadUnpacked", {"path": str(pkg)})
            ext_id = got["id"]
        finally:
            browser_target.close()

        # The manifest is written AFTER the id is known, because the id this
        # browser assigns is the only one `allowed_origins` may name and
        # Chrome 151 does not assign the documented path-derived one. Chromium
        # reads the manifest at connectNative time, so writing it here is in
        # time -- verified by the control location answering.
        hosts = profile / "NativeMessagingHosts"
        hosts.mkdir(parents=True, exist_ok=True)
        (hosts / f"{HOST_NAME}.json").write_text(json.dumps({
            "name": HOST_NAME,
            "description": "Win's VPN browser bridge (location probe)",
            "path": str(host_path),
            "type": "stdio",
            "allowed_origins": [f"chrome-extension://{ext_id}/"],
        }, indent=2), encoding="utf-8")

        deadline = time.time() + 25
        while time.time() < deadline and sw is None:
            for t in cdp.list_targets(port):
                if t["type"] == "service_worker" and ext_id in t["url"]:
                    sw = cdp.Target(t["webSocketDebuggerUrl"])
                    sw.call("Runtime.enable")
                    break
            if sw is None:
                time.sleep(0.4)
        if sw is None:
            return {"error": "the extension's service worker never appeared"}

        if mode == "extension":
            # A service worker cannot sendMessage to itself, so the extension's
            # own options page is the control surface -- the same path the popup
            # takes, rather than one built for the test.
            target = None
            info2 = cdp.wait_for_endpoint(port)
            bt = cdp.Target(info2["webSocketDebuggerUrl"])
            try:
                bt.call("Target.createTarget",
                        {"url": f"chrome-extension://{ext_id}/src/ui/options.html"})
            finally:
                bt.close()
            deadline = time.time() + 25
            while time.time() < deadline and target is None:
                for t in cdp.list_targets(port):
                    if t["type"] == "page" and ext_id in t["url"]:
                        target = cdp.Target(t["webSocketDebuggerUrl"])
                        target.call("Runtime.enable")
                        break
                if target is None:
                    time.sleep(0.4)
            if target is None:
                return {"error": "the extension's options page never became drivable"}
            expr = ("(async()=>{const API=chrome;"
                    + extension_body(wait_ms)
                    + "})().then(v=>JSON.stringify(v))")
            watch = ProcessWatch(host_path)
            try:
                with watch:
                    raw = target.evaluate(expr, timeout=(wait_ms / 1000.0) + 40)
            finally:
                target.close()
            result = json.loads(raw)
            result["processSeen"] = list(watch.seen)
            result["lingering"] = watch.lingering()
            return result

        expr = ("(async()=>{const API=chrome;"
                + probe_body(wait_ms)
                + "})().then(v=>JSON.stringify(v))")
        watch = ProcessWatch(host_path)
        with watch:
            raw = sw.evaluate(expr, timeout=(wait_ms / 1000.0) + 30)
        result = json.loads(raw)
        result["processSeen"] = list(watch.seen)
        result["lingering"] = watch.lingering()
        return result
    finally:
        if sw is not None:
            sw.close()
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()


# ---------------------------------------------------------------------------
# Firefox
# ---------------------------------------------------------------------------


FIREFOX_PREFS = """user_pref("marionette.port", {mport});
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("app.update.auto", false);
user_pref("extensions.autoDisableScopes", 0);
user_pref("xpinstall.signatures.required", false);
user_pref("network.trr.mode", 5);
user_pref("network.dns.disabled", true);
"""


def run_firefox(host_path: Path, work: Path, wait_ms: int, mode: str = "raw") -> dict:
    if not Path(FIREFOX).exists():
        return {"error": f"firefox is not installed at {FIREFOX}"}
    profile = work / "profile-firefox"
    if profile.exists():
        shutil.rmtree(profile)
    profile.mkdir(parents=True)

    if mode == "extension":
        pkg = (HERE.parent / "dist" / "firefox").resolve()
        addon_id = FIREFOX_PACKAGE_ID
        if not pkg.exists():
            return {"error": f"no built package at {pkg}; run build.py first"}
    else:
        pkg = write_probe_extension(work, "firefox")
        addon_id = FIREFOX_ADDON_ID

    FIREFOX_NATIVE_DIR.mkdir(parents=True, exist_ok=True)
    target = FIREFOX_NATIVE_DIR / f"{HOST_NAME}.json"
    backup = target.read_bytes() if target.exists() else None
    target.write_text(json.dumps({
        "name": HOST_NAME,
        "description": "Win's VPN browser bridge (location probe)",
        "path": str(host_path),
        "type": "stdio",
        "allowed_extensions": [addon_id],
    }, indent=2), encoding="utf-8")

    mport = free_port()
    (profile / "user.js").write_text(FIREFOX_PREFS.format(mport=mport), encoding="utf-8")
    env = dict(os.environ)
    env["MOZ_HEADLESS"] = "1"
    env.pop("MOZ_MARIONETTE_PORT", None)
    proc = subprocess.Popen(
        [FIREFOX, "-headless", "-no-remote", "-marionette",
         "-remote-allow-system-access", "-profile", str(profile), "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
    )
    m = Marionette(mport)
    try:
        m.connect(deadline=120)
        m.new_session(accept_insecure_certs=False)
        m.set_timeouts(page_load=25000, script=90000)
        m.value("Addon:Install", {"path": str(pkg), "temporary": True}, timeout=120)

        uuid = ""
        deadline = time.time() + 30
        while time.time() < deadline and not uuid:
            m.set_context("chrome")
            raw = m.execute(
                "const S = (typeof Services !== 'undefined') ? Services : null;"
                "try { return S.prefs.getStringPref('extensions.webextensions.uuids'); }"
                "catch (e) { return ''; }")
            m.set_context("content")
            try:
                uuid = (json.loads(raw or "{}")).get(addon_id, "")
            except json.JSONDecodeError:
                uuid = ""
            if not uuid:
                time.sleep(0.5)
        if not uuid:
            return {"error": "Firefox never assigned the probe add-on a uuid"}

        m.set_context("content")
        if mode == "extension":
            m.navigate(f"moz-extension://{uuid}/src/ui/options.html")
            body = extension_body(wait_ms)
        else:
            m.navigate(f"moz-extension://{uuid}/probe.html")
            body = probe_body(wait_ms)
        script = (
            "const done = arguments[arguments.length - 1];"
            "const API = (typeof browser !== 'undefined' && browser.runtime) ? browser"
            "  : ((window.wrappedJSObject && window.wrappedJSObject.browser) || null);"
            "if (!API) { done(JSON.stringify({error: 'no WebExtension namespace'})); }"
            "else { (async () => {" + body + "})()"
            ".then(v => done(JSON.stringify(v)))"
            ".catch(e => done(JSON.stringify({error: String((e && e.message) || e)})));}"
        )
        watch = ProcessWatch(host_path)
        with watch:
            raw = m.execute_async(script, timeout=(wait_ms / 1000.0) + 40)
        result = json.loads(raw) if isinstance(raw, str) else {"error": f"raw {raw!r}"}
        result["processSeen"] = list(watch.seen)
        result["lingering"] = watch.lingering()
        return result
    finally:
        try:
            m.close()
        except Exception:  # noqa: BLE001
            pass
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
        try:
            if backup is not None:
                target.write_bytes(backup)
            elif target.exists():
                target.unlink()
        except OSError:
            pass


def free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------


def extension_verdict(result: dict) -> tuple[str, str]:
    """What the SHIPPING extension made of the same situation.

    The verdict is the extension's own state, and the detail is the sentence a
    user would be shown and a diagnostician would be sent. An empty `lastError`
    here is a failure of this lane whatever else is green: it is the exact field
    that was blank on 2026-08-07 and the exact reason nobody could see why.
    """
    if result.get("error"):
        return "ERROR", str(result["error"])
    state = str(result.get("state", "?"))
    said = str(result.get("lastError", ""))
    facts = (f"hostAnswered={result.get('hostAnswered')} "
             f"openAge={result.get('hostOpenAgeMs')}ms "
             f"sent={result.get('requestsSent')}")
    # An empty lastError is only a defect where something went wrong. A bridge
    # that answered and truthfully reports `app_not_running` has nothing to put
    # in the field, and demanding a sentence there would be its own overclaim.
    # The failure is the pairing: nothing came back AND nothing was said.
    if not said and result.get("hostAnswered") is False:
        return state, f"SILENT AND UNEXPLAINED: lastError is empty -- {facts}"
    if not said:
        return state, f"nothing to report (the bridge answered) -- {facts}"
    return state, f"{facts}; lastError={said}"


def verdict(result: dict) -> tuple[str, str]:
    """What the browser did, in three distinguishable outcomes.

    `SPOKE` is the only one that means the host is usable, and it is the only
    one a message can produce: a reply requires a process that read stdin and
    wrote stdout. `SILENT` is the interesting failure -- a process the OS shows
    but that never says anything -- and `NO HOST` is nothing at all. Collapsing
    the last two into "did not work" is precisely the rounding this whole lane
    is about, so they are kept apart.
    """
    if result.get("error"):
        return "ERROR", str(result["error"])
    said = result.get("portError") or result.get("lastError") or result.get("threw") or ""
    tail = (f"disconnected after {result.get('disconnectMs', 0)}ms"
            if result.get("disconnected") else "no disconnect")
    tail += f"; browser said: {said or '(nothing)'}"
    if result.get("messages"):
        return "SPOKE", f"{len(result['messages'])} reply/replies; {tail}"
    if result.get("processSeen"):
        return "SILENT", f"process in the OS table but no reply; {tail}"
    return "NO HOST", f"no process, no reply; {tail}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--browser", default="all",
                    choices=["chrome", "edge", "firefox", "all"])
    ap.add_argument("--host", default=str(DEFAULT_HOST),
                    help="the compiled native-messaging host to place")
    ap.add_argument("--only", default="",
                    help="comma-separated candidate labels; default is all of them")
    ap.add_argument("--mode", default="raw", choices=["raw", "extension"],
                    help="raw: a throwaway extension calling connectNative. "
                         "extension: the shipping package, armed, and its own snapshot")
    ap.add_argument("--wait-ms", type=int, default=6000)
    ap.add_argument("--verbose", action="store_true",
                    help="print the whole result object for each pair")
    args = ap.parse_args()

    source = Path(args.host)
    if not source.exists():
        print(f"probe: no compiled host at {source}", file=sys.stderr)
        return 2
    digest = subprocess.run(["shasum", "-a", "256", str(source)],
                            capture_output=True, text=True).stdout.split()[0]
    print(f"probe: host {source}")
    print(f"       sha256 {digest}")

    wanted = [c for c in CANDIDATES
              if not args.only or c[0] in args.only.split(",")]
    browsers = ["chrome", "edge", "firefox"] if args.browser == "all" else [args.browser]

    work = Path(os.environ.get("TMPDIR", "/tmp")) / f"wv-probe-{os.getpid()}"
    work.mkdir(parents=True, exist_ok=True)

    rows: list[tuple[str, str, str, str, str]] = []
    try:
        for label, directory, why in wanted:
            print(f"\n=== {label}: {directory}")
            print(f"    {why}")
            try:
                host_path, created_root = place_host(source, directory)
            except OSError as e:
                print(f"    could not place the host here: {e}")
                for b in browsers:
                    rows.append((label, b, "UNPLACEABLE", str(e), directory))
                continue
            try:
                for b in browsers:
                    if b == "firefox":
                        result = run_firefox(host_path, work, args.wait_ms, args.mode)
                    else:
                        result = run_chromium(b, host_path, work, args.wait_ms, args.mode)
                    v, detail = (extension_verdict(result) if args.mode == "extension"
                                 else verdict(result))
                    print(f"    {b:8s} {v:20s} {detail}")
                    if result.get("messages"):
                        print(f"             first reply: {result['messages'][0][:120]}")
                    for line in result.get("processSeen", [])[:2]:
                        print(f"             ps: {line[:120]}")
                    for line in result.get("lingering", []):
                        print(f"             still running, not signalled: {line[:120]}")
                    if args.verbose:
                        print(f"             raw: {json.dumps(result)[:400]}")
                    rows.append((label, b, v, detail, directory))
            finally:
                remove_placed(created_root)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("\n" + "=" * 78)
    heading = ("what the extension reported" if args.mode == "extension"
               else "what the browser did")
    print(f"{'candidate':14s} {'browser':8s} {'verdict':20s} {heading}")
    print("-" * 78)
    for label, b, v, detail, _ in rows:
        print(f"{label:14s} {b:8s} {v:20s} {detail[:60]}")
    print("=" * 78)
    if args.mode == "extension":
        blank = [r for r in rows if "SILENT AND UNEXPLAINED" in r[3]]
        print(f"{len(rows)} pairs; {len(blank)} where the bridge never answered "
              f"and the extension had nothing to say about it")
        return 1 if blank else 0
    bad = [r for r in rows if r[2] != "SPOKE"]
    print(f"{len(rows) - len(bad)}/{len(rows)} browser/location pairs got a reply from the host")
    return 0


if __name__ == "__main__":
    sys.exit(main())
