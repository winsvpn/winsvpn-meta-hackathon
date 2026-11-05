#!/usr/bin/env python3
"""Read-only pre-ship gate: every inline <style> and inline <script> block in
web/index.html must match a SHA-256 hash pinned in the Content-Security-Policy
in BOTH web/_headers and web/_worker.js -- style-src for styles, script-src for
scripts -- and every sha256 pinned in those directives must still correspond to
a current inline block.

A stale pin after an edit to index.html's <style> or <script> makes the browser
drop that resource on a live site: a stale style hash renders the page unstyled,
a stale script hash blocks the whole page's JavaScript (language switching,
demos, payment buttons, AI chat all die). update_style_csp.py re-syncs the pins;
this script only VERIFIES they are in sync and never writes anything.

A would-be deployment package whose CSP pins were rewritten by a secret
scrubber to 'sha256-<REDACTED_WG_KEY>' (or any other placeholder / invalid /
duplicate / extra hash, or static/worker divergence) must fail this preflight.

Exit 0 if every inline block's hash is pinned in the correct directive of both
host files, both hosts carry the same policy body, and no pinned sha256 is
orphaned, duplicated, invalid, or a placeholder. Exit 1 otherwise.

Usage: python3 verify_inline_csp.py [WEB_DIR]   (default: this script's parent)
"""
from __future__ import annotations

import base64
import hashlib
import os
import pathlib
import re
import stat
import sys

WEB = pathlib.Path(__file__).resolve().parent
INDEX = WEB / "index.html"
HOSTS = (WEB / "_headers", WEB / "_worker.js")
INDEX_NAME = "index.html"
HOST_NAMES = ("_headers", "_worker.js")
KNOWN_NAMES = {INDEX_NAME, *HOST_NAMES}
MAX_FILE_BYTES = {
    INDEX_NAME: 8 * 1024 * 1024,
    "_headers": 1024 * 1024,
    "_worker.js": 1024 * 1024,
}

HASH_RE = re.compile(r"'sha256-[^']+'")
VALID_HASH_RE = re.compile(r"sha256-[A-Za-z0-9+/]{43}=")
PLACEHOLDER_POLICY_RE = re.compile(
    r"(?i)sha256-<|redacted_wg_key|<redacted|placeholder_hash")
PLACEHOLDER_PIN_RE = re.compile(
    r"(?i)redacted|placeholder|example|todo|changeme|<|>")
DIRECTIVE_NAME_RE = re.compile(r"[a-z][a-z0-9-]*")
NONFINITE_RE = re.compile(r"(?i)[+-]?(?:nan|inf|infinity)|1e\+?400")
ALLOWED_NON_HASH_SOURCES = {
    "style-src": {"'self'"},
    "script-src": {
        "'self'",
        "https://www.paypal.com",
        "https://www.paypalobjects.com",
    },
}

# The policy text itself, and nothing else, in each host file. _headers carries
# it on a `Content-Security-Policy:` line; _worker.js carries it in a
# `const CONTENT_SECURITY_POLICY = "..."`. Scoping to these is not fussiness:
# _worker.js has a prose comment containing the words "script-src/style-src",
# and a directive-shaped search over the whole file can read hashes from the
# wrong place (this mirrors update_style_csp.py's own policy-scoping).
POLICY_RE = re.compile(
    r"Content-Security-Policy:[ \t]*(?P<h>[^\n]+)"
    r"|CONTENT_SECURITY_POLICY\s*=\s*\"(?P<w>[^\"]+)\"")


def sha(body: str) -> str:
    return "sha256-" + base64.b64encode(
        hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii")


def inline_blocks(html: str):
    styles = re.findall(r"<style[^>]*>(.*?)</style>", html, re.S | re.I)
    scripts = [(attrs, body)
               for attrs, body in re.findall(
                   r"<script([^>]*)>(.*?)</script>", html, re.S | re.I)
               if not re.search(r"\bsrc\s*=", attrs, re.I)]
    return styles, scripts


def policy_spans(text: str):
    spans = []
    for m in POLICY_RE.finditer(text):
        key = "h" if m.group("h") is not None else "w"
        spans.append((m.start(key), m.end(key)))
    return spans


def policy_texts(text: str) -> list[str]:
    found = []
    for m in POLICY_RE.finditer(text):
        found.append((m.group("h") or m.group("w") or "").strip())
    return found


def _policy_syntax_errors(name: str, policy: str) -> list[str]:
    errors: list[str] = []
    if len(policy.encode("utf-8")) > 64 * 1024:
        return ["%s: Content-Security-Policy is oversized" % name]
    if any(ord(char) < 0x20 and char not in "\t" for char in policy):
        errors.append("%s: Content-Security-Policy contains a control byte" % name)
    seen: set[str] = set()
    for raw_directive in policy.split(";"):
        raw_directive = raw_directive.strip()
        if not raw_directive:
            continue
        parts = raw_directive.split()
        directive = parts[0]
        if DIRECTIVE_NAME_RE.fullmatch(directive) is None:
            errors.append("%s: malformed CSP directive name (%s)" %
                          (name, directive))
            continue
        if directive in seen:
            errors.append("%s: duplicate CSP directive (%s)" %
                          (name, directive))
        seen.add(directive)
        for source in parts[1:]:
            if NONFINITE_RE.fullmatch(source):
                errors.append("%s: non-finite CSP source (%s)" %
                              (name, source))
        if directive not in ALLOWED_NON_HASH_SOURCES:
            continue
        if len(parts) == 1:
            errors.append("%s: %s has no sources" % (name, directive))
        for source in parts[1:]:
            if HASH_RE.fullmatch(source):
                continue
            if source not in ALLOWED_NON_HASH_SOURCES[directive]:
                errors.append(
                    "%s: %s contains an unapproved fallback source (%s)" %
                    (name, directive, source))
    return errors


def pinned_hash_list(text: str, directive: str) -> tuple[list[str], int]:
    spans = policy_spans(text)
    found: list[str] = []
    seen = 0
    for m in re.finditer(r"%s ([^;]*)" % re.escape(directive), text):
        if not any(lo <= m.start() and m.end() <= hi for lo, hi in spans):
            continue  # a mention in prose, not the policy
        seen += 1
        for raw in HASH_RE.findall(m.group(1)):
            found.append(raw.strip("'"))
    return found, seen


def pinned_hashes(text: str, directive: str) -> set[str]:
    listed, _seen = pinned_hash_list(text, directive)
    return set(listed)


def _alias_error(path: pathlib.Path, web_dir: pathlib.Path) -> str | None:
    try:
        if path.is_symlink():
            return "%s: symbolic link is forbidden" % path.name
        if not path.exists():
            return "missing file: %s" % path.name
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode):
            return "%s: not a regular file" % path.name
        if st.st_nlink != 1:
            return "%s: hard link is forbidden" % path.name
        if path.name not in KNOWN_NAMES:
            return "%s: unexpected CSP path" % path.name
        if path.parent.resolve() != web_dir.resolve():
            return "%s: path substitution escapes web directory" % path.name
    except OSError as exc:
        return "%s: %s" % (path.name, exc)
    return None


def _read_regular(path: pathlib.Path, web_dir: pathlib.Path) -> bytes:
    err = _alias_error(path, web_dir)
    if err:
        raise OSError(err)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("%s: not a regular file" % path.name)
        if st.st_nlink != 1:
            raise OSError("%s: hard link is forbidden" % path.name)
        limit = MAX_FILE_BYTES[path.name]
        if st.st_size > limit:
            raise OSError("%s: file is oversized" % path.name)
        chunks = []
        total = 0
        while True:
            piece = os.read(fd, min(1024 * 1024, limit + 1))
            if not piece:
                break
            chunks.append(piece)
            total += len(piece)
            if total > limit:
                raise OSError("%s: file is oversized" % path.name)
        data = b"".join(chunks)
        if len(data) != st.st_size:
            raise OSError("%s mutated during read" % path.name)
        return data
    finally:
        os.close(fd)


def _pin_errors(host_name: str, listed: list[str], wanted: set[str],
                kind: str, tag: str) -> list[str]:
    errors: list[str] = []
    found = set(listed)
    if len(listed) != len(found):
        errors.append("%s: %s pins a duplicate hash" % (host_name, kind))
    for h in sorted(wanted - found):
        errors.append(
            "%s: %s is missing the pin for an inline %s block (%s)"
            % (host_name, kind, tag, h))
    for h in sorted(found - wanted):
        errors.append(
            "%s: %s pins %s but no current inline %s matches it"
            % (host_name, kind, h, tag))
    for h in listed:
        if PLACEHOLDER_PIN_RE.search(h) or VALID_HASH_RE.fullmatch(h) is None:
            errors.append(
                "%s: CSP hash pin is a placeholder or is not a "
                "SHA-256 digest (%s)" % (host_name, h))
    return errors


def check(web_dir: pathlib.Path) -> list[str]:
    web_dir = pathlib.Path(web_dir)
    errors: list[str] = []
    if not web_dir.is_dir() or web_dir.is_symlink():
        return ["WEB_DIR must be a real directory"]
    index = web_dir / INDEX_NAME
    hosts = tuple(web_dir / name for name in HOST_NAMES)
    for path in (index, *hosts):
        err = _alias_error(path, web_dir)
        if err:
            errors.append(err)
    if errors:
        return errors

    try:
        index_bytes = _read_regular(index, web_dir)
        host_bytes = {host: _read_regular(host, web_dir) for host in hosts}
    except OSError as exc:
        return [str(exc)]

    try:
        html = index_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return ["index.html is not valid UTF-8"]
    styles, scripts = inline_blocks(html)
    if len(styles) != 1:
        errors.append(
            "index.html: expected exactly one inline <style> block, found %d"
            % len(styles))
    want_style = {sha(s) for s in styles}
    want_scripts = {sha(body) for _, body in scripts}
    policies: dict[str, str] = {}
    for host in hosts:
        try:
            text = host_bytes[host].decode("utf-8")
        except UnicodeDecodeError:
            errors.append("%s is not valid UTF-8" % host.name)
            continue
        found_policies = policy_texts(text)
        if len(found_policies) != 1:
            errors.append(
                "%s: expected exactly one Content-Security-Policy, found %d"
                % (host.name, len(found_policies)))
            continue
        policy = found_policies[0]
        policies[host.name] = policy
        if PLACEHOLDER_POLICY_RE.search(policy):
            errors.append(
                "%s: CSP policy contains a redacted placeholder hash"
                % host.name)
        errors.extend(_policy_syntax_errors(host.name, policy))
        pinned_style, style_seen = pinned_hash_list(text, "style-src")
        pinned_script, script_seen = pinned_hash_list(text, "script-src")
        if style_seen != 1:
            errors.append(
                "%s: expected exactly one style-src in the policy, found %d"
                % (host.name, style_seen))
        if script_seen != 1:
            errors.append(
                "%s: expected exactly one script-src in the policy, found %d"
                % (host.name, script_seen))
        errors.extend(_pin_errors(
            host.name, pinned_style, want_style, "style-src", "<style>"))
        errors.extend(_pin_errors(
            host.name, pinned_script, want_scripts, "script-src", "<script>"))
    if (
            "_headers" in policies and "_worker.js" in policies
            and policies["_headers"] != policies["_worker.js"]):
        errors.append(
            "static/worker Content-Security-Policy bodies diverge")

    try:
        if _read_regular(index, web_dir) != index_bytes:
            errors.append("index.html mutated during preflight")
        for host in hosts:
            if _read_regular(host, web_dir) != host_bytes[host]:
                errors.append("%s mutated during preflight" % host.name)
    except OSError as exc:
        errors.append(str(exc))
    return errors


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    web_dir = WEB if not args else pathlib.Path(args[0])
    if len(args) > 1:
        print("usage: %s [WEB_DIR]" % pathlib.Path(sys.argv[0]).name,
              file=sys.stderr)
        return 2
    errors = check(web_dir)
    if errors:
        for e in errors:
            print("FAIL: %s" % e, file=sys.stderr)
        print("CSP inline <style>/<script> hash pins are STALE. "
              "Run `python3 web/update_style_csp.py` to resync, then re-run.",
              file=sys.stderr)
        return 1
    styles, scripts = inline_blocks(
        (web_dir / "index.html").read_text(encoding="utf-8"))
    n = len(styles); m = len(scripts)
    print("OK: %d inline <style> and %d inline <script> block(s) hash-pinned "
          "in _headers and _worker.js" % (n, m))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
