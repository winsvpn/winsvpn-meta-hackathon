#!/usr/bin/env python3
"""Recompute the inline <style> AND inline <script> CSP hashes and sync them into
_headers and _worker.js.

The site whitelists its inline stylesheet and its inline executable script by
SHA-256 in the Content-Security-Policy. ANY edit to the <style> block OR to the
main inline <script> changes its hash, and a stale hash makes the browser drop
that resource:

  * stale style hash  -> the page renders as unstyled HTML
  * stale script hash -> the entire page's JavaScript is blocked (language
    switching, demos, payment buttons, AI chat all die)

The application/ld+json block is data, not executable script, so its hash never
needs to change unless that block is edited; it is handled here too for
completeness.

A secret-scrubber that treats 32-byte base64 pins as WireGuard keys can rewrite
live or packaged policies to 'sha256-<REDACTED_WG_KEY>'. This updater matches
those leftover placeholder tokens, replaces every sha256 source in style-src
and script-src with the exact current inline hashes, writes both hosts
atomically, and fail-closes (restoring original bytes) on any partial rewrite.

Run this after ANY edit to index.html's <style> or <script>, before deploying:

    python3 update_style_csp.py && wrangler pages deploy . --project-name=winsvpn --branch=main
"""
from __future__ import annotations

import base64
import hashlib
import os
import pathlib
import re
import stat
import sys
import tempfile

WEB = pathlib.Path(__file__).resolve().parent
INDEX = WEB / "index.html"
TARGETS = [WEB / "_headers", WEB / "_worker.js"]
INDEX_NAME = "index.html"
TARGET_NAMES = ("_headers", "_worker.js")
KNOWN_NAMES = {INDEX_NAME, *TARGET_NAMES}
MAX_FILE_BYTES = {
    INDEX_NAME: 8 * 1024 * 1024,
    "_headers": 1024 * 1024,
    "_worker.js": 1024 * 1024,
}


class CspUpdateError(Exception):
    """Fail-closed CSP regeneration error. Never leaves a half-written pair."""


def sha(s: str) -> str:
    return "sha256-" + base64.b64encode(
        hashlib.sha256(s.encode("utf-8")).digest()).decode("ascii")


# Reconcile each CSP directive against the hashes that belong in *that*
# directive.
#
# This used to work on one flat set of hashes per file and pair stale against
# missing by sorted order. When the <style> block and the <script> block both
# changed in the same edit, that pairing was effectively random: on 2026-08-03
# it put the stylesheet's hash into script-src and the script's hash into
# style-src, then reported success, because the verification below only asked
# whether each hash appeared *somewhere* in the file. The result would have been
# a page with both its stylesheet and its main script blocked. Hashes are now
# matched to their own directive, and the verification checks placement.
# Match current pins and leftover placeholder tokens such as
# 'sha256-<REDACTED_WG_KEY>' so they are replaced, not left in the policy.
HASH_TOKEN_RE = re.compile(r"'sha256-[^']+'")
VALID_HASH_RE = re.compile(r"sha256-[A-Za-z0-9+/]{43}=")
PLACEHOLDER_POLICY_RE = re.compile(
    r"(?i)sha256-<|redacted_wg_key|<redacted|placeholder_hash")
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

# The policy text itself, and nothing else in the file. _headers carries it on a
# `Content-Security-Policy:` line; _worker.js carries it in a
# `const CONTENT_SECURITY_POLICY = "..."`. Scoping to these is not fussiness:
# _worker.js has a prose comment containing the words "script-src/style-src",
# and a directive-shaped search over the whole file rewrites that comment.
POLICY_RE = re.compile(
    r"Content-Security-Policy:[ \t]*(?P<h>[^\n]+)"
    r"|CONTENT_SECURITY_POLICY\s*=\s*\"(?P<w>[^\"]+)\"")
DIRECTIVE_RE_TMPL = r"(%s )([^;\"']*(?:'[^']*'[^;\"']*)*)"


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
            if HASH_TOKEN_RE.fullmatch(source):
                continue
            if source not in ALLOWED_NON_HASH_SOURCES[directive]:
                errors.append(
                    "%s: %s contains an unapproved fallback source (%s)" %
                    (name, directive, source))
    return errors


def _is_sha256_source(token: str) -> bool:
    if HASH_TOKEN_RE.fullmatch(token):
        return True
    return token.strip("'").startswith("sha256-")


def set_directive_hashes(text: str, directive: str, wanted_hashes: set[str]):
    """Replace the sha256 sources inside one CSP directive, leaving the rest."""
    spans = policy_spans(text)
    if not spans:
        raise CspUpdateError("no Content-Security-Policy found to update")
    out, n = [], 0
    pos = 0
    for m in re.finditer(DIRECTIVE_RE_TMPL % re.escape(directive), text):
        if not any(lo <= m.start() and m.end() <= hi for lo, hi in spans):
            continue          # a mention of the directive in prose, not the policy
        body = m.group(2)
        sources = [s for s in body.split() if not _is_sha256_source(s)]
        wanted = ["'%s'" % h for h in sorted(wanted_hashes)]
        if sources and sources[0] == "'self'":
            rebuilt = ["'self'"] + wanted + sources[1:]
        else:
            rebuilt = wanted + sources
        new_body = " ".join(rebuilt)
        if new_body != body.strip():
            n += 1
        out.append(text[pos:m.start(2)])
        out.append(new_body)
        pos = m.end(2)
    out.append(text[pos:])
    return "".join(out), n


def wanted_hashes(html: str) -> tuple[str, set[str]]:
    styles = re.findall(r"<style[^>]*>(.*?)</style>", html, re.S | re.I)
    if len(styles) != 1:
        raise CspUpdateError(
            "expected exactly 1 inline <style> block, found %d" % len(styles))
    want_style = sha(styles[0])
    inline = [
        (a, b) for a, b in re.findall(
            r"<script([^>]*)>(.*?)</script>", html, re.S | re.I)
        if not re.search(r"\bsrc\s*=", a, re.I)
    ]
    want_scripts = {sha(body) for _, body in inline}
    for label, digest in (("style", want_style), *[
            ("script", h) for h in want_scripts]):
        if VALID_HASH_RE.fullmatch(digest) is None:
            raise CspUpdateError(
                "internal error: computed %s hash is not a SHA-256 digest"
                % label)
    return want_style, want_scripts


def _directive_hash_list(text: str, directive: str) -> list[str]:
    spans = policy_spans(text)
    found: list[str] = []
    seen = 0
    for m in re.finditer(r"%s ([^;]*)" % re.escape(directive), text):
        if not any(lo <= m.start() and m.end() <= hi for lo, hi in spans):
            continue
        seen += 1
        for raw in HASH_TOKEN_RE.findall(m.group(1)):
            found.append(raw.strip("'"))
    if seen == 0:
        raise CspUpdateError("no %s directive found in the policy" % directive)
    if seen != 1:
        raise CspUpdateError(
            "expected exactly one %s in the policy, found %d"
            % (directive, seen))
    return found


def _verify_text(
        name: str, text: str, want_style: set[str],
        want_scripts: set[str]) -> list[str]:
    errors: list[str] = []
    policies = policy_texts(text)
    if len(policies) != 1:
        errors.append(
            "%s: expected exactly one Content-Security-Policy, found %d"
            % (name, len(policies)))
        return errors
    if PLACEHOLDER_POLICY_RE.search(policies[0]):
        errors.append(
            "%s: CSP policy contains a redacted placeholder hash" % name)
    errors.extend(_policy_syntax_errors(name, policies[0]))
    for directive, wanted in (
            ("style-src", want_style), ("script-src", want_scripts)):
        try:
            listed = _directive_hash_list(text, directive)
        except CspUpdateError as exc:
            errors.append("%s: %s" % (name, exc))
            continue
        if len(listed) != len(set(listed)):
            errors.append("%s %s: duplicate hash pin" % (name, directive))
        found = set(listed)
        if found != wanted:
            errors.append(
                "%s %s: has %s, wanted %s"
                % (name, directive, sorted(found) or "no hashes",
                   sorted(wanted)))
        for h in listed:
            if VALID_HASH_RE.fullmatch(h) is None:
                errors.append(
                    "%s: CSP hash pin is a placeholder or is not a "
                    "SHA-256 digest (%s)" % (name, h))
    return errors


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


def _assert_direct_regular_file(
        path: pathlib.Path, web_dir: pathlib.Path) -> None:
    err = _alias_error(path, web_dir)
    if err:
        raise CspUpdateError(err)


def _read_regular(path: pathlib.Path, web_dir: pathlib.Path) -> bytes:
    _assert_direct_regular_file(path, web_dir)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CspUpdateError("%s: not a regular file" % path.name)
        if st.st_nlink != 1:
            raise CspUpdateError("%s: hard link is forbidden" % path.name)
        limit = MAX_FILE_BYTES[path.name]
        if st.st_size > limit:
            raise CspUpdateError("%s: file is oversized" % path.name)
        chunks = []
        total = 0
        while True:
            piece = os.read(fd, min(1024 * 1024, limit + 1))
            if not piece:
                break
            chunks.append(piece)
            total += len(piece)
            if total > limit:
                raise CspUpdateError("%s: file is oversized" % path.name)
        data = b"".join(chunks)
        if len(data) != st.st_size:
            raise CspUpdateError("%s mutated during read" % path.name)
        return data
    finally:
        os.close(fd)


def _atomic_write(
        path: pathlib.Path, data: bytes, web_dir: pathlib.Path) -> None:
    _assert_direct_regular_file(path, web_dir)
    mode = stat.S_IMODE(path.lstat().st_mode)
    directory = path.parent
    fd, tmp_name = tempfile.mkstemp(
        prefix=".%s." % path.name, suffix=".tmp", dir=str(directory))
    tmp_path = pathlib.Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(str(tmp_path), str(path))
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        try:
            if tmp_path.exists() and not tmp_path.is_symlink():
                tmp_path.unlink()
        except OSError:
            pass
        raise


def _restore_committed(
        committed: list[pathlib.Path], originals: dict[pathlib.Path, bytes],
        web_dir: pathlib.Path, exc: BaseException) -> None:
    rollback_fail = []
    for path in committed:
        try:
            _atomic_write(path, originals[path], web_dir)
        except Exception as rex:
            rollback_fail.append("%s: %s" % (path.name, rex))
    if rollback_fail:
        raise CspUpdateError(
            "partial rewrite; rollback failed (%s); original error: %s"
            % ("; ".join(rollback_fail), exc)) from exc
    if not committed:
        if isinstance(exc, CspUpdateError):
            raise exc
        raise CspUpdateError(str(exc)) from exc
    raise CspUpdateError(
        "partial rewrite; original bytes restored (%s)" % exc) from exc


def sync_web_dir(web_dir: pathlib.Path) -> None:
    web_dir = pathlib.Path(web_dir)
    if not web_dir.is_dir() or web_dir.is_symlink():
        raise CspUpdateError("WEB_DIR must be a real directory")
    index = web_dir / INDEX_NAME
    targets = [web_dir / name for name in TARGET_NAMES]
    for path in [index, *targets]:
        _assert_direct_regular_file(path, web_dir)

    index_bytes = _read_regular(index, web_dir)
    try:
        index_text = index_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CspUpdateError("index.html is not valid UTF-8") from exc
    want_style, want_scripts = wanted_hashes(index_text)
    want_style_set = {want_style}

    print("want style          : %s" % want_style)
    for h in sorted(want_scripts):
        print("want script         : %s" % h)

    originals: dict[pathlib.Path, bytes] = {}
    planned: dict[pathlib.Path, bytes] = {}
    counts: dict[pathlib.Path, int] = {}
    for path in targets:
        original = _read_regular(path, web_dir)
        originals[path] = original
        try:
            text = original.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CspUpdateError("%s is not valid UTF-8" % path.name) from exc
        text, a = set_directive_hashes(text, "style-src", want_style_set)
        text, b = set_directive_hashes(text, "script-src", want_scripts)
        errors = _verify_text(path.name, text, want_style_set, want_scripts)
        if errors:
            raise CspUpdateError("\n  ".join(errors))
        planned[path] = text.encode("utf-8")
        counts[path] = a + b
        if planned[path] == original:
            print("  %-12s already in sync" % path.name)

    planned_policies = [
        policy_texts(planned[path].decode("utf-8"))[0] for path in targets]
    if planned_policies[0] != planned_policies[1]:
        raise CspUpdateError(
            "static/worker Content-Security-Policy bodies diverge")

    if _read_regular(index, web_dir) != index_bytes:
        raise CspUpdateError("index.html mutated during CSP regeneration")
    for path in targets:
        if _read_regular(path, web_dir) != originals[path]:
            raise CspUpdateError(
                "%s mutated during CSP regeneration" % path.name)

    committed: list[pathlib.Path] = []
    try:
        for path in targets:
            if planned[path] == originals[path]:
                continue
            _atomic_write(path, planned[path], web_dir)
            committed.append(path)
            print("  %-12s updated %d directive(s)"
                  % (path.name, counts[path]))
        for path in targets:
            disk = _read_regular(path, web_dir)
            if disk != planned[path]:
                raise CspUpdateError(
                    "%s did not persist planned CSP bytes" % path.name)
            errors = _verify_text(
                path.name, disk.decode("utf-8"), want_style_set, want_scripts)
            if errors:
                raise CspUpdateError("\n  ".join(errors))
        if _read_regular(index, web_dir) != index_bytes:
            raise CspUpdateError("index.html mutated during CSP regeneration")
    except Exception as exc:
        _restore_committed(committed, originals, web_dir, exc)

    changed = any(planned[path] != originals[path] for path in targets)
    print("in sync" if changed else "nothing to change")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) > 1:
        print("usage: %s [WEB_DIR]" % pathlib.Path(sys.argv[0]).name,
              file=sys.stderr)
        return 2
    web_dir = WEB if not args else pathlib.Path(args[0])
    try:
        sync_web_dir(web_dir)
    except CspUpdateError as exc:
        print("FAILED:\n  %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
