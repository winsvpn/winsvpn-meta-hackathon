#!/usr/bin/env python3
"""Fail fast on native-messaging manifests that would ship a placeholder.

    python3 tools/native_messaging/check_host_manifests.py

A standalone check of the host templates. extension/build.py no longer runs it:
the build checks the same identities per target with
extension/tools/assert_chrome_zip.py --native-identities and
extension/tools/assert_firefox_zip.py --check-host-identity. The three
templates under manifests/ are patterns a packager follows, and
`install_native_host.sh` is the place that substitutes the real extension id
into the FINAL manifest. This file closes the gap between the two: it refuses a
template that still names a placeholder, and it refuses a template whose value
disagrees with the recorded identity for its own target.

Where the store-listing ids come from, and why not inventing one matters:

  * Firefox: known. The gecko id the add-on ships with is its identity on
    addons.mozilla.org, so the canonical value is read from the manifest
    fragment and the template must match it exactly.
  * Chrome / Edge: the stores issue the 32-letter id when the listing exists,
    and it is stable for the life of the listing. The exact ids are recorded
    in the committed, reviewed file manifests/store_ids.json and read through
    render_host_manifest.py, which refuses a symlinked, hardlinked,
    group/world-writable, malformed, placeholder, or Chrome==Edge record. The
    same ids are recorded per target in
    extension/store_listings/store_identity.json, beside the listing name, the
    host template path and the exact allowlist; this file reads that record
    with the same bounded, bound-to-one-file read and the two must agree. No
    receipt, age or approval is read (owner ruling: AI-made expiry and receipt
    gates are out). WINSVPN_CHROME_STORE_ID / WINSVPN_EDGE_STORE_ID may only
    repeat the recorded ids. A template must name exactly the recorded id.
    PLACEHOLDER templates print developer diagnostics and then FAIL. A
    syntactically valid [a-p]{32} id that is not the recorded one FAILS here.
    A missing record value, a missing or inconsistent store identity record,
    and reused or swapped Chrome and Edge ids FAIL here and name the cause.
    This file never invents a store id or an approval.

A placeholder is the dangerous failure: a manifest naming
chrome-extension://PLACEHOLDER_... is syntactically fine, Chrome and Edge load
it without a word, and the host simply never answers. The bridge is silent,
and silence is the failure shape this project keeps finding.

Exit 0 = templates match the recorded store ids; Firefox matches the gecko id.
Exit 1 = refuse the build.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent / "extension" / "tools"))

import jsonc  # noqa: E402  (comment-tolerant loader, shared with the build)
import render_host_manifest as renderer  # noqa: E402

MANIFESTS = HERE / "manifests"
STORE_IDS_FILE = renderer.STORE_IDS_FILE
FIREFOX_FRAGMENT = renderer.FIREFOX_FRAGMENT
STORE_IDENTITY_FILE = renderer.REPO_ROOT / renderer.STORE_IDENTITY_RELATIVE
LISTING_NAMES = renderer.LISTING_NAMES

CHROMIUM_ID = re.compile(r"^[a-p]{32}$")
PLACEHOLDER = "PLACEHOLDER"

FAILED = False


def refuse(message: str) -> None:
    global FAILED
    FAILED = True
    print(f"  FAIL {message}")


def warn(message: str) -> None:
    print(f"  WARN {message}")


def canonical_firefox_id() -> str:
    try:
        return renderer.canonical_firefox_id()
    except ValueError as error:
        refuse(str(error))
        return ""


def recorded_store_identity() -> dict[str, str]:
    """Per-target ids from the checked-in store record. Never a receipt or an age."""
    invalid = renderer.OwnerIdentityInvalid
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        fd = os.open(STORE_IDENTITY_FILE, flags)
    except OSError as error:
        raise invalid(f"store identity record is unavailable: {STORE_IDENTITY_FILE}") from error
    try:
        info = os.fstat(fd)
        path_info = STORE_IDENTITY_FILE.lstat()
        if (
            stat.S_ISLNK(path_info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
            or info.st_nlink != 1
            or not 0 < info.st_size <= renderer.STORE_IDS_MAX_BYTES
        ):
            raise invalid("store identity record must be one bounded single-link regular file")
        payload = os.read(fd, info.st_size + 1)
        after = os.fstat(fd)
        if len(payload) != info.st_size or (
            info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns,
        ) != (
            after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns,
        ):
            raise invalid("store identity record changed while being read")
    except OSError as error:
        raise invalid("store identity record is unreadable") from error
    finally:
        os.close(fd)
    record = renderer._load_strict_json_object(payload, "store identity record")
    schema = record.get("schema_version")
    if (
        record.get("contract") != renderer.STORE_IDENTITY_CONTRACT
        or type(schema) is not int
        or schema != 1
        or record.get("native_host_name") != renderer.HOST_NAME
        or type(record.get("stores")) is not dict
    ):
        raise invalid("store identity record has an invalid schema")
    ids: dict[str, str] = {}
    for browser in ("chrome", "edge", "firefox"):
        entry = record["stores"].get(f"{browser}-extension-package")
        if type(entry) is not dict:
            raise invalid(f"{browser}: the store identity record has no entry")
        raw = renderer._exact_str(entry.get("store_id"), f"{browser} store id")
        extension_id = renderer.validated_extension_id(browser, raw)
        allowed = extension_id if browser == "firefox" else f"chrome-extension://{extension_id}/"
        if (
            raw != extension_id
            or entry.get("native_host_template")
            != f"tools/native_messaging/manifests/{renderer.HOST_NAME}.{browser}.json"
            or entry.get("native_host_allowlist") != [allowed]
            or (browser in LISTING_NAMES and entry.get("listing_name") != LISTING_NAMES[browser])
        ):
            raise invalid(f"{browser}: the store identity record is inconsistent")
        ids[browser] = extension_id
    if ids["chrome"] == ids["edge"]:
        raise invalid("Chrome and Edge store-listing ids must be distinct recorded identities")
    return ids


def known_ids() -> dict[str, str]:
    """Chrome/Edge ids recorded in manifests/store_ids.json, bound to store_identity.json.

    The committed compact record is read through the renderer, which also
    applies the environment corroboration; the per-target store identity record
    is read here. Both must name the same ids. Never a receipt or an age.
    """
    try:
        ids = renderer.owner_issued_chromium_ids()
        recorded = recorded_store_identity()
        listed = {"chrome": recorded["chrome"], "edge": recorded["edge"]}
        if listed != ids:
            raise renderer.OwnerIdentityInvalid(
                f"{STORE_IDS_FILE.name} and {STORE_IDENTITY_FILE.name} name different "
                "Chrome/Edge store ids; the recorded identities must agree"
            )
        return ids
    except (ValueError, OSError) as error:
        refuse(str(error))
        return {}


def distinct_bound_chromium_ids(ids: dict[str, str]) -> tuple[str | None, str | None]:
    chrome = ids.get("chrome") or None
    edge = ids.get("edge") or None
    if chrome or edge:
        if not chrome or not edge:
            refuse(
                "Chrome and Edge both need a recorded store id in "
                f"{STORE_IDS_FILE.name}; a partial record cannot be reused"
            )
            return None, None
        if chrome == edge:
            refuse(
                "Chrome and Edge store-listing ids must be distinct recorded identities"
            )
            return None, None
    return chrome, edge


def check_chromium(
    template: Path,
    browser: str,
    known: str | None,
    other_known: str | None = None,
) -> None:
    manifest = jsonc.load_file(template)
    origins = manifest.get("allowed_origins") or []
    expected = f"chrome-extension://{known}/" if known else ""
    if known:
        if not CHROMIUM_ID.fullmatch(known):
            refuse(f"{browser}: the recorded store id {known!r} is not 32 lowercase "
                   f"[a-p] letters -- refusing to build against it")
            return
        if other_known:
            other_origin = f"chrome-extension://{other_known}/"
            if other_origin in origins:
                refuse(
                    f"{browser}: allowed_origins reuses or swaps the other Chromium "
                    f"store identity {other_known!r}"
                )
                return
        if origins != [expected]:
            refuse(f"{browser}: allowed_origins is {origins!r}; the store-listing id "
                   f"{known!r} is on record, so the template must be exactly "
                   f"[{expected!r}]. A PLACEHOLDER here would install a manifest the "
                   f"browser accepts and the host never answers to.")
        else:
            print(f"  {browser}: allowed_origins names the recorded store id {known}")
        return
    for origin in origins:
        if not (isinstance(origin, str)
                and origin.startswith("chrome-extension://")
                and origin.endswith("/")):
            refuse(f"{browser}: allowed_origins entry {origin!r} is not a "
                   f"chrome-extension://<id>/ origin")
            continue
        inner = origin[len("chrome-extension://"):-1]
        if PLACEHOLDER in inner:
            warn(f"{browser}: allowed_origins still carries a placeholder and the "
                 f"store-listing id is NOT yet on record (record it as "
                 f"{browser!r} in {STORE_IDS_FILE.name} and in "
                 f"{STORE_IDENTITY_FILE.name}; WINSVPN_{browser.upper()}_STORE_ID "
                 f"may only repeat a recorded id). Developer diagnostics are "
                 f"preserved; Chrome/Edge remain owner-blocked.")
            refuse(f"{browser}: refused until {STORE_IDS_FILE.name} records the "
                   f"{browser} store id; placeholder native-host origins are not a "
                   f"release identity")
            continue
        if CHROMIUM_ID.fullmatch(inner):
            refuse(f"{browser}: allowed_origins names {inner!r} which is a "
                   f"syntactically valid store-id shape, but {STORE_IDS_FILE.name} "
                   f"records no {browser} id, so it is not bound to a recorded store "
                   f"identity. Refusing an arbitrary "
                   f"[a-p]{{32}} substitute.")
            continue
        refuse(f"{browser}: allowed_origins entry {origin!r} is not a "
               f"chrome-extension://<id>/ origin")


def main() -> int:
    firefox_id = canonical_firefox_id()
    if not firefox_id:
        refuse(f"firefox: no gecko id found in {FIREFOX_FRAGMENT}")
    ids = known_ids()
    chrome_id, edge_id = distinct_bound_chromium_ids(ids)

    firefox_tpl = MANIFESTS / "org.winsvpn.bridge.firefox.json"
    if firefox_tpl.is_file() and firefox_id:
        manifest = jsonc.load_file(firefox_tpl)
        allowed = manifest.get("allowed_extensions") or []
        if allowed != [firefox_id]:
            refuse(f"firefox: allowed_extensions is {allowed!r}; the canonical gecko id "
                   f"is {firefox_id!r} ({FIREFOX_FRAGMENT.name}) and the two must agree -- "
                   f"Firefox refuses the host with no user-visible error if they do not")
        else:
            print(f"  firefox: allowed_extensions matches the canonical gecko id {firefox_id}")
    elif firefox_id:
        refuse(f"firefox: host template missing: {firefox_tpl}")

    for browser in ("chrome", "edge"):
        template = MANIFESTS / f"org.winsvpn.bridge.{browser}.json"
        if not template.is_file():
            refuse(f"{browser}: host template missing: {template}")
            continue
        check_chromium(
            template,
            browser,
            chrome_id if browser == "chrome" else edge_id,
            other_known=(edge_id if browser == "chrome" else chrome_id),
        )

    print("  result:", "REFUSED (a Chrome/Edge store id is not recorded in store_ids.json, a template disagrees with it, or a placeholder is shipping against a known id)"
          if FAILED else "ok")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
