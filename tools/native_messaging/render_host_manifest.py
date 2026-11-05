#!/usr/bin/env python3
"""Render one final native-messaging host manifest, never a placeholder.

The checked-in JSON files are documentation/templates. Release installers call
this renderer with the store-issued extension identity and the exact installed
host path. Keeping rendering here gives Windows, macOS and Linux one validation
rule and makes the final JSON independently testable.

Chrome and Edge store ids are never invented here. They come only from the
committed, reviewed record manifests/store_ids.json (strict JSON, exact
[a-p]{32} ids, Chrome distinct from Edge, no placeholder). The record must be
one single-link regular file, not a symlink, and neither it nor its directory
may be group- or world-writable. A browser whose id the record does not carry
is refused with a message naming the missing value; the other browsers still
render. The record is opened without following a link or blocking, bound to
the checked path, read once with a size bound, and refused if it changed while
it was read. Where the per-target listing record
extension/store_listings/store_identity.json is present (a source checkout),
it must be valid and every recorded id must agree with it; an installed
package ships only the compact record. WINSVPN_CHROME_STORE_ID /
WINSVPN_EDGE_STORE_ID and --extension-id may only repeat the recorded id,
never supply or replace it. Identity resolution does not require an expiring
owner receipt. Firefox's add-on id is pinned.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
_EXT_TOOLS = HERE.parents[1] / "extension" / "tools"
if str(_EXT_TOOLS) not in sys.path:
    sys.path.insert(0, str(_EXT_TOOLS))

import jsonc  # noqa: E402  (comment-tolerant loader shared with the extension build)

HOST_NAME = "org.winsvpn.bridge"
FIREFOX_ID = "companion@winsvpn.org"
FIREFOX_FRAGMENT = HERE.parents[1] / "extension" / "manifest" / "firefox.jsonc"
STORE_IDS_FILE = HERE / "manifests" / "store_ids.json"
REPO_ROOT = HERE.parents[1]
CHROMIUM_ID = re.compile(r"^[a-p]{32}$")
PLACEHOLDER = re.compile(r"placeholder", re.IGNORECASE)
STORE_ID_ENV = {
    "chrome": "WINSVPN_CHROME_STORE_ID",
    "edge": "WINSVPN_EDGE_STORE_ID",
}
MISSING_STORE_ID_EXIT = 78
CHROMIUM_BROWSERS = ("chrome", "edge")
STORE_IDS_MAX_BYTES = 64 * 1024
STORE_IDS_RELATIVE = "tools/native_messaging/manifests/store_ids.json"
STORE_IDENTITY_CONTRACT = "winsvpn-browser-extension-store-identity-v1"
STORE_IDENTITY_RELATIVE = "extension/store_listings/store_identity.json"
LISTING_NAMES = {
    "chrome": "Win's VPN Proxy for Chrome",
    "edge": "Win's VPN Proxy for Microsoft Edge",
}


class OwnerIdentityBlocked(ValueError):
    """A Chrome or Edge id is not recorded in manifests/store_ids.json."""


class OwnerIdentityInvalid(ValueError):
    """The store id record is unsafe, malformed, or contradicted by a caller."""


def store_id_env_name(browser: str) -> str:
    if browser not in STORE_ID_ENV:
        raise ValueError(f"unsupported browser {browser!r}")
    return STORE_ID_ENV[browser]


def canonical_firefox_id() -> str:
    """Pinned add-on id, refused if firefox.jsonc's gecko.id disagrees."""
    if FIREFOX_FRAGMENT.is_file():
        fragment = jsonc.load_file(FIREFOX_FRAGMENT)
        gecko_id = (
            ((fragment.get("browser_specific_settings") or {}).get("gecko")) or {}
        ).get("id")
        if gecko_id != FIREFOX_ID:
            raise ValueError(
                f"{FIREFOX_FRAGMENT} gecko.id is {gecko_id!r}; the pinned "
                f"add-on id is {FIREFOX_ID!r}. Refusing to render a "
                "disagreeing host manifest."
            )
    return FIREFOX_ID


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]], label: str
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OwnerIdentityInvalid(f"{label} has a duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_strict_json_object(data: bytes, label: str) -> dict[str, object]:
    if not data or len(data) > STORE_IDS_MAX_BYTES:
        raise OwnerIdentityInvalid(f"{label} exceeds the reviewed JSON size ceiling")
    try:
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=lambda pairs: _reject_duplicate_json_keys(pairs, label),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise OwnerIdentityInvalid(f"{label} is not valid UTF-8 JSON") from error
    if type(document) is not dict:
        raise OwnerIdentityInvalid(f"{label} must be one JSON object")
    return document


def _exact_str(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise OwnerIdentityInvalid(f"{label} must be a non-empty JSON string")
    return value


def missing_store_id_message(browser: str) -> str:
    return (
        f"{browser} store-listing id is missing: {STORE_IDS_RELATIVE} has no "
        f"{browser!r} value. Record the 32-letter [a-p] {browser} store id there. "
        "Refusing to invent one."
    )


def _store_ids_unsafe(reason: str) -> OwnerIdentityInvalid:
    return OwnerIdentityInvalid(f"native-host store id record {STORE_IDS_RELATIVE} {reason}")


def _store_ids_directory_present(path: Path) -> bool:
    """False when the record's directory is absent; refuses an unsafe directory."""
    try:
        parent_info = os.lstat(path.parent)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise _store_ids_unsafe("directory is unreadable") from error
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise _store_ids_unsafe("directory must be a real directory, not a symlink")
    if os.name != "nt" and stat.S_IMODE(parent_info.st_mode) & 0o022:
        raise _store_ids_unsafe("directory must not be group- or world-writable")
    return True


def _read_store_ids_bytes(path: Path) -> bytes | None:
    """Read the committed record without following a link. None when absent.

    The record is opened with O_NOFOLLOW and O_NONBLOCK, so a symlink or a FIFO
    cannot be followed or block. The descriptor must be the file the path
    names, one regular single-link file of 1 to STORE_IDS_MAX_BYTES bytes, and
    not group- or world-writable; all of that is checked before any byte is
    read. One bounded read must return exactly st_size bytes, and the size,
    inode, mtime and ctime must be unchanged afterwards.
    """
    if not _store_ids_directory_present(path):
        return None
    flags = (
        os.O_RDONLY
        | _cloexec()
        | _nonblock()
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise _store_ids_unsafe("must not be a symlink") from error
        raise _store_ids_unsafe("is unreadable") from error
    try:
        info = os.fstat(fd)
        path_info = path.lstat()
        if stat.S_ISLNK(path_info.st_mode):
            raise _store_ids_unsafe("must not be a symlink")
        if not stat.S_ISREG(info.st_mode):
            raise _store_ids_unsafe("must be a regular file")
        if (
            (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
            or info.st_nlink != 1
            or not 0 < info.st_size <= STORE_IDS_MAX_BYTES
        ):
            raise _store_ids_unsafe(
                "must be one non-empty, bounded single-link regular file (no hardlink)"
            )
        if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o022:
            raise _store_ids_unsafe("must not be group- or world-writable")
        payload = os.read(fd, info.st_size + 1)
        after = os.fstat(fd)
        if len(payload) != info.st_size or (
            info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns,
        ) != (
            after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns,
        ):
            raise _store_ids_unsafe("changed while it was read")
    except OSError as error:
        raise _store_ids_unsafe("is unreadable") from error
    finally:
        os.close(fd)
    return payload


def _load_store_ids_file() -> dict[str, str] | None:
    """Committed Chrome/Edge ids. A browser absent from the record is omitted."""
    data = _read_store_ids_bytes(STORE_IDS_FILE)
    if data is None:
        return None
    document = _load_strict_json_object(data, "native-host store id record")
    unexpected = sorted(set(document) - set(CHROMIUM_BROWSERS))
    if unexpected:
        raise _store_ids_unsafe(
            "has unexpected fields: " + ", ".join(repr(key) for key in unexpected)
        )
    ids: dict[str, str] = {}
    for browser in CHROMIUM_BROWSERS:
        if browser not in document:
            continue
        raw = _exact_str(document[browser], f"native-host store id {browser}")
        value = validated_extension_id(browser, raw)
        if value != raw:
            raise _store_ids_unsafe(
                f"{browser} id carries surrounding whitespace; it must be exact and unpadded"
            )
        ids[browser] = value
    if "chrome" in ids and "edge" in ids and ids["chrome"] == ids["edge"]:
        raise _store_ids_unsafe(
            "names the same id for Chrome and Edge; they are distinct store listings"
        )
    return ids


def _load_store_identity_listing() -> dict[str, str] | None:
    """Chrome/Edge ids from extension/store_listings/store_identity.json.

    None when the listing record is absent (an installed package). A present
    record must be one bounded regular file with the exact schema, and each
    target's id, listing name, host template and allowlist must agree.
    """
    listing = REPO_ROOT / STORE_IDENTITY_RELATIVE
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(listing, flags)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise OwnerIdentityInvalid("store identity record is unreadable") from error
    try:
        info = os.fstat(fd)
        path_info = listing.lstat()
        if (
            stat.S_ISLNK(path_info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
            or info.st_nlink != 1
            or not 0 < info.st_size <= STORE_IDS_MAX_BYTES
        ):
            raise OwnerIdentityInvalid(
                "store identity record is not a regular bounded file"
            )
        payload = os.read(fd, info.st_size + 1)
        after = os.fstat(fd)
        if len(payload) != info.st_size or (
            info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns
        ) != (
            after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns
        ):
            raise OwnerIdentityInvalid(
                "store identity record changed while being read"
            )
    finally:
        os.close(fd)
    record = _load_strict_json_object(payload, "store identity record")
    if (
        record.get("contract") != STORE_IDENTITY_CONTRACT
        or type(record.get("schema_version")) is not int
        or record["schema_version"] != 1
        or record.get("native_host_name") != HOST_NAME
        or type(record.get("stores")) is not dict
    ):
        raise OwnerIdentityInvalid("store identity record has an invalid schema")
    listed: dict[str, str] = {}
    for browser, name in LISTING_NAMES.items():
        entry = record["stores"].get(f"{browser}-extension-package")
        if type(entry) is not dict:
            raise OwnerIdentityInvalid(f"{browser} store identity is missing")
        raw = _exact_str(entry.get("store_id"), f"{browser} store id")
        extension_id = validated_extension_id(browser, raw)
        if (
            raw != extension_id
            or entry.get("listing_name") != name
            or entry.get("native_host_template")
            != f"tools/native_messaging/manifests/org.winsvpn.bridge.{browser}.json"
            or entry.get("native_host_allowlist")
            != [f"chrome-extension://{extension_id}/"]
        ):
            raise OwnerIdentityInvalid(f"{browser} store identity is inconsistent")
        listed[browser] = extension_id
    if listed["chrome"] == listed["edge"]:
        raise OwnerIdentityInvalid("Chrome and Edge store identities must be distinct")
    return listed


def _env_store_ids() -> dict[str, str]:
    ids: dict[str, str] = {}
    for browser, env_name in STORE_ID_ENV.items():
        value = os.environ.get(env_name, "").strip()
        if value:
            ids[browser] = validated_extension_id(browser, value)
    return ids


def _corroborate_env_ids(recorded: dict[str, str]) -> None:
    for browser, value in _env_store_ids().items():
        if browser not in recorded:
            raise OwnerIdentityInvalid(
                f"{store_id_env_name(browser)} cannot supply an id that "
                f"{STORE_IDS_RELATIVE} does not record. "
                + missing_store_id_message(browser)
            )
        if value != recorded[browser]:
            raise OwnerIdentityInvalid(
                f"{store_id_env_name(browser)} does not match the {browser} id "
                f"recorded in {STORE_IDS_RELATIVE}"
            )


def recorded_store_ids() -> dict[str, str]:
    """Chrome/Edge ids from the committed record. Never synthesised.

    Where the listing record is present, every recorded id must agree with it.
    """
    recorded = _load_store_ids_file() or {}
    listed = _load_store_identity_listing()
    if listed is not None:
        for browser, value in recorded.items():
            if listed[browser] != value:
                raise OwnerIdentityInvalid(
                    f"packaged store ids disagree with the store identity record: "
                    f"{STORE_IDS_RELATIVE} {browser} is not the {browser} id in "
                    f"{STORE_IDENTITY_RELATIVE}"
                )
    _corroborate_env_ids(recorded)
    return dict(recorded)


def owner_issued_chromium_ids() -> dict[str, str]:
    """Both recorded Chrome and Edge ids, for producers that package both.

    The name is kept for the packaging gates that call it. A missing id raises
    OwnerIdentityBlocked naming the missing value.
    """
    ids = recorded_store_ids()
    missing = [browser for browser in CHROMIUM_BROWSERS if browser not in ids]
    if missing:
        raise OwnerIdentityBlocked(
            " ".join(missing_store_id_message(browser) for browser in missing)
        )
    return {"chrome": ids["chrome"], "edge": ids["edge"]}


def recorded_extension_id(browser: str) -> str | None:
    if browser == "firefox":
        return canonical_firefox_id()
    if browser not in CHROMIUM_BROWSERS:
        raise ValueError(f"unsupported browser {browser!r}")
    return recorded_store_ids().get(browser)


def validated_extension_id(browser: str, value: str) -> str:
    extension_id = value.strip()
    if not extension_id or PLACEHOLDER.search(extension_id):
        raise ValueError(f"{browser} extension id is missing or is a placeholder")
    if browser in {"chrome", "edge"}:
        if not CHROMIUM_ID.fullmatch(extension_id):
            raise ValueError(
                f"{browser} extension id must be exactly 32 lowercase [a-p] letters"
            )
    elif browser == "firefox":
        if extension_id != canonical_firefox_id():
            raise ValueError(
                f"firefox extension id must be the pinned add-on id {FIREFOX_ID!r}"
            )
    else:
        raise ValueError(f"unsupported browser {browser!r}")
    return extension_id


def validated_host_path(value: str, *, allow_relative: bool) -> str:
    host_path = value.strip()
    if not host_path or "\x00" in host_path or "\n" in host_path or "\r" in host_path:
        raise ValueError("host path is empty or contains a control character")
    if PLACEHOLDER.search(host_path):
        raise ValueError("host path is still a placeholder")
    if not allow_relative and not Path(host_path).is_absolute():
        raise ValueError("host path must be absolute on macOS and Linux")
    return host_path


def manifest_for(
    browser: str,
    extension_id: str,
    host_path: str,
    *,
    allow_relative_host_path: bool = False,
) -> dict[str, object]:
    extension_id = validated_extension_id(browser, extension_id)
    host_path = validated_host_path(host_path, allow_relative=allow_relative_host_path)
    manifest: dict[str, object] = {
        "name": HOST_NAME,
        "description": "Win's VPN browser bridge",
        "path": host_path,
        "type": "stdio",
    }
    if browser in {"chrome", "edge"}:
        manifest["allowed_origins"] = [f"chrome-extension://{extension_id}/"]
    else:
        manifest["allowed_extensions"] = [extension_id]
    return manifest


def _is_special_node(info: os.stat_result) -> bool:
    mode = info.st_mode
    return bool(
        stat.S_ISFIFO(mode)
        or stat.S_ISCHR(mode)
        or stat.S_ISBLK(mode)
        or stat.S_ISSOCK(mode)
    )


def _identity(info: os.stat_result) -> tuple[int, int]:
    return (info.st_dev, info.st_ino)


def _posix_symlink_is_replaceable(info: os.stat_result) -> bool:
    if info.st_uid == os.getuid():
        return True
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o002:
        return True
    if mode & 0o020:
        try:
            groups = os.getgroups()
        except OSError:
            return True
        if info.st_gid in groups or info.st_gid == os.getgid():
            return True
    return False


def _cloexec() -> int:
    return getattr(os, "O_CLOEXEC", 0)


def _nonblock() -> int:
    return getattr(os, "O_NONBLOCK", 0)


def posix_abs_path(path: str, *, label: str = "native-host path") -> str:
    if not path or "\x00" in path:
        raise OSError(label + " is invalid")
    absolute = path if path.startswith("/") else os.path.abspath(path)
    while absolute != "/" and absolute.endswith("/"):
        absolute = absolute[:-1]
    if not absolute.startswith("/"):
        raise OSError(label + " is not absolute")
    return absolute


def posix_abs_parts(path: str, *, label: str = "native-host path") -> list[str]:
    absolute = posix_abs_path(path, label=label)
    if absolute == "/":
        return []
    parts = absolute.split("/")[1:]
    if any(part in {"", ".", ".."} for part in parts):
        raise OSError(label + " has an empty, dot, or dot-dot component")
    return parts


def _posix_abs_parts(path: str) -> list[str]:
    return posix_abs_parts(path, label="native-host manifest path")


def _directory_bind_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise OSError("native-host path bind requires O_NOFOLLOW and O_DIRECTORY")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | _cloexec()


def _file_read_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("native-host path bind requires O_NOFOLLOW")
    return os.O_RDONLY | os.O_NOFOLLOW | _nonblock() | _cloexec()


def _file_excl_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("native-host path bind requires O_NOFOLLOW")
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | _nonblock()
        | _cloexec()
    )


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _copy_fd(src_fd: int, dst_fd: int) -> None:
    while True:
        chunk = os.read(src_fd, 1024 * 1024)
        if not chunk:
            return
        _write_all(dst_fd, chunk)


def _open_root_dir() -> int:
    return os.open("/", os.O_RDONLY | os.O_DIRECTORY | _cloexec())


def bind_posix_directory(path: str, *, create_missing: bool, label: str = "native-host directory") -> int:
    """Walk path from / with O_NOFOLLOW. Caller closes the returned directory fd."""
    parts = posix_abs_parts(path, label=label)
    if not parts:
        raise OSError(label + " must not be /")
    flags = _directory_bind_flags()
    follow_dir_flags = os.O_RDONLY | os.O_DIRECTORY | _cloexec()
    current = _open_root_dir()
    built = ""
    try:
        for index, name in enumerate(parts):
            built += "/" + name
            last = index == len(parts) - 1
            try:
                info = os.lstat(name, dir_fd=current)
            except FileNotFoundError:
                if not create_missing:
                    raise OSError(label + " is missing: " + built) from None
                try:
                    os.mkdir(name, 0o755, dir_fd=current)
                except FileExistsError:
                    pass
                info = os.lstat(name, dir_fd=current)
            if stat.S_ISLNK(info.st_mode):
                if last or _posix_symlink_is_replaceable(info):
                    raise OSError("refusing intermediate symlink native-host path " + built)
                nxt = os.open(name, follow_dir_flags, dir_fd=current)
            else:
                if _is_special_node(info):
                    raise OSError(label + " is a special file: " + built)
                if not stat.S_ISDIR(info.st_mode):
                    raise OSError(
                        "refusing non-directory intermediate native-host path " + built
                    )
                nxt = os.open(name, flags, dir_fd=current)
            opened = os.fstat(nxt)
            if not stat.S_ISDIR(opened.st_mode) or _is_special_node(opened):
                os.close(nxt)
                raise OSError(label + " is a special file: " + built)
            if not stat.S_ISLNK(info.st_mode) and _identity(opened) != _identity(info):
                os.close(nxt)
                raise OSError(label + " changed while it was bound")
            os.close(current)
            current = nxt
        return current
    except Exception:
        os.close(current)
        raise


def _bind_manifest_dir(parent: str, *, create_missing: bool) -> int:
    return bind_posix_directory(
        parent, create_missing=create_missing, label="native-host manifest directory"
    )


def _inspect_leaf(parent_fd: int, name: str, built: str, *, kind: str) -> os.stat_result | None:
    try:
        info = os.lstat(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode):
        raise OSError("refusing symlink native-host path " + built)
    if _is_special_node(info):
        raise OSError("refusing special native-host path " + built)
    if kind == "file" and not stat.S_ISREG(info.st_mode):
        raise OSError("refusing non-regular native-host path " + built)
    if kind == "dir" and not stat.S_ISDIR(info.st_mode):
        raise OSError("refusing non-directory native-host path " + built)
    return info


def _exclusive_temp(parent_fd: int, name: str, mode: int) -> tuple[int, str]:
    flags = _file_excl_flags()
    for _ in range(16):
        tmp = ".%s.%s.tmp" % (name, os.urandom(8).hex())
        try:
            fd = os.open(tmp, flags, mode, dir_fd=parent_fd)
        except FileExistsError:
            continue
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or _is_special_node(opened):
            os.close(fd)
            try:
                os.unlink(tmp, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            raise OSError("refusing special native-host temp " + tmp)
        return fd, tmp
    raise OSError("cannot create exclusive native-host temp beside " + name)


def posix_open_regular(path: str, *, label: str, refuse_hardlink: bool = False) -> tuple[int, os.stat_result]:
    """Open one regular file after a descriptor walk. Never opens FIFO/device/socket."""
    absolute = posix_abs_path(path, label=label)
    parts = posix_abs_parts(absolute, label=label)
    if not parts:
        raise OSError(label + " must not be /")
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else None
    name = parts[-1]
    built = absolute
    if parent is None:
        raise OSError(label + " must not be /")
    parent_fd = bind_posix_directory(parent, create_missing=False, label=label)
    try:
        info = _inspect_leaf(parent_fd, name, built, kind="file")
        if info is None:
            raise OSError(label + " is missing: " + built)
        if refuse_hardlink and info.st_nlink != 1:
            raise OSError("refusing hardlinked native-host path " + built)
        fd = os.open(name, _file_read_flags(), dir_fd=parent_fd)
        try:
            opened = os.fstat(fd)
            if (
                _identity(opened) != _identity(info)
                or not stat.S_ISREG(opened.st_mode)
                or _is_special_node(opened)
            ):
                raise OSError(label + " changed while it was bound")
            if refuse_hardlink and opened.st_nlink != 1:
                raise OSError("refusing hardlinked native-host path " + built)
            return fd, opened
        except Exception:
            os.close(fd)
            raise
    finally:
        os.close(parent_fd)


def posix_unlink_leaf(path: str, *, missing_parent_ok: bool = True) -> bool:
    """Unlink one regular leaf via dir_fd. Parent symlink/special fails closed."""
    if os.name == "nt":
        try:
            os.unlink(path)
            return True
        except FileNotFoundError:
            return False
    absolute = posix_abs_path(path)
    parts = posix_abs_parts(absolute)
    if not parts:
        raise OSError("native-host path must not be /")
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    name = parts[-1]
    try:
        parent_fd = bind_posix_directory(
            parent, create_missing=False, label="native-host directory"
        )
    except OSError as error:
        if missing_parent_ok and "is missing" in str(error):
            return False
        raise
    try:
        try:
            info = os.lstat(name, dir_fd=parent_fd)
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(info.st_mode):
            raise OSError("refusing symlink native-host path " + absolute)
        if _is_special_node(info):
            raise OSError("refusing special native-host path " + absolute)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("refusing non-regular native-host path " + absolute)
        os.unlink(name, dir_fd=parent_fd)
        return True
    finally:
        os.close(parent_fd)


def posix_replace_regular(
    parent_fd: int,
    leaf: str,
    src_fd: int,
    mode: int,
    dest_info: os.stat_result | None,
    *,
    refuse_hardlink: bool,
    built: str,
) -> None:
    if dest_info is not None:
        if stat.S_ISLNK(dest_info.st_mode):
            raise OSError("refusing symlink native-host path " + built)
        if _is_special_node(dest_info) or not stat.S_ISREG(dest_info.st_mode):
            raise OSError("refusing special native-host path " + built)
        if refuse_hardlink and dest_info.st_nlink != 1:
            raise OSError("refusing hardlinked native-host rollback destination")
    tmp_fd, tmp_name = _exclusive_temp(parent_fd, leaf, mode)
    try:
        _copy_fd(src_fd, tmp_fd)
        os.fchmod(tmp_fd, mode)
        os.fsync(tmp_fd)
        os.close(tmp_fd)
        tmp_fd = -1
        current = _inspect_leaf(parent_fd, leaf, built, kind="file")
        if dest_info is None:
            if current is not None:
                raise OSError("native-host dest appeared while it was bound")
        else:
            if current is None or _identity(current) != _identity(dest_info):
                raise OSError("native-host dest changed while it was bound")
            if refuse_hardlink and current.st_nlink != 1:
                raise OSError("refusing hardlinked native-host rollback destination")
        os.rename(tmp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        tmp_name = None
    finally:
        if tmp_fd >= 0:
            os.close(tmp_fd)
        if tmp_name is not None:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass


def _write_atomic_windows(output: Path, encoded: bytes) -> None:
    output_parent = output.parent
    if output_parent.exists() and (
        output_parent.is_symlink() or not output_parent.is_dir()
    ):
        raise OSError("native-host manifest directory is a symlink")
    output_parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=str(output_parent)
    )
    temporary = Path(temporary_name)
    try:
        if hasattr(os, "fchmod"):
            try:
                os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def write_atomic(
    output: Path, manifest: dict[str, object], *, mode: int = 0o600
) -> None:
    encoded = (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    raw = os.fspath(output)
    if os.name == "nt":
        _write_atomic_windows(Path(os.path.abspath(raw)), encoded)
        return
    if "\x00" in raw:
        raise OSError("native-host manifest path is invalid")
    if not raw.startswith("/"):
        cwd = os.getcwd()
        if not cwd.startswith("/"):
            raise OSError("working directory is not absolute")
        raw = cwd.rstrip("/") + "/" + raw
    while raw != "/" and raw.endswith("/"):
        raw = raw[:-1]
    parent = os.path.dirname(raw) or "/"
    name = os.path.basename(raw)
    if not name or name in {".", ".."}:
        raise OSError("native-host manifest name is invalid")
    parent_fd = _bind_manifest_dir(parent, create_missing=True)
    tmp_name = None
    tmp_fd = -1
    try:
        _inspect_leaf(parent_fd, name, raw, kind="file")
        flags = _file_excl_flags()
        for _ in range(16):
            candidate = f".{name}.{os.urandom(8).hex()}.tmp"
            try:
                tmp_fd = os.open(candidate, flags, 0o600, dir_fd=parent_fd)
                tmp_name = candidate
                break
            except FileExistsError:
                continue
        if tmp_fd < 0 or tmp_name is None:
            raise OSError("cannot create exclusive native-host manifest temp")
        if hasattr(os, "fchmod"):
            os.fchmod(tmp_fd, mode)
        _write_all(tmp_fd, encoded)
        os.fsync(tmp_fd)
        os.close(tmp_fd)
        tmp_fd = -1
        _inspect_leaf(parent_fd, name, raw, kind="file")
        os.rename(tmp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        tmp_name = None
    finally:
        if tmp_fd >= 0:
            os.close(tmp_fd)
        if tmp_name is not None:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", required=True, choices=("chrome", "edge", "firefox"))
    parser.add_argument(
        "--extension-id",
        help="omit to use the pinned Firefox id or the Chrome/Edge id recorded in manifests/store_ids.json",
    )
    parser.add_argument("--host-path", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--allow-relative-host-path",
        action="store_true",
        help="Windows only: permit a path relative to the manifest directory",
    )
    return parser.parse_args(argv)


def resolve_cli_extension_id(browser: str, supplied: str | None) -> str:
    if browser == "firefox":
        if supplied and supplied.strip():
            return validated_extension_id(browser, supplied)
        return canonical_firefox_id()
    if browser not in CHROMIUM_BROWSERS:
        raise ValueError(f"unsupported browser {browser!r}")
    supplied_id = None
    if supplied and supplied.strip():
        supplied_id = validated_extension_id(browser, supplied)
    recorded = recorded_store_ids().get(browser)
    if recorded is None:
        message = missing_store_id_message(browser)
        if supplied_id is not None:
            message += " A caller-supplied --extension-id cannot substitute for it."
        raise OwnerIdentityBlocked(message)
    if supplied_id is not None and supplied_id != recorded:
        raise OwnerIdentityInvalid(
            f"{browser} --extension-id does not match the recorded store identity "
            f"in {STORE_IDS_RELATIVE}"
        )
    return recorded


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        extension_id = resolve_cli_extension_id(args.browser, args.extension_id)
        manifest = manifest_for(
            args.browser,
            extension_id,
            args.host_path,
            allow_relative_host_path=args.allow_relative_host_path,
        )
        write_atomic(args.output, manifest)
    except (OSError, ValueError) as error:
        print(f"native-host manifest refused: {error}", file=sys.stderr)
        if isinstance(error, OwnerIdentityBlocked):
            return MISSING_STORE_ID_EXIT
        return 1
    print(f"rendered {args.browser} native-host manifest: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
