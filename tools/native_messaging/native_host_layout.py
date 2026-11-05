#!/usr/bin/env python3
"""Install, uninstall, and Windows registry contracts for the native host.

Manifest JSON is produced only by render_host_manifest.py. This module names
the directories and registry keys browsers actually consult, and it never
invents a Chrome or Edge store id: those come only from the committed record
manifests/store_ids.json (read by render_host_manifest.py). Firefox's add-on
id is already pinned.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import render_host_manifest as renderer  # noqa: E402

HOST_NAME = renderer.HOST_NAME
FIREFOX_ID = renderer.FIREFOX_ID
BROWSERS = ("chrome", "edge", "firefox")
MISSING_STORE_ID_EXIT = 78

# Machine-wide keys the Windows installer writes (both registry views).
# Local developer registration uses the same subkeys under HKCU.
WINDOWS_REGISTRY_SUBKEYS: dict[str, str] = {
    "chrome": rf"Software\Google\Chrome\NativeMessagingHosts\{HOST_NAME}",
    "edge": rf"Software\Microsoft\Edge\NativeMessagingHosts\{HOST_NAME}",
    "firefox": rf"Software\Mozilla\NativeMessagingHosts\{HOST_NAME}",
}

WINDOWS_MANIFEST_NAME = {
    "chrome": f"{HOST_NAME}.chrome.json",
    "edge": f"{HOST_NAME}.edge.json",
    "firefox": f"{HOST_NAME}.firefox.json",
}

UNIX_MANIFEST_NAME = f"{HOST_NAME}.json"


class MissingStoreIdError(ValueError):
    """Chrome/Edge registration asked for an id store_ids.json does not record."""


def unix_manifest_dir(
    browser: str,
    os_name: str,
    *,
    system: bool,
    home: Path,
) -> Path:
    if browser not in BROWSERS:
        raise ValueError(f"unsupported browser {browser!r}")
    home = Path(home)
    darwin = os_name in {"Darwin", "darwin", "macos"}
    linux = os_name in {"Linux", "linux"}
    if not darwin and not linux:
        raise ValueError(f"unix native-host dest is undefined for {os_name}")

    if browser == "chrome":
        if darwin:
            return Path(
                "/Library/Google/Chrome/NativeMessagingHosts"
                if system
                else home / "Library/Application Support/Google/Chrome/NativeMessagingHosts"
            )
        return Path(
            "/etc/opt/chrome/native-messaging-hosts"
            if system
            else home / ".config/google-chrome/NativeMessagingHosts"
        )
    if browser == "edge":
        if darwin:
            return Path(
                "/Library/Microsoft/Edge/NativeMessagingHosts"
                if system
                else home / "Library/Application Support/Microsoft Edge/NativeMessagingHosts"
            )
        return Path(
            "/etc/opt/edge/native-messaging-hosts"
            if system
            else home / ".config/microsoft-edge/NativeMessagingHosts"
        )
    if darwin:
        return Path(
            "/Library/Application Support/Mozilla/NativeMessagingHosts"
            if system
            else home / "Library/Application Support/Mozilla/NativeMessagingHosts"
        )
    return Path(
        "/usr/lib/mozilla/native-messaging-hosts"
        if system
        else home / ".mozilla/native-messaging-hosts"
    )


def unix_host_install_dir(*, os_name: str, system: bool, home: Path) -> Path:
    home = Path(home)
    if os_name in {"Darwin", "darwin", "macos"}:
        if system:
            return Path("/Library/Application Support/Win's VPN/NativeMessagingHost")
        return home / "Library/Application Support/Win's VPN/NativeMessagingHost"
    if os_name in {"Linux", "linux"}:
        if system:
            return Path("/usr/lib/wins-vpn")
        return home / ".local/lib/wins-vpn"
    raise ValueError(f"unix host install dir is undefined for {os_name}")


def windows_manifest_relpath(browser: str) -> str:
    if browser not in WINDOWS_MANIFEST_NAME:
        raise ValueError(f"unsupported browser {browser!r}")
    return rf"NativeMessagingHost\{WINDOWS_MANIFEST_NAME[browser]}"


def resolve_extension_id(browser: str, supplied: str | None) -> str:
    """Caller-supplied id wins; otherwise the id recorded in store_ids.json.

    A missing Chrome/Edge id is not defaulted to a made-up 32-letter string.
    """
    if supplied and supplied.strip():
        return renderer.validated_extension_id(browser, supplied)
    recorded = renderer.recorded_extension_id(browser)
    if recorded:
        return recorded
    if browser == "firefox":
        return renderer.canonical_firefox_id()
    raise MissingStoreIdError(renderer.missing_store_id_message(browser))


def read_installed_origins(path: Path) -> dict[str, object]:
    """Read bounded public browser identities without following a leaf link."""
    try:
        path.lstat()
        if os.name == "nt":
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise ValueError("native-host origin configuration is not a regular file")
            reader = path.open("rb")
        else:
            fd, _ = renderer.posix_open_regular(
                os.fspath(path), label="native-host origin configuration"
            )
            reader = os.fdopen(fd, "rb")
    except FileNotFoundError:
        return {}
    with reader:
        encoded = reader.read(4097)
    if len(encoded) > 4096:
        raise ValueError("native-host origin configuration is too large")
    document = json.loads(encoded)
    if not isinstance(document, dict) or set(document) - set(BROWSERS):
        raise ValueError("native-host origin configuration has invalid browsers")
    for browser, values in document.items():
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str):
            raise ValueError("native-host origin configuration has invalid identities")
        value = values[0]
        if browser == "firefox":
            renderer.validated_extension_id(browser, value)
        else:
            prefix = "chrome-extension://"
            if not value.startswith(prefix) or not value.endswith("/"):
                raise ValueError("native-host origin configuration has an invalid origin")
            renderer.validated_extension_id(browser, value[len(prefix):-1])
    return document


def install_manifest(
    *,
    browser: str,
    host_path: str,
    manifest_path: Path,
    extension_id: str | None = None,
    allow_relative_host_path: bool = False,
) -> dict[str, object]:
    resolved_id = resolve_extension_id(browser, extension_id)
    manifest = renderer.manifest_for(
        browser,
        resolved_id,
        host_path,
        allow_relative_host_path=allow_relative_host_path,
    )
    installed_host = Path(host_path)
    if not installed_host.is_absolute():
        installed_host = manifest_path.parent / installed_host
    companion = installed_host.parent / "allowed_origins.txt"
    # JSON preserves each browser's identity slot when another browser is
    # installed or its ID changes. The companion contains public IDs only.
    origins = read_installed_origins(companion)
    origin_key = "allowed_extensions" if browser == "firefox" else "allowed_origins"
    origins[browser] = manifest[origin_key]
    renderer.write_atomic(companion, origins, mode=0o644)
    manifest_companion = manifest_path.parent / "allowed_origins.txt"
    if manifest_companion != companion:
        renderer.write_atomic(manifest_companion, origins, mode=0o644)
    renderer.write_atomic(manifest_path, manifest)
    return manifest


def uninstall_manifest(manifest_path: Path) -> bool:
    """Remove one installed manifest. Missing is success (idempotent uninstall)."""
    if os.name == "nt":
        try:
            manifest_path.unlink()
            return True
        except FileNotFoundError:
            return False
    return renderer.posix_unlink_leaf(os.fspath(manifest_path), missing_parent_ok=True)


def posix_mkdir_p(path: str) -> None:
    fd = renderer.bind_posix_directory(
        path, create_missing=True, label="native-host directory"
    )
    os.close(fd)


def posix_install_host(source: str, dest: str, mode: int = 0o755) -> str:
    """Descriptor-bound host copy with exclusive backup. Returns backup path or ''."""
    dest_abs = renderer.posix_abs_path(dest, label="native-host dest")
    parts = renderer.posix_abs_parts(dest_abs, label="native-host dest")
    if not parts:
        raise OSError("native-host dest must not be /")
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    name = parts[-1]
    parent_fd = renderer.bind_posix_directory(
        parent, create_missing=True, label="native-host dest directory"
    )
    backup_name = None
    src_fd = None
    try:
        staged = name + ".new"
        try:
            staged_info = os.lstat(staged, dir_fd=parent_fd)
        except FileNotFoundError:
            staged_info = None
        if staged_info is not None:
            if stat.S_ISLNK(staged_info.st_mode):
                raise OSError("refusing preplanted staging symlink " + dest_abs + ".new")
            if renderer._is_special_node(staged_info) or not stat.S_ISREG(staged_info.st_mode):
                raise OSError("refusing preplanted staging path " + dest_abs + ".new")
        dest_info = renderer._inspect_leaf(parent_fd, name, dest_abs, kind="file")
        src_fd, _src_info = renderer.posix_open_regular(
            source, label="native-host source", refuse_hardlink=False
        )
        if dest_info is not None:
            backup_fd, backup_name = renderer._exclusive_temp(
                parent_fd, name + ".winsvpn-prev", dest_info.st_mode & 0o777
            )
            try:
                existing = os.open(name, renderer._file_read_flags(), dir_fd=parent_fd)
                try:
                    opened = os.fstat(existing)
                    if renderer._identity(opened) != renderer._identity(dest_info):
                        raise OSError("native-host dest changed while it was bound")
                    renderer._copy_fd(existing, backup_fd)
                finally:
                    os.close(existing)
                os.fsync(backup_fd)
            finally:
                os.close(backup_fd)
        renderer.posix_replace_regular(
            parent_fd,
            name,
            src_fd,
            mode,
            dest_info,
            refuse_hardlink=False,
            built=dest_abs,
        )
        if backup_name is None:
            return ""
        return parent.rstrip("/") + "/" + backup_name
    except Exception:
        if backup_name is not None:
            try:
                os.unlink(backup_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        if src_fd is not None:
            os.close(src_fd)
        os.close(parent_fd)


def posix_rollback_host(dest: str, backup: str) -> None:
    dest_abs = renderer.posix_abs_path(dest, label="native-host dest")
    parts = renderer.posix_abs_parts(dest_abs, label="native-host dest")
    if not parts:
        raise OSError("native-host dest must not be /")
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    name = parts[-1]
    parent_fd = renderer.bind_posix_directory(
        parent, create_missing=False, label="native-host dest directory"
    )
    backup_fd = None
    try:
        dest_info = renderer._inspect_leaf(parent_fd, name, dest_abs, kind="file")
        if backup:
            backup_abs = renderer.posix_abs_path(backup, label="native-host backup")
            backup_parts = renderer.posix_abs_parts(
                backup_abs, label="native-host backup"
            )
            if not backup_parts:
                raise OSError("native-host backup must not be /")
            backup_parent = (
                "/" + "/".join(backup_parts[:-1]) if len(backup_parts) > 1 else "/"
            )
            backup_leaf = backup_parts[-1]
            if backup_parent == parent:
                backup_info = renderer._inspect_leaf(
                    parent_fd, backup_leaf, backup_abs, kind="file"
                )
                if backup_info is None:
                    raise OSError("native-host backup is missing: " + backup_abs)
                if backup_info.st_nlink != 1:
                    raise OSError("refusing hardlinked native-host backup")
                backup_fd = os.open(
                    backup_leaf, renderer._file_read_flags(), dir_fd=parent_fd
                )
                try:
                    opened = os.fstat(backup_fd)
                    if (
                        renderer._identity(opened) != renderer._identity(backup_info)
                        or not stat.S_ISREG(opened.st_mode)
                        or renderer._is_special_node(opened)
                    ):
                        raise OSError("native-host backup changed while it was bound")
                    if opened.st_nlink != 1:
                        raise OSError("refusing hardlinked native-host backup")
                except Exception:
                    os.close(backup_fd)
                    backup_fd = None
                    raise
            else:
                backup_fd, backup_info = renderer.posix_open_regular(
                    backup, label="native-host backup", refuse_hardlink=True
                )
            renderer.posix_replace_regular(
                parent_fd,
                name,
                backup_fd,
                stat.S_IMODE(backup_info.st_mode),
                dest_info,
                refuse_hardlink=True,
                built=dest_abs,
            )
            if backup_parent == parent:
                try:
                    os.unlink(backup_leaf, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
        elif dest_info is not None:
            if dest_info.st_nlink != 1:
                raise OSError("refusing hardlinked native-host rollback destination")
            os.unlink(name, dir_fd=parent_fd)
    finally:
        if backup_fd is not None:
            os.close(backup_fd)
        os.close(parent_fd)


def windows_registry_plan(
    browser: str,
    manifest_path: str,
    *,
    hive: str = "HKLM",
) -> list[dict[str, str]]:
    if browser not in WINDOWS_REGISTRY_SUBKEYS:
        raise ValueError(f"unsupported browser {browser!r}")
    hive = hive.upper()
    if hive not in {"HKLM", "HKCU"}:
        raise ValueError(f"unsupported registry hive {hive!r}")
    subkey = WINDOWS_REGISTRY_SUBKEYS[browser]
    entries = []
    views = ("HKLM32", "HKLM64") if hive == "HKLM" else ("HKCU",)
    for view in views:
        entries.append(
            {
                "hive": view,
                "subkey": subkey,
                "value_name": "",
                "value": manifest_path,
                "uninstall": "delete_key",
            }
        )
    return entries


def registration_plan(
    *,
    browser: str,
    host_path: str,
    manifest_path: Path,
    extension_id: str | None = None,
    allow_relative_host_path: bool = False,
    windows_hive: str | None = None,
) -> dict[str, object]:
    resolved_id = resolve_extension_id(browser, extension_id)
    manifest = renderer.manifest_for(
        browser,
        resolved_id,
        host_path,
        allow_relative_host_path=allow_relative_host_path,
    )
    plan: dict[str, object] = {
        "browser": browser,
        "host_name": HOST_NAME,
        "extension_id": resolved_id,
        "manifest_path": str(manifest_path),
        "manifest": manifest,
        "registry": [],
    }
    if windows_hive:
        plan["registry"] = windows_registry_plan(
            browser, str(manifest_path), hive=windows_hive
        )
    return plan


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Native-host layout, install, uninstall, and registry plan"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    dest = sub.add_parser("unix-dest", help="print the per-browser manifest directory")
    dest.add_argument("--browser", required=True, choices=BROWSERS)
    dest.add_argument("--uname", required=True)
    dest.add_argument("--system", action="store_true")
    dest.add_argument("--home", type=Path, default=Path(os.path.expanduser("~")))
    dest.add_argument("--manifest-dir", type=Path)

    host_dest = sub.add_parser("unix-host-dest", help="print the host-binary install directory")
    host_dest.add_argument("--uname", required=True)
    host_dest.add_argument("--system", action="store_true")
    host_dest.add_argument("--home", type=Path, default=Path(os.path.expanduser("~")))

    install = sub.add_parser("install-manifest", help="render one final manifest")
    install.add_argument("--browser", required=True, choices=BROWSERS)
    install.add_argument("--host-path", required=True)
    install.add_argument("--output", required=True, type=Path)
    install.add_argument("--extension-id")
    install.add_argument("--allow-relative-host-path", action="store_true")

    uninstall = sub.add_parser("uninstall-manifest", help="delete one installed manifest")
    uninstall.add_argument("--output", required=True, type=Path)

    mkdir_p = sub.add_parser("mkdir-p", help="descriptor-walk mkdir for a dest directory")
    mkdir_p.add_argument("--dir", required=True)

    install_host = sub.add_parser("install-host", help="descriptor-bound host copy with exclusive backup")
    install_host.add_argument("--source", required=True)
    install_host.add_argument("--dest", required=True)
    install_host.add_argument("--mode", default="0755")

    rollback_host = sub.add_parser("rollback-host", help="restore a descriptor-bound host backup")
    rollback_host.add_argument("--dest", required=True)
    rollback_host.add_argument("--backup", default="")

    uninstall_leaf = sub.add_parser("uninstall-leaf", help="descriptor-bound unlink of one regular file")
    uninstall_leaf.add_argument("--output", required=True, type=Path)

    plan = sub.add_parser("plan", help="print install JSON including Windows registry keys")
    plan.add_argument("--browser", required=True, choices=BROWSERS)
    plan.add_argument("--host-path", required=True)
    plan.add_argument("--manifest-path", required=True, type=Path)
    plan.add_argument("--extension-id")
    plan.add_argument("--allow-relative-host-path", action="store_true")
    plan.add_argument("--windows-hive", choices=("HKLM", "HKCU"))

    recorded = sub.add_parser("recorded-id", help="print the recorded extension id or fail")
    recorded.add_argument("--browser", required=True, choices=BROWSERS)

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "unix-dest":
            if args.manifest_dir is not None:
                print(args.manifest_dir)
                return 0
            print(
                unix_manifest_dir(
                    args.browser, args.uname, system=args.system, home=args.home
                )
            )
            return 0
        if args.command == "unix-host-dest":
            print(
                unix_host_install_dir(
                    os_name=args.uname, system=args.system, home=args.home
                )
            )
            return 0
        if args.command == "install-manifest":
            install_manifest(
                browser=args.browser,
                host_path=args.host_path,
                manifest_path=args.output,
                extension_id=args.extension_id,
                allow_relative_host_path=args.allow_relative_host_path,
            )
            print(f"installed manifest: {args.output}")
            return 0
        if args.command == "uninstall-manifest":
            uninstall_manifest(args.output)
            print(f"uninstalled manifest: {args.output}")
            return 0
        if args.command == "mkdir-p":
            posix_mkdir_p(args.dir)
            return 0
        if args.command == "install-host":
            backup = posix_install_host(args.source, args.dest, int(args.mode, 8))
            print(backup)
            return 0
        if args.command == "rollback-host":
            posix_rollback_host(args.dest, args.backup)
            return 0
        if args.command == "uninstall-leaf":
            posix_unlink = renderer.posix_unlink_leaf(os.fspath(args.output), missing_parent_ok=True)
            if posix_unlink:
                print(f"uninstalled leaf: {args.output}")
            else:
                print(f"uninstalled leaf: {args.output}")
            return 0
        if args.command == "plan":
            plan = registration_plan(
                browser=args.browser,
                host_path=args.host_path,
                manifest_path=args.manifest_path,
                extension_id=args.extension_id,
                allow_relative_host_path=args.allow_relative_host_path,
                windows_hive=args.windows_hive,
            )
            json.dump(plan, sys.stdout, indent=2, ensure_ascii=True)
            sys.stdout.write("\n")
            return 0
        if args.command == "recorded-id":
            print(resolve_extension_id(args.browser, None))
            return 0
    except MissingStoreIdError as error:
        print(f"native-host registration refused: {error}", file=sys.stderr)
        return MISSING_STORE_ID_EXIT
    except (OSError, ValueError) as error:
        print(f"native-host registration refused: {error}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
