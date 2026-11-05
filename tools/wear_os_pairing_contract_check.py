#!/usr/bin/env python3
"""Measure whether the Wear OS app is wired to pair with the phone app.

Source-only. Reads named files, extracts named constants, and compares them.
A green that cannot be made to fail is not evidence: pass --mutate-scratch DIR
to copy the inputs, apply comment-only and deliberate breaks, and score those
against this same checker.

Exit 0 only when every live-tree check passes. Never writes the shared tree.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path


FILES = (
    "wear_os/app/build.gradle.kts",
    "android/app/build.gradle.kts",
    "wear_os/app/src/main/kotlin/org/winsvpn/app/wear/WatchLink.kt",
    "wear_os/app/src/main/kotlin/org/winsvpn/app/wear/PhoneLink.kt",
    "wear_os/app/src/main/kotlin/org/winsvpn/app/wear/PairingMatcher.kt",
    "wear_os/app/src/main/AndroidManifest.xml",
    "android/app/src/main/kotlin/org/winsvpn/app/WatchBridge.kt",
    "android/app/src/main/kotlin/org/winsvpn/app/WatchCommandService.kt",
    "android/app/src/main/AndroidManifest.xml",
    "android/app/src/main/res/values/wear.xml",
    "lib/watch_bridge.dart",
)

EXPECTED_PACKAGE = "org.winsvpn.app"
EXPECTED_DEBUG = "org.winsvpn.app.debug"
EXPECTED_QA = "org.winsvpn.app.test"
EXPECTED_CMD = "/winsvpn/cmd"
EXPECTED_STATE = "/winsvpn/state"
EXPECTED_SNAPSHOT_KEY = "snapshot"
EXPECTED_CAPABILITY = "wins_vpn_phone"
EXPECTED_CAPABILITY_ARRAY = "android_wear_capabilities"
EXPECTED_CHANNEL = "wins_vpn/watch"
EXPECTED_WEARABLE = "com.google.android.gms:play-services-wearable:20.0.1"


def one(pattern: str, text: str, name: str, flags: int = 0) -> tuple[str | None, str | None]:
    found = re.findall(pattern, text, flags)
    if len(found) != 1:
        return None, f"{name}: expected exactly 1 match, got {len(found)} {found!r}"
    value = found[0]
    if isinstance(value, tuple):
        value = value[0]
    return value, None


def load(root: Path) -> tuple[dict[str, str], list[str]]:
    texts: dict[str, str] = {}
    errors: list[str] = []
    for rel in FILES:
        path = root / rel
        if not path.is_file():
            errors.append(f"missing {rel}")
            continue
        texts[rel] = path.read_text(encoding="utf-8")
    return texts, errors


def measure(root: Path) -> dict:
    checks: list[dict] = []
    texts, load_errors = load(root)
    for err in load_errors:
        checks.append({"id": "load", "ok": False, "detail": err})
    if load_errors:
        return {"ok": False, "root": str(root), "checks": checks}

    def add(cid: str, ok: bool, detail: str, **extra):
        row = {"id": cid, "ok": ok, "detail": detail}
        row.update(extra)
        checks.append(row)

    def require(cid: str, value: str | None, err: str | None, expected: str | None = None):
        if err:
            add(cid, False, err)
            return None
        if expected is not None and value != expected:
            add(cid, False, f"got {value!r} want {expected!r}", got=value, expected=expected)
            return value
        add(cid, True, value if value is not None else "ok", got=value, expected=expected)
        return value

    wear_gradle = texts["wear_os/app/build.gradle.kts"]
    phone_gradle = texts["android/app/build.gradle.kts"]
    watch_link = texts["wear_os/app/src/main/kotlin/org/winsvpn/app/wear/WatchLink.kt"]
    phone_link = texts["wear_os/app/src/main/kotlin/org/winsvpn/app/wear/PhoneLink.kt"]
    pairing = texts["wear_os/app/src/main/kotlin/org/winsvpn/app/wear/PairingMatcher.kt"]
    wear_manifest = texts["wear_os/app/src/main/AndroidManifest.xml"]
    phone_bridge = texts["android/app/src/main/kotlin/org/winsvpn/app/WatchBridge.kt"]
    cmd_svc = texts["android/app/src/main/kotlin/org/winsvpn/app/WatchCommandService.kt"]
    phone_manifest = texts["android/app/src/main/AndroidManifest.xml"]
    wear_xml = texts["android/app/src/main/res/values/wear.xml"]
    dart_bridge = texts["lib/watch_bridge.dart"]

    wear_id, err = one(r'(?m)^\s*applicationId = "([^"]+)"', wear_gradle, "wear applicationId")
    require("wear_application_id", wear_id, err, EXPECTED_PACKAGE)

    wear_name, err = one(r'(?m)^\s*versionName = "([^"]+)"', wear_gradle, "wear versionName")
    require("wear_version_name", wear_name, err, "1.0.16")
    wear_code, err = one(r'(?m)^\s*versionCode = (\d+)', wear_gradle, "wear versionCode")
    require("wear_version_code", wear_code, err, "3301")
    wear_target, err = one(r'(?m)^\s*targetSdk = (\d+)', wear_gradle, "wear targetSdk")
    require("wear_target_sdk", wear_target, err, "37")
    wear_min, err = one(r'(?m)^\s*minSdk = (\d+)', wear_gradle, "wear minSdk")
    require("wear_min_sdk", wear_min, err, "30")
    add(
        "wear_release_minify",
        "isMinifyEnabled = true" in wear_gradle and "isShrinkResources = true" in wear_gradle,
        "Wear release minify and resource shrinking",
    )
    add(
        "wear_owner_signing_blocked",
        "OWNER-BLOCKED: missing Android upload keystore" in wear_gradle
        and "debug or test key" in wear_gradle,
        "Wear release signing is OWNER-BLOCKED without the upload keystore",
    )

    phone_id, err = one(r'(?m)^\s*applicationId = "([^"]+)"', phone_gradle, "phone applicationId")
    require("phone_application_id", phone_id, err, EXPECTED_PACKAGE)

    add(
        "application_ids_match",
        bool(wear_id and phone_id and wear_id == phone_id == EXPECTED_PACKAGE),
        f"wear={wear_id!r} phone={phone_id!r}",
        got={"wear": wear_id, "phone": phone_id},
        expected=EXPECTED_PACKAGE,
    )

    rel, err = one(r'const val RELEASE_PACKAGE = "([^"]+)"', pairing, "RELEASE_PACKAGE")
    require("pairing_release_package", rel, err, EXPECTED_PACKAGE)
    dbg, err = one(r'const val DEBUG_PACKAGE = "([^"]+)"', pairing, "DEBUG_PACKAGE")
    require("pairing_debug_package", dbg, err, EXPECTED_DEBUG)
    qa, err = one(r'const val QA_PACKAGE = "([^"]+)"', pairing, "QA_PACKAGE")
    require("pairing_qa_package", qa, err, EXPECTED_QA)

    add(
        "phone_debug_suffix",
        'applicationIdSuffix = ".debug"' in phone_gradle,
        "android/app/build.gradle.kts applicationIdSuffix .debug",
    )
    add(
        "phone_test_suffix",
        'applicationIdSuffix = ".test"' in phone_gradle,
        "android/app/build.gradle.kts applicationIdSuffix .test",
    )

    w_cmd, err = one(r'const val PATH_COMMAND = "([^"]+)"', watch_link, "watch PATH_COMMAND")
    require("watch_path_command", w_cmd, err, EXPECTED_CMD)
    p_cmd, err = one(r'const val PATH_COMMAND = "([^"]+)"', phone_bridge, "phone PATH_COMMAND")
    require("phone_path_command", p_cmd, err, EXPECTED_CMD)
    add(
        "path_command_match",
        bool(w_cmd and p_cmd and w_cmd == p_cmd == EXPECTED_CMD),
        f"watch={w_cmd!r} phone={p_cmd!r}",
    )

    w_state, err = one(r'const val PATH_STATE = "([^"]+)"', watch_link, "watch PATH_STATE")
    require("watch_path_state", w_state, err, EXPECTED_STATE)
    p_state, err = one(r'const val PATH_STATE = "([^"]+)"', phone_bridge, "phone PATH_STATE")
    require("phone_path_state", p_state, err, EXPECTED_STATE)
    add(
        "path_state_match",
        bool(w_state and p_state and w_state == p_state == EXPECTED_STATE),
        f"watch={w_state!r} phone={p_state!r}",
    )

    w_key, err = one(r'const val KEY_SNAPSHOT = "([^"]+)"', watch_link, "watch KEY_SNAPSHOT")
    require("watch_snapshot_key", w_key, err, EXPECTED_SNAPSHOT_KEY)
    p_key, err = one(r'const val KEY_SNAPSHOT = "([^"]+)"', phone_bridge, "phone KEY_SNAPSHOT")
    require("phone_snapshot_key", p_key, err, EXPECTED_SNAPSHOT_KEY)

    w_ver, err = one(r'const val PROTOCOL_VERSION = (\d+)', watch_link, "watch PROTOCOL_VERSION")
    require("watch_protocol_version", w_ver, err, "1")
    p_ver, err = one(r'private const val PROTOCOL_VERSION = (\d+)', phone_bridge, "phone PROTOCOL_VERSION")
    require("phone_protocol_version", p_ver, err, "1")

    for name, expected in (
        ("COMMAND_CONNECT", "connect"),
        ("COMMAND_DISCONNECT", "disconnect"),
        ("COMMAND_SELECT_COUNTRY", "selectCountry"),
        ("COMMAND_REQUEST_STATE", "requestState"),
    ):
        wv, err = one(rf'const val {name} = "([^"]+)"', watch_link, f"watch {name}")
        require(f"watch_{name.lower()}", wv, err, expected)
        pv, err = one(rf'const val {name} = "([^"]+)"', phone_bridge, f"phone {name}")
        require(f"phone_{name.lower()}", pv, err, expected)

    cap, err = one(r'const val PHONE_CAPABILITY = "([^"]+)"', phone_link, "PHONE_CAPABILITY")
    require("watch_phone_capability", cap, err, EXPECTED_CAPABILITY)
    array, err = one(
        r'<string-array name="([^"]+)"',
        wear_xml,
        "wear.xml string-array name",
    )
    require("phone_capability_array_name", array, err, EXPECTED_CAPABILITY_ARRAY)
    item, err = one(r"<item>([^<]+)</item>", wear_xml, "wear.xml capability item")
    require("phone_capability_item", item, err, EXPECTED_CAPABILITY)
    add(
        "phone_capability_kept_by_shrinker",
        f'tools:keep="@array/{EXPECTED_CAPABILITY_ARRAY}"' in wear_xml,
        "wear.xml keeps the capability array from the release resource shrinker",
    )
    add(
        "capability_match",
        bool(cap and item and cap == item == EXPECTED_CAPABILITY),
        f"watch={cap!r} phone_xml={item!r}",
    )

    add(
        "watch_resolves_capability",
        "getCapability(PHONE_CAPABILITY" in phone_link,
        "PhoneLink.getCapability(PHONE_CAPABILITY)",
    )
    add(
        "watch_gates_on_release_package",
        "PairingMatcher.isRelease(appContext.packageName)" in phone_link,
        "PhoneLink refuses to resolve a node unless this APK is the release package",
    )
    add(
        "watch_uses_data_client",
        "Wearable.getDataClient" in phone_link and "class PhoneLink" in phone_link,
        "PhoneLink uses Wearable.getDataClient",
    )
    add(
        "watch_uses_message_client",
        "Wearable.getMessageClient" in phone_link,
        "PhoneLink uses Wearable.getMessageClient",
    )

    standalone, err = one(
        r'android:name="com.google.android.wearable.standalone"\s+android:value="([^"]+)"',
        wear_manifest,
        "standalone",
        flags=re.S,
    )
    require("watch_not_standalone", standalone, err, "false")
    add(
        "watch_feature_is_watch",
        'android:name="android.hardware.type.watch"' in wear_manifest,
        "uses-feature android.hardware.type.watch",
    )

    add(
        "phone_watch_command_service",
        'android:name=".WatchCommandService"' in phone_manifest,
        "AndroidManifest declares WatchCommandService",
    )
    add(
        "phone_message_received_filter",
        "com.google.android.gms.wearable.MESSAGE_RECEIVED" in phone_manifest,
        "WatchCommandService listens for MESSAGE_RECEIVED",
    )
    prefix, err = one(
        r'android:pathPrefix="([^"]+)"',
        phone_manifest,
        "WatchCommandService pathPrefix",
    )
    require("phone_path_prefix", prefix, err, EXPECTED_CMD)
    add(
        "command_service_uses_bridge_path",
        "messageEvent.path != WatchBridge.PATH_COMMAND" in cmd_svc,
        "WatchCommandService compares the event path to WatchBridge.PATH_COMMAND",
    )
    add(
        "command_service_is_listener",
        "class WatchCommandService : WearableListenerService()" in cmd_svc,
        "WatchCommandService extends WearableListenerService",
    )

    dart_ch, err = one(r"MethodChannel\('([^']+)'\)", dart_bridge, "Dart MethodChannel")
    require("dart_watch_channel", dart_ch, err, EXPECTED_CHANNEL)
    kt_ch, err = one(r'const val DART_CHANNEL = "([^"]+)"', phone_bridge, "Kotlin DART_CHANNEL")
    require("kotlin_watch_channel", kt_ch, err, EXPECTED_CHANNEL)
    add(
        "watch_channel_match",
        bool(dart_ch and kt_ch and dart_ch == kt_ch == EXPECTED_CHANNEL),
        f"dart={dart_ch!r} kotlin={kt_ch!r}",
    )

    add(
        "phone_wearable_dep",
        EXPECTED_WEARABLE in phone_gradle,
        EXPECTED_WEARABLE + " in android/app/build.gradle.kts",
    )
    add(
        "watch_wearable_dep",
        EXPECTED_WEARABLE in wear_gradle,
        EXPECTED_WEARABLE + " in wear_os/app/build.gradle.kts",
    )

    ok = all(c["ok"] for c in checks)
    return {"ok": ok, "root": str(root), "n_ok": sum(1 for c in checks if c["ok"]), "n": len(checks), "checks": checks}


def copy_tree(src_root: Path, dst_root: Path) -> None:
    if dst_root.exists():
        shutil.rmtree(dst_root)
    for rel in FILES:
        dest = dst_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_root / rel, dest)


def apply_text(root: Path, rel: str, old: str, new: str) -> None:
    path = root / rel
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"mutation needle {old!r} in {rel} occurs {count} times, want 1")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def run_mutations(src_root: Path, scratch: Path) -> dict:
    scratch.mkdir(parents=True, exist_ok=True)
    results = []

    def run_case(name: str, mutate, expect_ok: bool) -> dict:
        case_root = scratch / name
        copy_tree(src_root, case_root)
        if mutate is not None:
            mutate(case_root)
        report = measure(case_root)
        caught = (not report["ok"]) if not expect_ok else report["ok"]
        failed = [c["id"] for c in report["checks"] if not c["ok"]]
        row = {
            "case": name,
            "expect_ok": expect_ok,
            "got_ok": report["ok"],
            "caught": caught,
            "failed_ids": failed,
        }
        results.append(row)
        return row

    run_case("no_mutation", None, True)
    run_case(
        "comment_only",
        lambda root: apply_text(
            root,
            "wear_os/app/src/main/kotlin/org/winsvpn/app/wear/WatchLink.kt",
            "object WatchLink {",
            "object WatchLink { // comment-only pairing probe",
        ),
        True,
    )
    run_case(
        "break_watch_application_id",
        lambda root: apply_text(
            root,
            "wear_os/app/build.gradle.kts",
            'applicationId = "org.winsvpn.app"',
            'applicationId = "org.winsvpn.app.debug"',
        ),
        False,
    )
    run_case(
        "break_path_command",
        lambda root: apply_text(
            root,
            "wear_os/app/src/main/kotlin/org/winsvpn/app/wear/WatchLink.kt",
            'const val PATH_COMMAND = "/winsvpn/cmd"',
            'const val PATH_COMMAND = "/winsvpn/cmd-broken"',
        ),
        False,
    )
    run_case(
        "break_capability",
        lambda root: apply_text(
            root,
            "android/app/src/main/res/values/wear.xml",
            "<item>wins_vpn_phone</item>",
            "<item>wins_vpn_phone_broken</item>",
        ),
        False,
    )
    run_case(
        "break_capability_shrinker_keep",
        lambda root: apply_text(
            root,
            "android/app/src/main/res/values/wear.xml",
            'tools:keep="@array/android_wear_capabilities"',
            'tools:keep=""',
        ),
        False,
    )
    run_case(
        "break_standalone_true",
        lambda root: apply_text(
            root,
            "wear_os/app/src/main/AndroidManifest.xml",
            'android:name="com.google.android.wearable.standalone"\n            android:value="false"',
            'android:name="com.google.android.wearable.standalone"\n            android:value="true"',
        ),
        False,
    )

    all_caught = all(r["caught"] for r in results)
    return {"ok": all_caught, "cases": results}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        default=str(Path(__file__).resolve().parent.parent),
        help="wins_vpn tree (default: parent of tools/)",
    )
    parser.add_argument("--receipt", default="", help="write JSON receipt here")
    parser.add_argument(
        "--mutate-scratch",
        default="",
        help="if set, copy inputs here and run no-mutation / comment / break cases",
    )
    args = parser.parse_args()
    root = Path(args.root).resolve()
    live = measure(root)
    out = {
        "probe": "wear_os_pairing_contract_check",
        "live": live,
    }
    mutate_ok = True
    if args.mutate_scratch:
        out["mutation"] = run_mutations(root, Path(args.mutate_scratch).resolve())
        mutate_ok = bool(out["mutation"]["ok"])
    text = json.dumps(out, indent=2, sort_keys=False) + "\n"
    if args.receipt:
        receipt = Path(args.receipt)
        receipt.parent.mkdir(parents=True, exist_ok=True)
        receipt.write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    if live["ok"] and mutate_ok:
        return 0
    return 1


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUTF8", "1")
    sys.exit(main())
