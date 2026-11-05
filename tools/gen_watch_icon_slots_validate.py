#!/usr/bin/env python3
"""Validate the WinsWatch watch app icon appiconset.

Walks an AppIcon.appiconset directory, loads its Contents.json, and asserts
that every referenced image file exists on disk with nonzero bytes. It also
asserts the slot layout: exactly 8 watch idiom slots plus 1 watch-marketing
slot. Prints PASS only when every reference resolves; otherwise prints which
reference failed and exits nonzero.
"""
import json
import os
import sys


def main() -> int:
    appiconset = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "ios", "WinsWatch Watch App", "Assets.xcassets",
        "AppIcon.appiconset",
    )
    contents_json = os.path.join(appiconset, "Contents.json")
    if not os.path.isfile(contents_json):
        print("FAIL: no Contents.json at " + contents_json)
        return 1

    with open(contents_json, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    images = data.get("images", [])
    if not isinstance(images, list):
        print("FAIL: images is not a list")
        return 1

    watch_slots = 0
    marketing_slots = 0
    failed = []
    for entry in images:
        if not isinstance(entry, dict):
            failed.append("non-dict image entry")
            continue
        filename = entry.get("filename")
        idiom = entry.get("idiom")
        if not filename:
            failed.append("image entry missing filename")
            continue
        if idiom == "watch":
            watch_slots += 1
        elif idiom == "watch-marketing":
            marketing_slots += 1

        path = os.path.join(appiconset, filename)
        if not os.path.isfile(path):
            failed.append(filename + " does not exist")
            continue
        if os.path.getsize(path) == 0:
            failed.append(filename + " exists but is zero bytes")

    if watch_slots != 8:
        failed.append("expected 8 watch idiom slots, found " + str(watch_slots))
    if marketing_slots != 1:
        failed.append(
            "expected 1 watch-marketing slot, found " + str(marketing_slots)
        )

    if failed:
        print("FAIL: " + "; ".join(failed))
        return 1

    print("PASS: all 9 icon references resolve (8 watch + 1 watch-marketing)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
