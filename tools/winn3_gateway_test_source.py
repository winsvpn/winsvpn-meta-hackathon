#!/usr/bin/env python3
"""Source the DP gateway block in function tests, keeping legacy CLI coverage.

The compatibility tail is used only by suites which still exercise G's CLI
and maintenance pending S4 and S5. Every moved function comes from DP, never
from G. The S3 contract tests inspect the raw block without this tail.

Since slice S6 the real G is a tombstone, so the tail is cut from the frozen
copy of G (tools/winn3_gateway_block.py SOURCE), never from the tombstone. It
goes with that copy when the tombstone is deleted.
"""
import argparse
from pathlib import Path
import tempfile

import winn3_gateway_block as block

ROOT = Path(__file__).resolve().parents[1]


def fixture(dp, legacy=False):
    text = dp.read_text(encoding="utf-8")
    if block.BEGIN not in text:
        return text
    result = block.sourceable(text)
    if legacy:
        source = (ROOT / block.SOURCE).read_text(encoding="utf-8")
        lines = source.split("\n")
        tail = []
        for item in block.segment(lines):
            if item["kind"] not in ("func", "assign") or block.moved(item)[0]:
                continue
            if item["name"] in ("WINN3_GATEWAY_CODE_STAMP", "WINN3_ENV_FILE"):
                continue
            tail.extend(lines[item["start"]:item["end"] + 1])
            tail.append("")
        result += "\n# Legacy-only CLI and maintenance test definitions.\n"
        result += "\n".join(block.transform(tail)) + "\n"
        result += 'if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then\n  main "$@"\nfi\n'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("dp", type=Path)
    parser.add_argument("--legacy-compat", action="store_true")
    args = parser.parse_args()
    # A caller-provided mutant which is already extracted is used directly.
    if block.BEGIN not in args.dp.read_text(encoding="utf-8"):
        print(args.dp)
        return
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", prefix="winn3-dp-test-",
                                     delete=False, encoding="utf-8") as output:
        output.write(fixture(args.dp, args.legacy_compat))
        print(output.name)


if __name__ == "__main__":
    main()
