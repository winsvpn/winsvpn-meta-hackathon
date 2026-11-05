#!/usr/bin/env python3
"""A raised per-account device_limit_override must admit a brand-new device
past the global DEVICE_LIMIT on the new-device enrollment path.

Run: python3 server/test_verify_device_limit_override_hub.py
"""
import os
import sys
import base64
import sqlite3
import traceback
from contextlib import closing

import _toolchain  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_account_deletion_hub as harness  # noqa: E402
import test_winn3_descriptor_hub as dh  # noqa: E402


def pub(seed):
    return base64.b64encode(bytes([seed]) * 31 + b"\x01").decode()


def test_override_admits_fourth_device(mod):
    tokens = harness.seed_account(mod, account="1111-2222-3333", devices=3)
    dh.arm_activation(mod)
    dh.seed_node(mod)
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute(
            "UPDATE users SET device_limit_override=5"
            " WHERE account_number='1111-2222-3333'")
        conn.execute("UPDATE devices SET location_slug='lab-alpha'")
        for i, dev in enumerate(tokens):
            conn.execute(
                "UPDATE devices SET device_model=?, client_public_key=?"
                " WHERE device_id=?", (f"ExistingModel{i}", pub(10 + i), dev))
    body = dh.served_config(mod, device_id="brand-new-dev",
                            device_model="audit-harness",
                            client_public_key=pub(20),
                            device_fingerprint="fp-brand-new")
    assert body.get("status") == "authenticated", body
    with closing(sqlite3.connect(mod._DB)) as conn:
        ids = [r[0] for r in conn.execute(
            "SELECT device_id FROM devices ORDER BY device_id")]
    assert "brand-new-dev" in ids and len(ids) == 4, ids


TESTS = [test_override_admits_fourth_device]


def main():
    passed = failed = 0
    for fn in TESTS:
        try:
            fn(dh.load_hub_with_ring())
        except Exception:
            failed += 1
            print(f"FAIL  {fn.__name__}")
            traceback.print_exc()
        else:
            passed += 1
            print(f"ok    {fn.__name__}")
    print(f"\n{passed} passed, {failed} failed, {len(TESTS)} total")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
