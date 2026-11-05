#!/usr/bin/env python3
"""A device-token reconnect must not delete another device by model name.

Run: python3 server/test_verify_model_dedupe_hub.py
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


def device_ids(mod):
    with closing(sqlite3.connect(mod._DB)) as conn:
        return [r[0] for r in conn.execute(
            "SELECT device_id FROM devices ORDER BY device_id")]


def test_reconnect_cannot_delete_other_device_by_model(mod):
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    dh.arm_activation(mod)
    dh.seed_node(mod)
    key_a, key_b = pub(3), pub(4)
    body = dh.served_config(mod, device_id="attacker-dev",
                            device_model="AttackerPhone",
                            client_public_key=key_a,
                            device_fingerprint="fp-attacker")
    bearer_a = body["device_auth_token"]
    now = mod.utcnow().isoformat()
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        conn.execute(
            "INSERT INTO devices (device_id, account_number, device_model,"
            " hardware_hash, vpn_internal_ip, client_private_key,"
            " client_public_key, last_seen, location_slug, updated_at,"
            " device_auth_token_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("victim-dev", "1111-2222-3333", "VictimPhone X1", "hw-victim",
             "10.8.0.99", "", key_b, now, "lab-alpha", now,
             mod.token_digest("victim-token")))
    dh.served_config(mod, request_headers={
        "authorization": f"Bearer {bearer_a}"},
        device_id="attacker-dev", device_model="VictimPhone",
        client_public_key=key_a, device_fingerprint="fp-attacker")
    assert device_ids(mod) == ["attacker-dev", "victim-dev"], device_ids(mod)


TESTS = [test_reconnect_cannot_delete_other_device_by_model]


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
