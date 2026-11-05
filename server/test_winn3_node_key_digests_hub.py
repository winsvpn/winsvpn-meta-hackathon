#!/usr/bin/env python3
"""Hub tests for per-node cover-set public digests (Round GK OI-GK-3 step 1).

Exercises the REAL control-plane source, extracted from the installer heredoc
exactly as test_winn3_descriptor_hub.py does. No test contacts a node, a live
hub, or the network.

WHAT IS UNDER TEST:

  * THE UNIQUENESS GUARD. A node that registers an ECH public key or a Winn
    leaf SPKI another node already holds is refused with 409, and nothing is
    recorded. That is the whole purpose of the table: the measured fleet state
    it replaces is one ECH key file shared by all eight data planes.
  * THE GUARD HOLDS BELOW THE HANDLER. The unique indexes refuse the same
    duplicate when the handler's pre-check is bypassed, which is the
    concurrent-registration case.
  * STEP 1 IS NOT BLOCKED BY STEP 2. The leaf digest is optional and absent
    leaves do not collide, because every node still holds the shared leaf
    until step 2 reissues it.
  * DIGESTS ONLY. Anything that is not 64 hex characters is refused, and the
    refusal never echoes the value.

Run:  python3 server/test_winn3_node_key_digests_hub.py
"""
from contextlib import closing
import _toolchain  # noqa: F401  (V-01 preflight)
import asyncio
import hashlib
import os
import sqlite3
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_account_deletion_hub as harness  # noqa: E402
from test_account_deletion_hub import FakeRequest, HTTPException  # noqa: E402

ADMIN = "test-admin-token"
PATH = "/admin/nodes/winn3/key-digests"

FAILURES = []
PASSED = [0]


def check(name, fn):
    try:
        fn()
    except Exception:
        FAILURES.append((name, traceback.format_exc()))
        print(f"  FAIL  {name}")
    else:
        PASSED[0] += 1
        print(f"  ok    {name}")


def expect_http(status, fn):
    try:
        fn()
    except HTTPException as exc:
        assert exc.status_code == status, f"expected {status}, got {exc.status_code}"
        return exc
    raise AssertionError(f"expected HTTPException {status}, nothing was raised")


def digest(label):
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def seed_node(mod, slug):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        conn.execute(
            "INSERT INTO nodes (slug, name, endpoint, public_key, status)"
            " VALUES (?, ?, ?, ?, 'online')",
            (slug, slug.title(), "198.51.100.7:9110", "A" * 43 + "="),
        )


def record(mod, slug, ech, *, config=None, leaf="", token=ADMIN):
    return mod.admin_record_node_winn3_key_digests(
        request=FakeRequest(path=PATH),
        slug=slug,
        ech_public_key_sha256=ech,
        ech_config_list_sha256=config if config is not None else digest("list-" + ech),
        leaf_spki_sha256=leaf,
        x_admin_token=token,
    )


def listing(mod):
    return mod.admin_list_node_winn3_key_digests(
        request=FakeRequest(path=PATH, method="GET"), x_admin_token=ADMIN)


def rows(mod):
    with closing(sqlite3.connect(mod._DB)) as conn:
        conn.row_factory = sqlite3.Row
        return {r["slug"]: dict(r) for r in conn.execute(
            "SELECT * FROM winn3_node_key_digests").fetchall()}


def fresh_hub():
    mod = harness.load_hub()
    for slug in ("alpha", "bravo", "charlie"):
        seed_node(mod, slug)
    return mod


# ================================ tests ====================================

def test_records_public_digests_for_a_node(mod):
    result = record(mod, "alpha", digest("ech-alpha"), leaf=digest("leaf-alpha"))
    assert result["ok"] is True
    stored = rows(mod)["alpha"]
    assert stored["ech_public_key_sha256"] == digest("ech-alpha")
    assert stored["leaf_spki_sha256"] == digest("leaf-alpha")
    report = listing(mod)
    assert report["distinct_ech_public_keys"] == 1
    assert report["nodes_without_digests"] == ["bravo", "charlie"]


def test_duplicate_ech_public_key_across_nodes_is_refused(mod):
    shared = digest("ech-fleet-shared")
    record(mod, "alpha", shared)
    exc = expect_http(409, lambda: record(mod, "bravo", shared))
    assert "alpha" in exc.detail and "Nothing was recorded" in exc.detail
    assert set(rows(mod)) == {"alpha"}, rows(mod)


def test_duplicate_leaf_spki_across_nodes_is_refused(mod):
    record(mod, "alpha", digest("ech-alpha"), leaf=digest("leaf-shared"))
    expect_http(409, lambda: record(
        mod, "bravo", digest("ech-bravo"), leaf=digest("leaf-shared")))
    assert set(rows(mod)) == {"alpha"}, rows(mod)


def test_nodes_without_a_leaf_digest_do_not_collide(mod):
    # Step 1 reality: per-node ECH, fleet-shared leaf not yet reported.
    for slug in ("alpha", "bravo", "charlie"):
        record(mod, slug, digest("ech-" + slug))
    assert listing(mod)["distinct_ech_public_keys"] == 3
    assert all(r["leaf_spki_sha256"] is None for r in rows(mod).values())


def test_re_recording_the_same_node_replaces_its_row(mod):
    record(mod, "alpha", digest("ech-alpha-1"))
    record(mod, "alpha", digest("ech-alpha-1"))
    record(mod, "alpha", digest("ech-alpha-2"))
    assert rows(mod)["alpha"]["ech_public_key_sha256"] == digest("ech-alpha-2")
    # alpha's rotation left one row, so a second node still records normally.
    record(mod, "bravo", digest("ech-bravo"))
    assert len(rows(mod)) == 2


def test_unique_index_refuses_a_duplicate_below_the_handler(mod):
    record(mod, "alpha", digest("ech-alpha"), leaf=digest("leaf-alpha"))
    with closing(sqlite3.connect(mod._DB)) as conn:
        for ech, leaf in ((digest("ech-alpha"), None),
                          (digest("ech-other"), digest("leaf-alpha"))):
            try:
                with conn:
                    conn.execute(
                        "INSERT INTO winn3_node_key_digests (slug,"
                        " ech_public_key_sha256, ech_config_list_sha256,"
                        " leaf_spki_sha256, recorded_at) VALUES (?,?,?,?,?)",
                        ("bravo", ech, digest("x"), leaf, "now"))
            except sqlite3.IntegrityError:
                continue
            raise AssertionError("unique index accepted a duplicate digest")
    assert set(rows(mod)) == {"alpha"}


def test_non_digest_values_are_refused_without_echo(mod):
    private_looking = "MC4CAQAwBQYDK2VuBCIEIH" + "q" * 22
    for bad in (private_looking, "a" * 63, "g" * 64, digest("x") + "00"):
        exc = expect_http(400, lambda b=bad: record(mod, "alpha", b))
        assert bad not in exc.detail, exc.detail
        exc = expect_http(400, lambda b=bad: record(
            mod, "alpha", digest("ok"), leaf=b))
        assert bad not in exc.detail, exc.detail
    expect_http(400, lambda: record(mod, "alpha", ""))
    expect_http(400, lambda: record(mod, "alpha", digest("ok"), config=""))
    assert rows(mod) == {}


def test_unknown_node_is_404(mod):
    expect_http(404, lambda: record(mod, "zulu", digest("ech-zulu")))
    assert rows(mod) == {}


def test_admin_token_is_required(mod):
    expect_http(401, lambda: record(mod, "alpha", digest("ech"), token="wrong"))
    assert rows(mod) == {}


def test_uppercase_digest_is_normalised_so_case_cannot_dodge_the_guard(mod):
    record(mod, "alpha", digest("ech-shared"))
    expect_http(409, lambda: record(mod, "bravo", digest("ech-shared").upper()))


UNIT_TESTS = (
    test_records_public_digests_for_a_node,
    test_duplicate_ech_public_key_across_nodes_is_refused,
    test_duplicate_leaf_spki_across_nodes_is_refused,
    test_nodes_without_a_leaf_digest_do_not_collide,
    test_re_recording_the_same_node_replaces_its_row,
    test_unique_index_refuses_a_duplicate_below_the_handler,
    test_non_digest_values_are_refused_without_echo,
    test_unknown_node_is_404,
    test_admin_token_is_required,
    test_uppercase_digest_is_normalised_so_case_cannot_dodge_the_guard,
)


def main():
    asyncio.set_event_loop(asyncio.new_event_loop())
    print("winn/3 per-node key digests")
    for fn in UNIT_TESTS:
        mod = fresh_hub()
        check(fn.__name__, lambda f=fn, m=mod: f(m))
    print()
    print(f"{PASSED[0]} passed, {len(FAILURES)} failed, {len(UNIT_TESTS)} total")
    for name, tb in FAILURES:
        print()
        print("=" * 70)
        print(name)
        print(tb)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
