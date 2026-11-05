#!/usr/bin/env python3
"""P2 P-15: real descriptor verification, LRU bounds, consumption and mutants.

Extract the shipped functions and their dependencies from the CP heredoc.
Use only standard-library imports, throwaway Ed25519 keys and an in-memory
SQLite database. No hub import, startup hook, host command or network access.
P2_CONTROL_PLANE_INSTALLER selects the immutable baseline for the red run.
"""
import ast
import base64
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import symtable
import tempfile
import threading
import time
import types
from typing import Any, Optional
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
INSTALLER = Path(os.environ.get("P2_CONTROL_PLANE_INSTALLER", HERE / "wins_control_plane_setup_ONETOUCH.sh"))
SCRIPT = INSTALLER.read_text(encoding="utf-8")
MATCH = re.search(r'cat > "\$\{APP_DIR\}/main.py" <<\'PYEOF\'\n(.*?)\nPYEOF\n', SCRIPT, re.S)
if MATCH is None:
    raise RuntimeError("CP main.py heredoc absent")
SOURCE = MATCH.group(1)
OPENSSL = os.environ.get("WINS_TEST_OPENSSL", "openssl")
DOMAIN = b"winsvpn-winn3-descriptor/v1"
MEASUREMENTS = {}


def load(source=SOURCE):
    tree = ast.parse(source)
    symbols = symtable.symtable(source, str(INSTALLER), "exec")
    blocks = {(block.get_name(), block.get_lineno()): block for block in symbols.get_children()}

    def global_names(block):
        names = {symbol.get_name() for symbol in block.get_symbols() if symbol.is_global() and symbol.is_referenced()}
        for child in block.get_children():
            names.update(global_names(child))
        return names
    definitions = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            definitions[node.name] = node
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    definitions[target.id] = node
    needed = set()
    pending = ["winn3_verify_descriptor_signature", "winn3_stored_descriptor", "winn3_inner_addresses_in_use"]
    while pending:
        name = pending.pop()
        if name in needed or name not in definitions:
            continue
        needed.add(name)
        node = definitions[name]
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            pending.extend(global_names(blocks[(node.name, node.lineno)]))
            if isinstance(node, ast.FunctionDef):
                pending.extend(n.id for n in ast.walk(node.args) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load))
        else:
            pending.extend(n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load))
    selected = {id(definitions[n]) for n in needed}
    module = ast.Module(body=[n for n in tree.body if id(n) in selected], type_ignores=[])
    imports = []
    for node in tree.body:
        if isinstance(node, ast.Import) and all(n.name.split(".")[0] in sys.stdlib_module_names for n in node.names):
            imports.append(node)
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in sys.stdlib_module_names:
            imports.append(node)
    namespace = {}
    exec(compile(ast.Module(body=imports, type_ignores=[]), "p2-stdlib-imports", "exec"), namespace)
    settings = {}
    env = types.SimpleNamespace(getenv=lambda name, default=None: settings.get(name, default))
    namespace.update(OrderedDict=OrderedDict, Any=Any, Optional=Optional, base64=base64,
                     hashlib=hashlib, ipaddress=ipaddress, json=json, os=env, re=re,
                     sqlite3=sqlite3, subprocess=subprocess, tempfile=tempfile,
                     threading=threading, time=time)
    # The verifier uses only os.path from this namespace in addition to getenv.
    env.path = os.path
    exec(compile(module, str(INSTALLER) + ":extracted-p2", "exec"), namespace)
    return types.SimpleNamespace(ns=namespace, settings=settings)


class Crypto:
    def __init__(self):
        self.work = tempfile.TemporaryDirectory(prefix="p2-test-keys-")
        self.directory = Path(self.work.name)
        self.keys = {}
        self.public = {}
        for slot in ("g1", "g2", "g3"):
            path = self.directory / (slot + ".pem")
            subprocess.run([OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", str(path)],
                           check=True, capture_output=True, timeout=10)
            raw = subprocess.run([OPENSSL, "pkey", "-in", str(path), "-pubout", "-outform", "DER"],
                                 check=True, capture_output=True, timeout=10).stdout
            if len(raw) != 44 or raw[:12] != bytes.fromhex("302a300506032b6570032100"):
                raise AssertionError("unexpected test public-key shape")
            self.keys[slot] = path
            self.public[slot] = base64.b64encode(raw[-32:]).decode("ascii")

    def sign(self, payload, slot="g1"):
        path = self.directory / "message.bin"
        path.write_bytes(DOMAIN + b"\x00" + payload)
        return subprocess.run([OPENSSL, "pkeyutl", "-sign", "-rawin", "-inkey", str(self.keys[slot]), "-in", str(path)],
                              check=True, capture_output=True, timeout=10).stdout


def payload(seq=1, slug="lab-cache", kid="g1", iat=None):
    issued = int(time.time()) - 60 if iat is None else iat
    return json.dumps({
        "v": 3, "alg": "ed25519", "kid": kid, "node": slug,
        "endpoint": "198.51.100.7:9111", "inner_router_v4": "10.10.0.1", "inner_resolver_v4": "10.10.0.1",
        "static_pub": base64.b64encode(b"S" * 32).decode(),
        "gateway_id": base64.b64encode(b"lab-gateway").decode(),
        "admission_secret": base64.b64encode(b"a" * 64).decode(),
        "admission_gen": 1, "tag_size": 32, "padding": "bucket", "bucket_window_s": 10,
        "max_skew_s": 60, "seq": seq, "iat": issued, "not_after": issued + 86400,
    }, sort_keys=True, separators=(",", ":")).encode()


class CacheTests(unittest.TestCase):
    source_override = None

    @classmethod
    def setUpClass(cls):
        cls.crypto = Crypto()

    @classmethod
    def tearDownClass(cls):
        cls.crypto.work.cleanup()

    def setUp(self):
        self.hub = load(self.source_override or SOURCE)
        self.ns = self.hub.ns
        for slot, public in self.crypto.public.items():
            self.hub.settings["WINN3_DESCRIPTOR_PUBKEY_" + slot.upper()] = public
        self.calls = []
        real_run = subprocess.run

        def run(args, **kwargs):
            self.calls.append(1)
            return real_run([OPENSSL, *args[1:]], **kwargs)

        self.ns["subprocess"] = types.SimpleNamespace(run=run, PIPE=subprocess.PIPE)
        self.message = payload()
        self.signature = self.crypto.sign(self.message)

    def verify(self, message=None, signature=None, slot="g1"):
        return self.ns["winn3_verify_descriptor_signature"](
            self.message if message is None else message,
            self.signature if signature is None else signature, slot)

    def cache(self):
        self.assertTrue("_WINN3_DESCRIPTOR_SIGNATURE_CACHE" in self.ns, "P-15 cache absent")
        return self.ns["_WINN3_DESCRIPTOR_SIGNATURE_CACHE"]

    def row(self, message=None, signature=None, slug="lab-cache"):
        return {"slug": slug, "winn3_descriptor_json": json.dumps({
            "payload": base64.b64encode(self.message if message is None else message).decode(),
            "sig": base64.b64encode(self.signature if signature is None else signature).decode()})}

    def test_hit_avoids_another_openssl_spawn(self):
        self.assertEqual(self.verify(), "g1")
        self.assertEqual(self.verify(), "g1")
        self.assertEqual(len(self.calls), 1)

    def test_changed_payload_and_signature_each_reverify(self):
        self.verify()
        for message, signature in ((self.message + b" ", self.signature),
                                   (self.message, bytes([self.signature[0] ^ 1]) + self.signature[1:])):
            with self.assertRaises(self.ns["Winn3ContractError"]):
                self.verify(message, signature)
        self.assertEqual(len(self.calls), 3)

    def test_slot_is_bound(self):
        self.verify()
        with self.assertRaises(self.ns["Winn3ContractError"]):
            self.verify(slot="g2")
        self.assertEqual(len(self.calls), 2)

    def test_ring_digest_is_in_the_cache_key(self):
        self.verify()
        first = tuple(self.cache())
        self.hub.settings["WINN3_DESCRIPTOR_PUBKEY_G2"] = self.crypto.public["g3"]
        self.verify()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(self.cache()), 1)
        self.assertNotEqual(first, tuple(self.cache()))

    def test_replaced_accepting_key_refuses_a_prior_hit(self):
        self.verify()
        self.hub.settings["WINN3_DESCRIPTOR_PUBKEY_G1"] = self.crypto.public["g2"]
        with self.assertRaises(self.ns["Winn3ContractError"]):
            self.verify()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(self.cache()), 0)

    def test_missing_and_empty_rings_clear_prior_hits(self):
        self.verify()
        del self.hub.settings["WINN3_DESCRIPTOR_PUBKEY_G1"]
        with self.assertRaises(self.ns["Winn3ContractError"]):
            self.verify()
        self.assertEqual(len(self.cache()), 0)
        self.hub.settings["WINN3_DESCRIPTOR_PUBKEY_G1"] = self.crypto.public["g1"]
        self.verify()
        self.hub.settings.clear()
        with self.assertRaises(self.ns["Winn3ContractError"]):
            self.verify()
        self.assertEqual(len(self.cache()), 0)

    def test_failed_checks_are_never_cached(self):
        bad = b"\x00" * 64
        for _ in range(2):
            with self.assertRaises(self.ns["Winn3ContractError"]):
                self.verify(signature=bad)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(self.cache()), 0)

    def test_verifier_timeout_is_never_cached(self):
        self.ns["subprocess"] = types.SimpleNamespace(run=lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("openssl", 15)), PIPE=subprocess.PIPE)
        for _ in range(2):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.verify()
        self.assertEqual(len(self.cache()), 0)

    def test_unknown_slot_and_bad_length_still_refuse(self):
        self.verify()
        for slot, signature in (("g4", self.signature), ("g1", b"short")):
            with self.assertRaises(self.ns["Winn3ContractError"]):
                self.verify(signature=signature, slot=slot)
        self.assertEqual(len(self.calls), 1)

    def test_only_digest_keys_and_accepting_slots_are_retained(self):
        self.verify()
        self.assertEqual(len(self.cache()), 1)
        for key, slot in self.cache().items():
            self.assertIsInstance(key, bytes)
            self.assertEqual(len(key), 32)
            self.assertEqual(slot, "g1")

    def test_clock_and_node_binding_run_on_each_consumption(self):
        stored = self.ns["winn3_stored_descriptor"]
        issued = json.loads(self.message)["iat"]
        row = self.row()
        self.assertTrue(stored(row))
        self.assertTrue(stored(row))
        self.assertEqual(len(self.calls), 1)
        reason = {}
        with patch.object(time, "time", return_value=issued + 86400):
            self.assertEqual(stored(row, reason_sink=reason), {})
            self.assertEqual(reason["reason"], "descriptor-expired")
            self.assertTrue(stored(row, clock_tolerant=True))
        with patch.object(time, "time", return_value=issued - 1):
            self.assertEqual(stored(row, reason_sink=reason), {})
            self.assertEqual(reason["reason"], "descriptor-not-yet-valid")
        self.assertEqual(stored(self.row(slug="lab-other"), reason_sink=reason), {})
        self.assertEqual(reason["reason"], "descriptor-node-mismatch")
        self.assertEqual(len(self.calls), 1)

    def test_shape_and_field_set_run_even_for_cached_signatures(self):
        for change in ({"extra": 1}, {"v": 2}, {"static_pub": "broken"}):
            decoded = json.loads(self.message)
            decoded.update(change)
            message = json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode()
            signature = self.crypto.sign(message)
            self.verify(message, signature)
            reason = {}
            self.assertEqual(self.ns["winn3_stored_descriptor"](self.row(message, signature), reason_sink=reason), {})
            self.assertTrue(reason)

    def test_lru_touch_preserves_the_recent_entry(self):
        self.cache()
        pairs = []
        for seq in range(257):
            message = payload(seq=seq)
            pairs.append((message, self.crypto.sign(message)))
        for pair in pairs[:256]:
            self.verify(*pair)
        self.verify(*pairs[0])
        self.verify(*pairs[256])
        count = len(self.calls)
        self.verify(*pairs[0])
        self.assertEqual(len(self.calls), count)
        self.verify(*pairs[1])
        self.assertEqual(len(self.calls), count + 1)
        self.assertLessEqual(len(self.cache()), 256)

    def test_10000_valid_versions_stay_bounded_and_eviction_reverifies(self):
        self.cache()
        first = None
        peak = 0
        for seq in range(10000):
            message = payload(seq=seq)
            signature = self.crypto.sign(message)
            if first is None:
                first = (message, signature)
            self.assertTrue(self.ns["winn3_stored_descriptor"](self.row(message, signature)))
            peak = max(peak, len(self.cache()))
            self.assertLessEqual(peak, 256)
        count = len(self.calls)
        self.verify(*first)
        self.assertEqual(len(self.calls), count + 1)
        MEASUREMENTS["valid_versions"] = 10000
        MEASUREMENTS["peak_cache_entries"] = peak
        MEASUREMENTS["verification_spawns_10000_versions"] = len(self.calls)

    def test_concurrent_hits_are_safe_and_bounded(self):
        self.verify()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.verify(), range(512)))
        self.assertEqual(results, ["g1"] * 512)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(self.cache()), 1)

    def test_ring_change_during_verification_cannot_repopulate_old_cache(self):
        entered, release = threading.Event(), threading.Event()
        real_run = self.ns["subprocess"].run
        paused_once = [False]

        def paused(args, **kwargs):
            result = real_run(args, **kwargs)
            if not paused_once[0]:
                paused_once[0] = True
                entered.set()
                if not release.wait(10):
                    raise AssertionError("test verifier release timed out")
            return result

        self.ns["subprocess"] = types.SimpleNamespace(run=paused, PIPE=subprocess.PIPE)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.verify)
            self.assertTrue(entered.wait(10))
            self.hub.settings["WINN3_DESCRIPTOR_PUBKEY_G1"] = self.crypto.public["g2"]
            try:
                with self.assertRaises(self.ns["Winn3ContractError"]):
                    self.verify()
            finally:
                release.set()
            self.assertEqual(future.result(timeout=10), "g1")
        self.assertEqual(len(self.cache()), 0)

    def test_64_slug_allocator_microbench_preserves_reservations(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        self.addCleanup(conn.close)
        conn.execute("CREATE TABLE nodes (slug TEXT, winn3_descriptor_json TEXT)")
        conn.execute("CREATE TABLE devices (winn3_inner_v4 TEXT)")
        for seq in range(64):
            slug = f"lab-cache-{seq}"
            message = payload(seq=seq, slug=slug)
            conn.execute("INSERT INTO nodes VALUES (?, ?)", (slug, self.row(message, self.crypto.sign(message), slug)["winn3_descriptor_json"]))
        allocation = self.ns["winn3_inner_addresses_in_use"]
        # Integration (INT2 s22): H3's canary reservations are read from the
        # hub database (winn3_canary_bindings) when no environment binding is
        # set, so the extracted module gets an empty database file of its own.
        hub_db = tempfile.NamedTemporaryFile(prefix="p2-cache-hub-", suffix=".db", delete=False)
        hub_db.close()
        self.addCleanup(os.unlink, hub_db.name)
        self.ns["DB_PATH"] = hub_db.name
        started = time.perf_counter()
        cold = allocation(conn)
        cold_s = time.perf_counter() - started
        count = len(self.calls)
        started = time.perf_counter()
        warm = allocation(conn)
        warm_s = time.perf_counter() - started
        self.assertEqual(cold, warm)
        self.assertIn("10.10.0.1", warm)
        self.assertEqual(count, 64)
        self.assertEqual(len(self.calls) - count, 0)
        MEASUREMENTS["allocator_64_slugs"] = {"cold_s": cold_s, "warm_s": warm_s, "cold_spawns": count, "warm_spawns": len(self.calls) - count}
        self.hub.settings["WINN3_DESCRIPTOR_PUBKEY_G1"] = self.crypto.public["g2"]
        self.assertNotIn("10.10.0.1", allocation(conn))


class MutantTests(unittest.TestCase):
    def test_cache_mutants_are_killed(self):
        if "_WINN3_DESCRIPTOR_SIGNATURE_CACHE" not in SOURCE:
            self.fail("P-15 cache absent; mutants cannot be applied to baseline")
        mutants = [
            ("no-ring-digest", "(slot.encode(\"ascii\"), payload, signature, ring_digest)", "(slot.encode(\"ascii\"), payload, signature)", "test_ring_digest_is_in_the_cache_key"),
            ("no-payload", "(slot.encode(\"ascii\"), payload, signature, ring_digest)", "(slot.encode(\"ascii\"), signature, ring_digest)", "test_changed_payload_and_signature_each_reverify"),
            ("no-signature", "(slot.encode(\"ascii\"), payload, signature, ring_digest)", "(slot.encode(\"ascii\"), payload, ring_digest)", "test_changed_payload_and_signature_each_reverify"),
            ("no-slot", "(slot.encode(\"ascii\"), payload, signature, ring_digest)", "(payload, signature, ring_digest)", "test_slot_is_bound"),
            ("no-ring-clear", "_WINN3_DESCRIPTOR_SIGNATURE_CACHE.clear()", "pass", "test_replaced_accepting_key_refuses_a_prior_hit"),
            ("unbounded", "WINN3_DESCRIPTOR_SIGNATURE_CACHE_LIMIT = 256", "WINN3_DESCRIPTOR_SIGNATURE_CACHE_LIMIT = 10000", "test_lru_touch_preserves_the_recent_entry"),
            ("no-lru-touch", "_WINN3_DESCRIPTOR_SIGNATURE_CACHE.move_to_end(cache_key)", "pass", "test_lru_touch_preserves_the_recent_entry"),
            ("stale-inflight-insert", "if _WINN3_DESCRIPTOR_SIGNATURE_CACHE_RING == ring_digest:", "if True:", "test_ring_change_during_verification_cannot_repopulate_old_cache"),
            ("skip-consumption-validation", "normalized = validate_winn3_descriptor_payload(decoded, slug=slug)", "normalized = decoded", "test_clock_and_node_binding_run_on_each_consumption"),
        ]
        kills = []
        for name, old, new, method in mutants:
            with self.subTest(mutant=name):
                self.assertTrue(old in SOURCE, "mutant target absent: " + name)
                case = CacheTests(method)
                case.crypto = self.crypto
                case.source_override = SOURCE.replace(old, new)
                result = unittest.TestResult()
                case.run(result)
                self.assertEqual(result.testsRun, 1)
                self.assertFalse(result.errors, "mutant must fail an assertion, not setup or syntax")
                self.assertEqual(len(result.failures), 1, "mutant survived")
                kills.append(name)
        MEASUREMENTS["mutants_killed"] = kills

    @classmethod
    def setUpClass(cls):
        cls.crypto = Crypto()

    @classmethod
    def tearDownClass(cls):
        cls.crypto.work.cleanup()


if __name__ == "__main__":
    program = unittest.main(exit=False, verbosity=2)
    print("P2_MEASUREMENTS " + json.dumps(MEASUREMENTS, sort_keys=True))
    raise SystemExit(not program.result.wasSuccessful())
