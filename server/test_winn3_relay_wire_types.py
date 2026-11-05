#!/usr/bin/env python3
"""Wire types of the ciphertext relay (w3r/2): the three fields whose pydantic
annotation decides whether a malformed value is refused by OUR strict code or
rejected (422) or coerced by pydantic before our code ever runs.

  * LoginRequest.supports_winn3_relay and FreeAccessRequest.supports_winn3_relay
    are typed `Any`, so request_client_capabilities sees the RAW value and
    refuses "true", 1 or [] as a malformed capability advertisement (H3). A typed
    `bool` would coerce "true" and 1 to True and upgrade a client that never
    advertised the capability.
  * CoreRegistration.relay is typed `Any`, so a malformed relay report (a scalar,
    a list, an object of the wrong shape) reaches sanitize_core_relay_report,
    is dropped whole and NEVER fails the registration with a 422: the Core's
    AmneziaWG heartbeat keeps working (H2).

Two layers, because pydantic is NOT installed on every machine that runs this
battery (it is not on the Mac this packet was built on):

  * SOURCE tests always run: they read the three annotations straight out of the
    hub source AST and run the strict capability check on raw values.
  * PYDANTIC tests run only when pydantic is importable; otherwise they are
    skipped with an explicit reason and the report must say NOT_RUN. They build a
    real pydantic model from the SAME annotation text and prove the wire
    behaviour the source tests can only imply.

Run:  python3 server/test_winn3_relay_wire_types.py
"""
import _toolchain  # noqa: F401
import ast
import os
import shutil
import sys
import unittest
from typing import Any, Optional

# The hub harness installs a pydantic stub in sys.modules. Capture the real
# wire constructor before importing that harness, or the real-wire tests run
# against the stub whenever pydantic is installed.
try:
    import pydantic as real_pydantic
    from pydantic import AliasChoices as RealAliasChoices
    from pydantic import Field as RealField
    from pydantic import create_model as real_create_model
except ImportError:
    real_pydantic = None
    RealAliasChoices = RealField = real_create_model = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_account_deletion_hub as harness  # noqa: E402
import test_winn3_descriptor_hub as desc  # noqa: E402

HAVE_PYDANTIC = real_create_model is not None
FIELDS = (("LoginRequest", "supports_winn3_relay"),
          ("FreeAccessRequest", "supports_winn3_relay"),
          ("CoreRegistration", "relay"))


def hub_tree():
    return ast.parse(harness._extract_main_block())


def field_node(tree, class_name, field_name):
    definition = next(node for node in tree.body
                      if isinstance(node, ast.ClassDef) and node.name == class_name)
    return next(node for node in definition.body
                if isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name) and node.target.id == field_name)


class RelayWireTypeSource(unittest.TestCase):
    """Always runs: the annotations and the strict check on raw values."""

    @classmethod
    def setUpClass(cls):
        cls.tree = hub_tree()

    def test_the_three_fields_are_annotated_any(self):
        for class_name, field_name in FIELDS:
            with self.subTest(model=class_name, field=field_name):
                node = field_node(self.tree, class_name, field_name)
                self.assertIsInstance(node.annotation, ast.Name)
                self.assertEqual("Any", node.annotation.id)

    def test_the_relay_capability_keeps_both_wire_spellings_and_a_false_default(self):
        for class_name in ("LoginRequest", "FreeAccessRequest"):
            with self.subTest(model=class_name):
                text = ast.unparse(field_node(self.tree, class_name, "supports_winn3_relay").value)
                self.assertIn("default=False", text)
                self.assertIn("'supports_winn3_relay'", text)
                self.assertIn("'supportswinn3relay'", text)

    def test_the_relay_report_defaults_to_absent(self):
        text = ast.unparse(field_node(self.tree, "CoreRegistration", "relay").value)
        self.assertIn("default=None", text)

    def test_no_neighbouring_capability_was_loosened(self):
        # The bool typed siblings stay bool: only the relay field is raw.
        for field_name in ("supports_winn3", "supports_winn3_descriptor", "supports_winn3_dualauth"):
            with self.subTest(field=field_name):
                node = field_node(self.tree, "LoginRequest", field_name)
                self.assertEqual("bool", node.annotation.id)


class RelayCapabilityStrictness(unittest.TestCase):
    """Always runs: what the hub does with the RAW value once pydantic is out of
    the way (the field is Any, so this is exactly what a request reaches)."""

    @classmethod
    def setUpClass(cls):
        cls.mod = desc.load_hub_with_ring(HIDE_CONTROL_ORIGIN="0", DOUBLE_VPN_ENABLED="1")
        if real_pydantic is not None:
            # The extracted hub has already captured the harness model classes.
            # Restore the real package before the independent wire tests run.
            sys.modules["pydantic"] = real_pydantic
        cls.addClassCleanup(shutil.rmtree, cls.mod._TMPDIR, ignore_errors=True)
        for handler in list(cls.mod.logger.handlers):
            handler.close()
            cls.mod.logger.removeHandler(handler)

    class Payload:
        def __init__(self, value):
            self.supports_winn3_relay = value

    def test_malformed_raw_values_are_refused_not_coerced(self):
        for raw in ("true", "false", "1", 1, 0, 2, [], {}, ["true"], "yes"):
            with self.subTest(raw=raw):
                with self.assertRaises(self.mod.Winn3ContractError) as caught:
                    self.mod.request_client_capabilities(self.Payload(raw))
                self.assertEqual("client-capability-malformed", caught.exception.reason)
                self.assertEqual(["supports_winn3_relay"], list(caught.exception.keys))

    def test_booleans_and_absence_are_accepted(self):
        self.assertTrue(self.mod.request_client_capabilities(self.Payload(True))["supports_winn3_relay"])
        for value in (False, None):
            self.assertNotIn("supports_winn3_relay",
                             self.mod.request_client_capabilities(self.Payload(value)))

    def test_a_malformed_relay_report_never_raises_out_of_the_sanitizer(self):
        for raw in ("junk", [], 42, 3.5, True, {"v": []}, {"v": 1, "state": ["x"]}, [[]], None):
            with self.subTest(raw=raw):
                clean, reason = self.mod.sanitize_core_relay_report(raw)
                self.assertIsNone(clean)
                self.assertTrue(reason.startswith("relay-report-"), reason)


@unittest.skipUnless(HAVE_PYDANTIC, "pydantic is not installed here: the real wire behaviour is NOT_RUN "
                                    "(the source level checks above still ran)")
class RelayWireTypesRealPydantic(unittest.TestCase):
    """Real pydantic, built from the hub's own annotation and field text."""

    @classmethod
    def setUpClass(cls):
        cls.tree = hub_tree()

    def wire_model(self, class_name, field_name):
        node = field_node(self.tree, class_name, field_name)
        namespace = {"Any": Any, "Optional": Optional, "Field": RealField,
                     "AliasChoices": RealAliasChoices}
        annotation = eval(compile(ast.Expression(node.annotation), "<annotation>", "eval"), namespace)
        default = eval(compile(ast.Expression(node.value), "<field>", "eval"), namespace)
        return real_create_model("Wire" + class_name, **{field_name: (annotation, default)})

    def test_relay_capability_preserves_malformed_raw_values(self):
        for name, raw in (("LoginRequest", "true"), ("FreeAccessRequest", 1), ("LoginRequest", [])):
            with self.subTest(model=name, raw=raw):
                model = self.wire_model(name, "supports_winn3_relay")
                parsed = model.model_validate({"supports_winn3_relay": raw})
                self.assertEqual(parsed.supports_winn3_relay, raw)
                self.assertIs(type(parsed.supports_winn3_relay), type(raw))

    def test_both_spellings_reach_the_field(self):
        model = self.wire_model("LoginRequest", "supports_winn3_relay")
        self.assertIs(model.model_validate({"supportswinn3relay": True}).supports_winn3_relay, True)
        self.assertIs(model.model_validate({}).supports_winn3_relay, False)

    def test_a_bad_relay_report_reaches_the_sanitizer(self):
        model = self.wire_model("CoreRegistration", "relay")
        for raw in ("junk", [], 42, {"v": "x"}):
            with self.subTest(raw=raw):
                self.assertEqual(model.model_validate({"relay": raw}).relay, raw)
        self.assertIsNone(model.model_validate({}).relay)


if __name__ == "__main__":
    unittest.main(verbosity=2)
