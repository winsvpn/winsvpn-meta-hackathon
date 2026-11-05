#!/usr/bin/env python3
"""Hostile tests for deployment-verifier TLS trust-store custody."""

from __future__ import annotations

import importlib.util
import pathlib
import ssl
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFY_PATH = ROOT / "tools/verify_deployment_supply_chain.py"


def load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_deployment_supply_chain_tls_test", VERIFY_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load deployment supply-chain verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_stat(*, inode: int = 7, mode: int = 0o100644):
    return types.SimpleNamespace(
        st_dev=1,
        st_ino=inode,
        st_mode=mode,
        st_nlink=1,
        st_uid=0,
        st_gid=0,
        st_size=1024,
        st_mtime_ns=10,
        st_ctime_ns=11,
    )


class FakeContext:
    def __init__(self, *, certificates: bool, secure: bool = True):
        self._certificates = certificates
        self.check_hostname = secure
        self.verify_mode = ssl.CERT_REQUIRED if secure else ssl.CERT_NONE

    def get_ca_certs(self):
        return [{}] if self._certificates else []


class DeploymentSupplyChainTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_verifier()

    def test_existing_strict_default_context_is_used_without_path_open(self) -> None:
        context = FakeContext(certificates=True)
        with mock.patch.object(
            self.module.ssl, "create_default_context", return_value=context
        ), mock.patch.object(self.module.os, "open") as open_mock:
            self.assertIs(self.module.verified_ssl_context(), context)
        open_mock.assert_not_called()

    def test_empty_default_context_loads_held_root_owned_bundle(self) -> None:
        empty = FakeContext(certificates=False)
        loaded = FakeContext(certificates=True)
        with mock.patch.object(self.module.sys, "platform", "darwin"), mock.patch.object(
            self.module.ssl,
            "create_default_context",
            side_effect=[empty, loaded],
        ) as create_context, mock.patch.object(
            self.module.os, "open", return_value=99
        ), mock.patch.object(
            self.module.os, "fstat", side_effect=[fake_stat(), fake_stat()]
        ), mock.patch.object(self.module.os, "close") as close_mock:
            self.assertIs(self.module.verified_ssl_context(), loaded)
        self.assertEqual(create_context.call_args_list[1].kwargs, {"cafile": "/dev/fd/99"})
        close_mock.assert_called_once_with(99)

    def test_bundle_identity_change_during_load_fails_closed(self) -> None:
        empty = FakeContext(certificates=False)
        loaded = FakeContext(certificates=True)
        with mock.patch.object(self.module.sys, "platform", "darwin"), mock.patch.object(
            self.module.ssl,
            "create_default_context",
            side_effect=[empty, loaded],
        ), mock.patch.object(self.module.os, "open", return_value=99), mock.patch.object(
            self.module.os,
            "fstat",
            side_effect=[fake_stat(inode=7), fake_stat(inode=8)],
        ), mock.patch.object(self.module.os, "close"):
            with self.assertRaisesRegex(RuntimeError, "verification is unavailable"):
                self.module.verified_ssl_context()

    def test_insecure_loaded_context_fails_closed(self) -> None:
        empty = FakeContext(certificates=False)
        insecure = FakeContext(certificates=True, secure=False)
        with mock.patch.object(self.module.sys, "platform", "darwin"), mock.patch.object(
            self.module.ssl,
            "create_default_context",
            side_effect=[empty, insecure],
        ), mock.patch.object(self.module.os, "open", return_value=99), mock.patch.object(
            self.module.os, "fstat", side_effect=[fake_stat(), fake_stat()]
        ), mock.patch.object(self.module.os, "close"):
            with self.assertRaisesRegex(RuntimeError, "verification is unavailable"):
                self.module.verified_ssl_context()


if __name__ == "__main__":
    unittest.main()
