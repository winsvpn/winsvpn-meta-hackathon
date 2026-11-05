#!/usr/bin/env python3
"""Focused static regression tests for the local AWG 3.1 image contract.

These tests only pass source strings to the deployment validator. They never
invoke the image producer, Docker, cloud APIs, or a container registry.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from validate_deployment_scripts import (  # noqa: E402
    validate_awg_31_server_image_contract,
)


BUILDER = (ROOT / "server" / "build_amneziawg_go_server_image.sh").read_text(
    encoding="utf-8"
)
INSTALLERS = {
    "core": (ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh").read_text(
        encoding="utf-8"
    ),
    "data": (ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh").read_text(
        encoding="utf-8"
    ),
}


def contract_error(builder: str = BUILDER, installers: dict[str, str] | None = None) -> str | None:
    try:
        validate_awg_31_server_image_contract(
            builder=builder,
            installers=INSTALLERS if installers is None else installers,
        )
    except SystemExit as exc:
        return str(exc)
    return None


class Awg31ServerImageDeploymentValidationTests(unittest.TestCase):
    def test_live_sources_satisfy_the_awg_31_contract(self) -> None:
        self.assertIsNone(contract_error())

    def test_tag_must_match_the_local_image_name_and_installers(self) -> None:
        broken = BUILDER.replace(
            'AWG_GO_TAG="v3.1.20260828"',
            'AWG_GO_TAG="v3.1.20260815"',
            1,
        )
        error = contract_error(builder=broken)
        self.assertIsNotNone(error)
        self.assertIn("local image name", error)

    def test_tools_tag_must_remain_an_awg_31_release_pin(self) -> None:
        broken = BUILDER.replace(
            'AWG_TOOLS_TAG="v3.1.20260812"',
            'AWG_TOOLS_TAG="latest"',
            1,
        )
        error = contract_error(builder=broken)
        self.assertIsNotNone(error)
        self.assertIn("tools 3.1 release tag", error)

    def test_receipt_verification_cannot_be_removed(self) -> None:
        broken = BUILDER.replace(
            'die "Local image provenance receipt is missing or inconsistent."',
            'die "local image verification failed"',
            1,
        )
        error = contract_error(builder=broken)
        self.assertIsNotNone(error)
        self.assertIn("provenance", error)

    def test_producer_must_not_pull_or_push_a_registry_image(self) -> None:
        error = contract_error(builder=BUILDER + "\ndocker pull ${AWG_SERVER_IMAGE}\n")
        self.assertIsNotNone(error)
        self.assertIn("docker pull", error)

    def test_installer_hash_must_match_the_exact_builder_source(self) -> None:
        installers = dict(INSTALLERS)
        installers["data"] = installers["data"].replace(
            "AWG_SERVER_IMAGE_PRODUCER_SHA256=\"421648801780800bd9d09f0a4801d3760b80d25d48ccfe6f0a14c6f337532883\"",
            "AWG_SERVER_IMAGE_PRODUCER_SHA256=\"0000000000000000000000000000000000000000000000000000000000000000\"",
            1,
        )
        error = contract_error(installers=installers)
        self.assertIsNotNone(error)
        self.assertIn("PRODUCER_SHA256", error)

    def test_fresh_installs_must_refuse_a_symlinked_or_unhashed_producer(self) -> None:
        installers = dict(INSTALLERS)
        installers["data"] = installers["data"].replace(
            '[[ -f "${AWG_SERVER_IMAGE_PRODUCER_SOURCE}" && ! -L "${AWG_SERVER_IMAGE_PRODUCER_SOURCE}" ]]',
            '[[ -f "${AWG_SERVER_IMAGE_PRODUCER_SOURCE}" ]]',
            1,
        )
        error = contract_error(installers=installers)
        self.assertIsNotNone(error)
        self.assertIn("source-staging", error)

    def test_core_sync_agent_must_use_offline_provenance_verification(self) -> None:
        installers = dict(INSTALLERS)
        installers["core"] = installers["core"].replace(
            'image="$(bash "${AWG_SERVER_IMAGE_PRODUCER}" --verify)"',
            'image="$(bash "${AWG_SERVER_IMAGE_PRODUCER}" --ensure)"',
            1,
        )
        error = contract_error(installers=installers)
        self.assertIsNotNone(error)
        self.assertIn("source-staging", error)


if __name__ == "__main__":
    unittest.main(verbosity=2)
