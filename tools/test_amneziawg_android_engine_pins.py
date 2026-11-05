#!/usr/bin/env python3
"""ANDROID-AWG31: recipe and committed AAR must name official v3.1, not zaneschepke."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "build_amneziawg_android_engine.sh"
OVERLAY = ROOT / "tools" / "amneziawg_android_official_jni"
AAR = ROOT / "android" / "app" / "libs" / "amneziawg.aar"
DEVICECHECK_BUILD = ROOT / "android" / "devicecheck" / "build_devicecheck.sh"
RESPONDER = ROOT / "android" / "devicecheck" / "awgresponder"
EXPECTED_AAR_SHA256 = "e4cc912ec3f1e63e9d46c47063fefb908837253c888bb771ee11a5115df274d6"


class AmneziawgAndroidEnginePinTest(unittest.TestCase):
    def test_build_script_pins_official_v31(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            'AWG_ANDROID_REPO="https://github.com/amnezia-vpn/amneziawg-android.git"',
            text,
        )
        self.assertIn('AWG_ANDROID_TAG="v3.1.20260814"', text)
        self.assertIn('AWG_ANDROID_COMMIT="5c16489e2cd9ed3a0a7a27c7445bba5238132f86"', text)
        self.assertIn('AWG_GO_TAG="v3.1.20260828"', text)
        self.assertIn(
            'AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"',
            text,
        )
        self.assertIn(
            'AWG_GO_SOURCE_SHA256="10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4"',
            text,
        )
        self.assertIn('REVIEWED_GO_VERSION="1.27.1"', text)
        self.assertNotEqual(
            "5c16489e2cd9ed3a0a7a27c7445bba5238132f86",
            "b5928efb6ca19f0153958460c3d141f04abc5c2e",
        )
        self.assertNotIn("zaneschepke/amneziawg-android.git", text)
        self.assertNotIn("ffb71fb3bcd15ac011ad7cfbe05f76d150fc37f9", text)
        self.assertNotIn("c1e9bb3758e71bb1adc402598465565bfc9663fd", text)
        self.assertIn("stability designation unavailable", text)
        self.assertNotIn("Companion latest-stable Go engine", text)
        self.assertNotIn("is not latest stable", text)

    def test_wrapper_engine_requirement_is_raised_to_frozen_go_tag(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        for pin in (
            'WRAPPER_REQUIRED_ENGINE_TAG="v3.1.20260814"',
            'WRAPPER_REQUIRED_ENGINE_H1="h1:l2AhBD+sFycU8Im81n/bZORMxW7fWtlZJEuJ4Hh0+z0="',
            'AWG_GO_MODULE_H1="h1:D8d8gGvwXcTxUIsE4z6F6vjy4/VZddu95vMNtOygh1c="',
            'OVERRIDDEN_GO_MOD_SHA256="05c0ab6a8b010a334e5443199789462ca2a29ede3e7a9b15e6049c9c13d1bd53"',
            'OVERRIDDEN_GO_SUM_SHA256="b6e8c738a3eec160d0cc58d10ea6dbbf17886b122ed140a379bd9a29eec8df82"',
            "tunnel/tools/libwg-go/go.mod\\n",
            "tunnel/tools/libwg-go/go.sum\\n",
            "was not linked against amneziawg-go ${AWG_GO_TAG}.",
        ):
            self.assertIn(pin, text)
        # The pristine upstream locks stay pinned; only the post-verification
        # copy is rewritten.
        self.assertIn(
            'UPSTREAM_GO_MOD_SHA256="cde303cebd847b122373b4d714645b8480d48283570ab9b0bc6540c364724a16"',
            text,
        )
        self.assertIn(
            'UPSTREAM_GO_SUM_SHA256="f8de8667720b798be4a9f2db1dd5eff0cbf09d05409fa80bec8abc6049c79e3d"',
            text,
        )

    def test_overlay_is_official_v3_plus_live_peer(self) -> None:
        api = (OVERLAY / "api-android.go").read_text(encoding="utf-8")
        adapt = (OVERLAY / "uapi_adapt.go").read_text(encoding="utf-8")
        self.assertIn("github.com/amnezia-vpn/amneziawg-go/v3", api)
        self.assertIn("awgUpdateTunnelPeers", api)
        self.assertNotIn("zaneschepke", api)
        self.assertNotIn("wireproxyawg", adapt)

    def test_devicecheck_responder_matches_official_v31_engine(self) -> None:
        module = (RESPONDER / "go.mod").read_text(encoding="utf-8")
        source = (RESPONDER / "main.go").read_text(encoding="utf-8")
        build = DEVICECHECK_BUILD.read_text(encoding="utf-8")

        self.assertIn("go 1.27.1", module)
        self.assertIn(
            "github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828",
            module,
        )
        self.assertIn(
            "// AWG_GO_COMMIT=b5928efb6ca19f0153958460c3d141f04abc5c2e",
            module,
        )
        self.assertNotIn("replace ", module)
        self.assertNotIn("github.com/wgtunnel/", module)
        for package in ("conn", "device", "tun"):
            self.assertIn(
                f'"github.com/amnezia-vpn/amneziawg-go/v3/{package}"',
                source,
            )
        self.assertIn(
            "device.NewDevice(stub, conn.NewStdNetBind(), logger)",
            source,
        )
        self.assertIn('REVIEWED_GO_VERSION="1.27.1"', build)
        self.assertIn('AWG_GO_VERSION="v3.1.20260828"', build)
        self.assertIn(
            'AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"',
            build,
        )
        self.assertEqual(
            build.count("# DEVICECHECK_PRODUCER_DISABLED=immutable-compiler-input-v1"),
            1,
        )
        self.assertIn(
            'echo "OWNER-BLOCKED: immutable compiler-input handoff is not '
            'implemented by the external controller/loader." >&2\nexit 1',
            build,
        )
        active_build = "\n".join(
            line
            for line in build.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        self.assertNotIn("${GO_BIN}", active_build)
        self.assertNotIn("gradlew", active_build)
        self.assertNotIn("sdkmanager", active_build)
        self.assertNotRegex(active_build, r"(?m)(?:^|[;&|]\s*)adb(?:\s|$)")
        self.assertNotIn("WINN_DEVICECHECK_PRODUCER_ONLY", active_build)
        self.assertNotIn("exit 0", active_build)
        self.assertNotIn("PASS", active_build)

    def test_committed_aar_is_official_v3(self) -> None:
        actual = hashlib.sha256(AAR.read_bytes()).hexdigest()
        self.assertEqual(EXPECTED_AAR_SHA256, actual)
        with zipfile.ZipFile(AAR) as archive:
            names = set(archive.namelist())
            for abi in ("arm64-v8a", "armeabi-v7a", "x86", "x86_64"):
                for library in ("libam-go.so", "libam.so", "libam-quick.so"):
                    self.assertIn(f"jni/{abi}/{library}", names)
            members = [
                name
                for name in archive.namelist()
                if name.startswith("jni/") and name.endswith("libam-go.so")
            ]
            self.assertGreaterEqual(len(members), 4)
            for member in members:
                native = archive.read(member)
                self.assertIn(b"go1.27.1", native, member)
                self.assertIn(b"github.com/amnezia-vpn/amneziawg-go/v3", native, member)
                self.assertNotIn(b"github.com/wgtunnel/amneziawg-go", native, member)
                self.assertIn(b"Java_org_amnezia_awg_GoBackend_awgUpdateTunnelPeers", native, member)
            with archive.open("classes.jar") as classes_file:
                with zipfile.ZipFile(classes_file) as classes:
                    class_names = set(classes.namelist())
                    self.assertIn(
                        "org/amnezia/awg/backend/AwgQuickBackend.class",
                        class_names,
                    )
                    self.assertNotIn(
                        "org/amnezia/awg/ProxyGoBackend.class",
                        class_names,
                    )
                    backend = classes.read("org/amnezia/awg/GoBackend.class")
                    self.assertIn(b"awgUpdateTunnelPeers", backend)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
