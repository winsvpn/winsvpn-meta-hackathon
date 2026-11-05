#!/usr/bin/env python3
"""Contract tests for the owner-approved D1 legal and store-preparation lane."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class D1LegalPolicyPublicationTests(unittest.TestCase):
    def test_every_human_facing_d1_document_retains_review_status(self) -> None:
        documents = (
            "legal/DRAFT_BROWSER_EXTENSION_PRIVACY_POLICY.txt",
            "legal/MASTER_LEGAL_DOCUMENT.txt",
            "legal/APP_PRIVACY_POLICY.txt",
            "legal/SERVER_LEGAL_DOCUMENT.txt",
            "legal/WEBSITE_PRIVACY.html",
            "web/browser-extension-privacy/index.html",
            "web/billing/index.html",
            "web/privacy/index.html",
            "web/terms/index.html",
            "web/vdp/index.html",
            "web/trusted-contact/index.html",
            "web/source/index.html",
            "app_store/apple/metadata/app_information.md",
            "app_store/apple/metadata/pricing_availability.md",
            "app_store/apple/review/export_compliance_facts.txt",
            "app_store/apple/review/privacy_answers.md",
            "app_store/apple/review/submission_answer_sheet.md",
            "app_store/apple/review/owner_review_packet.md",
            "app_store/apple/review/ios_review_notes.txt",
            "app_store/apple/review/macos_review_notes.txt",
            "docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md",
            "app_store/linux/review/flathub_submission_decision.md",
            "app_store/linux/review/snap_interface_request.md",
        )
        for relative in documents:
            with self.subTest(relative=relative):
                normalized = read(relative).lower().replace("-", " ")
                self.assertIn("owner approved", normalized)
                self.assertIn("counsel review pending", normalized)

    def test_extension_policy_is_published_and_all_listings_use_final_url(self) -> None:
        policy_url = "https://www.winsvpn.org/browser-extension-privacy/"
        self.assertIn(policy_url, read("legal/DRAFT_BROWSER_EXTENSION_PRIVACY_POLICY.txt"))
        self.assertIn(policy_url, read("extension/store_listings/privacy_label_manifest.json"))
        for relative in (
            "extension/store_listings/chrome.md",
            "extension/store_listings/edge.md",
            "extension/store_listings/firefox.md",
        ):
            with self.subTest(relative=relative):
                self.assertIn(policy_url, read(relative))
        self.assertIn(
            "https://www.winsvpn.org/browser-extension-privacy/",
            read("web/sitemap.xml"),
        )

    def test_recurring_terms_precede_site_and_app_purchase_actions(self) -> None:
        billing = read("web/billing/index.html")
        for required in (
            "charged by PayPal each month until canceled",
            "charged by PayPal each year until canceled",
            "Cancel before the next billing date",
            "does not automatically refund earlier charges",
            "non-waivable rights",
            "A partial refund does not automatically end",
        ):
            self.assertIn(required, billing)

        site = read("web/index.html")
        monthly_terms = site.index("$0.99 charged by PayPal every month until canceled")
        monthly_action = site.index("Choose Monthly", monthly_terms)
        yearly_terms = site.index("$11.88 charged by PayPal every year until canceled")
        yearly_action = site.index("Choose Yearly", yearly_terms)
        self.assertLess(monthly_terms, monthly_action)
        self.assertLess(yearly_terms, yearly_action)
        self.assertIn('href="/billing/"', site)

        app = read("lib/main.dart")
        app_terms = app.index("The 1 Month and 1 Year plans are recurring PayPal subscriptions")
        monthly_action = app.index("_launchPaymentURL(_trackedPaymentUrl('one_month'))", app_terms)
        yearly_action = app.index("_launchPaymentURL(_trackedPaymentUrl('one_year'))", app_terms)
        self.assertLess(app_terms, monthly_action)
        self.assertLess(app_terms, yearly_action)

    def test_canonical_legal_version_and_public_routes_are_wired(self) -> None:
        master = read("legal/MASTER_LEGAL_DOCUMENT.txt")
        self.assertIn("2026-08-31.v4", master)
        master_lower = master.lower()
        for required in (
            "Vulnerability Disclosure Program",
            "Trusted contact and duress response",
            "Insurance and risk transfer",
            "Hold harmless",
            "Limitation of liability",
            "non-waivable",
        ):
            self.assertIn(required.lower(), master_lower)

        sitemap = read("web/sitemap.xml")
        for route in ("/terms/", "/billing/", "/vdp/", "/trusted-contact/", "/source/"):
            with self.subTest(route=route):
                self.assertIn(f"https://www.winsvpn.org{route}", sitemap)

        client = read("lib/main.dart")
        server = read("server/wins_control_plane_setup_ONETOUCH.sh")
        self.assertIn("static const String _legalDocumentVersion = '2026-08-31.v4';", client)
        self.assertIn('LEGAL_DOCUMENT_VERSION_DEFAULT="2026-08-31.v4"', server)
        self.assertIn("https://www.winsvpn.org/billing/", client)
        self.assertIn("https://www.winsvpn.org/trusted-contact/", server)
        scope = "Win's VPN does not ship this feature."
        for relative in (
            "legal/APP_PRIVACY_POLICY.txt",
            "legal/SERVER_LEGAL_DOCUMENT.txt",
            "legal/WEBSITE_PRIVACY.html",
            "web/privacy/index.html",
        ):
            with self.subTest(relative=relative):
                self.assertIn(scope, read(relative))
        self.assertEqual(read("legal/WEBSITE_PRIVACY.html"), read("web/privacy/index.html"))
        trusted = read("web/trusted-contact/index.html")
        self.assertIn("There is no duress code, no duress wipe", trusted)
        self.assertIn("declares no SMS permission and sends no SMS", trusted)
        source = read("web/source/index.html")
        self.assertIn("Version 2026-08-25.v3", source)
        self.assertIn("does not claim that unavailable source bytes are public", source)
        self.assertIn("no live-fetch receipt or SHA-256 digest exists", source)
        self.assertIn("Release publication remains blocked", source)
        self.assertIn(
            'EMERGENCY_DISPATCH_ENABLED = _emergency_flag("EMERGENCY_DISPATCH_ENABLED", False)',
            server,
        )
        self.assertIn(
            "if EMERGENCY_DISPATCH_ENABLED:\n"
            "        asyncio.create_task(emergency_outbox_sweep_loop())",
            server,
        )
        for relative in (
            "legal/APP_PRIVACY_POLICY.txt",
            "legal/SERVER_LEGAL_DOCUMENT.txt",
            "legal/WEBSITE_PRIVACY.html",
            "web/privacy/index.html",
        ):
            with self.subTest(relative=relative):
                self.assertIn(
                    "Android TV and desktop builds have neither.", read(relative)
                )

    def test_apple_answer_sheet_is_conservative_and_portal_safe(self) -> None:
        sheet = read("app_store/apple/review/submission_answer_sheet.md")
        for required in (
            "United States only",
            "ITSAppUsesNonExemptEncryption`: **YES**",
            "Purchase History: **Not Collected**",
            "Product Interaction: **Collected**",
            "without `(R)`",
            "No App Store Connect action was taken",
            "Myanmar is a core intended beneficiary context",
        ):
            self.assertIn(required, sheet)

        export = json.loads(read("app_store/apple/review/export_compliance_status.json"))
        self.assertEqual(export["status"], "approved")
        self.assertIs(export["its_app_uses_non_exempt_encryption"], True)
        self.assertIs(export["apple_declaration_approved"], False)

        signoff = json.loads(read("app_store/apple/review/owner_signoff.json"))
        self.assertIs(signoff["submission_approved"], False)
        self.assertIs(signoff["owner_authorization"]["upload_authorized"], False)
        self.assertIn(
            "United States storefront only",
            signoff["required_decisions"]["pricing_and_availability"]["approved_value"],
        )

    def test_android_vpn_consent_has_separate_timestamp_and_server_binding(self) -> None:
        client = read("lib/main.dart")
        server = read("server/wins_control_plane_setup_ONETOUCH.sh")
        for required in (
            "_androidVpnServiceDisclosureAcceptedAtUtc",
            "DateTime.now().toUtc().toIso8601String()",
            "android_vpn_service_disclosure_accepted_at",
            "acceptedAt != null && acceptedAt.isUtc",
        ):
            self.assertIn(required, client)
        for required in (
            'ANDROID_VPN_SERVICE_DISCLOSURE_VERSION = "2026-08-31.v3"',
            "accepted_android_vpn_service_disclosure INTEGER DEFAULT 0",
            "android_vpn_service_disclosure_accepted_at TEXT DEFAULT ''",
            'sqlite_add_column_if_missing legal_acceptances android_vpn_service_disclosure_accepted_at "TEXT DEFAULT \'\'"',
            'row.get("android_vpn_service_disclosure_accepted_at")',
        ):
            self.assertIn(required, server)

    def test_linux_store_decisions_remain_unsubmitted(self) -> None:
        flathub = read("app_store/linux/review/flathub_submission_decision.md")
        self.assertIn("Adopt `org.winsvpn.WinsVPN`", flathub)
        self.assertIn("polkit", flathub)
        self.assertIn("NO application for the mature-project AI-policy exception", flathub)
        self.assertIn("INELIGIBLE / HELD", flathub)

        snap = read("app_store/linux/review/snap_interface_request.md")
        self.assertIn("strict confinement", snap)
        self.assertIn("network-control", snap)
        self.assertIn("network-observe", snap)
        self.assertIn("firewall-control", snap)
        self.assertIn("No Snap Store action", snap)


if __name__ == "__main__":
    unittest.main()
