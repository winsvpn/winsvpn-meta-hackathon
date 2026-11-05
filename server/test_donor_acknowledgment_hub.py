#!/usr/bin/env python3
"""Hub tests for the donor acknowledgment / certificate-of-recognition engine.

Like test_account_deletion_hub.py these exercise the REAL control-plane
source: the module is extracted from the `cat > "${APP_DIR}/main.py"
<<'PYEOF'` heredoc inside wins_control_plane_setup_ONETOUCH.sh and exec'd with
stubs for its three third-party imports. Nothing here is a reimplementation,
so a regression in the shipped installer fails these tests.

The SMTP transport is monkeypatched in every test that sends. No mail leaves
this process, and no test needs network, a live hub, or a real donor.

Run:  python3 server/test_donor_acknowledgment_hub.py
"""
from contextlib import closing
import _toolchain  # noqa: F401  (V-01 preflight)
import inspect
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Reuse the deletion suite's extraction harness so both suites are provably
# reading the same heredoc out of the same installer.
import test_account_deletion_hub as harness  # noqa: E402
from test_account_deletion_hub import BackgroundTasks, FakeRequest, HTTPException  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE = os.path.join(REPO, "brand", "donor_recognition", "certificate-of-recognition.svg")

RESULTS = []
_TMPDIRS = []


def test(fn):
    RESULTS.append(fn)
    return fn


test.__test__ = False


def call_handler(handler, *args, **kwargs):
    result = handler(*args, **kwargs)
    if inspect.isawaitable(result):
        return harness.asyncio.run(result)
    return result


class SentMail:
    """Stands in for smtp_dispatch_message. Records instead of sending."""

    def __init__(self, succeed=True):
        self.succeed = succeed
        self.messages = []

    def __call__(self, message, to_email):
        self.messages.append((message, to_email))
        return self.succeed


def load(**env):
    """Load the hub with the donor engine pointed at the real artwork and a
    private output directory."""
    outdir = tempfile.mkdtemp(prefix="wins-ack-out-")
    _TMPDIRS.append(outdir)
    settings = {
        "DONOR_CERT_TEMPLATE_PATH": TEMPLATE,
        "DONOR_CERT_OUTPUT_DIR": outdir,
        "SMTP_USER": "smtp-user",
        "SMTP_PASS": "smtp-pass",
        # load_hub() mutates the real os.environ, so EVERY knob this engine
        # reads has to be restated on each load. Without this a test that sets
        # one to "0" silently changes the behaviour of every later test.
        "DONOR_ACK_SIGNATORY_NAME": "",
        "DONOR_ACK_SIGNATORY_TITLE": "",
        "DONOR_ACK_ORG_CONTACT": "",
        "DONOR_ORG_EIN": "42-3223917",
        "DONOR_UNTIERED_LABEL": "SUPPORTER",
        "DONOR_CERT_MIN_AMOUNT": "100",
        "DONOR_ACK_ISSUE_BELOW_THRESHOLD": "1",
        "DONOR_ACK_AUTO_ISSUE": "1",
        "DONOR_TREAT_UNCLASSIFIED_ONE_TIME_AS_DONATION": "1",
        # Same reason, for the payment knobs the trigger consults. The webhook
        # tests below turn PayPal on; without restating these, every test that
        # loads afterwards would classify payments against that leftover
        # configuration instead of its own.
        "PAYPAL_CLIENT_ID": "",
        "PAYPAL_CLIENT_SECRET": "",
        "PAYPAL_WEBHOOK_ID": "",
        "PAYPAL_PLAN_1M": "",
        "PAYPAL_PLAN_1Y": "",
        "PAYPAL_PLAN_PERSONAL": "",
        "PAYPAL_DONATION_URL": "",
        "PAYPAL_LIFETIME_SUPPORT_URL": "",
        "PAYPAL_LIFETIME_NO_SUPPORT_URL": "",
        "PAYPAL_LIFETIME_SUPPORT_AMOUNT": "",
        "PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT": "",
        "PAYPAL_LIFETIME_CURRENCY": "",
        "PAYPAL_DONATION_MARKERS": "donation,donate,general_donation,contribution",
        "PAYPAL_PLAN_MARKERS": "one_month,one_year,wins_plan,personal_plan",
    }
    settings.update({k: str(v) for k, v in env.items()})
    mod = harness.load_hub(**settings)
    # No test may reach a real SMTP server or a real PDF converter.
    mod.smtp_dispatch_message = SentMail()
    mod._SENT = mod.smtp_dispatch_message
    mod._OUTDIR = outdir
    return mod


def no_pdf(mod):
    """Skip the converter probe (subprocess) and take the SVG-only path."""
    mod.donor_svg_to_pdf = lambda svg: (b"", "test_no_converter")


def issue(mod, **kwargs):
    kwargs.setdefault("donor_name", "Alexandra M. Whitfield")
    kwargs.setdefault("donor_email", "donor@example.test")
    kwargs.setdefault("gifts", [{"date": "2026-08-03", "amount": "250.00"}])
    return mod.donor_issue_and_deliver(**kwargs)


def _body(message):
    """Decode the covering note. MIMEText with an explicit charset is
    base64-encoded, so the raw payload is not readable text."""
    return message.get_payload()[0].get_payload(decode=True).decode()


def row(mod, ack_number):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT * FROM donation_acknowledgments WHERE ack_number = ?", (ack_number,)
        ).fetchone()


# ===================== field derivation: tier boundaries ==================

@test
def test_tier_derivation_at_every_boundary():
    mod = load()
    cases = [
        ("0.01", ""), ("99.99", ""),
        ("100.00", "BRONZE"), ("999.99", "BRONZE"),
        ("1000.00", "SILVER"), ("9999.99", "SILVER"),
        ("10000.00", "GOLD"), ("99999.99", "GOLD"),
        ("100000.00", "DIAMOND"), ("1000000.00", "DIAMOND"),
    ]
    for amount, expected in cases:
        actual = mod.donor_tier_for_amount(amount)
        assert actual == expected, f"{amount} -> {actual!r}, expected {expected!r}"


@test
def test_untiered_gift_prints_a_word_not_an_empty_token():
    """Below $100 there is no badge tier. The certificate must still show
    something in {{TIER}} -- never a gap and never a live token."""
    mod = load()
    fields = mod.donor_certificate_fields(
        donor_name="Small Donor", amount="25.00", contribution_dates=["2026-08-03"]
    )
    assert fields["TIER"] == "SUPPORTER"
    assert fields["_meta"]["tier"] == "", "SUPPORTER is not a badge tier"


@test
def test_tax_year_comes_from_the_contribution_not_from_today():
    mod = load()
    fields = mod.donor_certificate_fields(
        donor_name="Year End", amount="500.00", contribution_dates=["2026-12-31"],
        date_issued="2027-01-14",
    )
    assert fields["TAX_YEAR"] == "2026"
    assert fields["DATE_ISSUED"] == "January 14, 2027"
    assert fields["CONTRIBUTION_DATES"] == "December 31, 2026"


@test
def test_one_acknowledgment_cannot_span_two_tax_years():
    mod = load()
    try:
        mod.donor_certificate_fields(
            donor_name="Split", amount="500.00",
            contribution_dates=["2026-12-31", "2027-01-02"],
        )
    except mod.DonorCertificateError as exc:
        assert "one tax year" in str(exc)
    else:
        raise AssertionError("gifts spanning two tax years must be refused")


@test
def test_amount_and_date_formatting():
    mod = load()
    fields = mod.donor_certificate_fields(
        donor_name="Format Check", amount="25000", contribution_dates=["2026-03-04"],
        amount_words="twenty-five thousand USD",
    )
    assert fields["AMOUNT"] == "$25,000.00 (twenty-five thousand USD)"
    assert fields["CONTRIBUTION_DATES"] == "March 4, 2026"
    assert fields["EIN"] == "42-3223917", "the EIN belongs on the private acknowledgment"


# ============================ the $250 threshold ==========================

@test
def test_250_threshold_is_per_single_gift_and_never_aggregated():
    mod = load()
    assert not mod.donor_acknowledgment_required("249.99")
    assert mod.donor_acknowledgment_required("250.00")
    assert mod.donor_acknowledgment_required("250.01")
    # The aggregation trap: twelve $50 gifts are twelve sub-$250 gifts.
    result = issue(mod, gifts=[{"date": f"2026-{m:02d}-05", "amount": "50.00"} for m in range(1, 13)])
    assert result["amount_total"] == "600.00"
    assert result["largest_single_gift"] == "50.00"
    assert result["acknowledgment_required"] is False, "$600 of $50 gifts is not a $250 gift"


@test
def test_every_gift_of_250_or_more_is_flagged_and_delivered():
    mod = load()
    no_pdf(mod)
    result = issue(mod, gifts=[{"date": "2026-08-03", "amount": "250.00"}])
    assert result["acknowledgment_required"] is True
    assert result["delivery_status"] == "sent"
    stored = row(mod, result["ack_number"])
    assert stored["ack_required"] == 1
    assert stored["delivery_status"] == "sent"
    body = _body(mod._SENT.messages[0][0])
    assert "$250 or more" in body


@test
def test_below_250_is_still_issued_and_says_so():
    mod = load()
    no_pdf(mod)
    result = issue(mod, gifts=[{"date": "2026-08-03", "amount": "100.00"}])
    assert result["status"] == "issued"
    assert result["acknowledgment_required"] is False
    body = _body(mod._SENT.messages[0][0])
    assert "under $250" in body


# =================== the goods-and-services statement =====================

@test
def test_below_threshold_issuance_can_be_switched_off():
    """Documented default is to issue below $250 anyway. The knob that turns
    that off must actually be wired, not just declared."""
    mod = load(DONOR_ACK_ISSUE_BELOW_THRESHOLD="0")
    no_pdf(mod)
    skipped = issue(mod, gifts=[{"date": "2026-08-03", "amount": "100.00"}])
    assert skipped["status"] == "skipped_below_threshold"
    assert _count(mod, "donation_acknowledgments") == 0
    kept = issue(mod, gifts=[{"date": "2026-08-03", "amount": "250.00"}])
    assert kept["status"] == "issued"
    default_on = load()
    no_pdf(default_on)
    assert default_on.DONOR_ACK_ISSUE_BELOW_THRESHOLD is True
    assert issue(default_on, gifts=[{"date": "2026-08-03", "amount": "10.00"}])["status"] == "issued"


@test
def test_cash_gift_with_nothing_in_return_gets_the_required_sentence():
    mod = load()
    statement = mod.donor_goods_and_services(mod.Decimal("250.00"))
    assert statement["lines"][0] == (
        "No goods or services were provided by Win's VPN Inc. in return for this contribution."
    )
    assert statement["lines"][1] == "" and statement["lines"][2] == ""
    assert statement["goods_value"].startswith("$0.00")
    assert statement["quid_pro_quo"] is False


@test
def test_a_recognition_badge_does_not_change_the_statement():
    """DONOR_ACKNOWLEDGMENT_REQUIREMENTS.md section 6: a badge and a
    certificate are recognition, treated as insubstantial under the
    token-benefit rule, so the 'no goods or services' sentence stays true and
    no quid pro quo disclosure is triggered."""
    mod = load()
    fields = mod.donor_certificate_fields(
        donor_name="Gold Donor", amount="10000.00", contribution_dates=["2026-05-01"]
    )
    assert fields["TIER"] == "GOLD"
    assert fields["GS_LINE_1"].startswith("No goods or services were provided")
    assert fields["_meta"]["quid_pro_quo"] is False


@test
def test_a_real_benefit_switches_to_description_plus_good_faith_estimate():
    mod = load()
    statement = mod.donor_goods_and_services(
        mod.Decimal("500.00"), goods_description="two event tickets", goods_fmv="120.00"
    )
    joined = " ".join(statement["lines"])
    assert "two event tickets" in joined
    assert "$120.00" in joined
    assert "$380.00" in joined, "deductible amount must be contribution minus FMV"
    assert statement["quid_pro_quo"] is True
    assert statement["goods_value"] == "$120.00"


@test
def test_insubstantial_benefit_safe_harbours_use_the_2026_figures():
    mod = load()
    assert mod.DONOR_INSUBSTANTIAL_LIMITS_YEAR == 2026
    # 2% of payment, capped at $139.
    assert mod.donor_benefit_is_insubstantial(mod.Decimal("1000"), mod.Decimal("20"))
    assert not mod.donor_benefit_is_insubstantial(mod.Decimal("1000"), mod.Decimal("21"))
    # Low-cost article: payment >= $69.50, logo items costing <= $13.90.
    assert mod.donor_benefit_is_insubstantial(
        mod.Decimal("70"), mod.Decimal("30"), logo_items_only=True,
        logo_items_cost=mod.Decimal("13.90"))
    assert not mod.donor_benefit_is_insubstantial(
        mod.Decimal("70"), mod.Decimal("30"), logo_items_only=True,
        logo_items_cost=mod.Decimal("14.00"))


@test
def test_a_benefit_at_or_below_75_dollars_is_not_a_quid_pro_quo_disclosure():
    mod = load()
    statement = mod.donor_goods_and_services(
        mod.Decimal("75.00"), goods_description="a printed book", goods_fmv="40.00"
    )
    assert statement["quid_pro_quo"] is False, "IRC 6115 attaches above $75, not at it"


# ==================== the unreplaced-token hard guard =====================

@test
def test_guard_rejects_any_surviving_placeholder():
    mod = load()
    for leftover in ("{{GS_LINE_1}}", "{{DONOR_NAME}}", "{{ SOMETHING }}"):
        try:
            mod.donor_assert_no_unreplaced_tokens(f"<svg><text>{leftover}</text></svg>")
        except mod.DonorCertificateError as exc:
            assert "unreplaced placeholder" in str(exc)
        else:
            raise AssertionError(f"guard failed to catch {leftover}")


@test
def test_guard_accepts_a_fully_populated_document():
    mod = load()
    mod.donor_assert_no_unreplaced_tokens("<svg><text>No goods or services</text></svg>")


@test
def test_rendered_certificate_contains_no_tokens_and_the_expected_values():
    mod = load()
    fields = mod.donor_certificate_fields(
        donor_name="Alexandra M. Whitfield", amount="25000.00",
        contribution_dates=["2026-03-04", "2026-09-19"], ack_number="WV-2026-000418",
        date_issued="2027-01-14",
    )
    svg = mod.donor_render_certificate_svg(fields)
    assert re.search(r"\{\{[^{}]*\}\}", svg) is None, "a rendered certificate must carry no tokens"
    for expected in ("Alexandra M. Whitfield", "$25,000.00", "March 4, 2026 and September 19, 2026",
                     "GOLD", "2026", "42-3223917", "WV-2026-000418", "January 14, 2027",
                     "No goods or services were provided"):
        assert expected in svg, f"missing {expected!r} from the rendered certificate"


@test
def test_a_template_whose_statement_was_pre_filled_is_rejected():
    """The designer left {{GS_LINE_1}} unfilled on purpose. If someone ever
    'helpfully' bakes the sentence in, the loader must refuse the template
    rather than quietly printing a statement the engine did not choose."""
    mod = load()
    with open(TEMPLATE, encoding="utf-8") as handle:
        tampered = handle.read().replace("{{GS_LINE_1}}", "No goods or services were provided.")
    path = os.path.join(mod._OUTDIR, "tampered.svg")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(tampered)
    try:
        mod.donor_load_certificate_template(path)
    except mod.DonorCertificateError as exc:
        assert "GS_LINE_1" in str(exc)
    else:
        raise AssertionError("a template missing a required placeholder must be refused")


@test
def test_delivery_refuses_a_stored_certificate_with_a_live_token():
    """Second line of defence: even if a file on disk is tampered with after
    issuance, nothing with a {{TOKEN}} on it is ever emailed."""
    mod = load()
    no_pdf(mod)
    result = issue(mod, gifts=[{"date": "2026-08-03", "amount": "5000.00"}])
    stored = row(mod, result["ack_number"])
    with open(stored["certificate_path"], encoding="utf-8") as handle:
        good = handle.read()
    with open(stored["certificate_path"], "w", encoding="utf-8") as handle:
        handle.write(good.replace("No goods or services were provided", "{{GS_LINE_1}}"))
    before = len(mod._SENT.messages)
    outcome = mod.donor_deliver_acknowledgment(result["ack_number"])
    assert outcome["delivery_status"] == "blocked_unreplaced_token"
    assert len(mod._SENT.messages) == before, "nothing may be sent once the guard trips"
    assert row(mod, result["ack_number"])["delivery_status"] == "blocked_unreplaced_token"


@test
def test_a_donor_name_cannot_inject_a_placeholder():
    mod = load()
    fields = mod.donor_certificate_fields(
        donor_name="{{GS_LINE_1}} <script>", amount="150.00",
        contribution_dates=["2026-08-03"],
    )
    assert "{{" not in fields["DONOR_NAME"] and "}}" not in fields["DONOR_NAME"]
    svg = mod.donor_render_certificate_svg(fields)
    assert "<script>" not in svg and "&lt;script&gt;" in svg


# ======================== multi-donation aggregation ======================

@test
def test_two_gifts_in_one_year_are_listed_individually():
    mod = load()
    no_pdf(mod)
    result = issue(mod, gifts=[{"date": "2026-03-04", "amount": "300.00"},
                               {"date": "2026-09-19", "amount": "700.00"}])
    assert result["amount_total"] == "1000.00"
    assert result["largest_single_gift"] == "700.00"
    assert result["tier"] == "SILVER", "tier may use the aggregate; the $250 rule may not"
    assert result["gift_count"] == 2
    stored = row(mod, result["ack_number"])
    with open(stored["certificate_path"], encoding="utf-8") as handle:
        svg = handle.read()
    assert "March 4, 2026 and September 19, 2026" in svg


@test
def test_many_gifts_fall_back_to_a_schedule_attachment():
    mod = load()
    no_pdf(mod)
    gifts = [{"date": f"2026-{m:02d}-05", "amount": "300.00"} for m in range(1, 7)]
    result = issue(mod, gifts=gifts)
    stored = row(mod, result["ack_number"])
    with open(stored["certificate_path"], encoding="utf-8") as handle:
        svg = handle.read()
    assert "Various dates in 2026 (see attached schedule)" in svg
    parts = mod._SENT.messages[0][0].get_payload()
    schedule = [p for p in parts
                if "schedule" in str(p.get("Content-Disposition", ""))]
    assert len(schedule) == 1, "a schedule must be attached when dates do not fit the face"
    text = schedule[0].get_payload(decode=True).decode()
    assert text.count("$300.00") == 6 + 0, "each gift is listed separately"
    assert "$1,800.00" in text


@test
def test_annual_summary_gathers_a_year_of_single_gifts():
    mod = load()
    no_pdf(mod)
    for month, amount in ((3, "300.00"), (6, "50.00"), (9, "400.00")):
        issue(mod, gifts=[{"date": f"2026-{month:02d}-04", "amount": amount}])
    summary = mod.donor_issue_annual_summary("donor@example.test", "2026")
    assert summary["status"] == "issued"
    assert summary["gift_count"] == 3
    assert summary["amount_total"] == "750.00"
    assert summary["largest_single_gift"] == "400.00"
    assert summary["acknowledgment_required"] is True
    assert row(mod, summary["ack_number"])["kind"] == "annual_summary"


@test
def test_acknowledgment_numbers_are_unique_and_sequential_per_tax_year():
    mod = load()
    no_pdf(mod)
    numbers = [issue(mod, gifts=[{"date": "2026-04-0%d" % n, "amount": "150.00"}])["ack_number"]
               for n in range(1, 5)]
    cores = [re.fullmatch(r"WV-2026-(\d{6})-[0-9A-F]{4}", n) for n in numbers]
    assert all(cores), "each number is WV-<year>-<6-digit sequence>-<4-hex suffix>: %r" % numbers
    assert [core.group(1) for core in cores] == ["000001", "000002", "000003", "000004"]
    other_year = issue(mod, gifts=[{"date": "2025-04-01", "amount": "150.00"}])
    assert re.fullmatch(r"WV-2025-000001-[0-9A-F]{4}", other_year["ack_number"]), \
        "sequence restarts per tax year"
    assert len(set(numbers)) == len(numbers)


@test
def test_a_replayed_payment_does_not_mint_a_second_number():
    mod = load()
    no_pdf(mod)
    first = issue(mod, provider="paypal", provider_reference="CAPTURE-123")
    second = issue(mod, provider="paypal", provider_reference="CAPTURE-123")
    assert second["status"] == "duplicate"
    assert second["ack_number"] == first["ack_number"]
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        assert conn.execute("SELECT COUNT(*) FROM donation_acknowledgments").fetchone()[0] == 1


# =========================== delivery behaviour ==========================

@test
def test_missing_email_is_held_not_crashed_and_no_address_is_invented():
    """Crypto and anonymous donors have no address on file."""
    mod = load()
    no_pdf(mod)
    result = issue(mod, donor_name="Anonymous Donor", donor_email="",
                   gifts=[{"date": "2026-08-03", "amount": "5000.00"}])
    assert result["status"] == "issued"
    assert result["delivery_status"] == "no_email_on_file"
    assert mod._SENT.messages == [], "nothing may be sent to a guessed address"
    stored = row(mod, result["ack_number"])
    assert stored["donor_email"] == ""
    assert stored["delivery_status"] == "no_email_on_file"
    assert stored["certificate_path"], "the certificate is still produced and retained"


@test
def test_a_held_acknowledgment_can_be_delivered_later_without_a_new_number():
    mod = load()
    no_pdf(mod)
    result = issue(mod, donor_email="", gifts=[{"date": "2026-08-03", "amount": "300.00"}])
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute("UPDATE donation_acknowledgments SET donor_email = ? WHERE ack_number = ?",
                     ("late@example.test", result["ack_number"]))
        conn.commit()
    outcome = mod.donor_deliver_acknowledgment(result["ack_number"])
    assert outcome["delivery_status"] == "sent"
    assert outcome["ack_number"] == result["ack_number"]
    assert mod._SENT.messages[0][1] == "late@example.test"


@test
def test_unconfigured_smtp_holds_rather_than_losing_the_acknowledgment():
    mod = load(SMTP_PASS="")
    no_pdf(mod)
    result = issue(mod, gifts=[{"date": "2026-08-03", "amount": "300.00"}])
    assert result["delivery_status"] == "smtp_unconfigured"
    assert row(mod, result["ack_number"])["delivery_status"] == "smtp_unconfigured"


@test
def test_smtp_failure_is_recorded_and_retryable():
    mod = load()
    no_pdf(mod)
    mod.smtp_dispatch_message = SentMail(succeed=False)
    result = issue(mod, gifts=[{"date": "2026-08-03", "amount": "300.00"}])
    assert result["delivery_status"] == "failed"
    mod.smtp_dispatch_message = mod._SENT = SentMail(succeed=True)
    assert mod.donor_deliver_acknowledgment(result["ack_number"])["delivery_status"] == "sent"
    assert row(mod, result["ack_number"])["delivery_attempts"] == 2


@test
def test_email_carries_the_certificate_and_the_required_elements():
    mod = load()
    no_pdf(mod)
    result = issue(mod, gifts=[{"date": "2026-08-03", "amount": "1000.00"}])
    message, to_email = mod._SENT.messages[0]
    assert to_email == "donor@example.test"
    assert result["ack_number"] in message["Subject"]
    parts = message.get_payload()
    body = _body(message)
    for required in ("Win's VPN Inc.", "42-3223917", "$1,000.00", "August 3, 2026",
                     "No goods or services were provided",
                     "not an IRS\nreview, approval, or endorsement",
                     "Deductibility depends on your own"):
        assert required in body, f"email body is missing {required!r}"
    attachments = [p for p in parts if "attachment" in str(p.get("Content-Disposition", ""))]
    assert len(attachments) == 1
    assert attachments[0].get_filename().endswith(".svg"), "SVG when no PDF converter exists"


@test
def test_no_pdf_converter_degrades_honestly_rather_than_faking_one():
    mod = load()
    no_pdf(mod)
    result = issue(mod, gifts=[{"date": "2026-08-03", "amount": "1000.00"}])
    stored = row(mod, result["ack_number"])
    assert stored["render_status"].startswith("svg_only:")
    assert stored["pdf_path"] == ""
    assert stored["certificate_path"].endswith(".svg")


@test
def test_pdf_is_produced_from_the_same_populated_svg_when_a_converter_exists():
    """One populated source, two containers: the PDF the donor receives is a
    conversion of the exact SVG that was rendered and stored, so a presentable
    copy and a compliant copy cannot diverge."""
    mod = load()
    seen = {}

    def fake_converter(svg_text):
        seen["svg"] = svg_text
        return b"%PDF-1.4 fake", "fake-converter"

    mod.donor_svg_to_pdf = fake_converter
    result = issue(mod, gifts=[{"date": "2026-08-03", "amount": "1000.00"}])
    stored = row(mod, result["ack_number"])
    assert stored["render_status"] == "pdf:fake-converter"
    with open(stored["certificate_path"], encoding="utf-8") as handle:
        assert handle.read() == seen["svg"], "the PDF must come from the stored SVG"
    attachments = [p for p in mod._SENT.messages[0][0].get_payload()
                   if "attachment" in str(p.get("Content-Disposition", ""))]
    assert attachments[0].get_filename().endswith(".pdf")


# ======================= configuration and constraints ====================

@test
def test_org_contact_is_never_a_street_address():
    mod = load()
    contact = mod.DONOR_ACK_ORG_CONTACT
    assert contact == "winsvpn.org  |  support@winsvpn.org"
    assert not re.search(r"\d+\s+\w+\s+(street|st|avenue|ave|road|rd|drive|dr|suite|ste|blvd)\b",
                         contact, re.I), "the street address must never appear"
    assert "Florida" not in contact and "FL " not in contact


@test
def test_signatory_is_left_for_the_owner_and_never_fabricated():
    mod = load()
    assert mod.DONOR_ACK_SIGNATORY_NAME == ""
    assert mod.DONOR_ACK_SIGNATORY_TITLE == "Authorized Officer, Win's VPN Inc."
    fields = mod.donor_certificate_fields(
        donor_name="Someone", amount="150.00", contribution_dates=["2026-08-03"])
    assert fields["SIGNATORY_NAME"] == "", "no name is invented"
    assert fields["_meta"]["signatory_configured"] is False
    svg = mod.donor_render_certificate_svg(fields)
    assert "<image" not in svg, "no signature image is ever composited"
    configured = load(DONOR_ACK_SIGNATORY_NAME="A Real Officer",
                      DONOR_ACK_SIGNATORY_TITLE="President, Win's VPN Inc.")
    assert configured.donor_certificate_fields(
        donor_name="Someone", amount="150.00", contribution_dates=["2026-08-03"]
    )["SIGNATORY_NAME"] == "A Real Officer"


@test
def test_certificate_states_determination_not_endorsement():
    mod = load()
    fields = mod.donor_certificate_fields(
        donor_name="Someone", amount="150.00", contribution_dates=["2026-08-03"])
    svg = mod.donor_render_certificate_svg(fields)
    assert "not an IRS review, approval, or endorsement of the Win" in svg
    assert "Deductibility depends on your own tax situation" in svg
    assert "does not provide tax advice" in svg


@test
def test_long_text_is_fitted_rather_than_allowed_to_overflow():
    mod = load()
    long_name = "Bartholomew Fitzgerald-Montgomery Wellington III"
    fields = mod.donor_certificate_fields(
        donor_name=long_name, amount="150.00", contribution_dates=["2026-08-03"])
    svg = mod.donor_render_certificate_svg(fields)
    match = re.search(r'<text[^>]*font-size="([0-9.]+)"[^>]*>' + re.escape(long_name), svg)
    assert match, "the donor name element must still be present"
    assert float(match.group(1)) < 36.0, "an over-long name must be shrunk to fit"
    # Something that cannot fit at any allowed size is refused, not overflowed.
    try:
        mod.donor_render_certificate_svg(mod.donor_certificate_fields(
            donor_name="Q" * 400, amount="150.00", contribution_dates=["2026-08-03"]))
    except mod.DonorCertificateError as exc:
        assert "too long" in str(exc)
    else:
        raise AssertionError("an unfittable field must be refused, not overflowed")


@test
def test_statement_lines_are_wrapped_inside_the_callout_box():
    mod = load()
    fields = mod.donor_certificate_fields(
        donor_name="Someone", amount="500.00", contribution_dates=["2026-08-03"],
        goods_description="two tickets to the annual supporter dinner", goods_fmv="120.00")
    svg = mod.donor_render_certificate_svg(fields)
    # The wrap happens during rendering, so read the lines back off the
    # artwork rather than off the pre-wrap statement.
    rendered = re.findall(r'<text[^>]*font-size="([0-9.]+)"[^>]*font-weight="620"[^>]*>([^<]*)</text>', svg)
    assert len(rendered) == 3, "the statement box always carries exactly three lines"
    for size, line in rendered:
        assert mod.donor_text_width(line, float(size), bold=True) <= mod.DONOR_GS_LINE_WIDTH
    joined = " ".join(line for _, line in rendered)
    assert "two tickets to the annual supporter dinner" in joined
    assert "$120.00" in joined and "$380.00" in joined


# ==================== deletion vs. retention (tax records) ================

@test
def test_account_deletion_does_not_erase_donor_acknowledgments():
    """Tax records survive an account deletion. The two features must not
    contradict each other: acknowledgments carry no account_number and no
    foreign key, so deletion neither cascades into them nor is blocked."""
    mod = load()
    no_pdf(mod)
    account = "9999-8888-7777"
    tokens = harness.seed_account(mod, account=account, devices=1)
    issue(mod, donor_email=f"user-{account}@example.test",
          gifts=[{"date": "2026-08-03", "amount": "500.00"}])
    assert _count(mod, "donation_acknowledgments") == 1

    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        mod.ensure_schema(conn)
        conn.execute(
            """
            INSERT INTO account_deletion_requests (
                request_id, account_number, status, active_device_count,
                required_confirmations, single_device_path, requested_at
            ) VALUES ('req-1', ?, 'pending', 1, 1, 1, ?)
            """,
            (account, mod.utcnow().isoformat()),
        )
        pending = conn.execute(
            "SELECT * FROM account_deletion_requests WHERE request_id = 'req-1'").fetchone()
        mod.execute_account_deletion(conn, None, account, pending, 1)
        conn.commit()

    assert _count(mod, "users", "account_number = ?", (account,)) == 0, "the account is gone"
    assert _count(mod, "donation_acknowledgments") == 1, "the tax record is retained"
    assert list(tokens)


@test
def test_the_acknowledgment_table_has_no_account_link():
    mod = load()
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        columns = {r["name"] for r in conn.execute(
            "PRAGMA table_info(donation_acknowledgments)").fetchall()}
        foreign_keys = conn.execute(
            "PRAGMA foreign_key_list(donation_acknowledgments)").fetchall()
    assert "account_number" not in columns
    assert foreign_keys == [], "a foreign key to users would make deletion fail or cascade"
    assert "retained" in mod.donor_acknowledgment_retention_note()


@test
def test_legal_payload_contract_is_untouched():
    """This work must not disturb the clickwrap hash contract."""
    mod = load()
    assert len(mod.LEGAL_DOCUMENT_ACCEPTED_HASHES) == 3
    assert mod.legal_payload_is_current(mod.LEGAL_DOCUMENT_VERSION, mod.LEGAL_DOCUMENT_HASH)
    assert mod.legal_payload_is_current(mod.LEGAL_DOCUMENT_VERSION,
                                        mod.LEGAL_DOCUMENT_HASH_SUPERSEDED_20260721)
    assert not mod.legal_payload_is_current(mod.LEGAL_DOCUMENT_VERSION, "0" * 64)


# ============================ the payment path ===========================

@test
def test_a_paypal_donation_capture_produces_an_acknowledgment():
    mod = load()
    no_pdf(mod)
    payload = {
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {
            "id": "CAPTURE-9001",
            "amount": {"value": "500.00", "currency_code": "USD"},
            "create_time": "2026-08-03T10:00:00Z",
            "payer": {"email_address": "generous@example.test",
                      "name": {"given_name": "Gene", "surname": "Rous"}},
            "custom_id": "general_donation",
        },
    }
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        result = mod.donor_acknowledge_paypal_donation(
            conn, payload, payload["resource"], "CAPTURE-9001")
        conn.commit()
    assert result["status"] == "issued"
    assert result["amount_total"] == "500.00"
    assert result["acknowledgment_required"] is True
    stored = row(mod, result["ack_number"])
    assert stored["donor_email"] == "generous@example.test"
    assert stored["provider"] == "paypal"
    assert stored["tier"] == "BRONZE"
    assert mod.donor_deliver_acknowledgment(result["ack_number"])["delivery_status"] == "sent"


@test
def test_donation_classification_is_configurable():
    mod = load()
    marked = {"resource": {"custom_id": "general_donation"}}
    assert mod.classify_donation_payment(marked) is True
    strict = load(DONOR_TREAT_UNCLASSIFIED_ONE_TIME_AS_DONATION="0")
    assert strict.classify_donation_payment(marked) is True
    assert strict.classify_donation_payment({"resource": {"custom_id": "something-else"}}) is False
    assert mod.classify_donation_payment({"resource": {"custom_id": "something-else"}}) is True


@test
def test_zero_or_missing_amount_is_ignored_not_acknowledged():
    mod = load()
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        result = mod.donor_acknowledge_paypal_donation(conn, {}, {"id": "X"}, "X")
    assert result["status"] == "ignored"
    assert _count(mod, "donation_acknowledgments") == 0


# ============================== admin routes =============================

@test
def test_admin_issue_route_requires_a_token_and_then_works():
    mod = load()
    no_pdf(mod)
    handler = mod.app.routes[("POST", "/admin/donor-acknowledgment/issue")]
    request = FakeRequest(path="/admin/donor-acknowledgment/issue")
    try:
        call_handler(handler, request, BackgroundTasks(), donor_name="X", amount="100",
                     contribution_date="2026-08-03", x_admin_token="wrong")
    except HTTPException as exc:
        assert exc.status_code in (401, 403)
    else:
        raise AssertionError("the admin route must reject a bad token")

    result = call_handler(handler,
        request, BackgroundTasks(), donor_name="Retro Donor", amount="300.00,450.00",
        contribution_date="2026-02-01,2026-07-01", email="retro@example.test",
        x_admin_token="test-admin-token")
    assert result["status"] == "issued"
    assert result["gift_count"] == 2
    assert result["amount_total"] == "750.00"


@test
def test_admin_listing_reports_undelivered_required_acknowledgments():
    mod = load()
    no_pdf(mod)
    issue(mod, donor_email="", gifts=[{"date": "2026-08-03", "amount": "900.00"}])
    issue(mod, gifts=[{"date": "2026-08-04", "amount": "900.00"}])
    handler = mod.app.routes[("GET", "/admin/donor-acknowledgments")]
    request = FakeRequest(path="/admin/donor-acknowledgments", method="GET")
    request.query_params = {"undelivered": "1"}
    payload = call_handler(handler, request, x_admin_token="test-admin-token")
    assert payload["counts"]["total"] == 2
    assert payload["counts"]["sent"] == 1
    assert payload["counts"]["required_not_delivered"] == 1
    assert len(payload["acknowledgments"]) == 1
    assert payload["signatory_configured"] is False
    assert "retained" in payload["retention_policy"]


# ====================== the automatic trigger (webhook) ===================
#
# Everything above proves the ENGINE. This section proves the TRIGGER: that a
# completed PayPal payment arriving at POST /webhook/paypal issues and delivers
# an acknowledgment with nobody touching the admin route, that it does so
# exactly once per gift, and that a plan purchase never produces a tax
# document. The handler function is driven directly. There is no HTTP server,
# no uvicorn and no network; verify_paypal_webhook_signature is stubbed because
# it is an outbound call to PayPal, not part of what these prove.


class WebhookRequest(FakeRequest):
    """FakeRequest plus the raw body the webhook reads before it parses."""

    def __init__(self, payload, **kw):
        kw.setdefault("path", "/webhook/paypal")
        super().__init__(**kw)
        self._raw = json.dumps(payload).encode()

    async def body(self):
        return self._raw


def paypal_hub(**env):
    """A hub with PayPal switched on and its signature check stubbed."""
    settings = {
        "PAYPAL_CLIENT_ID": "test-client-id",
        "PAYPAL_CLIENT_SECRET": "test-client-secret",
        "PAYPAL_WEBHOOK_ID": "test-webhook-id",
    }
    settings.update(env)
    mod = load(**settings)
    no_pdf(mod)
    mod.verify_paypal_webhook_signature = lambda headers, raw_body, payload: True
    return mod


def capture(event_id, capture_id, amount="500.00", **resource):
    """A completed one-time PayPal capture, the shape the donate button makes."""
    payload = {
        "id": event_id,
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {
            "id": capture_id,
            "amount": {"value": amount, "currency_code": "USD"},
            "create_time": "2026-08-03T10:00:00Z",
            "payer": {"email_address": "generous@example.test",
                      "name": {"given_name": "Gene", "surname": "Rous"}},
        },
    }
    payload["resource"].update(resource)
    return payload


def post_webhook(mod, payload):
    """Post one webhook. Returns (result, queued background tasks)."""
    tasks = BackgroundTasks()
    handler = mod.app.routes[("POST", "/webhook/paypal")]
    return harness.asyncio.run(handler(WebhookRequest(payload), tasks)), tasks


def run_tasks(tasks):
    """The fake BackgroundTasks queues rather than runs. The real server runs
    them after the response; running them here is what makes delivery
    observable, and keeps the send off the webhook's own code path."""
    return [fn(*args, **kw) for fn, args, kw in tasks.tasks]


def acks(mod):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT * FROM donation_acknowledgments ORDER BY ack_number").fetchall()


def event_status(mod, event_id):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        found = conn.execute(
            "SELECT status FROM paypal_events WHERE event_id = ?", (event_id,)).fetchone()
    return found["status"] if found else ""


def undelivered_listing(mod):
    request = FakeRequest(path="/admin/donor-acknowledgments", method="GET")
    request.query_params = {"undelivered": "1"}
    handler = mod.app.routes[("GET", "/admin/donor-acknowledgments")]
    return call_handler(handler, request, x_admin_token="test-admin-token")


@test
def test_a_completed_donation_webhook_issues_and_delivers_on_its_own():
    """The whole job: a donor gives, and an acknowledgment goes out without
    anyone running the admin route by hand."""
    mod = paypal_hub()
    result, tasks = post_webhook(
        mod, capture("EVT-1", "CAPTURE-1", custom_id="general_donation"))
    assert result["status"] == "ok", result
    assert result["donation"]["status"] == "issued", result
    issued = acks(mod)
    assert len(issued) == 1, "one gift, one acknowledgment"
    assert issued[0]["provider"] == "paypal"
    assert issued[0]["provider_reference"] == "CAPTURE-1", "keyed on PayPal's capture id"
    assert issued[0]["donor_email"] == "generous@example.test"
    assert issued[0]["amount_total"] == "500.00"
    assert event_status(mod, "EVT-1") == "processed"
    # Delivery is queued, never inline: a slow or failing SMTP server must not
    # hold the webhook response open or turn a received gift into a 500.
    assert [fn.__name__ for fn, _, _ in tasks.tasks] == ["donor_deliver_acknowledgment"]
    assert len(mod._SENT.messages) == 0, "nothing is sent from the webhook itself"
    run_tasks(tasks)
    assert len(mod._SENT.messages) == 1
    assert mod._SENT.messages[0][1] == "generous@example.test"
    assert row(mod, issued[0]["ack_number"])["delivery_status"] == "sent"


@test
def test_a_replayed_webhook_issues_no_second_acknowledgment():
    """Same event delivered twice, which PayPal does on any non-2xx or timeout."""
    mod = paypal_hub()
    payload = capture("EVT-2", "CAPTURE-2", custom_id="general_donation")
    first, _ = post_webhook(mod, payload)
    again, again_tasks = post_webhook(mod, payload)
    assert first["donation"]["status"] == "issued"
    assert again["status"] == "duplicate", again
    assert again_tasks.tasks == [], "a replay must not queue a second delivery"
    assert len(acks(mod)) == 1


@test
def test_the_same_capture_under_a_new_event_id_still_mints_one_number():
    """Event-id dedup alone is not enough. A redelivery under a fresh event id,
    or a second webhook subscription on the same PayPal account, presents the
    same gift again. Idempotency is keyed on the capture id, which is the
    processor's own id for the money that moved."""
    mod = paypal_hub()
    first, _ = post_webhook(
        mod, capture("EVT-3a", "CAPTURE-3", custom_id="general_donation"))
    second, second_tasks = post_webhook(
        mod, capture("EVT-3b", "CAPTURE-3", custom_id="general_donation"))
    assert first["donation"]["status"] == "issued"
    assert second["status"] == "ok", second
    assert second["donation"]["status"] == "duplicate", second
    assert second["donation"]["ack_number"] == first["donation"]["ack_number"]
    assert second_tasks.tasks == [], "the donor is not emailed a second receipt"
    assert len(acks(mod)) == 1


@test
def test_the_database_not_the_application_enforces_one_number_per_gift():
    """The SELECT inside donor_issue_acknowledgment is an optimisation. The
    constraint is the partial UNIQUE index, so a writer that races past the
    SELECT is still refused by SQLite rather than by good intentions."""
    mod = paypal_hub()
    post_webhook(mod, capture("EVT-4", "CAPTURE-4", custom_id="general_donation"))
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        try:
            conn.execute(
                "INSERT INTO donation_acknowledgments (ack_number, tax_year, sequence,"
                " kind, donor_name, amount_total, largest_single_gift, provider,"
                " provider_reference, issued_at) VALUES ('WV-2026-999999', '2026',"
                " 999999, 'single', 'Racer', '1.00', '1.00', 'paypal', 'CAPTURE-4',"
                " '2026-08-03T00:00:00')")
        except sqlite3.IntegrityError as exc:
            assert "unique" in str(exc).lower(), exc
        else:
            raise AssertionError("the unique index must refuse a second row for one capture")
    assert len(acks(mod)) == 1


@test
def test_a_subscription_payment_issues_no_acknowledgment():
    """A VPN subscription is a purchase. Acknowledging one would assert a
    deductible charitable contribution that never happened."""
    mod = paypal_hub(PAYPAL_PLAN_1M="P-TEST-1M")
    mod.fetch_paypal_subscription = lambda subscription_id: {
        "id": subscription_id, "plan_id": "P-TEST-1M", "status": "ACTIVE",
        "subscriber": {"email_address": "buyer@example.test",
                       "name": {"given_name": "Bea", "surname": "Yer"}},
    }
    result, _ = post_webhook(mod, {
        "id": "EVT-5",
        "event_type": "PAYMENT.SALE.COMPLETED",
        "resource": {"id": "SALE-5", "billing_agreement_id": "I-SUB-5",
                     "amount": {"total": "9.99", "currency": "USD"}},
    })
    assert result["status"] == "ok", result
    assert "donation" not in result, "a plan payment must not reach the donation branch"
    assert len(acks(mod)) == 0, "a subscription must never produce a tax document"


@test
def test_a_lifetime_pass_purchase_issues_no_acknowledgment():
    """The other paid product. Also a purchase, also not deductible."""
    mod = paypal_hub(PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT="99.00",
                     PAYPAL_LIFETIME_CURRENCY="USD")
    mod.paypal_json_request = lambda *_args, **_kwargs: {
        "id": "ORDER-6",
        "status": "COMPLETED",
        "payer": {
            "email_address": "buyer@example.test",
            "name": {"given_name": "Life", "surname": "Time"},
        },
        "purchase_units": [
            {
                "payments": {
                    "captures": [
                        {
                            "id": "CAPTURE-6",
                            "status": "COMPLETED",
                            "amount": {"value": "99.00", "currency_code": "USD"},
                        }
                    ]
                }
            }
        ],
    }
    result, _ = post_webhook(
        mod,
        capture(
            "EVT-6",
            "CAPTURE-6",
            amount="99.00",
            custom_id="lifetime_no_support",
            supplementary_data={"related_ids": {"order_id": "ORDER-6"}},
        ),
    )
    assert result["status"] == "ok", result
    assert result.get("plan") == "lifetime_no_support", result
    assert "donation" not in result
    assert len(acks(mod)) == 0


@test
def test_a_plan_payment_reaching_the_donation_branch_is_still_refused():
    """The webhook routes subscriptions and lifetime passes before the donation
    branch, but ordering is not a check. This proves the branch does not lean on
    it: a capture carrying plan evidence and no lifetime marker, which is what a
    reordering or a renamed provider field would produce, is refused outright
    instead of being swept up by the unclassified-one-time catch-all."""
    mod = paypal_hub()
    payload = capture("EVT-7", "CAPTURE-7", plan_id="P-TEST-1Y")
    assert mod.paypal_payment_is_plan_purchase(payload) is True
    assert mod.classify_donation_payment(payload) is False
    result, tasks = post_webhook(mod, payload)
    assert result["status"] == "ignored", result
    assert result["reason"] == "one_time_payment_missing_lifetime_marker"
    assert tasks.tasks == []
    assert len(acks(mod)) == 0
    # A plan option key in the payload is refused the same way, and the refusal
    # beats an explicit donation marker rather than losing to it.
    assert mod.classify_donation_payment(
        capture("EVT-7b", "CAPTURE-7b", custom_id="one_year")) is False
    assert mod.classify_donation_payment(
        capture("EVT-7c", "CAPTURE-7c", custom_id="donation",
                billing_agreement_id="I-SUB-7")) is False


@test
def test_a_delivery_failure_on_the_automatic_path_leaves_a_retrievable_record():
    """A gift must never be lost because email failed, and the failure has to be
    visible rather than swallowed."""
    mod = paypal_hub()
    mod.smtp_dispatch_message = mod._SENT = SentMail(succeed=False)
    result, tasks = post_webhook(
        mod, capture("EVT-8", "CAPTURE-8", custom_id="general_donation"))
    assert result["status"] == "ok", "a failed send must not fail the webhook"
    ack_number = result["donation"]["ack_number"]
    outcome = run_tasks(tasks)[0]
    assert outcome["delivery_status"] == "failed", outcome
    stored = row(mod, ack_number)
    assert stored["delivery_status"] == "failed"
    assert stored["delivery_attempts"] == 1
    # Visible in the operational view the owner actually reads.
    listing = undelivered_listing(mod)
    assert [entry["ack_number"] for entry in listing["acknowledgments"]] == [ack_number]
    assert listing["counts"]["required_not_delivered"] == 1
    # And it can be delivered later on the SAME number.
    mod.smtp_dispatch_message = mod._SENT = SentMail(succeed=True)
    assert mod.donor_deliver_acknowledgment(ack_number)["delivery_status"] == "sent"
    assert [entry["ack_number"] for entry in acks(mod)] == [ack_number], "no number was burned"
    assert undelivered_listing(mod)["acknowledgments"] == []


@test
def test_the_unreplaced_token_guard_fires_on_the_automatic_path_too():
    """Checked at render time and again on the stored file before sending. The
    automatic path must be no weaker than the manual one."""
    mod = paypal_hub()
    result, tasks = post_webhook(mod, capture("EVT-9", "CAPTURE-9", amount="5000.00",
                                              custom_id="general_donation"))
    ack_number = result["donation"]["ack_number"]
    stored = row(mod, ack_number)
    with open(stored["certificate_path"], encoding="utf-8") as handle:
        good = handle.read()
    with open(stored["certificate_path"], "w", encoding="utf-8") as handle:
        handle.write(good.replace("No goods or services were provided", "{{GS_LINE_1}}"))
    before = len(mod._SENT.messages)
    outcome = run_tasks(tasks)[0]
    assert outcome["delivery_status"] == "blocked_unreplaced_token", outcome
    assert len(mod._SENT.messages) == before, "nothing may be sent once the guard trips"
    assert row(mod, ack_number)["delivery_status"] == "blocked_unreplaced_token"
    assert [entry["ack_number"] for entry in undelivered_listing(mod)["acknowledgments"]] \
        == [ack_number], "and it stays visible as undelivered"


@test
def test_a_donation_with_no_payer_email_is_held_not_dropped():
    """A gift with no address on file is still recorded, and nothing is
    invented so that something can be sent."""
    mod = paypal_hub()
    result, tasks = post_webhook(mod, {
        "id": "EVT-10",
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {"id": "CAPTURE-10", "custom_id": "general_donation",
                     "create_time": "2026-08-03T10:00:00Z",
                     "amount": {"value": "750.00", "currency_code": "USD"}},
    })
    assert result["donation"]["delivery_status"] == "no_email_on_file", result
    assert tasks.tasks == [], "there is no address to send to, so nothing is queued"
    stored = acks(mod)
    assert len(stored) == 1, "the gift is recorded anyway"
    assert stored[0]["donor_email"] == ""
    assert len(mod._SENT.messages) == 0


@test
def test_a_capture_with_no_amount_is_ignored_not_acknowledged():
    mod = paypal_hub()
    result, tasks = post_webhook(mod, {
        "id": "EVT-11",
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {"id": "CAPTURE-11", "custom_id": "general_donation",
                     "payer": {"email_address": "d@example.test"}},
    })
    assert result["donation"]["status"] == "ignored", result
    assert result["donation"]["reason"] == "donation_amount_missing"
    assert len(acks(mod)) == 0
    assert tasks.tasks == []


@test
def test_the_trigger_can_be_switched_off_and_the_manual_route_still_works():
    """DONOR_ACK_AUTO_ISSUE=0 restores the previous behaviour exactly, so the
    owner can stop automatic issuance without redeploying anything else."""
    mod = paypal_hub(DONOR_ACK_AUTO_ISSUE="0")
    result, tasks = post_webhook(
        mod, capture("EVT-12", "CAPTURE-12", custom_id="general_donation"))
    assert result["status"] == "ignored", result
    assert result["reason"] == "one_time_payment_missing_lifetime_marker"
    assert tasks.tasks == []
    assert len(acks(mod)) == 0
    manual = call_handler(
        mod.app.routes[("POST", "/admin/donor-acknowledgment/issue")],
        FakeRequest(path="/admin/donor-acknowledgment/issue"), BackgroundTasks(),
        donor_name="Hand Issued", amount="500.00", contribution_date="2026-08-03",
        email="hand@example.test", x_admin_token="test-admin-token")
    assert manual["status"] == "issued"
    assert len(acks(mod)) == 1


@test
def test_donor_drain_reclaims_an_expired_lease():
    """A drain worker that dies after claiming a row (process restart during
    SMTP) must not strand it: the lease is the expiry timestamp stored after
    'lease:', and once it has passed the row is claimable again."""
    mod = load(DURABILITY_BARRIER_ENABLED=0, DURABILITY_BARRIER_REQUIRED=0)
    no_pdf(mod)
    ack = issue(mod)["ack_number"]
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute(
            "UPDATE donation_acknowledgments SET delivery_status='pending',"
            " delivery_detail='lease:2000-01-01T00:00:00+00:00',"
            " delivery_attempts=0 WHERE ack_number=?", (ack,))
    called = []
    mod.donor_deliver_acknowledgment = (
        lambda a: (called.append(a), {"delivery_status": "sent"})[1])
    summary = mod.drain_donor_acknowledgment_outbox()
    assert called == [ack], (summary, called)
    assert summary["claimed"] == 1 and summary["sent"] == 1, summary


def _count(mod, table, where="", args=()):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        sql = f"SELECT COUNT(*) FROM {table}"
        if where:
            sql += f" WHERE {where}"
        return conn.execute(sql, args).fetchone()[0]


def main():
    passed = failed = 0
    for fn in RESULTS:
        try:
            fn()
        except Exception:
            failed += 1
            print(f"FAIL  {fn.__name__}")
            traceback.print_exc()
        else:
            passed += 1
            print(f"ok    {fn.__name__}")
    for directory in _TMPDIRS:
        shutil.rmtree(directory, ignore_errors=True)
    print(f"\n{passed} passed, {failed} failed, {len(RESULTS)} total")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
