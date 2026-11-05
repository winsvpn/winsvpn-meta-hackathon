#!/usr/bin/env python3
"""Read-only SMTP2GO and PayPal production integration verification.

Run only on the control hub as root.  The probe authenticates to SMTP2GO
without sending mail, obtains a PayPal OAuth token, and reads the configured
webhook and billing plans.  Output contains booleans and allow-listed error
classes only; credentials, identifiers, URLs, tokens, and provider responses
are never emitted.
"""

from __future__ import annotations

import base64
import json
import pathlib
import re
import smtplib
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable


ENV_PATH = pathlib.Path("/root/vpn_auth/.env")
REQUIRED_EVENTS = {
    "BILLING.SUBSCRIPTION.ACTIVATED",
    "BILLING.SUBSCRIPTION.UPDATED",
    "BILLING.SUBSCRIPTION.RE-ACTIVATED",
    "BILLING.SUBSCRIPTION.CANCELLED",
    "BILLING.SUBSCRIPTION.SUSPENDED",
    "BILLING.SUBSCRIPTION.EXPIRED",
    "BILLING.SUBSCRIPTION.PAYMENT.FAILED",
    "PAYMENT.SALE.COMPLETED",
    "PAYMENT.SALE.REFUNDED",
    "PAYMENT.SALE.REVERSED",
    "PAYMENT.CAPTURE.COMPLETED",
    "PAYMENT.CAPTURE.REFUNDED",
    "PAYMENT.CAPTURE.REVERSED",
}


def fail_class(exc: BaseException) -> str:
    allowed = (
        smtplib.SMTPAuthenticationError,
        smtplib.SMTPConnectError,
        smtplib.SMTPNotSupportedError,
        smtplib.SMTPServerDisconnected,
        ssl.SSLError,
        TimeoutError,
        urllib.error.HTTPError,
        urllib.error.URLError,
        json.JSONDecodeError,
        ValueError,
        OSError,
    )
    for kind in allowed:
        if isinstance(exc, kind):
            return kind.__name__
    return "ProviderVerificationError"


def load_owner_env(path: pathlib.Path = ENV_PATH) -> dict[str, str]:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise PermissionError("runtime environment is not owner-only")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, raw = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key):
            continue
        value = raw.strip()
        if len(value) >= 2 and value.startswith("'") and value.endswith("'"):
            value = value[1:-1].replace("'\"'\"'", "'")
        values[key] = value
    return values


def verify_smtp(
    values: dict[str, str],
    smtp_factory: Callable[..., Any] = smtplib.SMTP,
) -> dict[str, Any]:
    host = values.get("SMTP_SERVER", "").lower()
    port = int(values.get("SMTP_PORT", "0"))
    if (
        host != "mail.smtp2go.com"
        or port not in {25, 80, 2525, 587, 8025}
        or not values.get("SMTP_USER")
        or not values.get("SMTP_PASS")
    ):
        raise ValueError("invalid SMTP2GO contract")
    with smtp_factory(host, port, timeout=20) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ssl.create_default_context())
        smtp.ehlo()
        smtp.login(values["SMTP_USER"], values["SMTP_PASS"])
    return {
        "server_contract_valid": True,
        "starttls_negotiated": True,
        "authentication_succeeded": True,
        "message_sent": False,
    }


def provider_json(
    request: urllib.request.Request, timeout: int = 25
) -> dict[str, Any]:
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read(2 * 1024 * 1024)
    parsed = json.loads(payload.decode("utf-8", errors="strict"))
    if not isinstance(parsed, dict):
        raise ValueError("provider response is not an object")
    return parsed


def verify_paypal(
    values: dict[str, str],
    request_json: Callable[[urllib.request.Request, int], dict[str, Any]] = provider_json,
) -> dict[str, Any]:
    if values.get("PAYPAL_MODE", "").lower() != "live":
        raise ValueError("PayPal mode is not live")
    client_id = values.get("PAYPAL_CLIENT_ID", "")
    client_secret = values.get("PAYPAL_CLIENT_SECRET", "")
    if (
        not client_id
        or not client_secret
        or client_id != values.get("PAYPAL_PUBLIC_CLIENT_ID", "")
    ):
        raise ValueError("PayPal client contract is incomplete")
    base = "https://api-m.paypal.com"
    basic = base64.b64encode(
        f"{client_id}:{client_secret}".encode("utf-8")
    ).decode("ascii")
    token_request = urllib.request.Request(
        base + "/v1/oauth2/token",
        data=b"grant_type=client_credentials",
        method="POST",
        headers={
            "Authorization": "Basic " + basic,
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    token = str(request_json(token_request, 25).get("access_token") or "")
    if not token:
        raise ValueError("PayPal OAuth token is absent")

    def get(path: str) -> dict[str, Any]:
        request = urllib.request.Request(
            base + path,
            method="GET",
            headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/json",
            },
        )
        return request_json(request, 25)

    webhook_id = values.get("PAYPAL_WEBHOOK_ID", "")
    expected_url = values.get("PAYPAL_WEBHOOK_URL", "")
    if not webhook_id or not expected_url:
        raise ValueError("PayPal webhook material is absent")
    webhook = get("/v1/notifications/webhooks/" + urllib.parse.quote(webhook_id))
    actual_events = {
        str(item.get("name") or "")
        for item in webhook.get("event_types", [])
        if isinstance(item, dict)
    }
    webhook_ok = (
        str(webhook.get("id") or "") == webhook_id
        and str(webhook.get("url") or "") == expected_url
        and REQUIRED_EVENTS.issubset(actual_events)
    )
    plan_ids = {
        values.get("PAYPAL_PLAN_1M", ""),
        values.get("PAYPAL_PLAN_1Y", ""),
        values.get("PAYPAL_PLAN_PERSONAL", ""),
    }
    if "" in plan_ids or len(plan_ids) != 3:
        raise ValueError("PayPal billing plan contract is incomplete")
    plans_active = all(
        str(
            get("/v1/billing/plans/" + urllib.parse.quote(plan_id)).get(
                "status"
            )
            or ""
        ).upper()
        == "ACTIVE"
        for plan_id in sorted(plan_ids)
    )
    return {
        "live_endpoint_used": True,
        "oauth_succeeded": True,
        "webhook_identity_matches": webhook_ok,
        "required_webhook_events_present": REQUIRED_EVENTS.issubset(
            actual_events
        ),
        "all_billing_plans_active": plans_active,
        "mutation_attempted": False,
    }


def verify_local_hub() -> bool:
    request = urllib.request.Request(
        "http://127.0.0.1:8000/healthz",
        headers={"User-Agent": "WinsVPN-ReadOnly-Commerce-Probe/1.0"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return 200 <= int(response.status) < 300


def main() -> int:
    result: dict[str, Any] = {
        "schema_version": 1,
        "contract": "winsvpn-control-commerce-readonly-probe-v1",
        "secret_material_redacted": True,
        "provider_response_redacted": True,
        "mutation_attempted": False,
    }
    try:
        values = load_owner_env()
        result["environment_owner_only"] = True
    except Exception as exc:
        result.update(
            {
                "environment_owner_only": False,
                "error_stage": "environment",
                "error_type": fail_class(exc),
            }
        )
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 1
    try:
        result["smtp2go"] = verify_smtp(values)
    except Exception as exc:
        result["smtp2go"] = {
            "authentication_succeeded": False,
            "message_sent": False,
            "error_type": fail_class(exc),
        }
    try:
        result["paypal"] = verify_paypal(values)
    except Exception as exc:
        result["paypal"] = {
            "oauth_succeeded": False,
            "mutation_attempted": False,
            "error_type": fail_class(exc),
        }
    try:
        result["local_hub_health_ok"] = verify_local_hub()
    except Exception as exc:
        result["local_hub_health_ok"] = False
        result["local_hub_health_error_type"] = fail_class(exc)
    result["passed"] = bool(
        result["smtp2go"].get("authentication_succeeded")
        and result["paypal"].get("oauth_succeeded")
        and result["paypal"].get("webhook_identity_matches")
        and result["paypal"].get("required_webhook_events_present")
        and result["paypal"].get("all_billing_plans_active")
        and result["local_hub_health_ok"]
    )
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
