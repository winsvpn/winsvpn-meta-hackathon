#!/usr/bin/env python3
"""Paid activation/refresh matrix against the generated hub authorization.

The hub module is extracted from wins_control_plane_setup_ONETOUCH.sh by the
shared account-deletion harness. The Dart checks deliberately pin the client
half of the same contract so a future key rotation or dropped bearer cannot
turn the real hub's expected 401 back into a production reconnect outage.

Run: python3 server/test_paid_refresh_authorization_hub.py
"""
import os
import sys
import traceback

import _toolchain  # noqa: F401  (V-01 preflight)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_account_deletion_hub as harness  # noqa: E402
from test_account_deletion_hub import FakeRequest, HTTPException  # noqa: E402


ACCOUNT = "1111-2222-3333"
BEARER = "device-bearer-token-for-paid-refresh-tests"
SETUP_KEY = "setup-key-for-paid-refresh-tests"
KEY_A = "A" * 43 + "="
KEY_B = "B" * 43 + "="


def expect_http(status, fn):
    try:
        fn()
    except HTTPException as exc:
        assert exc.status_code == status, exc
        return
    raise AssertionError(f"expected HTTP {status}")


def device_row(mod):
    return {
        "client_public_key": KEY_A,
        "device_auth_token_hash": mod.token_digest(BEARER),
    }


def authorize(mod, *, public_key, bearer="", setup_key=""):
    headers = {}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if setup_key:
        headers["X-Wins-Activation"] = setup_key
    return mod.require_verify_authorization(
        activation_secret_hash=mod.token_digest(SETUP_KEY),
        device_row=device_row(mod),
        requested_client_public_key=public_key,
        request=FakeRequest(path="/verify", headers=headers),
        account_number=ACCOUNT,
    )


def test_real_hub_paid_activation_and_refresh_matrix(mod):
    # Paid activation/rekey is the only path allowed to change identity.
    assert authorize(mod, public_key=KEY_B, setup_key=SETUP_KEY) == "enrollment"

    # Second connect, automatic selection, explicit selection, and Double VPN
    # all hit the same authorization function. Selection fields are payload
    # policy, not alternate credentials, so every retry uses key A + bearer.
    for scenario in (
        "second-connect",
        "automatic-selection",
        "explicit-selection",
        "double-vpn-retry-1",
        "double-vpn-retry-2",
    ):
        assert authorize(mod, public_key=KEY_A, bearer=BEARER) == "device", scenario

    # A bearer cannot authorize rotation. This is the server-side proof that
    # refresh must never generate a candidate key.
    expect_http(401, lambda: authorize(mod, public_key=KEY_B, bearer=BEARER))

    # No credential remains fail closed even when the account number is known.
    expect_http(401, lambda: authorize(mod, public_key=KEY_A))


def _method_body(source, signature, next_signature):
    start = source.index(signature)
    end = source.index(next_signature, start)
    return source[start:end]


def test_client_refresh_contract_pins_timeout_and_rollback(mod):
    del mod
    source = open(os.path.join(ROOT, "lib", "main.dart"), encoding="utf-8").read()
    refresh = _method_body(
        source,
        "Future<bool> _refreshVpnConfigForCurrentSelection(",
        "Future<bool> _waitForTunnelState(",
    )
    activation = _method_body(
        source,
        "Future<void> _loginWithAccountNumber()",
        "Map<String, dynamic> _freeAccessPayload(",
    )

    assert "_loadExistingClientKeyPair(token)" in refresh
    assert "rotate: true" not in refresh
    assert "await _readDeviceAuthToken()" in refresh
    assert "VerifyRequestContext(" in refresh
    assert "headers: verifyRequest.headers" in refresh
    assert "_postDoubleVpnAssignmentWithRetry(" in refresh
    assert "verifyRequest," in refresh

    # Explicit setup-key activation stages a candidate. No timeout, 401, JSON
    # failure, or other pre-success branch may delete or replace the old pair.
    assert "_stageClientKeyPairCandidate(" in activation
    assert "_commitClientKeyPairCandidate(" in activation
    assert activation.index("response.statusCode == 200") < activation.index(
        "_commitClientKeyPairCandidate("
    )
    assert "rotate: true" not in activation
    assert "_deleteClientKeyPairForAccount" not in activation


TESTS = [
    test_real_hub_paid_activation_and_refresh_matrix,
    test_client_refresh_contract_pins_timeout_and_rollback,
]


def main():
    passed = failed = 0
    print("paid refresh authorization matrix")
    for fn in TESTS:
        try:
            fn(harness.load_hub())
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
