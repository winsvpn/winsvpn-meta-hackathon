#!/usr/bin/env python3
"""Exercise the real website with CSP and intercepted configuration responses.

Run with a Playwright environment and installed Chromium. All requests are
fulfilled locally or aborted; this test cannot create a real payment order.
"""
import argparse
import asyncio
import json
from pathlib import Path

async def check_site(web_root: Path, executable: str | None):
    from playwright.async_api import async_playwright

    html = (web_root / "index.html").read_text()
    csp = next(line.strip().split(":", 1)[1].strip() for line in
               (web_root / "_headers").read_text().splitlines()
               if line.strip().startswith("Content-Security-Policy:"))
    cases = {
        "loading": None,
        "failed": "fail",
        "disabled": {},
        "malformed": "malformed",
        "monero_only": {"monero_enabled": True, "crypto_enabled": False},
        "btcpay_only": {"monero_enabled": False, "crypto_enabled": True, "btcpay_chains": ["BTC", "DASH"]},
        "both": {"monero_enabled": True, "crypto_enabled": True, "btcpay_chains": ["BTC", "DASH"]},
        # Fleet reset TP-P9 (FLEET1 Turn 2): only the chains the hub names.
        "btc_only": {"monero_enabled": False, "crypto_enabled": True, "btcpay_chains": ["BTC"]},
        "no_chain_list": {"monero_enabled": True, "crypto_enabled": True},
    }
    results = []
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(**({"executable_path": executable} if executable else {}))
        try:
            for width in (390, 1440):
                for name, config in cases.items():
                    page = await browser.new_page(viewport={"width": width, "height": 1000})
                    held = []
                    async def route_request(route):
                        url = route.request.url
                        if url == "https://winsvpn.org/":
                            await route.fulfill(body=html, content_type="text/html", headers={"Content-Security-Policy": csp})
                        elif url.endswith("/api/site/crypto-config"):
                            if config is None:
                                held.append(route)
                            elif config == "fail":
                                await route.fulfill(status=503, body="unavailable")
                            elif config == "malformed":
                                await route.fulfill(body="{broken", content_type="application/json")
                            else:
                                await route.fulfill(body=json.dumps(config), content_type="application/json")
                        elif "/api/" in url or "/i18n/" in url or url.endswith(".json"):
                            await route.fulfill(body="{}", content_type="application/json")
                        else:
                            await route.abort()
                    await page.route("**/*", route_request)
                    await page.goto("https://winsvpn.org/", wait_until="domcontentloaded")
                    await page.wait_for_function("document.querySelector('.crypto-plan-btn').hasAttribute('aria-expanded')")
                    card = page.locator('[data-plan-key="one_month"]')
                    await card.locator(".crypto-plan-btn").click()
                    if isinstance(config, dict) and config:
                        await card.locator(".crypto-pay-button").first.wait_for()
                    elif config is not None:
                        await page.wait_for_function("document.querySelector('[data-plan-key=one_month] [data-crypto-row]').textContent.includes('Automated crypto checkout is unavailable')")
                    buttons = card.locator(".crypto-coin-selector-grid .crypto-coin-btn")
                    states = await buttons.evaluate_all("buttons => Object.fromEntries(buttons.map(b => [b.dataset.switch, !b.disabled]))")
                    expected = {"btc": False, "dash": False, "xmr": False}
                    if isinstance(config, dict):
                        chains = config.get("btcpay_chains") if config.get("crypto_enabled") else []
                        chains = chains if isinstance(chains, list) else []
                        expected.update(btc="BTC" in chains, dash="DASH" in chains, xmr=config.get("monero_enabled", False))
                    assert states == expected, (width, name, states, expected)
                    for coin, enabled in expected.items():
                        button = card.locator(f'.crypto-coin-btn[data-switch="{coin}"]')
                        if enabled:
                            await button.click()
                            panel = card.locator(".crypto-monero-panel" if coin == "xmr" else ".crypto-pay-panel:not(.crypto-monero-panel)")
                            assert await panel.is_visible(), (width, name, coin)
                            await button.click()
                    # Dispatch a synthetic event even through a disabled control:
                    # the handler itself must also refuse the donation fallback.
                    if not any(expected.values()):
                        await buttons.first.dispatch_event("click")
                        assert "Automated crypto checkout is unavailable" in await card.locator("[data-crypto-row]").inner_text()
                    assert await page.locator("#cryptoModalBackdrop").is_hidden()
                    assert not await page.locator("body").evaluate("el => el.classList.contains('crypto-modal-open')")
                    assert await page.locator("#cryptoModalBackdrop").evaluate("el => el.parentElement === document.body")
                    # Donation remains visible even if its former parent is hidden.
                    await page.locator("#cryptoBtnBtc").dispatch_event("click")
                    assert await page.locator("#cryptoDonationDrawer").is_hidden()
                    assert await page.locator("#cryptoModalBackdrop").is_visible()
                    await page.locator("#cryptoModalClose").click()
                    assert not await page.locator("body").evaluate("el => el.classList.contains('crypto-modal-open')")
                    for route in held:
                        await route.fulfill(status=503, body="unavailable")
                    results.append({"width": width, "configuration": name, "passed": True})
                    await page.close()
        finally:
            await browser.close()
    print(json.dumps({"cases": results, "passed": len(results)}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--web-root", type=Path, default=Path(__file__).resolve().parents[1] / "web")
    parser.add_argument("--executable")
    args = parser.parse_args()
    asyncio.run(check_site(args.web_root, args.executable))
