#!/usr/bin/env python3
"""Fleet reset TP-P9 on the website (FLEET1 Turn 2, Astra item 5).

With BTCPAY_CHECKOUT_CHAINS=BTC the hub offers BTCPay for Bitcoin only. The
website's /api/site/crypto-config proxy (web/_worker.js) reads GET /nodes, and
the pricing cards (web/index.html) enable a coin selector per chain. Both must
offer only the chains the hub names, and nothing when the list is missing or
malformed (an older hub, or a tampered response): fail closed.

The SHIPPED worker module runs under node with fetch faked; the SHIPPED page
functions are extracted verbatim from index.html and run under node against a
minimal fake DOM. Nothing reaches the network.

Run: python3 -B -m pytest -q -p no:cacheprovider server/test_fleet_reset_website_chains.py
     WINS_FLEET_WEB=/path/to/web ... (mutant runs)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = Path(os.environ.get("WINS_FLEET_WEB", str(ROOT / "web")))
NODE = shutil.which("node")

WORKER_HARNESS = r"""
const [workerPath, casesJson] = process.argv.slice(2);
const worker = (await import(workerPath)).default;
const out = {};
for (const [name, hub] of Object.entries(JSON.parse(casesJson))) {
  globalThis.fetch = async (url) => {
    if (!String(url).endsWith("/nodes")) throw new Error("unexpected fetch " + url);
    if (hub === "down") throw new Error("hub unreachable");
    return new Response(JSON.stringify(hub), { status: 200, headers: { "content-type": "application/json" } });
  };
  const request = new Request("https://winsvpn.org/api/site/crypto-config?refresh=1", {
    headers: { Origin: "https://winsvpn.org", "cf-connecting-ip": "203.0.113." + (Object.keys(out).length + 1) },
  });
  const response = await worker.fetch(request, { HOPPY_API_BASE: "https://sync.winsvpn.org" }, { waitUntil() {} });
  out[name] = { status: response.status, body: await response.json() };
}
console.log(JSON.stringify(out));
"""

PAGE_HARNESS = r"""
const [selectorsSrc, parseSrc, labelSrc, casesJson] = process.argv.slice(2);
const translateRuntimeText = (text) => text;
const setCryptoTierNotice = () => {};
const setCryptoCoinSelectors = new Function("translateRuntimeText", "setCryptoTierNotice",
  selectorsSrc + "\nreturn setCryptoCoinSelectors;")(translateRuntimeText, setCryptoTierNotice);
const parse = new Function("config", parseSrc + "\nreturn { btcpayChains, cryptoEnabled };");
const label = new Function("btcpayChains", labelSrc + "\nreturn paymentLabel;");
function fakeCard() {
  const buttons = ["btc", "dash", "xmr"].map((coin) => {
    const attrs = { "data-switch": coin };
    return {
      disabled: true,
      getAttribute: (k) => attrs[k] ?? null,
      setAttribute: (k, v) => { attrs[k] = String(v); },
      removeAttribute: (k) => { delete attrs[k]; },
    };
  });
  return { buttons, querySelectorAll: () => buttons };
}
const out = {};
for (const [name, config] of Object.entries(JSON.parse(casesJson))) {
  const { btcpayChains, cryptoEnabled } = parse(config);
  const moneroEnabled = Boolean(config && config.monero_enabled === true);
  const card = fakeCard();
  setCryptoCoinSelectors(card, moneroEnabled, cryptoEnabled, true, btcpayChains);
  out[name] = {
    chains: btcpayChains,
    cryptoEnabled,
    selectors: Object.fromEntries(card.buttons.map((b) => [b.getAttribute("data-switch"), !b.disabled])),
    label: cryptoEnabled ? label(btcpayChains) : null,
  };
}
console.log(JSON.stringify(out));
"""


def run_node(script: str, *args: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="fr-web-") as tmp:
        harness = Path(tmp) / "harness.mjs"
        harness.write_text(script, encoding="utf-8")
        r = subprocess.run([NODE, str(harness), *args], capture_output=True, text=True, timeout=120, cwd=tmp)
    if r.returncode != 0:
        raise AssertionError(f"node failed: {r.stderr[-2000:]}")
    return json.loads(r.stdout.strip().splitlines()[-1])


def page_function(source: str, name: str) -> str:
    start = source.index(f"      function {name}(")
    end = source.index("\n      }\n", start) + len("\n      }\n")
    return source[start:end]


def page_block(source: str, first: str, last: str) -> str:
    start = source.index(first)
    end = source.index(last, start) + len(last)
    return source[start:end]


@unittest.skipUnless(NODE, "node is required for the website harness")
class WorkerTests(unittest.TestCase):
    def test_the_proxy_passes_only_the_chains_the_hub_names(self) -> None:
        cases = {
            "btc only": {"monero_enabled": False, "crypto_enabled": True, "btcpay_chains": ["BTC"]},
            "both": {"monero_enabled": True, "crypto_enabled": True, "btcpay_chains": ["BTC", "DASH", "BTC"]},
            "older hub, no list": {"monero_enabled": True, "crypto_enabled": True},
            "unknown chain": {"monero_enabled": False, "crypto_enabled": True, "btcpay_chains": ["BTC", "LTC"]},
            "list is not a list": {"monero_enabled": False, "crypto_enabled": True, "btcpay_chains": "BTC"},
            "checkout off": {"monero_enabled": False, "crypto_enabled": False, "btcpay_chains": ["BTC"]},
            "hub down": "down",
        }
        with tempfile.TemporaryDirectory(prefix="fr-worker-") as tmp:
            worker = Path(tmp) / "worker.mjs"
            shutil.copyfile(WEB / "_worker.js", worker)
            out = run_node(WORKER_HARNESS, worker.as_uri(), json.dumps(cases))
        expect = {
            "btc only": (200, True, ["BTC"], False),
            "both": (200, True, ["BTC", "DASH"], True),
            "older hub, no list": (200, False, [], True),
            "unknown chain": (200, False, [], False),
            "list is not a list": (200, False, [], False),
            "checkout off": (200, False, [], False),
            "hub down": (503, False, [], False),
        }
        for name, (status, crypto, chains, monero) in expect.items():
            with self.subTest(case=name):
                got = out[name]
                self.assertEqual(got["status"], status)
                self.assertIs(got["body"]["crypto_enabled"], crypto)
                self.assertEqual(got["body"].get("btcpay_chains"), chains)
                self.assertIs(got["body"]["monero_enabled"], monero)


@unittest.skipUnless(NODE, "node is required for the website harness")
class PageTests(unittest.TestCase):
    def test_a_coin_selector_is_enabled_only_for_an_offered_chain(self) -> None:
        html = (WEB / "index.html").read_text(encoding="utf-8")
        selectors = page_function(html, "setCryptoCoinSelectors")
        parse = page_block(html, "const offered = config && config.btcpay_chains;",
                           "const cryptoEnabled = btcpayChains.length > 0;")
        label = page_block(html, "const paymentLabel = btcpayChains.includes(\"BTC\")", ': "Pay with Dash";')
        cases = {
            "btc only": {"monero_enabled": False, "crypto_enabled": True, "btcpay_chains": ["BTC"]},
            "dash only": {"monero_enabled": True, "crypto_enabled": True, "btcpay_chains": ["DASH"]},
            "both": {"monero_enabled": False, "crypto_enabled": True, "btcpay_chains": ["BTC", "DASH"]},
            "older proxy, no list": {"monero_enabled": True, "crypto_enabled": True},
            "unknown chain": {"monero_enabled": False, "crypto_enabled": True, "btcpay_chains": ["LTC"]},
            "checkout off": {"monero_enabled": True, "crypto_enabled": False, "btcpay_chains": ["BTC"]},
        }
        out = run_node(PAGE_HARNESS, selectors, parse, label, json.dumps(cases))
        expect = {
            "btc only": ({"btc": True, "dash": False, "xmr": False}, "Pay with Bitcoin"),
            "dash only": ({"btc": False, "dash": True, "xmr": True}, "Pay with Dash"),
            "both": ({"btc": True, "dash": True, "xmr": False}, "Pay with Bitcoin or Dash"),
            "older proxy, no list": ({"btc": False, "dash": False, "xmr": True}, None),
            "unknown chain": ({"btc": False, "dash": False, "xmr": False}, None),
            "checkout off": ({"btc": False, "dash": False, "xmr": True}, None),
        }
        for name, (selectors_state, button_label) in expect.items():
            with self.subTest(case=name):
                self.assertEqual(out[name]["selectors"], selectors_state)
                self.assertEqual(out[name]["label"], button_label)

    def test_the_calls_pass_the_chain_list(self) -> None:
        html = (WEB / "index.html").read_text(encoding="utf-8")
        self.assertIn("buildCryptoRow(row, planKey, moneroEnabled, cryptoEnabled, btcpayChains);", html)
        self.assertIn("setCryptoCoinSelectors(card, moneroEnabled, cryptoEnabled, true, btcpayChains);", html)
        self.assertIsNone(re.search(r"Boolean\(config && config\.crypto_enabled === true\)", html))
        self.assertIn("button.textContent = translateRuntimeText(paymentLabel);", html)
        for text in ("Pay with Bitcoin", "Pay with Dash"):
            self.assertEqual(html.count(f'"{text}": '), 2, text)


if __name__ == "__main__":
    unittest.main()
