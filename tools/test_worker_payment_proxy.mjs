import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import worker, { validatedCryptoInvoiceResponse } from "../web/_worker.js";

const checkout = "https://btcpay.winsvpn.org/i/probe";
assert.equal(
  validatedCryptoInvoiceResponse({ checkout_url: checkout }, {}).btcpay_checkout_origin,
  "https://btcpay.winsvpn.org"
);
assert.equal(
  validatedCryptoInvoiceResponse(
    { checkout_url: "https://pay.example.test/i/probe" },
    { BTCPAY_CHECKOUT_ORIGIN: "https://pay.example.test" }
  ).btcpay_checkout_origin,
  "https://pay.example.test"
);
assert.throws(
  () => validatedCryptoInvoiceResponse({ checkout_url: "https://attacker.example/i/probe" }, {}),
  /invalid_checkout_url/
);

function post(path, body, extraHeaders = {}) {
  return new Request(`https://winsvpn.org${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "origin": "https://winsvpn.org",
      "cf-connecting-ip": "198.51.100.42",
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  });
}

const originalFetch = globalThis.fetch;
try {
  let calls = 0;
  const outbound = [];
  globalThis.fetch = async (url, init) => {
    calls += 1;
    outbound.push({ url: String(url), redirect: init.redirect, headers: init.headers });
    // What redirect: "manual" hands back for a hub 3xx: the redirect itself.
    return new Response(null, { status: 307, headers: { location: "https://elsewhere.example/" } });
  };
  const cryptoRedirect = await worker.fetch(
    post("/pay/crypto/create-invoice", { plan_key: "one_month" }), {}, {}
  );
  assert.equal(cryptoRedirect.status, 502);
  assert.deepEqual(await cryptoRedirect.json(), { error: "crypto_unavailable" });
  const redeemRedirect = await worker.fetch(
    post("/api/redeem", { code: "A".repeat(27), account_number: "1111-2222-3333" },
      { "x-wins-activation": "A".repeat(32) }), {}, {}
  );
  assert.equal(redeemRedirect.status, 502);
  assert.deepEqual(await redeemRedirect.json(), { error: "redemption_unavailable" });
  assert.equal(calls, 2);
  assert.deepEqual(outbound.map(({ url, redirect }) => ({ url, redirect })), [
    { url: "https://sync.winsvpn.org/pay/crypto/create-invoice", redirect: "manual" },
    { url: "https://sync.winsvpn.org/api/redeem", redirect: "manual" },
  ]);
  assert.equal(outbound[1].headers["x-wins-activation"], "A".repeat(32));

  // The other three hub fetches never follow either: a 3xx is not ok, so each
  // takes its existing fallback instead of trusting or feeding another origin.
  const seen = [];
  globalThis.fetch = async (url, init) => {
    seen.push({ url: String(url), redirect: init.redirect });
    return new Response(null, { status: 307, headers: { location: "https://elsewhere.example/" } });
  };
  const env = { RATE_LIMITER_AI_CHAT: { limit: async () => ({ success: true }) } };
  const configHeaders = { origin: "https://winsvpn.org", "cf-connecting-ip": "198.51.100.42" };
  const walletConfig = await worker.fetch(
    new Request("https://winsvpn.org/api/site/wallet-config", { headers: configHeaders }), env, {}
  );
  assert.equal(walletConfig.status, 503);
  assert.equal((await walletConfig.json()).error, "wallet_not_configured");
  const cryptoConfig = await worker.fetch(
    new Request("https://winsvpn.org/api/site/crypto-config", { headers: configHeaders }), env, {}
  );
  assert.equal(cryptoConfig.status, 503);
  assert.equal((await cryptoConfig.json()).crypto_enabled, false);
  const chat = await worker.fetch(post("/api/site/ai-chat", { message: "How do I connect?" }), env, {});
  assert.equal(chat.status, 200);
  assert.equal((await chat.json()).mode, "fallback");
  assert.deepEqual(seen, [
    { url: "https://sync.winsvpn.org/nodes", redirect: "manual" },
    { url: "https://sync.winsvpn.org/nodes", redirect: "manual" },
    { url: "https://sync.winsvpn.org/api/site/ai-chat", redirect: "manual" },
  ]);

  // R23 W1-11: the two fetches that carry a Google API key (translate and
  // Gemini) never follow a 3xx either, so the key cannot reach another origin.
  const keyed = [];
  globalThis.fetch = async (url, init) => {
    keyed.push({
      url: String(url),
      redirect: init.redirect,
      key: (init.headers || {})["x-goog-api-key"] || null,
    });
    return new Response(null, { status: 307, headers: { location: "https://elsewhere.example/" } });
  };
  const apiKey = "AIza" + "K".repeat(35);
  const keyEnv = {
    GOOGLE_TRANSLATE_API_KEY: apiKey,
    GEMINI_API_KEY: apiKey,
    RATE_LIMITER_TRANSLATE: { limit: async () => ({ success: true }) },
    RATE_LIMITER_AI_CHAT: { limit: async () => ({ success: true }) },
  };
  const translated = await worker.fetch(
    post("/api/site/translate", { target: "my", texts: ["Connect"] }), keyEnv, {}
  );
  assert.equal(translated.status, 502);
  assert.equal((await translated.json()).error, "translation_failed");
  const geminiChat = await worker.fetch(post("/api/site/ai-chat", { message: "How do I connect?" }), keyEnv, {});
  assert.equal(geminiChat.status, 200);
  assert.equal((await geminiChat.json()).mode, "fallback");
  const keyedCalls = keyed.filter(({ key }) => key !== null);
  assert.ok(keyedCalls.length >= 2, "translate and Gemini each sent one keyed request");
  for (const call of keyedCalls) {
    assert.equal(call.redirect, "manual");
    assert.equal(new URL(call.url).hostname.endsWith(".googleapis.com"), true);
  }
  assert.ok(keyedCalls.some(({ url }) => url.startsWith("https://translation.googleapis.com/")));
  assert.ok(keyedCalls.some(({ url }) => url.startsWith("https://generativelanguage.googleapis.com/")));
  assert.equal(keyed.some(({ url }) => url.includes("elsewhere.example")), false);

  globalThis.fetch = async (_url, init) => {
    assert.equal(init.redirect, "manual");
    return new Response(JSON.stringify({ checkout_url: checkout }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const normal = await worker.fetch(
    post("/pay/crypto/create-invoice", { plan_key: "one_month" }), {}, {}
  );
  assert.equal(normal.status, 200);
  assert.equal((await normal.json()).btcpay_checkout_origin, "https://btcpay.winsvpn.org");
} finally {
  globalThis.fetch = originalFetch;
}

// Node's fetch accepts redirect: "error", but the Workers runtime throws a
// TypeError for it on every call ("error" won't be implemented at the edge),
// which turned every proxied payment and redemption into a 502. It must never
// come back into the worker.
const workerSource = readFileSync(new URL("../web/_worker.js", import.meta.url), "utf8");
assert.equal(workerSource.includes('redirect: "error"'), false);

process.stdout.write("worker payment origin and redirect tests: OK\n");
