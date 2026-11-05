"""Round R2: website and Worker handling of extension, referral and promo codes.

Runs the production Worker module and production slices of web/index.html
offline under node, with fetch and the DOM faked.
"""
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"


def run_node(script: str) -> dict:
    completed = subprocess.run([shutil.which("node"), "--input-type=module", "-e", script],
                               capture_output=True, text=True, timeout=20)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_worker_forwards_only_validated_redemption_fields():
    worker = (WEB / "_worker.js").read_text()
    script = r"""
const source = WORKER;
const mod = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));
const sent = [];
globalThis.fetch = async (url, init) => {
  sent.push({url: String(url), headers: init.headers, body: JSON.parse(init.body)});
  return new Response(JSON.stringify({ok: true}), {status: 200, headers: {"content-type": "application/json"}});
};
const env = {ASSETS: {fetch: async () => new Response("asset")}};
let ip = 1;
async function post(path, body, headers = {}) {
  const request = new Request("https://winsvpn.org" + path, {
    method: "POST",
    headers: {"content-type": "application/json", "origin": "https://winsvpn.org",
              "cf-connecting-ip": "198.51.100." + (ip++), ...headers},
    body: JSON.stringify(body),
  });
  const response = await mod.default.fetch(request, env, {waitUntil() {}});
  return {status: response.status, body: await response.json().catch(() => ({}))};
}
const code = "ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-234";
const key = "k".repeat(43);
const results = {};
results.extend = await post("/api/redeem", {code, account_number: "123456789012", device_id: "dev",
  referral_code: "friend_01", promo_code: "welcome7"},
  {"x-wins-activation": key, "authorization": "Bearer should-not-pass"});
results.extendSent = sent.at(-1);
results.noAccount = await post("/api/redeem", {code}, {"x-wins-activation": key});
results.noAccountSent = sent.at(-1);
const before = sent.length;
results.badPromo = await post("/api/redeem", {code, promo_code: "!!"});
results.badAccount = await post("/api/redeem", {code, account_number: "12-34"});
results.noHubCallForBad = sent.length === before;
results.ack = await post("/api/redeem/ack", {code, account_number: "123456789012", promo_code: "WELCOME7"});
results.ackSent = sent.at(-1);
results.monero = await post("/pay/monero/create-order", {plan_key: "one_month", email: "a@example.org",
  referral_code: "friend_01", promo_code: "crypto5"});
results.moneroSent = sent.at(-1);
results.btcpay = await post("/pay/crypto/create-invoice", {plan_key: "one_year", promo_code: "crypto5"});
results.btcpaySent = sent.at(-1);
console.log(JSON.stringify(results));
""".replace("WORKER", json.dumps(worker))
    r = run_node(script)
    sent = r["extendSent"]
    assert sent["url"].endswith("/api/redeem")
    assert sent["body"] == {"code": "ABCDEFGHJKMNPQRSTVWXYZ01234", "account_number": "123456789012",
                            "referral_code": "friend_01", "promo_code": "WELCOME7"}
    assert sent["headers"].get("x-wins-activation") == "k" * 43
    assert "authorization" not in {k.lower() for k in sent["headers"]}
    assert "x-wins-activation" not in r["noAccountSent"]["headers"], "a setup key travels only with an account"
    assert r["badPromo"] == {"status": 400, "body": {"error": "invalid_promo_code"}}
    assert r["badAccount"]["status"] == 400
    assert r["noHubCallForBad"]
    assert r["ackSent"]["body"] == {"code": "ABCDEFGHJKMNPQRSTVWXYZ01234"}
    assert r["moneroSent"]["body"] == {"plan_key": "one_month", "email": "a@example.org",
                                       "referral_code": "friend_01", "promo_code": "CRYPTO5"}
    assert r["btcpaySent"]["body"]["promo_code"] == "CRYPTO5"


def test_redeem_panel_reads_extras_and_renders_refusals_and_extensions():
    source = (WEB / "index.html").read_text()
    extras = source.split("      const redemptionAccountInput = document.getElementById", 1)[1]
    extras = "      const redemptionAccountInput = document.getElementById" + extras.split(
        '\n      redemptionCodeSubmit?.addEventListener("click", async () => {', 1)[0]
    handler = source.split('      redemptionCodeSubmit?.addEventListener("click", async () => {', 1)[1]
    handler = handler.split('\n      let supportedLanguages', 1)[0]
    script = r"""
const fields = {redemptionAccountInput: {value: ""}, redemptionSetupKeyInput: {value: ""},
                redemptionReferralInput: {value: ""}, redemptionPromoInput: {value: ""}};
const document = {getElementById: id => fields[id] || null};
const window = {confirm: () => true};
const translateRuntimeText = t => t;
let pendingAckCode = "x";
const updateAckButtonState = () => {};
const redemptionCredentials = {hidden: false};
const redemptionCodeStatus = {textContent: ""};
const api = eval("(() => {" + EXTRAS + "\nreturn {readRedemptionExtras, renderRedemptionExtension};})()");
const out = {};
fields.redemptionAccountInput.value = "1234 5678 9012";
fields.redemptionSetupKeyInput.value = "setup-key-from-support";
fields.redemptionReferralInput.value = " friend_01 ";
fields.redemptionPromoInput.value = "welcome7";
out.extras = api.readRedemptionExtras();
fields.redemptionAccountInput.value = "12345";
out.shortAccount = api.readRedemptionExtras();
fields.redemptionAccountInput.value = "";
fields.redemptionPromoInput.value = "x";
out.badPromo = api.readRedemptionExtras();
fields.redemptionPromoInput.value = "";
fields.redemptionReferralInput.value = "";
out.empty = api.readRedemptionExtras();

const cases = [
  [200, {ok: false, status: "account_inactive", message: "That account is not active. Your code has not been used."}],
  [200, {ok: false, status: "not_redeemable", message: "x"}],
  [400, {error: "invalid_promo_code"}],
  [200, {ok: true, mode: "extend", account_number: "1234-5678-9012", setup_key: "",
         expiration_date: "2027-02-01T00:00:00+00:00", referral_bonus_days: 0, promo_bonus_days: 7}],
];
out.handler = [];
for (const [status, payload] of cases) {
  let click;
  let message = "";
  let sentBody = null;
  const redemptionCodeSubmit = {disabled: false, addEventListener: (_e, fn) => { click = fn; }};
  const redemptionCodeInput = {value: "A".repeat(27)};
  const redemptionEmailInput = {value: ""};
  const normaliseRedemptionCode = value => value;
  const setRedemptionStatus = value => { message = value; };
  let rendered = null;
  const renderRedemptionExtension = p => { rendered = p.mode; };
  const readRedemptionExtras = () => ({body: {account_number: "1234-5678-9012"}, headers: {"X-Wins-Activation": "k"}});
  const fetch = async (_path, init) => { sentBody = {body: JSON.parse(init.body), headers: init.headers};
    return {status, ok: status >= 200 && status < 300, json: async () => payload}; };
  eval('redemptionCodeSubmit?.addEventListener("click", async () => {' + HANDLER);
  await click();
  out.handler.push({message, rendered, sentBody, retryEnabled: !redemptionCodeSubmit.disabled,
                    codeRetained: redemptionCodeInput.value === "A".repeat(27)});
}
api.renderRedemptionExtension({expiration_date: "2027-02-01T00:00:00+00:00", referral_bonus_days: 3, promo_bonus_days: 7});
out.extensionText = redemptionCodeStatus.textContent;
out.credentialsHidden = redemptionCredentials.hidden;
out.pendingCleared = pendingAckCode === "";
console.log(JSON.stringify(out));
""".replace("EXTRAS", json.dumps(extras)).replace("HANDLER", json.dumps(handler))
    r = run_node(script)
    assert r["extras"] == {"body": {"account_number": "1234-5678-9012", "referral_code": "friend_01",
                                    "promo_code": "WELCOME7"},
                           "headers": {"X-Wins-Activation": "setup-key-from-support"}}
    assert "12 digits" in r["shortAccount"]["error"]
    assert "promo code" in r["badPromo"]["error"]
    assert r["empty"] == {"body": {}, "headers": {}}
    refused, declined, bad_promo, extended = r["handler"]
    assert refused["message"].startswith("That account is not active") and refused["codeRetained"]
    assert refused["sentBody"]["body"]["account_number"] == "1234-5678-9012"
    assert refused["sentBody"]["headers"]["X-Wins-Activation"] == "k"
    assert declined["message"] == "That code is not valid, or has already been redeemed."
    assert "promo code is not valid" in bad_promo["message"] and bad_promo["codeRetained"]
    assert extended["rendered"] == "extend" and not extended["codeRetained"]
    assert all(case["retryEnabled"] for case in r["handler"])
    assert "2027-02-01" in r["extensionText"] and "Referral bonus days added: 3." in r["extensionText"]
    assert "Promo bonus days added: 7." in r["extensionText"]
    assert r["credentialsHidden"] and r["pendingCleared"]


def test_purchase_panel_codes_reach_wallet_and_crypto_bodies():
    source = (WEB / "index.html").read_text()
    referral = "      function walletReferralCode() {" + source.split("      function walletReferralCode() {", 1)[1].split(
        "\n      function setWalletStatus(row, text) {", 1)[0]
    script = r"""
// applyReferralLanding prefills the field on /ref/<code> pages.
const fields = {purchaseReferralInput: {value: "landing_code"}, purchasePromoInput: {value: ""}};
const document = {getElementById: id => fields[id] || null};
const window = {location: {pathname: "/ref/landing_code"}};
const {walletReferralCode, walletPromoCode, checkoutPromoError} = eval(
  "(() => {" + FUNCS + "\nreturn {walletReferralCode, walletPromoCode, checkoutPromoError};})()");
const out = {};
out.landing = walletReferralCode();
fields.purchaseReferralInput.value = " typed-code ";
out.typed = walletReferralCode();
fields.purchaseReferralInput.value = "";
out.cleared = walletReferralCode();
const noField = eval("(() => {" + FUNCS.replace('document.getElementById("purchaseReferralInput")', "null")
  + "\nreturn walletReferralCode;})()");
out.noFieldLanding = noField();
fields.purchasePromoInput.value = " crypto5 ";
out.promo = walletPromoCode();
out.err1 = checkoutPromoError(new Error("invalid_promo_code"));
out.err2 = checkoutPromoError(new Error("That promo code cannot be combined with a referral code."));
out.err3 = checkoutPromoError(new Error("monero_unavailable"));
console.log(JSON.stringify(out));
""".replace("FUNCS", json.dumps(referral))
    r = run_node(script)
    assert r["landing"] == "landing_code"
    assert r["typed"] == "typed-code"
    # R2-AUDIT-05: clearing the field on a /ref/<code> page clears the referral
    # for wallet, BTCPay and Monero too; the path fallback is only for pages
    # without the field.
    assert r["cleared"] == ""
    assert r["noFieldLanding"] == "landing_code"
    assert r["promo"] == "CRYPTO5"
    assert "not valid" in r["err1"]
    assert r["err2"].startswith("That promo code cannot be combined")
    assert r["err3"] == ""
    monero = source.split('const order = await walletApiCall("/pay/monero/create-order", payload);', 1)[0][-900:]
    assert "referral_code: referralCode" in monero and "promo_code: promoCode" in monero
