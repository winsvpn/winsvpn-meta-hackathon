"""Round R2 Burmese guard for the website and the hub messages.

Fails if a new R2 website string or a customer-facing hub message has no
Burmese entry in web/index.html `translations.my`, if a static R2 string is
out of the page translator's reach, or if the runtime path does not render the
Burmese. It also binds the hub's message tables in the installer to both
translation maps (website and the app's `_t` in lib/main.dart), so rewording a
hub message without its Burmese fails here.

Runs the production slices of web/index.html offline under node, with the DOM
faked, like test/web_r2_redeem_codes_test.py.
"""
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "web" / "index.html"
HUB = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
MAIN_DART = ROOT / "lib" / "main.dart"

STATIC = [
    "Referral and promo codes",
    "Referral code (optional)",
    "Friend's referral code",
    "Promo code (optional)",
    "Promo code",
    "A referral code gives you and the friend who referred you 20% extra VPN time once your payment "
    "completes. A promo code adds bonus days to crypto payments and prepaid cards; it does not apply to "
    "PayPal subscriptions or PayPal checkout links.",
    "Optional redemption details",
    "Existing account number (optional)",
    "Setup key from support (only for an expired account)",
    "Setup key (only for an expired account)",
    "Leave the account number empty to create a new account. Enter an active account number to add this "
    "card's time to it: nothing else about that account changes and no setup key is shown. An expired "
    "account also needs a setup key from support; otherwise redeem for a new account.",
]
RUNTIME = [
    "Enter the account number as 12 digits (1234-5678-9012), or leave it empty to create a new account.",
    "Add this card's time to this account? Time added to a mistyped account cannot be moved.",
    "Redemption canceled. Your code has not been used.",
    "That promo code is not valid. Check it or leave the field empty.",
    "That promo code is not valid for this plan or has expired.",
    "Account extended. Your existing credentials and devices are unchanged.",
    "New expiration date:",
    "Referral bonus days added:",
    "Promo bonus days added:",
]
R2_INPUT_IDS = ["purchaseReferralInput", "purchasePromoInput", "redemptionAccountInput",
                "redemptionSetupKeyInput", "redemptionReferralInput", "redemptionPromoInput"]
KEEP_VERBATIM = ["XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXX", "1234-5678-9012", "20%", "Win's VPN", "PayPal"]


def run_node(script: str) -> dict:
    completed = subprocess.run([shutil.which("node"), "--input-type=module", "-e", script],
                               capture_output=True, text=True, timeout=20)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def source() -> str:
    return INDEX.read_text(encoding="utf-8")


def translations_js() -> str:
    html = source()
    return html.split("      const translations = {", 1)[1].split("      const originalText = new WeakMap();", 1)[0]


def translations() -> dict:
    return run_node("const translations = {" + translations_js() +
                    "\nconsole.log(JSON.stringify(translations));")


def _table(name: str) -> dict:
    text = HUB.read_text(encoding="utf-8")
    body = text.split(f"\n{name} = {{\n", 1)[1].split("\n}\n", 1)[0]
    rows = dict(re.findall(r'^\s+"(\w+)": "([^"\\]+)",$', body, re.M))
    assert rows and len(rows) == body.count('":'), f"could not parse {name}"
    return rows


def hub_messages() -> list[str]:
    extension = "Account extended. Your existing credentials and devices are unchanged."
    assert f'"{extension}"' in HUB.read_text(encoding="utf-8")
    return [*_table("REDEMPTION_REFUSAL_MESSAGES").values(),
            *_table("CHECKOUT_PROMO_MESSAGES").values(), extension]


def check_burmese(english: str, burmese: object) -> list[str]:
    problems = []
    if not isinstance(burmese, str) or not burmese.strip():
        return [f"no Burmese entry: {english!r}"]
    if not re.search("[\u1000-\u109F]", burmese):
        problems.append(f"no Myanmar script: {english!r}")
    if burmese == english:
        problems.append(f"Burmese equals English: {english!r}")
    if re.search("[\u2012-\u2015]", burmese):
        problems.append(f"en or em dash: {english!r}")
    # Myanmar Unicode stores the vowel sign E after its consonant; Zawgyi
    # stores it first, so a sign E after a space or a non-letter is Zawgyi.
    if re.search("(?<![\u1000-\u102A\u103B-\u103E])\u1031", burmese):
        problems.append(f"looks like Zawgyi, not Unicode: {english!r}")
    if sorted(re.findall(r"\{\w+\}", english)) != sorted(re.findall(r"\{\w+\}", burmese)):
        problems.append(f"placeholders differ: {english!r}")
    problems += [f"{token!r} not kept: {english!r}" for token in KEEP_VERBATIM
                 if token in english and token not in burmese]
    return problems


def test_every_r2_website_string_and_hub_message_has_burmese():
    my = translations()["my"]
    keys = STATIC + RUNTIME + hub_messages()
    problems = [p for key in keys for p in check_burmese(key, my.get(key))]
    assert not problems, "\n".join(problems)
    for english in keys:
        assert not re.search(r"\s-\s", english), f"spaced hyphen as a dash: {english!r}"


def test_hub_messages_are_in_the_app_lookup_too():
    # The app shows the same refusals verbatim through main.dart `_t`;
    # test/r2_burmese_l10n_test.dart checks the Burmese values themselves.
    main = MAIN_DART.read_text(encoding="utf-8")
    lookup = main.split("    const localized = <String, Map<String, String>>{", 1)[1]
    burmese_block = lookup.split("\n      'de': {", 1)[0]
    missing = [m for m in _table("REDEMPTION_REFUSAL_MESSAGES").values()
               if f"'{m}':\n" not in burmese_block]
    assert not missing, missing


class _Reachable(HTMLParser):
    """Collects what translatePage can see: text and placeholder/aria-label/alt
    outside script, style and translate="no" subtrees."""

    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.keys, self.inputs = [], set(), {}

    def _blocked(self):
        return any(tag in ("script", "style") or no for tag, no in self.stack)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        blocked = self._blocked() or attrs.get("translate") == "no"
        if tag == "input" and attrs.get("id"):
            self.inputs[attrs["id"]] = attrs
        if not blocked:
            for name in ("placeholder", "aria-label", "alt"):
                if attrs.get(name):
                    self.keys.add(" ".join(attrs[name].split()))
        if tag not in self.VOID:
            self.stack.append((tag, attrs.get("translate") == "no"))

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        if data.strip() and not self._blocked():
            self.keys.add(" ".join(data.split()))


def test_static_r2_strings_reach_the_page_translator():
    parser = _Reachable()
    parser.feed(source())
    missing = [key for key in STATIC if key not in parser.keys]
    assert not missing, missing
    for input_id in R2_INPUT_IDS:
        assert parser.inputs[input_id].get("translate") != "no", input_id
    # Dropping translate="no" from those inputs is safe only because the
    # translator reads these attributes and never an input's value.
    assert 'const attributeNames = ["placeholder", "aria-label", "alt"];' in source()


def test_runtime_r2_strings_render_in_burmese():
    html = source()
    translate = "      function translateRuntimeText(text) {" + html.split(
        "      function translateRuntimeText(text) {", 1)[1].split("\n      // Classify the answer tier", 1)[0]
    set_status = "      const setRedemptionStatus = (message) => {" + html.split(
        "      const setRedemptionStatus = (message) => {", 1)[1].split("      const setRedemptionAckStatus", 1)[0]
    extras = "      const redemptionAccountInput = document.getElementById" + html.split(
        "      const redemptionAccountInput = document.getElementById", 1)[1].split(
        '\n      redemptionCodeSubmit?.addEventListener("click", async () => {', 1)[0]
    handler = html.split('      redemptionCodeSubmit?.addEventListener("click", async () => {', 1)[1].split(
        "\n      let supportedLanguages", 1)[0]
    wallet = "      function walletReferralCode() {" + html.split("      function walletReferralCode() {", 1)[1].split(
        "\n      function setWalletStatus(row, text) {", 1)[0]
    refusals = _table("REDEMPTION_REFUSAL_MESSAGES")
    script = r"""
const translations = {__TRANSLATIONS__
const HUB = __REFUSALS__;
async function redeem(values, reply, confirmAnswer = true) {
  const fields = {redemptionAccountInput: {value: ""}, redemptionSetupKeyInput: {value: ""},
                  redemptionReferralInput: {value: ""}, redemptionPromoInput: {value: ""},
                  purchaseReferralInput: {value: ""}, purchasePromoInput: {value: ""}};
  for (const [id, value] of Object.entries(values)) fields[id].value = value;
  const document = {documentElement: {lang: "my"}, getElementById: id => fields[id] || null};
  const asked = [];
  const window = {confirm: question => { asked.push(question); return confirmAnswer; }};
  const redemptionCodeStatus = {textContent: ""};
  const redemptionCredentials = {hidden: false};
  const redemptionCodeInput = {value: "A".repeat(27)};
  const redemptionEmailInput = {value: ""};
  const normaliseRedemptionCode = value => value;
  const updateAckButtonState = () => {};
  let pendingAckCode = "";
  let click;
  let fetched = 0;
  const redemptionCodeSubmit = {disabled: false, addEventListener: (_e, fn) => { click = fn; }};
  const fetch = async () => { fetched++; return {status: reply[0], ok: reply[0] >= 200 && reply[0] < 300,
                                                  json: async () => reply[1]}; };
  eval("(() => {" + __TRANSLATE__ + __SET_STATUS__ + __EXTRAS__ +
       '\nredemptionCodeSubmit?.addEventListener("click", async () => {' + __HANDLER__ + "})()");
  await click();
  return {status: redemptionCodeStatus.textContent, asked, fetched};
}
const out = {};
out.shortAccount = await redeem({redemptionAccountInput: "12345"}, [500, {}]);
out.canceled = await redeem({redemptionAccountInput: "1234 5678 9012"}, [500, {}], false);
out.badPromo = await redeem({redemptionPromoInput: "x"}, [500, {}]);
out.workerPromo = await redeem({}, [400, {error: "invalid_promo_code"}]);
out.workerShape = await redeem({}, [400, {error: "invalid_account_number"}]);
out.refusals = {};
for (const [status, message] of Object.entries(HUB)) {
  out.refusals[status] = await redeem({}, [200, {ok: false, status, message}]);
}
out.extended = await redeem({}, [200, {ok: true, mode: "extend", account_number: "1234-5678-9012",
  setup_key: "", expiration_date: "2027-02-01T00:00:00+00:00", referral_bonus_days: 3, promo_bonus_days: 7}]);
const document = {documentElement: {lang: "my"}, getElementById: () => null};
const window = {location: {pathname: "/"}};
out.checkout = eval("(() => {" + __TRANSLATE__ + __WALLET__ + `
  return [translateRuntimeText(checkoutPromoError(new Error("invalid_promo_code"))),
          translateRuntimeText(checkoutPromoError(new Error("That promo code cannot be combined with a referral code.")))];
})()`);
console.log(JSON.stringify(out));
"""
    values = {"TRANSLATIONS": translations_js(), "REFUSALS": json.dumps(refusals),
              "TRANSLATE": json.dumps(translate), "SET_STATUS": json.dumps(set_status),
              "EXTRAS": json.dumps(extras), "HANDLER": json.dumps(handler), "WALLET": json.dumps(wallet)}
    script = re.sub(r"__([A-Z_]+?)__", lambda m: values[m.group(1)], script)
    r = run_node(script)
    my = translations()["my"]
    twelve = "Enter the account number as 12 digits (1234-5678-9012), or leave it empty to create a new account."
    promo = "That promo code is not valid. Check it or leave the field empty."
    assert r["shortAccount"] == {"status": my[twelve], "asked": [], "fetched": 0}
    question = "Add this card's time to this account? Time added to a mistyped account cannot be moved."
    assert r["canceled"]["asked"] == [my[question] + " 1234-5678-9012"]
    assert r["canceled"]["status"] == my["Redemption canceled. Your code has not been used."]
    assert r["canceled"]["fetched"] == 0
    assert r["badPromo"]["status"] == my[promo] and r["badPromo"]["fetched"] == 0
    assert r["workerPromo"]["status"] == my[promo]
    assert r["workerShape"]["status"] == my[twelve]
    assert set(r["refusals"]) == set(refusals)
    for status, message in refusals.items():
        assert r["refusals"][status]["status"] == my[message], status
    assert r["extended"]["status"] == " ".join([
        my["Account extended. Your existing credentials and devices are unchanged."],
        my["New expiration date:"] + " 2027-02-01.",
        my["Referral bonus days added:"] + " 3.",
        my["Promo bonus days added:"] + " 7.",
    ])
    assert r["checkout"] == [my["That promo code is not valid for this plan or has expired."],
                             my["That promo code cannot be combined with a referral code."]]
