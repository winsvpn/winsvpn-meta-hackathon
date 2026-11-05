"""Offline execution of the website's referral-landing handler.

A visitor who arrives on /referral/<code> must leave for the hub's /pay/<option>
redirect with ?ref=<code>, because GET /pay/{option_key} on the hub reads the
referral from that query parameter and nowhere else.
"""
import json
from pathlib import Path
import shutil
import subprocess

WEB = Path(__file__).resolve().parents[1] / "web"


def test_referral_landing_carries_code_into_pay_links():
    source = (WEB / "index.html").read_text()
    handler = source.split("      function applyReferralLanding() {", 1)[1]
    handler = handler.split("\n      applyReferralLanding();", 1)[0]
    script = r"""
const links = [
  {href: "/pay/one_month?src=website"},
  {href: "/pay/lifetime_no_support?src=website"},
  {href: "/pay/donation?src=website_footer"},
  {href: "/pay/one_year?src=website&ref=already"},
  {href: "https://winsvpn.org/pay/one_year?src=website"},
  {href: "#referral"},
];
for (const link of links) {
  link.getAttribute = name => (name === "href" ? link.href : null);
  link.setAttribute = (name, value) => { if (name === "href") link.href = value; };
}
const notice = {replaceChildren: () => {}};
globalThis.window = {location: {pathname: "/referral/abcDEF-12_x", origin: "https://winsvpn.org"}};
globalThis.document = {
  querySelectorAll: selector => (selector === 'a[href^="/pay/"]' ? links.filter(l => l.href.startsWith("/pay/")) : []),
  getElementById: id => (id === "referralLandingNotice" ? notice : null),
  createElement: () => ({setAttribute: () => {}, textContent: ""}),
  createTextNode: () => ({}),
};
const applyReferralLanding = eval("(function applyReferralLanding() {" + HANDLER + ")");
applyReferralLanding();
console.log(JSON.stringify(links.map(l => l.href)));
""".replace("HANDLER", json.dumps(handler))
    completed = subprocess.run([shutil.which("node"), "--input-type=module", "-e", script],
                               capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0, completed.stderr
    hrefs = json.loads(completed.stdout)
    assert hrefs[0] == "/pay/one_month?src=website&ref=abcDEF-12_x"
    assert hrefs[1] == "/pay/lifetime_no_support?src=website&ref=abcDEF-12_x"
    assert hrefs[2] == "/pay/donation?src=website_footer&ref=abcDEF-12_x"
    assert hrefs[3] == "/pay/one_year?src=website&ref=already"
    assert hrefs[4] == "https://winsvpn.org/pay/one_year?src=website"
    assert hrefs[5] == "#referral"
