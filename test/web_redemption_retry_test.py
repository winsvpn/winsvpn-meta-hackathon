"""Offline execution of the website's actual redemption click handler."""
import json
from pathlib import Path
import shutil
import subprocess


def test_transient_redemption_responses_preserve_identical_retry():
    source = (Path(__file__).resolve().parents[1] / "web/index.html").read_text()
    handler = source.split('      redemptionCodeSubmit?.addEventListener("click", async () => {', 1)[1]
    handler = handler.split('\n      let supportedLanguages', 1)[0]
    script = r"""
const results = [];
for (const [status, payload] of [
  [503, {error: 'durability_unavailable'}],
  [502, {error: 'redemption_unavailable'}],
  [200, {}],
  [200, {ok: false, status: 'not_redeemable'}],
  [429, {error: 'rate_limited'}],
]) {
  let click;
  let message = '';
  const code = 'A'.repeat(27);
  const redemptionCodeSubmit = {disabled: false, addEventListener: (_event, fn) => {click = fn;}};
  const redemptionCodeInput = {value: code};
  const redemptionEmailInput = {value: ''};
  const normaliseRedemptionCode = value => value;
  const setRedemptionStatus = value => {message = value;};
  // R2: no optional extension, referral or promo fields in these cases.
  const readRedemptionExtras = () => ({body: {}, headers: {}});
  const fetch = async () => ({status, ok: status >= 200 && status < 300, json: async () => payload});
  eval('redemptionCodeSubmit?.addEventListener("click", async () => {' + HANDLER);
  await click();
  results.push({status, message, codeRetained: redemptionCodeInput.value === code,
    retryEnabled: !redemptionCodeSubmit.disabled});
}
console.log(JSON.stringify(results));
""".replace('HANDLER', json.dumps(handler))
    completed = subprocess.run([shutil.which('node'), '--input-type=module', '-e', script],
                               capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0, completed.stderr
    results = json.loads(completed.stdout)
    for result in results[:3]:
        assert 'same code and email' in result['message'], result['message']
        assert 'already been redeemed' not in result['message']
        assert result['codeRetained'] and result['retryEnabled']
    assert 'not valid' in results[3]['message']
    assert 'Too many attempts' in results[4]['message']
