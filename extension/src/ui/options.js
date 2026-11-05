import { api, isSafariRuntime } from '../adapters/index.js';
import {
  MODE_ALL_COST,
  MODE_ALL_LABEL,
  MODE_LISTED_COST,
  MODE_LISTED_LABEL,
  PANIC_CLEAR_COST,
  PANIC_CLEAR_LABEL,
  STORAGE_NOTE,
  SAFARI_WHAT_THIS_IS,
  WHAT_THIS_IS,
  edgeProxyControlNote,
  stateCopy,
} from '../core/copy.js';
import { STATE } from '../core/constants.js';
import { MODE_ALL, MODE_LISTED, normaliseRule } from '../core/rules.js';

import { COPY_LOCALE_CHOICE_KEY, displayedCopyLocale } from '../core/locale.js';

let copyLocaleChoice = null;

function renderCopyLocale() {
  document.documentElement.lang = displayedCopyLocale({ choice: copyLocaleChoice, uiLocale: snapshot?.uiLocale });
}

const $ = (id) => document.getElementById(id);
let snapshot = null;
const safariRuntime = isSafariRuntime();

// The limits, on the page, in the product: not only in a document nobody
// installing this will read. Every line here is something the extension is
// architecturally unable to do, not something that is merely unfinished.
const CANNOT = [
  'It cannot connect or disconnect the tunnel on its own. It can only ask, and the desktop app acts only for a browser you approved in the app; you can revoke that approval there at any time.',
  'It cannot encrypt anything. All of the encryption is the desktop app’s, and this proxy extension has no way to check that any of it happened.',
  'It cannot protect other programs. Only this browser is affected.',
  'It cannot see which server the desktop app uses. The desktop app describes its local connection point by port number only, so there is no address in this proxy extension for anyone to read out of it.',
  'It cannot measure or test a server. There is no request for that in the channel it speaks, deliberately: a timing figure attached to one server would reveal that server as surely as its address would.',
  'It cannot tell you whether the tunnel is really working. It repeats what the desktop app reports, and it says so.',
  'It cannot stop a website identifying you by other means: an account you are signed in to, or a fingerprint of this browser.',
];

function validSnapshot(value) {
  const settings = value?.settings;
  return Boolean(value && typeof value === 'object' && !value.error
    && settings && typeof settings.armed === 'boolean'
    && (settings.mode === 'all' || settings.mode === 'listed')
    && Array.isArray(settings.listed) && settings.listed.every((rule) => typeof rule === 'string')
    && Array.isArray(settings.excluded) && settings.excluded.every((rule) => typeof rule === 'string'));
}

function showInitializationFailure(value) {
  const error = value?.error;
  snapshot = null;
  $('liveHeadline').textContent = 'Not routing: this proxy extension could not start';
  $('liveDetail').textContent = error ? String(error).slice(0, 200) : '';
  for (const id of ['modeAll', 'modeListed', 'ruleInput', 'addRule', 'panic', 'forgetPairing']) $(id).disabled = true;
}

async function send(message) {
  const request = message.type === 'setSettings'
    ? { ...message, expectedSettings: snapshot?.settings }
    : message;
  try {
    const response = await api.runtime.sendMessage(request);
    if (!validSnapshot(response)) {
      showInitializationFailure(response);
      return null;
    }
    return response;
  } catch (error) {
    showInitializationFailure({ error: error?.message || error });
    return null;
  }
}

async function refresh() {
  try {
    const stored = await api.storage.local.get(COPY_LOCALE_CHOICE_KEY);
    copyLocaleChoice = stored[COPY_LOCALE_CHOICE_KEY];
  } catch { copyLocaleChoice = null; }
  snapshot = await send({ type: 'getState' });
  if (!validSnapshot(snapshot)) return;
  render();
}

function renderStatic(what = safariRuntime ? SAFARI_WHAT_THIS_IS : WHAT_THIS_IS) {
  document.title = "Win's VPN Proxy: sites & settings";
  $('whatTitle').textContent = what.title;
  const body = $('whatBody');
  body.textContent = '';
  for (const para of what.body) {
    const p = document.createElement('p');
    p.textContent = para;
    body.appendChild(p);
  }
  $('modeAllLabel').textContent = MODE_ALL_LABEL;
  $('modeAllCost').textContent = MODE_ALL_COST;
  $('modeListedLabel').textContent = MODE_LISTED_LABEL;
  $('modeListedCost').textContent = MODE_LISTED_COST;
  $('storageNote').textContent = STORAGE_NOTE;
  $('panic').textContent = PANIC_CLEAR_LABEL;
  $('panicCost').textContent = PANIC_CLEAR_COST;

  const ul = $('cannot');
  ul.textContent = '';
  for (const line of CANNOT) {
    const li = document.createElement('li');
    li.textContent = line;
    ul.appendChild(li);
  }
}

function render() {
  if (!validSnapshot(snapshot)) {
    showInitializationFailure(snapshot);
    return;
  }
  renderPairing();
  $('copyLocale').value = copyLocaleChoice === 'en' || copyLocaleChoice === 'my' ? copyLocaleChoice : '';
  renderStatic(snapshot.browser === 'safari' ? SAFARI_WHAT_THIS_IS : WHAT_THIS_IS);
  const unavailable = snapshot.routingSurface && snapshot.routingSurface.ok === false;
  $('routingSettingsHeading').hidden = unavailable;
  $('routingModeCard').hidden = unavailable;
  $('routingRuleCard').hidden = unavailable;
  const listed = snapshot.settings.mode === MODE_LISTED;
  $('modeAll').checked = !listed;
  $('modeListed').checked = listed;

  $('listHeading').textContent = listed
    ? 'Sites that go through the tunnel'
    : 'Sites kept outside the tunnel';

  const rules = listed ? snapshot.settings.listed : snapshot.settings.excluded;
  const ul = $('ruleList');
  ul.textContent = '';
  for (const rule of rules) {
    const li = document.createElement('li');
    const span = document.createElement('span');
    span.textContent = rule;
    const btn = document.createElement('button');
    btn.textContent = 'Remove';
    btn.setAttribute('aria-label', `Remove ${rule}`);
    btn.disabled = unavailable;
    btn.addEventListener('click', () => removeRule(rule));
    li.append(span, btn);
    ul.appendChild(li);
  }
  if (!rules.length) {
    const li = document.createElement('li');
    li.className = 'muted';
    li.textContent = listed
      ? 'Nothing listed yet. With nothing listed, no site is routed and this browser behaves exactly as it did before.'
      : 'Nothing excluded. Every site in this browser goes through the tunnel.';
    ul.appendChild(li);
  }

  renderCopyLocale();
  const copy = stateCopy(snapshot.state);
  $('liveHeadline').textContent = copy.headline;
  $('liveDetail').textContent = snapshot.state === STATE.NO_ROUTING_SURFACE && snapshot.detail
    ? `${copy.detail} ${snapshot.detail}`
    : copy.detail;
  if (snapshot.lastError) {
    $('liveDetail').textContent += ` ${snapshot.lastError}`;
  }
  $('liveMechanism').textContent = describeMechanism(snapshot);
  $('liveControl').textContent = edgeProxyControlNote(
    snapshot.proxyLevelOfControl,
    snapshot.browser,
  );
  $('livePrivacy').textContent = describePrivacy(snapshot);
  $('liveIncognito').textContent = unavailable
    ? 'Normal and private Safari routing depend on the standalone app. This panel does not control either.'
    : snapshot.incognitoAllowed === null
    ? 'Private-window permission could not be verified.'
    : snapshot.incognitoAllowed && snapshot.incognitoRouting?.ok !== false
    ? 'Private windows use the same routing as normal windows.'
    : 'Private windows are not covered. Allow this proxy extension in private windows from the browser’s add-on settings if you want them included.';

  // Both browser families need a permission that is not granted at install
  // time, and the reason differs, so the explanation does too.
  const needsGrant = !unavailable && snapshot.canAuthenticate === false;
  $('firefoxCard').hidden = !needsGrant;
  if (needsGrant) {
    $('firefoxDetail').textContent =
      snapshot.browser === 'firefox'
        ? 'The desktop app asks Firefox for a one-time key before its local proxy will carry anything. Without this permission the extension cannot choose per-site proxy routes or present the key when the proxy asks, so it cannot route and will block your chosen sites instead. It reads no page and changes no page content.'
        : 'The desktop app asks this browser for a key before it will carry anything. This browser only tells the extension about that request for addresses it has been given access to, so without this permission the key is never sent, nothing is routed, and your chosen sites are blocked instead. The extension listens for that one event and for nothing else: it reads no page and changes no request.';
  }
  for (const id of ['modeAll', 'modeListed', 'ruleInput', 'addRule']) {
    $(id).disabled = unavailable;
  }
  $('panic').disabled = false;
}

function describeMechanism(s) {
  if (s.routingMechanism === 'onRequest') {
    return 'Routing each request individually, and handing website names to the desktop app rather than looking them up here.';
  }
  if (s.routingMechanism === 'settings') {
    return 'Routing through a browser-wide proxy setting.';
  }
  if (s.routingMechanism === 'pac') {
    return 'Routing through a browser-wide proxy setting.';
  }
  return 'Not routing anything at the moment.';
}

function describePrivacy(s) {
  const p = s.privacy || {};
  const bits = [];
  if (p.webrtc === 'applied') bits.push('video and voice calls cannot open their own direct connections');
  else if (p.webrtc === 'not_applied') bits.push('this browser refused the setting that stops video and voice calls opening their own direct connections');
  else if (p.webrtc === 'unsupported') bits.push('this browser does not offer the setting that stops video and voice calls opening their own direct connections');
  if (p.prediction === 'applied') bits.push('looking up and connecting to links before you click them is turned off');
  return bits.length ? `${bits.join('; ')}.` : '';
}

async function setMode(mode) {
  if (!validSnapshot(snapshot)) return;
  snapshot = await send({ type: 'setSettings', settings: { ...snapshot.settings, mode } });
  render();
}

async function removeRule(rule) {
  if (!validSnapshot(snapshot)) return;
  const key = snapshot.settings.mode === MODE_LISTED ? 'listed' : 'excluded';
  const next = snapshot.settings[key].filter((r) => r !== rule);
  snapshot = await send({ type: 'setSettings', settings: { ...snapshot.settings, [key]: next } });
  render();
}

$('modeAll').addEventListener('change', () => setMode(MODE_ALL));
$('modeListed').addEventListener('change', () => setMode(MODE_LISTED));

$('addRule').addEventListener('click', async () => {
  if (!validSnapshot(snapshot)) return;
  const err = $('ruleError');
  const parsed = normaliseRule($('ruleInput').value);
  if (!parsed.ok) {
    err.hidden = false;
    err.textContent = parsed.reason;
    return;
  }
  err.hidden = true;
  const key = snapshot.settings.mode === MODE_LISTED ? 'listed' : 'excluded';
  const next = [...snapshot.settings[key], parsed.rule];
  snapshot = await send({ type: 'setSettings', settings: { ...snapshot.settings, [key]: next } });
  $('ruleInput').value = '';
  render();
});

$('ruleInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $('addRule').click();
});

/**
 * THE GRANT MUST HAPPEN HERE, IN THE CLICK, AND NOTHING MAY BE AWAITED FIRST.
 *
 * This used to send `{type:'requestHostPermission'}` to the background script,
 * which called `permissions.request()`. On Firefox 153 that silently cannot
 * grant: a runtime message handler is not a user input handler, so the browser
 * constructed the permission doorhanger and never showed it, the request never
 * resolved to a grant, and `catch { return false }` in the adapter threw away
 * the reason. Measured, on the shipped button.
 *
 * Chromium was then checked rather than assumed, because the obvious guess is
 * that it applies the same rule -- and it does not. Chrome 151 accepts the call
 * from a service worker's message handler and puts up its bubble. So the old
 * shape was broken on one of the two browsers, not both.
 *
 * It is written this way on both anyway. A call whose whole contract is "must
 * come from a user gesture" belongs where the gesture is, not two hops away
 * across a message boundary where one browser's rules already ate it; and the
 * page is where the outcome can be shown to the person who clicked.
 *
 * `permissions.request()` is therefore the FIRST statement in this handler.
 * Awaiting anything before it -- reading state, refreshing the snapshot, a
 * confirmation dialog -- consumes the gesture and puts the defect straight back.
 * The background is told afterwards, and only so that it re-reads the capability
 * from the browser; see the note on that message in background.js.
 */
$('grantHost').addEventListener('click', () => {
  let pending;
  try {
    pending = api.permissions.request({ origins: ['<all_urls>'] });
  } catch (e) {
    // Synchronous throw: the API is not available, or the gesture was already
    // spent. Reported rather than swallowed, because "nothing happened" is what
    // the old code looked like from here.
    pending = Promise.reject(e);
  }
  pending
    .catch((e) => {
      showGrantOutcome(`This browser refused the request: ${describeError(e)}`);
      return false;
    })
    .then(async (granted) => {
      // Sent whatever the request did. The handler re-reads the capability from
      // the browser, which is also the route for a user who granted the
      // permission from the browser's own add-on manager and then pressed this
      // button.
      snapshot = await send({ type: 'hostPermissionChanged' });
      if (granted === false && snapshot && snapshot.canAuthenticate !== true) {
        showGrantOutcome(
          'The permission was not granted, so this proxy extension still cannot present the desktop app’s key. Your chosen sites will be blocked rather than sent unprotected.',
        );
      }
      render();
    });
});

function showGrantOutcome(text) {
  const el = $('grantOutcome');
  if (!el) return;
  el.hidden = false;
  el.textContent = text;
}

function describeError(e) {
  if (!e) return 'no reason given';
  return String(e && e.message ? e.message : e).slice(0, 160);
}

function renderPairing() {
  const unavailable = snapshot.routingSurface && snapshot.routingSurface.ok === false;
  $('pairingHeading').hidden = unavailable;
  $('pairingCard').hidden = unavailable;
  if (unavailable) return;
  const pairing = snapshot.pairing || {};
  $('pairingStatus').textContent = pairing.status === 'paired'
    ? 'This browser is paired with the Win’s VPN app and can connect and disconnect the desktop VPN.'
    : pairing.stored
    ? 'This browser holds a pairing, but the Win’s VPN app is not answering right now.'
    : 'This browser is not paired. It shows the desktop app’s status only.';
  $('forgetPairing').disabled = !pairing.stored;
  $('pairingNote').textContent = 'Forgetting removes the pairing from this browser and asks the app to forget it too. '
    + 'The app’s own list of paired browsers can revoke it as well.';
}

$('forgetPairing').addEventListener('click', async () => {
  snapshot = await send({ type: 'forgetPairing' });
  render();
});

$('panic').addEventListener('click', async () => {
  snapshot = await send({ type: 'panicClear' });
  render();
});

renderStatic();
$('copyLocale').addEventListener('change', async () => {
  const choice = $('copyLocale').value;
  copyLocaleChoice = choice === 'en' || choice === 'my' ? choice : null;
  if (copyLocaleChoice) await api.storage.local.set({ [COPY_LOCALE_CHOICE_KEY]: copyLocaleChoice });
  else await api.storage.local.remove(COPY_LOCALE_CHOICE_KEY);
  render();
});

refresh();
