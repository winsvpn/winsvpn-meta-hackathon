import { api, isSafariRuntime } from '../adapters/index.js';
import {
  BLOCK_EXPLANATION,
  BLOCK_LAYER_FAILED_EXPLANATION,
  DNS_NOTE_ROUTED,
  INCOGNITO_COVERED_NOTE,
  INCOGNITO_NOT_COVERED,
  SCOPE_NOTE,
  WEBRTC_APPLIED,
  WEBRTC_NOT_APPLIED,
  WEBRTC_UNSUPPORTED,
  stateCopy,
  winnNote,
} from '../core/copy.js';
import { MODE_LISTED, normaliseRule, ruleMatches } from '../core/rules.js';
import { PAIRING_REFRESH_MS, STATE } from '../core/constants.js';

import { COPY_LOCALE_CHOICE_KEY, displayedCopyLocale } from '../core/locale.js';

let copyLocaleChoice = null;

function renderCopyLocale() {
  document.documentElement.lang = displayedCopyLocale({ choice: copyLocaleChoice, uiLocale: snapshot?.uiLocale });
}

const $ = (id) => document.getElementById(id);

let snapshot = null;
let activeHost = null;
const safariRuntime = isSafariRuntime();
if (safariRuntime) document.title = "Win's VPN Proxy";

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
  $('stateHeadline').textContent = 'Not routing: this proxy extension could not start';
  $('stateDetail').textContent = error ? String(error).slice(0, 200) : '';
  for (const id of ['toggle', 'siteAction', 'vpnAction']) $(id).disabled = true;
  activeHost = null;
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
  if (!snapshot.routingSurface || snapshot.routingSurface.ok !== false) {
    await readActiveTabHost();
  } else {
    activeHost = null;
  }
  render();
}

/**
 * activeTab, not tabs. The address of the current tab is read only while the
 * popup the user just opened is on screen, and it is never stored.
 */
async function readActiveTabHost() {
  activeHost = null;
  try {
    const tabs = await api.tabs.query({ active: true, currentWindow: true });
    const url = tabs && tabs[0] && tabs[0].url;
    if (!url) return;
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
    const n = normaliseRule(u.hostname);
    if (n.ok) activeHost = n.rule;
  } catch {
    /* no access to this tab; the popup simply does not offer the shortcut */
  }
}

function render() {
  if (!validSnapshot(snapshot)) {
    showInitializationFailure(snapshot);
    return;
  }
  renderCopyLocale();
  const copy = stateCopy(snapshot.state);

  $('stateCard').className = `card ${copy.tone}`;
  $('stateHeadline').textContent = copy.headline;

  // The explanation of WHY a block is happening must not be shown when no block
  // is happening. NOT_ENFORCING is the state where the mechanism did not start,
  // so it gets the sentence that says so instead of the one that reassures.
  let detail = copy.detail;
  if (snapshot.state === STATE.NO_ROUTING_SURFACE && snapshot.detail) {
    detail += ` ${snapshot.detail}`;
  }
  if (snapshot.state === STATE.NOT_ENFORCING) {
    detail += ` ${BLOCK_LAYER_FAILED_EXPLANATION}`;
  } else if (
    snapshot.state !== STATE.OFF
    && snapshot.state !== STATE.PROTECTED
    && snapshot.state !== STATE.NO_ROUTING_SURFACE
    && snapshot.state !== STATE.PRIVACY_FAILED
  ) {
    detail += ` ${BLOCK_EXPLANATION}`;
  }
  $('stateDetail').textContent = detail;
  $('stateAction').textContent = copy.action;

  const armed = snapshot.settings.armed;
  const unavailable = snapshot.routingSurface && snapshot.routingSurface.ok === false;
  $('toggle').textContent = unavailable
    ? 'Use standalone app'
    : armed
    ? 'Turn off proxy routing'
    : 'Turn on proxy routing';
  $('toggle').className = unavailable || armed ? '' : 'primary';
  $('toggle').disabled = unavailable;
  $('siteAction').disabled = unavailable;

  $('scopeNote').textContent = unavailable
    ? 'Safari routing is controlled in the standalone app. Browser per-site rules do not apply.'
    : SCOPE_NOTE;

  // The DNS statement is about a mechanism this extension can see: routing
  // through an HTTP CONNECT proxy means the browser hands over a name rather
  // than resolving it. It is not a claim about what the desktop app does with
  // that name afterwards, which the extension has no way to observe.
  $('dnsNote').textContent = snapshot.state === STATE.PROTECTED ? DNS_NOTE_ROUTED : '';

  const webrtc = snapshot.privacy && snapshot.privacy.webrtc;
  $('webrtcNote').textContent =
    snapshot.state !== STATE.PROTECTED
      ? ''
      : webrtc === 'applied'
      ? WEBRTC_APPLIED
      : webrtc === 'unsupported'
      ? WEBRTC_UNSUPPORTED
      : WEBRTC_NOT_APPLIED;

  $('incognitoNote').textContent = !unavailable && armed
    ? snapshot.incognitoAllowed === null
      ? 'Private-window permission could not be verified.'
      : snapshot.incognitoAllowed && snapshot.incognitoRouting?.ok !== false
      ? INCOGNITO_COVERED_NOTE
      : INCOGNITO_NOT_COVERED
    : '';

  // Repeated from the desktop app, never synthesised. The extension has no view
  // of the wire, and in particular never claims Winn Protocol v3, which does
  // not run on macOS or Windows at all, so on those platforms the desktop app
  // is carrying its ordinary tunnel and this line says so.
  $('tunnelNote').textContent = snapshot.state === STATE.PROTECTED ? winnNote(snapshot.winn) : '';

  const err = $('errNote');
  if (snapshot.lastError) {
    err.hidden = false;
    err.textContent = snapshot.lastError;
  } else {
    err.hidden = true;
  }

  renderSiteShortcut();
  renderVpnControl();
}

// -- desktop VPN control (R20 A1) -------------------------------------------

let pairingRefresh = null;

function formatCode(code) {
  return typeof code === 'string' && code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : '';
}

/**
 * Connect and disconnect, for a browser the desktop app has paired. The
 * popup never decides that on its own: `pairing.status` is the app's answer
 * for the credential this browser presented. An unpaired browser's button
 * asks the app to approve it, and the code shown here is the one the app
 * shows, so the user approves this browser and nothing else.
 */
function renderVpnControl() {
  const card = $('vpnCard');
  const pairing = snapshot.pairing || {};
  const tunnel = snapshot.tunnelStatus;
  const unavailable = snapshot.routingSurface && snapshot.routingSurface.ok === false;
  const flow = pairing.flow || '';
  if (unavailable || !tunnel || tunnel === 'app_not_running' || pairing.status === 'unsupported') {
    card.hidden = true;
    stopPairingRefresh();
    return;
  }
  card.hidden = false;
  const connected = tunnel === 'connected';
  const moving = tunnel === 'connecting' || tunnel === 'disconnecting';
  const action = $('vpnAction');
  const code = $('vpnCode');
  code.hidden = true;
  code.textContent = '';
  action.dataset.connect = connected ? '0' : '1';
  action.textContent = connected ? 'Disconnect VPN' : 'Connect VPN';
  action.className = '';
  action.disabled = moving;

  if (flow === 'pending' && pairing.status !== 'paired') {
    $('vpnHeadline').textContent = 'Approve this browser in the Win’s VPN app';
    code.hidden = false;
    code.textContent = formatCode(pairing.code);
    $('vpnDetail').textContent = 'Open Win’s VPN on this computer. Press Allow only if it shows this same code.';
    action.disabled = true;
    action.textContent = 'Waiting for the app…';
    startPairingRefresh();
    return;
  }
  stopPairingRefresh();

  if (pairing.status === 'paired') {
    $('vpnHeadline').textContent = connected ? 'The desktop VPN is connected' : 'The desktop VPN is not connected';
    if (!snapshot.canRequestConnect) {
      $('vpnDetail').textContent = 'The Win’s VPN app is locked or signed out. Open it to connect or disconnect.';
      action.disabled = true;
    } else {
      $('vpnDetail').textContent = connected
        ? 'Disconnecting turns off VPN protection and the kill switch for this whole computer, not only this browser.'
        : 'This browser is paired with the Win’s VPN app.';
    }
    action.className = connected ? '' : 'primary';
    return;
  }

  $('vpnHeadline').textContent = 'Control the desktop VPN from this browser';
  switch (flow) {
    case 'denied':
    case 'expired':
      $('vpnDetail').textContent = 'The Win’s VPN app did not approve this browser. Try again, and press Allow in the app if the codes match.';
      break;
    case 'busy':
      $('vpnDetail').textContent = 'Another approval is already waiting in the Win’s VPN app, or requests came too fast. If you did not start it, press Deny there, then try again.';
      break;
    case 'unavailable':
      $('vpnDetail').textContent = 'Open and unlock the Win’s VPN app, then try again.';
      break;
    default:
      $('vpnDetail').textContent = 'The first time, the Win’s VPN app asks you to approve this browser. Until then this browser only shows the status.';
  }
}

function startPairingRefresh() {
  if (pairingRefresh) return;
  pairingRefresh = setInterval(() => { refresh(); }, PAIRING_REFRESH_MS);
}

function stopPairingRefresh() {
  if (!pairingRefresh) return;
  clearInterval(pairingRefresh);
  pairingRefresh = null;
}

$('vpnAction').addEventListener('click', async () => {
  if (!validSnapshot(snapshot)) return;
  $('vpnAction').disabled = true;
  const next = await send({ type: 'requestTunnel', connect: $('vpnAction').dataset.connect === '1' });
  if (!validSnapshot(next)) return;
  snapshot = next;
  await refresh();
});

function renderSiteShortcut() {
  const card = $('siteCard');
  if (!activeHost || (snapshot.routingSurface && snapshot.routingSurface.ok === false)) {
    card.hidden = true;
    return;
  }
  card.hidden = false;
  const listed = snapshot.settings.mode === MODE_LISTED;
  const list = listed ? snapshot.settings.listed : snapshot.settings.excluded;
  const present = list.some((r) => ruleMatches(r, activeHost));

  if (listed) {
    $('siteLabel').textContent = present
      ? `${activeHost} is on your list, so it goes through the tunnel.`
      : `${activeHost} is not on your list, so it is sent normally.`;
    $('siteAction').textContent = present ? 'Take it off the list' : 'Add it to the list';
  } else {
    $('siteLabel').textContent = present
      ? `${activeHost} is outside the tunnel, so it is sent normally.`
      : `${activeHost} goes through the tunnel with everything else.`;
    $('siteAction').textContent = present ? 'Put it back in the tunnel' : 'Leave it outside the tunnel';
  }
  $('siteAction').dataset.present = present ? '1' : '0';
}

$('toggle').addEventListener('click', async () => {
  if (!validSnapshot(snapshot)) return;
  if (snapshot.routingSurface && snapshot.routingSurface.ok === false) return;
  $('toggle').disabled = true;
  snapshot = await send({
    type: 'setSettings',
    settings: { ...snapshot.settings, armed: !snapshot.settings.armed },
  });
  if (!validSnapshot(snapshot)) return;
  $('toggle').disabled = false;
  await refresh();
});

$('openOptions').addEventListener('click', () => {
  api.runtime.openOptionsPage();
});

$('siteAction').addEventListener('click', async () => {
  if (!validSnapshot(snapshot) || !activeHost) return;
  const listed = snapshot.settings.mode === MODE_LISTED;
  const key = listed ? 'listed' : 'excluded';
  const present = $('siteAction').dataset.present === '1';
  const next = present
    ? snapshot.settings[key].filter((r) => !ruleMatches(r, activeHost))
    : [...snapshot.settings[key], activeHost];
  snapshot = await send({ type: 'setSettings', settings: { ...snapshot.settings, [key]: next } });
  await refresh();
});

refresh();
