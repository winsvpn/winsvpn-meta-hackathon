// Every user-visible string, in one file, so the honesty rules can be tested.
//
// House rules, taken from the two app lanes that had to correct overclaiming
// copy -- the antivirus verdict vocabulary that implied a scan the engine could
// not perform, and the transport preference whose promise the node picker broke:
//
//  1. Lead with the state. Never open with a phrase that reads as good news and
//     then take it back; a stressed reader keeps the first clause.
//  2. The qualification goes on a second line and the instruction on a third. A
//     short status label cannot carry the caveat, so it is not asked to.
//  3. The cost is on screen in the same breath as the benefit. Not a tooltip,
//     not an expander, not a dialog after the fact.
//  4. Name the concrete thing -- the list, the desktop app, the setting -- not a
//     property of the user's network or a claim about their safety.
//  5. Never assert protection this extension cannot verify. It can verify that
//     it installed a proxy setting and that the desktop app reported a connected
//     tunnel. It cannot verify that any byte was encrypted, and it says so.
//  6. When copy and code disagree and the copy is a safety claim, the code gets
//     fixed. Softening the words is the fallback, not the default.
//
// Enforced by tools/checks.py, which asserts both the absence of overclaiming
// phrases and the presence of the qualifications, with a negation-aware matcher
// so that deleting a disclaimer is not the cheapest way to pass.

import { STATE } from './constants.js';
import { WINN_STATE } from './protocol.js';

export const WHAT_THIS_IS = {
  title: "Win's VPN Proxy",
  body: [
    'Win’s VPN Proxy is a browser add-on for the Win’s VPN desktop app. It sends the HTTPS sites you choose through the tunnel the desktop app has already opened.',
    'It carries HTTPS connections only. A routed site opened over plain HTTP is refused on this computer, does not leave through the proxy, and will not load.',
    'The desktop app and browser bridge must be installed first. It is not a VPN on its own. It cannot open a tunnel, it does not encrypt anything, and it does nothing at all unless the desktop app is running and connected.',
    'It only affects this browser. Other programs on this computer are not changed by it.',
  ],
};

export const SAFARI_WHAT_THIS_IS = {
  title: 'Safari Proxy uses its standalone app',
  body: [
    'On macOS, open the standalone Safari Proxy app to connect or disconnect. It embeds the v3 engine and routes intercepted Safari connections without the full VPN app. Its protected DNS provider affects system DNS while enabled.',
    'This browser panel does not route or block Safari traffic. It reports authenticated native readiness, and its per-site rules do not apply to the native proxy.',
    'The iOS app contains the Safari extension only and does not route traffic. A standalone v3 packet tunnel needs a user-approved VPN configuration.',
  ],
};

export const SCOPE_NOTE =
  'HTTPS sites you route through the tunnel are carried by the desktop app’s connection. A routed site opened over plain HTTP is refused on this computer and will not load. Sites you do not route are sent normally, and their names are looked up normally: your network can see them.';

// The DNS position, stated as what is known rather than as a promise.
export const DNS_NOTE_ROUTED =
  'For routed HTTPS sites, this browser hands the website name to the desktop app instead of looking it up here, so the lookup does not go to your network’s name server.';
export const DNS_NOTE_UNROUTED =
  'Sites you have not routed are looked up on this network as usual, before any connection is made.';

export const STATE_COPY = {
  [STATE.OFF]: {
    headline: 'Off',
    detail: 'This browser is set up normally. Nothing is being sent through the desktop app.',
    action: 'Turn on proxy routing to start sending your chosen sites through the tunnel.',
    tone: 'neutral',
  },
  [STATE.NO_ROUTING_SURFACE]: {
    headline: 'Routing is controlled outside this browser panel',
    detail:
      'This browser panel does not control routing and is not blocking browser traffic.',
    action:
      'For Safari, use the standalone Safari Proxy app. Browser routing controls and per-site rules stay disabled.',
    tone: 'neutral',
  },
  [STATE.PROTECTED]: {
    headline: 'Routing through the desktop app',
    detail:
      'The desktop app reports its tunnel is up and its local proxy is admitting traffic, and this browser is set to send your chosen HTTPS sites to it. The proxy carries HTTPS connections only; a routed site opened over plain HTTP is refused on this computer and will not load.',
    action: 'What the tunnel itself protects is decided by the desktop app, not by this add-on.',
    tone: 'good',
  },
  [STATE.NO_HOST]: {
    headline: 'Not routing: cannot reach the desktop app',
    detail:
      'This proxy extension cannot reach the Win’s VPN desktop app at all. Your chosen sites are being blocked, not sent unprotected.',
    action: 'Install and start the Win’s VPN desktop app. If it is already running, install or reinstall its browser bridge.',
    tone: 'blocked',
  },
  // THE BRIDGE WAS STARTED AND HAS NEVER SAID ANYTHING.
  //
  // The words have to survive a reader who is not going to run `ps`, and they
  // have to be TRUE of every way this happens rather than only of the one that
  // was measured. What is certainly true: the browser started something and it
  // has not answered. What is very often true on macOS, and is the reason this
  // state exists at all, is that the bridge is installed somewhere this browser
  // is not allowed to read -- the Documents, Desktop and Downloads folders,
  // which the system protects per-application. That is named as the likely
  // cause and not asserted as the cause, because the extension cannot see the
  // filesystem and must not claim to.
  //
  // The remedy is the desktop app's installer, not anything the reader can do
  // in this browser, so the action says so plainly instead of offering a
  // toggle that will not help.
  [STATE.HOST_NOT_ANSWERING]: {
    headline: 'Not routing: the bridge was started but never answered',
    detail:
      'This browser started the Win’s VPN browser bridge and it has not replied at all, and the browser reported no error. On macOS this is usually a bridge installed in a folder this browser is not permitted to read, such as Documents, Desktop or Downloads. Your chosen sites are being blocked, not sent unprotected.',
    action:
      'Reinstall the browser bridge from the Win’s VPN desktop app so it is installed where this browser can run it. Restarting the browser on its own will not change this.',
    tone: 'alarm',
  },

  [STATE.APP_NOT_RUNNING]: {
    headline: 'Not routing: Win’s VPN is not running',
    detail:
      'The bridge is installed but the Win’s VPN app is not running, so there is nothing to connect through. Your chosen sites are being blocked, not sent unprotected.',
    action: 'Open Win’s VPN.',
    tone: 'blocked',
  },
  [STATE.APP_DOWN]: {
    headline: 'Not routing: the tunnel is not connected',
    detail:
      'Win’s VPN is running but its tunnel is not up. Your chosen sites are being blocked, not sent unprotected.',
    action: 'Connect in the Win’s VPN app.',
    tone: 'blocked',
  },
  [STATE.PERMISSION_REQUIRED]: {
    headline: 'Not routing: Win’s VPN needs permission from this computer',
    detail:
      'The system has not granted Win’s VPN permission to create a tunnel. This proxy extension cannot grant it. Your chosen sites are being blocked, not sent unprotected.',
    action: 'Open Win’s VPN and allow the connection when the system asks.',
    tone: 'blocked',
  },
  [STATE.NOT_READY]: {
    headline: 'Not routing: the desktop app is not accepting traffic yet',
    detail:
      'The tunnel is reported up, but the desktop app’s own gate is still shut. Your chosen sites are being blocked, not sent unprotected.',
    action: 'Wait a moment. If it does not clear, reconnect in the Win’s VPN app.',
    tone: 'blocked',
  },
  [STATE.NO_CREDENTIAL]: {
    headline: 'Not routing: no key for this session yet',
    detail:
      'The desktop app gives this browser a one-time key each session so that no other program on this computer can use the tunnel. This browser does not have one right now. Your chosen sites are being blocked, not sent unprotected.',
    action: 'This usually clears on its own. If it does not, turn routing off and on again.',
    tone: 'blocked',
  },
  [STATE.STALE]: {
    headline: 'Not routing: no recent word from the desktop app',
    detail:
      'The desktop app has not reported its state recently enough to rely on. Your chosen sites are being blocked, not sent unprotected.',
    action: 'Check that the Win’s VPN app is still running.',
    tone: 'blocked',
  },
  [STATE.BAD_ENDPOINT]: {
    headline: 'Not routing: refused where the desktop app pointed',
    detail:
      'The desktop app pointed this browser somewhere other than this computer. This proxy extension only ever sends traffic to this computer, so it refused. Your chosen sites are being blocked, not sent unprotected.',
    action: 'Reinstall the Win’s VPN app. Do not turn this off to get around it.',
    tone: 'alarm',
  },
  [STATE.NOT_IN_CONTROL]: {
    headline: 'Not routing: another add-on controls this browser’s connection settings',
    detail:
      'Another extension has priority over the proxy setting this extension needs, so it cannot route anything while that is true. Your chosen sites are being blocked, not sent unprotected.',
    action: 'Remove or disable the other extension that changes proxy settings, then turn this on again.',
    tone: 'alarm',
  },
  [STATE.PROXY_NOT_CONTROLLABLE]: {
    headline: 'Not routing: this browser does not allow extension control of its proxy settings',
    detail:
      'This browser reports that extensions are not allowed to change its proxy settings. This is often set by whoever manages the computer. Your chosen sites are being blocked, not sent unprotected.',
    action:
      'Use the Win’s VPN desktop app on its own, or ask whoever manages this computer whether extensions may control the browser proxy.',
    tone: 'alarm',
  },
  [STATE.NO_AUTH_CAPABILITY]: {
    headline: 'Not routing: this browser cannot prove who it is to the desktop app',
    detail:
      'The desktop app asks for a key before it will carry anything, and this browser has not been given permission to answer. Your chosen sites are being blocked, not sent unprotected.',
    action: 'Open “Sites & settings” and grant the permission it asks for there.',
    tone: 'alarm',
  },

  // THE STATE THAT MUST NOT BORROW THE PROMISE.
  //
  // Every other entry above ends with "Your chosen sites are being blocked, not
  // sent unprotected", and that sentence is true in those states because one
  // mechanism keeps it. This is the state that exists for when the mechanism is
  // not there, so the sentence is absent here: and its absence is asserted by
  // tools/checks.py rather than left to whoever edits this file next. Deleting
  // this entry does not soften the problem either: without it, stateCopy() falls
  // back to the STALE entry, which promises the block. That fallback is what
  // makes a missing entry a lie rather than a gap, and it is why the checker
  // requires every state to have copy of its own.
  [STATE.NOT_ENFORCING]: {
    headline: 'Not routing: and not blocking either',
    detail:
      'This browser would not accept the rules that stop your chosen sites being sent over your ordinary connection, so they are not being stopped. They are not being sent through the tunnel either. Anything you open here may go out the way it normally would, and this proxy extension cannot prevent it.',
    action:
      'Turn this proxy extension off and use the Win’s VPN desktop app on its own until this clears. Do not rely on this browser for anything you would not send over your ordinary connection.',
    tone: 'alarm',
  },

  [STATE.PRIVACY_FAILED]: {
    headline: 'Not routing: browser privacy settings were refused',
    detail: 'Your chosen web requests are blocked. Video and voice connections may still open directly and reveal this computer’s address because this browser refused its privacy settings.',
    action: 'Close sensitive tabs and use the desktop app until this failure clears.',
    tone: 'alarm',
  },

  [STATE.ROUTING_FAILED]: {
    headline: 'Not routing: this browser refused the setting',
    detail:
      'This proxy extension asked this browser to send your chosen sites to the Win’s VPN desktop app, and the browser refused the request. Your chosen sites are being blocked, not sent unprotected.',
    action:
      'Turn routing off and on again. If it keeps happening, open this extension’s entry in the browser’s add-on settings. Firefox refuses its browser-wide proxy setting until the extension is allowed in private windows.',
    tone: 'alarm',
  },

  [STATE.ROUTING_UNAUTHENTICATED]: {
    headline: 'Not routing: the key never reached the desktop app',
    detail:
      'The desktop app will not carry anything from a browser that cannot present its one-time key, and this browser sent requests to it without one. Your chosen sites are being blocked, not sent unprotected.',
    action: 'Turn routing off and on again. If it keeps happening, restart the Win’s VPN desktop app.',
    tone: 'alarm',
  },
};

export const BLOCK_EXPLANATION =
  'Blocking is deliberate. The alternative is to send the page over your normal connection while this proxy extension is switched on, which would look protected and would not be.';

// The counterpart, for the one state where the sentence above would be false.
// It is a separate string rather than a softened version of the same one,
// because the two describe opposite situations and a reader who has learned what
// the first means must not be shown it when the second is true.
export const BLOCK_LAYER_FAILED_EXPLANATION =
  'This is not a deliberate block. The part of this proxy extension that stops pages being sent over your normal connection did not start, so there is nothing stopping them.';

export const INCOGNITO_NOT_COVERED =
  'Private windows are not covered. This proxy extension has not been allowed to run in private windows, so pages opened there are sent normally.';
export const INCOGNITO_COVERED_NOTE =
  'Private windows use the same routing as normal windows.';

export const WEBRTC_APPLIED =
  'Video and voice calls in this browser are stopped from opening their own direct connections, which would otherwise reveal this computer’s address.';
export const WEBRTC_NOT_APPLIED =
  'This browser did not accept the setting that stops video and voice calls opening their own direct connections. Such a call could reveal this computer’s address.';
export const WEBRTC_UNSUPPORTED =
  'This browser does not offer the setting that stops video and voice calls opening their own direct connections. Avoid video and voice calls in this browser while routing.';

export const STORAGE_NOTE =
  'The site list you type here is saved in this browser’s profile and can be read by anyone who has this computer. If you pair this browser with the desktop app, the pairing is saved there too: it lets this browser ask the app to connect or disconnect, and nothing more. Nothing else is saved: no account details, no record of which sites you visited, and no server addresses. The key the desktop app issues for routing is held in memory only and is gone when this browser closes.';

export const MODE_ALL_LABEL = 'All HTTPS sites through the tunnel';
export const MODE_ALL_COST =
  'Every HTTPS site in this browser goes through the desktop app. Plain HTTP sites in scope are refused locally and will not load. If the desktop app is not connected, nothing in this browser will load.';
export const MODE_LISTED_LABEL = 'Only the sites I list';
export const MODE_LISTED_COST =
  'Only HTTPS sites on your list go through the tunnel. Every other site is sent normally, over your ordinary connection. A listed site opened over plain HTTP is refused locally and will not load.';

export const PANIC_CLEAR_LABEL = 'Erase the site list';
export const PANIC_CLEAR_COST =
  'Removes the list, and any pairing with the desktop app, from this browser’s profile and turns routing off. This cannot be undone.';

/** Edge-specific explanation for the Chromium proxy-control observation. */
export function edgeProxyControlNote(levelOfControl, browser) {
  if (browser !== 'edge') return '';
  if (levelOfControl === 'not_controllable') {
    return 'Microsoft Edge reports that extensions are not allowed to change its proxy settings. On a managed profile, this is often set by your organization. Win’s VPN Proxy will not try to override it.';
  }
  if (levelOfControl === 'controlled_by_other_extensions') {
    return 'Microsoft Edge reports that another extension currently controls its proxy settings.';
  }
  return '';
}

/**
 * What the desktop app is carrying, in the app's own words.
 *
 * The extension has no view of the wire and does not guess. In particular it
 * never claims Winn Protocol v3: the desktop capability gate is absent on
 * macOS, Windows and iOS, so on those platforms the tunnel is plain AmneziaWG
 * and there is no vocabulary here that could say otherwise.
 */
export function winnNote(winn) {
  switch (winn) {
    case WINN_STATE.IN_USE:
      return 'The desktop app reports this session is carrying Winn Protocol v3.';
    case WINN_STATE.AVAILABLE_NOT_IN_USE:
      return 'The desktop app reports this session is not using Winn Protocol v3.';
    case WINN_STATE.UNAVAILABLE_ON_THIS_PLATFORM:
      return 'Winn Protocol v3 does not run on this operating system. The desktop app is carrying its ordinary tunnel.';
    default:
      return '';
  }
}

export function stateCopy(state) {
  return STATE_COPY[state] || STATE_COPY[STATE.STALE];
}
