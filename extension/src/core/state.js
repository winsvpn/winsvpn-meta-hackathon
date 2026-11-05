// The state machine.
//
// One pure function decides what state the extension is in. Behaviour (proxy
// settings, block rules) and words (the popup) are both derived from its
// output, so the browser can never be doing one thing while the popup says
// another. That coupling is deliberate: the failure this project keeps finding
// is copy that outlives the code it described.
//
// There is exactly one path to PROTECTED and it requires five independent facts
// to agree: the user armed it, the bridge is connected, the status is fresh, the
// desktop app says both `connected` AND `proxyReady`, and this extension holds a
// credential and a way to present it. Every other combination is fail-closed.
// Firefox previously required a sixth fact (the bridge serving TLS for
// proxyAuthorizationHeader), but that was removed with the certificate design per
// ruling 2026-08-07; Firefox now authenticates via webRequest over plaintext.
//
// -----------------------------------------------------------------------------
// WHY THAT WAS NOT ENOUGH, AND WHAT THE SECOND HALF OF THIS FILE IS FOR
// -----------------------------------------------------------------------------
//
// The first live Firefox run found the extension in PROTECTED, saying so, while
// it routed nothing and blocked nothing. Every one of those five facts was true.
// The browser had discarded the entire block rule set over two enum values it
// did not recognise, and it never sent the proxy credential -- and neither
// failure had any way to reach this function. `applyBlockRules` caught its error
// into a string field nobody read; `applyRouting` could reject and the snapshot
// would still say PROTECTED, because `this.current` had already been assigned.
//
// The lesson is not "add two more facts". It is that the five facts above are
// all about what the extension ASKED THE BROWSER FOR, and a state derived only
// from requests cannot notice a browser that accepted the request and did
// nothing. So the checks below are of a different kind: they are what the
// browser DID, reported by the component that watched it do it. A component that
// fails must reach the state machine, or the state machine is describing an
// intention rather than a system.
//
// The order matters. The enforcement checks run AFTER the ladder, not instead of
// it, so the underlying situation is still computed and still carried in
// `detail` -- a user whose desktop app is not running and whose block layer also
// failed needs to be told the second thing, but a diagnosing engineer needs both.

import {
  STATE,
  STATUS_TTL_MS,
  HOST_HANDSHAKE_TTL_MS,
  isFailClosedState,
  ENFORCEMENT_FAILURE_STATES,
} from './constants.js';
import { TUNNEL_STATUS, isCarryingTraffic } from './protocol.js';
import { validateEndpoint } from './endpoint.js';

/**
 * @param {object} input
 * @param {boolean} input.armed
 * @param {boolean} input.hostConnected
 * @param {boolean} input.hostSpoke
 * @param {number} input.hostOpenedAtMs
 * @param {object|null} input.status
 * @param {number} input.statusAtMs
 * @param {number} input.nowMs
 * @param {string} input.levelOfControl
 * @param {object|null} input.credential  {endpoint, token} held in memory only
 * @param {boolean} input.canAuthenticate
 * @param {{ok: boolean, reason: string}|null} input.routingSurface
 * @param {object|null} input.blockLayer
 * @param {object|null} input.routing
 * @param {object|null} input.authStats
 * @returns {{state: string, endpoint: object|null, detail: string, failClosed: boolean}}
 */
export function deriveState(input) {
  const { armed, blockLayer, routing, authStats } = input;

  const surface = normaliseRoutingSurface(input.routingSurface);
  if (!surface.ok) {
    return mk(STATE.NO_ROUTING_SURFACE, null, trim(surface.reason));
  }
  if (!armed) return mk(STATE.OFF, null, '');

  const intended = deriveIntended(input);

  // ---- what the browser actually did with what it was handed ---------------

  // THE BLOCK LAYER, FIRST AND FOR EVERY STATE.
  //
  // Every fail-closed state's copy ends with the same promise -- "Your chosen
  // sites are being blocked, not sent unprotected" -- and that promise is kept
  // by exactly one mechanism. If the mechanism is not installed, the promise is
  // false in every one of those states at once, so the check cannot live inside
  // any single branch of the ladder above.
  //
  // It applies to PROTECTED too, and that is not belt-and-braces: PROTECTED
  // includes the assurance that when routing stops working the traffic stops
  // with it. An extension that knows its fail-closed mechanism is unavailable
  // is an extension that cannot make that assurance.
  const block = blockLayer || {};
  if (block.ok === false) {
    // The situation underneath includes the routing and authentication checks
    // below. The ladder alone reads PROTECTED while routing has failed, for
    // example when the private-window permission could not be verified.
    const underneath = deriveState({ ...input, blockLayer: null });
    const reason = underneath.state === intended.state ? '' : `: ${underneath.detail}`;
    return mk(
      STATE.NOT_ENFORCING,
      null,
      `the block rules did not install: ${trim(block.error)}; ` +
        `the situation underneath is ${underneath.state}${reason}`,
    );
  }

  if (intended.state !== STATE.PROTECTED) return intended;

  // ROUTING. `applyRouting` can reject -- Firefox refuses `proxy.settings`
  // outright unless the add-on is allowed in private windows, and a rejected
  // promise used to propagate past an already-assigned PROTECTED and be
  // swallowed by the caller's `.catch`.
  const route = routing || {};
  if (route.ok === false) {
    return mk(STATE.ROUTING_FAILED, null, trim(route.error));
  }
  if (
    route.ok === true &&
    input.levelOfControl !== 'controlled_by_this_extension'
  ) {
    return mk(
      STATE.ROUTING_FAILED,
      null,
      `proxy control changed to ${trim(input.levelOfControl)}`,
    );
  }

  // AUTHENTICATION, counted rather than assumed. Answering a challenge proves
  // only that credentials were sent. A repeated challenge with the same browser
  // request id proves that those credentials were rejected; a cancelled local
  // proxy challenge proves that no credential was available.
  if (isUnauthenticatedRouting(authStats)) {
    const rejected = Number(authStats.credentialsRejected) || 0;
    const missing = Number(authStats.credentialsMissing) || 0;
    return mk(
      STATE.ROUTING_UNAUTHENTICATED,
      null,
      `${rejected} credential rejection(s) and ${missing} missing-credential request(s) ` +
        'were observed at the desktop proxy',
    );
  }

  return intended;
}

export function normaliseRoutingSurface(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { ok: false, reason: 'the browser adapter did not report a routing capability' };
  }
  if (value.ok === true) return { ok: true, reason: '' };
  const reason = value.reason === undefined || value.reason === null
    ? 'no routing capability was reported'
    : String(value.reason).slice(0, 200);
  return { ok: false, reason };
}

/**
 * The situation as the extension's own inputs describe it, before anything is
 * checked about what the browser did with them. Unchanged from the original
 * ladder; every early return here is a way this kind of tool has been observed
 * to claim protection it did not have.
 */
function deriveIntended(input) {
  const {
    hostConnected, hostSpoke, hostOpenedAtMs, status, statusAtMs, nowMs,
    levelOfControl, credential, canAuthenticate,
  } = input;

  // Someone else owns the proxy setting. A browser resolves this by precedence,
  // so a losing extension can call set() successfully and still not control a
  // single request. Reporting "protected" here would be exactly the class of
  // lie this extension is built not to tell.
  if (levelOfControl === 'controlled_by_other_extensions') {
    return mk(STATE.NOT_IN_CONTROL, null, levelOfControl);
  }
  if (levelOfControl === 'not_controllable') {
    return mk(STATE.PROXY_NOT_CONTROLLABLE, null, levelOfControl);
  }

  if (!hostConnected) return mk(STATE.NO_HOST, null, '');

  // A PORT THAT OPENED AND NEVER CARRIED A SINGLE MESSAGE.
  //
  // `hostSpoke` is not `status !== null`: it is true the moment ANY frame
  // arrives on this port, parseable or not. That distinction is the point. A
  // bridge sending nonsense is a bridge that is running and is reported as
  // such (the controller's `lastError` carries what was wrong with it); a
  // bridge that has sent nothing at all has not started, and no component
  // anywhere in the browser will say so, because from the browser's side
  // nothing failed.
  //
  // So the silence is measured here and named, rather than being allowed to
  // age into STALE -- whose copy sends the reader to check an app that may well
  // be running perfectly, and whose `lastError` on this path was the empty
  // string, which is the diagnostic equivalent of a shrug.
  const silentFor = hostOpenedAtMs ? nowMs - hostOpenedAtMs : 0;
  if (!hostSpoke && silentFor > HOST_HANDSHAKE_TTL_MS) {
    return mk(
      STATE.HOST_NOT_ANSWERING,
      null,
      `the browser opened the bridge ${Math.round(silentFor / 1000)}s ago and it has ` +
        'not answered once, and the browser reported no error',
    );
  }

  if (!status || !statusAtMs) return mk(STATE.STALE, null, 'no status yet');

  const age = nowMs - statusAtMs;
  // Negative ages are stale too. A clock that jumped backwards must not be able
  // to make an old status look fresh.
  if (age > STATUS_TTL_MS || age < -STATUS_TTL_MS) {
    return mk(STATE.STALE, null, `last report ${Math.round(Math.abs(age) / 1000)}s ago`);
  }

  if (status.status === TUNNEL_STATUS.APP_NOT_RUNNING) {
    return mk(STATE.APP_NOT_RUNNING, null, status.detail);
  }
  if (status.status === TUNNEL_STATUS.PERMISSION_REQUIRED) {
    return mk(STATE.PERMISSION_REQUIRED, null, status.detail);
  }
  // `unknown` lands here, and lands as not-connected. It is never rounded up.
  if (!isCarryingTraffic(status.status)) {
    return mk(STATE.APP_DOWN, null, status.status);
  }

  // The tunnel is up but the bridge's own proxy gate is shut. Two independent
  // things have to agree before anything is routed, and this is the case where
  // they do not.
  if (!status.proxyReady) return mk(STATE.NOT_READY, null, 'the desktop proxy is not admitting traffic');

  if (!canAuthenticate) {
    return mk(STATE.NO_AUTH_CAPABILITY, null, 'this browser cannot answer the proxy challenge');
  }
  if (!credential || !credential.token) {
    return mk(STATE.NO_CREDENTIAL, null, 'no proxy credential this session');
  }

  const checked = validateEndpoint(credential.endpoint);
  if (!checked.ok) return mk(STATE.BAD_ENDPOINT, null, checked.reason);

  if (status.proxyPort && status.proxyPort !== checked.endpoint.port) {
    return mk(STATE.NO_CREDENTIAL, null, 'the proxy moved to a different port');
  }

  return mk(STATE.PROTECTED, checked.endpoint, '');
}

/**
 * Both adapters publish the same evidence fields, so this stays
 * browser-agnostic. `credentialsAnswered` is deliberately not read here:
 * answering is not proof that the desktop proxy accepted the credential.
 */
function isUnauthenticatedRouting(authStats) {
  if (!authStats || typeof authStats !== 'object') return false;
  const missing = Number(authStats.credentialsMissing) || 0;
  const rejected = Number(authStats.credentialsRejected) || 0;
  return missing > 0 || rejected > 0;
}

function trim(text) {
  const s = text === undefined || text === null ? '' : String(text);
  return s ? s.slice(0, 200) : 'no reason given';
}

function mk(state, endpoint, detail) {
  return { state, endpoint, detail, failClosed: isFailClosedState(state) };
}

export { STATE, isFailClosedState, ENFORCEMENT_FAILURE_STATES };
