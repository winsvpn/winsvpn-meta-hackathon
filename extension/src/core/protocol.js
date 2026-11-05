// The native-messaging contract with the desktop bridge.
//
// THIS IS THE EXTENSION HALF OF A SHARED SPECIFICATION. The desktop half is
// normative and lives in `lib/browser_bridge_protocol.dart`, with the reasoning
// in `docs/handoff/BROWSER_EXTENSION_NATIVE_MESSAGING_BRIDGE_20260807.md`. Both
// sides carry the version constant; neither may change a shape without bumping
// it.
//
// -----------------------------------------------------------------------------
// WHY AN ADDRESS CANNOT ARRIVE HERE, AS OPPOSED TO MERELY NOT ARRIVING
// -----------------------------------------------------------------------------
//
// The desktop side made an address unrepresentable rather than merely absent:
// `detail` is a closed enum rather than free text, node identifiers are slugs
// whose character class excludes `.` `:` and `/`, integers are bounded below the
// 32 bits a packed IPv4 needs, and the proxy is described BY PORT NUMBER ALONE
// with no host field at all.
//
// That last one is the important one for this file. Because there is no host
// field, this extension supplies `127.0.0.1` itself, from a constant it owns.
// A compromised or replaced bridge cannot point this browser anywhere: not at a
// gateway, not at a collection endpoint, not anywhere but this machine. The
// guarantee is structural, and the validation below preserves it by never
// reading a host from the wire even if a future message tries to offer one.
//
// The extension additionally drops every field it does not understand, so a
// bridge that started sending something new cannot smuggle it into storage or
// onto the screen.

import { LOOPBACK_HOST, PROTOCOL_VERSION } from './constants.js';
import { validatePort } from './endpoint.js';

export const REQUEST = {
  HELLO: 'hello',
  GET_STATUS: 'get_status',
  SUBSCRIBE: 'subscribe',
  UNSUBSCRIBE: 'unsubscribe',
  REQUEST_CONNECT: 'request_connect',
  REQUEST_DISCONNECT: 'request_disconnect',
  ISSUE_PROXY_CREDENTIAL: 'issue_proxy_credential',
  REVOKE_PROXY_CREDENTIAL: 'revoke_proxy_credential',
  // Pairing (R20 A1). Connect and disconnect need the credential the desktop
  // app mints after the user approves this browser in the app.
  PAIR_BEGIN: 'pair_begin',
  SET_PAIRING: 'set_pairing',
  PAIR_FORGET: 'pair_forget',
};

// The app's answer to "is the pairing this browser presented one it knows".
// `unsupported` is this extension's word for a bridge too old to say.
export const PAIRING_STATUS = {
  PAIRED: 'paired',
  UNPAIRED: 'unpaired',
  UNSUPPORTED: 'unsupported',
};

export const PAIRING_FLOW = {
  PENDING: 'pending',
  APPROVED: 'approved',
  DENIED: 'denied',
  EXPIRED: 'expired',
  UNAVAILABLE: 'unavailable',
  BUSY: 'busy',
};

const PAIRING_FLOW_VALUES = new Set(Object.values(PAIRING_FLOW));
export const PAIRING_CREDENTIAL_RE = /^[0-9a-f]{64}$/;
const PAIRING_CODE_RE = /^[0-9]{6}$/;

// Deliberately absent from the vocabulary, on both sides: any request that
// would produce a latency figure attributable to a node. A number the extension
// could attribute to one gateway is an address oracle even with no address in
// it. This is the defect found and fixed in the desktop app on 2026-08-07, where
// the node picker was sending ICMP echo requests to every gateway's real
// address while a user-facing switch promised nothing is ever sent there. It is
// not reintroduced in a place whose source anyone can read.

export const TUNNEL_STATUS = {
  APP_NOT_RUNNING: 'app_not_running',
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  DISCONNECTING: 'disconnecting',
  FAILED: 'failed',
  PERMISSION_REQUIRED: 'permission_required',
  UNKNOWN: 'unknown',
};

const TUNNEL_STATUS_VALUES = new Set(Object.values(TUNNEL_STATUS));

export const WINN_STATE = {
  UNAVAILABLE_ON_THIS_PLATFORM: 'unavailable_on_this_platform',
  AVAILABLE_NOT_IN_USE: 'available_not_in_use',
  IN_USE: 'in_use',
};

const WINN_VALUES = new Set(Object.values(WINN_STATE));

const DETAIL_CODES = new Set([
  'none', 'app_not_running', 'permission_required', 'user_requested',
  'handshake_incomplete', 'data_path_unproven', 'config_rejected',
  'network_unavailable', 'refused_by_app', 'state_unavailable',
]);

const ERROR_CODES = new Set([
  'malformed', 'unsupported_version', 'unknown_request', 'app_not_running',
  'not_permitted', 'rate_limited', 'internal',
]);

// The only status that may result in traffic being routed. Matches
// `BridgeTunnelStatus.isCarryingTraffic` on the desktop side, which is likewise
// a single-value predicate rather than a list of "good enough" states.
export function isCarryingTraffic(status) {
  return status === TUNNEL_STATUS.CONNECTED;
}

// ---------------------------------------------------------------------------
// Outbound
// ---------------------------------------------------------------------------

export function request(id, type, fields = null) {
  return fields ? { ...fields, v: PROTOCOL_VERSION, id, type } : { v: PROTOCOL_VERSION, id, type };
}

// ---------------------------------------------------------------------------
// Inbound
// ---------------------------------------------------------------------------

/**
 * Validate and narrow an inbound message. Anything not understood is discarded
 * whole rather than partially applied.
 * @returns {{ok: true, msg: object} | {ok: false, reason: string}}
 */
export function parseInbound(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, reason: 'not an object' };
  }
  if (raw.v !== PROTOCOL_VERSION) {
    return { ok: false, reason: `protocol version ${describe(raw.v)} is not ${PROTOCOL_VERSION}` };
  }
  const id = typeof raw.id === 'string' ? raw.id.slice(0, 64) : '';

  // The bridge signals refusal with an `error` code; some replies carry
  // type:"error" as well. Either form is treated as an error, because the field
  // that matters is the code.
  if (raw.ok === false || typeof raw.error === 'string' || raw.type === 'error') {
    const code = typeof raw.error === 'string' && ERROR_CODES.has(raw.error) ? raw.error : 'internal';
    return { ok: true, msg: { type: 'error', id, code } };
  }

  switch (raw.type) {
    case 'hello':
      return { ok: true, msg: { type: 'hello', id, status: parseStatus(raw) } };
    case 'status':
      return { ok: true, msg: { type: 'status', id, status: parseStatus(raw) } };
    case 'proxy_credential':
      return parseCredential(raw, id);
    case 'pairing':
      return parsePairing(raw, id);
    default:
      return { ok: false, reason: `unknown type ${describe(raw.type)}` };
  }
}

/**
 * The status snapshot is carried at the top level of the reply, alongside the
 * envelope fields. Every value is narrowed to a known member of its closed set;
 * an unrecognised value becomes `unknown`, which every gate treats as "not
 * connected". Rounding an unknown state up to a good one is the one mistake
 * that would matter here.
 */
function parseStatus(raw) {
  const status = TUNNEL_STATUS_VALUES.has(raw.status) ? raw.status : TUNNEL_STATUS.UNKNOWN;
  const winn = WINN_VALUES.has(raw.winn) ? raw.winn : null;
  const detail = DETAIL_CODES.has(raw.detail) ? raw.detail : 'none';
  return {
    status,
    detail,
    winn,
    canRequestConnect: raw.canRequestConnect === true,
    proxyReady: raw.proxyReady === true,
    proxyPort: validatePort(raw.proxyPort) ? raw.proxyPort : 0,
    uiLocale: raw.ui_locale === 'en' || raw.ui_locale === 'my' ? raw.ui_locale : null,
    selectedSlug: slug(raw.selectedSlug),
    nodes: parseNodes(raw.nodes),
    rxKib: boundedInt(raw.rxKib),
    txKib: boundedInt(raw.txKib),
    pairing: raw.pairing === PAIRING_STATUS.PAIRED || raw.pairing === PAIRING_STATUS.UNPAIRED
      ? raw.pairing
      : PAIRING_STATUS.UNSUPPORTED,
  };
}

/**
 * A pairing reply or event. A code is kept only while pending and a
 * credential only on approval; anything else in the message is dropped.
 */
function parsePairing(raw, id) {
  if (!PAIRING_FLOW_VALUES.has(raw.state)) {
    return { ok: false, reason: `unknown pairing state ${describe(raw.state)}` };
  }
  const pending = raw.state === PAIRING_FLOW.PENDING;
  const approved = raw.state === PAIRING_FLOW.APPROVED;
  if (pending && !(typeof raw.code === 'string' && PAIRING_CODE_RE.test(raw.code))) {
    return { ok: false, reason: 'pending pairing carried no usable code' };
  }
  if (approved && !(typeof raw.credential === 'string' && PAIRING_CREDENTIAL_RE.test(raw.credential))) {
    return { ok: false, reason: 'approved pairing carried no usable credential' };
  }
  const expires = Number.isInteger(raw.expiresInSeconds) && raw.expiresInSeconds > 0
    && raw.expiresInSeconds <= 3600 ? raw.expiresInSeconds : 0;
  return {
    ok: true,
    msg: {
      type: 'pairing',
      id,
      state: raw.state,
      code: pending ? raw.code : '',
      expiresInSeconds: pending ? expires : 0,
      credential: approved ? raw.credential : '',
    },
  };
}

const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/;

function slug(value) {
  return typeof value === 'string' && SLUG_RE.test(value) ? value : '';
}

/**
 * Node display names are the one place a human-authored string reaches the
 * screen, and they are re-checked here rather than trusted. The desktop side
 * rejects an address-shaped name at construction and again at the choke point;
 * this is the third check, on the receiving side, because the receiving side is
 * the one that would render it.
 */
const ADDRESS_SHAPED = /(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-f]{1,4}:){2,}|\.(?:com|net|org|io|dev|co|us|uk|ru|cn|sg|jp|de|fr|nl|info|top|site)\b/i;

function parseNodes(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const item of value.slice(0, 64)) {
    if (!item || typeof item !== 'object') continue;
    const s = slug(item.slug);
    if (!s) continue;
    const name = typeof item.name === 'string' ? item.name.slice(0, 64) : '';
    if (ADDRESS_SHAPED.test(name)) continue; // dropped whole, never trimmed
    const flag = typeof item.flag === 'string' ? item.flag.slice(0, 8) : '';
    out.push({ slug: s, name, flag });
  }
  return out;
}

function boundedInt(value) {
  return Number.isInteger(value) && value >= 0 && value <= 1 << 24 ? value : 0;
}

function parseCredential(raw, id) {
  const port = raw.proxyPort;
  if (!validatePort(port)) {
    return { ok: false, reason: 'credential reply carried no usable port' };
  }
  if (typeof raw.token !== 'string' || raw.token.length < 16 || raw.token.length > 256) {
    return { ok: false, reason: 'credential reply carried no usable token' };
  }
  if (!/^[A-Za-z0-9_-]+$/.test(raw.token)) {
    return { ok: false, reason: 'token is not base64url' };
  }
  return {
    ok: true,
    msg: {
      type: 'proxy_credential',
      id,
      endpoint: { kind: 'http', host: LOOPBACK_HOST, port },
      token: raw.token,
    },
  };
}

function describe(v) {
  if (v === null) return 'null';
  if (v === undefined) return 'absent';
  if (typeof v === 'string') return JSON.stringify(v.slice(0, 24));
  return String(typeof v);
}
