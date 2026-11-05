// Win's VPN browser proxy shared constants.
//
// Everything in src/core/ is browser-agnostic: it must not reference `chrome`,
// `browser`, `window`, or `document`. Anything platform-specific belongs in
// src/adapters/.
//
// SECURITY INVARIANT (enforced by tools/leakscan.py at build time):
// no real infrastructure address may appear anywhere in this bundle. The only
// addresses permitted in shipped source are loopback literals, because the
// desktop endpoint is always loopback. Node addresses, gateway addresses and
// control-plane addresses live on the desktop side of the native-messaging
// boundary and are never sent to, stored by, or known to this extension.

// Wire protocol version. Must equal kBridgeProtocolVersion in the normative
// desktop-side contract, lib/browser_bridge_protocol.dart.
export const PROTOCOL_VERSION = 1;

// Native-messaging host identifier: the filename (minus .json) of the host
// manifest the desktop installer writes into each browser's native-messaging
// directory. Firefox requires the filename and this name to match, so both
// sides use the strictest rule.
export const NATIVE_HOST_NAME = 'org.winsvpn.bridge';

// The only network address this extension contains.
//
// The bridge describes its proxy by port number alone -- there is no host field
// anywhere in the contract -- so the host is supplied from here. That is what
// makes it structurally impossible for this browser to be pointed at anything
// but this machine, and it is why a build-time scan for address literals finds
// exactly this one and nothing else.
export const LOOPBACK_HOST = '127.0.0.1';

// How long a status report from the host stays trustworthy. After this, the
// extension treats connection state as UNKNOWN and fails closed. This exists
// because an MV3 service worker can be terminated and revived at any moment:
// on revival it must re-establish truth rather than trust a cached "connected".
export const STATUS_TTL_MS = 20_000;

// How long the bridge has to answer the handshake before its silence becomes a
// reported fact rather than a wait.
//
// The extension sends `hello`, `subscribe` and `get_status` the instant the
// port opens. A host that is running answers all three in well under a second;
// the real compiled host was measured at ~200ms on this machine. So a port that
// has been open for six seconds with NOTHING on it is not a slow host, it is
// not a host.
//
// Six seconds rather than one: a revived MV3 service worker can be descheduled
// between opening the port and the reply arriving, and a state that accuses the
// bridge of being dead because the browser was busy would be its own small lie.
// It is below HEARTBEAT_MS on purpose, so the first heartbeat after the port
// opens is the pass that notices.
export const HOST_HANDSHAKE_TTL_MS = 6_000;

// Heartbeat cadence. The native port keeps the service worker alive while it is
// open; the alarm is the backstop for when the port has died and nothing else
// would wake us.
export const HEARTBEAT_MS = 10_000;

// Cadence while the desktop tunnel is coming up and this browser is not yet
// routing: one status ask a second, so routing starts within about a second of
// the tunnel carrying traffic instead of up to HEARTBEAT_MS later.
export const FAST_HEARTBEAT_MS = 1_000;
// The fast cadence lasts at most this long per wait; a wait that has not
// ended by then (a host refusing to issue a key) goes back to HEARTBEAT_MS.
export const FAST_HEARTBEAT_WINDOW_MS = 30_000;

// Minimum spacing between automatic re-issues of a proxy credential that the
// desktop proxy has rejected. Bounded so a host that keeps rejecting cannot
// turn the heartbeat into a credential-request loop.
export const CREDENTIAL_REISSUE_MIN_MS = 30_000;
export const ALARM_NAME = 'wv-heartbeat';
export const ALARM_PERIOD_MINUTES = 1.0; // Supported throughout declared Chromium version range.

// Reconnect backoff for the native port, in milliseconds.
export const RECONNECT_BACKOFF_MS = [1_000, 2_000, 5_000, 10_000, 30_000];

// Declarative-net-request rule id space. Kept small and fixed so the rule set is
// fully replaced on every update and can never accumulate orphans.
export const DNR_BLOCK_RULE_ID = 1;
export const DNR_EXEMPT_RULE_ID_BASE = 1000;
export const DNR_MAX_EXEMPT_RULES = 500;

// A scratch id, outside the space the real rules use, for the capability probe
// in the adapter. It is added and removed inside one call and is also swept by
// allRuleIds() so that a background context killed mid-probe cannot leave an
// orphan behind.
export const DNR_PROBE_RULE_ID = 9000;

export const DNR_PRIORITY_BLOCK = 1;
export const DNR_PRIORITY_EXEMPT = 2;

// Resource types the fail-closed block ASKS FOR. Deliberately explicit rather
// than omitted: when `resourceTypes` is omitted, Chrome's declarativeNetRequest
// defaults to all types EXCEPT main_frame, which would let the top-level
// document through while blocking its subresources: a partial block that looks
// like a broken page rather than a refusal, and worse, one that still emits the
// request.
//
// This is a WANTED list, not the list that is submitted. `updateDynamicRules`
// validates the whole call, so a single value the running browser's schema does
// not know discards EVERY rule -- there is no partial install and the only
// symptom is a log line inside the extension. Firefox 153 knows thirteen of the
// fifteen below and rejects `webtransport` and `webbundle`, which cost this
// component its entire block layer on Firefox while the popup went on promising
// it. The adapter therefore intersects this list with what the running browser
// actually accepts, measured against the same validator that will judge the real
// call (see BaseAdapter.blockLayerTypes).
//
// Narrowing is not a weakening: a resource type a browser's schema does not know
// is a resource type that browser cannot label a request with. What must never
// be narrowed away is the top-level document, which is why the essential set
// below is checked separately and a negotiation that loses it counts as a failed
// block layer rather than a smaller one.
export const DNR_RESOURCE_TYPES = [
  'main_frame',
  'sub_frame',
  'stylesheet',
  'script',
  'image',
  'font',
  'object',
  'xmlhttprequest',
  'ping',
  'csp_report',
  'media',
  'websocket',
  'webtransport',
  'webbundle',
  'other',
];

// The part of the list that is not negotiable. A block that cannot cover the
// top-level document and its frames is not a block: it is a broken page that
// still emitted the request, which is the exact shape the comment above refuses.
export const DNR_ESSENTIAL_RESOURCE_TYPES = ['main_frame', 'sub_frame'];

// Routing modes.
//
// ALL    : every site goes through the tunnel, except hosts the user excluded.
//          This is the default because it is the mode that stores nothing
//          sensitive: an untouched profile holds an empty rule list.
// LISTED : only hosts the user listed go through the tunnel; everything else
//          goes direct. This is the capability the desktop apps do not have.
export const MODE_ALL = 'all';
export const MODE_LISTED = 'listed';

// Extension-level states. These drive both behaviour and the words shown to the
// user; there is exactly one source of truth for both.
export const STATE = {
  OFF: 'off', // Not armed. The browser is untouched.
  // The browser has no routing API and the containing app has attested that it
  // supplies no native replacement. This is non-blocking: a missing product
  // capability must not brick sites while implying that opening the app fixes it.
  NO_ROUTING_SURFACE: 'no_routing_surface',
  NO_HOST: 'no_host', // Armed; the desktop bridge is not reachable at all.

  // THE PORT IS OPEN AND NOTHING IS ON THE OTHER END OF IT.
  //
  // Not the same thing as NO_HOST and not the same thing as STALE, and the
  // difference is the whole reason this state exists. NO_HOST is a launch the
  // browser REFUSED and reported: connectNative threw, or the port disconnected
  // with a reason. STALE is a bridge that answered and then went quiet. This is
  // the third case, and until 2026-08-07 it was silently filed under STALE:
  // the browser accepted connectNative, started a process, and the process
  // never said one word -- so `status` stayed null, the port never disconnected,
  // and `lastError` stayed at the empty string it is constructed with.
  //
  // It is not hypothetical. Measured on this machine on 2026-08-07, on Chrome
  // 151, Edge 151 and Firefox 153, with the real compiled host: a host binary
  // installed under `~/Documents`, `~/Desktop` or `~/Downloads` -- all three
  // TCC-protected on macOS -- is spawned successfully and then blocks FOREVER
  // inside dyld, in `open(2)` on its own executable, because the browser is not
  // permitted to read that directory. The process is in the process table. The
  // pipe is open. Nothing is ever written to it. Every browser reports exactly
  // nothing, because from the browser's point of view nothing has gone wrong.
  //
  // A silence that no component reports is only visible as a silence, so the
  // extension times the handshake itself and says what it measured.
  HOST_NOT_ANSWERING: 'host_not_answering',

  APP_NOT_RUNNING: 'app_not_running', // Bridge up; the desktop app is not running.
  APP_DOWN: 'app_down', // App running, tunnel not connected.
  PERMISSION_REQUIRED: 'permission_required', // The OS VPN consent has not been granted.
  NOT_READY: 'not_ready', // Tunnel connected, but the bridge's proxy gate is shut.
  NO_CREDENTIAL: 'no_credential', // No proxy token this session; cannot authenticate.
  STALE: 'stale', // The bridge went quiet; the last status is too old to rely on.
  BAD_ENDPOINT: 'bad_endpoint', // A non-loopback endpoint was offered. Refused.
  NOT_IN_CONTROL: 'not_in_control', // Another extension owns the proxy setting.
  PROXY_NOT_CONTROLLABLE: 'proxy_not_controllable', // The browser refuses extension control of the proxy setting.
  NO_AUTH_CAPABILITY: 'no_auth_capability', // Cannot answer the proxy's challenge.

  // The three below exist because every fact deriveState checked could be true
  // while the browser was doing none of it. On Firefox 153 the extension reached
  // PROTECTED, the popup said so, and the block layer had been discarded whole
  // by the browser and the credential never left the extension -- so in-scope
  // traffic went out over the direct connection while the words said it was
  // being blocked. A state computed only from what the extension ASKED FOR is a
  // state that cannot notice that. These three are computed from what the
  // browser DID with those requests, and each one is fed by a component
  // reporting its own failure into the machine rather than into a log line.
  NOT_ENFORCING: 'not_enforcing', // The block layer is not installed. Nothing is being blocked.
  ROUTING_FAILED: 'routing_failed', // The browser refused the routing this extension asked for.
  ROUTING_UNAUTHENTICATED: 'routing_unauthenticated', // Routed, but the key never reached the proxy.
  PRIVACY_FAILED: 'privacy_failed', // Web requests are blocked; direct media traffic remains possible.

  PROTECTED: 'protected', // Routing installed; app connected; status fresh.
};

// Every state except PROTECTED means in-scope traffic must not leave over the
// direct connection. This is a statement of INTENT -- what the controller must
// try to do -- and not a claim that it succeeded. NOT_ENFORCING is fail-closed
// by this predicate and is precisely the state in which the attempt did not
// work; the difference between wanting to block and having blocked is the whole
// subject of that state, and the copy for it must not borrow the promise the
// others make.
export function isFailClosedState(state) {
  return state !== STATE.PROTECTED
    && state !== STATE.OFF
    && state !== STATE.NO_ROUTING_SURFACE;
}

// The states that exist because a component the extension armed did not do what
// it was asked. Named as a set so that the copy checker can require them to say
// so rather than inheriting a promise from a neighbouring state.
export const ENFORCEMENT_FAILURE_STATES = [
  STATE.NOT_ENFORCING,
  STATE.ROUTING_FAILED,
  STATE.ROUTING_UNAUTHENTICATED,
  STATE.PRIVACY_FAILED,
];

export const STORAGE_KEY_SETTINGS = 'settings';

// The pairing credential the desktop app minted after the user approved this
// browser in the app (R20 A1). The one connection fact this extension keeps
// across restarts: without it, every browser start would need a new in-app
// approval. It grants connect and disconnect, nothing else, and only while the
// app still remembers this browser; the app's "Paired browsers" list revokes
// it, and erasing the site list here erases it too.
export const STORAGE_KEY_PAIRING = 'pairing';

// How often the popup re-reads state while an in-app confirmation is open.
export const PAIRING_REFRESH_MS = 1_000;
