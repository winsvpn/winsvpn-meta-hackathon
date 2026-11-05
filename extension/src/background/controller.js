// Orchestration. Identical on Chrome, Edge and Firefox; every difference lives
// behind the adapter.
//
// Two rules shape the whole file.
//
// 1. BROWSER STATE IS RECONCILED FROM DERIVED STATE, ALWAYS IN THE SAME ORDER,
//    AND THE BLOCK LAYER GOES ON BEFORE THE ROUTING COMES OFF. There is no
//    ordering that makes the transition window zero, so it is arranged to fail
//    in the safe direction: blocked traffic, never leaked traffic.
//
// 2. NOTHING ABOUT THE CONNECTION IS EVER WRITTEN DOWN. The credential, the
//    port, the last known tunnel state and the node list all live in instance
//    fields that die with the background context, and are re-established from
//    the bridge on every revival. A browser profile lifted off a seized machine
//    contains the user's own site list and, once the user has paired this
//    browser in the desktop app, the pairing credential (STORAGE_KEY_PAIRING).
//    That credential lets the holder ask the app to connect or disconnect; it
//    carries no address, no account and no proxy key, and the app's "Paired
//    browsers" list revokes it.

import {
  ALARM_NAME,
  ALARM_PERIOD_MINUTES,
  CREDENTIAL_REISSUE_MIN_MS,
  FAST_HEARTBEAT_MS,
  FAST_HEARTBEAT_WINDOW_MS,
  HEARTBEAT_MS,
  HOST_HANDSHAKE_TTL_MS,
  NATIVE_HOST_NAME,
  RECONNECT_BACKOFF_MS,
  STATE,
  STORAGE_KEY_PAIRING,
  STORAGE_KEY_SETTINGS,
} from '../core/constants.js';
import { buildBlockRules } from '../core/blockrules.js';
import { deriveState, normaliseRoutingSurface } from '../core/state.js';
import { defaultSettings, sanitiseSettings } from '../core/rules.js';
import {
  PAIRING_CREDENTIAL_RE,
  PAIRING_FLOW,
  PAIRING_STATUS,
  REQUEST,
  TUNNEL_STATUS,
  parseInbound,
  request,
} from '../core/protocol.js';
import { createAdapter, api } from '../adapters/index.js';

const CHROMIUM_ADAPTER_NAMES = new Set(['chrome', 'edge']);
const CHROMIUM_EXTENSION_ID_RE = /^[a-p]{32}$/;
const INCOGNITO_UNVERIFIED = 'private-window permission could not be verified';

class StaleReconcileError extends Error {}

export class Controller {
  constructor() {
    this.adapter = createAdapter();
    this.settings = defaultSettings();

    this.port = null;
    this.hostSession = 0;
    this.hostConnected = false;
    // WHETHER THE THING ON THE OTHER END OF THE PORT HAS EVER EXISTED.
    //
    // `hostConnected` only says a port object was handed back, which every
    // browser does before it knows whether the host will run. These two say
    // whether anything ever came the other way, and when the asking started.
    // They are what makes "the bridge never started" a reportable fact rather
    // than an absence nobody is counting -- see STATE.HOST_NOT_ANSWERING.
    this.hostSpoke = false;
    this.hostOpenedAtMs = 0;
    // How many requests went out on the port that is open now. Counted so that
    // the silence can be reported with both sides of it -- "n sent, 0 back" is
    // a measurement; "no status yet" is a shrug.
    this.requestsSent = 0;
    this.status = null;
    this.statusAtMs = 0;
    this.reconnectAttempt = 0;
    this.reconnectTimer = null;
    this.heartbeatTimer = null;
    this.lastHeartbeatMs = 0;
    this.waitingForRouteSinceMs = 0;
    this.msgSeq = 0;

    // The session credential: {endpoint, token}. Memory only.
    // The desktop side reissues one per native-messaging session precisely so
    // that neither side has to persist it.
    this.credential = null;
    this.credentialRequested = false;
    this.credentialReissuedAtMs = 0;
    this.credentialRequestId = '';
    this.canAuthenticate = false;
    this.routingSurface = { ok: true, reason: '' };

    this.current = { state: STATE.OFF, endpoint: null, detail: '', failClosed: false };
    this.applied = { pacKey: null, blockKey: null };
    this.offCleanupComplete = false;
    this.privacy = { webrtc: 'unknown', prediction: 'unknown' };
    this.lastError = '';
    this.incognitoAllowed = false;
    this.routingMechanism = 'none';
    this.proxyLevelOfControl = 'unknown';

    // WHAT THE BROWSER DID, as opposed to what it was asked for.
    //
    // These two are inputs to deriveState, and they are the whole of the fix for
    // the failure the first live Firefox run found: `applyBlockRules` already
    // caught its error, and put it in a string that nothing downstream read, so
    // the extension reached PROTECTED with no block layer installed and the
    // popup promised a block that was not there. `ok: null` means not yet
    // attempted; a component that has failed sets `ok: false` and the state
    // machine stops being able to say PROTECTED.
    this.blockLayer = { ok: null, error: '', dropped: [] };
    this.routing = { ok: null, error: '' };
    // Set when an enforcement outcome changes during a reconcile, so that one
    // extra pass can re-derive from it rather than reporting a state that is one
    // action out of date.
    this.enforcementChanged = false;
    this.reconcileGeneration = 0;
    this.reconcilePending = false;
    this.reconcilePromise = null;
    this.settingsMutation = Promise.resolve();

    // PAIRING WITH THE DESKTOP APP (R20 A1).
    //
    // The app grants connect and disconnect only to a browser the user
    // approved in the app. `credential` is what the app minted then; `flow` is
    // where an in-app approval this browser asked for stands, and `code` is
    // the six digits the app shows while it waits, repeated in the popup so
    // the user approves this browser and not some other local program.
    this.pairing = { credential: '', flow: '', code: '', expiresAtMs: 0 };
    this.pairingRequestId = '';
    // Set once the bridge has acknowledged the credential presented on this
    // port, so an `unpaired` answer after that means the app revoked it.
    this.pairingPresented = false;
  }

  // -- lifecycle ------------------------------------------------------------

  async init() {
    const stored = await this.adapter.loadSettings(STORAGE_KEY_SETTINGS);
    this.settings = sanitiseSettings(stored);
    try {
      const pairing = await this.adapter.loadSettings(STORAGE_KEY_PAIRING);
      const credential = pairing && typeof pairing === 'object' ? pairing.credential : '';
      this.pairing.credential = typeof credential === 'string' && PAIRING_CREDENTIAL_RE.test(credential)
        ? credential
        : '';
    } catch {
      this.pairing.credential = '';
    }
    this.incognitoAllowed = await this.adapter.isAllowedIncognitoAccess();
    this.routingSurface = normaliseRoutingSurface(await this.adapter.routingSurface());
    this.canAuthenticate = await this.adapter.canAuthenticate();

    // Settle what this browser will accept in a block rule BEFORE the first
    // reconcile, so the first state is derived from a block layer whose
    // availability is known rather than assumed. On a browser that accepts the
    // whole list this is one round trip.
    if (this.routingSurface.ok) await this.negotiateBlockLayer();

    // Reconcile before anything else. If this context was revived after being
    // killed while armed, the browser may still hold proxy settings and block
    // rules from the previous life. The first job is to make the browser agree
    // with what is true now, not with what was true when we died.
    await this.reconcile();

    if (this.settings.armed && this.routingSurface.ok) this.openHost();
  }

  runSettingsMutation(operation) {
    const result = this.settingsMutation.then(operation);
    this.settingsMutation = result.catch(() => {});
    return result;
  }

  setSettings(next, expectedSettings = null) {
    const clean = sanitiseSettings(next);
    const expected = expectedSettings === null ? null : sanitiseSettings(expectedSettings);
    return this.runSettingsMutation(async () => {
      if (expected !== null && JSON.stringify(expected) !== JSON.stringify(this.settings)) {
        this.lastError = "Settings changed in another window. Review the current settings and retry your change.";
        return this.snapshot();
      }
      const wasArmed = this.settings.armed;
      await this.adapter.saveSettings(STORAGE_KEY_SETTINGS, clean);
      this.reconcileGeneration += 1;
      this.reconcilePending = true;
      this.settings = clean;

      if (clean.armed && !wasArmed) this.openHost();
      if (!clean.armed && wasArmed) this.closeHost();

      await this.reconcile();
      return this.snapshot();
    });
  }

  // -- native messaging -----------------------------------------------------

  openHost() {
    if (!this.routingSurface.ok) return;
    if (this.port) return;
    const identityError = chromiumNativeIdentityError(this.adapter);
    if (identityError) {
      // Keep `settings.armed` intact. Reconciliation will therefore retain the
      // block layer while this package refuses to open a native pipe under an
      // identity the Chromium adapter did not bind exactly. The alarm can
      // re-check after a browser update or service-worker revival; a static
      // identity failure does not need a tight reconnect loop.
      this.hostConnected = false;
      this.hostSpoke = false;
      this.hostOpenedAtMs = 0;
      this.requestsSent = 0;
      this.status = null;
      this.statusAtMs = 0;
      this.dropCredential();
      this.lastError = identityError;
      this.stopHeartbeat();
      return;
    }
    const hostSession = ++this.hostSession;
    this.port = this.adapter.connectNative(NATIVE_HOST_NAME, {
      onMessage: (raw) => {
        if (hostSession === this.hostSession) return this.onHostMessage(raw);
      },
      onDisconnect: (reason) => {
        if (hostSession === this.hostSession) this.onHostDisconnect(reason);
      },
    });
    if (!this.port) {
      this.hostConnected = false;
      this.hostOpenedAtMs = 0;
      this.scheduleReconnect();
      return;
    }
    this.hostConnected = true;
    // The handshake clock starts here, before the first request goes out, so
    // that the age reported later is the age of the whole exchange rather than
    // of the last thing we happened to send.
    this.hostSpoke = false;
    this.hostOpenedAtMs = Date.now();
    this.requestsSent = 0;
    this.credentialRequested = false;
    this.pairingPresented = false;
    this.send(request(this.nextId(), REQUEST.HELLO));
    // Present the stored pairing before subscribing, so every status the host
    // pushes on this port is the app's answer for this browser.
    if (this.pairing.credential) {
      this.pairingRequestId = this.nextId();
      this.send(request(this.pairingRequestId, REQUEST.SET_PAIRING, {
        credential: this.pairing.credential,
      }));
    }
    this.send(request(this.nextId(), REQUEST.SUBSCRIBE));
    this.send(request(this.nextId(), REQUEST.GET_STATUS));
    this.startHeartbeat();
  }

  closeHost() {
    this.hostSession += 1;
    this.stopHeartbeat();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.port) {
      try {
        // Ask the desktop side to destroy the token as well. Best effort: the
        // token dies with the host process anyway, which is the guarantee that
        // actually matters.
        this.send(request(this.nextId(), REQUEST.REVOKE_PROXY_CREDENTIAL));
        this.port.disconnect();
      } catch {
        /* already gone */
      }
    }
    this.port = null;
    this.hostConnected = false;
    this.hostSpoke = false;
    this.hostOpenedAtMs = 0;
    this.status = null;
    this.statusAtMs = 0;
    this.dropCredential();
    this.abandonPairingFlow();
  }

  /** The host that was watching an in-app approval is gone. */
  abandonPairingFlow() {
    this.pairingPresented = false;
    if (this.pairing.flow === PAIRING_FLOW.PENDING) {
      this.pairing.flow = PAIRING_FLOW.EXPIRED;
      this.pairing.code = '';
      this.pairing.expiresAtMs = 0;
    }
  }

  dropCredential() {
    this.credential = null;
    this.credentialRequested = false;
    this.credentialRequestId = '';
    try {
      this.adapter.setCredential(null);
    } catch {
      /* adapter without credential support */
    }
  }

  send(msg) {
    if (!this.port) return;
    try {
      this.port.postMessage(msg);
      this.requestsSent += 1;
    } catch (e) {
      this.onHostDisconnect(
        `this browser refused to write to the bridge: ${String(e && e.message ? e.message : e)}`,
      );
    }
  }

  nextId() {
    this.msgSeq += 1;
    return String(this.msgSeq);
  }

  async onHostMessage(raw) {
    // BEFORE PARSING, AND ON PURPOSE. A frame that arrives and turns out to be
    // nonsense still proves a process is running and writing to the pipe, which
    // is a different situation from a pipe nothing has ever come out of. Setting
    // this after a successful parse would let a bridge that only ever sends
    // rubbish be reported as one that never started.
    this.hostSpoke = true;
    const parsed = parseInbound(raw);
    if (!parsed.ok) {
      // A message that is not understood is discarded, not partially applied,
      // and it does not refresh the status clock. A bridge that only ever sends
      // nonsense therefore ages into STALE and the extension fails closed.
      this.lastError = `bridge sent something unusable: ${parsed.reason}`;
      return;
    }
    // A returned Port is not proof that the native host has answered.
    this.reconnectAttempt = 0;
    const msg = parsed.msg;

    if (msg.type === 'pairing') {
      await this.onPairing(msg);
      return;
    }

    if (msg.type === 'error') {
      this.lastError = `the desktop app refused a request: ${msg.code}`;
      if (msg.id && msg.id === this.pairingRequestId) {
        this.pairingRequestId = '';
        if (this.pairing.flow === PAIRING_FLOW.PENDING || this.pairing.flow === '') {
          this.pairing.flow = msg.code === 'rate_limited' ? PAIRING_FLOW.BUSY : PAIRING_FLOW.UNAVAILABLE;
          this.pairing.code = '';
        }
      }
      if (this.credentialRequested && msg.id === this.credentialRequestId) {
        this.credentialRequested = false;
        this.credentialRequestId = '';
      }
      if (msg.code === 'app_not_running') this.dropCredential();
      await this.reconcile();
      return;
    }

    if (msg.type === 'proxy_credential') {
      if (
        !this.credentialRequested
        || msg.id !== this.credentialRequestId
        || !this.hostConnected
        || !this.settings.armed
        || !this.status?.proxyReady
      ) {
        return;
      }
      this.credentialRequested = false;
      this.credentialRequestId = '';
      this.credential = {
        endpoint: msg.endpoint,
        token: msg.token,
      };
      // The host rotates an expired listener inside this very request and
      // answers with the new port before its subscription poll pushes a status
      // saying so. The correlated reply is the newer fact; keeping the older
      // status port would refuse the fresh credential as "moved".
      this.status = { ...this.status, proxyPort: msg.endpoint.port };
      this.adapter.setCredential(this.credential);
      this.lastError = '';
      await this.reconcile();
      return;
    }

    if (msg.type === 'status' || msg.type === 'hello') {
      this.status = msg.status;
      this.statusAtMs = Date.now();
      this.lastError = '';
      await this.notePairingStatus(msg);
      this.maybeRequestCredential();
      await this.reconcile();
    }
  }

  /**
   * Ask for a credential only when the desktop side says it would issue one.
   *
   * Asking earlier would make the extension start the desktop proxy as a side
   * effect of merely being switched on, which is a listening socket the user
   * did not ask for. Asking when `proxyReady` is true keeps the local port's
   * lifetime tied to a tunnel that is actually up.
   */
  maybeRequestCredential() {
    if (!this.settings.armed || !this.status) return;
    if (!this.status.proxyReady) {
      // The gate shut. Any credential in hand is for a proxy that is no longer
      // admitting traffic, so it is dropped rather than kept warm.
      this.dropCredential();
      return;
    }
    // A subscribed host can rotate its listener before the browser makes a
    // request with the expired credential. Reissue through the correlated
    // request path when status reports a different port.
    if (this.credential && this.status.proxyPort
        && this.credential.endpoint.port !== this.status.proxyPort) {
      this.dropCredential();
    }
    // A token the desktop proxy has started rejecting (its 8 h expiry, or a
    // host restart behind the same port) is dead. Drop it and ask again, at
    // most once per CREDENTIAL_REISSUE_MIN_MS, instead of staying in
    // ROUTING_UNAUTHENTICATED until the user toggles routing.
    const stats = this.adapter.authStats;
    if (
      this.credential
      && stats
      && Number(stats.credentialsRejected) > 0
      && Date.now() - this.credentialReissuedAtMs >= CREDENTIAL_REISSUE_MIN_MS
    ) {
      this.credentialReissuedAtMs = Date.now();
      this.dropCredential();
    }
    if (this.credential || this.credentialRequested) return;
    this.credentialRequested = true;
    this.credentialRequestId = this.nextId();
    this.send(request(this.credentialRequestId, REQUEST.ISSUE_PROXY_CREDENTIAL));
  }

  onHostDisconnect(reason) {
    this.hostSession += 1;
    this.port = null;
    this.hostConnected = false;
    this.hostSpoke = false;
    this.hostOpenedAtMs = 0;
    this.status = null;
    this.statusAtMs = 0;
    this.dropCredential();
    this.abandonPairingFlow();
    // The adapter always supplies a reason now -- including the case where the
    // browser had nothing to say, which it reports as that rather than leaving
    // the field to fall back to ''. The `||` stays as a guard on a caller that
    // is not the adapter (`send()` passes an exception string).
    this.lastError = reason || 'the bridge stopped, and nothing said why';
    this.stopHeartbeat();
    // Reconcile immediately rather than waiting for the next poll. Losing the
    // bridge is precisely the moment the block layer needs to be on.
    this.reconcile();
    if (this.settings.armed) this.scheduleReconnect();
  }

  scheduleReconnect() {
    if (this.reconnectTimer || !this.settings.armed) return;
    const delay =
      RECONNECT_BACKOFF_MS[Math.min(this.reconnectAttempt, RECONNECT_BACKOFF_MS.length - 1)];
    this.reconnectAttempt += 1;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (this.settings.armed) this.openHost();
    }, delay);
  }

  startHeartbeat() {
    this.stopHeartbeat();
    this.lastHeartbeatMs = Date.now();
    // Ticks every FAST_HEARTBEAT_MS and asks only when the current cadence is
    // due, so a status that says the tunnel is coming up shortens the wait for
    // the next ask without restarting the timer.
    this.heartbeatTimer = setInterval(() => {
      const now = Date.now();
      if (now - this.lastHeartbeatMs < this.heartbeatDelayMs()) return;
      this.lastHeartbeatMs = now;
      this.send(request(this.nextId(), REQUEST.GET_STATUS));
      // Re-derive even when the bridge says nothing: that is how a status ages
      // out of validity and the extension moves itself into STALE.
      this.reconcile();
    }, FAST_HEARTBEAT_MS);
  }

  /**
   * While the desktop tunnel is coming up, or is up but this browser does not
   * yet hold a working key, every second of waiting is a second the user's
   * sites stay blocked: ask once a second, for at most
   * FAST_HEARTBEAT_WINDOW_MS per wait, so a wait that is stuck (a refusing
   * host) falls back to the slow cadence. An app that is not running is never
   * asked faster.
   */
  heartbeatDelayMs() {
    const s = this.status;
    const waiting = Boolean(this.settings.armed && s && (
      s.status === TUNNEL_STATUS.CONNECTING
      || (s.status === TUNNEL_STATUS.CONNECTED && (!s.proxyReady || !this.credential))
    ));
    if (!waiting) {
      this.waitingForRouteSinceMs = 0;
      return HEARTBEAT_MS;
    }
    const now = Date.now();
    if (!this.waitingForRouteSinceMs) this.waitingForRouteSinceMs = now;
    return now - this.waitingForRouteSinceMs <= FAST_HEARTBEAT_WINDOW_MS
      ? FAST_HEARTBEAT_MS
      : HEARTBEAT_MS;
  }

  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  /**
   * A service worker can be killed at any point, taking setInterval with it.
   * The alarm is the only thing that reliably brings it back, so the alarm --
   * not the interval -- is what makes the staleness rule real.
   */
  async onAlarm() {
    if (!this.routingSurface.ok) {
      await this.reconcile();
      return;
    }
    if (this.settings.armed && !this.port) this.openHost();
    else this.send(request(this.nextId(), REQUEST.GET_STATUS));
    await this.reconcile();
  }

  // -- reconciliation -------------------------------------------------------

  /**
   * Ask the adapter what this browser will accept in a block rule, and record
   * the answer as a fact about the block layer rather than as a log line.
   *
   * A browser that refuses the rule shape is a browser where the fail-closed
   * mechanism does not exist, and that has to be visible in the state, not in a
   * string. Firefox 153 refuses two of the fifteen resource types and discards
   * the whole rule set for it; the negotiation drops exactly those two and keeps
   * the other thirteen, which is not a weakening because a type this browser's
   * schema does not know is a type it cannot label a request with.
   */
  async negotiateBlockLayer() {
    let got;
    try {
      got = await this.adapter.blockLayerTypes();
    } catch (e) {
      got = { ok: false, types: [], dropped: [], error: describe(e) };
    }
    if (got.ok) {
      // Negotiation succeeding removes one reason a rule might not install; it
      // does not prove one does. A standing failure is left standing until an
      // actual install succeeds, which is the only thing that is evidence.
      this.blockLayer = { ...this.blockLayer, dropped: got.dropped || [] };
    } else {
      if (this.blockLayer.ok !== false) this.enforcementChanged = true;
      this.blockLayer = {
        ok: false,
        error: got.error || 'this browser refused every block rule shape offered to it',
        dropped: got.dropped || [],
      };
      this.lastError = `this browser will not accept the block rules: ${this.blockLayer.error}`;
    }
    return got;
  }

  async reconcile() {
    this.reconcileGeneration += 1;
    this.reconcilePending = true;
    if (!this.reconcilePromise) {
      this.reconcilePromise = this.drainReconciles().finally(() => {
        this.reconcilePromise = null;
        if (this.reconcilePending) void this.reconcile();
      });
    }
    return this.reconcilePromise;
  }

  async drainReconciles() {
    while (this.reconcilePending) {
      this.reconcilePending = false;
      const generation = this.reconcileGeneration;
      this.enforcementChanged = false;
      try {
        await this.reconcileOnce(generation);
      } catch (e) {
        if (!(e instanceof StaleReconcileError)) throw e;
        this.reconcilePending = true;
      }
      if (this.enforcementChanged) this.reconcilePending = true;
    }
  }

  assertReconcileGeneration(generation) {
    if (generation !== this.reconcileGeneration) throw new StaleReconcileError();
  }

  /**
   * Turn a port that has never carried a message into a sentence.
   *
   * This is the half of the 2026-08-07 finding that no component could report.
   * When a native-messaging host is spawned and then blocks forever -- which is
   * what a host installed in a macOS TCC-protected folder does, measured on all
   * three browsers -- the browser has no complaint to make: it started a
   * process and the pipe is open. `port.error` is unset, `runtime.lastError` is
   * unset, `onDisconnect` never fires. The only observable is the silence, so
   * the silence is what is measured and what is said.
   *
   * It is written as an observation plus a likely cause, in that order, and the
   * cause is offered rather than asserted: this extension cannot see the
   * filesystem and will not claim to know why. Everything before the em dash is
   * something it counted itself.
   */
  noteHandshakeSilence(nowMs) {
    if (!this.hostConnected || this.hostSpoke || !this.hostOpenedAtMs) return;
    const silentFor = nowMs - this.hostOpenedAtMs;
    if (silentFor <= HOST_HANDSHAKE_TTL_MS) return;
    this.lastError =
      `the bridge has not answered since this browser started it ${Math.round(silentFor / 1000)}s ago: `
      + `${this.requestsSent} request(s) sent, 0 replies, the port is still open and the browser `
      + 'reported no error: a host that is started and never answers is usually one the browser '
      + 'is not permitted to read, such as a bridge installed under Documents, Desktop or Downloads';
  }

  async reconcileOnce(generation) {
    if (this.adapter.name === 'safari') {
      const surface = normaliseRoutingSurface(await this.adapter.routingSurface());
      this.assertReconcileGeneration(generation);
      this.routingSurface = surface;
    }
    let levelOfControl = this.settings.armed && this.routingSurface.ok
      ? await this.adapter.proxyLevelOfControl()
      : 'unknown';
    this.assertReconcileGeneration(generation);

    const incognitoAllowed = typeof this.adapter.isAllowedIncognitoAccess === 'function'
      ? await this.adapter.isAllowedIncognitoAccess()
      : false;
    this.assertReconcileGeneration(generation);
    if (incognitoAllowed === null) {
      levelOfControl = 'unknown';
      this.applied.pacKey = null;
    }
    // AN UNKNOWN PRIVATE-WINDOW PERMISSION IS A ROUTING FAILURE, ON EVERY ADAPTER.
    //
    // The level override above is not enough by itself: deriveState does not
    // read 'unknown' as a failure until routing has once succeeded, and the
    // Firefox adapter's own control check never consults the permission. Without
    // this, a Firefox profile whose permission query fails published PROTECTED
    // and removed every block rule on each reconcile before the next pass put
    // them back. Recorded before deriveState so no pass reaches PROTECTED, and
    // withdrawn only when the permission reads back again, at which point the
    // cleared pacKey forces routing to be written and verified afresh.
    if (incognitoAllowed === null && this.settings.armed && this.routingSurface.ok) {
      this.routing = { ok: false, error: INCOGNITO_UNVERIFIED };
    } else if (incognitoAllowed !== null && this.routing.error === INCOGNITO_UNVERIFIED) {
      this.routing = { ok: null, error: '' };
    }

    const nowMs = Date.now();
    this.noteHandshakeSilence(nowMs);

    const next = deriveState({
      armed: this.settings.armed,
      hostConnected: this.hostConnected,
      hostSpoke: this.hostSpoke,
      hostOpenedAtMs: this.hostOpenedAtMs,
      status: this.status,
      statusAtMs: this.statusAtMs,
      nowMs,
      levelOfControl,
      credential: this.credential,
      canAuthenticate: this.canAuthenticate,
      routingSurface: this.routingSurface,
      blockLayer: this.blockLayer,
      routing: this.routing,
      authStats: this.adapter.authStats || null,
    });
    // Any active enforcement work invalidates the completed OFF cleanup.
    if (next.state !== STATE.OFF) this.offCleanupComplete = false;
    if (next.state === STATE.NO_ROUTING_SURFACE) {
      await this.applyBlockRules([], generation);
      this.assertReconcileGeneration(generation);
      await this.adapter.clearRouting();
      this.assertReconcileGeneration(generation);
      await this.adapter.releasePrivacyProtections();
      this.assertReconcileGeneration(generation);
      this.current = next;
      this.proxyLevelOfControl = levelOfControl;
      this.incognitoAllowed = incognitoAllowed;
      this.applied = { pacKey: null, blockKey: null };
      this.privacy = { webrtc: 'unsupported', prediction: 'unsupported' };
      this.routingMechanism = 'none';
      this.routing = { ok: null, error: '' };
      this.lastError = '';
      await this.paintBadge();
      return;
    }

    if (next.state === STATE.OFF) {
      if (this.offCleanupComplete) {
        const clearedLevel = await this.adapter.proxyLevelOfControl();
        this.assertReconcileGeneration(generation);
        this.current = next;
        this.proxyLevelOfControl = clearedLevel;
        this.incognitoAllowed = incognitoAllowed;
        await this.paintBadge();
        return;
      }
      // Keep a verified block in place until every routing scope has actually
      // relinquished control. Firefox can resolve clear() to false, and an OFF
      // state must not be published while its listener is still installed.
      //
      // The block is for a teardown, so it is installed only when there is
      // routing to tear down. A background context that starts OFF holds no
      // proxy setting and no listener unless a previous life left one behind,
      // and installing the global block in that case stops every request in
      // this browser for the length of the clear below, once per service-worker
      // start, which the heartbeat alarm causes every minute, for a user who
      // never switched this extension on. The adapter answers from the browser;
      // an adapter that cannot answer keeps the conservative order.
      const holdsRouting = typeof this.adapter.holdsRouting === 'function'
        ? await this.adapter.holdsRouting()
        : true;
      this.assertReconcileGeneration(generation);
      if (holdsRouting !== false) {
        const negotiated = await this.blockResourceTypes();
        this.assertReconcileGeneration(generation);
        await this.applyBlockRules(buildBlockRules(this.settings, true, negotiated), generation);
        this.assertReconcileGeneration(generation);
      }
      try {
        await this.adapter.clearRouting();
      } catch (e) {
        if (e instanceof StaleReconcileError) throw e;
        this.routing = { ok: false, error: describe(e) };
        this.lastError = `this browser did not clear routing while turning off: ${this.routing.error}`;
        this.current = {
          state: STATE.ROUTING_FAILED,
          endpoint: null,
          detail: this.routing.error,
          failClosed: true,
        };
        this.proxyLevelOfControl = levelOfControl;
        this.incognitoAllowed = incognitoAllowed;
        await this.paintBadge();
        return;
      }
      this.assertReconcileGeneration(generation);
      const clearedLevel = await this.adapter.proxyLevelOfControl();
      this.assertReconcileGeneration(generation);
      await this.adapter.releasePrivacyProtections();
      this.assertReconcileGeneration(generation);
      await this.applyBlockRules([], generation);
      this.assertReconcileGeneration(generation);
      this.current = next;
      this.proxyLevelOfControl = clearedLevel;
      this.incognitoAllowed = incognitoAllowed;
      this.applied = { pacKey: null, blockKey: null };
      this.privacy = { webrtc: 'unknown', prediction: 'unknown' };
      this.routingMechanism = 'none';
      // Nothing is armed, so nothing is claimed about routing. The block layer's
      // own availability is a property of the browser and is not reset here.
      this.routing = { ok: null, error: '' };
      // Cache only a complete cleanup verified by this reconciliation.
      this.offCleanupComplete = true;
      await this.paintBadge();
      return;
    }

    if (next.failClosed) {
      // BLOCK FIRST. The block rules are what actually stop traffic; the proxy
      // setting is only what would have routed it. Installing the block before
      // touching the proxy means there is no instant at which the extension is
      // armed, unrouted and unblocked.
      const negotiated = await this.blockResourceTypes();
      this.assertReconcileGeneration(generation);
      try {
        await this.applyBlockRules(buildBlockRules(this.settings, true, negotiated), generation);
      } catch (e) {
        await this.installFailClosedSink(generation, e);
        this.current = deriveState({
          armed: this.settings.armed,
          hostConnected: this.hostConnected,
          hostSpoke: this.hostSpoke,
          hostOpenedAtMs: this.hostOpenedAtMs,
          status: this.status,
          statusAtMs: this.statusAtMs,
          nowMs: Date.now(),
          levelOfControl,
          credential: this.credential,
          canAuthenticate: this.canAuthenticate,
          routingSurface: this.routingSurface,
          blockLayer: this.blockLayer,
          routing: this.routing,
          authStats: this.adapter.authStats || null,
        });
        this.proxyLevelOfControl = levelOfControl;
        this.incognitoAllowed = incognitoAllowed;
        await this.paintBadge();
        return;
      }
      this.assertReconcileGeneration(generation);
      try {
        this.privacy = await this.adapter.applyPrivacyProtections();
        this.assertReconcileGeneration(generation);
        if (this.lastError.startsWith('this browser refused privacy protection:')) {
          this.lastError = '';
        }
      } catch (error) {
        if (error instanceof StaleReconcileError) throw error;
        this.privacy = { webrtc: 'not_applied', prediction: 'not_applied' };
        this.lastError = `this browser refused privacy protection: ${describe(error)}`;
        this.current = {
          state: STATE.PRIVACY_FAILED,
          endpoint: null,
          detail: describe(error),
          failClosed: true,
        };
        this.proxyLevelOfControl = levelOfControl;
        this.incognitoAllowed = incognitoAllowed;
        await this.paintBadge();
        return;
      }
      try {
        await this.adapter.clearRouting();
      } catch (error) {
        this.assertReconcileGeneration(generation);
        this.applied.pacKey = null;
        this.routing = { ok: false, error: describe(error) };
        this.lastError = `this browser did not clear routing while blocking: ${this.routing.error}`;
        this.current = {
          state: STATE.ROUTING_FAILED,
          endpoint: null,
          detail: this.routing.error,
          failClosed: true,
        };
        this.proxyLevelOfControl = levelOfControl;
        this.incognitoAllowed = incognitoAllowed;
        await this.paintBadge();
        return;
      }
      this.assertReconcileGeneration(generation);
      const clearedLevel = await this.adapter.proxyLevelOfControl();
      this.assertReconcileGeneration(generation);
      this.current = next;
      this.proxyLevelOfControl = clearedLevel;
      this.incognitoAllowed = incognitoAllowed;
      this.applied.pacKey = null;
      this.routingMechanism = 'none';
      this.routing = { ok: null, error: '' };
      await this.paintBadge();
      return;
    }

    // Permission changes alter the set of Chromium proxy scopes that must be
    // written and verified, even when the PAC bytes themselves did not change.
    const pacKey = JSON.stringify([this.settings, next.endpoint, incognitoAllowed]);
    if (pacKey !== this.applied.pacKey) {
      // applyRouting can reject. It used to reject past this point and out of
      // reconcile() entirely, into a caller that swallowed it -- leaving
      // `this.current` already assigned PROTECTED and the popup saying so while
      // the browser had refused the setting. Firefox does exactly that: it
      // refuses `proxy.settings` outright unless the add-on is allowed in
      // private windows. The rejection is now a fact the state machine reads.
      try {
        const negotiated = await this.blockResourceTypes();
        this.assertReconcileGeneration(generation);
        await this.applyBlockRules(
          buildBlockRules(this.settings, true, negotiated), generation,
        );
        this.assertReconcileGeneration(generation);
        const routingMechanism = (await this.adapter.applyRouting(this.settings, next.endpoint)) || 'pac';
        this.assertReconcileGeneration(generation);
        const routedLevel = await this.adapter.proxyLevelOfControl();
        this.assertReconcileGeneration(generation);
        if (routedLevel !== 'controlled_by_this_extension') {
          throw new Error(
            `proxy setting did not become controlled by this extension (${routedLevel})`,
          );
        }
        this.routingMechanism = routingMechanism;
        this.proxyLevelOfControl = routedLevel;
        this.applied.pacKey = pacKey;
        if (this.routing.ok !== true) this.enforcementChanged = true;
        this.routing = { ok: true, error: '' };
      } catch (e) {
        if (e instanceof StaleReconcileError) throw e;
        this.routingMechanism = 'none';
        this.applied.pacKey = null;
        this.routing = { ok: false, error: describe(e) };
        this.lastError = `this browser refused the routing: ${this.routing.error}`;
        this.enforcementChanged = true;
        // Fail closed on the way out, in the same order as above: the block goes
        // on before anything else happens.
        const negotiated = await this.blockResourceTypes();
        this.assertReconcileGeneration(generation);
        try {
          await this.applyBlockRules(buildBlockRules(this.settings, true, negotiated), generation);
        } catch (blockError) {
          await this.installFailClosedSink(generation, blockError);
        }
        this.current = deriveState({
          armed: this.settings.armed,
          hostConnected: this.hostConnected,
          hostSpoke: this.hostSpoke,
          hostOpenedAtMs: this.hostOpenedAtMs,
          status: this.status,
          statusAtMs: this.statusAtMs,
          nowMs: Date.now(),
          levelOfControl: this.proxyLevelOfControl,
          credential: this.credential,
          canAuthenticate: this.canAuthenticate,
          routingSurface: this.routingSurface,
          blockLayer: this.blockLayer,
          routing: this.routing,
          authStats: this.adapter.authStats || null,
        });
        this.incognitoAllowed = incognitoAllowed;
        await this.paintBadge();
        return;
      }
    }
    try {
      this.privacy = await this.adapter.applyPrivacyProtections();
      this.assertReconcileGeneration(generation);
      await this.applyBlockRules([], generation);
    } catch (e) {
      if (e instanceof StaleReconcileError) throw e;
      this.routing = { ok: false, error: describe(e) };
      this.lastError = `this browser refused an enforcement write: ${this.routing.error}`;
      this.enforcementChanged = true;
      const negotiated = await this.blockResourceTypes();
      this.assertReconcileGeneration(generation);
      try {
        await this.applyBlockRules(buildBlockRules(this.settings, true, negotiated), generation);
      } catch (blockError) {
        await this.installFailClosedSink(generation, blockError);
      }
    }
    this.current = deriveState({
      armed: this.settings.armed,
      hostConnected: this.hostConnected,
      hostSpoke: this.hostSpoke,
      hostOpenedAtMs: this.hostOpenedAtMs,
      status: this.status,
      statusAtMs: this.statusAtMs,
      nowMs: Date.now(),
      levelOfControl: this.proxyLevelOfControl,
      credential: this.credential,
      canAuthenticate: this.canAuthenticate,
      routingSurface: this.routingSurface,
      blockLayer: this.blockLayer,
      routing: this.routing,
      authStats: this.adapter.authStats || null,
    });
    this.incognitoAllowed = incognitoAllowed;
    await this.paintBadge();
  }

  /** The negotiated set, re-establishing it if a previous attempt failed. */
  async blockResourceTypes() {
    const got = await this.negotiateBlockLayer();
    return got.ok ? got.types : [];
  }

  async applyBlockRules(rules, generation = null) {
    const key = JSON.stringify(rules.map((r) => [
      r.id,
      r.priority,
      r.action.type,
      r.condition.urlFilter,
      [...(r.condition.resourceTypes || [])].sort(),
    ]));
    if (key === this.applied.blockKey) return;
    try {
      if (generation !== null) this.assertReconcileGeneration(generation);
      await this.adapter.setBlockRules(rules);
      // Record completed adapter writes before checking reconciliation currency.
      this.applied.blockKey = key;
      if (rules.length) {
        // Only a call that had rules to install proves the rule SHAPE is
        // accepted. An empty update succeeds on a browser that would reject
        // every rule in the set, so it is not evidence and does not clear a
        // previous failure.
        if (this.blockLayer.ok !== true) this.enforcementChanged = true;
        this.blockLayer = { ok: true, error: '', dropped: this.adapter.blockTypesDropped || [] };
        if (this.lastError.startsWith('could not install the block rules')) this.lastError = '';
      }
      if (generation !== null) this.assertReconcileGeneration(generation);
    } catch (e) {
      if (e instanceof StaleReconcileError) throw e;
      // If the block layer cannot be installed, the extension must not carry on
      // as though it had been -- and, since 2026-08-07, it must not merely say
      // so in a string either. This is the input that stops deriveState reaching
      // any state whose copy promises a block.
      this.lastError = `could not install the block rules: ${describe(e)}`;
      this.applied.blockKey = null;
      if (this.blockLayer.ok !== false) this.enforcementChanged = true;
      this.blockLayer = { ok: false, error: describe(e), dropped: this.adapter.blockTypesDropped || [] };
      // The likeliest cause is a rule shape this browser will not take, so the
      // negotiated set is thrown away and established again on the next pass.
      if (typeof this.adapter.invalidateBlockLayerTypes === 'function') {
        this.adapter.invalidateBlockLayerTypes();
      }
      throw e;
    }
  }

  async installFailClosedSink(generation, blockError) {
    this.assertReconcileGeneration(generation);
    if (typeof this.adapter.installFailClosedSink !== 'function') {
      this.lastError += '; no adapter fail-closed sink is available';
      return false;
    }
    try {
      const mechanism = await this.adapter.installFailClosedSink();
      this.assertReconcileGeneration(generation);
      this.routingMechanism = mechanism || 'sink';
      this.lastError = `block rules failed, so routing was retained behind a verified sink: ${describe(blockError)}`;
      return true;
    } catch (sinkError) {
      if (sinkError instanceof StaleReconcileError) throw sinkError;
      this.lastError = `block rules failed and the backup sink also failed: ${describe(blockError)}; ${describe(sinkError)}`;
      return false;
    }
  }

  async paintBadge() {
    const action = api.action || api.browserAction;
    if (!action) return;
    const s = this.current.state;
    const text = s === STATE.OFF || s === STATE.NO_ROUTING_SURFACE
      ? ''
      : s === STATE.PROTECTED
      ? 'ON'
      : '!';
    const colour = s === STATE.PROTECTED ? '#1b7f3b' : '#a11';
    try {
      await action.setBadgeText({ text });
      if (text) await action.setBadgeBackgroundColor({ color: colour });
    } catch {
      /* the badge is cosmetic; never let it break reconciliation */
    }
  }

  /**
   * Wait briefly for a session credential.
   *
   * Called while the browser is holding a proxy challenge open. A revived
   * service worker has to reconnect to the bridge and be issued a token before
   * it can answer, and that takes a moment; the alternative to waiting is
   * answering wrongly and quickly. Returns null on timeout, which the caller
   * turns into a cancelled request -- fail closed, as everywhere else.
   */
  async waitForCredential(timeoutMs) {
    if (this.credential) return this.credential;
    if (!this.settings.armed) return null;
    if (!this.port) this.openHost();
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (this.credential) return this.credential;
      this.maybeRequestCredential();
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    return null;
  }

  // -- pairing ---------------------------------------------------------------

  async onPairing(msg) {
    if (msg.id && msg.id === this.pairingRequestId) this.pairingRequestId = '';
    this.pairing.flow = msg.state;
    this.pairing.code = msg.code;
    this.pairing.expiresAtMs = msg.expiresInSeconds ? Date.now() + msg.expiresInSeconds * 1000 : 0;
    if (msg.state === PAIRING_FLOW.APPROVED && msg.credential) {
      this.pairing.credential = msg.credential;
      // The host presents the credential itself from this moment on.
      this.pairingPresented = true;
      try {
        await this.adapter.saveSettings(STORAGE_KEY_PAIRING, { credential: msg.credential });
      } catch (e) {
        this.lastError = `the pairing works now but could not be saved: ${describe(e)}`;
      }
    }
    await this.reconcile();
  }

  /**
   * A running app that answers `unpaired` after acknowledging this browser's
   * credential has revoked it. Drop the copy here so the popup offers pairing
   * again instead of a control the app will refuse.
   */
  async notePairingStatus(msg) {
    const status = msg.status;
    if (msg.id && msg.id === this.pairingRequestId) {
      this.pairingRequestId = '';
      this.pairingPresented = true;
    }
    if (!this.pairingPresented || !this.pairing.credential) return;
    if (status.status === TUNNEL_STATUS.APP_NOT_RUNNING) return;
    if (status.pairing !== PAIRING_STATUS.UNPAIRED) return;
    await this.dropPairing();
  }

  async dropPairing() {
    this.pairing.credential = '';
    this.pairingPresented = false;
    try {
      await this.adapter.saveSettings(STORAGE_KEY_PAIRING, { credential: '' });
    } catch {
      /* the next status repeats the revocation */
    }
  }

  beginPairing() {
    if (!this.port || !this.status) return false;
    if (this.status.pairing === PAIRING_STATUS.UNSUPPORTED) return false;
    if (this.pairing.flow === PAIRING_FLOW.PENDING && this.pairing.expiresAtMs > Date.now()) {
      return true;
    }
    this.pairing.flow = '';
    this.pairing.code = '';
    this.pairingRequestId = this.nextId();
    this.send(request(this.pairingRequestId, REQUEST.PAIR_BEGIN));
    return true;
  }

  async forgetPairing() {
    if (this.port) this.send(request(this.nextId(), REQUEST.PAIR_FORGET));
    this.pairing.flow = '';
    this.pairing.code = '';
    await this.dropPairing();
    await this.reconcile();
    return this.snapshot();
  }

  // -- requests the user can make of the desktop app ------------------------

  /**
   * Connect or disconnect, for a paired browser. The first request from an
   * unpaired browser starts the in-app approval instead; it never reaches the
   * tunnel. Disconnecting turns off the app's kill switch, which is why it
   * needs exactly the same pairing as connecting.
   */
  requestTunnel(connect) {
    if (!this.status) return { sent: false, pairing: false };
    if (this.status.pairing !== PAIRING_STATUS.PAIRED) {
      return { sent: false, pairing: this.beginPairing() };
    }
    if (!this.status.canRequestConnect) return { sent: false, pairing: false };
    this.send(request(this.nextId(), connect ? REQUEST.REQUEST_CONNECT : REQUEST.REQUEST_DISCONNECT));
    return { sent: true, pairing: false };
  }

  // -- what the popup and the verification harness read ---------------------

  snapshot() {
    return {
      state: this.current.state,
      detail: this.current.detail,
      failClosed: this.current.failClosed,
      settings: this.settings,
      // The port is reported because a user may need it to diagnose a local
      // problem. The host is a loopback constant by construction and there is
      // no other address in this object, because there is no other address in
      // this extension.
      endpoint: this.current.endpoint ? { port: this.current.endpoint.port } : null,
      routingTransport: this.current.endpoint ? this.current.endpoint.kind : '',
      // Passed through from the desktop app, unmodified. The extension has no
      // view of the wire and does not guess -- in particular it never claims
      // Winn Protocol v3, which does not run on macOS or Windows at all.
      tunnelStatus: this.status ? this.status.status : '',
      tunnelDetail: this.status ? this.status.detail : '',
      winn: this.status ? this.status.winn : null,
      nodes: this.status ? this.status.nodes : [],
      uiLocale: this.status ? this.status.uiLocale : null,
      selectedSlug: this.status ? this.status.selectedSlug : '',
      canRequestConnect: this.status ? this.status.canRequestConnect : false,
      // Pairing with the desktop app. The credential itself never leaves the
      // background context; the popup sees only whether one is held.
      pairing: {
        status: this.status ? this.status.pairing : PAIRING_STATUS.UNSUPPORTED,
        flow: this.pairing.flow,
        code: this.pairing.flow === PAIRING_FLOW.PENDING ? this.pairing.code : '',
        expiresInMs: this.pairing.flow === PAIRING_FLOW.PENDING && this.pairing.expiresAtMs
          ? Math.max(0, this.pairing.expiresAtMs - Date.now())
          : 0,
        stored: Boolean(this.pairing.credential),
      },
      proxyReady: this.status ? this.status.proxyReady : false,
      hasCredential: Boolean(this.credential),
      canAuthenticate: this.canAuthenticate,
      routingSurface: this.routingSurface,
      authStats: this.adapter.authStats || null,
      privacy: this.privacy,
      routingMechanism: this.routingMechanism,
      // What the browser did with the two things this extension armed. These are
      // the inputs deriveState now reads, reported here as well so that a
      // failure is diagnosable from outside rather than only inferable from the
      // state it produced.
      blockLayer: {
        ok: this.blockLayer.ok,
        error: this.blockLayer.error,
        dropped: this.blockLayer.dropped || [],
      },
      routing: { ok: this.routing.ok, error: this.routing.error },
      proxyLevelOfControl: this.proxyLevelOfControl,
      incognitoAllowed: this.incognitoAllowed,
      incognitoRouting: this.adapter.incognitoRouting || null,
      statusAgeMs: this.statusAtMs ? Date.now() - this.statusAtMs : null,
      // THE HANDSHAKE, AS THREE NUMBERS RATHER THAN AS AN INFERENCE.
      //
      // `statusAgeMs` above is null both when the bridge has never spoken and
      // when it spoke rubbish, and those need telling apart from outside the
      // extension as much as inside it. These three do that without anyone
      // having to read `lastError` and guess: a port that has been open for
      // eleven seconds with three requests out and `hostAnswered: false` is a
      // host that was never running, and no other reading of those numbers
      // exists.
      hostAnswered: this.hostSpoke,
      hostOpenAgeMs: this.hostOpenedAtMs ? Date.now() - this.hostOpenedAtMs : null,
      requestsSent: this.requestsSent,
      lastError: this.lastError,
      browser: this.adapter.name,
      version: extensionVersion(),
    };
  }

  panicClear() {
    return this.runSettingsMutation(async () => {
      // The app forgets this browser too, while the port is still open.
      if (this.port && this.pairing.credential) this.send(request(this.nextId(), REQUEST.PAIR_FORGET));
      await this.adapter.clearStorage();
      this.pairing = { credential: '', flow: '', code: '', expiresAtMs: 0 };
      this.pairingPresented = false;
      this.reconcileGeneration += 1;
      this.reconcilePending = true;
      this.settings = defaultSettings();
      this.closeHost();
      await this.reconcile();
      return this.snapshot();
    });
  }
}

function chromiumNativeIdentityError(adapter) {
  if (!adapter || !CHROMIUM_ADAPTER_NAMES.has(adapter.name)) return '';
  if (typeof adapter.nativeMessagingIdentity !== 'function') {
    return 'this Chromium package did not expose its native-messaging identity; '
      + 'the bridge was not opened';
  }

  let identity;
  try {
    identity = adapter.nativeMessagingIdentity();
  } catch (e) {
    return `this Chromium package could not read its native-messaging identity: ${describe(e)}; `
      + 'the bridge was not opened';
  }

  if (!identity || typeof identity !== 'object' || Array.isArray(identity)) {
    return 'this Chromium package returned no usable native-messaging identity; '
      + 'the bridge was not opened';
  }

  let ok;
  let extensionId;
  let boundOrigin;
  try {
    ({ ok, extensionId, boundOrigin } = identity);
  } catch (e) {
    return `this Chromium package returned an unreadable native-messaging identity: ${describe(e)}; `
      + 'the bridge was not opened';
  }

  if (ok !== true) {
    return 'this Chromium package did not validate its native-messaging identity; '
      + 'the bridge was not opened';
  }
  if (typeof extensionId !== 'string' || !CHROMIUM_EXTENSION_ID_RE.test(extensionId)) {
    return 'this Chromium package returned a malformed native-messaging extension id; '
      + 'the bridge was not opened';
  }
  if (boundOrigin !== `chrome-extension://${extensionId}/`) {
    return 'this Chromium package returned a native-messaging origin that does not match its '
      + 'extension id exactly; the bridge was not opened';
  }
  return '';
}

function describe(e) {
  if (!e) return 'no reason given';
  return String(e && e.message ? e.message : e).slice(0, 200);
}

function extensionVersion() {
  try {
    return api.runtime.getManifest().version;
  } catch {
    return '0';
  }
}

export { ALARM_NAME, ALARM_PERIOD_MINUTES };
