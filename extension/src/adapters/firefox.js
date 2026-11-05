// Firefox: webRequest path, no certificate.
//
// RULING 2026-08-07: the certificate/TLS design does not ship. A visible CA
// trust bit may not enter the user Firefox, the app may not write into a
// Firefox profile (cert9.db survives uninstall), and the only Firefox trust
// flag that works creates a CA-classified record. webRequest is the approved
// alternative. This file implements it.
//
// WHAT CHANGED FROM THE TLS LANE:
//   * No proxyAuthorizationHeader, no type:'https', no requiresTlsProxy.
//   * The 407 is answered from webRequest.onAuthRequired, over plaintext, the
//     same mechanism Chromium uses. The hop is loopback, same gate, same token.
//   * The bridge reports no proxyTls; the state machine no longer branches on it.
//   * The extension carries no certificate material and writes no profile.
//
// -----------------------------------------------------------------------------
// WHAT IS ACTUALLY DIFFERENT ABOUT FIREFOX (remaining differences)
// -----------------------------------------------------------------------------
// 1. Background context. Firefox MV3 runs an event page, not a service worker.
// 2. proxy.onRequest vs proxy.settings: Firefox's per-request proxy API is the
//    functional product path when host permission is granted. The data: URL PAC
//    is containment for a permission-revocation race, not a reduced-function
//    mode: without host permission webRequest cannot answer the 407 challenge.
// 3. Host permissions are OPTIONAL in Firefox MV3; the adapter cannot assume them.
// 4. network.proxy.failover_direct makes the block layer load-bearing.

import { BaseAdapter, api, describeError } from './base.js';
import { PAC_FAIL_CLOSED, buildPac } from '../core/pac.js';
import { isInScope } from '../core/rules.js';
import { LOOPBACK_HOST, isLoopbackHost, validatePort } from '../core/endpoint.js';

// --- proxy auth scope (keep in lockstep with chromium.js) ---
export const WINS_PROXY_AUTH_SCHEME = 'basic';
export const WINS_PROXY_AUTH_REALM = 'wins-bridge';

export function challengerMatchesWinsProxy(details, credential) {
  if (!details || details.isProxy !== true) return false;
  if (!credential || !credential.endpoint || typeof credential.endpoint !== 'object') return false;
  const challenger = details.challenger;
  if (!challenger || typeof challenger !== 'object') return false;
  const host = challenger.host;
  const port = challenger.port;
  const scheme = details.scheme;
  const realm = details.realm;
  if (typeof host !== 'string' || host !== credential.endpoint.host) return false;
  if (!Number.isInteger(port) || !Number.isInteger(credential.endpoint.port)) return false;
  if (port !== credential.endpoint.port) return false;
  if (scheme !== WINS_PROXY_AUTH_SCHEME) return false;
  if (realm !== WINS_PROXY_AUTH_REALM) return false;
  return true;
}

export function proxyAuthDecision(details, credential) {
  if (!details || details.isProxy !== true) return { action: 'ignore' };
  if (credential && credential.endpoint) {
    if (!challengerMatchesWinsProxy(details, credential)) return { action: 'ignore' };
    if (credential.token) {
      return {
        action: 'answer',
        authCredentials: { username: 'extension', password: credential.token },
      };
    }
    return { action: 'cancel' };
  }
  if (
    details.scheme === WINS_PROXY_AUTH_SCHEME &&
    details.realm === WINS_PROXY_AUTH_REALM &&
    details.challenger &&
    details.challenger.host === '127.0.0.1'
  ) {
    return { action: 'cancel' };
  }
  return { action: 'ignore' };
}
// --- end proxy auth scope ---

const RELINQUISHED_PROXY_SETTING_LEVELS = new Set([
  'controllable_by_this_extension',
  'controlled_by_other_extensions',
  'not_controllable',
]);

export class FirefoxAdapter extends BaseAdapter {
  constructor() {
    super('firefox');
    this._onRequest = null;
    this._primedOnRequest = null;
    this._live = { settings: null, endpoint: null };
    this.routingMechanism = 'none';
    this._credential = null;
    this._credentialGeneration = 0;
    this._answeredRequestIds = new Map();
    this._authListener = null;
    this._settingsPacUrl = '';
    // webRequest counters use the same evidence fields as Chromium. `sink` and
    // `direct` remain mechanism diagnostics rather than authentication claims.
    this.authStats = {
      seen: 0,
      proxy: 0,
      answered: 0,
      cancelled: 0,
      credentialsAnswered: 0,
      credentialsMissing: 0,
      credentialsRejected: 0,
      sink: 0,
      direct: 0,
    };
  }

  setCredential(credential) {
    const token = credential && credential.token ? credential.token : '';
    const previous = this._credential && this._credential.token ? this._credential.token : '';
    this._credential = credential || null;
    if (token !== previous) {
      this._credentialGeneration += 1;
      this._answeredRequestIds.clear();
      this.authStats.credentialsMissing = 0;
      this.authStats.credentialsRejected = 0;
    }
  }

  /**
   * MUST BE CALLED SYNCHRONOUSLY FROM THE TOP LEVEL OF THE BACKGROUND SCRIPT.
   * Firefox's event page is non-persistent; a listener added at runtime belongs
   * only to the generation that added it. See chromium.js for the same rule.
   * @param {() => Promise<object|null>} resolveCredential
   */
  installProxyAuth(resolveCredential) {
    if (this._authListener || !api.webRequest || !api.webRequest.onAuthRequired) return false;
    this._authListener = (details, callback) => {
      this.authStats.seen += 1;
      if (!details.isProxy) {
        callback({});
        return;
      }
      this.authStats.proxy += 1;
      const generation = this._credentialGeneration;
      Promise.resolve()
        .then(resolveCredential)
        .then((credential) => {
          // A disconnect or reconnect can replace credentials while the
          // resolver waits. Only the current generation may answer a 407.
          const active = generation === this._credentialGeneration
            ? credential || this._credential
            : this._credential;
          const decision = proxyAuthDecision(details, active);
          if (decision.action === 'answer') {
            if (this._challengeRepeatsRejectedCredential(details)) {
              this.authStats.cancelled += 1;
              this.authStats.credentialsRejected += 1;
              callback({ cancel: true });
              return;
            }
            this.authStats.answered += 1;
            this.authStats.credentialsAnswered += 1;
            this._rememberAnsweredChallenge(details);
            callback({ authCredentials: decision.authCredentials });
            return;
          }
          if (decision.action === 'cancel') {
            this.authStats.cancelled += 1;
            this.authStats.credentialsMissing += 1;
            callback({ cancel: true });
            return;
          }
          callback({});
        })
        .catch(() => callback({ cancel: true }));
    };
    try {
      api.webRequest.onAuthRequired.addListener(
        this._authListener,
        { urls: ['<all_urls>'] },
        ['asyncBlocking'],
      );
      return true;
    } catch (e) {
      this._authListener = null;
      this.authError = describeError(e);
      return false;
    }
  }

  _challengeRepeatsRejectedCredential(details) {
    return details?.requestId !== undefined
      && this._answeredRequestIds.get(String(details.requestId)) === this._credentialGeneration;
  }

  _rememberAnsweredChallenge(details) {
    if (details?.requestId === undefined) return;
    const id = String(details.requestId);
    this._answeredRequestIds.set(id, this._credentialGeneration);
    if (this._answeredRequestIds.size > 256) {
      this._answeredRequestIds.delete(this._answeredRequestIds.keys().next().value);
    }
  }

  removeProxyAuth() {
    if (!this._authListener) return;
    try {
      api.webRequest.onAuthRequired.removeListener(this._authListener);
    } catch { /* was not installed */ }
    this._authListener = null;
  }

  async canAuthenticate() {
    if (!this._authListener || !api.webRequest || !api.webRequest.onAuthRequired) return false;
    try {
      return await api.permissions.contains({
        permissions: ['webRequest', 'webRequestAuthProvider'],
        origins: ['<all_urls>'],
      });
    } catch {
      return false;
    }
  }

  async hasHostPermission() {
    try {
      return await api.permissions.contains({ origins: ['<all_urls>'] });
    } catch {
      return false;
    }
  }

  async applyRouting(settings, endpoint) {
    this._live = { settings, endpoint };
    if (await this.hasHostPermission()) {
      this._installOnRequest();
      this.routingMechanism = 'onRequest';
      await this._clearSettings();
      return 'onRequest';
    }
    // Permission can be revoked between state derivation and this call. Keep
    // in-scope traffic pointed at the authenticated local proxy with no DIRECT
    // fallback. It will fail authentication closed until the next reconcile
    // removes routing and leaves the block layer in control.
    this._removeOnRequest();
    await this._setPacViaSettings(settings, endpoint);
    this.routingMechanism = 'settings';
    return 'settings';
  }

  /**
   * MUST BE CALLED SYNCHRONOUSLY FROM THE TOP LEVEL OF THE BACKGROUND SCRIPT.
   *
   * The single proxy.onRequest registration for the life of the event page.
   * Routing decisions are delegated to the live `_onRequest` decider when
   * routing is installed; before init() has finished, or while the controller
   * holds no route, an armed profile's in-scope request goes to the dead
   * loopback sink instead of leaving directly.
   *
   * @param {() => Promise<object>} resolveSettings  resolves the sanitised
   *   settings once the controller has initialised
   */
  installPrimedRouting(resolveSettings) {
    if (this._primedOnRequest || !api.proxy || !api.proxy.onRequest) return false;
    this._primedOnRequest = async (requestInfo) => {
      let settings = null;
      try {
        settings = await resolveSettings();
      } catch {
        settings = null;
      }
      if (this._onRequest) return this._onRequest(requestInfo);
      if (settings && settings.armed !== true) return { type: 'direct' };
      try {
        const host = new URL(requestInfo.url).hostname.toLowerCase().replace(/\.$/, '');
        if (settings && !isInScope(settings, host)) {
          this.authStats.direct += 1;
          return { type: 'direct' };
        }
      } catch {
        /* unparseable URL: sink below */
      }
      this.authStats.sink += 1;
      return [{ type: 'http', host: LOOPBACK_HOST, port: 1 }, null];
    };
    api.proxy.onRequest.addListener(this._primedOnRequest, { urls: ['<all_urls>'] });
    return true;
  }

  _activeOnRequestListener() {
    return this._primedOnRequest || this._onRequest;
  }

  _installOnRequest() {
    if (this._onRequest) return;
    this._onRequest = (requestInfo) => {
      try {
        const host = new URL(requestInfo.url).hostname.toLowerCase().replace(/\.$/, '');
        const { settings, endpoint } = this._live;
        if (!settings || !endpoint
          || !isLoopbackHost(endpoint.host) || !validatePort(endpoint.port)) {
          this.authStats.sink += 1;
          return [{ type: 'http', host: LOOPBACK_HOST, port: 1 }, null];
        }
        if (!isInScope(settings, host)) {
          this.authStats.direct += 1;
          return { type: 'direct' };
        }
        // Plaintext HTTP proxy; authentication is via webRequest, not header.
        return [{ type: 'http', host: endpoint.host, port: endpoint.port }, null];
      } catch (e) {
        this.authStats.sink += 1;
        return [{ type: 'http', host: LOOPBACK_HOST, port: 1 }, null];
      }
    };
    if (!this._primedOnRequest) {
      api.proxy.onRequest.addListener(this._onRequest, { urls: ['<all_urls>'] });
    }
  }

  _removeOnRequest() {
    if (!this._onRequest) return;
    if (!this._primedOnRequest) {
      try {
        api.proxy.onRequest.removeListener(this._onRequest);
      } catch { /* was not installed */ }
    }
    this._onRequest = null;
  }

  async _setPacViaSettings(settings, endpoint) {
    // Round 37 cross-examination: an invalid endpoint must not leave the
    // browser unproxied. Fail closed to a dead loopback proxy instead.
    let pac;
    try {
      pac = buildPac(settings, endpoint);
    } catch {
      pac = PAC_FAIL_CLOSED;
    }
    const url = `data:application/x-ns-proxy-autoconfig;base64,${btoa(pac)}`;
    await api.proxy.settings.set({ value: { proxyType: 'autoConfig', autoConfigUrl: url } });
    this._settingsPacUrl = url;
  }

  async _clearSettings() {
    // BrowserSetting.clear() reports whether the call changed the active
    // setting. A fresh profile with no value from this extension returns false,
    // as can a precedence change or a preference race. The post-state is the
    // authority; an absent or unknown readback remains a hard failure.
    const cleared = await api.proxy.settings.clear({});
    if (cleared !== true && cleared !== false) {
      throw new Error('Firefox returned an invalid proxy.settings.clear result');
    }
    const got = await api.proxy.settings.get({});
    const level = got?.levelOfControl;
    if (!RELINQUISHED_PROXY_SETTING_LEVELS.has(level)) {
      throw new Error(
        `Firefox proxy.settings was not verifiably relinquished after clear (${String(level)})`,
      );
    }
    // Firefox can drop the settings-store record, detect that its preferences
    // changed concurrently, and decline to rewrite them. In that case the level
    // is no longer ours even though the exact PAC bytes we wrote remain live.
    if (
      this._settingsPacUrl
      && got?.value?.proxyType === 'autoConfig'
      && got.value.autoConfigUrl === this._settingsPacUrl
    ) {
      throw new Error("Firefox retained this extension's proxy.settings PAC after clear");
    }
    this._settingsPacUrl = '';
  }

  async clearRouting() {
    await this._clearSettings();
    this._removeOnRequest();
    this._live = { settings: null, endpoint: null };
    this.routingMechanism = 'none';
  }

  async installFailClosedSink() {
    this._live = { settings: null, endpoint: null };
    this._installOnRequest();
    if (!this._onRequest || !api.proxy.onRequest.hasListener(this._activeOnRequestListener())) {
      throw new Error('Firefox did not retain the fail-closed proxy listener');
    }
    this.routingMechanism = 'onRequest-sink';
  }

  /**
   * A live onRequest decider, or a proxy.settings value this extension still
   * owns (the PAC written without host permission persists across an event-page
   * suspension), is routing that a teardown must block first. A failed read
   * answers true, the conservative side.
   */
  async holdsRouting() {
    if (this._onRequest) return true;
    try {
      const got = await api.proxy.settings.get({});
      return got?.levelOfControl === 'controlled_by_this_extension';
    } catch {
      return true;
    }
  }

  async proxyLevelOfControl() {
    if (this._onRequest) {
      try {
        return api.proxy.onRequest.hasListener(this._activeOnRequestListener())
          ? 'controlled_by_this_extension'
          : 'unknown';
      } catch {
        return 'unknown';
      }
    }
    try {
      const got = await api.proxy.settings.get({});
      return got?.levelOfControl || 'unknown';
    } catch {
      return 'unknown';
    }
  }

  async applyPrivacyProtections() {
    const webrtcSet = await api.privacy.network.webRTCIPHandlingPolicy.set({ value: 'proxy_only' });
    const webrtc = await api.privacy.network.webRTCIPHandlingPolicy.get({});
    if (webrtcSet !== true || webrtc?.value !== 'proxy_only'
      || webrtc?.levelOfControl !== 'controlled_by_this_extension') {
      throw new Error('Firefox WebRTC protection did not take effect');
    }
    const predictionSet = await api.privacy.network.networkPredictionEnabled.set({ value: false });
    const prediction = await api.privacy.network.networkPredictionEnabled.get({});
    if (predictionSet !== true || prediction?.value !== false
      || prediction?.levelOfControl !== 'controlled_by_this_extension') {
      throw new Error('Firefox network prediction remained enabled');
    }
    return { webrtc: 'applied', prediction: 'applied' };
  }

  async releasePrivacyProtections() {
    for (const setting of ['webRTCIPHandlingPolicy', 'networkPredictionEnabled']) {
      try {
        await api.privacy.network[setting].clear({});
      } catch { /* not ours */ }
    }
  }

  async describeProxyState() {
    const out = { mechanism: this.routingMechanism };
    try {
      const got = await api.proxy.settings.get({});
      out.proxyType = got?.value?.proxyType || null;
      out.levelOfControl = got?.levelOfControl || null;
    } catch (e) {
      out.error = describeError(e);
    }
    return out;
  }
}
