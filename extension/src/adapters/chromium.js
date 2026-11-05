// Chrome and Microsoft Edge.
//
// Edge is Chromium with a different brand string; every API used here behaves
// identically on both, and the build emits two packages only so that the store
// listings, the extension ids and the native-messaging manifest paths can
// differ. Both were run.

import { BaseAdapter, api, describeError } from './base.js';
import { PAC_FAIL_CLOSED, buildPac } from '../core/pac.js';

export const CHROMIUM_PROXY_CONTROL_LEVELS = new Set([
  'not_controllable',
  'controlled_by_other_extensions',
  'controllable_by_this_extension',
  'controlled_by_this_extension',
]);

export function normaliseChromiumProxyControlLevel(level) {
  return CHROMIUM_PROXY_CONTROL_LEVELS.has(level) ? level : 'unknown';
}

// --- proxy auth scope (keep in lockstep with firefox.js) ---
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

// --- native-messaging identity (keep in lockstep with base.js/controller.js) ---
//
// A Chromium extension is identified to the native-messaging host by its
// extension id, and the host manifest's `allowed_origins` must name exactly
// `chrome-extension://<id>/` for the browser to launch the bridge for THIS
// extension. The browser enforces that match, but nothing on this side has
// ever READ its own id to confirm the origin it is bound under, so a package
// loaded under an id the host manifest does not name would arm silently and
// then never get a reply. These helpers let the adapter read the runtime id
// and state the exact origin the host must name, fail-closed: a malformed or
// absent id yields null/false so the caller can refuse to arm rather than
// wait on a bridge that was never permitted to run for it.
//
// The store issues the id; this tree never invents one. The shape is the same
// 32 lowercase [a-p] letters the store and the unpacked loader both derive,
// and it is the exact shape tools/native_messaging/check_host_manifests.py
// validates the recorded store-listing id against.
export const CHROMIUM_EXTENSION_ID_RE = /^[a-p]{32}$/;

export function isChromiumExtensionId(id) {
  return typeof id === 'string' && CHROMIUM_EXTENSION_ID_RE.test(id);
}

export function chromiumAllowedOrigin(extensionId) {
  if (!isChromiumExtensionId(extensionId)) return null;
  return `chrome-extension://${extensionId}/`;
}

/**
 * True only when the host manifest `allowed_origins` entry is EXACTLY the
 * extension-scoped origin this package binds, with the trailing slash and no
 * wildcard. An entry naming another extension id, a pattern, or a bare
 * `chrome-extension://<id>` without the slash is not an identity match.
 */
export function nativeHostOriginMatches(extensionId, origin) {
  const expected = chromiumAllowedOrigin(extensionId);
  if (expected === null) return false;
  return typeof origin === 'string' && origin === expected;
}
// --- end native-messaging identity ---

export class ChromiumAdapter extends BaseAdapter {
  constructor(name) {
    super(name);
    // The proxy token, in memory only, for the lifetime of this background
    // context. It is never written to storage. The desktop side reissues one
    // per native-messaging session precisely so that no side has to persist it,
    // on the assumption that a seized device's browser profile is readable.
    this._credential = null;
    this._credentialGeneration = 0;
    this._answeredRequestIds = new Map();
    this._authListener = null;
    this.incognitoRouting = { required: false, ok: null, error: '' };
    // Counters, not content. They are what the options page uses to tell a user
    // "the desktop app asked for a key N times and this browser answered M" --
    // the difference between "wrong key" and "never asked" is the difference
    // between two completely different problems, and without these it is
    // invisible from outside.
    //
    // `credentialsMissing` and `credentialsRejected` are the evidence the state
    // machine reads. A first answer proves only that the challenge arrived;
    // repeating the same request id proves the proxy rejected that answer.
    this.authStats = {
      seen: 0,
      proxy: 0,
      answered: 0,
      cancelled: 0,
      credentialsAnswered: 0,
      credentialsMissing: 0,
      credentialsRejected: 0,
    };
  }

  setCredential(credential) {
    const token = credential && credential.token ? credential.token : '';
    const previous = this._credential && this._credential.token ? this._credential.token : '';
    this._credential = credential || null;
    // A newly issued key makes the refusals that came before it obsolete. See
    // the same note in firefox.js.
    if (token !== previous) {
      this._credentialGeneration += 1;
      this._answeredRequestIds.clear();
      this.authStats.credentialsMissing = 0;
      this.authStats.credentialsRejected = 0;
    }
  }

  // -- proxy authentication -------------------------------------------------
  //
  // The desktop proxy answers an unauthenticated CONNECT with 407 and
  // `Proxy-Authenticate: Basic realm="wins-bridge"`. Answering that challenge is
  // the only reason this extension asks for webRequest at all, and the
  // permission that makes it possible in MV3 is `webRequestAuthProvider`, which
  // exists for exactly this.
  //
  // The listener answers ONLY when the challenger exactly matches the active
  // Wins proxy host, port, scheme, and realm. An arbitrary 407 -- another
  // proxy, another port, Digest, a different realm -- must not receive the
  // session token. When it has no token for a challenge that is ours, it
  // CANCELS rather than falling through. A fall-through would let the browser
  // show a password box, and a user typing something into it is a user being
  // trained to hand credentials to a prompt.

  /**
   * MUST BE CALLED SYNCHRONOUSLY FROM THE TOP LEVEL OF THE BACKGROUND SCRIPT.
   *
   * This was originally called from applyRouting, and it did not work. The
   * listener registered, hasListener() returned true, and the event was never
   * delivered: an MV3 service worker is terminated when idle, and a webRequest
   * listener added at runtime belongs only to the service-worker generation
   * that added it. It also cannot wake a terminated worker. The symptom was the
   * desktop proxy logging challenge after challenge with no credentials ever
   * arriving, and the browser giving up with ERR_TOO_MANY_RETRIES -- a failure
   * that looks exactly like a wrong password and is not one.
   *
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
      // asyncBlocking, because on a revived worker the credential has to be
      // re-established from the bridge before the challenge can be answered.
      // The browser holds the request meanwhile, which is the correct place for
      // the wait: the alternative is answering wrongly and fast.
      Promise.resolve()
        .then(resolveCredential)
        .then((credential) => {
          const active = credential || this._credential;
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
            // The username is ignored by the desktop proxy; the token is the
            // secret. Reached only after the challenger matched the active
            // Wins host, port, scheme, and realm.
            callback({ authCredentials: decision.authCredentials });
            return;
          }
          if (decision.action === 'cancel') {
            this.authStats.cancelled += 1;
            this.authStats.credentialsMissing += 1;
            // Cancel rather than fall through. Falling through lets the browser
            // put a password box in front of the user, and a user typing
            // something into a box that appeared because their VPN broke is a
            // user being trained to hand credentials to prompts.
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
    } catch {
      /* was not installed */
    }
    this._authListener = null;
  }

  async canAuthenticate() {
    if (!api.webRequest || !api.webRequest.onAuthRequired) return false;
    try {
      // The origins check is the one that actually matters, and it was found by
      // running it rather than by reading about it. Chromium delivers a
      // webRequest event only for a URL the extension has host access to, so
      // with `optional_host_permissions` ungranted the listener registers
      // successfully, reports hasListener() true, and is simply never called.
      // The observable symptom is the desktop proxy logging challenge after
      // challenge with no credentials ever arriving, and the browser giving up
      // with ERR_INVALID_AUTH_CREDENTIALS. Checking only the API permissions
      // here would have made the extension believe it could authenticate when
      // it could not, and it would have gone to PROTECTED while nothing loaded.
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

  /**
   * The native-messaging identity this package is running under, read from the
   * browser at runtime.
   *
   * Returns fail-closed: when the runtime id is absent or not a well-formed
   * Chromium extension id, `ok` is false and `boundOrigin` is null. A caller
   * that wants to be certain the bridge it is about to connect to is permitted
   * to launch for this extension can refuse to arm on `ok === false` rather
   * than silently wait on a host whose allowed_origins never named this id.
   */
  nativeMessagingIdentity() {
    let extensionId = '';
    try {
      extensionId = api.runtime.id;
    } catch {
      extensionId = '';
    }
    if (!isChromiumExtensionId(extensionId)) {
      return { ok: false, extensionId: extensionId || null, boundOrigin: null };
    }
    return {
      ok: true,
      extensionId,
      boundOrigin: chromiumAllowedOrigin(extensionId),
    };
  }

  // There is deliberately no requestHostPermission() here any more.
  //
  // The Firefox run proved the message-to-the-background indirection cannot
  // complete a grant on that browser. Chromium was then measured rather than
  // assumed to behave the same way, and it does NOT: Chrome 151 accepts
  // permissions.request() from a service worker's message handler and puts up
  // its bubble. So this browser did not have that defect.
  //
  // The indirection went anyway. It bought nothing here, it was the defect on
  // the other browser, and a shared options page that has to branch on which
  // browser will honour a user gesture is a shape nobody should have to
  // maintain. The request is made in the click handler; see options.js.

  // -- routing --------------------------------------------------------------

  async applyRouting(settings, endpoint) {
    // Round 37 cross-examination: an invalid endpoint must not leave the
    // browser unproxied on first run. Fail closed to a dead loopback proxy.
    let pac;
    try {
      pac = buildPac(settings, endpoint);
    } catch {
      pac = PAC_FAIL_CLOSED;
    }
    const value = {
      mode: 'pac_script',
      pacScript: {
        data: pac,
        // `mandatory: true` tells Chromium not to fall back to a direct
        // connection if the PAC script fails to parse or run. Without it, a
        // malformed script silently becomes DIRECT -- the fail-open path this
        // extension exists to close. The generated script is also wrapped in
        // try/catch for the same reason: two independent guards, because this
        // is the property everything else depends on.
        mandatory: true,
      },
    };
    await this._setAndVerifyProxyValue(value);
    return 'pac';
  }

  async clearRouting() {
    // The auth listener is deliberately NOT removed here. It is registered once
    // at top level for the life of the background script, and it answers only
    // when a credential exists; with none, it cancels. Removing and re-adding it
    // around every state change would put it back in the runtime-registration
    // trap this comment block exists to record.
    // clear() hands the setting back to whatever owned it before this extension
    // did, rather than pinning it to DIRECT. Pinning would leave the browser
    // configured by an extension that has been switched off, which is its own
    // small dishonesty.
    await this._forEachScope(async ({ scope, query }) => {
      // Read the control level of THIS scope: policy can own the incognito
      // setting and not the regular one, and the guard below must judge the
      // scope whose clear it is excusing.
      let controlBeforeClear = 'unknown';
      try {
        controlBeforeClear = normaliseChromiumProxyControlLevel(
          (await api.proxy.settings.get(query))?.levelOfControl,
        );
      } catch {
        /* unknown: a failed clear below is then reported, never excused */
      }
      try {
        await api.proxy.settings.clear({ scope });
      } catch (e) {
        // Microsoft Edge policy can make proxy settings not controllable and can
        // reject even a request to relinquish this extension's stored value. The
        // value is not effective while policy owns the setting, and the controller
        // keeps the fail-closed block in place. The controller retries the clear
        // on later reconciliation, including after policy changes. Any other clear
        // failure is real and must still reach the controller.
        if (controlBeforeClear !== 'not_controllable') throw e;
      }
      const got = await api.proxy.settings.get(query);
      if (got?.levelOfControl === 'controlled_by_this_extension') {
        throw new Error(`proxy scope ${scope} remained controlled after clear`);
      }
    }, { routing: true });
  }

  async _forEachScope(fn, { routing = false, regularSinkOnUnknown = false } = {}) {
    const incognitoAllowed = await this.isAllowedIncognitoAccess();
    if (incognitoAllowed === null) {
      const error = 'private-window permission could not be verified';
      this.incognitoRouting = { required: null, ok: false, error };
      if (regularSinkOnUnknown) {
        await fn({ scope: 'regular', query: { incognito: false } });
      }
      throw new Error(error);
    }
    if (routing) {
      this.incognitoRouting = { required: incognitoAllowed, ok: incognitoAllowed ? null : false, error: '' };
    }
    await fn({ scope: 'regular', query: { incognito: false } });
    if (incognitoAllowed) {
      try {
        await fn({ scope: 'incognito_persistent', query: { incognito: true } });
        if (routing) this.incognitoRouting = { required: true, ok: true, error: '' };
      } catch (e) {
        if (routing) this.incognitoRouting = { required: true, ok: false, error: describeError(e) };
        throw e;
      }
    }
  }

  async _setAndVerifyProxyValue(value, { regularSinkOnUnknown = false } = {}) {
    await this._forEachScope(async ({ scope, query }) => {
      await api.proxy.settings.set({ value, scope });
      const got = await api.proxy.settings.get(query);
      if (!chromiumProxyValueMatches(got, value)) {
        throw new Error(`proxy scope ${scope} readback differed from the requested PAC`);
      }
    }, { routing: true, regularSinkOnUnknown });
  }

  async installFailClosedSink() {
    await this._setAndVerifyProxyValue({
      mode: 'pac_script',
      pacScript: {
        data: 'function FindProxyForURL(){return "PROXY 127.0.0.1:1";}',
        mandatory: true,
      },
    }, { regularSinkOnUnknown: true });
    return 'pac-sink';
  }

  /**
   * True when ANY scope this extension could own still reports
   * controlled_by_this_extension. The folded answer from proxyLevelOfControl
   * is not enough here: it says `controllable` when only the regular scope is
   * still ours, and a teardown of that scope still needs its block. Unknown
   * permission state or a failed read answers true, the conservative side.
   */
  async holdsRouting() {
    const incognitoAllowed = await this.isAllowedIncognitoAccess();
    if (incognitoAllowed === null) return true;
    const queries = [{ incognito: false }];
    if (incognitoAllowed) queries.push({ incognito: true });
    for (const query of queries) {
      let level;
      try {
        level = normaliseChromiumProxyControlLevel(
          (await api.proxy.settings.get(query))?.levelOfControl,
        );
      } catch {
        return true;
      }
      if (level === 'controlled_by_this_extension' || level === 'unknown') return true;
    }
    return false;
  }

  async proxyLevelOfControl() {
    const levels = [];
    try {
      const got = await api.proxy.settings.get({ incognito: false });
      levels.push(normaliseChromiumProxyControlLevel(got?.levelOfControl));
    } catch {
      levels.push('unknown');
    }
    const incognitoAllowed = await this.isAllowedIncognitoAccess();
    if (incognitoAllowed === null) {
      this.incognitoRouting = {
        required: null, ok: false, error: 'private-window permission could not be verified',
      };
      return 'unknown';
    }
    this.incognitoRouting = { required: incognitoAllowed, ok: false, error: '' };
    if (incognitoAllowed) {
      try {
        const got = await api.proxy.settings.get({ incognito: true });
        const level = normaliseChromiumProxyControlLevel(got?.levelOfControl);
        levels.push(level);
        this.incognitoRouting = {
          required: true,
          ok: level === 'controlled_by_this_extension',
          error: level === 'controlled_by_this_extension' ? '' : `incognito proxy control is ${level}`,
        };
      } catch (e) {
        levels.push('unknown');
        this.incognitoRouting = { required: true, ok: false, error: describeError(e) };
      }
    }
    // Every enabled scope must be owned before the controller can claim routing.
    for (const level of ['not_controllable', 'controlled_by_other_extensions', 'unknown']) {
      if (levels.includes(level)) return level;
    }
    return levels.every(level => level === 'controlled_by_this_extension')
      ? 'controlled_by_this_extension' : 'controllable_by_this_extension';
  }

  // -- privacy --------------------------------------------------------------

  async applyPrivacyProtections() {
    const result = { webrtc: 'unsupported', prediction: 'unsupported' };

    // WebRTC opens its own UDP connections, and those do not follow the proxy
    // setting. A page can therefore learn this computer's real address while
    // every HTTP request is being routed. `disable_non_proxied_udp` is the only
    // value that stops it; the two `default_public*` values reduce what is
    // exposed but still permit non-proxied UDP.
    await this._forEachScope(async ({ scope, query }) => {
      const setting = api.privacy.network.webRTCIPHandlingPolicy;
      await setting.set({ value: 'disable_non_proxied_udp', scope });
      const got = await setting.get(query);
      if (got?.value !== 'disable_non_proxied_udp'
          || got?.levelOfControl !== 'controlled_by_this_extension') {
        throw new Error(`WebRTC protection did not take effect in ${scope}`);
      }
    });
    result.webrtc = 'applied';

    // Network prediction is the browser speculatively resolving names and
    // opening connections for links it thinks might be clicked. Those happen
    // before any routing decision for a navigation the user has not committed
    // to, so they are a name-lookup leak with no benefit here.
    await this._forEachScope(async ({ scope, query }) => {
      const setting = api.privacy.network.networkPredictionEnabled;
      await setting.set({ value: false, scope });
      const got = await setting.get(query);
      if (got?.value !== false || got?.levelOfControl !== 'controlled_by_this_extension') {
        throw new Error(`network prediction remained enabled in ${scope}`);
      }
    });
    result.prediction = 'applied';

    return result;
  }

  async releasePrivacyProtections() {
    for (const setting of ['webRTCIPHandlingPolicy', 'networkPredictionEnabled']) {
      await this._forEachScope(async ({ scope }) => {
        await api.privacy.network[setting].clear({ scope });
      });
    }
  }
}

export function chromiumProxyValueMatches(readBack, expected) {
  if (readBack?.levelOfControl !== 'controlled_by_this_extension') return false;
  const actual = readBack?.value;
  return actual?.mode === expected.mode
    && actual?.pacScript?.data === expected.pacScript.data
    && actual?.pacScript?.mandatory === expected.pacScript.mandatory;
}
