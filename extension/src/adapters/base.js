// Shared adapter behaviour.
//
// The split between core, adapters and background is:
//   core/      pure logic, no browser API, unit-testable in plain JS
//   adapters/  the only place a browser API is touched
//   background/ orchestration, one file, identical on all three targets
//
// Everything that is genuinely the same across Chrome, Edge and Firefox lives
// here. The two subclasses hold only the differences that are real, and each of
// those differences is commented with what it is and why it exists: otherwise
// an adapter becomes a place where "it's different on Firefox" accumulates
// without anyone checking whether it still is.

import { allRuleIds } from '../core/blockrules.js';
import {
  DNR_ESSENTIAL_RESOURCE_TYPES,
  DNR_PRIORITY_BLOCK,
  DNR_PROBE_RULE_ID,
  DNR_RESOURCE_TYPES,
} from '../core/constants.js';

/** The WebExtension namespace. Firefox exposes promise-based `browser`; */
/** Chrome and Edge expose `chrome`, which is promise-based under MV3. */
export const api = typeof globalThis.browser !== 'undefined' && globalThis.browser?.runtime
  ? globalThis.browser
  : globalThis.chrome;

// A negotiation is not re-run more often than this while it is failing. The
// failure is already visible as a state and is retried on the heartbeat; there
// is no reason to spend sixteen round trips every ten seconds establishing the
// same answer.
const RENEGOTIATE_AFTER_MS = 30_000;

export class BaseAdapter {
  constructor(name) {
    this.name = name;
    // The negotiated block-layer resource types, and the record of how the
    // browser answered. Null until the first negotiation.
    this._blockTypes = null;
    this._blockTypesAt = 0;
    this.blockTypesDropped = [];
    this.blockTypesError = '';
    // Both concrete adapters overwrite this with real counters. The state
    // machine reads only proven missing or rejected credential events. Merely
    // answering a 407 is not recorded as successful authentication.
    this.authStats = null;
  }

  // -- storage --------------------------------------------------------------
  //
  // Only the user's own routing preferences are stored. Assume this profile can
  // be read off a seized machine: there are no credentials here, no account
  // identifier, no token, no server or node data, and no record of which sites
  // were actually visited or routed.

  async loadSettings(key) {
    const got = await api.storage.local.get(key);
    return got ? got[key] : undefined;
  }

  async saveSettings(key, value) {
    await api.storage.local.set({ [key]: value });
  }

  async clearStorage() {
    await api.storage.local.clear();
  }

  // -- native messaging -----------------------------------------------------

  /**
   * Open the native-messaging port, and report the failure the browser reports.
   *
   * THE PREVIOUS VERSION OF THIS METHOD THREW AWAY THE ONLY EVIDENCE THERE WAS.
   * The disconnect listener took no argument, so `port.error` -- which is where
   * Firefox puts the reason, and the ONLY place it puts it -- could not be read
   * at all. It then asserted "the bridge closed the connection" whenever
   * `runtime.lastError` was absent, which on Firefox is always, and which says a
   * connection existed even when nothing was ever launched. Two different
   * failures, one sentence, and the sentence was wrong for one of them.
   *
   * Both fields are read now, because the two engines disagree about which one
   * exists and neither documents the other's:
   *   Firefox  -> `port.error`, an object with a `message`.
   *   Chromium -> `runtime.lastError`, valid only INSIDE this callback.
   *
   * And when neither says anything, that is reported as what it is rather than
   * dressed up: whether the host had ever spoken is the difference between a
   * bridge that died and a bridge that never started, and the caller is told
   * which.
   */
  connectNative(hostName, { onMessage, onDisconnect }) {
    let port;
    try {
      port = api.runtime.connectNative(hostName);
    } catch (e) {
      // No host manifest installed, or the browser refused to launch it. This
      // is the ordinary state on a machine where the desktop app has not been
      // installed, and it must degrade to a visible disconnected state rather
      // than to anything that resembles working.
      onDisconnect(`this browser would not open the bridge: ${describeError(e)}`);
      return null;
    }
    let heard = false;
    port.onMessage.addListener((message) => {
      heard = true;
      onMessage(message);
    });
    port.onDisconnect.addListener((disconnected) => {
      const reported = describePortFailure(disconnected);
      // WHETHER IT EVER SPOKE DECIDES THE SENTENCE, NOT WHETHER THERE IS A
      // REASON. "Native host has exited" is the same string for a bridge that
      // ran for an hour and for one that could not start, and the two need
      // different remedies -- so the browser's reason is APPENDED to the fact
      // this adapter established itself rather than replacing it.
      if (heard) {
        onDisconnect(reported
          ? `the bridge answered and then stopped: ${reported}`
          : 'the bridge answered and then closed the connection');
      } else {
        onDisconnect(reported
          ? `the browser could not run the bridge: ${reported}`
          : 'the browser started the bridge, it stopped without answering once, '
            + 'and the browser reported no reason');
      }
    });
    return port;
  }

  // -- fail-closed block layer ----------------------------------------------

  async setBlockRules(rules) {
    // Every id this extension may ever use is removed first, so the rule set is
    // fully replaced rather than merged. A merge would let an orphaned block
    // rule from an earlier configuration survive a settings change.
    await api.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: allRuleIds(),
      addRules: rules,
    });
    const readBack = await api.declarativeNetRequest.getDynamicRules();
    const expected = normaliseDynamicRules(rules);
    const actual = normaliseDynamicRules(Array.isArray(readBack) ? readBack : []);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      throw new Error(
        `dynamic block-rule readback differed: expected ${JSON.stringify(expected)}, `
          + `got ${JSON.stringify(actual)}`,
      );
    }
  }

  async getBlockRuleCount() {
    const rules = await api.declarativeNetRequest.getDynamicRules();
    return Array.isArray(rules) ? rules.length : 0;
  }

  /**
   * Which resourceTypes will THIS browser accept in a dynamic rule?
   *
   * `updateDynamicRules` validates the whole call, so one value the running
   * browser's schema does not know discards every rule in it. Firefox 153 does
   * not know `webtransport` or `webbundle`; the cost of asking for them was the
   * entire block layer, silently, while the popup went on promising it. Reading
   * the list back from a documented table would repeat that mistake with a new
   * value later, so the list is settled against the same validator that will
   * judge the real call.
   *
   * The full list is tried first, which is one round trip on a browser that
   * accepts it and the only cost Chromium ever pays. Only a refusal turns into
   * one call per type, and the answer is cached.
   *
   * @returns {Promise<{ok: boolean, types: string[], dropped: string[], error: string}>}
   */
  async blockLayerTypes() {
    if (this._blockTypes) {
      return { ok: true, types: this._blockTypes, dropped: this.blockTypesDropped, error: '' };
    }
    const now = Date.now();
    if (this.blockTypesError && now - this._blockTypesAt < RENEGOTIATE_AFTER_MS) {
      return { ok: false, types: [], dropped: this.blockTypesDropped, error: this.blockTypesError };
    }
    this._blockTypesAt = now;

    if (await this._acceptsResourceTypes(DNR_RESOURCE_TYPES)) {
      this._blockTypes = DNR_RESOURCE_TYPES.slice();
      this.blockTypesDropped = [];
      this.blockTypesError = '';
      return { ok: true, types: this._blockTypes, dropped: [], error: '' };
    }

    const accepted = [];
    const rejected = [];
    for (const type of DNR_RESOURCE_TYPES) {
      // eslint-disable-next-line no-await-in-loop
      if (await this._acceptsResourceTypes([type])) accepted.push(type);
      else rejected.push(type);
    }
    this.blockTypesDropped = rejected;

    const missing = DNR_ESSENTIAL_RESOURCE_TYPES.filter((t) => !accepted.includes(t));
    if (!accepted.length || missing.length) {
      // A block that cannot cover the top-level document is not a smaller block,
      // it is a broken page that still emitted the request. Refused as a failure
      // so that it reaches the state machine rather than being installed and
      // believed.
      this._blockTypes = null;
      this.blockTypesError = accepted.length
        ? `this browser will not block ${missing.join(', ')}`
        : 'this browser accepted no resource type at all';
      return { ok: false, types: [], dropped: rejected, error: this.blockTypesError };
    }

    this._blockTypes = accepted;
    this.blockTypesError = '';
    return { ok: true, types: accepted, dropped: rejected, error: '' };
  }

  /** Forget the negotiated set, so the next call establishes it again. */
  invalidateBlockLayerTypes() {
    this._blockTypes = null;
    this._blockTypesAt = 0;
  }

  /**
   * Add one throwaway rule carrying `types`, then remove it. The urlFilter names
   * a reserved-by-RFC-2606 host that resolves nowhere, so even if a background
   * context is killed between the add and the remove the orphan blocks nothing;
   * allRuleIds() sweeps its id on the next real update regardless.
   */
  async _acceptsResourceTypes(types) {
    try {
      await api.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: [DNR_PROBE_RULE_ID],
        addRules: [{
          id: DNR_PROBE_RULE_ID,
          priority: DNR_PRIORITY_BLOCK,
          action: { type: 'block' },
          condition: { urlFilter: '||wv-block-layer-probe.invalid^', resourceTypes: types },
        }],
      });
      return true;
    } catch {
      return false;
    } finally {
      try {
        await api.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [DNR_PROBE_RULE_ID] });
      } catch {
        /* nothing was installed */
      }
    }
  }

  // -- incognito / private windows ------------------------------------------

  async isAllowedIncognitoAccess() {
    try {
      // Chrome exposes this on chrome.extension; Firefox on browser.extension.
      const allowed = await api.extension.isAllowedIncognitoAccess();
      return typeof allowed === 'boolean' ? allowed : null;
    } catch {
      return null;
    }
  }

  // -- to be provided by the concrete adapter -------------------------------

  /* eslint-disable no-unused-vars */
  /** Whether this browser has a real mechanism that can route traffic. */
  async routingSurface() {
    return { ok: true, reason: '' };
  }
  /**
   * Does this extension currently hold any routing in the browser: a proxy
   * setting it wrote, or a request listener it installed? Read from the
   * browser, never from a cached field, because the question is asked by a
   * background context that may have just been revived. `true` is the safe
   * answer when the browser cannot be asked: the controller then keeps its
   * block-first teardown.
   */
  async holdsRouting() {
    return true;
  }
  /** Hold the session credential in memory. Never persisted, by either adapter. */
  setCredential(credential) {
    throw new Error('not implemented');
  }
  /** Can this browser answer the desktop proxy's 407 challenge? */
  async canAuthenticate() {
    throw new Error('not implemented');
  }
  async applyRouting(settings, endpoint) {
    throw new Error('not implemented');
  }
  async clearRouting() {
    throw new Error('not implemented');
  }
  async proxyLevelOfControl() {
    throw new Error('not implemented');
  }
  async applyPrivacyProtections() {
    throw new Error('not implemented');
  }
  async releasePrivacyProtections() {
    throw new Error('not implemented');
  }
  /* eslint-enable no-unused-vars */
}

export function describeError(e) {
  if (!e) return 'unknown error';
  const m = e.message || String(e);
  return m.slice(0, 200);
}

export function normaliseDynamicRules(rules) {
  return rules.map((rule) => ({
    id: rule?.id,
    priority: rule?.priority === undefined ? 1 : rule.priority,
    action: rule?.action?.type,
    urlFilter: rule?.condition?.urlFilter,
    resourceTypes: Array.isArray(rule?.condition?.resourceTypes)
      ? [...rule.condition.resourceTypes].sort()
      : [],
  })).sort((a, b) => a.id - b.id);
}

/**
 * Whatever this browser is willing to say about a native port that ended.
 *
 * Both places are read on both browsers rather than branching on which browser
 * this is. That is deliberate: the adapters exist to hold differences that are
 * real, and "which property carries the error" is a difference that costs
 * nothing to stop caring about -- whereas a branch would have to be kept in
 * agreement with two vendors' future behaviour. Returns '' when the browser
 * genuinely said nothing, which is a fact the caller needs and must not be
 * given a sentence in place of.
 */
export function describePortFailure(port) {
  const fromPort = port && port.error ? (port.error.message || port.error) : '';
  if (fromPort) return String(fromPort).slice(0, 200);
  // Chromium sets this and clears it on read, and it is only valid while this
  // callback is on the stack.
  let last = null;
  try {
    last = api.runtime.lastError;
  } catch {
    last = null;
  }
  if (!last) return '';
  return String(last.message || last).slice(0, 200);
}
