// Safari Web Extension adapter.
//
// Safari does not expose browser.proxy or chrome.proxy. Native messaging is
// also intentionally different: Safari ignores the application id and sends a
// message only to the native app extension inside the containing macOS app.
// The existing org.winsvpn.bridge executable is therefore not reachable from
// this JavaScript context.
//
// The standalone native app owns routing. This adapter reports its
// authenticated status without enabling the external-host controller.

import { BaseAdapter, api } from './base.js';

export const SAFARI_CONTAINING_APP_ID = 'org.winsvpn.app';
export const SAFARI_CAPABILITY_REASON = 'no_native_routing_surface';
const CAPABILITY_TIMEOUT_MS = 4_000;

export function parseSafariCapability(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  if (raw.v !== 1 || raw.type !== 'capability') return null;
  if (raw.routing !== false) return null;
  if (raw.reason === 'native_app_managed') {
    if (!['macos', 'ios'].includes(raw.platform)
        || typeof raw.nativeAuthenticated !== 'boolean'
        || typeof raw.nativeRouting !== 'boolean'
        || (raw.nativeRouting && !raw.nativeAuthenticated)
        || (raw.platform === 'ios' && (raw.nativeRouting || raw.nativeAuthenticated))) return null;
    return {
      ok: false,
      reason: raw.platform === 'ios'
        ? 'The iOS app contains a Safari extension only. It does not route traffic. Standalone v3 routing requires a packet tunnel and a user-approved VPN configuration.'
        : raw.nativeRouting
        ? 'The standalone Safari Proxy app reports that its engine, DNS and Safari flow capture are ready. Routing is controlled in that app; this browser panel cannot verify traffic on the wire.'
        : raw.nativeAuthenticated
        ? 'The standalone Safari Proxy provider answered, but its forwarding checks are not all ready. Open that app for connection status.'
        : 'No authenticated active Safari Proxy provider was reached. Open the standalone Safari Proxy app to connect. The full VPN app is not required.',
    };
  }
  if (raw.reason !== SAFARI_CAPABILITY_REASON) return null;
  return {
    ok: false,
    reason: 'The Safari app extension reported no native routing mechanism for this build.',
  };
}

function withTimeout(promise, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('the Safari app extension did not answer')), timeoutMs);
    Promise.resolve(promise).then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

export class SafariAdapter extends BaseAdapter {
  constructor() {
    super('safari');
    this.authStats = null;
    this._surface = null;
  }

  async routingSurface() {
    if (!api.runtime || typeof api.runtime.sendNativeMessage !== 'function') {
      this._surface = {
        ok: false,
        reason: 'Safari did not expose its containing-app message channel.',
      };
      return this._surface;
    }
    try {
      const response = await withTimeout(
        api.runtime.sendNativeMessage(
          SAFARI_CONTAINING_APP_ID,
          { v: 1, type: 'capability_probe' },
        ),
        CAPABILITY_TIMEOUT_MS,
      );
      this._surface = parseSafariCapability(response) || {
        ok: false,
        reason: 'The Safari app extension returned an unrecognised capability response.',
      };
    } catch (error) {
      const message = error && error.message ? error.message : String(error || 'unknown error');
      this._surface = {
        ok: false,
        reason: `The Safari app extension capability check failed: ${message.slice(0, 120)}`,
      };
    }
    return this._surface;
  }

  installProxyAuth() {
    return false;
  }

  removeProxyAuth() {}

  setCredential() {}

  async canAuthenticate() {
    return false;
  }

  async applyRouting() {
    throw new Error('Safari has no WebExtension proxy routing surface');
  }

  async clearRouting() {}

  async holdsRouting() {
    return false;
  }

  async setBlockRules() {}

  async proxyLevelOfControl() {
    return 'unknown';
  }

  async applyPrivacyProtections() {
    return { webrtc: 'unsupported', prediction: 'unsupported' };
  }

  async releasePrivacyProtections() {}
}
