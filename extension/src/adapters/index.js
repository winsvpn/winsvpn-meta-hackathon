// Adapter selection.
//
// One codebase, four targets. The source is not forked; the build emits four
// packages that differ only in the manifest and in a handful of listing strings.
// Which adapter runs is decided here, at runtime, by feature detection rather
// than by a build flag: a build flag would mean the Firefox path is never even
// parsed when a Chromium package is loaded, which is exactly how a per-browser
// path rots without anyone noticing.

import { ChromiumAdapter } from './chromium.js';
import { FirefoxAdapter } from './firefox.js';
import { SafariAdapter } from './safari.js';
import { api } from './base.js';

export function isSafariRuntime() {
  // Safari rotates the extension URL host, but its scheme is stable. Detect it
  // before Firefox: a future partial proxy namespace must not make Safari fall
  // into an adapter that assumes proxy.onRequest can route traffic.
  try {
    return api.runtime.getURL('/').startsWith('safari-web-extension://');
  } catch {
    return false;
  }
}

export function createAdapter() {
  if (isSafariRuntime()) return new SafariAdapter();
  // proxy.onRequest exists only on Firefox and is the API this extension most
  // wants, so it is the right thing to detect on.
  if (typeof globalThis.browser !== 'undefined' && globalThis.browser?.proxy?.onRequest) {
    return new FirefoxAdapter();
  }
  // Edge and Chrome are the same engine and the same code path. The name is
  // used only for diagnostics and for the wording of one install hint.
  const ua = (globalThis.navigator && globalThis.navigator.userAgent) || '';
  return new ChromiumAdapter(/Edg\//.test(ua) ? 'edge' : 'chrome');
}

export { api };
