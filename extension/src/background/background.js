// Background entry point. One file for all four targets.
//
// Chrome and Edge load this as an MV3 service worker. Firefox loads the same
// file as an MV3 event page, and Safari loads it from a nonpersistent module
// background page. Every context can be terminated at any moment and revived
// by an event, which is why every listener is registered synchronously at the
// top level here, before any await. A listener registered inside an async
// callback is a listener that is missing on the revival that matters.

import { ALARM_NAME, ALARM_PERIOD_MINUTES, Controller } from './controller.js';
import { api } from '../adapters/index.js';

const controller = new Controller();

// One promise for the initial load, awaited by every handler. Handlers must not
// each kick off their own initialisation or they will race each other into
// applying two different configurations.
let readyPromise = null;
function ready() {
  if (!readyPromise) {
    readyPromise = controller.init().catch((e) => {
      readyPromise = null;
      controller.lastError = `initialization failed and will be retried: ${String(e && e.message ? e.message : e)}`;
      throw e;
    });
  }
  return readyPromise;
}

function startReady() {
  return ready().catch((error) => {
    controller.lastError = 'initialization failed and will be retried';
  });
}

// Registered synchronously, before any await, for the reason spelled out in
// ChromiumAdapter.installProxyAuth: a webRequest listener added later belongs
// only to the service-worker generation that added it and cannot wake a
// terminated one. On Firefox and Safari this is a no-op.
controller.adapter.installProxyAuth(async () => {
  await ready();
  return controller.waitForCredential(8000);
});

// Firefox only: the one proxy.onRequest listener, registered here for the same
// reason as the auth listener above. Firefox keeps no proxy setting across a
// restart or an event-page suspension; a listener added later from
// applyRouting() does not exist for requests issued before init() finishes
// (session restore) or after the page is suspended, and PROTECTED has already
// removed the block rules, so those requests would leave directly.
if (typeof controller.adapter.installPrimedRouting === 'function') {
  controller.adapter.installPrimedRouting(async () => {
    await ready();
    return controller.settings;
  });
}

function reconcileOptionalHostPermission(removed) {
  // A removal event is already authoritative. Drop the cached capability
  // synchronously so no later state derivation can remain protected while the
  // asynchronous browser re-read and fail-closed reconcile are pending.
  if (removed) controller.canAuthenticate = false;
  ready()
    .then(async () => {
      controller.canAuthenticate = await controller.adapter.canAuthenticate();
      await controller.reconcile();
    })
    .catch((e) => {
      controller.lastError = `could not reconcile the Firefox site permission: ${String(e && e.message ? e.message : e)}`;
    });
}

// Firefox may revoke optional site access from about:addons, and Chrome or
// Edge from chrome://extensions "Site access", while routing is live. Without
// that access Chromium stops delivering webRequest.onAuthRequired, so the
// desktop proxy's 407 reaches the user as a browser password prompt while the
// popup still says PROTECTED. These listeners must be registered synchronously
// so the background can wake on the change on every target.
if (api.permissions?.onRemoved) {
  api.permissions.onRemoved.addListener(() => {
    reconcileOptionalHostPermission(true);
  });
}
if (api.permissions?.onAdded) {
  api.permissions.onAdded.addListener(() => {
    reconcileOptionalHostPermission(false);
  });
}

api.runtime.onInstalled.addListener(() => {
  ensureAlarm();
  startReady();
});

api.runtime.onStartup.addListener(() => {
  ensureAlarm();
  startReady();
});

api.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== ALARM_NAME) return;
  try {
    await ready();
    // A browser-managed permission change should deliver onAdded/onRemoved, but
    // the browser remains the authority. Re-read on every Firefox alarm so a
    // missed event cannot leave a stale protected state for the session.
    if (typeof controller.adapter.canAuthenticate === 'function') {
      controller.canAuthenticate = await controller.adapter.canAuthenticate();
    }
    await controller.onAlarm();
  } catch {
    controller.lastError = 'alarm reconciliation failed and will be retried';
  }
});

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Drop anything the browser does not attribute to this extension itself. The
  // comments below explain why a direct web page has no channel here, but the
  // listener is the one place every message passes through and the sender is
  // cheap to check: a message from any other extension, or from a web page in
  // the unlikely event a browser starts delivering one, is refused before the
  // handler even looks at it.
  if (!sender || sender.id !== api.runtime.id) return;
  // Nothing outside this extension can reach here: there are no content
  // scripts, and `externally_connectable` is not declared, so web pages have no
  // channel to this listener at all.
  handleMessage(message)
    .then(sendResponse)
    .catch((e) => sendResponse({ error: String(e && e.message ? e.message : e) }));
  return true; // keep the channel open for the async reply
});

async function handleMessage(message) {
  await ready();
  switch (message && message.type) {
    case 'getState':
      // Re-derive rather than return a cached snapshot: the caller is usually a
      // popup that just opened, and the most likely reason the user opened it
      // is that something changed.
      if (typeof controller.adapter.canAuthenticate === 'function') {
        controller.canAuthenticate = await controller.adapter.canAuthenticate();
      }
      await controller.reconcile();
      return controller.snapshot();
    case 'setSettings':
      return controller.setSettings(message.settings, message.expectedSettings || null);
    case 'panicClear':
      return controller.panicClear();
    // Connect or disconnect the desktop tunnel. An unpaired browser's first
    // request starts the in-app approval instead (R20 A1).
    case 'requestTunnel': {
      const outcome = controller.requestTunnel(message.connect === true);
      await controller.reconcile();
      return { ...controller.snapshot(), tunnelRequest: outcome };
    }
    case 'beginPairing':
      controller.beginPairing();
      await controller.reconcile();
      return controller.snapshot();
    case 'forgetPairing':
      return controller.forgetPairing();
    // THIS HANDLER DOES NOT REQUEST THE PERMISSION, AND MUST NOT.
    //
    // It used to, and on Firefox that was the whole of the third defect the
    // 2026-08-07 run found: `permissions.request()` needs a live user input
    // handler, a runtime message handler is not one, and the browser built the
    // prompt and never showed it. Chromium, measured afterwards, does not apply
    // that rule here -- but the request belongs in the click on both browsers,
    // and it is now in the options page. What is left here is the part that was
    // always useful: re-reading the capability from the browser afterwards,
    // whatever the request did. That is also the route for a user who grants the
    // permission from the browser's own add-on manager and then presses the
    // button.
    //
    // `requestHostPermission` is accepted as a synonym so that an options page
    // from an older build, or a verification harness driving the message
    // directly, still lands somewhere honest.
    case 'hostPermissionChanged':
    case 'requestHostPermission': {
      // The browser is the authority on what it actually gave; nothing here
      // trusts what was asked for.
      controller.canAuthenticate = await controller.adapter.canAuthenticate();
      const granted = typeof controller.adapter.hasHostPermission === 'function'
        ? await controller.adapter.hasHostPermission()
        : false;
      await controller.reconcile();
      return { granted, ...controller.snapshot() };
    }
    default:
      return { error: 'unknown request' };
  }
}

function ensureAlarm() {
  try {
    Promise.resolve(api.alarms.create(ALARM_NAME, {
      periodInMinutes: ALARM_PERIOD_MINUTES,
    })).catch(() => {
      controller.lastError = 'alarm scheduling failed and will be retried';
    });
  } catch {
    controller.lastError = 'alarm scheduling failed and will be retried';
  }
}

// Also run on plain load, which covers the service worker being revived by an
// event that is not one of the two above.
ensureAlarm();
startReady();
