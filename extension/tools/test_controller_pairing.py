"""Desktop pairing in the controller (R20 A1).

Connect and disconnect reach the bridge only for a browser the desktop app
paired; the first request from an unpaired browser asks the app to approve
it instead. The credential is stored, presented on every new port, never put
in the snapshot the popup reads, and dropped when the running app says the
pairing is gone.
"""
from test_audit_c_extension import CHROME_FAKE, _run_node

# Record whole outbound messages, not only their types.
RECORD = r"""
const sent = [];
const realConnect = chrome.runtime.connectNative;
chrome.runtime.connectNative = (name) => {
  const p = realConnect(name);
  const post = p.postMessage;
  p.postMessage = (m) => { sent.push(JSON.parse(JSON.stringify(m))); post(m); };
  return p;
};
const CRED = 'ab'.repeat(32);
const typesSent = () => sent.map((m) => m.type);
const lastOf = (type) => [...sent].reverse().find((m) => m.type === type);
"""


def test_unpaired_request_starts_pairing_and_never_controls(tmp_path):
    got = _run_node(tmp_path, CHROME_FAKE + RECORD + r"""
const { Controller } = await import('./src/background/controller.js');
const c = new Controller();
await c.init();
await c.setSettings({armed: true, mode: 'all', listed: [], excluded: []});
await c.onHostMessage({...STATUS, pairing: 'unpaired'});
const outcome = c.requestTunnel(false);
const begin = lastOf('pair_begin');
const pendingId = begin ? begin.id : '';
await c.onHostMessage({v: 1, id: pendingId, type: 'pairing', ok: true, state: 'pending', code: '042917', expiresInSeconds: 120});
const pending = c.snapshot().pairing;
// A credential smuggled into a pending message is dropped by the parser.
await c.onHostMessage({v: 1, id: '', type: 'pairing', ok: true, state: 'pending', code: '042917', credential: CRED});
const storedAfterSmuggle = store.pairing ? store.pairing.credential : '';
// A malformed approval is refused whole.
await c.onHostMessage({v: 1, id: '', type: 'pairing', ok: true, state: 'approved', credential: 'not-hex'});
const storedAfterMalformed = store.pairing ? store.pairing.credential : '';
c.stopHeartbeat();
console.log(JSON.stringify({
  outcome, controls: typesSent().filter((t) => t.startsWith('request_')),
  beganPairing: Boolean(begin), pending, storedAfterSmuggle, storedAfterMalformed,
}));
process.exit(0);
""")
    assert got["outcome"] == {"sent": False, "pairing": True}
    assert got["controls"] == []
    assert got["beganPairing"] is True
    assert got["pending"]["flow"] == "pending"
    assert got["pending"]["code"] == "042917"
    assert got["pending"]["status"] == "unpaired"
    assert got["pending"]["stored"] is False
    assert 0 < got["pending"]["expiresInMs"] <= 120000
    assert got["storedAfterSmuggle"] == ""
    assert got["storedAfterMalformed"] == ""


def test_approval_is_stored_presented_and_never_shown_to_the_popup(tmp_path):
    got = _run_node(tmp_path, CHROME_FAKE + RECORD + r"""
const { Controller } = await import('./src/background/controller.js');
const c = new Controller();
await c.init();
await c.setSettings({armed: true, mode: 'all', listed: [], excluded: []});
await c.onHostMessage({...STATUS, pairing: 'unpaired'});
c.beginPairing();
await c.onHostMessage({v: 1, id: '', type: 'pairing', ok: true, state: 'approved', credential: CRED});
const stored = store.pairing.credential;
const snap = JSON.stringify(c.snapshot());
await c.onHostMessage({...STATUS, pairing: 'paired'});
const disconnect = c.requestTunnel(false);
const connect = c.requestTunnel(true);
const controlBodies = sent.filter((m) => m.type.startsWith('request_'));
// Paired, but the app is locked: nothing is sent.
await c.onHostMessage({...STATUS, pairing: 'paired', canRequestConnect: false});
const locked = c.requestTunnel(false);
c.stopHeartbeat();

// A new background context: the stored pairing is presented before subscribe.
sent.length = 0;
const d = new Controller();
await d.init();
const order = typesSent();
const presented = lastOf('set_pairing');
d.stopHeartbeat();
console.log(JSON.stringify({
  stored, leaked: snap.includes(CRED), disconnect, connect,
  controlTypes: controlBodies.map((m) => m.type),
  controlCarriesCredential: controlBodies.some((m) => JSON.stringify(m).includes(CRED)),
  locked, order, presentedCredential: presented ? presented.credential : '',
}));
process.exit(0);
""")
    assert got["stored"] == "ab" * 32
    assert got["leaked"] is False
    assert got["disconnect"] == {"sent": True, "pairing": False}
    assert got["connect"] == {"sent": True, "pairing": False}
    assert got["controlTypes"] == ["request_disconnect", "request_connect"]
    # The host already holds the credential; controls do not repeat it.
    assert got["controlCarriesCredential"] is False
    assert got["locked"] == {"sent": False, "pairing": False}
    order = got["order"]
    assert order.index("hello") < order.index("set_pairing") < order.index("subscribe")
    assert got["presentedCredential"] == "ab" * 32


def test_revocation_by_a_running_app_drops_the_copy_but_app_absence_does_not(tmp_path):
    got = _run_node(tmp_path, CHROME_FAKE + RECORD + r"""
store.pairing = { credential: CRED };
const { Controller } = await import('./src/background/controller.js');
const c = new Controller();
await c.init();
await c.setSettings({armed: true, mode: 'all', listed: [], excluded: []});
const present = lastOf('set_pairing');
// The app is not running: say nothing about the pairing.
await c.onHostMessage({...STATUS, id: present.id, status: 'app_not_running', pairing: 'unpaired', canRequestConnect: false, proxyReady: false});
const keptWhileAbsent = store.pairing.credential;
// The running app answers that it does not know this browser any more.
await c.onHostMessage({...STATUS, pairing: 'unpaired'});
const afterRevoke = store.pairing.credential;
const snap = c.snapshot().pairing;
c.stopHeartbeat();
console.log(JSON.stringify({ keptWhileAbsent, afterRevoke, snap }));
process.exit(0);
""")
    assert got["keptWhileAbsent"] == "ab" * 32
    assert got["afterRevoke"] == ""
    assert got["snap"]["stored"] is False
    assert got["snap"]["status"] == "unpaired"


def test_old_bridge_without_pairing_is_status_only(tmp_path):
    got = _run_node(tmp_path, CHROME_FAKE + RECORD + r"""
const { Controller } = await import('./src/background/controller.js');
const c = new Controller();
await c.init();
await c.setSettings({armed: true, mode: 'all', listed: [], excluded: []});
await c.onHostMessage(STATUS);   // a 1.0.16 host: no pairing field at all
const outcome = c.requestTunnel(true);
c.stopHeartbeat();
console.log(JSON.stringify({ outcome, status: c.snapshot().pairing.status, types: typesSent() }));
process.exit(0);
""")
    assert got["status"] == "unsupported"
    assert got["outcome"] == {"sent": False, "pairing": False}
    assert "pair_begin" not in got["types"]
    assert "request_connect" not in got["types"]


def test_refused_pairing_and_erase_forget_the_pairing(tmp_path):
    got = _run_node(tmp_path, CHROME_FAKE + RECORD + r"""
store.pairing = { credential: CRED };
const { Controller } = await import('./src/background/controller.js');
const c = new Controller();
await c.init();
await c.setSettings({armed: true, mode: 'all', listed: [], excluded: []});
await c.onHostMessage({...STATUS, pairing: 'unpaired', id: lastOf('set_pairing').id, status: 'app_not_running', canRequestConnect: false, proxyReady: false});
await c.onHostMessage({...STATUS, pairing: 'unpaired', status: 'disconnected', canRequestConnect: false, proxyReady: false});
c.beginPairing();
const id = lastOf('pair_begin').id;
await c.onHostMessage({v: 1, id, type: 'error', ok: false, error: 'rate_limited'});
const busy = c.snapshot().pairing.flow;
c.beginPairing();
await c.onHostMessage({v: 1, id: lastOf('pair_begin').id, type: 'pairing', ok: true, state: 'unavailable'});
const unavailable = c.snapshot().pairing.flow;
c.pairing.credential = CRED;
await c.panicClear();
const forgot = typesSent().includes('pair_forget');
console.log(JSON.stringify({ busy, unavailable, forgot, after: c.pairing.credential }));
process.exit(0);
""")
    assert got["busy"] == "busy"
    assert got["unavailable"] == "unavailable"
    assert got["forgot"] is True
    assert got["after"] == ""
