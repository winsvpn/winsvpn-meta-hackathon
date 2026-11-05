"""A subscribed native host rotates its listener when its credential expires."""
from test_audit_c_extension import CHROME_FAKE, _run_node


def test_unsolicited_rotation_recovers_with_correlated_credential(tmp_path):
    got = _run_node(tmp_path, CHROME_FAKE + r"""
const { Controller } = await import('./src/background/controller.js');
const c = new Controller();
c.adapter.installProxyAuth(async () => c.credential);
await c.init();
await c.setSettings({armed: true, mode: 'all', listed: [], excluded: []});
await c.onHostMessage(STATUS);
await c.onHostMessage(token());
const before = c.current.state;
const issuesBefore = posted.filter(t => t === 'issue_proxy_credential').length;
// The native host's subscription timer uses an empty id on automatic rotation.
await c.onHostMessage({...TOKEN, id: '', proxyPort: 50001});
const unsolicitedIgnored = c.credential.endpoint.port === 50000;
await c.onHostMessage({...STATUS, proxyPort: 50001});
const reissued = posted.filter(t => t === 'issue_proxy_credential').length - issuesBefore;
const blockedBeforeReply = c.current.failClosed;
await c.onHostMessage({...token(), proxyPort: 50001});
await c.onHostMessage({...STATUS, proxyPort: 50001});
const recovered = c.current.state;
const currentPort = c.credential.endpoint.port;
c.stopHeartbeat();
console.log(JSON.stringify({before, unsolicitedIgnored, reissued, blockedBeforeReply, recovered, currentPort}));
process.exit(0);
""")
    assert got['before'] == 'protected'
    assert got['unsolicitedIgnored'] is True
    assert got['reissued'] == 1
    assert got['blockedBeforeReply'] is True
    assert got['recovered'] == 'protected'
    assert got['currentPort'] == 50001


def test_correlated_reissue_on_a_rotated_port_is_not_refused_as_moved(tmp_path):
    # The host rotates an expired listener inside the issue request itself
    # (_issueCredentialNow) and answers with the new port before its 2 s
    # subscription poll pushes a status that says so. The correlated reply is
    # the newer fact; the extension must not fail closed on the older status.
    got = _run_node(tmp_path, CHROME_FAKE + r"""
const { Controller } = await import('./src/background/controller.js');
const c = new Controller();
c.adapter.installProxyAuth(async () => c.credential);
await c.init();
await c.setSettings({armed: true, mode: 'all', listed: [], excluded: []});
await c.onHostMessage(STATUS);
await c.onHostMessage(token());
const before = c.current.state;
c.adapter.authStats.credentialsRejected = 1;
c.credentialReissuedAtMs = 0;
c.maybeRequestCredential();
const reissueAsked = c.credentialRequested === true && c.credential === null;
await c.onHostMessage({...token(), token: 'B'.repeat(43), proxyPort: 50001});
const stateAfterReply = c.current.state;
const failClosedAfterReply = c.current.failClosed;
const statusPort = c.status.proxyPort;
await c.onHostMessage({...STATUS, proxyPort: 50001});
const afterPush = c.current.state;
const issues = posted.filter(t => t === 'issue_proxy_credential').length;
c.stopHeartbeat();
console.log(JSON.stringify({before, reissueAsked, stateAfterReply, failClosedAfterReply, statusPort, afterPush, issues}));
process.exit(0);
""")
    assert got['before'] == 'protected'
    assert got['reissueAsked'] is True
    assert got['stateAfterReply'] == 'protected'
    assert got['failClosedAfterReply'] is False
    assert got['statusPort'] == 50001
    assert got['afterPush'] == 'protected'
    assert got['issues'] == 2
