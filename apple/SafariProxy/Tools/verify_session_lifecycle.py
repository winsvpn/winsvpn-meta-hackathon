from pathlib import Path
import hashlib,json,argparse,subprocess,sys
parser=argparse.ArgumentParser(description="Compile and run offline checks extracted from actual Safari session lifecycle methods.")
parser.add_argument("--source-root",type=Path,default=Path(__file__).resolve().parents[3])
parser.add_argument("--output-dir",type=Path,required=True)
args=parser.parse_args()
root=args.source_root
out=args.output_dir
out.mkdir(parents=True,exist_ok=True)
src=(root/'apple/SafariProxy/App/SafariConnection.swift').read_text()
app=(root/'apple/SafariProxy/App/SafariProxyApp.swift').read_text()
store=(root/'apple/SafariProxy/Shared/SafariSessionStore.swift').read_text()
def method(s, signature):
 start=s.index(signature); pos=s.index('{',start); depth=1; end=pos+1
 while depth:
  if s[end]=='{': depth+=1
  elif s[end]=='}': depth-=1
  end+=1
 return s[start:end]
methods={name:method(text,sig) for name,text,sig in [('disconnect',src,'    func disconnect() async throws'),('startProviders',src,'    private func startProviders() async throws'),('disconnectProxy',app,'    @objc private func disconnectProxy()'),('optionalRead',store,'    static func optionalRead(_ account: String) throws'),('checkStatus',app,'    @objc private func checkStatus()')]}
(out/'extracted-methods.json').write_text(json.dumps({k:hashlib.sha256(v.encode()).hexdigest() for k,v in methods.items()},indent=2)+'\n')
head=r'''import Foundation
struct Failure: Error {}
enum SafariForwardError: Error { case invalid, missing, unavailable }
final class Bundle { static let main = Bundle(); func object(forInfoDictionaryKey: String) -> Any? { "own-provider" } }
@MainActor final class MockConnection {
 enum Status { case disconnected, invalid, connected }
 var stops=0; var starts=0; var status=Status.disconnected
 func stopVPNTunnel() { stops += 1; status = .disconnected }
 func startVPNTunnel() throws { starts += 1; status = .connected }
}
final class NETunnelProviderProtocol { var providerBundleIdentifier: String?; var serverAddress: String? }
final class NEDNSProxyProviderProtocol { var providerBundleIdentifier: String? }
@MainActor final class NETransparentProxyManager {
 static var all: [NETransparentProxyManager] = []
 static var failLoad=false; static var deferred=false
 static var pending: [([NETransparentProxyManager]?, Error?) -> Void] = []
 var protocolConfiguration: Any?; var localizedDescription: String?; var isEnabled=false
 let connection=MockConnection()
 static func loadAllFromPreferences(_ completion: @escaping ([NETransparentProxyManager]?, Error?) -> Void) {
  if deferred { pending.append(completion) } else { completion(all, failLoad ? Failure() : nil) }
 }
 func saveToPreferences(_ completion: @escaping (Error?) -> Void) { completion(nil) }
 func loadFromPreferences(_ completion: @escaping (Error?) -> Void) { completion(nil) }
}
@MainActor final class NEDNSProxyManager {
 static let instance=NEDNSProxyManager(); static func shared() -> NEDNSProxyManager { instance }
 var providerProtocol: NEDNSProxyProviderProtocol?; var localizedDescription: String?; var isEnabled=true
 var failLoad=false; var failSave=false; var deferLoad=false; var deferSave=false; var saves=0
 var pendingLoads: [(Error?) -> Void] = []; var pendingSaves: [(Error?) -> Void] = []
 func loadFromPreferences(_ completion: @escaping (Error?) -> Void) {
  if deferLoad { pendingLoads.append(completion) } else { completion(failLoad ? Failure() : nil) }
 }
 func saveToPreferences(_ completion: @escaping (Error?) -> Void) {
  saves += 1
  if deferSave { pendingSaves.append(completion) } else { completion(failSave ? Failure() : nil) }
 }
}
struct SafariProviderStatus { let routing: Bool }
@MainActor enum SafariControlClient {
 static var pending: [(SafariProviderStatus?) -> Void] = []
 static func status(_ reply: @escaping (SafariProviderStatus?) -> Void) { pending.append(reply) }
}
@MainActor enum SafariSessionStore {
 static var clears=0; static var failClear=false; static var active: String?="old"
 static var readError: SafariForwardError?
 static func read(_ account: String) throws -> Data { if let readError { throw readError }; return Data([1,2,3]) }
 OPTIONAL_READ_BODY
 static func clearSession() throws { clears += 1; if failClear { throw Failure() }; active=nil }
}
@MainActor final class SafariConnection {
 private var manager: NETransparentProxyManager?
 init(manager: NETransparentProxyManager?=nil) { self.manager=manager }
 func testStart() async throws { try await startProviders() }
'''
mockapp='''\n}\n@MainActor final class Detail { var stringValue="" }\n@MainActor final class MockApp: NSObject {\n let connection=SafariConnection(); var connectionTask: Task<Void,Never>?\n var operation=UUID(); var connecting=false; var disconnecting=false; let detail=Detail()\n func requestDisconnect() { disconnectProxy() }\n func requestStatus() { checkStatus() }\n'''
tests=r'''
}
@main struct Checks {
 @MainActor static func waitFor(_ label: String, _ predicate: () -> Bool) async {
  for _ in 0..<500 { if predicate() { return }; try? await Task.sleep(nanoseconds: 1_000_000) }
  fatalError("timeout: " + label)
 }
 @MainActor static func reset(_ owner: String="own-provider") {
  NETransparentProxyManager.all=[]; NETransparentProxyManager.failLoad=false; NETransparentProxyManager.deferred=false; NETransparentProxyManager.pending=[]
  let d=NEDNSProxyManager.shared(); let p=NEDNSProxyProviderProtocol(); p.providerBundleIdentifier=owner; d.providerProtocol=p
  d.isEnabled=true; d.failLoad=false; d.failSave=false; d.deferLoad=false; d.deferSave=false; d.saves=0; d.pendingLoads=[]; d.pendingSaves=[]
  SafariSessionStore.clears=0; SafariSessionStore.failClear=false; SafariSessionStore.active="old"
 }
 @MainActor static func owned() -> NETransparentProxyManager {
  let m=NETransparentProxyManager(); let p=NETunnelProviderProtocol(); p.providerBundleIdentifier="own-provider"; m.protocolConfiguration=p; return m
 }
 @MainActor static func main() async throws {
  SafariSessionStore.readError = .missing
  let absent=try SafariSessionStore.optionalRead("identity-v1"); precondition(absent==nil)
  SafariSessionStore.readError = .unavailable
  do { _=try SafariSessionStore.optionalRead("identity-v1"); fatalError("unexpected missing") } catch SafariForwardError.unavailable {} catch { fatalError("wrong error") }
  SafariSessionStore.readError=nil
  let present=try SafariSessionStore.optionalRead("identity-v1"); precondition(present==Data([1,2,3]))
  print("PASS optionalRead returns nil only for missing and propagates unavailable")
  reset(); let cancelApp=MockApp(); var observedCancellation=false
  cancelApp.connectionTask=Task { do { try await Task.sleep(nanoseconds: 30_000_000_000) } catch { observedCancellation=Task.isCancelled } }
  cancelApp.requestDisconnect()
  await waitFor("cancel completion") { !cancelApp.connecting }
  precondition(observedCancellation && SafariSessionStore.clears==1 && cancelApp.connectionTask==nil)
  print("PASS app Disconnect cancels and awaits in-flight connect before cleanup")
  reset("foreign-provider"); let foreign=NETransparentProxyManager(); let fp=NETunnelProviderProtocol(); fp.providerBundleIdentifier="foreign-provider"; foreign.protocolConfiguration=fp
  let own=owned(); NETransparentProxyManager.all=[own,foreign]
  try await SafariConnection().disconnect()
  precondition(NEDNSProxyManager.shared().isEnabled && NEDNSProxyManager.shared().saves==0 && foreign.connection.stops==0 && own.connection.stops==1 && SafariSessionStore.clears==1)
  print("PASS foreign DNS and transparent managers untouched; own stop and session clear attempted")
  reset(); let cached=owned(); NEDNSProxyManager.shared().failSave=true
  do { try await SafariConnection(manager:cached).disconnect(); fatalError("expected failure") } catch {}
  precondition(cached.connection.stops==1 && SafariSessionStore.clears==1)
  print("PASS DNS save failure does not skip cached stop or clear")
  reset(); NETransparentProxyManager.failLoad=true
  do { try await SafariConnection().disconnect(); fatalError("expected failure") } catch {}
  precondition(!NEDNSProxyManager.shared().isEnabled && NEDNSProxyManager.shared().saves==1 && SafariSessionStore.clears==1)
  print("PASS transparent lookup failure does not skip owned DNS or clear")
  reset(); NEDNSProxyManager.shared().failLoad=true; SafariSessionStore.failClear=true; let cached2=owned()
  do { try await SafariConnection(manager:cached2).disconnect(); fatalError("expected failure") } catch {}
  precondition(cached2.connection.stops==1 && SafariSessionStore.clears==1)
  print("PASS independent DNS load and clear failures retain cached stop attempt")
  reset(); NETransparentProxyManager.deferred=true; let loaded=owned(); NETransparentProxyManager.all=[loaded]
  var done=false; let lookup=Task { try await SafariConnection().disconnect(); done=true }
  await waitFor("lookup pending") { !NETransparentProxyManager.pending.isEmpty }
  precondition(!done && loaded.connection.stops==0)
  NETransparentProxyManager.pending.removeFirst()([loaded],nil); try await lookup.value
  precondition(done && loaded.connection.stops==1)
  print("PASS disconnect waits for relaunch lookup before returning")
  reset(); NETransparentProxyManager.deferred=true; let cancelled=owned(); let task=Task { try await SafariConnection().testStart() }
  await waitFor("start lookup pending") { !NETransparentProxyManager.pending.isEmpty }; task.cancel()
  NETransparentProxyManager.pending.removeFirst()([cancelled],nil)
  do { try await task.value; fatalError("expected cancellation") } catch is CancellationError {} catch { fatalError("wrong error") }
  precondition(cancelled.connection.starts==0)
  print("PASS cancellation after pending initial lookup prevents tunnel start")
  reset(); let started=owned(); NETransparentProxyManager.all=[started]; let dns=NEDNSProxyManager.shared(); dns.deferLoad=true
  let late=Task { try await SafariConnection().testStart() }
  await waitFor("DNS pending") { !dns.pendingLoads.isEmpty }; late.cancel(); dns.pendingLoads.removeFirst()(nil)
  do { try await late.value; fatalError("expected cancellation") } catch is CancellationError {} catch { fatalError("wrong error") }
  precondition(started.connection.starts==1 && started.connection.stops==1 && dns.saves==0)
  print("PASS cancellation during DNS load stops tunnel without DNS save")
  reset(); let started2=owned(); NETransparentProxyManager.all=[started2]; dns.deferSave=true
  let saved=Task { try await SafariConnection().testStart() }
  await waitFor("DNS save pending") { !dns.pendingSaves.isEmpty }; saved.cancel(); dns.pendingSaves.removeFirst()(nil)
  do { try await saved.value; fatalError("expected cancellation") } catch is CancellationError {} catch { fatalError("wrong error") }
  precondition(started2.connection.starts==1 && started2.connection.stops==1)
  print("PASS cancellation after DNS save stops tunnel")
  reset(); dns.deferSave=true; let app=MockApp()
  app.requestDisconnect(); await waitFor("first disconnect") { dns.pendingSaves.count==1 }
  app.requestDisconnect()
  try await Task.sleep(nanoseconds: 10_000_000)
  precondition(dns.pendingSaves.count==1 && app.connecting && app.disconnecting && app.connectionTask != nil)
  dns.pendingSaves.removeFirst()(nil)
  await waitFor("serialized completion") { app.connecting==false }
  precondition(!app.disconnecting && app.connectionTask==nil && SafariSessionStore.clears==1)
  SafariSessionStore.active="new-session"
  try await Task.sleep(nanoseconds: 10_000_000)
  precondition(dns.pendingSaves.isEmpty && SafariSessionStore.active=="new-session")
  print("PASS repeated Disconnect is coalesced, UI remains gated and a later session survives")
  let statusApp=MockApp(); statusApp.detail.stringValue="sentinel"
  statusApp.requestStatus(); statusApp.operation=UUID(); SafariControlClient.pending.removeFirst()(SafariProviderStatus(routing:true))
  try await Task.sleep(nanoseconds: 10_000_000)
  precondition(statusApp.detail.stringValue=="sentinel")
  print("PASS status callback from obsolete operation is ignored")
  statusApp.requestStatus(); statusApp.connecting=true; SafariControlClient.pending.removeFirst()(SafariProviderStatus(routing:true))
  try await Task.sleep(nanoseconds: 10_000_000)
  precondition(statusApp.detail.stringValue=="sentinel")
  print("PASS status callback during pending operation is ignored")
  statusApp.connecting=false; statusApp.requestStatus(); SafariControlClient.pending.removeFirst()(SafariProviderStatus(routing:true))
  await waitFor("current status") { statusApp.detail.stringValue.hasPrefix("Connected.") }
  print("PASS current status callback updates idle UI")
 }
}
'''
head=head.replace('OPTIONAL_READ_BODY',methods['optionalRead'])
(out/'LifecycleChecks.swift').write_text(head+methods['startProviders']+'\n'+methods['disconnect']+mockapp+methods['disconnectProxy']+'\n'+methods['checkStatus']+tests)
print('Extracted five source methods without body edits')
compile_command=['swiftc','-parse-as-library','-module-cache-path',str(out/'module-cache'),str(out/'LifecycleChecks.swift'),'-o',str(out/'lifecycle-checks')]
compiled=subprocess.run(compile_command,capture_output=True,text=True,timeout=60)
(out/'compiler-output.txt').write_text(compiled.stdout+compiled.stderr)
if compiled.returncode:
 print(compiled.stdout+compiled.stderr);sys.exit(compiled.returncode)
run=subprocess.run([str((out/'lifecycle-checks').resolve())],capture_output=True,text=True,timeout=15)
(out/'test-output.txt').write_text(run.stdout+run.stderr)
print(run.stdout+run.stderr,end='')
(out/'checks.json').write_text(json.dumps({'compile_command':compile_command,'compile_exit':compiled.returncode,'test_exit':run.returncode,'passing_scenarios':run.stdout.count('PASS ')},indent=2)+'\n')
sys.exit(run.returncode)
