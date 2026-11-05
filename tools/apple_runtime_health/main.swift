import Darwin
import Foundation

// Test-only promotion and relay interfaces. No provider, routes or archive starts.
enum WinsWinn3 { static let createSymbol = "WinnTunnelCreateWinn3" }
protocol WinsWinn3PacketRelay: AnyObject {
  func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void)
  func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool
}
enum WinsWinn3PromotionGate {
  static let innerMTUKey = "engine_runtime_winn_engine_winn3_inner_mtu"
  static func unsignedValue(_ value: Any?) -> UInt64 { (value as? NSNumber)?.uint64Value ?? 0 }
  static func converged(engineStatusFields: [String: Any]) -> Bool { false }
}
func require(_ condition: @autoclosure () -> Bool, _ message: String) {
  if !condition() { print("FAIL: \(message)"); exit(1) }
}
final class LegacyFixture {
  var isRunning = true
  func seamObservabilityStatusFields() -> [String: Any] { ["legacy_sample": 7] }
}
struct ConfigFixture {
  let transportMode = "winn"
  let xrayEnabled = false
  let winnEnabled = true
}
class ProviderFixture {
  let lifecycleGate = WinsTunnelOperationGate()
  var activeStatusGeneration = "fixture_current"
  func currentStatusGeneration() -> String { activeStatusGeneration }
  var winn3Datapath: WinsWinn3Datapath?
  var packetEngine: LegacyFixture?
  var activeConfig: ConfigFixture? = ConfigFixture()
  var activeEngineStatusFields: [String: Any] = [:]
  var recorded: [String: Any] = [:]
  var settingsReleaseCalls = 0
  func handleAppMessage(_ data: Data, completionHandler: ((Data?) -> Void)?) { fatalError("override") }
  class func winnRuntimeMemorySampleFields() -> [String: Any] { [:] }
  func writeProviderStatus(stage: String, config: ConfigFixture?, engineReady: Bool, networkSettingsReady: Bool, extra: [String: Any], statusGeneration: String?) {
    recorded = extra
    recorded["writer_generation"] = statusGeneration
    recorded["engine_ready"] = engineReady
    recorded["network_settings_ready"] = networkSettingsReady
    // This fixture records readiness supplied to the real status writer.
    recorded["healthy"] = engineReady && networkSettingsReady
  }
}
let name = CommandLine.arguments[1]
let live = name == "live"
let receiveFailure = name == "receive_failure"
let legacy = name == "legacy"
let missing = name == "missing"
let unavailable = name == "unavailable"
var statusCalls = 0
var closes = 0
var frees = 0
func fakeCreate(_ text: UnsafeMutablePointer<CChar>?, _ fd: Int32, _ error: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int64 { 41 }
func fakeWrite(_ h: Int64, _ b: UnsafeMutablePointer<CChar>?, _ n: Int32) -> Int32 { n }
func fakeRead(_ h: Int64, _ b: UnsafeMutablePointer<CChar>?, _ n: Int32, _ t: Int32) -> Int32 { receiveFailure ? WinsWinn3ABIStatus.tooLarge.rawValue : WinsWinn3ABIStatus.closed.rawValue }
func fakeStatus(_ h: Int64) -> UnsafeMutablePointer<CChar>? {
  require(h == 41, "stable handle")
  statusCalls += 1
  if unavailable { return nil }
  let completion = missing ? "" : "\"winn3_runtime_completed\":\((live || receiveFailure) ? "false" : "true"),"
  return strdup("{\(completion)\"winn3_rx_packets\":9,\"winn3_gate_state\":\"\(live ? "carrying" : "down")\",\"carrier_error\":\"fixture local detail\"}")
}
func fakeClose(_ h: Int64) -> UnsafeMutablePointer<CChar>? { closes += 1; return nil }
func fakeFree(_ p: UnsafeMutablePointer<CChar>?) { frees += 1; free(p) }
func ptr<T>(_ f: T) -> UnsafeMutableRawPointer { unsafeBitCast(f, to: UnsafeMutableRawPointer.self) }
let create: WinsWinn3ABI.CreateWinn3Fn = fakeCreate
let write: WinsWinn3ABI.WriteInboundFn = fakeWrite
let read: WinsWinn3ABI.ReadOutboundFn = fakeRead
let status: WinsWinn3ABI.StatusJSONFn = fakeStatus
let close: WinsWinn3ABI.CloseFn = fakeClose
let release: WinsWinn3ABI.FreeStringFn = fakeFree
WinsWinn3ABI.testSymbols = [WinsWinn3.createSymbol:ptr(create),WinsWinn3ABI.writeInboundSymbol:ptr(write),WinsWinn3ABI.readOutboundSymbol:ptr(read),WinsWinn3ABI.statusJSONSymbol:ptr(status),WinsWinn3ABI.closeSymbol:ptr(close),WinsWinn3ABI.freeStringSymbol:ptr(release)]
require(!WinsWinn3ABI.batchSymbolsAvailable, "no optional symbols or real archive")
let datapath = WinsWinn3Datapath()
if !legacy { try datapath.start(document: "{}", carrierDescriptor: -1) }
final class ReceiveFailureRelay: WinsWinn3PacketRelay {
  func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void) {}
  func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool { true }
}
if receiveFailure {
  require(datapath.healthSnapshot().isOperational, "native completion false before local failure")
  datapath.resume(relay: ReceiveFailureRelay())
  let deadline = Date().addingTimeInterval(2)
  while Date() < deadline {
    let health = datapath.healthSnapshot()
    if !health.isOperational && health.fields["winn3_datapath_proof_engine_to_host_refused"] as? Int == 1 { break }
    usleep(1000)
  }
  require(!datapath.healthSnapshot().isOperational, "local receive failure is visible")
  require(datapath.pumpStatusFields()["winn3_datapath_proof_engine_to_host_refused"] as? Int == 1, "one local refusal")
}
let prefix = WinsWinnSeamObservabilitySample.engineFieldPrefix
// The actual gate must return values without advancing its generation.
let gate = WinsTunnelOperationGate()
let generation = gate.begin()
require(gate.withLock { 17 } == 17 && gate.isCurrent(generation), "scoped return and generation preservation")
for provider in [IOSFixture(), MacFixture()] as [ProviderFixture] {
  let operation = provider.lifecycleGate.begin()
  provider.winn3Datapath = legacy ? nil : datapath
  provider.packetEngine = legacy ? LegacyFixture() : nil
  provider.activeEngineStatusFields = [prefix + "winn3_runtime_completed":false, prefix + "winn3_rx_packets":100, prefix + "winn3_gate_state":"carrying", "winn3_datapath_proof_host_to_engine_packets":100]
  provider.activeEngineStatusFields["status_generation"] = "fixture_cached_old"
  let before = statusCalls
  var completionReentered = false
  var response: [String: Any] = [:]
  provider.handleAppMessage(Data("health".utf8)) { data in
    provider.lifecycleGate.withLock { completionReentered = true }
    response = (try? JSONSerialization.jsonObject(with: data!) as? [String: Any]) ?? [:]
  }
  require(completionReentered, "external completion can reenter gate after unlock")
  require(provider.lifecycleGate.isCurrent(operation), "health does not advance operation generation")
  require(provider.recorded["status_generation"] as? String == "fixture_current", "cached generation normalized")
  require(provider.recorded["writer_generation"] as? String == "fixture_current", "captured generation passed explicitly")
  require(statusCalls - before == (legacy ? 0 : 1), "one native sample per callback")
  let expected = live || legacy
  require(response["engine_running"] as? Bool == expected, "response operational state")
  require(provider.recorded["engine_ready"] as? Bool == expected && provider.recorded["network_settings_ready"] as? Bool == expected, "same persisted readiness")
  require(provider.recorded["healthy"] as? Bool == expected, "derived readiness health")
  require(provider.settingsReleaseCalls == 0 && closes == 0, "no owner close or route release")
  if !legacy {
    require(datapath.isRunning && datapath.currentHandle == 41, "owner handle retained")
    require(provider.recorded["winn3_datapath_proof_host_to_engine_packets"] as? Int == 0, "fresh pump counter replaces cache")
    require(provider.recorded[prefix + "carrier_error"] == nil, "raw error stays redacted")
    if unavailable { require(provider.recorded[prefix + "winn3_rx_packets"] == nil, "no stale native counter") }
    else { require((provider.recorded[prefix + "winn3_rx_packets"] as? NSNumber)?.intValue == 9, "fresh native counter") }
    if missing || unavailable { require(provider.recorded[prefix + "winn3_runtime_completed"] == nil, "unknown is not cached live evidence") }
  } else { require(provider.recorded["legacy_sample"] as? Int == 7, "legacy sample preserved") }
  // Ordinary gate-protected transition, then a second coherent health publication.
  require(provider.lifecycleGate.performIfCurrent(operation) {
    provider.winn3Datapath = nil
    provider.packetEngine = nil
    provider.activeConfig = nil
    provider.activeStatusGeneration = ""
    provider.activeEngineStatusFields = ["status_generation": "fixture_cached_old"]
  }, "normal transition accepted by same generation")
  let callsBeforeTransitionHealth = statusCalls
  var stoppedResponse: [String: Any] = [:]
  provider.handleAppMessage(Data("health".utf8)) { data in
    provider.lifecycleGate.withLock { completionReentered = true }
    stoppedResponse = (try? JSONSerialization.jsonObject(with: data!) as? [String: Any]) ?? [:]
  }
  require(statusCalls == callsBeforeTransitionHealth, "transitioned state never samples old datapath")
  require(stoppedResponse["engine_running"] as? Bool == false, "transitioned response observes no owner")
  require(stoppedResponse["transport_mode"] as? String == "", "transitioned response observes cleared config")
  require(provider.recorded["healthy"] as? Bool == false, "transitioned publication matches response")
  require(provider.recorded["status_generation"] == nil, "empty captured generation removes cached generation")
  require(provider.recorded["writer_generation"] as? String == "", "empty captured generation passed explicitly")
  require(provider.lifecycleGate.isCurrent(operation), "second health preserves generation")
  require(closes == 0 && provider.settingsReleaseCalls == 0, "health never closes owner or releases settings")
}
if !legacy {
  require(datapath.stop() == nil && datapath.stop() == nil && closes == 1, "explicit owner close once")
  require(!datapath.isRunning, "owner retirement unchanged")
}
require(frees == (unavailable || legacy ? 0 : statusCalls), "native string freed once")
print("PASS \(name): actual datapath, sampler, app-message and source-derived provider callbacks")
