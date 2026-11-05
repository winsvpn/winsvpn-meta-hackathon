import Darwin
import Foundation

// Fake dependencies only. No archive, provider, route or socket is loaded.
enum WinsWinn3 { static let createSymbol = "WinnTunnelCreateWinn3" }
protocol WinsWinn3PacketRelay: AnyObject {
  func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void)
  func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool
}
enum WinsWinn3PromotionGate {
  static let innerMTUKey = "fixture_inner_mtu"
  static func unsignedValue(_ value: Any?) -> UInt64 { (value as? NSNumber)?.uint64Value ?? 0 }
  static func converged(engineStatusFields: [String: Any]) -> Bool { false }
}
enum WinsWinnSeamObservabilitySample {
  static let engineFieldPrefix = "engine_"
  static func fields(seamStatsJSON: String?, engineStatusJSON: String?) -> [String: Any] {
    guard let text = engineStatusJSON, let data = text.data(using: .utf8),
          let fields = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { return [:] }
    return fields
  }
}
func require(_ condition: @autoclosure () -> Bool, _ message: String) {
  if !condition() { print("FAIL: \(message)"); exit(1) }
}
let mode = CommandLine.arguments[1]
let batch = mode.hasPrefix("batch_")
let stale = mode.hasSuffix("stale")
let ordinary = mode.hasSuffix("ordinary")
let prefix = mode == "batch_prefix_short"
let tiny = Data([0x45, 0, 0, 4])
final class State {
  let lock = NSLock()
  let entered = DispatchSemaphore(value: 0)
  let releaseRead = DispatchSemaphore(value: 0)
  let finishedResult = DispatchSemaphore(value: 0)
  var reads = 0
  var creates = 0
  var closes = 0
  var writes = 0
  func nextRead() -> Int32 {
    lock.lock(); reads += 1; let number = reads; lock.unlock()
    entered.signal()
    if stale {
      require(releaseRead.wait(timeout: .now() + 2) == .success, "owner close releases pending fake read")
      finishedResult.signal()
      return WinsWinn3ABIStatus.tooLarge.rawValue
    }
    if ordinary {
      if number == 1 { return WinsWinn3ABIStatus.timedOut.rawValue }
      if number == 2 { return 0 }
      if number == 3 { return 1 }
      finishedResult.signal()
      return WinsWinn3ABIStatus.closed.rawValue
    }
    if prefix && number == 1 { return 1 }
    finishedResult.signal()
    return WinsWinn3ABIStatus.tooLarge.rawValue
  }
  func counts() -> (reads: Int, creates: Int, closes: Int, writes: Int) {
    lock.lock(); defer { lock.unlock() }; return (reads, creates, closes, writes)
  }
}
let state = State()
final class Relay: WinsWinn3PacketRelay {
  let lock = NSLock()
  var callback: (@Sendable ([Data], [NSNumber]) -> Void)?
  var received: [Data] = []
  var families: [NSNumber] = []
  func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void) {
    lock.lock(); callback = completionHandler; lock.unlock()
  }
  func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool {
    lock.lock(); received += packets; families += protocols; lock.unlock(); return true
  }
  func deliverHostPacket() {
    lock.lock(); let handler = callback; callback = nil; lock.unlock()
    handler?([tiny], [NSNumber(value: AF_INET)])
  }
  func delivered() -> ([Data], [NSNumber]) {
    lock.lock(); defer { lock.unlock() }; return (received, families)
  }
}
func fakeCreate(_ text: UnsafeMutablePointer<CChar>?, _ fd: Int32, _ error: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int64 {
  state.lock.lock(); state.creates += 1; let handle = Int64(40 + state.creates); state.lock.unlock()
  error?.pointee = nil
  return handle
}
func fakeWrite(_ h: Int64, _ p: UnsafeMutablePointer<CChar>?, _ n: Int32) -> Int32 {
  state.lock.lock(); state.writes += 1; state.lock.unlock(); return n
}
func fakeRead(_ h: Int64, _ p: UnsafeMutablePointer<CChar>?, _ n: Int32, _ timeout: Int32) -> Int32 {
  require(h == 41 && p != nil && n == 2048 && timeout == 250, "ordinary scalar arguments")
  let result = state.nextRead()
  if result > 0 { tiny.withUnsafeBytes { raw in memcpy(p!, raw.baseAddress!, tiny.count) }; return Int32(tiny.count) }
  return result
}
func fakeEnqueue(_ h: Int64, _ p: UnsafeMutableRawPointer?, _ n: Int32, _ stride: Int32) -> Int32 {
  state.lock.lock(); state.writes += 1; state.lock.unlock(); return n
}
func fakeDequeue(_ h: Int64, _ p: UnsafeMutableRawPointer?, _ n: Int32, _ stride: Int32, _ timeout: Int32) -> Int32 {
  require(h == 41 && p != nil && n == 32 && stride == 24 && timeout == 250, "ordinary batch arguments")
  let result = state.nextRead()
  if result > 0 {
    let descriptor = p!.assumingMemoryBound(to: WinsWinn3PacketDescriptor.self)
    require(descriptor.pointee.capacity == 2048, "unchanged capacity")
    tiny.withUnsafeBytes { raw in memcpy(descriptor.pointee.data!, raw.baseAddress!, tiny.count) }
    descriptor.pointee.length = UInt32(tiny.count)
    descriptor.pointee.family = UInt32(AF_INET)
  }
  return result
}
func fakeStatus(_ h: Int64) -> UnsafeMutablePointer<CChar>? {
  strdup("{\"fixture_inner_mtu\":1280,\"engine_winn3_runtime_completed\":false}")
}
func fakeClose(_ h: Int64) -> UnsafeMutablePointer<CChar>? {
  state.lock.lock(); state.closes += 1; state.lock.unlock()
  if stale { state.releaseRead.signal() }
  return nil
}
func fakeFree(_ p: UnsafeMutablePointer<CChar>?) { free(p) }
func ptr<T>(_ value: T) -> UnsafeMutableRawPointer { unsafeBitCast(value, to: UnsafeMutableRawPointer.self) }
let create: WinsWinn3ABI.CreateWinn3Fn = fakeCreate
let write: WinsWinn3ABI.WriteInboundFn = fakeWrite
let read: WinsWinn3ABI.ReadOutboundFn = fakeRead
let enqueue: WinsWinn3ABI.EnqueuePacketsFn = fakeEnqueue
let dequeue: WinsWinn3ABI.DequeuePacketsFn = fakeDequeue
let status: WinsWinn3ABI.StatusJSONFn = fakeStatus
let close: WinsWinn3ABI.CloseFn = fakeClose
let release: WinsWinn3ABI.FreeStringFn = fakeFree
var symbols = [WinsWinn3.createSymbol: ptr(create), WinsWinn3ABI.writeInboundSymbol: ptr(write), WinsWinn3ABI.readOutboundSymbol: ptr(read), WinsWinn3ABI.statusJSONSymbol: ptr(status), WinsWinn3ABI.closeSymbol: ptr(close), WinsWinn3ABI.freeStringSymbol: ptr(release)]
if batch { symbols[WinsWinn3ABI.enqueuePacketsSymbol] = ptr(enqueue); symbols[WinsWinn3ABI.dequeuePacketsSymbol] = ptr(dequeue) }
WinsWinn3ABI.testSymbols = symbols
require(WinsWinn3ABI.pumpSymbolsAvailable && WinsWinn3ABI.batchSymbolsAvailable == batch, "fake ABI selection; no native archive")
let pump = WinsWinn3Datapath()
try pump.start(document: "{}", carrierDescriptor: -1)
require(pump.healthSnapshot().isOperational, "fresh instance with native completion false is operational")
let relay = Relay()
pump.resume(relay: relay)
require(state.entered.wait(timeout: .now() + 2) == .success, "reader entered")
if stale {
  require(pump.stop() == nil, "owner stop joins pending reader")
  // Reflection only after owner stop joined the reader; no production test API.
  let failed = Mirror(reflecting: pump).children.first { $0.label == "receiveSizingFailed" }?.value as? Bool
  require(failed == false, "stale handle failure not attributed")
} else {
  require(state.finishedResult.wait(timeout: .now() + 2) == .success, "finite fake sequence reaches terminal result")
  if !ordinary {
    let deadline = Date().addingTimeInterval(2)
    while pump.healthSnapshot().isOperational && Date() < deadline { usleep(1000) }
    require(!pump.healthSnapshot().isOperational, "local sizing failure overrides native completion false")
  } else { require(pump.healthSnapshot().isOperational, "ordinary timeout/zero/success do not latch sizing failure") }
  require(pump.isRunning && pump.currentHandle == 41 && state.counts().closes == 0, "ownership stays with caller")
  let calls = state.counts().reads
  pump.resume(relay: relay)
  relay.deliverHostPacket()
  require(state.counts().writes == 1, "opposite direction still accepts ordinary packet")
  require(pump.stop() == nil, "owner stop")
  require(state.counts().reads == calls, "no second failed read or duplicate resume reader")
}
require(pump.stop() == nil && state.counts().closes == 1, "owner closes once")
let expectedReads = ordinary ? 4 : (prefix ? 2 : 1)
require(state.counts().reads == expectedReads, "exact bounded read sequence")
let fields = pump.pumpStatusFields()
require(fields["winn3_datapath_proof_engine_to_host_refused"] as? Int == (ordinary || stale ? 0 : 1), "exact refusal count, no stale attribution")
let successful = ordinary || prefix
require(fields["winn3_datapath_proof_engine_to_host_packets"] as? Int == (successful ? 1 : 0), "accepted prefix counter")
let delivered = relay.delivered()
require(delivered.0 == (successful ? [tiny] : []) && delivered.1 == (successful ? [NSNumber(value: AF_INET)] : []), "prefix bytes/family preserved")
let fresh = WinsWinn3Datapath()
try fresh.start(document: "{}", carrierDescriptor: -1)
require(fresh.currentHandle == 42 && fresh.healthSnapshot().isOperational, "new instance isolated from old latch")
require(fresh.stop() == nil && state.counts().closes == 2, "fresh owner closes once")
WinsWinn3ABI.testSymbols = nil
print("PASS \(mode): receive sizing, health, ownership, prefix and fresh instance")
