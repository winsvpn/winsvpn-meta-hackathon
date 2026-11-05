import Darwin
import Foundation
import NetworkExtension

/*
 * WinsWinn3Datapath.swift: the Apple PACKET PUMP for winn/3 STANDALONE.
 *
 * ===========================================================================
 * WHAT WAS MISSING, AND WHY THIS FILE IS IT
 * ===========================================================================
 *
 * `WinsWinn3HostContract.swift` describes the three obligations a winn/3 host
 * has: a device, a carrier socket kept off the tunnel, and a clock: and
 * discharges the two that are decisions: the promotion predicate
 * (`WinsWinn3PromotionGate`), the bootstrap-posture check
 * (`WinsWinn3BootstrapPosture`), the carrier-exclusion refusal
 * (`winn3CarrierExclusionIsUsable`) and the create document
 * (`WinsWinn3CreateDocument`). It deliberately contains no moving parts.
 *
 * It also declares `WinsWinn3PacketRelay` and states that
 * `packetFlow.readPackets -> WinnTunnelWriteInbound` and
 * `packetFlow.writePackets <- WinnTunnelReadOutbound` are the two halves of
 * `winn3/tun.Device` on Apple. NOTHING IMPLEMENTED THAT. The protocol existed,
 * the conformance existed, and no code moved a byte between them: a winn/3
 * handle could be created from Swift and then had nothing driving it.
 *
 * This file is that pump, and only that pump. It makes no policy decision, it
 * installs no network settings, it promotes no route, and it does not decide
 * whether a winn/3 session may start: `WinsTunnelConfig.winn3StartRefusalReason`
 * still refuses, `kWinnHostCapabilities` still reports `.absent` on every
 * platform, and a pump that works is not evidence that a session does.
 *
 * ===========================================================================
 * THE DIRECTION NAMES, WHICH ARE THE ENGINE'S AND NOT THE HOST'S
 * ===========================================================================
 *
 * The two ABI names read backwards from inside a provider, and getting them
 * backwards is silent: both take a buffer and return a count.
 *
 *     WinnTunnelWriteInbound   host -> engine.  Packets the OS handed us off
 *                              the utun, on their way OUT to the gateway.
 *                              Lands in `abiDevice.offer`, which is what
 *                              `winn3/tun.Device.ReadPacket` drains.
 *
 *     WinnTunnelReadOutbound   engine -> host.  Packets the tun layer has
 *                              already VALIDATED, on their way IN to the OS.
 *                              Comes from `abiDevice.take`, fed by
 *                              `winn3/tun.Device.WritePacket`.
 *
 * "Inbound" and "outbound" are spelled from the ENGINE's point of view because
 * the ABI is shared with the relay, where they were named first. The property
 * names on this side are spelled from the HOST's, and the two are bridged here
 * once so no caller has to hold both conventions in its head.
 *
 * ===========================================================================
 * WHY A THREAD FOR ONE DIRECTION AND A CALLBACK FOR THE OTHER
 * ===========================================================================
 *
 * They are not symmetric, because the two sides are not.
 *
 * `NEPacketTunnelFlow.readPackets(completionHandler:)` is a one-shot
 * asynchronous read: the idiom is to call it again from inside its own
 * completion handler, which is what `pumpHostToEngine` does. There is no thread
 * to own: the NetworkExtension runtime supplies one.
 *
 * `WinnTunnelReadOutbound` is a BLOCKING call into Go. It parks on a
 * `sync.Cond` until a packet is delivered, the timeout expires, or the device
 * closes. Calling that on a queue that anything else shares is how an appex
 * deadlocks, so it gets a dedicated `Thread`, and it is given a bounded timeout
 * rather than a blocking-forever one so the loop reaches its own exit check
 * even if the engine never delivers anything.
 *
 * ===========================================================================
 * CLOSE IS SAFE FROM ANY THREAD, AND THAT IS A PROPERTY OF THE GO SIDE
 * ===========================================================================
 *
 * `stop()` may be called while the reader thread is parked inside
 * `WinnTunnelReadOutbound`. That is not a race and does not need a lock held
 * across the ABI call, because `WinnTunnelClose` removes the handle from
 * `winn3Registry` under a mutex and then closes the device, which broadcasts
 * and unblocks the parked reader (`errClosed`). A read that arrives AFTER the
 * registry entry is gone gets `errHandle` from the lookup miss. Neither is a
 * use-after-free: the reader holds a Go pointer obtained before the close, and
 * Go's collector (not this file) owns its lifetime.
 *
 * What this file must still not do is call the ABI with a handle it has already
 * closed TWICE, so `handleLock` guards the transition and `stop()` is
 * idempotent.
 */

// MARK: - the C ABI, resolved by name

/// The winn/3 half of the datapath C ABI.
///
/// Resolved with `dlsym` against the process itself even though Apple
/// PacketTunnel targets now force-load the Winn Go archive. This preserves an
/// explicit start-time refusal if staging, architecture selection, or linking
/// produced an appex without the required ABI, instead of deferring discovery
/// until the first packet.
enum WinsWinn3ABI {
  typealias CreateWinn3Fn = @convention(c) (
    UnsafeMutablePointer<CChar>?, Int32, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
  ) -> Int64
  typealias WriteInboundFn = @convention(c) (Int64, UnsafeMutablePointer<CChar>?, Int32) -> Int32
  typealias ReadOutboundFn = @convention(c) (Int64, UnsafeMutablePointer<CChar>?, Int32, Int32) -> Int32
  typealias StatusJSONFn = @convention(c) (Int64) -> UnsafeMutablePointer<CChar>?
  typealias CloseFn = @convention(c) (Int64) -> UnsafeMutablePointer<CChar>?
  typealias FreeStringFn = @convention(c) (UnsafeMutablePointer<CChar>?) -> Void

  typealias EnqueuePacketsFn = @convention(c) (Int64, UnsafeMutableRawPointer?, Int32, Int32) -> Int32
  typealias DequeuePacketsFn = @convention(c) (Int64, UnsafeMutableRawPointer?, Int32, Int32, Int32) -> Int32

  /// `WinsWinn3.createSymbol` is the standalone entry point and is spelled in
  /// the contract file. The other four are shared with the relay: the Go side
  /// dispatches on the handle, which is drawn from one counter, so a handle is
  /// in at most one registry and these four are unambiguous for both datapaths.
  static let writeInboundSymbol = "WinnTunnelWriteInbound"
  static let readOutboundSymbol = "WinnTunnelReadOutbound"
  static let statusJSONSymbol = "WinnTunnelStatusJSON"
  static let closeSymbol = "WinnTunnelClose"
  static let freeStringSymbol = "WinnTunnelFreeString"
  static let enqueuePacketsSymbol = "WinsWinn3EnqueuePackets"
  static let dequeuePacketsSymbol = "WinsWinn3DequeuePackets"

  /// TEST-ONLY symbol override. `nil` in production.
  ///
  /// Apple PacketTunnel targets force-load the reviewed Winn Go archive and
  /// preserve these symbols on the link line. A unit test still uses this
  /// override to prove the pump without depending on a native archive. When
  /// set, `resolve` prefers a symbol table supplied by the test
  /// before asking the dynamic loader, so `WinsWinn3Datapath.start` can be
  /// exercised against a fake ABI. It is never set outside a test target and is
  /// deliberately left `nil` in every shipping build.
  static var testSymbols: [String: UnsafeMutableRawPointer]?

  static func resolve<T>(_ name: String, as type: T.Type) -> T? {
    if let override = testSymbols?[name] {
      return unsafeBitCast(override, to: type)
    }
    guard let image = dlopen(nil, RTLD_NOW | RTLD_LOCAL) else { return nil }
    defer { dlclose(image) }
    guard let pointer = dlsym(image, name) else { return nil }
    return unsafeBitCast(pointer, to: type)
  }

  /// Whether every symbol the pump needs is present.
  ///
  /// Checked as a SET rather than one at a time at first use: a build that has
  /// the create symbol but not the read symbol would start a session and then
  /// carry nothing, which is the failure that looks like censorship.
  static var pumpSymbolsAvailable: Bool {
    resolve(WinsWinn3.createSymbol, as: CreateWinn3Fn.self) != nil
      && resolve(writeInboundSymbol, as: WriteInboundFn.self) != nil
      && resolve(readOutboundSymbol, as: ReadOutboundFn.self) != nil
      && resolve(statusJSONSymbol, as: StatusJSONFn.self) != nil
      && resolve(closeSymbol, as: CloseFn.self) != nil
      && resolve(freeStringSymbol, as: FreeStringFn.self) != nil
  }

  /// Whether the Stage 4 batched packet arrays ABI is present.
  static var batchSymbolsAvailable: Bool {
    resolve(enqueuePacketsSymbol, as: EnqueuePacketsFn.self) != nil
      && resolve(dequeuePacketsSymbol, as: DequeuePacketsFn.self) != nil
  }
}

/// 24-byte packet descriptor matching winn_packet_batch.h C ABI layout exactly.
struct WinsWinn3PacketDescriptor {
  var data: UnsafeMutableRawPointer?
  var length: UInt32
  var capacity: UInt32
  var family: UInt32
  var reserved: UInt32
}

/// The negative codes the datapath ABI returns, named.
///
/// These are `winn_datapath.go`'s `errHandle ... errArgument` and they are shared
/// by the relay and standalone paths. They are enumerated here so a pump can
/// tell "this packet was too big" from "the session is gone": the first is a
/// sizing bug worth reporting, the second is an ordinary teardown.
enum WinsWinn3ABIStatus: Int32 {
  case unknownHandle = -1
  case closed = -2
  case timedOut = -3
  case tooLarge = -4
  case carrierFailed = -5
  case badArgument = -6

  /// True when the loop that saw this code should stop rather than retry.
  /// A timeout is not terminal: it is the reader's own idle tick.
  var isTerminal: Bool {
    switch self {
    case .timedOut:
      return false
    case .unknownHandle, .closed, .carrierFailed, .badArgument, .tooLarge:
      return true
    }
  }
}

// MARK: - the pump

/// Owns one winn/3 standalone handle and moves packets across the C ABI.
///
/// One instance per session. It is NOT reusable after `stop()`: a handle is
/// closed exactly once and a second start would need a second create, which is
/// a decision for the caller that owns the configuration.
final class WinsWinn3Datapath {
  /// How long a single `WinnTunnelReadOutbound` parks before returning
  /// `errTimeout` so the reader loop can check whether it should exit.
  ///
  /// Not "block forever": a forever-blocked reader is only unblocked by the
  /// close, which makes `stop()`'s latency a property of the engine rather than
  /// of this file. Not "a few milliseconds" either: a short timeout turns an
  /// idle tunnel into a spin that costs battery on a phone for no signal.
  static let readTimeoutMilliseconds: Int32 = 250

  /// The floor for the inbound buffer, used until the engine publishes its own
  /// inner MTU. Larger than any inner MTU the plan floor can produce, so the
  /// first reads cannot take `errTooLarge` for a reason this file chose.
  static let readBufferFloor = 2048

  enum StartError: LocalizedError {
    case symbolsUnavailable
    case refused(String)
    case refusedWithoutMessage

    var errorDescription: String? {
      switch self {
      case .symbolsUnavailable:
        return "The winn/3 datapath ABI is not present in this build; the standalone datapath cannot start."
      case .refused(let message):
        return "The winn/3 datapath refused to start: \(message)"
      case .refusedWithoutMessage:
        return "The winn/3 datapath refused to start and supplied no reason."
      }
    }
  }

  private let handleLock = NSLock()
  private var handle: Int64 = 0
  private var stopped = false
  private var receiveSizingFailed = false
  private var engineToHostPumpHalted = false
  /// Set when the host -> engine pump stopped re-arming while the handle is
  /// live. Such a session carries nothing outbound and is not operational.
  private var hostPumpHalted = false

  /// Set false to make both pumps exit at their next check.
  private var pumping = false

  private var readerThread: Thread?

  /// Host-side drop counters. The Go side counts its own queue drops
  /// (`winn3_queue_dropped_*`, renamed 2026-08-09 from
  /// `winn3_host_queue_dropped_*` because the sampler's denylist ate the `host`
  /// token and the host therefore never received either of them); these count
  /// the ones that happen on THIS side of the ABI, which the engine cannot see
  /// and which would otherwise be an unexplained silence.
  private let counterLock = NSLock()
  private var hostToEngineRefused: UInt64 = 0
  private var engineToHostRefused: UInt64 = 0
  private var hostToEnginePackets: UInt64 = 0
  private var engineToHostPackets: UInt64 = 0

  private var readBufferCapacity = WinsWinn3Datapath.readBufferFloor

  /// Host -> engine entry points, resolved ONCE in `start`. The packet path
  /// must not call dlopen/dlsym/dlclose (each takes the dyld lock) per read.
  private var enqueuePackets: WinsWinn3ABI.EnqueuePacketsFn?
  private var writeInbound: WinsWinn3ABI.WriteInboundFn?

  /// The handle, or 0 when the session has not started or has been closed.
  var currentHandle: Int64 {
    handleLock.lock()
    defer { handleLock.unlock() }
    return handle
  }

  var isRunning: Bool {
    handleLock.lock()
    defer { handleLock.unlock() }
    return handle > 0 && !stopped
  }

  // MARK: start

  /// Creates the standalone tunnel.
  ///
  /// - Parameters:
  ///   - document: the JSON from `WinsWinn3CreateDocument.json()`. Never logged
  ///     by this file: it carries the static private key and the admission
  ///     secret.
  ///   - carrierDescriptor: a UDP descriptor the ABI TAKES OWNERSHIP of, or -1
  ///     to let the engine open its own. -1 is only accepted by the Go side when
  ///     the document sets `allow_own_socket`, which on Apple is the normal case
  ///     and is why `winn3CarrierExclusionIsUsable` must be checked BEFORE this
  ///     is called: the excludedRoutes /32 is the only thing keeping that socket
  ///     off the tunnel.
  ///
  /// Starting does NOT begin pumping. `resume(relay:)` does, so a caller can
  /// inspect the status document (the inner MTU it must set on the interface)
  /// before any packet moves.
  func start(document: String, carrierDescriptor: Int32) throws {
    guard WinsWinn3ABI.pumpSymbolsAvailable,
          let create = WinsWinn3ABI.resolve(WinsWinn3.createSymbol, as: WinsWinn3ABI.CreateWinn3Fn.self)
    else {
      throw StartError.symbolsUnavailable
    }

    var errorOut: UnsafeMutablePointer<CChar>?
    let created = document.withCString { pointer -> Int64 in
      let mutable = strdup(pointer)
      defer { free(mutable) }
      return create(mutable, carrierDescriptor, &errorOut)
    }

    guard created > 0 else {
      guard let errorOut else { throw StartError.refusedWithoutMessage }
      let message = String(cString: errorOut)
      WinsWinn3ABI.resolve(WinsWinn3ABI.freeStringSymbol, as: WinsWinn3ABI.FreeStringFn.self)?(errorOut)
      throw StartError.refused(message)
    }

    enqueuePackets = WinsWinn3ABI.batchSymbolsAvailable
      ? WinsWinn3ABI.resolve(WinsWinn3ABI.enqueuePacketsSymbol, as: WinsWinn3ABI.EnqueuePacketsFn.self)
      : nil
    writeInbound = WinsWinn3ABI.resolve(WinsWinn3ABI.writeInboundSymbol, as: WinsWinn3ABI.WriteInboundFn.self)

    handleLock.lock()
    handle = created
    stopped = false
    engineToHostPumpHalted = false
    handleLock.unlock()

    // Size the inbound buffer from the engine's own inner MTU rather than from
    // a constant this file picked. §4.2 makes the inner MTU an obligation, and
    // a buffer below it turns every full-size inbound packet into errTooLarge:
    // a drop that looks exactly like a censored link.
    let published = statusFields()[WinsWinn3PromotionGate.innerMTUKey]
    let innerMTU = Int(clamping: WinsWinn3PromotionGate.unsignedValue(published))
    readBufferCapacity = max(innerMTU + 128, Self.readBufferFloor)
  }

  // MARK: pump

  /// Starts both directions against `relay`.
  ///
  /// `relay` is the provider's `packetFlow`. It is held weakly nowhere and
  /// strongly here for the life of the pump, which matches the appex's own
  /// lifetime: a provider that has torn down has already called `stop()`.
  func resume(relay: WinsWinn3PacketRelay) {
    handleLock.lock()
    guard handle > 0, !stopped, !pumping else {
      handleLock.unlock()
      return
    }
    pumping = true
    handleLock.unlock()

    pumpHostToEngine(relay: relay)

    let readerHandle = currentHandle
    let thread = Thread { [weak self] in
      guard let self else { return }
      defer { self.recordEngineToHostPumpHalted(for: readerHandle) }
      if WinsWinn3ABI.batchSymbolsAvailable {
        self.pumpEngineBatchToHost(relay: relay)
      } else {
        self.pumpEngineToHost(relay: relay)
      }
    }
    thread.name = "org.winsvpn.winn3.datapath.reader"
    // Big enough for the read buffer and the Swift frames above it; the default
    // 512 KiB is more than an appex with a ~50 MiB footprint budget should
    // spend on a loop that owns one buffer.
    thread.stackSize = 128 * 1024
    readerThread = thread
    thread.start()
  }

  /// host -> engine. Re-arms itself from inside its own completion handler,
  /// which is the only supported way to read an `NEPacketTunnelFlow`.
  private func pumpHostToEngine(relay: WinsWinn3PacketRelay) {
    relay.readPackets { [weak self] packets, _ in
      guard let self else { return }
      guard self.shouldKeepPumping() else { return }
      // A zero-length read is no packet, and as a batch descriptor it makes
      // the ABI refuse the WHOLE batch (ERR_ARGUMENT). Drop it here, copying
      // the array only when an empty element is actually present.
      let packets = packets.contains(where: { $0.isEmpty })
        ? packets.filter { !$0.isEmpty }
        : packets

      if self.enqueuePackets != nil {
        var index = 0
        while index < packets.count && self.shouldKeepPumping() {
          let chunkSize = min(32, packets.count - index)
          let ok = self.writeBatchToEngine(packets: packets, offset: index, count: chunkSize)
          if !ok {
            self.recordHostPumpHalted()
            return
          }
          index += chunkSize
        }
      } else {
        for packet in packets {
          guard self.writeToEngine(packet) else {
            self.recordHostPumpHalted()
            return
          }
        }
      }

      guard self.shouldKeepPumping() else { return }
      self.pumpHostToEngine(relay: relay)
    }
  }

  /// Hands a slice of up to 32 packets to the engine in a single CGO call.
  private func writeBatchToEngine(packets: [Data], offset: Int, count: Int) -> Bool {
    guard count > 0 else { return true }
    handleLock.lock()
    let live = handle
    let running = !stopped
    handleLock.unlock()
    guard live > 0, running, let enqueue = enqueuePackets else { return false }

    var descriptors = [WinsWinn3PacketDescriptor](
      repeating: WinsWinn3PacketDescriptor(data: nil, length: 0, capacity: 0, family: 0, reserved: 0),
      count: count
    )

    let written = withBoundPackets(packets: packets, offset: offset, count: count, descriptors: &descriptors, depth: 0) { descBase, descCount in
      enqueue(live, descBase, descCount, 24)
    }

    if written >= 0 {
      counterLock.lock()
      hostToEnginePackets &+= UInt64(written)
      if written < Int32(count) {
        hostToEngineRefused &+= UInt64(Int32(count) - written)
      }
      counterLock.unlock()
      return true
    }

    counterLock.lock()
    hostToEngineRefused &+= UInt64(count)
    counterLock.unlock()
    guard let status = WinsWinn3ABIStatus(rawValue: written) else { return false }
    return !Self.haltsHostToEngine(status)
  }

  private func withBoundPackets(
    packets: [Data],
    offset: Int,
    count: Int,
    descriptors: inout [WinsWinn3PacketDescriptor],
    depth: Int,
    body: (UnsafeMutableRawPointer, Int32) -> Int32
  ) -> Int32 {
    if depth == count {
      return descriptors.withUnsafeMutableBufferPointer { descBuf in
        guard let base = descBuf.baseAddress else { return WinsWinn3ABIStatus.badArgument.rawValue }
        return body(UnsafeMutableRawPointer(base), Int32(count))
      }
    }
    let packet = packets[offset + depth]
    if packet.isEmpty {
      return withBoundPackets(packets: packets, offset: offset, count: count, descriptors: &descriptors, depth: depth + 1, body: body)
    }
    return packet.withUnsafeBytes { raw in
      guard let base = raw.baseAddress else { return WinsWinn3ABIStatus.badArgument.rawValue }
      let family: UInt32 = (packet.first.map { ($0 >> 4) == 6 } ?? false) ? UInt32(AF_INET6) : UInt32(AF_INET)
      descriptors[depth] = WinsWinn3PacketDescriptor(
        data: UnsafeMutableRawPointer(mutating: base),
        length: UInt32(raw.count),
        capacity: UInt32(raw.count),
        family: family,
        reserved: 0
      )
      return withBoundPackets(
        packets: packets,
        offset: offset,
        count: count,
        descriptors: &descriptors,
        depth: depth + 1,
        body: body
      )
    }
  }

  /// Hands one packet to the engine. Returns false when the loop should stop.
  private func writeToEngine(_ packet: Data) -> Bool {
    guard !packet.isEmpty else { return true }
    handleLock.lock()
    let live = handle
    let running = !stopped
    handleLock.unlock()
    guard live > 0, running, let write = writeInbound else { return false }

    let written = packet.withUnsafeBytes { raw -> Int32 in
      guard let base = raw.baseAddress else { return 0 }
      return write(
        live,
        UnsafeMutableRawPointer(mutating: base).assumingMemoryBound(to: CChar.self),
        Int32(raw.count)
      )
    }

    if written >= 0 {
      counterLock.lock()
      hostToEnginePackets &+= 1
      counterLock.unlock()
      return true
    }

    counterLock.lock()
    hostToEngineRefused &+= 1
    counterLock.unlock()
    guard let status = WinsWinn3ABIStatus(rawValue: written) else { return false }
    return !Self.haltsHostToEngine(status)
  }

  /// engine -> host batched pump. Drains up to 32 packets in one CGO call.
  private func pumpEngineBatchToHost(relay: WinsWinn3PacketRelay) {
    guard let dequeue = WinsWinn3ABI.resolve(WinsWinn3ABI.dequeuePacketsSymbol, as: WinsWinn3ABI.DequeuePacketsFn.self)
    else {
      pumpEngineToHost(relay: relay)
      return
    }

    let batchLimit = 32
    let packetCapacity = readBufferCapacity
    var backingStorage = [UInt8](repeating: 0, count: batchLimit * packetCapacity)
    var descriptors = [WinsWinn3PacketDescriptor](
      repeating: WinsWinn3PacketDescriptor(data: nil, length: 0, capacity: 0, family: 0, reserved: 0),
      count: batchLimit
    )

    while shouldKeepPumping() {
      handleLock.lock()
      let live = handle
      let running = !stopped
      handleLock.unlock()
      guard live > 0, running else { return }

      let readCount: Int32 = backingStorage.withUnsafeMutableBufferPointer { storageBuf in
        guard let storageBase = storageBuf.baseAddress else { return WinsWinn3ABIStatus.badArgument.rawValue }
        for i in 0..<batchLimit {
          descriptors[i].data = UnsafeMutableRawPointer(storageBase.advanced(by: i * packetCapacity))
          descriptors[i].length = 0
          descriptors[i].capacity = UInt32(packetCapacity)
          descriptors[i].family = 0
          descriptors[i].reserved = 0
        }
        return descriptors.withUnsafeMutableBufferPointer { descBuf in
          guard let descBase = descBuf.baseAddress else { return WinsWinn3ABIStatus.badArgument.rawValue }
          return dequeue(live, UnsafeMutableRawPointer(descBase), Int32(batchLimit), 24, Self.readTimeoutMilliseconds)
        }
      }

      if readCount > 0 {
        guard readCount <= Int32(batchLimit) else { return }
        var packets = [Data]()
        packets.reserveCapacity(Int(readCount))
        var protocols = [NSNumber]()
        protocols.reserveCapacity(Int(readCount))

        for i in 0..<Int(readCount) {
          let desc = descriptors[i]
          guard desc.length > 0, Int(desc.length) <= packetCapacity else { continue }
          let start = i * packetCapacity
          let end = start + Int(desc.length)
          let packetData = Data(backingStorage[start..<end])
          let family: Int32
          if desc.family != 0 {
            family = Int32(desc.family)
          } else if let first = packetData.first, (first >> 4) == 6 {
            family = AF_INET6
          } else {
            family = AF_INET
          }
          packets.append(packetData)
          protocols.append(NSNumber(value: family))
        }

        if !packets.isEmpty {
          let accepted = relay.writePackets(packets, withProtocols: protocols)
          counterLock.lock()
          if accepted {
            engineToHostPackets &+= UInt64(packets.count)
          } else {
            engineToHostRefused &+= UInt64(packets.count)
          }
          counterLock.unlock()
        }
        continue
      }

      if readCount == 0 { continue }

      guard let status = WinsWinn3ABIStatus(rawValue: readCount) else { return }
      if status == .tooLarge {
        recordReceiveSizingFailure(for: live)
        return
      }
      if status.isTerminal { return }
    }
  }

  /// engine -> host scalar fallback. Runs on its own thread because the read blocks.
  private func pumpEngineToHost(relay: WinsWinn3PacketRelay) {
    guard let read = WinsWinn3ABI.resolve(WinsWinn3ABI.readOutboundSymbol, as: WinsWinn3ABI.ReadOutboundFn.self)
    else { return }

    var buffer = [CChar](repeating: 0, count: readBufferCapacity)

    while shouldKeepPumping() {
      handleLock.lock()
      let live = handle
      let running = !stopped
      handleLock.unlock()
      guard live > 0, running else { return }

      let count = buffer.withUnsafeMutableBufferPointer { raw -> Int32 in
        guard let base = raw.baseAddress else { return WinsWinn3ABIStatus.badArgument.rawValue }
        return read(live, base, Int32(raw.count), Self.readTimeoutMilliseconds)
      }

      if count > 0 {
        let packet = buffer.withUnsafeBufferPointer { raw -> Data in
          guard let base = raw.baseAddress else { return Data() }
          return Data(bytes: base, count: Int(count))
        }
        deliverToHost(packet, relay: relay)
        continue
      }

      // A zero-length read is not a packet and not an error code; treat it as
      // an idle tick rather than inventing a meaning for it.
      if count == 0 { continue }

      guard let status = WinsWinn3ABIStatus(rawValue: count) else { return }
      if status == .tooLarge {
        // The native queue retains this packet; an identical read cannot progress.
        recordReceiveSizingFailure(for: live)
        return
      }
      if status.isTerminal { return }
    }
  }

  private func deliverToHost(_ packet: Data, relay: WinsWinn3PacketRelay) {
    // winn/3's inner layer is IPv4 here; `winn3_inner_ipv6` reports whether the
    // session negotiated a v6 assignment at all, and a config whose floor
    // cannot carry one is refused at create. Reading the version off the packet
    // rather than off the config keeps the two from disagreeing.
    let family: Int32
    if let first = packet.first, (first >> 4) == 6 {
      family = AF_INET6
    } else {
      family = AF_INET
    }
    let accepted = relay.writePackets([packet], withProtocols: [NSNumber(value: family)])
    counterLock.lock()
    if accepted {
      engineToHostPackets &+= 1
    } else {
      engineToHostRefused &+= 1
    }
    counterLock.unlock()
  }

  private func recordEngineToHostPumpHalted(for live: Int64) {
    handleLock.lock()
    defer { handleLock.unlock() }
    guard live > 0, handle == live, !stopped else { return }
    engineToHostPumpHalted = true
  }

  private func recordReceiveSizingFailure(for live: Int64) {
    handleLock.lock()
    guard handle == live, live > 0, !stopped else {
      handleLock.unlock()
      return
    }
    receiveSizingFailed = true
    handleLock.unlock()

    counterLock.lock()
    engineToHostRefused &+= 1
    counterLock.unlock()
  }

  private func recordHostPumpHalted() {
    handleLock.lock()
    if handle > 0, !stopped {
      hostPumpHalted = true
    }
    handleLock.unlock()
  }

  /// The write direction refuses one packet or batch with `tooLarge` or
  /// `badArgument`: that drops those packets, it does not end the session.
  private static func haltsHostToEngine(_ status: WinsWinn3ABIStatus) -> Bool {
    switch status {
    case .unknownHandle, .closed, .carrierFailed:
      return true
    case .timedOut, .tooLarge, .badArgument:
      return false
    }
  }

  private func shouldKeepPumping() -> Bool {
    handleLock.lock()
    defer { handleLock.unlock() }
    return handle > 0 && !stopped && pumping
  }

  // MARK: status

  /// The engine's status document, mapped into the seam namespace.
  ///
  /// Goes through `WinsWinnSeamObservabilitySample` rather than parsing the
  /// JSON here so the winn3 keys land under the same `engineFieldPrefix` the
  /// rest of the host reads, and so `WinsWinn3PromotionGate` can be handed the
  /// result unchanged.
  func statusFields() -> [String: Any] {
    handleLock.lock()
    let live = handle
    handleLock.unlock()
    guard live > 0,
          let status = WinsWinn3ABI.resolve(WinsWinn3ABI.statusJSONSymbol, as: WinsWinn3ABI.StatusJSONFn.self),
          let raw = status(live)
    else { return [:] }
    let text = String(cString: raw)
    WinsWinn3ABI.resolve(WinsWinn3ABI.freeStringSymbol, as: WinsWinn3ABI.FreeStringFn.self)?(raw)
    return WinsWinnSeamObservabilitySample.fields(seamStatsJSON: nil, engineStatusJSON: text)
  }

  /// What the pump itself observed, which the engine cannot report.
  ///
  /// Published under the same `winn3_datapath_proof_` prefix
  /// `WinsWinn3PromotionGate` uses, because a reader looking at why a promotion
  /// did not happen needs both halves in one place.
  func pumpStatusFields() -> [String: Any] {
    // Reports batch symbol availability (1: the enqueue/dequeue pair resolves,
    // 0: it does not, as after a stripped link). Pump counters still
    // establish carriage. Resolve before taking the counter lock.
    let batchABI = WinsWinn3ABI.batchSymbolsAvailable ? 1 : 0
    counterLock.lock()
    defer { counterLock.unlock() }
    return [
      "winn3_datapath_proof_host_to_engine_packets": Int(clamping: hostToEnginePackets),
      "winn3_datapath_proof_host_to_engine_refused": Int(clamping: hostToEngineRefused),
      "winn3_datapath_proof_engine_to_host_packets": Int(clamping: engineToHostPackets),
      "winn3_datapath_proof_engine_to_host_refused": Int(clamping: engineToHostRefused),
      "winn3_datapath_proof_batch_abi": batchABI
    ]
  }

  /// Samples operational health without changing ownership or tunnel routes.
  /// Missing completion evidence is unknown, never proof of a live runtime.
  ///
  /// `isOperational` is what the provider reports to the app as a ready,
  /// connected engine, so a supervised engine must also SAY `connected`: a
  /// recovering engine keeps its tunnel, settings and capture (nothing here
  /// stops or releases anything) but is not reported ready, and a blocked one
  /// is reported action-required, with who observed it. Neither is a reason
  /// for any other protocol. Only an engine that publishes NO lifecycle keeps
  /// the rule it had before; a present but invalid one is refused.
  func healthSnapshot() -> (fields: [String: Any], isOperational: Bool) {
    var fields = statusFields()
    let completed = fields[
      WinsWinnSeamObservabilitySample.engineFieldPrefix + "winn3_runtime_completed"
    ] as? Bool
    let host = WinsWinn3Lifecycle.hostStatus(
      engineStatusFields: fields,
      clock: recoveryClock,
      history: lifecycleHistory
    )
    fields.merge(pumpStatusFields()) { _, new in new }
    fields.merge(host.fields) { _, new in new }
    handleLock.lock()
    let operational = handle > 0 && !stopped && !receiveSizingFailed
      && !hostPumpHalted && !engineToHostPumpHalted
    handleLock.unlock()
    return (fields, operational && completed == false && host.verdict.claimsConnected)
  }

  /// When this host first saw the current recovery episode, on the monotonic
  /// clock (`WinsWinn3RecoveryClock.monotonicSeconds`).
  private let recoveryClock = WinsWinn3RecoveryClock()

  /// What this datapath has seen of the lifecycle (promotion, and whether one
  /// was ever reported). Lives and dies with the datapath.
  private let lifecycleHistory = WinsWinn3LifecycleHistory()

  /// The promotion decision both providers make for THIS datapath, with its
  /// proof recorded into this datapath's lifecycle history before the caller
  /// exposes the datapath. See `WinsWinn3Lifecycle.promotionConverged`.
  func promotionConverged(engineStatusFields fields: [String: Any], probeSatisfied: Bool) -> Bool {
    WinsWinn3Lifecycle.promotionConverged(
      engineStatusFields: fields,
      probeSatisfied: probeSatisfied,
      history: lifecycleHistory
    )
  }

  /// The §4.1 predicate against the engine's live status.
  func converged() -> Bool {
    WinsWinn3PromotionGate.converged(engineStatusFields: statusFields())
  }

  // MARK: stop

  /// Closes the handle. Idempotent, and safe to call while the reader is parked
  /// inside `WinnTunnelReadOutbound`: see the note at the top of this file.
  ///
  /// - Returns: the engine's close error, or nil.
  @discardableResult
  func stop() -> String? {
    handleLock.lock()
    guard handle > 0, !stopped else {
      handleLock.unlock()
      return nil
    }
    let live = handle
    stopped = true
    pumping = false
    handle = 0
    handleLock.unlock()

    var message: String?
    if let closeTunnel = WinsWinn3ABI.resolve(WinsWinn3ABI.closeSymbol, as: WinsWinn3ABI.CloseFn.self),
       let raw = closeTunnel(live) {
      message = String(cString: raw)
      WinsWinn3ABI.resolve(WinsWinn3ABI.freeStringSymbol, as: WinsWinn3ABI.FreeStringFn.self)?(raw)
    }

    // The close above unblocks the reader; wait briefly so the thread is gone
    // before this object can be released. Bounded, because a reader that has
    // not exited is a bug to observe rather than a reason to hang teardown:
    // and the appex's own stop path has a deadline of its own.
    if let thread = readerThread {
      let deadline = Date().addingTimeInterval(2.0)
      while !thread.isFinished && Date() < deadline {
        usleep(2000)
      }
      readerThread = nil
    }
    return message
  }

  deinit {
    stop()
  }
}
