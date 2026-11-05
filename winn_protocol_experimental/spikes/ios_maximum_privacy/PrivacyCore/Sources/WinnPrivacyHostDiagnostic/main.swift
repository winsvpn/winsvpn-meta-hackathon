import Darwin
import Foundation
import WinnPrivacyStageACore

private let diagnosticSchema = "winn-ios-privacy-host-diagnostic/1"
private let minimumDurationMilliseconds: UInt64 = 200
private let maximumDurationMilliseconds: UInt64 = 5_000
private let nanosecondsPerMillisecond: UInt64 = 1_000_000

private enum DiagnosticError: Error, CustomStringConvertible {
  case invalidArguments
  case invalidHash
  case invalidToolchain
  case resourceSamplingUnavailable
  case clockOverflow
  case invariantViolation
  case encodingFailure

  var description: String {
    switch self {
    case .invalidArguments:
      return "invalid or duplicate diagnostic argument"
    case .invalidHash:
      return "source and binary hashes must be nonzero lowercase SHA-256"
    case .invalidToolchain:
      return "toolchain identity is invalid"
    case .resourceSamplingUnavailable:
      return "required host resource counters are unavailable"
    case .clockOverflow:
      return "monotonic diagnostic clock overflow"
    case .invariantViolation:
      return "host diagnostic invariant failed"
    case .encodingFailure:
      return "canonical diagnostic encoding failed"
    }
  }
}

private struct DiagnosticConfiguration {
  let mode: SpikeMode
  let profile: SyntheticTrafficProfile
  let rotation: StageARotationCadence
  let durationMilliseconds: UInt64
  let sourceSHA256: String
  let binarySHA256: String
  let toolchain: String

  static func parse(_ arguments: [String]) throws -> Self {
    let allowed = Set([
      "--mode",
      "--profile",
      "--rotation",
      "--duration-ms",
      "--source-sha256",
      "--binary-sha256",
      "--toolchain",
    ])
    guard arguments.count == allowed.count * 2 else {
      throw DiagnosticError.invalidArguments
    }
    var values: [String: String] = [:]
    var index = 0
    while index < arguments.count {
      let key = arguments[index]
      guard allowed.contains(key),
            values[key] == nil,
            index + 1 < arguments.count
      else {
        throw DiagnosticError.invalidArguments
      }
      values[key] = arguments[index + 1]
      index += 2
    }
    guard values.count == allowed.count,
          let modeValue = values["--mode"],
          let mode = SpikeMode(rawValue: modeValue),
          let profileValue = values["--profile"],
          let profile = SyntheticTrafficProfile(rawValue: profileValue),
          let rotationValue = values["--rotation"],
          let rotation = StageARotationCadence(rawValue: rotationValue),
          let durationText = values["--duration-ms"],
          let durationMilliseconds = UInt64(durationText),
          durationText == String(durationMilliseconds),
          durationMilliseconds >= minimumDurationMilliseconds,
          durationMilliseconds <= maximumDurationMilliseconds,
          let sourceSHA256 = values["--source-sha256"],
          let binarySHA256 = values["--binary-sha256"],
          validSHA256(sourceSHA256),
          validSHA256(binarySHA256),
          let toolchain = values["--toolchain"],
          validToolchain(toolchain)
    else {
      throw DiagnosticError.invalidArguments
    }
    return Self(
      mode: mode,
      profile: profile,
      rotation: rotation,
      durationMilliseconds: durationMilliseconds,
      sourceSHA256: sourceSHA256,
      binarySHA256: binarySHA256,
      toolchain: toolchain
    )
  }

  private static func validSHA256(_ value: String) -> Bool {
    guard value.count == 64,
          value != String(repeating: "0", count: 64)
    else {
      return false
    }
    return value.utf8.allSatisfy {
      ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
    }
  }

  private static func validToolchain(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 160 else {
      return false
    }
    return value.utf8.allSatisfy { $0 >= 32 && $0 <= 126 }
  }
}

private struct HostResourceSample {
  let residentBytes: UInt64
  let physicalFootprintBytes: UInt64
  let userCPUNanoseconds: UInt64
  let systemCPUNanoseconds: UInt64
  let interruptWakeups: UInt64
  let platformIdleWakeups: UInt64
  let thermalProxy: String
}

private enum HostResourceSampler {
  static func sample() throws -> HostResourceSample {
    guard let virtualMemory = taskVirtualMemory(),
          let power = taskPower()
    else {
      throw DiagnosticError.resourceSamplingUnavailable
    }
    return HostResourceSample(
      residentBytes: virtualMemory.resident_size,
      physicalFootprintBytes: virtualMemory.phys_footprint,
      userCPUNanoseconds: try ticksToNanoseconds(power.total_user),
      systemCPUNanoseconds: try ticksToNanoseconds(power.total_system),
      interruptWakeups: power.task_interrupt_wakeups,
      platformIdleWakeups: power.task_platform_idle_wakeups,
      thermalProxy: ProcessInfo.processInfo.thermalState.diagnosticName
    )
  }

  private static func taskVirtualMemory() -> task_vm_info_data_t? {
    var information = task_vm_info_data_t()
    var count = mach_msg_type_number_t(
      MemoryLayout<task_vm_info_data_t>.size /
        MemoryLayout<natural_t>.size
    )
    let result = withUnsafeMutablePointer(to: &information) {
      $0.withMemoryRebound(
        to: integer_t.self,
        capacity: Int(count)
      ) {
        task_info(
          mach_task_self_,
          task_flavor_t(TASK_VM_INFO),
          $0,
          &count
        )
      }
    }
    return result == KERN_SUCCESS ? information : nil
  }

  private static func taskPower() -> task_power_info_data_t? {
    var information = task_power_info_data_t()
    var count = mach_msg_type_number_t(
      MemoryLayout<task_power_info_data_t>.size /
        MemoryLayout<natural_t>.size
    )
    let result = withUnsafeMutablePointer(to: &information) {
      $0.withMemoryRebound(
        to: integer_t.self,
        capacity: Int(count)
      ) {
        task_info(
          mach_task_self_,
          task_flavor_t(TASK_POWER_INFO),
          $0,
          &count
        )
      }
    }
    return result == KERN_SUCCESS ? information : nil
  }

  private static func ticksToNanoseconds(
    _ ticks: UInt64
  ) throws -> UInt64 {
    var timebase = mach_timebase_info_data_t()
    guard mach_timebase_info(&timebase) == KERN_SUCCESS,
          timebase.denom != 0
    else {
      throw DiagnosticError.resourceSamplingUnavailable
    }
    let (scaled, overflow) = ticks.multipliedReportingOverflow(
      by: UInt64(timebase.numer)
    )
    guard !overflow else {
      throw DiagnosticError.clockOverflow
    }
    return scaled / UInt64(timebase.denom)
  }
}

private struct DiagnosticRecord: Encodable {
  let schema: String
  let physicalEvidenceEligible: Bool
  let networkExtensionActivated: Bool
  let stageBActivated: Bool
  let platform: String
  let hardwareModel: String
  let toolchain: String
  let sourceSHA256: String
  let binarySHA256: String
  let mode: String
  let profile: String
  let rotationCadence: String
  let durationMilliseconds: UInt64
  let samples: UInt64
  let residentStartBytes: UInt64
  let residentPeakBytes: UInt64
  let residentEndBytes: UInt64
  let physicalFootprintStartBytes: UInt64
  let physicalFootprintPeakBytes: UInt64
  let physicalFootprintEndBytes: UInt64
  let userCPUDeltaNanoseconds: UInt64
  let systemCPUDeltaNanoseconds: UInt64
  let interruptWakeupDelta: UInt64
  let platformIdleWakeupDelta: UInt64
  let timerCallbacks: UInt64
  let maximumTimerLatenessNanoseconds: UInt64
  let allocatedPrivacyCellBytes: Int
  let inboundQueueDepth: Int
  let outboundQueueDepth: Int
  let inboundHighWatermark: Int
  let outboundHighWatermark: Int
  let droppedCells: UInt64
  let coverPairsAccepted: UInt64
  let coverPairsEmitted: UInt64
  let coverDeadlinesMissed: UInt64
  let rotationCount: UInt64
  let rotationStandbyPresentAtStop: Bool
  let stopLatencyNanoseconds: UInt64
  let workChangedAfterStop: Bool
  let worstThermalProxy: String
  let terminalReason: String
}

private struct ResourceAccumulator {
  private(set) var samples: UInt64 = 0
  private(set) var residentPeakBytes: UInt64 = 0
  private(set) var physicalFootprintPeakBytes: UInt64 = 0
  private(set) var worstThermalProxy = "nominal"

  mutating func add(_ sample: HostResourceSample) {
    samples &+= 1
    residentPeakBytes = max(residentPeakBytes, sample.residentBytes)
    physicalFootprintPeakBytes = max(
      physicalFootprintPeakBytes,
      sample.physicalFootprintBytes
    )
    if sample.thermalProxy.diagnosticRank >
      worstThermalProxy.diagnosticRank
    {
      worstThermalProxy = sample.thermalProxy
    }
  }
}

private func run(
  configuration: DiagnosticConfiguration
) throws -> DiagnosticRecord {
  let durationNanoseconds = configuration.durationMilliseconds
    .multipliedReportingOverflow(by: nanosecondsPerMillisecond)
  guard !durationNanoseconds.overflow else {
    throw DiagnosticError.clockOverflow
  }
  let stageConfiguration = try StageAConfiguration(
    mode: configuration.mode,
    trafficProfile: configuration.profile,
    coverSemantics: .continuousWhileConnected,
    rotationCadence: configuration.rotation,
    testCondition: .smoke,
    durationNanoseconds: 30_000_000_000
  )
  let harness = try StageAHarness(configuration: stageConfiguration)
  let startResource = try HostResourceSampler.sample()
  var resources = ResourceAccumulator()
  resources.add(startResource)

  let startNanoseconds = DispatchTime.now().uptimeNanoseconds
  let (deadlineNanoseconds, deadlineOverflow) =
    startNanoseconds.addingReportingOverflow(durationNanoseconds.partialValue)
  guard !deadlineOverflow else {
    throw DiagnosticError.clockOverflow
  }
  harness.start(nowNanoseconds: startNanoseconds)
  var stoppedByOwner = false
  defer {
    if !stoppedByOwner {
      _ = harness.stop(
        nowNanoseconds: DispatchTime.now().uptimeNanoseconds
      )
    }
  }
  var snapshot = harness.snapshot(nowNanoseconds: startNanoseconds)
  var timerCallbacks: UInt64 = 0
  var maximumTimerLatenessNanoseconds: UInt64 = 0

  while true {
    let beforeSleep = DispatchTime.now().uptimeNanoseconds
    if beforeSleep >= deadlineNanoseconds {
      break
    }
    let requestedDelay = min(
      harness.recommendedNextStepDelayNanoseconds(
        nowNanoseconds: beforeSleep
      ),
      deadlineNanoseconds - beforeSleep
    )
    let (requestedWake, wakeOverflow) =
      beforeSleep.addingReportingOverflow(requestedDelay)
    guard !wakeOverflow else {
      throw DiagnosticError.clockOverflow
    }
    Thread.sleep(
      forTimeInterval: Double(requestedDelay) / 1_000_000_000
    )
    let observed = DispatchTime.now().uptimeNanoseconds
    timerCallbacks &+= 1
    if observed > requestedWake {
      maximumTimerLatenessNanoseconds = max(
        maximumTimerLatenessNanoseconds,
        observed - requestedWake
      )
    }
    snapshot = try harness.step(nowNanoseconds: observed)
    resources.add(try HostResourceSampler.sample())
    if ProcessInfo.processInfo.thermalState == .critical {
      throw DiagnosticError.invariantViolation
    }
  }

  let acceptedBeforeStop = snapshot.dataPath.acceptedCells
  let emittedBeforeStop = snapshot.dataPath.emittedCells
  let stopStarted = DispatchTime.now().uptimeNanoseconds
  let stopped = harness.stop(nowNanoseconds: stopStarted)
  stoppedByOwner = true
  let stopFinished = DispatchTime.now().uptimeNanoseconds
  let afterStop = try harness.step(
    nowNanoseconds: stopFinished.addingClamped(1_000_000_000)
  )
  let workChangedAfterStop =
    afterStop.dataPath.acceptedCells != acceptedBeforeStop ||
    afterStop.dataPath.emittedCells != emittedBeforeStop
  guard stopped.completed,
        !workChangedAfterStop,
        stopped.dataPath.allocatedPrivacyCellBytes ==
          (configuration.mode == .maximumPrivacy ? 2_097_152 : 0),
        stopped.dataPath.inboundHighWatermark <=
          WCF3Constants.defaultRingCapacity,
        stopped.dataPath.outboundHighWatermark <=
          WCF3Constants.defaultRingCapacity
  else {
    throw DiagnosticError.invariantViolation
  }

  let endResource = try HostResourceSampler.sample()
  resources.add(endResource)
  return DiagnosticRecord(
    schema: diagnosticSchema,
    physicalEvidenceEligible: false,
    networkExtensionActivated: false,
    stageBActivated: false,
    platform: "macos-host-proxy",
    hardwareModel: hardwareModel(),
    toolchain: configuration.toolchain,
    sourceSHA256: configuration.sourceSHA256,
    binarySHA256: configuration.binarySHA256,
    mode: configuration.mode.rawValue,
    profile: configuration.profile.rawValue,
    rotationCadence: configuration.rotation.rawValue,
    durationMilliseconds: configuration.durationMilliseconds,
    samples: resources.samples,
    residentStartBytes: startResource.residentBytes,
    residentPeakBytes: resources.residentPeakBytes,
    residentEndBytes: endResource.residentBytes,
    physicalFootprintStartBytes:
      startResource.physicalFootprintBytes,
    physicalFootprintPeakBytes:
      resources.physicalFootprintPeakBytes,
    physicalFootprintEndBytes:
      endResource.physicalFootprintBytes,
    userCPUDeltaNanoseconds: checkedDelta(
      endResource.userCPUNanoseconds,
      startResource.userCPUNanoseconds
    ),
    systemCPUDeltaNanoseconds: checkedDelta(
      endResource.systemCPUNanoseconds,
      startResource.systemCPUNanoseconds
    ),
    interruptWakeupDelta: checkedDelta(
      endResource.interruptWakeups,
      startResource.interruptWakeups
    ),
    platformIdleWakeupDelta: checkedDelta(
      endResource.platformIdleWakeups,
      startResource.platformIdleWakeups
    ),
    timerCallbacks: timerCallbacks,
    maximumTimerLatenessNanoseconds:
      maximumTimerLatenessNanoseconds,
    allocatedPrivacyCellBytes:
      stopped.dataPath.allocatedPrivacyCellBytes,
    inboundQueueDepth: stopped.dataPath.inboundQueueDepth,
    outboundQueueDepth: stopped.dataPath.outboundQueueDepth,
    inboundHighWatermark: stopped.dataPath.inboundHighWatermark,
    outboundHighWatermark: stopped.dataPath.outboundHighWatermark,
    droppedCells: stopped.dataPath.droppedCells,
    coverPairsAccepted: stopped.dataPath.coverPairsAccepted,
    coverPairsEmitted: stopped.dataPath.coverPairsEmitted,
    coverDeadlinesMissed: stopped.dataPath.coverDeadlinesMissed,
    rotationCount: stopped.dataPath.rotationCount,
    rotationStandbyPresentAtStop:
      stopped.dataPath.rotationStandbyCircuit != nil,
    stopLatencyNanoseconds: stopFinished - stopStarted,
    workChangedAfterStop: workChangedAfterStop,
    worstThermalProxy: resources.worstThermalProxy,
    terminalReason: "smoke-duration-reached"
  )
}

private func checkedDelta(_ end: UInt64, _ start: UInt64) -> UInt64 {
  end >= start ? end - start : 0
}

private func hardwareModel() -> String {
  var size = 0
  guard sysctlbyname("hw.machine", nil, &size, nil, 0) == 0,
        size > 1
  else {
    return "unknown"
  }
  var value = [CChar](repeating: 0, count: size)
  guard sysctlbyname("hw.machine", &value, &size, nil, 0) == 0
  else {
    return "unknown"
  }
  return String(cString: value)
}

private func emit(_ record: DiagnosticRecord) throws {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  let data = try encoder.encode(record)
  guard let line = String(data: data, encoding: .utf8),
        !line.contains("\n")
  else {
    throw DiagnosticError.encodingFailure
  }
  FileHandle.standardOutput.write(Data((line + "\n").utf8))
}

private extension UInt64 {
  func addingClamped(_ value: UInt64) -> UInt64 {
    let (sum, overflow) = addingReportingOverflow(value)
    return overflow ? UInt64.max : sum
  }
}

private extension ProcessInfo.ThermalState {
  var diagnosticName: String {
    switch self {
    case .nominal: return "nominal"
    case .fair: return "fair"
    case .serious: return "serious"
    case .critical: return "critical"
    @unknown default: return "unknown"
    }
  }
}

private extension String {
  var diagnosticRank: Int {
    switch self {
    case "nominal": return 0
    case "fair": return 1
    case "serious": return 2
    case "critical": return 3
    default: return 4
    }
  }
}

do {
  let configuration = try DiagnosticConfiguration.parse(
    Array(CommandLine.arguments.dropFirst())
  )
  try emit(run(configuration: configuration))
} catch {
  fputs("WINN_PRIVACY_HOST_DIAGNOSTIC_REFUSED: \(error)\n", stderr)
  exit(64)
}
