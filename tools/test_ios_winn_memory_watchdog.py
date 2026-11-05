#!/usr/bin/env python3
"""Execute production Swift memory gates and watchdogs without native engines.

The watchdog, lifecycle gate, and footprint reader are extracted unchanged.
A retained timer double delivers canceled callbacks deliberately; a second
program uses real Dispatch timers. No NetworkExtension session is started.
"""
from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROVIDER = ROOT / "ios/PacketTunnel/PacketTunnelProvider.swift"


def declaration(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def swift_run(program: str, *, typecheck: bool = False) -> str:
    compiler = shutil.which("swiftc")
    if compiler is None:
        raise unittest.SkipTest("Swift compiler unavailable")
    with tempfile.TemporaryDirectory(prefix="winsvpn-memory-watchdog-") as directory:
        path = pathlib.Path(directory)
        source = path / "main.swift"
        binary = path / "watchdog"
        source.write_text(program, encoding="utf-8", newline="\n")
        commands = [
            ([compiler, "-swift-version", "5", str(source), "-o", str(binary)], 60),
            ([str(binary)], 20),
        ]
        if typecheck:
            commands = [([compiler, "-swift-version", "5", "-typecheck", str(source)], 60)]
        for command, timeout in commands:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
            if result.returncode:
                raise AssertionError(f"Swift check failed ({result.returncode}):\n"
                                     f"{result.stdout}\n{result.stderr}")
        return result.stdout


BASE = r'''
import Foundation
import Dispatch

struct WinsTunnelConfig {
  static let supportedWinnCarrier = "direct-awg"
  static let supportedWinnCarrierWinn3 = "winn3"
  var winnEnabled = true
}

class RecordingProvider {
  var errors: [NSError] = []
  var onCancel: (() -> Void)?
  func cancelTunnelWithError(_ error: Error?) {
    errors.append(error! as NSError)
    onCancel?()
  }
}

final class MemorySamples {
  let lock = NSLock()
  var footprint: Int? = 0
  var count = 0
  var entered: DispatchSemaphore?
  var release: DispatchSemaphore?
  let sampled = DispatchSemaphore(value: 0)
  func set(_ value: Int?) {
    lock.lock()
    footprint = value
    lock.unlock()
  }
  func read() -> Int? {
    lock.lock()
    let value = footprint
    count += 1
    lock.unlock()
    entered?.signal()
    if let release {
      precondition(release.wait(timeout: .now() + 5) == .success)
    }
    sampled.signal()
    return value
  }
}
'''

# Keep canceled handlers and timer owners alive to model a handler already
# delivered by Dispatch before cancel(), including replacement in one token.
TIMER_DOUBLE = r'''
final class DispatchSourceTimer {
  var handler: (() -> Void)?
  var delivered: (() -> Void)?
  var canceled = false
  var resumed = false
  var interval: Double = 0
  var deadline: DispatchTime = .now()
  var retainedOwner: AnyObject?
  var leeway: DispatchTimeInterval = .nanoseconds(0)
  func schedule(deadline: DispatchTime, repeating: Double, leeway: DispatchTimeInterval = .nanoseconds(0)) {
    self.deadline = deadline
    interval = repeating
    self.leeway = leeway
  }
  func setEventHandler(handler: @escaping () -> Void) { self.handler = handler }
  func resume() { resumed = true; delivered = handler }
  func cancel() { canceled = true }
  func fireDelivered() { delivered!() }
}
enum DispatchSource {
  static var timers: [DispatchSourceTimer] = []
  static func makeTimerSource(queue: DispatchQueue) -> DispatchSourceTimer {
    let timer = DispatchSourceTimer()
    timers.append(timer)
    return timer
  }
}
'''


def harness(*, fake_timer: bool) -> str:
    source = PROVIDER.read_text()
    gate_source = (ROOT / "apple/WinsTunnelCore/WinsPacketTunnelEngine.swift").read_text()
    gate = declaration(gate_source, "final class WinsTunnelOperationGate")
    constants = "\n".join(re.findall(
        r"^  private static let (?:winnDirectAwgDatapathRequiredBytes|"
        r"winnStrictPhysicalFootprintCeilingBytes|winnMemoryWatchdogIntervalSeconds|"
        r"winnMemoryWatchdogPromotedIntervalSeconds) = .+$",
        source, re.MULTILINE,
    ))
    members = "\n".join(declaration(source, marker) for marker in (
        "private final class WinnMemoryWatchdog",
        "struct WinsWinnAppexMemoryGate",
        "private func stopWinnMemoryWatchdog()",
        "private func startWinnMemoryWatchdog(lifecycleToken:",
        "override func cancelTunnelWithError(",
        "private func cancelTunnelUnderLifecycleGate(",
    ))
    begin = declaration(source, "let lifecycleToken = lifecycleGate.begin {")
    # Use the actual begin/stop capture blocks, which own watchdog teardown.
    begin = begin[begin.index("{") + 1:-1]
    stop = declaration(source, "override func stopTunnel(")
    stop = declaration(stop, "lifecycleGate.invalidate {")
    stop = stop[stop.index("{") + 1:-1]
    policy_source = (ROOT / "apple/WinsTunnelCore/WinsKillSwitch.swift").read_text()
    policy = (declaration(policy_source, "enum WinsWinnMemoryWatchdogPolicy")
              if "enum WinsWinnMemoryWatchdogPolicy" in policy_source else "")
    return BASE + (TIMER_DOUBLE if fake_timer else "") + gate + "\n" + policy + '''
final class Harness: RecordingProvider {
  static let samples = MemorySamples()
  let lifecycleGate = WinsTunnelOperationGate()
  private let winnMemoryWatchdogQueue = DispatchQueue(label: "watchdog-test")
  private var winnMemoryWatchdog: WinnMemoryWatchdog?
  var activeConfig: WinsTunnelConfig?
  var activeStatusGeneration = ""
  var activeEngineStatusFields: [String: Any] = [:]
  var packetEngine: Int?
  var winn3Datapath: Int?
  var provingPacketEngine: Int?
  var provingWinn3Datapath: Int?
  var statuses: [[String: Any]] = []
''' + constants + "\n" + members + r'''
  static func physicalFootprintBytes() -> Int? { samples.read() }
  static func providerError(code: Int, message: String,
                            statusFields: [String: Any]) -> NSError {
    NSError(domain: "org.winsvpn.PacketTunnel", code: code, userInfo: statusFields)
  }
  func writeProviderStatus(stage: String, config: WinsTunnelConfig?,
                           engineReady: Bool, networkSettingsReady: Bool,
                           error: Error?, extra: [String: Any],
                           statusGeneration: String) { statuses.append(extra) }
  func statusGeneration(options: Int?) -> String { "new" }
  func start(winn: Bool = true) -> UInt64 {
    let options: Int? = nil
    var previousEngine: Int?
    var previousWinn3: Int?
    var previousProvingEngine: Int?
    var previousProvingWinn3: Int?
    let token = lifecycleGate.begin {
''' + begin + r'''
      activeConfig = WinsTunnelConfig(winnEnabled: winn)
    }
    precondition(lifecycleGate.performIfCurrent(token) {
      startWinnMemoryWatchdog(lifecycleToken: token)
    })
    return token
  }
  func stop() {
    var engineAtStop: Int?
    var winn3AtStop: Int?
    var provingEngineAtStop: Int?
    var provingWinn3AtStop: Int?
    var configAtStop: WinsTunnelConfig?
    var statusGenerationAtStop = ""
    lifecycleGate.invalidate {
''' + stop + r'''
    }
  }
  func rearm(_ token: UInt64) {
    precondition(lifecycleGate.performIfCurrent(token) {
      startWinnMemoryWatchdog(lifecycleToken: token)
    })
  }
  func retainedWatchdog() -> AnyObject? { winnMemoryWatchdog }
  func watchdogExists() -> Bool { winnMemoryWatchdog != nil }
}
'''


class IOSWinnMemoryWatchdogTests(unittest.TestCase):
    def test_strict_startup_boundaries_and_unmeasured_inputs(self) -> None:
        program = harness(fake_timer=True) + r'''
let ceiling = 15 * 1024 * 1024
let reserve = 12 * 1024 * 1024
func check(_ footprint: Int?, _ expected: String?, available: Int? = Int.max,
           required: Int = 12 * 1024 * 1024, carrier: String = "winn3") {
  let gate = Harness.WinsWinnAppexMemoryGate(
    availableBytes: available, carrier: carrier, requiredBytes: required,
    physicalFootprintCeilingBytes: ceiling, physicalFootprintBytes: footprint)
  precondition(gate.refusalReason == expected, "wrong refusal: \(String(describing: gate.refusalReason))")
  precondition(gate.allowed == (expected == nil))
  precondition(gate.statusFields["winn_memory_gate_physical_footprint_ceiling_bytes"] as? Int == ceiling)
}
check(0, nil)
check(ceiling - reserve - 1, nil, available: reserve)
check(ceiling - reserve, nil)
check(ceiling - reserve + 1, nil)
check(14 * 1024 * 1024, nil, available: reserve)
check(ceiling - 1, nil)
check(ceiling - 1, nil, required: 0)
check(ceiling, "appex_physical_footprint_ceiling_reached", required: 0)
check(ceiling + 1, "appex_physical_footprint_ceiling_reached")
check(Int.max, "appex_physical_footprint_ceiling_reached")
check(nil, "appex_physical_footprint_unknown")
check(-1, "appex_physical_footprint_unknown")
check(0, "appex_available_memory_unknown", available: nil)
check(0, "appex_available_memory_below_winn_datapath_requirement", available: reserve - 1)
check(0, "appex_available_memory_below_winn_datapath_requirement", available: reserve, required: Int.max)
check(0, "winn_carrier_memory_profile_unmeasured", carrier: "unmeasured")
check(0, nil, carrier: "direct-awg")
check(0, nil, carrier: "")
print("strict startup boundaries passed")
'''
        self.assertIn("strict startup boundaries passed", swift_run(program))

    def test_watchdog_cancellation_and_replacement_races(self) -> None:
        program = harness(fake_timer=True) + r'''
let owner = Harness()
let samples = Harness.samples
let ceiling = 15 * 1024 * 1024
samples.set(ceiling - 1)
let token = owner.start()
let first = DispatchSource.timers.last!
first.retainedOwner = owner.retainedWatchdog()
precondition(first.resumed && first.interval == 1.0)
first.fireDelivered()
precondition(owner.errors.isEmpty && !first.canceled)
samples.set(ceiling)
first.fireDelivered()
precondition(owner.errors.count == 1 && owner.errors[0].code == 1038)
precondition(owner.errors[0].userInfo["winn_memory_sample_phys_footprint_bytes"] as? Int == ceiling)
precondition(first.canceled && !owner.watchdogExists())
first.fireDelivered()
precondition(owner.errors.count == 1)

// A stopped source's already delivered callback cannot affect the next token.
_ = owner.start()
let second = DispatchSource.timers.last!
second.retainedOwner = owner.retainedWatchdog()
first.fireDelivered()
precondition(owner.errors.count == 1 && !second.canceled)
owner.stop()
second.fireDelivered()
precondition(owner.errors.count == 1 && second.canceled && !owner.watchdogExists())

// Timer identity matters even if a source is replaced in the same generation.
let sameToken = owner.start()
let replaced = DispatchSource.timers.last!
replaced.retainedOwner = owner.retainedWatchdog()
owner.rearm(sameToken)
let replacement = DispatchSource.timers.last!
replaced.fireDelivered()
precondition(owner.errors.count == 1 && !replacement.canceled)
samples.set(ceiling)
replacement.fireDelivered()
precondition(owner.errors.count == 2 && owner.errors.last!.code == 1038)
precondition(owner.errors.last!.userInfo["winn_memory_watchdog_sample_failed"] as? Bool == false)
precondition(replacement.canceled)

// Generation rejection also holds while the retained source identity matches.
_ = owner.start()
let invalidated = DispatchSource.timers.last!
owner.lifecycleGate.invalidate()
let sampleCount = samples.count
invalidated.fireDelivered()
precondition(owner.errors.count == 2 && samples.count == sampleCount)
owner.stop()

for footprint in [ceiling + 1] {
  _ = owner.start()
  let timer = DispatchSource.timers.last!
  samples.set(footprint)
  timer.fireDelivered()
  precondition(timer.canceled && owner.errors.last!.code == 1038)
}

// A non-Winn start tears down its predecessor without creating a watchdog.
_ = owner.start()
let beforeNonWinn = DispatchSource.timers.last!
let timerCount = DispatchSource.timers.count
_ = owner.start(winn: false)
precondition(beforeNonWinn.canceled && DispatchSource.timers.count == timerCount)
precondition(!owner.watchdogExists())

// Other cancellation paths stop the timer and invalidate pending callbacks.
let canceledToken = owner.start()
let canceled = DispatchSource.timers.last!
canceled.retainedOwner = owner.retainedWatchdog()
owner.cancelTunnelWithError(NSError(domain: "other", code: 1019))
precondition(canceled.canceled && !owner.lifecycleGate.isCurrent(canceledToken))
let errorsBefore = owner.errors.count
canceled.fireDelivered()
precondition(owner.errors.count == errorsBefore)

// Force begin() to race an in-flight sample. The old session is canceled
// while the lifecycle lock still belongs to it; only then may begin proceed.
samples.set(ceiling)
let raceToken = owner.start()
let racing = DispatchSource.timers.last!
racing.retainedOwner = owner.retainedWatchdog()
samples.entered = DispatchSemaphore(value: 0)
samples.release = DispatchSemaphore(value: 0)
let fireDone = DispatchSemaphore(value: 0)
let beginEntered = DispatchSemaphore(value: 0)
let beginDone = DispatchSemaphore(value: 0)
owner.activeStatusGeneration = "old"
owner.onCancel = { precondition(owner.activeStatusGeneration == "old") }
DispatchQueue.global().async { racing.fireDelivered(); fireDone.signal() }
precondition(samples.entered!.wait(timeout: .now() + 5) == .success)
DispatchQueue.global().async {
  beginEntered.signal()
  _ = owner.start()
  beginDone.signal()
}
precondition(beginEntered.wait(timeout: .now() + 5) == .success)
precondition(beginDone.wait(timeout: .now() + 0.1) == .timedOut)
samples.release!.signal()
precondition(fireDone.wait(timeout: .now() + 5) == .success)
precondition(beginDone.wait(timeout: .now() + 5) == .success)
samples.entered = nil
samples.release = nil
owner.onCancel = nil
precondition(owner.errors.count == errorsBefore + 1)
precondition(!owner.lifecycleGate.isCurrent(raceToken))
let newest = DispatchSource.timers.last!
racing.fireDelivered()
precondition(owner.errors.count == errorsBefore + 1 && !newest.canceled)
owner.stop()
print("watchdog cancellation, teardown, and lifecycle races passed")
'''
        self.assertIn("lifecycle races passed", swift_run(program))

    def test_real_dispatch_timer_samples_periodically_then_stops(self) -> None:
        program = harness(fake_timer=False) + r'''
let owner = Harness()
let samples = Harness.samples
let canceled = DispatchSemaphore(value: 0)
owner.onCancel = { canceled.signal() }
samples.set(15 * 1024 * 1024 - 1)
_ = owner.start()
precondition(samples.sampled.wait(timeout: .now() + 4) == .success)
precondition(samples.sampled.wait(timeout: .now() + 4) == .success)
samples.set(15 * 1024 * 1024)
precondition(canceled.wait(timeout: .now() + 4) == .success)
owner.lifecycleGate.begin {
  precondition(owner.errors.count == 1 && owner.errors[0].code == 1038)
  precondition(!owner.watchdogExists())
}
// Drain the sample that triggered cancellation, then wait beyond one interval.
precondition(samples.sampled.wait(timeout: .now() + 1) == .success)
precondition(samples.sampled.wait(timeout: .now() + 1.2) == .timedOut)
print("real one-second Dispatch timer sampled repeatedly and stopped")
'''
        self.assertIn("sampled repeatedly and stopped", swift_run(program))

    def test_unknown_footprint_samples_do_not_cancel(self) -> None:
        program = harness(fake_timer=True) + r'''
let owner = Harness()
for footprint: Int? in [nil, -1] {
  Harness.samples.set(footprint)
  _ = owner.start()
  let timer = DispatchSource.timers.last!
  timer.retainedOwner = owner.retainedWatchdog()
  timer.fireDelivered()
  precondition(owner.errors.isEmpty && !timer.canceled && owner.watchdogExists())
  precondition(timer.interval == 1.0)
  owner.stop()
  precondition(timer.canceled && !owner.watchdogExists())
}
print("unknown samples ignored without canceling")
'''
        self.assertIn("unknown samples ignored", swift_run(program))

    def test_promoted_pressure_is_telemetry_with_relaxed_cadence(self) -> None:
        program = harness(fake_timer=True) + r'''
let owner = Harness()
Harness.samples.set(15 * 1024 * 1024)
_ = owner.start()
owner.packetEngine = 1
let timer = DispatchSource.timers.last!
timer.retainedOwner = owner.retainedWatchdog()
timer.fireDelivered()
precondition(owner.errors.isEmpty && !timer.canceled && owner.watchdogExists())
precondition(owner.activeEngineStatusFields["winn_memory_watchdog_ceiling_exceeded"] as? Bool == true)
precondition(owner.activeEngineStatusFields["winn_memory_watchdog_canceled"] as? Bool == false)
precondition(timer.interval == 5.0)
if case .seconds(2) = timer.leeway {} else { preconditionFailure("wrong promoted leeway") }
timer.fireDelivered()
precondition(owner.errors.isEmpty && !timer.canceled)
owner.stop()
precondition(timer.canceled && !owner.watchdogExists())
print("promoted pressure remains telemetry")
'''
        self.assertIn("promoted pressure remains telemetry", swift_run(program))

    def test_all_session_handoffs_and_startup_gate_are_wired(self) -> None:
        source = PROVIDER.read_text()
        handoffs = re.findall(
            r"self\.(?:packetEngine = engine|winn3Datapath = datapath)\s+"
            r"self.activeEngineStatusFields = \w+\s+"
            r"self.startWinnMemoryWatchdog\(lifecycleToken: lifecycleToken\)", source)
        self.assertEqual(len(handoffs), 3)
        start = declaration(source, "override func startTunnel(")
        self.assertLess(start.index("winnAppexMemoryGate(for:"),
                        start.index("setTunnelNetworkSettings("))
        gate = declaration(source, "private func winnAppexMemoryGate(for")
        self.assertIn("guard config.winnEnabled", gate)
        self.assertIn("requiredBytes: Self.winnDirectAwgDatapathRequiredBytes", gate)
        self.assertIn("physicalFootprintCeilingBytes: Self.winnStrictPhysicalFootprintCeilingBytes", gate)
        self.assertIn("physicalFootprintBytes: Self.physicalFootprintBytes()", gate)

    @unittest.skipUnless(sys.platform == "darwin", "NetworkExtension requires Darwin")
    def test_watchdog_typechecks_against_networkextension(self) -> None:
        program = harness(fake_timer=False).replace(
            "import Foundation", "import Foundation\nimport NetworkExtension", 1
        ).replace("final class Harness: RecordingProvider",
                  "final class Harness: NEPacketTunnelProvider")
        swift_run(program, typecheck=True)

    @unittest.skipUnless(sys.platform == "darwin", "TASK_VM_INFO requires Darwin")
    def test_production_physical_footprint_reader(self) -> None:
        reader = declaration(PROVIDER.read_text(), "private static func physicalFootprintBytes()")
        program = "import Foundation\nfinal class Sampler {\n" + reader + r'''
  static func verify() {
    let footprint = physicalFootprintBytes()
    precondition(footprint != nil && footprint! > 0)
    print("production TASK_VM_INFO footprint reader passed")
  }
}
Sampler.verify()
'''
        self.assertIn("footprint reader passed", swift_run(program))


if __name__ == "__main__":
    unittest.main()
