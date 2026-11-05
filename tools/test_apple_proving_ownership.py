#!/usr/bin/env python3
"""Run extracted provider ownership code with observed Swift engine doubles.

The gate and ownership statements come from production source. NetworkExtension
and native engines are not run; provider type checks are a separate check.
"""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def block(source, marker):
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[opening + 1:end - 1]


PRELUDE = r'''
import Foundation
import Dispatch

final class MockEngine {
  private let lock = NSLock()
  var stopped = false
  var stopCount = 0
  var entered: DispatchSemaphore?
  var release: DispatchSemaphore?
  func stop() {
    lock.lock()
    defer { lock.unlock() }
    if stopped { return }
    entered?.signal()
    if let release { precondition(release.wait(timeout: .now() + 5) == .success) }
    stopped = true
    stopCount += 1
  }
}
typealias WinsPacketTunnelEngine = MockEngine
typealias WinsWinn3Datapath = MockEngine
struct WinsTunnelConfig {}
'''


class AppleProvingOwnershipTests(unittest.TestCase):
    def test_stop_owns_proof_and_waits_for_inflight_failure_teardown(self):
        gate_source = (ROOT / "apple/WinsTunnelCore/WinsPacketTunnelEngine.swift").read_text()
        gate = "final class WinsTunnelOperationGate {" + block(
            gate_source, "final class WinsTunnelOperationGate"
        ) + "}"
        for platform in ("ios", "macos"):
            source = (ROOT / platform / "PacketTunnel/PacketTunnelProvider.swift").read_text()
            stop = block(source, "override func stopTunnel(")
            capture = "lifecycleGate.invalidate {" + block(stop, "lifecycleGate.invalidate {") + "}"
            lock_start = stop.index("    provingStopLock.lock()")
            lock_end = stop.index("    provingStopLock.unlock()", lock_start) + len("    provingStopLock.unlock()")
            stop_proof = stop[lock_start:lock_end]
            for function, resource, pending, active in (
                ("runWinnDatapathProofConvergence", "engine", "provingPacketEngine", "packetEngine"),
                ("runWinn3StandaloneConvergence", "datapath", "provingWinn3Datapath", "winn3Datapath"),
            ):
                with self.subTest(platform=platform, resource=resource):
                    body = block(source, "private func " + function + "(")
                    register = body[:body.index("    func stopProvingResource()")]
                    failure = block(body, "func stopProvingResource()")
                    promotion = block(body, "let handedOver = self.lifecycleGate.performIfCurrent")
                    promotion = promotion[:promotion.index("              self.activeEngineStatusFields")]
                    program = PRELUDE + gate + f'''
final class Harness {{
  var packetEngine: WinsPacketTunnelEngine?
  var winn3Datapath: WinsWinn3Datapath?
  var provingPacketEngine: WinsPacketTunnelEngine?
  var provingWinn3Datapath: WinsWinn3Datapath?
  let provingStopLock = NSLock()
  let lifecycleGate = WinsTunnelOperationGate()
  var activeConfig: WinsTunnelConfig?
  var activeStatusGeneration = ""
  var activeEngineStatusFields: [String: Any] = [:]
  // The watchdog suite exercises timer behavior; this fixture observes stop ownership.
  var memoryWatchdogStarts = 0
  var memoryWatchdogStops = 0
  func startWinnMemoryWatchdog(lifecycleToken: UInt64) {{ memoryWatchdogStarts += 1 }}
  func stopWinnMemoryWatchdog() {{ memoryWatchdogStops += 1 }}
  static func canceledStartError() -> NSError {{ NSError(domain: "canceled", code: 1) }}
  func register({resource}: MockEngine, lifecycleToken: UInt64, completionHandler: (Error?) -> Void) {{
{register}
  }}
  func fail({resource}: MockEngine, lifecycleToken: UInt64) {{
{failure}
  }}
  func promote({resource}: MockEngine, lifecycleToken: UInt64) -> Bool {{
    lifecycleGate.performIfCurrent(lifecycleToken) {{
{promotion}
    }}
  }}
  func stop(completionHandler: () -> Void) {{
    var engineAtStop: WinsPacketTunnelEngine?
    var winn3AtStop: WinsWinn3Datapath?
    var provingEngineAtStop: WinsPacketTunnelEngine?
    var provingWinn3AtStop: WinsWinn3Datapath?
    var configAtStop: WinsTunnelConfig?
    var statusGenerationAtStop = ""
{capture}
{stop_proof}
    engineAtStop?.stop()
    winn3AtStop?.stop()
    _ = configAtStop
    _ = statusGenerationAtStop
    completionHandler()
  }}
}}

let owner = Harness()
let token = owner.lifecycleGate.begin()
let live = MockEngine()
owner.register({resource}: live, lifecycleToken: token) {{ _ in preconditionFailure("registration canceled") }}
precondition(owner.{pending} === live)
precondition(owner.{active} == nil)
precondition(owner.memoryWatchdogStarts == {1 if platform == "ios" else 0})
owner.stop {{ precondition(live.stopped && live.stopCount == 1) }}
precondition(owner.memoryWatchdogStops == {1 if platform == "ios" else 0})
precondition(owner.{pending} == nil)
precondition(!owner.promote({resource}: live, lifecycleToken: token))
precondition(owner.{active} == nil)

let stale = MockEngine()
var canceled = false
owner.register({resource}: stale, lifecycleToken: token) {{ error in canceled = error != nil }}
precondition(canceled && stale.stopped && owner.{pending} == nil)

let promotedToken = owner.lifecycleGate.begin()
let promoted = MockEngine()
owner.register({resource}: promoted, lifecycleToken: promotedToken) {{ _ in preconditionFailure() }}
precondition(owner.promote({resource}: promoted, lifecycleToken: promotedToken))
precondition(owner.{pending} == nil && owner.{active} === promoted)
owner.stop {{ precondition(promoted.stopped && promoted.stopCount == 1) }}

let failingToken = owner.lifecycleGate.begin()
let failing = MockEngine()
let entered = DispatchSemaphore(value: 0)
let release = DispatchSemaphore(value: 0)
let failureDone = DispatchSemaphore(value: 0)
let stopDone = DispatchSemaphore(value: 0)
failing.entered = entered
failing.release = release
owner.register({resource}: failing, lifecycleToken: failingToken) {{ _ in preconditionFailure() }}
DispatchQueue.global().async {{
  owner.fail({resource}: failing, lifecycleToken: failingToken)
  failureDone.signal()
}}
precondition(entered.wait(timeout: .now() + 5) == .success)
DispatchQueue.global().async {{
  owner.stop {{
    precondition(failing.stopped && failing.stopCount == 1)
    stopDone.signal()
  }}
}}
precondition(stopDone.wait(timeout: .now() + 0.05) == .timedOut)
release.signal()
precondition(failureDone.wait(timeout: .now() + 5) == .success)
precondition(stopDone.wait(timeout: .now() + 5) == .success)
precondition(owner.{pending} == nil)
print("{platform} {resource}: ownership and concurrent stop passed")
'''
                    with tempfile.TemporaryDirectory(prefix="winsvpn-proof-test-") as directory:
                        swift = pathlib.Path(directory) / "main.swift"
                        binary = pathlib.Path(directory) / "proof"
                        swift.write_text(program)
                        subprocess.run(["xcrun", "swiftc", "-swift-version", "5", str(swift),
                                        "-o", str(binary)], check=True, timeout=60)
                        subprocess.run([str(binary)], check=True, timeout=15)


if __name__ == "__main__":
    unittest.main()
