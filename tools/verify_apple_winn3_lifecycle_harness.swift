import Foundation

// verify_apple_winn3_lifecycle_harness.swift
//
// Round A3: the Apple host CONSUMING the Winn v3 engine's lifecycle.
//
// Pure. It links every apple/WinsTunnelCore Swift source and drives only the
// host-side functions that read a status document, so it needs no Go archive,
// no socket and no tunnel. Documents go through the SAME sampler and sanitizer
// the provider uses, the SAME host step `WinsWinn3Datapath.healthSnapshot`
// takes (`WinsWinn3Lifecycle.hostStatus`), and the SAME key list and value
// sanitizer the app forwarders in ios/Runner/AppDelegate.swift and
// macos/Runner/MainFlutterWindow.swift iterate.
//
// What it pins:
//   1. the sampler forwards both lifecycle keys, and keeps a PRESENT but
//      invalid lifecycle (wrong type, empty, oversized, unknown) apart from an
//      ABSENT one all the way to the promotion gate;
//   2. the promotion gate never converges on anything but connected or absent;
//   3. the host verdict, including who observed a blocked end;
//   4. the recovery clock is monotonic: wall-clock jumps move nothing;
//   5. every host-derived field has a forwarding path to the app;
//   6. test/fixtures/winn3_host_lifecycle_readiness.json, step by step.

var passed = 0
var failures: [String] = []

func check(_ condition: Bool, _ label: String) {
  if condition {
    passed += 1
    print("  ok  \(label)")
  } else {
    failures.append(label)
    print("  NOT OK  \(label)")
  }
}

func section(_ title: String) {
  print("\n[\(title)]")
}

let prefix = WinsWinnSeamObservabilitySample.engineFieldPrefix
typealias L = WinsWinn3Lifecycle

/// A cdatapath status document with the promotion counters of a proven round
/// and the given lifecycle value (any JSON value, or nil for absent).
func engineDocument(lifecycle: Any?, cause: Any? = nil) -> String {
  var document: [String: Any] = [
    "winn3_gate_state": "carrying",
    "winn3_may_carry": true,
    "winn3_rx_packets": 7,
    "winn3_rx_offered": 7,
    "winn3_runtime_completed": false
  ]
  if let lifecycle { document["winn3_lifecycle"] = lifecycle }
  if let cause { document["winn3_lifecycle_cause"] = cause }
  let data = try! JSONSerialization.data(withJSONObject: document, options: [.sortedKeys])
  return String(data: data, encoding: .utf8)!
}

func sampled(_ json: String) -> [String: Any] {
  WinsWinnSeamObservabilitySample.fields(seamStatsJSON: nil, engineStatusJSON: json)
}

/// The app forwarders' loop, verbatim in shape: every published key the
/// provider status carries, through the same value sanitizer, as `provider_`.
func forwardedToApp(_ status: [String: Any]) -> [String: Any] {
  var fields: [String: Any] = [:]
  for source in WinsWinnSeamObservability.publishedStatusKeys {
    if let value = status[source],
       let mappedValue = WinsPacketTunnelProviderStatus.safeMappedStatusValue(
        value,
        sourceKey: source
       ) {
      fields["provider_" + source] = mappedValue
    }
  }
  return fields
}

/// One lifecycle history per datapath, and a datapath here is its clock. The
/// clock is retained with its history so a freed clock's address can never be
/// reused by a new "datapath" and inherit the old history.
var histories: [ObjectIdentifier: (clock: WinsWinn3RecoveryClock, history: WinsWinn3LifecycleHistory)] = [:]
func historyFor(_ clock: WinsWinn3RecoveryClock) -> WinsWinn3LifecycleHistory {
  if let known = histories[ObjectIdentifier(clock)] { return known.history }
  let made = WinsWinn3LifecycleHistory()
  histories[ObjectIdentifier(clock)] = (clock, made)
  return made
}

final class FakeTime {
  var wall: TimeInterval = 1_000
  var elapsed: TimeInterval = 50
}

func runSamplerTests() {
  section("sampler: the lifecycle keys reach the host, absent kept apart from invalid")
  let recovering = sampled(engineDocument(lifecycle: "recovering"))
  check(recovering[L.lifecycleKey] as? String == "recovering", "winn3_lifecycle survives the sampler and its sanitizer")
  check(recovering[L.lifecycleInvalidKey] == nil, "a valid lifecycle raises no invalid flag")
  for cause in ["never_established", "budget_spent", "terminal"] {
    let fields = sampled(engineDocument(lifecycle: "blocked", cause: cause))
    check(fields[L.causeKey] as? String == cause, "the cause `\(cause)` survives the sampler")
  }
  let absent = sampled(engineDocument(lifecycle: nil))
  check(absent[L.lifecycleKey] == nil && absent[L.lifecycleInvalidKey] == nil,
        "an ABSENT lifecycle publishes neither a value nor an invalid flag")
  check(L.reading(engineStatusFields: absent) == .absent, "absent reads as absent through the real sampler")

  let oversized = String(repeating: "r", count: WinsWinnSeamObservabilitySample.maximumStringFieldLength + 1)
  let invalidCases: [(String, Any)] = [
    ("a number", 1),
    ("a boolean", true),
    ("JSON null", NSNull()),
    ("an object", ["state": "connected"]),
    ("an empty string", ""),
    ("an oversized string", oversized),
    ("an unknown value", "a-state-nobody-defined"),
    ("a wrong-case value", "Connected"),
    ("a padded value", " connected")
  ]
  for (label, value) in invalidCases {
    let fields = sampled(engineDocument(lifecycle: value))
    check(fields[L.lifecycleKey] == nil, "\(label): no lifecycle value is published")
    check(fields[L.lifecycleInvalidKey] as? Bool == true, "\(label): the invalid flag is published")
    check(L.reading(engineStatusFields: fields) == .invalid, "\(label): reads as INVALID, not absent")
    check(!L.permitsConnectedClaim(L.reading(engineStatusFields: fields)), "\(label): refuses the connected claim")
    check(!WinsWinn3PromotionGate.converged(engineStatusFields: fields),
          "\(label): proven counters beside it do NOT converge (no promotion)")
    let freshClock = WinsWinn3RecoveryClock(elapsed: { 0 })
    let verdict = L.hostStatus(engineStatusFields: fields, clock: freshClock, history: historyFor(freshClock)).verdict
    check(verdict == .blocked(.invalidStatus), "\(label): the host verdict is blocked by invalid_status")
    check(!verdict.claimsConnected, "\(label): the provider does not report it ready")
  }
  let badCause = sampled(engineDocument(lifecycle: "blocked", cause: 3))
  check(badCause[L.causeKey] == nil, "an invalid cause publishes no value")
  check(badCause[prefix + "winn3_lifecycle_cause_invalid"] as? Bool == true, "an invalid cause raises its own flag")

  let keys = WinsWinnSeamObservabilitySample.publishedStatusKeys
  for key in [L.lifecycleKey, L.causeKey, L.lifecycleInvalidKey, prefix + "winn3_lifecycle_cause_invalid"] {
    check(keys.contains(key), "the app forwarder lists \(key)")
  }
  check(!WinsWinnSeamObservabilitySample.engineStringFields.contains("winn3_lifecycle"),
        "the lifecycle is not sampled as a free string, where invalid would look absent")
}

func runPromotionTests() {
  section("promotion gate: the lifecycle can only subtract")
  check(WinsWinn3PromotionGate.converged(engineStatusFields: sampled(engineDocument(lifecycle: "connected"))),
        "proven counters with lifecycle connected converge")
  check(WinsWinn3PromotionGate.converged(engineStatusFields: sampled(engineDocument(lifecycle: nil))),
        "proven counters with NO lifecycle converge, exactly as before the field existed")
  for state in ["recovering", "blocked", "stopped", "connecting"] {
    check(!WinsWinn3PromotionGate.converged(engineStatusFields: sampled(engineDocument(lifecycle: state))),
          "proven counters beside lifecycle `\(state)` do NOT converge")
  }
}

func runVerdictTests() {
  section("host verdict")
  for state in L.State.allCases {
    check(L.reading(engineStatusFields: [L.lifecycleKey: state.rawValue]) == .state(state), "`\(state.rawValue)` reads as itself")
  }
  check(L.reading(engineStatusFields: [L.lifecycleKey: 7]) == .invalid, "a non-string value placed directly is invalid")
  check(L.verdict(reading: .absent, recoveringFor: nil) == .unreported, "absent is unreported")
  check(L.verdict(reading: .state(.connected), recoveringFor: nil) == .connected, "connected is connected")
  check(L.verdict(reading: .state(.recovering), recoveringFor: 0) == .recovering, "recovering at the start of an episode")
  check(L.verdict(reading: .state(.recovering), recoveringFor: WinsWinn3RecoveryCeiling.ceilingSeconds) == .recovering,
        "recovering AT the ceiling is still recovering")
  check(L.verdict(reading: .state(.recovering), recoveringFor: WinsWinn3RecoveryCeiling.ceilingSeconds + 0.001)
          == .blocked(.recoveryCeiling),
        "recovering PAST the ceiling is blocked, observed by the HOST ceiling")
  check(L.verdict(reading: .state(.blocked), recoveringFor: nil) == .blocked(.engine), "engine blocked is observed by the engine")
  check(L.verdict(reading: .invalid, recoveringFor: nil) == .blocked(.invalidStatus), "invalid is blocked by invalid_status")
  check(L.verdict(reading: .state(.stopped), recoveringFor: nil) == .notLive, "stopped is not live")
  check(L.verdict(reading: .state(.connecting), recoveringFor: nil) == .notLive, "connecting after proof is not live")

  let engine = L.statusFields(verdict: .blocked(.engine), engineCause: "terminal", recoveringFor: nil)
  check(engine["winn3_recovery_observer"] as? String == "engine", "engine blocked names the engine as observer")
  check(engine["winn3_recovery_cause"] as? String == "terminal", "engine blocked carries the engine's cause")
  let ceiling = L.statusFields(verdict: .blocked(.recoveryCeiling), engineCause: "terminal", recoveringFor: 200)
  check(ceiling["winn3_recovery_observer"] as? String == "recovery_ceiling", "the host ceiling names itself as observer")
  check(ceiling["winn3_recovery_cause"] == nil, "the host ceiling claims no engine cause")
  check(ceiling["winn3_recovery_action_required"] as? Bool == true, "the host ceiling is action-required")
  check(ceiling["winn3_recovery_capture_held"] as? Bool == true, "the host ceiling keeps capture")
  let recovering = L.statusFields(verdict: .recovering, engineCause: nil, recoveringFor: 12.5)
  check(recovering["winn3_recovery_claims_connected"] as? Bool == false, "recovering claims nothing")
  check(recovering["winn3_recovery_capture_held"] as? Bool == true, "recovering holds capture")
  check(recovering["winn3_recovery_observed_ms"] as? Int == 12_500, "the observed episode age is published in ms")
}

func runCeilingTests() {
  section("host ceiling arithmetic")
  let budget = WinsWinn3RecoveryCeiling.handshakeBudgetSeconds()
  check(abs(budget - 23.5) < 1e-9, "failed-handshake budget = 0.5+1+2+4+8+8 = 23.5 s (got \(budget))")
  let episode = WinsWinn3RecoveryCeiling.failedHandshakeEpisodeSeconds
  check(abs(episode - 157.5) < 1e-9, "5 * 23.5 + 5 * 8 = 157.5 s (got \(episode))")
  let ceiling = WinsWinn3RecoveryCeiling.ceilingSeconds
  check(abs(ceiling - 167.5) < 1e-9, "host-selected ceiling = 157.5 + 10 = 167.5 s (got \(ceiling))")
}

func runClockTests() {
  section("recovery clock: monotonic, wall-clock jumps move nothing")
  let time = FakeTime()
  let clock = WinsWinn3RecoveryClock(elapsed: { time.elapsed })
  check(clock.observe(.state(.connected)) == nil, "no episode while connected")
  check(clock.observe(.state(.recovering)) == 0, "an episode starts at its first observation")
  time.wall += 200
  check(clock.observe(.state(.recovering)) == 0, "a FORWARD wall-clock jump of 200 s with no elapsed change ages nothing")
  time.wall -= 3_600
  check(clock.observe(.state(.recovering)) == 0, "a BACKWARD wall-clock jump of an hour ages nothing")
  time.elapsed += 30
  check(clock.observe(.state(.recovering)) == 30, "the episode ages only with elapsed time")
  time.wall += 10_000
  let verdictAfterJump = L.verdict(reading: .state(.recovering), recoveringFor: clock.observe(.state(.recovering)))
  check(verdictAfterJump == .recovering, "a large forward wall jump cannot trip the ceiling")
  check(clock.observe(.state(.connected)) == nil, "connected ends the episode")
  time.elapsed += 1
  check(clock.observe(.state(.recovering)) == 0, "a later episode starts its own clock")
  time.elapsed += 100
  check(clock.observe(.invalid) == 100, "an invalid reading is no delivery proof: the episode keeps aging")
  check(clock.observe(.absent) == 100, "an absent reading is no delivery proof: the episode keeps aging")
  for state in [L.State.blocked, .stopped, .connecting] {
    check(clock.observe(.state(state)) == 100, "`\(state.rawValue)` is no delivery proof: the episode keeps aging")
  }
  time.elapsed += 5
  check(clock.observe(.state(.recovering)) == 105, "a later recovering continues the SAME episode")

  // Anti-vacuity: the same steps on a WALL-clock source do move, so the
  // checks above would catch a Date-based clock.
  let wallTime = FakeTime()
  let wallClock = WinsWinn3RecoveryClock(elapsed: { wallTime.wall })
  _ = wallClock.observe(.state(.recovering))
  wallTime.wall += 200
  check(wallClock.observe(.state(.recovering)) == 200, "anti-vacuity: a wall-based source WOULD see the jump")

  let first = WinsWinn3RecoveryClock.monotonicSeconds()
  let second = WinsWinn3RecoveryClock.monotonicSeconds()
  check(second >= first, "the production source never runs backwards")
}

func runInterruptedSamplingTests() {
  section("interrupted sampling: only engine-proven connected restarts the episode")
  let recovering = sampled(engineDocument(lifecycle: "recovering"))
  let unavailable = sampled("{}")
  check(unavailable.isEmpty && L.reading(engineStatusFields: unavailable) == .absent,
        "an unavailable sample is an empty document, which reads as absent")
  let time = FakeTime()
  time.elapsed = 0
  let clock = WinsWinn3RecoveryClock(elapsed: { time.elapsed })
  let atZero = L.hostStatus(engineStatusFields: recovering, clock: clock, history: historyFor(clock))
  check(atZero.verdict == .recovering, "recovering at 0 s")
  time.elapsed = 166
  let gap = L.hostStatus(engineStatusFields: unavailable, clock: clock, history: historyFor(clock))
  check(gap.verdict == .recovering, "absent at 166 s inside the episode is still recovering, not unreported")
  check(gap.fields["winn3_recovery_observed_ms"] as? Int == 166_000, "and it is 166 s old")
  check(!gap.verdict.claimsConnected, "an absent sample inside an episode claims nothing")
  time.elapsed = 168
  let resumed = L.hostStatus(engineStatusFields: recovering, clock: clock, history: historyFor(clock))
  check(resumed.fields["winn3_recovery_observed_ms"] as? Int == 168_000, "recovering at 168 s is 168 s old, not 0 s")
  check(resumed.verdict == .blocked(.recoveryCeiling), "and it has reached the host ceiling")

  let invalid = sampled(engineDocument(lifecycle: 1))
  let time2 = FakeTime()
  time2.elapsed = 0
  let clock2 = WinsWinn3RecoveryClock(elapsed: { time2.elapsed })
  _ = L.hostStatus(engineStatusFields: recovering, clock: clock2, history: historyFor(clock2))
  time2.elapsed = 100
  check(L.hostStatus(engineStatusFields: invalid, clock: clock2, history: historyFor(clock2)).verdict == .blocked(.invalidStatus),
        "an invalid sample inside an episode keeps its blocked verdict")
  time2.elapsed = 170
  check(L.hostStatus(engineStatusFields: recovering, clock: clock2, history: historyFor(clock2)).verdict == .blocked(.recoveryCeiling),
        "and does not restart the episode: 170 s later it is past the ceiling")

  let connected = sampled(engineDocument(lifecycle: "connected"))
  let time3 = FakeTime()
  time3.elapsed = 0
  let clock3 = WinsWinn3RecoveryClock(elapsed: { time3.elapsed })
  _ = L.hostStatus(engineStatusFields: recovering, clock: clock3, history: historyFor(clock3))
  time3.elapsed = 150
  check(L.hostStatus(engineStatusFields: connected, clock: clock3, history: historyFor(clock3)).verdict == .connected, "connected proof at 150 s")
  time3.elapsed = 160
  let fresh = L.hostStatus(engineStatusFields: recovering, clock: clock3, history: historyFor(clock3))
  check(fresh.fields["winn3_recovery_observed_ms"] as? Int == 0, "real connected proof starts a NEW episode")
  time3.elapsed = 300
  check(L.hostStatus(engineStatusFields: recovering, clock: clock3, history: historyFor(clock3)).verdict == .recovering,
        "140 s into the new episode is inside the ceiling")
  let legacy = WinsWinn3RecoveryClock(elapsed: { 0 })
  check(L.hostStatus(engineStatusFields: unavailable, clock: legacy, history: historyFor(legacy)).verdict == .unreported,
        "absent with no episode open is still a legacy engine")
}

func runPostProofStateTests() {
  section("post-proof states: per-datapath history keeps capture actionable")
  func proven(_ lifecycle: Any?) -> [String: Any] { sampled(engineDocument(lifecycle: lifecycle)) }
  let clock = WinsWinn3RecoveryClock(elapsed: { 0 })
  let history = WinsWinn3LifecycleHistory()
  func step(_ lifecycle: Any?) -> (verdict: L.Verdict, fields: [String: Any]) {
    L.hostStatus(engineStatusFields: proven(lifecycle), clock: clock, history: history)
  }
  check(step("connected").verdict == .connected, "promoted: connected")
  let stopped = step("stopped")
  check(stopped.verdict == .blocked(.sessionEnded), "stopped after proof is blocked by session_ended")
  check(stopped.fields["winn3_recovery_capture_held"] as? Bool == true, "stopped after proof: capture is held")
  check(stopped.fields["winn3_recovery_action_required"] as? Bool == true, "stopped after proof: action required")
  check(stopped.fields["winn3_recovery_observer"] as? String == "session_ended", "stopped after proof names session_ended")
  check(!stopped.verdict.claimsConnected, "stopped after proof claims nothing")
  check(step("connected").verdict == .connected, "reversible: a later engine-proven connected is connected again")
  let connecting = step("connecting")
  check(connecting.verdict == .blocked(.invalidTransition), "connecting after proof is an invalid transition")
  check(connecting.fields["winn3_recovery_capture_held"] as? Bool == true, "connecting after proof: capture is held")
  check(step("connected").verdict == .connected, "and reversible too")
  let gone = step(nil)
  check(gone.verdict == .blocked(.invalidTransition), "a lifecycle that disappears outside an episode is an invalid transition")
  check(!gone.verdict.claimsConnected, "a disappeared lifecycle never permits a connected claim")
  check(gone.fields["winn3_recovery_action_required"] as? Bool == true, "and it is actionable")
  let empty = L.hostStatus(engineStatusFields: sampled("{}"), clock: clock, history: history)
  check(empty.verdict == .blocked(.invalidTransition), "an unavailable sample after a reported lifecycle claims nothing either")

  let fresh = WinsWinn3LifecycleHistory()
  let freshClock = WinsWinn3RecoveryClock(elapsed: { 0 })
  func pre(_ lifecycle: Any?) -> L.Verdict {
    L.hostStatus(engineStatusFields: proven(lifecycle), clock: freshClock, history: fresh).verdict
  }
  check(pre("stopped") == .notLive, "stopped BEFORE any proof on this datapath is not live, not a held session")
  check(pre("connecting") == .notLive, "connecting before any proof is not live")

  let legacy = WinsWinn3LifecycleHistory()
  let legacyClock = WinsWinn3RecoveryClock(elapsed: { 0 })
  for n in 1...3 {
    let v = L.hostStatus(engineStatusFields: proven(nil), clock: legacyClock, history: legacy).verdict
    check(v == .unreported, "a datapath that never reported a lifecycle stays legacy (sample \(n))")
  }
  check(legacy.record(.absent) == .none, "absence alone records nothing")
}

func runPromotionHandoffTests() {
  section("promotion handoff: the providers' own gate records promotion before exposure")
  // Exactly what both PacketTunnelProvider timers now run on the proving
  // datapath (`datapath.promotionConverged(engineStatusFields:probeSatisfied:)`),
  // then the health sample the app message takes. There is NO connected
  // health sample in between: the provider's promotion never takes one.
  let proof = sampled(engineDocument(lifecycle: "connected"))
  let followUps: [(String, [String: Any], L.Observer)] = [
    ("stopped", sampled(engineDocument(lifecycle: "stopped")), .sessionEnded),
    ("connecting", sampled(engineDocument(lifecycle: "connecting")), .invalidTransition),
    ("a missing lifecycle", sampled(engineDocument(lifecycle: nil)), .invalidTransition),
    ("an unavailable sample", sampled("{}"), .invalidTransition)
  ]
  for (label, fields, observer) in followUps {
    let history = WinsWinn3LifecycleHistory()
    let clock = WinsWinn3RecoveryClock(elapsed: { 0 })
    check(L.promotionConverged(engineStatusFields: proof, probeSatisfied: true, history: history),
          "promotion on connected proof passes the providers' gate (\(label))")
    let first = L.hostStatus(engineStatusFields: fields, clock: clock, history: history)
    check(first.verdict == .blocked(observer), "\(label) as the FIRST health sample after promotion is blocked by \(observer.rawValue)")
    check(first.fields["winn3_recovery_capture_held"] as? Bool == true, "\(label) first: capture is held")
    check(first.fields["winn3_recovery_action_required"] as? Bool == true, "\(label) first: action required")
    check(!first.verdict.claimsConnected, "\(label) first: claims nothing")
    let forwarded = forwardedToApp(first.fields)
    check(forwarded["provider_winn3_recovery_observer"] as? String == observer.rawValue,
          "\(label) first: the observer reaches the app")
    let later = L.hostStatus(engineStatusFields: proof, clock: clock, history: history)
    check(later.verdict == .connected, "\(label): a later engine-proven connected recovers")
  }

  let refused = WinsWinn3LifecycleHistory()
  check(!L.promotionConverged(engineStatusFields: proof, probeSatisfied: false, history: refused),
        "an unsatisfied probe refuses promotion")
  check(refused.record(.absent) == .none, "and a refused promotion records nothing")
  let unproven = WinsWinn3LifecycleHistory()
  check(!L.promotionConverged(engineStatusFields: sampled(engineDocument(lifecycle: "recovering")),
                              probeSatisfied: true, history: unproven),
        "recovering never promotes")

  let legacy = WinsWinn3LifecycleHistory()
  let legacyClock = WinsWinn3RecoveryClock(elapsed: { 0 })
  check(L.promotionConverged(engineStatusFields: sampled(engineDocument(lifecycle: nil)),
                             probeSatisfied: true, history: legacy),
        "a legacy engine (no lifecycle) still promotes on its counters")
  check(L.hostStatus(engineStatusFields: sampled(engineDocument(lifecycle: nil)), clock: legacyClock,
                     history: legacy).verdict == .unreported,
        "and keeps legacy absence semantics after promotion")

  // The production datapath itself: its wrapper, its own history, its own
  // healthSnapshot. With no native handle its live sample is unavailable,
  // which is the fourth case above.
  let promoted = WinsWinn3Datapath()
  check(promoted.promotionConverged(engineStatusFields: proof, probeSatisfied: true),
        "WinsWinn3Datapath.promotionConverged passes on connected proof")
  let snapshot = promoted.healthSnapshot()
  check(snapshot.fields["winn3_recovery_state"] as? String == "blocked",
        "the promoted datapath's first healthSnapshot is blocked, not unreported")
  check(snapshot.fields["winn3_recovery_observer"] as? String == "invalid_transition",
        "by invalid_transition")
  check(snapshot.fields["winn3_recovery_capture_held"] as? Bool == true, "with capture held")
  check(!snapshot.isOperational, "and not reported ready")
  let never = WinsWinn3Datapath()
  check(never.healthSnapshot().fields["winn3_recovery_state"] as? String == "unreported",
        "a datapath that was never promoted and never reported stays unreported")
}

func runForwardingTests() {
  section("forwarding: host-derived fields reach the app")
  let keys = Set(WinsWinnSeamObservability.publishedStatusKeys)
  for key in L.hostStatusKeys {
    check(keys.contains(key), "the app forwarder lists \(key)")
  }
  let verdicts: [L.Verdict] = [
    .connected, .recovering, .blocked(.engine), .blocked(.recoveryCeiling), .blocked(.invalidStatus),
    .blocked(.sessionEnded), .blocked(.invalidTransition), .notLive, .unreported
  ]
  for verdict in verdicts {
    let fields = L.statusFields(verdict: verdict, engineCause: "budget_spent", recoveringFor: 3)
    for (key, value) in fields {
      check(L.hostStatusKeys.contains(key), "\(verdict.wire): \(key) is a declared host key")
      let forwarded = forwardedToApp(fields)["provider_" + key]
      check(forwarded != nil && "\(forwarded!)" == "\(value)", "\(verdict.wire): \(key) reaches the app unchanged")
    }
  }
}

func runFixtureTests() {
  section("fixture: test/fixtures/winn3_host_lifecycle_readiness.json")
  guard let data = FileManager.default.contents(atPath: "test/fixtures/winn3_host_lifecycle_readiness.json"),
        let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
        let steps = root["apple"] as? [[String: Any]] else {
    check(false, "the fixture could not be read")
    return
  }
  check(steps.count >= 8, "the fixture has its Apple steps (\(steps.count))")
  let time = FakeTime()
  var clock = WinsWinn3RecoveryClock(elapsed: { time.elapsed })
  for step in steps {
    let name = step["step"] as? String ?? "?"
    if step["new_datapath"] as? Bool == true {
      clock = WinsWinn3RecoveryClock(elapsed: { time.elapsed })
    }
    time.elapsed = (step["at_seconds"] as? NSNumber)?.doubleValue ?? -1
    let engine = step["engine"] as? [String: Any] ?? [:]
    let json = String(data: try! JSONSerialization.data(withJSONObject: engine, options: [.sortedKeys]), encoding: .utf8)!
    var fields = sampled(json)
    if step["promote"] as? Bool == true {
      // The providers' promotion gate, not a health sample: it publishes no
      // host verdict of its own.
      let promotedNow = L.promotionConverged(
        engineStatusFields: fields,
        probeSatisfied: true,
        history: historyFor(clock)
      )
      check(promotedNow == (step["converged"] as? Bool), "\(name): promoted by the providers' gate")
      check((step["forwarded"] as? [String: Any] ?? [:]).isEmpty, "\(name): promotion forwards no host verdict")
      continue
    }
    let converged = WinsWinn3PromotionGate.converged(engineStatusFields: fields)
    check(converged == (step["converged"] as? Bool), "\(name): converged is \(step["converged"] ?? "?")")
    let host = L.hostStatus(engineStatusFields: fields, clock: clock, history: historyFor(clock))
    fields.merge(host.fields) { _, new in new }
    let forwarded = forwardedToApp(fields).filter { key, _ in
      key.hasPrefix("provider_winn3_recovery_") || key.hasPrefix("provider_" + L.lifecycleKey)
    }
    let expected = step["forwarded"] as? [String: Any] ?? [:]
    let same = NSDictionary(dictionary: forwarded).isEqual(to: expected)
    if !same {
      print("    expected \(expected)")
      print("    forwarded \(forwarded)")
    }
    check(same, "\(name): the forwarded lifecycle keys equal the fixture")
    let claims = (expected["provider_winn3_recovery_claims_connected"] as? Bool) ?? false
    check(host.verdict.claimsConnected == claims, "\(name): the provider reports ready only when it claims connected")
  }
}

@main
struct WinsAppleWinn3LifecycleHarness {
  static func main() {
    runSamplerTests()
    runPromotionTests()
    runVerdictTests()
    runCeilingTests()
    runClockTests()
    runInterruptedSamplingTests()
    runPostProofStateTests()
    runPromotionHandoffTests()
    runForwardingTests()
    runFixtureTests()

    print("")
    if failures.isEmpty {
      print("Apple winn3 lifecycle harness passed: \(passed)/\(passed) checks.")
      exit(0)
    }
    print("Apple winn3 lifecycle harness FAILED: \(failures.count) of \(passed + failures.count) checks.")
    for failure in failures {
      print("  FAIL  \(failure)")
    }
    exit(1)
  }
}
