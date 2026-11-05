import Foundation

/*
 * winn3_conformance_swift_harness.swift — the APPLE half of the winn/3
 * cross-host conformance suite.
 *
 * ===========================================================================
 * WHAT IT PROVES
 * ===========================================================================
 *
 * That the REAL Apple host — WinsTunnelConfig's `[winn]` readers and
 * WinsWinn3CreateDocument, compiled unmodified from apple/WinsTunnelCore —
 * hands the engine the same admission-tag inputs the gateway derives from the
 * same operator configuration.
 *
 * This is the platform defect 1 was on. `cdatapath` base64-decoded `gateway_id`
 * while the four other call sites took the operator string's raw bytes, so
 * Apple was the one host that computed a different tag from the same operator
 * value — and a v3 gateway does not answer a datagram it could not
 * authenticate. No response, no ICMP, no log line, and on a censored network
 * that is indistinguishable from the gateway being blocked.
 *
 * The fix moved the decode to the DESCRIPTOR BOUNDARY, in
 * `WinsTunnelConfig.winn3GatewayIDOperatorText`. That boundary is now the thing
 * under test: the descriptor genuinely carries base64, so exactly one decode
 * must happen and it must happen here.
 *
 * ===========================================================================
 * WHAT THIS HOST DOES NOT DERIVE, AND WHY THAT IS CORRECT
 * ===========================================================================
 *
 * The plan floor. `WinsWinn3Settings.bootstrap` takes `innerMTU` as a parameter
 * and says so in its own doc comment:
 *
 *   > It is NOT recomputed here: the plan floor is driver.NewSizing over the
 *   > whole migration plan, and a second implementation of that arithmetic in
 *   > Swift would be a number that can disagree with the engine's.
 *
 * That is the right call and this harness must not undermine it by computing
 * one. So the sizing fields are declared `not_derived` — which the verifier
 * treats as a claim to be checked, not as a skip: a host that declares a field
 * not derived and then reports a value for it fails.
 *
 * Android is the opposite case and its harness reports real floors, because
 * WinnV3EngineConfig genuinely computes them and the create seam refuses any
 * other number.
 *
 * ===========================================================================
 * WHAT IT DELIBERATELY DOES NOT DO
 * ===========================================================================
 *
 * It compares nothing. It reads an inputs-only task list, runs the host's real
 * code, and prints JSON. `cmd/winn3-conformance -verify` does the comparing.
 *
 * Usage: winn3_conformance_swift_harness <task-list-path>   (JSON to stdout)
 */

let reportHost =
  "apple/WinsTunnelCore/WinsWinn3SessionStart.swift:winn3GatewayIDOperatorText + "
  + "WinsWinn3HostContract.swift:WinsWinn3CreateDocument.json"

// MARK: - the task list

struct Task {
  let key: String
  let args: [String]
}

func readTasks(_ path: String) -> [Task] {
  guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
    FileHandle.standardError.write(Data("cannot read task list at \(path)\n".utf8))
    exit(2)
  }
  return text.split(separator: "\n").compactMap { line in
    let trimmed = line.trimmingCharacters(in: .whitespaces)
    guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return nil }
    let parts = trimmed.split(separator: " ").map(String.init)
    return Task(key: parts[0], args: Array(parts.dropFirst()))
  }
}

func unhex(_ s: String) -> Data {
  var out = Data()
  var index = s.startIndex
  while index < s.endIndex {
    let next = s.index(index, offsetBy: 2)
    out.append(UInt8(s[index..<next], radix: 16) ?? 0)
    index = next
  }
  return out
}

func hexOf(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

func jsonString(_ value: String) -> String {
  let data = try? JSONSerialization.data(withJSONObject: [value], options: [])
  guard let data, let text = String(data: data, encoding: .utf8) else { return "\"\"" }
  return String(text.dropFirst().dropLast())
}

// MARK: - the derivation

/// Builds the `[winn]` INI the control plane will eventually serve, and runs
/// the host's real reader over it.
///
/// The descriptor carries every byte-valued field base64-encoded — the hub
/// refuses anything else with `descriptor-field-not-base64` — so `gateway_id`
/// and `admission_key` are base64 HERE, in the configuration, and it is the
/// host's job to get from that to what the engine takes.
func iniFor(gatewayID: Data, admissionFile: Data, pathMTU: Int, classes: [String]) -> String {
  """
  [interface]
  PrivateKey = <REDACTED_WG_KEY>
  Address = 10.13.0.2/32

  [peer]
  PublicKey = <REDACTED_WG_KEY>
  Endpoint = 192.0.2.9:51820
  AllowedIPs = 0.0.0.0/0

  [winn]
  carrier = winn3
  endpoint = 192.0.2.9:51820
  inner_v4 = 10.13.0.2
  inner_router_v4 = 10.13.0.1
  static_private = \(Data(repeating: 0x11, count: 32).base64EncodedString())
  gateway_static = \(Data(repeating: 0x22, count: 32).base64EncodedString())
  gateway_id = \(gatewayID.base64EncodedString())
  admission_key = \(admissionFile.base64EncodedString())
  path_mtu = \(pathMTU)
  carrier_classes = \(classes.joined(separator: ","))
  session_id = conformance
  """
}

// MARK: - main

let arguments = CommandLine.arguments
guard arguments.count > 1 else {
  FileHandle.standardError.write(Data("usage: winn3_conformance_swift_harness <task-list>\n".utf8))
  exit(2)
}

var gatewayIDBytes = Data()
var admissionFileBytes = Data()
var pathMTU = 0
var classes: [String] = []

for task in readTasks(arguments[1]) {
  switch task.key {
  case "operator_gateway_id_hex": gatewayIDBytes = unhex(task.args[0])
  case "operator_admission_file_hex": admissionFileBytes = unhex(task.args[0])
  case "operator_path_mtu": pathMTU = Int(task.args[0]) ?? 0
  case "operator_classes": classes = task.args[0].split(separator: ",").map(String.init)
  default: break
  }
}

// The admission secret as the ENGINE takes it: the FILE's bytes with a trailing
// CR/LF removed, which is what every file-reading consumer in the tree does. The
// descriptor transports those bytes base64; nothing decodes them further,
// because the secret is opaque.
var admissionSecret = admissionFileBytes
while let last = admissionSecret.last, last == 0x0a || last == 0x0d {
  admissionSecret.removeLast()
}

let ini = iniFor(
  gatewayID: gatewayIDBytes,
  admissionFile: admissionSecret,
  pathMTU: pathMTU,
  classes: classes
)
let config = WinsTunnelConfig.parse(ini)

// THE derivation. `winn3GatewayIDOperatorText` is the descriptor boundary: the
// one place the base64 comes off, and the value the engine is handed.
guard let operatorText = config.winn3GatewayIDOperatorText else {
  let why = WinsWinn3StartRequirements.unmetReasons(config).joined(separator: "; ")
  FileHandle.standardError.write(Data("the host refused the conformance gateway_id; unmetReasons: \(why)\n".utf8))
  exit(1)
}

// Read back off the CREATE DOCUMENT, not off the accessor. What reaches the
// engine is the JSON, and a document that dropped or re-encoded a field would
// look fine at the accessor and wrong on the wire.
guard let document = WinsWinn3CreateDocument.make(config: config),
      let json = try? document.json(),
      let parsed = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
else {
  let why = WinsWinn3StartRequirements.unmetReasons(config).joined(separator: "; ")
  FileHandle.standardError.write(Data("the host could not build a create document; unmetReasons: \(why)\n".utf8))
  exit(1)
}

let emittedGatewayID = (parsed["gateway_id"] as? String) ?? ""
let emittedAdmission = (parsed["admission_key"] as? String) ?? ""
let emittedPathMTU = (parsed["path_mtu"] as? Int) ?? 0
let emittedClasses = (parsed["carrier_classes"] as? [String]) ?? []

// The create document carries gateway_id as TEXT and admission_key as base64.
// Both are rendered to the bytes the engine keys with, which is the only form
// two hosts can be compared in.
let gatewayIDHex = hexOf(Data(emittedGatewayID.utf8))
let admissionHex = hexOf(Data(base64Encoded: emittedAdmission) ?? Data())

// Cross-check the accessor against the document. A disagreement between them is
// a host that decodes correctly and then emits something else, which is a real
// shape of this bug and is invisible to a test that only reads one of them.
if emittedGatewayID != operatorText {
  FileHandle.standardError.write(Data(
    "the create document's gateway_id (\(emittedGatewayID)) is not what the descriptor boundary decoded (\(operatorText))\n".utf8))
  exit(1)
}

let report: [String: Any] = [
  "host": reportHost,
  "language": "swift",
  "gateway_id_hex": gatewayIDHex,
  "admission_key_hex": admissionHex,
  // The Apple host sets no tag size; the engine's default applies.
  "tag_size": 32,
  "path_mtu": emittedPathMTU,
  "carrier_classes": emittedClasses,
  "message_size": 0,
  "inner_mtu": 0,
  "inner_ipv6": false,
  "floors": [],
  "overheads": [],
  // Declared, not skipped. WinsWinn3Settings takes the engine's published
  // winn3_inner_mtu as a parameter and never recomputes the plan floor — a
  // second implementation of that arithmetic in Swift would be a number that
  // can disagree with the engine's, which §4.2 makes a black hole rather than
  // an inefficiency. The verifier CHECKS this claim: a host that declares a
  // field not derived and then reports a value for it fails.
  // This input-only harness never starts an engine or sends traffic. Reporting
  // false would claim an observation it did not make and would disagree with
  // the reference's carried-traffic vector. The Apple runtime observation is
  // covered by WinsPacketTunnelEngine and its native contract tests.
  "not_derived": [
    "message_size", "inner_mtu", "inner_ipv6", "floors", "overheads",
    "transport_observed_both_ways"
  ]
]

guard let body = try? JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]),
      let text = String(data: body, encoding: .utf8) else {
  exit(1)
}
print(text)
_ = jsonString("")  // silence the unused-helper warning without deleting a helper a reader expects
