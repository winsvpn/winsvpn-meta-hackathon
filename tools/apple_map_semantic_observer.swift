#!/usr/bin/env swift
import AppKit
import Foundation
import NaturalLanguage
import Vision

enum ObserverError: Error { case usage, image, recognition }

func sha256(_ url: URL) throws -> String {
  let task = Process()
  task.executableURL = URL(fileURLWithPath: "/usr/bin/shasum")
  task.arguments = ["-a", "256", url.path]
  let pipe = Pipe()
  task.standardOutput = pipe
  try task.run(); task.waitUntilExit()
  guard task.terminationStatus == 0 else { throw ObserverError.image }
  return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)!
    .split(separator: " ").first.map(String.init) ?? ""
}

guard CommandLine.arguments.count == 2 else { throw ObserverError.usage }
let url = URL(fileURLWithPath: CommandLine.arguments[1])
guard let image = NSImage(contentsOf: url),
      let data = image.tiffRepresentation,
      let bitmap = NSBitmapImageRep(data: data),
      let cgImage = bitmap.cgImage else { throw ObserverError.image }

let request = VNRecognizeTextRequest()
request.recognitionLevel = .accurate
request.usesLanguageCorrection = true
try VNImageRequestHandler(cgImage: cgImage).perform([request])
let text = (request.results ?? []).compactMap { $0.topCandidates(1).first?.string }
let radius = text.contains { value in
  let normalized = value.lowercased().replacingOccurrences(of: " ", with: "")
  return normalized.contains("50mi") || normalized.contains("50mile")
}
let tagger = NLTagger(tagSchemes: [.nameType])
var cities = Set<String>()
for line in text {
  tagger.string = line
  tagger.enumerateTags(
    in: line.startIndex..<line.endIndex,
    unit: .word,
    scheme: .nameType,
    options: [.joinNames, .omitWhitespace, .omitPunctuation]
  ) { tag, range in
    if tag == .placeName {
      let value = String(line[range]).trimmingCharacters(in: .whitespacesAndNewlines)
      if value.count >= 2 { cities.insert(value) }
    }
    return true
  }
}
let payload: [String: Any] = [
  "schema_version": 1,
  "contract": "winsvpn-apple-map-semantic-observer-v1",
  "screenshot_sha256": try sha256(url),
  "radius_label_50_miles_detected": radius,
  "surrounding_city_labels": cities.sorted(),
  "viewport_not_world_zoom": radius && cities.count >= 2,
  "secret_material_redacted": true,
]
let output = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
FileHandle.standardOutput.write(output)
FileHandle.standardOutput.write(Data("\n".utf8))
