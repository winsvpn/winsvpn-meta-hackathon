import AppKit
import CoreGraphics

let outputPath = CommandLine.arguments.dropFirst().first
  ?? "ios/Runner/Assets.xcassets/CalculatorIcon.appiconset/Calculator-1024.png"
let size = 1024
let colorSpace = CGColorSpaceCreateDeviceRGB()
guard let context = CGContext(
  data: nil,
  width: size,
  height: size,
  bitsPerComponent: 8,
  bytesPerRow: size * 4,
  space: colorSpace,
  bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue
) else {
  fatalError("Unable to create calculator icon context")
}

func color(_ red: CGFloat, _ green: CGFloat, _ blue: CGFloat) -> CGColor {
  CGColor(
    colorSpace: colorSpace,
    components: [red / 255, green / 255, blue / 255, 1]
  )!
}

func fillRoundedRect(_ rect: CGRect, radius: CGFloat, fill: CGColor) {
  context.setFillColor(fill)
  context.addPath(CGPath(roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil))
  context.fillPath()
}

context.setFillColor(color(32, 33, 36))
context.fill(CGRect(x: 0, y: 0, width: size, height: size))

fillRoundedRect(
  CGRect(x: 72, y: 48, width: 880, height: 928),
  radius: 104,
  fill: color(24, 24, 26)
)
fillRoundedRect(
  CGRect(x: 154, y: 720, width: 716, height: 174),
  radius: 44,
  fill: color(38, 38, 40)
)

context.setStrokeColor(color(242, 242, 247))
context.setLineWidth(24)
context.strokeEllipse(in: CGRect(x: 774, y: 762, width: 54, height: 88))

let utilityColor = color(166, 166, 170)
let numberColor = color(72, 72, 74)
let operationColor = color(255, 159, 10)
let buttonSize: CGFloat = 118
let xPositions: [CGFloat] = [166, 338, 510, 682]
let yPositions: [CGFloat] = [540, 392, 244, 96]
for (row, y) in yPositions.enumerated() {
  for (column, x) in xPositions.enumerated() {
    let fill = column == 3
      ? operationColor
      : (row == 0 ? utilityColor : numberColor)
    fillRoundedRect(
      CGRect(x: x, y: y, width: buttonSize, height: buttonSize),
      radius: buttonSize / 2,
      fill: fill
    )
  }
}

guard let image = context.makeImage() else {
  fatalError("Unable to render calculator icon")
}
let representation = NSBitmapImageRep(cgImage: image)
guard let png = representation.representation(using: .png, properties: [:]) else {
  fatalError("Unable to encode calculator icon")
}
try png.write(to: URL(fileURLWithPath: outputPath), options: .atomic)
