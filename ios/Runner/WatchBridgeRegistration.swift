import Flutter
import Foundation

/// The only place that ties `WatchSessionBridge` to Flutter.
///
/// Kept separate from both `AppDelegate` and the bridge itself so the
/// WatchConnectivity logic stays independently readable and compilable, and so
/// wiring the watch in costs `AppDelegate` exactly one line.
///
/// The channel name and the JSON on it are identical to the Android side
/// (`WatchBridge.kt`), so `lib/watch_bridge.dart` serves both platforms.
enum WatchBridgeRegistration {

  private static let channelName = "wins_vpn/watch"
  private static let methodPublishState = "publishWatchState"
  private static let methodOnCommand = "onWatchCommand"

  static func register(with messenger: FlutterBinaryMessenger) {
    let channel = FlutterMethodChannel(name: channelName, binaryMessenger: messenger)

    channel.setMethodCallHandler { call, result in
      switch call.method {
      case methodPublishState:
        guard
          let arguments = call.arguments as? [String: Any],
          let payload = arguments["payload"] as? String
        else {
          result(FlutterError(code: "BAD_ARGS", message: "Watch payload missing", details: nil))
          return
        }
        result(WatchSessionBridge.shared.publish(payload: payload))
      default:
        result(FlutterMethodNotImplemented)
      }
    }

    // Registering the handler is also what tells the bridge a Dart layer
    // exists, and therefore that connecting and country switching are possible.
    WatchSessionBridge.shared.start { command, slug in
      channel.invokeMethod(
        methodOnCommand,
        arguments: ["command": command, "slug": slug]
      )
    }
  }
}
