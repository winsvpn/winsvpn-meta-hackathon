import Flutter
import UIKit

// H-4: native app-switcher/task-switcher privacy shield.
//
// Without this, the OS can capture an app-switcher snapshot of whatever
// Flutter is currently rendering *before* the Dart-side decoy state (see
// `didChangeAppLifecycleState` in lib/main.dart) has a chance to update --
// that Dart-side update is asynchronous and is racing the synchronous
// snapshot the system takes as soon as the scene resigns active. Covering
// the key window synchronously here, in the same native call that reports
// the resign, closes that race independent of anything Flutter/Dart does.
//
// `FlutterSceneDelegate` (see Flutter's FlutterSceneDelegate.mm) implements
// `sceneWillResignActive:`/`sceneDidBecomeActive:` concretely -- forwarding
// to any plugins registered for scene lifecycle events -- so these are real
// overrides, not just optional-protocol stubs, and `super` must still be
// called so that forwarding keeps working for any plugin that relies on it.
class SceneDelegate: FlutterSceneDelegate {
  private var privacyShields: [UIView] = []

  private func removePrivacyShields() {
    privacyShields.forEach { $0.removeFromSuperview() }
    privacyShields.removeAll()
  }

  override func sceneWillResignActive(_ scene: UIScene) {
    removePrivacyShields()
    if let windowScene = scene as? UIWindowScene {
      for window in windowScene.windows {
        let shield = UIView(frame: window.bounds)
        shield.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        shield.backgroundColor = UIColor(
          red: 0.07, green: 0.09, blue: 0.12, alpha: 1.0
        )
        window.addSubview(shield)
        privacyShields.append(shield)
      }
    }
    super.sceneWillResignActive(scene)
  }

  override func sceneDidBecomeActive(_ scene: UIScene) {
    removePrivacyShields()
    super.sceneDidBecomeActive(scene)
  }
}
