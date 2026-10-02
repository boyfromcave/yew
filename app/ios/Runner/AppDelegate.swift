import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
    // "cash.ycash.yew/backup" exclude(path): NSURLIsExcludedFromBackupKey on the core's data
    // directory (lib/state/secrets.dart AppDataDirs; audit G-10), so the SQLite cache never
    // enters an iCloud or iTunes backup. No plugin, no other method.
    guard let registrar = engineBridge.pluginRegistry.registrar(forPlugin: "cash.ycash.yew.backup") else { return }
    let channel = FlutterMethodChannel(name: "cash.ycash.yew/backup", binaryMessenger: registrar.messenger())
    channel.setMethodCallHandler { call, result in
      guard call.method == "exclude", let path = call.arguments as? String else {
        result(FlutterMethodNotImplemented)
        return
      }
      do {
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
        var url = URL(fileURLWithPath: path)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try url.setResourceValues(values)
        result(nil)
      } catch {
        result(FlutterError(code: "backup", message: "\(error)", details: nil))
      }
    }
  }
}
