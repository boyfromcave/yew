# yew_app

The Flutter application of YEW (see the repository README). Generated with
`flutter create --project-name yew_app --org cash.ycash.yew --platforms ios,android app`
on Flutter 3.47.5 / Dart 3.13.4. Phase W3 added the screens (`lib/screens`), the one app state
(`lib/state`), the `WalletApi` interface (`lib/api`) and the generated bridge (`lib/src/rust`,
from `scripts/gen-bridge.sh` at the repository root; do not edit by hand). See the repository
README, section W3, for how to build the core for a device and run the tests.

Regenerate platform folders (after a Flutter upgrade): run the same `flutter create` command from
the repository root; it leaves `lib/` and `test/` alone. Re-apply the pins afterwards: the NDK
version in `android/app/build.gradle.kts` and the `environment:` block in `pubspec.yaml`, and the
W3 platform edits: `INTERNET` / `USE_BIOMETRIC` in `android/app/src/main/AndroidManifest.xml`,
`MainActivity : FlutterFragmentActivity()` (local_auth), `NSCameraUsageDescription` /
`NSFaceIDUsageDescription` in `ios/Runner/Info.plist`.
