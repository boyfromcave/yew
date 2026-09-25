// Screen privacy for the seed and private-key screens (W5 review, docs/security-review.md
// A-3): on Android, FLAG_SECURE blanks the window in screenshots, screen recordings and the
// recent-apps switcher while such a screen is up. It is set through a small MethodChannel in
// MainActivity.kt (no plugin). iOS has no equivalent flag; the call is a no-op there, and the
// widget tests have no platform, so a missing handler is ignored.
import 'package:flutter/services.dart';

const MethodChannel _channel = MethodChannel('cash.ycash.yew/screen');

/// Blank (or un-blank) the window for screenshots and the app switcher.
Future<void> setScreenSecure(bool secure) async {
  try {
    await _channel.invokeMethod<void>('setSecure', secure);
  } on MissingPluginException {
    // No platform side (tests, iOS): nothing to do.
  } on PlatformException {
    // The platform refused; the screen still shows, the user was warned in words.
  }
}
