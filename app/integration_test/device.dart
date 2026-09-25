// Helpers for the integration tests on a real phone screen (W6). The screens are lazy
// `ListView`s: on a 6" display the button below the trust text or the send form is not built
// until it is scrolled to, so `find.byKey` sees nothing — unlike the 800x600 widget-test
// surface. Every tap and entry scrolls its target into view first.
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

Future<Finder> _visible(WidgetTester tester, Finder f) async {
  if (f.evaluate().isEmpty) {
    await tester.scrollUntilVisible(
      f,
      200,
      scrollable: find.byType(Scrollable).first,
    );
  } else {
    await tester.ensureVisible(f);
  }
  await tester.pumpAndSettle();
  return f;
}

Future<void> tapKey(WidgetTester tester, String key) async =>
    tester.tap(await _visible(tester, find.byKey(Key(key))));

Future<void> longPressKey(WidgetTester tester, String key) async =>
    tester.longPress(await _visible(tester, find.byKey(Key(key))));

Future<void> enterKey(WidgetTester tester, String key, String text) async =>
    tester.enterText(await _visible(tester, find.byKey(Key(key))), text);

/// Puts the `SwitchListTile` at [key] in state [on] (a blind tap toggles: the regtest
/// default server prefills `plain` already on).
Future<void> setSwitchKey(WidgetTester tester, String key, bool on) async {
  final f = await _visible(tester, find.byKey(Key(key)));
  if (tester.widget<SwitchListTile>(f).value != on) await tester.tap(f);
  await tester.pumpAndSettle();
}

/// Pumps until [done] holds or [timeout] passes (a real core call takes as long as the server
/// does; a fixed `pumpAndSettle` duration is a guess). Fails with the screen's `error` text
/// when one appears.
Future<void> waitFor(WidgetTester tester, FutureOr<bool> Function() done, {Duration timeout = const Duration(seconds: 120)}) async {
  final deadline = DateTime.now().add(timeout);
  while (!await done()) {
    final err = find.byKey(const Key('error'));
    if (err.evaluate().isNotEmpty) fail('screen error: ${tester.widget<Text>(err).data}');
    if (DateTime.now().isAfter(deadline)) fail('timed out after $timeout; on screen: ${onScreen()}');
    await tester.pump(const Duration(milliseconds: 250));
  }
  await tester.pumpAndSettle();
}

/// `expect(finder, findsOneWidget)` for a lazy list: scrolls until [finder] matches (fails after
/// the list's end) and asserts exactly one match.
Future<void> expectVisible(WidgetTester tester, Finder finder, {String? reason}) async {
  if (finder.evaluate().isEmpty) {
    try {
      await tester.scrollUntilVisible(finder, 200, scrollable: find.byType(Scrollable).first);
    } on StateError {
      // the finder still matches nothing: expect below says so
    }
  }
  if (finder.evaluate().length != 1) {
    fail('${reason ?? finder}: ${finder.evaluate().length} matches; on screen: ${onScreen()}');
  }
}

/// [waitFor] the widget at [key], scrolling the current list for it on every check (a screen
/// that appears after a core call may put it below the fold).
Future<void> waitForKey(WidgetTester tester, String key, {Duration timeout = const Duration(seconds: 120)}) async {
  final f = find.byKey(Key(key));
  await waitFor(tester, () async {
    if (f.evaluate().isNotEmpty) return true;
    if (find.byType(Scrollable).evaluate().isNotEmpty) {
      try {
        await tester.scrollUntilVisible(f, 200, scrollable: find.byType(Scrollable).first);
      } on StateError {
        // not there yet
      }
    }
    return f.evaluate().isNotEmpty;
  }, timeout: timeout);
}

/// Every `Text` in the tree, for a failure message.
String onScreen() => find.byType(Text).evaluate().map((e) => (e.widget as Text).data).whereType<String>().join(' | ');
