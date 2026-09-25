#!/usr/bin/env bash
# Builds yew-core for iOS (scripts/build-core-ios.sh -> app/ios/Frameworks/YewCore.xcframework,
# force-loaded into the Runner by app/ios/Flutter/YewCore.xcconfig) and runs the app, or one of
# the integration tests, on an iOS simulator against a lightwalletd-dd `--yellowback` server.
#
#   scripts/run-ios.sh [host:port] [--test m1|m2]     default server 127.0.0.1:9267 (the armed devnet)
#
# Simulator: $YEW_SIM (a udid or a name), else the booted one, else the first available iPhone
# (booted here). The server goes to the app as --dart-define=YEW_SERVER (the integration tests
# read it; the app itself takes the server from Onboarding: network regtest, the host:port, plain).
# Needs: Xcode with an iOS simulator runtime, Flutter (README "Toolchain"), the Rust targets.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
server="127.0.0.1:9267"; test=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --test) test="${2:?--test m1|m2}"; shift 2 ;;
    *) server="$1"; shift ;;
  esac
done
"$here/scripts/build-core-ios.sh"
sim="${YEW_SIM:-}"
if [[ -z "$sim" ]]; then
  sim="$(xcrun simctl list devices booted | sed -n 's/.*(\([0-9A-F-]\{36\}\)) (Booted).*/\1/p' | head -1)"
fi
if [[ -z "$sim" ]]; then
  sim="$(xcrun simctl list devices available | grep -E '^\s+iPhone' | sed -n 's/.*(\([0-9A-F-]\{36\}\)).*/\1/p' | head -1)"
  [[ -n "$sim" ]] || { echo "run-ios: no iOS simulator (Xcode > Settings > Components: install an iOS runtime)" >&2; exit 1; }
fi
xcrun simctl boot "$sim" 2>/dev/null || true
open -a Simulator
cd "$here/app"
if [[ -n "$test" ]]; then
  exec flutter test "integration_test/${test}_flow_test.dart" -d "$sim" --dart-define="YEW_SERVER=$server"
fi
echo "run-ios: simulator $sim, server $server (Onboarding: Create > network regtest > $server > plain)"
exec flutter run -d "$sim" --dart-define="YEW_SERVER=$server"
