#!/usr/bin/env bash
# Builds yew-core for Android (scripts/build-core-android.sh -> app/android/app/src/main/jniLibs)
# and runs the app, or one of the integration tests, on an Android emulator against a
# lightwalletd-dd `--yellowback` server.
#
#   scripts/run-android.sh [host:port] [--test m1|m2]   default server 10.0.2.2:9267
#                                                       (the emulator's name for the host's loopback)
#
# Emulator: the connected device $YEW_DEVICE (default emulator-5554); when none is connected the
# AVD $YEW_AVD (default yew_pixel) is started and waited for. Create one once with Android Studio
# (Device Manager) or:  sdkmanager "system-images;android-35;google_apis;arm64-v8a" &&
#   avdmanager create avd -n yew_pixel -k "system-images;android-35;google_apis;arm64-v8a" -d pixel_7
# (the command-line tools need JAVA_HOME, e.g. Android Studio's JBR). The server goes to the app as
# --dart-define=YEW_SERVER (the integration tests read it; the app itself takes the server from
# Onboarding: network regtest, the host:port, plain).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
server="10.0.2.2:9267"; test=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --test) test="${2:?--test m1|m2}"; shift 2 ;;
    *) server="$1"; shift ;;
  esac
done
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
adb="$sdk/platform-tools/adb"
[[ -x "$adb" ]] || { echo "run-android: no adb under $sdk (set ANDROID_HOME)" >&2; exit 1; }
"$here/scripts/build-core-android.sh"
device="${YEW_DEVICE:-emulator-5554}"
if ! "$adb" devices | grep -q "^$device[[:space:]]*device"; then
  avd="${YEW_AVD:-yew_pixel}"
  "$sdk/emulator/emulator" -list-avds | grep -qx "$avd" || { echo "run-android: no AVD '$avd' (see the header of this script)" >&2; exit 1; }
  echo "run-android: starting emulator $avd"
  nohup "$sdk/emulator/emulator" -avd "$avd" -no-snapshot -no-audio >/dev/null 2>&1 &
  "$adb" wait-for-device
  until [[ "$("$adb" -s "$device" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]]; do sleep 2; done
fi
cd "$here/app"
if [[ -n "$test" ]]; then
  exec flutter test "integration_test/${test}_flow_test.dart" -d "$device" --dart-define="YEW_SERVER=$server"
fi
echo "run-android: device $device, server $server (Onboarding: Create > network regtest > $server > plain)"
exec flutter run -d "$device" --dart-define="YEW_SERVER=$server"
