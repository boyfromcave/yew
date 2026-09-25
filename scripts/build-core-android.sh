#!/usr/bin/env bash
# Builds yew-core for Android (arm64-v8a device, x86_64 emulator) into
# app/android/app/src/main/jniLibs/ with cargo-ndk. Idempotent.
# Requires: cargo-ndk, the Android NDK pinned in app/android/app/build.gradle.kts, protoc.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"
need() { command -v "$1" >/dev/null 2>&1 || { echo "build-core-android: missing '$1'. $2" >&2; exit 1; }; }
need cargo "Install Rust: https://rustup.rs (the version is in rust-toolchain.toml)"
need protoc "Install protobuf: brew install protobuf / apt install protobuf-compiler"
cargo ndk --version >/dev/null 2>&1 || { echo "build-core-android: missing cargo-ndk. Install: cargo install cargo-ndk" >&2; exit 1; }
ndk_ver="$(sed -n 's/.*ndkVersion = "\([^"]*\)".*/\1/p' app/android/app/build.gradle.kts | head -1)"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  if [[ -d "$sdk/ndk/$ndk_ver" ]]; then export ANDROID_NDK_HOME="$sdk/ndk/$ndk_ver"; else
    echo "build-core-android: Android NDK $ndk_ver not found under $sdk/ndk." >&2
    echo "  Install: Android Studio > SDK Manager > SDK Tools > NDK $ndk_ver, or sdkmanager \"ndk;$ndk_ver\"," >&2
    echo "  or set ANDROID_NDK_HOME." >&2; exit 1; fi
fi
for t in aarch64-linux-android x86_64-linux-android; do
  rustup target list --installed | grep -qx "$t" || rustup target add "$t"
done
out="$here/app/android/app/src/main/jniLibs"
mkdir -p "$out"
cargo ndk -t arm64-v8a -t x86_64 -o "$out" build -p yew-core --lib --release
echo "build-core-android: wrote $out (NDK $ndk_ver)"
