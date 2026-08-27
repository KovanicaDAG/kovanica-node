#!/usr/bin/env bash
# Build the kovanica-ffi cdylib for Android and lay it out for AAR packaging.
#
# Prerequisites (one-time):
#   rustup target add aarch64-linux-android x86_64-linux-android
#   cargo install cargo-ndk
#   Android NDK installed (Android Studio SDK Manager, or sdkmanager
#   "ndk;27.0.12077973") AND exported:
#     export ANDROID_NDK_HOME="$HOME/Android/Sdk/ndk/27.0.12077973"
#
# Usage (from crates/kovanica-ffi or repo root):
#   ./build-android.sh              # both ABIs below
#   ABIS="arm64-v8a" ./build-android.sh   # subset, space-separated
#
# Output:
#   android/src/main/jniLibs/<abi>/libkovanica_ffi.so   (consumed by the
#     Gradle module in android/, packaged into the AAR alongside the
#     committed Kotlin bindings under bindings/kotlin)
#
# The Kotlin side needs the `uniffi` runtime helpers — they are generated
# inline in bindings/kotlin/uniffi/kovanica/kovanica.kt (JNA-based), so the
# only external dependency is net.java.dev.jna:jna@5.x at runtime.
set -euo pipefail

cd "$(dirname "$0")"

ABIS="${ABIS:-arm64-v8a x86_64}"

# cargo-ndk maps Gradle ABI -> Rust triple.
abi_to_target() {
  case "$1" in
    arm64-v8a) echo aarch64-linux-android ;;
    x86_64) echo x86_64-linux-android ;;
    armeabi-v7a) echo armv7-linux-androideabi ;;
    *) echo "unsupported ABI: $1 (add a mapping)" >&2; exit 1 ;;
  esac
}

command -v cargo-ndk >/dev/null || { echo "cargo-ndk missing — see header" >&2; exit 1; }
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME not set — see header}"

ARGS=()
for abi in $ABIS; do
  target="$(abi_to_target "$abi")"
  rustup target add "$target"
  ARGS+=( -t "$target" )
done

# --no-cargo-install: cargo-ndk must not mutate our toolchain here; the
# targets were pinned above. -o lays the .so files straight into jniLibs.
cargo ndk --platform 24 --no-cargo-install \
  "${ARGS[@]}" -o android/src/main/jniLibs \
  build --release -p kovanica-ffi

echo
echo "jniLibs layout:"
find android/src/main/jniLibs -name '*.so' | sort
echo "Next: cd android && ./gradlew assembleRelease  (AAR bundles jniLibs + bindings)"
