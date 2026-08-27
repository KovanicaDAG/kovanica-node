#!/usr/bin/env bash
# Build the kovanica-ffi static library for iOS and macOS and bundle it as an
# XCFRAMEWORK for Swift consumption.
#
# Prerequisites (macOS only):
#   rustup target add aarch64-apple-ios aarch64-apple-darwin x86_64-apple-darwin
#   Xcode with command-line tools (xcodebuild on PATH)
#
# Usage:
#   ./build-apple.sh                 # all three slices
#   SLICES="aarch64-apple-ios" ./build-apple.sh   # subset, space-separated
#
# Output:
#   target/kovanica.xcframework      # drag into Xcode / add via SPM local path
#   (Swift sources + modulemap come from the committed bindings/swift/ —
#    kovanica.swift is compiled into your app target; kovanicaFFI.h +
#    kovanicaFFI.modulemap are embedded in the framework headers.)
#
# The Swift side has no external runtime dependency: uniffi 0.32 generates
# everything inline (the modulemap names the FFI symbols).
set -euo pipefail

cd "$(dirname "$0")"

SLICES="${SLICES:-aarch64-apple-ios aarch64-apple-darwin x86_64-apple-darwin}"
OUT="target/kovanica.xcframework"

XCFRAMEWORK_ARGS=()
for triple in $SLICES; do
  rustup target add "$triple"
  cargo build --release --target "$triple" -p kovanica-ffi

  lib="target/$triple/release/libkovanica_ffi.a"
  [ -f "$lib" ] || { echo "missing $lib" >&2; exit 1; }

  slice_dir="target/xcframework/$triple"
  mkdir -p "$slice_dir"
  cp bindings/swift/kovanicaFFI.h bindings/swift/kovanicaFFI.modulemap "$slice_dir/"

  XCFRAMEWORK_ARGS+=( -library "$lib" -headers "$slice_dir" )
done

rm -rf "$OUT"
xcodebuild -create-xcframework "${XCFRAMEWORK_ARGS[@]}" -output "$OUT"

echo
echo "Built $OUT:"
ls "$OUT"
echo "Next: add the framework to your app; compile bindings/swift/kovanica.swift"
echo "into the same target (module name kovanicaFFI via the bundled modulemap)."
