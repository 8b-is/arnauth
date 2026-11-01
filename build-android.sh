#!/usr/bin/env bash
# Build arnauth for Android (WearOS) — aarch64-linux-android
#
# Prerequisites:
#   1. Android SDK + NDK installed
#   2. NDK in PATH or ANDROID_NDK_HOME set
#   3. rustup target add aarch64-linux-android
#
# For Zig SIMD kernels on Android:
#   - zig cc --target=aarch64-linux-android wupz-zig/src/kernels.zig -c -o wupz.o
#   - Link with -lwupz_zig

set -euo pipefail

ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/27.0.12077973}"
export ANDROID_NDK_HOME

TARGET=aarch64-linux-android
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}"

# Linker from NDK
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin/${TARGET}24-clang"
export CC_aarch64_linux_android="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin/${TARGET}24-clang"
export CXX_aarch64_linux_android="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin/${TARGET}24-clang++"
export AR_aarch64_linux_android="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"

# Check NDK exists
if [[ ! -f "${CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER}" ]]; then
    echo "ERROR: NDK linker not found at ${CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER}"
    echo "Install Android NDK r27+ and set ANDROID_NDK_HOME"
    exit 1
fi

echo "Building arnauth-core for ${TARGET}..."
cargo build --release --target "${TARGET}" -p arnauth-core

echo "Building arnauth-cli for ${TARGET}..."
cargo build --release --target "${TARGET}" -p arnauth-cli

# Optional: Zig SIMD kernels for Android
if command -v zig >/dev/null 2>&1; then
    echo "Building Zig SIMD kernels for ${TARGET}..."
    cd wupz/wupz-rs
    zig cc --target="${TARGET}" -O3 -c ../../wupz/wupz-zig/src/kernels.zig -o ../target/${TARGET}/release/wupz_kernels.o
    echo "wupz_kernels.o ready for linking"
    cd ../..
fi

echo ""
echo "Output:"
echo "  ${CARGO_TARGET_DIR}/${TARGET}/release/arnauth"
echo ""
echo "To run on WearOS:"
echo "  adb push ${CARGO_TARGET_DIR}/${TARGET}/release/arnauth /data/local/tmp/arnauth"
echo "  adb shell chmod +x /data/local/tmp/arnauth"
echo "  adb shell /data/local/tmp/arnauth --help"
