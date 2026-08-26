# Building Custom Tailscale for Android

This guide provides step-by-step instructions for setting up the compilation environment and building **`libtailscale.aar`** and **`tailscale-optimized-release.apk`** from source.

---

## 🛠️ Toolchain Prerequisites

Ensure the following tools are installed on your Linux build machine:

| Tool | Required Version | Environment Variable / Path |
| --- | --- | --- |
| **Go** | 1.26+ | `TOOLCHAIN_DIR=/path/to/go` |
| **JDK** | OpenJDK 17 | `JAVA_HOME=/path/to/jdk17` |
| **Android SDK** | API 36 | `ANDROID_HOME=/path/to/Android/Sdk` |
| **Android NDK** | NDK 26.1.10909125 | `NDK_ROOT=$ANDROID_HOME/ndk/26.1.10909125` |
| **gomobile** | Latest | `$HOME/go/bin/gomobile` |

---

## 🏗️ Step-by-Step Build Instructions

### Step 1: Export Environment Variables

```bash
export JAVA_HOME=/path/to/jdk17
export ANDROID_HOME=/path/to/Android/Sdk
export NDK_ROOT=$ANDROID_HOME/ndk/26.1.10909125
export TOOLCHAIN_DIR=/path/to/go
export PATH=$JAVA_HOME/bin:$HOME/go/bin:$TOOLCHAIN_DIR/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH
```

### Step 2: Build `libtailscale.aar` (Go Native Library)

Navigate to your workspace `tailscale-android` directory:

```bash
cd $WORKSPACE_DIR/tailscale-android

make libtailscale TOOLCHAINDIR=$TOOLCHAIN_DIR GOTOOLCHAIN=auto
```

This command executes `gomobile bind` with 16 KB page-size alignment (`-extldflags=-Wl,-z,max-page-size=16384`) and generates:
- `android/libs/libtailscale.aar` (Stripped production AAR)
- `android/libs/libtailscale_unstripped.aar` (Unstripped debugging AAR)

### Step 3: Assemble Production Release APK

```bash
cd $WORKSPACE_DIR/tailscale-android/android

./gradlew assembleRelease
```

This runs R8 bytecode minification, dead-code elimination, and resource shrinking, generating an unsigned release APK at `android/build/outputs/apk/release/android-release-unsigned.apk`.

### Step 4: Zipalign & Sign with Keystore

Sign the release APK using your machine's debug keystore (`~/.android/debug.keystore`) so you can update directly via `adb install -r`:

```bash
# Zipalign 4-byte boundaries
$ANDROID_HOME/build-tools/36.0.0/zipalign -v -p 4 \
  android/build/outputs/apk/release/android-release-unsigned.apk \
  /tmp/tailscale-aligned.apk

# Sign with debug keystore
export PATH=$JAVA_HOME/bin:$PATH
$ANDROID_HOME/build-tools/36.0.0/apksigner sign \
  --ks ~/.android/debug.keystore \
  --ks-pass pass:android \
  --ks-key-alias androiddebugkey \
  --out tailscale-optimized-release.apk \
  /tmp/tailscale-aligned.apk

rm -f /tmp/tailscale-aligned.apk
```

Your final APK is **`tailscale-optimized-release.apk`**.

---

## 🔧 Troubleshooting Matrix

| Symptom | Cause | Solution |
| --- | --- | --- |
| `undefined: runtime.TailscaleCurrentP` | `build-tags.sh` returned `tailscale_go` tag when using stock Go. | Set `export TOOLCHAIN_DIR=/path/to/go` before running `make`. |
| `fatal error: android/log.h` | CGO build running without Android target. | Specify `GOOS=android GOARCH=arm64` or run through `gomobile bind`. |
| `module ../tailscale requires go >= 1.26.6` | `go.mod` mismatch between Android app and core repo. | Ensure `go 1.26.6` is set in `tailscale-android/go.mod` and run `go mod tidy`. |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | Installed APK signed with a different key. | Sign the new APK with your machine's keystore (`~/.android/debug.keystore`) or uninstall prior version. |
