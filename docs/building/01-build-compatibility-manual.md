# Build Compatibility and Maintenance

This document details toolchain requirements, API compatibility targets (Android 11 to 17), build commands, and maintenance procedures.

---

## 1. Compatibility Targets

| Property | Value | Description |
| --- | --- | --- |
| **`minSdkVersion`** | `26` (Android 8.0 Oreo) | Ensures compatibility with Android 8, 9, 10, **Android 11 (API 30)**, 12, 13, 14, 15+. |
| **`compileSdkVersion`** | `36` (Android 16 / 17) | Compiles against latest Android API definitions. |
| **`targetSdkVersion`** | `36` (Android 16 / 17) | Adheres to latest Android platform security & behavior rules. |
| **Page Alignment** | 16 KB ELF Alignment | `-extldflags=-Wl,-z,max-page-size=16384` required for Android 15/16/17+ devices. |

---

## 2. Toolchain Prerequisites

- **JDK**: OpenJDK 17 or higher (`JAVA_HOME=$HOME/jdk17`).
- **Go**: Go 1.26.6 or higher.
- **`gomobile`**: `golang.org/x/mobile/cmd/gomobile` and `gobind`.
- **Android SDK**: `platforms;android-36`, `build-tools;36.0.0`, `cmdline-tools;latest`.
- **Android NDK**: NDK r25 or NDK r26 (`ndk;26.1.10909125`).

---

## 3. Environment Variables Setup

Before building locally, set up the required toolchain environment:

```sh
export JAVA_HOME=$HOME/jdk17
export ANDROID_HOME=$HOME/Android/Sdk
export NDK_ROOT=$ANDROID_HOME/ndk/26.1.10909125
export PATH=$JAVA_HOME/bin:$HOME/go/bin:$HOME/go_sdk/go/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH
```

**Do not set `TOOLCHAINDIR`.** `tool/go` refuses to run with it set, because it
would bypass the Tailscale Go revision pinned in `go.toolchain.rev`. That is not
a theoretical concern: an APK built against a mismatched toolchain compiled and
tested cleanly and then panicked at Go init on the device, because `libgojni.so`
had been produced by an older Tailscale Go compiler. If your shell exports it for
some other project, unset it before building here.

Only a deliberate external-toolchain build - F-Droid, say - may override this,
by also setting `TS_ANDROID_ALLOW_EXTERNAL_TOOLCHAIN=1`.

---

## 4. Build Commands

### Step 1: Generate Version Information
```sh
./tool/go run tailscale.com/cmd/mkversion > tailscale.version
```

### Step 2: Build the `libtailscale.aar` Library
```sh
unset TOOLCHAINDIR
make libtailscale
```
This builds `android/libs/libtailscale_unstripped.aar`, strips symbols via `llvm-objcopy`, and outputs `android/libs/libtailscale.aar`.

### Step 3: Build the Debug APK
```sh
cd android
./gradlew assembleDebug
```
The output APK is generated at:
`android/build/outputs/apk/debug/android-debug.apk`

---

## 5. Verification & Testing

### Test Go Backend Code
```sh
GOOS=android GOARCH=arm64 CGO_ENABLED=0 $HOME/go_sdk/go/bin/go build ./libtailscale
```

### Test Core DNS Unit Tests
```sh
cd ../tailscale
$HOME/go_sdk/go/bin/go test ./net/dns ./net/dns/resolver
```
