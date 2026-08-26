# Architecture and AAR Deep Dive

This document explains the end-to-end architecture of the custom Tailscale Android client, focusing on how Go code is compiled, packaged into an **AAR (Android Archive)**, and integrated into the Android Kotlin application.

---

## 1. Dual-Repository Structure

The application consists of two decoupled repositories working together:

```text
ts_app_work/
├── tailscale/            # Go core backend engine (tailscale.com module)
└── tailscale-android/    # Android UI app, Kotlin/Compose, & libtailscale gomobile wrapper
```

### Module Replacement (`go.mod`)
`tailscale-android` uses Go's `replace` directive to link directly to the local patched Go core:

```go
// tailscale-android/go.mod
replace tailscale.com => ../tailscale
```

This guarantees that any changes made to `tailscale` (such as custom DNS hooks or diagnostic logging) are compiled directly into the Android native library during build time.

---

## 2. What is an AAR (Android Archive)?

An **AAR** is the standard binary distribution format for Android library modules (analogous to a JAR in Java or a framework in iOS/macOS).

### Internal Anatomy of `libtailscale.aar`

If you unzip `android/libs/libtailscale.aar`, you will see the following structure:

```text
libtailscale.aar
├── AndroidManifest.xml       # Declares library permissions & min SDK
├── classes.jar               # Java/Kotlin bytecode for Go-Java JNI bindings
├── proguard.txt              # Proguard obfuscation rules for bind interfaces
├── R.txt                     # Resource symbol list
└── jni/                      # Native shared libraries per CPU architecture
    ├── arm64-v8a/
    │   └── libgojni.so       # 64-bit ARM (phones, tablets, modern devices)
    ├── armeabi-v7a/
    │   └── libgojni.so       # 32-bit ARM (older devices)
    ├── x86/
    │   └── libgojni.so       # 32-bit x86 (older emulators)
    └── x86_64/
        └── libgojni.so       # 64-bit x86 (modern emulators & Chromebooks)
```

---

## 3. How `gomobile` Compiles Go into an AAR

The bridge between Go and Android Kotlin is built using `gomobile bind` (from `golang.org/x/mobile`).

```text
Go Source Code
(libtailscale/*.go + tailscale.com/...)
         │
         ▼
  gomobile bind
         │
         ├───► 1. Runs `gobind`: Generates Java JNI wrapper classes in `classes.jar`
         │
         └───► 2. Runs Go Cross-Compiler + Android NDK Clang:
                  Compiles Go code into 4 native shared objects (`libgojni.so`)
                  - arm64-v8a
                  - armeabi-v7a
                  - x86
                  - x86_64
         │
         ▼
  `libtailscale_unstripped.aar`
         │
         ▼
  `llvm-objcopy` (Strips debug symbols while preserving 16 KB page alignment)
         │
         ▼
  `libtailscale.aar` (Placed into android/libs/ for Gradle)
```

### Key Build Steps in `Makefile`

1. **`gomobile bind` Execution**:
   ```sh
   gomobile bind -target android -androidapi 26 \
       -tags "not_tailscale_go ts_omit_cachenetmap" \
       -ldflags "-linkmode=external -extldflags=-Wl,-z,max-page-size=16384" \
       -o android/libs/libtailscale_unstripped.aar ./libtailscale
   ```
   - `-target android -androidapi 26`: Target Android API 26 (Android 8.0+).
   - `-extldflags=-Wl,-z,max-page-size=16384`: Forces 16 KB ELF page alignment for compatibility with **Android 15, 16, and 17**.

2. **Symbol Stripping**:
   ```sh
   llvm-objcopy --strip-debug libgojni.so.unstripped libgojni.so.stripped
   ```
   Debug symbols are stripped into `libgojni.so.debug` (for crash symbolication) to keep the final APK size lean.

---

## 4. How Android Gradle Plugin (AGP) Consumes the AAR

In `android/build.gradle`:

```groovy
dependencies {
    implementation ':libtailscale@aar'
}
```

When Gradle builds the APK (`./gradlew assembleDebug` or `bundleRelease`):

1. **DEX Merging (`mergeLibDexDebug`)**:
   AGP extracts `classes.jar` from `libtailscale.aar` and compiles its Java bytecode into Android DEX bytecode (`classes.dex`).
2. **Native Library Packaging (`mergeDebugNativeLibs`)**:
   AGP extracts `jni/<arch>/libgojni.so` and copies it directly into the APK's `lib/<arch>/` directory.
3. **Runtime Execution (JNI)**:
   When the Android app starts, Kotlin code in `App.kt` or `backend.go` initializes the Go runtime:
   ```kotlin
   // Kotlin calls gomobile bindings generated in classes.jar
   Libtailscale.applyDNSSettings()
   ```
   Java Native Interface (JNI) routes this call through `libgojni.so` directly to Go's `libtailscale.ApplyDNSSettings()`.

---

## 5. Build Artifacts and Safe Verification

The build intentionally produces two AARs:

- `android/libs/libtailscale_unstripped.aar` is the diagnostic artifact. It retains native debug information and is the right input for inspecting the generated `libgojni.so`.
- `android/libs/libtailscale.aar` is the Gradle input. It is repackaged with the arm64 library stripped of debug symbols to reduce APK size; the other ABI libraries remain in the archive.

`make build-unstripped-aar` is a compatibility entry point to the real unstripped-AAR file target. The file target must not be `.PHONY`: two simultaneous `gomobile bind` processes can rewrite the same zip archive and leave a corrupt AAR. Run one AAR-producing make target at a time.

`./gradlew clean` removes `android/build`, but `libtailscale.aar` is a local runtime dependency rather than a Gradle-generated source artifact. If a clean test run reports that `android/libs/libtailscale.aar` is missing, run:

```sh
make libtailscale
(cd android && ./gradlew clean testDebugUnitTest)
```

The Android and core checkouts must use the same pinned Tailscale Go toolchain revision. Do not set `TS_PERMIT_TOOLCHAIN_MISMATCH`; the runtime assertion prevents an APK compiled with an incompatible Go toolchain from crashing at launch.
