# Manual HTTP Proxy Patch

## Goal

The stock Android client has no Android UI for manually setting a Tailscale
control-plane HTTP proxy. Tailscale core already has proxy support through
`tshttpproxy`, so the Android patch only needs to provide a validated proxy URL
to the existing hook.

The user model is:

```text
Settings
  -> HTTP proxy
     -> http://host:port
     -> https://host:port
```

The proxy is scoped to Tailscale HTTP transports. It is not a general VPN proxy.

## User Behavior

The Settings screen shows an `HTTP proxy` row after DNS settings. Pressing it
opens a dialog. The user can enter:

```text
http://proxy.example.com:8080
https://proxy.example.com:8443
http://user:pass@proxy.example.com:8080
```

An empty value disables the proxy.

The subtitle shows `Disabled` when empty, or the configured URL when present.

## Persistence

The setting is stored in Android encrypted preferences:

```text
controlProxyURL
```

Encrypted preferences are used because proxy URLs can contain credentials:

```text
http://user:pass@proxy.example.com:8080
```

## Code Paths

Android UI/state:

```text
android/src/main/java/com/tailscale/ipn/ui/view/SettingsView.kt
android/src/main/java/com/tailscale/ipn/ui/viewModel/SettingsViewModel.kt
android/src/main/res/values/strings_proxy.xml
```

Go-side Android bridge:

```text
libtailscale/control_proxy.go
```

Runtime path:

```text
Settings UI
  -> encrypted Android preference: controlProxyURL
  -> libtailscale/control_proxy.go
  -> tshttpproxy.SetProxyFunc
  -> Tailscale HTTP transport proxy function
  -> control/login/DERP/log upload HTTP(S)
```

## Architecture

`installAndroidControlProxy` runs early during `libtailscale` startup. It
installs a proxy resolver with:

```go
tshttpproxy.SetProxyFunc(...)
```

For each Tailscale HTTP request, the resolver:

1. Reads `controlProxyURL` from encrypted Android preferences.
2. Trims whitespace.
3. Returns no proxy if the setting is empty.
4. Parses the value as a URL.
5. Requires a host.
6. Allows only `http` and `https` schemes.
7. Returns the parsed URL to Tailscale core.

The patch does not alter Tailscale control protocol behavior. It only feeds a
proxy URL into the existing HTTP transport mechanism.

## Endpoint Coverage

| Endpoint / traffic type | Coverage | Reason |
| --- | --- | --- |
| Login and auth HTTP(S) | Fully proxied | Uses Tailscale HTTP transports that consult the proxy hook. |
| Control-plane HTTPS | Fully proxied | Control client HTTP transport uses the proxy function. |
| DERP HTTPS connection | Fully proxied after reconnect | DERP HTTP clients consult the proxy hook and use HTTP `CONNECT` when a proxy is present. Existing DERP connections may keep their old path until recreated. |
| WireGuard packets relayed over DERP | Indirectly proxied | Relayed packets are encrypted DERP frames; if the DERP stream is proxied, those frames ride inside it. |
| Direct peer-to-peer WireGuard UDP | Not proxied | Direct peer traffic is not HTTP. |
| STUN / NAT traversal UDP probes | Not proxied | STUN/netcheck is UDP and does not use `tshttpproxy`. |
| DERP latency / netcheck behavior | Partially proxied | DERP HTTP(S) attempts can use the proxy; UDP probing does not. |
| Log uploads | Expected to be proxied | Log upload HTTP transport uses Tailscale proxy-aware HTTP plumbing. |
| Public DoH resolver traffic | Not controlled by this setting | DoH forwarding uses DNS forwarder routing and the `Route DoH through Tailscale` setting. |
| MagicDNS and split-DNS queries | Not controlled by this setting | They use Tailscale DNS routing, not the control HTTP proxy hook. |
| Taildrop / localapi peer traffic | Not controlled by this setting | These paths are local or peer data paths, not control HTTP transport. |

## Architectural Decisions

### Use Tailscale's Existing Proxy Hook

The patch uses `tshttpproxy.SetProxyFunc` instead of adding a separate HTTP
client stack. This keeps behavior aligned with Tailscale's existing proxy-aware
transports and avoids duplicating TLS, DERP, or control client behavior.

### Validate Only Scheme and Host

The Android side accepts `http` and `https` proxy URLs with a host. It does not
try to actively connect or preflight the proxy when saving the setting. The
proxy may be reachable only under certain network conditions, and connection
errors belong to the HTTP transport path where request context and retry logic
already exist.

### Do Not Proxy WireGuard Direct Traffic

The setting is explicitly not a full-device proxy and not a WireGuard transport
proxy. Direct peer-to-peer WireGuard packets are UDP data-path traffic. Sending
that through an HTTP proxy would require a different transport design, not just
an HTTP proxy URL.

### Encrypted Storage

The setting is encrypted because proxy credentials are commonly encoded in the
URL. Plain preferences would make credential exposure easier during device
inspection and backup workflows.

## Debug Logging

HTTP proxy debug logs are controlled by the `HTTP proxy debug logs` switch in
Settings. They are disabled by default.

Keyword:

```text
ANDROID_HTTPPROXY
```

Filter:

```sh
adb logcat | grep -Ei 'ANDROID_HTTPPROXY|control proxy|tshttpproxy|proxy|CONNECT|derphttp|controlclient'
```

Representative lines:

```text
ANDROID_HTTPPROXY control proxy: installing Android httpproxy resolver
ANDROID_HTTPPROXY control proxy: installed Android httpproxy resolver
ANDROID_HTTPPROXY control proxy: httpproxy disabled for "https://..."
ANDROID_HTTPPROXY control proxy: using httpproxy "http://..." for "https://..."
ANDROID_HTTPPROXY control proxy: ignoring invalid httpproxy URL "..."
ANDROID_HTTPPROXY control proxy: ignoring unsupported httpproxy URL scheme "..."
```

Sensitive fields:

- Proxy URL, possibly including credentials.
- Destination URL, including Tailscale control, telemetry, or DERP host.

## Common Failure Modes

### Stale AAR

Changing `libtailscale/control_proxy.go` requires regenerating the AAR. A Kotlin
or Gradle-only rebuild is not enough.

### Existing Transports

Existing control or DERP HTTP transports can keep their current connection path
until recreated. Force-stop the app when testing path changes:

```sh
adb shell am force-stop com.tailscale.ipn
adb shell monkey -p com.tailscale.ipn 1
```

### Android Loopback

On Android and emulators, `127.0.0.1` means the device or emulator loopback, not
the development host.

Use this for Android emulator to host:

```text
http://10.0.2.2:1089
```

For physical devices, use the workstation LAN IP and make sure the proxy listens
on that interface.

