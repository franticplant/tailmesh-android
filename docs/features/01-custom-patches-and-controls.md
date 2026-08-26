# Custom Patches and Network Features

This document provides a technical guide to the custom network controls added to this Tailscale fork:

1. **Manual HTTP Proxy Control**: Allows routing control-plane, auth, DERP, and log traffic through a user-defined HTTP/HTTPS proxy.
2. **Public DoH (DNS-over-HTTPS) Selection**: Allows replacing public/fallback DNS with a user-selected DoH provider without bypassing MagicDNS or split-DNS policy.

---

## 1. Manual HTTP Proxy Control

### Overview
Stock Tailscale for Android relies on system proxy detection, which is often unavailable or coarse. This patch adds a direct setting in the Android app UI to configure an HTTP/HTTPS proxy URL (`http://proxy:8080` or `https://proxy:8443`).

### Architecture & Call Flow

```text
Settings UI (SettingsView.kt)
   │
   ▼
SettingsViewModel.kt
   │ Writes to encrypted Android preferences (`controlProxyURL`)
   ▼
libtailscale/control_proxy.go
   │ `installAndroidControlProxy(appCtx)` registers a resolver
   ▼
tshttpproxy.SetProxyFunc(...)
   │ Replaced HTTP proxy resolver in Tailscale core
   ▼
Tailscale Transports (Control HTTPS, DERP HTTPS, Telemetry)
```

### Key Implementation Details
- **Storage**: Proxy URLs are saved in Android encrypted preferences (`EncryptedSharedPreferences`) because proxy URLs may contain basic-auth credentials (`http://user:pass@host:port`).
- **Resolver**: `installAndroidControlProxy` installs a custom proxy function using `tshttpproxy.SetProxyFunc`. For every outbound HTTP/HTTPS request, `tshttpproxy` checks `controlProxyURL` and returns the parsed `*url.URL`.
- **Debugging**: Includes gated `ANDROID_HTTPPROXY` logcat debugging toggled via Settings.

---

## 2. Public DoH (DNS-over-HTTPS) Selection

### Overview
Tailscale manages DNS via its internal DNS manager. Replacing public DNS at the VPN output level would risk breaking MagicDNS (`100.100.100.100`) or split-DNS routes. This feature injects a pre-compilation hook into Tailscale core so that only fallback/public DNS (`DefaultResolvers`) is replaced.

### Core Hook (`tailscale` Repo)

In `net/dns/config.go`:
```go
// HookModifyConfig allows platform-specific code to adjust DNS configuration
// before it is compiled into resolver and OS configuration.
var HookModifyConfig feature.Hooks[func(*Config)]
```

In `net/dns/manager.go` (`setLocked`):
```go
effectiveCfg := *cfg.Clone()
for _, hook := range HookModifyConfig {
    hook(&effectiveCfg)
}
rcfg, ocfg, err := m.compileConfig(effectiveCfg)
```

### Android Integration (`tailscale-android` Repo)

In `libtailscale/control_doh.go`:
```go
dns.HookModifyConfig.Add(func(cfg *dns.Config) {
    // Replaces ONLY cfg.DefaultResolvers with the selected public DoH provider
    // Leaves cfg.Routes and cfg.Hosts intact for MagicDNS & split-DNS
})
```

### Application Path & VPN Refresh

```text
DNSSettingsView.kt
   │ User selects DoH Provider (Cloudflare, Quad9, Mullvad, etc.)
   ▼
DNSSettingsViewModel.kt
   │ Encrypts preference & calls `Libtailscale.applyDNSSettings()`
   ▼
libtailscale/dns_apply.go (`ApplyDNSSettings`)
   │ 1. Triggers `DNSManager.RecompileDNSConfig()`
   │ 2. Invokes `HookModifyConfig`
   │ 3. Calls `VPNFacade.ReconfigureVPN()` to update Android VPN DNS list
   ▼
Android System VPN Facade
```

### Route-Aware DoH Dialing (`UserDialUseRoutes`)
- Controls whether the HTTPS connection to the DoH resolver is dialed over the device's default interface or through Tailscale's route-aware dialer.
- When `Route DoH through Tailscale` changes, `forwarder.go` executes `closeDoHClientsLocked()` to clear cached HTTP transport clients and apply the new dialing strategy immediately.

### Diagnostic Logcat Keywords
- `ANDROID_HTTPPROXY`: HTTP proxy resolver logs.
- `ANDROID_DNS_USAGE`: Per-query path, resolver address, latency, and error classification logs (`tailscale-selected-doh-route-aware`, `tailscale-selected-doh-system-route`, `classic-dns-*`).
