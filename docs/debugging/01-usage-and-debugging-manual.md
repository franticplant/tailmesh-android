# Usage & Debugging Manual

This manual explains how to configure custom features in the Android app UI, verify DNS leak-freedom, and inspect live execution logs via `adb logcat`.

---

## 📱 User Interface Setup

### 1. Manual HTTP Proxy Configuration
1. Launch Tailscale on Android.
2. Navigate to **Settings** (gear icon) -> **HTTP Proxy**.
3. Enter your proxy URL:
   - `http://10.0.2.2:8080` (Emulator host proxy)
   - `http://user:password@proxy.example.com:8080` (Authenticated HTTP proxy)
   - `https://proxy.example.com:8443` (Secure HTTPS proxy)
4. Tap **Save**.
5. *Note*: To apply changes to existing DERP streams, force-stop and restart the app:
   ```bash
   adb shell am force-stop com.tailscale.ipn
   ```

### 2. Public DoH Resolver Configuration
1. Navigate to **Settings** -> **DNS Settings**.
2. Tap **Public DoH Resolver** and choose your preferred provider:
   - **Cloudflare** (`https://dns.cloudflare.com/dns-query`)
   - **Quad9** (`https://dns.quad9.net/dns-query`)
   - **Mullvad** (`https://dns.mullvad.net/dns-query`)
   - **AdGuard** (`https://dns.adguard-dns.com/dns-query`)
   - **Google** (`https://dns.google/dns-query`)
3. Toggle **Route DoH through Tailscale** to control whether DoH HTTPS requests travel over Tailscale routes (`useRoutes=true`) or device network interfaces (`useRoutes=false`).

---

## 🔍 Logcat Diagnostic Filters

Use these `adb` logcat commands to trace live network traffic:

### 1. HTTP Proxy Logcat Tracing
```bash
adb logcat | grep -Ei 'ANDROID_HTTPPROXY|tshttpproxy|CONNECT|derphttp|controlclient'
```

Representative output:
```text
ANDROID_HTTPPROXY control proxy: installing Android httpproxy resolver
ANDROID_HTTPPROXY control proxy: using httpproxy "http://10.0.2.2:8080" for "https://controlplane.tailscale.com"
```

### 2. DoH & DNS Tracing
```bash
adb logcat | grep -Ei 'ANDROID_DNS_USAGE|public DoH|dns query'
```

Representative output:
```text
ANDROID_DNS_USAGE public DoH: route-aware dialing set to true
ANDROID_DNS_USAGE public DoH: forwarding DNS query via DoH resolver="https://dns.cloudflare.com/dns-query" bytes=34 useRoutes=true
ANDROID_DNS_USAGE dns query result=success path=tailscale-selected-doh-route-aware resolver="https://dns.cloudflare.com/dns-query" query="example.com." type=A duration_ms=38 response_bytes=50
```

---

## 🛡️ Exit Node Interaction Rules

| Exit Node Status | Override Exit-Node DNS | Route DoH through Tailscale | Resulting Behavior |
| --- | --- | --- | --- |
| **Off** | On | Off | Selected DoH resolver over system default route. |
| **Off** | On | On | Selected DoH resolver with route-aware dialing. |
| **On** | Off | Off / On | Preserves exit-node DNS proxy. |
| **On** | On | Off | Selected DoH resolver over system route. |
| **On** | On | On | Selected DoH resolver with route-aware dialing following exit-node route. |
