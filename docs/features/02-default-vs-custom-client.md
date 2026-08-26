# How Tailscale Works: Default Client vs. Custom Patch Set

This document provides a comprehensive architectural explanation of how the **official (default) Tailscale Android client** operates under the hood, and how our **custom patch set** extends it with control-plane HTTP proxying and leak-proof DNS-over-HTTPS (DoH) selection.

---

## 🏗️ Part 1: Official (Default) Tailscale Android Client

The stock Tailscale Android application is a hybrid system combining a **Kotlin Compose Android frontend** with a **Go Userspace Engine** compiled into an Android Archive (`libtailscale.aar`).

```mermaid
sequenceDiagram
    autonumber
    participant UI as Android UI (Kotlin/Compose)
    participant Bridge as libtailscale (Go/CGO)
    participant Engine as wgengine & netstack
    participant Control as Control Server (controlplane.tailscale.com)
    participant DNS as DNS Manager (net/dns)
    participant OS as Android OS (VpnService)

    UI->>Bridge: start(dataDir, appCtx)
    Bridge->>Engine: wgengine.NewUserspaceEngine()
    Engine->>Control: Direct HTTPS connection (No Proxy Support)
    Control-->>Engine: Network Map & DNS Config
    Engine->>DNS: Set(cfg)
    DNS->>OS: VpnService.Builder.addDnsServer(100.100.100.100)
    OS-->>Engine: Hand over /dev/tun file descriptor
```

### 1. Packet Interception & gVisor netstack
- When the VPN starts, Android creates a virtual TUN interface (`/dev/tun`).
- Android routes device IP traffic into this file descriptor.
- Inside `libtailscale`, gVisor `netstack` reads raw IP packets from the TUN descriptor, encrypts WireGuard headers, and transmits them over UDP (or DERP relays).

### 2. Control Plane Connection
- Stock Tailscale establishes direct HTTPS connections to `controlplane.tailscale.com` over the device's default network interfaces.
- **Limitation**: Stock Tailscale Android provides no UI or setting to configure an HTTP or SOCKS proxy for control-plane or DERP relay traffic.

### 3. Default DNS Resolution Pipeline
- Tailscale control server sends a DNS configuration containing:
  1. **MagicDNS Hosts**: Maps tailnet machine names to `100.x.y.z` addresses.
  2. **Split-DNS Routes**: Routes specific domain suffixes (e.g. `*.corp.internal`) to internal DNS servers.
  3. **Fallback Resolvers**: Standard unencrypted public resolvers (e.g. `1.1.1.1`, `8.8.8.8`).
- `dns.Manager` compiles these rules and updates Android's `VpnService.Builder.addDnsServer`.

---

## 🚀 Part 2: Custom Client Enhancements & Data Flow

Our custom client introduces three core network control systems into this pipeline:

```mermaid
sequenceDiagram
    autonumber
    participant UI as Custom Android UI
    participant Prefs as Encrypted SharedPreferences
    participant Bridge as libtailscale (Go/CGO)
    participant Proxy as tshttpproxy (HTTP Proxy Hook)
    participant DNS as dns.Manager (Patched Core)
    participant DoH as Selected DoH Provider

    UI->>Prefs: Save controlProxyURL & publicDoHURL
    UI->>Bridge: Libtailscale.applyDNSSettings()
    
    rect rgb(235, 245, 255)
        note over Bridge,Proxy: Control-Plane Proxy Subsystem
        Bridge->>Proxy: tshttpproxy.SetProxyFunc(resolver)
        Proxy-->>Bridge: Returns parsed HTTP/HTTPS proxy URL
    end

    rect rgb(240, 255, 240)
        note over Bridge,DoH: Public DoH Subsystem
        Bridge->>DNS: dns.HookModifyConfig(effectiveCfg)
        DNS->>DNS: Replace DefaultResolvers with DoH URL
        DNS->>DoH: Query public names via DoH (HTTPS)
        note over DNS: MagicDNS & Split-DNS remain intact
    end
```

### 1. Manual Control-Plane HTTP Proxy
- **Mechanism**: Registers a custom proxy resolver function with Tailscale's existing `tshttpproxy.SetProxyFunc`.
- **Coverage**:
  - Auth and login HTTP requests.
  - Control-plane RPC synchronization.
  - DERP relay HTTPS connections (DERP frames ride inside the proxied HTTPS tunnel).
  - Telemetry log uploads.
- **Security**: Credentials embedded in proxy URLs (e.g. `http://user:pass@proxy.example.com:8080`) are stored inside Android's hardware-backed Encrypted SharedPreferences (`security-crypto`).

### 2. Custom Public DNS-over-HTTPS (DoH) Selection
- **The Problem with Post-Compilation Changes**: If you try to swap DNS servers after Tailscale compiles its OS configuration, you risk breaking MagicDNS or leaking DNS queries to system resolvers.
- **Our Seam (`dns.HookModifyConfig`)**: We added a hook inside `net/dns/manager.go` that runs **before** DNS compilation.
- **How it works**:
  - When `dns.Manager` sets a new configuration, `HookModifyConfig` intercepts `cfg`.
  - It mutates **only `cfg.DefaultResolvers`**, replacing default resolvers with your chosen public DoH provider URL (Cloudflare, Quad9, Mullvad, AdGuard, Google, etc.).
  - `Routes`, `Hosts`, and `SearchDomains` are left untouched under Tailscale control.

### 3. Route-Aware DoH Dialing
- Controls how the HTTPS connection to the selected DoH resolver is dialed:
  - `useRoutes=true`: The DoH HTTPS connection is dialed through Tailscale's userspace engine routes.
  - `useRoutes=false`: The DoH HTTPS connection is dialed over the device default route.
- Changing this setting automatically clears cached DoH HTTP clients so the next query immediately adopts the new dialer policy.

---

## 📊 Summary Comparison Matrix

| Aspect | Stock Tailscale Client | Custom Tailscale Client |
| --- | --- | --- |
| **Control HTTP Proxy** | None (Direct connection only) | Custom HTTP/HTTPS proxy with credential support |
| **Public Fallback DNS** | Standard unencrypted UDP/TCP | Custom Public DoH (HTTPS) with fail-closed protection |
| **MagicDNS Resolution** | Supported | 100% Preserved |
| **Split-DNS Route Policy** | Supported | 100% Preserved |
| **Android 11–17 Support** | Target API 34/35 | Target API 36 (Android 17) + 16 KB Page Alignment |
| **Logcat Diagnostics** | Mixed default logs | Gated diagnostic tags (`ANDROID_HTTPPROXY`, `ANDROID_DNS_USAGE`) |
