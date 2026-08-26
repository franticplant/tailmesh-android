# Architecture Blueprint & Patch Specifications

This document provides a deep, production-grade architectural specification for the custom patches applied to **Tailscale Core** (`tailscale`) and **Tailscale Android** (`tailscale-android`).

---

## 📐 System Component Diagram

```mermaid
flowchart TD
    subgraph Android_UI["Android UI & State Layer"]
        A["DNSSettingsView / SettingsView"] --> B["SettingsViewModel / DNSSettingsViewModel"]
        B --> C["Encrypted SharedPreferences"]
    end

    subgraph Go_Bridge["libtailscale (Go / CGO Bridge)"]
        C --> D["Libtailscale.applyDNSSettings()"]
        D --> E["installAndroidControlProxy()"]
        D --> F["installAndroidPublicDoH()"]
    end

    subgraph Tailscale_Core["Tailscale Core Engine"]
        E --> G["tshttpproxy.SetProxyFunc()"]
        F --> H["dns.HookModifyConfig"]
        H --> I["dns.Manager.setLocked()"]
        I --> J["m.compileConfig(effectiveCfg)"]
    end

    subgraph Resolution_Paths["DNS Resolution Output"]
        J --> K["MagicDNS (100.100.100.100)"]
        J --> L["Split-DNS Route Resolvers"]
        J --> M["Selected Public DoH Resolver (HTTPS)"]
    end
```

---

## 🔒 1. Core DNS Mutation Seam: `dns.HookModifyConfig`

### Design Rationale
To alter fallback DNS without breaking **MagicDNS** or **Tailnet split-DNS routes**, the mutation must occur **before** DNS policy compilation inside the DNS manager.

### Seam Implementation
1. **`net/dns/config.go`**:
   ```go
   // HookModifyConfig allows platform-specific code to adjust DNS configuration
   // before it is compiled into resolver and OS configuration.
   var HookModifyConfig feature.Hooks[func(*Config)]
   ```

2. **`net/dns/manager.go`**:
   ```go
   func (m *Manager) setLocked(cfg Config) error {
       syncs.AssertLocked(&m.mu)

       effectiveCfg := *cfg.Clone()
       for _, hook := range HookModifyConfig {
           hook(&effectiveCfg)
       }

       m.logf("Set: %v", logger.ArgWriter(func(w *bufio.Writer) {
           effectiveCfg.WriteToBufioWriter(w)
       }))

       rcfg, ocfg, err := m.compileConfig(effectiveCfg)
       ...
   }
   ```

### Safety & Isolation Properties
- `HookModifyConfig` mutates **only `cfg.DefaultResolvers`**.
- It explicitly preserves `Routes`, `Hosts`, `SubdomainHosts`, and `SearchDomains`.
- Invalid or unsupported DoH URLs fail closed by installing a deliberate dummy resolver (`https://invalid.tailscale.local/dns-query`), preventing silent fallback to plain-text system DNS.

---

## 🌐 2. Control-Plane HTTP Proxy Integration

```mermaid
sequenceDiagram
    autonumber
    participant Client as Control Client / DERP / Telemetry
    participant ProxyHook as tshttpproxy.SetProxyFunc
    participant Prefs as Encrypted Preferences
    participant ProxyServer as External HTTP/HTTPS Proxy

    Client->>ProxyHook: Query proxy for destination URL
    ProxyHook->>Prefs: Read controlProxyURL
    Prefs-->>ProxyHook: "http://user:pass@proxy.example.com:8080"
    ProxyHook-->>Client: Return parsed *url.URL
    Client->>ProxyServer: Connect via HTTP CONNECT / HTTPS Tunnel
```

- **Location**: `libtailscale/control_proxy.go`
- **Mechanism**: Registers a proxy resolver function via `tshttpproxy.SetProxyFunc`.
- **Validation**:
  - Accepts `http://` and `https://` URLs.
  - Supports embedded user credentials (`http://user:pass@host:port`).
  - Trims whitespace and ignores malformed inputs.
- **Security**: Proxy URLs are saved in Android's hardware-backed Encrypted SharedPreferences (`security-crypto`).

---

## 📡 3. Local Proxy Listener Architecture (Design Specification)

Tailscale core ships with `net/socks5` (a complete SOCKS5/SOCKS5h server supporting TCP & UDP) and `net/proxymux` (a dual HTTP/SOCKS5 listener).

```mermaid
flowchart LR
    subgraph Client_Device["Android Device / Local LAN"]
        App1["Browser / Non-VPN App"] -->|HTTP / SOCKS5h| Listener
        App2["LAN Device (Wi-Fi)"] -->|HTTP / SOCKS5h| Listener
    end

    subgraph Tailscale_Listener["Local Proxy Listener"]
        Listener["proxymux.Mux (127.0.0.1:1055)"] --> SOCKS["socks5.Server"]
        Listener --> HTTP["http.Server"]
    end

    subgraph Routing["Tailscale Router"]
        SOCKS -->|tsdial.Dialer| Netstack["gVisor netstack"]
        HTTP -->|tsdial.Dialer| Netstack
        Netstack --> Tailnet["MagicDNS / Tailnet Peers / Exit Nodes"]
    end
```

### Key Technical Properties
- **Loopback (`127.0.0.1:port`)**: Requires **no Android permissions**.
- **LAN (`0.0.0.0:port`)**: Shares your phone's Tailscale connection with other devices on your local Wi-Fi.
- **SOCKS5h Remote DNS**: Domain names sent to the SOCKS5h listener resolve using `tsdial.Dialer`, automatically honoring MagicDNS and exit-node routing for non-VPN applications.
