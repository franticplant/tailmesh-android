# Comprehensive End-to-End Architecture & Operational Deep Dive

This document provides a complete, exhaustive, end-to-end technical breakdown of **Custom Tailscale for Android**. It explains every layer from Android OS process initialization down to Go CGO JNI bindings, WireGuard packet routing, gVisor `netstack` TCP/IP reassembly, control-plane proxying, and DoH DNS resolution.

---

## 🗺️ 1. End-to-End System Blueprint

```mermaid
graph TD
    subgraph Layer1_Android_OS["Layer 1: Android OS & UI (Kotlin / Java)"]
        A1["App.kt / MainActivity.kt"] -->|Starts Service| A2["IPNProxyService (VpnService)"]
        A2 -->|Allocates| A3["/dev/tun File Descriptor"]
        A4["SettingsView / DNSSettingsView"] -->|Writes| A5["Encrypted SharedPreferences (Android KeyStore)"]
    end

    subgraph Layer2_JNI_Bridge["Layer 2: JNI / Gomobile Bridge (CGO)"]
        A3 -->|Pass FD via JNI| B1["libtailscale/backend.go (start)"]
        A5 -->|Read Proxy & DoH Prefs| B2["libtailscale/control_proxy.go & control_doh.go"]
    end

    subgraph Layer3_Go_Engine["Layer 3: Tailscale Go Core Engine"]
        B1 -->|Initialize Engine| C1["wgengine.NewUserspaceEngine()"]
        C1 -->|Packet Processing| C2["gVisor netstack (Userspace TCP/IP)"]
        B2 -->|Hook 1: HTTP Proxy| C3["tshttpproxy.SetProxyFunc()"]
        B2 -->|Hook 2: DoH Mutation| C4["dns.HookModifyConfig (net/dns)"]
    end

    subgraph Layer4_Network_Output["Layer 4: Network Transports & Resolution"]
        C3 -->|HTTP CONNECT Tunnel| D1["Corporate HTTP/HTTPS Proxy"]
        D1 -->|Noise Protocol TS2021| D2["Tailscale Control Server (controlplane.tailscale.com)"]
        C4 -->|MagicDNS Queries| D3["In-Memory Resolver (100.100.100.100)"]
        C4 -->|Public Internet Queries| D4["Selected DoH Provider (HTTPS)"]
        C2 -->|Direct / DERP Encrypted UDP| D5["Peer WireGuard Mesh"]
    end
```

---

## ⚡ 2. App Bootstrapping & Lifecycle

### Step 1: Process Creation & JNI Initialization
When the user launches Tailscale or enables the VPN toggle:
1. Android OS instantiates `com.tailscale.ipn.App` and `IPNProxyService` (a subclass of `android.net.VpnService`).
2. Android loads the compiled native shared library `libgojni.so` contained within `libtailscale.aar` via JNI (`System.loadLibrary("gojni")`).
3. Go runtime `init()` functions execute, allocating Go memory, starting the Go garbage collector, and registering exported `Libtailscale` CGO methods.

### Step 2: TUN File Descriptor Handshake
```mermaid
sequenceDiagram
    autonumber
    participant Vpn as VpnService (Java/Kotlin)
    participant Builder as VpnService.Builder
    participant JNI as CGO JNI Bridge
    participant Go as libtailscale (backend.go)
    participant Netstack as gVisor netstack

    Vpn->>Builder: Configure IP addresses (100.64.0.1/32) & DNS (100.100.100.100)
    Builder->>Vpn: establish() -> returns ParcelFileDescriptor (/dev/tun)
    Vpn->>JNI: Pass raw int File Descriptor to Go
    JNI->>Go: libtailscale.start(dataDir, appCtx)
    Go->>Netstack: Attach /dev/tun to netstack link endpoint
```

1. `VpnService.Builder` configures:
   - Tailnet IP assignment (e.g. `100.115.x.y`).
   - DNS server address (`100.100.100.100` and `fd7a:115c:a1e0::53`).
   - Included/excluded apps (for split tunneling).
2. `VpnService.Builder.establish()` returns an OS file descriptor pointing to `/dev/tun`.
3. Java code calls `libtailscale.start()`, passing the raw integer file descriptor across CGO boundary into Go.
4. Go wraps the file descriptor into a `os.File` and binds it as a packet reader/writer inside `wgengine/netstack`.

---

## 🔐 3. Control-Plane HTTP Proxy Subsystem (`tshttpproxy`)

### The Architecture Problem
Tailscale's control protocol uses aNoise-encrypted session (`ts2021`) running over HTTPS. Stock Tailscale Android dials `controlplane.tailscale.com` directly over default network interfaces, which fails behind strict corporate firewalls requiring HTTP proxies.

```mermaid
flowchart TD
    A["Tailscale Control / DERP Client"] -->|Needs HTTP Transport| B["tshttpproxy.SetProxyFunc Hook"]
    B -->|Reads Preference| C["controlProxyURL ('http://user:pass@proxy:8080')"]
    C -->|Validates Scheme & Host| D{"Is Proxy URL Valid?"}
    D -->|Yes| E["Construct *url.URL Proxy Object"]
    D -->|No / Empty| F["Return Direct Connection (No Proxy)"]
    E -->|http.Transport| G["Send 'HTTP CONNECT controlplane.tailscale.com:443'"]
    G -->|Established Tunnel| H["Establish TS2021 Encrypted Noise Handshake"]
```

### Key Technical Implementation Details
1. **`libtailscale/control_proxy.go`**:
   During `libtailscale` startup, `installAndroidControlProxy(appCtx)` registers a custom proxy resolver with `tshttpproxy.SetProxyFunc`:
   ```go
   tshttpproxy.SetProxyFunc(func(req *http.Request) (*url.URL, error) {
       proxyStr := decryptPref("controlProxyURL")
       if proxyStr == "" {
           return nil, nil
       }
       u, err := url.Parse(proxyStr)
       if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
           return nil, nil
       }
       return u, nil
   })
   ```
2. **Coverage**:
   - **Auth & Login**: User authentication flow.
   - **Control Map Polling**: Fetching node maps and DERP region maps.
   - **DERP Relays**: WebSockets over HTTPS to DERP relays use HTTP `CONNECT` tunneling.
   - **Telemetry**: Diagnostic log uploads.

---

## 🧪 4. DNS Pipeline & `dns.HookModifyConfig` Seam

### End-to-End DNS Query Routing Decision Tree

```mermaid
flowchart TD
    A["Incoming Query from Android App (e.g. UDP port 53)"] --> B["Intercepted by Tailscale DNS Manager"]
    B --> C{"Is Query for MagicDNS? (*.ts.net)"}
    C -->|Yes| D["Resolve via In-Memory Host Table"]
    D --> E["Return 100.x.y.z IP immediately (0ms WAN latency)"]
    C -->|No| F{"Does Query Match Split-DNS Route? (*.corp.internal)"}
    F -->|Yes| G["Forward to Tailnet Corporate Resolver"]
    F -->|No| H["Pass to Default Resolvers Pipeline"]
    H --> I["Apply dns.HookModifyConfig"]
    I --> J["Replace DefaultResolvers with Custom DoH URL"]
    J --> K{"Route DoH through Tailscale? (useRoutes)"}
    K -->|true| L["Dial DoH HTTPS over Tailscale Engine Routes"]
    K -->|false| M["Dial DoH HTTPS over Device Default Interface"]
    L --> N["Send DNS Wire Format over HTTPS POST (application/dns-message)"]
    M --> N
    N --> O["Return DNS Answer to Application"]
```

### The `dns.HookModifyConfig` Seam
To prevent plain-text DNS leaks without breaking MagicDNS or split-DNS, the DoH override executes inside `net/dns/manager.go` before DNS policy compilation:

```go
func (m *Manager) setLocked(cfg Config) error {
    syncs.AssertLocked(&m.mu)

    // Clone incoming control config
    effectiveCfg := *cfg.Clone()

    // Execute registered Android hooks
    for _, hook := range HookModifyConfig {
        hook(&effectiveCfg)
    }

    // Compile effective config into OS & resolver tables
    rcfg, ocfg, err := m.compileConfig(effectiveCfg)
    ...
}
```

### Android DoH Hook Logic (`libtailscale/control_doh.go`)
```go
dns.HookModifyConfig.Add(func(cfg *dns.Config) {
    dohURL := decryptPref("publicDoHURL")
    if dohURL == "" {
        return // User did not select a custom resolver; keep default
    }

    // Parse and validate DoH URL against known bootstrap providers
    resolver, err := parseKnownDoHProvider(dohURL)
    if err != nil {
        // Install dummy fail-closed resolver to prevent plain-text fallback
        cfg.DefaultResolvers = []*dnstype.Resolver{{Addr: "https://invalid.tailscale.local/dns-query"}}
        return
    }

    // Replace ONLY public default resolvers
    cfg.DefaultResolvers = []*dnstype.Resolver{resolver}
})
```

---

## 🔬 5. Detailed Packet-Level Walkthrough (3 Real-World Examples)

### Scenario A: Resolving a Tailnet Peer (`my-laptop.tailnet.ts.net`)

```mermaid
sequenceDiagram
    autonumber
    participant App as Android Web Browser
    participant TUN as Android /dev/tun Interface
    participant Netstack as gVisor netstack
    participant DNS as Tailscale DNS Forwarder (net/dns)
    participant Table as In-Memory Hosts Map

    App->>TUN: UDP Packet: DNS Query A "my-laptop.tailnet.ts.net"
    TUN->>Netstack: Read raw IP packet (dst: 100.100.100.100:53)
    Netstack->>DNS: Pass payload bytes to Manager.Query()
    DNS->>Table: Lookup "my-laptop.tailnet.ts.net" in Host Table
    Table-->>DNS: Found IP "100.64.10.19"
    DNS->>Netstack: Construct DNS Response packet
    Netstack->>TUN: Write IP packet (src: 100.100.100.100:53)
    TUN-->>App: Browser gets "100.64.10.19" (Latency: <1ms)
```

---

### Scenario B: Resolving a Public Site (`example.com`) via Custom DoH

```mermaid
sequenceDiagram
    autonumber
    participant App as Android App
    participant TUN as Android /dev/tun Interface
    participant DNS as Tailscale DNS Manager
    participant DoH as Cloudflare DoH (https://dns.cloudflare.com/dns-query)

    App->>TUN: UDP Packet: DNS Query A "example.com"
    TUN->>DNS: Intercepted at 100.100.100.100:53
    DNS->>DNS: Check MagicDNS & Split-DNS (No match)
    DNS->>DNS: Selected resolver: DefaultResolvers[0] = "https://dns.cloudflare.com/dns-query"
    DNS->>DoH: HTTP POST "https://dns.cloudflare.com/dns-query" (Content-Type: application/dns-message)
    DoH-->>DNS: HTTP 200 OK + Wire-format DNS Response
    DNS->>TUN: Send UDP DNS Answer to App
    TUN-->>App: App receives public IP (Logged: path=tailscale-selected-doh-route-aware)
```

---

### Scenario C: Connecting through a Corporate HTTP Proxy

```mermaid
sequenceDiagram
    autonumber
    participant Core as Tailscale Engine
    participant Proxy as Corporate HTTP Proxy (10.0.0.50:8080)
    participant Control as Tailscale Control Server (controlplane.tailscale.com)

    Core->>Proxy: TCP Connect to 10.0.0.50:8080
    Core->>Proxy: "HTTP/1.1 CONNECT controlplane.tailscale.com:443" (Proxy-Authorization: Basic ...)
    Proxy-->>Core: "HTTP/1.1 200 Connection Established"
    Core->>Control: Initiate TLS / Noise Protocol Handshake over proxied TCP stream
    Control-->>Core: TS2021 Session Active (Network Map Synced)
```

---

## 🛠️ 6. Build System & Optimization Pipeline

```mermaid
flowchart TD
    subgraph Go_Compilation["1. Go / CGO Compilation Phase"]
        A["libtailscale/*.go + tailscale core"] -->|gomobile bind| B["Compile libgojni.so (ARM64, ARMv7, x86, x86_64)"]
        B -->|Flags: -extldflags=-Wl,-z,max-page-size=16384| C["16 KB Page Aligned Shared Objects"]
        C -->|llvm-objcopy --strip-debug| D["Stripped libgojni.so"]
        D -->|Zip into AAR| E["android/libs/libtailscale.aar"]
    end

    subgraph Gradle_Compilation["2. Android Gradle & R8 Phase"]
        E --> F["Gradle assembleRelease"]
        F -->|R8 Bytecode Minification| G["Shrunk classes.dex"]
        F -->|Resource Shrinker| H["Optimized res/ & resources.arsc"]
        G & H --> I["android-release-unsigned.apk"]
    end

    subgraph Packaging_Phase["3. Zipalign & Keystore Signing"]
        I -->|zipalign -v -p 4| J["4-Byte Aligned APK"]
        J -->|apksigner with ~/.android/debug.keystore| K["tailscale-optimized-release.apk (Verified v2 & v3)"]
    end
```

---

## 📋 7. Summary of Safety & Operational Guarantees

1. **Zero DNS Leaks**: Replacing `DefaultResolvers` inside `dns.HookModifyConfig` guarantees fallback DNS uses HTTPS while leaving internal tailnet names under MagicDNS control.
2. **Fail-Closed Protection**: Malformed or unparseable DoH settings install a dummy non-resolvable endpoint instead of silently falling back to system DNS.
3. **No Uninstalls Needed**: Production release APKs signed with your machine's keystore (`~/.android/debug.keystore`) allow direct updates via `adb install -r`.
4. **Modern Hardware Ready**: Native CGO libraries are compiled with 16 KB page-size alignment (`max-page-size=16384`) for Android 15, 16, and 17 hardware.
