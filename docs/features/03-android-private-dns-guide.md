# Android Private DNS Interaction and System Resolver Analysis

This document provides a deep technical analysis of how **Android's system-level Private DNS feature (DNS-over-TLS / DoT)** interacts with the Tailscale VPN client and our custom public DNS-over-HTTPS (DoH) patch.

The analysis in this document is validated directly against the **GrapheneOS / AOSP (Android Open Source Project) source tree** (`packages/modules/Connectivity`, `packages/modules/DnsResolver`, and `frameworks/base/services/core/java/com/android/server/connectivity/Vpn.java`).

---

## 1. Executive Summary

| Private DNS Mode (Android Settings) | OS Behavior with Tailscale VPN | Interaction with Custom Public DoH Patch | MagicDNS Behavior | Recommended? |
| --- | --- | --- | --- | --- |
| **Off** | OS sends all DNS queries to Tailscale VPN (`100.100.100.100:53`). | **Fully Active**: Default names use selected DoH provider over HTTPS. | **100% Functional** | **Yes** |
| **Automatic / Opportunistic** | OS probes `100.100.100.100:853` for DoT. Probe fails (no TLS listener on 853). OS gracefully falls back to UDP/TCP port 53. | **Fully Active**: Operates identically to "Off" mode after fallback. | **100% Functional** | **Yes (Default)** |
| **Strict Mode (Specified Hostname)** | OS intercepts app DNS queries and forces them directly to the strict DoT server (e.g. `dns.quad9.net:853`). | **Bypassed**: OS intercepts queries before they reach `100.100.100.100`. | **Broken**: `.ts.net` names fail because strict DoT server does not know internal tailnet IPs. | **No (Set to Auto/Off for Tailscale)** |

---

## 2. Android OS System Architecture (`netd` & `DnsResolver`)

In Android (AOSP / GrapheneOS), DNS resolution is divided between system services and native daemons:

```text
Android App (e.g. Chrome / Browser)
  │
  ▼
libc `getaddrinfo()` / `DnsResolver` API
  │
  ▼ JNI / IPC
packages/modules/DnsResolver/ (Native C++ netd / DnsResolver daemon)
  │
  ├──► 1. Checks PrivateDNSConfiguration.cpp (`mPrivateDnsModes[netId]`)
  │
  ├──► Strict Mode: Forces TLS connection (`DnsTlsTransport.cpp`) to strict provider on port 853.
  │    (Bypasses VPN DNS listener at 100.100.100.100:53)
  │
  └──► Automatic/Off Mode: Sends DNS queries to LinkProperties DNS (`100.100.100.100:53`).
       │
       ▼
  Tailscale Local DNS Manager & Forwarder
       │
       ├──► MagicDNS / Split-DNS: Resolved via Tailnet routes
       └──► Default/Public DNS: Forwarded via Selected Public DoH (HTTPS)
```

---

## 3. Detailed Breakdown by Private DNS Mode

### A. Mode: `Off` (`PRIVATE_DNS_MODE_OFF`)
- **AOSP Implementation**:
  - `DnsManager.java` sets `useTls = false` on `LinkProperties`.
  - `PrivateDnsConfiguration.cpp` sets `PrivateDnsMode::OFF`.
- **Behavior**:
  - Android OS routes 100% of application DNS requests to the DNS servers provided by the active VPN (`100.100.100.100:53`).
  - Tailscale's local DNS manager receives all queries.
  - Public queries use our custom selected DoH resolver (e.g., Cloudflare/Quad9 DoH). MagicDNS and split-DNS queries resolve natively.

### B. Mode: `Automatic / Opportunistic` (`PRIVATE_DNS_MODE_OPPORTUNISTIC`)
- **AOSP Implementation**:
  - `PrivateDnsConfiguration.cpp` creates validation tracking threads (`DnsTlsServer`) targeting `100.100.100.100:853`.
  - `DnsTlsTransport.cpp` attempts a TLS handshake on port 853.
- **Behavior**:
  - Tailscale's local DNS listener operates on UDP/TCP port 53 and does not serve TLS on port 853.
  - The OS DoT probe to `100.100.100.100:853` fails/times out.
  - Per AOSP specification (`PrivateDnsConfiguration::setDns`), when opportunistic DoT fails, `DnsResolver` **gracefully falls back to plain DNS on port 53**.
  - **Result**: All DNS traffic flows through Tailscale's `100.100.100.100:53`, enabling our custom DoH selector and MagicDNS with zero configuration changes required by the user!

### C. Mode: `Strict Mode` (`PRIVATE_DNS_MODE_PROVIDER_HOSTNAME`)
- **AOSP Implementation**:
  - In `DnsManager.java` and `PrivateDnsConfiguration.cpp`, `strictMode = true`.
  - Android OS resolves the user-specified hostname (e.g. `dns.google` or `one.one.one.one`) and forces all DNS queries to be sent over DoT (port 853) directly to those validated IPs.
- **Behavior**:
  - Android OS overrides the VPN's `LinkProperties` DNS servers (`100.100.100.100`).
  - Application queries bypass `100.100.100.100:53` entirely.
  - **Impact**:
    1. **MagicDNS fails**: Tailnet internal domains (`*.ts.net` or node names) cannot be resolved by public DoT providers.
    2. **Custom DoH setting is bypassed**: Because queries never hit Tailscale's forwarder, Tailscale's DoH setting has no effect.

---

## 4. Why Our Custom Public DoH Patch Solves the Problem

Many users set Android Private DNS to `Strict` because they want DoH/DoT privacy on public Wi-Fi without trusting local networks. However, doing so breaks VPN MagicDNS.

Our custom DoH patch provides the **ideal solution**:

1. **Keep Android Private DNS on `Automatic` or `Off`**.
2. **Select your preferred DoH Provider (Cloudflare, Quad9, Mullvad, etc.) in Tailscale Settings**.

This achieves **both goals simultaneously**:
- **100% Privacy**: All public/default internet DNS queries leave your device encrypted via HTTPS (DoH) directly to your chosen provider.
- **100% Tailnet Functionality**: Internal MagicDNS and split-DNS routes continue to resolve correctly through Tailscale.

---

## 5. Summary Recommendations for Users

- **Recommended Android Setting**: `Settings -> Network & internet -> Private DNS -> Automatic` (or `Off`).
- **Recommended Tailscale Setting**: `Settings -> DNS -> Public DoH Provider -> Select Cloudflare / Quad9 / Mullvad / etc.`
- **Route DoH through Tailscale**: Enable `Route DoH through Tailscale` if you want DoH HTTPS connections routed through your active exit node or Tailnet routing table.
