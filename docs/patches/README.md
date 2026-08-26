# Android Patch Set

This directory documents the Android-specific patches carried by this branch on
top of the regular Tailscale Android client.

The patch set has two user-facing network controls:

- Manual HTTP proxy selection for Tailscale login, control-plane, telemetry, and
  DERP relay HTTP(S) transports.
- Public DNS-over-HTTPS resolver selection for default/public DNS while
  preserving MagicDNS and split-DNS behavior from Tailscale policy.

It also has supporting diagnostics:

- Toggleable HTTP proxy debug logging.
- Toggleable DNS config/apply logging.
- Toggleable per-query DNS/DoH path, latency, and error logging.

## Documents

| Document | Purpose |
| --- | --- |
| [manual-http-proxy.md](manual-http-proxy.md) | Architecture, endpoint coverage, persistence, safety limits, and debugging for the HTTP proxy patch. |
| [public-doh.md](public-doh.md) | Architecture, core hook, Android apply path, route-aware dialing, leak hardening, and limitations for public DoH selection. |
| [logging-and-privacy.md](logging-and-privacy.md) | Complete list of introduced log categories, toggle behavior, sensitive fields, logcat filters, and why logging is off by default. |
| [build-and-maintenance.md](build-and-maintenance.md) | Build requirements, local patched-core dependency, verification checklist, and maintenance guidance. |

## High-Level Design

The patches deliberately separate three concerns:

```text
Android UI/state
  - Compose screens and ViewModels
  - encrypted preference storage
  - gomobile calls into libtailscale

Android libtailscale glue
  - reads encrypted preferences
  - installs Tailscale hooks
  - requests DNS recompilation and VPN refresh
  - controls Android-specific logging flags

Tailscale core patch
  - exposes a DNS config modification hook
  - applies that hook before DNS config compilation
  - emits gated DNS forwarder diagnostics
```

The HTTP proxy feature is mostly Android-side because upstream Tailscale already
has HTTP proxy plumbing through `tshttpproxy`.

The public DoH feature needs a small Tailscale core patch because Android must
modify `dns.Config.DefaultResolvers` before the DNS manager compiles routing and
OS-facing resolver configuration. Doing this later in Android VPN DNS output
would be too coarse and would risk breaking MagicDNS or split DNS.

## Patch Boundaries

These patches do not attempt to:

- Proxy direct peer-to-peer WireGuard UDP traffic.
- Proxy STUN or NAT traversal probes through the manual HTTP proxy.
- Replace Tailscale control-plane MagicDNS hosts.
- Replace Tailscale split-DNS routes.
- Support arbitrary DoH URLs outside Tailscale's known public DoH bootstrap
  table.
- Hide every possible domain from Android or application-level caches.

The intended behavior is narrower:

```text
control/login/DERP HTTP(S)
  -> optional manual HTTP proxy

public/default DNS
  -> optional selected public DoH resolver

MagicDNS and split DNS
  -> normal Tailscale policy
```

