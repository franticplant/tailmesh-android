# Public DNS-over-HTTPS Patch

## Goal

The public DoH patch gives Android users local control over default/public DNS
resolution without taking over Tailscale-owned DNS behavior.

The desired split is:

```text
MagicDNS / split DNS
  -> Tailscale policy from the control plane

default/public DNS
  -> selected known public DoH resolver
```

This avoids the unsafe approach of rewriting the final Android VPN DNS server
list after Tailscale has compiled DNS policy.

## User Behavior

DNS Settings includes a `Public DNS over HTTPS` section with:

- `Public DoH resolver`
- `Override exit-node DNS`
- `Route DoH through Tailscale`

The resolver picker shows known providers grouped by provider and endpoint
variant. It intentionally does not accept arbitrary URLs.

Examples of provider groups:

```text
Cloudflare
  Standard
  Malware blocking
  Family

Quad9
  Standard
  ECS + DNSSEC
  No DNSSEC

Mullvad
  Default
  Adblock
  Base
  Extended
  Family
  All
```

## Persistence

Android stores the DoH state in encrypted preferences:

```text
publicDoHURL
publicDoHOverrideExitNode
publicDoHRouteThroughTailscale
```

Encrypted preferences are used for consistency with the HTTP proxy setting and
because resolver choice can reveal user preference or threat model.

## Code Paths

Android UI/state:

```text
android/src/main/java/com/tailscale/ipn/ui/model/PublicDoHProvider.kt
android/src/main/java/com/tailscale/ipn/ui/view/DNSSettingsView.kt
android/src/main/java/com/tailscale/ipn/ui/viewModel/DNSSettingsViewModel.kt
android/src/main/res/values/strings_doh.xml
```

Android Go glue:

```text
libtailscale/control_doh.go
libtailscale/dns_apply.go
libtailscale/backend.go
```

Patched Tailscale core:

```text
../tailscale-core-patched/net/dns/config.go
../tailscale-core-patched/net/dns/manager.go
../tailscale-core-patched/net/dns/resolver/forwarder.go
```

Module wiring:

```go
replace tailscale.com => ../tailscale-core-patched
```

The active DoH backend depends on that local core patch. Without it, the Android
UI can save state, but selected public DoH cannot safely replace
`dns.Config.DefaultResolvers`.

## Core Hook

The patched core adds:

```go
dns.HookModifyConfig
```

The hook runs inside the DNS manager before DNS config compilation. Android uses
it to modify:

```go
cfg.DefaultResolvers
```

It deliberately does not modify:

```text
Routes
Hosts
SubdomainHosts
SearchDomains
```

That is the core safety property. `DefaultResolvers` represent fallback/public
DNS. `Routes` and host maps represent Tailscale-controlled MagicDNS and
split-DNS behavior.

## Runtime Flow

Resolver selection path:

```text
DNSSettingsView
  -> DNSSettingsViewModel
  -> encrypted Android prefs
  -> Libtailscale.applyDNSSettings()
  -> libtailscale.ApplyDNSSettings()
  -> DNSManager.RecompileDNSConfig()
  -> dns.HookModifyConfig
  -> cfg.DefaultResolvers replacement
  -> VPNFacade.ReconfigureVPN()
```

Forwarding path:

```text
App DNS query
  -> Android VPN DNS listener
  -> Tailscale DNS forwarder
  -> compiled DNS config
  -> selected public DoH resolver for default/public names
  -> MagicDNS/split-DNS routes stay under Tailscale policy
```

## Apply Path Decisions

### Recompile DNS Directly

Earlier behavior only triggered a network-change style reconfiguration. That
was not reliable enough: DNS changes could appear to apply only after unrelated
state changes such as enabling or disabling an exit node.

The patch now calls:

```go
DNSManager.RecompileDNSConfig()
```

This forces the DNS manager to re-run compilation using current Android
preferences.

### Reconfigure the VPN Facade

On Android, `dns.Manager` computes resolver state, but `VPNFacade.SetDNS` stores
that state for the active VPN builder path. The patch keeps a pointer to the
active `VPNFacade` and calls:

```go
VPNFacade.ReconfigureVPN()
```

This makes the changed DNS config visible without requiring the user to toggle
exit-node state or restart the app.

### Reuse `applyDNSSettings` for Log Toggles

The network debug logging switches also call:

```kotlin
Libtailscale.applyDNSSettings()
```

That exported gomobile binding already exists and is known to be generated into
the Android AAR. `ApplyDNSSettings` reloads logging preferences before applying
DNS. This avoids relying on a new Kotlin-visible gomobile method name.

## Resolver Validation

The selected resolver must:

- Parse as a URL.
- Use `https`.
- Have a host.
- Exist in Tailscale's known public DoH bootstrap table.

The known-provider restriction is intentional. Tailscale's DoH forwarder uses
known bootstrap mappings from `publicdns`. Arbitrary DoH URLs would require
resolving the DoH host before the chosen resolver is available, which can
reintroduce bootstrap leaks or failure modes.

## Leak Hardening

The patch uses these guardrails:

| Case | Behavior | Reason |
| --- | --- | --- |
| No resolver selected | Keep normal Tailscale/default DNS. | User did not request override. |
| Valid known resolver selected | Replace `DefaultResolvers` with selected DoH URL. | Only public/default DNS changes. |
| Unsupported non-empty resolver in prefs | Install deliberate invalid DoH resolver. | Fail closed instead of silently falling back to system DNS. |
| Exit-node DNS present and `Override exit-node DNS` off | Preserve exit-node DNS proxy. | User explicitly chose not to override exit-node DNS. |
| `Route DoH through Tailscale` on but no valid resolver | Do not enable route-aware DNS dialing. | Avoid changing DNS dial behavior when there is no selected DoH path. |
| Route-aware setting changes | Clear cached DoH HTTP clients. | Existing clients could otherwise keep old dialer behavior. |

## Route-Aware DoH

`Route DoH through Tailscale` controls how the HTTPS connection to the selected
DoH resolver is dialed. It does not choose which resolver answers DNS.

```text
Resolver choice:
  Cloudflare / Quad9 / Mullvad / etc.

Resolver transport path:
  system route or Tailscale route-aware dialing
```

The Android glue sets:

```go
ControlKnobs().UserDialUseRoutes
```

Android must also pass the same control-knob set into the userspace engine:

```go
wgengine.Config{
    ControlKnobs: sys.ControlKnobs(),
}
```

This matters on Android and iOS because `resolver.ShouldUseRoutes` returns true
only when the DNS forwarder can see `UserDialUseRoutes`. If the userspace engine
is created with nil control knobs, the Android setting can log:

```text
ANDROID_DNS_USAGE public DoH: route-aware DNS dialing set to true ...
```

while the forwarder still logs:

```text
useRoutes=false
path=tailscale-selected-doh-system-route
```

That state means the selected DoH resolver is active, but the DoH HTTPS
connection is still using the device/system route.

The patched core clears cached DoH HTTP clients when this value changes, so the
next DoH client uses the current route policy.

Fresh route-aware proof requires logs like:

```text
ANDROID_DNS_USAGE public DoH: route-aware DNS dialing set to true ...
ANDROID_DNS_USAGE public DoH: route-aware dialing changed; cleared cached DoH clients useRoutes=true
ANDROID_DNS_USAGE public DoH: forwarding DNS query via DoH resolver="..." bytes=... useRoutes=true
ANDROID_DNS_USAGE dns query result=success path=tailscale-selected-doh-route-aware resolver="..." query="..." ...
```

Fresh device/system-route proof looks like:

```text
ANDROID_DNS_USAGE public DoH: forwarding DNS query via DoH resolver="..." bytes=... useRoutes=false
ANDROID_DNS_USAGE dns query result=success path=tailscale-selected-doh-system-route resolver="..." query="..." ...
```

`system-route` is not a plain-DNS leak by itself. It means the DNS query was
sent to the selected DoH resolver over HTTPS, but the HTTPS connection used the
device's normal network route instead of route-aware Tailscale dialing.

## DNS Leak Guarantees and Non-Guarantees

For queries that enter Tailscale's DNS forwarder after a valid public DoH
resolver is selected, the patch is designed to avoid fallback to Android/system
DNS:

- Public/default DNS is replaced at `dns.Config.DefaultResolvers`.
- MagicDNS and split-DNS routes remain controlled by Tailscale policy.
- Unsupported resolver preferences fail closed by installing a deliberate
  invalid DoH resolver.
- DoH HTTP status, transport, content-type, and response-read failures return
  errors rather than intentionally falling back to system DNS.
- Query logs can prove the selected resolver path with
  `path=tailscale-selected-doh-*`.

The patch does not guarantee that every DNS-like lookup on the device is forced
through the selected resolver:

- Apps excluded from the VPN by split tunneling are outside this DNS path.
- Apps, browsers, or WebView may use their own DNS, DoH, or cached answers.
- DNS cached before the setting changed may be reused until the cache expires.
- DNS before Tailscale is connected or before the VPN is established is outside
  this patch.
- Android or OEM components outside the VPN boundary may have their own network
  behavior.
- `Route DoH through Tailscale` is only proven active when fresh logs show
  `useRoutes=true` or `path=tailscale-selected-doh-route-aware`.

## Known Limitations

- This patch requires the local patched Tailscale core until an equivalent hook
  exists upstream.
- Arbitrary DoH URLs are not supported.
- DoH provider ECH behavior is determined by Go/TLS and the provider endpoint;
  this patch does not add ECH handling.
- DNS already cached by apps, WebView, Chrome, or Android may remain cached
  outside Tailscale until those caches expire.
- If the selected DoH provider rejects a query with an HTTP error, the patch logs
  the error when query logs are enabled and returns failure; it does not fall
  back to system DNS.
