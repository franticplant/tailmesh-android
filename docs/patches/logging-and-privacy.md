# Logging and Privacy

## Goal

The network patches need detailed diagnostics because proxy and DNS behavior can
fail silently from the user's point of view. For example:

- A proxy URL can be valid but unreachable from Android.
- DERP can keep an existing direct connection after a proxy setting changes.
- DNS can appear unchanged if the VPN DNS config is not refreshed.
- A DoH provider can reject queries with HTTP errors.
- Route-aware DoH dialing can keep old cached HTTP clients if not reset.

The same logs can expose sensitive information. Therefore Android-specific
network logs are opt-in and split by sensitivity.

Important: these logs currently use the Go logger. If Tailscale client remote
logging is enabled, opt-in debug lines can be included in logtail upload payloads.
This is especially sensitive for `DNS query debug logs`, because those lines
include queried domain names. Disable client remote logging while collecting
DNS-query diagnostics if those names should remain local to the device.

## UI Toggles

Settings exposes three independent switches:

```text
HTTP proxy debug logs
DNS config debug logs
DNS query debug logs
```

All three default to `false`.

The switches are stored in encrypted preferences:

```text
debugHTTPProxyLogging
debugDNSConfigLogging
debugDNSQueryLogging
```

When a switch changes, the ViewModel calls:

```kotlin
Libtailscale.applyDNSSettings()
```

The Go binding reloads logging preferences before applying DNS settings. This
keeps the Kotlin side on an already-generated gomobile method and avoids adding
a separate binding only for diagnostics.

## Log Categories

| Toggle | Keyword | Files | Sensitivity |
| --- | --- | --- | --- |
| `HTTP proxy debug logs` | `ANDROID_HTTPPROXY` | `libtailscale/control_proxy.go` | Can expose proxy URL and request URL. |
| `DNS config debug logs` | `ANDROID_DNS_USAGE` | `libtailscale/control_doh.go`, patched `forwarder.go` route reset log | Can expose selected DoH resolver and DNS setting state. |
| `DNS query debug logs` | `ANDROID_DNS_USAGE` | patched `net/dns/resolver/forwarder.go` | Can expose queried domains, resolver, route path, latency, and DoH errors. |

## HTTP Proxy Logs

Controlled by:

```text
HTTP proxy debug logs
```

Keyword:

```text
ANDROID_HTTPPROXY
```

Introduced log lines:

```text
ANDROID_HTTPPROXY control proxy: installing Android httpproxy resolver
ANDROID_HTTPPROXY control proxy: installed Android httpproxy resolver
ANDROID_HTTPPROXY control proxy: failed to read httpproxy setting: ...
ANDROID_HTTPPROXY control proxy: httpproxy disabled for "https://..."
ANDROID_HTTPPROXY control proxy: ignoring invalid httpproxy URL "...": ...
ANDROID_HTTPPROXY control proxy: using httpproxy "http://..." for "https://..."
ANDROID_HTTPPROXY control proxy: ignoring unsupported httpproxy URL scheme "..."
ANDROID_HTTPPROXY control proxy: failed to install httpproxy resolver: ...
ANDROID_HTTPPROXY control proxy: reloaded Android network debug logging settings httpProxy=...
```

Sensitive fields:

- Proxy URL, possibly including credentials.
- Destination URL for Tailscale HTTP requests.
- Whether a proxy is configured.

Recommended filter:

```sh
adb logcat | grep -Ei 'ANDROID_HTTPPROXY|control proxy|tshttpproxy|proxy|CONNECT|derphttp|controlclient'
```

## DNS Config Logs

Controlled by:

```text
DNS config debug logs
```

Keyword:

```text
ANDROID_DNS_USAGE
```

Introduced Android glue logs:

```text
ANDROID_DNS_USAGE public DoH: installed Android DNS config hook
ANDROID_DNS_USAGE public DoH: backend unavailable; changed DNS usage will apply on next backend start
ANDROID_DNS_USAGE public DoH: DNS manager unavailable; falling back to network-change reconfigure
ANDROID_DNS_USAGE public DoH: no DNS config to recompile yet; falling back to network-change reconfigure
ANDROID_DNS_USAGE public DoH: failed to recompile changed DNS usage: ...
ANDROID_DNS_USAGE public DoH: VPN facade unavailable after DNS recompile
ANDROID_DNS_USAGE public DoH: failed to reconfigure VPN after DNS usage change: ...
ANDROID_DNS_USAGE public DoH: reapplied changed DNS usage
ANDROID_DNS_USAGE public DoH: failed to read resolver URL for route setting: ...
ANDROID_DNS_USAGE public DoH: route-aware DNS dialing set to ... selectedResolver="..." validResolver=...
ANDROID_DNS_USAGE public DoH: failed to read resolver URL: ...
ANDROID_DNS_USAGE public DoH: no selected resolver; keeping tailnet/default DNS usage
ANDROID_DNS_USAGE public DoH: refusing unsupported selected resolver URL "..."; DNS will fail closed
ANDROID_DNS_USAGE public DoH: preserving exit-node DNS proxy selectedResolver="..." overrideExitNode=false
ANDROID_DNS_USAGE public DoH: changed DNS usage to selected resolver "..." overrideExitNode=...
ANDROID_DNS_USAGE public DoH: failed to read <key>: ...
ANDROID_DNS_USAGE public DoH: ignoring invalid boolean <key>="..."
ANDROID_DNS_USAGE public DoH: reloaded Android network debug logging settings dnsConfig=... dnsQuery=...
```

Introduced patched-core config log:

```text
ANDROID_DNS_USAGE public DoH: route-aware dialing changed; cleared cached DoH clients useRoutes=...
```

Sensitive fields:

- Selected DoH resolver URL.
- Whether exit-node DNS is overridden.
- Whether route-aware DNS dialing is enabled.
- Preference key names and preference parse errors.

Recommended filter:

```sh
adb logcat | grep -Ei 'ANDROID_DNS_USAGE|public DoH'
```

## DNS Query Logs

Controlled by:

```text
DNS query debug logs
```

Keyword:

```text
ANDROID_DNS_USAGE
```

Introduced DoH transaction logs:

```text
ANDROID_DNS_USAGE public DoH: forwarding DNS query via DoH resolver="..." bytes=... useRoutes=...
ANDROID_DNS_USAGE public DoH: failed to build DoH request resolver="..." err=...
ANDROID_DNS_USAGE public DoH: DoH transport error resolver="..." err=...
ANDROID_DNS_USAGE public DoH: DoH HTTP status error resolver="..." status=...
ANDROID_DNS_USAGE public DoH: DoH content-type error resolver="..." contentType=...
ANDROID_DNS_USAGE public DoH: failed reading DoH response resolver="..." err=...
ANDROID_DNS_USAGE public DoH: DoH query succeeded resolver="..." responseBytes=...
```

Introduced per-query result logs:

```text
ANDROID_DNS_USAGE dns query result=success path=... resolver="..." query="..." type=... duration_ms=... response_bytes=...
ANDROID_DNS_USAGE dns query result=error path=... resolver="..." query="..." type=... duration_ms=... error_class=... err=...
```

Sensitive fields:

- Queried domain name.
- DNS record type.
- Resolver URL or IP address.
- Whether the path used system route or route-aware dialing.
- Latency and timeout behavior.
- HTTP DoH status or transport error detail.

Recommended filter:

```sh
adb logcat | grep -Ei 'ANDROID_DNS_USAGE dns query|DoH transport error|DoH HTTP status|DoH content-type|failed reading DoH|forwarding DNS query|DoH query succeeded'
```

## Local Logcat vs Logtail Upload Payloads

The app writes Go logs to Android logcat, and the normal Tailscale logtail path
can also collect Go logger output when client remote logging is enabled. In
logcat, uploaded logtail batches can appear as JSON payload fragments containing
older `ANDROID_DNS_USAGE` lines, for example:

```text
{"logtail":{"client_time":"..."},"text":"... ANDROID_DNS_USAGE dns query ..."}
```

Those JSON fragments are not necessarily fresh DNS activity. Use the embedded
`client_time` field to determine when the original event happened.

For clean local testing:

```sh
adb logcat -c
adb logcat | grep -Ei 'ANDROID_DNS_USAGE.*(route-aware|useRoutes|dns query)'
```

Then trigger a fresh DNS lookup after the filter is running.

For privacy-sensitive DNS testing:

```text
Client remote logging: off
DNS config debug logs: on only while testing
DNS query debug logs: on only while testing
```

Future hardening option: route these diagnostics through an Android-local logger
instead of `log.Printf`, so opt-in local diagnostics do not enter logtail.

## Path Labels

Per-query logs include a path label:

| Path label | Meaning |
| --- | --- |
| `tailscale-selected-doh-system-route` | Selected public DoH resolver dialed using the system network path. |
| `tailscale-selected-doh-route-aware` | Selected public DoH resolver dialed with Tailscale route-aware dialing. It can follow an active exit node when routes allow it. |
| `tailscale-dns-proxy-system-route` | Tailscale HTTP DNS proxy resolver, usually exit-node or PeerAPI DNS, dialed using the system path. |
| `tailscale-dns-proxy-route-aware` | Tailscale HTTP DNS proxy resolver dialed with route-aware dialing. |
| `classic-dns-system-route` | Plain UDP/TCP resolver dialed using the system path. |
| `classic-dns-route-aware` | Plain UDP/TCP resolver dialed with route-aware dialing. |

## Error Classes

Per-query error logs classify common failures:

| Error class | Meaning |
| --- | --- |
| `timeout` | Query exceeded its deadline or upstream timed out. |
| `canceled` | Context was canceled before completion. |
| `server-failure` | DNS server failure or translated DoH server failure. |
| `refused` | DNS refusal. |
| `txid-mismatch` | Response transaction ID did not match the query. |
| `error` | Fallback class for other errors, including many HTTP DoH errors. |

## Why Logging Is Split

### HTTP Proxy Logs Are Request-Path Sensitive

These logs are needed to confirm whether Tailscale HTTP transports are asking
for a proxy and whether DERP/control requests are using it. They can expose
proxy credentials and Tailscale destination URLs, so they are isolated behind
their own switch.

### DNS Config Logs Are State Sensitive

These logs explain why a selected resolver did or did not become active. They
are useful for apply-path bugs and exit-node interactions. They usually do not
show every domain the user visits, but they do show resolver choice and policy
state.

### DNS Query Logs Are Browsing Sensitive

Per-query logs are the most sensitive category because they include domain
names. They should only be enabled while reproducing a DNS issue and disabled
after collecting the needed evidence.

## Operational Guidance

For normal use:

```text
HTTP proxy debug logs: off
DNS config debug logs: off
DNS query debug logs: off
```

For proxy debugging:

```text
HTTP proxy debug logs: on
DNS config debug logs: off
DNS query debug logs: off
```

For DoH apply debugging:

```text
HTTP proxy debug logs: off
DNS config debug logs: on
DNS query debug logs: off
```

For DNS leak or latency debugging:

```text
HTTP proxy debug logs: off
DNS config debug logs: on
DNS query debug logs: on only while testing
```
