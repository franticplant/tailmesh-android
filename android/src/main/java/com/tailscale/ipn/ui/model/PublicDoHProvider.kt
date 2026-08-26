// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.model

data class PublicDoHEndpoint(val label: String, val url: String)

data class PublicDoHProvider(val name: String, val endpoints: List<PublicDoHEndpoint>)

object PublicDoHProviders {
  const val OFF = ""

  val grouped: List<PublicDoHProvider> =
      listOf(
          PublicDoHProvider(
              "Cloudflare",
              listOf(
                  PublicDoHEndpoint("Standard", "https://cloudflare-dns.com/dns-query"),
                  PublicDoHEndpoint("Malware blocking", "https://security.cloudflare-dns.com/dns-query"),
                  PublicDoHEndpoint("Family", "https://family.cloudflare-dns.com/dns-query"))),
          PublicDoHProvider("Google", listOf(PublicDoHEndpoint("Standard", "https://dns.google/dns-query"))),
          PublicDoHProvider(
              "Quad9",
              listOf(
                  PublicDoHEndpoint("Standard", "https://dns.quad9.net/dns-query"),
                  PublicDoHEndpoint("ECS + DNSSEC", "https://dns11.quad9.net/dns-query"),
                  PublicDoHEndpoint("No DNSSEC", "https://dns10.quad9.net/dns-query"))),
          PublicDoHProvider(
              "Mullvad",
              listOf(
                  PublicDoHEndpoint("Default", "https://dns.mullvad.net/dns-query"),
                  PublicDoHEndpoint("Adblock", "https://adblock.dns.mullvad.net/dns-query"),
                  PublicDoHEndpoint("Base", "https://base.dns.mullvad.net/dns-query"),
                  PublicDoHEndpoint("Extended", "https://extended.dns.mullvad.net/dns-query"),
                  PublicDoHEndpoint("Family", "https://family.dns.mullvad.net/dns-query"),
                  PublicDoHEndpoint("All", "https://all.dns.mullvad.net/dns-query"))),
          PublicDoHProvider(
              "Wikimedia",
              listOf(PublicDoHEndpoint("Standard", "https://wikimedia-dns.org/dns-query"))),
          PublicDoHProvider(
              "LibreDNS",
              listOf(
                  PublicDoHEndpoint("Standard", "https://doh.libredns.gr/dns-query"),
                  PublicDoHEndpoint("Ads blocking", "https://doh.libredns.gr/ads"))),
          PublicDoHProvider(
              "Control D Free",
              listOf(
                  PublicDoHEndpoint("Default", "https://freedns.controld.com/p0"),
                  PublicDoHEndpoint("Malware", "https://freedns.controld.com/p1"),
                  PublicDoHEndpoint("Malware + Ads", "https://freedns.controld.com/p2"),
                  PublicDoHEndpoint("Malware + Ads + Social", "https://freedns.controld.com/p3"),
                  PublicDoHEndpoint("Family", "https://freedns.controld.com/family"))),
          PublicDoHProvider(
              "CIRA Canadian Shield",
              listOf(
                  PublicDoHEndpoint("Private", "https://private.canadianshield.cira.ca/dns-query"),
                  PublicDoHEndpoint("Protected", "https://protected.canadianshield.cira.ca/dns-query"),
                  PublicDoHEndpoint("Family", "https://family.canadianshield.cira.ca/dns-query"))))

  fun labelFor(url: String): String {
    if (url.isBlank()) {
      return "Tailnet default"
    }
    grouped.forEach { provider ->
      provider.endpoints.firstOrNull { it.url == url }?.let { endpoint ->
        return "${provider.name} · ${endpoint.label}"
      }
    }
    return url
  }
}
