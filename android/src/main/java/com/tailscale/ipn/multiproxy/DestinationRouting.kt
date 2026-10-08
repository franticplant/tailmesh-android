// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy

import java.net.InetAddress

/**
 * One route, reduced to what destination-aware direct dialing needs. Android's
 * [android.net.RouteInfo] carries more, but this is the whole of what the selection below reads,
 * which is what makes it host-testable with no Android framework present.
 *
 * @param networkKey identifies the underlying network the route belongs to (for Android, a stable
 *   string for a `ConnectivityManager.Network`, or an interface name for a directly-connected
 *   interface that is not a managed network - e.g. a USB-tether downstream).
 * @param destinationCidr e.g. `0.0.0.0/0`, `172.27.85.0/24`, `fd7a:115c:a1e0::/64`.
 * @param isDefaultRoute Android's own `RouteInfo.isDefaultRoute`.
 * @param hasGateway false means the route is directly connected (on-link); this is the property
 *   that matters for a local network the default route would otherwise shadow.
 */
data class LocalRoute(
    val networkKey: String,
    val interfaceName: String?,
    val destinationCidr: String,
    val isDefaultRoute: Boolean,
    val hasGateway: Boolean,
)

/** The chosen route for one destination. */
data class DestinationRoute(
    val networkKey: String,
    val interfaceName: String?,
    val prefixLength: Int,
    val onLink: Boolean,
)

/**
 * Picks which underlying network a direct (non-VPN) dial to a destination should use.
 *
 * This exists because `@direct` currently binds every IPv4 dial to the cached default network
 * (`NetworkChangeCallback.pickNetworkForDial`), which sends traffic to a directly-connected local
 * network - a USB-tether subnet, a NAS, a printer - out the default route instead. The rule here is
 * the ordinary longest-prefix match, with a directly-connected (on-link) route preferred over a
 * gatewayed one at equal specificity.
 *
 * Deliberately pure: no Android, no I/O, so it can be tested exhaustively on the host. Wiring it
 * into the dial path is a separate change that must be device-verified - see the project's
 * attribution-first plan; this module only makes the decision itself correct and testable.
 *
 * NOTE: not yet called by production code. It is the host-testable half of the proposed
 * "protected-but-unbound for on-link destinations" fix.
 */
object DestinationRouting {

  /**
   * The most-specific route containing [dst], or null when none matches (the caller then falls back
   * to today's cached-default-network behaviour). [dst] must be a literal IP; a hostname returns
   * null rather than triggering a DNS lookup.
   */
  fun pick(dst: String, routes: List<LocalRoute>): DestinationRoute? {
    val addr = literalAddress(dst) ?: return null
    var best: DestinationRoute? = null
    for (route in routes) {
      val cidr = parseCidr(route.destinationCidr) ?: continue
      if (cidr.address.size != addr.size) continue
      if (!matches(addr, cidr.address, cidr.prefix)) continue
      val candidate =
          DestinationRoute(
              networkKey = route.networkKey,
              interfaceName = route.interfaceName,
              prefixLength = cidr.prefix,
              onLink = !route.hasGateway,
          )
      if (best == null || isBetter(candidate, best)) best = candidate
    }
    return best
  }

  /** Whether [dst] is directly connected via any [routes] entry (no gateway). */
  fun isOnLink(dst: String, routes: List<LocalRoute>): Boolean = pick(dst, routes)?.onLink == true

  private fun isBetter(candidate: DestinationRoute, best: DestinationRoute): Boolean {
    if (candidate.prefixLength != best.prefixLength) {
      return candidate.prefixLength > best.prefixLength
    }
    if (candidate.onLink != best.onLink) return candidate.onLink
    return false
  }

  private class Cidr(val address: ByteArray, val prefix: Int)

  private fun parseCidr(s: String): Cidr? {
    val slash = s.indexOf('/')
    if (slash <= 0 || slash == s.length - 1) return null
    val address = literalAddress(s.substring(0, slash)) ?: return null
    val prefix = s.substring(slash + 1).toIntOrNull() ?: return null
    if (prefix < 0 || prefix > address.size * 8) return null
    return Cidr(address, prefix)
  }

  private fun matches(addr: ByteArray, net: ByteArray, prefix: Int): Boolean {
    var bits = prefix
    var i = 0
    while (bits >= 8) {
      if (addr[i] != net[i]) return false
      i++
      bits -= 8
    }
    if (bits > 0) {
      val mask = (0xFF shl (8 - bits)) and 0xFF
      if ((addr[i].toInt() and mask) != (net[i].toInt() and mask)) return false
    }
    return true
  }

  /**
   * Parses a literal IPv4/IPv6 address to its bytes, or null. Never resolves a hostname: only
   * digit/dot (v4) or hex/colon/dot (v6) strings are attempted, and a zone id is stripped.
   */
  private fun literalAddress(raw: String): ByteArray? {
    val s = raw.substringBefore('%').trim()
    if (s.isEmpty()) return null
    val v4 = s.all { it.isDigit() || it == '.' }
    val v6 =
        s.contains(':') &&
            s.all { it.isDigit() || it == ':' || it == '.' || it in 'a'..'f' || it in 'A'..'F' }
    if (!v4 && !v6) return null
    return try {
      InetAddress.getByName(s).address
    } catch (e: Exception) {
      null
    }
  }
}
