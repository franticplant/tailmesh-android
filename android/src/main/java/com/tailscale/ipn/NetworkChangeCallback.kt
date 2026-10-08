// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package com.tailscale.ipn

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import com.tailscale.ipn.multiproxy.NetworkInventory
import com.tailscale.ipn.multiproxy.NetworkInventoryEntry
import com.tailscale.ipn.multiproxy.NetworkRouteEntry
import com.tailscale.ipn.util.TSLog
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import libtailscale.Libtailscale

object NetworkChangeCallback {

  private const val TAG = "NetworkChangeCallback"

  private data class NetworkInfo(var caps: NetworkCapabilities, var linkProps: LinkProperties)

  private val lock = ReentrantLock()

  // All currently active non-VPN networks we know about.
  private val activeNetworks = mutableMapOf<Network, NetworkInfo>()

  // Cached chosen default network for outbound sockets.
  @Volatile
  var cachedDefaultNetwork: Network? = null
    private set

  // Cached info for the chosen default network.
  @Volatile private var cachedDefaultNetworkInfo: NetworkInfo? = null

  // Convenience: cached interface name for logging.
  @Volatile
  var cachedDefaultInterfaceName: String? = null
    private set

  // MULTIPROXY EXTENSION
  @Volatile
  var currentDnsServerStr: String? = null
    private set

  // Set by monitorDnsChanges/snapshotIfEmpty so networkInventory() can enumerate every network
  // Android knows about, not just the INTERNET+NOT_VPN set this object tracks for DNS/default.
  @Volatile private var connectivityManager: ConnectivityManager? = null

  // Optional destination the inventory logs an on-link answer for on each recompute. Left unset by
  // default; a debug action can point it at the address under investigation (e.g. a tether peer) so
  // an attribution run reads "would this destination be on-link, via which interface?" from logcat.
  @Volatile
  var diagnosticDestination: String? = null
    private set

  fun setDiagnosticDestination(dst: String?) {
    diagnosticDestination = dst
  }

  fun currentUnderlyingDnsServer(): String? = currentDnsServerStr

  // snapshotIfEmpty synchronously reads the connectivity state Android
  // already has, for the window right after monitorDnsChanges registers its
  // callback but before that callback's first onAvailable/
  // onLinkPropertiesChanged has actually been delivered - callback delivery
  // is asynchronous, so on a freshly (re)started process there is a real gap
  // where currentDnsServerStr is still null even though the device's network
  // and DNS servers haven't changed at all. A Multi-Tailnet (re)start that
  // lands in that gap calls applyUpstreamDNS with an empty DNS value, which
  // sets Engine.upstreamDNS to "" and silently fails every non-tailnet DNS
  // lookup until the callback eventually catches up (or forever, if it
  // doesn't fire again because nothing about the network actually changes).
  // See validation_and_gaps.md #78. This does not replace the callback -
  // only fills the gap before its first delivery - so it's a no-op once
  // currentDnsServerStr is already set.
  fun snapshotIfEmpty(connectivityManager: ConnectivityManager) {
    this.connectivityManager = connectivityManager
    if (currentDnsServerStr != null) return
    lock.withLock {
      if (currentDnsServerStr != null) return@withLock
      for (network in connectivityManager.allNetworks) {
        val caps = connectivityManager.getNetworkCapabilities(network) ?: continue
        val linkProps = connectivityManager.getLinkProperties(network) ?: continue
        activeNetworks[network] = NetworkInfo(caps, linkProps)
      }
      recomputeDefaultNetworkLocked("snapshotIfEmpty")
      val info = cachedDefaultNetworkInfo ?: return@withLock
      currentDnsServerStr = info.linkProps.dnsServers.firstOrNull()?.hostAddress
      TSLog.d(TAG, "snapshotIfEmpty: seeded currentDnsServerStr=$currentDnsServerStr")
    }
  }

  // monitorDnsChanges sets up a network callback to monitor changes to the
  // system's network state and update the DNS configuration when interfaces
  // become available or properties of those interfaces change.
  fun monitorDnsChanges(connectivityManager: ConnectivityManager, dns: DnsConfig) {
    this.connectivityManager = connectivityManager
    val networkConnectivityRequest =
        NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()

    // Use registerNetworkCallback to listen for updates from all networks, and
    // then update DNS configs for the best network when LinkProperties are changed.
    // Per
    // https://developer.android.com/reference/android/net/ConnectivityManager.NetworkCallback#onAvailable(android.net.Network), this happens after all other updates.
    //
    // Note that we can't use registerDefaultNetworkCallback because the
    // default network used by Tailscale will always show up with capability
    // NOT_VPN=false, and we must filter out NOT_VPN networks to avoid routing
    // loops.
    connectivityManager.registerNetworkCallback(
        networkConnectivityRequest,
        object : ConnectivityManager.NetworkCallback() {

          override fun onAvailable(network: Network) {
            super.onAvailable(network)

            TSLog.d(TAG, "onAvailable: network $network")

            lock.withLock {
              activeNetworks[network] = NetworkInfo(NetworkCapabilities(), LinkProperties())
              recomputeDefaultNetworkLocked("onAvailable")
            }
          }

          override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            super.onCapabilitiesChanged(network, capabilities)

            lock.withLock {
              activeNetworks[network]?.caps = capabilities
              recomputeDefaultNetworkLocked("onCapabilitiesChanged")
            }
          }

          override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            super.onLinkPropertiesChanged(network, linkProperties)

            lock.withLock {
              activeNetworks[network]?.linkProps = linkProperties
              recomputeDefaultNetworkLocked("onLinkPropertiesChanged")
              maybeUpdateDNSConfig("onLinkPropertiesChanged", dns)
            }
          }

          override fun onLost(network: Network) {
            super.onLost(network)

            TSLog.d(TAG, "onLost: network $network")

            lock.withLock {
              activeNetworks.remove(network)
              recomputeDefaultNetworkLocked("onLost")
              maybeUpdateDNSConfig("onLost", dns)
            }
          }
        })
  }

  // pickNonMetered returns the first non-metered network in the list of
  // networks, or the first network if none are non-metered.
  private fun pickNonMetered(networks: Map<Network, NetworkInfo>): Network? {
    for ((network, info) in networks) {
      if (info.caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)) {
        return network
      }
    }
    return networks.keys.firstOrNull()
  }

  // pickDefaultNetwork returns a non-VPN network to use as the 'default'
  // network; one that is used as a gateway to the internet and from which we
  // obtain our DNS servers.
  private fun pickDefaultNetwork(): Network? {
    // Filter the list of all networks to those that have the INTERNET
    // capability, are not VPNs, and have a non-zero number of DNS servers
    // available.
    val networks =
        activeNetworks.filter { (_, info) ->
          info.caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
              info.caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
              info.linkProps.dnsServers.isNotEmpty()
        }

    // If we have one; just return it; otherwise, prefer networks that are also
    // not metered (i.e. cell modems).
    val nonMeteredNetwork = pickNonMetered(networks)
    if (nonMeteredNetwork != null) {
      return nonMeteredNetwork
    }

    // Okay, less good; just return the first network that has the INTERNET and
    // NOT_VPN capabilities; even though this interface doesn't have any DNS
    // servers set, we'll use our DNS fallback servers to make queries. It's
    // strictly better to return an interface + use the DNS fallback servers
    // than to return nothing and not be able to route traffic.
    for ((network, info) in activeNetworks) {
      if (info.caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
          info.caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
        Log.w(TAG, "no networks with DNS; falling back to first network $network")
        return network
      }
    }

    // Otherwise, return nothing; we don't want to return a VPN network since
    // it could result in a routing loop, and a non-INTERNET network isn't
    // helpful.
    Log.w(TAG, "no networks available to pick default network")
    return null
  }

  // hasUsableIPv6 reports whether a network's LinkProperties show an actual
  // IPv6 default route - not just an IPv6 link-local/ULA address, which
  // every interface tends to have regardless of whether the upstream
  // actually forwards v6 traffic. Broken/absent IPv6 uplinks are common
  // (a Wi-Fi AP or carrier with v4-only backhaul, tethering, some VPNs) and
  // Android still reports the interface as "up" with an IPv6 address in
  // that case - only the default route distinguishes "has an address" from
  // "can actually reach the v6 internet".
  private fun hasUsableIPv6(linkProps: LinkProperties): Boolean =
      linkProps.routes.any { it.isDefaultRoute && it.destination.address is java.net.Inet6Address }

  /**
   * Reports whether the device's current default network has Android's system-wide "Private DNS"
   * set to a specific hostname (Settings > Network & internet > Private DNS > "Private DNS provider
   * hostname", sometimes called "strict mode").
   *
   * This matters because it is a structural DNS leak Tailmesh cannot close from inside a
   * VpnService: in strict mode, Android resolves and connects directly to that provider's own
   * DNS-over-TLS server on port 853, using whatever route table entry matches that real IP - not
   * the synthetic DNS address this app advertises via VpnService.Builder.addDnsServer. Unless that
   * specific address happens to be covered by an active VPN route (broad capture on, or the
   * provider's IP happens to fall in a route already added for another reason), the query leaves
   * over the underlying network completely untouched by Tailmesh, and a DNS-leak-test site will
   * correctly report the ISP's (or provider's) resolver instead of the tailnet's - not because
   * Tailmesh mis-routed anything, but because the OS never handed it the packets in the first
   * place. "Automatic" mode (opportunistic DoT, falling back to the network's own advertised
   * servers on failure) is not this problem: LinkProperties.isPrivateDnsActive is only true for
   * strict mode.
   *
   * Callers should surface this as a warning telling the user to set Private DNS to "Automatic" or
   * "Off" for full protection, rather than attempt to route around it - there is no VpnService API
   * to override or intercept the OS's own strict-mode DoT connection.
   */
  fun hasStrictPrivateDnsActive(): Boolean =
      lock.withLock { cachedDefaultNetworkInfo?.linkProps?.isPrivateDnsActive == true }

  /**
   * Every network Android knows about, with its transports and full route table - the diagnostics
   * inventory for the destination-aware direct-routing investigation.
   *
   * A directly-connected interface Android does not expose as a managed network (typically a
   * USB-tether downstream) is simply absent: there is no `Network` object to bind a socket to,
   * which is itself the answer to "is the tether subnet selectable?".
   * [NetworkInventoryEntry.bindable] marks the ones the existing default-selection filter accepts.
   */
  fun networkInventory(): List<NetworkInventoryEntry> {
    val cm = connectivityManager ?: return emptyList()
    return lock.withLock {
      cm.allNetworks.mapNotNull { network ->
        val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
        val linkProps = cm.getLinkProperties(network) ?: return@mapNotNull null
        NetworkInventoryEntry(
            networkKey = network.toString(),
            interfaceName = linkProps.interfaceName,
            transports = transportsOf(caps),
            bindable =
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
            isDefault = network == cachedDefaultNetwork,
            hasInternetCapability = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
            isVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
            routes =
                linkProps.routes.mapNotNull { route ->
                  val address = route.destination?.address ?: return@mapNotNull null
                  NetworkRouteEntry(
                      cidr = "${address.hostAddress}/${route.destination.prefixLength}",
                      gateway = route.gateway?.hostAddress,
                      onLink = route.gateway == null,
                      isDefault = route.isDefaultRoute,
                  )
                },
        )
      }
    }
  }

  /**
   * Logs the network inventory and, when [destination] is given, which network/interface a direct
   * dial to it would pick and whether that is on-link. Emitted on every default-network recompute
   * and on the startup snapshot, so an OFF/ON attribution run captures it from logcat with no
   * debugger. See the destination-routing attribution checklist.
   */
  fun logNetworkInventory(why: String, destination: String? = null) {
    val entries = networkInventory()
    TSLog.d(TAG, "network inventory ($why): ${NetworkInventory.toJson(entries)}")
    if (!destination.isNullOrBlank()) {
      val picked = NetworkInventory.pickFor(destination, entries)
      TSLog.d(
          TAG,
          "destination $destination -> " +
              (picked?.let {
                "network=${it.networkKey} iface=${it.interfaceName} /${it.prefixLength} onLink=${it.onLink}"
              } ?: "no route (falls back to cached default)"))
    }
  }

  private fun transportsOf(caps: NetworkCapabilities): List<String> = buildList {
    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) add("wifi")
    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) add("cellular")
    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) add("ethernet")
    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) add("bluetooth")
    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) add("vpn")
    if (android.os.Build.VERSION.SDK_INT >= 31 &&
        caps.hasTransport(NetworkCapabilities.TRANSPORT_USB)) {
      add("usb")
    }
  }

  /**
   * One-line description of a chosen network (interface, transports, whether it is the cached
   * default) for the bind-time log, so an OFF/ON attribution run can see which interface a direct
   * dial actually bound to.
   */
  fun networkDescription(network: Network?): String {
    if (network == null) return "none"
    val cm = connectivityManager ?: return network.toString()
    val iface = cm.getLinkProperties(network)?.interfaceName ?: "?"
    val transports = cm.getNetworkCapabilities(network)?.let { transportsOf(it) } ?: emptyList()
    val isDefault = network == cachedDefaultNetwork
    return "iface=$iface transports=$transports default=$isDefault"
  }

  // pickNetworkForDial returns the network to bind an outbound socket of the
  // given IP family to. IPv4 dials use the same single "default network" as
  // before; IPv6 dials are family-aware, because the chosen default network
  // can be IPv4-only (or have a broken v6 uplink) even when some other
  // active network does carry usable IPv6 - forcing an IPv6 socket onto a
  // v4-only network doesn't fail cleanly, it produces a connection that
  // completes a TCP handshake / TLS ClientHello and then hangs for hundreds
  // of milliseconds before the remote resets it, instead of failing fast
  // enough for the caller's own Happy Eyeballs logic to retry over IPv4.
  // Returns null when no active network can carry the requested family, so
  // the caller can fail the dial immediately rather than binding to a
  // network that will not actually deliver it.
  fun pickNetworkForDial(isIPv6: Boolean): Network? =
      lock.withLock {
        if (!isIPv6) return@withLock cachedDefaultNetwork

        cachedDefaultNetworkInfo?.let { info ->
          if (hasUsableIPv6(info.linkProps)) return@withLock cachedDefaultNetwork
        }

        for ((network, info) in activeNetworks) {
          if (info.caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
              info.caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
              hasUsableIPv6(info.linkProps)) {
            return@withLock network
          }
        }

        null
      }

  // Update cached default network + log interface name.
  // Last network-source label reported to the observability event store, so
  // a transition event only fires on an actual change - not on every
  // NetworkCallback delivery, most of which don't change which transport is
  // the default (e.g. onLinkPropertiesChanged for a non-default network).
  @Volatile private var lastReportedNetworkSource: String? = null

  private fun networkSourceLabel(caps: NetworkCapabilities?): String =
      when {
        caps == null -> "none"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "vpn"
        else -> "other"
      }

  private fun recomputeDefaultNetworkLocked(why: String) {
    val newNetwork = pickDefaultNetwork()
    cachedDefaultNetwork = newNetwork

    val info = if (newNetwork != null) activeNetworks[newNetwork] else null
    cachedDefaultNetworkInfo = info
    cachedDefaultInterfaceName = info?.linkProps?.interfaceName

    TSLog.d(
        TAG, "$why: cachedDefaultNetwork=$newNetwork iface=${cachedDefaultInterfaceName ?: "none"}")

    // Discrete, deduplicated transition event for the diagnostics event log -
    // this is purely a label derived from data ConnectivityManager already
    // pushed us, not a new poll or lookup.
    val newSource = networkSourceLabel(info?.caps)
    val prevSource = lastReportedNetworkSource
    if (prevSource != null && prevSource != newSource) {
      MultiProxySessionCoordinator.recordNetworkSourceEvent(newSource, prevSource, newSource)
    }
    lastReportedNetworkSource = newSource

    // Diagnostics: capture the full network/route inventory (and, when set, a destination's on-link
    // answer) on every recompute, so an OFF/ON attribution run has it in logcat.
    logNetworkInventory(why, diagnosticDestination)
  }

  // maybeUpdateDNSConfig will maybe update our DNS configuration based on the
  // current set of active Networks.
  private fun maybeUpdateDNSConfig(why: String, dns: DnsConfig) {
    val defaultNetwork = cachedDefaultNetwork
    if (defaultNetwork == null) {
      TSLog.d(TAG, "$why: no default network available; not updating DNS")
      currentDnsServerStr = null
      IPNService.onUnderlyingDnsChanged("")
      return
    }

    val info = cachedDefaultNetworkInfo
    if (info == null) {
      Log.w(TAG, "$why: no info for default network; not updating DNS")
      return
    }

    // MULTIPROXY EXTENSION: Check if the raw IP list changed, if so, notify IPNService.
    val newDnsStr = info.linkProps.dnsServers.firstOrNull()?.hostAddress
    if (currentDnsServerStr != newDnsStr) {
      currentDnsServerStr = newDnsStr
      IPNService.onUnderlyingDnsChanged(newDnsStr ?: "")
    }

    val sb = StringBuilder()
    for (ip in info.linkProps.dnsServers) {
      sb.append(ip.hostAddress).append(" ")
    }

    val searchDomains: String? = info.linkProps.domains
    if (searchDomains != null) {
      sb.append("\n")
      sb.append(searchDomains)
    }

    if (dns.updateDNSFromNetwork(sb.toString())) {
      TSLog.d(TAG, "$why: updated DNS config for iface=${info.linkProps.interfaceName}")

      val gatewayIP =
          info.linkProps.routes
              .filter { it.isDefaultRoute && it.gateway != null }
              .sortedBy { if (it.gateway is java.net.Inet4Address) 0 else 1 }
              .firstNotNullOfOrNull { it.gateway?.hostAddress } ?: ""

      Libtailscale.onGatewayChanged(gatewayIP)
      Libtailscale.onDNSConfigChanged(info.linkProps.interfaceName)
    }
  }
}
