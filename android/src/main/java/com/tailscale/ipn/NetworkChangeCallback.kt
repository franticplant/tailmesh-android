// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package com.tailscale.ipn

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
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

  // Update cached default network + log interface name.
  // Last network-source label reported to the observability event store, so
  // a transition event only fires on an actual change - not on every
  // NetworkCallback delivery, most of which don't change which transport is
  // the default (e.g. onLinkPropertiesChanged for a non-default network).
  @Volatile private var lastReportedNetworkSource: String? = null

  private fun networkSourceLabel(caps: NetworkCapabilities?): String = when {
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
