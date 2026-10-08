// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** One route on one network, shaped for the diagnostics inventory. */
@Serializable
data class NetworkRouteEntry(
    val cidr: String,
    val gateway: String? = null,
    val onLink: Boolean,
    val isDefault: Boolean,
)

/**
 * One Android network as the diagnostics inventory reports it - enough to answer "is the local
 * tether subnet a selectable network, and what routes does it carry?" without a device shell.
 *
 * @param bindable whether this network qualifies for `Network.bindSocket` under the same filter
 *   `pickDefaultNetwork` uses (has INTERNET capability and is not a VPN). A directly-connected
 *   interface that is not a managed `ConnectivityManager` network (typically a USB-tether
 *   downstream) will simply be absent from the inventory - which is itself the answer.
 * @param isDefault whether this is the currently cached default network.
 */
@Serializable
data class NetworkInventoryEntry(
    val networkKey: String,
    val interfaceName: String? = null,
    val transports: List<String> = emptyList(),
    val bindable: Boolean,
    val isDefault: Boolean = false,
    val hasInternetCapability: Boolean,
    val isVpn: Boolean,
    val routes: List<NetworkRouteEntry> = emptyList(),
)

/**
 * Pure shaping/serialisation for the network inventory, kept free of Android types so it is
 * host-testable. The Android side (NetworkChangeCallback) builds the entries; this decides how they
 * are described and how a destination maps onto them.
 */
object NetworkInventory {
  val json: Json = Json { encodeDefaults = true }

  fun toJson(entries: List<NetworkInventoryEntry>): String = json.encodeToString(entries)

  /** Flattens every network's routes into the flat list [DestinationRouting] reads. */
  fun toLocalRoutes(entries: List<NetworkInventoryEntry>): List<LocalRoute> =
      entries.flatMap { entry ->
        entry.routes.map { route ->
          LocalRoute(
              networkKey = entry.networkKey,
              interfaceName = entry.interfaceName,
              destinationCidr = route.cidr,
              isDefaultRoute = route.isDefault,
              hasGateway = !route.onLink,
          )
        }
      }

  /** The route a direct dial to [dst] would pick across the whole inventory, or null. */
  fun pickFor(dst: String, entries: List<NetworkInventoryEntry>): DestinationRoute? =
      DestinationRouting.pick(dst, toLocalRoutes(entries))
}
