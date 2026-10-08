// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import com.tailscale.ipn.multiproxy.NetworkInventory
import com.tailscale.ipn.multiproxy.NetworkInventoryEntry
import com.tailscale.ipn.multiproxy.NetworkRouteEntry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Host tests for the pure network-inventory shaping and destination lookup. */
class NetworkInventoryTest {

  private fun inventory() =
      listOf(
          NetworkInventoryEntry(
              networkKey = "cellular",
              interfaceName = "rmnet0",
              transports = listOf("cellular"),
              bindable = true,
              isDefault = true,
              hasInternetCapability = true,
              isVpn = false,
              routes =
                  listOf(
                      NetworkRouteEntry(
                          cidr = "8.8.8.8/32",
                          gateway = "10.0.0.1",
                          onLink = false,
                          isDefault = false),
                      NetworkRouteEntry(
                          cidr = "0.0.0.0/0",
                          gateway = "10.0.0.1",
                          onLink = false,
                          isDefault = true),
                  ),
          ),
          NetworkInventoryEntry(
              networkKey = "tether-??",
              interfaceName = "rndis0",
              transports = listOf("ethernet"),
              // Deliberately NOT bindable - models a tether downstream Android does not expose as a
              // managed network. The inventory still lists its routes so diagnostics can see them.
              bindable = false,
              hasInternetCapability = false,
              isVpn = false,
              routes =
                  listOf(
                      NetworkRouteEntry(cidr = "172.27.85.0/24", onLink = true, isDefault = false)),
          ),
      )

  @Test
  fun jsonRoundTrips() {
    val entries = inventory()
    val decoded =
        NetworkInventory.json.decodeFromString<List<NetworkInventoryEntry>>(
            NetworkInventory.toJson(entries))
    assertEquals(entries, decoded)
  }

  @Test
  fun flattensRoutesForSelection() {
    val routes = NetworkInventory.toLocalRoutes(inventory())
    assertEquals(3, routes.size)
    val tether = routes.first { it.interfaceName == "rndis0" }
    assertEquals("172.27.85.0/24", tether.destinationCidr)
    assertTrue("a gateway-less route is on-link", !tether.hasGateway)
  }

  @Test
  fun pickForSelectsOnLinkTetherEvenWhenNotBindable() {
    val picked = NetworkInventory.pickFor("172.27.85.178", inventory())
    assertEquals("tether-??", picked?.networkKey)
    assertEquals("rndis0", picked?.interfaceName)
    assertEquals(24, picked?.prefixLength)
    assertTrue(picked!!.onLink)
  }

  @Test
  fun pickForFallsBackToDefaultForPublicDestination() {
    val picked = NetworkInventory.pickFor("1.1.1.1", inventory())
    assertEquals("cellular", picked?.networkKey)
  }

  @Test
  fun pickForDefaultsToNullWhenDestinationIsHostname() {
    assertNull(NetworkInventory.pickFor("fedora.local", inventory()))
  }
}
