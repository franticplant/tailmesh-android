// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import com.tailscale.ipn.multiproxy.DestinationRouting
import com.tailscale.ipn.multiproxy.LocalRoute
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host tests for the destination-aware direct-dial selection. Plain JUnit - [DestinationRouting] is
 * deliberately free of Android types so the whole decision is exercised here, with no emulator.
 */
class DestinationRoutingTest {

  private fun route(
      key: String,
      cidr: String,
      onLink: Boolean,
      iface: String? = null,
      default: Boolean = cidr.endsWith("/0"),
  ) = LocalRoute(key, iface, cidr, default, hasGateway = !onLink)

  /**
   * The exact reported scenario: a local tether subnet must not be forced out the default route.
   */
  @Test
  fun picksOnLinkTetherOverCellularDefault() {
    val routes =
        listOf(
            route("cellular", "0.0.0.0/0", onLink = false, iface = "rmnet0"),
            route("tether", "172.27.85.0/24", onLink = true, iface = "rndis0"),
        )
    val picked = DestinationRouting.pick("172.27.85.178", routes)
    assertEquals("tether", picked?.networkKey)
    assertEquals("rndis0", picked?.interfaceName)
    assertEquals(24, picked?.prefixLength)
    assertTrue(picked!!.onLink)
  }

  @Test
  fun mostSpecificPrefixWins() {
    val routes =
        listOf(
            route("a", "10.0.0.0/8", onLink = true),
            route("b", "10.1.0.0/16", onLink = true),
            route("c", "10.1.2.0/24", onLink = true),
        )
    assertEquals("c", DestinationRouting.pick("10.1.2.5", routes)?.networkKey)
  }

  @Test
  fun onLinkPreferredOverGatewayAtEqualPrefix() {
    val routes =
        listOf(
            route("viaGateway", "192.168.1.0/24", onLink = false),
            route("onLink", "192.168.1.0/24", onLink = true),
        )
    val picked = DestinationRouting.pick("192.168.1.10", routes)
    assertEquals("onLink", picked?.networkKey)
    assertTrue(picked!!.onLink)
  }

  @Test
  fun ipv6OnLinkSelected() {
    val routes =
        listOf(
            route("v6default", "::/0", onLink = false),
            route("v6link", "fd7a:115c:a1e0::/64", onLink = true),
        )
    val picked = DestinationRouting.pick("fd7a:115c:a1e0::1", routes)
    assertEquals("v6link", picked?.networkKey)
    assertEquals(64, picked?.prefixLength)
  }

  @Test
  fun fallsBackToDefaultRouteWhenNothingMoreSpecific() {
    val routes =
        listOf(
            route("cellular", "0.0.0.0/0", onLink = false),
            route("tether", "172.27.85.0/24", onLink = true),
        )
    val picked = DestinationRouting.pick("8.8.8.8", routes)
    assertEquals("cellular", picked?.networkKey)
    assertFalse(picked!!.onLink)
  }

  @Test
  fun noMatchReturnsNull() {
    val routes = listOf(route("tether", "172.27.85.0/24", onLink = true))
    assertNull(DestinationRouting.pick("8.8.8.8", routes))
  }

  @Test
  fun addressFamilyMismatchIgnored() {
    val routes =
        listOf(
            route("v4", "172.27.85.0/24", onLink = true),
            route("v6", "fd7a::/64", onLink = true),
        )
    assertEquals("v6", DestinationRouting.pick("fd7a::1", routes)?.networkKey)
    assertEquals("v4", DestinationRouting.pick("172.27.85.1", routes)?.networkKey)
  }

  @Test
  fun hostRoute32Selected() {
    val routes =
        listOf(
            route("subnet", "172.27.85.0/24", onLink = true),
            route("host", "172.27.85.178/32", onLink = false),
        )
    val picked = DestinationRouting.pick("172.27.85.178", routes)
    assertEquals("host", picked?.networkKey)
    assertEquals(32, picked?.prefixLength)
  }

  @Test
  fun hostnameDestinationNeverResolves() {
    val routes = listOf(route("cellular", "0.0.0.0/0", onLink = false))
    assertNull(DestinationRouting.pick("example.com", routes))
    assertNull(DestinationRouting.pick("", routes))
    assertNull(DestinationRouting.pick("not an ip", routes))
  }

  @Test
  fun malformedRouteCidrsSkipped() {
    val routes =
        listOf(
            LocalRoute("bad1", null, "172.27.85.0", false, hasGateway = false),
            LocalRoute("bad2", null, "172.27.85.0/33", false, hasGateway = false),
            LocalRoute("bad3", null, "172.27.85.0/-1", false, hasGateway = false),
            LocalRoute("good", null, "172.27.85.0/24", false, hasGateway = false),
        )
    assertEquals("good", DestinationRouting.pick("172.27.85.178", routes)?.networkKey)
  }

  @Test
  fun zoneIdStrippedFromDestination() {
    val routes = listOf(route("v6link", "fe80::/64", onLink = true))
    assertEquals("v6link", DestinationRouting.pick("fe80::1%wlan0", routes)?.networkKey)
  }

  @Test
  fun isOnLinkReflectsGatewayPresence() {
    val routes =
        listOf(
            route("cellular", "0.0.0.0/0", onLink = false),
            route("tether", "172.27.85.0/24", onLink = true),
        )
    assertTrue(DestinationRouting.isOnLink("172.27.85.178", routes))
    assertFalse(DestinationRouting.isOnLink("8.8.8.8", routes))
    assertFalse(DestinationRouting.isOnLink("example.com", routes))
  }
}
