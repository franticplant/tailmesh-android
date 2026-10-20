// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import com.tailscale.ipn.remote.RemoteMethods
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Guards the shape of the remote-control method catalog. The server trusts the `mutating` flag to
 * decide what a read-only session may call, so a write method mislabelled as a read would be a
 * privilege escalation - these tests pin the classification of every method that changes state.
 */
@RunWith(RobolectricTestRunner::class)
class RemoteMethodsTest {
  private data class M(val name: String, val mutating: Boolean, val description: String)

  private val catalog: List<M> by lazy {
    val arr = RemoteMethods.catalogJson()
    (0 until arr.length()).map {
      val o = arr.getJSONObject(it)
      M(o.getString("name"), o.getBoolean("mutating"), o.getString("description"))
    }
  }

  @Test
  fun namesAreUniqueAndDescribed() {
    assertEquals(catalog.size, catalog.map { it.name }.toSet().size)
    catalog.forEach { assertTrue("${it.name} has no description", it.description.isNotBlank()) }
  }

  /** Remote control must never be able to reconfigure, extend or silence itself. */
  @Test
  fun nothingTouchesRemoteControlItself() {
    catalog.forEach {
      val n = it.name.lowercase()
      assertFalse("${it.name} exposes remote control", n.startsWith("remote"))
      assertFalse("${it.name} exposes sessions", n.contains("session"))
      assertFalse("${it.name} exposes the access log", n.contains("access"))
      assertFalse("${it.name} exposes approvals", n.contains("approv"))
    }
  }

  /** Every verb that changes state must be marked mutating. */
  @Test
  fun stateChangingVerbsAreMutating() {
    val writeVerbs =
        listOf(
            "start",
            "stop",
            "restart",
            "connect",
            "disconnect",
            "add",
            "import",
            "set",
            "rename",
            "forget",
            "save",
            "delete",
            "bind",
            "unbind",
            "reset",
            "export",
            "call",
        )
    catalog.forEach { m ->
      // The leading camelCase word: "setEnabled" -> "set", "addressConflicts" -> "address".
      val verb = m.name.substringAfterLast('.').takeWhile { it.isLowerCase() }
      if (verb in writeVerbs) {
        assertTrue("${m.name} changes state but is not marked mutating", m.mutating)
      }
    }
  }

  /** And the read side really is read-only: lists, gets and snapshots. */
  @Test
  fun readMethodsAreReads() {
    val reads = catalog.filterNot { it.mutating }.map { it.name.substringAfterLast('.') }
    val allowed =
        listOf(
            "status",
            "list",
            "peers",
            "states",
            "addressConflicts",
            "exitNodeCandidates",
            "routable",
            "stats",
            "exitNodeStates",
            "get",
            "snapshot",
            "events",
            "dnsLog",
            "routeDecisions",
            "exports",
        )
    reads.forEach { assertTrue("unexpected read method verb $it", it in allowed) }
  }
}
