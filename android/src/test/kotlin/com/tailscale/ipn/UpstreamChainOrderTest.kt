// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import com.tailscale.ipn.multiproxy.db.Upstream
import com.tailscale.ipn.multiproxy.db.UpstreamKind
import com.tailscale.ipn.multiproxy.db.orderByChain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers the ordering used when registering upstreams with a running engine.
 *
 * The database itself needs an Android runtime to exercise, so the ordering was kept as a pure
 * function - it is the part with logic in it, and the part where a cycle could hang or drop an
 * upstream the user configured.
 */
class UpstreamChainOrderTest {

  private fun upstream(id: String, via: String = "") =
      Upstream(id = id, kind = UpstreamKind.SOCKS5, label = id, via = via)

  private fun ids(list: List<Upstream>) = list.map { it.id }

  @Test
  fun unchainedUpstreamsKeepTheirOrder() {
    val input = listOf(upstream("a"), upstream("b"), upstream("c"))
    assertEquals(listOf("a", "b", "c"), ids(orderByChain(input)))
  }

  @Test
  fun parentIsPlacedBeforeItsChild() {
    // Given in the awkward order: the child comes first in the input.
    val input = listOf(upstream("child", via = "parent"), upstream("parent"))
    assertEquals(listOf("parent", "child"), ids(orderByChain(input)))
  }

  @Test
  fun aThreeHopChainIsFullyOrdered() {
    val input =
        listOf(
            upstream("top", via = "middle"),
            upstream("middle", via = "bottom"),
            upstream("bottom"),
        )
    assertEquals(listOf("bottom", "middle", "top"), ids(orderByChain(input)))
  }

  @Test
  fun everyUpstreamAppearsExactlyOnce() {
    // Two children sharing one parent: the parent must not be emitted twice.
    val input =
        listOf(
            upstream("one", via = "shared"),
            upstream("two", via = "shared"),
            upstream("shared"),
        )
    val ordered = ids(orderByChain(input))
    assertEquals(listOf("shared", "one", "two"), ordered)
    assertEquals(ordered.size, ordered.toSet().size)
  }

  /**
   * A cycle has no valid order, and Go refuses to register one. The requirement here is only that
   * this terminates and loses nothing, so the refusal happens where it can be explained.
   */
  @Test
  fun aCycleIsReturnedRatherThanDroppedOrHung() {
    val input = listOf(upstream("a", via = "b"), upstream("b", via = "a"))
    val ordered = ids(orderByChain(input))
    assertEquals(setOf("a", "b"), ordered.toSet())
    assertEquals(2, ordered.size)
  }

  @Test
  fun aSelfCycleIsReturnedRatherThanDroppedOrHung() {
    val ordered = ids(orderByChain(listOf(upstream("a", via = "a"))))
    assertEquals(listOf("a"), ordered)
  }

  /**
   * A parent that is missing - deleted, or disabled and so filtered out before this runs - must not
   * take its children with it. Those fail closed at dial time, which the user can see and fix.
   */
  @Test
  fun anUpstreamWithAMissingParentIsKept() {
    val ordered = ids(orderByChain(listOf(upstream("orphan", via = "gone"))))
    assertEquals(listOf("orphan"), ordered)
  }

  @Test
  fun emptyInputGivesEmptyOutput() {
    assertTrue(orderByChain(emptyList()).isEmpty())
  }
}
