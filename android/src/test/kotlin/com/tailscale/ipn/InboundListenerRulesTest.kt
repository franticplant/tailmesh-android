// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import com.tailscale.ipn.multiproxy.InboundListenerRules
import com.tailscale.ipn.multiproxy.db.InboundListenerRecord
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Tier-3 host tests for the tailnet-facing inbound listener UI logic. Plain JUnit, no Android or
 * engine - the same harness the other host tests in this tree use.
 */
class InboundListenerRulesTest {

  @Test
  fun parsesValidListenPort() {
    assertEquals(22, InboundListenerRules.parseListenPort("22"))
    assertEquals(65535, InboundListenerRules.parseListenPort(" 65535 "))
  }

  @Test
  fun rejectsInvalidListenPort() {
    assertNull(InboundListenerRules.parseListenPort("0"))
    assertNull(InboundListenerRules.parseListenPort("65536"))
    assertNull(InboundListenerRules.parseListenPort(""))
    assertNull(InboundListenerRules.parseListenPort("abc"))
  }

  @Test
  fun parsesAndNormalisesLocalTarget() {
    assertEquals("127.0.0.1:22", InboundListenerRules.parseLocalTarget("127.0.0.1:22"))
    assertEquals("127.0.0.1:22", InboundListenerRules.parseLocalTarget("  127.0.0.1:22  "))
    assertEquals("localhost:8080", InboundListenerRules.parseLocalTarget("localhost:8080"))
    assertEquals("::1:22", InboundListenerRules.parseLocalTarget("[::1]:22"))
  }

  @Test
  fun rejectsInvalidLocalTarget() {
    assertNull(InboundListenerRules.parseLocalTarget("127.0.0.1"))
    assertNull(InboundListenerRules.parseLocalTarget(":22"))
    assertNull(InboundListenerRules.parseLocalTarget("127.0.0.1:0"))
    assertNull(InboundListenerRules.parseLocalTarget("127.0.0.1:70000"))
    assertNull(InboundListenerRules.parseLocalTarget("127.0.0.1:notaport"))
    assertNull(InboundListenerRules.parseLocalTarget(""))
  }

  private fun record(id: String, upstream: String, enabled: Boolean = true) =
      InboundListenerRecord(
          id = id,
          upstream = upstream,
          listenPort = 22,
          localTarget = "127.0.0.1:22",
          enabled = enabled,
      )

  /** Disabling a listener's tailnet must pause that listener; others stay. */
  @Test
  fun desiredKeepsOnlyEnabledListenersOnAvailableTailnets() {
    val configured =
        listOf(
            record("a", "tailnetA"),
            record("b", "tailnetB"),
            record("c", "tailnetA", enabled = false),
        )
    val desired = InboundListenerRules.desired(configured, setOf("tailnetA"))
    assertEquals(listOf("a"), desired.map { it.id })
  }

  @Test
  fun desiredEmptyWhenTailnetUnavailable() {
    val configured = listOf(record("a", "tailnetA"))
    assertEquals(
        emptyList<InboundListenerRecord>(), InboundListenerRules.desired(configured, emptySet()))
  }
}
