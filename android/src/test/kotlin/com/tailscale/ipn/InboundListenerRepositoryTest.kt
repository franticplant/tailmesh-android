// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.tailscale.ipn.multiproxy.db.InboundListenerRepository
import com.tailscale.ipn.multiproxy.db.TailnetDatabaseHelper
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Robolectric host tests for the inbound-listener persistence layer - the first tests in this tree
 * to exercise a real SQLite-backed repository without a device. Also a regression guard for the
 * v7->v8 `inbound_listeners` migration actually creating a usable table.
 */
@RunWith(RobolectricTestRunner::class)
class InboundListenerRepositoryTest {

  private lateinit var repo: InboundListenerRepository

  @Before
  fun setUp() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    context.deleteDatabase(TailnetDatabaseHelper.DATABASE_NAME)
    repo = InboundListenerRepository(context)
  }

  @Test
  fun saveAndReadBack() = runBlocking {
    repo.saveConfig("l1", "tailnetA", 22, "127.0.0.1:22", proxyProtocol = false)
    val all = repo.getAllImmediate()
    assertEquals(1, all.size)
    val r = all.first()
    assertEquals("l1", r.id)
    assertEquals("tailnetA", r.upstream)
    assertEquals(22, r.listenPort)
    assertEquals("127.0.0.1:22", r.localTarget)
    assertFalse(r.proxyProtocol)
    assertTrue(r.enabled)
    // The StateFlow the UI observes is refreshed after every write.
    assertEquals(1, repo.listeners.value.size)
  }

  @Test
  fun savePreservesEnabledAndCreatedAtAcrossEdit() = runBlocking {
    repo.saveConfig("l1", "tailnetA", 22, "127.0.0.1:22", proxyProtocol = false)
    val createdAt = repo.getImmediate("l1")!!.createdAt
    repo.setEnabled("l1", false)
    repo.saveConfig("l1", "tailnetB", 8080, "127.0.0.1:8080", proxyProtocol = true)
    val r = repo.getImmediate("l1")!!
    assertFalse("edit must not revert the user's enabled choice", r.enabled)
    assertEquals("edit must preserve createdAt", createdAt, r.createdAt)
    assertEquals("tailnetB", r.upstream)
    assertEquals(8080, r.listenPort)
    assertTrue(r.proxyProtocol)
  }

  @Test
  fun setEnabledToggles() = runBlocking {
    repo.saveConfig("l1", "tailnetA", 22, "127.0.0.1:22", proxyProtocol = false)
    repo.setEnabled("l1", false)
    assertFalse(repo.getImmediate("l1")!!.enabled)
    repo.setEnabled("l1", true)
    assertTrue(repo.getImmediate("l1")!!.enabled)
  }

  @Test
  fun deleteRemoves() = runBlocking {
    repo.saveConfig("l1", "tailnetA", 22, "127.0.0.1:22", proxyProtocol = false)
    repo.saveConfig("l2", "tailnetB", 80, "127.0.0.1:80", proxyProtocol = false)
    repo.delete("l1")
    assertNull(repo.getImmediate("l1"))
    assertEquals(listOf("l2"), repo.getAllImmediate().map { it.id })
  }

  @Test
  fun multipleListenersRoundTrip() = runBlocking {
    repo.saveConfig("a", "tailnetA", 22, "127.0.0.1:22", proxyProtocol = true)
    repo.saveConfig("b", "tailnetB", 22, "127.0.0.1:22", proxyProtocol = false)
    val byId = repo.getAllImmediate().associateBy { it.id }
    assertEquals("tailnetA", byId["a"]!!.upstream)
    assertTrue(byId["a"]!!.proxyProtocol)
    assertEquals("tailnetB", byId["b"]!!.upstream)
    assertFalse(byId["b"]!!.proxyProtocol)
  }
}
