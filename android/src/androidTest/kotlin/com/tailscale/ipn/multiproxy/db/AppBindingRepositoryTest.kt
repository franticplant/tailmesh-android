// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy.db

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Exercises [AppBindingRepository] against a real on-device database. In particular, proves the
 * "preserve the other column" behaviour its `upsert` helper depends on:
 * [AppBindingRepository.bind], [AppBindingRepository.setDNSUpstream], and
 * [AppBindingRepository.setTunnelLAN] each write only one column but must never clobber the others,
 * which is exactly what a plain column-keyed `INSERT OR REPLACE` would do.
 */
@RunWith(AndroidJUnit4::class)
class AppBindingRepositoryTest {
  private val context = InstrumentationRegistry.getInstrumentation().targetContext
  private lateinit var repo: AppBindingRepository

  @Before
  fun setUp() {
    context.deleteDatabase(TailnetDatabaseHelper.DATABASE_NAME)
    repo = AppBindingRepository(context)
  }

  @After
  fun tearDown() {
    context.deleteDatabase(TailnetDatabaseHelper.DATABASE_NAME)
  }

  @Test
  fun bind_thenSetDNSUpstream_preservesTheDataRoute() = runBlocking {
    repo.bind("com.example.app", "upstream-a")
    repo.setDNSUpstream("com.example.app", "upstream-b")

    val binding = repo.getAllImmediate()["com.example.app"]
    assertEquals("upstream-a", binding?.upstreamId)
    assertEquals("upstream-b", binding?.dnsUpstreamId)
  }

  @Test
  fun setDNSUpstream_thenBindToADifferentRoute_preservesTheDNSOverride() = runBlocking {
    repo.bind("com.example.app", "upstream-a")
    repo.setDNSUpstream("com.example.app", "upstream-b")
    repo.bind("com.example.app", "upstream-c")

    val binding = repo.getAllImmediate()["com.example.app"]
    assertEquals("upstream-c", binding?.upstreamId)
    assertEquals("upstream-b", binding?.dnsUpstreamId)
  }

  @Test
  fun unbind_removesTheRowEntirely() = runBlocking {
    repo.bind("com.example.app", "upstream-a")
    repo.setDNSUpstream("com.example.app", "upstream-b")

    repo.unbind("com.example.app")

    assertNull(repo.getAllImmediate()["com.example.app"])
  }

  @Test
  fun setDNSUpstream_onAnUnboundApp_createsARowWithNoDataRoute() = runBlocking {
    // The row is stored even with an empty upstreamId - the UI is what enforces "only show the
    // DNS picker once there's a data route" (BuildAppBindingPolicyJSON skips the whole rule when
    // upstream is empty); the repository itself has no opinion on that.
    repo.setDNSUpstream("com.example.app", "upstream-b")

    val binding = repo.getAllImmediate()["com.example.app"]
    assertEquals("", binding?.upstreamId)
    assertEquals("upstream-b", binding?.dnsUpstreamId)
  }

  @Test
  fun concurrentBindAndSetDNSUpstream_forTheSameApp_bothTakeEffect() = runBlocking {
    // Regression test for the race fixed by reading "existing" via a fresh DB query inside
    // upsert()'s transaction instead of the in-memory StateFlow snapshot: launching both calls
    // together and letting them race should never lose either write.
    val bindJob = launch { repo.bind("com.example.app", "upstream-a") }
    val dnsJob = launch { repo.setDNSUpstream("com.example.app", "upstream-b") }
    bindJob.join()
    dnsJob.join()

    val binding = repo.getAllImmediate()["com.example.app"]
    assertEquals("upstream-a", binding?.upstreamId)
    assertEquals("upstream-b", binding?.dnsUpstreamId)
  }

  @Test
  fun refresh_reflectsWhatWasPersisted_acrossANewRepositoryInstance() = runBlocking {
    repo.bind("com.example.app", "upstream-a")
    repo.setDNSUpstream("com.example.app", "upstream-b")

    val reopened = AppBindingRepository(context)
    val binding = reopened.getAllImmediate()["com.example.app"]
    assertTrue(binding != null)
    assertEquals("upstream-a", binding?.upstreamId)
    assertEquals("upstream-b", binding?.dnsUpstreamId)
  }

  @Test
  fun setTunnelLAN_preservesTheDataRouteAndDNSOverride() = runBlocking {
    repo.bind("com.example.app", "upstream-a")
    repo.setDNSUpstream("com.example.app", "upstream-b")

    repo.setTunnelLAN("com.example.app", true)

    val binding = repo.getAllImmediate()["com.example.app"]
    assertEquals("upstream-a", binding?.upstreamId)
    assertEquals("upstream-b", binding?.dnsUpstreamId)
    assertEquals(true, binding?.tunnelLan)
  }

  @Test
  fun bind_afterSetTunnelLAN_preservesTheTunnelLANOverride() = runBlocking {
    repo.bind("com.example.app", "upstream-a")
    repo.setTunnelLAN("com.example.app", true)

    repo.bind("com.example.app", "upstream-c")

    val binding = repo.getAllImmediate()["com.example.app"]
    assertEquals("upstream-c", binding?.upstreamId)
    assertEquals(true, binding?.tunnelLan)
  }

  @Test
  fun newBinding_defaultsTunnelLANToFalse() = runBlocking {
    repo.bind("com.example.app", "upstream-a")

    assertEquals(false, repo.getAllImmediate()["com.example.app"]?.tunnelLan)
  }
}
