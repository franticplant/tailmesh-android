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
 * Exercises [UpstreamRepository] against a real on-device database, in particular
 * [UpstreamRepository.saveConfig] - the fix for the same stale-snapshot race
 * [AppBindingRepositoryTest] covers for [AppBindingRepository.bind]/`setDNSUpstream`, applied here
 * to `setEnabled` racing an edit.
 */
@RunWith(AndroidJUnit4::class)
class UpstreamRepositoryTest {
  private val context = InstrumentationRegistry.getInstrumentation().targetContext
  private lateinit var repo: UpstreamRepository

  @Before
  fun setUp() {
    context.deleteDatabase(TailnetDatabaseHelper.DATABASE_NAME)
    repo = UpstreamRepository(context)
  }

  @After
  fun tearDown() {
    context.deleteDatabase(TailnetDatabaseHelper.DATABASE_NAME)
  }

  @Test
  fun saveConfig_createsANewEnabledUpstream() = runBlocking {
    repo.saveConfig("u1", UpstreamKind.SOCKS5, "test", "")

    val upstream = repo.getImmediate("u1")
    assertEquals(UpstreamKind.SOCKS5, upstream?.kind)
    assertEquals("test", upstream?.label)
    assertEquals(true, upstream?.enabled)
  }

  @Test
  fun saveConfig_editingAnExistingUpstream_preservesEnabledAndCreatedAt() = runBlocking {
    repo.saveConfig("u1", UpstreamKind.SOCKS5, "test", "")
    repo.setEnabled("u1", false)
    val createdAt = repo.getImmediate("u1")?.createdAt

    // Edit the label - a real user editing the upstream's config, same shape as
    // UpstreamRoutingViewModel.save().
    repo.saveConfig("u1", UpstreamKind.SOCKS5, "renamed", "")

    val upstream = repo.getImmediate("u1")
    assertEquals("renamed", upstream?.label)
    assertEquals(false, upstream?.enabled) // must NOT have been reverted to the true default
    assertEquals(createdAt, upstream?.createdAt) // must NOT have been reset to now
  }

  @Test
  fun concurrentSetEnabledAndSaveConfig_forTheSameUpstream_bothTakeEffect() = runBlocking {
    // Regression test for the race UpstreamRepository.saveConfig fixes: previously, the caller
    // (UpstreamRoutingViewModel.save()) read "existing" from an in-memory snapshot before
    // writing, so a concurrent setEnabled() call for the same id could have its change silently
    // reverted by a racing edit. saveConfig reads fresh from the DB inside its own transaction
    // instead.
    repo.saveConfig("u1", UpstreamKind.SOCKS5, "test", "")

    val disableJob = launch { repo.setEnabled("u1", false) }
    val editJob = launch { repo.saveConfig("u1", UpstreamKind.SOCKS5, "renamed", "") }
    disableJob.join()
    editJob.join()

    val upstream = repo.getImmediate("u1")
    assertEquals("renamed", upstream?.label)
    assertEquals(false, upstream?.enabled)
  }

  @Test
  fun delete_removesTheUpstream_clearsViaReferences_andClearsAppBindings() = runBlocking {
    repo.saveConfig("parent", UpstreamKind.SOCKS5, "parent", "")
    repo.saveConfig("child", UpstreamKind.SOCKS5, "child", "parent")
    val bindings = AppBindingRepository(context)
    bindings.bind("com.example.app", "parent")

    repo.delete("parent")

    assertNull(repo.getImmediate("parent"))
    assertEquals("", repo.getImmediate("child")?.via)
    // UpstreamRepository.delete() writes to app_bindings directly via SQL, not through
    // AppBindingRepository, so the existing `bindings` instance's in-memory snapshot won't see
    // it - the same way a real, separately-constructed screen would need to (re-)query. A fresh
    // instance is what actually proves the row is gone from the database.
    assertNull(AppBindingRepository(context).getAllImmediate()["com.example.app"])
  }

  @Test
  fun save_forAFreshlyGeneratedId_neverCollidesWithAnExistingRow() = runBlocking {
    // save(Upstream) (used by saveExitNode) always constructs a whole new row; this is a basic
    // sanity check that it doesn't corrupt an unrelated existing row of a different id.
    repo.saveConfig("u1", UpstreamKind.SOCKS5, "existing", "")
    repo.save(
        Upstream(
            id = "u2",
            kind = UpstreamKind.EXITNODE,
            label = "exit",
            sourceTailnetId = "tailnet-1",
            peerAddr = "100.64.0.1",
        ))

    assertEquals("existing", repo.getImmediate("u1")?.label)
    val exitNode = repo.getImmediate("u2")
    assertEquals(UpstreamKind.EXITNODE, exitNode?.kind)
    assertEquals("tailnet-1", exitNode?.sourceTailnetId)
    assertTrue(exitNode?.enabled == true)
  }
}
