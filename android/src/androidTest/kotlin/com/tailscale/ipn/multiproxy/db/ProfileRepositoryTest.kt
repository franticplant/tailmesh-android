// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy.db

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Exercises [ProfileRepository] against a real on-device database - the one store in this package
 * with no prior automated coverage at all (`validation_and_gaps.md` §5.1/§5.2's original gap,
 * unaddressed by §66's pass over the other two stores).
 */
@RunWith(AndroidJUnit4::class)
class ProfileRepositoryTest {
  private val context = InstrumentationRegistry.getInstrumentation().targetContext
  private lateinit var repo: ProfileRepository

  @Before
  fun setUp() {
    context.deleteDatabase(TailnetDatabaseHelper.DATABASE_NAME)
    repo = ProfileRepository(context)
  }

  @After
  fun tearDown() {
    context.deleteDatabase(TailnetDatabaseHelper.DATABASE_NAME)
  }

  @Test
  fun createProfile_isUnprovisionedAndDisabledByDefault() = runBlocking {
    val profile = repo.createProfile("My Tailnet")

    assertEquals("My Tailnet", profile.displayName)
    assertEquals(false, profile.enabled)
    assertEquals(ProvisioningState.UNPROVISIONED, profile.provisioningState)
    assertEquals(profile, repo.getProfileImmediate(profile.id))
  }

  @Test
  fun importRegularProfile_isIdempotentOnSourceProfileId() = runBlocking {
    val first = repo.importRegularProfile("std-1", "Standard Tailnet")
    val second = repo.importRegularProfile("std-1", "Standard Tailnet (renamed)")

    // The second call must return the existing profile rather than creating a duplicate -
    // TABLE_PROFILES has a UNIQUE constraint on source_profile_id, so a naive re-insert would
    // throw; importRegularProfile checks first instead.
    assertEquals(first.id, second.id)
    assertEquals(1, repo.getProfilesImmediate().size)
    assertEquals(ProvisioningState.READY, first.provisioningState)
  }

  @Test
  fun updateProfile_persistsChangesAndBumpsUpdatedAt() = runBlocking {
    val profile = repo.createProfile("My Tailnet")
    val originalUpdatedAt = profile.updatedAt

    repo.updateProfile(profile.copy(enabled = true, provisioningState = ProvisioningState.READY))

    val updated = repo.getProfileImmediate(profile.id)
    assertEquals(true, updated?.enabled)
    assertEquals(ProvisioningState.READY, updated?.provisioningState)
    assertTrue((updated?.updatedAt ?: 0) >= originalUpdatedAt)
  }

  @Test
  fun deleteProfile_removesIt() = runBlocking {
    val profile = repo.createProfile("My Tailnet")

    repo.deleteProfile(profile.id)

    assertNull(repo.getProfileImmediate(profile.id))
    assertTrue(repo.getProfilesImmediate().none { it.id == profile.id })
  }

  @Test
  fun refresh_reflectsWhatWasPersisted_acrossANewRepositoryInstance() = runBlocking {
    val profile = repo.createProfile("My Tailnet")

    val reopened = ProfileRepository(context)
    assertEquals(profile, reopened.getProfileImmediate(profile.id))
  }
}
