// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import com.tailscale.ipn.remote.AppUpdater
import com.tailscale.ipn.remote.RemoteControl
import com.tailscale.ipn.remote.RemoteMethods
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * A build without -PdevTools (every release) must not hand the remote-control server the shell or
 * the update directory, nor offer app.update. The Go server enables both only from its config
 * (remotectl Config.Shell, Config.UpdateDir), so this is what keeps them off in a release, where
 * the Go code itself is present. scripts/check-release-apk.sh checks the built APK.
 */
@RunWith(RobolectricTestRunner::class)
class DevToolsGateTest {
  @Before
  fun releaseConfigOnly() {
    // A local -PdevTools test run has nothing to check here.
    assumeFalse(BuildConfig.DEV_TOOLS)
  }

  @Test
  fun serverConfigHasNoShellOrUpdateDir() {
    val config = JSONObject().put("addr", "127.0.0.1:7373")
    RemoteControl.putDevTools(config)
    assertEquals(listOf("addr"), config.keys().asSequence().toList())
  }

  @Test
  fun noAppUpdateMethod() {
    val arr = RemoteMethods.catalogJson()
    val names = (0 until arr.length()).map { arr.getJSONObject(it).getString("name") }
    assertTrue(names.isNotEmpty())
    assertFalse("app.update offered without DEV_TOOLS", "app.update" in names)
  }

  @Test
  fun installRefuses() {
    val e = runCatching { AppUpdater.install("/nonexistent.apk") }.exceptionOrNull()
    assertTrue("install did not refuse: $e", e?.message?.contains("development builds") == true)
  }
}
