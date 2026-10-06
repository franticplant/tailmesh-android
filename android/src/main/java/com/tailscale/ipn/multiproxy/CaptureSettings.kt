// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy

import android.content.Context

/**
 * How long a saved packet capture file (see PacketCaptureView) is kept before automatic cleanup
 * deletes it.
 *
 * Stored in the same unencrypted preferences file [RoutingSettings] uses, since this is the same
 * kind of setting: a user preference with nothing sensitive in it. Captures accumulate silently in
 * app-private storage (there is no OS-level "downloads" notification for them, unlike an exported
 * copy) - without a retention limit they simply grow forever, most of them from a debugging session
 * the user has long forgotten about. 14 days is long enough to still have a capture around for a
 * bug report a week later, short enough that idle accumulation stays bounded without the user
 * having to think about it.
 */
class CaptureSettings(context: Context) {
  private val prefs =
      context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

  var maxAgeDays: Int
    get() = prefs.getInt(KEY_MAX_AGE_DAYS, DEFAULT_MAX_AGE_DAYS)
    set(value) {
      prefs.edit().putInt(KEY_MAX_AGE_DAYS, value.coerceAtLeast(1)).apply()
    }

  companion object {
    private const val PREFS_NAME = "unencrypted"
    private const val KEY_MAX_AGE_DAYS = "packetCaptureMaxAgeDays"
    const val DEFAULT_MAX_AGE_DAYS = 14
  }
}
