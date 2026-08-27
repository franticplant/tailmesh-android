// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy

import android.content.Context

/**
 * The routing choices that are not per-app.
 *
 * Stored in the same unencrypted preferences file the split-tunnel package selection uses, since
 * this is the same kind of setting: a user preference about routing, with nothing sensitive in it.
 */
class RoutingSettings(context: Context) {
  private val prefs =
      context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

  /**
   * The upstream that carries traffic from apps with no binding of their own, or empty for none.
   *
   * This is exit-node selection for ordinary, non-Tailnet traffic. Empty is the default and means
   * unbound apps keep today's behaviour exactly: subnet routes, then the exit-node Tailnet, then
   * fail. Set to the direct upstream's id to have unbound apps bypass the VPN entirely.
   */
  var defaultUpstreamId: String
    get() = prefs.getString(KEY_DEFAULT_UPSTREAM, "") ?: ""
    set(value) {
      prefs.edit().putString(KEY_DEFAULT_UPSTREAM, value).apply()
    }

  companion object {
    private const val PREFS_NAME = "unencrypted"
    private const val KEY_DEFAULT_UPSTREAM = "multiproxyDefaultUpstream"
  }
}
