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

  /**
   * Whether the Multi-Tailnet VPN captures ordinary internet and LAN traffic, not just the
   * synthetic and real-Tailscale ranges it always has.
   *
   * Off by default so enabling Multi-Tailnet never silently changes what an existing user's other
   * apps can reach. With this on and [defaultUpstreamId] unset, [UpstreamPolicyApplier] defaults
   * unbound apps to the built-in direct upstream rather than leaving the newly-captured traffic to
   * the legacy subnet-route/exit-node fallback, which was never meant to carry ordinary internet
   * traffic for apps the user has not routed anywhere.
   */
  var broadCaptureEnabled: Boolean
    get() = prefs.getBoolean(KEY_BROAD_CAPTURE, false)
    set(value) {
      prefs.edit().putBoolean(KEY_BROAD_CAPTURE, value).apply()
    }

  /**
   * Whether traffic to well-known local/private destinations (a printer, a NAS, a dev server on
   * the same network) stays direct instead of following an app's or the default route.
   *
   * On by default: LAN reachability breaking because an app got routed through a remote proxy is
   * the more surprising failure mode. This is a single global choice today - there is no per-app
   * override yet to deliberately tunnel LAN traffic for one app (e.g. to reach a remote LAN
   * through a WireGuard upstream); turning this off entirely is the only way to get that today.
   */
  var lanExclusionEnabled: Boolean
    get() = prefs.getBoolean(KEY_LAN_EXCLUSION, true)
    set(value) {
      prefs.edit().putBoolean(KEY_LAN_EXCLUSION, value).apply()
    }

  companion object {
    private const val PREFS_NAME = "unencrypted"
    private const val KEY_DEFAULT_UPSTREAM = "multiproxyDefaultUpstream"
    private const val KEY_BROAD_CAPTURE = "multiproxyBroadCapture"
    private const val KEY_LAN_EXCLUSION = "multiproxyLanExclusion"
  }
}
