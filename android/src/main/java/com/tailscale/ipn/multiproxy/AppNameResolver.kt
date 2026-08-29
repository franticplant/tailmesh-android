// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package com.tailscale.ipn.multiproxy

import android.content.Context
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable

/**
 * Resolves an Android UID to a human-readable app label (and icon) for the diagnostics screen.
 *
 * This is display-only and never touches the datapath: uidStats (observability.go) already
 * accounts traffic by raw UID without any package lookup, exactly as PHASE 6 of the observability
 * spec requires ("do not perform package-manager lookups in packet handling"). This resolver runs
 * only when the Apps tab actually renders a row, well off any hot path, and caches results since a
 * UID's owning package does not change within a process lifetime.
 */
object AppNameResolver {
  private val labelCache = mutableMapOf<Int, String>()
  private val iconCache = mutableMapOf<Int, Drawable?>()

  fun labelFor(context: Context, uid: Int): String {
    labelCache[uid]?.let {
      return it
    }
    val label = resolveLabel(context, uid)
    labelCache[uid] = label
    return label
  }

  fun iconFor(context: Context, uid: Int): Drawable? {
    if (iconCache.containsKey(uid)) return iconCache[uid]
    val icon = resolveIcon(context, uid)
    iconCache[uid] = icon
    return icon
  }

  private fun resolveLabel(context: Context, uid: Int): String {
    if (uid < 0) return "Unattributed"
    if (uid == android.os.Process.myUid()) return "Tailmesh (self)"
    val pm = context.applicationContext.packageManager
    val pkgs =
        try {
          pm.getPackagesForUid(uid)
        } catch (e: Exception) {
          null
        }
    val pkg = pkgs?.firstOrNull() ?: return "UID $uid"
    return try {
      val info = pm.getApplicationInfo(pkg, 0)
      pm.getApplicationLabel(info).toString()
    } catch (e: PackageManager.NameNotFoundException) {
      pkg
    }
  }

  private fun resolveIcon(context: Context, uid: Int): Drawable? {
    if (uid < 0 || uid == android.os.Process.myUid()) return null
    val pm = context.applicationContext.packageManager
    val pkg =
        try {
          pm.getPackagesForUid(uid)?.firstOrNull()
        } catch (e: Exception) {
          null
        } ?: return null
    return try {
      pm.getApplicationIcon(pkg)
    } catch (e: PackageManager.NameNotFoundException) {
      null
    }
  }
}
