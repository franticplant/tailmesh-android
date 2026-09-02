// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.util

import android.Manifest
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.tailscale.ipn.BuildConfig

data class InstalledApp(
    val name: String,
    val packageName: String,
    // A preinstalled app the user never chose to install. FLAG_UPDATED_SYSTEM_APP is excluded
    // deliberately: an app like Chrome or the Play Store ships preinstalled but is then updated
    // through the Play Store like any other app, and a user filtering out "system apps" expects
    // those to stay visible - only the ones nobody ever interacts with (radio config, system UI
    // internals, etc.) should be hidden.
    val isSystemApp: Boolean,
)

class InstalledAppsManager(
    val packageManager: PackageManager,
) {
  fun fetchInstalledApps(): List<InstalledApp> {
    return packageManager
        .getInstalledApplications(PackageManager.GET_META_DATA)
        .filter(appIsIncluded)
        .map {
          InstalledApp(
              name = it.loadLabel(packageManager).toString(),
              packageName = it.packageName,
              isSystemApp =
                  (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                      (it.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0,
          )
        }
        .sortedBy { it.name }
  }

  private val appIsIncluded: (ApplicationInfo) -> Boolean = { app ->
    app.packageName != BuildConfig.APPLICATION_ID &&
        // Only show apps that can access the Internet
        packageManager.checkPermission(Manifest.permission.INTERNET, app.packageName) ==
            PackageManager.PERMISSION_GRANTED
  }
}
