// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.remote

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.tailscale.ipn.App
import com.tailscale.ipn.BuildConfig
import com.tailscale.ipn.IPNService
import com.tailscale.ipn.R
import com.tailscale.ipn.multiproxy.ControlException
import com.tailscale.ipn.util.TSLog
import java.io.File
import java.security.MessageDigest
import org.json.JSONObject

/**
 * Installs a newer build of this app over itself, for remote control's `app.update`.
 *
 * An update keeps the app's data only if it is the same package, signed with the same key, and not
 * a lower versionCode (a downgrade needs an uninstall, which wipes it). Android enforces the first
 * two at install time; all three are checked here first, so a bad upload is refused with a reason
 * instead of failing half-way or offering a destructive way out.
 *
 * Development builds only ([BuildConfig.DEV_TOOLS]; releases have neither this path nor the install
 * permissions). Off unless the user turns on "Allow remote updates", and Android additionally
 * requires "Install unknown apps" for this app. Where Android allows it (Android 12+, updating
 * itself) the install needs no tap; otherwise a notification asks for one.
 */
object AppUpdater {
  private const val TAG = "AppUpdater"
  private const val CHANNEL_ID = "app-update"
  private const val NOTIFICATION_ID = 0x7a11

  fun updateDir(): File = File(App.get().filesDir, "remote-control/update")

  /** Checks the APK at [path] and starts installing it. Returns what was started. */
  fun install(path: String): JSONObject {
    if (!BuildConfig.DEV_TOOLS)
        throw ControlException("remote updates exist only in development builds")
    val app = App.get()
    if (!RemoteControlSettings().allowRemoteUpdates) {
      throw ControlException(
          "remote updates are off; turn on \"Allow remote updates\" on the phone")
    }
    val apk = File(path).canonicalFile
    if (apk.parentFile != updateDir().canonicalFile || !apk.isFile) {
      throw ControlException("no uploaded APK at $path; upload one with POST /v1/app/update")
    }
    if (!app.packageManager.canRequestPackageInstalls()) {
      throw ControlException(
          "Android does not allow this app to install updates yet; on the phone, allow " +
              "\"Install unknown apps\" for Tailmesh")
    }

    val pm = app.packageManager
    val flags =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) PackageManager.GET_SIGNING_CERTIFICATES
        else @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
    val incoming =
        pm.getPackageArchiveInfo(apk.path, flags) ?: throw ControlException("not a valid APK")
    val installed = pm.getPackageInfo(app.packageName, flags)

    if (incoming.packageName != app.packageName) {
      throw ControlException(
          "APK is ${incoming.packageName}, not ${app.packageName}; it would install as another app")
    }
    if (signers(incoming) != signers(installed)) {
      throw ControlException(
          "APK is signed with a different key; Android would refuse it, and the only way past " +
              "that is an uninstall, which wipes the app's data")
    }
    val from = versionCode(installed)
    val to = versionCode(incoming)
    if (to < from) {
      throw ControlException(
          "APK is older (versionCode $to < $from); Android refuses downgrades, and the only way " +
              "past that is an uninstall, which wipes the app's data")
    }

    val installer = pm.packageInstaller
    val params =
        PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
          setAppPackageName(app.packageName)
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
          }
        }
    val sessionId = installer.createSession(params)
    installer.openSession(sessionId).use { session ->
      session.openWrite("base.apk", 0, apk.length()).use { out ->
        apk.inputStream().use { it.copyTo(out) }
        session.fsync(out)
      }
      val status =
          PendingIntent.getBroadcast(
              app,
              sessionId,
              Intent(app, AppUpdateReceiver::class.java),
              PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
          )
      session.commit(status.intentSender)
    }
    TSLog.d(TAG, "installing update: versionCode $from -> $to, ${incoming.versionName}")
    return JSONObject()
        .put("installing", true)
        .put("fromVersionCode", from)
        .put("toVersionCode", to)
        .put("toVersionName", incoming.versionName)
        .put("note", "the app restarts when the install finishes, so this session ends")
  }

  private fun versionCode(p: PackageInfo): Long =
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) p.longVersionCode
      else @Suppress("DEPRECATION") p.versionCode.toLong()

  /** SHA-256 digests of the signing certificates, comparable across the two packages. */
  private fun signers(p: PackageInfo): Set<String> {
    val sigs =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          val info = p.signingInfo ?: return emptySet()
          if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory
        } else {
          @Suppress("DEPRECATION") p.signatures
        } ?: return emptySet()
    return sigs
        .map { sig ->
          MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()).joinToString("") {
            "%02x".format(it)
          }
        }
        .toSet()
  }

  /** Install progress from PackageInstaller. */
  class AppUpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
      val status =
          intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
      val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: ""
      when (status) {
        PackageInstaller.STATUS_PENDING_USER_ACTION -> {
          // Android wants a tap. Starting the confirmation from the background is not allowed, so
          // hand it to the user as a notification.
          @Suppress("DEPRECATION")
          val confirm = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT) ?: return
          TSLog.d(TAG, "update needs confirmation on the phone")
          notify(
              context,
              context.getString(R.string.app_update_confirm_title),
              context.getString(R.string.app_update_confirm_text),
              PendingIntent.getActivity(
                  context,
                  0,
                  confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                  PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
              ),
          )
        }
        PackageInstaller.STATUS_SUCCESS -> TSLog.d(TAG, "update installed")
        else -> {
          TSLog.e(TAG, "update failed: status $status $message")
          notify(
              context,
              context.getString(R.string.app_update_failed_title),
              message.ifEmpty { "status $status" },
              null,
          )
        }
      }
    }

    private fun notify(context: Context, title: String, text: String, tap: PendingIntent?) {
      val nm = NotificationManagerCompat.from(context)
      if (!nm.areNotificationsEnabled()) return
      App.get()
          .createNotificationChannel(
              CHANNEL_ID,
              context.getString(R.string.app_update_channel),
              context.getString(R.string.app_update_channel_description),
              NotificationManagerCompat.IMPORTANCE_HIGH,
          )
      val n =
          NotificationCompat.Builder(context, CHANNEL_ID)
              .setSmallIcon(R.drawable.ic_notification)
              .setContentTitle(title)
              .setContentText(text)
              .setAutoCancel(true)
              .apply { tap?.let { setContentIntent(it) } }
              .build()
      try {
        nm.notify(NOTIFICATION_ID, n)
      } catch (e: SecurityException) {
        TSLog.w(TAG, "no notification permission: $e")
      }
    }
  }

  /**
   * Runs after this app is updated, by any means. Android killed the old process, so bring back
   * what was running: App.onCreate has already restored remote control (if it was on and has not
   * lapsed); this restarts the VPN or Multi-Tailnet session the user had on.
   */
  class PackageReplacedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
      if (intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
      // App.onCreate tried already, but from the background, where Android may refuse it; this
      // broadcast is allowed to start foreground services.
      com.tailscale.ipn.SpeedMeter.startIfEnabled(context)
      val prefs = context.getSharedPreferences("vpn_mode", Context.MODE_PRIVATE)
      if (!prefs.getBoolean("wantRunning", false)) return
      val multiTailnet = prefs.getString("selectedMode", "STANDARD") == "MULTIPROXY"
      TSLog.d(
          TAG, "updated; restarting the ${if (multiTailnet) "Multi-Tailnet" else "VPN"} session")
      if (!multiTailnet && App.get().isProxyOnlyMode()) {
        App.get().startUserspaceOnly()
      } else {
        // A null action is IPNService's "restore what wantRunning says" path.
        context.startForegroundService(Intent(context, IPNService::class.java))
      }
    }
  }
}
