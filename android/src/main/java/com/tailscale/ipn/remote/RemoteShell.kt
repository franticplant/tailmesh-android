// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.remote

import android.app.PendingIntent
import android.content.Intent
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.tailscale.ipn.App
import com.tailscale.ipn.BuildConfig
import com.tailscale.ipn.MainActivity
import com.tailscale.ipn.R
import com.tailscale.ipn.util.TSLog
import java.io.File
import java.text.DateFormat
import java.time.Instant
import java.util.Date
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import libtailscale.Libtailscale
import org.json.JSONArray
import org.json.JSONObject

/**
 * The phone's side of the remote shell (libtailscale/remotectl/shell.go), development builds only.
 *
 * Puts every shell in front of the user: a notification to allow or deny each request (allowing
 * needs the phone unlocked), an ongoing notification with End while one is open, and the shell log
 * with its verification on the Remote control screen. Every log entry is also written to logcat,
 * which the shell, running as this app, cannot rewrite - a second copy to check the file against.
 */
object RemoteShell {
  private const val TAG = "RemoteShell"
  const val CHANNEL_ID = "remote-shell"
  private const val ONGOING_ID = 7380
  private const val REQUEST_BASE = 7500

  data class Request(
      val id: String,
      val session: String,
      val client: String,
      val remote: String,
      val code: String,
      val minutes: Int
  )

  data class Grant(val session: String, val client: String, val remote: String, val until: String)

  data class Entry(
      val seq: Long,
      val time: String,
      val kind: String,
      val client: String,
      val cmd: String,
      val exit: Int?,
      val note: String,
      val hash: String
  )

  data class Verification(
      val ok: Boolean,
      val entries: Long,
      val head: String,
      val problem: String
  )

  private val _requests = MutableStateFlow<List<Request>>(emptyList())
  val requests: StateFlow<List<Request>> = _requests.asStateFlow()

  private val _grants = MutableStateFlow<List<Grant>>(emptyList())
  val grants: StateFlow<List<Grant>> = _grants.asStateFlow()

  fun logFile(): File = File(App.get().filesDir, "remote-control/shell.log")

  fun homeDir(): File = File(App.get().filesDir, "remote-control/shell-home").apply { mkdirs() }

  /** Whether the server is to offer the shell: a development build with the switch on. */
  fun enabled(): Boolean = BuildConfig.DEV_TOOLS && RemoteControlSettings().allowRemoteShell

  /** The shell part of the server config. */
  fun configure(config: JSONObject) {
    if (!enabled()) return
    config
        .put("shell", true)
        .put("shellLogPath", logFile().absolutePath)
        .put("shellDir", homeDir().absolutePath)
        .put("shellMaxMinutes", 30)
  }

  fun onRequest(json: String) {
    val o = JSONObject(json)
    val r =
        Request(
            id = o.getString("id"),
            session = o.optString("session"),
            client = o.optString("client"),
            remote = o.optString("remote"),
            code = o.optString("code"),
            minutes = o.optInt("minutes"),
        )
    _requests.value = _requests.value + r
    showRequest(r)
  }

  fun onEntry(json: String) {
    val e = parseEntries("[$json]").firstOrNull() ?: return
    // Logcat is the copy the shell cannot edit. Log.i directly, not TSLog, so it is never filtered
    // out with debug logging.
    Log.i(
        TAG,
        "#${e.seq} ${e.kind} client=${e.client}" +
            (if (e.cmd.isNotEmpty()) " cmd=${JSONObject.quote(e.cmd)}" else "") +
            (e.exit?.let { " exit=$it" } ?: "") +
            (if (e.note.isNotEmpty()) " note=${JSONObject.quote(e.note)}" else "") +
            " hash=${e.hash}")
  }

  fun onChanged() {
    refreshGrants()
    updateOngoing()
  }

  fun approve(id: String) {
    try {
      Libtailscale.remoteControlApproveShell(id)
    } catch (e: Exception) {
      TSLog.w(TAG, "approve shell $id: ${e.message}")
    }
    clearRequest(id)
  }

  fun deny(id: String) {
    try {
      Libtailscale.remoteControlDenyShell(id)
    } catch (e: Exception) {
      TSLog.w(TAG, "deny shell $id: ${e.message}")
    }
    clearRequest(id)
  }

  fun end(session: String) {
    Libtailscale.remoteControlEndShell(session)
    onChanged()
  }

  fun endAll() {
    Libtailscale.remoteControlEndAllShells()
    onChanged()
  }

  /** The server stopped: nothing is open or waiting any more. */
  fun onStopped() {
    _requests.value.forEach { cancel(requestNotificationId(it.id)) }
    _requests.value = emptyList()
    _grants.value = emptyList()
    cancel(ONGOING_ID)
  }

  fun readLog(n: Int = 300): List<Entry> =
      parseEntries(Libtailscale.remoteControlShellLogJSON(logFile().absolutePath, n))

  fun verify(): Verification {
    val o = JSONObject(Libtailscale.remoteControlVerifyShellLogJSON(logFile().absolutePath))
    return Verification(
        ok = o.optBoolean("ok"),
        entries = o.optLong("entries"),
        head = o.optString("lastHash"),
        problem = o.optString("problem"),
    )
  }

  private fun refreshGrants() {
    val arr =
        JSONArray(
            Libtailscale.remoteControlShellGrantsJSON().let { if (it == "null") "[]" else it })
    _grants.value =
        (0 until arr.length()).map { i ->
          val o = arr.getJSONObject(i)
          Grant(
              session = o.optString("session"),
              client = o.optString("client"),
              remote = o.optString("remote"),
              until = o.optString("until"),
          )
        }
  }

  private fun clearRequest(id: String) {
    _requests.value = _requests.value.filterNot { it.id == id }
    cancel(requestNotificationId(id))
  }

  private fun parseEntries(json: String): List<Entry> {
    val arr =
        try {
          JSONArray(if (json.isBlank() || json == "null") "[]" else json)
        } catch (e: Exception) {
          return emptyList()
        }
    return (0 until arr.length()).map { i ->
      val o = arr.getJSONObject(i)
      Entry(
          seq = o.optLong("seq"),
          time = o.optString("time"),
          kind = o.optString("kind"),
          client = o.optString("client"),
          cmd = o.optString("cmd"),
          exit = if (o.has("exit")) o.optInt("exit") else null,
          note = o.optString("note"),
          hash = o.optString("hash"),
      )
    }
  }

  /** "14:05" for a Go RFC 3339 time, or the raw string if it does not parse. */
  fun shortTime(rfc3339: String): String =
      try {
        DateFormat.getTimeInstance(DateFormat.SHORT).format(Date.from(Instant.parse(rfc3339)))
      } catch (e: Exception) {
        rfc3339
      }

  // ---------------------------------------------------------------------------
  // notifications
  // ---------------------------------------------------------------------------

  fun createChannel() {
    val app = App.get()
    app.createNotificationChannel(
        CHANNEL_ID,
        app.getString(R.string.remote_shell_channel),
        app.getString(R.string.remote_shell_channel_description),
        NotificationManagerCompat.IMPORTANCE_HIGH,
    )
  }

  private fun requestNotificationId(id: String) = REQUEST_BASE + (id.hashCode() and 0xffff)

  private fun action(action: String, extra: String?, code: Int): PendingIntent {
    val app = App.get()
    val intent =
        Intent(app, RemoteControlReceiver::class.java)
            .setAction(action)
            .putExtra(RemoteControlReceiver.EXTRA_REQUEST_ID, extra)
    return PendingIntent.getBroadcast(
        app, code, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
  }

  private fun openApp(): PendingIntent {
    val app = App.get()
    return PendingIntent.getActivity(
        app,
        1,
        Intent(app, MainActivity::class.java)
            .setAction(MainActivity.ACTION_OPEN_REMOTE_CONTROL)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
  }

  private fun showRequest(r: Request) {
    createChannel()
    val app = App.get()
    val nid = requestNotificationId(r.id)
    val allow =
        NotificationCompat.Action.Builder(
                0,
                app.getString(R.string.remote_shell_allow, r.minutes),
                action(RemoteControlReceiver.ACTION_SHELL_ALLOW, r.id, nid * 4 + 1))
            // A shell is the whole app: never from the lock screen.
            .setAuthenticationRequired(true)
            .build()
    val n =
        NotificationCompat.Builder(app, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(app.getString(R.string.remote_shell_request_title, r.client))
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText(app.getString(R.string.remote_shell_request_body, r.remote, r.code)))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setAutoCancel(true)
            .setTimeoutAfter(120_000)
            .setContentIntent(openApp())
            .addAction(allow)
            .addAction(
                0,
                app.getString(R.string.remote_control_deny),
                action(RemoteControlReceiver.ACTION_SHELL_DENY, r.id, nid * 4 + 2))
            .build()
    notify(nid, n)
  }

  private fun updateOngoing() {
    val g = _grants.value
    if (g.isEmpty()) {
      cancel(ONGOING_ID)
      return
    }
    createChannel()
    val app = App.get()
    val who = g.joinToString(", ") { "${it.client} (${it.remote.substringBeforeLast(':')})" }
    val until = g.maxOf { it.until }
    val n =
        NotificationCompat.Builder(app, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(app.getString(R.string.remote_shell_open_title))
            .setContentText(app.getString(R.string.remote_shell_open_text, who, shortTime(until)))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(openApp())
            .addAction(
                0,
                app.getString(R.string.remote_shell_end),
                action(RemoteControlReceiver.ACTION_SHELL_END_ALL, null, 2))
            .build()
    notify(ONGOING_ID, n)
  }

  private fun notify(id: Int, n: android.app.Notification) {
    if (!NotificationManagerCompat.from(App.get()).areNotificationsEnabled()) return
    try {
      NotificationManagerCompat.from(App.get()).notify(id, n)
    } catch (e: SecurityException) {
      TSLog.w(TAG, "no notification permission: $e")
    }
  }

  private fun cancel(id: Int) = NotificationManagerCompat.from(App.get()).cancel(id)
}
