// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.remote

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.tailscale.ipn.App
import com.tailscale.ipn.BuildConfig
import com.tailscale.ipn.MainActivity
import com.tailscale.ipn.R
import com.tailscale.ipn.multiproxy.PacketCaptures
import com.tailscale.ipn.util.TSLog
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import libtailscale.Libtailscale
import org.json.JSONArray
import org.json.JSONObject

/**
 * Runs the remote-control endpoint (libtailscale/remotectl) and is its bridge into the app.
 *
 * The server itself handles authentication, sessions, the access log and log streaming; this object
 * starts and stops it from [RemoteControlSettings], answers its method calls through
 * [RemoteMethods], and puts what the user must see in front of them: an ongoing notification while
 * it is on, and an Allow / Allow read-only / Deny notification for every client asking to connect.
 */
object RemoteControl {
  private const val TAG = "RemoteControl"
  const val STATUS_CHANNEL_ID = "remote-control-status"
  const val APPROVAL_CHANNEL_ID = "remote-control-approval"
  private const val STATUS_NOTIFICATION_ID = 7373
  private const val APPROVAL_NOTIFICATION_BASE = 7400
  private const val CALL_TIMEOUT_MILLIS = 55_000L
  private const val RECENT_ACCESS = 200

  data class State(
      val running: Boolean = false,
      val address: String = "",
      val error: String? = null,
      val stoppedReason: String? = null,
  )

  data class Pending(
      val id: String,
      val client: String,
      val remote: String,
      val code: String,
  )

  data class Session(
      val id: String,
      val client: String,
      val remote: String,
      val via: String,
      val control: Boolean,
      val lastUsed: String,
  )

  data class Access(
      val time: String,
      val remote: String,
      val client: String,
      val action: String,
      val status: Int,
      val error: String,
  )

  private val _state = MutableStateFlow(State())
  val state: StateFlow<State> = _state.asStateFlow()

  private val _pending = MutableStateFlow<List<Pending>>(emptyList())
  val pending: StateFlow<List<Pending>> = _pending.asStateFlow()

  private val _sessions = MutableStateFlow<List<Session>>(emptyList())
  val sessions: StateFlow<List<Session>> = _sessions.asStateFlow()

  private val _recentAccess = MutableStateFlow<List<Access>>(emptyList())
  val recentAccess: StateFlow<List<Access>> = _recentAccess.asStateFlow()

  fun accessLogFile(): File = File(App.get().filesDir, "remote-control/access.log")

  /** Called once at app start: brings remote control back if it is on and has not lapsed. */
  fun restore() {
    createChannels()
    val s = RemoteControlSettings()
    if (!s.enabled) return
    if (s.expiresAtMillis != 0L && System.currentTimeMillis() >= s.expiresAtMillis) {
      s.enabled = false
      return
    }
    start()
  }

  /** Turns remote control on, starting a fresh auto-off window. */
  fun enable() {
    val s = RemoteControlSettings()
    s.enabled = true
    s.expiresAtMillis =
        if (s.autoOffMinutes > 0) System.currentTimeMillis() + s.autoOffMinutes * 60_000L else 0L
    start()
  }

  /** Turns remote control off and ends every session. */
  fun disable() {
    RemoteControlSettings().enabled = false
    Libtailscale.stopRemoteControl()
  }

  /** (Re)starts the server from the current settings. Ends existing sessions. */
  fun start() {
    createChannels()
    val s = RemoteControlSettings()
    val config =
        JSONObject()
            .put("addr", "${s.listenHost()}:${s.port}")
            .put("approvalEnabled", s.approvalEnabled)
            .put("password", s.password)
            .put("passwordGrantsControl", s.passwordGrantsControl)
            .put("allowControl", s.allowControl)
            .put("expiresAtUnix", if (s.expiresAtMillis == 0L) 0 else s.expiresAtMillis / 1000)
            .put("accessLogPath", accessLogFile().absolutePath)
            .put(
                "fileRoots",
                JSONArray(
                    listOf(
                        PacketCaptures.capturesDir().absolutePath,
                        RemoteMethods.exportsDir().absolutePath,
                    )),
            )
            .apply {
              // Development builds only; without it the server has no update endpoint.
              if (BuildConfig.DEV_TOOLS) put("updateDir", AppUpdater.updateDir().absolutePath)
            }
            .put("version", BuildConfig.VERSION_NAME)
            .put("methods", RemoteMethods.catalogJson())
            // Development builds with "Allow remote shell" on; otherwise adds nothing.
            .also { RemoteShell.configure(it) }
    try {
      val addr = Libtailscale.startRemoteControl(config.toString(), handler)
      _state.value = State(running = true, address = addr)
      _recentAccess.value = emptyList()
      refreshSessions()
      showStatusNotification(addr)
    } catch (e: Exception) {
      TSLog.e(TAG, "could not start remote control: $e")
      _state.value = State(running = false, error = e.message ?: "Could not start")
      s.enabled = false
    }
  }

  /** Applies the global control switch live, without restarting or ending sessions. */
  fun setAllowControl(allow: Boolean) {
    RemoteControlSettings().allowControl = allow
    Libtailscale.remoteControlSetAllowControl(allow)
    refreshSessions()
  }

  fun approve(id: String, control: Boolean) {
    try {
      Libtailscale.remoteControlApprove(id, control)
    } catch (e: Exception) {
      TSLog.w(TAG, "approve $id: ${e.message}")
    }
    clearPending(id)
  }

  fun deny(id: String) {
    try {
      Libtailscale.remoteControlDeny(id)
    } catch (e: Exception) {
      TSLog.w(TAG, "deny $id: ${e.message}")
    }
    clearPending(id)
  }

  fun revoke(sessionId: String) {
    Libtailscale.remoteControlRevokeSession(sessionId)
    refreshSessions()
  }

  /** The persisted access log, newest last. */
  fun readAccessLog(n: Int = 500): List<Access> =
      parseAccess(Libtailscale.remoteControlAccessLogJSON(accessLogFile().absolutePath, n))

  /** Clears the access log. Refused by the Go side while remote control is running. */
  fun clearAccessLog() {
    Libtailscale.remoteControlClearAccessLog(accessLogFile().absolutePath)
    _recentAccess.value = emptyList()
  }

  private val handler =
      object : libtailscale.RemoteControlHandler {
        override fun call(method: String, argsJSON: String): String = runBlocking {
          withTimeout(CALL_TIMEOUT_MILLIS) { RemoteMethods.call(method, argsJSON) }
        }

        override fun onApprovalRequest(requestJSON: String) {
          val o = JSONObject(requestJSON)
          val p =
              Pending(
                  id = o.getString("id"),
                  client = o.optString("client"),
                  remote = o.optString("remote"),
                  code = o.optString("code"),
              )
          _pending.value = _pending.value + p
          showApprovalNotification(p)
        }

        override fun onAccess(entryJSON: String) {
          val a = parseAccess("[$entryJSON]").firstOrNull() ?: return
          _recentAccess.value = (_recentAccess.value + a).takeLast(RECENT_ACCESS)
        }

        override fun onSessionsChanged() = refreshSessions()

        override fun onShellRequest(requestJSON: String) {
          // The server only asks when configured with the shell, but a release never acts on it.
          if (BuildConfig.DEV_TOOLS) RemoteShell.onRequest(requestJSON)
        }

        override fun onShellEntry(entryJSON: String) = RemoteShell.onEntry(entryJSON)

        override fun onShellChanged() = RemoteShell.onChanged()

        override fun onStopped(reason: String) {
          _state.value = State(running = false, stoppedReason = reason)
          _sessions.value = emptyList()
          _pending.value.forEach { cancelApprovalNotification(it.id) }
          _pending.value = emptyList()
          RemoteShell.onStopped()
          if (reason == "expired") RemoteControlSettings().enabled = false
          NotificationManagerCompat.from(App.get()).cancel(STATUS_NOTIFICATION_ID)
        }
      }

  private fun refreshSessions() {
    val arr =
        JSONArray(
            Libtailscale.remoteControlSessionsJSON()
                .ifBlank { "[]" }
                .let { if (it == "null") "[]" else it })
    _sessions.value =
        (0 until arr.length()).map { i ->
          val o = arr.getJSONObject(i)
          Session(
              id = o.optString("id"),
              client = o.optString("client"),
              remote = o.optString("remote"),
              via = o.optString("via"),
              control = o.optBoolean("control") && RemoteControlSettings().allowControl,
              lastUsed = o.optString("lastUsed"),
          )
        }
  }

  private fun clearPending(id: String) {
    _pending.value = _pending.value.filterNot { it.id == id }
    cancelApprovalNotification(id)
  }

  private fun parseAccess(json: String): List<Access> {
    val arr =
        try {
          JSONArray(if (json.isBlank() || json == "null") "[]" else json)
        } catch (e: Exception) {
          return emptyList()
        }
    return (0 until arr.length()).map { i ->
      val o = arr.getJSONObject(i)
      Access(
          time = o.optString("time"),
          remote = o.optString("remote"),
          client = o.optString("client"),
          action = o.optString("action"),
          status = o.optInt("status"),
          error = o.optString("error"),
      )
    }
  }

  // ---------------------------------------------------------------------------
  // notifications
  // ---------------------------------------------------------------------------

  private fun createChannels() {
    val app = App.get()
    app.createNotificationChannel(
        STATUS_CHANNEL_ID,
        app.getString(R.string.remote_control_status_channel),
        app.getString(R.string.remote_control_status_channel_description),
        NotificationManagerCompat.IMPORTANCE_LOW,
    )
    app.createNotificationChannel(
        APPROVAL_CHANNEL_ID,
        app.getString(R.string.remote_control_approval_channel),
        app.getString(R.string.remote_control_approval_channel_description),
        NotificationManagerCompat.IMPORTANCE_HIGH,
    )
    if (BuildConfig.DEV_TOOLS) RemoteShell.createChannel()
  }

  private fun openAppIntent(): PendingIntent {
    val app = App.get()
    val intent =
        Intent(app, MainActivity::class.java)
            .setAction(MainActivity.ACTION_OPEN_REMOTE_CONTROL)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
    return PendingIntent.getActivity(
        app,
        0,
        intent,
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )
  }

  private fun actionIntent(action: String, requestId: String?, code: Int): PendingIntent {
    val app = App.get()
    val intent =
        Intent(app, RemoteControlReceiver::class.java)
            .setAction(action)
            .putExtra(RemoteControlReceiver.EXTRA_REQUEST_ID, requestId)
    return PendingIntent.getBroadcast(
        app,
        code,
        intent,
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )
  }

  private fun canNotify(): Boolean =
      NotificationManagerCompat.from(App.get()).areNotificationsEnabled()

  private fun showStatusNotification(addr: String) {
    if (!canNotify()) return
    val app = App.get()
    val n =
        NotificationCompat.Builder(app, STATUS_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(app.getString(R.string.remote_control_active))
            .setContentText(app.getString(R.string.remote_control_active_on, addr))
            .setOngoing(true)
            .setContentIntent(openAppIntent())
            .addAction(
                0,
                app.getString(R.string.remote_control_turn_off),
                actionIntent(RemoteControlReceiver.ACTION_STOP, null, 1),
            )
            .build()
    try {
      NotificationManagerCompat.from(app).notify(STATUS_NOTIFICATION_ID, n)
    } catch (e: SecurityException) {
      TSLog.w(TAG, "no notification permission: $e")
    }
  }

  private fun approvalNotificationId(requestId: String) =
      APPROVAL_NOTIFICATION_BASE + (requestId.hashCode() and 0xffff)

  private fun showApprovalNotification(p: Pending) {
    if (!canNotify()) return
    val app = App.get()
    val nid = approvalNotificationId(p.id)
    val n =
        NotificationCompat.Builder(app, APPROVAL_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(app.getString(R.string.remote_control_request_title, p.client))
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText(app.getString(R.string.remote_control_request_body, p.remote, p.code)))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setAutoCancel(true)
            .setTimeoutAfter(120_000)
            .setContentIntent(openAppIntent())
            .addAction(
                0,
                app.getString(R.string.remote_control_allow_control),
                actionIntent(RemoteControlReceiver.ACTION_APPROVE_CONTROL, p.id, nid * 4 + 1),
            )
            .addAction(
                0,
                app.getString(R.string.remote_control_allow_read_only),
                actionIntent(RemoteControlReceiver.ACTION_APPROVE_READ, p.id, nid * 4 + 2),
            )
            .addAction(
                0,
                app.getString(R.string.remote_control_deny),
                actionIntent(RemoteControlReceiver.ACTION_DENY, p.id, nid * 4 + 3),
            )
            .build()
    try {
      NotificationManagerCompat.from(app).notify(nid, n)
    } catch (e: SecurityException) {
      TSLog.w(TAG, "no notification permission: $e")
    }
  }

  private fun cancelApprovalNotification(requestId: String) {
    (App.get().getSystemService(NotificationManager::class.java))?.cancel(
        approvalNotificationId(requestId))
  }
}
