// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.remote

import com.tailscale.ipn.App

/**
 * Remote control settings, kept in the app's encrypted preferences.
 *
 * Nothing in the remote-control API can read or change these: [RemoteMethods] has no method for
 * them, deliberately, so a remote client can never widen its own access, extend its own lifetime or
 * silence its own logging. Only the Remote control screen writes them.
 */
class RemoteControlSettings(private val app: App = App.get()) {
  /** Whether the user has turned remote control on. */
  var enabled: Boolean
    get() = bool(KEY_ENABLED, false)
    set(v) = put(KEY_ENABLED, v.toString())

  /** Where it listens: [BIND_LOOPBACK], [BIND_ALL], or a literal address to bind. */
  var bind: String
    get() = str(KEY_BIND) ?: BIND_LOOPBACK
    set(v) = put(KEY_BIND, v)

  var port: Int
    get() = str(KEY_PORT)?.toIntOrNull() ?: DEFAULT_PORT
    set(v) = put(KEY_PORT, v.toString())

  /** Whether a client may ask to be approved on this device. */
  var approvalEnabled: Boolean
    get() = bool(KEY_APPROVAL, true)
    set(v) = put(KEY_APPROVAL, v.toString())

  /** Empty means password sign-in is off. */
  var password: String
    get() = str(KEY_PASSWORD) ?: ""
    set(v) = put(KEY_PASSWORD, v)

  /** Whether a password session may change things, or only read. */
  var passwordGrantsControl: Boolean
    get() = bool(KEY_PASSWORD_CONTROL, false)
    set(v) = put(KEY_PASSWORD_CONTROL, v.toString())

  /** The global control switch: off makes every session read-only, immediately. */
  var allowControl: Boolean
    get() = bool(KEY_ALLOW_CONTROL, true)
    set(v) = put(KEY_ALLOW_CONTROL, v.toString())

  /**
   * Whether a control session may install a newer build of the app (`app.update`). Separate from
   * [allowControl] and off by default: it replaces the app's code, not just its settings.
   */
  var allowRemoteUpdates: Boolean
    get() = bool(KEY_ALLOW_UPDATES, false)
    set(v) = put(KEY_ALLOW_UPDATES, v.toString())

  /** How long remote control stays on once enabled; 0 means until turned off. */
  var autoOffMinutes: Int
    get() = str(KEY_AUTO_OFF)?.toIntOrNull() ?: 60
    set(v) = put(KEY_AUTO_OFF, v.toString())

  /** When the current enablement lapses, epoch millis; 0 means never. */
  var expiresAtMillis: Long
    get() = str(KEY_EXPIRES)?.toLongOrNull() ?: 0L
    set(v) = put(KEY_EXPIRES, v.toString())

  /** The host part of the listen address. */
  fun listenHost(): String =
      when (bind) {
        BIND_LOOPBACK -> "127.0.0.1"
        BIND_ALL -> "0.0.0.0"
        else -> bind
      }

  private fun str(key: String): String? = app.decryptFromPref(key)

  private fun bool(key: String, default: Boolean): Boolean =
      str(key)?.toBooleanStrictOrNull() ?: default

  private fun put(key: String, value: String) = app.encryptToPref(key, value)

  companion object {
    const val BIND_LOOPBACK = "loopback"
    const val BIND_ALL = "all"
    const val DEFAULT_PORT = 7373

    private const val KEY_ENABLED = "remoteControl.enabled"
    private const val KEY_BIND = "remoteControl.bind"
    private const val KEY_PORT = "remoteControl.port"
    private const val KEY_APPROVAL = "remoteControl.approval"
    private const val KEY_PASSWORD = "remoteControl.password"
    private const val KEY_PASSWORD_CONTROL = "remoteControl.passwordControl"
    private const val KEY_ALLOW_CONTROL = "remoteControl.allowControl"
    private const val KEY_AUTO_OFF = "remoteControl.autoOffMinutes"
    private const val KEY_ALLOW_UPDATES = "remoteControl.allowUpdates"
    private const val KEY_EXPIRES = "remoteControl.expiresAt"
  }
}
