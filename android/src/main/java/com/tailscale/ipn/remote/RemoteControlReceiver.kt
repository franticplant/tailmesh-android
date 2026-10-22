// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.remote

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.tailscale.ipn.BuildConfig

/**
 * Handles the remote-control notification buttons. Not exported: only this app's own PendingIntents
 * can reach it, so nothing else on the device can approve a client.
 */
class RemoteControlReceiver : BroadcastReceiver() {
  override fun onReceive(context: Context, intent: Intent) {
    val id = intent.getStringExtra(EXTRA_REQUEST_ID)
    when (intent.action) {
      ACTION_APPROVE_CONTROL -> id?.let { RemoteControl.approve(it, control = true) }
      ACTION_APPROVE_READ -> id?.let { RemoteControl.approve(it, control = false) }
      ACTION_DENY -> id?.let { RemoteControl.deny(it) }
      ACTION_STOP -> RemoteControl.disable()
      ACTION_SHELL_ALLOW -> if (BuildConfig.DEV_TOOLS) id?.let { RemoteShell.approve(it) }
      ACTION_SHELL_DENY -> id?.let { RemoteShell.deny(it) }
      ACTION_SHELL_END_ALL -> RemoteShell.endAll()
    }
  }

  companion object {
    const val ACTION_APPROVE_CONTROL = "com.tailscale.ipn.remote.APPROVE_CONTROL"
    const val ACTION_APPROVE_READ = "com.tailscale.ipn.remote.APPROVE_READ"
    const val ACTION_DENY = "com.tailscale.ipn.remote.DENY"
    const val ACTION_STOP = "com.tailscale.ipn.remote.STOP"
    const val ACTION_SHELL_ALLOW = "com.tailscale.ipn.remote.SHELL_ALLOW"
    const val ACTION_SHELL_DENY = "com.tailscale.ipn.remote.SHELL_DENY"
    const val ACTION_SHELL_END_ALL = "com.tailscale.ipn.remote.SHELL_END_ALL"
    const val EXTRA_REQUEST_ID = "requestId"
  }
}
