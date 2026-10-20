// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.tailscale.ipn.R
import com.tailscale.ipn.remote.RemoteControl
import com.tailscale.ipn.remote.RemoteControlSettings
import com.tailscale.ipn.ui.util.Lists
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private val autoOffChoices = listOf(15, 60, 240, 1440, 0)

/**
 * Turns the remote-control endpoint on and off and manages who may use it.
 *
 * This screen is the only place its settings, sessions and access log can be changed: the API
 * itself has no method for any of them (see [com.tailscale.ipn.remote.RemoteMethods]).
 */
@Composable
fun RemoteControlView(backToSettings: BackNavigation) {
  val settings = remember { RemoteControlSettings() }
  val state by RemoteControl.state.collectAsState()
  val pending by RemoteControl.pending.collectAsState()
  val sessions by RemoteControl.sessions.collectAsState()
  val recent by RemoteControl.recentAccess.collectAsState()

  var bind by remember { mutableStateOf(settings.bind) }
  var customAddr by remember {
    mutableStateOf(
        settings.bind.takeUnless {
          it == RemoteControlSettings.BIND_LOOPBACK || it == RemoteControlSettings.BIND_ALL
        } ?: "")
  }
  var port by remember { mutableStateOf(settings.port.toString()) }
  var approval by remember { mutableStateOf(settings.approvalEnabled) }
  var password by remember { mutableStateOf(settings.password) }
  var passwordControl by remember { mutableStateOf(settings.passwordGrantsControl) }
  var allowControl by remember { mutableStateOf(settings.allowControl) }
  var autoOff by remember { mutableStateOf(settings.autoOffMinutes) }
  var formError by remember { mutableStateOf<String?>(null) }
  var log by remember { mutableStateOf<List<RemoteControl.Access>>(emptyList()) }

  // The persisted log, re-read whenever new accesses arrive.
  LaunchedEffect(recent.size, state.running) {
    log = withContext(Dispatchers.IO) { RemoteControl.readAccessLog(300) }.reversed()
  }

  /** Validates and saves the form; returns false (with formError set) if it is invalid. */
  fun save(): Boolean {
    val portNum = port.trim().toIntOrNull()
    if (portNum == null || portNum !in 1..65535) {
      formError = "Port must be a number from 1 to 65535"
      return false
    }
    if (password.isNotEmpty() && password.length < 8) {
      formError = "The password must be at least 8 characters"
      return false
    }
    if (!approval && password.isEmpty()) {
      formError = "Turn on device approval, set a password, or both"
      return false
    }
    val effectiveBind =
        if (bind == "custom") customAddr.trim().ifEmpty { RemoteControlSettings.BIND_LOOPBACK }
        else bind
    settings.bind = effectiveBind
    settings.port = portNum
    settings.approvalEnabled = approval
    settings.password = password
    settings.passwordGrantsControl = passwordControl
    settings.allowControl = allowControl
    settings.autoOffMinutes = autoOff
    formError = null
    return true
  }

  Scaffold(topBar = { Header(titleRes = R.string.remote_control, onBack = backToSettings) }) {
      innerPadding ->
    LazyColumn(modifier = Modifier.padding(innerPadding)) {
      item("explanation") {
        ListItem(headlineContent = { Text(stringResource(R.string.remote_control_explanation)) })
      }

      item("toggle") {
        ListItem(
            headlineContent = { Text(stringResource(R.string.remote_control_enable)) },
            supportingContent = {
              Text(
                  when {
                    state.running ->
                        stringResource(R.string.remote_control_running_on, state.address)
                    state.error != null -> state.error!!
                    else -> stringResource(R.string.remote_control_off)
                  })
            },
            trailingContent = {
              Switch(
                  checked = state.running,
                  onCheckedChange = { on ->
                    if (on) {
                      if (save()) RemoteControl.enable()
                    } else {
                      RemoteControl.disable()
                    }
                  },
              )
            },
        )
      }

      item("allowControl") {
        ListItem(
            headlineContent = { Text(stringResource(R.string.remote_control_allow_changes)) },
            supportingContent = {
              Text(stringResource(R.string.remote_control_allow_changes_subtitle))
            },
            trailingContent = {
              Switch(
                  checked = allowControl,
                  onCheckedChange = {
                    allowControl = it
                    RemoteControl.setAllowControl(it)
                  },
              )
            },
        )
      }

      if (pending.isNotEmpty()) {
        item("pendingHeader") {
          Lists.SectionDivider(stringResource(R.string.remote_control_pending))
        }
        items(pending, key = { "p-" + it.id }) { p ->
          ListItem(
              headlineContent = { Text("${p.client} - ${p.code}") },
              supportingContent = { Text(p.remote) },
              trailingContent = {
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                  TextButton(onClick = { RemoteControl.approve(p.id, control = true) }) {
                    Text(stringResource(R.string.remote_control_allow_control))
                  }
                  TextButton(onClick = { RemoteControl.approve(p.id, control = false) }) {
                    Text(stringResource(R.string.remote_control_allow_read_only))
                  }
                  TextButton(onClick = { RemoteControl.deny(p.id) }) {
                    Text(stringResource(R.string.remote_control_deny))
                  }
                }
              },
          )
        }
      }

      item("sessionsHeader") {
        Lists.SectionDivider(stringResource(R.string.remote_control_sessions))
      }
      if (sessions.isEmpty()) {
        item("noSessions") {
          ListItem(headlineContent = { Text(stringResource(R.string.remote_control_no_sessions)) })
        }
      }
      items(sessions, key = { "s-" + it.id }) { s ->
        ListItem(
            headlineContent = {
              Text("${s.client} (${if (s.control) "control" else "read-only"}, ${s.via})")
            },
            supportingContent = { Text("${s.remote} - last used ${s.lastUsed.take(19)}") },
            trailingContent = {
              TextButton(onClick = { RemoteControl.revoke(s.id) }) {
                Text(stringResource(R.string.remote_control_revoke))
              }
            },
        )
      }

      item("configHeader") {
        Lists.SectionDivider(stringResource(R.string.remote_control_listen_on))
      }
      item("bind") {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          FilterChip(
              selected = bind == RemoteControlSettings.BIND_LOOPBACK,
              onClick = { bind = RemoteControlSettings.BIND_LOOPBACK },
              label = { Text(stringResource(R.string.remote_control_bind_loopback)) },
          )
          FilterChip(
              selected = bind == RemoteControlSettings.BIND_ALL,
              onClick = { bind = RemoteControlSettings.BIND_ALL },
              label = { Text(stringResource(R.string.remote_control_bind_all)) },
          )
        }
        Row(modifier = Modifier.padding(horizontal = 16.dp)) {
          FilterChip(
              selected =
                  bind != RemoteControlSettings.BIND_LOOPBACK &&
                      bind != RemoteControlSettings.BIND_ALL,
              onClick = { bind = "custom" },
              label = { Text(stringResource(R.string.remote_control_bind_custom)) },
          )
        }
        if (bind != RemoteControlSettings.BIND_LOOPBACK) {
          Text(
              stringResource(R.string.remote_control_bind_warning),
              style = MaterialTheme.typography.bodySmall,
              color = MaterialTheme.colorScheme.error,
              modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
          )
        }
      }
      if (bind != RemoteControlSettings.BIND_LOOPBACK && bind != RemoteControlSettings.BIND_ALL) {
        item("customAddr") {
          OutlinedTextField(
              value = customAddr,
              onValueChange = { customAddr = it },
              label = { Text(stringResource(R.string.remote_control_address)) },
              placeholder = { Text("10.146.109.63") },
              singleLine = true,
              modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
          )
        }
      }
      item("port") {
        OutlinedTextField(
            value = port,
            onValueChange = { port = it },
            label = { Text(stringResource(R.string.remote_control_port)) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
        )
      }

      item("approval") {
        ListItem(
            headlineContent = { Text(stringResource(R.string.remote_control_approval)) },
            supportingContent = { Text(stringResource(R.string.remote_control_approval_subtitle)) },
            trailingContent = { Switch(checked = approval, onCheckedChange = { approval = it }) },
        )
      }
      item("password") {
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text(stringResource(R.string.remote_control_password)) },
            placeholder = { Text(stringResource(R.string.remote_control_password_hint)) },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
        )
      }
      if (password.isNotEmpty()) {
        item("passwordControl") {
          ListItem(
              headlineContent = { Text(stringResource(R.string.remote_control_password_control)) },
              trailingContent = {
                Switch(checked = passwordControl, onCheckedChange = { passwordControl = it })
              },
          )
        }
      }

      item("autoOff") {
        Text(
            stringResource(R.string.remote_control_auto_off),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          autoOffChoices.forEach { minutes ->
            FilterChip(
                selected = autoOff == minutes,
                onClick = { autoOff = minutes },
                label = {
                  Text(
                      when {
                        minutes == 0 -> stringResource(R.string.remote_control_auto_off_never)
                        minutes < 60 -> "${minutes}m"
                        else -> "${minutes / 60}h"
                      })
                },
            )
          }
        }
      }

      item("apply") {
        formError?.let {
          Text(
              it,
              color = MaterialTheme.colorScheme.error,
              modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
          )
        }
        if (state.running) {
          Button(
              onClick = { if (save()) RemoteControl.enable() },
              modifier = Modifier.padding(16.dp),
          ) {
            Text(stringResource(R.string.remote_control_apply))
          }
        }
      }

      item("logHeader") { Lists.SectionDivider(stringResource(R.string.remote_control_access_log)) }
      item("clearLog") {
        OutlinedButton(
            onClick = {
              try {
                RemoteControl.clearAccessLog()
                log = emptyList()
              } catch (e: Exception) {
                formError = e.message
              }
            },
            enabled = !state.running,
            modifier = Modifier.padding(horizontal = 16.dp),
        ) {
          Text(
              stringResource(
                  if (state.running) R.string.remote_control_clear_log_needs_off
                  else R.string.remote_control_clear_log))
        }
      }
      items(log.size) { i ->
        val a = log[i]
        ListItem(
            headlineContent = {
              Text(
                  "${a.action}  ${a.status}",
                  fontFamily = FontFamily.Monospace,
                  style = MaterialTheme.typography.bodySmall,
              )
            },
            supportingContent = {
              Text(
                  "${a.time.take(19)}  ${a.client.ifEmpty { "-" }}  ${a.remote}" +
                      if (a.error.isNotEmpty()) "  ${a.error}" else "",
                  style = MaterialTheme.typography.bodySmall,
              )
            },
        )
      }
    }
  }
}
