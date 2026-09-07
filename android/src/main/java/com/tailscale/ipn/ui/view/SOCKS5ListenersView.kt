// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.tailscale.ipn.R
import com.tailscale.ipn.multiproxy.db.SOCKS5ListenerRecord
import com.tailscale.ipn.ui.util.Lists
import com.tailscale.ipn.ui.viewModel.RoutableUpstream
import com.tailscale.ipn.ui.viewModel.SOCKS5ListenersViewModel

/**
 * Manages inbound SOCKS5 listeners: each hands out one fixed upstream (a Tailnet, a proxy, a
 * WireGuard tunnel, or the direct bypass) to whatever connects to it, by port - see
 * `libtailscale/multiproxy/socks5_listener.go`.
 *
 * A listener behaves like an app binding for its upstream's availability: switching that upstream
 * off pauses the listener rather than leaving it accepting connections that can only fail, and it
 * resumes automatically once the upstream is available again - see
 * [com.tailscale.ipn.multiproxy.UpstreamPolicyApplier.applySOCKS5Listeners]. This screen shows that
 * as a "Paused" status line rather than as a second on/off switch: the switch here is always the
 * user's own intent.
 */
@Composable
fun SOCKS5ListenersView(
    backToSettings: BackNavigation,
    model: SOCKS5ListenersViewModel = viewModel(),
) {
  val listeners by model.listeners.collectAsState()
  val routable by model.routableUpstreams.collectAsState()
  val errorMessage by model.errorMessage.collectAsState()

  var editing by remember { mutableStateOf<SOCKS5ListenerRecord?>(null) }
  var creating by remember { mutableStateOf(false) }
  var deleting by remember { mutableStateOf<SOCKS5ListenerRecord?>(null) }

  errorMessage?.let { message ->
    AlertDialog(
        onDismissRequest = { model.errorMessage.value = null },
        title = { Text(stringResource(R.string.socks5_listener_invalid)) },
        text = { Text(message) },
        confirmButton = {
          TextButton(onClick = { model.errorMessage.value = null }) {
            Text(stringResource(R.string.ok))
          }
        },
    )
  }

  deleting?.let { listener ->
    AlertDialog(
        onDismissRequest = { deleting = null },
        title = { Text(stringResource(R.string.socks5_listener_delete_title, listener.port)) },
        text = { Text(stringResource(R.string.socks5_listener_delete_explanation)) },
        confirmButton = {
          TextButton(
              onClick = {
                model.delete(listener.id)
                deleting = null
              }) {
                Text(stringResource(R.string.delete))
              }
        },
        dismissButton = {
          TextButton(onClick = { deleting = null }) { Text(stringResource(R.string.cancel)) }
        },
    )
  }

  if (creating || editing != null) {
    SOCKS5ListenerEditorDialog(
        existing = editing,
        initialAuth = editing?.let { model.authFor(it.id) },
        upstreamCandidates = routable,
        onDismiss = {
          creating = false
          editing = null
        },
        onSave = { id, bindAddr, port, upstream, username, password ->
          model.save(id, bindAddr, port, upstream, username, password)
          creating = false
          editing = null
        },
    )
  }

  Scaffold(
      topBar = { Header(titleRes = R.string.socks5_listeners, onBack = backToSettings) },
      floatingActionButton = {
        FloatingActionButton(onClick = { creating = true }) {
          Icon(Icons.Default.Add, stringResource(R.string.socks5_listener_add))
        }
      },
  ) { innerPadding ->
    LazyColumn(modifier = Modifier.padding(innerPadding)) {
      item("explanation") {
        ListItem(
            headlineContent = { Text(stringResource(R.string.socks5_listeners_explanation)) },
        )
      }

      item("header") {
        Lists.SectionDivider(stringResource(R.string.count_socks5_listeners, listeners.count()))
      }
      if (listeners.isEmpty()) {
        item("empty") {
          ListItem(headlineContent = { Text(stringResource(R.string.socks5_listeners_empty)) })
        }
      } else {
        items(listeners, key = { it.id }) { listener ->
          val upstreamLabel = routable.firstOrNull { it.id == listener.upstream }?.label
          ListItem(
              modifier = Modifier.fillMaxWidth(),
              headlineContent = {
                Text("${listener.bindAddr}:${listener.port}", fontWeight = FontWeight.SemiBold)
              },
              supportingContent = {
                Column {
                  Text(
                      upstreamLabel ?: stringResource(R.string.upstream_missing, listener.upstream),
                      color = MaterialTheme.colorScheme.secondary,
                      fontSize = MaterialTheme.typography.bodySmall.fontSize,
                  )
                  if (listener.hasAuth) {
                    Text(
                        stringResource(R.string.socks5_listener_auth_required),
                        color = MaterialTheme.colorScheme.secondary,
                        fontSize = MaterialTheme.typography.bodySmall.fontSize,
                    )
                  }
                  SOCKS5ListenerStatusLine(listener, model.isRegistered(listener.id))
                }
              },
              trailingContent = {
                Switch(
                    checked = listener.enabled,
                    onCheckedChange = { model.setEnabled(listener.id, it) },
                )
              },
          )
          Row(modifier = Modifier.padding(start = 16.dp, bottom = 8.dp)) {
            TextButton(onClick = { editing = listener }) { Text(stringResource(R.string.edit)) }
            TextButton(onClick = { deleting = listener }) { Text(stringResource(R.string.delete)) }
          }
          Lists.ItemDivider()
        }
      }
    }
  }
}

/**
 * One status line under a listener row: the user's on/off choice ([SOCKS5ListenerRecord.enabled])
 * plus, when on, whether it is actually registered with the running engine right now
 * ([isRegistered] - false means its upstream is currently switched off and
 * [com.tailscale.ipn.multiproxy.UpstreamPolicyApplier] has paused it).
 */
@Composable
private fun SOCKS5ListenerStatusLine(listener: SOCKS5ListenerRecord, isRegistered: Boolean) {
  val fontSize = MaterialTheme.typography.bodySmall.fontSize
  val (text, color) =
      when {
        !listener.enabled ->
            stringResource(R.string.socks5_listener_status_off) to
                MaterialTheme.colorScheme.secondary
        isRegistered ->
            stringResource(R.string.socks5_listener_status_running) to
                MaterialTheme.colorScheme.secondary
        else ->
            stringResource(R.string.socks5_listener_status_paused) to
                MaterialTheme.colorScheme.error
      }
  Text(text, color = color, fontSize = fontSize)
}

/** Creates or edits one SOCKS5 listener. */
@Composable
fun SOCKS5ListenerEditorDialog(
    existing: SOCKS5ListenerRecord?,
    initialAuth: Pair<String, String>?,
    upstreamCandidates: List<RoutableUpstream>,
    onDismiss: () -> Unit,
    onSave: (String?, String, String, String, String, String) -> Unit,
) {
  var bindAddr by remember { mutableStateOf(existing?.bindAddr ?: "127.0.0.1") }
  var port by remember { mutableStateOf(existing?.port?.toString() ?: "") }
  var upstream by remember { mutableStateOf(existing?.upstream ?: "") }
  var username by remember { mutableStateOf(initialAuth?.first ?: "") }
  var password by remember { mutableStateOf(initialAuth?.second ?: "") }
  var upstreamMenuOpen by remember { mutableStateOf(false) }

  AlertDialog(
      onDismissRequest = onDismiss,
      title = {
        Text(
            stringResource(
                if (existing == null) R.string.socks5_listener_add
                else R.string.socks5_listener_edit))
      },
      text = {
        Column(
            modifier = Modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          OutlinedTextField(
              value = bindAddr,
              onValueChange = { bindAddr = it },
              label = { Text(stringResource(R.string.socks5_listener_bind_addr)) },
              placeholder = { Text("127.0.0.1") },
              singleLine = true,
          )
          OutlinedTextField(
              value = port,
              onValueChange = { port = it },
              label = { Text(stringResource(R.string.socks5_listener_port)) },
              placeholder = { Text("1080") },
              singleLine = true,
          )

          val upstreamLabel =
              upstreamCandidates.firstOrNull { it.id == upstream }?.label
                  ?: stringResource(R.string.socks5_listener_upstream_unset)
          TextButton(onClick = { upstreamMenuOpen = true }) {
            Text(stringResource(R.string.socks5_listener_upstream, upstreamLabel))
          }
          DropdownMenu(
              expanded = upstreamMenuOpen, onDismissRequest = { upstreamMenuOpen = false }) {
                upstreamCandidates.forEach { candidate ->
                  DropdownMenuItem(
                      text = {
                        Text(
                            if (candidate.enabled) candidate.label
                            else stringResource(R.string.upstream_disabled, candidate.label))
                      },
                      onClick = {
                        upstream = candidate.id
                        upstreamMenuOpen = false
                      },
                  )
                }
              }

          OutlinedTextField(
              value = username,
              onValueChange = { username = it },
              label = { Text(stringResource(R.string.socks5_listener_username_optional)) },
              singleLine = true,
          )
          OutlinedTextField(
              value = password,
              onValueChange = { password = it },
              label = { Text(stringResource(R.string.socks5_listener_password_optional)) },
              singleLine = true,
          )
        }
      },
      confirmButton = {
        TextButton(
            onClick = { onSave(existing?.id, bindAddr, port, upstream, username, password) }) {
              Text(stringResource(R.string.save))
            }
      },
      dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
  )
}
