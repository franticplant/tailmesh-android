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
import com.tailscale.ipn.multiproxy.db.InboundListenerRecord
import com.tailscale.ipn.ui.util.Lists
import com.tailscale.ipn.ui.viewModel.InboundListenersViewModel
import com.tailscale.ipn.ui.viewModel.RoutableUpstream

/**
 * Manages tailnet-facing inbound listeners: a connection a tailnet peer opens to an enabled
 * tailnet's node on a chosen port is forwarded to a local service on the device - see
 * `libtailscale/multiproxy/inbound_listener.go`.
 *
 * A listener is a "workload identity" for its tailnet, the same way an app binding is: switching
 * that tailnet off pauses the listener instead of leaving it accepting connections that can only
 * fail, and it resumes automatically once the tailnet is available again - see
 * [com.tailscale.ipn.multiproxy.UpstreamPolicyApplier.applyInboundListeners].
 */
@Composable
fun InboundListenersView(
    backToSettings: BackNavigation,
    model: InboundListenersViewModel = viewModel(),
) {
  val listeners by model.listeners.collectAsState()
  val candidates by model.tailnetCandidates.collectAsState()
  val errorMessage by model.errorMessage.collectAsState()

  var editing by remember { mutableStateOf<InboundListenerRecord?>(null) }
  var creating by remember { mutableStateOf(false) }
  var deleting by remember { mutableStateOf<InboundListenerRecord?>(null) }

  errorMessage?.let { message ->
    AlertDialog(
        onDismissRequest = { model.errorMessage.value = null },
        title = { Text(stringResource(R.string.inbound_listener_invalid)) },
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
        title = {
          Text(stringResource(R.string.inbound_listener_delete_title, listener.listenPort))
        },
        text = { Text(stringResource(R.string.inbound_listener_delete_explanation)) },
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
    InboundListenerEditorDialog(
        existing = editing,
        tailnetCandidates = candidates,
        onDismiss = {
          creating = false
          editing = null
        },
        onSave = { id, upstream, listenPort, localTarget, proxyProtocol ->
          model.save(id, upstream, listenPort, localTarget, proxyProtocol)
          creating = false
          editing = null
        },
    )
  }

  Scaffold(
      topBar = { Header(titleRes = R.string.inbound_listeners, onBack = backToSettings) },
      floatingActionButton = {
        FloatingActionButton(onClick = { creating = true }) {
          Icon(Icons.Default.Add, stringResource(R.string.inbound_listener_add))
        }
      },
  ) { innerPadding ->
    LazyColumn(modifier = Modifier.padding(innerPadding)) {
      item("explanation") {
        ListItem(
            headlineContent = { Text(stringResource(R.string.inbound_listeners_explanation)) },
        )
      }

      item("header") {
        Lists.SectionDivider(stringResource(R.string.count_inbound_listeners, listeners.count()))
      }
      if (listeners.isEmpty()) {
        item("empty") {
          ListItem(headlineContent = { Text(stringResource(R.string.inbound_listeners_empty)) })
        }
      } else {
        items(listeners, key = { it.id }) { listener ->
          val tailnetLabel = candidates.firstOrNull { it.id == listener.upstream }?.label
          ListItem(
              modifier = Modifier.fillMaxWidth(),
              headlineContent = {
                Text(
                    "${tailnetLabel ?: listener.upstream} :${listener.listenPort}",
                    fontWeight = FontWeight.SemiBold)
              },
              supportingContent = {
                Column {
                  Text(
                      stringResource(R.string.inbound_listener_forward_to, listener.localTarget),
                      color = MaterialTheme.colorScheme.secondary,
                      fontSize = MaterialTheme.typography.bodySmall.fontSize,
                  )
                  if (listener.proxyProtocol) {
                    Text(
                        stringResource(R.string.inbound_listener_proxy_protocol_on),
                        color = MaterialTheme.colorScheme.secondary,
                        fontSize = MaterialTheme.typography.bodySmall.fontSize,
                    )
                  }
                  InboundListenerStatusLine(listener, model.isRegistered(listener.id))
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

@Composable
private fun InboundListenerStatusLine(listener: InboundListenerRecord, isRegistered: Boolean) {
  val fontSize = MaterialTheme.typography.bodySmall.fontSize
  val (text, color) =
      when {
        !listener.enabled ->
            stringResource(R.string.inbound_listener_status_off) to
                MaterialTheme.colorScheme.secondary
        isRegistered ->
            stringResource(R.string.inbound_listener_status_running) to
                MaterialTheme.colorScheme.secondary
        else ->
            stringResource(R.string.inbound_listener_status_paused) to
                MaterialTheme.colorScheme.error
      }
  Text(text, color = color, fontSize = fontSize)
}

/** Creates or edits one inbound listener. */
@Composable
fun InboundListenerEditorDialog(
    existing: InboundListenerRecord?,
    tailnetCandidates: List<RoutableUpstream>,
    onDismiss: () -> Unit,
    onSave: (String?, String, String, String, Boolean) -> Unit,
) {
  var upstream by remember { mutableStateOf(existing?.upstream ?: "") }
  var listenPort by remember { mutableStateOf(existing?.listenPort?.toString() ?: "") }
  var localTarget by remember { mutableStateOf(existing?.localTarget ?: "127.0.0.1:") }
  var proxyProtocol by remember { mutableStateOf(existing?.proxyProtocol ?: false) }
  var upstreamMenuOpen by remember { mutableStateOf(false) }

  AlertDialog(
      onDismissRequest = onDismiss,
      title = {
        Text(
            stringResource(
                if (existing == null) R.string.inbound_listener_add
                else R.string.inbound_listener_edit))
      },
      text = {
        Column(
            modifier = Modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          val upstreamLabel =
              tailnetCandidates.firstOrNull { it.id == upstream }?.label
                  ?: stringResource(R.string.inbound_listener_upstream_unset)
          TextButton(onClick = { upstreamMenuOpen = true }) {
            Text(stringResource(R.string.inbound_listener_upstream, upstreamLabel))
          }
          DropdownMenu(
              expanded = upstreamMenuOpen, onDismissRequest = { upstreamMenuOpen = false }) {
                tailnetCandidates.forEach { candidate ->
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
              value = listenPort,
              onValueChange = { listenPort = it },
              label = { Text(stringResource(R.string.inbound_listener_listen_port)) },
              placeholder = { Text("22") },
              singleLine = true,
          )
          OutlinedTextField(
              value = localTarget,
              onValueChange = { localTarget = it },
              label = { Text(stringResource(R.string.inbound_listener_local_target)) },
              placeholder = { Text("127.0.0.1:22") },
              singleLine = true,
          )
          Row {
            Switch(checked = proxyProtocol, onCheckedChange = { proxyProtocol = it })
            Text(
                stringResource(R.string.inbound_listener_proxy_protocol),
                modifier = Modifier.padding(start = 8.dp),
            )
          }
        }
      },
      confirmButton = {
        TextButton(
            onClick = { onSave(existing?.id, upstream, listenPort, localTarget, proxyProtocol) }) {
              Text(stringResource(R.string.save))
            }
      },
      dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
  )
}
