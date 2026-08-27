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
import com.tailscale.ipn.MultiProxySessionCoordinator
import com.tailscale.ipn.UpstreamStatSnapshot
import com.tailscale.ipn.R
import com.tailscale.ipn.multiproxy.db.Upstream
import com.tailscale.ipn.multiproxy.db.UpstreamKind
import com.tailscale.ipn.ui.util.Lists
import com.tailscale.ipn.ui.viewModel.ExitNodeCandidate
import com.tailscale.ipn.ui.viewModel.RoutableUpstream
import com.tailscale.ipn.ui.viewModel.UpstreamRoutingViewModel

/**
 * Manages the non-Tailnet upstreams traffic can be routed through, and picks the one that carries
 * apps with no binding of their own.
 *
 * Tailnets are not listed here: they are managed on the Multi-Tailnet screen and appear in the
 * pickers automatically.
 */
@Composable
fun UpstreamsView(
    backToSettings: BackNavigation,
    model: UpstreamRoutingViewModel = viewModel(),
) {
  val upstreams by model.upstreams.collectAsState()
  val routable by model.routableUpstreams.collectAsState()
  val defaultUpstreamId by model.defaultUpstreamId.collectAsState()
  val defaultDNSUpstreamId by model.defaultDNSUpstreamId.collectAsState()
  val errorMessage by model.errorMessage.collectAsState()
  val broadCaptureEnabled by model.broadCaptureEnabled.collectAsState()
  val lanExclusionEnabled by model.lanExclusionEnabled.collectAsState()
  val liveStats by MultiProxySessionCoordinator.upstreamStats.collectAsState()
  val runtimeStates by MultiProxySessionCoordinator.runtimeStates.collectAsState()

  var editing by remember { mutableStateOf<Upstream?>(null) }
  var creating by remember { mutableStateOf(false) }
  var deleting by remember { mutableStateOf<Upstream?>(null) }

  errorMessage?.let { message ->
    AlertDialog(
        onDismissRequest = { model.errorMessage.value = null },
        title = { Text(stringResource(R.string.upstream_invalid)) },
        text = { Text(message) },
        confirmButton = {
          TextButton(onClick = { model.errorMessage.value = null }) {
            Text(stringResource(R.string.ok))
          }
        },
    )
  }

  deleting?.let { upstream ->
    AlertDialog(
        onDismissRequest = { deleting = null },
        title = { Text(stringResource(R.string.upstream_delete_title, upstream.label)) },
        text = { Text(stringResource(R.string.upstream_delete_explanation)) },
        confirmButton = {
          TextButton(
              onClick = {
                model.deleteUpstream(upstream.id)
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
    UpstreamEditorDialog(
        existing = editing,
        initialConfig = editing?.let { model.configFor(it.id) },
        chainCandidates = routable.filter { it.id != editing?.id },
        tailnetCandidates = routable.filter { it.kind == "tailnet" },
        fetchExitNodeCandidates = model::fetchExitNodeCandidates,
        onDismiss = {
          creating = false
          editing = null
        },
        onSaveSocks5 = { id, label, address, username, password, via ->
          model.saveSocks5(id, label, address, username, password, via)
          creating = false
          editing = null
        },
        onSaveWireGuard = { id, label, config, via ->
          model.saveWireGuard(id, label, config, via)
          creating = false
          editing = null
        },
        onSaveExitNode = { label, sourceTailnetId, authKey, peerAddr ->
          model.saveExitNode(label, sourceTailnetId, authKey, peerAddr)
          creating = false
          editing = null
        },
    )
  }

  Scaffold(
      topBar = { Header(titleRes = R.string.upstreams, onBack = backToSettings) },
      floatingActionButton = {
        FloatingActionButton(onClick = { creating = true }) {
          Icon(Icons.Default.Add, stringResource(R.string.upstream_add))
        }
      },
  ) { innerPadding ->
    LazyColumn(modifier = Modifier.padding(innerPadding)) {
      item("explanation") {
        ListItem(
            headlineContent = { Text(stringResource(R.string.upstreams_explanation)) },
        )
      }

      item("broadCapture") {
        ListItem(
            modifier = Modifier.fillMaxWidth(),
            headlineContent = { Text(stringResource(R.string.broad_capture_title)) },
            supportingContent = { Text(stringResource(R.string.broad_capture_explanation)) },
            trailingContent = {
              Switch(
                  checked = broadCaptureEnabled,
                  onCheckedChange = { model.setBroadCaptureEnabled(it) },
              )
            },
        )
        Lists.ItemDivider()
      }

      item("lanExclusion") {
        ListItem(
            modifier = Modifier.fillMaxWidth(),
            headlineContent = { Text(stringResource(R.string.lan_exclusion_title)) },
            supportingContent = { Text(stringResource(R.string.lan_exclusion_explanation)) },
            trailingContent = {
              Switch(
                  checked = lanExclusionEnabled,
                  onCheckedChange = { model.setLanExclusionEnabled(it) },
              )
            },
        )
        Lists.ItemDivider()
      }

      item("defaultHeader") { Lists.SectionDivider(stringResource(R.string.default_route)) }
      item("default") {
        UpstreamPickerRow(
            title = stringResource(R.string.unbound_apps),
            subtitle = stringResource(R.string.default_route_explanation),
            selectedId = defaultUpstreamId,
            unsetLabel = stringResource(R.string.default_route_unset),
            candidates = routable,
            onSelect = { model.setDefaultUpstream(it) },
        )
      }
      item("defaultDNS") {
        UpstreamPickerRow(
            title = stringResource(R.string.default_dns_title),
            subtitle = stringResource(R.string.default_dns_explanation),
            selectedId = defaultDNSUpstreamId,
            unsetLabel = stringResource(R.string.default_dns_unset),
            candidates = routable,
            onSelect = { model.setDefaultDNSUpstream(it) },
        )
      }

      item("upstreamsHeader") {
        Lists.SectionDivider(stringResource(R.string.count_upstreams, upstreams.count()))
      }
      if (upstreams.isEmpty()) {
        item("empty") {
          ListItem(headlineContent = { Text(stringResource(R.string.upstreams_empty)) })
        }
      } else {
        items(upstreams, key = { it.id }) { upstream ->
          val viaLabel = routable.firstOrNull { it.id == upstream.via }?.label
          val stats = liveStats[upstream.id]
          ListItem(
              modifier = Modifier.fillMaxWidth(),
              headlineContent = { Text(upstream.label, fontWeight = FontWeight.SemiBold) },
              supportingContent = {
                Column {
                  Text(
                      upstream.kind.name.lowercase(),
                      color = MaterialTheme.colorScheme.secondary,
                      fontSize = MaterialTheme.typography.bodySmall.fontSize,
                  )
                  viaLabel?.let {
                    Text(
                        stringResource(R.string.upstream_chained_via, it),
                        color = MaterialTheme.colorScheme.secondary,
                        fontSize = MaterialTheme.typography.bodySmall.fontSize,
                    )
                  }
                  UpstreamHealthLine(upstream.enabled, stats)
                  if (upstream.kind == UpstreamKind.EXITNODE) {
                    ExitNodeIdentityLine(upstream.enabled, runtimeStates[upstream.id])
                  }
                }
              },
              trailingContent = {
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                  Switch(
                      checked = upstream.enabled,
                      onCheckedChange = { model.setUpstreamEnabled(upstream.id, it) },
                  )
                }
              },
          )
          Row(modifier = Modifier.padding(start = 16.dp, bottom = 8.dp)) {
            TextButton(onClick = { editing = upstream }) { Text(stringResource(R.string.edit)) }
            TextButton(onClick = { deleting = upstream }) { Text(stringResource(R.string.delete)) }
          }
          Lists.ItemDivider()
        }
      }
    }
  }
}

/**
 * One line of live status under an upstream row: ready/degraded plus its dial counts and last
 * error, from the engine's real-time per-upstream stats (see stats.go). A switched-off upstream
 * shows nothing here - there is nothing live to report - and one that has never been dialed shows
 * only "Ready", since zero attempts is not itself a problem worth surfacing.
 */
@Composable
private fun UpstreamHealthLine(enabled: Boolean, stats: UpstreamStatSnapshot?) {
  if (!enabled || stats == null) return
  val fontSize = MaterialTheme.typography.bodySmall.fontSize
  val degraded = !stats.ready || stats.dialFailures > 0
  val color = if (degraded) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.secondary

  Column {
    val summary =
        if (stats.dialAttempts == 0L) {
          if (stats.ready) stringResource(R.string.upstream_status_ready)
          else stringResource(R.string.upstream_status_not_ready)
        } else {
          stringResource(
              R.string.upstream_status_counts,
              stats.dialSuccesses,
              stats.dialFailures,
          )
        }
    Text(summary, color = color, fontSize = fontSize)
    if (degraded && stats.lastError.isNotEmpty()) {
      Text(stats.lastError, color = color, fontSize = fontSize)
    }
  }
}

/**
 * One line under an EXITNODE-kind upstream showing its own dedicated node identity's state -
 * distinct from [UpstreamHealthLine]'s dial stats, and the only way to see a stuck identity: a
 * second auth that needs approval on its source tailnet, or whose auth key was already consumed
 * elsewhere, registers fine locally (`AddExitNodeUpstream`'s `EditPrefs` call succeeds regardless)
 * but never actually carries traffic. See `Engine.GetExitNodeStatesJSON`'s doc comment.
 */
@Composable
private fun ExitNodeIdentityLine(enabled: Boolean, state: String?) {
  if (!enabled || state.isNullOrEmpty()) return
  val fontSize = MaterialTheme.typography.bodySmall.fontSize
  val needsAttention = state == "NEEDS_MACHINE_AUTH" || state == "NEEDS_LOGIN" || state == "ERROR"
  val color = if (needsAttention) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.secondary
  val text =
      when (state) {
        "RUNNING" -> stringResource(R.string.upstream_exitnode_identity_running)
        "NEEDS_MACHINE_AUTH" -> stringResource(R.string.upstream_exitnode_identity_needs_auth)
        "NEEDS_LOGIN" -> stringResource(R.string.upstream_exitnode_identity_needs_login)
        "STARTING" -> stringResource(R.string.upstream_exitnode_identity_starting)
        else -> stringResource(R.string.upstream_exitnode_identity_other, state)
      }
  Text(text, color = color, fontSize = fontSize)
}

/** A row that shows the current upstream choice and opens a menu of the alternatives. */
@Composable
fun UpstreamPickerRow(
    title: String,
    subtitle: String?,
    selectedId: String,
    unsetLabel: String,
    candidates: List<RoutableUpstream>,
    onSelect: (String) -> Unit,
) {
  var expanded by remember { mutableStateOf(false) }
  val selected = candidates.firstOrNull { it.id == selectedId }

  ListItem(
      modifier = Modifier.fillMaxWidth(),
      headlineContent = { Text(title, fontWeight = FontWeight.SemiBold) },
      supportingContent = {
        Column {
          subtitle?.let {
            Text(
                it,
                color = MaterialTheme.colorScheme.secondary,
                fontSize = MaterialTheme.typography.bodySmall.fontSize,
            )
          }
          // An upstream that exists but is switched off is shown as such rather
          // than as unset, so a binding never looks like it was lost.
          val label =
              when {
                selectedId.isEmpty() -> unsetLabel
                selected == null -> stringResource(R.string.upstream_missing, selectedId)
                !selected.enabled -> stringResource(R.string.upstream_disabled, selected.label)
                else -> selected.label
              }
          TextButton(onClick = { expanded = true }) {
            Text(stringResource(R.string.route_via, label))
          }
          DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            DropdownMenuItem(
                text = { Text(unsetLabel) },
                onClick = {
                  expanded = false
                  onSelect("")
                },
            )
            candidates.forEach { candidate ->
              DropdownMenuItem(
                  text = {
                    Text(
                        if (candidate.enabled) candidate.label
                        else stringResource(R.string.upstream_disabled, candidate.label))
                  },
                  onClick = {
                    expanded = false
                    onSelect(candidate.id)
                  },
              )
            }
          }
        }
      },
  )
}

/** Creates or edits one upstream. */
@Composable
fun UpstreamEditorDialog(
    existing: Upstream?,
    initialConfig: String?,
    chainCandidates: List<RoutableUpstream>,
    tailnetCandidates: List<RoutableUpstream>,
    fetchExitNodeCandidates: (String) -> List<ExitNodeCandidate>,
    onDismiss: () -> Unit,
    onSaveSocks5: (String?, String, String, String, String, String) -> Unit,
    onSaveWireGuard: (String?, String, String, String) -> Unit,
    onSaveExitNode: (String, String, String, String) -> Unit,
) {
  val initial = remember(initialConfig) { parseInitialConfig(initialConfig) }

  var kind by remember { mutableStateOf(existing?.kind ?: UpstreamKind.SOCKS5) }
  var label by remember { mutableStateOf(existing?.label ?: "") }
  var via by remember { mutableStateOf(existing?.via ?: "") }
  var address by remember { mutableStateOf(initial.address) }
  var username by remember { mutableStateOf(initial.username) }
  var password by remember { mutableStateOf(initial.password) }
  var wireGuardConfig by remember { mutableStateOf(if (existing?.kind == UpstreamKind.WIREGUARD) initialConfig.orEmpty() else "") }
  var kindMenuOpen by remember { mutableStateOf(false) }
  var viaMenuOpen by remember { mutableStateOf(false) }

  // Exit-node fields. Only creation is supported (see saveExitNode's doc
  // comment) - the peer and node identity are set together once, so editing
  // an existing exit-node row shows them read-only instead of pickers.
  var exitSourceTailnetId by remember { mutableStateOf(existing?.sourceTailnetId ?: "") }
  var exitPeerAddr by remember { mutableStateOf(existing?.peerAddr ?: "") }
  var exitAuthKey by remember { mutableStateOf("") }
  var exitTailnetMenuOpen by remember { mutableStateOf(false) }
  var exitPeerMenuOpen by remember { mutableStateOf(false) }
  val exitPeerCandidates =
      remember(exitSourceTailnetId) {
        if (exitSourceTailnetId.isBlank()) emptyList()
        else fetchExitNodeCandidates(exitSourceTailnetId)
      }

  AlertDialog(
      onDismissRequest = onDismiss,
      title = {
        Text(
            stringResource(
                if (existing == null) R.string.upstream_add else R.string.upstream_edit))
      },
      text = {
        Column(
            modifier = Modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          OutlinedTextField(
              value = label,
              onValueChange = { label = it },
              label = { Text(stringResource(R.string.upstream_name)) },
              singleLine = true,
          )

          // The kind is fixed once created: changing it would mean the stored
          // configuration no longer matches the row, and re-creating is clearer.
          if (existing == null) {
            TextButton(onClick = { kindMenuOpen = true }) {
              Text(stringResource(R.string.upstream_kind, kind.name.lowercase()))
            }
            DropdownMenu(expanded = kindMenuOpen, onDismissRequest = { kindMenuOpen = false }) {
              UpstreamKind.entries.forEach { candidate ->
                DropdownMenuItem(
                    text = { Text(candidate.name.lowercase()) },
                    onClick = {
                      kind = candidate
                      kindMenuOpen = false
                    },
                )
              }
            }
          }

          when (kind) {
            UpstreamKind.SOCKS5 -> {
              OutlinedTextField(
                  value = address,
                  onValueChange = { address = it },
                  label = { Text(stringResource(R.string.upstream_address)) },
                  placeholder = { Text("127.0.0.1:10808") },
                  singleLine = true,
              )
              OutlinedTextField(
                  value = username,
                  onValueChange = { username = it },
                  label = { Text(stringResource(R.string.upstream_username_optional)) },
                  singleLine = true,
              )
              OutlinedTextField(
                  value = password,
                  onValueChange = { password = it },
                  label = { Text(stringResource(R.string.upstream_password_optional)) },
                  singleLine = true,
              )
            }
            UpstreamKind.WIREGUARD -> {
              Text(
                  stringResource(R.string.upstream_wireguard_help),
                  color = MaterialTheme.colorScheme.secondary,
                  fontSize = MaterialTheme.typography.bodySmall.fontSize,
              )
              OutlinedTextField(
                  value = wireGuardConfig,
                  onValueChange = { wireGuardConfig = it },
                  label = { Text(stringResource(R.string.upstream_wireguard_config)) },
                  minLines = 6,
              )
            }
            UpstreamKind.EXITNODE -> {
              if (existing != null) {
                Text(
                    stringResource(
                        R.string.upstream_exitnode_readonly, exitPeerAddr, exitSourceTailnetId),
                    color = MaterialTheme.colorScheme.secondary,
                    fontSize = MaterialTheme.typography.bodySmall.fontSize,
                )
              } else {
                Text(
                    stringResource(R.string.upstream_exitnode_help),
                    color = MaterialTheme.colorScheme.secondary,
                    fontSize = MaterialTheme.typography.bodySmall.fontSize,
                )
                val tailnetLabel =
                    tailnetCandidates.firstOrNull { it.id == exitSourceTailnetId }?.label
                        ?: stringResource(R.string.upstream_exitnode_source_tailnet_unset)
                TextButton(onClick = { exitTailnetMenuOpen = true }) {
                  Text(stringResource(R.string.upstream_exitnode_source_tailnet, tailnetLabel))
                }
                DropdownMenu(
                    expanded = exitTailnetMenuOpen,
                    onDismissRequest = { exitTailnetMenuOpen = false }) {
                      tailnetCandidates.forEach { candidate ->
                        DropdownMenuItem(
                            text = { Text(candidate.label) },
                            onClick = {
                              exitSourceTailnetId = candidate.id
                              exitPeerAddr = ""
                              exitTailnetMenuOpen = false
                            },
                        )
                      }
                    }

                val peerLabel =
                    exitPeerCandidates.firstOrNull { it.ip == exitPeerAddr }?.hostname
                        ?: exitPeerAddr.ifEmpty {
                          stringResource(R.string.upstream_exitnode_peer_unset)
                        }
                TextButton(
                    onClick = { exitPeerMenuOpen = true },
                    enabled = exitSourceTailnetId.isNotBlank(),
                ) {
                  Text(stringResource(R.string.upstream_exitnode_peer, peerLabel))
                }
                DropdownMenu(
                    expanded = exitPeerMenuOpen, onDismissRequest = { exitPeerMenuOpen = false }) {
                      exitPeerCandidates.forEach { candidate ->
                        DropdownMenuItem(
                            text = { Text("${candidate.hostname} (${candidate.ip})") },
                            onClick = {
                              exitPeerAddr = candidate.ip
                              exitPeerMenuOpen = false
                            },
                        )
                      }
                    }

                OutlinedTextField(
                    value = exitAuthKey,
                    onValueChange = { exitAuthKey = it },
                    label = { Text(stringResource(R.string.upstream_exitnode_auth_key)) },
                    singleLine = true,
                )
              }
            }
          }

          // Not shown for EXITNODE: its dedicated tsnet.Server dials directly
          // (upstream_exitnode.go), the same as a Tailnet upstream - neither
          // implements ChainedProvider, so there is no via for onSaveExitNode
          // to apply. Showing this picker anyway would silently discard
          // whatever the user picked.
          if (kind != UpstreamKind.EXITNODE) {
            val viaLabel =
                chainCandidates.firstOrNull { it.id == via }?.label
                    ?: stringResource(R.string.upstream_chain_none)
            TextButton(onClick = { viaMenuOpen = true }) {
              Text(stringResource(R.string.upstream_chain_through, viaLabel))
            }
            DropdownMenu(expanded = viaMenuOpen, onDismissRequest = { viaMenuOpen = false }) {
              DropdownMenuItem(
                  text = { Text(stringResource(R.string.upstream_chain_none)) },
                  onClick = {
                    via = ""
                    viaMenuOpen = false
                  },
              )
              chainCandidates.forEach { candidate ->
                DropdownMenuItem(
                    text = { Text(candidate.label) },
                    onClick = {
                      via = candidate.id
                      viaMenuOpen = false
                    },
                )
              }
            }
          }
        }
      },
      confirmButton = {
        TextButton(
            enabled = kind != UpstreamKind.EXITNODE || existing == null,
            onClick = {
              when (kind) {
                UpstreamKind.SOCKS5 ->
                    onSaveSocks5(existing?.id, label, address, username, password, via)
                UpstreamKind.WIREGUARD ->
                    onSaveWireGuard(existing?.id, label, wireGuardConfig, via)
                UpstreamKind.EXITNODE ->
                    onSaveExitNode(label, exitSourceTailnetId, exitAuthKey, exitPeerAddr)
              }
            }) {
              Text(stringResource(R.string.save))
            }
      },
      dismissButton = {
        TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
      },
  )
}

private data class InitialSocks5(
    val address: String = "",
    val username: String = "",
    val password: String = "",
)

/**
 * Prefills the SOCKS5 fields from a stored configuration.
 *
 * A configuration that will not parse yields empty fields rather than throwing: the editor is
 * exactly where the user would go to fix one, so it must open.
 */
private fun parseInitialConfig(configJson: String?): InitialSocks5 {
  if (configJson.isNullOrBlank()) return InitialSocks5()
  return try {
    val json = org.json.JSONObject(configJson)
    InitialSocks5(
        address = json.optString("address"),
        username = json.optString("username"),
        password = json.optString("password"),
    )
  } catch (e: Exception) {
    InitialSocks5()
  }
}
