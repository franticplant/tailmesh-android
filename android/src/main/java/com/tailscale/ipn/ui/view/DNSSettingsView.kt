// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.tailscale.ipn.R
import com.tailscale.ipn.mdm.MDMSettings
import com.tailscale.ipn.ui.model.DnsType
import com.tailscale.ipn.ui.model.PublicDoHProviders
import com.tailscale.ipn.ui.notifier.Notifier
import com.tailscale.ipn.ui.util.ClipboardValueView
import com.tailscale.ipn.ui.util.Lists
import com.tailscale.ipn.ui.util.LoadingIndicator
import com.tailscale.ipn.ui.util.itemsWithDividers
import com.tailscale.ipn.ui.util.set
import com.tailscale.ipn.ui.viewModel.DNSEnablementState
import com.tailscale.ipn.ui.viewModel.DNSSettingsViewModel
import com.tailscale.ipn.ui.viewModel.DNSSettingsViewModelFactory

data class ViewableRoute(val name: String, val resolvers: List<DnsType.Resolver>)

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun DNSSettingsView(
    backToSettings: BackNavigation,
    model: DNSSettingsViewModel = viewModel(factory = DNSSettingsViewModelFactory())
) {
  val state: DNSEnablementState by model.enablementState.collectAsState()
  val resolvers = model.dnsConfig.collectAsState().value?.Resolvers ?: emptyList()
  val domains = model.dnsConfig.collectAsState().value?.Domains ?: emptyList()
  val routes: List<ViewableRoute> =
      model.dnsConfig.collectAsState().value?.Routes?.mapNotNull { entry ->
        entry.value?.let { resolvers -> ViewableRoute(name = entry.key, resolvers) } ?: run { null }
      } ?: emptyList()
  val useCorpDNS = Notifier.prefs.collectAsState().value?.CorpDNS == true
  val dnsSettingsMDMDisposition by MDMSettings.useTailscaleDNSSettings.flow.collectAsState()
  val publicDoHURL by model.publicDoHURL.collectAsState()
  val publicDoHOverrideExitNode by model.publicDoHOverrideExitNode.collectAsState()
  val publicDoHRouteThroughTailscale by model.publicDoHRouteThroughTailscale.collectAsState()
  val isMultiProxy by model.isMultiProxy.collectAsState()
  // These three prefs are read only by Standard mode's DNS manager. Say so instead of
  // leaving switches that look live but change nothing.
  val standardOnlyNote = if (isMultiProxy) stringResource(R.string.standard_mode_only) else null
  var showPublicDoHDialog by remember { mutableStateOf(false) }
  val isKnownPublicDoHURL =
      publicDoHURL.isBlank() ||
          PublicDoHProviders.grouped.any { provider ->
            provider.endpoints.any { it.url == publicDoHURL }
          }
  var customDoHURL by
      remember(publicDoHURL) { mutableStateOf(if (isKnownPublicDoHURL) "" else publicDoHURL) }

  Scaffold(topBar = { Header(R.string.dns_settings, onBack = backToSettings) }) { innerPadding ->
    LoadingIndicator.Wrap {
      LazyColumn(Modifier.padding(innerPadding)) {
        item("state") {
          ListItem(
              leadingContent = {
                Icon(
                    painter = painterResource(state.symbolDrawable),
                    contentDescription = null,
                    tint = state.tint(),
                    modifier = Modifier.size(36.dp))
              },
              headlineContent = {
                Text(stringResource(state.title), style = MaterialTheme.typography.titleMedium)
              },
              supportingContent = { Text(stringResource(state.caption)) })

          if (!dnsSettingsMDMDisposition.value.hiddenFromUser) {
            Lists.ItemDivider()
            Setting.Switch(
                R.string.use_ts_dns,
                subtitle = standardOnlyNote,
                isOn = useCorpDNS,
                enabled = !isMultiProxy,
                onToggle = {
                  LoadingIndicator.start()
                  model.toggleCorpDNS { LoadingIndicator.stop() }
                })
          }
        }

        item("publicDoHHeader") { Lists.SectionDivider(stringResource(R.string.public_doh)) }

        item("publicDoHResolver") {
          Setting.Text(
              R.string.public_doh_resolver,
              subtitle = PublicDoHProviders.labelFor(publicDoHURL),
              onClick = { showPublicDoHDialog = true })
        }

        item("publicDoHOverrideExit") {
          Lists.ItemDivider()
          Setting.Switch(
              R.string.public_doh_override_exit_node,
              subtitle =
                  standardOnlyNote
                      ?: stringResource(R.string.public_doh_override_exit_node_subtitle),
              isOn = publicDoHOverrideExitNode,
              enabled = publicDoHURL.isNotBlank() && !isMultiProxy,
              onToggle = { model.togglePublicDoHOverrideExitNode() })
        }

        item("publicDoHRoute") {
          Lists.ItemDivider()
          Setting.Switch(
              R.string.public_doh_route_through_tailscale,
              subtitle =
                  standardOnlyNote
                      ?: stringResource(R.string.public_doh_route_through_tailscale_subtitle),
              isOn = publicDoHRouteThroughTailscale,
              enabled = publicDoHURL.isNotBlank() && !isMultiProxy,
              onToggle = { model.togglePublicDoHRouteThroughTailscale() })
        }

        if (resolvers.isNotEmpty()) {
          item("resolversHeader") { Lists.SectionDivider(stringResource(R.string.resolvers)) }

          itemsWithDividers(resolvers) { resolver -> ClipboardValueView(resolver.Addr.orEmpty()) }
        }

        if (domains.isNotEmpty()) {
          item("domainsHeader") { Lists.SectionDivider(stringResource(R.string.search_domains)) }

          itemsWithDividers(domains) { domain -> ClipboardValueView(domain) }
        }

        if (routes.isNotEmpty()) {
          routes.forEach { route ->
            item { Lists.SectionDivider("Route: ${route.name}") }

            itemsWithDividers(route.resolvers) { resolver ->
              ClipboardValueView(resolver.Addr.orEmpty())
            }
          }
        }
      }
    }
  }

  if (showPublicDoHDialog) {
    AlertDialog(
        onDismissRequest = { showPublicDoHDialog = false },
        title = { Text(stringResource(R.string.public_doh_resolver)) },
        text = {
          LazyColumn {
            item("off") {
              ListItem(
                  modifier =
                      Modifier.clickable {
                        model.updatePublicDoHURL(PublicDoHProviders.OFF)
                        showPublicDoHDialog = false
                      },
                  headlineContent = { Text(stringResource(R.string.tailnet_default)) },
                  supportingContent = { Text(stringResource(R.string.public_doh_off_subtitle)) })
            }
            PublicDoHProviders.grouped.forEach { provider ->
              item("provider-${provider.name}") { Lists.SectionDivider(provider.name) }
              itemsWithDividers(provider.endpoints) { endpoint ->
                ListItem(
                    modifier =
                        Modifier.clickable {
                          model.updatePublicDoHURL(endpoint.url)
                          showPublicDoHDialog = false
                        },
                    headlineContent = { Text(endpoint.label) },
                    supportingContent = { Text(endpoint.url) })
              }
            }
            item("customHeader") {
              Lists.SectionDivider(stringResource(R.string.public_doh_custom))
            }
            item("customEntry") {
              Column(modifier = Modifier.padding(16.dp)) {
                OutlinedTextField(
                    value = customDoHURL,
                    onValueChange = { customDoHURL = it },
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text(stringResource(R.string.public_doh_custom_url_hint)) },
                    singleLine = true)
                Text(
                    stringResource(R.string.public_doh_custom_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 4.dp, bottom = 8.dp))
                Row {
                  TextButton(
                      enabled = customDoHURL.isNotBlank(),
                      onClick = {
                        model.updatePublicDoHURL(customDoHURL.trim())
                        showPublicDoHDialog = false
                      }) {
                        Text(stringResource(R.string.use))
                      }
                }
              }
            }
          }
        },
        confirmButton = {},
        dismissButton = {
          TextButton(onClick = { showPublicDoHDialog = false }) {
            Text(stringResource(R.string.cancel))
          }
        })
  }
}

@Preview
@Composable
fun DNSSettingsViewPreview() {
  val vm = DNSSettingsViewModel()
  vm.enablementState.set(DNSEnablementState.ENABLED)
  DNSSettingsView(backToSettings = {}, vm)
}
