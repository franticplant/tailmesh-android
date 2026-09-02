// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.viewmodel.compose.viewModel
import com.tailscale.ipn.R
import com.tailscale.ipn.ui.util.Lists
import com.tailscale.ipn.ui.viewModel.SplitTunnelAppPickerViewModel
import com.tailscale.ipn.ui.viewModel.UpstreamRoutingViewModel

/**
 * Chooses which upstream each installed app's traffic takes.
 *
 * This is a different question from split tunnelling, which is about whether an app uses the VPN at
 * all. An app can be inside the VPN and still need to reach the Internet through a particular
 * exit - a Tailnet, a proxy core, or a WireGuard tunnel - and that is what this screen decides.
 *
 * An app with no choice made here keeps today's behaviour, which is what the "Default" route on the
 * Upstreams screen governs.
 */
@Composable
fun AppRoutingView(
    backToSettings: BackNavigation,
    appModel: SplitTunnelAppPickerViewModel = viewModel(),
    model: UpstreamRoutingViewModel = viewModel(),
) {
  val installedApps by appModel.installedApps.collectAsState()
  val bindings by model.bindings.collectAsState()
  val routable by model.routableUpstreams.collectAsState()
  val defaultUpstreamId by model.defaultUpstreamId.collectAsState()
  val lanExclusionEnabled by model.lanExclusionEnabled.collectAsState()

  // Screen-local, not persisted: a search/filter state that outlives this view isn't useful, and
  // rememberSaveable keeps it across rotation without needing a ViewModel round-trip.
  var searchQuery by rememberSaveable { mutableStateOf("") }
  var hideSystemApps by rememberSaveable { mutableStateOf(false) }
  var customizedOnly by rememberSaveable { mutableStateOf(false) }

  val filteredApps =
      installedApps.filter { app ->
        (!hideSystemApps || !app.isSystemApp) &&
            (!customizedOnly || bindings.containsKey(app.packageName)) &&
            (searchQuery.isBlank() ||
                app.name.contains(searchQuery, ignoreCase = true) ||
                app.packageName.contains(searchQuery, ignoreCase = true))
      }

  val defaultLabel =
      routable.firstOrNull { it.id == defaultUpstreamId }?.label
          ?: stringResource(R.string.default_route_unset)

  Scaffold(topBar = { Header(titleRes = R.string.app_routing, onBack = backToSettings) }) {
      innerPadding ->
    LazyColumn(modifier = Modifier.padding(innerPadding)) {
      item("explanation") {
        ListItem(headlineContent = { Text(stringResource(R.string.app_routing_explanation)) })
      }
      item("search") {
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            placeholder = { Text(stringResource(R.string.app_routing_search_hint)) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
            singleLine = true,
        )
      }
      item("filters") {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          FilterChip(
              selected = hideSystemApps,
              onClick = { hideSystemApps = !hideSystemApps },
              label = { Text(stringResource(R.string.app_routing_hide_system_apps)) },
          )
          FilterChip(
              selected = customizedOnly,
              onClick = { customizedOnly = !customizedOnly },
              label = { Text(stringResource(R.string.app_routing_customized_only)) },
          )
        }
      }
      item("appsHeader") {
        Lists.SectionDivider(
            stringResource(R.string.count_bound_apps, bindings.count(), installedApps.count()))
      }

      if (installedApps.isEmpty()) {
        item("spinner") {
          Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator(
                modifier = Modifier.width(64.dp),
                color = MaterialTheme.colorScheme.secondary,
                trackColor = MaterialTheme.colorScheme.surfaceVariant,
            )
          }
        }
      } else if (filteredApps.isEmpty()) {
        item("noMatches") {
          ListItem(headlineContent = { Text(stringResource(R.string.app_routing_no_apps_match)) })
        }
      } else {
        items(filteredApps, key = { it.packageName }) { app ->
          val binding = bindings[app.packageName]
          ListItem(
              headlineContent = { Text(app.name) },
              leadingContent = {
                Image(
                    bitmap =
                        appModel.installedAppsManager.packageManager
                            .getApplicationIcon(app.packageName)
                            .toBitmap()
                            .asImageBitmap(),
                    contentDescription = null,
                    modifier = Modifier.width(40.dp).height(40.dp),
                )
              },
          )
          UpstreamPickerRow(
              title = app.packageName,
              subtitle = null,
              selectedId = binding?.upstreamId.orEmpty(),
              // Unbinding is spelled as "follow the default" because that is what
              // it does; "none" would read as "no network".
              unsetLabel = stringResource(R.string.route_default, defaultLabel),
              candidates = routable,
              onSelect = { id ->
                if (id.isEmpty()) model.unbindApp(app.packageName)
                else model.bindApp(app.packageName, id)
              },
          )
          // Only meaningful once the app has an explicit data route: the engine
          // has nothing to attach a DNS-only override to otherwise (see
          // AppBindingRepository.setDNSUpstream's doc comment).
          if (!binding?.upstreamId.isNullOrEmpty()) {
            UpstreamPickerRow(
                title = stringResource(R.string.app_dns_title),
                subtitle = null,
                selectedId = binding?.dnsUpstreamId.orEmpty(),
                unsetLabel = stringResource(R.string.app_dns_unset),
                candidates = routable,
                onSelect = { id -> model.setAppDNSUpstream(app.packageName, id) },
                buttonFormatRes = R.string.app_dns_via,
            )
          }
          // Only meaningful with both a data route to tunnel LAN traffic through
          // (same constraint as the DNS picker above) and the global exclusion
          // actually on - with it off, LAN traffic already follows the app's
          // normal binding, so there is nothing for this to override.
          if (!binding?.upstreamId.isNullOrEmpty() && lanExclusionEnabled) {
            ListItem(
                modifier = Modifier.fillMaxWidth(),
                headlineContent = { Text(stringResource(R.string.app_tunnel_lan_title)) },
                trailingContent = {
                  Switch(
                      checked = binding?.tunnelLan == true,
                      onCheckedChange = { model.setAppTunnelLAN(app.packageName, it) },
                  )
                },
            )
          }
          Lists.ItemDivider()
        }
      }
    }
  }
}
