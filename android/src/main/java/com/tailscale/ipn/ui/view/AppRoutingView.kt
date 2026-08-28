// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
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
 * all. An app can be inside the VPN and still need to reach the Internet through a particular exit -
 * a Tailnet, a proxy core, or a WireGuard tunnel - and that is what this screen decides.
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

  val defaultLabel =
      routable.firstOrNull { it.id == defaultUpstreamId }?.label
          ?: stringResource(R.string.default_route_unset)

  Scaffold(topBar = { Header(titleRes = R.string.app_routing, onBack = backToSettings) }) {
      innerPadding ->
    LazyColumn(modifier = Modifier.padding(innerPadding)) {
      item("explanation") {
        ListItem(headlineContent = { Text(stringResource(R.string.app_routing_explanation)) })
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
      } else {
        items(installedApps, key = { it.packageName }) { app ->
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
          Lists.ItemDivider()
        }
      }
    }
  }
}
