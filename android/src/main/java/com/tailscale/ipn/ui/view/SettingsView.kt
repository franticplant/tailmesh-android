// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.viewmodel.compose.viewModel
import com.tailscale.ipn.BuildConfig
import com.tailscale.ipn.R
import com.tailscale.ipn.mdm.AlwaysNeverUserDecides
import com.tailscale.ipn.mdm.MDMSettings
import com.tailscale.ipn.mdm.ShowHide
import com.tailscale.ipn.ui.Links
import com.tailscale.ipn.ui.theme.link
import com.tailscale.ipn.ui.theme.listItem
import com.tailscale.ipn.ui.util.AndroidTVUtil
import com.tailscale.ipn.ui.util.AndroidTVUtil.isAndroidTV
import com.tailscale.ipn.ui.util.AppVersion
import com.tailscale.ipn.ui.util.Lists
import com.tailscale.ipn.ui.util.set
import com.tailscale.ipn.ui.viewModel.AppViewModel
import com.tailscale.ipn.ui.viewModel.SettingsNav
import com.tailscale.ipn.ui.viewModel.SettingsViewModel

@Composable
fun SettingsView(
    settingsNav: SettingsNav,
    viewModel: SettingsViewModel = viewModel(),
    appViewModel: AppViewModel = viewModel()
) {
  val handler = LocalUriHandler.current

  val user by viewModel.loggedInUser.collectAsState()
  val isAdmin by viewModel.isAdmin.collectAsState()
  val managedByOrganization by viewModel.managedByOrganization.collectAsState()
  val tailnetLockEnabled by viewModel.tailNetLockEnabled.collectAsState()
  val corpDNSEnabled by viewModel.corpDNSEnabled.collectAsState()
  val isVPNPrepared by appViewModel.vpnPrepared.collectAsState()
  val showTailnetLock by MDMSettings.manageTailnetLock.flow.collectAsState()
  val useTailscaleSubnets by MDMSettings.useTailscaleSubnets.flow.collectAsState()
  val isClientRemoteLoggingEnabled by viewModel.isClientRemoteLoggingEnabled.collectAsState()
  val controlProxyURL by viewModel.controlProxyURL.collectAsState()
  val debugHTTPProxyLogging by viewModel.debugHTTPProxyLogging.collectAsState()
  val debugDNSConfigLogging by viewModel.debugDNSConfigLogging.collectAsState()
  val debugDNSQueryLogging by viewModel.debugDNSQueryLogging.collectAsState()
  var showDisableLoggingDialog by remember { mutableStateOf(false) }
  var showControlProxyDialog by remember { mutableStateOf(false) }
  var controlProxyDraft by remember(controlProxyURL) { mutableStateOf(controlProxyURL) }

  Scaffold(
      topBar = {
        Header(titleRes = R.string.settings_title, onBack = settingsNav.onNavigateBackHome)
      }) { innerPadding ->
        Column(modifier = Modifier.padding(innerPadding).verticalScroll(rememberScrollState())) {
          if (isVPNPrepared) {
            UserView(
                profile = user,
                actionState = UserActionState.NAV,
                onClick = settingsNav.onNavigateToUserSwitcher)
          }

          if (isAdmin && !isAndroidTV()) {
            Lists.ItemDivider()
            AdminTextView { handler.openUri(Links.ADMIN_URL) }
          }

          Lists.SectionDivider()
          Setting.Text(
              R.string.dns_settings,
              subtitle =
                  corpDNSEnabled?.let {
                    stringResource(
                        if (it) R.string.using_tailscale_dns else R.string.not_using_tailscale_dns)
                  },
              onClick = settingsNav.onNavigateToDNSSettings)

          Lists.ItemDivider()
          Setting.Text(
              title = "Network Diagnostics",
              subtitle = "Live NAT type, DERP latency, and firewall health",
              onClick = settingsNav.onNavigateToNetcheck)

          Lists.ItemDivider()
          Setting.Text(
              title = "Upstreams (Experimental)",
              subtitle = "Choose one Standard upstream or enable multiple proxy upstreams",
              onClick = settingsNav.onNavigateToMultiProxy)

          // Routing through things that are not Tailnets. Kept next to the
          // Multi-Tailnet entry because they are the same decision from the
          // user's side - where does traffic go - and separate from split
          // tunneling, which decides only whether an app uses the VPN at all.
          Lists.ItemDivider()
          Setting.Text(
              R.string.upstreams,
              subtitle = stringResource(R.string.upstreams_subtitle),
              onClick = settingsNav.onNavigateToProxyUpstreams)

          Lists.ItemDivider()
          Setting.Text(
              R.string.app_routing,
              subtitle = stringResource(R.string.app_routing_subtitle),
              onClick = settingsNav.onNavigateToAppRouting)

          Lists.ItemDivider()
          Setting.Switch(
              title = "Proxy-Only Mode (No VPN)",
              subtitle = "Connect to Tailnet without intercepting device traffic",
              isOn = viewModel.userspaceOnlyMode.collectAsState().value,
              onToggle = { viewModel.toggleUserspaceOnlyMode() })

          Lists.ItemDivider()
          Setting.Switch(
              title = "Local Proxy Listener",
              subtitle = "Serve a SOCKS5/HTTP proxy locally",
              isOn = viewModel.localProxyEnabled.collectAsState().value,
              onToggle = { viewModel.toggleLocalProxyListener() })

          if (viewModel.localProxyEnabled.collectAsState().value) {
            Lists.ItemDivider()
            var localProxyDraft by remember { mutableStateOf<String>(viewModel.localProxyAddress.value) }
            var showLocalProxyDialog by remember { mutableStateOf(false) }

            Setting.Text(
                title = "Local Proxy Address",
                subtitle = viewModel.localProxyAddress.collectAsState().value,
                onClick = {
                    localProxyDraft = viewModel.localProxyAddress.value
                    showLocalProxyDialog = true
                })

            if (showLocalProxyDialog) {
                AlertDialog(
                    onDismissRequest = { showLocalProxyDialog = false },
                    title = { Text("Local Proxy Address") },
                    text = {
                        Column {
                            Text("Configure the address and port where the proxy listens (e.g. 127.0.0.1:1055)")
                            OutlinedTextField(
                                value = localProxyDraft,
                                onValueChange = { localProxyDraft = it },
                                label = { Text("Address") },
                                singleLine = true
                            )
                        }
                    },
                    confirmButton = {
                        TextButton(onClick = {
                            viewModel.updateLocalProxyAddress(localProxyDraft)
                            showLocalProxyDialog = false
                        }) { Text(stringResource(R.string.save)) }
                    },
                    dismissButton = {
                        TextButton(onClick = { showLocalProxyDialog = false }) {
                            Text(stringResource(R.string.cancel))
                        }
                    }
                )
            }
          }

          Lists.ItemDivider()
          Setting.Text(
              R.string.control_proxy,
              subtitle =
                  if (controlProxyURL.isBlank()) stringResource(R.string.disabled)
                  else controlProxyURL,
              onClick = {
                controlProxyDraft = controlProxyURL
                showControlProxyDialog = true
              })

          Lists.ItemDivider()
          Setting.Text(
              R.string.split_tunneling,
              subtitle = stringResource(R.string.filter_apps_allowed_to_access_tailscale),
              onClick = settingsNav.onNavigateToSplitTunneling)

          if (showTailnetLock.value == ShowHide.Show) {
            Lists.ItemDivider()
            Setting.Text(
                R.string.tailnet_lock,
                subtitle =
                    tailnetLockEnabled?.let {
                      stringResource(if (it) R.string.enabled else R.string.disabled)
                    },
                onClick = settingsNav.onNavigateToTailnetLock)
          }
          if (useTailscaleSubnets.value == AlwaysNeverUserDecides.UserDecides) {
            Lists.ItemDivider()
            Setting.Text(R.string.subnet_routing, onClick = settingsNav.onNavigateToSubnetRouting)
          }

          Lists.ItemDivider()
          Setting.Switch(
              R.string.client_remote_logging_enabled,
              subtitle =
                  stringResource(
                      if (MDMSettings.isMDMConfigured)
                          R.string.client_remote_logging_enabled_subtitle_mdm
                      else R.string.client_remote_logging_enabled_subtitle),
              isOn = isClientRemoteLoggingEnabled,
              enabled = !MDMSettings.isMDMConfigured,
              onToggle = {
                if (isClientRemoteLoggingEnabled) {
                  showDisableLoggingDialog = true
                } else {
                  viewModel.toggleIsClientRemoteLoggingEnabled()
                }
              })

          Lists.ItemDivider()
          Setting.Switch(
              R.string.debug_http_proxy_logging,
              subtitle = stringResource(R.string.debug_http_proxy_logging_subtitle),
              isOn = debugHTTPProxyLogging,
              onToggle = { viewModel.toggleDebugHTTPProxyLogging() })

          Lists.ItemDivider()
          Setting.Switch(
              R.string.debug_dns_config_logging,
              subtitle = stringResource(R.string.debug_dns_config_logging_subtitle),
              isOn = debugDNSConfigLogging,
              onToggle = { viewModel.toggleDebugDNSConfigLogging() })

          Lists.ItemDivider()
          Setting.Switch(
              R.string.debug_dns_query_logging,
              subtitle = stringResource(R.string.debug_dns_query_logging_subtitle),
              isOn = debugDNSQueryLogging,
              onToggle = { viewModel.toggleDebugDNSQueryLogging() })

          if (!AndroidTVUtil.isAndroidTV()) {
            Lists.ItemDivider()
            Setting.Text(R.string.permissions, onClick = settingsNav.onNavigateToPermissions)
          }

          managedByOrganization.value?.let {
            Lists.ItemDivider()
            Setting.Text(
                title = stringResource(R.string.managed_by_orgName, it),
                onClick = settingsNav.onNavigateToManagedBy)
          }

          Lists.SectionDivider()
          Setting.Text(R.string.bug_report, onClick = settingsNav.onNavigateToBugReport)

          Lists.ItemDivider()
          Setting.Text(
              R.string.about_tailscale,
              subtitle = "${stringResource(id = R.string.version)} ${AppVersion.Short()}",
              onClick = settingsNav.onNavigateToAbout)

          // TODO: put a heading for the debug section
          if (BuildConfig.DEBUG) {
            Lists.SectionDivider()
            Lists.MutedHeader(text = stringResource(R.string.internal_debug_options))
            Setting.Text(R.string.mdm_settings, onClick = settingsNav.onNavigateToMDMSettings)
          }
        }
      }

  if (showControlProxyDialog) {
    AlertDialog(
        onDismissRequest = { showControlProxyDialog = false },
        title = { Text(stringResource(R.string.control_proxy)) },
        text = {
          Column {
            Text(stringResource(R.string.control_proxy_explainer))
            OutlinedTextField(
                value = controlProxyDraft,
                onValueChange = { controlProxyDraft = it },
                label = { Text(stringResource(R.string.control_proxy_url)) },
                placeholder = { Text(stringResource(R.string.control_proxy_placeholder)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
          }
        },
        confirmButton = {
          TextButton(
              onClick = {
                viewModel.updateControlProxyURL(controlProxyDraft)
                showControlProxyDialog = false
              }) {
                Text(stringResource(R.string.save))
              }
        },
        dismissButton = {
          TextButton(onClick = { showControlProxyDialog = false }) {
            Text(stringResource(R.string.cancel))
          }
        })
  }

  if (showDisableLoggingDialog) {
    AlertDialog(
        onDismissRequest = { showDisableLoggingDialog = false },
        title = { Text(stringResource(R.string.client_remote_logging_disable_confirm_title)) },
        text = { Text(stringResource(R.string.client_remote_logging_disable_confirm_message)) },
        confirmButton = {
          TextButton(
              onClick = {
                showDisableLoggingDialog = false
                viewModel.toggleIsClientRemoteLoggingEnabled()
              }) {
                Text(
                    stringResource(R.string.client_remote_logging_disable_confirm_button),
                    color = MaterialTheme.colorScheme.error)
              }
        },
        dismissButton = {
          TextButton(onClick = { showDisableLoggingDialog = false }) {
            Text(stringResource(R.string.cancel))
          }
        })
  }
}

object Setting {
  @Composable
  fun Text(
      titleRes: Int = 0,
      title: String? = null,
      subtitle: String? = null,
      destructive: Boolean = false,
      enabled: Boolean = true,
      onClick: (() -> Unit)? = null
  ) {
    var modifier: Modifier = Modifier
    if (enabled) {
      onClick?.let { modifier = modifier.clickable(onClick = it) }
    }
    ListItem(
        modifier = modifier,
        colors = MaterialTheme.colorScheme.listItem,
        headlineContent = {
          Text(
              title ?: stringResource(titleRes),
              style = MaterialTheme.typography.bodyMedium,
              color = if (destructive) MaterialTheme.colorScheme.error else Color.Unspecified)
        },
        supportingContent =
            subtitle?.let {
              {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
              }
            })
  }

  @Composable
  fun Switch(
      titleRes: Int = 0,
      title: String? = null,
      subtitle: String? = null,
      isOn: Boolean,
      enabled: Boolean = true,
      onToggle: (Boolean) -> Unit = {}
  ) {
    ListItem(
        colors = MaterialTheme.colorScheme.listItem,
        headlineContent = {
          Text(
              title ?: stringResource(titleRes),
              style = MaterialTheme.typography.bodyMedium,
          )
        },
        supportingContent =
            subtitle?.let {
              {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
              }
            },
        trailingContent = {
          TintedSwitch(checked = isOn, onCheckedChange = onToggle, enabled = enabled)
        })
  }
}

@Composable
fun AdminTextView(onNavigateToAdminConsole: () -> Unit) {
  val adminStr = buildAnnotatedString {
    append(stringResource(id = R.string.settings_admin_prefix))

    pushStringAnnotation(tag = "link", annotation = Links.ADMIN_URL)
    withStyle(
        style =
            SpanStyle(
                color = MaterialTheme.colorScheme.link,
                textDecoration = TextDecoration.Underline)) {
          append(stringResource(id = R.string.settings_admin_link))
        }
  }

  Lists.InfoItem(adminStr, onClick = onNavigateToAdminConsole)
}

@Preview
@Composable
fun SettingsPreview() {
  val vm = SettingsViewModel()
  vm.corpDNSEnabled.set(true)
  vm.tailNetLockEnabled.set(true)
  vm.isAdmin.set(true)
  vm.managedByOrganization.set("Tails and Scales Inc.")
  SettingsView(SettingsNav({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}), vm)
}
