// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.viewModel

import androidx.lifecycle.viewModelScope
import com.tailscale.ipn.App
import com.tailscale.ipn.ui.localapi.Client
import com.tailscale.ipn.ui.notifier.Notifier
import com.tailscale.ipn.ui.util.LoadingIndicator
import com.tailscale.ipn.ui.util.set
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import libtailscale.Libtailscale

data class SettingsNav(
    val onNavigateToBugReport: () -> Unit,
    val onNavigateToAbout: () -> Unit,
    val onNavigateToDNSSettings: () -> Unit,
    val onNavigateToSplitTunneling: () -> Unit,
    val onNavigateToTailnetLock: () -> Unit,
    val onNavigateToSubnetRouting: () -> Unit,
    val onNavigateToMDMSettings: () -> Unit,
    val onNavigateToManagedBy: () -> Unit,
    val onNavigateToUserSwitcher: () -> Unit,
    val onNavigateToPermissions: () -> Unit,
    val onNavigateToNetcheck: () -> Unit,
    val onNavigateToMultiProxy: () -> Unit,
    val onNavigateBackHome: () -> Unit,
    val onBackToSettings: () -> Unit,
)

class SettingsViewModel : IpnViewModel() {
  companion object {
    const val CONTROL_PROXY_URL_KEY = "controlProxyURL"
    const val DEBUG_HTTP_PROXY_LOGGING_KEY = "debugHTTPProxyLogging"
    const val DEBUG_DNS_CONFIG_LOGGING_KEY = "debugDNSConfigLogging"
    const val DEBUG_DNS_QUERY_LOGGING_KEY = "debugDNSQueryLogging"
  }

  // Display name for the logged in user
  val isAdmin: StateFlow<Boolean> = MutableStateFlow(false)
  // True if tailnet lock is enabled.  nil if not yet known.
  val tailNetLockEnabled: StateFlow<Boolean?> = MutableStateFlow(null)
  // True if tailscaleDNS is enabled. nil if not yet known.
  val corpDNSEnabled: StateFlow<Boolean?> = MutableStateFlow(null)
  val isClientRemoteLoggingEnabled: StateFlow<Boolean> = MutableStateFlow(true)
  val controlProxyURL: StateFlow<String> = MutableStateFlow("")
  val debugHTTPProxyLogging: StateFlow<Boolean> = MutableStateFlow(false)
  val debugDNSConfigLogging: StateFlow<Boolean> = MutableStateFlow(false)
  val debugDNSQueryLogging: StateFlow<Boolean> = MutableStateFlow(false)
  val localProxyEnabled = MutableStateFlow((App.get().decryptFromPref("localProxyEnabled") ?: "false").toBoolean())
  val localProxyAddress = MutableStateFlow(App.get().decryptFromPref("localProxyAddress") ?: "127.0.0.1:1055")
  val userspaceOnlyMode = MutableStateFlow((App.get().decryptFromPref("userspaceOnlyMode") ?: "false").toBoolean())

  init {
    isClientRemoteLoggingEnabled.set(App.get().isClientLoggingEnabled())
    controlProxyURL.set(App.get().decryptFromPref(CONTROL_PROXY_URL_KEY) ?: "")
    debugHTTPProxyLogging.set(readEncryptedBool(DEBUG_HTTP_PROXY_LOGGING_KEY, false))
    debugDNSConfigLogging.set(readEncryptedBool(DEBUG_DNS_CONFIG_LOGGING_KEY, false))
    debugDNSQueryLogging.set(readEncryptedBool(DEBUG_DNS_QUERY_LOGGING_KEY, false))
    userspaceOnlyMode.set(readEncryptedBool("userspaceOnlyMode", false))

    viewModelScope.launch {
      Notifier.netmap.collect { netmap -> isAdmin.set(netmap?.SelfNode?.isAdmin ?: false) }
    }

    Client(viewModelScope).tailnetLockStatus { result ->
      result.onSuccess { status -> tailNetLockEnabled.set(status.Enabled) }

      LoadingIndicator.stop()
    }

    viewModelScope.launch {
      Notifier.prefs.collect {
        it?.let { corpDNSEnabled.set(it.CorpDNS) } ?: run { corpDNSEnabled.set(null) }
      }
    }
  }

  fun toggleIsClientRemoteLoggingEnabled() {
    isClientRemoteLoggingEnabled.set(!isClientRemoteLoggingEnabled.value)
    App.get().updateIsClientLoggingEnabled(isClientRemoteLoggingEnabled.value)
  }

  fun updateControlProxyURL(proxyURL: String) {
    val trimmed = proxyURL.trim()
    App.get().encryptToPref(CONTROL_PROXY_URL_KEY, trimmed)
    controlProxyURL.set(trimmed)
  }

  fun toggleDebugHTTPProxyLogging() {
    val next = !debugHTTPProxyLogging.value
    App.get().encryptToPref(DEBUG_HTTP_PROXY_LOGGING_KEY, next.toString())
    debugHTTPProxyLogging.set(next)
    applyNetworkDebugLoggingSettings()
  }

  fun toggleDebugDNSConfigLogging() {
    val next = !debugDNSConfigLogging.value
    App.get().encryptToPref(DEBUG_DNS_CONFIG_LOGGING_KEY, next.toString())
    debugDNSConfigLogging.set(next)
    applyNetworkDebugLoggingSettings()
  }

  fun toggleDebugDNSQueryLogging() {
    val next = !debugDNSQueryLogging.value
    App.get().encryptToPref(DEBUG_DNS_QUERY_LOGGING_KEY, next.toString())
    debugDNSQueryLogging.set(next)
    applyNetworkDebugLoggingSettings()
  }

  fun toggleUserspaceOnlyMode() {
    val next = !userspaceOnlyMode.value
    App.get().encryptToPref("userspaceOnlyMode", next.toString())
    userspaceOnlyMode.set(next)
  }

  fun toggleLocalProxyListener() {
    val next = !localProxyEnabled.value
    App.get().encryptToPref("localProxyEnabled", next.toString())
    localProxyEnabled.set(next)
    App.get().updateLocalProxyListener(next, localProxyAddress.value)
  }

  fun updateLocalProxyAddress(addr: String) {
    App.get().encryptToPref("localProxyAddress", addr)
    localProxyAddress.set(addr)
    if (localProxyEnabled.value) {
      App.get().updateLocalProxyListener(true, addr)
    }
  }

  private fun readEncryptedBool(key: String, default: Boolean): Boolean {
    return App.get().decryptFromPref(key)?.toBooleanStrictOrNull() ?: default
  }

  private fun applyNetworkDebugLoggingSettings() {
    Libtailscale.applyDNSSettings()
  }
}
