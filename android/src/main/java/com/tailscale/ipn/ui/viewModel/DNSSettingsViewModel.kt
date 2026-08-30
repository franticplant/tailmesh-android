// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.viewModel

import androidx.annotation.StringRes
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.tailscale.ipn.App
import com.tailscale.ipn.IPNService
import com.tailscale.ipn.MultiProxySessionCoordinator
import com.tailscale.ipn.R
import com.tailscale.ipn.VpnRuntimeMode
import com.tailscale.ipn.ui.localapi.Client
import com.tailscale.ipn.ui.model.Ipn
import com.tailscale.ipn.ui.model.Tailcfg
import com.tailscale.ipn.ui.notifier.Notifier
import com.tailscale.ipn.ui.theme.off
import com.tailscale.ipn.ui.theme.success
import com.tailscale.ipn.ui.util.set
import com.tailscale.ipn.util.TSLog
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import libtailscale.Libtailscale

class DNSSettingsViewModelFactory : ViewModelProvider.Factory {
  @Suppress("UNCHECKED_CAST")
  override fun <T : ViewModel> create(modelClass: Class<T>): T {
    return DNSSettingsViewModel() as T
  }
}

class DNSSettingsViewModel : IpnViewModel() {
  companion object {
    const val PUBLIC_DOH_URL_KEY = "publicDoHURL"
    const val PUBLIC_DOH_OVERRIDE_EXIT_NODE_KEY = "publicDoHOverrideExitNode"
    const val PUBLIC_DOH_ROUTE_THROUGH_TAILSCALE_KEY = "publicDoHRouteThroughTailscale"
  }

  val enablementState: StateFlow<DNSEnablementState> =
      MutableStateFlow(DNSEnablementState.NOT_RUNNING)
  val dnsConfig: StateFlow<Tailcfg.DNSConfig?> = MutableStateFlow(null)
  val publicDoHURL: StateFlow<String> = MutableStateFlow("")
  val publicDoHOverrideExitNode: StateFlow<Boolean> = MutableStateFlow(true)
  val publicDoHRouteThroughTailscale: StateFlow<Boolean> = MutableStateFlow(false)

  /**
   * True while Multi-Tailnet mode owns the datapath. The controls backed by CorpDNS,
   * publicDoHOverrideExitNode and publicDoHRouteThroughTailscale are only read by Standard mode's
   * DNS manager (libtailscale/control_doh.go), so the UI presents them as inapplicable rather than
   * letting them look effective.
   */
  val isMultiProxy: StateFlow<Boolean> = MutableStateFlow(false)

  init {
    publicDoHURL.set(App.get().decryptFromPref(PUBLIC_DOH_URL_KEY) ?: "")
    publicDoHOverrideExitNode.set(
        App.get().decryptFromPref(PUBLIC_DOH_OVERRIDE_EXIT_NODE_KEY)?.toBooleanStrictOrNull()
            ?: true)
    publicDoHRouteThroughTailscale.set(
        App.get().decryptFromPref(PUBLIC_DOH_ROUTE_THROUGH_TAILSCALE_KEY)?.toBooleanStrictOrNull()
            ?: false)

    viewModelScope.launch {
      combine(Notifier.netmap, Notifier.prefs, IPNService.runtimeMode) { netmap, prefs, mode ->
            Triple(netmap, prefs, mode)
          }
          .stateIn(viewModelScope)
          .collect { (netmap, prefs, mode) ->
            TSLog.d("DNSSettingsViewModel", "prefs: CorpDNS=" + prefs?.CorpDNS.toString())
            val multi = mode == VpnRuntimeMode.MULTIPROXY
            isMultiProxy.set(multi)
            when {
              // Multi-Tailnet's resolver runs regardless of CorpDNS, so report what is
              // actually resolving rather than what the unused pref says.
              multi -> enablementState.set(DNSEnablementState.MULTI_TAILNET)
              prefs == null -> enablementState.set(DNSEnablementState.NOT_RUNNING)
              prefs.CorpDNS -> enablementState.set(DNSEnablementState.ENABLED)
              else -> enablementState.set(DNSEnablementState.DISABLED)
            }
            netmap?.let { dnsConfig.set(netmap.DNS) }
          }
    }
  }

  fun toggleCorpDNS(callback: (Result<Ipn.Prefs>) -> Unit) {
    val prefs =
        Notifier.prefs.value
            ?: run {
              callback(Result.failure(Exception("no prefs")))
              return@toggleCorpDNS
            }

    val prefsOut = Ipn.MaskedPrefs()
    prefsOut.CorpDNS = !prefs.CorpDNS
    Client(viewModelScope).editPrefs(prefsOut, callback)
  }

  fun updatePublicDoHURL(url: String) {
    App.get().encryptToPref(PUBLIC_DOH_URL_KEY, url)
    publicDoHURL.set(url)
    applyPublicDoHSettings()
  }

  fun togglePublicDoHOverrideExitNode() {
    val next = !publicDoHOverrideExitNode.value
    App.get().encryptToPref(PUBLIC_DOH_OVERRIDE_EXIT_NODE_KEY, next.toString())
    publicDoHOverrideExitNode.set(next)
    applyPublicDoHSettings()
  }

  fun togglePublicDoHRouteThroughTailscale() {
    val next = !publicDoHRouteThroughTailscale.value
    App.get().encryptToPref(PUBLIC_DOH_ROUTE_THROUGH_TAILSCALE_KEY, next.toString())
    publicDoHRouteThroughTailscale.set(next)
    applyPublicDoHSettings()
  }

  private fun applyPublicDoHSettings() {
    // Standard mode: reads these same prefs via the regular backend's DNS
    // manager (control_doh.go). Multi-Tailnet mode has its own from-scratch
    // DNS server with no link to that backend, so it needs its own push.
    Libtailscale.applyDNSSettings()
    MultiProxySessionCoordinator.refreshUpstreamDNS()
  }
}

enum class DNSEnablementState(
    @StringRes val title: Int,
    @StringRes val caption: Int,
    val symbolDrawable: Int,
    val tint: @Composable () -> Color
) {
  NOT_RUNNING(
      R.string.not_running,
      R.string.tailscale_is_not_running_this_device_is_using_the_system_dns_resolver,
      R.drawable.xmark_circle,
      { MaterialTheme.colorScheme.off }),
  ENABLED(
      R.string.using_tailscale_dns,
      R.string.this_device_is_using_tailscale_to_resolve_dns_names,
      R.drawable.check_circle,
      { MaterialTheme.colorScheme.success }),
  DISABLED(
      R.string.not_using_tailscale_dns,
      R.string.this_device_is_using_the_system_dns_resolver,
      R.drawable.xmark_circle,
      { MaterialTheme.colorScheme.error }),

  // Multi-Tailnet mode resolves DNS through libtailscale/multiproxy/dns.go, which
  // never consults the CorpDNS pref. Reporting ENABLED/DISABLED off that pref here
  // would describe a resolver that isn't the one in use.
  MULTI_TAILNET(
      R.string.using_multi_tailnet_dns,
      R.string.this_device_is_using_multi_tailnet_dns,
      R.drawable.check_circle,
      { MaterialTheme.colorScheme.success })
}
