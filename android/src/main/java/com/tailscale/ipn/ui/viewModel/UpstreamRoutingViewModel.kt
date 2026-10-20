// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.viewModel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.tailscale.ipn.App
import com.tailscale.ipn.multiproxy.ControlException
import com.tailscale.ipn.multiproxy.MultiProxyControls
import com.tailscale.ipn.multiproxy.db.AppBinding
import com.tailscale.ipn.multiproxy.db.ProvisioningState
import com.tailscale.ipn.multiproxy.db.Upstream
import com.tailscale.ipn.util.TSLog
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * One entry a routing choice can point at.
 *
 * The three sources are deliberately flattened into one list, because to the user they are the same
 * kind of decision - "where does this app's traffic go" - even though a Tailnet, a proxy, and the
 * direct bypass have nothing in common underneath.
 */
data class RoutableUpstream(
    val id: String,
    val label: String,
    /** One of `tailnet`, `socks5`, `wireguard`, `exitnode`, `direct`. */
    val kind: String,
    val enabled: Boolean,
)

/**
 * One peer of some tailnet that offers to be an exit node. See
 * [UpstreamRoutingViewModel.fetchExitNodeCandidates].
 */
data class ExitNodeCandidate(
    val id: String,
    val hostname: String,
    val dnsName: String,
    val ip: String,
)

/**
 * Backs both the upstream list and the per-app routing screens.
 *
 * They share every repository and would otherwise have to keep two copies of the same state in
 * sync, which is exactly the bug this avoids: a picker offering an upstream the list has just
 * deleted.
 */
class UpstreamRoutingViewModel : ViewModel() {
  private val session = App.get().multiProxySession

  private val upstreamRepository = session.upstreamRepository
  private val bindingRepository = session.appBindingRepository
  private val secrets = session.upstreamSecretStore
  private val settings = session.routingSettings
  private val controls = MultiProxyControls(session)

  /** The user's configured non-Tailnet upstreams. */
  val upstreams: StateFlow<List<Upstream>> = upstreamRepository.upstreams

  /** Package name to its full binding (upstream id and DNS override), for bound apps. */
  val bindings: StateFlow<Map<String, AppBinding>> = bindingRepository.bindings

  val defaultUpstreamId: MutableStateFlow<String> = MutableStateFlow(settings.defaultUpstreamId)

  /** Where DNS goes for apps with no route of their own; empty means "same as the data path". */
  val defaultDNSUpstreamId: MutableStateFlow<String> =
      MutableStateFlow(settings.defaultDNSUpstreamId)

  /** Whether the Multi-Tailnet VPN captures ordinary internet and LAN traffic. Off by default. */
  val broadCaptureEnabled: MutableStateFlow<Boolean> =
      MutableStateFlow(settings.broadCaptureEnabled)

  /** Whether LAN-destination traffic stays direct regardless of routing. On by default. */
  val lanExclusionEnabled: MutableStateFlow<Boolean> =
      MutableStateFlow(settings.lanExclusionEnabled)

  /** Surfaces a failed save to the screen that asked for it. */
  val errorMessage: MutableStateFlow<String?> = MutableStateFlow(null)

  /**
   * Everything a rule can route to: ready Tailnets, configured upstreams, and the direct bypass.
   *
   * A disabled entry is still listed, marked not enabled, so the UI can show that an app is bound
   * to something currently switched off. Hiding it would make the binding look lost.
   */
  val routableUpstreams: StateFlow<List<RoutableUpstream>> =
      combine(session.profileRepository.profiles, upstreamRepository.upstreams) {
              profiles,
              configured ->
            buildList {
              add(
                  RoutableUpstream(
                      id = DIRECT_UPSTREAM_ID,
                      label = "Direct (bypass the VPN)",
                      kind = "direct",
                      enabled = true,
                  ))
              profiles
                  .filter { it.provisioningState == ProvisioningState.READY }
                  .forEach {
                    add(
                        RoutableUpstream(
                            id = it.id,
                            label = it.displayName,
                            kind = "tailnet",
                            enabled = it.enabled,
                        ))
                  }
              configured.forEach {
                add(
                    RoutableUpstream(
                        id = it.id,
                        label = it.label,
                        kind = it.kind.name.lowercase(),
                        enabled = it.enabled,
                    ))
              }
            }
          }
          .stateIn(
              scope = viewModelScope,
              started = SharingStarted.WhileSubscribed(5000),
              initialValue = emptyList(),
          )

  // -------------------------------------------------------------------------
  // actions - all delegated to MultiProxyControls, which the remote-control
  // API also uses, so the two can never behave differently.
  // -------------------------------------------------------------------------

  /** Saves a SOCKS5 upstream. Pass the id of an existing one to edit it, or null to create. */
  fun saveSocks5(
      id: String?,
      label: String,
      address: String,
      username: String,
      password: String,
      via: String,
  ) = act { controls.saveSocks5(id, label, address, username, password, via) }

  /** Saves a WireGuard upstream from a wg-quick `.conf` or the JSON form. */
  fun saveWireGuard(id: String?, label: String, config: String, via: String) = act {
    controls.saveWireGuard(id, label, config, via)
  }

  /** Adds an exit-node upstream. See [MultiProxyControls.saveExitNode]. */
  fun saveExitNode(label: String, sourceTailnetId: String, authKey: String, peerAddr: String) =
      act {
        controls.saveExitNode(label, sourceTailnetId, authKey, peerAddr)
      }

  /** Peers of a running tailnet that offer to be an exit node. */
  fun fetchExitNodeCandidates(tailnetId: String): List<ExitNodeCandidate> =
      controls.exitNodeCandidates(tailnetId)

  /** Points a running tailnet's own traffic at one of its peers; empty peerAddr clears it. */
  fun setTailnetExitNode(tailnetId: String, peerAddr: String) = act {
    controls.setTailnetExitNode(tailnetId, peerAddr)
  }

  fun setUpstreamEnabled(id: String, enabled: Boolean) = act {
    controls.setUpstreamEnabled(id, enabled)
  }

  fun deleteUpstream(id: String) = act {
    controls.deleteUpstream(id)
    defaultUpstreamId.value = settings.defaultUpstreamId
    defaultDNSUpstreamId.value = settings.defaultDNSUpstreamId
  }

  /** Reads back the stored configuration so an edit form can be prefilled. */
  fun configFor(id: String): String? = controls.configFor(id)

  /** The upstream for apps with no binding of their own; empty leaves them on today's route. */
  fun setDefaultUpstream(id: String) {
    defaultUpstreamId.value = id
    act { controls.setDefaultUpstream(id) }
  }

  /** Splits where default-route DNS goes from where default-route data goes. */
  fun setDefaultDNSUpstream(id: String) {
    defaultDNSUpstreamId.value = id
    act { controls.setDefaultDNSUpstream(id) }
  }

  /** Turns broad VPN capture on or off; restarts the VPN if it is running. */
  fun setBroadCaptureEnabled(enabled: Boolean) {
    broadCaptureEnabled.value = enabled
    controls.setBroadCaptureEnabled(enabled)
  }

  /** Turns the LAN-stays-direct default rule on or off; applied live. */
  fun setLanExclusionEnabled(enabled: Boolean) {
    lanExclusionEnabled.value = enabled
    act { controls.setLanExclusionEnabled(enabled) }
  }

  fun bindApp(packageName: String, upstreamId: String) = act {
    controls.bindApp(packageName, upstreamId)
  }

  fun unbindApp(packageName: String) = act { controls.unbindApp(packageName) }

  /** Sets (or, with an empty id, clears) one app's DNS override. */
  fun setAppDNSUpstream(packageName: String, dnsUpstreamId: String) = act {
    controls.setAppDNSUpstream(packageName, dnsUpstreamId)
  }

  /** Sets whether this app's LAN-destined traffic keeps following its own data route. */
  fun setAppTunnelLAN(packageName: String, tunnelLan: Boolean) = act {
    controls.setAppTunnelLAN(packageName, tunnelLan)
  }

  fun bindingFor(packageName: String): AppBinding? =
      bindingRepository.getAllImmediate()[packageName]

  /** Runs one action, surfacing a validation failure to the screen that asked for it. */
  private fun act(block: suspend () -> Unit) {
    viewModelScope.launch {
      try {
        block()
      } catch (e: ControlException) {
        errorMessage.value = e.message
      } catch (e: Exception) {
        TSLog.e(TAG, "action failed: $e")
        errorMessage.value = e.message ?: "That did not work"
      }
    }
  }

  companion object {
    private const val TAG = "UpstreamRoutingViewModel"

    /** Matches multiproxy.DirectUpstreamID. */
    const val DIRECT_UPSTREAM_ID = MultiProxyControls.DIRECT_UPSTREAM_ID
  }
}
