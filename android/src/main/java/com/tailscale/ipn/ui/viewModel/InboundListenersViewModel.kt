// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.viewModel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.tailscale.ipn.App
import com.tailscale.ipn.multiproxy.InboundListenerRules
import com.tailscale.ipn.multiproxy.db.InboundListenerRecord
import com.tailscale.ipn.multiproxy.db.ProvisioningState
import com.tailscale.ipn.util.TSLog
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Backs the Inbound Listeners settings screen: tailnet peers reach a local service through an
 * enabled tailnet's node, by port - see `libtailscale/multiproxy/inbound_listener.go`.
 *
 * Only tailnets are selectable, because only a tailnet has a node to accept on; this is the ingress
 * counterpart to the outbound TUN datapath, which no tailnet address is ever assigned to.
 */
class InboundListenersViewModel : ViewModel() {
  private val session = App.get().multiProxySession
  private val repository = session.inboundListenerRepository

  /** The user's configured listeners. */
  val listeners: StateFlow<List<InboundListenerRecord>> = repository.listeners

  /** Surfaces a failed save to the screen that asked for it. */
  val errorMessage: MutableStateFlow<String?> = MutableStateFlow(null)

  /**
   * The tailnets a listener can be pointed at: every profile, with its enabled state, so the picker
   * can still show a disabled one marked as such rather than silently dropping it.
   */
  val tailnetCandidates: StateFlow<List<RoutableUpstream>> =
      session.profileRepository.profiles
          .map { profiles ->
            profiles.map {
              RoutableUpstream(
                  id = it.id,
                  label = it.displayName,
                  kind = "tailnet",
                  enabled = it.enabled && it.provisioningState == ProvisioningState.READY,
              )
            }
          }
          .stateIn(
              scope = viewModelScope,
              started = SharingStarted.WhileSubscribed(5000),
              initialValue = emptyList(),
          )

  fun save(
      id: String?,
      upstream: String,
      listenPort: String,
      localTarget: String,
      proxyProtocol: Boolean
  ) {
    val portNum = InboundListenerRules.parseListenPort(listenPort)
    if (portNum == null) {
      errorMessage.value = "Port must be a number from 1 to 65535"
      return
    }
    if (upstream.isBlank()) {
      errorMessage.value = "Choose which tailnet this listener accepts on"
      return
    }
    val target = InboundListenerRules.parseLocalTarget(localTarget)
    if (target == null) {
      errorMessage.value = "Local target must be host:port, e.g. 127.0.0.1:22"
      return
    }
    val listenerId = id ?: "inbound-${UUID.randomUUID()}"
    viewModelScope.launch {
      repository.saveConfig(listenerId, upstream, portNum, target, proxyProtocol)
      applyNow()
    }
  }

  fun setEnabled(id: String, enabled: Boolean) {
    viewModelScope.launch {
      repository.setEnabled(id, enabled)
      applyNow()
    }
  }

  fun delete(id: String) {
    viewModelScope.launch {
      repository.delete(id)
      applyNow()
    }
  }

  /**
   * Whether a listener is currently registered with the running engine - distinct from
   * [InboundListenerRecord.enabled] (user intent), so the UI can show "paused: tailnet is off".
   * Best-effort: returns false with no engine running.
   */
  fun isRegistered(id: String): Boolean {
    val json =
        try {
          session.engine?.getInboundListenersJSON() ?: "[]"
        } catch (e: Exception) {
          "[]"
        }
    return try {
      val arr = org.json.JSONArray(json)
      (0 until arr.length()).any { i -> arr.getJSONObject(i).optString("id") == id }
    } catch (e: Exception) {
      false
    }
  }

  private suspend fun applyNow() {
    val engine = session.engine ?: return
    withContext(Dispatchers.IO) {
      try {
        session.upstreamPolicyApplier.apply(engine)
      } catch (e: Exception) {
        TSLog.e(TAG, "could not apply inbound listener configuration: $e")
      }
    }
  }

  companion object {
    private const val TAG = "InboundListenersViewModel"
  }
}
