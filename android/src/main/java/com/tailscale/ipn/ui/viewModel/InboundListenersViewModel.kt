// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.viewModel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.tailscale.ipn.App
import com.tailscale.ipn.multiproxy.ControlException
import com.tailscale.ipn.multiproxy.MultiProxyControls
import com.tailscale.ipn.multiproxy.db.InboundListenerRecord
import com.tailscale.ipn.multiproxy.db.ProvisioningState
import com.tailscale.ipn.util.TSLog
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

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
  private val controls = MultiProxyControls(session)

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
      proxyProtocol: Boolean,
  ) = act { controls.saveInboundListener(id, upstream, listenPort, localTarget, proxyProtocol) }

  fun setEnabled(id: String, enabled: Boolean) = act {
    controls.setInboundListenerEnabled(id, enabled)
  }

  fun delete(id: String) = act { controls.deleteInboundListener(id) }

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
    private const val TAG = "InboundListenersViewModel"
  }
}
