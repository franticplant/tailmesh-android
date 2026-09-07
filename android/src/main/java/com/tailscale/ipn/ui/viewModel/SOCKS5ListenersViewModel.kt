// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.viewModel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.tailscale.ipn.App
import com.tailscale.ipn.multiproxy.db.ProvisioningState
import com.tailscale.ipn.multiproxy.db.SOCKS5ListenerRecord
import com.tailscale.ipn.util.TSLog
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Backs the SOCKS5 Listeners settings screen: the list of configured listeners, their add/edit/
 * remove/enable actions, and the upstream picker they share with app routing (see
 * [routableUpstreams]).
 *
 * A listener is a "workload identity" the same way an app binding is - see
 * [com.tailscale.ipn.multiproxy.UpstreamPolicyApplier.applySOCKS5Listeners] for how disabling a
 * listener's upstream tailnet stops it, and re-enabling that tailnet brings it back, without this
 * screen having to do anything itself: it only ever writes user intent
 * ([SOCKS5ListenerRecord.enabled] plus the listener's own configuration), never the live
 * registered-with-the-engine state.
 */
class SOCKS5ListenersViewModel : ViewModel() {
  private val session = App.get().multiProxySession
  private val listenerRepository = session.socks5ListenerRepository
  private val secrets = session.upstreamSecretStore

  /** The user's configured listeners. */
  val listeners: StateFlow<List<SOCKS5ListenerRecord>> = listenerRepository.listeners

  /** Surfaces a failed save to the screen that asked for it. */
  val errorMessage: MutableStateFlow<String?> = MutableStateFlow(null)

  /**
   * Everything a listener can be pointed at: ready Tailnets, configured upstreams, and the direct
   * bypass. Same shape and same "still show a disabled entry, just marked not enabled" behaviour as
   * [UpstreamRoutingViewModel.routableUpstreams] - duplicated rather than shared, since the two
   * screens' ViewModels have no lifecycle relationship to share a `stateIn` scope through.
   */
  val routableUpstreams: StateFlow<List<RoutableUpstream>> =
      combine(session.profileRepository.profiles, session.upstreamRepository.upstreams) {
              profiles,
              configured ->
            buildList {
              add(
                  RoutableUpstream(
                      id = UpstreamRoutingViewModel.DIRECT_UPSTREAM_ID,
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
                            enabled = it.enabled))
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

  /**
   * Saves a listener. Pass the id of an existing one to edit it, or null to create. `username`/
   * `password` empty means no RFC 1929 auth required to connect to it.
   */
  fun save(
      id: String?,
      bindAddr: String,
      port: String,
      upstream: String,
      username: String,
      password: String,
  ) {
    val trimmedBindAddr = bindAddr.trim().ifEmpty { "127.0.0.1" }
    val portNum = port.trim().toIntOrNull()
    if (portNum == null || portNum !in 1..65535) {
      errorMessage.value = "Port must be a number from 1 to 65535"
      return
    }
    if (upstream.isBlank()) {
      errorMessage.value = "Choose which upstream this listener hands out"
      return
    }
    val listenerId = id ?: "listener-${UUID.randomUUID()}"
    val hasAuth = username.isNotEmpty() || password.isNotEmpty()
    viewModelScope.launch {
      if (hasAuth) {
        val auth = JSONObject().put("username", username).put("password", password).toString()
        withContext(Dispatchers.IO) { secrets.saveListenerAuth(listenerId, auth) }
      } else {
        withContext(Dispatchers.IO) { secrets.deleteListenerAuth(listenerId) }
      }
      listenerRepository.saveConfig(listenerId, trimmedBindAddr, portNum, upstream, hasAuth)
      applyNow()
    }
  }

  fun setEnabled(id: String, enabled: Boolean) {
    viewModelScope.launch {
      listenerRepository.setEnabled(id, enabled)
      applyNow()
    }
  }

  fun delete(id: String) {
    viewModelScope.launch {
      listenerRepository.delete(id)
      withContext(Dispatchers.IO) { secrets.deleteListenerAuth(id) }
      applyNow()
    }
  }

  /** Reads back the stored username/password so an edit form can be prefilled, or null if none. */
  fun authFor(id: String): Pair<String, String>? {
    val json = secrets.getListenerAuth(id) ?: return null
    return try {
      val obj = JSONObject(json)
      Pair(obj.optString("username"), obj.optString("password"))
    } catch (e: Exception) {
      null
    }
  }

  /**
   * Whether a listener is currently actually registered with the running engine - distinct from
   * [SOCKS5ListenerRecord.enabled] (user intent), so the UI can show "paused: upstream is off"
   * rather than only the user's own on/off choice. Best-effort: returns false with no engine
   * running, the same as every other live-state read in this app.
   */
  fun isRegistered(id: String): Boolean {
    val json =
        try {
          session.engine?.getSOCKS5ListenersJSON() ?: "[]"
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
        TSLog.e(TAG, "could not apply SOCKS5 listener configuration: $e")
      }
    }
  }

  companion object {
    private const val TAG = "SOCKS5ListenersViewModel"
  }
}
