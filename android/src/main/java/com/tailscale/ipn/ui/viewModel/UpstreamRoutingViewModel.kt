// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.viewModel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.tailscale.ipn.App
import com.tailscale.ipn.multiproxy.db.AppBinding
import com.tailscale.ipn.multiproxy.db.ProvisioningState
import com.tailscale.ipn.multiproxy.db.Upstream
import com.tailscale.ipn.multiproxy.db.UpstreamKind
import com.tailscale.ipn.util.TSLog
import java.util.UUID
import libtailscale.Libtailscale
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
 * One entry a routing choice can point at.
 *
 * The three sources are deliberately flattened into one list, because to the user they are the same
 * kind of decision - "where does this app's traffic go" - even though a Tailnet, a proxy, and the
 * direct bypass have nothing in common underneath.
 */
data class RoutableUpstream(
    val id: String,
    val label: String,
    /** One of `tailnet`, `socks5`, `wireguard`, `direct`. */
    val kind: String,
    val enabled: Boolean,
)

/**
 * Backs both the upstream list and the per-app routing screens.
 *
 * They share every repository and would otherwise have to keep two copies of the same state in sync,
 * which is exactly the bug this avoids: a picker offering an upstream the list has just deleted.
 */
class UpstreamRoutingViewModel : ViewModel() {
  private val session = App.get().multiProxySession

  private val upstreamRepository = session.upstreamRepository
  private val bindingRepository = session.appBindingRepository
  private val secrets = session.upstreamSecretStore
  private val settings = session.routingSettings

  /** The user's configured non-Tailnet upstreams. */
  val upstreams: StateFlow<List<Upstream>> = upstreamRepository.upstreams

  /** Package name to upstream id, for apps the user has explicitly bound. */
  val bindings: StateFlow<Map<String, String>> = bindingRepository.bindings

  val defaultUpstreamId: MutableStateFlow<String> = MutableStateFlow(settings.defaultUpstreamId)

  /** Whether the Multi-Tailnet VPN captures ordinary internet and LAN traffic. Off by default. */
  val broadCaptureEnabled: MutableStateFlow<Boolean> = MutableStateFlow(settings.broadCaptureEnabled)

  /** Whether LAN-destination traffic stays direct regardless of routing. On by default. */
  val lanExclusionEnabled: MutableStateFlow<Boolean> = MutableStateFlow(settings.lanExclusionEnabled)

  /** Surfaces a failed save to the screen that asked for it. */
  val errorMessage: MutableStateFlow<String?> = MutableStateFlow(null)

  /**
   * Everything a rule can route to: ready Tailnets, configured upstreams, and the direct bypass.
   *
   * A disabled entry is still listed, marked not enabled, so the UI can show that an app is bound to
   * something currently switched off. Hiding it would make the binding look lost.
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
  // upstreams
  // -------------------------------------------------------------------------

  /**
   * Saves a SOCKS5 upstream. Pass the id of an existing one to edit it, or null to create.
   *
   * The address is checked here rather than only in Go, so a typo is reported while the user is
   * still looking at the field they typed it into.
   */
  fun saveSocks5(
      id: String?,
      label: String,
      address: String,
      username: String,
      password: String,
      via: String,
  ) {
    if (!isHostPort(address)) {
      errorMessage.value = "Address must be host:port, for example 127.0.0.1:10808"
      return
    }
    val config =
        JSONObject()
            .put("address", address.trim())
            .put("username", username)
            .put("password", password)
            .toString()
    save(id, UpstreamKind.SOCKS5, label, via, config)
  }

  /**
   * Saves a WireGuard upstream.
   *
   * The text may be either a wg-quick `.conf`, which is what a provider hands out, or the JSON form
   * directly. Which one it is is decided by looking at it rather than by asking, because a user
   * pasting a config should not have to know or care that the two forms exist.
   */
  fun saveWireGuard(id: String?, label: String, config: String, via: String) {
    val text = config.trim()
    if (text.isEmpty()) {
      errorMessage.value = "A WireGuard configuration is required"
      return
    }

    val json =
        if (text.startsWith("{")) {
          try {
            JSONObject(text)
            text
          } catch (e: Exception) {
            errorMessage.value = "That is not valid JSON: ${e.message}"
            return
          }
        } else {
          try {
            Libtailscale.multiProxyWireGuardConfigFromQuick(text)
          } catch (e: Exception) {
            errorMessage.value = e.message ?: "That is not a usable WireGuard configuration"
            return
          }
        }

    save(id, UpstreamKind.WIREGUARD, label, via, json)
  }

  private fun save(
      id: String?,
      kind: UpstreamKind,
      label: String,
      via: String,
      configJson: String,
  ) {
    val upstreamId = id ?: "upstream-${UUID.randomUUID()}"
    if (via == upstreamId) {
      errorMessage.value = "An upstream cannot be chained through itself"
      return
    }
    viewModelScope.launch {
      val existing = upstreamRepository.getImmediate(upstreamId)
      // The config is written first: a row with no configuration is skipped at
      // registration with a complaint, whereas an orphaned config is harmless.
      withContext(Dispatchers.IO) { secrets.saveConfig(upstreamId, configJson) }
      upstreamRepository.save(
          Upstream(
              id = upstreamId,
              kind = kind,
              label = label.ifBlank { upstreamId },
              via = via,
              enabled = existing?.enabled ?: true,
              createdAt = existing?.createdAt ?: System.currentTimeMillis(),
          ))
      applyNow()
    }
  }

  fun setUpstreamEnabled(id: String, enabled: Boolean) {
    viewModelScope.launch {
      upstreamRepository.setEnabled(id, enabled)
      applyNow()
    }
  }

  fun deleteUpstream(id: String) {
    viewModelScope.launch {
      upstreamRepository.delete(id)
      withContext(Dispatchers.IO) { secrets.deleteConfig(id) }
      if (defaultUpstreamId.value == id) setDefaultUpstream("")
      applyNow()
    }
  }

  /** Reads back the stored configuration so an edit form can be prefilled. */
  fun configFor(id: String): String? = secrets.getConfig(id)

  // -------------------------------------------------------------------------
  // routing choices
  // -------------------------------------------------------------------------

  /** The upstream for apps with no binding of their own; empty leaves them on today's route. */
  fun setDefaultUpstream(id: String) {
    settings.defaultUpstreamId = id
    defaultUpstreamId.value = id
    viewModelScope.launch { applyNow() }
  }

  /**
   * Turns broad VPN capture on or off.
   *
   * Unlike [setDefaultUpstream], this changes what the VPN's TUN device itself captures
   * (IPNService.kt's rebuildMultiProxyTunLocked), not just the policy applied over a live engine -
   * so it only takes effect on the next VPN (re)build, not immediately.
   */
  fun setBroadCaptureEnabled(enabled: Boolean) {
    settings.broadCaptureEnabled = enabled
    broadCaptureEnabled.value = enabled
    if (session.engine != null) {
      val intent = android.content.Intent(session.app, com.tailscale.ipn.IPNService::class.java)
          .setAction(com.tailscale.ipn.IPNService.ACTION_RESTART_VPN)
      session.app.startService(intent)
    }
  }

  /**
   * Turns the LAN-stays-direct default rule on or off.
   *
   * Unlike [setBroadCaptureEnabled], this is a policy change the live engine picks up immediately
   * via [applyNow] - it does not touch what the TUN captures, only where captured LAN traffic goes.
   */
  fun setLanExclusionEnabled(enabled: Boolean) {
    settings.lanExclusionEnabled = enabled
    lanExclusionEnabled.value = enabled
    viewModelScope.launch { applyNow() }
  }

  fun bindApp(packageName: String, upstreamId: String) {
    viewModelScope.launch {
      bindingRepository.bind(packageName, upstreamId)
      applyNow()
    }
  }

  fun unbindApp(packageName: String) {
    viewModelScope.launch {
      bindingRepository.unbind(packageName)
      applyNow()
    }
  }

  fun bindingFor(packageName: String): AppBinding? =
      bindingRepository.getAllImmediate()[packageName]?.let { AppBinding(packageName, it) }

  /**
   * Pushes the current configuration into the running engine, if there is one.
   *
   * Upstream registration and policy are both designed to be replaced live, so a routing change
   * takes effect on the next flow rather than needing the VPN restarted. With no engine running this
   * does nothing and the configuration is applied at the next VPN build instead.
   */
  private suspend fun applyNow() {
    val engine = session.engine ?: return
    withContext(Dispatchers.IO) {
      try {
        session.upstreamPolicyApplier.apply(engine)
      } catch (e: Exception) {
        TSLog.e(TAG, "could not apply routing configuration: $e")
      }
    }
  }

  private fun isHostPort(value: String): Boolean {
    val trimmed = value.trim()
    val port = trimmed.substringAfterLast(':', "")
    val host = trimmed.substringBeforeLast(':', "")
    return host.isNotEmpty() && (port.toIntOrNull() ?: 0) in 1..65535
  }

  companion object {
    private const val TAG = "UpstreamRoutingViewModel"

    /** Matches multiproxy.DirectUpstreamID. */
    const val DIRECT_UPSTREAM_ID = "@direct"
  }
}
